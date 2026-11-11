"""H2: bounded, read-only Kali diagnostics. Never scan, pair or reconfigure radios."""

import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from .models import safe_text


@dataclass
class Probe:
    argv: list[str]
    status: str
    output: str = ""
    error: str = ""


class ReadOnlyRunner:
    """Only the fixed read-only probe plan below calls this argv-based runner."""

    def __init__(self, timeout=3, budget=45, output_limit=131072):
        self.timeout = timeout
        self.deadline = time.monotonic() + budget
        self.output_limit = output_limit

    def __call__(self, argv):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            return Probe(argv, "SKIPPED", error="Diagnostic time budget exhausted")
        binary = shutil.which(argv[0])
        if not binary:
            return Probe(argv, "MISSING", error="Tool not installed/on PATH")
        output = bytearray()
        truncated = threading.Event()
        with tempfile.TemporaryDirectory(prefix="polterheist-diagnostic-") as folder:
            env = dict(os.environ, LC_ALL="C", LANG="C", GST_REGISTRY=str(Path(folder) / "gst.bin"))
            try:
                process = subprocess.Popen(
                    [binary, *argv[1:]],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    env=env,
                    shell=False,
                )
            except OSError as error:
                return Probe(argv, "ERROR", error=str(error))

            def consume():
                while chunk := process.stdout.read(4096):
                    room = max(0, self.output_limit - len(output))
                    output.extend(chunk[:room])
                    if len(chunk) > room:
                        truncated.set()

            reader = threading.Thread(target=consume, daemon=True)
            reader.start()
            status, error = "OK", ""
            try:
                process.wait(timeout=min(self.timeout, remaining))
                if process.returncode:
                    status = "ERROR"
                    error = f"Command returned {process.returncode}; inspect output for permissions/service state"
            except subprocess.TimeoutExpired:
                status, error = "TIMEOUT", "Read-only query timed out"
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=2)
                reader.join(timeout=2)
                process.stdout.close()
            if truncated.is_set():
                status, error = (
                    "TRUNCATED",
                    "Probe output exceeded limit; missing capabilities remain unknown",
                )
            return Probe(argv, status, output.decode("utf-8", "replace"), error)


def parse_iw_devices(text):
    devices, current, phy = [], None, "Unknown"
    for line in text.splitlines():
        if match := re.match(r"\s*phy#(\d+)", line):
            phy, current = "phy" + match[1], None
        match = re.match(r"\s*Interface\s+([a-zA-Z0-9_.:-]{1,32})\s*$", line)
        if match or "Unnamed/non-netdev interface" in line:
            current = {"name": match[1] if match else "(non-netdev)", "phy": phy, "type": "Unknown"}
            devices.append(current)
        if current and (match := re.match(r"\s*type\s+(\S+)", line)):
            current["type"] = match[1]
    return devices


def parse_phys(text):
    result = {}
    for block in re.split(r"(?m)^Wiphy ", text)[1:]:
        lines = block.splitlines()
        name = lines[0].strip()
        modes = []
        match = re.search(r"Supported interface modes:\s*\n((?:\s+\*[^\n]+\n?)+)", block)
        if match:
            modes = re.findall(r"\*\s+([^\n]+)", match[1])
        frequencies = [
            {"mhz": int(m[1]), "disabled": "disabled" in m[2], "flags": m[2].strip()}
            for m in re.finditer(r"\*\s+(\d+) MHz\s+\[\d+\]([^\n]*)", block)
        ]
        bands = sorted(
            {
                "2.4 GHz"
                if f["mhz"] < 3000
                else "5 GHz"
                if f["mhz"] < 5925
                else "6 GHz"
                if f["mhz"] < 8000
                else "Other"
                for f in frequencies
            }
        )
        combinations = ""
        if "valid interface combinations:" in block:
            combinations = (
                block.split("valid interface combinations:", 1)[1]
                .split("\n\tSupported commands:", 1)[0][:4000]
                .strip()
            )
        result[name] = {
            "modes": [m.strip() for m in modes],
            "modes_reported": match is not None,
            "bands": bands,
            "frequencies": frequencies,
            "interface_combinations": combinations,
        }
    return result


def chipset(interface, sysfs):
    base = (Path(sysfs) / "class" / "net" / interface / "device").resolve()
    info = {"driver": "Unknown", "chipset_id": "Unknown", "modalias": "Unknown"}
    try:
        driver = base / "driver"
        if driver.exists():
            info["driver"] = driver.resolve().name
        for path in (base, base.parent):
            for vendor, product in (("vendor", "device"), ("idVendor", "idProduct")):
                if (path / vendor).is_file() and (path / product).is_file():
                    info["chipset_id"] = (
                        (path / vendor).read_text().strip()
                        + ":"
                        + (path / product).read_text().strip()
                    )
                    break
            if info["chipset_id"] != "Unknown":
                break
        if (base / "modalias").is_file():
            info["modalias"] = (base / "modalias").read_text()[:512].strip()
    except OSError:
        pass
    return info


def bluez_adapters(text):
    try:
        document = json.loads(text)
        objects = document["data"][0]
        result = []
        for path, interfaces in objects.items():
            if "org.bluez.Adapter1" not in interfaces:
                continue
            properties = interfaces["org.bluez.Adapter1"]

            def get(name):
                return properties.get(name, {}).get("data")

            result.append(
                {
                    "path": path,
                    "name": get("Name"),
                    "powered": get("Powered"),
                    "discovering": get("Discovering"),
                    "uuids": get("UUIDs") or [],
                }
            )
        return result
    except (ValueError, KeyError, TypeError, IndexError, AttributeError):
        return []


def collect(runner=None, platform=None, sysfs="/sys", environ=None, progress=None):
    platform = sys.platform if platform is None else platform
    environ = os.environ if environ is None else environ
    report = {
        "schema": 1,
        "recorded_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "platform": platform,
        "linux_supported": platform.startswith("linux"),
        "mode": "READ_ONLY_NO_RADIO_DISCOVERY",
        "probes": {},
        "wifi": [],
        "bluetooth": [],
        "limitations": [
            "Advertised capabilities are not a successful hardware/receiver test.",
            "No scan, pairing, capture, service activation or network changes were requested.",
        ],
    }
    if not report["linux_supported"]:
        report["limitations"].append(
            "Run --tv-diagnostics on Kali/Linux for hardware evidence; this host is not Linux."
        )
        return report
    runner = runner or ReadOnlyRunner()

    def probe(key, argv):
        if progress:
            progress("Checking " + " ".join(argv))
        result = runner(argv)
        report["probes"][key] = asdict(result)
        return result

    iw = probe("iw_devices", ["iw", "dev"])
    phy = probe("iw_phys", ["iw", "phy"])
    phys = parse_phys(phy.output) if phy.status == "OK" else {}
    for interface in parse_iw_devices(iw.output)[:16] if iw.status == "OK" else []:
        capability = phys.get(interface["phy"])
        interface.update(
            chipset(interface["name"], sysfs) if interface["name"] != "(non-netdev)" else {}
        )
        interface["p2p"] = {
            mode: mode in capability["modes"]
            if capability and capability["modes_reported"]
            else None
            for mode in ("P2P-client", "P2P-GO", "P2P-device")
        }
        interface["phy_capabilities"] = capability
        report["wifi"].append(interface)
        if interface["name"] != "(non-netdev)":
            probe(
                "wpa_modes_" + interface["name"],
                ["wpa_cli", "-i", interface["name"], "get_capability", "modes"],
            )
    probe("ip_addresses", ["ip", "-j", "address", "show"])
    probe("ip_routes", ["ip", "-j", "route", "show"])
    probe("ip6_routes", ["ip", "-j", "-6", "route", "show"])
    probe("neighbors", ["ip", "-j", "neigh", "show"])
    probe("networkmanager", ["nmcli", "-t", "-f", "DEVICE,TYPE,STATE", "device", "status"])
    probe("rfkill", ["rfkill", "--json", "list"])
    bus = ["busctl", "--system", "--auto-start=no", "--timeout=3"]
    supplicant = probe(
        "supplicant",
        [
            *bus,
            "get-property",
            "fi.w1.wpa_supplicant1",
            "/fi/w1/wpa_supplicant1",
            "fi.w1.wpa_supplicant1",
            "Capabilities",
        ],
    )
    wfd = probe(
        "wfd_property",
        [
            *bus,
            "get-property",
            "fi.w1.wpa_supplicant1",
            "/fi/w1/wpa_supplicant1",
            "fi.w1.wpa_supplicant1",
            "WFDIEs",
        ],
    )
    report["wfd"] = {
        "supplicant_p2p_advertised": '"p2p"' in supplicant.output
        if supplicant.status == "OK"
        else None,
        "wfd_property_readable": wfd.status == "OK",
        "session_verified": False,
        "note": "Readable WFDIEs or P2P support alone does not establish Miracast compatibility.",
    }
    bluez = probe(
        "bluez_objects",
        [
            *bus,
            "--json=short",
            "call",
            "org.bluez",
            "/",
            "org.freedesktop.DBus.ObjectManager",
            "GetManagedObjects",
        ],
    )
    report["bluetooth"] = bluez_adapters(bluez.output) if bluez.status == "OK" else []
    probe("bluetooth_tools", ["bluetoothctl", "--version"])
    encoders = probe("ffmpeg_encoders", ["ffmpeg", "-hide_banner", "-encoders"])
    names = re.findall(r"(?m)^\s*V[A-Z.]{5}\s+(\S+)", encoders.output)
    report["h264_encoders"] = [n for n in names if "264" in n] if encoders.status == "OK" else []
    probe("ffprobe", ["ffprobe", "-version"])
    probe("gstreamer", ["gst-inspect-1.0", "--version"])
    for element in ("x264enc", "openh264enc", "vah264enc", "nvh264enc", "pipewiresrc"):
        probe("gst_" + element, ["gst-inspect-1.0", element])
    probe("pipewire", ["pipewire", "--version"])
    probe("pipewire_server", ["pw-cli", "info", "0"])
    portal = probe(
        "screencast_portal",
        [
            "busctl",
            "--user",
            "--auto-start=no",
            "--timeout=3",
            "get-property",
            "org.freedesktop.portal.Desktop",
            "/org/freedesktop/portal/desktop",
            "org.freedesktop.portal.ScreenCast",
            "AvailableSourceTypes",
        ],
    )
    report["desktop"] = {
        "type": environ.get("XDG_SESSION_TYPE", "Unknown"),
        "name": environ.get("XDG_CURRENT_DESKTOP", "Unknown"),
        "x11_display_present": bool(environ.get("DISPLAY")),
        "wayland_display_present": bool(environ.get("WAYLAND_DISPLAY")),
        "portal_query": portal.status,
        "capture_started": False,
    }
    return report


def print_report(report):
    print("\nTV HARDWARE DIAGNOSTICS (read-only)")
    print("  Platform: " + safe_text(report["platform"]))
    for wifi in report["wifi"]:
        print(
            f"  {safe_text(wifi['name'])} / {wifi['phy']} / {safe_text(wifi.get('driver', 'Unknown'))} / {safe_text(wifi.get('chipset_id', 'Unknown'))}"
        )
        print(
            "    "
            + ", ".join(
                f"{k}={'yes' if v is True else 'no' if v is False else 'unknown'}"
                for k, v in wifi["p2p"].items()
            )
        )
        print(
            "    Advertised bands (restrictions in report): "
            + ", ".join((wifi.get("phy_capabilities") or {}).get("bands", []))
        )
    for adapter in report["bluetooth"]:
        print(
            f"  BlueZ: {safe_text(adapter['path'])} | powered={adapter['powered']} | local profile UUIDs={safe_text(adapter['uuids'])}"
        )
    for key, result in report["probes"].items():
        print(
            f"  {key}: {result['status']}"
            + (" - " + safe_text(result["error"]) if result["error"] else "")
        )
    if "h264_encoders" in report:
        print("  H.264 encoders listed (not runtime-tested): " + ", ".join(report["h264_encoders"]))
    for limitation in report["limitations"]:
        print("  [!] " + limitation)


def run(root):
    report = collect(progress=lambda message: print("  " + safe_text(message)))
    print_report(report)
    folder = Path(root) / "reports" / "tv_control"
    folder.mkdir(parents=True, exist_ok=True)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    path = folder / f"hardware_{stamp}.json"
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("  Diagnostic report: " + str(path))
    return 0 if report["linux_supported"] else 1
