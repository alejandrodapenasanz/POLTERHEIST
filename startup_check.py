"""Bounded local capability checks; unknown probes never imply missing hardware."""

import importlib.util
import json
import logging
import os
import re
import shutil
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

from tv_control.hardware import ReadOnlyRunner, bluez_adapters, parse_iw_devices, parse_phys


@dataclass
class Capability:
    label: str
    available: bool | None = True
    reason: str = ""


CURRENT = {}


def collect(*, runner=None, platform=None, windows_interfaces=None, which=None, root=None):
    platform = sys.platform if platform is None else platform
    which = which or shutil.which
    caps = {
        key: Capability(label)
        for key, label in (
            ("1", "LAN RECON"),
            ("2", "WIRELESS RECON"),
            ("3", "CAPTIVE PORTAL"),
            ("4", "IoT SCANNING"),
            ("monitor", "Wi-Fi monitor mode"),
            ("ap", "Wi-Fi access point"),
            ("p2p", "Wi-Fi Direct (P2P modes)"),
            ("ble", "Bluetooth adapter"),
            ("video", "Video conversion"),
        )
    }

    def set_cap(key, state, reason):
        caps[key].available, caps[key].reason = state, reason

    if platform.startswith("linux"):
        runner = runner or ReadOnlyRunner(timeout=1.5, budget=8)
        devices, phys = runner(["iw", "dev"]), runner(["iw", "phy"])
        missing = [name for name in ("ip", "nmap") if not which(name)]
        if missing:
            set_cap("1", False, "Missing tools: " + ", ".join(missing))
        elif hasattr(os, "geteuid") and os.geteuid() != 0:
            set_cap("1", False, "Root permissions required for LAN recon")
        links = runner(["ip", "-j", "address", "show"])
        if links.status == "OK":
            try:
                active = any(
                    interface.get("ifname") != "lo"
                    and any(
                        addr.get("family") == "inet" and addr.get("scope") == "global"
                        for addr in interface.get("addr_info", [])
                    )
                    for interface in json.loads(links.output)
                )
                if not active:
                    set_cap("1", False, "No LAN interface with an IPv4 address")
            except (ValueError, TypeError, AttributeError):
                pass
        if devices.status == "OK":
            wifi = parse_iw_devices(devices.output)
            if not wifi:
                set_cap("2", False, "No Wi-Fi interface detected")
        else:
            wifi = None
            set_cap(
                "2",
                False if devices.status == "MISSING" else None,
                "iw missing"
                if devices.status == "MISSING"
                else "Wi-Fi probe failed; check permissions/driver",
            )
        capabilities = parse_phys(phys.output) if phys.status == "OK" else {}
        modes = {mode for phy in capabilities.values() for mode in phy["modes"]}
        known = bool(capabilities) and all(phy["modes_reported"] for phy in capabilities.values())
        for key, required in (
            ("monitor", {"monitor"}),
            ("ap", {"AP"}),
            ("p2p", {"P2P-client", "P2P-GO", "P2P-device"}),
        ):
            supported = bool(modes & required)
            missing_iw = devices.status == "MISSING" or phys.status == "MISSING"
            state = True if supported else False if known or wifi == [] or missing_iw else None
            set_cap(
                key,
                state,
                "Advertised by driver; runtime validation required"
                if state
                else "iw is not installed"
                if missing_iw
                else "No compatible Wi-Fi radio/mode"
                if state is False
                else "Capability unknown; check iw/permissions",
            )
        bus = runner(
            [
                "busctl",
                "--system",
                "--auto-start=no",
                "--allow-interactive-authorization=no",
                "--timeout=1",
                "--json=short",
                "call",
                "org.bluez",
                "/",
                "org.freedesktop.DBus.ObjectManager",
                "GetManagedObjects",
            ]
        )
        if bus.status == "OK":
            adapters = bluez_adapters(bus.output)
            powered = any(adapter.get("powered") for adapter in adapters)
            set_cap(
                "ble", powered, "Adapter available" if powered else "No powered Bluetooth adapter"
            )
        else:
            set_cap("ble", None, "BlueZ unavailable or probe denied; hardware unverified")
        missing = [name for name in ("nmcli", "ip", "dnsmasq", "nft") if not which(name)]
        if missing:
            set_cap(
                "3", False, "Portal network needs: " + ", ".join(missing) + "; preview available"
            )
    else:
        set_cap("1", False, "Requires Kali/Linux")
        set_cap("3", False, "Portal network requires Linux; local preview available")
        for key in ("ap", "p2p"):
            set_cap(key, False, "Implemented backend requires Kali/Linux")
        set_cap("ble", None, "Bluetooth availability is checked when scanning")
        if platform == "win32" and windows_interfaces:
            try:
                wifi = windows_interfaces()
                set_cap(
                    "2",
                    bool(wifi),
                    "Native WLAN interface" if wifi else "No Wi-Fi adapter detected",
                )
                modes = [iface.get("capabilities", []) for iface in wifi]
                supported = any("monitor" in mode for mode in modes)
                state = True if supported else False if not wifi or all(modes) else None
                set_cap(
                    "monitor",
                    state,
                    "Driver advertises monitor mode"
                    if supported
                    else "Monitor mode unavailable"
                    if state is False
                    else "Driver capabilities unknown",
                )
            except (OSError, ValueError, RuntimeError) as error:
                set_cap("2", None, "Native WLAN query failed: " + str(error))
                set_cap("monitor", None, "Native WLAN query failed")
        else:
            set_cap("2", False, "Requires Linux or Windows WLAN")
            set_cap("monitor", None, "No supported local probe")
    root = Path(root) if root else Path(__file__).resolve().parent

    def media_tool(name):
        filename = name + (".exe" if platform == "win32" else "")
        return which(name) or any(
            path.is_file()
            for path in (root / ".cache/tv_control/tools/ffmpeg").glob("*/bin/" + filename)
        )

    if not all(media_tool(name) for name in ("ffmpeg", "ffprobe")):
        set_cap("video", False, "FFmpeg/ffprobe not installed; images remain available")
    missing = [
        name
        for name in ("PIL", "zeroconf", "pychromecast")
        if importlib.util.find_spec(name) is None
    ]
    if missing:
        set_cap("4", None, "Some backends need Python packages: " + ", ".join(missing))
    return caps


def refresh(**kwargs):
    global CURRENT
    try:
        CURRENT = collect(**kwargs)
    except Exception:
        logging.getLogger("polterheist.hardware").exception("Startup hardware check failed")
        CURRENT = {
            key: Capability(label, None, "Check failed; see logs")
            for key, label in (
                ("1", "LAN RECON"),
                ("2", "WIRELESS RECON"),
                ("3", "CAPTIVE PORTAL"),
                ("4", "IoT SCANNING"),
            )
        }
    logging.getLogger("polterheist.hardware").info(
        "Hardware check: %s", {k: asdict(v) for k, v in CURRENT.items()}
    )
    return CURRENT


def annotate(key, label, *, color=False):
    cap = CURRENT.get(key)
    if cap and cap.available is not True:
        status = "UNAVAILABLE" if cap.available is False else "UNKNOWN"
        text = f"{label} [{status}: {cap.reason}]"
        if color:
            return ("\033[91m" if cap.available is False else "\033[93m") + text + "\033[0m"
        return text
    return label


def display():
    color = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
    print("\n  LOCAL HARDWARE CHECK (no network scan)")
    for key, cap in CURRENT.items():
        suffix = (" [READY]" + (" — " + cap.reason if cap.reason else "")) if cap.available else ""
        print("  " + annotate(key, cap.label, color=color) + suffix)


def annotate_menu(text, mapping):
    color = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
    lines = []
    for line in text.split("\n"):
        match = re.match(r"\s*\[([^]]+)\]", line)
        key = mapping.get(match[1]) if match else None
        lines.append(annotate(key, line, color=color) if key else line)
    return "\n".join(lines)
