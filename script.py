#!/usr/bin/env python3
"""POLTERHEIST: LAN inventory (Linux) and Wi-Fi reconnaissance (Linux/Windows)."""

import argparse
import csv
import ctypes
import datetime
import getpass
import hashlib
import html
import http.server
import importlib.util
import ipaddress
import json
import os
import platform
import re
import secrets
import shutil
import signal
import subprocess
import sys
import threading
import time
import uuid
import xml.etree.ElementTree as ET
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

VERSION = "2.6.0"
BASE = Path(__file__).resolve().parent
PROFILE_PATH = BASE / "config" / "profile.json"
REPORTS = BASE / "reports"
UPSTREAM_COMMIT = "3cb3ef77d6b71e8441a51668c7e2b919608180f9"
VENDOR = BASE / "vendor" / "broadcom-wps"
PROFILE_FIELDS = {
    "name_alias": "Name / alias",
    "specialization": "Specialization",
    "biography": "Biography",
    "github": "GitHub",
    "linkedin": "LinkedIn",
    "website": "Web",
    "contact": "Contact",
}

GREEN = "\033[92m"
AMBER = "\033[93m"
RESET = "\033[0m"
COLOR = sys.stdout.isatty() and not os.getenv("NO_COLOR")


def tint(s, c=GREEN):
    return c + str(s) + RESET if COLOR else str(s)


BANNER = """
⠀⠀⠀⠀⠀⠀⠀⠀⠀⡠⠀⠀⠀⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢠⢠⣿⣿⣿⣦⡀⠀⠀⠀⠀⠀⠄⠀⠀⠄⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢀⠀⠀⠀⠀⣸⣦⣸⣧⣼⣿⣦⣄⣀⣈⣴⣾⣿⣿⣦⡐⠄⠀⠀⠀⠀
⠀⢠⣶⣶⣦⣤⣤⣤⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡀⠀⠀⠀⠀
⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡌⡀⠀⠀
⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⢠⠀⠀
⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠛⡙⢿⡿⠛⢿⣿⣿⣿⠀⠀⠀
⠀⠄⢿⣿⣿⣿⡿⠿⣿⡿⠉⠙⣿⣿⣿⣿⣿⡇⢘⠐⠨⠄⠁⠄⢻⣿⣿⠀⠀⠀
⠀⠀⡈⢿⣿⣿⡇⠆⠈⠃⠃⠁⠸⣿⣿⣿⣿⣷⢸⠀⠀⠀⠀⠈⡈⢿⡿⢀⠀⠀
⠀⠀⠀⠄⠻⣿⣇⠠⠀⠀⠀⠀⠂⢹⣿⣿⣿⣿⠈⠀⠀⠀⠀⠀⢀⠸⠋⠄⠀⠀
⠀⠀⠀⠀⠀⠈⠻⡆⠀⠀⠀⠀⠈⠄⢿⣿⣿⣿⡆⠂⠀⠀⠀⠀⠀⠀⠈⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠂⠀⠀⠀⠀⠀⠈⠄⢻⣿⣿⣧⠐⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢀⠹⣿⣿⡆⢁⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡘⢿⣿⡀⠄⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠀⡙⠳⠈⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀
                     P O L T E R H E I S T
"""

MACLINE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})\s+([a-fA-F0-9:]{17})\s*(.*)$")
CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
PERCENT = re.compile(r"(\d+(?:\.\d+)?)%\s+done", re.I)
REMAIN = re.compile(r"\(([^)]*remaining)\)", re.I)


class Spinner:
    """Indeterminate activity indicator: not a fabricated percentage."""

    def __init__(self, label):
        self.label = label
        self.stop_event = threading.Event()
        self.thread = None
        self.progress = ""
        self.failed = False

    def __enter__(self):
        self.started = time.monotonic()

        def animate():
            frames = "|/-\\"
            i = 0
            while not self.stop_event.wait(0.12):
                elapsed = int(time.monotonic() - self.started)
                msg = f"  [{frames[i % 4]}] {self.label} [{elapsed}s] {self.progress}"
                width = max(20, shutil.get_terminal_size((110, 24)).columns - 1)
                print("\r" + tint(cut(msg, width).ljust(width), AMBER), end="", flush=True)
                i += 1

        if sys.stdout.isatty():
            self.thread = threading.Thread(target=animate, daemon=True)
            self.thread.start()
        return self

    def __exit__(self, *args):
        self.stop_event.set()
        if self.thread:
            self.thread.join()
            print("\r" + " " * (shutil.get_terminal_size((110, 24)).columns - 1) + "\r", end="")
        mark = "!" if args[0] or self.failed else "+"
        print(tint(f"  [{mark}] {self.label} ({time.monotonic() - self.started:.1f}s)"))


def safe_text(value):
    """Keep untrusted SSIDs, banners and scanner output from controlling the terminal."""
    return "".join(c if c.isprintable() else f"\\x{ord(c):02x}" for c in str(value))


def stop_process(proc):
    if proc.poll() is not None:
        return
    try:
        if os.name == "posix":
            os.killpg(proc.pid, signal.SIGINT)
        else:
            proc.terminate()
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        if os.name == "posix":
            os.killpg(proc.pid, signal.SIGKILL)
        else:
            proc.kill()
        proc.wait()
    except ProcessLookupError:
        pass


def run_progress(cmd, label, logfile, timeout=None, stop_after_timeout=False):
    """Stream original output to disk; show only real per-phase Nmap progress."""
    env = dict(os.environ, LC_ALL="C", LANG="C")
    with Path(logfile).open("w", encoding="utf-8") as log, Spinner(label) as activity:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            start_new_session=(os.name == "posix"),
        )

        def consume():
            for line in proc.stdout:
                log.write(line)
                log.flush()
                match = PERCENT.search(line)
                if match:
                    percent = float(match.group(1))
                    remaining = REMAIN.search(line)
                    filled = min(16, max(0, round(percent * 16 / 100)))
                    phase = line.split("Timing:")[0].strip() if "Timing:" in line else "Nmap"
                    activity.progress = (
                        f"{safe_text(phase)} [{'#' * filled}{'-' * (16 - filled)}] "
                        f"{percent:g}% ETA: {remaining.group(1) if remaining else 'unknown'}"
                    )
                elif "Initiating " in line:
                    activity.progress = safe_text(line.strip())

        reader = threading.Thread(target=consume, daemon=True)
        reader.start()
        try:
            try:
                status = proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                if not stop_after_timeout:
                    raise
                stop_process(proc)
                status = proc.returncode
            activity.failed = status != 0
        finally:
            stop_process(proc)
            reader.join(timeout=5)
            proc.stdout.close()
    output = Path(logfile).read_text(encoding="utf-8")
    return subprocess.CompletedProcess(cmd, status, output, "")


def run_quiet(cmd, timeout=120):
    try:
        return subprocess.run(
            cmd,
            text=True,
            capture_output=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
            env=dict(os.environ, LC_ALL="C", LANG="C"),
        )
    except (subprocess.TimeoutExpired, OSError):
        return None


def require_linux(root=False):
    if not sys.platform.startswith("linux"):
        raise RuntimeError(
            "This feature requires Kali/Linux. Windows supports the menu, profile, WIRELESS RECON, and portal preview."
        )
    if root and os.geteuid() != 0:
        raise RuntimeError("Root privileges required: sudo .venv/bin/python script.py")


def require_tools(*names):
    missing = [name for name in names if not shutil.which(name)]
    if missing:
        raise RuntimeError(
            "Missing: " + ", ".join(missing) + ". Run python3 script.py --setup on Kali/Linux."
        )


def operating_system():
    if sys.platform == "win32":
        return {"id": "windows", "name": "Windows", "family": "windows"}
    if sys.platform.startswith("linux"):
        try:
            release = platform.freedesktop_os_release()
        except OSError:
            release = {}
        return {
            "id": release.get("ID", "linux"),
            "name": release.get("PRETTY_NAME", "Linux"),
            "family": "linux",
            "like": release.get("ID_LIKE", ""),
        }
    return {"id": sys.platform, "name": platform.system(), "family": "unsupported"}


def setup_environment():
    system = operating_system()
    print("  Setting up POLTERHEIST for " + system["name"])
    if system["family"] == "linux":
        if not shutil.which("apt-get"):
            raise RuntimeError("Automatic Linux setup requires APT (Kali/Debian/Ubuntu).")
        prefix = [] if os.geteuid() == 0 else ["sudo", "--"]
        if prefix:
            require_tools("sudo")
        packages = [
            "python3-venv",
            "python3-pip",
            "iw",
            "iproute2",
            "tcpdump",
            "network-manager",
            "dnsmasq-base",
            "nftables",
            "nmap",
            "arp-scan",
            "ffmpeg",
        ]
        if system["id"] == "kali":
            packages.append("firmware-mediatek")
        subprocess.run(prefix + ["apt-get", "update"], check=True)
        subprocess.run(prefix + ["apt-get", "install", "-y", *packages], check=True)
    elif system["family"] != "windows":
        raise RuntimeError("Supported systems: Kali/Linux or Windows.")
    environment = BASE / ".venv"
    python = environment / ("Scripts/python.exe" if system["family"] == "windows" else "bin/python")
    # A checkout copied between operating systems may contain an incompatible venv.
    other = environment / ("bin/python" if system["family"] == "windows" else "Scripts/python.exe")
    if other.exists() and not python.exists():
        environment = BASE / (".venv-windows" if system["family"] == "windows" else ".venv-linux")
        python = environment / (
            "Scripts/python.exe" if system["family"] == "windows" else "bin/python"
        )
    if not python.exists():
        subprocess.run([sys.executable, "-m", "venv", str(environment)], check=True)
    subprocess.run(
        [str(python), "-m", "pip", "install", "-r", str(BASE / "requirements.txt")], check=True
    )
    print("  Ready. Run: " + str(python) + " script.py --wireless")
    return 0


def linux_elevated_wireless(ssid=None, bssid=None):
    require_tools("sudo")
    args = ["sudo", "--", sys.executable, str(BASE / "script.py"), "--wireless"]
    if ssid is not None:
        args.extend(["--ssid", ssid])
    if bssid is not None:
        args.extend(["--bssid", bssid])
    print("  Linux will request sudo privileges to prepare and restore the adapter.")
    return subprocess.run(args, check=False).returncode


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def report_folder(kind):
    folder = (
        REPORTS
        / kind
        / (
            datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
            + "_"
            + uuid.uuid4().hex[:6]
        )
    )
    folder.mkdir(parents=True, exist_ok=False)
    return folder


def netinfo():
    routes = json.loads(
        subprocess.check_output(["ip", "-j", "-4", "route", "show", "default"], text=True)
    )
    route = next((r for r in routes if r.get("dev")), None)
    if not route:
        raise RuntimeError("No default IPv4 route")
    dev = route["dev"]
    gateway = route.get("gateway")
    addr = json.loads(
        subprocess.check_output(["ip", "-j", "-4", "addr", "show", "dev", dev], text=True)
    )
    info = next(
        (
            x
            for d in addr
            for x in d.get("addr_info", [])
            if x.get("family") == "inet" and x.get("scope") == "global"
        ),
        None,
    )
    if info is None:
        raise RuntimeError("The default interface has no global IPv4 address")
    my_ip = info["local"]
    network = ipaddress.ip_network(f"{my_ip}/{info['prefixlen']}", strict=False)
    return dev, my_ip, gateway, network


def good_vendor(v):
    return bool(v) and not any(
        x in v.lower() for x in ["unknown", "desconocido", "locally administered"]
    )


def discover(dev, my_ip, gateway, network, folder):
    found = {}

    def add(ip, mac="", vendor="", source=""):
        try:
            if ipaddress.ip_address(ip) not in network:
                return
        except ValueError:
            return
        entry = found.setdefault(
            ip,
            {
                "ip": ip,
                "mac": "-",
                "vendor": "Unknown",
                "sources": [],
                "manufacturer_evidence": [],
                "local": False,
            },
        )
        if mac and entry["mac"] == "-":
            entry["mac"] = mac.lower()
        if good_vendor(vendor):
            evidence = {"source": source, "vendor": vendor.strip(), "mac": mac.lower()}
            if evidence not in entry["manufacturer_evidence"]:
                entry["manufacturer_evidence"].append(evidence)
        if good_vendor(vendor) and (not good_vendor(entry["vendor"]) or source == "Nmap"):
            entry["vendor"] = vendor.strip()
        if source and source not in entry["sources"]:
            entry["sources"].append(source)

    res = None
    if shutil.which("arp-scan"):
        try:
            res = run_progress(
                ["arp-scan", "--interface", dev, "--localnet", "--plain", "--ignoredups"],
                "ARP discovery",
                folder / "discovery_arp.log",
                timeout=70,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            print(tint(f"  [!] ARP: {error}", AMBER))
    if res and res.returncode == 0:
        for line in res.stdout.splitlines():
            match = MACLINE.match(line.strip())
            if match:
                add(*match.groups(), source="ARP")
    else:
        print(tint("  [!] arp-scan failed; continuing with Nmap.", AMBER))

    # XML to file avoids mixing messages with parser output.
    xml = folder / "discovery_nmap.xml"
    try:
        res = run_progress(
            ["nmap", "-sn", "-PR", "-n", "--stats-every", "5s", "-oX", str(xml), str(network)],
            "Nmap host discovery",
            folder / "discovery_nmap.log",
            timeout=180,
        )
        if res.returncode:
            print(tint("  [!] Nmap discovery failed; check discovery_nmap.log.", AMBER))
    except (OSError, subprocess.TimeoutExpired) as error:
        print(tint(f"  [!] Nmap discovery: {error}", AMBER))
    if xml.exists():
        try:
            root = ET.parse(xml).getroot()
            for h in root.findall("host"):
                if h.find("status") is None or h.find("status").get("state") != "up":
                    continue
                ipv4 = mac = vendor = ""
                for a in h.findall("address"):
                    if a.get("addrtype") == "ipv4":
                        ipv4 = a.get("addr", "")
                    if a.get("addrtype") == "mac":
                        mac = a.get("addr", "")
                        vendor = a.get("vendor", "")
                if ipv4:
                    add(ipv4, mac, vendor, "Nmap")
        except ET.ParseError:
            print(tint("  [!] Unable to read the discovery XML.", AMBER))
    else:
        print(tint("  [!] No Nmap discovery XML available.", AMBER))

    local_mac = Path("/sys/class/net") / dev / "address"
    add(my_ip, mac=local_mac.read_text().strip() if local_mac.exists() else "", source="LOCAL")
    found[my_ip]["local"] = True
    hosts = [found[ip] for ip in sorted(found, key=ipaddress.ip_address)]
    for index, h in enumerate(hosts, 1):
        h["id"] = index
        h["gateway"] = h["ip"] == gateway
    return hosts


def cut(s, w):
    s = safe_text(s)
    return s if len(s) <= w else s[: w - 3] + "..."


def table(headers, rows, widths):
    border = "+" + "+".join("-" * (w + 2) for w in widths) + "+"

    def line(row):
        return "|" + "|".join(" " + cut(v, w).ljust(w) + " " for v, w in zip(row, widths)) + "|"

    print(border)
    print(line(headers))
    print(border)
    for r in rows:
        print(line(r))
    print(border)


def show_hosts(hosts):
    print(tint("\n[+] POLTERHEIST :: NETWORK DISCOVERY"))
    rows = [[h["id"], h["ip"], h["mac"], h["vendor"], ", ".join(h["sources"])] for h in hosts]
    table(["ID", "IP", "MAC", "VENDOR / INFO", "SOURCE"], rows, [3, 15, 17, 38, 16])
    print(f"  Total: {len(hosts)} IPs; LOCAL identifies this computer.")


def identify(host, folder):
    ip = host["ip"]
    vendor = host["vendor"]
    loc = host["local"]
    data = {
        "id": host["id"],
        "ip": ip,
        "vendor": vendor,
        "vendor_confidence": "Medium" if good_vendor(vendor) else "Low",
        "type": "Unknown",
        "os": "Unknown",
        "type_confidence": "Low",
        "evidence": list(host.get("manufacturer_evidence", [])),
        "mobile": False,
        "local": loc,
        "mac": host["mac"],
        "sources": host["sources"],
    }
    if host["mac"] != "-" and int(host["mac"].split(":")[0], 16) & 2:
        data["vendor_confidence"] = "Low"
        data["evidence"].append("Locally administered MAC: unreliable OUI")
    if loc:
        distro = Path("/etc/os-release")
        kali = distro.exists() and re.search(
            r"^ID=[\"\x27]?kali[\"\x27]?$", distro.read_text(), re.M
        )
        data.update(
            type="Kali (LOCAL)" if kali else "Linux (LOCAL)", os="Linux", type_confidence="High"
        )
        data["evidence"].append("Local interface")
        return data
    if host["gateway"]:
        data.update(type="Router / gateway", type_confidence="High")
        data["evidence"].append("Default gateway")
    elif "apple" in vendor.lower():
        data["type"] = "Apple device"
        data["evidence"].append("Apple OUI; device type unidentified")
    elif "sichuan ai-link" in vendor.lower():
        data["type"] = "Possible IoT device"
        data["evidence"].append("Wi-Fi module vendor; inconclusive")

    path = folder / f"identify_{ip}.xml"
    cmd = [
        "nmap",
        "-n",
        "-Pn",
        "-sS",
        "-sV",
        "--version-light",
        "-O",
        "--osscan-guess",
        "-p",
        "21,22,23,53,80,139,443,445,554,3389,62078,8080,8443,9100",
        "--max-retries",
        "1",
        "--host-timeout",
        "75s",
        "-T2",
        "--stats-every",
        "5s",
        "-oX",
        str(path),
        ip,
    ]
    try:
        res = run_progress(
            cmd, f"Identifying ID {host['id']}: {ip}", folder / f"identify_{ip}.log", timeout=90
        )
        if res.returncode:
            data["evidence"].append(f"Nmap exited with code {res.returncode}; see log")
    except (OSError, subprocess.TimeoutExpired) as error:
        data["evidence"].append(f"Incomplete identification: {error}")
    if not path.exists():
        return data
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError:
        return data
    match = root.find("./host/os/osmatch")
    accuracy = 0
    if match is not None:
        name = match.get("name", "")
        accuracy = int(match.get("accuracy", "0"))
        low = name.lower()
        for token, label in [
            ("windows", "Windows"),
            ("iphone", "iOS"),
            ("apple ios", "iOS"),
            ("android", "Android"),
            ("mac os", "macOS"),
            ("linux", "Linux"),
        ]:
            if token in low:
                data["os"] = label + " (estimated)"
                break
        else:
            if name:
                data["os"] = cut(name, 30)
        data["evidence"].append(f"Nmap osmatch {accuracy}% similarity")
    ports = {}
    products = []
    for p in root.findall("./host/ports/port"):
        st = p.find("state")
        if st is not None and st.get("state") == "open":
            number = int(p.get("portid"))
            ports[number] = True
            svc = p.find("service")
            if svc is not None:
                products.append(svc.get("product", "").lower())
    data["evidence"].append({"open_ports": sorted(ports), "products": products})
    if not host["gateway"]:
        if 9100 in ports:
            data.update(type="Likely printer", type_confidence="Medium")
        elif any(x in " ".join(products) for x in ["routeros", "openwrt", "fritz!os"]):
            data.update(type="Likely router", type_confidence="Medium")
        elif data["os"] in ("iOS (estimated)", "Android (estimated)") and accuracy >= 95:
            data.update(type="Likely phone/tablet", type_confidence="Medium", mobile=True)
        elif 3389 in ports or 445 in ports:
            data.update(type="Possible PC / server", type_confidence="Medium")
    return data


def show_ids(ident):
    print(tint("\n[+] POLTERHEIST :: PRELIMINARY IDENTIFICATION"))
    rows = [
        [
            d["id"],
            d["ip"],
            d["vendor"],
            d["type"],
            d["os"],
            d["vendor_confidence"],
            d["type_confidence"],
        ]
        for d in ident
    ]
    table(
        ["ID", "IP", "VENDOR", "ESTIMATED TYPE", "ESTIMATED OS", "VENDOR CONF", "TYPE CONF"],
        rows,
        [3, 15, 27, 23, 19, 8, 9],
    )
    print("  Classifications are estimates; Apple does not imply iPhone.")


def choose(hosts, ident):
    by_id = {host["id"]: host for host in hosts}
    defaults = [host for host in hosts if not host["local"]]
    valid = [d for d in ident if not d["mobile"] and not by_id[d["id"]]["local"]]
    print(tint("\n[+] POLTERHEIST :: TARGETS"))
    print(f"  [0] All IPs ({len(defaults)}; excludes LOCAL)")
    print(f"  [1] All non-mobile IPs ({len(valid)}; excludes Kali)")
    for d in valid:
        print(f"      [{d['id']}] {d['ip']} - {d['type']}")
    print("  [2] Custom - comma-separated IDs, e.g. 1,3,5")
    while True:
        mode = input("  Select [0/1/2] (q to quit): ").strip().lower()
        if mode == "q":
            return []
        if mode == "0":
            selected = defaults
        elif mode == "1":
            selected = [by_id[d["id"]] for d in valid]
        elif mode == "2":
            raw = input("  IDs: ").strip()
            parts = [p.strip() for p in raw.split(",")]
            if not parts or any(not p.isdigit() for p in parts):
                print("  Invalid format")
                continue
            ids = list(dict.fromkeys(int(p) for p in parts))
            if any(i not in by_id for i in ids):
                print("  ID out of range")
                continue
            selected = [by_id[i] for i in ids]
        else:
            continue
        if selected:
            print("  Selected: " + ", ".join(h["ip"] for h in selected))
            return selected
        print("  No targets. Try another option.")


def scan_one(host, mode, folder, index, total):
    ip = host["ip"]
    xml = folder / f"scan_{ip}.xml"
    cmd = [
        "nmap",
        "-n",
        "-Pn",
        "-sS",
        "-sV",
        "--script",
        "default or vuln",
        "-p-",
        "--stats-every",
        "10s",
        "-v",
        "-oX",
        str(xml),
    ]
    cmd += ["-T2", "--max-rate", "50"] if mode == "1" else ["-T3"]
    cmd.append(ip)
    print(tint(f"\n[{index}/{total}] Scanning {ip}"))
    status = {
        "id": host["id"],
        "ip": ip,
        "command": cmd,
        "started_at": utc_now(),
        "status": "running",
    }
    status_path = folder / f"scan_{ip}_status.json"
    dump_json(status_path, status)
    try:
        res = run_progress(cmd, f"ID {host['id']}: {ip}", folder / f"scan_{ip}.log")
        status.update(
            returncode=res.returncode, status="completed" if res.returncode == 0 else "error"
        )
        if res.returncode:
            print(tint(f"  [!] Nmap: exit code {res.returncode}; check scan_{ip}.log", AMBER))
    except KeyboardInterrupt:
        status["status"] = "cancelled"
        raise
    except OSError as error:
        status.update(status="error", error=str(error))
        raise
    finally:
        status["finished_at"] = utc_now()
        dump_json(status_path, status)
    return parse_scan_xml(xml, host)


def parse_scan_xml(xml, host):
    ip = host["ip"]
    rows = []
    if not xml.exists():
        return rows
    try:
        root = ET.parse(xml).getroot()
    except ET.ParseError:
        return rows
    for h in root.findall("host"):
        host_cves = set()
        for script in h.findall("./hostscript/script"):
            host_cves.update(CVE.findall(ET.tostring(script, encoding="unicode")))
        open_ports = []
        for p in h.findall("./ports/port"):
            st = p.find("state")
            if st is not None and st.get("state") == "open":
                open_ports.append(p)
        if not open_ports:
            rows.append(
                {
                    "ip": ip,
                    "vendor": host["vendor"],
                    "port": "-",
                    "service": "-",
                    "version": "-",
                    "cves": ",".join(sorted(host_cves)) or "-",
                }
            )
        for p in open_ports:
            svc = p.find("service")
            pcves = set(host_cves)
            for s in p.findall("script"):
                pcves.update(CVE.findall(ET.tostring(s, encoding="unicode")))
            rows.append(
                {
                    "ip": ip,
                    "vendor": host["vendor"],
                    "port": p.get("portid", "?") + "/" + p.get("protocol", "tcp"),
                    "service": svc.get("name", "-") if svc is not None else "-",
                    "version": " ".join(
                        filter(None, [svc.get(k, "") for k in ("product", "version", "extrainfo")])
                    )
                    or "-"
                    if svc is not None
                    else "-",
                    "cves": ",".join(sorted(pcves)) or "-",
                }
            )
    for row in rows:
        row["id"] = host["id"]
        row["cves"] = row["cves"].upper()
    return rows


def dump_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temporary.replace(path)


def lan_recon():
    require_linux(root=True)
    require_tools("nmap", "ip")
    dev, my_ip, gateway, network = netinfo()
    if network.num_addresses > 4096:
        raise RuntimeError("Subnet too large (>4096 addresses)")
    print(f"  Interface={dev} | Local={my_ip} | Gateway={gateway} | Network={network}")
    print("\n  [1] GHOST MODE: full scan, slower speed (detectable)")
    print("  [2] HUNTER MODE: full scan, normal speed")
    mode = input("  Mode [1/2]: ").strip()
    if mode not in ("1", "2"):
        return
    print(
        tint(
            "  Both modes generate traffic and logs; some vuln scripts can be intrusive.",
            AMBER,
        )
    )
    if input("  Do you own this network or have authorization? [y/N]: ").strip().lower() not in (
        "y",
        "yes",
    ):
        return
    folder = report_folder("lan")
    rows = []
    ident = []
    report = {
        "tool": "POLTERHEIST",
        "version": VERSION,
        "started_at": utc_now(),
        "mode": mode,
        "interface": dev,
        "local_ip": my_ip,
        "gateway": gateway,
        "network": str(network),
        "status": "running",
    }
    dump_json(folder / "report.json", report)
    try:
        hosts = discover(dev, my_ip, gateway, network, folder)
        show_hosts(hosts)
        dump_json(folder / "discovery.json", hosts)
        for h in hosts:
            ident.append(identify(h, folder))
            dump_json(folder / "identification.json", ident)
        show_ids(ident)
        selected = choose(hosts, ident)
        dump_json(
            folder / "selection.json",
            {"mode": mode, "ids": [h["id"] for h in selected], "ips": [h["ip"] for h in selected]},
        )
        if not selected or input("  Press ENTER to scan (q to return): ").strip().lower() == "q":
            report["status"] = "discovery_only"
            return
        for i, h in enumerate(selected, 1):
            rows.extend(scan_one(h, mode, folder, i, len(selected)))
            dump_json(folder / "results.json", rows)
        statuses = [json.loads(p.read_text()) for p in folder.glob("scan_*_status.json")]
        report["status"] = (
            "completed" if all(s["status"] == "completed" for s in statuses) else "partial_error"
        )
    except (KeyboardInterrupt, EOFError):
        report["status"] = "cancelled"
        print("\n  Interrupted; preserving evidence.")
    except Exception as error:
        report.update(status="error", error=str(error))
        raise
    finally:
        report.update(finished_at=utc_now(), results=rows)
        dump_json(folder / "report.json", report)
        with (folder / "report.csv").open("w", newline="", encoding="utf-8") as f:
            cols = ["id", "ip", "vendor", "port", "service", "version", "cves"]
            writer = csv.DictWriter(f, fieldnames=cols)
            writer.writeheader()
            writer.writerows(rows)
        print(f"  Reports: {folder}")
    print(tint("\n[+] POLTERHEIST :: RESULTS"))
    table(
        ["ID", "IP", "VENDOR", "PORT", "SERVICE", "VERSION", "CVEs"],
        [
            [r[k] for k in ("id", "ip", "vendor", "port", "service", "version", "cves")]
            for r in rows
        ],
        [3, 15, 24, 10, 14, 30, 28],
    )
    print("  CVEs are potential references, not confirmed vulnerabilities.")


# Wireless inventory. These parsers operate on saved scanner output as well as live scans.
MAC = re.compile(r"^[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}$")


# Native Wi-Fi API: fixed-width fields also make the binary parsers testable on Linux.
class WinGUID(ctypes.Structure):
    _fields_ = [
        ("data1", ctypes.c_uint32),
        ("data2", ctypes.c_uint16),
        ("data3", ctypes.c_uint16),
        ("data4", ctypes.c_ubyte * 8),
    ]

    @classmethod
    def from_text(cls, value):
        return cls.from_buffer_copy(uuid.UUID(value.strip("{}")).bytes_le)

    def text(self):
        return str(uuid.UUID(bytes_le=bytes(self)))


class WinInterface(ctypes.Structure):
    _fields_ = [
        ("guid", WinGUID),
        ("description", ctypes.c_uint16 * 256),
        ("state", ctypes.c_uint32),
    ]


class WinSSID(ctypes.Structure):
    _fields_ = [("length", ctypes.c_uint32), ("data", ctypes.c_ubyte * 32)]


class WinRateSet(ctypes.Structure):
    _fields_ = [("length", ctypes.c_uint32), ("rates", ctypes.c_uint16 * 126)]


class WinBssEntry(ctypes.Structure):
    _fields_ = [
        ("ssid", WinSSID),
        ("phy_id", ctypes.c_uint32),
        ("bssid", ctypes.c_ubyte * 6),
        ("bss_type", ctypes.c_uint32),
        ("phy_type", ctypes.c_uint32),
        ("rssi", ctypes.c_int32),
        ("quality", ctypes.c_uint32),
        ("in_reg_domain", ctypes.c_ubyte),
        ("beacon_period", ctypes.c_uint16),
        ("timestamp", ctypes.c_uint64),
        ("host_timestamp", ctypes.c_uint64),
        ("capability", ctypes.c_uint16),
        ("frequency_khz", ctypes.c_uint32),
        ("rates", WinRateSet),
        ("ie_offset", ctypes.c_uint32),
        ("ie_size", ctypes.c_uint32),
    ]


class WinNotification(ctypes.Structure):
    _fields_ = [
        ("source", ctypes.c_uint32),
        ("code", ctypes.c_uint32),
        ("guid", WinGUID),
        ("size", ctypes.c_uint32),
        ("data", ctypes.c_void_p),
    ]


class WinConnectionParameters(ctypes.Structure):
    _fields_ = [
        ("mode", ctypes.c_uint32),
        ("profile", ctypes.c_wchar_p),
        ("ssid", ctypes.c_void_p),
        ("bssids", ctypes.c_void_p),
        ("bss_type", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
    ]


def windows_wlan_error(code, operation):
    if code == 5:
        detail = (
            "Access denied: enable Location access in Settings > "
            "Privacy & security > Location for this application/terminal."
        )
    elif code == 1062:
        detail = "Start the WLAN AutoConfig service (WlanSvc)."
    elif code == 5023:
        detail = (
            "The interface is unavailable in this mode; check the radio, driver, and monitor mode."
        )
    else:
        detail = "Check the adapter, Wi-Fi radio, and its driver."
    return RuntimeError(f"{operation}: Windows error {code}. {detail}")


def parse_windows_interfaces(data):
    if len(data) < 8:
        raise ValueError("Truncated WLAN interface list")
    count = int.from_bytes(data[:4], "little")
    size = ctypes.sizeof(WinInterface)
    if count > 1024 or 8 + count * size > len(data):
        raise ValueError("Invalid WLAN interface list size")
    result = []
    for offset in range(8, 8 + count * size, size):
        item = WinInterface.from_buffer_copy(data, offset)
        guid = item.guid.text()
        result.append(
            {
                "name": guid,
                "guid": guid,
                "display_name": bytes(item.description)
                .decode("utf-16-le", errors="replace")
                .split("\0")[0],
                "capture_name": "\\Device\\NPF_{" + guid.upper() + "}",
                "backend": "windows",
                "mode": "managed",
                "phy": None,
                "driver": "Windows Native Wi-Fi",
                "connected": item.state not in {0, 4},
                "connection_state": item.state,
                "channel": None,
                "frequency_mhz": None,
                "capabilities": [],
                "frequencies": [],
            }
        )
    return result


def information_element_security(ap, raw, capability):
    """Decode discovery evidence only; WPS vulnerability decisions stay in upstream."""
    labels = []
    offset = 0
    warnings = []
    while offset < len(raw):
        if offset + 2 > len(raw):
            warnings.append("Truncated IE header")
            break
        element, size = raw[offset : offset + 2]
        offset += 2
        if offset + size > len(raw):
            warnings.append("Truncated IE contents")
            break
        body = raw[offset : offset + size]
        offset += size
        if element == 48:
            try:
                labels.extend(security_from_akms(rsn_akms(body)))
            except ValueError:
                labels.append("RSN (AKM unknown)")
        elif element == 221 and body.startswith(b"\x00\x50\xf2\x01"):
            labels.append("WPA")
        elif element == 221 and body.startswith(b"\x00\x50\xf2\x04"):
            ap["wps"] = "Detected"
            ap["wps_indicators"].append("WPS IE / Windows Native Wi-Fi")
            pos = 4
            while pos + 4 <= len(body):
                key = int.from_bytes(body[pos : pos + 2], "big")
                length = int.from_bytes(body[pos + 2 : pos + 4], "big")
                pos += 4
                if pos + length > len(body):
                    warnings.append("Truncated WPS attribute")
                    break
                value = body[pos : pos + length]
                pos += length
                if key == 0x1021:
                    ap["manufacturer_evidence"].append(
                        {
                            "source": "WPS IE / Windows Native Wi-Fi",
                            "value": value.rstrip(b"\0").decode("utf-8", errors="replace"),
                        }
                    )
                elif key in {0x1044, 0x1057}:
                    ap["wps_indicators"].append(
                        f"{'WPS state' if key == 0x1044 else 'AP setup locked'}: {value.hex()}"
                    )
    ap["security"] = (
        "/".join(dict.fromkeys(labels))
        if labels
        else ("Unknown" if warnings else "WEP/Unknown" if capability & 0x10 else "OPEN")
    )
    if warnings:
        ap["discovery_warnings"] = warnings


def parse_windows_bss(data):
    if len(data) < 8:
        raise ValueError("Truncated BSS list")
    total = int.from_bytes(data[:4], "little")
    count = int.from_bytes(data[4:8], "little")
    size = ctypes.sizeof(WinBssEntry)
    entries_end = 8 + count * size
    if total != len(data) or entries_end > total:
        raise ValueError("Invalid BSS size")
    aps = []
    for offset in range(8, entries_end, size):
        item = WinBssEntry.from_buffer_copy(data, offset)
        if item.ssid.length > 32:
            raise ValueError("SSID longer than 32 bytes in BSS")
        start = offset + item.ie_offset
        end = start + item.ie_size
        if item.ie_size and (start < entries_end or end > total):
            raise ValueError("IE outside the BSS buffer")
        ssid = bytes(item.ssid.data[: item.ssid.length])
        ap = new_ap(
            bytes(item.bssid).hex(":"),
            ssid.decode("utf-8", errors="replace"),
            "Windows Native Wi-Fi",
        )
        ap.update(
            ssid_hex=ssid.hex(),
            frequency_mhz=item.frequency_khz // 1000,
            signal_dbm=item.rssi,
            signal_percent=item.quality,
            in_reg_domain=bool(item.in_reg_domain),
            seen_at_windows_ticks=item.host_timestamp,
        )
        ap["channel"] = frequency_channel(ap["frequency_mhz"])
        raw = data[start:end] if item.ie_size else b""
        ap["information_elements_hex"] = raw.hex()
        information_element_security(ap, raw, item.capability)
        aps.append(ap)
    return stable_ap_ids(aps)


class WindowsWlan:
    """Minimal Native Wi-Fi client. No locale-dependent netsh parsing or mode changes."""

    def __enter__(self):
        if sys.platform != "win32":
            raise RuntimeError("Native Wi-Fi requires Windows")
        self.dll = ctypes.WinDLL("wlanapi.dll", winmode=0x800)
        ptr = ctypes.c_void_p
        uint = ctypes.c_uint32
        signatures = {
            "WlanOpenHandle": [uint, ptr, ctypes.POINTER(uint), ctypes.POINTER(ptr)],
            "WlanCloseHandle": [ptr, ptr],
            "WlanEnumInterfaces": [ptr, ptr, ctypes.POINTER(ptr)],
            "WlanQueryInterface": [
                ptr,
                ctypes.POINTER(WinGUID),
                uint,
                ptr,
                ctypes.POINTER(uint),
                ctypes.POINTER(ptr),
                ctypes.POINTER(uint),
            ],
            "WlanConnect": [
                ptr,
                ctypes.POINTER(WinGUID),
                ctypes.POINTER(WinConnectionParameters),
                ptr,
            ],
            "WlanGetNetworkBssList": [
                ptr,
                ctypes.POINTER(WinGUID),
                ptr,
                uint,
                ctypes.c_int32,
                ptr,
                ctypes.POINTER(ptr),
            ],
            "WlanScan": [ptr, ctypes.POINTER(WinGUID), ptr, ptr, ptr],
            "WlanRegisterNotification": [
                ptr,
                uint,
                ctypes.c_int32,
                ptr,
                ptr,
                ptr,
                ctypes.POINTER(uint),
            ],
            "WlanFreeMemory": [ptr],
        }
        for name, arguments in signatures.items():
            function = getattr(self.dll, name)
            function.argtypes = arguments
            function.restype = None if name == "WlanFreeMemory" else uint
        self.handle = ptr()
        version = uint()
        self.check(
            self.dll.WlanOpenHandle(2, None, ctypes.byref(version), ctypes.byref(self.handle)),
            "WlanOpenHandle",
        )
        return self

    @staticmethod
    def check(code, operation):
        if code:
            raise windows_wlan_error(code, operation)

    def __exit__(self, *args):
        self.dll.WlanCloseHandle(self.handle, None)
        self._scan_callback = None

    def connected_profile(self, guid, ssid_only=False):
        """Read only the profile name/state, never profile XML or credentials."""
        native_guid = WinGUID.from_text(guid)
        ptr, size, kind = ctypes.c_void_p(), ctypes.c_uint32(), ctypes.c_uint32()
        code = self.dll.WlanQueryInterface(
            self.handle,
            ctypes.byref(native_guid),
            7,
            None,
            ctypes.byref(size),
            ctypes.byref(ptr),
            ctypes.byref(kind),
        )
        if code == 5023:  # Not connected / invalid state.
            return None
        self.check(code, "WlanQueryInterface/current_connection")
        try:
            required = 556 if ssid_only else 520
            if not ptr.value or size.value < required:
                raise ValueError("Truncated WLAN connection data")
            header = ctypes.string_at(ptr, required)
            if int.from_bytes(header[:4], "little") != 1:
                return None
            if ssid_only:
                length = int.from_bytes(header[520:524], "little")
                if not 1 <= length <= 32:
                    raise ValueError("Invalid connection SSID")
                return header[524 : 524 + length].decode("utf-8")
            profile = header[8:520].decode("utf-16-le").split("\0")[0]
            if not profile:
                raise RuntimeError(
                    "The current connection has no saved profile that can be restored."
                )
            return profile
        finally:
            self.dll.WlanFreeMemory(ptr)

    def connect_profile(self, guid, profile, timeout=15):
        native_guid = WinGUID.from_text(guid)
        parameters = WinConnectionParameters(mode=0, profile=profile, bss_type=3)
        self.check(
            self.dll.WlanConnect(
                self.handle, ctypes.byref(native_guid), ctypes.byref(parameters), None
            ),
            "WlanConnect/restore connection",
        )
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.connected_profile(guid) == profile:
                return
            time.sleep(0.25)
        raise RuntimeError("Windows did not confirm reconnection to the previous profile.")

    def interfaces(self):
        ptr = ctypes.c_void_p()
        self.check(
            self.dll.WlanEnumInterfaces(self.handle, None, ctypes.byref(ptr)), "WlanEnumInterfaces"
        )
        try:
            if not ptr.value:
                raise RuntimeError("WlanEnumInterfaces returned an empty buffer")
            count = ctypes.c_uint32.from_address(ptr.value).value
            if count > 1024:
                raise ValueError("Too many WLAN interfaces")
            return parse_windows_interfaces(
                ctypes.string_at(ptr, 8 + count * ctypes.sizeof(WinInterface))
            )
        finally:
            self.dll.WlanFreeMemory(ptr)

    def scan(self, guid_text, timeout=15):
        guid = WinGUID.from_text(guid_text)
        done = threading.Event()
        outcome = []
        callback_type = ctypes.WINFUNCTYPE(None, ctypes.POINTER(WinNotification), ctypes.c_void_p)

        def notified(pointer, _context):
            notice = pointer.contents
            if notice.source & 8 and bytes(notice.guid) == bytes(guid) and notice.code in {7, 8}:
                outcome.append(notice.code)
                done.set()

        callback = callback_type(notified)
        self._scan_callback = callback
        self.check(
            self.dll.WlanRegisterNotification(self.handle, 8, False, callback, None, None, None),
            "WlanRegisterNotification",
        )
        try:
            self.check(
                self.dll.WlanScan(self.handle, ctypes.byref(guid), None, None, None), "WlanScan"
            )
            if not done.wait(timeout):
                return "Windows did not confirm a refresh within 15 seconds; results may be cached."
            if outcome[-1] == 8:
                return "Windows reported a refresh failure; retaining the available BSS cache."
            return None
        finally:
            # Unregister outside the callback; keep it alive until callbacks have finished.
            self.dll.WlanRegisterNotification(self.handle, 0, False, None, None, None, None)

    def bss(self, guid_text):
        guid = WinGUID.from_text(guid_text)
        ptr = ctypes.c_void_p()
        self.check(
            self.dll.WlanGetNetworkBssList(
                self.handle, ctypes.byref(guid), None, 3, False, None, ctypes.byref(ptr)
            ),
            "WlanGetNetworkBssList",
        )
        try:
            if not ptr.value:
                raise RuntimeError("WlanGetNetworkBssList returned an empty buffer")
            size = ctypes.c_uint32.from_address(ptr.value).value
            if not 8 <= size <= 64 * 1024 * 1024:
                raise ValueError("Invalid BSS buffer size")
            return ctypes.string_at(ptr, size)
        finally:
            self.dll.WlanFreeMemory(ptr)


def wlan_helper_path():
    root = os.environ.get("SystemRoot", r"C:\Windows")
    candidate = Path(root) / "System32" / "Npcap" / "WlanHelper.exe"
    return str(candidate) if candidate.is_file() else None


def wlan_helper(guid, setting, value=None):
    path = wlan_helper_path()
    if not path:
        raise RuntimeError(
            "Install Npcap with Support raw 802.11 traffic (and monitor mode); WlanHelper.exe is missing."
        )
    guid = str(uuid.UUID(guid.strip("{}")))
    if setting not in {"mode", "modes", "channel", "freq"}:
        raise ValueError("Unsupported WlanHelper operation")
    command = [path, guid, setting]
    if value is not None:
        if setting == "mode" and value in {"managed", "monitor"}:
            command.append(value)
        elif setting in {"channel", "freq"}:
            number = int(value)
            if not (1 <= number <= 14 if setting == "channel" else 2300 <= number <= 7125):
                raise ValueError("WlanHelper channel/frequency out of range")
            command.append(str(number))
        else:
            raise ValueError("Unsupported WlanHelper operation")
    result = run_quiet(command, timeout=10)
    if result is None or result.returncode:
        detail = (result.stdout or "").strip() if result is not None else "timeout"
        raise RuntimeError(
            f"WlanHelper {setting}: {safe_text(detail)}. Check permissions and the driver."
        )
    return result.stdout.strip()


def detect_windows_interfaces():
    with WindowsWlan() as wlan:
        interfaces = wlan.interfaces()
        for iface in interfaces:
            if iface.get("connected"):
                try:
                    iface["connected_ssid"] = wlan.connected_profile(iface["guid"], ssid_only=True)
                except (RuntimeError, ValueError, UnicodeError) as error:
                    iface["connection_note"] = str(error)
    for iface in interfaces:
        if not wlan_helper_path():
            iface["monitor_note"] = (
                "Npcap/WlanHelper is not installed; native discovery is available."
            )
            continue
        try:
            mode = wlan_helper(iface["guid"], "mode").casefold()
            iface["mode"] = mode if mode in {"monitor", "managed"} else "unknown"
            iface["capabilities"] = [
                m.strip().casefold() for m in wlan_helper(iface["guid"], "modes").split(",")
            ]
            if mode == "monitor":
                channel = wlan_helper(iface["guid"], "channel")
                if channel.isdigit():
                    iface["channel"] = int(channel)
        except RuntimeError as error:
            iface["monitor_note"] = str(error)
    return interfaces


def discover_windows_wifi(iface, folder, limitations):
    if iface["mode"] == "monitor":
        raise RuntimeError(
            "Use a managed interface for Windows discovery; monitor mode is selected later for the WPS test."
        )
    with WindowsWlan() as wlan, Spinner("Wi-Fi / Windows Native Wi-Fi"):
        warning = wlan.scan(iface["guid"])
        if warning:
            limitations.append(warning)
        data = wlan.bss(iface["guid"])
    (folder / "windows_bss.bin").write_bytes(data)
    aps = parse_windows_bss(data)
    dump_json(folder / "windows_discovery.json", aps)
    limitations.append(
        "BSS/IE data from the Windows driver, not a PCAP capture. The API may use cached data."
    )
    return aps


def parse_iw_interfaces(output):
    interfaces = []
    phy = None
    current = None
    for line in output.splitlines():
        match = re.match(r"\s*phy#(\d+)", line)
        if match:
            phy = "phy" + match.group(1)
            current = None
        if "Unnamed/non-netdev interface" in line:
            current = None
        match = re.match(r"\s*Interface\s+(\S+)", line)
        if match:
            current = {
                "name": match.group(1),
                "phy": phy,
                "mode": "unknown",
                "channel": None,
                "frequency_mhz": None,
                "capabilities": [],
                "frequencies": [],
            }
            interfaces.append(current)
        if current:
            match = re.match(r"\s*type\s+(\S+)", line)
            if match:
                current["mode"] = match.group(1)
            match = re.match(r"\s*channel\s+(\d+)\s+\((\d+) MHz\)", line)
            if match:
                current["channel"] = int(match.group(1))
                current["frequency_mhz"] = int(match.group(2))
    return interfaces


def parse_phy(output):
    modes = []
    frequencies = []
    in_modes = False
    for line in output.splitlines():
        if "Supported interface modes:" in line:
            in_modes = True
            continue
        if in_modes:
            match = re.match(r"\s*\*\s+(.+)", line)
            if match:
                modes.append(match.group(1).strip())
            else:
                in_modes = False
        match = re.search(r"\*\s+(\d+) MHz\s+\[(\d+)\](.*)", line)
        if match:
            flags = match.group(3).lower()
            frequencies.append(
                {
                    "frequency_mhz": int(match.group(1)),
                    "channel": int(match.group(2)),
                    "disabled": "disabled" in flags,
                    "no_ir": "no ir" in flags or "no-ir" in flags or "passive scan" in flags,
                    "radar": "radar" in flags,
                }
            )
    return modes, frequencies


def detect_wireless_interfaces():
    if sys.platform == "win32":
        return detect_windows_interfaces()
    require_tools("iw")
    result = run_quiet(["iw", "dev"], timeout=10)
    if result is None or result.returncode:
        raise RuntimeError("iw cannot query interfaces; check permissions, the driver, and rfkill.")
    interfaces = parse_iw_interfaces(result.stdout)
    phys = {}
    for iface in interfaces:
        phy = iface["phy"]
        if phy not in phys:
            result = run_quiet(["iw", "phy", phy, "info"], timeout=10) if phy else None
            phys[phy] = parse_phy(result.stdout) if result and result.returncode == 0 else ([], [])
        iface["capabilities"], iface["frequencies"] = phys[phy]
        driver = Path("/sys/class/net") / iface["name"] / "device" / "driver"
        iface["driver"] = driver.resolve().name if driver.exists() else "Unknown"
        link = run_quiet(["iw", "dev", iface["name"], "link"], timeout=10)
        iface["connected"] = bool(link and link.returncode == 0 and "Connected to " in link.stdout)
        iface["backend"] = "linux"
        if iface["connected"]:
            ssid = re.search(r"^\s*SSID: (.*)$", link.stdout, re.M)
            if ssid:
                iface["connected_ssid"] = decode_iw_ssid(ssid.group(1))
    return interfaces


def decode_iw_ssid(value):
    chunks = re.findall(r"\\x[0-9a-fA-F]{2}|.", value)
    return b"".join(
        bytes.fromhex(c[2:]) if re.fullmatch(r"\\x[0-9a-fA-F]{2}", c) else c.encode("utf-8")
        for c in chunks
    ).decode("utf-8", errors="replace")


def require_isolated_monitor(iface, interfaces):
    if iface["mode"] != "monitor":
        raise RuntimeError("Select an interface already in monitor mode; see the README.")
    if not iface.get("phy"):
        raise RuntimeError("Unknown PHY; unable to check whether the radio is shared.")
    siblings = [
        i["name"] for i in interfaces if i["phy"] == iface["phy"] and i["name"] != iface["name"]
    ]
    if siblings:
        raise RuntimeError(
            "The radio is shared with "
            + ", ".join(siblings)
            + ". Use a dedicated adapter to avoid disrupting other connections."
        )


def linux_radio_candidate(interfaces, preferred, ap=None):
    candidates = []
    for iface in interfaces:
        if iface.get("mode") not in {"managed", "monitor"} or "monitor" not in iface.get(
            "capabilities", []
        ):
            continue
        try:
            require_isolated_monitor(dict(iface, mode="monitor"), interfaces)
            if ap is not None:
                validate_linux_target(ap, iface)
        except (RuntimeError, ValueError):
            continue
        candidates.append(iface)
    if not candidates:
        raise RuntimeError(
            "No dedicated Linux radio supports monitor mode on the permitted target channel. Check iw phy, regulatory restrictions, and the driver."
        )
    return min(
        candidates, key=lambda i: (i.get("connected", False), i["name"] != preferred["name"])
    )


def linux_command(arguments, timeout=20):
    result = run_quiet(arguments, timeout=timeout)
    if result is None or result.returncode:
        detail = (result.stderr or result.stdout).strip() if result is not None else "timeout"
        raise RuntimeError(f"{arguments[0]}: {safe_text(detail)}")
    return result.stdout.strip()


def linux_nm_state(name):
    result = run_quiet(
        ["nmcli", "-g", "GENERAL.NM-MANAGED,GENERAL.CON-UUID", "device", "show", name], timeout=10
    )
    if result is None or result.returncode:
        return None, None
    fields = result.stdout.splitlines()
    if not fields or fields[0] not in {"yes", "no"}:
        raise RuntimeError("NetworkManager returned an unrecognized state.")
    connection = fields[1].strip() if len(fields) > 1 else ""
    connection = str(uuid.UUID(connection)) if connection not in {"", "--"} else None
    return fields[0] == "yes", connection


def validate_linux_target(ap, iface):
    if not MAC.fullmatch(ap["bssid"]):
        raise ValueError("Invalid BSSID")
    if not ap["ssid"] or len(ap["ssid"].encode("utf-8")) > 32:
        raise ValueError("Hidden/invalid SSID; the exact SSID is required")
    frequency = ap.get("frequency_mhz")
    if (
        frequency is None
        or frequency >= 5925
        or not ap.get("channel")
        or frequency_channel(frequency) != ap["channel"]
    ):
        raise RuntimeError(
            "The detector requires a matching channel/frequency in 2.4/5 GHz; 6 GHz is unsupported."
        )
    supported = next((f for f in iface["frequencies"] if f["frequency_mhz"] == frequency), None)
    if not supported or supported["disabled"] or supported["no_ir"] or supported["radar"]:
        raise RuntimeError(
            "This channel does not permit active testing under the current capabilities/regulations (disabled/no IR/DFS)."
        )


@contextmanager
def prepared_linux_monitor(ap, iface, interfaces, folder, state):
    require_linux(root=True)
    require_tools("iw", "ip", "nmcli")
    validate_linux_target(ap, iface)
    require_isolated_monitor(dict(iface, mode="monitor"), interfaces)
    if iface["mode"] not in {"managed", "monitor"}:
        raise RuntimeError("The original interface mode does not support automatic restoration.")
    name = iface["name"]
    links = json.loads(linux_command(["ip", "-json", "link", "show", "dev", name]))
    if len(links) != 1 or links[0].get("ifname") != name:
        raise RuntimeError("Unable to save the original adapter state.")
    was_up = "UP" in links[0].get("flags", [])
    managed, connection = linux_nm_state(name)
    if iface.get("connected") and (not managed or not connection):
        raise RuntimeError(
            "NetworkManager does not control this radio connection; automatic restoration is unavailable."
        )
    if iface["mode"] == "monitor" and not iface.get("frequency_mhz"):
        raise RuntimeError("The original monitor frequency is unknown and cannot be restored.")
    state.update(
        interface=name,
        original_mode=iface["mode"],
        original_frequency=iface.get("frequency_mhz"),
        original_up=was_up,
        nm_managed=managed,
        connection_uuid=connection,
        restored=None,
    )
    dump_json(folder / "radio_setup.json", state)
    nm_changed = radio_changed = False
    try:
        if managed:
            nm_changed = True
            linux_command(["nmcli", "device", "set", name, "managed", "no"])
        radio_changed = True
        linux_command(["ip", "link", "set", "dev", name, "down"])
        if iface["mode"] == "managed":
            linux_command(["iw", "dev", name, "set", "monitor", "otherbss", "control"])
        linux_command(["ip", "link", "set", "dev", name, "up"])
        set_frequency(name, ap["frequency_mhz"])
        live = detect_wireless_interfaces()
        ready = next((i for i in live if i["name"] == name and i["phy"] == iface["phy"]), None)
        if (
            ready is None
            or ready["mode"] != "monitor"
            or ready["frequency_mhz"] != ap["frequency_mhz"]
        ):
            raise RuntimeError("The driver did not confirm monitor mode and frequency after setup.")
        require_isolated_monitor(ready, live)
        state["prepared"] = True
        dump_json(folder / "radio_setup.json", state)
        yield ready, live
    finally:
        errors = []

        def restore(action):
            try:
                action()
            except (Exception, KeyboardInterrupt) as error:
                errors.append(str(error) or "Restoration interrupted")

        if radio_changed:
            restore(lambda: linux_command(["ip", "link", "set", "dev", name, "down"]))
            restore(lambda: linux_command(["iw", "dev", name, "set", "type", iface["mode"]]))
            if was_up:
                restore(lambda: linux_command(["ip", "link", "set", "dev", name, "up"]))
            if iface["mode"] == "monitor":
                restore(lambda: set_frequency(name, iface["frequency_mhz"]))
        if nm_changed:
            restore(lambda: linux_command(["nmcli", "device", "set", name, "managed", "yes"]))
            if connection:
                restore(
                    lambda: linux_command(
                        [
                            "nmcli",
                            "--wait",
                            "20",
                            "connection",
                            "up",
                            "uuid",
                            connection,
                            "ifname",
                            name,
                        ],
                        timeout=25,
                    )
                )
                if not errors:
                    restore(lambda: verify_linux_connection(name, connection))
        if radio_changed and not errors:
            restore(
                lambda: verify_linux_radio(
                    name,
                    iface["mode"],
                    was_up,
                    iface.get("frequency_mhz") if iface["mode"] == "monitor" else None,
                )
            )
        state["restored"] = not errors
        if errors:
            state["restore_error"] = "; ".join(errors)
        dump_json(folder / "radio_setup.json", state)


def verify_linux_connection(name, connection):
    managed, active = linux_nm_state(name)
    if not managed or active != connection:
        raise RuntimeError("NetworkManager did not confirm restoration of the original connection.")


def verify_linux_radio(name, mode, was_up, frequency=None):
    current = next((i for i in detect_wireless_interfaces() if i["name"] == name), None)
    link = json.loads(linux_command(["ip", "-json", "link", "show", "dev", name]))
    if (
        current is None
        or current["mode"] != mode
        or len(link) != 1
        or ("UP" in link[0].get("flags", [])) != was_up
        or (frequency is not None and current["frequency_mhz"] != frequency)
    ):
        raise RuntimeError("Linux did not confirm restoration of the original adapter mode/state.")


def frequency_channel(frequency):
    if frequency == 2484:
        return 14
    if 2412 <= frequency <= 2472:
        return (frequency - 2407) // 5
    if frequency == 5935:
        return 2
    if 5955 <= frequency <= 7115:
        return (frequency - 5950) // 5
    if 5000 <= frequency <= 5895:
        return (frequency - 5000) // 5
    return None


def new_ap(bssid, ssid="", backend="iw"):
    return {
        "ssid": ssid,
        "bssid": bssid.lower(),
        "channel": None,
        "frequency_mhz": None,
        "security": "Unknown",
        "wps": "Unknown",
        "wps_indicators": [],
        "signal_dbm": None,
        "signal_percent": None,
        "manufacturer_evidence": [],
        "backend": backend,
        "assessment": "NOT_TESTED",
    }


def security_from_akms(akms):
    labels = []
    if any(k in {2, 4, 6} for k in akms):
        labels.append("WPA2-PSK")
    if any(k in {1, 3, 5} for k in akms):
        labels.append("WPA2-EAP")
    if any(k in {8, 9, 24, 25} for k in akms):
        labels.append("WPA3-SAE")
    if any(k in {11, 12, 13} for k in akms):
        labels.append("WPA3-EAP")
    if 18 in akms:
        labels.append("OWE")
    known = {1, 2, 3, 4, 5, 6, 8, 9, 11, 12, 13, 18, 24, 25}
    if not labels or any(k not in known for k in akms):
        labels.append("RSN (AKM unknown)")
    return labels


def iw_security(block):
    labels = []
    if re.search(r"^\s*WPA:\s*", block, re.M):
        labels.append("WPA")
    # Read AKM suites from the RSN section only, preserving mixed modes.
    if re.search(r"^\s*RSN:", block, re.M):
        tail = block.split("RSN:", 1)[1]
        match = re.search(r"Authentication suites:\s*([^\n]+)", tail)
        suites = match.group(1).upper() if match else ""
        if re.search(r"\b(?:FT/)?PSK\b", suites):
            labels.append("WPA2-PSK")
        if "SAE" in suites:
            labels.append("WPA3-SAE")
        if "SUITE-B" in suites or "SUITE B" in suites:
            labels.append("WPA3-EAP")
        elif "802.1X" in suites or "802.1X" in suites.replace("/", ""):
            labels.append("WPA2-EAP")
        if "OWE" in suites:
            labels.append("OWE")
        if not suites or not any(
            t in suites for t in ("PSK", "SAE", "802.1X", "OWE", "SUITE-B", "SUITE B")
        ):
            labels.append("RSN (AKM unknown)")
    if labels:
        return "/".join(dict.fromkeys(labels))
    capability = re.search(r"^\s*capability:\s*([^\n]+)", block, re.M)
    if not capability:
        return "Unknown"
    return "WEP/Unknown" if "Privacy" in capability.group(1) else "OPEN"


def parse_iw_scan(output):
    access_points = []
    for block in re.split(r"(?=^BSS [0-9a-fA-F:]{17})", output, flags=re.M):
        match = re.match(r"BSS ([0-9a-fA-F:]{17})", block)
        if not match or not MAC.fullmatch(match.group(1)):
            continue
        ap = new_ap(match.group(1))
        ssid = re.search(r"^\s*SSID: ?(.*)$", block, re.M)
        ap["ssid"] = ssid.group(1) if ssid else ""
        # iw uses C-style hexadecimal escapes for non-printable SSID bytes.
        chunks = re.split(r"(\\x[0-9a-fA-F]{2})", ap["ssid"])
        ap["ssid"] = b"".join(
            bytes.fromhex(c[2:]) if re.fullmatch(r"\\x[0-9a-fA-F]{2}", c) else c.encode("utf-8")
            for c in chunks
        ).decode("utf-8", errors="replace")
        frequency = re.search(r"^\s*freq:\s*(\d+)", block, re.M)
        if frequency:
            ap["frequency_mhz"] = int(frequency.group(1))
            ap["channel"] = frequency_channel(ap["frequency_mhz"])
        channel = re.search(r"(?:DS Parameter set: channel|primary channel:)\s*(\d+)", block)
        if ap["channel"] is None and channel:
            ap["channel"] = int(channel.group(1))
        signal_match = re.search(r"^\s*signal:\s*(-?[\d.]+)\s*dBm", block, re.M)
        if signal_match:
            ap["signal_dbm"] = float(signal_match.group(1))
        ap["security"] = iw_security(block)
        if re.search(r"^\s*WPS:", block, re.M):
            ap["wps"] = "Detected"
            ap["wps_indicators"] = [
                line.strip()
                for line in block.splitlines()
                if re.search(
                    r"WPS:|WPS state:|AP setup locked:|Device name:|Model:|Manufacturer:", line
                )
            ]
            vendor = re.search(r"^\s*\*?\s*Manufacturer:\s*(.*)", block, re.M)
            if vendor:
                ap["manufacturer_evidence"].append(
                    {"source": "WPS IE / iw", "value": vendor.group(1)}
                )
        access_points.append(ap)
    return stable_ap_ids(access_points)


def split_nmcli(line):
    fields = []
    field = []
    escaped = False
    for char in line:
        if escaped:
            field.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == ":":
            fields.append("".join(field))
            field = []
        else:
            field.append(char)
    if escaped:
        field.append("\\")
    fields.append("".join(field))
    return fields


def parse_nmcli(output):
    aps = []
    for line in output.splitlines():
        fields = split_nmcli(line)
        if len(fields) != 6:
            continue
        ssid, bssid, channel, frequency, security, level = fields
        if not MAC.fullmatch(bssid):
            continue
        ap = new_ap(bssid, ssid, "nmcli")
        ap["channel"] = int(channel) if channel.isdigit() else None
        match = re.match(r"(\d+)", frequency)
        if match:
            ap["frequency_mhz"] = int(match.group(1))
        ap["signal_percent"] = int(level) if level.isdigit() and 0 <= int(level) <= 100 else None
        ap["security"] = security.strip() or "OPEN"
        if security.strip() == "--":
            ap["security"] = "OPEN"
        aps.append(ap)
    return stable_ap_ids(aps)


def stable_ap_ids(aps):
    merged = {}
    for ap in aps:
        key = ap["bssid"].lower()
        if key not in merged:
            merged[key] = ap
        else:
            previous = merged[key]
            for name, value in ap.items():
                if isinstance(value, list):
                    previous[name] = previous.get(name, []) + [
                        v for v in value if v not in previous.get(name, [])
                    ]
                elif value is not None and value not in ("", "Unknown", "NOT_TESTED"):
                    previous[name] = value
    result = [merged[key] for key in sorted(merged)]
    for index, ap in enumerate(result, 1):
        ap["id"] = index
    return result


def load_upstream():
    """Import only the pinned, byte-for-byte original detector, never its CLI."""
    manifest = json.loads((VENDOR / "UPSTREAM.json").read_text(encoding="utf-8"))
    path = VENDOR / "broadcom_fingerprint.py"
    if (
        manifest.get("commit") != UPSTREAM_COMMIT
        or hashlib.sha256(path.read_bytes()).hexdigest()
        != manifest["files"]["broadcom_fingerprint.py"]
    ):
        raise RuntimeError(
            "The detector copy does not match the pinned commit. Restore vendor/broadcom-wps."
        )
    name = "_polterheist_upstream"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except ImportError as error:
        sys.modules.pop(name, None)
        raise RuntimeError(
            "Install Scapy in this interpreter: python -m pip install -r requirements.txt"
        ) from error
    return module


def rsn_akms(body):
    if len(body) < 8:
        raise ValueError("Truncated RSN")
    count = int.from_bytes(body[6:8], "little")
    offset = 8 + 4 * count
    if offset + 2 > len(body):
        raise ValueError("RSN without AKM")
    count = int.from_bytes(body[offset : offset + 2], "little")
    offset += 2
    if offset + 4 * count > len(body):
        raise ValueError("Truncated AKM")
    return [
        body[i + 3] if body[i : i + 3] == b"\x00\x0f\xac" else -1
        for i in range(offset, offset + 4 * count, 4)
    ]


def packet_ap(packet, upstream, frequency=None):
    observed = upstream.parse_advertisement(
        packet, channel_hint=frequency_channel(frequency) if frequency else 0
    )
    if observed is None:
        return None
    ap = new_ap(observed.bssid, observed.ssid, "tcpdump/Scapy")
    ap["channel"] = observed.channel or None
    try:
        radiotap = packet[upstream.RadioTap]
        ap["frequency_mhz"] = (
            int(radiotap.ChannelFrequency) if radiotap.ChannelFrequency else frequency
        )
        ap["signal_dbm"] = (
            int(radiotap.dBm_AntSignal) if radiotap.dBm_AntSignal is not None else None
        )
    except (AttributeError, IndexError, TypeError, ValueError):
        ap["frequency_mhz"] = frequency
    if ap["frequency_mhz"]:
        ap["channel"] = frequency_channel(ap["frequency_mhz"])
    labels = []
    if observed.wpa is not None:
        labels.append("WPA")
    if observed.rsn is not None:
        try:
            labels.extend(security_from_akms(rsn_akms(observed.rsn)))
        except ValueError:
            labels.append("RSN (AKM unknown)")
    if labels:
        ap["security"] = "/".join(labels)
    else:
        capability = getattr(packet[upstream.Dot11].payload, "cap", None)
        if capability is not None:
            ap["security"] = "WEP/Unknown" if int(capability) & 0x10 else "OPEN"
    if observed.wps_advertised:
        ap["wps"] = "Detected"
        ap["wps_indicators"] = ["WPS vendor-specific IE"]
    if observed.vendor != "Unknown":
        ap["manufacturer_evidence"].append({"source": "WPS IE", "value": observed.vendor})
    return ap


def capture_beacons(interface, pcap_path, seconds=4):
    require_tools("tcpdump")
    cmd = [
        "tcpdump",
        "-i",
        interface,
        "-U",
        "-s",
        "0",
        "-w",
        str(pcap_path),
        "type mgt subtype beacon or type mgt subtype probe-resp",
    ]
    result = run_progress(
        cmd,
        "Passive 802.11 capture",
        pcap_path.with_suffix(".log"),
        timeout=seconds,
        stop_after_timeout=True,
    )
    if result.returncode:
        raise RuntimeError("tcpdump failed; check " + str(pcap_path.with_suffix(".log")))
    if not pcap_path.exists() or pcap_path.stat().st_size < 24:
        raise RuntimeError("tcpdump did not produce a valid PCAP; check the log and driver.")


def set_frequency(interface, frequency):
    result = run_quiet(["iw", "dev", interface, "set", "freq", str(frequency)], timeout=10)
    if result is None or result.returncode:
        detail = result.stderr.strip() if result else "timeout"
        raise RuntimeError(f"Unable to select {frequency} MHz: {detail}")


def monitor_discovery(iface, interfaces, folder, limitations):
    require_linux(root=True)
    require_isolated_monitor(iface, interfaces)
    upstream = load_upstream()
    from scapy.utils import PcapReader

    original = iface["frequency_mhz"]
    if not original:
        raise RuntimeError("Set an initial channel on the monitor interface; see the README.")
    frequencies = [f["frequency_mhz"] for f in iface["frequencies"] if not f["disabled"]]
    if not frequencies:
        frequencies = [original]
        limitations.append(
            "Unable to query the channel list: only the current channel was captured."
        )
    aps = []
    try:
        for frequency in dict.fromkeys(frequencies):
            try:
                set_frequency(iface["name"], frequency)
            except RuntimeError as error:
                limitations.append(str(error))
                continue
            pcap = folder / f"discovery_{frequency}MHz.pcap"
            capture_beacons(iface["name"], pcap)
            with PcapReader(str(pcap)) as reader:
                for packet in reader:
                    ap = packet_ap(packet, upstream, frequency)
                    if ap:
                        aps.append(ap)
            dump_json(folder / "discovery.json", stable_ap_ids(aps))
    finally:
        try:
            set_frequency(iface["name"], original)
        except RuntimeError as error:
            limitations.append("Frequency restoration failed: " + str(error))
    limitations.append(
        "Passive capture per channel; hidden SSIDs or APs without beacons during the capture window may be missing."
    )
    return stable_ap_ids(aps)


def discover_wifi(iface, interfaces, folder, limitations):
    if iface.get("backend") == "windows":
        return discover_windows_wifi(iface, folder, limitations)
    if iface["mode"] == "monitor":
        return monitor_discovery(iface, interfaces, folder, limitations)
    if iface["mode"] != "managed":
        raise RuntimeError("Discovery supports managed or monitor interfaces.")
    # Passive scan does not switch modes, disconnect or stop NetworkManager.
    result = None
    try:
        result = run_progress(
            ["iw", "dev", iface["name"], "scan", "passive"],
            "Wi-Fi / iw",
            folder / "iw_scan.log",
            timeout=40,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        limitations.append(str(error))
    if result and result.returncode == 0:
        return parse_iw_scan(result.stdout)
    limitations.append(
        "iw scan is unavailable; nmcli may return cached data and does not expose WPS or RSSI in dBm."
    )
    if not shutil.which("nmcli"):
        raise RuntimeError(
            "iw scan failed and nmcli is missing. Check iw_scan.log, permissions, and rfkill; install network-manager."
        )
    result = run_progress(
        [
            "nmcli",
            "--terse",
            "--escape",
            "yes",
            "--colors",
            "no",
            "--fields",
            "SSID,BSSID,CHAN,FREQ,SECURITY,SIGNAL",
            "device",
            "wifi",
            "list",
            "ifname",
            iface["name"],
            "--rescan",
            "auto",
        ],
        "Wi-Fi / NetworkManager",
        folder / "nmcli_scan.log",
        timeout=45,
    )
    if result.returncode:
        raise RuntimeError("nmcli failed; check nmcli_scan.log and NetworkManager status.")
    return parse_nmcli(result.stdout)


def terminal_control_available():
    if not sys.stdout.isatty() or os.environ.get("TERM") == "dumb":
        return False
    if sys.platform != "win32":
        return True
    kernel = ctypes.WinDLL("kernel32.dll", winmode=0x800)
    kernel.GetStdHandle.argtypes = [ctypes.c_uint32]
    kernel.GetStdHandle.restype = ctypes.c_void_p
    kernel.GetConsoleMode.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
    kernel.SetConsoleMode.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    handle, mode = kernel.GetStdHandle(0xFFFFFFF5), ctypes.c_uint32()
    return bool(
        kernel.GetConsoleMode(handle, ctypes.byref(mode))
        and kernel.SetConsoleMode(handle, mode.value | 4)
    )


def show_wifi(aps, title="WIRELESS RESULTS", refresh=False):
    if refresh and terminal_control_available():
        print("\033[2J\033[H", end="")
    print(tint("\nPOLTERHEIST :: " + title))
    rows = []
    for ap in aps:
        level = (
            f"{ap['signal_dbm']:g} dBm"
            if ap["signal_dbm"] is not None
            else f"{ap['signal_percent']}% (NM)"
            if ap["signal_percent"] is not None
            else "Unknown"
        )
        rows.append(
            [
                ap["id"],
                ap["ssid"] or "<oculto>",
                ap["bssid"],
                ap["channel"] or "?",
                ap["security"],
                ap["wps"],
                level,
                ap["assessment"],
            ]
        )
    table(
        ["ID", "SSID", "BSSID", "CHANNEL", "SECURITY", "WPS", "SIGNAL", "ASSESSMENT"],
        rows,
        [3, 24, 17, 7, 25, 8, 12, 27],
    )


def select_item(items, label, key="name", show_items=True):
    if not items:
        return None
    mapping = {str(item.get("id", index)): item for index, item in enumerate(items, 1)}
    if show_items:
        for number, item in mapping.items():
            label_value = item.get("display_name", item[key]) if key == "name" else item[key]
            print(f"  [{number}] {safe_text(label_value)}")
    while True:
        choice = input(f"  {label} (q to return): ").strip().lower()
        if choice == "q":
            return None
        if choice in mapping:
            return mapping[choice]
        print("  Invalid ID.")


def authorize_target(ap):
    print(
        f"  Target: SSID={safe_text(repr(ap['ssid']))} | BSSID={ap['bssid']} | channel={ap['channel']}"
    )
    print("  The detector will send an active WPS test to this BSSID only.")
    print("  Deauthentication cleanup is blocked; the session may wait for the AP timeout.")
    expected = "AUTHORIZE " + ap["bssid"]
    return (
        input(f"  Type {expected} if you have authorization (ENTER cancels): ").strip().casefold()
        == expected.casefold()
    )


def assessment_from_upstream(document, ap):
    if not isinstance(document, dict):
        return "ERROR"
    target = document.get("target", {})
    if (
        not isinstance(target, dict)
        or not isinstance(target.get("bssid"), str)
        or target["bssid"].lower() != ap["bssid"].lower()
        or target.get("ssid") != ap["ssid"]
    ):
        return "ERROR"
    assessment = document.get("assessment")
    if not isinstance(assessment, str):
        return "INCONCLUSIVE"
    if assessment in {
        "LIKELY_VULNERABLE",
        "PATCHED_HOSTAPD",
        "NO_BROADCOM_FINGERPRINT",
        "INCONCLUSIVE",
    }:
        return assessment
    return "INCONCLUSIVE"


def fingerprint_summary(target, classification, original=None, reason=None):
    """Explain the actual detector result; missing evidence is never a positive/negative."""
    labels = {
        "LIKELY_VULNERABLE": "LIKELY VULNERABLE",
        "PATCHED_HOSTAPD": "BROADCOM WITH HOSTAPD ACCORDING TO THE DETECTOR",
        "NO_BROADCOM_FINGERPRINT": "NO BROADCOM FINGERPRINT ACCORDING TO THE DETECTOR",
        "INCONCLUSIVE": "INCONCLUSIVE",
        "NOT_TESTED": "NOT TESTED",
        "ERROR": "ASSESSMENT ERROR",
    }
    evidence_error = None
    if classification not in labels:
        classification = "INCONCLUSIVE"
    if classification in {
        "LIKELY_VULNERABLE",
        "PATCHED_HOSTAPD",
        "NO_BROADCOM_FINGERPRINT",
        "INCONCLUSIVE",
    }:
        if original is not None:
            detected = assessment_from_upstream(original, target)
            if detected == "ERROR":
                evidence_error = "The detector result does not match the selected SSID/BSSID or has an invalid format."
            classification = detected
        elif classification != "INCONCLUSIVE":
            classification = "INCONCLUSIVE"
            evidence_error = "No original detector output supports a vulnerability conclusion."
    document = original if isinstance(original, dict) and not evidence_error else {}
    transactions = document.get("transactions", [])
    if not isinstance(transactions, list):
        transactions = []
    explanations = {
        "LIKELY_VULNERABLE": "The detector identifies a response consistent with Broadcom WPS Monitor: likely vulnerable, without confirming RCE.",
        "PATCHED_HOSTAPD": "The fragment received an ACK as in hostapd and the advertisement contains Broadcom evidence. The detector identifies a Broadcom device using hostapd.",
        "NO_BROADCOM_FINGERPRINT": "The fragment received an ACK as in hostapd, without Broadcom evidence in the advertisement. The detector does not identify the Broadcom WPS stack.",
        "INCONCLUSIVE": "There is insufficient evidence to determine vulnerability. Missing responses or WPS advertisements are not interpreted as a negative result.",
        "NOT_TESTED": "Active fingerprinting has not been run for this target.",
        "ERROR": "Assessment failed; it cannot determine whether the target is vulnerable.",
    }
    return {
        "tool": "POLTERHEIST",
        "version": VERSION,
        "upstream_commit": UPSTREAM_COMMIT,
        "target": {
            "id": target.get("id"),
            "ssid": target["ssid"],
            "bssid": target["bssid"],
            "channel": target.get("channel"),
        },
        "assessment": classification,
        "verdict": labels[classification],
        "explanation": explanations[classification],
        "reason": evidence_error or reason,
        "detector_assessment": document.get("assessment"),
        "implementation": document.get("implementation"),
        "target_health": document.get("target_health"),
        "warning": document.get("warning"),
        "transactions": [
            transaction for transaction in transactions if isinstance(transaction, dict)
        ],
        "claim_boundary": "Implementation fingerprint; it does not confirm exploitation or code execution.",
    }


def show_fingerprint_result(summary, folder):
    target = summary["target"]
    print(tint("\nPOLTERHEIST :: WPS FINGERPRINT"))
    print(
        f"  SSID: {safe_text(target['ssid'])} | BSSID: {safe_text(target['bssid'])} | channel: {target['channel']}"
    )
    print(tint("  " + summary["verdict"] + " [" + summary["assessment"] + "]", AMBER))
    print("  " + summary["explanation"])
    if summary["reason"]:
        print("  Reason: " + safe_text(summary["reason"]))
    if summary["detector_assessment"]:
        print("  Original result: " + safe_text(summary["detector_assessment"]))
    if summary["implementation"]:
        print("  Estimated implementation: " + safe_text(summary["implementation"]))
    if summary["target_health"]:
        print("  Detector health status: " + safe_text(summary["target_health"]))
    for transaction in summary["transactions"]:
        print("  Observed response: " + safe_text(transaction.get("response", "Unknown")))
        if transaction.get("detail"):
            print("    " + safe_text(transaction["detail"]))
    if summary["warning"]:
        print("  Detector warning: " + safe_text(summary["warning"]))
    print(f"  Result: {folder / 'fingerprint.json'}")


def save_fingerprint_summary(folder, report):
    target = report.get("selected_target")
    if target is None:
        return None
    summary = fingerprint_summary(
        target,
        report["assessment"],
        report.get("original_fingerprint"),
        report.get("error") or report.get("not_tested_reason"),
    )
    report["assessment"] = target["assessment"] = summary["assessment"]
    for ap in report["access_points"]:
        if ap["bssid"].lower() == target["bssid"].lower():
            ap["assessment"] = summary["assessment"]
    report["fingerprint"] = summary
    dump_json(folder / "fingerprint.json", summary)
    return summary


def restricted_backend(upstream):
    class SelectedTargetBackend(upstream.ScapyFingerprintBackend):
        """Transport guard only. Upstream fragment generation and decisions are unchanged."""

        def __enter__(self):
            try:
                return super().__enter__()
            except BaseException:
                # __exit__ is not called when capture startup itself is interrupted.
                self._stop_capture()
                raise

        def _deauthenticate(self, station):
            # Raising is intentional: upstream must report cleanup_sent=False.
            raise upstream.FingerprintError(
                "POLTERHEIST blocks deauthentication; no cleanup frame sent"
            )

        def _transmit(self, packet):
            dot11 = packet.getlayer(upstream.Dot11)
            if dot11 is None or (int(dot11.type) == 0 and int(dot11.subtype) in {10, 12}):
                raise upstream.FingerprintError(
                    "POLTERHEIST blocks deauthentication/disassociation"
                )
            if (
                str(dot11.addr1).lower() != self.target.bssid.lower()
                or str(dot11.addr3).lower() != self.target.bssid.lower()
            ):
                raise upstream.FingerprintError("POLTERHEIST blocks transmission to another BSSID")
            return super()._transmit(packet)

    return SelectedTargetBackend


def observe_selected(upstream, iface, ap, writer, seconds=8):
    """Passively reacquire exactly the authorized BSSID before any active exchange."""
    observations = []
    lock = threading.Lock()
    ready = threading.Event()

    def receive(packet):
        observed = upstream.parse_advertisement(packet, channel_hint=ap["channel"])
        if (
            observed
            and observed.bssid.lower() == ap["bssid"].lower()
            and observed.ssid == ap["ssid"]
        ):
            if observed.channel != ap["channel"]:
                return
            if iface.get("backend") == "windows":
                # A Windows monitor must provide real Radiotap evidence of the band.
                frequency = getattr(packet.getlayer(upstream.RadioTap), "ChannelFrequency", None)
                if frequency != ap["frequency_mhz"]:
                    return
            with lock:
                writer.write(packet)
                observations.append(observed)
            ready.set()

    sniffer = upstream.AsyncSniffer(iface=iface["name"], store=False, prn=receive)
    sniffer.start()
    try:
        ready.wait(timeout=seconds)
    finally:
        sniffer.stop()
    if not observations:
        raise RuntimeError(
            "The selected SSID/BSSID was not observed on its channel; run discovery again."
        )
    return observations[-1]


def windows_is_admin():
    return sys.platform == "win32" and bool(ctypes.windll.shell32.IsUserAnAdmin())


class WinShellExecuteInfo(ctypes.Structure):
    _fields_ = [
        ("size", ctypes.c_uint32),
        ("mask", ctypes.c_uint32),
        ("window", ctypes.c_void_p),
        ("verb", ctypes.c_wchar_p),
        ("file", ctypes.c_wchar_p),
        ("parameters", ctypes.c_wchar_p),
        ("directory", ctypes.c_wchar_p),
        ("show", ctypes.c_int32),
        ("instance", ctypes.c_void_p),
        ("id_list", ctypes.c_void_p),
        ("class_name", ctypes.c_wchar_p),
        ("class_key", ctypes.c_void_p),
        ("hot_key", ctypes.c_uint32),
        ("icon", ctypes.c_void_p),
        ("process", ctypes.c_void_p),
    ]


def windows_elevated_wireless(ssid=None, bssid=None):
    """Use the normal Windows UAC prompt and keep the interactive result window open."""
    shell = ctypes.WinDLL("shell32.dll", use_last_error=True, winmode=0x800)
    kernel = ctypes.WinDLL("kernel32.dll", use_last_error=True, winmode=0x800)
    shell.ShellExecuteExW.argtypes = [ctypes.POINTER(WinShellExecuteInfo)]
    shell.ShellExecuteExW.restype = ctypes.c_int32
    kernel.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    kernel.WaitForSingleObject.restype = ctypes.c_uint32
    kernel.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
    kernel.GetExitCodeProcess.restype = ctypes.c_int32
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel.CloseHandle.restype = ctypes.c_int32
    arguments = [str(BASE / "script.py"), "--wireless", "--windows-elevated"]
    if ssid is not None:
        arguments.extend(["--ssid", ssid])
    if bssid is not None:
        arguments.extend(["--bssid", bssid])
    request = WinShellExecuteInfo(
        size=ctypes.sizeof(WinShellExecuteInfo),
        mask=0x40 | 0x100,
        verb="runas",
        file=sys.executable,
        directory=str(BASE),
        show=1,
        parameters=subprocess.list2cmdline(arguments),
    )
    print(
        "  Windows will request administrator privileges to prepare Wi-Fi; continue in that window."
    )
    if not shell.ShellExecuteExW(ctypes.byref(request)):
        raise RuntimeError("Windows did not grant UAC elevation; the adapter was not modified.")
    if not request.process:
        raise RuntimeError("Windows did not return the elevated process.")
    try:
        while True:
            try:
                status = kernel.WaitForSingleObject(request.process, 250)
            except KeyboardInterrupt:
                print("  Cancel the test in the administrator window to restore the adapter.")
                continue
            if status == 0:
                break
            if status != 258:
                raise RuntimeError("Unable to wait for the administrator process.")
        code = ctypes.c_uint32()
        if not kernel.GetExitCodeProcess(request.process, ctypes.byref(code)):
            raise RuntimeError("Unable to query the administrator process result.")
        return code.value
    finally:
        kernel.CloseHandle(request.process)


def windows_monitor_candidate(interfaces, preferred):
    capable = [
        i
        for i in interfaces
        if i.get("backend") == "windows"
        and (i["mode"] == "monitor" or "monitor" in i.get("capabilities", []))
    ]
    if not capable:
        details = "; ".join(
            safe_text(i.get("display_name", i["name"]))
            + ": "
            + (i.get("monitor_note") or "available modes = " + ", ".join(i.get("capabilities", [])))
            for i in interfaces
            if i.get("backend") == "windows"
        )
        raise RuntimeError(
            "Monitor mode is unavailable with the current Windows driver. "
            + details
            + ". An adapter/driver exposing monitor mode is required; software cannot enable unsupported hardware capabilities."
        )
    return min(capable, key=lambda i: (i.get("connected", False), i["name"] != preferred["name"]))


def validate_windows_target(ap):
    if sys.platform != "win32":
        raise RuntimeError("Npcap transport requires Windows")
    if not ap.get("frequency_mhz") or not 2412 <= ap["frequency_mhz"] <= 2484:
        raise RuntimeError(
            "The Windows WPS test supports 2.4 GHz; use Linux for 5 GHz. The detector does not support 6 GHz."
        )
    if not ap.get("channel") or frequency_channel(ap["frequency_mhz"]) != ap["channel"]:
        raise RuntimeError("Inconsistent target channel/frequency")
    if not MAC.fullmatch(ap["bssid"]) or not ap["ssid"] or len(ap["ssid"].encode("utf-8")) > 32:
        raise ValueError("Invalid SSID/BSSID for the detector")
    if ap.get("ssid_hex") and ap["ssid"].encode("utf-8").hex() != ap["ssid_hex"]:
        raise ValueError(
            "The SSID is not UTF-8; the upstream detector requires an exact UTF-8 SSID."
        )
    if ap.get("in_reg_domain") is False:
        raise RuntimeError("Windows reports that the AP is outside the regulatory domain.")


def require_windows_monitor(ap, iface):
    validate_windows_target(ap)
    if not windows_is_admin():
        raise RuntimeError("Windows requires administrator privileges to prepare the adapter.")
    mode = wlan_helper(iface["guid"], "mode").casefold()
    channel = wlan_helper(iface["guid"], "channel")
    if mode != "monitor" or channel != str(ap["channel"]):
        raise RuntimeError(
            f"The driver did not confirm monitor mode and channel {ap['channel']} after automatic setup."
        )


@contextmanager
def prepared_windows_monitor(ap, iface, folder, state):
    """Prepare only the chosen adapter and restore it even if setup or capture fails."""
    validate_windows_target(ap)
    guid = iface["guid"]
    mode = wlan_helper(guid, "mode").casefold()
    modes = [m.strip().casefold() for m in wlan_helper(guid, "modes").split(",")]
    if mode != "monitor" and "monitor" not in modes:
        raise RuntimeError(
            f"{iface.get('display_name', guid)}: the Windows driver only advertises {', '.join(modes)}; monitor mode unavailable."
        )
    if mode not in {"managed", "monitor"}:
        raise RuntimeError("The current adapter mode cannot be restored automatically.")
    if not windows_is_admin():
        raise RuntimeError("Windows did not grant administrator privileges to prepare the adapter.")
    state.update(interface=guid, original_mode=mode, requested_channel=ap["channel"], restored=None)
    original_frequency, profile = None, None
    if mode == "monitor":
        original_frequency = int(wlan_helper(guid, "freq"))
        if not 2300 <= original_frequency <= 7125:
            raise RuntimeError("The driver cannot save the original frequency for restoration.")
    else:
        with WindowsWlan() as wlan:
            profile = wlan.connected_profile(guid)
    state.update(original_frequency=original_frequency, original_profile=profile)
    dump_json(folder / "radio_setup.json", state)
    changed = False
    try:
        # A failed call may still have partially changed the radio.
        changed = True
        if mode != "monitor":
            wlan_helper(guid, "mode", "monitor")
        wlan_helper(guid, "channel", ap["channel"])
        require_windows_monitor(ap, iface)
        state["prepared"] = True
        dump_json(folder / "radio_setup.json", state)
        yield
    finally:
        if changed:
            try:
                if mode == "managed":
                    wlan_helper(guid, "mode", "managed")
                    if wlan_helper(guid, "mode").casefold() != "managed":
                        raise RuntimeError("The driver did not confirm the return to managed mode.")
                    if profile:
                        with WindowsWlan() as wlan:
                            wlan.connect_profile(guid, profile)
                else:
                    wlan_helper(guid, "freq", original_frequency)
                    if int(wlan_helper(guid, "freq")) != original_frequency:
                        raise RuntimeError("The driver did not confirm the restored frequency.")
                state["restored"] = True
            except (Exception, KeyboardInterrupt) as error:
                state.update(restored=False, restore_error=str(error) or "Restoration interrupted")
            finally:
                dump_json(folder / "radio_setup.json", state)


def open_windows_monitor_socket(capture_name):
    from scapy.config import conf

    if not conf.use_pcap:
        raise RuntimeError(
            "Scapy cannot find Npcap. Install it with raw 802.11 support and restart the terminal."
        )
    socket = conf.L2socket(iface=capture_name, monitor=True)
    try:
        if socket.pcap_fd.datalink() != 127:
            raise RuntimeError(
                "Npcap is not delivering Radiotap/802.11; the WPS test cannot run with Ethernet frames."
            )
    except BaseException:
        socket.close()
        raise
    return socket


@contextmanager
def windows_upstream_transport(upstream, iface, ap):
    """Replace only platform I/O temporarily; never touch the upstream detector/frames."""
    send, sniff, channel = upstream.sendp, upstream.AsyncSniffer, upstream.set_channel
    capture_name = "\\Device\\NPF_{" + str(uuid.UUID(iface["guid"])).upper() + "}"
    socket = open_windows_monitor_socket(capture_name)

    def pinned_channel(interface, requested):
        if interface != iface["name"] or requested != ap["channel"]:
            raise RuntimeError("The detector attempted to change the interface/channel")
        if wlan_helper(iface["guid"], "mode") != "monitor" or wlan_helper(
            iface["guid"], "channel"
        ) != str(requested):
            raise RuntimeError(
                "The mode/channel changed during the test; cancelling and restoring the adapter."
            )

    def pinned_send(packet, **kwargs):
        if kwargs.pop("iface", None) != iface["name"]:
            raise RuntimeError("Transmit interface differs from the selected interface")
        return send(packet, iface=capture_name, socket=socket, **kwargs)

    def pinned_sniff(**kwargs):
        if kwargs.pop("iface", None) != iface["name"]:
            raise RuntimeError("Capture interface differs from the selected interface")
        return sniff(iface=capture_name, monitor=True, **kwargs)

    upstream.sendp, upstream.AsyncSniffer, upstream.set_channel = (
        pinned_send,
        pinned_sniff,
        pinned_channel,
    )
    try:
        yield
    finally:
        upstream.sendp, upstream.AsyncSniffer, upstream.set_channel = send, sniff, channel
        socket.close()


def fingerprint_windows(ap, iface, folder, authorized=False):
    result = {
        "classification": "NOT_TESTED",
        "original": None,
        "error": None,
        "upstream_commit": UPSTREAM_COMMIT,
        "authorized": bool(authorized),
        "limitations": [],
        "radio_setup": {},
    }
    if not authorized:
        return result
    writer = None
    prepared = False
    try:
        upstream = load_upstream()
        with prepared_windows_monitor(ap, iface, folder, result["radio_setup"]):
            prepared = True
            with (
                windows_upstream_transport(upstream, iface, ap),
                Spinner("WPS / Npcap / " + ap["bssid"]),
            ):
                writer = upstream.PcapWriter(
                    str(folder / "fingerprint.pcap"), linktype=127, sync=True
                )
                observed = observe_selected(upstream, iface, ap, writer)
                with restricted_backend(upstream)(iface["name"], observed, writer) as backend:
                    detected = upstream.fingerprint_target(observed, backend)
                upstream.write_result_json(
                    detected, folder / "upstream_result.json", folder / "fingerprint.pcap"
                )
        result["original"] = json.loads(
            (folder / "upstream_result.json").read_text(encoding="utf-8")
        )
        result["classification"] = assessment_from_upstream(result["original"], ap)
    except (KeyboardInterrupt, EOFError):
        result.update(classification="INCONCLUSIVE", error="Interrupted by the operator")
    except Exception as error:
        result.update(
            classification="ERROR" if prepared else "NOT_TESTED",
            error=f"{type(error).__name__}: {error}",
        )
    finally:
        if writer is not None:
            try:
                writer.close()
            except Exception as error:
                result["limitations"].append("Error closing PCAP: " + str(error))
    result["limitations"].extend(
        [
            "Windows/Npcap: automatic monitor mode/2.4 GHz channel setup and restoration recorded in radio_setup.json.",
            "Reception/injection depend on Npcap and the driver. No response does not prove the AP is safe.",
            "Deauthentication blocked in transport: cleanup_sent=false; upstream target_health preserved.",
        ]
    )
    if result["radio_setup"].get("restore_error"):
        result["limitations"].append(
            "Unable to restore Wi-Fi: " + result["radio_setup"]["restore_error"]
        )
    return result


def fingerprint_selected(ap, iface, interfaces, folder, authorized=False):
    if iface.get("backend") == "windows":
        return fingerprint_windows(ap, iface, folder, authorized=authorized)
    result = {
        "classification": "NOT_TESTED",
        "original": None,
        "error": None,
        "limitations": [],
        "upstream_commit": UPSTREAM_COMMIT,
        "authorized": bool(authorized),
    }
    state = {}
    prepared = False
    if not authorized:
        return result
    try:
        load_upstream()
        with prepared_linux_monitor(ap, iface, interfaces, folder, state) as (ready, live):
            prepared = True
            result = fingerprint_linux_monitor(ap, ready, live, folder, authorized=True)
    except (KeyboardInterrupt, EOFError):
        result.update(classification="INCONCLUSIVE", error="Interrupted by the operator")
    except Exception as error:
        result["classification"] = "ERROR" if prepared else "NOT_TESTED"
        result["error"] = f"{type(error).__name__}: {error}"
    result["radio_setup"] = state
    if state.get("restore_error"):
        result["limitations"].append("Unable to restore Wi-Fi: " + state["restore_error"])
    return result


def fingerprint_linux_monitor(ap, iface, interfaces, folder, authorized=False):
    result = {
        "classification": "NOT_TESTED",
        "original": None,
        "error": None,
        "limitations": [],
        "upstream_commit": UPSTREAM_COMMIT,
        "authorized": bool(authorized),
    }
    if not authorized:
        return result
    state = None
    writer = None
    upstream = None
    try:
        require_linux(root=True)
        require_isolated_monitor(iface, interfaces)
        validate_linux_target(ap, iface)
        frequency = ap.get("frequency_mhz")
        upstream = load_upstream()
        state = upstream.inspect_monitor_interface(iface["name"])
        if state.channel is None or not iface.get("frequency_mhz"):
            raise RuntimeError("The original channel is unknown; unable to restore the radio.")
        set_frequency(iface["name"], frequency)
        writer = upstream.PcapWriter(str(folder / "fingerprint.pcap"), linktype=127, sync=True)
        with Spinner("WPS fingerprint / " + ap["bssid"]):
            observed = observe_selected(upstream, iface, ap, writer)
            with restricted_backend(upstream)(iface["name"], observed, writer) as backend:
                detected = upstream.fingerprint_target(observed, backend)
        upstream.write_result_json(
            detected, folder / "upstream_result.json", folder / "fingerprint.pcap"
        )
        result["original"] = json.loads(
            (folder / "upstream_result.json").read_text(encoding="utf-8")
        )
        result["classification"] = assessment_from_upstream(result["original"], ap)
        result["limitations"].append(
            "Deauthentication blocked in transport: cleanup_sent=false; upstream target_health preserved."
        )
    except (KeyboardInterrupt, EOFError):
        result.update(classification="INCONCLUSIVE", error="Interrupted by the operator")
    except Exception as error:
        result.update(classification="ERROR", error=f"{type(error).__name__}: {error}")
    finally:
        if writer is not None:
            try:
                writer.close()
            except Exception as error:
                result["limitations"].append("Error closing PCAP: " + str(error))
        if state is not None and iface.get("frequency_mhz"):
            try:
                set_frequency(iface["name"], iface["frequency_mhz"])
            except Exception as error:
                result["limitations"].append("Unable to restore the channel: " + str(error))
    return result


def write_wireless_report(folder, report):
    report["updated_at"] = utc_now()
    artifacts = []
    for path in sorted(folder.rglob("*")):
        if path.is_file() and path != folder / "report.json" and not path.name.endswith(".tmp"):
            with path.open("rb") as source:
                digest = hashlib.file_digest(source, "sha256").hexdigest()
            artifacts.append(
                {
                    "path": path.relative_to(folder).as_posix(),
                    "bytes": path.stat().st_size,
                    "sha256": digest,
                }
            )
    report["artifacts"] = artifacts
    dump_json(folder / "report.json", report)


def wireless_recon(ssid=None, bssid=None):
    system = operating_system()
    if system["family"] == "unsupported":
        raise RuntimeError("WIRELESS RECON requires Kali/Linux or Windows.")
    if system["family"] == "linux":
        require_linux()
        if os.geteuid() != 0:
            return linux_elevated_wireless(ssid, bssid)
    if bssid is not None:
        bssid = bssid.lower()
        if not MAC.fullmatch(bssid):
            raise ValueError("Invalid BSSID")
    if ssid is not None and (not ssid or len(ssid.encode("utf-8")) > 32):
        raise ValueError("The SSID must contain 1 to 32 UTF-8 bytes.")
    interfaces = detect_wireless_interfaces()
    if not interfaces:
        raise RuntimeError(
            "No Wi-Fi interfaces found. In Kali Live, check firmware/rfkill; a VM requires USB Wi-Fi passthrough. Virtual Ethernet cannot perform this test."
        )
    if (
        any(
            i.get("backend") == "windows"
            and (i["mode"] == "monitor" or "monitor" in i.get("capabilities", []))
            for i in interfaces
        )
        and not windows_is_admin()
    ):
        return windows_elevated_wireless(ssid, bssid)
    connected = [i for i in interfaces if i.get("connected") and i.get("connected_ssid")]
    iface = (
        connected[0]
        if connected
        else interfaces[0]
        if len(interfaces) == 1
        else select_item(interfaces, "Wi-Fi interface")
    )
    if iface is None:
        return
    explicit = ssid is not None
    scope_ssid = ssid if explicit else iface.get("connected_ssid")
    if scope_ssid is not None and not isinstance(scope_ssid, str):
        raise ValueError("The driver did not return a valid connection SSID.")
    folder = report_folder("wireless")
    report = {
        "tool": "POLTERHEIST",
        "version": VERSION,
        "operating_system": system,
        "upstream_commit": UPSTREAM_COMMIT,
        "timestamp": utc_now(),
        "interfaces": interfaces,
        "discovery_interface": iface["name"],
        "access_points": [],
        "targets": [],
        "selected_target": None,
        "assessment": "NOT_TESTED",
        "original_fingerprint": None,
        "authorization": {
            "granted": bool(scope_ssid),
            "ssid": scope_ssid,
            "bssid": bssid,
            "source": "explicit_ssid" if explicit else "connected_network",
            "timestamp": utc_now(),
        },
        "status": "running",
        "technical_limitations": [],
        "not_tested_reason": None,
    }
    write_wireless_report(folder, report)
    try:
        aps = discover_wifi(iface, interfaces, folder, report["technical_limitations"])
        report["access_points"] = aps
        dump_json(folder / "discovery.json", aps)
        targets = [
            ap
            for ap in aps
            if scope_ssid and ap["ssid"] == scope_ssid and (bssid is None or ap["bssid"] == bssid)
        ]
        report["selected_targets"] = [dict(ap) for ap in targets]
        report["status"] = "discovered"
        write_wireless_report(folder, report)
        if not scope_ssid:
            report["not_tested_reason"] = (
                "No network is connected. Connect to your Wi-Fi or specify its name with --ssid."
            )
            return
        if not targets:
            report["not_tested_reason"] = (
                "The authorized SSID/BSSID was not observed during discovery."
            )
            return
        print(
            "  Fingerprint for "
            + safe_text(repr(scope_ssid))
            + f": {len(targets)} BSSID(s). Automatic setup and restoration."
        )
        for index, target in enumerate(targets, 1):
            target_folder = folder / "targets" / target["bssid"].replace(":", "")
            target_folder.mkdir(parents=True, exist_ok=False)
            target_report = {
                "selected_target": dict(target),
                "access_points": [target],
                "assessment": "NOT_TESTED",
                "original_fingerprint": None,
                "authorization": dict(report["authorization"], bssid=target["bssid"]),
                "technical_limitations": [],
                "status": "preparing",
            }
            outcome = {
                "classification": "NOT_TESTED",
                "original": None,
                "error": None,
                "limitations": [],
            }
            try:
                current = detect_wireless_interfaces()
                if iface.get("backend") == "windows":
                    if not wlan_helper_path():
                        raise RuntimeError("Npcap with raw 802.11 support is missing.")
                    validate_windows_target(target)
                    radio = windows_monitor_candidate(current, iface)
                else:
                    radio = linux_radio_candidate(current, iface, target)
                target_report["fingerprint_interface"] = radio["name"]
                target_report["assessment"] = target["assessment"] = "INCONCLUSIVE"
                target_report["status"] = "fingerprinting"
                write_wireless_report(target_folder, target_report)
                print(f"  Assessing {index}/{len(targets)}: ID {target['id']}")
                outcome = fingerprint_selected(
                    target, radio, current, target_folder, authorized=True
                )
            except (KeyboardInterrupt, EOFError):
                outcome.update(classification="INCONCLUSIVE", error="Interrupted by the operator")
            except (RuntimeError, ValueError, OSError) as error:
                outcome["error"] = str(error)
            target_report.update(
                assessment=outcome["classification"],
                original_fingerprint=outcome["original"],
                error=outcome["error"],
                technical_limitations=outcome["limitations"],
                radio_setup=outcome.get("radio_setup"),
                status="assessed",
            )
            summary = save_fingerprint_summary(target_folder, target_report)
            write_wireless_report(target_folder, target_report)
            report["targets"].append(
                {
                    "target": dict(target),
                    "assessment": summary["assessment"],
                    "fingerprint": summary,
                    "evidence_directory": target_folder.relative_to(folder).as_posix(),
                    "radio_setup": outcome.get("radio_setup"),
                }
            )
            if len(targets) == 1:
                report.update(
                    selected_target=dict(target),
                    assessment=summary["assessment"],
                    original_fingerprint=outcome["original"],
                    fingerprint=summary,
                    radio_setup=outcome.get("radio_setup"),
                )
                dump_json(folder / "fingerprint.json", summary)
            else:
                report["assessment"] = None
            write_wireless_report(folder, report)
            radio_state = outcome.get("radio_setup") or {}
            if outcome["error"] == "Interrupted by the operator" or radio_state.get(
                "restore_error"
            ):
                report["status"] = (
                    "cancelled" if not radio_state.get("restore_error") else "restore_failed"
                )
                break
        else:
            report["status"] = "completed"
    except (KeyboardInterrupt, EOFError):
        report["status"] = "cancelled"
        report["not_tested_reason"] = "Interrupted by the operator; preserving evidence."
    except Exception as error:
        report.update(status="error", error=str(error))
        raise
    finally:
        report["assessment_counts"] = {
            value: sum(ap["assessment"] == value for ap in report["access_points"])
            for value in sorted({ap["assessment"] for ap in report["access_points"]})
        }
        write_wireless_report(folder, report)
        show_wifi(report["access_points"])
        if report.get("not_tested_reason"):
            print("  NOT_TESTED: " + safe_text(report["not_tested_reason"]))
        for result in report["targets"]:
            summary = result["fingerprint"]
            if summary["reason"] or summary["warning"]:
                print(
                    f"  ID {result['target']['id']}: "
                    + safe_text(summary["reason"] or summary["warning"])
                )
            radio = result.get("radio_setup") or {}
            if radio.get("restore_error"):
                print("  Unable to restore Wi-Fi: " + safe_text(radio["restore_error"]))
        print(f"  Report and evidence: {folder}")


def portal_validate(config):
    """Validate all values before passing them to NetworkManager or nftables."""
    if config["mode"] not in {"wifi", "router"}:
        raise ValueError("Invalid portal mode")
    for key in ("lan", "wan"):
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", config[key]):
            raise ValueError("Invalid interface name")
    if config["lan"] == config["wan"]:
        raise ValueError("The portal requires two distinct interfaces: Internet and clients.")
    network = ipaddress.IPv4Network(config["network"])
    private = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
    if network.prefixlen != 24 or not any(
        network.subnet_of(ipaddress.IPv4Network(n)) for n in private
    ):
        raise ValueError("The portal network must be a private IPv4 /24 subnet.")
    if not 10 <= config.get("session_seconds", 3600) <= 86400:
        raise ValueError("Invalid session duration")
    if config["mode"] == "wifi":
        ssid = config["ssid"]
        if not 1 <= len(ssid.encode("utf-8")) <= 32 or any(ord(c) < 32 for c in ssid):
            raise ValueError(
                "The Wi-Fi name must contain 1 to 32 UTF-8 bytes without control characters."
            )
        password = config["password"]
        if not 8 <= len(password) <= 63 or any(not 32 <= ord(c) <= 126 for c in password):
            raise ValueError("The Wi-Fi password must contain 8 to 63 ASCII characters.")
        if not 1 <= config["channel"] <= 11:
            raise ValueError("The Wi-Fi portal uses a permitted 2.4 GHz channel (1–11).")
    return network


def portal_profile(config, connection):
    network = portal_validate(config)
    kind = "wifi" if config["mode"] == "wifi" else "ethernet"
    profile = (
        f"[connection]\nid=POLTERHEIST Portal\nuuid={uuid.UUID(connection)}\n"
        f"type={kind}\ninterface-name={config['lan']}\nautoconnect=false\n\n"
        f"[ipv4]\nmethod=shared\naddress1={network[1]}/24\nnever-default=true\n\n"
        "[ipv6]\nmethod=disabled\n"
    )
    if kind == "wifi":
        # A byte-array SSID avoids keyfile escaping and preserves UTF-8 names.
        ssid = ";".join(str(b) for b in config["ssid"].encode("utf-8")) + ";"
        psk = hashlib.pbkdf2_hmac(
            "sha1", config["password"].encode(), config["ssid"].encode(), 4096, 32
        ).hex()
        profile += (
            f"\n[wifi]\nmode=ap\nband=bg\nchannel={config['channel']}\nssid={ssid}\n"
            "\n[wifi-security]\nkey-mgmt=wpa-psk\nproto=rsn;\npairwise=ccmp;\n"
            f"group=ccmp;\npsk={psk}\n"
        )
    return profile


def portal_nft_rules(config, table):
    network = portal_validate(config)
    if not re.fullmatch(r"polterheist_[0-9a-f]{12}", table):
        raise ValueError("Invalid portal table name")
    lan, wan = config["lan"], config["wan"]
    # These hooks only govern the dedicated client interface. Existing tables survive.
    return f'''table inet {table} {{
 set clients {{ type ipv4_addr . ether_addr; flags timeout; size 256; }}
 set destinations {{ type ipv4_addr; flags timeout; size 256; }}
 chain input {{
  type filter hook input priority -10; policy accept;
  iifname "{lan}" udp sport 68 udp dport 67 accept
  iifname "{lan}" ip saddr {network} ip daddr {network[1]} udp dport 53 accept
  iifname "{lan}" ip saddr {network} ip daddr {network[1]} tcp dport {{ 53, 8080 }} accept
  iifname "{lan}" drop
 }}
 chain forward {{
  type filter hook forward priority -10; policy accept;
  iifname "{lan}" oifname "{wan}" ip saddr . ether saddr @clients accept
  oifname "{lan}" iifname "{wan}" ip daddr @destinations ct state established,related accept
  iifname "{lan}" drop
  oifname "{lan}" drop
 }}
 chain capture {{
  type nat hook prerouting priority -110; policy accept;
  iifname "{lan}" ip saddr . ether saddr @clients return
  iifname "{lan}" ip saddr {network} tcp dport 80 redirect to :8080
 }}
}}
'''


def portal_nft(source, check=False):
    result = subprocess.run(
        ["nft", *(["--check"] if check else []), "--file", "-"],
        input=source,
        text=True,
        capture_output=True,
        timeout=15,
        env=dict(os.environ, LC_ALL="C"),
    )
    if result.returncode:
        raise RuntimeError("nftables: " + safe_text(result.stderr.strip()))


def portal_grant(table, ip, mac, seconds):
    if not re.fullmatch(r"polterheist_[0-9a-f]{12}", table) or not MAC.fullmatch(mac):
        raise ValueError("Invalid portal identity")
    ip = str(ipaddress.IPv4Address(ip))
    if not 10 <= seconds <= 86400:
        raise ValueError("Invalid session duration")
    portal_nft(
        f"add element inet {table} clients {{ {ip} . {mac} timeout {seconds}s }}\n"
        f"add element inet {table} destinations {{ {ip} timeout {seconds}s }}\n"
    )


def portal_identity(lan, ip):
    ip = str(ipaddress.IPv4Address(ip))
    rows = json.loads(linux_command(["ip", "-json", "neigh", "show", "to", ip, "dev", lan]))
    for row in rows:
        mac = row.get("lladdr", "").lower()
        if row.get("dst") == ip and MAC.fullmatch(mac):
            return mac
    raise ValueError("Unable to identify the device on the portal interface.")


class PortalAccess:
    """Short-lived, single-use acceptance tokens bound to the direct client's IP/MAC."""

    def __init__(self, network, identity, grant, seconds=3600):
        self.network = ipaddress.IPv4Network(network)
        self.identity = identity
        self.grant = grant
        self.seconds = seconds
        self.pending = {}
        self.active = {}
        self.lock = threading.Lock()

    def client(self, ip):
        address = ipaddress.IPv4Address(ip)
        if address not in self.network or address in (
            self.network.network_address,
            self.network.broadcast_address,
            self.network[1],
        ):
            raise ValueError("Device is outside the portal network")
        return str(address), self.identity(str(address))

    def page(self, ip):
        client = self.client(ip)
        now = time.monotonic()
        with self.lock:
            self.pending = {k: v for k, v in self.pending.items() if v[1] > now}
            self.active = {k: expiry for k, expiry in self.active.items() if expiry > now}
            if client in self.active:
                return None
            # Refreshing a captive browser must not exhaust the token pool.
            self.pending = {k: v for k, v in self.pending.items() if v[0] != client}
            if len(self.pending) >= 256:
                raise ValueError("Portal busy; try again")
            token = secrets.token_urlsafe(32)
            self.pending[token] = (client, now + 300)
            return token

    def accept(self, ip, token):
        client = self.client(ip)
        with self.lock:
            entry = self.pending.get(token)
            if entry is None or entry[0] != client or entry[1] <= time.monotonic():
                raise ValueError("This page has expired; reopen the portal")
            self.grant(*client, self.seconds)
            del self.pending[token]
            self.active[client] = time.monotonic() + self.seconds


def portal_page(title, token=None, connected=False, preview=False):
    message = "Accept access to browse the Internet from this network."
    form = (
        '<form method="post" action="/accept"><input type="hidden" name="token" value="'
        + html.escape(token or "", quote=True)
        + '"><button name="accept" value="yes">Accept and connect</button></form>'
    )
    if preview:
        message = "Portal preview. This window does not change Internet access."
        form = "<button disabled>Accept and connect</button>"
    elif connected:
        message = "Access granted. You can now continue browsing."
        form = ""
    return f"""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)} · POLTERHEIST</title>
<style>body{{margin:0;background:#0b1211;color:#e8f4ee;font:18px system-ui;display:grid;
min-height:100vh;place-items:center}}main{{margin:24px;padding:32px;max-width:440px;
border:1px solid #35554a;border-radius:20px}}small{{color:#85bca3;letter-spacing:2px}}
h1{{overflow-wrap:anywhere}}p{{line-height:1.6;color:#c4d8cd}}button{{padding:16px 24px;
border:0;border-radius:10px;background:#8ff0bb;color:#082b1a;font:700 17px system-ui;
cursor:pointer;width:100%}}button:disabled{{opacity:.55;cursor:default}}</style>
<main><small>POLTERHEIST · WI-FI ACCESS</small><h1>{html.escape(title)}</h1>
<p>{message}</p>{form}<p><small>Use this connection responsibly.</small></p></main></html>"""


class PortalServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, title, access=None):
        self.title = title
        self.access = access
        self.slots = threading.BoundedSemaphore(32)
        super().__init__(address, PortalHandler)

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        request.settimeout(5)
        try:
            super().process_request(request, address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()


class PortalHandler(http.server.BaseHTTPRequestHandler):
    server_version = "POLTERHEIST"
    sys_version = ""

    def log_message(self, *args):
        pass  # Never log form contents, tokens, or browsing destinations.

    def reply(self, status, body="", location=None):
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'",
        )
        if location:
            self.send_header("Location", location)
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if self.server.access is None:
            self.reply(200, portal_page(self.server.title, preview=True))
            return
        address, port = self.server.server_address
        if self.headers.get("Host") != f"{address}:{port}":
            self.reply(302, location=f"http://{address}:{port}/")
            return
        try:
            token = self.server.access.page(self.client_address[0])
            self.reply(200, portal_page(self.server.title, token, connected=token is None))
        except (ValueError, RuntimeError, subprocess.SubprocessError) as error:
            self.reply(403, html.escape(str(error)))

    def do_POST(self):
        if urlsplit(self.path).path != "/accept" or self.server.access is None:
            self.reply(404)
            return
        try:
            if self.headers.get_content_type() != "application/x-www-form-urlencoded":
                raise ValueError("Invalid form")
            if (
                self.headers.get("Transfer-Encoding")
                or len(self.headers.get_all("Content-Length", [])) != 1
            ):
                raise ValueError("Invalid length")
            length = int(self.headers["Content-Length"])
            if not 1 <= length <= 2048:
                raise ValueError("Form too large")
            fields = parse_qs(self.rfile.read(length).decode("ascii"), max_num_fields=3)
            if fields.get("accept") != ["yes"] or len(fields.get("token", [])) != 1:
                raise ValueError("Invalid form")
            self.server.access.accept(self.client_address[0], fields["token"][0])
            address, port = self.server.server_address
            self.reply(303, location=f"http://{address}:{port}/connected")
        except (ValueError, UnicodeError, RuntimeError, subprocess.SubprocessError) as error:
            self.reply(403, html.escape(str(error)))


def portal_preview():
    with PortalServer(("127.0.0.1", 8080), "Welcome", None) as server:
        print("  Local preview: http://127.0.0.1:8080 — Ctrl+C to return.")
        print("  Preview does not create Wi-Fi or control access for other devices.")
        try:
            server.serve_forever(poll_interval=0.25)
        except KeyboardInterrupt:
            pass


def portal_candidate_rows(links, radios, wan, mode):
    rows = []
    for link in links:
        name = link["ifname"]
        radio = next((r for r in (radios or []) if r["name"] == name), None)
        kind = link.get("linkinfo", {}).get("info_kind", "")
        category = "Wi-Fi" if radio else kind or link.get("link_type", "?")
        if name == wan:
            reason = "Internet uplink; in use"
        elif link.get("link_type") != "ether":
            reason = "Cannot carry Ethernet/Wi-Fi clients"
        elif link.get("master") or kind == "bridge":
            reason = "Bridge for another network; not a free interface"
        elif mode == "wifi" and radio is None:
            reason = "Ethernet cannot broadcast Wi-Fi"
        elif mode == "wifi" and "AP" not in radio.get("capabilities", []):
            reason = "The driver does not advertise AP mode"
        elif mode == "router" and radio is not None:
            reason = "An Ethernet connection to the router/AP is required"
        elif any(a.get("scope") == "global" for a in link.get("addr_info", [])):
            reason = "Has assigned addresses; in use"
        else:
            reason = "Available for checking"
        rows.append(
            {
                "name": name,
                "type": category,
                "reason": reason,
                "candidate": reason == "Available for checking",
                "link": link,
            }
        )
    return rows


def portal_virtualization():
    result = run_quiet(["systemd-detect-virt"], timeout=5)
    return result.stdout.strip() if result is not None and result.returncode == 0 else None


def portal_explain_interfaces(links, radios, wan, mode, virtualization=None):
    print(tint("\nPOLTERHEIST :: PORTAL / INTERFACES"))
    table(
        ["INTERFACE", "TYPE", "AVAILABILITY"],
        [
            [r["name"], r["type"], r["reason"]]
            for r in portal_candidate_rows(links, radios, wan, mode)
        ],
        [16, 12, 52],
    )
    if virtualization:
        label = "VirtualBox" if virtualization == "oracle" else virtualization
        print("  Virtual environment detected: " + safe_text(label))
    if radios is None:
        print("  Unable to check for Wi-Fi radios; check iw and the driver.")
    elif not radios:
        print(
            "  Linux detects no Wi-Fi radio. It cannot create an SSID or run wireless fingerprinting."
        )
        if virtualization:
            print(
                "  Bridging the VM over the host Wi-Fi does not expose the radio: it is still virtual Ethernet."
            )
            print(
                "  To broadcast Wi-Fi: pass a compatible USB adapter to the VM, or boot Kali Live on the PC."
            )
    if mode == "wifi":
        print(
            "  Single-radio alternative: use Ethernet or phone USB tethering for Internet and leave Wi-Fi free for the AP."
        )
        print(
            "  Client + AP on the same radio depends on the driver and is not implemented in this portal."
        )
    else:
        print(
            "  An external router/AP needs a client Ethernet interface separate from the Internet uplink."
        )
        if virtualization:
            print(
                "  A second virtual adapter supports a lab; for a physical AP it must bridge to dedicated physical Ethernet."
            )
    print(
        "  Preview [3] → [v] works without a second interface but does not control access for other devices."
    )


def portal_check():
    require_linux()
    require_tools("ip")
    links = json.loads(linux_command(["ip", "-json", "-details", "address", "show"]))
    routes = json.loads(linux_command(["ip", "-json", "-4", "route", "show"]))
    defaults = sorted(
        (r for r in routes if r.get("dst") == "default" and r.get("dev")),
        key=lambda r: r.get("metric", 0),
    )
    wan = defaults[0]["dev"] if defaults else None
    radios = None
    if shutil.which("iw"):
        try:
            radios = detect_wireless_interfaces()
        except RuntimeError as error:
            print("  Unable to query radios: " + safe_text(error))
    else:
        print("  iw is missing; install dependencies with --setup to query radios.")
    portal_explain_interfaces(links, radios, wan, "wifi", portal_virtualization())
    if not wan:
        print("  No default IPv4 route is available to share Internet access.")
    if shutil.which("nft"):
        firewall = run_quiet(["nft", "--json", "list", "ruleset"])
        if firewall is not None and firewall.returncode == 0:
            hooks = sorted(
                {
                    x["chain"]["table"]
                    for x in json.loads(firewall.stdout).get("nftables", [])
                    if x.get("chain", {}).get("hook") in {"input", "forward"}
                }
            )
            if hooks:
                print(
                    "  Another firewall/gateway is active: "
                    + safe_text(", ".join(hooks))
                    + ". This portal does not modify those rules."
                )
        else:
            print("  Run --portal-check with sudo to also inspect the firewall.")
    return 0


class PortalInterfaceUnavailable(RuntimeError):
    """A client interface failed read-only checks; another can be tried safely."""


def portal_interface_state(config, links, radios):
    """Shared eligibility checks for discovery and the last check before activation."""
    lan = next((i for i in links if i["ifname"] == config["lan"]), None)
    if (
        lan is None
        or config["lan"] == config["wan"]
        or lan.get("link_type") != "ether"
        or lan.get("master")
        or lan.get("linkinfo", {}).get("info_kind") == "bridge"
    ):
        raise PortalInterfaceUnavailable(
            "Use a dedicated client Ethernet/Wi-Fi interface outside bridges."
        )
    if any(a.get("scope") == "global" for a in lan.get("addr_info", [])):
        raise PortalInterfaceUnavailable("The client interface already has addresses.")
    managed, connection = linux_nm_state(config["lan"])
    if managed is None:
        raise PortalInterfaceUnavailable("NetworkManager cannot query this interface.")
    if connection:
        raise PortalInterfaceUnavailable("The client interface has an active connection.")
    channels = []
    radio = next((r for r in (radios or []) if r["name"] == config["lan"]), None)
    if config["mode"] == "wifi":
        if (
            radio is None
            or radio.get("mode") != "managed"
            or "AP" not in radio.get("capabilities", [])
        ):
            raise PortalInterfaceUnavailable("The interface must be managed and support AP mode.")
        if radio.get("connected"):
            raise PortalInterfaceUnavailable("The Wi-Fi interface is already connected.")
        if not radio.get("phy") or any(
            r.get("phy") == radio["phy"] and r["name"] != radio["name"] for r in radios
        ):
            raise PortalInterfaceUnavailable("The radio must have a known, dedicated PHY.")
        channels = [
            f["channel"]
            for f in radio.get("frequencies", [])
            if 1 <= f["channel"] <= 11
            and not (f["disabled"] or f["no_ir"] or f["radar"])
            and f["frequency_mhz"] < 2500
        ]
        if not channels or ("channel" in config and config["channel"] not in channels):
            raise PortalInterfaceUnavailable("No permitted AP channel is available on this radio.")
    elif radio is not None or Path("/sys/class/net", config["lan"], "wireless").exists():
        raise PortalInterfaceUnavailable("Router/AP mode requires a client Ethernet interface.")
    return lan, managed, channels


def portal_interface_plans(links, radios, wan, preferred, network):
    """Check every free interface, preferred mode first, without changing any adapter."""
    plans = []
    for mode in (preferred, "router" if preferred == "wifi" else "wifi"):
        for row in portal_candidate_rows(links, radios, wan, mode):
            if not row["candidate"]:
                continue
            config = {
                "mode": mode,
                "lan": row["name"],
                "wan": wan,
                "network": network,
                "session_seconds": 3600,
            }
            try:
                _, _, channels = portal_interface_state(config, links, radios)
            except PortalInterfaceUnavailable as error:
                print(f"  Skipping {safe_text(row['name'])}: {safe_text(error)}")
                continue
            if mode == "wifi":
                config["channel"] = next((c for c in (1, 6, 11) if c in channels), channels[0])
            plans.append(config)
    return plans


def portal_preflight(config):
    require_linux(root=True)
    require_tools("nmcli", "ip", "nft", "sysctl", "dnsmasq")
    network = portal_validate(config)
    links = json.loads(linux_command(["ip", "-json", "-details", "address", "show"]))
    radios = None
    if config["mode"] == "wifi":
        require_tools("iw")
        radios = detect_wireless_interfaces()
    lan, managed, _ = portal_interface_state(config, links, radios)
    routes = json.loads(linux_command(["ip", "-json", "-4", "route", "show"]))
    if not any(r.get("dst") == "default" and r.get("dev") == config["wan"] for r in routes):
        raise RuntimeError("The Internet interface must have an active default route.")
    for route in routes:
        if route.get("dst") not in (None, "default"):
            if network.overlaps(ipaddress.IPv4Network(route["dst"], strict=False)):
                raise RuntimeError("The portal subnet overlaps an existing route.")
    rules = json.loads(linux_command(["nft", "--json", "list", "ruleset"]))
    if any(
        item.get("chain", {}).get("hook") in {"forward", "input"}
        for item in rules.get("nftables", [])
    ):
        raise RuntimeError(
            "Another firewall/gateway is active. The portal requires a dedicated machine without existing "
            "input/forward rules; existing rules will not be deleted."
        )
    return {
        "original_managed": managed,
        "original_up": "UP" in lan.get("flags", []),
        "original_forward": linux_command(["sysctl", "-n", "net.ipv4.ip_forward"]),
    }


@contextmanager
def portal_keyfile(config, connection):
    directory = Path("/run/NetworkManager/system-connections")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    profile = directory / f"polterheist-{uuid.UUID(connection)}.nmconnection"
    descriptor = os.open(profile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(portal_profile(config, connection))
        yield profile
    finally:
        profile.unlink(missing_ok=True)


def portal_verify_restored(config, state):
    managed, connection = linux_nm_state(config["lan"])
    links = json.loads(linux_command(["ip", "-json", "address", "show", "dev", config["lan"]]))
    if (
        managed != state["original_managed"]
        or connection is not None
        or len(links) != 1
        or ("UP" in links[0].get("flags", [])) != state["original_up"]
        or any(a.get("scope") == "global" for a in links[0].get("addr_info", []))
        or linux_command(["sysctl", "-n", "net.ipv4.ip_forward"]) != state["original_forward"]
    ):
        raise RuntimeError(
            "Restoration of the original interface/forwarding state was not confirmed."
        )


@contextmanager
def portal_lock():
    import fcntl  # Linux only; importing POLTERHEIST remains possible on Windows.

    with Path("/run/polterheist-portal.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError("A POLTERHEIST portal is already active.") from error
        yield


@contextmanager
def portal_network(config, folder):
    with portal_lock():
        state = portal_preflight(config)
        connection = str(uuid.uuid4())
        table = "polterheist_" + uuid.uuid4().hex[:12]
        state.update(
            connection_uuid=connection,
            nft_table=table,
            lan=config["lan"],
            mode=config["mode"],
            restored=None,
            status="preparing",
        )
        dump_json(folder / "network.json", state)
        rules = portal_nft_rules(config, table)
        portal_nft(rules, check=True)
        loaded = changed = firewall = False
        with portal_keyfile(config, connection) as profile:
            try:
                firewall = True
                portal_nft(rules)  # Block client forwarding before enabling DHCP/NAT.
                changed = True
                linux_command(["nmcli", "device", "set", config["lan"], "managed", "yes"])
                loaded = True
                linux_command(["nmcli", "connection", "load", str(profile)])
                linux_command(
                    [
                        "nmcli",
                        "--wait",
                        "30",
                        "connection",
                        "up",
                        "uuid",
                        connection,
                        "ifname",
                        config["lan"],
                    ],
                    timeout=35,
                )
                current = linux_nm_state(config["lan"])
                if current != (True, connection):
                    raise RuntimeError("NetworkManager did not confirm the portal connection.")
                addresses = json.loads(
                    linux_command(["ip", "-json", "address", "show", "dev", config["lan"]])
                )
                expected = str(ipaddress.IPv4Network(config["network"])[1])
                if not any(
                    a.get("local") == expected for i in addresses for a in i.get("addr_info", [])
                ):
                    raise RuntimeError("The interface does not have the gateway address.")
                state["status"] = "active"
                dump_json(folder / "network.json", state)
                yield table, state
            finally:
                errors = []

                def restore(action):
                    try:
                        action()
                    except (Exception, KeyboardInterrupt) as error:
                        errors.append(str(error) or "Restoration interrupted")

                def remove_connection():
                    # Deletion deactivates this UUID only and removes the temporary keyfile.
                    present = run_quiet(["nmcli", "connection", "show", "uuid", connection])
                    if present is None:
                        raise RuntimeError("Unable to query the temporary connection")
                    if present.returncode == 0:
                        linux_command(
                            ["nmcli", "--wait", "15", "connection", "delete", "uuid", connection]
                        )

                if loaded:
                    restore(remove_connection)
                if changed:
                    restore(
                        lambda: linux_command(
                            ["nmcli", "device", "set", config["lan"], "managed", "no"]
                        )
                    )
                    restore(
                        lambda: linux_command(["ip", "link", "set", "dev", config["lan"], "down"])
                    )
                    if config["mode"] == "wifi":
                        restore(
                            lambda: linux_command(
                                ["iw", "dev", config["lan"], "set", "type", "managed"]
                            )
                        )
                    restore(
                        lambda: linux_command(
                            [
                                "nmcli",
                                "device",
                                "set",
                                config["lan"],
                                "managed",
                                "yes" if state["original_managed"] else "no",
                            ]
                        )
                    )
                    restore(
                        lambda: linux_command(
                            [
                                "ip",
                                "link",
                                "set",
                                "dev",
                                config["lan"],
                                "up" if state["original_up"] else "down",
                            ]
                        )
                    )
                    restore(
                        lambda: linux_command(
                            ["sysctl", "-w", "net.ipv4.ip_forward=" + state["original_forward"]]
                        )
                    )
                    if not errors:
                        restore(lambda: portal_verify_restored(config, state))
                # Keep the guard if cleanup fails; do not accidentally leave an open gateway.
                if firewall and not errors:
                    present = run_quiet(["nft", "list", "table", "inet", table])
                    if present is None:
                        errors.append("Unable to query the guard table")
                    elif present.returncode == 0:
                        restore(lambda: portal_nft(f"delete table inet {table}\n"))
                state.update(
                    restored=not errors,
                    status="stopped" if not errors else "restore_failed",
                    restore_errors=errors,
                )
                dump_json(folder / "network.json", state)
                for error in errors:
                    print("  Restoration pending: " + safe_text(error))
                if errors:
                    print(f"  Guard retained: {table}. State saved in {folder / 'network.json'}")


def portal_run(config):
    folder = report_folder("portal")
    folder.chmod(0o700)
    dump_json(folder / "config.json", {k: v for k, v in config.items() if k != "password"})
    previous = signal.getsignal(signal.SIGTERM)

    def interrupted(*_):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupted)
    try:
        with portal_network(config, folder) as (table, state):
            network = ipaddress.IPv4Network(config["network"])
            access = PortalAccess(
                str(network),
                lambda ip: portal_identity(config["lan"], ip),
                lambda ip, mac, seconds: portal_grant(table, ip, mac, seconds),
                config.get("session_seconds", 3600),
            )
            with PortalServer(
                (str(network[1]), 8080), config.get("ssid") or "Welcome", access
            ) as server:
                print(f"  Portal active: http://{network[1]}:8080 | Ctrl+C to stop and restore.")
                print(
                    "  If the device does not open the portal, visit that address in its browser."
                )
                try:
                    server.serve_forever(poll_interval=0.25)
                except KeyboardInterrupt:
                    pass
    finally:
        signal.signal(signal.SIGTERM, previous)
        print(f"  Portal state: {folder}")


def captive_portal(choice=None):
    print(tint("\nPOLTERHEIST :: CAPTIVE PORTAL"))
    print("  [1] Create Wi-Fi (choose a name and password) — Kali/Linux")
    print("  [2] Use a router as an access point — Kali/Linux")
    print("  [v] Local preview — Windows/Linux\n  [q] Back")
    if choice is None:
        choice = input("  > ").strip().lower()
    if choice == "v":
        return portal_preview()
    if choice not in {"1", "2"}:
        return
    require_linux()
    if os.geteuid() != 0:
        require_tools("sudo")
        return subprocess.run(
            [
                "sudo",
                "--",
                sys.executable,
                str(BASE / "script.py"),
                "--portal",
                "--portal-choice",
                choice,
            ],
            check=False,
        ).returncode
    require_tools("ip", "nmcli", "nft", "dnsmasq")
    print("  Two interfaces are required: Internet and clients. The client interface must be free.")
    routes = json.loads(linux_command(["ip", "-json", "-4", "route", "show"]))
    defaults = sorted(
        (r for r in routes if r.get("dst") == "default" and r.get("dev")),
        key=lambda r: r.get("metric", 0),
    )
    if not defaults:
        raise RuntimeError("Connect this computer to the Internet first.")
    wan = defaults[0]["dev"]
    print("  Internet uplink: " + safe_text(wan))
    radios = None
    if shutil.which("iw"):
        try:
            radios = detect_wireless_interfaces()
        except RuntimeError as error:
            print("  Wi-Fi discovery unavailable: " + safe_text(error))
    links = json.loads(linux_command(["ip", "-json", "-details", "address", "show"]))
    used = [
        ipaddress.IPv4Network(r["dst"], strict=False)
        for r in routes
        if r.get("dst") not in (None, "default")
    ]
    network = next(
        (
            f"10.77.{n}.0/24"
            for n in range(256)
            if not any(ipaddress.IPv4Network(f"10.77.{n}.0/24").overlaps(r) for r in used)
        ),
        None,
    )
    if network is None:
        raise RuntimeError("No free subnet was found for the portal.")
    preferred = "wifi" if choice == "1" else "router"
    plans = portal_interface_plans(links, radios, wan, preferred, network)
    wifi_settings = None
    router_ready = False
    previous_mode = preferred
    for config in plans:
        mode = config["mode"]
        if mode != previous_mode:
            label = "Create Wi-Fi" if mode == "wifi" else "External router/AP"
            print("  No usable interface remains in the selected mode. Trying " + label + ".")
        previous_mode = mode
        print("  Trying client interface: " + safe_text(config["lan"]))
        if mode == "wifi":
            if wifi_settings is None:
                wifi_settings = {
                    "ssid": input("  New Wi-Fi name [POLTERHEIST]: ").strip() or "POLTERHEIST",
                    "password": getpass.getpass("  Wi-Fi password (8–63 characters): "),
                }
            config.update(wifi_settings)
        elif not router_ready:
            print("  Connect a router LAN port to the client interface on this PC.")
            print(
                "  Use AP/bridge mode, disable its DHCP, and disconnect its other Internet uplink."
            )
            print("  Clients will use the Wi-Fi name configured on that router.")
            if (
                input(
                    "  Type AP when the router is configured and connected as described: "
                ).strip()
                != "AP"
            ):
                return
            router_ready = True
        portal_validate(config)
        try:
            return portal_run(config)
        except PortalInterfaceUnavailable as error:
            # This exception is raised before any network mutation. Do not retry
            # firewall, activation, or cleanup failures as interface discovery.
            print(f"  Skipping {safe_text(config['lan'])}: {safe_text(error)}")
            if mode == "router":
                router_ready = False  # A different physical port needs its own cable.
    raise RuntimeError("No usable network interface is available for the captive portal.")


def load_profile(path=None):
    path = PROFILE_PATH if path is None else Path(path)
    if not path.exists():
        dump_json(path, {key: "" for key in PROFILE_FIELDS})
    profile = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(profile, dict) or any(
        not isinstance(profile.get(k, ""), str) for k in PROFILE_FIELDS
    ):
        raise ValueError("The profile must be a JSON object with text fields: " + str(path))
    return {key: profile.get(key, "") for key in PROFILE_FIELDS}


def who_am_i():
    while True:
        profile = load_profile()
        print(tint("\nPOLTERHEIST :: WHO AM I?"))
        for key, label in PROFILE_FIELDS.items():
            print(f"  {label}: {safe_text(profile[key]) or '[not configured]'}")
        choice = input("  [e] Edit profile | [q/ENTER] Back: ").strip().lower()
        if choice != "e":
            return
        print("  ENTER keeps the value; a hyphen (-) clears it.")
        updated = dict(profile)
        for key, label in PROFILE_FIELDS.items():
            value = input(f"  {label}: ").strip()
            if value:
                updated[key] = "" if value == "-" else value
        dump_json(PROFILE_PATH, updated)


def tv_control():
    from tv_control.cli import run

    return run(BASE)


def tv_diagnostics():
    from tv_control.hardware import run

    return run(BASE)


def shutdown_tv_control():
    # Do not import TV dependencies unless the feature has been opened.
    module = sys.modules.get("tv_control.cli")
    if module:
        module.shutdown()


def main(argv=None):
    try:
        return run_main(argv)
    finally:
        shutdown_tv_control()


def run_main(argv=None):
    parser = argparse.ArgumentParser(
        description="POLTERHEIST: authorized LAN and Wi-Fi reconnaissance"
    )
    parser.add_argument("--version", action="version", version="POLTERHEIST " + VERSION)
    parser.add_argument(
        "--check", action="store_true", help="Local diagnostics; does not scan the network"
    )
    parser.add_argument(
        "--setup",
        action="store_true",
        help="Install dependencies and create a Python environment for this operating system",
    )
    parser.add_argument(
        "--ssid", help="Authorized SSID to assess; defaults to the connected network"
    )
    parser.add_argument("--bssid", help="Limit assessment to one BSSID of the authorized SSID")
    parser.add_argument(
        "--wireless",
        "--wpscan",
        "--fingerprint",
        action="store_true",
        help="Open Wi-Fi discovery and WPS assessment directly",
    )
    parser.add_argument("--windows-elevated", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument(
        "--portal-check",
        action="store_true",
        help="Portal and interface diagnostics without changing the network",
    )
    parser.add_argument("--portal-choice", choices=("1", "2"), help=argparse.SUPPRESS)
    parser.add_argument("--portal", action="store_true", help="Open the captive portal wizard")
    parser.add_argument(
        "--iot-scan",
        "--tv-control",
        dest="tv_control",
        action="store_true",
        help="Open IoT scanning, connection options and media control (--tv-control is an alias)",
    )
    parser.add_argument(
        "--tv-diagnostics",
        action="store_true",
        help="Read-only Kali TV hardware diagnostics; no network required",
    )
    parser.add_argument(
        "--portal-preview",
        action="store_true",
        help="Preview the portal on localhost without changing the network",
    )
    options = parser.parse_args(argv)
    if options.tv_diagnostics:
        if any(
            (
                options.tv_control,
                options.setup,
                options.check,
                options.portal_check,
                options.portal,
                options.portal_preview,
                options.portal_choice,
                options.wireless,
                options.ssid,
                options.bssid,
            )
        ):
            parser.error(
                "Run --tv-diagnostics separately; it never installs tools or changes networking."
            )
        try:
            return tv_diagnostics()
        except (KeyboardInterrupt, EOFError):
            return 130
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            print("  [!] " + safe_text(error))
            return 1
    if options.tv_control and (
        options.portal
        or options.portal_preview
        or options.portal_choice
        or options.wireless
        or options.ssid
        or options.bssid
    ):
        parser.error("Run IoT Scanning separately from portal/wireless workflows.")
    if options.portal_choice:
        options.portal = True
    if (options.portal or options.portal_preview) and (
        options.wireless or options.ssid or options.bssid
    ):
        parser.error("Run the portal and fingerprinting separately.")
    if options.setup:
        try:
            return setup_environment()
        except (OSError, RuntimeError, subprocess.SubprocessError) as error:
            print("  [!] " + safe_text(error))
            return 1
    if options.portal_check:
        try:
            return portal_check()
        except (OSError, ValueError, RuntimeError) as error:
            print("  [!] " + safe_text(error))
            return 1
    if options.ssid is not None or options.bssid is not None:
        options.wireless = True
    if options.check:
        print(
            "POLTERHEIST "
            + VERSION
            + " | Python "
            + sys.version.split()[0]
            + " | "
            + operating_system()["name"]
        )
        if sys.platform == "win32":
            print("  Wi-Fi/WPS discovery: native Windows API (no WSL/Nmap)")
            print(
                "  Npcap / WlanHelper: "
                + (wlan_helper_path() or "not installed; required for active fingerprinting")
            )
            try:
                for iface in detect_windows_interfaces():
                    print(
                        f"  {safe_text(iface['display_name'])} | GUID={iface['guid']} | mode={iface['mode']} | available modes={', '.join(iface['capabilities']) or 'unknown'}"
                    )
                    if iface["capabilities"] and "monitor" not in iface["capabilities"]:
                        print(
                            "    The current Windows driver does not advertise monitor mode; active fingerprinting is unavailable."
                        )
                    if iface.get("monitor_note"):
                        print("    " + safe_text(iface["monitor_note"]))
            except (OSError, ValueError, RuntimeError) as error:
                print("  Wi-Fi: " + safe_text(error))
        else:
            for binary in ("nmap", "arp-scan", "ip", "iw", "nmcli", "tcpdump"):
                print(f"  {binary}: {shutil.which(binary) or 'not found'}")
        try:
            load_upstream()
            print("  Upstream detector: hash verified, Scapy available")
        except (OSError, ValueError, RuntimeError) as error:
            print("  Detector: " + str(error))
        return 0
    print(tint(BANNER))
    print(tint(f"  POLTERHEIST :: WATCHING THE WIRE :: v{VERSION}", AMBER))
    if options.tv_control:
        try:
            return tv_control() or 0
        except (KeyboardInterrupt, EOFError):
            return 130
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            print(tint("  [!] " + safe_text(error), AMBER))
            return 1
    if options.portal or options.portal_preview:
        try:
            if options.portal_preview:
                return portal_preview() or 0
            return (
                captive_portal(options.portal_choice) if options.portal_choice else captive_portal()
            ) or 0
        except (KeyboardInterrupt, EOFError):
            return 130
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            print(tint("  [!] " + safe_text(error), AMBER))
            return 1
    if options.wireless:
        try:
            if options.windows_elevated and not windows_is_admin():
                raise RuntimeError("The process did not receive administrator privileges.")
            if options.ssid is not None or options.bssid is not None:
                return wireless_recon(ssid=options.ssid, bssid=options.bssid) or 0
            return wireless_recon() or 0
        except (KeyboardInterrupt, EOFError):
            return 130
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            print(tint("  [!] " + safe_text(error), AMBER))
            return 1
        finally:
            if options.windows_elevated:
                try:
                    input("  Press ENTER to close this window: ")
                except (KeyboardInterrupt, EOFError):
                    pass
    while True:
        print(
            tint(
                "\n[0] WHO AM I?\n[1] LAN RECON\n[2] WIRELESS RECON\n[3] CAPTIVE PORTAL\n[4] IoT SCANNING — Discovery & Control\n\n[q] EXIT"
            )
        )
        try:
            choice = input("  > ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print("\n  Goodbye.")
            return 0
        if choice == "q":
            return 0
        action = {
            "0": who_am_i,
            "1": lan_recon,
            "2": wireless_recon,
            "3": captive_portal,
            "4": tv_control,
        }.get(choice)
        if action is None:
            print("  Invalid option.")
            continue
        try:
            action()
        except (KeyboardInterrupt, EOFError):
            print("\n  Returning to the menu.")
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            print(tint("  [!] " + safe_text(error), AMBER))


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.exit(main())
