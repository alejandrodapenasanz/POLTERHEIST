#!/usr/bin/env python3
"""POLTERHEIST: inventario LAN (Linux) y reconocimiento Wi-Fi (Linux/Windows)."""

import argparse
import csv
import ctypes
import datetime
import hashlib
import importlib.util
import ipaddress
import json
import os
import re
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

VERSION = "2.1.0"
BASE = Path(__file__).resolve().parent
PROFILE_PATH = BASE / "config" / "profile.json"
REPORTS = BASE / "reports"
UPSTREAM_COMMIT = "3cb3ef77d6b71e8441a51668c7e2b919608180f9"
VENDOR = BASE / "vendor" / "broadcom-wps"
PROFILE_FIELDS = {
    "name_alias": "Nombre / alias",
    "specialization": "Especialización",
    "biography": "Biografía",
    "github": "GitHub",
    "linkedin": "LinkedIn",
    "website": "Web",
    "contact": "Contacto",
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
                        f"{percent:g}% ETA: {remaining.group(1) if remaining else 'desconocida'}"
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
            "Esta función requiere Kali/Linux. En Windows están disponibles el menú, el perfil y WIRELESS RECON."
        )
    if root and os.geteuid() != 0:
        raise RuntimeError("Necesitas root: sudo .venv/bin/python script.py")


def require_tools(*names):
    missing = [name for name in names if not shutil.which(name)]
    if missing:
        raise RuntimeError(
            "Falta: " + ", ".join(missing) + ". Consulta los paquetes Kali del README."
        )


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
        raise RuntimeError("No hay ruta predeterminada IPv4")
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
        raise RuntimeError("La interfaz predeterminada no tiene una dirección IPv4 global")
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
                "vendor": "Desconocido",
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
        print(tint("  [!] arp-scan falló; se continúa con Nmap.", AMBER))

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
            print(tint("  [!] Nmap discovery falló; revisa discovery_nmap.log.", AMBER))
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
            print(tint("  [!] XML de descubrimiento ilegible.", AMBER))
    else:
        print(tint("  [!] Sin XML de descubrimiento Nmap.", AMBER))

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
    table(["ID", "IP", "MAC", "FABRICANTE / INFO", "FUENTE"], rows, [3, 15, 17, 38, 16])
    print(f"  Total: {len(hosts)} IPs; LOCAL identifica esta máquina.")


def identify(host, folder):
    ip = host["ip"]
    vendor = host["vendor"]
    loc = host["local"]
    data = {
        "id": host["id"],
        "ip": ip,
        "vendor": vendor,
        "vendor_confidence": "Media" if good_vendor(vendor) else "Baja",
        "type": "Desconocido",
        "os": "Desconocido",
        "type_confidence": "Baja",
        "evidence": list(host.get("manufacturer_evidence", [])),
        "mobile": False,
        "local": loc,
        "mac": host["mac"],
        "sources": host["sources"],
    }
    if host["mac"] != "-" and int(host["mac"].split(":")[0], 16) & 2:
        data["vendor_confidence"] = "Baja"
        data["evidence"].append("MAC administrada localmente: OUI no fiable")
    if loc:
        distro = Path("/etc/os-release")
        kali = distro.exists() and re.search(
            r"^ID=[\"\x27]?kali[\"\x27]?$", distro.read_text(), re.M
        )
        data.update(
            type="Kali (LOCAL)" if kali else "Linux (LOCAL)", os="Linux", type_confidence="Alta"
        )
        data["evidence"].append("Interfaz local")
        return data
    if host["gateway"]:
        data.update(type="Router / gateway", type_confidence="Alta")
        data["evidence"].append("Puerta de enlace")
    elif "apple" in vendor.lower():
        data["type"] = "Apple device"
        data["evidence"].append("OUI Apple; sin identificar tipo")
    elif "sichuan ai-link" in vendor.lower():
        data["type"] = "IoT posible"
        data["evidence"].append("Marca de modulo WiFi; no concluyente")

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
            cmd, f"Identificando ID {host['id']}: {ip}", folder / f"identify_{ip}.log", timeout=90
        )
        if res.returncode:
            data["evidence"].append(f"Nmap terminó con código {res.returncode}; ver log")
    except (OSError, subprocess.TimeoutExpired) as error:
        data["evidence"].append(f"Identificación incompleta: {error}")
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
                data["os"] = label + " (estimado)"
                break
        else:
            if name:
                data["os"] = cut(name, 30)
        data["evidence"].append(f"Nmap osmatch {accuracy}% similitud")
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
            data.update(type="Impresora probable", type_confidence="Media")
        elif any(x in " ".join(products) for x in ["routeros", "openwrt", "fritz!os"]):
            data.update(type="Router probable", type_confidence="Media")
        elif data["os"] in ("iOS (estimado)", "Android (estimado)") and accuracy >= 95:
            data.update(type="Movil/tablet probable", type_confidence="Media", mobile=True)
        elif 3389 in ports or 445 in ports:
            data.update(type="PC / servidor posible", type_confidence="Media")
    return data


def show_ids(ident):
    print(tint("\n[+] POLTERHEIST :: IDENTIFICACION PRELIMINAR"))
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
        ["ID", "IP", "FABRICANTE", "TIPO ESTIMADO", "SO ESTIMADO", "CONF FAB", "CONF TIPO"],
        rows,
        [3, 15, 27, 23, 19, 8, 9],
    )
    print("  Las clasificaciones son estimaciones; Apple no implica iPhone.")


def choose(hosts, ident):
    by_id = {host["id"]: host for host in hosts}
    defaults = [host for host in hosts if not host["local"]]
    valid = [d for d in ident if not d["mobile"] and not by_id[d["id"]]["local"]]
    print(tint("\n[+] POLTERHEIST :: OBJETIVOS"))
    print(f"  [0] All IPs ({len(defaults)}; excluye LOCAL)")
    print(f"  [1] All non-mobile IPs ({len(valid)}; excluye Kali)")
    for d in valid:
        print(f"      [{d['id']}] {d['ip']} - {d['type']}")
    print("  [2] Custom - IDs separados por comas, ej. 1,3,5")
    while True:
        mode = input("  Selecciona [0/1/2] (q salir): ").strip().lower()
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
                print("  Formato no valido")
                continue
            ids = list(dict.fromkeys(int(p) for p in parts))
            if any(i not in by_id for i in ids):
                print("  ID fuera de rango")
                continue
            selected = [by_id[i] for i in ids]
        else:
            continue
        if selected:
            print("  Seleccionados: " + ", ".join(h["ip"] for h in selected))
            return selected
        print("  Sin objetivos. Prueba otra opcion.")


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
    print(tint(f"\n[{index}/{total}] Analizando {ip}"))
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
            print(tint(f"  [!] Nmap: código {res.returncode}; revisa scan_{ip}.log", AMBER))
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
        raise RuntimeError("Subred demasiado grande (>4096 direcciones)")
    print(f"  Interface={dev} | Local={my_ip} | Gateway={gateway} | Network={network}")
    print("\n  [1] GHOST MODE: completo, menor velocidad (detectable)")
    print("  [2] HUNTER MODE: completo, velocidad normal")
    mode = input("  Modo [1/2]: ").strip()
    if mode not in ("1", "2"):
        return
    print(
        tint(
            "  Ambos modos generan tráfico y logs; algunos scripts vuln pueden ser intrusivos.",
            AMBER,
        )
    )
    if input("  ¿Red propia o autorizada? [s/N]: ").strip().lower() not in ("s", "si", "sí"):
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
        if not selected or input("  Pulsa INTRO para escanear (q volver): ").strip().lower() == "q":
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
        print("\n  Interrumpido; conservando las evidencias.")
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
        print(f"  Informes: {folder}")
    print(tint("\n[+] POLTERHEIST :: RESULTADOS"))
    table(
        ["ID", "IP", "FABRICANTE", "PUERTO", "SERVICIO", "VERSION", "CVEs"],
        [
            [r[k] for k in ("id", "ip", "vendor", "port", "service", "version", "cves")]
            for r in rows
        ],
        [3, 15, 24, 10, 14, 30, 28],
    )
    print("  Los CVE son referencias potenciales, no vulnerabilidades confirmadas.")


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


def windows_wlan_error(code, operation):
    if code == 5:
        detail = (
            "Acceso denegado: activa el acceso a Ubicación en Configuración > "
            "Privacidad y seguridad > Ubicación para esta aplicación/terminal."
        )
    elif code == 1062:
        detail = "Inicia el servicio Configuración automática de WLAN (WlanSvc)."
    elif code == 5023:
        detail = (
            "La interfaz no está disponible en este modo; revisa radio, controlador y modo monitor."
        )
    else:
        detail = "Revisa el adaptador, la radio Wi-Fi y su controlador."
    return RuntimeError(f"{operation}: error Windows {code}. {detail}")


def parse_windows_interfaces(data):
    if len(data) < 8:
        raise ValueError("Lista de interfaces WLAN truncada")
    count = int.from_bytes(data[:4], "little")
    size = ctypes.sizeof(WinInterface)
    if count > 1024 or 8 + count * size > len(data):
        raise ValueError("Tamaño de interfaces WLAN no válido")
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
            warnings.append("Cabecera IE truncada")
            break
        element, size = raw[offset : offset + 2]
        offset += 2
        if offset + size > len(raw):
            warnings.append("Contenido IE truncado")
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
                    warnings.append("Atributo WPS truncado")
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
        raise ValueError("Lista BSS truncada")
    total = int.from_bytes(data[:4], "little")
    count = int.from_bytes(data[4:8], "little")
    size = ctypes.sizeof(WinBssEntry)
    entries_end = 8 + count * size
    if total != len(data) or entries_end > total:
        raise ValueError("Tamaño BSS no válido")
    aps = []
    for offset in range(8, entries_end, size):
        item = WinBssEntry.from_buffer_copy(data, offset)
        if item.ssid.length > 32:
            raise ValueError("SSID de más de 32 bytes en BSS")
        start = offset + item.ie_offset
        end = start + item.ie_size
        if item.ie_size and (start < entries_end or end > total):
            raise ValueError("IE fuera del buffer BSS")
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
            raise RuntimeError("Native Wi-Fi requiere Windows")
        self.dll = ctypes.WinDLL("wlanapi.dll", winmode=0x800)
        ptr = ctypes.c_void_p
        uint = ctypes.c_uint32
        signatures = {
            "WlanOpenHandle": [uint, ptr, ctypes.POINTER(uint), ctypes.POINTER(ptr)],
            "WlanCloseHandle": [ptr, ptr],
            "WlanEnumInterfaces": [ptr, ptr, ctypes.POINTER(ptr)],
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

    def interfaces(self):
        ptr = ctypes.c_void_p()
        self.check(
            self.dll.WlanEnumInterfaces(self.handle, None, ctypes.byref(ptr)), "WlanEnumInterfaces"
        )
        try:
            if not ptr.value:
                raise RuntimeError("WlanEnumInterfaces devolvió un buffer vacío")
            count = ctypes.c_uint32.from_address(ptr.value).value
            if count > 1024:
                raise ValueError("Demasiadas interfaces WLAN")
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
                return "Windows no confirmó la actualización en 15 s; los resultados pueden proceder de caché."
            if outcome[-1] == 8:
                return "Windows notificó un fallo de actualización; se conserva la caché BSS disponible."
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
                raise RuntimeError("WlanGetNetworkBssList devolvió un buffer vacío")
            size = ctypes.c_uint32.from_address(ptr.value).value
            if not 8 <= size <= 64 * 1024 * 1024:
                raise ValueError("Buffer BSS de tamaño no válido")
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
            "Instala Npcap con Support raw 802.11 traffic (and monitor mode); falta WlanHelper.exe."
        )
    guid = str(uuid.UUID(guid.strip("{}")))
    if setting not in {"mode", "modes", "channel", "freq"} or (
        value is not None and setting not in {"channel", "freq"}
    ):
        raise ValueError("Operación WlanHelper no permitida")
    command = [path, guid, setting]
    if value is not None:
        command.append(str(int(value)))
    result = run_quiet(command, timeout=10)
    if result is None or result.returncode:
        raise RuntimeError(
            "WlanHelper no pudo consultar/configurar el adaptador. Abre PowerShell como administrador y revisa Npcap/controlador."
        )
    return result.stdout.strip()


def detect_windows_interfaces():
    with WindowsWlan() as wlan:
        interfaces = wlan.interfaces()
    for iface in interfaces:
        if not wlan_helper_path():
            iface["monitor_note"] = (
                "Npcap/WlanHelper no instalado; disponible descubrimiento nativo."
            )
            continue
        try:
            mode = wlan_helper(iface["guid"], "mode").casefold()
            iface["mode"] = mode if mode in {"monitor", "managed"} else "unknown"
            iface["capabilities"] = [
                m.strip() for m in wlan_helper(iface["guid"], "modes").split(",")
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
            "Para descubrir redes con Windows usa una interfaz managed; el monitor se selecciona después para la prueba WPS."
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
        "Datos BSS/IE del controlador Windows; no son una captura PCAP. La API puede usar caché."
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
        raise RuntimeError(
            "iw no puede consultar las interfaces; revisa permisos, controlador y rfkill."
        )
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
    return interfaces


def require_isolated_monitor(iface, interfaces):
    if iface["mode"] != "monitor":
        raise RuntimeError(
            "Selecciona una interfaz ya preparada en modo monitor; consulta el README."
        )
    if not iface.get("phy"):
        raise RuntimeError("No se conoce el PHY; no se puede comprobar si comparte la radio.")
    siblings = [
        i["name"] for i in interfaces if i["phy"] == iface["phy"] and i["name"] != iface["name"]
    ]
    if siblings:
        raise RuntimeError(
            "La radio está compartida con "
            + ", ".join(siblings)
            + ". Usa un adaptador dedicado para no alterar otras conexiones."
        )


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
            "La copia del detector no coincide con el commit fijado. Restaura vendor/broadcom-wps."
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
            "Instala Scapy en este intérprete: python -m pip install -r requirements.txt"
        ) from error
    return module


def rsn_akms(body):
    if len(body) < 8:
        raise ValueError("RSN truncado")
    count = int.from_bytes(body[6:8], "little")
    offset = 8 + 4 * count
    if offset + 2 > len(body):
        raise ValueError("RSN sin AKM")
    count = int.from_bytes(body[offset : offset + 2], "little")
    offset += 2
    if offset + 4 * count > len(body):
        raise ValueError("AKM truncado")
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
        "Captura pasiva 802.11",
        pcap_path.with_suffix(".log"),
        timeout=seconds,
        stop_after_timeout=True,
    )
    if result.returncode:
        raise RuntimeError("tcpdump falló; revisa " + str(pcap_path.with_suffix(".log")))
    if not pcap_path.exists() or pcap_path.stat().st_size < 24:
        raise RuntimeError("tcpdump no produjo un PCAP válido; revisa el log y el controlador.")


def set_frequency(interface, frequency):
    result = run_quiet(["iw", "dev", interface, "set", "freq", str(frequency)], timeout=10)
    if result is None or result.returncode:
        detail = result.stderr.strip() if result else "timeout"
        raise RuntimeError(f"No se pudo seleccionar {frequency} MHz: {detail}")


def monitor_discovery(iface, interfaces, folder, limitations):
    require_linux(root=True)
    require_isolated_monitor(iface, interfaces)
    upstream = load_upstream()
    from scapy.utils import PcapReader

    original = iface["frequency_mhz"]
    if not original:
        raise RuntimeError("Configura un canal inicial en la interfaz monitor; consulta el README.")
    frequencies = [f["frequency_mhz"] for f in iface["frequencies"] if not f["disabled"]]
    if not frequencies:
        frequencies = [original]
        limitations.append(
            "No se pudo consultar la lista de canales: solo se capturó el canal actual."
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
            limitations.append("Restauración de frecuencia fallida: " + str(error))
    limitations.append(
        "Captura pasiva por canal; SSID ocultos o AP sin beacons durante la ventana pueden faltar."
    )
    return stable_ap_ids(aps)


def discover_wifi(iface, interfaces, folder, limitations):
    if iface.get("backend") == "windows":
        return discover_windows_wifi(iface, folder, limitations)
    if iface["mode"] == "monitor":
        return monitor_discovery(iface, interfaces, folder, limitations)
    if iface["mode"] != "managed":
        raise RuntimeError("Descubrimiento compatible con interfaces managed o monitor.")
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
        "iw scan no disponible; nmcli puede devolver su caché y no expone WPS ni RSSI en dBm."
    )
    if not shutil.which("nmcli"):
        raise RuntimeError(
            "iw scan falló y falta nmcli. Revisa iw_scan.log, permisos y rfkill; instala network-manager."
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
        raise RuntimeError("nmcli falló; revisa nmcli_scan.log y el estado de NetworkManager.")
    return parse_nmcli(result.stdout)


def show_wifi(aps):
    print(tint("\nPOLTERHEIST :: WIRELESS DISCOVERY"))
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


def select_item(items, label, key="name"):
    if not items:
        return None
    mapping = {str(item.get("id", index)): item for index, item in enumerate(items, 1)}
    for number, item in mapping.items():
        label_value = item.get("display_name", item[key]) if key == "name" else item[key]
        print(f"  [{number}] {safe_text(label_value)}")
    while True:
        choice = input(f"  {label} (q volver): ").strip().lower()
        if choice == "q":
            return None
        if choice in mapping:
            return mapping[choice]
        print("  ID no válido.")


def authorize_target(ap):
    print(
        f"  Objetivo: SSID={safe_text(repr(ap['ssid']))} | BSSID={ap['bssid']} | canal={ap['channel']}"
    )
    print("  El detector enviará una prueba WPS activa únicamente a este BSSID.")
    print(
        "  La limpieza por desautenticación está bloqueada; la sesión puede esperar al timeout del AP."
    )
    expected = "AUTORIZO " + ap["bssid"]
    return (
        input(f"  Escribe {expected} si tienes autorización (INTRO cancela): ").strip().casefold()
        == expected.casefold()
    )


def assessment_from_upstream(document, ap):
    target = document.get("target", {})
    if target.get("bssid", "").lower() != ap["bssid"].lower() or target.get("ssid") != ap["ssid"]:
        return "ERROR"
    return {
        "LIKELY_VULNERABLE": "LIKELY_VULNERABLE",
        "PATCHED_HOSTAPD": "NOT_VULNERABLE_PER_DETECTOR",
        "NO_BROADCOM_FINGERPRINT": "NOT_VULNERABLE_PER_DETECTOR",
        "INCONCLUSIVE": "INCONCLUSIVE",
    }.get(document.get("assessment"), "INCONCLUSIVE")


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
            "El SSID/BSSID seleccionado no se ha observado en su canal; vuelve a descubrir."
        )
    return observations[-1]


def require_windows_monitor(ap, iface):
    if sys.platform != "win32":
        raise RuntimeError("El transporte Npcap requiere Windows")
    if not ctypes.windll.shell32.IsUserAnAdmin():
        raise RuntimeError("Para evaluar WPS con Npcap, abre PowerShell como administrador.")
    if not ap.get("frequency_mhz") or not 2412 <= ap["frequency_mhz"] <= 2484:
        raise RuntimeError(
            "La prueba WPS en Windows admite 2.4 GHz; para 5 GHz utiliza Linux. El detector no admite 6 GHz."
        )
    if not ap.get("channel") or frequency_channel(ap["frequency_mhz"]) != ap["channel"]:
        raise RuntimeError("Canal/frecuencia del objetivo incoherente")
    if iface.get("connected"):
        raise RuntimeError(
            "El adaptador sigue conectado. Prepara manualmente un adaptador dedicado en modo monitor."
        )
    if not MAC.fullmatch(ap["bssid"]) or not ap["ssid"] or len(ap["ssid"].encode("utf-8")) > 32:
        raise ValueError("SSID/BSSID no válido para el detector")
    if ap.get("ssid_hex") and ap["ssid"].encode("utf-8").hex() != ap["ssid_hex"]:
        raise ValueError("El SSID no es UTF-8; el detector upstream requiere un SSID UTF-8 exacto.")
    if ap.get("in_reg_domain") is False:
        raise RuntimeError("Windows indica que el AP está fuera del dominio regulatorio.")
    mode = wlan_helper(iface["guid"], "mode").casefold()
    channel = wlan_helper(iface["guid"], "channel")
    if mode != "monitor" or channel != str(ap["channel"]):
        raise RuntimeError(
            f"Prepara manualmente el adaptador en modo monitor y canal {ap['channel']}. No se ha cambiado tu conexión."
        )


def open_windows_monitor_socket(capture_name):
    from scapy.config import conf

    if not conf.use_pcap:
        raise RuntimeError(
            "Scapy no encuentra Npcap. Instálalo con soporte raw 802.11 y reinicia la terminal."
        )
    socket = conf.L2socket(iface=capture_name, monitor=True)
    try:
        if socket.pcap_fd.datalink() != 127:
            raise RuntimeError(
                "Npcap no entrega Radiotap/802.11; no se puede ejecutar la prueba WPS con tramas Ethernet."
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
            raise RuntimeError("El detector intentó cambiar de interfaz/canal")
        if wlan_helper(iface["guid"], "mode") != "monitor" or wlan_helper(
            iface["guid"], "channel"
        ) != str(requested):
            raise RuntimeError(
                "El modo/canal cambió durante la prueba; vuelve a preparar el adaptador."
            )

    def pinned_send(packet, **kwargs):
        if kwargs.pop("iface", None) != iface["name"]:
            raise RuntimeError("Interfaz de transmisión distinta a la seleccionada")
        return send(packet, iface=capture_name, socket=socket, **kwargs)

    def pinned_sniff(**kwargs):
        if kwargs.pop("iface", None) != iface["name"]:
            raise RuntimeError("Interfaz de captura distinta a la seleccionada")
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
    }
    if not authorized:
        return result
    writer = None
    try:
        require_windows_monitor(ap, iface)
        upstream = load_upstream()
        with (
            windows_upstream_transport(upstream, iface, ap),
            Spinner("WPS / Npcap / " + ap["bssid"]),
        ):
            writer = upstream.PcapWriter(str(folder / "fingerprint.pcap"), linktype=127, sync=True)
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
        result.update(classification="INCONCLUSIVE", error="Interrumpido por el operador")
    except Exception as error:
        result.update(classification="ERROR", error=f"{type(error).__name__}: {error}")
    finally:
        if writer is not None:
            try:
                writer.close()
            except Exception as error:
                result["limitations"].append("Error cerrando PCAP: " + str(error))
    result["limitations"].extend(
        [
            "Windows/Npcap: modo monitor y canal 2.4 GHz preparados manualmente; no se cambian desde la aplicación.",
            "Recepción/inyección dependen de Npcap y del controlador. La ausencia de respuesta no demuestra que el AP sea seguro.",
            "Desautenticación bloqueada en transporte: cleanup_sent=false; se conserva target_health upstream.",
        ]
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
    if not authorized:
        return result
    state = None
    writer = None
    upstream = None
    try:
        require_linux(root=True)
        require_isolated_monitor(iface, interfaces)
        if not MAC.fullmatch(ap["bssid"]):
            raise ValueError("BSSID no válido")
        if not ap["ssid"] or len(ap["ssid"].encode("utf-8")) > 32:
            raise ValueError("SSID oculto/no válido; se necesita el SSID exacto")
        frequency = ap.get("frequency_mhz")
        if frequency is None or frequency >= 5925 or not ap.get("channel"):
            raise RuntimeError(
                "El detector fijado requiere un canal conocido en 2.4/5 GHz; 6 GHz no está soportado."
            )
        supported = next((f for f in iface["frequencies"] if f["frequency_mhz"] == frequency), None)
        if not supported or supported["disabled"] or supported["no_ir"] or supported["radar"]:
            raise RuntimeError(
                "El canal no admite esta prueba activa según capacidades/regulación (disabled/no IR/DFS)."
            )
        upstream = load_upstream()
        state = upstream.inspect_monitor_interface(iface["name"])
        if state.channel is None or not iface.get("frequency_mhz"):
            raise RuntimeError("No se conoce el canal original; no se puede restaurar la radio.")
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
            "Desautenticación bloqueada en transporte: cleanup_sent=false; se conserva target_health upstream."
        )
    except (KeyboardInterrupt, EOFError):
        result.update(classification="INCONCLUSIVE", error="Interrumpido por el operador")
    except Exception as error:
        result.update(classification="ERROR", error=f"{type(error).__name__}: {error}")
    finally:
        if writer is not None:
            try:
                writer.close()
            except Exception as error:
                result["limitations"].append("Error cerrando PCAP: " + str(error))
        if state is not None and iface.get("frequency_mhz"):
            try:
                set_frequency(iface["name"], iface["frequency_mhz"])
            except Exception as error:
                result["limitations"].append("No se pudo restaurar el canal: " + str(error))
    return result


def write_wireless_report(folder, report):
    report["updated_at"] = utc_now()
    artifacts = []
    for path in sorted(folder.iterdir()):
        if path.is_file() and path.name not in {"report.json", "report.json.tmp"}:
            with path.open("rb") as source:
                digest = hashlib.file_digest(source, "sha256").hexdigest()
            artifacts.append({"path": path.name, "bytes": path.stat().st_size, "sha256": digest})
    report["artifacts"] = artifacts
    dump_json(folder / "report.json", report)


def wireless_recon():
    if sys.platform != "win32":
        require_linux()
    interfaces = detect_wireless_interfaces()
    if not interfaces:
        raise RuntimeError(
            "No hay interfaces Wi-Fi. Revisa la radio, WlanSvc (Windows), rfkill (Linux), firmware y controladores. "
            "En VirtualBox necesitas USB Wi-Fi passthrough; Ethernet puenteada no captura 802.11."
        )
    print(tint("\nPOLTERHEIST :: WIRELESS INTERFACES"))
    for iface in interfaces:
        print(
            f"  {safe_text(iface.get('display_name', iface['name']))} | {iface['mode']} | PHY={iface['phy']} | "
            f"driver={safe_text(iface['driver'])} | modos={', '.join(iface['capabilities'])} | conectada={iface['connected']}"
        )
        if iface.get("monitor_note"):
            print("    " + safe_text(iface["monitor_note"]))
    iface = select_item(interfaces, "Interfaz para descubrimiento")
    if iface is None:
        return
    folder = report_folder("wireless")
    report = {
        "tool": "POLTERHEIST",
        "version": VERSION,
        "upstream_commit": UPSTREAM_COMMIT,
        "timestamp": utc_now(),
        "interfaces": interfaces,
        "discovery_interface": iface["name"],
        "access_points": [],
        "selected_target": None,
        "assessment": "NOT_TESTED",
        "original_fingerprint": None,
        "authorization": None,
        "status": "running",
        "technical_limitations": [],
        "remediation": [
            "Consultar actualizaciones del fabricante/ISP para el modelo y firmware exactos.",
            "Desactivar WPS si no es necesario y confirmar la mitigación con el fabricante.",
            "Sustituir equipos sin soporte si no existe una corrección.",
            "El fingerprint no confirma ejecución de código ni una vulnerabilidad explotable.",
        ],
    }
    write_wireless_report(folder, report)
    try:
        aps = discover_wifi(iface, interfaces, folder, report["technical_limitations"])
        report["access_points"] = aps
        dump_json(folder / "discovery.json", aps)
        show_wifi(aps)
        report["status"] = "discovered"
        write_wireless_report(folder, report)
        if not aps:
            print("  Sin AP observados. Revisa antena, banda, canal, rfkill y permisos.")
            return
        target = select_item(aps, "ID del AP para evaluar WPS", "bssid")
        if target is None:
            return
        report["selected_target"] = dict(target)
        write_wireless_report(folder, report)
        # Re-read immediately before authorization: never trust stale radio topology.
        current = detect_wireless_interfaces()
        monitors = [i for i in current if i["mode"] == "monitor"]
        if not monitors and iface.get("backend") == "windows" and wlan_helper_path():
            print(
                "  Prepara manualmente un adaptador dedicado en modo monitor y en el canal del AP (README)."
            )
            if (
                input(
                    "  INTRO para volver a buscar interfaces monitor; q para guardar sin evaluar: "
                )
                .strip()
                .lower()
                != "q"
            ):
                current = detect_wireless_interfaces()
                monitors = [i for i in current if i["mode"] == "monitor"]
        if not monitors:
            report["technical_limitations"].append(
                "NOT_TESTED: no hay una interfaz monitor preparada."
            )
            print(
                "  NOT_TESTED: necesitas un adaptador dedicado ya en modo monitor. Consulta el README."
            )
            return
        monitor = select_item(monitors, "Interfaz monitor para el detector")
        if monitor is None:
            return
        if monitor.get("backend") != "windows":
            require_isolated_monitor(monitor, current)
        authorized = authorize_target(target)
        report["authorization"] = {
            "granted": authorized,
            "ssid": target["ssid"],
            "bssid": target["bssid"],
            "timestamp": utc_now(),
        }
        report["fingerprint_interface"] = monitor["name"]
        write_wireless_report(folder, report)
        if not authorized:
            report["technical_limitations"].append("NOT_TESTED: el operador no autorizó el BSSID.")
            return
        outcome = fingerprint_selected(target, monitor, current, folder, authorized=True)
        target["assessment"] = outcome["classification"]
        report["selected_target"] = dict(target)
        report["assessment"] = outcome["classification"]
        report["original_fingerprint"] = outcome["original"]
        report["error"] = outcome["error"]
        report["technical_limitations"].extend(outcome["limitations"])
        report["status"] = "assessed"
        if outcome["original"]:
            identity = outcome["original"].get("target", {}).get("wps_identity", {})
            report["manufacturer_evidence"] = target["manufacturer_evidence"] + [
                {"source": "upstream WPS identity", "value": identity}
            ]
        if outcome["error"]:
            print(tint("  " + safe_text(outcome["error"]), AMBER))
        show_wifi([target])
    except (KeyboardInterrupt, EOFError):
        report["status"] = "cancelled"
        print("\n  Cancelado; se conservan las evidencias disponibles.")
    except Exception as error:
        report.update(status="error", error=str(error))
        raise
    finally:
        write_wireless_report(folder, report)
        print(f"  Informe y evidencias: {folder}")


def load_profile(path=None):
    path = PROFILE_PATH if path is None else Path(path)
    if not path.exists():
        dump_json(path, {key: "" for key in PROFILE_FIELDS})
    profile = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(profile, dict) or any(
        not isinstance(profile.get(k, ""), str) for k in PROFILE_FIELDS
    ):
        raise ValueError("El perfil debe ser un objeto JSON con campos de texto: " + str(path))
    return {key: profile.get(key, "") for key in PROFILE_FIELDS}


def who_am_i():
    while True:
        profile = load_profile()
        print(tint("\nPOLTERHEIST :: WHO AM I?"))
        for key, label in PROFILE_FIELDS.items():
            print(f"  {label}: {safe_text(profile[key]) or '[sin configurar]'}")
        choice = input("  [e] Editar perfil | [q/INTRO] Volver: ").strip().lower()
        if choice != "e":
            return
        print("  INTRO mantiene el valor; un guion (-) lo borra.")
        updated = dict(profile)
        for key, label in PROFILE_FIELDS.items():
            value = input(f"  {label}: ").strip()
            if value:
                updated[key] = "" if value == "-" else value
        dump_json(PROFILE_PATH, updated)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="POLTERHEIST: reconocimiento LAN y Wi-Fi autorizado"
    )
    parser.add_argument("--version", action="version", version="POLTERHEIST " + VERSION)
    parser.add_argument("--check", action="store_true", help="Diagnóstico local; no escanea la red")
    parser.add_argument(
        "--wireless",
        "--wpscan",
        action="store_true",
        help="Abrir directamente el descubrimiento Wi-Fi y la evaluación WPS",
    )
    options = parser.parse_args(argv)
    if options.check:
        print(
            "POLTERHEIST " + VERSION + " | Python " + sys.version.split()[0] + " | " + sys.platform
        )
        if sys.platform == "win32":
            print("  Descubrimiento Wi-Fi/WPS: API nativa de Windows (sin WSL/Nmap)")
            print(
                "  Npcap / WlanHelper: "
                + (wlan_helper_path() or "no instalado; necesario para fingerprint activo")
            )
            try:
                for iface in detect_windows_interfaces():
                    print(
                        f"  {safe_text(iface['display_name'])} | GUID={iface['guid']} | modo={iface['mode']}"
                    )
                    if iface.get("monitor_note"):
                        print("    " + safe_text(iface["monitor_note"]))
            except (OSError, ValueError, RuntimeError) as error:
                print("  Wi-Fi: " + safe_text(error))
        else:
            for binary in ("nmap", "arp-scan", "ip", "iw", "nmcli", "tcpdump"):
                print(f"  {binary}: {shutil.which(binary) or 'no encontrado'}")
        try:
            load_upstream()
            print("  Detector upstream: hash verificado, Scapy disponible")
        except (OSError, ValueError, RuntimeError) as error:
            print("  Detector: " + str(error))
        return 0
    print(tint(BANNER))
    print(tint(f"  POLTERHEIST :: WATCHING THE WIRE :: v{VERSION}", AMBER))
    if options.wireless:
        try:
            wireless_recon()
            return 0
        except (KeyboardInterrupt, EOFError):
            return 130
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            print(tint("  [!] " + safe_text(error), AMBER))
            return 1
    while True:
        print(tint("\n[0] WHO AM I?\n[1] LAN RECON\n[2] WIRELESS RECON\n\n[q] EXIT"))
        try:
            choice = input("  > ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print("\n  Hasta pronto.")
            return 0
        if choice == "q":
            return 0
        action = {"0": who_am_i, "1": lan_recon, "2": wireless_recon}.get(choice)
        if action is None:
            print("  Opción no válida.")
            continue
        try:
            action()
        except (KeyboardInterrupt, EOFError):
            print("\n  Volviendo al menú.")
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            print(tint("  [!] " + safe_text(error), AMBER))


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.exit(main())
