#!/usr/bin/env python3
"""POLTERHEIST: inventario LAN y reconocimiento Wi-Fi autorizado (Kali Linux)."""

import argparse
import csv
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
from pathlib import Path

VERSION = "2.0.0"
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
            "El reconocimiento requiere Kali/Linux. El menú y las pruebas funcionan aquí."
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
        print(f"  [{number}] {safe_text(item[key])}")
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


def fingerprint_selected(ap, iface, interfaces, folder, authorized=False):
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
    require_linux()
    interfaces = detect_wireless_interfaces()
    if not interfaces:
        raise RuntimeError(
            "No hay interfaces Wi-Fi. Revisa rfkill, firmware y controladores. "
            "En VirtualBox necesitas USB Wi-Fi passthrough; Ethernet puenteada no captura 802.11."
        )
    print(tint("\nPOLTERHEIST :: WIRELESS INTERFACES"))
    for iface in interfaces:
        print(
            f"  {safe_text(iface['name'])} | {iface['mode']} | PHY={iface['phy']} | "
            f"driver={safe_text(iface['driver'])} | modos={', '.join(iface['capabilities'])} | conectada={iface['connected']}"
        )
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
    options = parser.parse_args(argv)
    if options.check:
        print(
            "POLTERHEIST " + VERSION + " | Python " + sys.version.split()[0] + " | " + sys.platform
        )
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
