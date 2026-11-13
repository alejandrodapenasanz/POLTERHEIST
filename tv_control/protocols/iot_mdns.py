"""Bounded DNS-SD discovery of advertised IoT services; no login or control."""

import ipaddress
import logging
import threading
import time

from ..models import Endpoint

LOG = logging.getLogger(__name__)
# A service identifies an advertised role, never the physical device by its name.
SERVICES = {
    "_hap._tcp.local.": ("HomeKit", "HomeKit accessory"),
    "_hap._udp.local.": ("HomeKit", "HomeKit accessory"),
    "_matter._tcp.local.": ("Matter", "Matter operational node"),
    "_matterc._udp.local.": ("Matter", "Matter commissionable accessory"),
    "_matterd._udp.local.": ("Matter", "Matter commissioner"),
    "_shelly._tcp.local.": ("Shelly", "Smart home device (function unknown)"),
    "_esphomelib._tcp.local.": ("ESPHome", "Programmable IoT node"),
    "_home-assistant._tcp.local.": ("Home Assistant", "Home automation hub"),
    "_ipp._tcp.local.": ("IPP", "Printer"),
    "_ipps._tcp.local.": ("IPPS", "Printer"),
    "_printer._tcp.local.": ("LPD", "Printer"),
    "_pdl-datastream._tcp.local.": ("Print service", "Printer"),
    "_mqtt._tcp.local.": ("MQTT", "MQTT broker (not individual sensors)"),
    "_secure-mqtt._tcp.local.": ("MQTT TLS", "MQTT broker (not individual sensors)"),
    "_http._tcp.local.": ("HTTP", "Web service (IoT type unknown)"),
    "_https._tcp.local.": ("HTTPS", "Web service (IoT type unknown)"),
}
HOMEKIT_CATEGORIES = {
    "2": "Home automation bridge",
    "3": "Fan",
    "4": "Garage door opener",
    "5": "Light",
    "6": "Door lock",
    "7": "Smart plug / outlet",
    "8": "Switch",
    "9": "Thermostat",
    "10": "Sensor",
    "11": "Alarm system",
    "12": "Door",
    "13": "Window",
    "14": "Window covering",
    "17": "Camera",
    "18": "Video doorbell",
    "19": "Air purifier",
    "20": "Heater",
    "21": "Air conditioner",
    "22": "Humidifier",
    "23": "Dehumidifier",
    "26": "Speaker",
    "31": "Television",
}
TXT_KEYS = {
    b"md",
    b"model",
    b"ty",
    b"ci",
    b"sf",
    b"gen",
    b"version",
    b"board",
    b"project_name",
    b"project_version",
    b"api_encryption",
    b"DN",
    b"DT",
    b"CM",
}


def from_service(info, network, service):
    if service not in SERVICES or type(info.port) is not int or not 1 <= info.port <= 65535:
        return None
    if (
        not isinstance(info.name, str)
        or not info.name.endswith("." + service)
        or len(info.name) > 512
    ):
        return None
    addresses = []
    for raw in info.parsed_addresses()[:32]:
        try:
            address = ipaddress.ip_address(raw)
        except ValueError:
            continue
        if not (address.is_multicast or address.is_unspecified or address.is_loopback):
            addresses.append(str(address))
    ip = next((a for a in addresses if network.accepts(a)), "")
    # IPv6 seen through this IPv4 mDNS interface is evidence only, not a usable route.
    ipv6 = [a for a in addresses if ipaddress.ip_address(a).version == 6]
    if not ip and (not ipv6 or any(ipaddress.ip_address(a).version == 4 for a in addresses)):
        return None
    txt = {
        k.decode("ascii"): (v or b"").decode("utf-8", "replace")[:256]
        for k, v in list(info.properties.items())[:64]
        if k in TXT_KEYS and isinstance(v, (bytes, type(None)))
    }
    protocol, kind = SERVICES[service]
    authentication = "UNKNOWN; NO LOGIN ATTEMPTED"
    if protocol == "HomeKit":
        kind = HOMEKIT_CATEGORIES.get(txt.get("ci"), kind)
        authentication = "PAIRING / AUTHORIZED CONTROLLER REQUIRED"
    elif protocol == "Matter":
        authentication = "COMMISSIONING / FABRIC CREDENTIALS REQUIRED"
    elif protocol == "ESPHome" and txt.get("api_encryption"):
        authentication = "API ENCRYPTION ADVERTISED; KEY REQUIRED"
    transport = "tcp" if "._tcp." in service else "udp"
    if protocol == "Matter":
        transport = "matter"  # _matter._tcp is not proof of a listening TCP socket.
    details = {
        "service": service,
        "advertised_txt": txt,
        "iot_type": kind,
        "transport": "mdns_ipv6" if not ip else "mdns",
        "service_transport": transport,
        "discovery_interface": network.name,
        "source_ip": network.ip,
    }
    if protocol in ("HTTP", "HTTPS") and ip:
        details["web_url"] = f"{protocol.lower()}://{ip}:{info.port}/"
    return Endpoint(
        protocol,
        f"{network.ip}:{info.name}",
        ip,
        info.port,
        txt.get("DN") or info.name.removesuffix("." + service)[:256],
        txt.get("model") or txt.get("md") or txt.get("ty") or "Unknown",
        kind=kind,
        note="Advertised service; no control adapter or authenticated session",
        details=details,
        sources=["mDNS/DNS-SD"],
        addresses=addresses,
        reachability="ADVERTISEMENT RECEIVED; CONNECTION UNTESTED"
        if ip
        else "IPv6 OBSERVATION ONLY; CONNECTION UNSUPPORTED",
        authentication=authentication,
        evidence=[service + " service record"]
        + (
            ["HomeKit advertised category " + txt["ci"]]
            if protocol == "HomeKit" and "ci" in txt
            else []
        ),
    )


def discover(network, config, target=None):
    if target:
        return []
    from zeroconf import IPVersion, ServiceBrowser, Zeroconf

    found, lock, stopped = {}, threading.Lock(), threading.Event()
    deadline = time.monotonic() + config.discovery_timeout

    class Listener:
        def add_service(self, zc, type_, name):
            with lock:
                if stopped.is_set() or len(found) >= config.max_devices:
                    return
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            try:
                info = zc.get_service_info(type_, name, timeout=min(500, remaining * 1000))
                endpoint = from_service(info, network, type_) if info else None
                if endpoint:
                    with lock:
                        if not stopped.is_set() and len(found) < config.max_devices:
                            found[(type_, name)] = endpoint
            except (ValueError, TypeError, AttributeError):
                LOG.debug("Ignored malformed IoT DNS-SD service", exc_info=True)

        update_service = add_service

        def remove_service(self, zc, type_, name):
            with lock:
                found.pop((type_, name), None)

    zc = Zeroconf(interfaces=[network.ip], ip_version=IPVersion.V4Only)
    browser = None
    try:
        browser = ServiceBrowser(zc, list(SERVICES), Listener())
        stopped.wait(max(0, deadline - time.monotonic()))
    finally:
        stopped.set()
        try:
            if browser:
                browser.cancel()
        finally:
            zc.close()
    with lock:
        return list(found.values())
