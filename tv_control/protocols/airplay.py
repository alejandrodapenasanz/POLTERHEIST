"""Bonjour AirPlay/RAOP observations only. No pairing or playback implementation."""

import ipaddress
import threading
import time

from ..models import Endpoint

SERVICES = ("_airplay._tcp.local.", "_raop._tcp.local.")


def from_service(info, network, service):
    addresses = []
    for raw in info.parsed_addresses()[:32]:
        try:
            address = ipaddress.ip_address(raw)
        except ValueError:
            continue
        if not (address.is_multicast or address.is_unspecified or address.is_loopback):
            addresses.append(str(address))
    ip = next((address for address in addresses if network.accepts(address)), None)
    if not ip or not info.port or not 1 <= info.port <= 65535:
        return None
    # Explicit allowlist: no arbitrary TXT payloads or authentication material in reports.
    properties = {
        key.decode("utf-8", "replace"): (value or b"").decode("utf-8", "replace")[:512]
        for key, value in list(info.properties.items())[:64]
        if key in (b"deviceid", b"model", b"am", b"features", b"ft", b"sf", b"pw", b"srcvers")
    }
    raop = service == SERVICES[1]
    endpoint = Endpoint(
        "RAOP" if raop else "AirPlay",
        info.name,
        ip,
        info.port,
        info.name.removesuffix("." + service)[:256],
        properties.get("model", properties.get("am", "Unknown")),
        kind="Audio receiver" if raop else "AirPlay receiver (media capabilities unverified)",
        note="Discovery only; pairing and playback adapter deferred",
        details={"advertised_txt": properties, "service": service},
        sources=["mDNS/DNS-SD"],
        addresses=addresses,
        reachability="ADVERTISEMENT RECEIVED; TRANSPORT UNTESTED",
        evidence=[service + " service record; feature flags are not runtime verification"],
    )
    if properties.get("pw", "").lower() in ("true", "1"):
        endpoint.authentication = "PASSWORD ADVERTISED; PAIRING UNTESTED"
    return endpoint


def discover(network, config, target=None):
    if target:
        return []  # No guessed ports or mDNS across routed boundaries.
    from zeroconf import IPVersion, ServiceBrowser, Zeroconf

    found, lock = {}, threading.Lock()
    deadline = time.monotonic() + config.discovery_timeout

    class Listener:
        def add_service(self, zc, type_, name):
            with lock:
                if len(found) >= config.max_devices:
                    return
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            info = zc.get_service_info(type_, name, timeout=min(500, remaining * 1000))
            if info:
                endpoint = from_service(info, network, type_)
                if endpoint:
                    with lock:
                        found[(endpoint.protocol, endpoint.uid)] = endpoint

        update_service = add_service

        def remove_service(self, zc, type_, name):
            pass

    zc = Zeroconf(interfaces=[network.ip], ip_version=IPVersion.V4Only)
    browser = None
    try:
        browser = ServiceBrowser(zc, list(SERVICES), Listener())
        threading.Event().wait(max(0, deadline - time.monotonic()))
    finally:
        if browser:
            browser.cancel()
        zc.close()
    return list(found.values())[: config.max_devices]
