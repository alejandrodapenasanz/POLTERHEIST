"""Evidence-based IoT labels and explicit, bounded transport checks."""

import datetime
import re
import socket
import time

UPNP_TYPES = {
    "MediaRenderer": "Media renderer",
    "MediaServer": "Media server",
    "InternetGatewayDevice": "Router / gateway",
    "WANDevice": "Router / WAN device",
    "LANDevice": "Network infrastructure",
    "WLANAccessPointDevice": "Wi-Fi access point",
    "Printer": "Printer",
    "Scanner": "Scanner",
    "BinaryLight": "Light",
    "DimmableLight": "Dimmable light",
    "HVAC_System": "Climate control",
    "DigitalSecurityCamera": "Camera",
    "SensorManagement": "Sensor controller",
}
TCP_PROTOCOLS = {"Google Cast", "DLNA", "DIAL", "UPnP", "AirPlay", "RAOP"}


def device_type(endpoint):
    if endpoint.details.get("transport") == "ble":
        return "BLE peripheral (type unknown)"
    if endpoint.details.get("iot_type"):
        return endpoint.details["iot_type"]
    if endpoint.details.get("transport") == "p2p":
        return (
            "Wireless display receiver"
            if endpoint.details.get("wfd", {}).get("sink")
            else "P2P peer (type unknown)"
        )
    if endpoint.protocol == "UPnP":
        match = re.fullmatch(
            r"urn:schemas-upnp-org:device:([A-Za-z_]+):\d+", endpoint.details.get("device_type", "")
        )
        return (
            UPNP_TYPES.get(match[1], "UPnP device (type unknown)")
            if match
            else "UPnP device (type unknown)"
        )
    if endpoint.protocol in ("Google Cast", "DLNA", "AirPlay", "RAOP", "DIAL"):
        return endpoint.kind
    return "Unknown IoT / network service"


def access(endpoint, available=True):
    if not available:
        return "UNAVAILABLE / CACHED"
    if endpoint.details.get("transport") == "ble":
        return "GATT CONNECTION AVAILABLE; pairing/access unverified"
    if endpoint.controllable and endpoint.protocol in ("Google Cast", "DLNA"):
        return "MEDIA CONTROL AVAILABLE; session untested"
    if endpoint.details.get("transport") == "p2p":
        return (
            "MIRACAST NOT IMPLEMENTED"
            if endpoint.details.get("wfd", {}).get("sink")
            else "P2P ONLY; no control adapter"
        )
    if not endpoint.ip:
        return "IPv6 OBSERVATION; connection unsupported"
    if endpoint.protocol in ("HomeKit", "Matter"):
        return "PAIRING / CONTROLLER REQUIRED; not integrated"
    if endpoint.details.get("web_url"):
        return "WEB INTERFACE ADVERTISED; login unverified"
    return "EXTERNAL CLIENT REQUIRED; discovery only"


def summary(device):
    kinds = list(dict.fromkeys(device_type(e) for e in device.endpoints))
    if len(kinds) > 1:
        specific = [k for k in kinds if "unknown" not in k.lower()]
        kinds = specific or kinds
    return {
        "type": " / ".join(kinds),
        "classification": "Advertised role; physical identity unverified",
        "connection": list(dict.fromkeys(access(e, device.available) for e in device.endpoints)),
        "control_available": device.controllable,
        "protocols": list(dict.fromkeys(e.protocol for e in device.endpoints)),
    }


def tcp_candidates(device, network):
    if not device.available:
        raise ValueError("Device is stale/unavailable; repeat discovery first")
    if network is None:
        raise ValueError("An IPv4 LAN is required for connection checks")
    candidates = {}
    for endpoint in device.endpoints:
        if (
            not network.accepts(endpoint.ip)
            or type(endpoint.port) is not int
            or not 1 <= endpoint.port <= 65535
        ):
            continue
        transport = endpoint.details.get("service_transport")
        if transport == "tcp" or (transport is None and endpoint.protocol in TCP_PROTOCOLS):
            candidates.setdefault((endpoint.ip, endpoint.port), []).append(endpoint)
    return candidates


def check_connections(device, network, config, confirmed=False):
    if not confirmed:
        raise ValueError("Select the connection-check action before testing advertised services")
    candidates = tcp_candidates(device, network)
    deadline = time.monotonic() + min(8, config.connect_timeout)
    results = []
    for index, ((ip, port), endpoints) in enumerate(candidates.items()):
        remaining = deadline - time.monotonic()
        result = {
            "ip": ip,
            "port": port,
            "status": "NOT CHECKED",
            "error": "",
            "observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "meaning": "TCP handshake only; not login, pairing or control authorization",
        }
        if index >= 4 or remaining <= 0:
            result["error"] = "Per-device check budget reached (four ports / eight seconds maximum)"
        else:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as channel:
                    channel.settimeout(min(2, remaining))
                    channel.bind((network.ip, 0))
                    channel.connect((ip, port))
                result["status"] = "TCP REACHABLE"
            except OSError as error:
                result.update(status="TCP UNREACHABLE", error=str(error)[:256])
        for endpoint in endpoints:
            endpoint.details["connection_check"] = result.copy()
        results.append(result)
    return results
