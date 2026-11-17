"""Step one: bounded, read-only TV identification on the explicitly selected LAN host."""

import json
import plistlib
import re
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field

from .models import Config, Endpoint
from .network import detect_network, local_request, parse_xml
from .protocols import airplay, dlna, google_cast
from .scopes import route_to


@dataclass
class TVProfile:
    target: str
    network: object
    endpoints: list = field(default_factory=list)
    probes: list = field(default_factory=list)
    ports: list = field(default_factory=list)

    @property
    def family(self):
        protocols = {e.protocol for e in self.endpoints}
        if "Samsung Remote" in protocols:
            return "Samsung Tizen"
        if "webOS" in protocols:
            return "LG webOS"
        if "Roku ECP" in protocols:
            return "Roku OS"
        if "Android TV Remote" in protocols:
            return "Android TV / Google TV"
        text = " ".join(f"{e.manufacturer} {e.model}" for e in self.endpoints).lower()
        if "appletv" in text:
            return "Apple TV / tvOS"
        if "fire tv" in text or re.search(r"\baft[a-z0-9_-]+\b", text):
            return "Amazon Fire TV (advertised identity)"
        if "Google Cast" in protocols:
            return "Google Cast receiver (OS unverified)"
        # Brands span several operating systems. Never classify by brand alone.
        return "TV / media receiver (OS unverified)" if self.endpoints else "Unidentified"

    def document(self):
        return {
            "target": self.target,
            "source_ip": self.network.ip,
            "family": self.family,
            "devices": [asdict(e) for e in self.endpoints],
            "probes": self.probes,
            "open_ports": self.ports,
            "note": "An open port is not proof of protocol support or installation permission.",
        }


def mdns(network, config, target):
    from zeroconf import IPVersion, ServiceBrowser, Zeroconf

    services = [
        google_cast.SERVICE,
        airplay.SERVICES[0],
        "_webostv._tcp.local.",
        "_androidtvremote2._tcp.local.",
        "_adb-tls-connect._tcp.local.",
    ]
    found = {}
    lock = threading.Lock()
    deadline = time.monotonic() + config.discovery_timeout

    class Listener:
        def add_service(self, zc, type_, name):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            info = zc.get_service_info(type_, name, timeout=min(400, remaining * 1000))
            if not info or target not in info.parsed_addresses():
                return
            if type_ == google_cast.SERVICE:
                endpoint = google_cast.from_service(info, network)
            elif type_ == airplay.SERVICES[0]:
                endpoint = airplay.from_service(info, network, type_)
            else:
                protocol = {
                    services[2]: "webOS",
                    services[3]: "Android TV Remote",
                    services[4]: "ADB TLS",
                }[type_]
                endpoint = Endpoint(
                    protocol, name, target, info.port, name=name, sources=["mDNS"], evidence=[type_]
                )
            if endpoint and endpoint.ip == target:
                with lock:
                    found[(endpoint.protocol, endpoint.uid)] = endpoint

        update_service = add_service

        def remove_service(self, zc, type_, name):
            pass

    zc = Zeroconf(interfaces=[network.ip], ip_version=IPVersion.V4Only)
    browser = None
    try:
        browser = ServiceBrowser(zc, services, Listener())
        threading.Event().wait(max(0, deadline - time.monotonic()))
    finally:
        if browser:
            browser.cancel()
        zc.close()
    return list(found.values())


def samsung(network, config, target):
    code, raw = local_request(
        f"http://{target}:8001/api/v2/", target, network, config.request_timeout
    )
    data = json.loads(raw)
    device = data.get("device", {})
    if code != 200 or not device.get("modelName") or not device.get("id"):
        return []
    return [
        Endpoint(
            "Samsung Remote",
            device["id"],
            target,
            8002,
            name=data.get("name", "Samsung TV"),
            model=device["modelName"],
            manufacturer="Samsung",
            evidence=["Samsung /api/v2 device JSON"],
            details={"os": device.get("OS", "Unknown")},
        )
    ]


def roku(network, config, target):
    code, raw = local_request(
        f"http://{target}:8060/query/device-info", target, network, config.request_timeout
    )
    info = parse_xml(raw)
    if code != 200 or info.tag != "device-info" or not info.findtext("model-number"):
        return []
    return [
        Endpoint(
            "Roku ECP",
            info.findtext("udn", target),
            target,
            8060,
            name=info.findtext("friendly-device-name", "Roku"),
            model=info.findtext("model-name", "Unknown"),
            manufacturer="Roku",
            evidence=["Roku ECP device-info XML"],
            details={
                "developer_enabled": info.findtext("developer-enabled", "unknown"),
                "software_version": info.findtext("software-version", "unknown"),
            },
        )
    ]


def airplay_http(network, config, target):
    code, raw = local_request(f"http://{target}:7000/info", target, network, config.request_timeout)
    data = plistlib.loads(raw)
    if (
        code != 200
        or not isinstance(data, dict)
        or not data.get("deviceID")
        or "features" not in data
    ):
        return []
    return [
        Endpoint(
            "AirPlay",
            str(data["deviceID"]),
            target,
            7000,
            name=str(data.get("name", "AirPlay")),
            model=str(data.get("model", "Unknown")),
            evidence=["AirPlay /info plist"],
            details={"features": str(data["features"])},
        )
    ]


def webos_hello(network, config, target):
    from .payload_adapters import receive, websocket_connect

    ws = websocket_connect(target, 3001, "/", config.request_timeout)
    try:
        ws.send(json.dumps({"id": "hello", "type": "hello"}))
        message = receive(ws, time.monotonic() + config.request_timeout)
        data = message.get("payload", {})
        if message.get("type") != "hello" or not data.get("deviceUUID"):
            return []
        return [
            Endpoint(
                "webOS",
                data["deviceUUID"],
                target,
                3001,
                name=data.get("deviceName", "LG TV"),
                model=data.get("deviceModel", "Unknown"),
                manufacturer="LG",
                evidence=["Unauthenticated webOS hello (no registration/pairing)"],
            )
        ]
    finally:
        ws.close()


def sony(network, config, target):
    body = json.dumps({"method": "getSystemInformation", "params": [], "id": 1, "version": "1.0"})
    code, raw = local_request(
        f"http://{target}/sony/system",
        target,
        network,
        config.request_timeout,
        body=body.encode(),
        headers={"Content-Type": "application/json"},
    )
    data = json.loads(raw)
    results = data.get("result", [])
    if (
        code != 200
        or not results
        or not isinstance(results[0], dict)
        or not results[0].get("model")
    ):
        return []
    info = results[0]
    return [
        Endpoint(
            "Sony ScalarWebAPI",
            "sony:" + target,
            target,
            80,
            name=info.get("name", "Sony TV"),
            model=info["model"],
            manufacturer="Sony",
            evidence=["ScalarWebAPI getSystemInformation response (OS not inferred)"],
        )
    ]


def philips(network, config, target):
    code, raw = local_request(
        f"http://{target}:1925/1/system", target, network, config.request_timeout
    )
    data = json.loads(raw)
    if code != 200 or not data.get("model") or not data.get("name"):
        return []
    return [
        Endpoint(
            "Philips JointSpace",
            "jointspace:" + target,
            target,
            1925,
            name=data["name"],
            model=data["model"],
            manufacturer="Philips",
            evidence=["JointSpace system metadata (control/OS unverified)"],
        )
    ]


def detect(target, config=None, adb_port=5555):
    config = config or Config(discovery_timeout=3, request_timeout=2)
    if type(adb_port) is not int or not 1 <= adb_port <= 65535:
        raise ValueError("Invalid ADB port")
    route = route_to(target, config.bind_ip)
    network = detect_network(route.ip)
    target = network.target(target)
    profile = TVProfile(target, network)
    probes = {
        "cast": lambda: google_cast.discover(network, config, target),
        "cast_description": lambda: dlna.describe(
            f"http://{target}:8008/ssdp/device-desc.xml",
            target,
            network,
            config,
            include_other=True,
        ),
        "upnp": lambda: dlna.discover(network, config, target),
        "mdns": lambda: mdns(network, config, target),
        "samsung": lambda: samsung(network, config, target),
        "roku": lambda: roku(network, config, target),
        "airplay": lambda: airplay_http(network, config, target),
        "webos": lambda: webos_hello(network, config, target),
        "sony": lambda: sony(network, config, target),
        "philips": lambda: philips(network, config, target),
    }

    def port_check(port):
        with socket.create_connection(
            (target, port), timeout=config.request_timeout, source_address=(network.ip, 0)
        ):
            return port

    with ThreadPoolExecutor(max_workers=10) as pool:
        jobs = {pool.submit(probe): name for name, probe in probes.items()}
        ports = {pool.submit(port_check, port): port for port in (adb_port, 26101, 9922, 3001)}
        for future in as_completed({**jobs, **ports}):
            if future in ports:
                try:
                    profile.ports.append(future.result())
                except OSError:
                    pass
                continue
            name = jobs[future]
            try:
                endpoints = future.result()
                profile.endpoints.extend(e for e in endpoints if e.ip == target)
                profile.probes.append(
                    {"probe": name, "state": "DETECTED" if endpoints else "NO_RESPONSE"}
                )
            except Exception as error:
                profile.probes.append(
                    {"probe": name, "state": "UNAVAILABLE", "detail": str(error)[:500]}
                )
    # Keep the strongest capability record for each protocol/identity.
    merged = {}
    for endpoint in profile.endpoints:
        key = (endpoint.protocol, endpoint.uid)
        if key not in merged or endpoint.controllable:
            merged[key] = endpoint
    profile.endpoints = sorted(merged.values(), key=lambda e: (e.protocol, e.uid))
    for cast in (e for e in profile.endpoints if e.protocol == "Google Cast"):
        # Match device UUIDs, not just a shared IP, before enriching legacy Cast info.
        identity = next(
            (
                e
                for e in profile.endpoints
                if e.protocol == "DIAL" and e.uid.removeprefix("uuid:") == cast.uid
            ),
            None,
        )
        if identity:
            for field_name in ("model", "manufacturer"):
                if getattr(cast, field_name) == "Unknown":
                    setattr(cast, field_name, getattr(identity, field_name))
    profile.ports.sort()
    profile.probes.sort(key=lambda p: p["probe"])
    return profile
