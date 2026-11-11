"""Bounded SSDP discovery and standard UPnP AVTransport SOAP actions."""

import logging
import re
import socket
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

from ..models import Endpoint, PlaybackStatus, SessionLost, Unsupported
from ..network import checked_url, local_request, parse_xml
from .base import Backend

LOG = logging.getLogger(__name__)
SSDP = ("239.255.255.250", 1900)
RENDERER = "urn:schemas-upnp-org:device:MediaRenderer:1"
SOAP = "http://schemas.xmlsoap.org/soap/envelope/"
REQUIRED = {"SetAVTransportURI", "Play", "Stop", "GetTransportInfo", "GetMediaInfo"}


def value(node, name):
    return node.findtext("{*}" + name, default="")


def action(service, name, args, peer, network, timeout):
    if name not in service["actions"]:
        raise Unsupported(f"DLNA does not advertise {name}")
    envelope = ET.Element(
        f"{{{SOAP}}}Envelope",
        {f"{{{SOAP}}}encodingStyle": "http://schemas.xmlsoap.org/soap/encoding/"},
    )
    command = ET.SubElement(
        ET.SubElement(envelope, f"{{{SOAP}}}Body"), f"{{{service['type']}}}{name}"
    )
    for key, data in args.items():
        ET.SubElement(command, key).text = str(data)
    code, raw = local_request(
        service["url"],
        peer,
        network,
        timeout,
        ET.tostring(envelope, encoding="utf-8", xml_declaration=True),
        {"Content-Type": 'text/xml; charset="utf-8"', "SOAPAction": f'"{service["type"]}#{name}"'},
    )
    root = parse_xml(raw)
    fault = root.find(".//{*}Fault")
    if fault is not None or code != 200:
        detail = " ".join(root.itertext()).strip()[:300]
        raise RuntimeError("DLNA rejected action: " + detail)
    result = root.find(f".//{{*}}{name}Response")
    if result is None:
        raise ValueError("Invalid UPnP action response")
    return {child.tag.split("}")[-1]: child.text or "" for child in result}


def describe(location, peer, network, config, deadline=None, include_other=False):
    deadline = deadline or time.monotonic() + config.request_timeout * 4

    def remaining():
        budget = deadline - time.monotonic()
        if budget <= 0:
            raise TimeoutError("UPnP description deadline exceeded")
        return min(budget, config.request_timeout)

    checked_url(location, peer, network)
    response_headers = {}
    code, raw = local_request(
        location, peer, network, remaining(), response_headers=response_headers
    )
    if code != 200:
        raise RuntimeError("Cannot read UPnP device description")
    root = parse_xml(raw)
    base = value(root, "URLBase") or location
    checked_url(base, peer, network)
    endpoints = []
    for device in root.findall(".//{*}device")[: config.max_devices]:
        device_type = value(device, "deviceType")
        renderer = bool(re.fullmatch(r"urn:schemas-upnp-org:device:MediaRenderer:\d+", device_type))
        dial_service = any(
            re.fullmatch(
                r"urn:dial-multiscreen-org:service:dial:\d+", value(service, "serviceType")
            )
            for service in device.findall("{*}serviceList/{*}service")[:32]
        )
        if not renderer or dial_service:
            if include_other and value(device, "UDN") and device_type:
                service_types = [
                    value(service, "serviceType")
                    for service in device.findall("{*}serviceList/{*}service")[:32]
                ]
                dial = any(
                    re.fullmatch(
                        r"urn:dial-multiscreen-org:(?:service:dial|device:dialreceiver):\d+", urn
                    )
                    for urn in [device_type, *service_types]
                )
                endpoint = Endpoint(
                    "DIAL" if dial else "UPnP",
                    value(device, "UDN"),
                    peer,
                    checked_url(location, peer, network).port or 80,
                    value(device, "friendlyName") or "Unknown",
                    value(device, "modelName") or "Unknown",
                    value(device, "manufacturer") or "Unknown",
                    kind="DIAL app receiver" if dial else "UPnP device (not necessarily a TV)",
                    note="Discovery only; DIAL launches apps, not arbitrary media"
                    if dial
                    else "Discovery only; no media renderer verified",
                    details={"device_type": device_type, "service_types": service_types},
                    sources=["SSDP", "UPnP description"],
                    reachability="HTTP REACHABLE",
                    confidence="PROTOCOL RESPONSE",
                    evidence=["UPnP device description: " + device_type],
                )
                application_url = response_headers.get("application-url", "")
                if dial and application_url:
                    try:
                        checked_url(application_url, peer, network)
                        endpoint.details["application_url"] = application_url
                        endpoint.evidence.append("Same-peer DIAL Application-URL; no app launched")
                    except ValueError:
                        endpoint.evidence.append("Rejected Application-URL outside responding peer")
                endpoints.append(endpoint)
            if not renderer:
                continue
        endpoint = Endpoint(
            "DLNA",
            value(device, "UDN") or location,
            peer,
            checked_url(location, peer, network).port or 80,
            value(device, "friendlyName") or "Unknown",
            value(device, "modelName") or "Unknown",
            value(device, "manufacturer") or "Unknown",
        )
        endpoint.kind = (
            "TV (advertised model)"
            if "tv" in endpoint.model.lower()
            else "MediaRenderer (type unknown)"
        )
        services = {}
        for service in device.findall("{*}serviceList/{*}service")[:16]:
            type_ = value(service, "serviceType")
            if type_.split(":")[-2:-1] and type_.split(":")[-2] in services:
                continue
            if not re.fullmatch(
                r"urn:schemas-upnp-org:service:(AVTransport|ConnectionManager):\d+", type_
            ):
                continue
            try:
                url = urljoin(base, value(service, "controlURL"))
                scpd = urljoin(base, value(service, "SCPDURL"))
                checked_url(url, peer, network)
                checked_url(scpd, peer, network)
                code, xml = local_request(scpd, peer, network, remaining())
                if code != 200:
                    continue
                schema = parse_xml(xml)
                actions = {value(a, "name") for a in schema.findall(".//{*}actionList/{*}action")}
                modes = [
                    a.text
                    for state in schema.findall(".//{*}stateVariable")
                    if value(state, "name") == "CurrentPlayMode"
                    for a in state.findall("{*}allowedValueList/{*}allowedValue")
                ]
                services[type_.split(":")[-2]] = {
                    "type": type_,
                    "url": url,
                    "actions": actions,
                    "modes": modes,
                }
            except Exception:
                LOG.debug("Cannot inspect receiver service", exc_info=True)
        endpoint.details = services
        endpoint.sources = ["SSDP", "UPnP description", "SCPD"]
        endpoint.reachability = "HTTP REACHABLE"
        endpoint.confidence = "PROTOCOL RESPONSE"
        endpoint.evidence = ["MediaRenderer description; available actions checked in SCPD"]
        transport = services.get("AVTransport", {})
        endpoint.controllable = REQUIRED <= transport.get("actions", set())
        endpoint.note = (
            "AVTransport actions verified; connection/formats unverified"
            if endpoint.controllable
            else "Discovered only; AVTransport/ownership queries unavailable"
        )
        connection = services.get("ConnectionManager")
        if connection:
            try:
                sink = action(connection, "GetProtocolInfo", {}, peer, network, remaining()).get(
                    "Sink", ""
                )
                endpoint.details["sink"] = sink.split(",") if sink else []
                if sink:
                    endpoint.note = "Advertised formats; " + ", ".join(
                        sorted({x.split(":")[2] for x in sink.split(",") if len(x.split(":")) >= 4})
                    )
            except Exception:
                LOG.debug("Cannot query receiver formats", exc_info=True)
        endpoints.append(endpoint)
    return endpoints


def discover(network, config, target=None):
    destination = (target, 1900) if target else SSDP
    locations = set()
    hints = {}
    deadline = time.monotonic() + config.discovery_timeout
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
        sock.bind((network.ip, 0))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(network.ip))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        # One request; no address sweep or port scan. ssdp:all finds renderer v2 too.
        packet = (
            f"M-SEARCH * HTTP/1.1\r\nHOST: {destination[0]}:1900\r\n"
            'MAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n'
        ).encode("ascii")
        sock.sendto(packet, destination)
        while len(locations) < config.max_devices and time.monotonic() < deadline:
            sock.settimeout(max(0.01, deadline - time.monotonic()))
            try:
                packet, (peer, _) = sock.recvfrom(16384)
            except socket.timeout:
                break
            if not network.accepts(peer) or (target and peer != target):
                continue
            lines = packet.decode("iso-8859-1").split("\r\n")
            if not lines[0].startswith("HTTP/1.1 200"):
                continue
            fields = dict(
                (k.strip().lower(), v.strip())
                for line in lines[1:]
                if ":" in line
                for k, v in [line.split(":", 1)]
            )
            location = fields.get("location", "")
            try:
                checked_url(location, peer, network)
            except ValueError:
                continue
            locations.add((location, peer))
            hints[(location, peer)] = fields
    found = []
    description_deadline = time.monotonic() + config.request_timeout * 4
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = {
            pool.submit(describe, url, peer, network, config, description_deadline, True): (
                url,
                peer,
            )
            for url, peer in sorted(locations)
        }
        for future in as_completed(futures):
            try:
                found.extend(future.result())
            except Exception:
                LOG.debug("Rejected/unreachable UPnP description", exc_info=True)
                url, peer = futures[future]
                fields = hints[(url, peer)]
                if fields.get("st", "").startswith("urn:schemas-upnp-org:device:MediaRenderer:"):
                    found.append(
                        Endpoint(
                            "DLNA",
                            fields.get("usn", url).split("::")[0],
                            peer,
                            checked_url(url, peer, network).port or 80,
                            note="SSDP advertisement only; description unavailable/invalid",
                        )
                    )
    return found[: config.max_devices]


def seconds(text):
    try:
        h, m, s = text.split(":")
        return int(h) * 3600 + int(m) * 60 + float(s)
    except (ValueError, AttributeError):
        return 0


class DLNA(Backend):
    def __init__(self, *args):
        super().__init__(*args)
        self.native_repeat = False
        self.previous_position = 0
        self.duration = 0

    def call(self, name, **args):
        return action(
            self.endpoint.details["AVTransport"],
            name,
            {"InstanceID": 0, **args},
            self.endpoint.ip,
            self.network,
            self.config.request_timeout,
        )

    def connect(self):
        if self.get_status().state in ("PLAYING", "PAUSED", "BUFFERING"):
            raise RuntimeError("Receiver busy; stop its current content on the receiver and retry")

    def play(self, url, media):
        if self.url:
            self.require_owned()
        metadata = ET.Element(
            "DIDL-Lite",
            {
                "xmlns": "urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/",
                "xmlns:dc": "http://purl.org/dc/elements/1.1/",
                "xmlns:upnp": "urn:schemas-upnp-org:metadata-1-0/upnp/",
            },
        )
        item = ET.SubElement(metadata, "item", {"id": "0", "parentID": "-1", "restricted": "1"})
        ET.SubElement(item, "dc:title").text = media.path.name
        ET.SubElement(item, "upnp:class").text = (
            "object.item.imageItem.photo" if media.image else "object.item.videoItem"
        )
        ET.SubElement(item, "res", {"protocolInfo": f"http-get:*:{media.mime}:*"}).text = url
        self.url = url
        self.previous_position = 0
        self.duration = media.duration
        self.call(
            "SetAVTransportURI",
            CurrentURI=url,
            CurrentURIMetaData=ET.tostring(metadata, encoding="unicode"),
        )
        transport = self.endpoint.details["AVTransport"]
        if "SetPlayMode" in transport["actions"] and "REPEAT_ALL" in transport["modes"]:
            try:
                self.call("SetPlayMode", NewPlayMode="REPEAT_ALL")
                self.native_repeat = True
            except RuntimeError:
                LOG.debug("Native repeat rejected; using client EOF detection", exc_info=True)
        self.call("Play", Speed=1)

    def get_status(self):
        info = self.call("GetMediaInfo")
        transport = self.call("GetTransportInfo")
        state = transport.get("CurrentTransportState", "UNKNOWN")
        state = {"PAUSED_PLAYBACK": "PAUSED", "TRANSITIONING": "BUFFERING"}.get(state, state)
        url = info.get("CurrentURI", "")
        duration = seconds(info.get("MediaDuration", "")) or self.duration
        position = self.previous_position
        if "GetPositionInfo" in self.endpoint.details["AVTransport"]["actions"]:
            timing = self.call("GetPositionInfo")
            current = seconds(timing.get("RelTime", ""))
            position = current if state == "PLAYING" else max(position, current)
            duration = seconds(timing.get("TrackDuration", "")) or duration
        # UPnP has no explicit EOF reason: only restart after measured near-end playback.
        finished = (
            state == "STOPPED"
            and duration > 0
            and position >= max(0.5, duration - self.config.poll_interval - 0.5)
        )
        if state == "PLAYING":
            self.previous_position = position
        error = (
            "DLNA transport error"
            if transport.get("CurrentTransportStatus") == "ERROR_OCCURRED"
            else ""
        )
        return PlaybackStatus(state, url, finished, error)

    def pause(self):
        self.require_owned()
        self.call("Pause")

    def resume(self):
        self.require_owned()
        self.call("Play", Speed=1)

    def stop(self):
        try:
            self.require_owned()
        except SessionLost:
            return False
        self.call("Stop")
        return True

    def disconnect(self):
        pass  # HTTP connections are closed after every bounded request.
