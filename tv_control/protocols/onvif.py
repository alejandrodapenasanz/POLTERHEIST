"""ONVIF WS-Discovery advertisements. No camera login, stream or control."""

import io
import logging
import socket
import time
import uuid
import xml.etree.ElementTree as ET
from urllib.parse import unquote, urlsplit

from ..models import Endpoint
from ..network import parse_xml

LOG = logging.getLogger(__name__)
SOAP = "http://www.w3.org/2003/05/soap-envelope"
WSA = "http://schemas.xmlsoap.org/ws/2004/08/addressing"
WSD = "http://schemas.xmlsoap.org/ws/2005/04/discovery"
DESTINATION = ("239.255.255.250", 3702)


def probe(message_id):
    root = ET.Element(f"{{{SOAP}}}Envelope")
    header = ET.SubElement(root, f"{{{SOAP}}}Header")
    for name, value in (
        ("MessageID", message_id),
        ("To", "urn:schemas-xmlsoap-org:ws:2005:04:discovery"),
        ("Action", WSD + "/Probe"),
    ):
        ET.SubElement(header, f"{{{WSA}}}{name}").text = value
    reply = ET.SubElement(header, f"{{{WSA}}}ReplyTo")
    ET.SubElement(reply, f"{{{WSA}}}Address").text = WSA + "/role/anonymous"
    ET.SubElement(ET.SubElement(root, f"{{{SOAP}}}Body"), f"{{{WSD}}}Probe")
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def from_packet(packet, peer, network, message_id):
    if len(packet) > 65535 or not network.accepts(peer):
        return []
    root = parse_xml(packet)
    if (
        root.tag != f"{{{SOAP}}}Envelope"
        or root.findtext(f"{{{SOAP}}}Header/{{{WSA}}}RelatesTo") != message_id
    ):
        return []
    if root.findtext(f"{{{SOAP}}}Header/{{{WSA}}}Action") != WSD + "/ProbeMatches":
        return []
    # Resolve QName prefixes, rather than treating an arbitrary ':Device' as ONVIF.
    namespaces = dict(value for _, value in ET.iterparse(io.BytesIO(packet), events=("start-ns",)))
    found = []
    for match in root.findall(f"{{{SOAP}}}Body/{{{WSD}}}ProbeMatches/{{{WSD}}}ProbeMatch")[:16]:
        identity = match.findtext(f"{{{WSA}}}EndpointReference/{{{WSA}}}Address", "")
        if not identity or len(identity) > 512:
            continue
        types = []
        for value in match.findtext(f"{{{WSD}}}Types", "").split()[:16]:
            prefix, _, name = value.rpartition(":")
            types.append((namespaces.get(prefix, ""), name))
        scopes = match.findtext(f"{{{WSD}}}Scopes", "").split()[:32]
        onvif_types = [
            name
            for ns, name in types
            if ns
            in ("http://www.onvif.org/ver10/network/wsdl", "http://www.onvif.org/ver10/device/wsdl")
        ]
        if not onvif_types and not any(s.startswith("onvif://www.onvif.org/") for s in scopes):
            continue
        urls = []
        for url in match.findtext(f"{{{WSD}}}XAddrs", "").split()[:16]:
            try:
                parsed = urlsplit(url)
                port = (
                    parsed.port
                    if parsed.port is not None
                    else (443 if parsed.scheme == "https" else 80)
                )
                if (
                    len(url) <= 2048
                    and parsed.scheme in ("http", "https")
                    and parsed.hostname == peer
                    and parsed.username is None
                    and parsed.password is None
                    and not parsed.fragment
                    and not any(ord(c) <= 32 or ord(c) == 127 for c in url)
                    and 1 <= port <= 65535
                ):
                    urls.append(url)
            except ValueError:
                continue
        if not urls:
            continue

        def scope_value(key):
            prefix = "onvif://www.onvif.org/" + key + "/"
            return next(
                (unquote(s[len(prefix) :])[:256] for s in scopes if s.startswith(prefix)), "Unknown"
            )

        kind = (
            "Camera / video transmitter"
            if "NetworkVideoTransmitter" in onvif_types
            or "onvif://www.onvif.org/type/video_encoder" in scopes
            else "ONVIF device (function unknown)"
        )
        parsed = urlsplit(urls[0])
        found.append(
            Endpoint(
                "ONVIF",
                f"{peer}:{identity}",
                peer,
                parsed.port or (443 if parsed.scheme == "https" else 80),
                scope_value("name"),
                scope_value("hardware"),
                kind=kind,
                note="Discovery only; camera credentials/controller required; no stream opened",
                details={
                    "iot_type": kind,
                    "service_transport": "tcp",
                    "xaddrs": urls,
                    "types": onvif_types,
                },
                sources=["ONVIF WS-Discovery"],
                reachability="PROBE RESPONSE RECEIVED; SERVICE UNTESTED",
                authentication="CREDENTIALS MAY BE REQUIRED; NO LOGIN ATTEMPTED",
                evidence=[
                    "Correlated WS-Discovery ProbeMatches",
                    "ONVIF type/scope; service URL matches response IP",
                ],
            )
        )
    return found


def discover(network, config, target=None):
    message_id = "urn:uuid:" + str(uuid.uuid4())
    deadline, found = time.monotonic() + config.discovery_timeout, {}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
        sock.bind((network.ip, 0))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(network.ip))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        sock.sendto(probe(message_id), (target, 3702) if target else DESTINATION)
        while len(found) < config.max_devices and time.monotonic() < deadline:
            sock.settimeout(max(0.01, deadline - time.monotonic()))
            try:
                packet, (peer, _) = sock.recvfrom(65536)
            except socket.timeout:
                break
            if target and peer != target:
                continue
            try:
                for endpoint in from_packet(packet, peer, network, message_id):
                    if len(found) < config.max_devices:
                        found[endpoint.uid] = endpoint
            except (ET.ParseError, ValueError):
                LOG.debug("Ignored invalid WS-Discovery reply", exc_info=True)
    return list(found.values())
