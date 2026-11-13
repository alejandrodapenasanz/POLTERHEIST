"""Single bounded CoAP discovery GET; no observation subscriptions or actuations."""

import re
import secrets
import socket
import time

from ..models import Endpoint

DESTINATION = ("224.0.1.187", 5683)


def request(token, identifier):
    if len(token) != 4 or not 0 <= identifier <= 65535:
        raise ValueError("Invalid discovery token/message ID")
    # NON GET, Uri-Path .well-known/core, Accept application/link-format (40).
    return b"\x54\x01" + identifier.to_bytes(2, "big") + token + b"\xbb.well-known\x04core\x61\x28"


def parse_response(packet, token):
    if not 4 <= len(packet) <= 16384 or packet[0] >> 6 != 1:
        raise ValueError("Invalid CoAP version/size")
    length, message_type = packet[0] & 15, (packet[0] >> 4) & 3
    if length > 8 or len(packet) < 4 + length or packet[4 : 4 + length] != token:
        raise ValueError("Uncorrelated CoAP token")
    if message_type != 1 or packet[1] not in (69, 129, 131):
        raise ValueError("Unsupported discovery response type/code")
    offset, number, options = 4 + length, 0, {}

    def extended(value):
        nonlocal offset
        size = 1 if value == 13 else 2 if value == 14 else 0
        if value == 15 or offset + size > len(packet):
            raise ValueError("Invalid CoAP option")
        if not size:
            return value
        result = int.from_bytes(packet[offset : offset + size], "big") + (13 if size == 1 else 269)
        offset += size
        return result

    while offset < len(packet) and packet[offset] != 255:
        header = packet[offset]
        offset += 1
        number += extended(header >> 4)
        size = extended(header & 15)
        if offset + size > len(packet) or len(options) >= 64:
            raise ValueError("Truncated/excessive CoAP options")
        value = packet[offset : offset + size]
        if number in (12, 23) and (number in options or len(value) > 3):
            raise ValueError("Invalid content format/block option")
        options[number] = value
        offset += size
    payload = packet[offset + 1 :] if offset < len(packet) else b""
    if offset < len(packet) and not payload:
        raise ValueError("CoAP payload marker without payload")
    return {
        "code": packet[1],
        "content_format": int.from_bytes(options[12], "big") if 12 in options else None,
        "partial": bool(int.from_bytes(options.get(23, b""), "big") & ~7),
        "payload": payload,
    }


def links(payload):
    text = payload.decode("utf-8", "strict")
    # Quoted attribute values can contain commas; split only outside quotes/URIs.
    chunks, start, quoted, escaped, uri = [], 0, False, False, False
    for index, char in enumerate(text):
        if escaped:
            escaped = False
        elif quoted and char == "\\":
            escaped = True
        elif char == '"' and not uri:
            quoted = not quoted
        elif not quoted and char == "<":
            uri = True
        elif not quoted and char == ">":
            uri = False
        elif char == "," and not quoted and not uri:
            chunks.append(text[start:index])
            start = index + 1
    if quoted or uri or escaped:
        raise ValueError("Truncated CoRE link format")
    chunks.append(text[start:])
    result = []
    for chunk in chunks[:64]:
        match = re.fullmatch(
            r'\s*<([^<>\s]{1,1024})>((?:\s*;\s*[\w-]+(?:=(?:"(?:[^"\\]|\\.)*"|[^\s;,]+))?)*)\s*',
            chunk,
        )
        if not match:
            raise ValueError("Invalid CoRE link")
        attributes = re.findall(r';\s*([\w-]+)(?:=("(?:[^"\\]|\\.)*"|[^\s;,]+))?', match[2])
        result.append(
            {
                "target": match[1],
                "attributes": {
                    k: v.strip('"')[:256]
                    for k, v in attributes
                    if k in ("rt", "if", "ct", "title", "obs")
                },
            }
        )
    return result


def from_packet(packet, peer, port, network, token):
    if not network.accepts(peer) or not 1 <= port <= 65535:
        return None
    parsed = parse_response(packet, token)
    resources, problem = [], ""
    if parsed["code"] == 69 and parsed["content_format"] == 40:
        try:
            resources = links(parsed["payload"])
        except (ValueError, UnicodeError) as error:
            problem = str(error)
    return Endpoint(
        "CoAP",
        f"{peer}:{port}",
        peer,
        port,
        "CoAP service " + peer,
        kind="CoAP resource server",
        note="Discovery only; resource links were not followed",
        details={
            "iot_type": "CoAP resource server",
            "service_transport": "udp",
            "resources": resources,
            "directory_partial": parsed["partial"],
            "directory_error": problem,
            "content_format": parsed["content_format"],
            "response_code": parsed["code"],
        },
        sources=["CoAP /.well-known/core"],
        reachability="CORRELATED UDP RESPONSE; SESSION UNTESTED",
        authentication="DISCOVERY DIRECTORY ACCESSIBLE; RESOURCE AUTH UNKNOWN"
        if parsed["code"] == 69
        else "DISCOVERY DIRECTORY REQUIRES AUTHORIZATION",
        evidence=["Matching CoAP token; bounded NON response"],
    )


def discover(network, config, target=None):
    token = secrets.token_bytes(4)
    packet = request(token, secrets.randbelow(65536))
    deadline, found = time.monotonic() + config.discovery_timeout, {}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as channel:
        channel.bind((network.ip, 0))
        channel.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(network.ip))
        channel.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        channel.sendto(packet, (target, 5683) if target else DESTINATION)
        while time.monotonic() < deadline and len(found) < config.max_devices:
            channel.settimeout(max(0.01, deadline - time.monotonic()))
            try:
                response, (peer, port) = channel.recvfrom(16385)
            except socket.timeout:
                break
            if target and peer != target:
                continue
            try:
                endpoint = from_packet(response, peer, port, network, token)
                if endpoint:
                    found[endpoint.uid] = endpoint
            except ValueError:
                continue
    return list(found.values())
