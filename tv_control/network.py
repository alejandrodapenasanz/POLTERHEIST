"""Read-only interface selection and strictly scoped UPnP HTTP/XML."""

import http.client
import ipaddress
import socket
import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Network:
    name: str
    ip: str
    subnet: ipaddress.IPv4Network

    def accepts(self, ip):
        try:
            address = ipaddress.IPv4Address(ip)
            return (
                address in self.subnet
                and address not in (self.subnet.network_address, self.subnet.broadcast_address)
                and not address.is_multicast
                and not address.is_loopback
                and not address.is_unspecified
                and str(address) != self.ip
            )
        except ValueError:
            return False

    def target(self, ip):
        ip = str(ipaddress.IPv4Address(ip))
        if not self.accepts(ip):
            raise ValueError(f"Target must be a receiver on {self.subnet}")
        return ip


def detect_network(bind_ip=""):
    try:
        import ifaddr
    except ImportError as error:
        raise RuntimeError(
            "TV dependencies missing: install requirements.txt in the venv"
        ) from error
    candidates = []
    for adapter in ifaddr.get_adapters():
        for addr in adapter.ips:
            if isinstance(addr.ip, str):
                ip = ipaddress.IPv4Address(addr.ip)
                if not (ip.is_loopback or ip.is_unspecified or ip.is_link_local):
                    candidates.append(
                        Network(
                            adapter.nice_name,
                            str(ip),
                            ipaddress.IPv4Network(f"{ip}/{addr.network_prefix}", strict=False),
                        )
                    )
    preferred = bind_ip
    if not preferred:
        try:
            # UDP connect only selects a route; no packet is transmitted.
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.connect(("239.255.255.250", 1900))
                preferred = sock.getsockname()[0]
        except OSError:
            pass
    match = next((n for n in candidates if n.ip == preferred), None)
    if match:
        return match
    if not bind_ip and len(candidates) == 1:
        return candidates[0]
    raise RuntimeError(
        "No unambiguous local IPv4 interface; configure bind_ip in config/tv_control.json"
    )


def checked_url(url, peer, network):
    parsed = urlsplit(url)
    if (
        parsed.scheme != "http"
        or parsed.hostname != peer
        or not network.accepts(peer)
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or parsed.port == 0
        or any(ord(c) < 32 or ord(c) == 127 for c in url)
        or not 1 <= (parsed.port or 80) <= 65535
    ):
        raise ValueError("UPnP URL must use HTTP and the responding receiver's literal local IP")
    return parsed


def local_request(url, peer, network, timeout, body=None, headers=None, response_headers=None):
    parsed = checked_url(url, peer, network)
    connection = http.client.HTTPConnection(
        peer, parsed.port or 80, timeout=timeout, source_address=(network.ip, 0)
    )
    deadline = time.monotonic() + timeout
    timer = None
    channel = None
    response = None
    try:
        connection.connect()
        # HTTP/1.0 may close HTTPConnection.sock after headers while the response
        # file still owns the transport. Keep a handle for the absolute deadline.
        channel = connection.sock.dup()

        def expire():
            try:
                channel.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

        # An absolute deadline also bounds a receiver dribbling HTTP headers/body.
        timer = threading.Timer(max(0.001, deadline - time.monotonic()), expire)
        timer.daemon = True
        timer.start()
        connection.request(
            "POST" if body is not None else "GET",
            (parsed.path or "/") + ("?" + parsed.query if parsed.query else ""),
            body=body,
            headers=headers or {},
        )
        response = connection.getresponse()
        if response_headers is not None:
            response_headers.update((key.lower(), value) for key, value in response.getheaders())
        if response.status not in (200, 500):
            raise RuntimeError(
                f"Receiver HTTP {response.status}; redirects/authentication are not bypassed"
            )
        chunks = []
        size = 0
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Receiver HTTP response timeout")
            # read1 returns available bytes instead of waiting to fill a large buffer.
            channel.settimeout(remaining)
            part = response.read1(65536)
            if not part:
                break
            size += len(part)
            if size > 1024 * 1024:
                raise ValueError("Receiver XML exceeds 1 MiB")
            chunks.append(part)
        return response.status, b"".join(chunks)
    finally:
        if timer:
            timer.cancel()
        if response is not None:
            response.close()
        connection.close()
        if channel is not None:
            channel.close()


def parse_xml(data):
    # Also reject UTF-16/32 DTDs. ElementTree never retrieves remote schemas.
    normalized = data.replace(b"\x00", b"").upper()
    if b"<!DOCTYPE" in normalized or b"<!ENTITY" in normalized:
        raise ValueError("DTD/entity declarations are not allowed in UPnP descriptions")
    return ET.fromstring(data)
