"""Explicit, small IPv4 scopes; DNS is resolved once, then literal addresses are pinned."""

import ipaddress
import queue
import re
import socket
import threading
from dataclasses import dataclass

from .network import Network


def receiver_address(value):
    ip = ipaddress.IPv4Address(value)
    if ip.is_multicast or ip.is_unspecified or ip.is_loopback or ip.is_reserved:
        raise ValueError("Target must be a unicast receiver IPv4 address")
    return str(ip)


def resolve_hostname(hostname, timeout=5):
    # A daemon prevents an OS resolver stuck outside Python's control blocking exit.
    result = queue.Queue(maxsize=1)

    def resolve():
        try:
            result.put(socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_STREAM))
        except Exception as error:
            result.put(error)

    threading.Thread(target=resolve, daemon=True).start()
    try:
        records = result.get(timeout=timeout)
    except queue.Empty as error:
        raise TimeoutError("Hostname resolution timed out") from error
    if isinstance(records, Exception):
        raise ValueError(f"Cannot resolve hostname: {records}") from records
    return [record[4][0] for record in records]


def expand_scope(value, max_hosts=16, resolver=resolve_hostname):
    value = value.strip()
    if not value or len(value) > 253:
        raise ValueError("Enter one IPv4 address, hostname or small IPv4 CIDR")
    if ":" in value:
        raise ValueError(
            "Directed IPv6 transport is not implemented in H3; IPv6 metadata is retained"
        )
    if "/" in value:
        subnet = ipaddress.IPv4Network(value, strict=True)
        count = subnet.num_addresses if subnet.prefixlen >= 31 else subnet.num_addresses - 2
        if count > max_hosts:
            raise ValueError(f"Scope contains {count} hosts; maximum is {max_hosts}")
        addresses = [str(ip) for ip in subnet.hosts()]
    else:
        try:
            addresses = [str(ipaddress.IPv4Address(value))]
        except ValueError:
            if not re.fullmatch(
                r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.?", value
            ) or re.fullmatch(r"[0-9.]+", value):
                raise ValueError("Invalid hostname or IPv4 address") from None
            addresses = resolver(value)
    addresses = sorted(set(addresses), key=ipaddress.IPv4Address)
    if not addresses or len(addresses) > max_hosts:
        raise ValueError(f"Scope must resolve to 1..{max_hosts} addresses")
    return tuple(receiver_address(ip) for ip in addresses)


@dataclass(frozen=True)
class DirectedNetwork(Network):
    peer: str

    def accepts(self, ip):
        return ip == self.peer and ip != self.ip


def route_to(peer, bind_ip=""):
    peer = receiver_address(peer)
    # UDP connect selects a route without transmitting a packet or altering routing.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        if bind_ip:
            sock.bind((bind_ip, 0))
        sock.connect((peer, 1900))
        source = sock.getsockname()[0]
    if source == peer:
        raise ValueError("The target is this computer, not a receiver")
    return DirectedNetwork(
        "Explicit routed target", source, ipaddress.IPv4Network(peer + "/32"), peer
    )
