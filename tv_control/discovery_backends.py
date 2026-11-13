"""Small discovery contract; control and media remain separate."""

from dataclasses import dataclass
from typing import Callable

from .protocols import airplay, coap, dlna, google_cast, iot_mdns, onvif


@dataclass(frozen=True)
class DiscoveryBackend:
    key: str
    label: str
    discover: Callable
    directed: bool = False


def builtins():
    return (
        DiscoveryBackend("cast", "Google Cast / mDNS", google_cast.discover, True),
        DiscoveryBackend("upnp", "SSDP / UPnP / DLNA / DIAL", dlna.discover, True),
        DiscoveryBackend("airplay", "AirPlay / RAOP / mDNS", airplay.discover),
        DiscoveryBackend("iot_mdns", "IoT / DNS-SD", iot_mdns.discover),
        DiscoveryBackend("onvif", "ONVIF / WS-Discovery", onvif.discover, True),
        DiscoveryBackend("coap", "CoAP / CoRE discovery", coap.discover, True),
    )
