"""Configuration and protocol-neutral device/session records."""

import ipaddress
import json
import math
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class Config:
    bind_ip: str = ""
    http_port: int = 8765
    discovery_timeout: float = 5
    request_timeout: float = 5
    connect_timeout: float = 10
    poll_interval: float = 2
    retries: int = 2
    max_devices: int = 32
    conversion_timeout: float = 600
    auto_convert: bool = True
    discovery_backends: tuple[str, ...] = ("cast", "upnp", "airplay")
    directed_max_hosts: int = 16
    directed_workers: int = 4

    def __post_init__(self):
        for name in ("discovery_timeout", "request_timeout", "connect_timeout", "poll_interval"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (float, int)):
                raise ValueError(f"{name} must be numeric")
            if not math.isfinite(value) or not 0.1 <= value <= 60:
                raise ValueError(f"{name} must be between 0.1 and 60 seconds")
        for name, low, high in (("http_port", 1, 65535), ("retries", 0, 3), ("max_devices", 1, 64)):
            if type(getattr(self, name)) is not int or not low <= getattr(self, name) <= high:
                raise ValueError(f"{name} must be an integer between {low} and {high}")
        if type(self.auto_convert) is not bool:
            raise ValueError("auto_convert must be true or false")
        if (
            isinstance(self.conversion_timeout, bool)
            or not isinstance(self.conversion_timeout, (float, int))
            or not 1 <= self.conversion_timeout <= 7200
        ):
            raise ValueError("conversion_timeout must be between 1 and 7200 seconds")
        if not isinstance(self.bind_ip, str):
            raise ValueError("bind_ip must be an IPv4 address string or empty string")
        if self.bind_ip:
            ipaddress.IPv4Address(self.bind_ip)
        if type(self.directed_max_hosts) is not int or not 1 <= self.directed_max_hosts <= 64:
            raise ValueError("directed_max_hosts must be between 1 and 64")
        if type(self.directed_workers) is not int or not 1 <= self.directed_workers <= 8:
            raise ValueError("directed_workers must be between 1 and 8")
        backends = self.discovery_backends
        if (
            not isinstance(backends, (tuple, list))
            or not backends
            or any(not isinstance(b, str) or b not in ("cast", "upnp", "airplay") for b in backends)
            or len(backends) != len(set(backends))
        ):
            raise ValueError("discovery_backends must contain unique names: cast, upnp, airplay")
        object.__setattr__(self, "discovery_backends", tuple(backends))

    @classmethod
    def load(cls, root):
        path = Path(root) / "config" / "tv_control.json"
        if not path.exists():
            return cls()
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or set(data) - set(cls.__dataclass_fields__):
            raise ValueError("Invalid TV configuration; see config/tv_control.example.json")
        return cls(**data)


@dataclass
class Endpoint:
    protocol: str
    uid: str
    ip: str
    port: int
    name: str = "Unknown"
    model: str = "Unknown"
    manufacturer: str = "Unknown"
    kind: str = "Media receiver (type unknown)"
    controllable: bool = False
    note: str = "Discovered only"
    details: dict = field(default_factory=dict)
    sources: list[str] = field(default_factory=list)
    addresses: list[str] = field(default_factory=list)
    reachability: str = "NOT CHECKED"
    confidence: str = "ADVERTISED"
    authentication: str = "UNKNOWN"
    evidence: list[str] = field(default_factory=list)
    observed_at: str = ""


@dataclass
class Device:
    id: int
    endpoints: list[Endpoint]
    available: bool = True

    @property
    def primary(self):
        return next((e for e in self.endpoints if e.controllable), self.endpoints[0])

    @property
    def controllable(self):
        return self.available and any(e.controllable for e in self.endpoints)


@dataclass(frozen=True)
class PlaybackStatus:
    state: str
    url: str = ""
    finished: bool = False
    error: str = ""


class Unsupported(RuntimeError):
    """The receiver does not advertise this operation/format."""


class SessionLost(RuntimeError):
    """The receiver is no longer playing media owned by this session."""


def safe_text(value):
    return "".join(c if c.isprintable() else f"\\x{ord(c):02x}" for c in str(value))
