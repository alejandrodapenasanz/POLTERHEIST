"""Discovery aggregation, persistent session IDs and validated selection."""

import datetime
import json
import logging
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict
from pathlib import Path

from .discovery_backends import builtins
from .models import Device
from .scopes import expand_scope, route_to

LOG = logging.getLogger(__name__)


class Discovery:
    def __init__(self, network, config, backends=None):
        self.network = network
        self.config = config
        self.devices = {}
        self.identities = {}
        self.warnings = []
        self.backends = backends
        self.results = []

    def enabled(self):
        return [
            b
            for b in (self.backends if self.backends is not None else builtins())
            if b.key in self.config.discovery_backends
        ]

    def prepare_scope(self, text):
        addresses = expand_scope(text, self.config.directed_max_hosts)
        return [route_to(ip, self.config.bind_ip) for ip in addresses]

    def merge(self, endpoints, refresh=True):
        if not refresh:
            incoming = {(e.protocol, e.uid) for e in endpoints}
            endpoints = list(endpoints) + [
                e
                for d in self.devices.values()
                if d.available
                for e in d.endpoints
                if (e.protocol, e.uid) not in incoming
            ]
        if refresh:
            for device in self.devices.values():
                device.available = False
        groups = []
        for endpoint in sorted(endpoints, key=lambda e: (e.ip, e.protocol != "Google Cast", e.uid)):
            match = next(
                (
                    g
                    for g in groups
                    if any((e.protocol, e.uid) == (endpoint.protocol, endpoint.uid) for e in g)
                ),
                None,
            )
            if match is None:
                # Cross-protocol IP evidence is used only in the current snapshot.
                # Distinct same-protocol identities on one IP (e.g. Cast groups) stay separate.
                match = next(
                    (
                        g
                        for g in groups
                        if endpoint.ip
                        and g[0].ip == endpoint.ip
                        and endpoint.protocol not in {e.protocol for e in g}
                    ),
                    None,
                )
            if match is not None:
                if not any((e.protocol, e.uid) == (endpoint.protocol, endpoint.uid) for e in match):
                    match.append(endpoint)
            else:
                groups.append([endpoint])
        assigned = set()
        for group in groups:
            old_ids = {
                self.identities[(e.protocol, e.uid)]
                for e in group
                if (e.protocol, e.uid) in self.identities
            }
            reusable = old_ids - assigned
            identifier = min(reusable) if reusable else max(self.devices, default=0) + 1
            # Retire merged aliases without reusing their IDs.
            for old in old_ids - {identifier} - assigned:
                self.devices[old].available = False
            assigned.add(identifier)
            self.devices[identifier] = Device(identifier, group)
            for endpoint in group:
                self.identities[(endpoint.protocol, endpoint.uid)] = identifier
        return list(self.devices.values())

    def scan(self, target=None):
        if self.network is None:
            raise ValueError("No selected IPv4 LAN; Wi-Fi Direct discovery remains available")
        if target:
            target = self.network.target(target)
        self.warnings = []
        self.results = []
        endpoints = []
        with ThreadPoolExecutor(max_workers=3) as pool:
            futures = {
                pool.submit(self._probe, backend, self.network, target): backend.label
                for backend in self.enabled()
                if not target or backend.directed
            }
            try:
                for future in as_completed(futures):
                    found, result = future.result()
                    endpoints.extend(found)
                    self._record(result)
            except BaseException:
                pool.shutdown(wait=False, cancel_futures=True)
                raise
        if target is None:
            return self.replace_scope(endpoints, lambda e: e.details.get("transport") != "p2p")
        return self.merge(endpoints, refresh=False)

    def replace_scope(self, endpoints, predicate):
        retained = [
            e
            for device in self.devices.values()
            if device.available
            for e in device.endpoints
            if not predicate(e)
        ]
        for device in self.devices.values():
            if any(predicate(e) for e in device.endpoints):
                device.available = False
        return self.merge([*endpoints, *retained], refresh=False)

    def add_wireless(self, result):
        if not result.started:
            return list(self.devices.values())
        interface = result.adapter["interface"]
        fresh_ids = {e.uid for e in result.endpoints if e.details.get("fresh")}
        self.replace_scope(
            result.endpoints,
            lambda e: (
                e.details.get("transport") == "p2p" and e.details.get("interface") == interface
            ),
        )
        for device in self.devices.values():
            if (
                device.primary.details.get("transport") == "p2p"
                and device.primary.details.get("interface") == interface
            ):
                device.available = any(e.uid in fresh_ids for e in device.endpoints)
        self.results.append(
            {
                "backend": "p2p/" + result.adapter["backend"],
                "scope": interface,
                "status": result.state,
                "fresh_count": result.fresh_count,
                "cached_count": result.cached_count,
                "recorded_at": result.recorded_at,
                "state_preserved": result.state_preserved,
            }
        )
        return list(self.devices.values())

    def _probe(self, backend, network, target):
        start = time.monotonic()
        result = {
            "backend": backend.key,
            "scope": target or str(network.subnet),
            "source_ip": network.ip,
            "status": "NO RESPONSE",
            "count": 0,
            "error": "",
        }
        found = []
        try:
            found = [
                e for e in backend.discover(network, self.config, target) if network.accepts(e.ip)
            ][: self.config.max_devices]
            result.update(status="DETECTED" if found else "NO RESPONSE", count=len(found))
            for endpoint in found:
                endpoint.observed_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
                if not endpoint.addresses:
                    endpoint.addresses = [endpoint.ip]
                if not endpoint.sources:
                    endpoint.sources = [backend.label]
        except Exception as error:
            LOG.exception("%s discovery failed", backend.label)
            result.update(status="ERROR", error=str(error))
        result["elapsed_seconds"] = round(time.monotonic() - start, 3)
        return found, result

    def _record(self, result):
        self.results.append(result)
        if result["error"]:
            self.warnings.append(f"{result['backend']} / {result['scope']}: {result['error']}")

    def scan_directed(self, networks, confirmed=False, progress=None):
        if not confirmed:
            raise ValueError("Explicit scope confirmation is required before directed discovery")
        if not 1 <= len(networks) <= self.config.directed_max_hosts:
            raise ValueError("Directed scope exceeds configured host limit")
        self.warnings, self.results, endpoints = [], [], []
        jobs = [
            (backend, network)
            for network in networks
            for backend in self.enabled()
            if backend.directed
        ]
        if not jobs:
            self.warnings.append("No enabled backend supports directed discovery")
            return list(self.devices.values())
        with ThreadPoolExecutor(max_workers=self.config.directed_workers) as pool:
            futures = {
                pool.submit(self._probe, backend, network, network.peer): network
                for backend, network in jobs
            }
            try:
                for future in as_completed(futures):
                    network = futures[future]
                    found, result = future.result()
                    for endpoint in found:
                        endpoint.sources.append("Explicit routed scope")
                        if (
                            self.network is None
                            or not self.network.accepts(endpoint.ip)
                            or network.ip != self.network.ip
                        ):
                            endpoint.controllable = False
                            endpoint.note += "; discovery only outside selected LAN; media return route unverified"
                    endpoints.extend(found)
                    self._record(result)
                    if progress:
                        progress(result)
            except BaseException:
                # Cancel queued targets; only already-running, bounded probes finish.
                pool.shutdown(wait=False, cancel_futures=True)
                raise
        peers = {network.peer for network in networks}
        for device in self.devices.values():
            if any(endpoint.ip in peers for endpoint in device.endpoints):
                device.available = False
        return self.merge(endpoints, refresh=False)

    def export(self, root):
        folder = Path(root) / "reports" / "tv_control"
        folder.mkdir(parents=True, exist_ok=True)
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        path = folder / f"discovery_{stamp}.json"
        document = {
            "schema": 1,
            "recorded_at": stamp,
            "enabled_backends": self.config.discovery_backends,
            "results": self.results,
            "warnings": self.warnings,
            "devices": [asdict(device) for device in self.devices.values()],
            "limitations": [
                "Discovery does not establish a media session or authenticate a receiver.",
                "Same-IP grouping is provisional; physical identity correlation is deferred.",
                "IPv4 transport; IPv6 addresses in Bonjour records are metadata only.",
            ],
        }
        path.write_text(
            json.dumps(
                document,
                indent=2,
                ensure_ascii=False,
                default=lambda value: sorted(value) if isinstance(value, set) else str(value),
            )
            + "\n",
            encoding="utf-8",
        )
        return path


def select_devices(devices, text=None):
    candidates = {d.id: d for d in devices}
    if text is None:
        selected = [d for d in devices if d.controllable]
        if not selected:
            raise ValueError("No available devices with a playback backend")
        return selected
    if not re.fullmatch(r"\s*[0-9]+\s*(,\s*[0-9]+\s*)*", text):
        raise ValueError("Enter one or more numeric IDs, separated by commas")
    ids = [int(part.strip()) for part in text.split(",")]
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate IDs are not allowed")
    for identifier in ids:
        if identifier not in candidates:
            raise ValueError(f"Unknown device ID: {identifier}")
        if not candidates[identifier].controllable:
            raise ValueError(
                f"Device {identifier} is unavailable or discovered only; refresh discovery"
            )
    return [candidates[identifier] for identifier in ids]
