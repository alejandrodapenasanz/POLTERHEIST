"""Explicit bounded P2P discovery, cleanup verification and local evidence reports."""

import datetime
import hashlib
import json
import logging
import os
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .p2p import LocalRadio, NetworkManagerP2P, SupplicantP2P
from .wfd import peer_endpoint
from .wireless_bus import WirelessError

LOG = logging.getLogger(__name__)


class PhyLease:
    """OS-released lock between POLTERHEIST processes using this workspace/PHY."""

    def __init__(self, root, phy):
        folder = Path(root) / "reports" / "tv_control"
        folder.mkdir(parents=True, exist_ok=True)
        self.path = folder / ("p2p_" + hashlib.sha256(phy.encode()).hexdigest()[:16] + ".lock")
        self.file = None

    def __enter__(self):
        self.file = self.path.open("a+b")
        try:
            if os.name == "nt":
                import msvcrt

                if self.file.seek(0, 2) == 0:
                    self.file.write(b"\0")
                    self.file.flush()
                self.file.seek(0)
                msvcrt.locking(self.file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(self.file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            self.file.close()
            self.file = None
            raise WirelessError(
                "ADAPTER_BUSY", "Another POLTERHEIST operation holds this PHY"
            ) from error
        return self

    def __exit__(self, *args):
        if self.file:
            try:
                if os.name == "nt":
                    import msvcrt

                    self.file.seek(0)
                    msvcrt.locking(self.file.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(self.file.fileno(), fcntl.LOCK_UN)
            finally:
                self.file.close()
                self.file = None


@dataclass
class WirelessScan:
    adapter: dict
    recorded_at: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )
    state: str = "CHECKING"
    history: list[str] = field(default_factory=lambda: ["CHECKING"])
    endpoints: list = field(default_factory=list)
    error_code: str = ""
    error: str = ""
    warnings: list[str] = field(default_factory=list)
    before: dict = field(default_factory=dict)
    after: dict = field(default_factory=dict)
    stop_confirmed: bool = False
    state_preserved: bool | None = None
    started: bool = False
    fresh_count: int = 0
    cached_count: int = 0

    def transition(self, state):
        self.state = state
        self.history.append(state)

    def export(self, root):
        folder = Path(root) / "reports" / "tv_control"
        folder.mkdir(parents=True, exist_ok=True)
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        path = folder / f"wireless_{stamp}.json"
        path.write_text(
            json.dumps(asdict(self), ensure_ascii=True, indent=2) + "\n", encoding="utf-8"
        )
        return path


def boot_time():
    if hasattr(time, "CLOCK_BOOTTIME"):
        return time.clock_gettime(time.CLOCK_BOOTTIME)
    return time.monotonic()


class WirelessDiscovery:
    def __init__(
        self, root, config, radio=None, backend=None, clock=time.monotonic, boot_clock=boot_time
    ):
        self.root, self.config = Path(root), config
        self.radio = radio or LocalRadio()
        self.backend = backend or (
            NetworkManagerP2P() if config.p2p_backend == "networkmanager" else SupplicantP2P()
        )
        self.clock, self.boot_clock = clock, boot_clock

    def adapters(self):
        return self.radio.inventory(self.backend)

    def snapshot(self, adapter):
        return {"radio": self.radio.snapshot(adapter), "control": self.backend.snapshot(adapter)}

    def scan(self, adapter, confirmed=False, cancel=None, progress=None):
        if not confirmed:
            raise WirelessError(
                "CONFIRMATION_REQUIRED",
                "Active radio discovery needs explicit confirmation for the selected adapter",
            )
        self.radio.require_linux()
        if not adapter.eligible or adapter.backend != self.backend.name:
            raise WirelessError(
                "P2P_UNSUPPORTED",
                "; ".join(adapter.reasons) or "Refresh and select a compatible adapter",
            )
        cancel = cancel or threading.Event()
        result = WirelessScan(asdict(adapter))
        duration = self.config.p2p_timeout
        observations, baseline = {}, {}
        start_attempted = False
        terminal = "ERROR"

        def transition(state):
            result.transition(state)
            if progress:
                progress(state)

        with PhyLease(self.root, adapter.phy):
            try:
                if cancel.is_set():
                    raise WirelessError("CANCELLED", "Discovery cancelled before starting")
                result.before = self.snapshot(adapter)
                baseline = dict(
                    self.backend.peers(adapter, self.clock() + 3, self.config.max_devices)
                )
                started_boot = self.boot_clock()
                transition("STARTING")
                start_attempted = True
                try:
                    self.backend.start(adapter, duration)
                except WirelessError as error:
                    if error.code in (
                        "PERMISSION_DENIED",
                        "ADAPTER_BUSY",
                        "UNSUPPORTED_API",
                        "SERVICE_UNAVAILABLE",
                    ):
                        start_attempted = False  # Rejected: never stop somebody else's operation.
                    raise
                result.started = True
                transition("DISCOVERING")
                deadline = self.clock() + duration
                while not cancel.is_set() and self.clock() < deadline:
                    for path, properties in self.backend.peers(
                        adapter, deadline, self.config.max_devices
                    ):
                        last_seen = properties.get("LastSeen")
                        if self.backend.name == "networkmanager" and type(last_seen) is int:
                            fresh = last_seen >= int(started_boot) and (
                                path not in baseline or baseline[path].get("LastSeen") != last_seen
                            )
                        else:
                            # Supplicant's Peer API has no last-seen property. Never relabel
                            # unchanged cached entries as freshly heard on the radio.
                            fresh = path not in baseline or properties != baseline[path]
                        try:
                            endpoint = peer_endpoint(
                                properties, adapter, self.backend.name, path, fresh
                            )
                            if (
                                endpoint.uid in observations
                                and observations[endpoint.uid].details["fresh"]
                            ):
                                endpoint.details["fresh"] = True
                                if not fresh:
                                    continue
                            if (
                                endpoint.uid in observations
                                or len(observations) < self.config.max_devices
                            ):
                                observations[endpoint.uid] = endpoint
                        except (ValueError, TypeError):
                            if "Ignored malformed P2P peer record" not in result.warnings:
                                result.warnings.append("Ignored malformed P2P peer record")
                    cancel.wait(max(0, min(0.5, deadline - self.clock())))
                result.fresh_count = sum(e.details["fresh"] for e in observations.values())
                result.cached_count = len(observations) - result.fresh_count
                terminal = (
                    "CANCELLED"
                    if cancel.is_set()
                    else "COMPLETED"
                    if result.fresh_count
                    else "CACHE_ONLY"
                    if observations
                    else "NO_PEERS"
                )
            except KeyboardInterrupt:
                cancel.set()
                terminal = "CANCELLED"
                result.error_code, result.error = "CANCELLED", "Discovery cancelled by operator"
            except WirelessError as error:
                terminal = "CANCELLED" if error.code == "CANCELLED" else "ERROR"
                result.error_code, result.error = error.code, str(error)
                LOG.debug("P2P discovery failed", exc_info=True)
            except Exception as error:
                terminal = "ERROR"
                result.error_code, result.error = "DISCOVERY_FAILED", str(error)
                LOG.exception("P2P discovery failed")
            finally:
                if start_attempted:
                    # Shield cleanup from a second Ctrl+C; the daemon's finite timeout
                    # remains a final bound when StopFind cannot be delivered.
                    result.transition("STOPPING")
                    try:
                        self.backend.stop(adapter)
                        result.stop_confirmed = True
                    except (Exception, KeyboardInterrupt) as error:
                        result.warnings.append(
                            "StopFind unconfirmed; daemon timeout is the remaining bound: "
                            + str(error)
                        )
                if result.before:
                    try:
                        result.after = self.snapshot(adapter)
                        result.state_preserved = result.before == result.after
                    except (Exception, KeyboardInterrupt) as error:
                        result.warnings.append(
                            "Cannot verify original interface state: " + str(error)
                        )
                        result.state_preserved = None
                    if result.state_preserved is not True:
                        result.warnings.append(
                            "Original state is not verified; no automatic reconnect or configuration restore attempted"
                        )
                result.endpoints = list(observations.values())
                result.fresh_count = sum(e.details["fresh"] for e in result.endpoints)
                result.cached_count = len(result.endpoints) - result.fresh_count
                if start_attempted and (
                    not result.stop_confirmed or result.state_preserved is not True
                ):
                    terminal = "CLEANUP_UNVERIFIED"
                result.transition(terminal)
        return result
