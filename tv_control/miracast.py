"""H4.3/H4.4 preparation and local presentation. No implicit network reconfiguration."""

import datetime
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import threading
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .media import MediaLibrary, confined
from .wireless_bus import WirelessError

LOG = logging.getLogger(__name__)


@dataclass
class MiracastPlan:
    receiver: dict
    media: str = ""
    state: str = "PREPARATION_ONLY"
    selected_backend: str = "gnome-network-displays"
    dependencies: dict = field(default_factory=dict)
    blockers: list[str] = field(default_factory=list)
    effects_requiring_review: list[str] = field(
        default_factory=lambda: [
            "Creating an authorized P2P group changes temporary addressing/routing through NetworkManager.",
            "GNOME Network Displays can create/configure a firewalld zone; no no-firewall option was verified.",
            "FluxCast's reviewed revision changes P2P device name/GO intent and disconnects the P2P device.",
            "Screen mirroring can expose the selected screen; receiver and capture consent remain necessary.",
        ]
    )
    session_verified: bool = False
    media_verified_on_receiver: bool = False

    def export(self, root):
        folder = Path(root) / "reports" / "tv_control"
        folder.mkdir(parents=True, exist_ok=True)
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        path = folder / f"miracast_plan_{stamp}.json"
        path.write_text(
            json.dumps(asdict(self), ensure_ascii=True, indent=2) + "\n", encoding="utf-8"
        )
        return path


class MiracastAdapter:
    """Prepare an external stack integration; H4.3 cannot be certified without hardware."""

    def __init__(self, root, config, platform=None, which=shutil.which):
        self.root, self.config = Path(root), config
        self.platform = sys.platform if platform is None else platform
        self.which = which

    def prepare(self, endpoint, source=None):
        if endpoint.details.get("transport") != "p2p":
            raise WirelessError(
                "WFD_UNSUPPORTED", "Select a P2P receiver with an advertised WFD receiving role"
            )
        wfd = endpoint.details.get("wfd", {})
        plan = MiracastPlan(
            {
                "name": endpoint.name,
                "p2p_address": endpoint.details.get("p2p_address"),
                "interface": endpoint.details.get("interface"),
                "phy": endpoint.details.get("phy"),
                "wfd": wfd,
                "authorization": endpoint.authentication,
            }
        )
        if not self.platform.startswith("linux"):
            plan.blockers.append(
                "PLATFORM_UNSUPPORTED: physical Linux is required for this integration"
            )
        if not wfd.get("sink"):
            plan.blockers.append("WFD_UNSUPPORTED: no valid WFD sink role advertised")
        if wfd.get("session_available") is False:
            plan.blockers.append("ADAPTER_BUSY: receiver advertises no available WFD session")
        if not endpoint.details.get("fresh"):
            plan.blockers.append(
                "STALE_OBSERVATION: repeat discovery before preparing a receiver session"
            )
        for tool in (
            "gnome-network-displays",
            "fluxcast",
            "busctl",
            "iw",
            "ffmpeg",
            "ffprobe",
            "ffplay",
            "gst-inspect-1.0",
            "pipewire",
        ):
            plan.dependencies[tool] = self.which(tool)
        if not plan.dependencies["gnome-network-displays"]:
            plan.blockers.append(
                "DEPENDENCY_MISSING: GNOME Network Displays is not installed/on PATH"
            )
        for tool in ("busctl", "iw", "gst-inspect-1.0"):
            if not plan.dependencies[tool]:
                plan.blockers.append("DEPENDENCY_MISSING: " + tool)
        plan.blockers.extend(
            [
                "ENCODER_UNVERIFIED: use Hardware diagnostics to inspect H.264/GStreamer capabilities; runtime encoding is still untested",
                "SYSTEM_CHANGES_REVIEW_REQUIRED: approve an installed/versioned external stack and its exact effects before activation",
                "PHYSICAL_VALIDATION_REQUIRED: pairing, RTSP/RTP, capture and receiver playback have not been verified",
            ]
        )
        if source is not None:
            library = MediaLibrary(self.root, self.config)
            source = confined(source, (library.folder,))
            media = library.inspect(source)
            plan.media = str(media.path)
            if not plan.dependencies["ffplay"]:
                plan.blockers.append(
                    "DEPENDENCY_MISSING: ffplay is required for local image/video presentation"
                )
        return plan

    def connect(self, plan, confirmed=False):
        if not confirmed:
            raise WirelessError(
                "CONFIRMATION_REQUIRED",
                "Miracast session requires explicit receiver and screen-sharing consent",
            )
        # Installed binaries alone cannot establish that their system changes are
        # authorized or that a receiver accepted pairing. Never label this Connected.
        raise WirelessError(
            "MIRACAST_NOT_ACTIVATED",
            "Activation is not implemented in this delivery. " + "; ".join(plan.blockers),
        )


class LocalPresentation:
    """Own one ffplay process. This is local playback, never evidence of casting."""

    def __init__(self, library):
        self.library = library
        self.process = None
        self.output = None
        self.state = "STOPPED"
        self.cancel = threading.Event()
        self.monitor = None

    def start(self, source, confirmed=False):
        if not confirmed:
            raise WirelessError(
                "CONFIRMATION_REQUIRED", "Local presentation requires explicit confirmation"
            )
        source = confined(source, (self.library.folder,))
        media = self.library.inspect(source)
        binary = shutil.which("ffplay")
        if not binary:
            raise WirelessError(
                "DEPENDENCY_MISSING", "ffplay is missing; no installation attempted"
            )
        self.stop()
        self.output = tempfile.TemporaryFile()
        try:
            self.process = subprocess.Popen(
                [
                    binary,
                    "-protocol_whitelist",
                    "file",
                    "-loglevel",
                    "warning",
                    "-nostats",
                    "-fs",
                    "-loop",
                    "0",
                    "-window_title",
                    "POLTERHEIST local presentation",
                    "-i",
                    str(media.path),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=self.output,
                shell=False,
            )
        except OSError:
            self.output.close()
            self.output = None
            raise
        self.state = "LOCAL_PRESENTATION_ONLY"
        self.cancel.clear()
        process, output = self.process, self.output

        def watch():
            while not self.cancel.wait(0.2):
                if process.poll() is not None:
                    return
                if os.fstat(output.fileno()).st_size > 2_000_000:
                    process.terminate()
                    try:
                        process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=2)
                    return

        self.monitor = threading.Thread(target=watch, name="local-presentation", daemon=True)
        self.monitor.start()

    def poll(self):
        if self.process is None:
            return self.state
        code = self.process.poll()
        if self.output and os.fstat(self.output.fileno()).st_size > 2_000_000:
            self.stop()
            self.state = "LOCAL_PLAYER_ERROR"
            raise WirelessError(
                "STREAMING_FAILED",
                "Local player exceeded diagnostic output limit; no receiver session was started",
            )
        if code is not None:
            self.stop()
            self.state = "STOPPED" if code == 0 else "LOCAL_PLAYER_ERROR"
            if code:
                raise WirelessError(
                    "STREAMING_FAILED", f"Local player exited with {code}; see TV log"
                )
        return self.state

    def stop(self):
        self.cancel.set()
        if self.monitor:
            self.monitor.join(timeout=5)
            self.monitor = None
        try:
            if self.process and self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=2)
        finally:
            self.process = None
            if self.output:
                self.output.seek(max(0, os.fstat(self.output.fileno()).st_size - 8000))
                message = self.output.read(8000).decode("utf-8", "replace")
                if message:
                    LOG.debug("Local presentation: %s", message)
                self.output.close()
                self.output = None
            self.state = "STOPPED"
