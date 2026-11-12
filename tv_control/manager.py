"""Independent receiver workers; bounded retries, ownership and HTTP lifetimes."""

import logging
import queue
import threading
import time

from .http_server import MediaServer
from .media import MediaLibrary
from .models import SessionLost, Unsupported
from .protocols.dlna import DLNA
from .protocols.google_cast import GoogleCast

LOG = logging.getLogger(__name__)
BACKENDS = {"Google Cast": GoogleCast, "DLNA": DLNA}
ACTIVE = {"PREPARING", "CONNECTING", "STARTING", "PLAYING", "PAUSED", "BUFFERING", "RETRYING"}


class Session:
    def __init__(self, device, source, manager):
        self.device, self.source, self.manager = device, source, manager
        self.endpoint = device.primary
        self.backend = manager.backend_factory(self.endpoint, manager.network, manager.config)
        self.state = "PREPARING"
        self.error = ""
        self.url = ""
        self.media = None
        self.awaiting_restart = False
        self.commands = queue.Queue()
        self.cancel = threading.Event()
        self.ready = threading.Event()
        self.thread = threading.Thread(target=self.run, name=f"tv-{device.id}", daemon=True)

    @property
    def active(self):
        return self.state in ACTIVE

    def _start_playback(self):
        self.state = "CONNECTING"
        for attempt in range(self.manager.config.retries + 1):
            if self.cancel.is_set():
                return False
            try:
                self.backend.connect()
                break
            except Exception:
                self.backend.disconnect()
                if attempt == self.manager.config.retries:
                    raise
                if self.cancel.wait(0.5):
                    return False
        if self.cancel.is_set():
            return False
        self.url = self.manager.server.publish(self.media, self.endpoint.ip)
        self.state = "STARTING"
        self.backend.play(self.url, self.media)
        deadline = time.monotonic() + self.manager.config.connect_timeout
        while not self.cancel.is_set():
            status = self.backend.get_status()
            if status.error:
                raise RuntimeError(status.error)
            if status.url == self.url and status.state in ("PLAYING", "PAUSED"):
                self.state = status.state
                return True
            if status.url and status.url != self.url:
                raise SessionLost("Receiver switched to other content")
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    "Playback not acknowledged; check receiver authorization, format and access to the HTTP server"
                )
            self.cancel.wait(0.2)
        return False

    def tick(self):
        status = self.backend.get_status()
        if status.error:
            raise RuntimeError(status.error)
        if status.url != self.url:
            raise SessionLost("Receiver content changed or playback was interrupted")
        if status.finished:
            if self.media.image:
                # Native still-image display is left to the renderer; never continually reload.
                self.state = "PLAYING"
                return
            if self.awaiting_restart:
                raise RuntimeError("Receiver did not restart playback after end of media")
            self.backend.play(self.url, self.media)
            self.awaiting_restart = True
            self.state = "STARTING"
        elif status.state in ("PLAYING", "PAUSED", "BUFFERING"):
            self.state = status.state
            if self.state == "PLAYING":
                self.awaiting_restart = False
        elif status.state in ("IDLE", "STOPPED", "NO_MEDIA_PRESENT", "EXTERNAL"):
            raise SessionLost("Playback stopped on the receiver")
        else:
            raise RuntimeError("Receiver returned an unknown playback state")

    def run(self):
        try:
            self.media = self.manager.library.prepare(self.source, self.endpoint, self.cancel)
            if not self._start_playback():
                self.state = "STOPPED"
                return
            self.ready.set()
            failures = 0
            stalled = None
            while not self.cancel.is_set():
                try:
                    command = self.commands.get(timeout=self.manager.config.poll_interval)
                except queue.Empty:
                    command = "refresh"
                if self.cancel.is_set():
                    break
                try:
                    if command in ("pause", "resume"):
                        getattr(self.backend, command)()
                    self.tick()
                    if self.state in ("STARTING", "BUFFERING"):
                        stalled = stalled or time.monotonic()
                        if time.monotonic() - stalled > self.manager.config.connect_timeout:
                            raise RuntimeError(
                                "Receiver remains buffering; check HTTP reachability/format"
                            )
                    else:
                        stalled = None
                    if failures or command != "refresh":
                        self.error = ""
                    failures = 0
                except Unsupported as error:
                    self.error = str(error)
                except SessionLost:
                    raise
                except Exception as error:
                    failures += 1
                    self.error = str(error)
                    LOG.debug("Receiver status/control error", exc_info=True)
                    if failures > self.manager.config.retries:
                        raise
                    self.state = "RETRYING"
                    self.cancel.wait(self.manager.config.poll_interval)
            self.state = "STOPPED"
        except SessionLost as error:
            self.state, self.error = "INTERRUPTED", str(error)
        except Exception as error:
            self.state, self.error = ("STOPPED" if self.cancel.is_set() else "ERROR"), str(error)
            LOG.exception("Playback failed for device %s", self.device.id)
        finally:
            try:
                if self.url:
                    self.backend.stop()  # Each backend verifies ownership again before sending Stop.
            except Exception as error:
                self.error = (
                    (self.error + "; " if self.error else "") + "Stop unconfirmed: " + str(error)
                )
                LOG.debug("Cannot confirm receiver stop", exc_info=True)
            try:
                self.backend.disconnect()
            except Exception:
                LOG.debug("Receiver disconnect failed", exc_info=True)
            if self.url:
                self.manager.server.release(self.url)
            self.ready.set()


class Manager:
    def __init__(self, root, network, config, backend_factory=None):
        self.network, self.config = network, config
        self.library = MediaLibrary(root, config)
        self.server = (
            MediaServer(network.ip, config.http_port, self.library.roots) if network else None
        )
        self.sessions = {}
        self.backend_factory = backend_factory or (lambda e, n, c: BACKENDS[e.protocol](e, n, c))

    @property
    def active(self):
        return [s for s in self.sessions.values() if s.active or s.thread.is_alive()]

    def start(self, devices, source, confirmed=False):
        if not confirmed:
            raise ValueError("Explicit confirmation is required before every playback session")
        if self.network is None:
            raise ValueError("IP playback requires a selected local network")
        if not devices or any(not d.controllable for d in devices):
            raise ValueError("Select available devices with a playback backend")
        if len({d.id for d in devices}) != len(devices):
            raise ValueError("Duplicate target devices")
        # Complete validation before stopping the previous selection.
        self.library.inspect(source)
        self.stop()
        if self.active:
            raise RuntimeError("Previous sessions are still stopping; wait and retry")
        self.sessions = {d.id: Session(d, source, self) for d in devices}
        for session in self.sessions.values():
            session.thread.start()

    def command(self, command):
        if command not in ("pause", "resume", "refresh"):
            raise ValueError("Unknown playback command")
        for session in self.sessions.values():
            if session.active:
                session.commands.put(command)

    def stop(self):
        for session in self.sessions.values():
            session.cancel.set()
            session.commands.put("refresh")
            if session.thread.ident is None:
                session.state = "STOPPED"
        # Workers stop concurrently; one shared deadline avoids N sequential timeouts.
        deadline = (
            time.monotonic() + self.config.request_timeout * 5 + self.config.connect_timeout + 1
        )
        for session in self.sessions.values():
            if session.thread.is_alive():
                session.thread.join(timeout=max(0, deadline - time.monotonic()))

    def close(self):
        self.stop()
        if not self.active and self.server is not None:
            self.server.close()
