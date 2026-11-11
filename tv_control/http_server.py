"""Threaded, token-addressed file serving with byte ranges and reference counting."""

import http.server
import logging
import re
import secrets
import threading
from urllib.parse import urlsplit

from .media import confined

LOG = logging.getLogger(__name__)


class MediaServer:
    def __init__(self, ip, port, roots):
        self.ip, self.port, self.roots = ip, port, roots
        self._lock = threading.RLock()
        self._files = {}
        self._server = None
        self._thread = None

    @property
    def running(self):
        with self._lock:
            return self._server is not None

    def publish(self, media, peer):
        path = confined(media.path, self.roots)
        with self._lock:
            if self._server is None:
                self._start()
            route = "/" + secrets.token_urlsafe(24) + path.suffix.lower()
            self._files[route] = (path, media.mime, peer)
            return f"http://{self.ip}:{self._server.server_port}{route}"

    def release(self, url):
        with self._lock:
            self._files.pop(urlsplit(url).path, None)
            if not self._files:
                self._close()

    def close(self):
        with self._lock:
            self._files.clear()
            self._close()

    def _close(self):
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._thread.join(timeout=2)
            self._server = None
            self._thread = None

    def _start(self):
        owner = self

        class Server(http.server.ThreadingHTTPServer):
            daemon_threads = True
            block_on_close = False
            allow_reuse_address = False
            slots = threading.BoundedSemaphore(32)

            def process_request(self, request, client_address):
                if not self.slots.acquire(blocking=False):
                    self.shutdown_request(request)
                    return
                try:
                    super().process_request(request, client_address)
                except BaseException:
                    self.slots.release()
                    raise

            def process_request_thread(self, request, client_address):
                try:
                    super().process_request_thread(request, client_address)
                finally:
                    self.slots.release()

            def handle_error(self, request, client_address):
                LOG.debug("HTTP client error", exc_info=True)

        class Handler(http.server.BaseHTTPRequestHandler):
            server_version = "POLTERHEIST"
            sys_version = ""

            def setup(self):
                super().setup()
                self.connection.settimeout(10)

            def log_message(self, format_, *args):
                # Do not log the bearer URL or local filesystem path.
                LOG.debug("Media HTTP request from %s", self.client_address[0])

            def do_HEAD(self):
                self.serve(head=True)

            def do_GET(self):
                self.serve(head=False)

            def serve(self, head):
                with owner._lock:
                    entry = owner._files.get(self.path)
                if not entry or self.client_address[0] != entry[2]:
                    self.send_error(404, "Not found")
                    return
                try:
                    path = confined(entry[0], owner.roots)
                    source = path.open("rb")
                except (OSError, ValueError):
                    self.send_error(404, "Media unavailable")
                    return
                with source:
                    source.seek(0, 2)
                    size = source.tell()
                    start, end = 0, size - 1
                    header = self.headers.get("Range")
                    if header:
                        match = re.fullmatch(r"bytes=([0-9]*)-([0-9]*)", header)
                        try:
                            if not match or not any(match.groups()) or size == 0:
                                raise ValueError
                            first, last = match.groups()
                            if first:
                                start = int(first)
                                end = min(int(last), size - 1) if last else size - 1
                            else:
                                count = int(last)
                                if count <= 0:
                                    raise ValueError
                                start = max(0, size - count)
                            if not 0 <= start <= end < size:
                                raise ValueError
                        except ValueError:
                            self.send_response(416)
                            self.send_header("Content-Range", f"bytes */{size}")
                            self.send_header("Content-Length", "0")
                            self.end_headers()
                            return
                    self.send_response(206 if header else 200)
                    self.send_header("Content-Type", entry[1])
                    self.send_header("Content-Length", str(max(0, end - start + 1)))
                    self.send_header("Accept-Ranges", "bytes")
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.send_header("X-Content-Type-Options", "nosniff")
                    self.send_header("Cache-Control", "private, no-store")
                    if header:
                        self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
                    self.end_headers()
                    if head:
                        return
                    source.seek(start)
                    remaining = end - start + 1
                    try:
                        while remaining > 0:
                            chunk = source.read(min(65536, remaining))
                            if not chunk:
                                break
                            self.wfile.write(chunk)
                            remaining -= len(chunk)
                    except (OSError, TimeoutError):
                        LOG.debug("Receiver closed media transfer")

        try:
            self._server = Server((self.ip, self.port), Handler)
        except OSError as error:
            raise RuntimeError(
                f"Cannot bind media HTTP to {self.ip}:{self.port}; port occupied or interface unavailable"
            ) from error
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            kwargs={"poll_interval": 0.1},
            daemon=True,
            name="tv-http",
        )
        self._thread.start()
