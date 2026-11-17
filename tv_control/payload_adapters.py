"""Step two adapters. Payload URLs stay local; authentication is never inferred from ports."""

import base64
import json
import re
import socket
import ssl
import time
from urllib.parse import urlencode
from uuid import UUID

from .media import Media


def dlna_image(folder, endpoint):
    """Adapt baseline JPEG dimensions to an advertised DLNA image profile."""
    from PIL import Image

    supported = {
        "JPEG_LRG": (4096, 4096),
        "JPEG_MED": (1024, 768),
        "JPEG_SM": (640, 480),
        "JPEG_TN": (160, 160),
    }
    profiles = set()
    for sink in endpoint.details.get("sink", []):
        parts = sink.split(":", 3)
        if len(parts) != 4 or parts[0] != "http-get" or parts[2] not in ("image/jpeg", "*"):
            continue
        match = re.search(r"(?:^|;)DLNA\.ORG_PN=([^;]+)", parts[3], re.I)
        if match is None:
            return Media(folder / "image.jpg", "image/jpeg", True)
        profiles.add(match.group(1))
    for profile, dimensions in supported.items():
        if profile in profiles:
            path = folder / (profile + ".jpg")
            with Image.open(folder / "image.jpg") as image:
                image.thumbnail(dimensions, Image.Resampling.LANCZOS)
                image.save(path, "JPEG", quality=95, progressive=False)
            return Media(path, "image/jpeg", True, dlna_profile=profile)
    return None


def cast_connection(endpoint, config):
    import pychromecast
    from pychromecast.models import CastInfo, HostServiceInfo

    info = CastInfo(
        {HostServiceInfo(endpoint.ip, endpoint.port)},
        UUID(endpoint.uid),
        endpoint.model,
        endpoint.name,
        endpoint.ip,
        endpoint.port,
        endpoint.details.get("cast_type", "cast"),
        endpoint.manufacturer,
    )
    cast = pychromecast.get_chromecast_from_cast_info(
        info, None, tries=1, timeout=config.request_timeout, retry_wait=0.2
    )
    try:
        cast.wait(timeout=config.connect_timeout)
        return cast
    except BaseException:
        cast.disconnect(timeout=config.request_timeout)
        raise


class CastHTML:
    def __init__(self, endpoint, config):
        self.endpoint, self.config = endpoint, config
        self.cast = None
        self.session = None

    def launch(self, url):
        from pychromecast.controllers.dashcast import DashCastController
        from pychromecast.response_handler import WaitResponse

        self.cast = cast_connection(self.endpoint, self.config)
        controller = DashCastController()
        self.cast.register_handler(controller)
        # Force-navigation replaces DashCast's document and its custom namespace.
        # LAUNCH on that same app can return the old session instead of reloading it.
        if self.cast.app_id == controller.supporting_app_id and not controller.is_active:
            self.cast.quit_app(timeout=self.config.connect_timeout)
        response = WaitResponse(self.config.connect_timeout, "TV Payload web viewer")
        controller.launch(callback_function=response.callback)
        response.wait_response()
        deadline = time.monotonic() + self.config.connect_timeout
        while not controller.is_active:
            if time.monotonic() >= deadline:
                raise TimeoutError("DashCast did not expose its URL-loading namespace")
            self.cast.socket_client.receiver_controller.update_status()
            time.sleep(0.2)
        # DashCast navigation has no request-id response. The HTML's receipt is
        # the execution acknowledgement, not a Cast load callback.
        controller.load_url(url, force=True)
        self.session = getattr(self.cast.status, "session_id", None)

    def close(self):
        if self.cast:
            # Disconnect only. The self-contained HTML can remain visible on the TV.
            self.cast.disconnect(timeout=self.config.request_timeout)
            self.cast = None


def websocket_connect(target, port, path, timeout):
    import websocket

    # These TV APIs use self-signed device certificates. Never follow a redirect to another host.
    secure = port in (8002, 3001)
    transport = socket.create_connection((target, port), timeout=timeout)
    try:
        if secure:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            transport = context.wrap_socket(transport, server_hostname=target)
        return websocket.create_connection(
            f"{'wss' if secure else 'ws'}://{target}:{port}{path}",
            socket=transport,
            timeout=timeout,
            redirect_limit=0,
            suppress_origin=True,
        )
    except BaseException:
        transport.close()
        raise


def receive(ws, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("TV response timed out")
    ws.settimeout(remaining)
    raw = ws.recv()
    if len(raw) > 1024 * 1024:
        raise ValueError("TV websocket response too large")
    return json.loads(raw)


class SamsungHTML:
    def __init__(self, endpoint, config, credentials):
        self.endpoint, self.config, self.credentials = endpoint, config, credentials

    def launch(self, url):
        token = self.credentials.get("samsung_token")
        if not token:
            raise RuntimeError("Samsung requires a previously authorized remote token")
        params = urlencode({"name": base64.b64encode(b"POLTERHEIST").decode(), "token": token})
        ws = websocket_connect(
            self.endpoint.ip,
            8002,
            "/api/v2/channels/samsung.remote.control?" + params,
            self.config.connect_timeout,
        )
        try:
            deadline = time.monotonic() + self.config.connect_timeout
            while True:
                data = receive(ws, deadline)
                if data.get("event") == "ms.channel.unauthorized":
                    raise RuntimeError("Samsung rejected the stored authorization")
                if data.get("event") == "ms.channel.connect":
                    break
            ws.send(
                json.dumps(
                    {
                        "method": "ms.channel.emit",
                        "params": {
                            "event": "ed.apps.launch",
                            "to": "host",
                            "data": {
                                "appId": "org.tizen.browser",
                                "action_type": "NATIVE_LAUNCH",
                                "metaTag": url,
                            },
                        },
                    }
                )
            )
            # The HTML render receipt, not a websocket write, confirms execution.
        finally:
            ws.close()

    def close(self):
        pass


class WebOSHTML:
    def __init__(self, endpoint, config, credentials):
        self.endpoint, self.config, self.credentials = endpoint, config, credentials

    def launch(self, url):
        key = self.credentials.get("webos_client_key")
        if not key:
            raise RuntimeError("LG webOS requires a previously authorized client key")
        ws = websocket_connect(self.endpoint.ip, 3001, "/", self.config.connect_timeout)
        try:
            ws.send(
                json.dumps(
                    {
                        "id": "register",
                        "type": "register",
                        "payload": {
                            "client-key": key,
                            "manifest": {
                                "manifestVersion": 1,
                                "appVersion": "1.0",
                                "permissions": ["LAUNCH", "LAUNCH_WEBAPP"],
                            },
                        },
                    }
                )
            )
            deadline = time.monotonic() + self.config.connect_timeout
            while True:
                data = receive(ws, deadline)
                if data.get("type") == "registered":
                    break
                if data.get("type") == "error" or data.get("payload", {}).get("pairingType"):
                    raise RuntimeError(
                        "LG webOS requires renewed authorization; no pairing attempted"
                    )
            ws.send(
                json.dumps(
                    {
                        "id": "open",
                        "type": "request",
                        "uri": "ssap://system.launcher/open",
                        "payload": {"target": url},
                    }
                )
            )
            while True:
                data = receive(ws, deadline)
                if data.get("id") == "open":
                    if (
                        data.get("type") == "error"
                        or data.get("payload", {}).get("returnValue") is not True
                    ):
                        raise RuntimeError("LG webOS did not acknowledge browser launch")
                    break
        finally:
            ws.close()

    def close(self):
        pass
