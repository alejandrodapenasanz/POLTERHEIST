"""Google Cast discovery via mDNS and playback through PyChromecast."""

import json
import logging
import threading
import time
from uuid import UUID

from ..models import Endpoint, PlaybackStatus, SessionLost, Unsupported
from ..network import local_request
from .base import Backend

LOG = logging.getLogger(__name__)
SERVICE = "_googlecast._tcp.local."
MEDIA_APP = "CC1AD845"
IDLE_APP = "E8C28D3C"


def cast_endpoint(uid, ip, port, name, model, manufacturer="Unknown", video=None):
    UUID(str(uid))  # Reject fabricated identities/partial advertisements for control.
    kind = "Media receiver (display capability unknown)"
    if video is False:
        kind = "Audio receiver"
    elif video:
        kind = "TV (advertised model)" if "tv" in model.lower() else "Video receiver"
    return Endpoint(
        "Google Cast",
        str(UUID(str(uid))),
        ip,
        port,
        name,
        model,
        manufacturer,
        kind,
        video is True,
        "Video advertised; connection unverified" if video else "Discovered only",
        {"cast_type": "audio" if video is False else "cast"},
    )


def from_service(info, network):
    ip = next((ip for ip in info.parsed_addresses() if network.accepts(ip)), None)
    if not ip or not info.port or not 1 <= info.port <= 65535:
        return None
    properties = {
        k.decode("utf-8", "replace"): (v or b"").decode("utf-8", "replace")
        for k, v in info.properties.items()
    }
    try:
        video = bool(int(properties["ca"]) & 1) if "ca" in properties else None
        endpoint = cast_endpoint(
            properties.get("id", ""),
            ip,
            info.port,
            properties.get("fn", "Unknown"),
            properties.get("md", "Unknown"),
            video=video,
        )
        endpoint.sources = ["mDNS/DNS-SD"]
        endpoint.addresses = info.parsed_addresses()[:32]
        endpoint.reachability = "ADVERTISEMENT RECEIVED; TRANSPORT UNTESTED"
        endpoint.evidence = ["_googlecast._tcp service, UUID and advertised capability bitmask"]
        return endpoint
    except (ValueError, TypeError):
        return Endpoint(
            "Google Cast",
            info.name,
            ip,
            info.port,
            properties.get("fn", "Unknown"),
            properties.get("md", "Unknown"),
            note="Partial mDNS advertisement; identity/capabilities invalid",
        )


def discover(network, config, target=None):
    if target:
        # A protocol response, never an open TCP port, establishes identity.
        _, raw = local_request(
            f"http://{target}:8008/setup/eureka_info?params=device_info,name",
            target,
            network,
            config.request_timeout,
        )
        data = json.loads(raw)
        detail = data.get("device_info", {})
        uid = detail.get("ssdp_udn") or data.get("ssdp_udn", "")
        endpoint = cast_endpoint(
            uid.removeprefix("uuid:"),
            target,
            8009,
            detail.get("name") or data.get("name", "Unknown"),
            detail.get("model_name", "Unknown"),
            detail.get("manufacturer", "Unknown"),
            detail.get("capabilities", {}).get("display_supported"),
        )
        endpoint.sources = ["Directed HTTP / Cast device info"]
        endpoint.reachability = "HTTP REACHABLE; CAST TRANSPORT UNTESTED"
        endpoint.confidence = "PROTOCOL RESPONSE"
        endpoint.evidence = ["Cast device-info JSON with valid UUID; not a Cast connection test"]
        return [endpoint]
    from zeroconf import IPVersion, ServiceBrowser, Zeroconf

    found = {}
    lock = threading.Lock()
    deadline = time.monotonic() + config.discovery_timeout

    class Listener:
        def add_service(self, zc, type_, name):
            with lock:
                if len(found) >= config.max_devices:
                    return
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            info = zc.get_service_info(type_, name, timeout=min(remaining * 1000, 500))
            if info:
                endpoint = from_service(info, network)
                if endpoint:
                    with lock:
                        found[endpoint.uid] = endpoint

        update_service = add_service

        def remove_service(self, zc, type_, name):
            pass

    zc = Zeroconf(interfaces=[network.ip], ip_version=IPVersion.V4Only)
    browser = None
    try:
        browser = ServiceBrowser(zc, SERVICE, Listener())
        threading.Event().wait(max(0, deadline - time.monotonic()))
    finally:
        if browser:
            browser.cancel()
        zc.close()
    return list(found.values())


class GoogleCast(Backend):
    def __init__(self, *args):
        super().__init__(*args)
        self.cast = None

    def connect(self):
        import pychromecast
        from pychromecast.models import CastInfo, HostServiceInfo

        e = self.endpoint
        info = CastInfo(
            {HostServiceInfo(e.ip, e.port)},
            UUID(e.uid),
            e.model,
            e.name,
            e.ip,
            e.port,
            e.details["cast_type"],
            e.manufacturer,
        )
        # Supplying verified discovery metadata avoids a second, unscoped DIAL probe.
        self.cast = pychromecast.get_chromecast_from_cast_info(
            info, None, tries=1, timeout=self.config.request_timeout, retry_wait=0.2
        )
        self.cast.wait(timeout=self.config.connect_timeout)
        if self.cast.app_id not in (None, IDLE_APP, MEDIA_APP):
            raise RuntimeError("Receiver busy in another app; close it on the receiver and retry")
        if self.cast.app_id == MEDIA_APP and self.get_status().state in (
            "PLAYING",
            "PAUSED",
            "BUFFERING",
        ):
            raise RuntimeError(
                "Receiver busy playing other content; stop it on the receiver and retry"
            )

    def _request(self, method, *args, **kwargs):
        from pychromecast.response_handler import WaitResponse

        response = WaitResponse(self.config.request_timeout, "TV control")
        method(*args, callback_function=response.callback, **kwargs)
        response.wait_response()
        data = response.response or {}
        if data.get("type") in (
            "LOAD_FAILED",
            "LOAD_CANCELLED",
            "INVALID_REQUEST",
            "INVALID_PLAYER_STATE",
        ):
            raise RuntimeError(
                "Cast rejected operation: " + data["type"] + " " + str(data.get("reason", ""))
            )
        return data

    def play(self, url, media):
        if self.url:
            self.require_owned()
        self.url = url
        mc = self.cast.media_controller
        # Public PyChromecast controller API; one-item native Cast repeat queue.
        try:
            self._request(
                mc.send_message,
                {
                    "type": "QUEUE_LOAD",
                    "repeatMode": "REPEAT_ALL",
                    "startIndex": 0,
                    "items": [
                        {
                            "autoplay": True,
                            "startTime": 0,
                            "preloadTime": 0,
                            "media": {
                                "contentId": url,
                                "contentType": media.mime,
                                "streamType": "BUFFERED",
                            },
                        }
                    ],
                },
                inc_session_id=True,
            )
        except RuntimeError as error:
            if "INVALID_REQUEST" not in str(error):
                raise
            # Legacy receivers without queues use the session's bounded EOF loop.
            self._request(mc.play_media, url, media.mime, title=media.path.name)

    def get_status(self):
        if self.cast.app_id not in (MEDIA_APP,):
            return PlaybackStatus("IDLE" if self.cast.app_id in (None, IDLE_APP) else "EXTERNAL")
        response = self._request(self.cast.media_controller.update_status)
        if "status" in response and not response["status"]:
            return PlaybackStatus(
                "IDLE"
            )  # PyChromecast otherwise retains its last nonempty status.
        status = self.cast.media_controller.status
        state = status.player_state
        reason = status.idle_reason
        if state == "IDLE" and reason == "ERROR":
            return PlaybackStatus(
                "ERROR",
                status.content_id or "",
                error="Receiver rejected media or cannot reach HTTP URL",
            )
        return PlaybackStatus(state, status.content_id or "", reason == "FINISHED")

    def pause(self):
        self.require_owned()
        if not self.cast.media_controller.status.supports_pause:
            raise Unsupported("Cast receiver does not support pause for this media")
        self.cast.media_controller.pause(timeout=self.config.request_timeout)

    def resume(self):
        self.require_owned()
        if not self.cast.media_controller.status.supports_pause:
            raise Unsupported("Cast receiver does not support resume for this media")
        self.cast.media_controller.play(timeout=self.config.request_timeout)

    def stop(self):
        try:
            self.require_owned()
        except SessionLost:
            return False
        self.cast.media_controller.stop(timeout=self.config.request_timeout)
        return True

    def disconnect(self):
        if self.cast:
            self.cast.disconnect(timeout=self.config.request_timeout)
            self.cast = None
