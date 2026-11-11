"""Offline protocol fixtures, receiver mocks and real loopback HTTP; no TV required."""

import contextlib
import io
import ipaddress
import json
import logging
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock, patch

import script as app
from tv_control import cli, discovery, media, network
from tv_control.http_server import MediaServer
from tv_control.manager import Manager, Session
from tv_control.models import Config, Device, Endpoint, PlaybackStatus, SessionLost, Unsupported
from tv_control.protocols import airplay, dlna, google_cast
from tv_control.protocols.base import Backend

NETWORK = network.Network("fixture", "192.0.2.10", ipaddress.IPv4Network("192.0.2.0/24"))
CONFIG = Config(
    discovery_timeout=0.1, request_timeout=0.2, connect_timeout=0.3, poll_interval=0.1, retries=0
)
UID = "00000000-0000-0000-0000-000000000001"
VIDEO = {
    "codec_type": "video",
    "codec_name": "h264",
    "width": 1280,
    "height": 720,
    "pix_fmt": "yuv420p",
    "profile": "Main",
    "level": 31,
    "avg_frame_rate": "30/1",
}
AUDIO = {"codec_type": "audio", "codec_name": "aac", "profile": "LC", "channels": 2}
DESCRIPTION = b"""<root xmlns="urn:schemas-upnp-org:device-1-0"><device>
<deviceType>urn:schemas-upnp-org:device:MediaRenderer:1</deviceType><UDN>uuid:renderer</UDN>
<friendlyName>Fixture TV</friendlyName><manufacturer>Fixture</manufacturer><modelName>TV-1</modelName>
<serviceList><service><serviceType>urn:schemas-upnp-org:service:AVTransport:1</serviceType>
<controlURL>/control</controlURL><SCPDURL>/av.xml</SCPDURL></service>
<service><serviceType>urn:schemas-upnp-org:service:ConnectionManager:1</serviceType>
<controlURL>/connection</controlURL><SCPDURL>/cm.xml</SCPDURL></service></serviceList></device></root>"""


def schema(actions):
    return (
        "<scpd><actionList>"
        + "".join(f"<action><name>{a}</name></action>" for a in actions)
        + "</actionList><serviceStateTable><stateVariable><name>CurrentPlayMode</name>"
        "<allowedValueList><allowedValue>REPEAT_ALL</allowedValue></allowedValueList>"
        "</stateVariable></serviceStateTable></scpd>"
    ).encode()


def soap(name, values):
    return (
        f'<s:Envelope xmlns:s="{dlna.SOAP}"><s:Body><u:{name}Response xmlns:u="urn:fixture">'
        + "".join(f"<{k}>{v}</{k}>" for k, v in values.items())
        + f"</u:{name}Response></s:Body></s:Envelope>"
    ).encode()


def endpoint(index=1, protocol="Google Cast", ip=None):
    return Endpoint(
        protocol,
        f"00000000-0000-0000-0000-{index:012d}",
        ip or f"192.0.2.{index}",
        8009,
        f"Receiver {index}",
        "Fixture TV",
        controllable=True,
        details={"cast_type": "cast"},
    )


def device(index=1, **kwargs):
    return Device(index, [endpoint(index, **kwargs)])


def fixture_dlna(url, *args, **kwargs):
    if url.endswith("device.xml"):
        return 200, DESCRIPTION
    if url.endswith("av.xml"):
        return 200, schema(dlna.REQUIRED | {"Pause", "GetPositionInfo", "SetPlayMode"})
    if url.endswith("cm.xml"):
        return 200, schema({"GetProtocolInfo"})
    if url.endswith("connection"):
        return 200, soap(
            "GetProtocolInfo",
            {"Source": "", "Sink": "http-get:*:video/mp4:*,http-get:*:image/jpeg:*"},
        )
    raise AssertionError(url)


class QuietTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.output = io.StringIO()
        capture = contextlib.redirect_stdout(self.output)
        capture.__enter__()
        self.addCleanup(capture.__exit__, None, None, None)
        # Production installs a rotating file handler, tests keep expected failures quiet.
        logger = logging.getLogger("tv_control")
        previous = logger.disabled
        disable = patch("logging.Logger.handle", return_value=None)
        disable.start()
        self.addCleanup(disable.stop)
        self.addCleanup(setattr, logger, "disabled", previous)


class DiscoveryTests(QuietTest):
    def service(self, properties=None):
        return SimpleNamespace(
            name="fixture." + google_cast.SERVICE,
            port=8009,
            parsed_addresses=lambda: ["192.0.2.1"],
            properties=properties
            or {b"id": UID.encode(), b"fn": b"Lab TV", b"md": b"Fixture TV", b"ca": b"5"},
        )

    def test_cast_mdns_discovery_and_cleanup(self):
        zc = Mock()
        zc.get_service_info.return_value = self.service()
        browser = Mock()

        def create(zconf, type_, listener):
            listener.add_service(zconf, type_, "fixture")
            return browser

        with (
            patch("zeroconf.Zeroconf", return_value=zc) as construct,
            patch("zeroconf.ServiceBrowser", side_effect=create),
        ):
            found = google_cast.discover(NETWORK, CONFIG)
        self.assertEqual(found[0].name, "Lab TV")
        self.assertEqual(found[0].ip, "192.0.2.1")
        self.assertTrue(found[0].controllable)
        self.assertEqual(construct.call_args.kwargs["interfaces"], [NETWORK.ip])
        browser.cancel.assert_called_once()
        zc.close.assert_called_once()

    def test_partial_audio_and_off_subnet_cast(self):
        partial = google_cast.from_service(self.service({b"fn": b"Partial"}), NETWORK)
        self.assertFalse(partial.controllable)
        audio = google_cast.from_service(self.service({b"id": UID.encode(), b"ca": b"4"}), NETWORK)
        self.assertEqual(audio.kind, "Audio receiver")
        self.assertFalse(audio.controllable)
        service = self.service()
        service.parsed_addresses = lambda: ["198.51.100.1"]
        self.assertIsNone(google_cast.from_service(service, NETWORK))

    def test_directed_cast_requires_protocol_evidence(self):
        data = {
            "name": "Manual TV",
            "device_info": {
                "ssdp_udn": UID,
                "model_name": "Model",
                "capabilities": {"display_supported": True},
            },
        }
        with patch.object(
            google_cast, "local_request", return_value=(200, json.dumps(data).encode())
        ):
            self.assertTrue(google_cast.discover(NETWORK, CONFIG, "192.0.2.1")[0].controllable)
        with patch.object(google_cast, "local_request", return_value=(200, b"{}")):
            with self.assertRaises(ValueError):
                google_cast.discover(NETWORK, CONFIG, "192.0.2.1")

    def test_dlna_ssdp_description_and_capabilities(self):
        response = b"HTTP/1.1 200 OK\r\nLOCATION: http://192.0.2.1/device.xml\r\n\r\n"
        sock = MagicMock()
        sock.__enter__.return_value = sock
        sock.recvfrom.side_effect = [(response, ("192.0.2.1", 1900)), socket.timeout()]
        with (
            patch.object(dlna.socket, "socket", return_value=sock),
            patch.object(dlna, "local_request", side_effect=fixture_dlna),
        ):
            found = dlna.discover(NETWORK, CONFIG)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].manufacturer, "Fixture")
        self.assertTrue(found[0].controllable)
        self.assertIn("http-get:*:image/jpeg:*", found[0].details["sink"])
        self.assertEqual(sock.sendto.call_count, 1)

    def test_dlna_partial_description_and_external_service_rejected(self):
        with patch.object(
            dlna,
            "local_request",
            return_value=(200, DESCRIPTION.replace(b"/av.xml", b"http://198.51.100.1/av.xml")),
        ):
            result = dlna.describe("http://192.0.2.1/device.xml", "192.0.2.1", NETWORK, CONFIG)
        self.assertFalse(result[0].controllable)

    def test_dlna_non_renderer_is_not_a_tv(self):
        with patch.object(
            dlna,
            "local_request",
            return_value=(200, DESCRIPTION.replace(b"MediaRenderer", b"MediaServer")),
        ):
            self.assertEqual(
                dlna.describe("http://192.0.2.1/device.xml", "192.0.2.1", NETWORK, CONFIG), []
            )

    def test_dlna_unreachable_renderer_is_shown_as_discovery_only(self):
        packet = (
            "HTTP/1.1 200 OK\r\nLOCATION: http://192.0.2.1/device.xml\r\n"
            "ST: urn:schemas-upnp-org:device:MediaRenderer:1\r\nUSN: uuid:partial\r\n\r\n"
        ).encode()
        sock = MagicMock()
        sock.__enter__.return_value = sock
        sock.recvfrom.side_effect = [(packet, ("192.0.2.1", 1900)), socket.timeout()]
        with (
            patch.object(dlna.socket, "socket", return_value=sock),
            patch.object(dlna, "describe", side_effect=TimeoutError),
        ):
            result = dlna.discover(NETWORK, CONFIG)
        self.assertEqual(result[0].uid, "uuid:partial")
        self.assertFalse(result[0].controllable)
        self.assertEqual(result[0].model, "Unknown")

    def test_dedup_ids_stable_across_refresh_ip_change_and_directed_scan(self):
        registry = discovery.Discovery(NETWORK, CONFIG)
        cast = endpoint()
        renderer = endpoint(protocol="DLNA")
        registry.merge([cast, cast, renderer])
        self.assertEqual(len(registry.devices), 1)
        self.assertEqual(len(registry.devices[1].endpoints), 2)
        registry.merge([replace(cast, ip="192.0.2.30"), endpoint(2)])
        self.assertEqual(registry.devices[1].primary.ip, "192.0.2.30")
        self.assertEqual(set(registry.devices), {1, 2})
        registry.merge([replace(renderer, ip="192.0.2.30")], refresh=False)
        self.assertEqual(len(registry.devices[1].endpoints), 2)
        self.assertTrue(registry.devices[2].available)
        registry.merge([])
        self.assertTrue(all(not d.available for d in registry.devices.values()))

    def test_same_protocol_receivers_on_same_host_are_not_collapsed(self):
        registry = discovery.Discovery(NETWORK, CONFIG)
        registry.merge([endpoint(1), endpoint(2, ip="192.0.2.1")])
        self.assertEqual(len(registry.devices), 2)

    def test_one_discovery_protocol_failure_preserves_other(self):
        registry = discovery.Discovery(NETWORK, CONFIG)
        with (
            patch.object(google_cast, "discover", side_effect=RuntimeError("mDNS failed")),
            patch.object(dlna, "discover", return_value=[endpoint(protocol="DLNA")]),
            patch.object(airplay, "discover", return_value=[]),
        ):
            registry.scan()
        self.assertTrue(registry.devices[1].controllable)
        self.assertIn("mDNS failed", registry.warnings[0])

    def test_select_all_specific_and_invalid_ids(self):
        devices = [device(1), device(2), Device(3, [replace(endpoint(3), controllable=False)])]
        self.assertEqual([d.id for d in discovery.select_devices(devices)], [1, 2])
        self.assertEqual([d.id for d in discovery.select_devices(devices, "2, 1")], [2, 1])
        for text in ("", " ", "1,1", "99", "1;2", "1,,2", "-1", "3", "1,", "one"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                discovery.select_devices(devices, text)
        devices[0].available = False
        with self.assertRaisesRegex(ValueError, "unavailable"):
            discovery.select_devices(devices, "1")


class NetworkTests(QuietTest):
    def test_url_scope_redirect_credentials_and_xml_entities(self):
        for url in (
            "https://192.0.2.1/a",
            "file:///a",
            "http://198.51.100.1/a",
            "http://localhost/a",
            "http://user@192.0.2.1/a",
            "http://192.0.2.1:99999/a",
            "http://192.0.2.1/a#x",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                network.checked_url(url, "192.0.2.1", NETWORK)
        with self.assertRaises(ValueError):
            network.parse_xml(b'<!DOCTYPE root [<!ENTITY a "x">]><root>&a;</root>')
        with self.assertRaises(ValueError):
            network.parse_xml("<!DOCTYPE root><root/>".encode("utf-16"))
        connection = MagicMock()
        connection.getresponse.return_value.status = 302
        with patch.object(network.http.client, "HTTPConnection", return_value=connection):
            with self.assertRaisesRegex(RuntimeError, "302"):
                network.local_request("http://192.0.2.1/a", "192.0.2.1", NETWORK, 1)
        connection.close.assert_called_once()

    def test_description_size_is_bounded(self):
        connection = MagicMock()
        response = connection.getresponse.return_value
        response.status = 200
        response.read1.return_value = b"x" * 65536
        with patch.object(network.http.client, "HTTPConnection", return_value=connection):
            with self.assertRaisesRegex(ValueError, "1 MiB"):
                network.local_request("http://192.0.2.1/a", "192.0.2.1", NETWORK, 1)
        self.assertEqual(response.read1.call_count, 17)

    def test_select_interface_subnet_and_reject_nonlocal_target(self):
        adapter = SimpleNamespace(
            nice_name="Ethernet", ips=[SimpleNamespace(ip="192.0.2.10", network_prefix=24)]
        )
        with patch("ifaddr.get_adapters", return_value=[adapter]):
            selected = network.detect_network("192.0.2.10")
        self.assertEqual(selected.subnet, NETWORK.subnet)
        for ip in ("8.8.8.8", "192.0.2.0", "192.0.2.255", "192.0.2.10", "localhost"):
            with self.subTest(ip=ip), self.assertRaises(ValueError):
                selected.target(ip)


class MediaTests(QuietTest):
    def setUp(self):
        super().setUp()
        self.library = media.MediaLibrary(self.root, CONFIG)

    def file(self, name="movie.mp4"):
        path = self.library.folder / name
        path.write_bytes(b"fixture")
        return path

    def test_listing_uses_project_media_not_cwd_or_system(self):
        for name in (
            "photo.PNG",
            "photo.jpg",
            "photo.webp",
            "movie.MP4",
            "movie.mkv",
            "movie.mov",
            "movie.webm",
            "ignore.txt",
        ):
            self.file(name)
        self.assertEqual(len(self.library.list("image")), 3)
        self.assertEqual(len(self.library.list("video")), 4)

    def test_mismatched_image_extension_and_corrupt_file(self):
        path = self.file("fake.png")
        probe = json.dumps({"streams": [{**VIDEO, "codec_name": "mjpeg"}]}).encode()
        with patch.object(self.library, "_run", return_value=probe):
            with self.assertRaisesRegex(ValueError, "extension"):
                self.library.inspect(path)
        probe = json.dumps({"streams": [{**VIDEO, "codec_name": "png"}]}).encode()
        with patch.object(self.library, "_run", side_effect=[probe, ValueError("corrupt")]):
            with self.assertRaisesRegex(ValueError, "corrupt"):
                self.library.inspect(path)

    def test_video_probe_codec_and_container_checks(self):
        path = self.file()
        data = {
            "streams": [VIDEO, AUDIO],
            "format": {"format_name": "mov,mp4,m4a,3gp,3g2,mj2", "duration": "3.5"},
        }
        with patch.object(self.library, "_run", return_value=json.dumps(data).encode()) as run:
            result = self.library.inspect(path)
        self.assertEqual(result.duration, 3.5)
        self.assertTrue(self.library.baseline(result))
        self.assertIn("-protocol_whitelist", run.call_args.args[1])
        data["format"]["format_name"] = "matroska,webm"
        with patch.object(self.library, "_run", return_value=json.dumps(data).encode()):
            with self.assertRaisesRegex(ValueError, "container"):
                self.library.inspect(path)

    def test_missing_tools_and_nonzero_exit(self):
        with patch.object(media.shutil, "which", return_value=None):
            with self.assertRaisesRegex(RuntimeError, "ffprobe not installed"):
                self.library.inspect(self.file())
        process = Mock()
        process.communicate.return_value = (b"", b"decoder failed")
        process.returncode = 1
        process.poll.return_value = 1
        with (
            patch.object(media.shutil, "which", return_value="ffmpeg"),
            patch.object(media.subprocess, "Popen", return_value=process),
        ):
            with self.assertRaises(ValueError):
                self.library._run("ffmpeg", [], 1)

    def test_compatible_video_no_conversion_and_incompatible_policy(self):
        compatible = media.Media(self.file(), "video/mp4", False, 3, VIDEO, (AUDIO,))
        with (
            patch.object(self.library, "inspect", return_value=compatible),
            patch.object(self.library, "convert") as convert,
        ):
            self.assertIs(self.library.prepare(compatible.path, endpoint()), compatible)
            convert.assert_not_called()
        incompatible = replace(compatible, video={**VIDEO, "codec_name": "hevc"})
        self.library.config = replace(CONFIG, auto_convert=False)
        with patch.object(self.library, "inspect", return_value=incompatible):
            with self.assertRaisesRegex(Unsupported, "Conversion needed"):
                self.library.prepare(compatible.path, endpoint())

    def test_native_dlna_image_and_unadvertised_video(self):
        image = media.Media(self.file("photo.jpg"), "image/jpeg", True)
        receiver = endpoint(protocol="DLNA")
        receiver.details["sink"] = ["http-get:*:image/jpeg:*"]
        with (
            patch.object(self.library, "inspect", return_value=image),
            patch.object(self.library, "convert") as convert,
        ):
            self.assertIs(self.library.prepare(image.path, receiver), image)
            convert.assert_not_called()
        with patch.object(self.library, "inspect", return_value=replace(image, mime="image/png")):
            with self.assertRaises(Unsupported):
                self.library.prepare(image.path, receiver)

    def test_restrictive_dlna_profiles_are_not_overridden_by_mime(self):
        content = media.Media(self.file(), "video/mp4", False, 10, VIDEO, (AUDIO,))
        receiver = endpoint(protocol="DLNA")
        receiver.details["sink"] = ["http-get:*:video/mp4:DLNA.ORG_PN=AVC_MP4_BL_CIF15_AAC_520"]
        with patch.object(self.library, "inspect", return_value=content):
            with self.assertRaisesRegex(Unsupported, "profile-specific"):
                self.library.prepare(content.path, receiver)

    def test_compatible_webm_plays_without_conversion(self):
        content = media.Media(
            self.file("video.webm"),
            "video/webm",
            False,
            10,
            {**VIDEO, "codec_name": "vp8"},
            ({**AUDIO, "codec_name": "vorbis"},),
        )
        with (
            patch.object(self.library, "inspect", return_value=content),
            patch.object(self.library, "convert") as convert,
        ):
            self.assertIs(self.library.prepare(content.path, endpoint()), content)
            convert.assert_not_called()

    def test_image_conversion_parameters_cache_and_source_change(self):
        image = media.Media(self.file("photo.png"), "image/png", True)
        calls = []

        def run(binary, args, timeout):
            calls.append(args)
            Path(args[-1]).write_bytes(b"converted")

        def inspect(path):
            return media.Media(Path(path), "video/mp4", False, 10, VIDEO, ())

        with (
            patch.object(self.library, "_run", side_effect=run),
            patch.object(self.library, "inspect", side_effect=inspect),
        ):
            first = self.library.convert(image)
            second = self.library.convert(image)
            self.assertEqual(first.path, second.path)
            self.assertEqual(len(calls), 1)
            image.path.write_bytes(b"changed")
            third = self.library.convert(image)
            self.assertNotEqual(first.path, third.path)
        for option in ("libx264", "yuv420p", "+faststart", "-loop", "stillimage"):
            self.assertIn(option, calls[0])
        self.assertIn("force_original_aspect_ratio=decrease", " ".join(calls[0]))
        self.assertEqual(calls[0][calls[0].index("-t") + 1], "10")

    def test_conversion_failure_removes_partial_output(self):
        image = media.Media(self.file("photo.png"), "image/png", True)

        def fail(binary, args, timeout):
            Path(args[-1]).write_bytes(b"partial")
            raise RuntimeError("conversion failed")

        with patch.object(self.library, "_run", side_effect=fail):
            with self.assertRaises(RuntimeError):
                self.library.convert(image)
        self.assertEqual(list(self.library.cache.iterdir()), [])

    def test_cancellation_terminates_converter(self):
        event = threading.Event()
        self.library._local.cancel = event
        process = Mock()
        process.poll.return_value = None

        def communicate(timeout):
            event.set()
            if timeout == 0.2:
                raise subprocess.TimeoutExpired("ffmpeg", timeout)
            return b"", b""

        process.communicate.side_effect = communicate
        with (
            patch.object(media.shutil, "which", return_value="ffmpeg"),
            patch.object(media.subprocess, "Popen", return_value=process),
        ):
            with self.assertRaises(InterruptedError):
                self.library._run("ffmpeg", [], 1)
        process.terminate.assert_called_once()


class HTTPTests(QuietTest):
    def setUp(self):
        super().setUp()
        self.path = self.root / "movie.mp4"
        self.path.write_bytes(b"0123456789")
        self.server = MediaServer("127.0.0.1", 0, (self.root,))
        self.addCleanup(self.server.close)
        self.url = self.server.publish(media.Media(self.path, "video/mp4", False), "127.0.0.1")
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def fetch(self, url=None, headers=None, method="GET"):
        return self.opener.open(
            urllib.request.Request(url or self.url, headers=headers or {}, method=method), timeout=3
        )

    def test_full_get_head_mime_and_opaque_url(self):
        self.assertNotIn("movie", self.url)
        with self.fetch() as response:
            self.assertEqual(response.read(), b"0123456789")
            self.assertEqual(response.headers["Content-Type"], "video/mp4")
        with self.fetch(method="HEAD") as response:
            self.assertEqual(response.read(), b"")
            self.assertEqual(response.headers["Content-Length"], "10")

    def test_ranges_including_suffix_open_ended_and_invalid(self):
        for header, expected in (
            ("bytes=2-5", b"2345"),
            ("bytes=-3", b"789"),
            ("bytes=8-", b"89"),
            ("bytes=8-999", b"89"),
        ):
            with self.subTest(header=header), self.fetch(headers={"Range": header}) as response:
                self.assertEqual(response.status, 206)
                self.assertEqual(response.read(), expected)
        for header in (
            "bytes=11-",
            "bytes=5-2",
            "bytes=-0",
            "bytes=0-1,4-5",
            "bytes=-",
            "items=0-1",
        ):
            with self.subTest(header=header), self.assertRaises(urllib.error.HTTPError) as caught:
                self.fetch(headers={"Range": header})
            self.assertEqual(caught.exception.code, 416)
            caught.exception.close()

    def test_no_directory_traversal_unregistered_paths_or_arbitrary_publication(self):
        base = self.url.rsplit("/", 1)[0]
        for path in ("/", "/../movie.mp4", "/%2e%2e/movie.mp4", "/movie.mp4"):
            with self.subTest(path=path), self.assertRaises(urllib.error.HTTPError) as caught:
                self.fetch(base + path)
            self.assertEqual(caught.exception.code, 404)
            caught.exception.close()
        with tempfile.TemporaryDirectory() as outside:
            file = Path(outside) / "secret.mp4"
            file.write_bytes(b"private")
            with self.assertRaises(ValueError):
                self.server.publish(media.Media(file, "video/mp4", False), "127.0.0.1")

    def test_concurrent_requests_and_last_session_resource_release(self):
        from concurrent.futures import ThreadPoolExecutor

        def fetch():
            with self.fetch() as response:
                return response.read()

        other = self.server.publish(media.Media(self.path, "video/mp4", False), "127.0.0.1")
        with ThreadPoolExecutor(max_workers=4) as pool:
            self.assertEqual(list(pool.map(lambda _: fetch(), range(8))), [b"0123456789"] * 8)
        self.server.release(other)
        self.assertTrue(self.server.running)
        self.server.release(self.url)
        self.assertFalse(self.server.running)

    def test_wrong_peer_deleted_file_and_port_conflict(self):
        other = self.server.publish(media.Media(self.path, "video/mp4", False), "192.0.2.1")
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.fetch(other)
        self.assertEqual(caught.exception.code, 404)
        caught.exception.close()
        self.path.unlink()
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.fetch()
        caught.exception.close()
        self.path.write_bytes(b"data")
        occupied = MediaServer("127.0.0.1", self.server._server.server_port, (self.root,))
        with self.assertRaisesRegex(RuntimeError, "port occupied"):
            occupied.publish(media.Media(self.path, "video/mp4", False), "127.0.0.1")


class FakeBackend(Backend):
    def __init__(self, *args):
        super().__init__(*args)
        self.status = PlaybackStatus("IDLE")
        self.calls = []

    def connect(self):
        self.calls.append("connect")

    def play(self, url, media):
        self.calls.append("play")
        self.url = url
        self.status = PlaybackStatus("PLAYING", url)

    def get_status(self):
        return self.status

    def pause(self):
        self.require_owned()
        self.status = PlaybackStatus("PAUSED", self.url)

    def resume(self):
        self.require_owned()
        self.status = PlaybackStatus("PLAYING", self.url)

    def stop(self):
        if self.status.url == self.url:
            self.calls.append("stop")
            self.status = PlaybackStatus("STOPPED", self.url)

    def disconnect(self):
        self.calls.append("disconnect")


class SessionTests(QuietTest):
    def setUp(self):
        super().setUp()
        local = network.Network("loopback", "127.0.0.1", ipaddress.IPv4Network("127.0.0.0/8"))
        self.manager = Manager(self.root, local, CONFIG, FakeBackend)
        self.manager.server.port = 0
        self.addCleanup(self.manager.close)
        self.path = self.manager.library.folder / "video.mp4"
        self.path.write_bytes(b"video")
        self.content = media.Media(self.path, "video/mp4", False, 10, VIDEO, ())
        self.manager.library.inspect = Mock(return_value=self.content)
        self.manager.library.prepare = Mock(return_value=self.content)
        self.devices = [device(1, ip="127.0.0.1"), device(2, ip="127.0.0.1")]

    def wait_ready(self):
        for session in self.manager.sessions.values():
            self.assertTrue(session.ready.wait(3))

    def test_single_and_multiple_playback_stop_disconnect_and_http_release(self):
        self.manager.start(self.devices[:1], self.path, confirmed=True)
        self.wait_ready()
        self.assertEqual(self.manager.sessions[1].state, "PLAYING")
        self.manager.start(self.devices, self.path, confirmed=True)
        self.wait_ready()
        self.assertEqual([s.state for s in self.manager.sessions.values()], ["PLAYING", "PLAYING"])
        self.assertTrue(self.manager.server.running)
        self.manager.stop()
        self.assertFalse(self.manager.server.running)
        self.assertFalse(self.manager.active)
        for session in self.manager.sessions.values():
            self.assertIn("stop", session.backend.calls)
            self.assertIn("disconnect", session.backend.calls)

    def test_multiple_requires_confirmation_before_any_side_effect(self):
        with self.assertRaisesRegex(ValueError, "confirmation"):
            self.manager.start(self.devices, self.path)
        self.manager.library.inspect.assert_not_called()
        self.assertEqual(self.manager.sessions, {})

    def test_one_failure_does_not_stop_successful_receiver(self):
        def factory(e, n, c):
            backend = FakeBackend(e, n, c)
            if e.name.endswith("2"):
                backend.connect = Mock(side_effect=TimeoutError("offline"))
            return backend

        self.manager.backend_factory = factory
        self.manager.start(self.devices, self.path, confirmed=True)
        self.wait_ready()
        self.assertEqual(self.manager.sessions[1].state, "PLAYING")
        self.assertEqual(self.manager.sessions[2].state, "ERROR")
        self.assertTrue(self.manager.server.running)

    def test_eof_repeats_but_external_content_is_never_restarted(self):
        session = Session(self.devices[0], self.path, self.manager)
        session.media = self.content
        session.url = "http://local/owned"
        session.backend.url = session.url
        session.backend.status = PlaybackStatus("IDLE", session.url, finished=True)
        session.tick()
        self.assertEqual(session.backend.calls, ["play"])
        session.tick()
        self.assertEqual(session.state, "PLAYING")
        session.backend.status = PlaybackStatus("PLAYING", "http://other/foreign")
        with self.assertRaises(SessionLost):
            session.tick()
        self.assertEqual(session.backend.calls, ["play"])
        session.backend.stop()
        self.assertNotIn("stop", session.backend.calls)

    def test_failed_repeat_is_bounded(self):
        session = Session(self.devices[0], self.path, self.manager)
        session.media, session.url = self.content, "http://local/owned"
        session.backend.status = PlaybackStatus("IDLE", session.url, finished=True)
        session.backend.play = Mock()
        session.tick()
        with self.assertRaisesRegex(RuntimeError, "did not restart"):
            session.tick()
        session.backend.play.assert_called_once()

    def test_pause_resume_commands_and_cancellation(self):
        self.manager.start(self.devices[:1], self.path, confirmed=True)
        self.wait_ready()
        session = self.manager.sessions[1]
        self.manager.command("pause")
        deadline = time.monotonic() + 2
        while session.state != "PAUSED" and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertEqual(session.state, "PAUSED")
        self.manager.command("resume")
        deadline = time.monotonic() + 2
        while session.state != "PLAYING" and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertEqual(session.state, "PLAYING")
        self.manager.close()
        self.assertFalse(session.thread.is_alive())
        self.assertFalse(self.manager.server.running)

    def test_cancel_during_prepare_prevents_connect_and_http(self):
        entered = threading.Event()

        def prepare(source, endpoint, cancel):
            entered.set()
            cancel.wait(2)
            raise InterruptedError("cancelled")

        self.manager.library.prepare = prepare
        self.manager.start(self.devices[:1], self.path, confirmed=True)
        self.assertTrue(entered.wait(1))
        self.manager.stop()
        self.assertFalse(self.manager.server.running)
        self.assertNotIn("connect", self.manager.sessions[1].backend.calls)

    def test_stuck_buffering_has_finite_retries_and_releases_http(self):
        self.manager.start(self.devices[:1], self.path, confirmed=True)
        self.wait_ready()
        session = self.manager.sessions[1]
        session.backend.status = PlaybackStatus("BUFFERING", session.url)
        session.thread.join(timeout=3)
        self.assertFalse(session.thread.is_alive())
        self.assertEqual(session.state, "ERROR")
        self.assertIn("buffering", session.error)
        self.assertFalse(self.manager.server.running)

    def test_unsupported_command_remains_visible_after_status_poll(self):
        self.manager.start(self.devices[:1], self.path, confirmed=True)
        self.wait_ready()
        session = self.manager.sessions[1]
        session.backend.pause = Mock(side_effect=Unsupported("Pause unavailable"))
        self.manager.command("pause")
        deadline = time.monotonic() + 2
        while not session.error and time.monotonic() < deadline:
            time.sleep(0.01)
        time.sleep(CONFIG.poll_interval * 2)
        self.assertEqual(session.error, "Pause unavailable")
        self.assertEqual(session.state, "PLAYING")


class ProtocolTests(QuietTest):
    def test_cast_connect_uses_verified_metadata_and_finite_timeouts(self):
        backend = google_cast.GoogleCast(endpoint(), NETWORK, CONFIG)
        cast = Mock(app_id=google_cast.IDLE_APP)
        with patch("pychromecast.get_chromecast_from_cast_info", return_value=cast) as factory:
            backend.connect()
        self.assertEqual(factory.call_args.kwargs["tries"], 1)
        self.assertEqual(factory.call_args.args[0].host, "192.0.2.1")
        cast.wait.assert_called_once_with(timeout=CONFIG.connect_timeout)
        backend.disconnect()
        cast.disconnect.assert_called_once_with(timeout=CONFIG.request_timeout)

    def test_cast_native_queue_repeat_and_status_response(self):
        backend = google_cast.GoogleCast(endpoint(), NETWORK, CONFIG)
        backend.cast = Mock(app_id=google_cast.MEDIA_APP)

        def respond(*args, callback_function, **kwargs):
            callback_function(True, {"type": "MEDIA_STATUS"})

        backend.cast.media_controller.send_message.side_effect = respond
        backend.cast.media_controller.update_status.side_effect = respond
        backend.cast.media_controller.status = SimpleNamespace(
            player_state="PLAYING", content_id="http://owned", idle_reason=None
        )
        backend.play("http://owned", media.Media(Path("video.mp4"), "video/mp4", False))
        payload = backend.cast.media_controller.send_message.call_args.args[0]
        self.assertEqual(payload["repeatMode"], "REPEAT_ALL")
        self.assertEqual(payload["items"][0]["media"]["contentId"], "http://owned")
        self.assertEqual(backend.get_status().state, "PLAYING")

    def test_cast_busy_unsupported_pause_and_external_stop_guard(self):
        backend = google_cast.GoogleCast(endpoint(), NETWORK, CONFIG)
        cast = Mock(app_id="OTHER_APP")
        with patch("pychromecast.get_chromecast_from_cast_info", return_value=cast):
            with self.assertRaisesRegex(RuntimeError, "busy"):
                backend.connect()
        backend.url = "http://owned"
        self.assertFalse(backend.stop())
        cast.media_controller.stop.assert_not_called()
        backend.get_status = Mock(return_value=PlaybackStatus("PLAYING", backend.url))
        cast.media_controller.status.supports_pause = False
        with self.assertRaises(Unsupported):
            backend.pause()

    def test_cast_empty_status_does_not_reuse_cached_ownership(self):
        backend = google_cast.GoogleCast(endpoint(), NETWORK, CONFIG)
        backend.cast = Mock(app_id=google_cast.MEDIA_APP)
        backend.url = "http://old-session"
        backend._request = Mock(return_value={"type": "MEDIA_STATUS", "status": []})
        backend.cast.media_controller.status = SimpleNamespace(
            player_state="PLAYING", content_id=backend.url
        )
        self.assertFalse(backend.stop())
        backend.cast.media_controller.stop.assert_not_called()

    def test_cast_explicit_queue_rejection_uses_ordinary_load(self):
        backend = google_cast.GoogleCast(endpoint(), NETWORK, CONFIG)
        backend.cast = Mock(app_id=google_cast.MEDIA_APP)
        replies = [{"type": "INVALID_REQUEST", "reason": "NOT_SUPPORTED"}, {"type": "MEDIA_STATUS"}]

        def respond(*args, callback_function, **kwargs):
            callback_function(True, replies.pop(0))

        backend.cast.media_controller.send_message.side_effect = respond
        backend.cast.media_controller.play_media.side_effect = respond
        backend.play("http://owned", media.Media(Path("video.mp4"), "video/mp4", False))
        self.assertEqual(backend.cast.media_controller.play_media.call_count, 1)

    def dlna_backend(self):
        with patch.object(dlna, "local_request", side_effect=fixture_dlna):
            receiver = dlna.describe("http://192.0.2.1/device.xml", "192.0.2.1", NETWORK, CONFIG)[0]
        return dlna.DLNA(receiver, NETWORK, CONFIG)

    def test_dlna_soap_escaping_play_repeat_and_unsupported_pause(self):
        backend = self.dlna_backend()
        bodies = []

        def reply(url, peer, net, timeout, body, headers):
            bodies.append(body)
            name = headers["SOAPAction"].split("#")[-1].strip('"')
            return 200, soap(name, {})

        with patch.object(dlna, "local_request", side_effect=reply):
            backend.play(
                "http://192.0.2.10/token?x=1&y=2",
                media.Media(Path("a&b.mp4"), "video/mp4", False, 10),
            )
        self.assertEqual(len(bodies), 3)
        self.assertIn(b"SetAVTransportURI", bodies[0])
        self.assertIn(b"&amp;y=2", bodies[0])
        self.assertTrue(backend.native_repeat)
        backend.endpoint.details["AVTransport"]["actions"].remove("Pause")
        backend.get_status = Mock(return_value=PlaybackStatus("PLAYING", backend.url))
        with self.assertRaises(Unsupported):
            backend.pause()

    def test_dlna_soap_fault_and_no_foreign_stop(self):
        backend = self.dlna_backend()
        backend.url = "http://owned"
        backend.get_status = Mock(return_value=PlaybackStatus("PLAYING", "http://foreign"))
        with patch.object(dlna, "local_request") as request:
            self.assertFalse(backend.stop())
            request.assert_not_called()
        fault = b"<Envelope><Body><Fault><errorCode>701</errorCode></Fault></Body></Envelope>"
        with patch.object(dlna, "local_request", return_value=(500, fault)):
            with self.assertRaisesRegex(RuntimeError, "701"):
                backend.call("Play", Speed=1)

    def test_dlna_eof_requires_timing_evidence(self):
        backend = self.dlna_backend()
        backend.url = "http://owned"

        def reply(name, **kwargs):
            return {
                "GetMediaInfo": {"CurrentURI": backend.url, "MediaDuration": "0:00:10"},
                "GetTransportInfo": {"CurrentTransportState": "STOPPED"},
                "GetPositionInfo": {"RelTime": "0:00:00"},
            }[name]

        backend.call = Mock(side_effect=reply)
        self.assertFalse(backend.get_status().finished)
        backend.previous_position = 10
        self.assertTrue(backend.get_status().finished)


class MenuTests(QuietTest):
    def test_main_menu_routes_existing_and_new_options_and_cleans_up(self):
        with (
            patch("builtins.input", side_effect=["0", "1", "2", "3", "4", "q"]),
            patch.object(app, "who_am_i") as profile,
            patch.object(app, "lan_recon") as lan,
            patch.object(app, "wireless_recon") as wifi,
            patch.object(app, "captive_portal") as portal,
            patch.object(app, "tv_control") as tv,
            patch.object(app, "shutdown_tv_control") as cleanup,
        ):
            self.assertEqual(app.main([]), 0)
        for action in (profile, lan, wifi, portal, tv, cleanup):
            action.assert_called_once_with()
        self.assertIn("[4] TV CONTROL", self.output.getvalue())

    def test_direct_entry_and_multitarget_default_no(self):
        with patch.object(app, "tv_control", return_value=None) as tv:
            self.assertEqual(app.main(["--tv-control"]), 0)
        tv.assert_called_once_with()
        for answer in ("", "n", "yes", "Y"):
            with patch("builtins.input", return_value=answer):
                self.assertEqual(cli.confirm_playback([device(1), device(2)]), answer == "Y")

    def application(self):
        application = cli.Application.__new__(cli.Application)
        application.manager = Mock()
        application.manager.active = [Mock()]
        application.manager.sessions = {1: Mock()}
        application.selected = [device(1)]
        application.source = Path("video.mp4")
        return application

    def test_keep_running_return_stop_return_and_cancel(self):
        application = self.application()
        with patch("builtins.input", side_effect=["0", "2"]):
            application.controls()
        application.manager.stop.assert_not_called()
        application.status = Mock()
        with patch("builtins.input", side_effect=["0", "0", "0", "1"]):
            application.controls()
        application.manager.stop.assert_called_once()

    def test_keyboard_interrupt_closes_sessions(self):
        application = self.application()
        with patch("builtins.input", side_effect=KeyboardInterrupt):
            application.run()
        application.manager.close.assert_called_once()

    def test_cancel_media_does_not_start_or_change_targets(self):
        application = self.application()
        self.assertFalse(application.start([device(2)], None))
        application.manager.start.assert_not_called()
        self.assertEqual(application.selected[0].id, 1)

    def test_config_unknown_keys_and_bounds(self):
        for arguments in (
            {"http_port": 0},
            {"retries": 9},
            {"poll_interval": float("nan")},
            {"auto_convert": "yes"},
            {"bind_ip": "0.0.0.999"},
        ):
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                Config(**arguments)
        (self.root / "config").mkdir()
        (self.root / "config" / "tv_control.json").write_text('{"unknown": 1}')
        with self.assertRaises(ValueError):
            Config.load(self.root)


@unittest.skipUnless(
    shutil.which("ffmpeg") and shutil.which("ffprobe"), "FFmpeg/ffprobe not installed"
)
class RealFFmpegTests(QuietTest):
    def test_real_image_conversion_probe_and_cache(self):
        library = media.MediaLibrary(self.root, CONFIG)
        for extension in ("png", "jpg", "webp"):
            with self.subTest(extension=extension):
                image = library.folder / ("fixture." + extension)
                subprocess.run(
                    [
                        shutil.which("ffmpeg"),
                        "-v",
                        "error",
                        "-f",
                        "lavfi",
                        "-i",
                        "color=blue:s=321x241",
                        "-frames:v",
                        "1",
                        "-threads",
                        "1",
                        str(image),
                    ],
                    check=True,
                    capture_output=True,
                )
                converted = library.prepare(image, endpoint())
                self.assertTrue(library.baseline(converted))
                self.assertEqual(converted.video["pix_fmt"], "yuv420p")
                self.assertEqual((converted.video["width"], converted.video["height"]), (1280, 720))
                self.assertEqual(library.prepare(image, endpoint()).path, converted.path)
                data = converted.path.read_bytes()
                self.assertLess(data.index(b"moov"), data.index(b"mdat"))

    def test_real_video_conversion_and_direct_compatible_playback(self):
        library = media.MediaLibrary(self.root, CONFIG)
        original = library.folder / "fixture.mkv"
        subprocess.run(
            [
                shutil.which("ffmpeg"),
                "-v",
                "error",
                "-f",
                "lavfi",
                "-i",
                "testsrc2=size=320x240:rate=30",
                "-f",
                "lavfi",
                "-i",
                "sine=frequency=1000:sample_rate=44100",
                "-t",
                "1",
                "-c:v",
                "mpeg4",
                "-c:a",
                "pcm_s16le",
                "-threads",
                "1",
                str(original),
            ],
            check=True,
            capture_output=True,
        )
        converted = library.prepare(original, endpoint())
        self.assertTrue(library.baseline(converted))
        self.assertEqual(converted.audio[0]["codec_name"], "aac")
        direct = library.folder / "compatible.mp4"
        shutil.copyfile(converted.path, direct)
        self.assertEqual(library.prepare(direct, endpoint()).path, direct.resolve())


if __name__ == "__main__":
    unittest.main()
