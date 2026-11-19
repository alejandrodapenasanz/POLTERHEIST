"""Adaptive planning, protocol responses, native packages and real loopback delivery."""

import contextlib
import io
import ipaddress
import json
import re
import tempfile
import unittest
import urllib.request
import zipfile
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock, patch
from urllib.parse import urlsplit

from PIL import Image

from tv_control import payload_adapters as adapters
from tv_control import payload_assets as assets
from tv_control import payload_detection as detection
from tv_control import payload_native as native
from tv_control import payload_runtime as runtime
from tv_control.http_server import MediaServer
from tv_control.media import Media
from tv_control.models import Config, Endpoint
from tv_control.network import Network

LAN = Network("fixture", "192.0.2.10", ipaddress.IPv4Network("192.0.2.0/24"))
LOOP = Network("loopback fixture", "127.0.0.1", ipaddress.IPv4Network("127.0.0.0/8"))
CONFIG = Config(request_timeout=0.2, connect_timeout=0.2, discovery_timeout=0.1)
UID = "00000000-0000-0000-0000-000000000001"


def endpoint(protocol="Google Cast", **kwargs):
    return Endpoint(protocol, UID, "192.0.2.20", 8009, **kwargs)


class AdaptiveTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (self.root / "media").mkdir()
        self.source = self.root / "media/image.jpg"
        Image.new("RGB", (160, 90), "blue").save(self.source)
        self.enterContext(contextlib.redirect_stdout(io.StringIO()))
        self.addCleanup(runtime.shutdown)

    def profile(self, *endpoints, ports=()):
        return detection.TVProfile("192.0.2.20", LAN, list(endpoints), ports=list(ports))

    def test_same_brand_can_have_different_os(self):
        google = self.profile(endpoint(manufacturer="Samsung"))
        samsung = self.profile(endpoint("Samsung Remote", manufacturer="Samsung"))
        unknown = self.profile(endpoint("UPnP", manufacturer="Samsung"))
        self.assertEqual(samsung.family, "Samsung Tizen")
        self.assertIn("OS unverified", google.family)
        self.assertIn("OS unverified", unknown.family)

    def test_cast_program_precedes_media_and_does_not_require_adb(self):
        plans = runtime.options(self.root, self.profile(endpoint()), {})
        self.assertEqual(plans[0].strategy, "cast-html")
        self.assertTrue(plans[0].ready)
        self.assertNotIn("android-app", [p.strategy for p in plans])

    def test_audio_cast_not_selected_for_image_display(self):
        plans = runtime.options(
            self.root, self.profile(endpoint(details={"cast_type": "audio"})), {}
        )
        self.assertEqual(plans, [])

    def test_ports_do_not_prove_a_brand_or_authorized_adb(self):
        profile = self.profile(ports=[5555, 3001, 26101])
        self.assertEqual(profile.family, "Unidentified")
        with patch.object(runtime, "find_adb", side_effect=RuntimeError("missing")):
            plans = runtime.options(self.root, profile, {})
        self.assertEqual([p.strategy for p in plans], ["android-app"])
        self.assertFalse(plans[0].ready)

    def test_paired_vendor_routes_only_when_key_provided(self):
        profile = self.profile(endpoint("Samsung Remote"), endpoint("webOS"))
        unpaired = runtime.options(self.root, profile, {})
        self.assertFalse(any(p.ready for p in unpaired))
        paired = runtime.options(
            self.root, profile, {"samsung_token": "token", "webos_client_key": "key"}
        )
        self.assertEqual({p.strategy for p in paired if p.ready}, {"samsung-html", "webos-html"})
        serialized = json.dumps([p.document() for p in paired])
        self.assertNotIn('"token"', serialized)
        self.assertNotIn('"key"', serialized)

    def test_roku_requires_developer_mode_and_slot_opt_in(self):
        profile = self.profile(endpoint("Roku ECP", details={"developer_enabled": "true"}))
        self.assertFalse(runtime.options(self.root, profile, {"roku_password": "secret"})[0].ready)
        self.assertTrue(
            runtime.options(
                self.root, profile, {"roku_password": "secret", "roku_replace_dev": True}
            )[0].ready
        )

    def test_generic_renderer_covers_unknown_brands(self):
        profile = self.profile(endpoint("DLNA", manufacturer="Unknown Brand", controllable=True))
        plans = runtime.options(self.root, profile, {})
        self.assertEqual(plans[0].strategy, "dlna")
        self.assertIn("not uploaded code", plans[0].kind)
        self.assertFalse(plans[0].ready)

    def test_dlna_image_adapts_dimensions_and_headers_to_announced_profile(self):
        Image.new("RGB", (1920, 1080), "red").save(self.source)
        folder = assets.prepare(self.root, self.source)
        receiver = endpoint("DLNA", details={"sink": ["http-get:*:image/jpeg:DLNA.ORG_PN=JPEG_SM"]})
        media = adapters.dlna_image(folder, receiver)
        self.assertEqual(media.dlna_profile, "JPEG_SM")
        with Image.open(media.path) as image:
            self.assertEqual(image.size, (640, 360))
            self.assertFalse(image.info.get("progressive", False))
        server = MediaServer("127.0.0.1", 0, (folder,))
        self.addCleanup(server.close)
        url = server.publish(media, "127.0.0.1")
        with urllib.request.urlopen(url) as response:
            self.assertIn("DLNA.ORG_PN=JPEG_SM", response.headers["contentFeatures.dlna.org"])
            self.assertEqual(response.headers["transferMode.dlna.org"], "Interactive")

    def test_unimplemented_dlna_profile_is_not_assumed_compatible(self):
        folder = assets.prepare(self.root, self.source)
        receiver = endpoint("DLNA", details={"sink": ["http-get:*:image/jpeg:DLNA.ORG_PN=UNKNOWN"]})
        self.assertIsNone(adapters.dlna_image(folder, receiver))

    def test_samsung_metadata_requires_real_identity(self):
        with patch.object(detection, "local_request", return_value=(200, b'{"device": {}}')):
            self.assertEqual(detection.samsung(LAN, CONFIG, "192.0.2.20"), [])
        raw = json.dumps(
            {
                "name": "Living room",
                "device": {"modelName": "Test", "id": "uuid:test", "OS": "Tizen"},
            }
        ).encode()
        with patch.object(detection, "local_request", return_value=(200, raw)):
            found = detection.samsung(LAN, CONFIG, "192.0.2.20")
        self.assertEqual(found[0].protocol, "Samsung Remote")

    def test_webos_hello_never_registers_or_pairs(self):
        ws = Mock()
        ws.recv.return_value = json.dumps(
            {"type": "hello", "payload": {"deviceUUID": UID, "deviceModel": "fixture"}}
        )
        with patch.object(adapters, "websocket_connect", return_value=ws):
            found = detection.webos_hello(LAN, CONFIG, "192.0.2.20")
        self.assertEqual(found[0].protocol, "webOS")
        self.assertEqual(json.loads(ws.send.call_args.args[0])["type"], "hello")
        ws.close.assert_called_once_with()

    def test_html_is_self_contained_and_receipt_after_decode(self):
        folder = assets.prepare(self.root, self.source)
        receipt = "http://127.0.0.1:1234/receipt"
        html = assets.write_html(folder, receipt).read_text()
        self.assertIn("data:image/jpeg;base64,", html)
        self.assertIn("p.naturalWidth", html)
        self.assertIn("p.onload=ready", html)
        self.assertIn(receipt, html)
        self.assertNotIn("<script src=", html)
        with Image.open(folder / "image.jpg") as image:
            self.assertEqual(image.size, (160, 90))

    def test_native_source_archives_are_platform_specific_and_offline(self):
        folder = assets.prepare(self.root, self.source)
        assets.write_html(folder, "http://127.0.0.1/private-session")
        expected = {"webos": "appinfo.json", "tizen": "config.xml", "roku": "source/main.brs"}
        for platform, required in expected.items():
            with self.subTest(platform=platform):
                archive = assets.native_sources(folder, platform)
                with zipfile.ZipFile(archive) as package:
                    self.assertIn(required, package.namelist())
                    if platform != "roku":
                        self.assertNotIn(b"private-session", package.read("index.html"))
                    if platform == "webos":
                        self.assertEqual(json.loads(package.read(required))["main"], "index.html")
                    if platform == "roku":
                        self.assertIn("image.jpg", package.namelist())

    def test_http_gets_counted_but_head_and_unknown_urls_do_not(self):
        folder = assets.prepare(self.root, self.source)
        server = MediaServer("127.0.0.1", 0, (folder,))
        self.addCleanup(server.close)
        url = server.publish(Media(folder / "image.jpg", "image/jpeg", True), "127.0.0.1")
        with urllib.request.urlopen(urllib.request.Request(url, method="HEAD")):
            pass
        self.assertEqual(server.requests(url), 0)
        with urllib.request.urlopen(url) as response:
            response.read()
        self.assertEqual(server.requests(url), 1)
        server.release(url)
        self.assertFalse(server.running)
        self.assertEqual(server.requests(url), 0)

    def job(self):
        profile = detection.TVProfile("127.0.0.1", LOOP, [endpoint()])
        plan = runtime.Option("cast-html", endpoint(), True, "fixture", "HTML/JavaScript")
        return runtime.PayloadJob(self.root, profile, [plan], {}, CONFIG)

    def test_real_http_transfer_and_render_receipt_confirm_program_execution(self):
        def launch(url):
            with urllib.request.urlopen(url) as response:
                html = response.read().decode()
            receipt = json.loads(re.search(r"var receipt=(.*?);", html).group(1))
            with urllib.request.urlopen(receipt) as response:
                response.read()

        fake = Mock()
        fake.launch.side_effect = launch
        with (
            patch.object(
                runtime,
                "MediaServer",
                side_effect=lambda ip, port, roots: MediaServer(ip, 0, roots),
            ),
            patch.object(adapters, "CastHTML", return_value=fake),
        ):
            job = self.job()
            report = job.start(self.source, confirmed=True)
        self.assertEqual(report["state"], "HTML_EXECUTION_CONFIRMED")
        self.assertFalse(report["visual_confirmation"])
        self.assertTrue(report["program_execution"])
        self.assertFalse(report["requires_host"])
        self.assertEqual(report["host_session"], "CLOSED_AFTER_TRANSFER")
        self.assertIsNone(job.server)
        fake.close.assert_called_once_with()
        job.close()
        self.assertIsNone(job.server)
        fake.close.assert_called_once_with()

    def test_socket_write_without_html_execution_is_not_success(self):
        with (
            patch.object(
                runtime,
                "MediaServer",
                side_effect=lambda ip, port, roots: MediaServer(ip, 0, roots),
            ),
            patch.object(adapters, "CastHTML", return_value=Mock()),
        ):
            job = self.job()
            with self.assertRaisesRegex(RuntimeError, "All eligible"):
                job.start(self.source, confirmed=True)
        self.assertEqual(job.report["state"], "FAILED")
        self.assertIsNone(job.server)

    def test_payload_uses_free_port_when_media_control_is_already_serving(self):
        existing = MediaServer("127.0.0.1", 0, (self.root / "media",))
        self.addCleanup(existing.close)
        existing_url = existing.publish(Media(self.source, "image/jpeg", True), "127.0.0.1")
        job = self.job()
        job.config = replace(CONFIG, http_port=urlsplit(existing_url).port)

        def load(url):
            self.assertNotEqual(urlsplit(url).port, urlsplit(existing_url).port)
            with urllib.request.urlopen(url) as response:
                html = response.read().decode()
            receipt = json.loads(re.search(r"var receipt=(.*?);", html).group(1))
            with urllib.request.urlopen(receipt) as response:
                response.read()

        with patch.object(adapters, "CastHTML", return_value=Mock(launch=load)):
            report = job.start(self.source, confirmed=True)
        self.assertEqual(report["host_session"], "CLOSED_AFTER_TRANSFER")
        self.assertTrue(existing.running)
        with urllib.request.urlopen(existing_url) as response:
            self.assertEqual(response.read(), self.source.read_bytes())

    def test_failed_route_falls_back_and_redacts_authentication(self):
        job = self.job()
        job.settings = {"samsung_token": "PRIVATE_TOKEN"}
        job.plans.append(runtime.Option("webos-html", endpoint("webOS"), True, "fixture", "HTML"))
        with patch.object(
            job,
            "execute",
            side_effect=[
                RuntimeError("Rejected PRIVATE_TOKEN"),
                {
                    "state": "HTML_EXECUTION_CONFIRMED",
                    "program_execution": True,
                    "requires_host": False,
                },
            ],
        ):
            report = job.start(self.source, confirmed=True)
        self.assertEqual(report["strategy"], "webos-html")
        self.assertTrue(report["program_execution"])
        self.assertNotIn("PRIVATE_TOKEN", job.report_path.read_text())

    def test_streaming_routes_cannot_be_forced_even_if_marked_ready(self):
        for strategy in ("cast-media", "dlna", "airplay"):
            with self.subTest(strategy=strategy):
                job = self.job()
                job.plans = [runtime.Option(strategy, endpoint(), True, "fixture", "media")]
                with patch.object(job, "execute") as execute, self.assertRaises(RuntimeError):
                    job.start(self.source, strategy=strategy, confirmed=True)
                execute.assert_not_called()
                job.close()

    def test_host_dependent_adapter_result_is_rejected(self):
        job = self.job()
        with (
            patch.object(job, "execute", return_value={"state": "PLAYING", "requires_host": True}),
            self.assertRaises(RuntimeError),
        ):
            job.start(self.source, confirmed=True)
        self.assertEqual(job.report["state"], "FAILED")

    def test_configured_entry_offers_schedule_before_sending(self):
        (self.root / "config").mkdir()
        (self.root / "config/tv_payload.json").write_text(
            json.dumps(
                {"default_target": "192.0.2.20", "default_media": "media/image.jpg", "devices": {}}
            )
        )
        with (
            patch("builtins.input", return_value="1") as prompt,
            patch.object(
                runtime, "inspect", return_value=(self.profile(endpoint()), [], {})
            ) as inspect,
            patch.object(runtime, "PayloadJob") as constructor,
        ):
            runtime.run(self.root)
        inspect.assert_called_once_with(self.root, "192.0.2.20")
        prompt.assert_called_once()
        constructor.return_value.start.assert_called_once_with(
            self.source, confirmed=True, schedule=None
        )
        constructor.return_value.close.assert_called_once_with()

    def test_cli_never_asks_for_confirmation_without_yes_flag(self):
        with (
            patch("builtins.input", side_effect=AssertionError("No prompt expected")),
            patch.object(runtime, "automatic_source", return_value=self.source),
            patch.object(runtime, "automatic_target", return_value="192.0.2.20"),
            patch.object(runtime, "inspect", return_value=(self.profile(endpoint()), [], {})),
            patch.object(runtime, "PayloadJob") as constructor,
        ):
            self.assertEqual(runtime.main([]), 0)
        constructor.return_value.start.assert_called_once_with(
            self.source, "auto", confirmed=True, schedule=None
        )

    def test_ready_native_package_precedes_browser(self):
        profile = self.profile(endpoint(), endpoint("Android TV Remote"), ports=[5555])
        with patch.object(runtime, "find_adb"), patch.object(runtime, "build_tools"):
            plans = runtime.options(self.root, profile, {})
        self.assertEqual(plans[0].strategy, "android-app")

    def test_cast_reopens_previous_navigated_document_and_does_not_wait_for_load_ack(self):
        cast, controller = Mock(), Mock()
        controller.supporting_app_id = "84912283"
        controller.is_active = False
        cast.app_id = "84912283"

        def launched(**kwargs):
            controller.is_active = True
            kwargs["callback_function"](True, {})

        controller.launch.side_effect = launched
        with (
            patch.object(adapters, "cast_connection", return_value=cast),
            patch("pychromecast.controllers.dashcast.DashCastController", return_value=controller),
        ):
            adapter = adapters.CastHTML(endpoint(), CONFIG)
            adapter.launch("http://local/viewer")
        cast.quit_app.assert_called_once_with(timeout=CONFIG.connect_timeout)
        controller.load_url.assert_called_once_with("http://local/viewer", force=True)

    def test_cast_restarts_previous_viewer_even_when_namespace_is_still_advertised(self):
        cast, controller = Mock(), Mock()
        controller.supporting_app_id = cast.app_id = "84912283"
        controller.is_active = True  # Xiaomi retains this after force-navigation.

        def launched(**kwargs):
            kwargs["callback_function"](True, {})

        controller.launch.side_effect = launched
        with (
            patch.object(adapters, "cast_connection", return_value=cast),
            patch("pychromecast.controllers.dashcast.DashCastController", return_value=controller),
        ):
            adapters.CastHTML(endpoint(), CONFIG).launch("http://local/replacement")
        cast.quit_app.assert_called_once_with(timeout=CONFIG.connect_timeout)
        controller.load_url.assert_called_once_with("http://local/replacement", force=True)

    def test_auto_discovery_uses_unique_tv_and_rejects_ambiguous_targets(self):
        from tv_control.protocols import dlna, google_cast

        with (
            patch.object(runtime.Config, "load", return_value=Config(bind_ip=LAN.ip)),
            patch("tv_control.network.detect_network", return_value=LAN),
            patch.object(google_cast, "discover", return_value=[endpoint()]),
            patch.object(dlna, "discover", return_value=[]),
        ):
            self.assertEqual(runtime.automatic_target(self.root), "192.0.2.20")
        with (
            patch.object(runtime.Config, "load", return_value=Config(bind_ip=LAN.ip)),
            patch("tv_control.network.detect_network", return_value=LAN),
            patch.object(google_cast, "discover", return_value=[endpoint()]),
            patch.object(
                dlna, "discover", return_value=[Endpoint("DLNA", "second", "192.0.2.21", 80)]
            ),
            self.assertRaisesRegex(ValueError, "No unique TV"),
        ):
            runtime.automatic_target(self.root)

    def test_unconfirmed_execution_never_builds_or_sends(self):
        job = self.job()
        with patch.object(assets, "prepare") as prepare, self.assertRaises(ValueError):
            job.start(self.source)
        prepare.assert_not_called()

    def test_unreachable_device_produces_artifact_and_honest_report(self):
        job = runtime.PayloadJob(self.root, self.profile(), [], {})
        with self.assertRaisesRegex(RuntimeError, "No ready execution route"):
            job.start(self.source, confirmed=True)
        self.assertTrue((job.folder / "index.html").is_file())
        self.assertEqual(job.report["state"], "UNSUPPORTED_OR_UNREACHABLE")

    def test_detect_only_does_not_prepare_or_launch(self):
        with (
            patch.object(runtime, "inspect", return_value=(self.profile(endpoint()), [], {})),
            patch.object(
                runtime, "automatic_source", side_effect=AssertionError("No media required")
            ),
            patch.object(assets, "prepare") as prepare,
            patch.object(runtime, "PayloadJob") as job,
        ):
            self.assertEqual(runtime.main(["--target", "192.0.2.20", "--detect-only"]), 0)
        prepare.assert_not_called()
        job.assert_not_called()

    def test_empty_vendor_credentials_never_open_websocket(self):
        for cls in (adapters.SamsungHTML, adapters.WebOSHTML):
            with self.subTest(cls=cls), patch.object(adapters, "websocket_connect") as connect:
                with self.assertRaises(RuntimeError):
                    cls(endpoint(), CONFIG, {}).launch("http://local/viewer")
                connect.assert_not_called()

    def test_samsung_cached_token_rejection_stops_before_launch(self):
        ws = Mock()
        ws.recv.return_value = '{"event":"ms.channel.unauthorized"}'
        with (
            patch.object(adapters, "websocket_connect", return_value=ws),
            self.assertRaises(RuntimeError),
        ):
            adapters.SamsungHTML(endpoint(), CONFIG, {"samsung_token": "fixture"}).launch(
                "http://local/viewer"
            )
        ws.send.assert_not_called()
        ws.close.assert_called_once_with()

    def test_webos_alias_must_match_target_before_install(self):
        listed = json.dumps([{"name": "tv", "deviceinfo": {"ip": "192.0.2.99"}}])
        with (
            patch.object(native, "sdk_command", return_value=listed) as command,
            self.assertRaises(ValueError),
        ):
            native.webos(
                "192.0.2.20", assets.prepare(self.root, self.source), {"webos_device": "tv"}
            )
        command.assert_called_once_with("ares-setup-device", "--listfull")

    def test_webos_native_pack_install_launch_and_running_check(self):
        folder = assets.prepare(self.root, self.source)

        def command(tool, *args):
            if tool == "ares-setup-device":
                return json.dumps([{"name": "tv", "deviceinfo": {"ip": "192.0.2.20"}}])
            if tool == "ares-package":
                (folder / "org.polterheist.tvpayload_1.0.0_all.ipk").write_bytes(b"fixture")
            if tool == "ares-launch" and "--running" in args:
                return "org.polterheist.tvpayload"
            return "Success"

        with patch.object(native, "sdk_command", side_effect=command):
            report = native.webos("192.0.2.20", folder, {"webos_device": "tv"})
        self.assertEqual(report["state"], "NATIVE_APP_RUNNING")

    def test_roku_slot_never_replaced_without_explicit_configuration(self):
        with (
            patch.object(native.urllib.request, "build_opener") as opener,
            self.assertRaises(ValueError),
        ):
            native.roku(
                "192.0.2.20", assets.prepare(self.root, self.source), {"roku_password": "secret"}
            )
        opener.assert_not_called()

    def test_sdk_profile_is_not_shell_input(self):
        for value in ("$(whoami)", "profile & echo bad", "x\ny", ""):
            with self.subTest(value=value), self.assertRaises(ValueError):
                native.name(value)

    def test_tizen_build_sign_install_and_launch_use_selected_serial(self):
        folder = assets.prepare(self.root, self.source)
        calls = []

        def command(tool, *args):
            calls.append((tool, args))
            if tool == "sdb" and args == ("devices",):
                return "192.0.2.20:26101 device fixture"
            if tool == "tizen" and args[0] == "build-web":
                (folder / "tizen/.buildResult").mkdir()
            if tool == "tizen" and args[0] == "package":
                (folder / "tizen/.buildResult/TVPayload.wgt").write_bytes(b"fixture")
            if tool == "tizen" and args[0] == "run":
                return "Successfully launched the app"
            return "Success"

        with patch.object(native, "sdk_command", side_effect=command):
            result = native.tizen("192.0.2.20", folder, {"tizen_certificate": "existing"})
        self.assertEqual(result["state"], "NATIVE_LAUNCH_ACKNOWLEDGED")
        for tool, args in calls:
            if tool == "tizen" and args[0] in ("install", "run"):
                self.assertIn("192.0.2.20:26101", args)

    def test_unknown_sdb_connection_never_installs_tizen(self):
        folder = assets.prepare(self.root, self.source)
        with patch.object(native, "sdk_command", return_value="other-device device") as command:
            with self.assertRaisesRegex(RuntimeError, "authorized device session"):
                native.tizen("192.0.2.20", folder, {"tizen_certificate": "existing"})
        self.assertTrue(all(call.args[0] == "sdb" for call in command.call_args_list))
        command.assert_called_once_with("sdb", "devices")

    def test_roku_install_and_active_app_are_both_verified(self):
        from unittest.mock import MagicMock

        folder = assets.prepare(self.root, self.source)
        opener = Mock()
        install, launch, active = (MagicMock() for _ in range(3))
        install.__enter__.return_value.read.return_value = b"Install Success"
        active.__enter__.return_value.read.return_value = (
            b'<active-app><app id="dev">TV Payload</app></active-app>'
        )
        opener.open.side_effect = [install, launch, active]
        with patch.object(native.urllib.request, "build_opener", return_value=opener):
            result = native.roku(
                "192.0.2.20", folder, {"roku_password": "secret", "roku_replace_dev": True}
            )
        self.assertEqual(result["state"], "NATIVE_APP_RUNNING")
        request = opener.open.call_args_list[0].args[0]
        self.assertEqual(request.full_url, "http://192.0.2.20/plugin_install")
        self.assertIn(b'name="archive"', request.data)
        self.assertNotIn(b"secret", request.data)

    def test_dlna_metadata_contains_the_actual_generated_profile(self):
        from tv_control.protocols.dlna import DLNA

        receiver = endpoint(
            "DLNA", details={"AVTransport": {"actions": {"SetAVTransportURI", "Play"}, "modes": []}}
        )
        backend = DLNA(receiver, LAN, CONFIG)
        backend.call = Mock()
        media = Media(self.source, "image/jpeg", True, dlna_profile="JPEG_SM")
        backend.play("http://local/image", media)
        metadata = backend.call.call_args_list[0].kwargs["CurrentURIMetaData"]
        self.assertIn("DLNA.ORG_PN=JPEG_SM", metadata)

    def test_configuration_is_scoped_to_requested_device(self):
        (self.root / "config").mkdir()
        path = self.root / "config/tv_payload.json"
        path.write_text(json.dumps({"devices": {"192.0.2.20": {"webos_client_key": "secret"}}}))
        self.assertEqual(runtime.settings_for(self.root, "192.0.2.21"), {})
        self.assertEqual(
            runtime.settings_for(self.root, "192.0.2.20")["webos_client_key"], "secret"
        )
        path.write_text('{"devices": []}')
        with self.assertRaises(ValueError):
            runtime.settings_for(self.root, "192.0.2.20")


if __name__ == "__main__":
    unittest.main()
