"""Offline installation failures, menu integration and optional real Android SDK build."""

import contextlib
import io
import ipaddress
import json
import os
import socket
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import Mock, patch

from PIL import Image

import script
from tv_control import cli, payload, payload_build
from tv_control.network import Network

ROOT = Path(__file__).resolve().parent.parent
NETWORK = Network("fixture LAN", "192.0.2.10", ipaddress.IPv4Network("192.0.2.0/24"))


class PayloadTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (self.root / "media").mkdir()
        self.source = self.root / "media/image.jpg"
        Image.new("RGB", (32, 24), "blue").save(self.source)
        self.apk = self.root / "test.apk"
        self.apk.write_bytes(b"fixture apk")
        self.enterContext(contextlib.redirect_stdout(io.StringIO()))
        self.enterContext(patch.object(payload, "route_to", return_value=NETWORK))
        self.enterContext(patch.object(payload, "detect_network", return_value=NETWORK))

    def receiver(self):
        return payload.TVPayload(self.root, "192.0.2.20")

    def test_image_must_be_real_and_inside_project_media(self):
        self.assertEqual(payload_build.validate_image(self.root, self.source), self.source)
        outside = self.root / "outside.jpg"
        outside.write_bytes(self.source.read_bytes())
        with self.assertRaises(ValueError):
            payload_build.validate_image(self.root, outside)
        self.source.write_bytes(b"not an image")
        with self.assertRaises(OSError):
            payload_build.validate_image(self.root, self.source)

    def test_local_address_and_port_validation_before_adb(self):
        for host in ("192.0.2.10", "198.51.100.20", "192.0.2.0", "192.0.2.255", "$(echo bad)"):
            with self.subTest(host=host), self.assertRaises(ValueError):
                payload.TVPayload(self.root, host)
        for port in (0, -1, 65536, True):
            with self.subTest(port=port), self.assertRaises(ValueError):
                payload.TVPayload(self.root, "192.0.2.20", port)

    def test_closed_port_does_not_start_adb_or_attempt_install(self):
        receiver = self.receiver()
        with (
            patch.object(socket, "create_connection", side_effect=TimeoutError),
            patch.object(payload, "run_command") as command,
            self.assertRaisesRegex(RuntimeError, "ADB is unavailable"),
        ):
            receiver.install(self.apk)
        command.assert_not_called()

    def test_unauthorized_device_never_gets_install_command(self):
        receiver = self.receiver()
        with (
            patch.object(socket, "create_connection"),
            patch.object(payload, "find_adb", return_value=Path("adb")),
            patch.object(
                payload,
                "run_command",
                return_value="List of devices attached\n192.0.2.20:5555 unauthorized\n",
            ) as command,
            self.assertRaisesRegex(RuntimeError, "not authorized"),
        ):
            receiver.install(self.apk)
        self.assertEqual(command.call_count, 1)
        self.assertNotIn("connect", command.call_args.args[0])
        self.assertFalse(any("install" in call.args[0] for call in command.call_args_list))

    def test_non_tv_adb_device_is_not_installed(self):
        receiver = self.receiver()
        with (
            patch.object(socket, "create_connection"),
            patch.object(payload, "find_adb", return_value=Path("adb")),
            patch.object(payload, "run_command", return_value="192.0.2.20:5555 device"),
            patch.object(
                receiver, "adb", side_effect=["device", "feature:android.hardware.touchscreen"]
            ),
            self.assertRaisesRegex(RuntimeError, "Android TV support"),
        ):
            receiver.install(self.apk)

    def test_install_failure_does_not_launch_or_uninstall(self):
        receiver = self.receiver()
        with (
            patch.object(receiver, "connect"),
            patch.object(
                receiver, "adb", return_value="Failure [INSTALL_FAILED_UPDATE_INCOMPATIBLE]"
            ) as adb,
            self.assertRaisesRegex(RuntimeError, "installation failed"),
        ):
            receiver.install(self.apk)
        adb.assert_called_once_with("install", "-r", str(self.apk), timeout=120)

    def test_success_requires_package_and_activity_evidence(self):
        receiver = self.receiver()
        with (
            patch.object(receiver, "connect"),
            patch.object(
                receiver,
                "adb",
                side_effect=[
                    "Success",
                    "package:/data/app/fixture/base.apk",
                    "Status: ok\nComplete",
                    "mResumedActivity: ActivityRecord{123 org.polterheist.tvpayload/.ImageActivity}",
                ],
            ),
        ):
            result = receiver.install(self.apk)
        self.assertEqual(result["status"], "FOREGROUND_CONFIRMED")
        self.assertTrue(result["installed"])
        self.assertFalse(result["visual_confirmation"])

    def test_background_launch_is_not_claimed_as_displayed(self):
        receiver = self.receiver()
        with (
            patch.object(receiver, "connect"),
            patch.object(
                receiver,
                "adb",
                side_effect=[
                    "Success",
                    "package:/data/app/fixture/base.apk",
                    "Status: ok",
                    "other activity",
                ],
            ),
        ):
            result = receiver.install(self.apk)
        self.assertEqual(result["status"], "LAUNCH_ACKNOWLEDGED")
        self.assertFalse(result["foreground_confirmed"])

    def test_launch_error_is_reported(self):
        receiver = self.receiver()
        with (
            patch.object(receiver, "connect"),
            patch.object(
                receiver,
                "adb",
                side_effect=[
                    "Success",
                    "package:/data/app/fixture/base.apk",
                    "Error type 3: activity missing",
                ],
            ),
            self.assertRaisesRegex(RuntimeError, "launch was not confirmed"),
        ):
            receiver.install(self.apk)

    def test_every_command_selects_only_the_requested_receiver(self):
        receiver = self.receiver()
        with (
            patch.object(payload, "find_adb", return_value=Path("adb")),
            patch.object(payload, "run_command") as command,
        ):
            receiver.adb("shell", "pm", "path", payload.PACKAGE)
        self.assertEqual(command.call_args.args[0][:3], [Path("adb"), "-s", "192.0.2.20:5555"])

    def test_deployment_failure_preserves_apk_and_writes_truthful_report(self):
        with (
            patch.object(payload.TVPayload, "install", side_effect=RuntimeError("ADB unavailable")),
            self.assertRaisesRegex(RuntimeError, "ADB unavailable"),
        ):
            payload.deploy(self.root, "192.0.2.20", self.source, confirmed=True, apk=self.apk)
        self.assertTrue(self.apk.exists())
        report = json.loads(next((self.root / "reports/tv_payload").glob("*.json")).read_text())
        self.assertEqual(report["status"], "FAILED")
        self.assertEqual(report["error"], "ADB unavailable")
        self.assertFalse(report["visual_confirmation"])
        self.assertEqual(len(report["apk_sha256"]), 64)

    def test_unconfirmed_install_does_not_build_or_connect(self):
        with patch.object(payload, "build_apk") as build, self.assertRaises(ValueError):
            payload.deploy(self.root, "192.0.2.20", self.source)
        build.assert_not_called()

    def test_report_preserves_successful_install_when_launch_fails(self):
        with (
            patch.object(payload.TVPayload, "connect"),
            patch.object(
                payload.TVPayload,
                "adb",
                side_effect=[
                    "Success",
                    "package:/data/app/fixture/base.apk",
                    "Error type 3: activity missing",
                ],
            ),
            self.assertRaisesRegex(RuntimeError, "launch was not confirmed"),
        ):
            payload.deploy(self.root, "192.0.2.20", self.source, confirmed=True, apk=self.apk)
        report = json.loads(next((self.root / "reports/tv_payload").glob("*.json")).read_text())
        self.assertTrue(report["installed"])
        self.assertFalse(report["launch_acknowledged"])

    def test_direct_entry_skips_iot_survey(self):
        with patch.object(script, "tv_payload") as entry, patch.object(script, "tv_control") as iot:
            entry.return_value = None
            self.assertEqual(script.main(["--tv-payload"]), 0)
        entry.assert_called_once_with()
        iot.assert_not_called()

    def test_direct_entry_rejects_combined_workflows(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            script.main(["--tv-payload", "--tv-control"])

    def test_tv_receiver_menu_routes_payload_and_returns(self):
        application = cli.Application.__new__(cli.Application)
        application.show_devices = Mock()
        application.payload = Mock()
        with patch("builtins.input", side_effect=["11", "0"]):
            self.assertIsNone(application.targets())
        application.payload.assert_called_once_with()

    def test_iot_menu_routes_payload(self):
        application = cli.Application.__new__(cli.Application)
        application.network = NETWORK
        application.discover_all = Mock()
        application.show_devices = Mock()
        application.payload = Mock()
        application.connections = Mock()
        application.manager = Mock(active=[])
        with patch("builtins.input", side_effect=["12", "0"]):
            application.run()
        application.payload.assert_called_once_with()


@unittest.skipUnless(
    os.environ.get("TV_PAYLOAD_BUILD_TEST") == "1", "Optional real Android SDK build"
)
class AndroidBuildTest(unittest.TestCase):
    def test_real_build_embeds_image_dex_and_verified_signature(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "media") as folder:
            source = Path(folder) / "fixture.png"
            Image.new("RGBA", (2400, 1200), (255, 0, 0, 128)).save(source)
            apk = payload_build.build_apk(ROOT, source)
            with zipfile.ZipFile(apk) as archive:
                self.assertTrue(archive.read("classes.dex").startswith(b"dex\n"))
                self.assertIn("AndroidManifest.xml", archive.namelist())
                with Image.open(io.BytesIO(archive.read("assets/image.jpg"))) as image:
                    self.assertEqual(image.size, (1920, 960))
                    red, green, blue = image.getpixel((20, 20))
                    self.assertTrue(120 <= red <= 135 and green < 5 and blue < 5)


if __name__ == "__main__":
    unittest.main()
