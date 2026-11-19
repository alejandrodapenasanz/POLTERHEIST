"""Capability failure semantics and persistent diagnostic logs."""

import json
import logging
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import app_logging
import startup_check
from tv_control.hardware import Probe


class HardwareTests(unittest.TestCase):
    def test_absent_radio_is_unavailable_but_failed_query_is_unknown(self):
        def runner(argv):
            return Probe(argv, "OK", "")

        caps = startup_check.collect(runner=runner, platform="linux", which=lambda _: "/bin/tool")
        self.assertFalse(caps["2"].available)
        self.assertFalse(caps["p2p"].available)
        caps = startup_check.collect(
            runner=lambda argv: Probe(argv, "TIMEOUT"),
            platform="linux",
            which=lambda _: None,
            root="nonexistent-test-tool-directory",
        )
        self.assertIsNone(caps["2"].available)
        self.assertIsNone(caps["p2p"].available)
        self.assertFalse(caps["video"].available)
        self.assertFalse(caps["1"].available)

    def test_supported_radio_and_missing_driver_mode(self):
        def runner(argv):
            output = (
                "phy#0\n\tInterface wlan0\n\t\ttype managed\n"
                if argv == ["iw", "dev"]
                else (
                    "Wiphy phy0\n\tSupported interface modes:\n\t\t * managed\n\t\t * AP\n\t\t * P2P-client\n"
                )
            )
            return Probe(argv, "OK", output)

        caps = startup_check.collect(runner=runner, platform="linux", which=lambda _: "/bin/tool")
        self.assertTrue(caps["2"].available)
        self.assertTrue(caps["ap"].available)
        self.assertTrue(caps["p2p"].available)
        self.assertFalse(caps["monitor"].available)

    def test_windows_no_wifi_does_not_disable_iot_or_preview(self):
        caps = startup_check.collect(
            platform="win32", windows_interfaces=lambda: [], which=lambda _: "/tool"
        )
        self.assertFalse(caps["2"].available)
        self.assertIn("preview", caps["3"].reason)
        self.assertIsNot(caps["4"].available, False)

    def test_static_and_animated_menu_mark_unavailable_in_red(self):
        from terminal_ui import AnimatedMenu

        cap = startup_check.Capability("Wi-Fi", False, "No adapter")
        with patch.object(startup_check, "CURRENT", {"2": cap}):
            self.assertIn("\033[91m", startup_check.annotate("2", "WIRELESS", color=True))
            self.assertIn("UNAVAILABLE", startup_check.annotate("2", "WIRELESS"))
        menu = object.__new__(AnimatedMenu)
        menu.capabilities = {"2": cap}
        fragments = menu.menu_fragments()
        self.assertTrue(
            any(style == "class:unavailable" and "No adapter" in text for style, text in fragments)
        )


class LoggingTests(unittest.TestCase):
    def tearDown(self):
        app_logging.close_logging()

    def test_json_session_exception_redaction_and_rotation(self):
        app_logging.close_logging()
        with tempfile.TemporaryDirectory() as folder:
            path = app_logging.configure_logging(folder)
            self.assertEqual(path, app_logging.configure_logging(folder))
            app_logging.register_secrets(["paired-secret-123"])
            logger = logging.getLogger("polterheist.test")
            try:
                raise RuntimeError("Failure with paired-secret-123 and token=abc123")
            except RuntimeError:
                logger.exception("Action failed")
            entries = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertEqual(entries[-1]["level"], "ERROR")
            self.assertIn("RuntimeError", entries[-1]["exception"])
            self.assertNotIn("paired-secret-123", path.read_text())
            self.assertNotIn("abc123", path.read_text())
            self.assertEqual(entries[0]["session"], entries[-1]["session"])
            app_logging._handler.maxBytes = 100
            logger.info("rotate " * 30)
            self.assertTrue(Path(str(path) + ".1").exists())
            app_logging.close_logging()

    def test_unwritable_project_uses_user_log_directory(self):
        app_logging.close_logging()
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "reports").write_text("not a directory")
            with patch("app_logging.Path.home", return_value=root / "user"):
                path = app_logging.configure_logging(root)
            self.assertTrue(path.is_relative_to(root / "user"))
            app_logging.close_logging()
