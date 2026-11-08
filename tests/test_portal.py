"""Portal HTTP, authorization, and reversible network lifecycle (no live Wi-Fi)."""

import contextlib
import http.client
import io
import json
import re
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from urllib.parse import urlencode

import script as app

CONFIG = {
    "mode": "wifi",
    "lan": "wlan1",
    "wan": "eth0",
    "network": "10.77.0.0/24",
    "ssid": "Mi Wi-Fi ñ",
    "password": "test-only-pass",
    "channel": 6,
}
TABLE = "polterheist_123456abcdef"
MAC = "02:00:00:00:00:02"


class PortalTests(unittest.TestCase):
    def test_menu_and_cli_route_to_portal(self):
        for args, answers in (([], ["3", "q"]), (["--portal"], [])):
            with (
                self.subTest(args=args),
                patch("builtins.input", side_effect=answers),
                patch.object(app, "captive_portal", return_value=None) as portal,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(app.main(args), 0)
                portal.assert_called_once_with()

    def test_windows_only_offers_preview_without_modifying_network(self):
        with (
            patch.object(app.sys, "platform", "win32"),
            patch("builtins.input", return_value="1"),
            patch.object(app, "portal_run") as run,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            with self.assertRaisesRegex(RuntimeError, "Kali/Linux"):
                app.captive_portal()
            run.assert_not_called()
        with (
            patch("builtins.input", return_value="v"),
            patch.object(app, "portal_preview") as preview,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            app.captive_portal()
            preview.assert_called_once()

    def test_profile_preserves_ssid_without_plaintext_password_or_autoconnect(self):
        content = app.portal_profile(CONFIG, "11111111-1111-4111-8111-111111111111")
        encoded = re.search(r"^ssid=(.+)$", content, re.M)[1]
        self.assertEqual(bytes(int(n) for n in encoded.split(";") if n).decode(), CONFIG["ssid"])
        self.assertNotIn(CONFIG["password"], content)
        self.assertRegex(content, r"psk=[0-9a-f]{64}")
        self.assertIn("autoconnect=false", content)
        self.assertIn("method=disabled", content)
        router = app.portal_profile(
            dict(CONFIG, mode="router"), "11111111-1111-4111-8111-111111111111"
        )
        self.assertNotIn("[wifi]", router)

    def test_invalid_configuration_never_generates_commands(self):
        for change in (
            {"lan": "x\nflush ruleset"},
            {"wan": "wlan1"},
            {"network": "8.8.8.0/24"},
            {"password": "short"},
            {"ssid": "x\ny"},
            {"ssid": "ñ" * 17},
            {"channel": 0},
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                app.portal_nft_rules(dict(CONFIG, **change), TABLE)
        with self.assertRaises(ValueError):
            app.portal_grant(TABLE, "10.77.0.3", "bad; flush ruleset", 3600)

    def test_page_escapes_ssid_and_preview_cannot_accept(self):
        page = app.portal_page('<script>alert("x")</script>', preview=True)
        self.assertNotIn("<script>", page)
        self.assertIn("&lt;script&gt;", page)
        self.assertNotIn("<form", page)

    def test_acceptance_is_bound_to_ip_mac_single_use_and_expiry(self):
        identity, grant = Mock(return_value=MAC), Mock()
        access = app.PortalAccess(CONFIG["network"], identity, grant)
        token = access.page("10.77.0.2")
        with self.assertRaises(ValueError):
            access.accept("10.77.0.3", token)
        identity.return_value = "02:00:00:00:00:03"
        with self.assertRaises(ValueError):
            access.accept("10.77.0.2", token)
        identity.return_value = MAC
        access.accept("10.77.0.2", token)
        grant.assert_called_once_with("10.77.0.2", MAC, 3600)
        self.assertIsNone(access.page("10.77.0.2"))
        with self.assertRaises(ValueError):
            access.accept("10.77.0.2", token)
        with patch.object(app.time, "monotonic", return_value=app.time.monotonic() + 3601):
            self.assertIsNotNone(access.page("10.77.0.2"))
        token = access.page("10.77.0.3")
        with patch.object(app.time, "monotonic", return_value=app.time.monotonic() + 301):
            with self.assertRaises(ValueError):
                access.accept("10.77.0.3", token)

    def test_outside_subnet_and_gateway_are_not_clients(self):
        identity = Mock(return_value=MAC)
        access = app.PortalAccess(CONFIG["network"], identity, Mock())
        for ip in ("10.77.0.1", "10.77.0.0", "10.77.0.255", "192.168.1.2", "::1"):
            with self.subTest(ip=ip), self.assertRaises(ValueError):
                access.page(ip)
        identity.assert_not_called()

    def test_firewall_failure_never_reports_client_authorized(self):
        access = app.PortalAccess(
            CONFIG["network"], lambda ip: MAC, Mock(side_effect=RuntimeError("nft failed"))
        )
        token = access.page("10.77.0.2")
        with self.assertRaises(RuntimeError):
            access.accept("10.77.0.2", token)
        self.assertFalse(access.active)

    def test_real_http_preview_and_acceptance_with_validated_tokens(self):
        grant = Mock()
        access = app.PortalAccess(CONFIG["network"], lambda ip: MAC, grant)
        # HTTP test uses loopback; topology/IP validation has independent tests.
        access.client = Mock(side_effect=lambda ip: (ip, MAC))
        with app.PortalServer(("127.0.0.1", 0), "Portal", access) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            connection = http.client.HTTPConnection(*server.server_address, timeout=5)
            try:
                connection.request("GET", "/", headers={"X-Forwarded-For": "10.77.0.99"})
                response = connection.getresponse()
                self.assertEqual(response.status, 200)
                token = re.search(r'name="token" value="([^"]+)"', response.read().decode())[1]
                access.client.assert_called_with("127.0.0.1")
                connection.request(
                    "POST",
                    "/accept",
                    urlencode({"accept": "yes", "token": "forged"}),
                    {"Content-Type": "application/x-www-form-urlencoded"},
                )
                response = connection.getresponse()
                self.assertEqual(response.status, 403)
                response.read()
                grant.assert_not_called()
                connection.request(
                    "POST",
                    "/accept",
                    urlencode({"accept": "yes", "token": token}),
                    {"Content-Type": "application/x-www-form-urlencoded"},
                )
                response = connection.getresponse()
                self.assertEqual(response.status, 303)
                self.assertEqual(
                    response.getheader("Location"),
                    f"http://127.0.0.1:{server.server_port}/connected",
                )
                response.read()
                grant.assert_called_once_with("127.0.0.1", MAC, 3600)
                server.access = None
                connection.request("POST", "/accept", "")
                response = connection.getresponse()
                self.assertEqual(response.status, 404)
                response.read()
            finally:
                connection.close()
                server.shutdown()
                thread.join(timeout=5)

    def test_network_rollback_on_normal_exit_cancel_partial_start_and_failure(self):
        for failure in (None, "cancel", "start", "cleanup"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                folder = Path(directory)
                state = {"original_managed": True, "original_up": False, "original_forward": "0"}
                connection = [None]
                calls = []

                def command(args, **kwargs):
                    calls.append(args)
                    if args[:3] == ["nmcli", "connection", "load"]:
                        if failure == "start":
                            raise RuntimeError("start failed")
                    if "up" in args and "uuid" in args:
                        connection[0] = args[args.index("uuid") + 1]
                    if "delete" in args and failure == "cleanup":
                        raise RuntimeError("cleanup failed")
                    if args[:3] == ["ip", "-json", "address"]:
                        return '[{"addr_info":[{"local":"10.77.0.1"}]}]'
                    return ""

                with (
                    patch.object(app, "portal_lock", return_value=contextlib.nullcontext()),
                    patch.object(app, "portal_preflight", return_value=state),
                    patch.object(
                        app,
                        "portal_keyfile",
                        return_value=contextlib.nullcontext(folder / "profile"),
                    ),
                    patch.object(app, "linux_command", side_effect=command),
                    patch.object(
                        app, "linux_nm_state", side_effect=lambda name: (True, connection[0])
                    ),
                    patch.object(app, "run_quiet", return_value=Mock(returncode=0)),
                    patch.object(app, "portal_nft") as nft,
                    patch.object(app, "portal_verify_restored") as verify,
                    contextlib.redirect_stdout(io.StringIO()),
                ):
                    try:
                        with app.portal_network(CONFIG, folder):
                            if failure == "cancel":
                                raise KeyboardInterrupt
                    except (RuntimeError, KeyboardInterrupt):
                        self.assertIn(failure, {"start", "cancel"})
                    saved = json.loads((folder / "network.json").read_text())
                    self.assertEqual(saved["restored"], failure != "cleanup")
                    self.assertTrue(any("delete" in c and "uuid" in c for c in calls))
                    self.assertTrue(any("net.ipv4.ip_forward=0" in c for c in calls))
                    deleted = any(c.args[0].startswith("delete table") for c in nft.call_args_list)
                    self.assertEqual(deleted, failure != "cleanup")
                    if failure != "cleanup":
                        verify.assert_called_once()


if __name__ == "__main__":
    unittest.main()
