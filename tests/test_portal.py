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


def radio(name, phy):
    return {
        "name": name,
        "phy": phy,
        "mode": "managed",
        "capabilities": ["managed", "AP"],
        "frequencies": [
            {"channel": 6, "frequency_mhz": 2437, "disabled": False, "no_ir": False, "radar": False}
        ],
    }


@contextlib.contextmanager
def wizard_environment(names, radios, answers=()):
    links = [{"ifname": name, "link_type": "ether"} for name in ["eth0", *names]]
    routes = [{"dst": "default", "dev": "eth0"}]
    output = io.StringIO()
    with (
        patch.object(app, "require_linux"),
        patch.object(app, "require_tools"),
        patch.object(app.os, "geteuid", return_value=0, create=True),
        patch.object(app.shutil, "which", return_value="/bin/tool"),
        patch.object(app, "linux_command", side_effect=[json.dumps(routes), json.dumps(links)]),
        patch.object(app, "detect_wireless_interfaces", return_value=radios),
        patch.object(app, "linux_nm_state", return_value=(True, None)),
        patch.object(app.getpass, "getpass", return_value="test-only-pass"),
        patch("builtins.input", side_effect=answers) as prompt,
        patch.object(app, "portal_run", return_value=0) as run,
        contextlib.redirect_stdout(output),
    ):
        yield run, output, prompt


class PortalTests(unittest.TestCase):
    def test_plans_skip_busy_unsupported_shared_and_restricted_radios(self):
        radios = [radio(f"wlan{n}", f"phy{n}") for n in range(7)]
        radios[1]["frequencies"][0]["no_ir"] = True
        radios[2]["phy"] = radios[3]["phy"]
        radios[4]["capabilities"] = ["managed"]
        radios[6]["connected"] = True
        links = [{"ifname": r["name"], "link_type": "ether"} for r in radios]
        links += [{"ifname": n, "link_type": "ether"} for n in ["eth0", "eth1"]]

        def nm(name):
            return True, "busy-connection" if name == "wlan0" else None

        with (
            patch.object(app, "linux_nm_state", side_effect=nm),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            plans = app.portal_interface_plans(links, radios, "eth0", "wifi", "10.77.0.0/24")
        self.assertEqual(
            [(p["lan"], p["mode"]) for p in plans], [("wlan5", "wifi"), ("eth1", "router")]
        )
        self.assertEqual(plans[0]["channel"], 6)

    def test_wizard_falls_back_in_both_directions(self):
        cases = [
            ("1", ["eth1"], [], ["AP"], "router", "eth1"),
            ("2", ["wlan1"], [radio("wlan1", "phy1")], ["My network"], "wifi", "wlan1"),
        ]
        for choice, names, radios, answers, mode, interface in cases:
            with (
                self.subTest(choice=choice),
                wizard_environment(names, radios, answers) as (run, output, _),
            ):
                self.assertEqual(app.captive_portal(choice), 0)
                run.assert_called_once()
                config = run.call_args.args[0]
                self.assertEqual((config["mode"], config["lan"]), (mode, interface))
                self.assertIn("No usable interface remains in the selected mode", output.getvalue())
                self.assertEqual(config["wan"], "eth0")

    def test_wizard_tries_next_interface_if_final_checks_fail(self):
        for choice, names, radios, answers in [
            ("2", ["eth1", "eth2"], [], ["AP", "AP"]),
            (
                "1",
                ["wlan1", "wlan2"],
                [radio("wlan1", "phy1"), radio("wlan2", "phy2")],
                ["My network"],
            ),
        ]:
            with (
                self.subTest(choice=choice),
                wizard_environment(names, radios, answers) as (run, _, prompt),
            ):
                run.side_effect = [app.PortalInterfaceUnavailable("Interface disappeared"), 0]
                self.assertEqual(app.captive_portal(choice), 0)
                self.assertEqual([c.args[0]["lan"] for c in run.call_args_list], names)
                self.assertEqual(prompt.call_count, len(answers))

    def test_all_candidates_exhausted_report_no_usable_interface(self):
        with wizard_environment(["eth1", "eth2"], [], ["AP", "AP"]) as (run, _, _):
            run.side_effect = app.PortalInterfaceUnavailable("Interface disappeared")
            with self.assertRaisesRegex(
                RuntimeError, "^No usable network interface is available for the captive portal\\.$"
            ):
                app.captive_portal("2")
            self.assertEqual(run.call_count, 2)

    def test_main_prints_one_clear_error_when_no_interface_can_be_used(self):
        for choice in ("1", "2"):
            with self.subTest(choice=choice), wizard_environment([], []) as (run, output, prompt):
                self.assertEqual(app.main(["--portal-choice", choice]), 1)
                errors = [line.strip() for line in output.getvalue().splitlines() if "[!]" in line]
                self.assertEqual(
                    errors, ["[!] No usable network interface is available for the captive portal."]
                )
                self.assertNotIn("PORTAL / INTERFACES", output.getvalue())
                run.assert_not_called()
                prompt.assert_not_called()

    def test_firewall_errors_and_cancellation_do_not_trigger_retry(self):
        with wizard_environment(["eth1", "eth2"], [], ["AP"]) as (run, _, _):
            run.side_effect = RuntimeError("Firewall conflict")
            with self.assertRaisesRegex(RuntimeError, "Firewall conflict"):
                app.captive_portal("2")
            run.assert_called_once()
        with wizard_environment(["eth1", "eth2"], [], [""]) as (run, _, prompt):
            self.assertIsNone(app.captive_portal("2"))
            run.assert_not_called()
            prompt.assert_called_once()

    def test_missing_iw_can_fall_back_to_ethernet(self):
        with wizard_environment(["eth1"], [], ["AP"]) as (run, _, _):
            with patch.object(app.shutil, "which", return_value=None):
                self.assertEqual(app.captive_portal("1"), 0)
            self.assertEqual(run.call_args.args[0]["mode"], "router")

    def test_unknown_wifi_radio_is_not_reused_as_ethernet(self):
        with wizard_environment(["wlan1"], [], []) as (run, _, _):
            with patch.object(app.Path, "exists", return_value=True):
                with self.assertRaisesRegex(RuntimeError, "No usable network interface"):
                    app.captive_portal("2")
            run.assert_not_called()

    def test_vm_ethernet_and_docker_do_not_become_wireless_candidates(self):
        links = [
            {"ifname": "lo", "link_type": "loopback"},
            {"ifname": "eth0", "link_type": "ether", "addr_info": [{"scope": "global"}]},
            {"ifname": "docker0", "link_type": "ether", "linkinfo": {"info_kind": "bridge"}},
        ]
        for mode in ("wifi", "router"):
            rows = app.portal_candidate_rows(links, [], "eth0", mode)
            self.assertFalse(any(r["candidate"] for r in rows))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            app.portal_explain_interfaces(links, [], "eth0", "wifi", "oracle")
        self.assertIn("VirtualBox", output.getvalue())
        self.assertIn("no Wi-Fi radio", output.getvalue())
        self.assertIn("still virtual Ethernet", output.getvalue())
        self.assertIn("Kali Live", output.getvalue())

    def test_free_radio_and_free_ethernet_are_distinct_candidates(self):
        links = [
            {"ifname": "eth0", "link_type": "ether"},
            {"ifname": "wlan0", "link_type": "ether"},
            {"ifname": "eth1", "link_type": "ether"},
        ]
        radios = [{"name": "wlan0", "capabilities": ["managed", "AP"]}]
        for mode, expected in (("wifi", ["wlan0"]), ("router", ["eth1"])):
            rows = app.portal_candidate_rows(links, radios, "eth0", mode)
            self.assertEqual([r["name"] for r in rows if r["candidate"]], expected)
        radios[0]["capabilities"] = ["managed"]
        self.assertFalse(
            any(r["candidate"] for r in app.portal_candidate_rows(links, radios, "eth0", "wifi"))
        )

    def test_portal_diagnostics_are_read_only_and_report_firewall(self):
        links = [{"ifname": "eth0", "link_type": "ether"}]
        routes = [{"dst": "default", "dev": "eth0"}]
        firewall = {"nftables": [{"chain": {"table": "filter", "hook": "forward"}}]}
        output = io.StringIO()
        with (
            patch.object(app, "require_linux"),
            patch.object(app, "require_tools"),
            patch.object(app.shutil, "which", return_value="/bin/tool"),
            patch.object(
                app, "linux_command", side_effect=[json.dumps(links), json.dumps(routes)]
            ) as commands,
            patch.object(app, "detect_wireless_interfaces", return_value=[]),
            patch.object(app, "portal_virtualization", return_value="oracle"),
            patch.object(
                app, "run_quiet", return_value=Mock(returncode=0, stdout=json.dumps(firewall))
            ) as quiet,
            contextlib.redirect_stdout(output),
        ):
            self.assertEqual(app.portal_check(), 0)
        self.assertIn("Another firewall/gateway", output.getvalue())
        self.assertTrue(
            all(c.args[0][0] == "ip" and "show" in c.args[0] for c in commands.call_args_list)
        )
        quiet.assert_called_once_with(["nft", "--json", "list", "ruleset"])

    def test_unknown_radio_discovery_is_not_reported_as_no_hardware(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            app.portal_explain_interfaces([], None, None, "wifi")
        self.assertNotIn("no Wi-Fi radio", output.getvalue())
        self.assertIn("Unable to check", output.getvalue())

    def test_elevation_keeps_selected_portal_mode(self):
        with (
            patch.object(app, "require_linux"),
            patch.object(app, "require_tools"),
            patch.object(app.os, "geteuid", return_value=1000, create=True),
            patch.object(app.subprocess, "run", return_value=Mock(returncode=0)) as run,
            patch("builtins.input") as prompt,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(app.captive_portal("2"), 0)
        prompt.assert_not_called()
        self.assertEqual(run.call_args.args[0][-2:], ["--portal-choice", "2"])

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
        self.assertIn('lang="en"', page)
        self.assertIn("Accept and connect", page)
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
