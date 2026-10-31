"""Offline regression tests; all radio/network fixtures below are synthetic lab data."""

import contextlib
import hashlib
import http.server
import io
import ipaddress
import json
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import script as app

IW_DEV = """phy#0
	Interface wlan0
		type managed
		channel 6 (2437 MHz), width: 20 MHz
phy#1
	Interface wlan1mon
		type monitor
		channel 36 (5180 MHz), width: 20 MHz
"""
PHY = """Wiphy phy1
	Supported interface modes:
		 * managed
		 * monitor
	Band 1:
		Frequencies:
			* 2412 MHz [1] (20.0 dBm)
			* 2437 MHz [6] (20.0 dBm)
			* 5180 MHz [36] (20.0 dBm)
			* 5260 MHz [52] (20.0 dBm) (no IR, radar detection)
			* 5825 MHz [165] (disabled)
"""
IW_SCAN = r"""BSS 02:00:00:00:00:01(on wlan0)
	freq: 2437
	signal: -48.00 dBm
	capability: ESS Privacy (0x0011)
	SSID: LAB-WIFI
	RSN: * Version: 1
		 * Authentication suites: PSK SAE
	WPS: * Version: 1.0
		 * Manufacturer: Lab Vendor
BSS 02:00:00:00:00:02(on wlan0)
	freq: 5180
	signal: -62.00 dBm
	capability: ESS Privacy (0x0011)
	SSID: LAB-WIFI
	RSN: * Version: 1
		 * Authentication suites: SAE
BSS 02:00:00:00:00:03(on wlan0)
	freq: 2412
	capability: ESS (0x0001)
	SSID: Caf\xc3\xa9
""".replace(r"\t", "\t")
DISCOVERY = """<?xml version="1.0"?>
<nmaprun><host><status state="up"/><address addr="192.0.2.1" addrtype="ipv4"/>
<address addr="00:11:22:33:44:55" addrtype="mac" vendor="Router vendor"/></host>
<host><status state="up"/><address addr="192.0.2.3" addrtype="ipv4"/>
<address addr="00:11:22:33:44:77" addrtype="mac" vendor="Apple"/></host>
<host><status state="down"/><address addr="192.0.2.8" addrtype="ipv4"/></host></nmaprun>"""
SCAN_XML = """<nmaprun><host><status state="up"/>
<ports><port protocol="tcp" portid="80"><state state="open"/>
<service name="http" product="Test HTTP" version="1.0"/>
<script id="fixture-vuln" output="potential cve-2024-12345"/></port>
<port protocol="tcp" portid="443"><state state="closed"/></port></ports>
<hostscript><script id="fixture-host" output="CVE-2023-54321"/></hostscript>
</host></nmaprun>"""


def completed(stdout="", code=0):
    return subprocess.CompletedProcess([], code, stdout, "")


def host(index, ip=None, local=False, vendor="Unknown"):
    return {
        "id": index,
        "ip": ip or f"192.0.2.{index}",
        "local": local,
        "vendor": vendor,
        "mac": "00:11:22:33:44:55",
        "sources": ["ARP"],
        "gateway": False,
        "manufacturer_evidence": [],
    }


class QuietTest(unittest.TestCase):
    def setUp(self):
        self.output = io.StringIO()
        self.capture = contextlib.redirect_stdout(self.output)
        self.capture.__enter__()
        self.temp = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp.name)

    def tearDown(self):
        self.capture.__exit__(None, None, None)
        self.temp.cleanup()


class MenuProfileTests(QuietTest):
    def test_all_menu_routes_and_return(self):
        with (
            patch("builtins.input", side_effect=["invalid", "0", "1", "2", "q"]),
            patch.object(app, "who_am_i") as profile,
            patch.object(app, "lan_recon") as lan,
            patch.object(app, "wireless_recon") as wifi,
        ):
            self.assertEqual(app.main([]), 0)
        for action in (profile, lan, wifi):
            action.assert_called_once_with()
        self.assertIn("POLTERHEIST", self.output.getvalue())

    def test_menu_recovers_from_feature_error_and_cancellation(self):
        with (
            patch("builtins.input", side_effect=["1", "2", "q"]),
            patch.object(app, "lan_recon", side_effect=RuntimeError("missing tool")),
            patch.object(app, "wireless_recon", side_effect=KeyboardInterrupt),
        ):
            self.assertEqual(app.main([]), 0)
        self.assertIn("missing tool", self.output.getvalue())

    def test_eof_exits(self):
        with patch("builtins.input", side_effect=EOFError):
            self.assertEqual(app.main([]), 0)

    def test_profile_created_without_invented_identity(self):
        path = self.folder / "profile.json"
        profile = app.load_profile(path)
        self.assertEqual(set(profile), set(app.PROFILE_FIELDS))
        self.assertTrue(all(value == "" for value in profile.values()))
        self.assertEqual(json.loads(path.read_text()), profile)

    def test_profile_edit_persists_and_returns(self):
        path = self.folder / "profile.json"
        answers = ["e", "Lab alias", "", "", "", "", "", "", "q"]
        with patch.object(app, "PROFILE_PATH", path), patch("builtins.input", side_effect=answers):
            app.who_am_i()
        self.assertEqual(app.load_profile(path)["name_alias"], "Lab alias")

    def test_malformed_profile_preserved(self):
        path = self.folder / "profile.json"
        for data in ("{", "[]", '{"name_alias": 10}'):
            path.write_text(data)
            with self.assertRaises(ValueError):
                app.load_profile(path)
            self.assertEqual(path.read_text(), data)

    def test_terminal_control_characters_escaped(self):
        self.assertNotIn("\x1b", app.safe_text("SSID\x1b[2J\nnew"))
        self.assertIn("\\x1b", app.safe_text("\x1b"))

    def test_platform_check_is_lazy(self):
        with patch.object(sys, "platform", "win32"), patch("builtins.input", return_value="q"):
            self.assertEqual(app.main([]), 0)
            with self.assertRaisesRegex(RuntimeError, "Kali/Linux"):
                app.require_linux()


class LanTests(QuietTest):
    def test_merge_arp_nmap_no_duplicates_and_vendor_evidence(self):
        def run(cmd, label, logfile, timeout=None):
            if cmd[0] == "arp-scan":
                return completed(
                    "192.0.2.1\t00:11:22:33:44:55\tARP vendor\n"
                    "192.0.2.1\t00:11:22:33:44:55\tARP vendor\n"
                    "198.51.100.1\t00:11:22:33:44:66\tOutside\n"
                )
            (self.folder / "discovery_nmap.xml").write_text(DISCOVERY)
            return completed()

        with (
            patch.object(app, "run_progress", side_effect=run),
            patch.object(app.shutil, "which", return_value="tool"),
        ):
            hosts = app.discover(
                "test0", "192.0.2.2", "192.0.2.1", ipaddress.ip_network("192.0.2.0/24"), self.folder
            )
        self.assertEqual([h["ip"] for h in hosts], ["192.0.2.1", "192.0.2.2", "192.0.2.3"])
        self.assertEqual(hosts[0]["sources"], ["ARP", "Nmap"])
        self.assertEqual(len(hosts[0]["manufacturer_evidence"]), 2)
        self.assertEqual(hosts[0]["vendor"], "Router vendor")
        self.assertTrue(hosts[0]["gateway"])
        self.assertTrue(hosts[1]["local"])
        self.assertEqual([h["id"] for h in hosts], [1, 2, 3])

    def test_local_and_arp_survive_broken_nmap_xml(self):
        (self.folder / "discovery_nmap.xml").write_text("<nmaprun>")
        with (
            patch.object(app, "run_progress", return_value=completed("", 1)),
            patch.object(app.shutil, "which", return_value=None),
        ):
            hosts = app.discover(
                "test0", "192.0.2.2", None, ipaddress.ip_network("192.0.2.0/24"), self.folder
            )
        self.assertEqual(len(hosts), 1)
        self.assertTrue(hosts[0]["local"])

    def test_default_selections_exclude_local_keep_unknown_and_apple(self):
        hosts = [host(10, local=True), host(20), host(30, vendor="Apple"), host(40)]
        identification = [
            {"id": h["id"], "ip": h["ip"], "mobile": h["id"] == 40, "type": "Unknown"}
            for h in hosts
        ]
        with patch("builtins.input", return_value="0"):
            self.assertEqual([h["id"] for h in app.choose(hosts, identification)], [20, 30, 40])
        with patch("builtins.input", return_value="1"):
            self.assertEqual([h["id"] for h in app.choose(hosts, identification)], [20, 30])
        with patch("builtins.input", side_effect=["2", "10,10,30"]):
            self.assertEqual([h["id"] for h in app.choose(hosts, identification)], [10, 30])

    def test_invalid_custom_selection_reprompts(self):
        hosts = [host(1)]
        ids = [{"id": 1, "ip": hosts[0]["ip"], "mobile": False, "type": "Unknown"}]
        with patch("builtins.input", side_effect=["2", "abc", "2", "900", "q"]):
            self.assertEqual(app.choose(hosts, ids), [])

    def test_apple_oui_alone_does_not_imply_mobile(self):
        with patch.object(app, "run_progress", return_value=completed()):
            identified = app.identify(host(1, vendor="Apple"), self.folder)
        self.assertFalse(identified["mobile"])
        self.assertEqual(identified["type_confidence"], "Baja")
        self.assertEqual(identified["vendor_confidence"], "Media")

    def test_cisco_ios_does_not_imply_apple_ios(self):
        target = host(1)
        (self.folder / f"identify_{target['ip']}.xml").write_text(
            '<nmaprun><host><os><osmatch name="Cisco IOS 15" accuracy="99"/></os></host></nmaprun>'
        )
        with patch.object(app, "run_progress", return_value=completed()):
            identified = app.identify(target, self.folder)
        self.assertFalse(identified["mobile"])
        self.assertNotEqual(identified["os"], "iOS (estimado)")

    def test_high_confidence_android_classification(self):
        target = host(1)
        (self.folder / f"identify_{target['ip']}.xml").write_text(
            '<nmaprun><host><os><osmatch name="Android 14" accuracy="98"/></os></host></nmaprun>'
        )
        with patch.object(app, "run_progress", return_value=completed()):
            self.assertTrue(app.identify(target, self.folder)["mobile"])

    def test_cves_services_ports_and_id_extracted(self):
        path = self.folder / "scan.xml"
        path.write_text(SCAN_XML)
        rows = app.parse_scan_xml(path, host(4))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["port"], "80/tcp")
        self.assertEqual(rows[0]["version"], "Test HTTP 1.0")
        self.assertEqual(rows[0]["id"], 4)
        self.assertEqual(rows[0]["cves"], "CVE-2023-54321,CVE-2024-12345")

    def test_both_modes_keep_full_scan_and_scripts(self):
        target = host(1)
        for mode in ("1", "2"):
            with patch.object(app, "run_progress", return_value=completed()) as run:
                app.scan_one(target, mode, self.folder, 1, 1)
            command = run.call_args.args[0]
            for arg in ("-p-", "-sV", "-sS", "default or vuln", "--stats-every"):
                self.assertIn(arg, command)
            self.assertEqual("--max-rate" in command, mode == "1")

    def test_cancelled_scan_preserves_xml_log_and_status(self):
        xml = self.folder / "scan_192.0.2.1.xml"
        xml.write_text("<partial>")
        with patch.object(app, "run_progress", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                app.scan_one(host(1), "1", self.folder, 1, 1)
        self.assertEqual(xml.read_text(), "<partial>")
        status = json.loads((self.folder / "scan_192.0.2.1_status.json").read_text())
        self.assertEqual(status["status"], "cancelled")

    def test_lan_workflow_saves_reports_on_cancellation(self):
        h = host(1)
        with (
            patch.object(app, "require_linux"),
            patch.object(app, "require_tools"),
            patch.object(
                app,
                "netinfo",
                return_value=("test0", "192.0.2.2", None, ipaddress.ip_network("192.0.2.0/24")),
            ),
            patch.object(app, "report_folder", return_value=self.folder),
            patch.object(app, "discover", return_value=[h]),
            patch.object(app, "identify", return_value={"id": 1}),
            patch.object(app, "show_ids"),
            patch.object(app, "choose", return_value=[h]),
            patch.object(app, "scan_one", side_effect=KeyboardInterrupt),
            patch("builtins.input", side_effect=["1", "s", ""]),
        ):
            app.lan_recon()
        report = json.loads((self.folder / "report.json").read_text())
        self.assertEqual(report["status"], "cancelled")
        self.assertTrue((self.folder / "report.csv").exists())

    def test_report_directories_are_unique(self):
        with patch.object(app, "REPORTS", self.folder):
            self.assertNotEqual(app.report_folder("lan"), app.report_folder("lan"))


class WirelessParsingTests(QuietTest):
    def test_interfaces_and_capabilities(self):
        interfaces = app.parse_iw_interfaces(IW_DEV)
        self.assertEqual([i["mode"] for i in interfaces], ["managed", "monitor"])
        self.assertEqual(interfaces[1]["phy"], "phy1")
        modes, frequencies = app.parse_phy(PHY)
        self.assertIn("monitor", modes)
        self.assertTrue(frequencies[-1]["disabled"])
        self.assertTrue(frequencies[-2]["no_ir"])
        self.assertTrue(frequencies[-2]["radar"])

    def test_detect_interfaces_uses_real_iw_format(self):
        with (
            patch.object(app.sys, "platform", "linux"),
            patch.object(app, "require_tools"),
            patch.object(
                app,
                "run_quiet",
                side_effect=[
                    completed(IW_DEV),
                    completed(PHY),
                    completed("Connected to 02:00:00:00:00:01"),
                    completed(PHY),
                    completed("Not connected."),
                ],
            ),
        ):
            interfaces = app.detect_wireless_interfaces()
        self.assertTrue(interfaces[0]["connected"])
        self.assertFalse(interfaces[1]["connected"])

    def test_missing_hardware_message_mentions_usb_passthrough(self):
        with (
            patch.object(app, "require_linux"),
            patch.object(app, "detect_wireless_interfaces", return_value=[]),
        ):
            with self.assertRaisesRegex(RuntimeError, "USB Wi-Fi passthrough"):
                app.wireless_recon()

    def test_shared_radio_rejected_even_if_sibling_disconnected(self):
        monitor = app.parse_iw_interfaces(IW_DEV)[1]
        sibling = dict(monitor, name="wlan1", mode="managed", connected=False)
        with self.assertRaisesRegex(RuntimeError, "compartida"):
            app.require_isolated_monitor(monitor, [monitor, sibling])

    def test_distinct_bssids_same_ssid_and_real_units(self):
        aps = app.parse_iw_scan(IW_SCAN)
        self.assertEqual(len(aps), 3)
        self.assertEqual(aps[0]["ssid"], aps[1]["ssid"])
        self.assertEqual(aps[0]["security"], "WPA2-PSK/WPA3-SAE")
        self.assertEqual(aps[0]["wps"], "Detected")
        self.assertEqual(aps[0]["signal_dbm"], -48.0)
        self.assertEqual(aps[1]["wps"], "Unknown")
        self.assertEqual(aps[1]["channel"], 36)
        self.assertEqual(aps[2]["ssid"], "Café")
        self.assertEqual(aps[2]["security"], "OPEN")
        self.assertIsNone(aps[2]["signal_dbm"])

    def test_security_classification_from_scanner_output(self):
        cases = {
            "WPA: * Version: 1": "WPA",
            "WPA: * Version: 1\nRSN: * Version: 1\n* Authentication suites: PSK": "WPA/WPA2-PSK",
            "RSN: * Version: 1\n* Authentication suites: SAE": "WPA3-SAE",
            "RSN: * Version: 1\n* Authentication suites: OWE": "OWE",
            "RSN: * Version: 1\n* Authentication suites: IEEE 802.1X": "WPA2-EAP",
            "RSN: * Version: 1\n* Authentication suites: IEEE 802.1X/SUITE-B-192": "WPA3-EAP",
            "RSN: * Version: 1": "RSN (AKM unknown)",
            "capability: ESS Privacy (0x0011)": "WEP/Unknown",
            "capability: ESS (0x0001)": "OPEN",
            "SSID: Unknown": "Unknown",
        }
        for text, expected in cases.items():
            with self.subTest(text=text):
                self.assertEqual(app.iw_security(text), expected)

    def test_nmcli_escaped_ssid_mac_and_percent(self):
        text = r"Lab\:WiFi\\One:02\:00\:00\:00\:00\:01:6:2437 MHz:WPA2 WPA3:80"
        ap = app.parse_nmcli(text)[0]
        self.assertEqual(ap["ssid"], "Lab:WiFi\\One")
        self.assertEqual(ap["bssid"], "02:00:00:00:00:01")
        self.assertEqual(ap["security"], "WPA2 WPA3")
        self.assertEqual(ap["signal_percent"], 80)
        self.assertIsNone(ap["signal_dbm"])
        self.assertEqual(ap["wps"], "Unknown")

    def test_stable_ids_and_deduplication(self):
        aps = app.parse_iw_scan(IW_SCAN)
        merged = app.stable_ap_ids(list(reversed(aps)) + [dict(aps[0])])
        self.assertEqual([a["bssid"] for a in merged], [a["bssid"] for a in aps])
        self.assertEqual([a["id"] for a in merged], [1, 2, 3])

    def test_nmcli_fallback_after_iw_failure(self):
        iface = app.parse_iw_interfaces(IW_DEV)[0]
        limitations = []
        with (
            patch.object(
                app,
                "run_progress",
                side_effect=[
                    completed("busy", 1),
                    completed(r"LAB:02\:00\:00\:00\:00\:01:6:2437 MHz:WPA2:85"),
                ],
            ),
            patch.object(app.shutil, "which", return_value="nmcli"),
        ):
            aps = app.discover_wifi(iface, [iface], self.folder, limitations)
        self.assertEqual(aps[0]["backend"], "nmcli")
        self.assertTrue(limitations)

    def test_frequency_6ghz_not_confused_with_24ghz(self):
        for freq, channel in [(2412, 1), (2484, 14), (5180, 36), (5955, 1), (5935, 2)]:
            self.assertEqual(app.frequency_channel(freq), channel)

    def test_authorization_is_target_specific(self):
        ap = app.parse_iw_scan(IW_SCAN)[0]
        for answer, expected in [
            ("", False),
            ("yes", False),
            ("AUTORIZO 02:00:00:00:00:02", False),
            ("AUTORIZO " + ap["bssid"], True),
        ]:
            with patch("builtins.input", return_value=answer):
                self.assertEqual(app.authorize_target(ap), expected)

    def test_denied_fingerprint_never_imports_or_transmits(self):
        with patch.object(app, "load_upstream") as loader:
            result = app.fingerprint_selected({}, {}, [], self.folder, authorized=False)
        loader.assert_not_called()
        self.assertEqual(result["classification"], "NOT_TESTED")

    def test_assessment_uses_actual_outputs_and_checks_target(self):
        ap = app.parse_iw_scan(IW_SCAN)[0]
        document = {"target": {"ssid": ap["ssid"], "bssid": ap["bssid"]}}
        for raw, expected in [
            ("LIKELY_VULNERABLE", "LIKELY_VULNERABLE"),
            ("PATCHED_HOSTAPD", "NOT_VULNERABLE_PER_DETECTOR"),
            ("NO_BROADCOM_FINGERPRINT", "NOT_VULNERABLE_PER_DETECTOR"),
            ("INCONCLUSIVE", "INCONCLUSIVE"),
            ("NEW_VALUE", "INCONCLUSIVE"),
        ]:
            self.assertEqual(
                app.assessment_from_upstream(dict(document, assessment=raw), ap), expected
            )
        document["target"]["bssid"] = "02:00:00:00:00:ff"
        self.assertEqual(app.assessment_from_upstream(document, ap), "ERROR")


class UpstreamIntegrationTests(QuietTest):
    @classmethod
    def setUpClass(cls):
        cls.up = app.load_upstream()

    def observation(self, wps=True, evidence=True):
        return self.up.Observation(
            "LAB-WIFI",
            "02:00:00:00:00:01",
            6,
            -48,
            wps_advertised=wps,
            broadcom_evidence=("fixture",) if evidence else (),
        )

    def test_monitor_discovery_restores_original_frequency_on_cancel(self):
        iface = app.parse_iw_interfaces(IW_DEV)[1]
        iface["capabilities"], iface["frequencies"] = app.parse_phy(PHY)
        with (
            patch.object(app, "require_linux"),
            patch.object(app, "set_frequency") as tune,
            patch.object(app, "capture_beacons", side_effect=KeyboardInterrupt),
        ):
            with self.assertRaises(KeyboardInterrupt):
                app.monitor_discovery(iface, [iface], self.folder, [])
        self.assertEqual(tune.call_args.args, (iface["name"], 5180))

    def test_selected_reobservation_ignores_other_bssid_same_ssid(self):
        ap = app.parse_iw_scan(IW_SCAN)[0]
        iface = app.parse_iw_interfaces(IW_DEV)[1]
        other = self.up.Observation(ap["ssid"], "02:00:00:00:00:02", 6, -30)
        writer = Mock()

        def build_sniffer(**kwargs):
            sniffer = Mock()
            sniffer.start.side_effect = lambda: kwargs["prn"](object())
            return sniffer

        with (
            patch.object(self.up, "AsyncSniffer", side_effect=build_sniffer),
            patch.object(self.up, "parse_advertisement", return_value=other),
        ):
            with self.assertRaisesRegex(RuntimeError, "no se ha observado"):
                app.observe_selected(self.up, iface, ap, writer, seconds=0)
        writer.write.assert_not_called()

    def test_wireless_workflow_saves_denied_authorization_without_probe(self):
        iface = app.parse_iw_interfaces(IW_DEV)[1]
        iface.update(driver="fixture", connected=False)
        aps = app.parse_iw_scan(IW_SCAN)
        with (
            patch.object(app, "require_linux"),
            patch.object(app, "detect_wireless_interfaces", return_value=[iface]),
            patch.object(app, "report_folder", return_value=self.folder),
            patch.object(app, "discover_wifi", return_value=aps),
            patch.object(app, "fingerprint_selected") as fingerprint,
            patch("builtins.input", side_effect=["1", "1", "1", ""]),
        ):
            app.wireless_recon()
        fingerprint.assert_not_called()
        report = json.loads((self.folder / "report.json").read_text())
        self.assertEqual(report["assessment"], "NOT_TESTED")
        self.assertFalse(report["authorization"]["granted"])
        self.assertEqual(report["selected_target"]["bssid"], aps[0]["bssid"])

    def test_wireless_workflow_annotates_only_selected_ap(self):
        iface = app.parse_iw_interfaces(IW_DEV)[1]
        iface.update(driver="fixture", connected=False)
        aps = app.parse_iw_scan(IW_SCAN)
        outcome = {
            "classification": "LIKELY_VULNERABLE",
            "original": None,
            "error": None,
            "limitations": [],
        }
        with (
            patch.object(app, "require_linux"),
            patch.object(app, "detect_wireless_interfaces", return_value=[iface]),
            patch.object(app, "report_folder", return_value=self.folder),
            patch.object(app, "discover_wifi", return_value=aps),
            patch.object(app, "fingerprint_selected", return_value=outcome) as fingerprint,
            patch("builtins.input", side_effect=["1", "2", "1", "AUTORIZO " + aps[1]["bssid"]]),
        ):
            app.wireless_recon()
        fingerprint.assert_called_once()
        self.assertEqual(fingerprint.call_args.args[0]["bssid"], aps[1]["bssid"])
        report = json.loads((self.folder / "report.json").read_text())
        self.assertEqual(report["assessment"], report["selected_target"]["assessment"])
        self.assertEqual(
            [a["assessment"] for a in report["access_points"]],
            ["NOT_TESTED", "LIKELY_VULNERABLE", "NOT_TESTED"],
        )

    def test_pinned_vendor_files_unchanged(self):
        manifest = json.loads((app.VENDOR / "UPSTREAM.json").read_text())
        self.assertEqual(manifest["commit"], app.UPSTREAM_COMMIT)
        for name, digest in manifest["files"].items():
            self.assertEqual(hashlib.sha256((app.VENDOR / name).read_bytes()).hexdigest(), digest)

    def test_actual_detector_with_mock_response_matrix(self):
        for response, expected in [
            (self.up.ResponseKind.REJECTED, "LIKELY_VULNERABLE"),
            (self.up.ResponseKind.ACK, "PATCHED_HOSTAPD"),
            (self.up.ResponseKind.SILENCE, "INCONCLUSIVE"),
            (self.up.ResponseKind.ERROR, "INCONCLUSIVE"),
        ]:
            backend = Mock()
            backend.probe_first_fragment.return_value = self.up.TransactionOutcome(
                response, False, None, "fixture"
            )
            target = self.observation()
            result = self.up.fingerprint_target(target, backend)
            self.assertEqual(str(result.assessment), expected)
            self.assertEqual(result.target_health, "DEGRADED")
            backend.probe_first_fragment.assert_called_once_with(target, 0, b"", recover=False)

    def test_no_wps_does_not_transmit(self):
        backend = Mock()
        result = self.up.fingerprint_target(self.observation(wps=False), backend)
        backend.probe_first_fragment.assert_not_called()
        self.assertEqual(str(result.assessment), "INCONCLUSIVE")

    def test_transport_blocks_deauth_disassoc_and_other_bssid(self):
        backend = app.restricted_backend(self.up)("wlan1mon", self.observation(), Mock())
        with patch.object(self.up, "sendp") as send:
            with self.assertRaises(self.up.FingerprintError):
                backend._deauthenticate("02:00:00:00:00:10")
            for subtype in (10, 12):
                packet = self.up.RadioTap() / self.up.Dot11(
                    type=0,
                    subtype=subtype,
                    addr1=backend.target.bssid,
                    addr2="02:00:00:00:00:10",
                    addr3=backend.target.bssid,
                )
                with self.assertRaises(self.up.FingerprintError):
                    backend._transmit(packet)
            wrong = self.up.RadioTap() / self.up.Dot11(
                type=0,
                subtype=11,
                addr1="02:00:00:00:00:ff",
                addr2="02:00:00:00:00:10",
                addr3=backend.target.bssid,
            )
            with self.assertRaises(self.up.FingerprintError):
                backend._transmit(wrong)
        send.assert_not_called()

    def test_cleanup_is_not_falsely_reported_successful(self):
        backend = app.restricted_backend(self.up)("wlan1mon", self.observation(), Mock())
        with (
            patch.object(backend, "_start_wps", return_value=1),
            patch.object(backend, "_send_eapol"),
            patch.object(backend, "_wait_eap", return_value=(4, 1, b"")),
            patch.object(self.up, "sendp") as send,
        ):
            result = self.up.fingerprint_target(backend.target, backend)
        self.assertEqual(str(result.assessment), "LIKELY_VULNERABLE")
        self.assertFalse(result.outcomes[0].cleanup_sent)
        self.assertIn("blocks deauthentication", result.outcomes[0].detail)
        send.assert_not_called()

    def test_packet_security_and_pcap_preserved(self):
        from scapy.layers.dot11 import Dot11Beacon
        from scapy.utils import PcapReader, PcapWriter

        rsn = bytes.fromhex("0100000fac040100000fac040200000fac02000fac080000")
        packet = (
            self.up.RadioTap(present="dBm_AntSignal", dBm_AntSignal=-55)
            / self.up.Dot11(
                type=0,
                subtype=8,
                addr1="ff:ff:ff:ff:ff:ff",
                addr2="02:00:00:00:00:01",
                addr3="02:00:00:00:00:01",
            )
            / Dot11Beacon(cap="ESS+privacy")
            / self.up.Dot11Elt(ID=0, info=b"LAB-WIFI")
            / self.up.Dot11Elt(ID=3, info=b"\x06")
            / self.up.Dot11Elt(ID=48, info=rsn)
            / self.up.Dot11Elt(ID=221, info=self.up.WPS_IE_PREFIX)
        )
        path = self.folder / "fixture.pcap"
        with PcapWriter(str(path), linktype=127, sync=True) as writer:
            writer.write(packet)
        original = path.read_bytes()
        with PcapReader(str(path)) as reader:
            ap = app.packet_ap(next(reader), self.up, 2437)
        self.assertEqual(ap["security"], "WPA2-PSK/WPA3-SAE")
        self.assertEqual(ap["wps"], "Detected")
        self.assertEqual(ap["signal_dbm"], -55)
        app.write_wireless_report(self.folder, {"assessment": "NOT_TESTED", "selected_target": ap})
        self.assertEqual(path.read_bytes(), original)
        report = json.loads((self.folder / "report.json").read_text())
        self.assertEqual(report["artifacts"][0]["sha256"], hashlib.sha256(original).hexdigest())

    def test_fingerprint_orchestration_keeps_original_json_and_restores_frequency(self):
        ap = app.parse_iw_scan(IW_SCAN)[0]
        iface = app.parse_iw_interfaces(IW_DEV)[1]
        iface["capabilities"], iface["frequencies"] = app.parse_phy(PHY)
        result = self.up.FingerprintResult(
            ap["ssid"], ap["bssid"], 6, assessment=self.up.Assessment.LIKELY_VULNERABLE
        )
        with (
            patch.object(app, "require_linux"),
            patch.object(
                self.up, "inspect_monitor_interface", return_value=self.up.MonitorState(36)
            ),
            patch.object(app, "set_frequency") as tune,
            patch.object(app, "observe_selected", return_value=self.observation()),
            patch.object(
                app,
                "restricted_backend",
                return_value=Mock(return_value=contextlib.nullcontext(Mock())),
            ),
            patch.object(self.up, "fingerprint_target", return_value=result),
        ):
            outcome = app.fingerprint_selected(ap, iface, [iface], self.folder, authorized=True)
        self.assertEqual(outcome["classification"], "LIKELY_VULNERABLE")
        raw = (self.folder / "upstream_result.json").read_bytes()
        app.write_wireless_report(self.folder, {"original_fingerprint": outcome["original"]})
        self.assertEqual((self.folder / "upstream_result.json").read_bytes(), raw)
        self.assertEqual(outcome["original"]["target"]["bssid"], ap["bssid"])
        self.assertEqual(tune.call_args.args, (iface["name"], 5180))

    def test_interrupted_fingerprint_restores_frequency_and_keeps_pcap(self):
        ap = app.parse_iw_scan(IW_SCAN)[0]
        iface = app.parse_iw_interfaces(IW_DEV)[1]
        iface["capabilities"], iface["frequencies"] = app.parse_phy(PHY)
        with (
            patch.object(app, "require_linux"),
            patch.object(
                self.up, "inspect_monitor_interface", return_value=self.up.MonitorState(36)
            ),
            patch.object(app, "set_frequency") as tune,
            patch.object(app, "observe_selected", side_effect=KeyboardInterrupt),
        ):
            outcome = app.fingerprint_selected(ap, iface, [iface], self.folder, authorized=True)
        self.assertEqual(outcome["classification"], "INCONCLUSIVE")
        self.assertTrue((self.folder / "fingerprint.pcap").exists())
        self.assertEqual(tune.call_args.args, (iface["name"], 5180))

    def test_6ghz_active_probe_rejected(self):
        ap = dict(app.parse_iw_scan(IW_SCAN)[0], frequency_mhz=5955)
        iface = app.parse_iw_interfaces(IW_DEV)[1]
        with patch.object(app, "require_linux"), patch.object(app, "load_upstream") as load:
            outcome = app.fingerprint_selected(ap, iface, [iface], self.folder, authorized=True)
        self.assertEqual(outcome["classification"], "ERROR")
        load.assert_not_called()


class ProcessTests(QuietTest):
    def test_subprocess_log_and_exit_code(self):
        path = self.folder / "process.log"
        result = app.run_progress(
            [sys.executable, "-c", "print('Timing: About 25.00% done; (0:00:03 remaining)')"],
            "fixture",
            path,
            timeout=5,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("25.00%", path.read_text())
        self.assertNotIn("\r", self.output.getvalue())

    def test_timeout_terminates_child_and_keeps_output(self):
        path = self.folder / "timeout.log"
        code = "import time; print('evidence', flush=True); time.sleep(30)"
        with self.assertRaises(subprocess.TimeoutExpired):
            app.run_progress([sys.executable, "-c", code], "timeout fixture", path, timeout=0.3)
        self.assertIn("evidence", path.read_text())

    def test_missing_binary_actionable_error(self):
        with patch.object(app.shutil, "which", return_value=None):
            with self.assertRaisesRegex(RuntimeError, "nmap.*README"):
                app.require_tools("nmap")


class NmapSmokeTest(QuietTest):
    @unittest.skipUnless(shutil.which("nmap"), "Nmap is not installed on this host")
    def test_real_nmap_against_ephemeral_loopback_http_server(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"POLTERHEIST test fixture")

            def log_message(self, *args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        path = self.folder / "real_nmap.xml"
        try:
            result = app.run_progress(
                [
                    "nmap",
                    "-sT",
                    "-Pn",
                    "-n",
                    "-sV",
                    "--version-light",
                    "--script",
                    "banner",
                    "-p",
                    str(server.server_port),
                    "-oX",
                    str(path),
                    "127.0.0.1",
                ],
                "loopback only",
                self.folder / "real_nmap.log",
                timeout=60,
            )
            self.assertEqual(result.returncode, 0)
            rows = app.parse_scan_xml(path, host(1, "127.0.0.1", local=True))
            self.assertEqual(rows[0]["port"], f"{server.server_port}/tcp")
            self.assertEqual(rows[0]["service"], "http")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
