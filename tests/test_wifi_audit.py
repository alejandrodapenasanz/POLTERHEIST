"""Offline password-audit regressions; synthetic authentication, no radio traffic."""

import contextlib
import hashlib
import hmac
import io
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scapy.all import (
    EAPOL,
    EAPOL_KEY,
    LLC,
    SNAP,
    AKMSuite,
    Dot11,
    Dot11Beacon,
    Dot11Elt,
    Dot11EltRSN,
    PcapReader,
    RadioTap,
    wrpcap,
)

import script as app
import wifi_audit as audit
from app_logging import JsonFormatter

SSID = "POLTERHEIST-LAB"
BSSID = "02:00:00:00:00:01"
PASSWORD = "fixture-passphrase-only"


def handshake(bssid=BSSID, ssid=SSID, password=PASSWORD):
    """Build a WPA2-PSK M1/M2 exchange with a real MIC for a known fixture key."""
    station = "02:00:00:00:00:10"
    ap_mac, client_mac = (bytes.fromhex(mac.replace(":", "")) for mac in (bssid, station))
    anonce, snonce = bytes(range(32)), bytes(range(32, 64))
    context = min(ap_mac, client_mac) + max(ap_mac, client_mac) + anonce + snonce
    pmk = hashlib.pbkdf2_hmac("sha1", password.encode(), ssid.encode(), 4096, 32)
    kck = hmac.digest(pmk, b"Pairwise key expansion\0" + context + b"\0", "sha1")[:16]
    rsn = Dot11EltRSN(akm_suites=[AKMSuite(suite=2)], mfp_capable=0, mfp_required=0)
    beacon = (
        RadioTap()
        / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid)
        / Dot11Beacon(cap="ESS+privacy")
        / Dot11Elt(ID="SSID", info=ssid.encode())
        / rsn
    )
    first = EAPOL(version=1, type=3) / EAPOL_KEY(
        key_descriptor_type=2,
        key_descriptor_type_version=2,
        key_type=1,
        key_ack=1,
        has_key_mic=0,
        key_length=16,
        key_replay_counter=1,
        key_nonce=anonce,
    )
    second = EAPOL(version=1, type=3) / EAPOL_KEY(
        key_descriptor_type=2,
        key_descriptor_type_version=2,
        key_type=1,
        key_ack=0,
        has_key_mic=1,
        key_length=16,
        key_replay_counter=1,
        key_nonce=snonce,
        key_mic=bytes(16),
        key_data=bytes(rsn),
    )
    second[EAPOL_KEY].key_mic = hmac.digest(kck, bytes(second), "sha1")[:16]
    one = (
        RadioTap()
        / Dot11(type=2, FCfield=2, addr1=station, addr2=bssid, addr3=bssid)
        / LLC()
        / SNAP(code=0x888E)
        / first
    )
    two = (
        RadioTap()
        / Dot11(type=2, FCfield=1, addr1=bssid, addr2=station, addr3=bssid)
        / LLC()
        / SNAP(code=0x888E)
        / second
    )
    for index, packet in enumerate((beacon, one, two)):
        packet.time = 1700000000 + index * 0.1
    return [beacon, one, two]


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.folder = Path(self.temporary.name).resolve()
        self.capture = self.folder / "input.pcap"
        wrpcap(str(self.capture), handshake())
        self.wordlist = self.folder / "dictionary, with spaces.txt"
        self.wordlist.write_text("another-candidate\n" + PASSWORD + "\n", encoding="utf-8")
        self.output = io.StringIO()
        redirect = contextlib.redirect_stdout(self.output)
        redirect.__enter__()
        self.addCleanup(redirect.__exit__, None, None, None)
        self.target = {"ssid": SSID, "bssid": BSSID, "security": "WPA2-PSK"}

    def test_capture_excludes_other_bssids_even_with_same_ssid(self):
        foreign = handshake("02:00:00:00:00:02")
        wrpcap(str(self.capture), handshake() + foreign)
        destination = self.folder / "selected.cap"
        counts = audit.scoped_capture(app, self.capture, destination, SSID, BSSID)
        self.assertEqual(counts, {"beacons": 1, "eapol_frames": 2})
        with PcapReader(str(destination)) as packets:
            self.assertEqual(len(list(packets)), 3)

    def test_ssid_mismatch_and_unreadable_capture_rejected(self):
        with self.assertRaisesRegex(ValueError, "SSID does not match"):
            audit.scoped_capture(app, self.capture, self.folder / "mismatch.cap", "Wrong", BSSID)
        self.capture.write_bytes(b"invalid pcap contents")
        with self.assertRaisesRegex(ValueError, "Unable to read"):
            audit.scoped_capture(app, self.capture, self.folder / "invalid.cap", SSID, BSSID)

    def test_imported_sae_and_enterprise_captures_are_rejected(self):
        for suite in (8, 1):
            with self.subTest(suite=suite):
                packets = handshake()
                packets[0][Dot11EltRSN].akm_suites = [AKMSuite(suite=suite)]
                wrpcap(str(self.capture), packets)
                with self.assertRaisesRegex(ValueError, "Unsupported captured authentication"):
                    audit.scoped_capture(
                        app, self.capture, self.folder / "unsupported.cap", SSID, BSSID
                    )

    def test_candidate_result_and_secret_never_share_report(self):
        def successful(_app, command, _label, _timeout, *, stdin):
            self.assertEqual(command[command.index("-w") + 1], "-")
            self.assertIn(PASSWORD.encode(), stdin.read())
            self.secret_file = Path(command[command.index("-l") + 1])
            self.secret_file.write_text(PASSWORD, encoding="utf-8")
            return 0, "KEY FOUND! [ " + PASSWORD + " ]", False

        folder = self.folder / "report"
        folder.mkdir()
        report = {}
        with (
            patch.object(app, "require_tools"),
            patch.object(audit.shutil, "which", return_value="aircrack-ng"),
            patch.object(audit, "execute", side_effect=successful),
        ):
            self.assertEqual(
                audit.audit(
                    app, folder, report, self.target, self.wordlist, 10, source=self.capture
                ),
                0,
            )
        self.assertEqual(report["status"], "RECOVERED")
        self.assertIn(PASSWORD, self.output.getvalue())
        self.assertFalse(self.secret_file.exists())
        self.assertNotIn(PASSWORD, (folder / "report.json").read_text())
        import logging

        record = logging.LogRecord("test", 20, "", 0, "secret: %s", (PASSWORD,), None)
        self.assertNotIn(PASSWORD, JsonFormatter("test").format(record))

    def test_non_success_outcomes_are_distinct(self):
        for code, output, timed_out, expected in (
            (1, "\nKEY NOT FOUND\n", False, "NOT_RECOVERED"),
            (1, "No valid WPA handshakes found.", False, "NO_HANDSHAKE"),
            (1, "No matching network found - check your bssid.", False, "NO_HANDSHAKE"),
            (1, "Unknown internal failure", False, "ERROR"),
            (0, "KEY FOUND! [ unreliable-output ]", False, "ERROR"),
            (1, "KEY NOT FOUND", True, "TIMEOUT"),
        ):
            with (
                self.subTest(expected=expected),
                patch.object(audit.shutil, "which", return_value="aircrack-ng"),
                patch.object(audit, "execute", return_value=(code, output, timed_out)),
            ):
                result, secret = audit.crack(app, self.capture, self.wordlist, SSID, BSSID, 10)
                self.assertEqual(result["status"], expected)
                self.assertIsNone(secret)

    def test_no_eapol_does_not_start_dictionary(self):
        wrpcap(str(self.capture), handshake()[:1])
        with patch.object(app, "require_tools"), patch.object(audit, "crack") as crack:
            report = {}
            audit.audit(
                app, self.folder, report, self.target, self.wordlist, 10, source=self.capture
            )
        crack.assert_not_called()
        self.assertEqual(report["status"], "NO_HANDSHAKE")

    def test_cancel_preserves_report(self):
        with (
            patch.object(app, "require_tools"),
            patch.object(audit, "crack", side_effect=KeyboardInterrupt),
        ):
            report = {}
            self.assertEqual(
                audit.audit(
                    app, self.folder, report, self.target, self.wordlist, 10, source=self.capture
                ),
                130,
            )
        self.assertEqual(
            json.loads((self.folder / "report.json").read_text())["status"], "CANCELLED"
        )

    def test_missing_tool_and_unsupported_auth_never_capture(self):
        for security in ("WPA3-SAE", "WPA2-EAP", "OPEN", "WEP", "WPA2", "Unknown"):
            with (
                self.subTest(security=security),
                patch.object(app, "require_tools"),
                patch.object(audit, "capture_live") as capture,
            ):
                report = {}
                result = audit.audit(
                    app,
                    self.folder,
                    report,
                    dict(self.target, security=security),
                    self.wordlist,
                    10,
                )
                self.assertEqual(result, 1)
                capture.assert_not_called()
        self.assertTrue(audit.psk_supported("WPA2-PSK/WPA3-SAE"))
        with (
            patch.object(app, "require_tools", side_effect=RuntimeError("Missing aircrack-ng")),
            patch.object(audit, "capture_live") as capture,
        ):
            report = {}
            audit.audit(app, self.folder, report, self.target, self.wordlist, 10)
            self.assertEqual(report["status"], "ERROR")
            capture.assert_not_called()

    def test_capture_cleanup_on_success_cancel_and_failure(self):
        for outcome in ("success", "cancel", "failure", "restore_failure"):
            with self.subTest(outcome=outcome):
                report = {}
                restored = []

                @contextlib.contextmanager
                def prepared(target, radio, interfaces, folder, state):
                    try:
                        yield {"name": "wlan-fixture"}, []
                    finally:
                        restored.append(True)
                        state["restored"] = outcome != "restore_failure"
                        if outcome == "restore_failure":
                            state["restore_error"] = "fixture restoration error"

                def capture(*args, **kwargs):
                    if outcome == "cancel":
                        raise KeyboardInterrupt
                    if outcome == "failure":
                        raise OSError("fixture startup error")
                    shutil.copyfile(self.capture, self.folder / "capture-01.cap")
                    return -2, "", True

                with (
                    patch.object(app, "require_linux"),
                    patch.object(app, "require_tools"),
                    patch.object(app, "detect_wireless_interfaces", return_value=[]),
                    patch.object(app, "linux_radio_candidate", return_value={}),
                    patch.object(app, "prepared_linux_monitor", side_effect=prepared),
                    patch.object(audit, "execute", side_effect=capture),
                ):
                    if outcome == "success":
                        self.assertTrue(
                            audit.capture_live(
                                app, dict(self.target, channel=6), {}, self.folder, report, 1
                            ).exists()
                        )
                    else:
                        expected = (
                            KeyboardInterrupt
                            if outcome == "cancel"
                            else OSError
                            if outcome == "failure"
                            else RuntimeError
                        )
                        with self.assertRaises(expected):
                            audit.capture_live(
                                app, dict(self.target, channel=6), {}, self.folder, report, 1
                            )
                self.assertEqual(restored, [True])

    def test_restore_failure_takes_precedence_and_stops_cracking(self):
        def failed_capture(_app, _target, _preferred, _folder, report, _seconds):
            report["radio_setup"] = {"restore_error": "fixture"}
            raise RuntimeError("Restoration failed")

        with (
            patch.object(app, "require_tools"),
            patch.object(audit, "capture_live", side_effect=failed_capture),
            patch.object(audit, "crack") as crack,
        ):
            report = {}
            audit.audit(app, self.folder, report, self.target, self.wordlist, 10)
        self.assertEqual(report["status"], "RESTORE_FAILED")
        crack.assert_not_called()

    def test_submenu_and_cli_route_to_new_audit(self):
        with (
            patch("builtins.input", side_effect=["bad", "1", "2", "q"]),
            patch.object(app, "wireless_recon") as wps,
            patch.object(app, "aircrack_audit") as password,
        ):
            app.wireless_menu()
            wps.assert_called_once_with()
            password.assert_called_once_with()
        with (
            patch.object(app.startup_check, "refresh"),
            patch.object(app.startup_check, "display"),
            patch.object(app, "aircrack_audit", return_value=0) as password,
            patch.object(app, "wireless_recon") as wps,
        ):
            self.assertEqual(
                app.run_main(["--aircrack", "file", "--ssid", SSID, "--bssid", BSSID]), 0
            )
            password.assert_called_once_with(SSID, BSSID, "file")
            wps.assert_not_called()

    def test_file_wizard_needs_no_radio(self):
        answers = [str(self.capture), SSID, BSSID, str(self.wordlist), "10"]
        with (
            patch("builtins.input", side_effect=answers),
            patch.object(app, "require_tools"),
            patch.object(app, "report_folder", return_value=self.folder),
            patch.object(app, "detect_wireless_interfaces") as radio,
            patch.object(audit, "audit", return_value=0) as run,
        ):
            self.assertEqual(audit.wizard(app, mode="file"), 0)
        radio.assert_not_called()
        self.assertEqual(run.call_args.kwargs["source"], self.capture)

    def test_process_drains_output_and_timeout_stops_child(self):
        code, output, timed_out = audit.execute(
            app, [sys.executable, "-c", "print('x' * 100000)"], "fixture", 10
        )
        self.assertEqual(code, 0)
        self.assertLessEqual(len(output), 65536)
        self.assertFalse(timed_out)
        code, _, timed_out = audit.execute(
            app, [sys.executable, "-c", "import time; time.sleep(30)"], "fixture", 0.1
        )
        self.assertTrue(timed_out)
        self.assertIsInstance(code, int)

    def test_process_is_stopped_on_keyboard_interrupt(self):
        original = subprocess.Popen.wait
        interrupted = []

        def interrupt_once(process, *args, **kwargs):
            if not interrupted:
                interrupted.append(process)
                raise KeyboardInterrupt
            return original(process, *args, **kwargs)

        with (
            patch.object(subprocess.Popen, "wait", interrupt_once),
            self.assertRaises(KeyboardInterrupt),
        ):
            audit.execute(app, [sys.executable, "-c", "import time; time.sleep(30)"], "fixture", 20)
        self.assertIsNotNone(interrupted[0].poll())

    @unittest.skipUnless(shutil.which("aircrack-ng"), "Aircrack-ng not installed")
    def test_real_aircrack_known_key_absent_key_and_wrong_bssid(self):
        for contents, bssid, expected in (
            ("wrong-candidate\n" + PASSWORD + "\n", BSSID, "RECOVERED"),
            ("wrong-candidate\n", BSSID, "NOT_RECOVERED"),
            (PASSWORD + "\n", "02:00:00:00:00:99", "NO_HANDSHAKE"),
        ):
            with self.subTest(expected=expected):
                folder = self.folder / expected
                folder.mkdir()
                self.wordlist.write_text(contents, encoding="utf-8")
                report = {}
                audit.audit(
                    app,
                    folder,
                    report,
                    dict(self.target, bssid=bssid),
                    self.wordlist,
                    15,
                    source=self.capture,
                )
                self.assertEqual(report["status"], expected, report)
                self.assertNotIn(PASSWORD, (folder / "report.json").read_text())


if __name__ == "__main__":
    unittest.main()
