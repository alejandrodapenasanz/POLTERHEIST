"""Verdicts must come from the selected target's original detector evidence."""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import script as app


class FingerprintTests(unittest.TestCase):
    def setUp(self):
        self.ap = dict(app.new_ap("02:00:00:00:00:01", "Lab"), id=1, channel=6)
        self.temp = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def evidence(self, assessment):
        return {
            "target": {"ssid": "Lab", "bssid": self.ap["bssid"]},
            "assessment": assessment,
            "implementation": "HOSTAPD",
            "transactions": [{"response": "ACK", "cleanup_sent": False}],
            "target_health": "DEGRADED",
            "warning": "cleanup failed",
        }

    def test_explicit_detector_verdicts(self):
        for original, expected, title in [
            ("LIKELY_VULNERABLE", "LIKELY_VULNERABLE", "PROBABLEMENTE VULNERABLE"),
            ("PATCHED_HOSTAPD", "NOT_VULNERABLE_PER_DETECTOR", "NEGATIVO SEGÚN EL DETECTOR"),
            (
                "NO_BROADCOM_FINGERPRINT",
                "NOT_VULNERABLE_PER_DETECTOR",
                "NEGATIVO SEGÚN EL DETECTOR",
            ),
            ("INCONCLUSIVE", "INCONCLUSIVE", "NO CONCLUYENTE"),
        ]:
            with self.subTest(original=original):
                summary = app.fingerprint_summary(self.ap, "INCONCLUSIVE", self.evidence(original))
                self.assertEqual(summary["assessment"], expected)
                self.assertEqual(summary["verdict"], title)
                self.assertEqual(summary["detector_assessment"], original)

    def test_missing_original_never_supports_positive_or_negative(self):
        for classification in ["LIKELY_VULNERABLE", "NOT_VULNERABLE_PER_DETECTOR"]:
            summary = app.fingerprint_summary(self.ap, classification)
            self.assertEqual(summary["assessment"], "INCONCLUSIVE")
            self.assertIn("salida original", summary["reason"])

    def test_wrong_target_never_supports_conclusion(self):
        for field, wrong in [("ssid", "Other"), ("bssid", "02:00:00:00:00:02")]:
            original = self.evidence("LIKELY_VULNERABLE")
            original["target"][field] = wrong
            summary = app.fingerprint_summary(self.ap, "LIKELY_VULNERABLE", original)
            self.assertEqual(summary["assessment"], "ERROR")
            self.assertIsNone(summary["detector_assessment"])
            self.assertIn("SSID/BSSID", summary["reason"])

    def test_unknown_and_invalid_detector_outputs(self):
        for original in [None, [], {"target": []}, {"target": {"bssid": None}}]:
            self.assertEqual(app.assessment_from_upstream(original, self.ap), "ERROR")
        for value in ["FUTURE_STATUS", None, []]:
            original = self.evidence(value)
            self.assertEqual(app.assessment_from_upstream(original, self.ap), "INCONCLUSIVE")

    def test_wps_present_or_vendor_never_becomes_vulnerability(self):
        self.ap.update(wps="Detected", manufacturer_evidence=[{"value": "Broadcom"}])
        summary = app.fingerprint_summary(self.ap, "NOT_TESTED", reason="Falta Npcap")
        self.assertEqual(summary["verdict"], "NO EVALUADO")
        self.assertEqual(summary["reason"], "Falta Npcap")
        self.assertIsNone(summary["detector_assessment"])

    def test_actual_upstream_silence_and_no_wps_remain_inconclusive(self):
        upstream = app.load_upstream()
        backend = Mock()
        backend.probe_first_fragment.return_value = upstream.TransactionOutcome(
            upstream.ResponseKind.SILENCE, False, None, "timeout"
        )
        for advertised in (False, True):
            target = upstream.Observation(
                "Lab", self.ap["bssid"], 6, -48, wps_advertised=advertised
            )
            result = upstream.fingerprint_target(target, backend)
            path = self.folder / "upstream_result.json"
            upstream.write_result_json(result, path, self.folder / "unused.pcap")
            summary = app.fingerprint_summary(self.ap, "INCONCLUSIVE", json.loads(path.read_text()))
            self.assertEqual(summary["verdict"], "NO CONCLUYENTE")

    def test_saved_summary_preserves_raw_file_and_only_changes_selected_ap(self):
        original = self.evidence("PATCHED_HOSTAPD")
        raw_path = self.folder / "upstream_result.json"
        app.dump_json(raw_path, original)
        raw = raw_path.read_bytes()
        other = dict(self.ap, id=2, bssid="02:00:00:00:00:02")
        report = {
            "selected_target": dict(self.ap),
            "access_points": [self.ap, other],
            "assessment": "NOT_VULNERABLE_PER_DETECTOR",
            "original_fingerprint": original,
        }
        summary = app.save_fingerprint_summary(self.folder, report)
        app.write_wireless_report(self.folder, report)
        self.assertEqual(raw_path.read_bytes(), raw)
        self.assertEqual(report["assessment"], summary["assessment"])
        self.assertEqual(report["selected_target"]["assessment"], summary["assessment"])
        self.assertEqual(other["assessment"], "NOT_TESTED")
        self.assertTrue(any(a["path"] == "fingerprint.json" for a in report["artifacts"]))

    def test_no_target_does_not_create_a_result(self):
        self.assertIsNone(app.save_fingerprint_summary(self.folder, {"selected_target": None}))
        self.assertFalse((self.folder / "fingerprint.json").exists())

    def test_human_output_includes_reason_response_and_health(self):
        summary = app.fingerprint_summary(self.ap, "INCONCLUSIVE", self.evidence("PATCHED_HOSTAPD"))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            app.show_fingerprint_result(summary, self.folder)
        for text in [
            "WPS FINGERPRINT",
            "NEGATIVO SEGÚN EL DETECTOR",
            "ACK",
            "DEGRADED",
            "cleanup failed",
            "fingerprint.json",
            self.ap["bssid"],
        ]:
            self.assertIn(text, output.getvalue())

    def test_fingerprint_cli_alias(self):
        with (
            patch.object(app, "wireless_recon") as wireless,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(app.main(["--fingerprint"]), 0)
        wireless.assert_called_once_with()

    def test_missing_npcap_shows_not_tested_and_never_probes(self):
        iface = {
            "name": "fixture",
            "mode": "managed",
            "phy": None,
            "driver": "fixture",
            "capabilities": [],
            "connected": True,
            "backend": "windows",
        }
        output = io.StringIO()
        with (
            patch.object(app, "require_linux"),
            patch.object(app, "detect_wireless_interfaces", return_value=[iface]),
            patch.object(app, "report_folder", return_value=self.folder),
            patch.object(app, "discover_wifi", return_value=[self.ap]),
            patch.object(app, "wlan_helper_path", return_value=None),
            patch.object(app, "fingerprint_selected") as probe,
            patch("builtins.input", side_effect=["1", "1"]),
            contextlib.redirect_stdout(output),
        ):
            app.wireless_recon()
        probe.assert_not_called()
        report = json.loads((self.folder / "report.json").read_text(encoding="utf-8"))
        self.assertEqual(report["assessment"], "NOT_TESTED")
        self.assertIn("Falta Npcap", report["fingerprint"]["reason"])
        self.assertIn("NO EVALUADO", output.getvalue())
        self.assertTrue((self.folder / "fingerprint.json").is_file())


if __name__ == "__main__":
    unittest.main()
