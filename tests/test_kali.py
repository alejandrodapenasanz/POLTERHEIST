"""Kali setup and automatic connected-network flow; no real radio traffic."""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import script as app

CONNECTION = "12345678-1234-5678-9abc-123456789abc"


class KaliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp.name)
        self.iface = {
            "name": "wlan0",
            "phy": "phy0",
            "mode": "managed",
            "backend": "linux",
            "frequency_mhz": 2437,
            "channel": 6,
            "capabilities": ["managed", "monitor"],
            "connected": True,
            "connected_ssid": "Lab",
            "frequencies": [
                {
                    "frequency_mhz": 2437,
                    "channel": 6,
                    "disabled": False,
                    "no_ir": False,
                    "radar": False,
                }
            ],
        }
        self.ap = dict(app.new_ap("02:00:00:00:00:01", "Lab"), id=1, channel=6, frequency_mhz=2437)

    def tearDown(self):
        self.temp.cleanup()

    @contextlib.contextmanager
    def radio(self, fail=None, mode="managed", connected=True):
        hardware = dict(
            mode=mode,
            up=True,
            managed=mode == "managed",
            connection=CONNECTION if connected else None,
            frequency=2437,
        )
        iface = dict(self.iface, mode=mode, connected=connected)

        def interfaces():
            return [
                dict(
                    iface,
                    mode=hardware["mode"],
                    frequency_mhz=hardware["frequency"],
                    connected=bool(hardware["connection"]),
                )
            ]

        def command(args, **kwargs):
            if args[:3] == ["ip", "-json", "link"]:
                return json.dumps([{"ifname": "wlan0", "flags": ["UP"] if hardware["up"] else []}])
            if args[:2] == ["ip", "link"]:
                hardware["up"] = args[-1] == "up"
            elif args[:3] == ["iw", "dev", "wlan0"]:
                if args[4] == "monitor":
                    self.assertEqual(args[5:], ["otherbss", "control"])
                    hardware["mode"] = "monitor"
                else:
                    hardware["mode"] = args[-1]
            elif args[:3] == ["nmcli", "device", "set"]:
                hardware["managed"] = args[-1] == "yes"
                if not hardware["managed"]:
                    hardware["connection"] = None
            elif args[:3] == ["nmcli", "--wait", "20"]:
                hardware["connection"] = args[6]
            else:
                self.fail("Unexpected command: " + repr(args))
            if fail is not None and args == fail:
                raise RuntimeError("driver failed after a partial change")
            return ""

        with (
            patch.object(app, "require_linux"),
            patch.object(app, "require_tools"),
            patch.object(app, "linux_command", side_effect=command) as commands,
            patch.object(
                app,
                "linux_nm_state",
                side_effect=lambda name: (hardware["managed"], hardware["connection"]),
            ),
            patch.object(app, "detect_wireless_interfaces", side_effect=interfaces),
            patch.object(
                app,
                "set_frequency",
                side_effect=lambda name, value: hardware.update(frequency=value),
            ),
        ):
            yield iface, hardware, commands

    def test_monitor_flags_and_original_connection_are_restored(self):
        state = {}
        with self.radio() as (iface, hardware, commands):
            with app.prepared_linux_monitor(self.ap, iface, [iface], self.folder, state) as (
                ready,
                live,
            ):
                self.assertEqual(ready["mode"], "monitor")
                self.assertFalse(hardware["managed"])
                self.assertTrue(hardware["up"])
                self.assertEqual(len(live), 1)
            self.assertEqual(
                hardware,
                dict(mode="managed", up=True, managed=True, connection=CONNECTION, frequency=2437),
            )
        self.assertTrue(state["restored"])
        self.assertEqual(json.loads((self.folder / "radio_setup.json").read_text()), state)
        self.assertTrue(
            any(
                c.args[0] == ["iw", "dev", "wlan0", "set", "monitor", "otherbss", "control"]
                for c in commands.call_args_list
            )
        )

    def test_partial_failures_and_cancellation_always_restore(self):
        for failure in [
            ["nmcli", "device", "set", "wlan0", "managed", "no"],
            ["ip", "link", "set", "dev", "wlan0", "down"],
            ["iw", "dev", "wlan0", "set", "monitor", "otherbss", "control"],
            None,
        ]:
            with self.subTest(failure=failure), self.radio(fail=failure) as (iface, hardware, _):
                state = {}
                with self.assertRaises((RuntimeError, KeyboardInterrupt)):
                    with app.prepared_linux_monitor(self.ap, iface, [iface], self.folder, state):
                        raise KeyboardInterrupt()
                self.assertEqual(hardware["mode"], "managed")
                self.assertTrue(hardware["managed"])
                self.assertEqual(hardware["connection"], CONNECTION)
                # A repeated failure during restoration must remain visible.
                self.assertEqual(
                    state["restored"], failure != ["ip", "link", "set", "dev", "wlan0", "down"]
                )

    def test_restoration_failure_is_not_hidden(self):
        state = {}
        with self.radio(fail=["nmcli", "device", "set", "wlan0", "managed", "yes"]) as (
            iface,
            _,
            _,
        ):
            with app.prepared_linux_monitor(self.ap, iface, [iface], self.folder, state):
                pass
        self.assertFalse(state["restored"])
        self.assertIn("driver failed", state["restore_error"])

    def test_shared_radio_and_disallowed_channels_never_change_state(self):
        for shared in (False, True):
            with self.radio() as (iface, _, commands):
                ap = self.ap if shared else dict(self.ap, frequency_mhz=5955)
                interfaces = [iface, dict(iface, name="wlan1")] if shared else [iface]
                with self.assertRaises(RuntimeError):
                    with app.prepared_linux_monitor(ap, iface, interfaces, self.folder, {}):
                        self.fail("unsafe preparation")
                commands.assert_not_called()

    def test_fingerprint_wrapper_restores_after_capture_error(self):
        with (
            self.radio() as (iface, hardware, _),
            patch.object(app, "load_upstream"),
            patch.object(
                app, "fingerprint_linux_monitor", side_effect=RuntimeError("capture failed")
            ),
        ):
            result = app.fingerprint_selected(self.ap, iface, [iface], self.folder, authorized=True)
            self.assertEqual(hardware["connection"], CONNECTION)
        self.assertTrue(result["radio_setup"]["restored"])
        self.assertIn("capture failed", result["error"])

    def test_existing_monitor_restores_frequency_without_reconnection(self):
        state = {}
        with self.radio(mode="monitor", connected=False) as (iface, hardware, commands):
            with app.prepared_linux_monitor(self.ap, iface, [iface], self.folder, state):
                hardware["frequency"] = 2412
        self.assertEqual(hardware["mode"], "monitor")
        self.assertEqual(hardware["frequency"], 2437)
        self.assertFalse(any(c.args[0][0] == "nmcli" for c in commands.call_args_list))

    def test_connected_ssid_with_escaped_bytes(self):
        self.assertEqual(app.decode_iw_ssid(r"Caf\xc3\xa9"), "Café")
        self.assertEqual(app.decode_iw_ssid(r"A\x20B"), "A B")

    def test_batch_fingerprints_connected_network_before_single_table(self):
        aps = [
            self.ap,
            dict(self.ap, id=2, bssid="02:00:00:00:00:02"),
            dict(self.ap, id=3, ssid="Other", bssid="02:00:00:00:00:03"),
        ]
        output = io.StringIO()

        def probe(ap, radio, interfaces, folder, authorized):
            self.assertTrue(authorized)
            self.assertNotIn("WIRELESS RESULTS", output.getvalue())
            assessment = "LIKELY_VULNERABLE" if ap["id"] == 1 else "PATCHED_HOSTAPD"
            original = {
                "target": {"ssid": ap["ssid"], "bssid": ap["bssid"]},
                "assessment": assessment,
            }
            app.dump_json(folder / "upstream_result.json", original)
            return {
                "classification": assessment,
                "original": original,
                "error": None,
                "limitations": [],
            }

        with (
            patch.object(
                app,
                "operating_system",
                return_value={"family": "linux", "name": "Kali", "id": "kali"},
            ),
            patch.object(app.os, "geteuid", return_value=0, create=True),
            patch.object(app, "require_linux"),
            patch.object(app, "detect_wireless_interfaces", return_value=[self.iface]),
            patch.object(app, "discover_wifi", return_value=aps),
            patch.object(app, "report_folder", return_value=self.folder),
            patch.object(app, "fingerprint_selected", side_effect=probe) as probes,
            patch(
                "builtins.input", side_effect=AssertionError("No network selection prompt expected")
            ),
            contextlib.redirect_stdout(output),
        ):
            app.wireless_recon()
        self.assertEqual(probes.call_count, 2)
        self.assertEqual(output.getvalue().count("WIRELESS RESULTS"), 1)
        self.assertEqual(
            [ap["assessment"] for ap in aps], ["LIKELY_VULNERABLE", "PATCHED_HOSTAPD", "NOT_TESTED"]
        )
        report = json.loads((self.folder / "report.json").read_text(encoding="utf-8"))
        self.assertIsNone(report["assessment"])
        self.assertEqual(report["authorization"]["source"], "connected_network")
        self.assertEqual(len(report["targets"]), 2)
        self.assertEqual(
            sum(a["path"].endswith("upstream_result.json") for a in report["artifacts"]), 2
        )

    def test_cancel_or_failed_restore_stops_remaining_targets(self):
        for restore_failed in (False, True):
            folder = self.folder / str(restore_failed)
            folder.mkdir()
            aps = [dict(self.ap), dict(self.ap, id=2, bssid="02:00:00:00:00:02")]
            outcome = {
                "classification": "INCONCLUSIVE",
                "original": None,
                "limitations": [],
                "error": None if restore_failed else "Interrupted by the operator",
                "radio_setup": {"restore_error": "driver failed"}
                if restore_failed
                else {"restored": True},
            }
            with (
                self.subTest(restore_failed=restore_failed),
                patch.object(
                    app, "operating_system", return_value={"family": "linux", "id": "kali"}
                ),
                patch.object(app.os, "geteuid", return_value=0, create=True),
                patch.object(app, "require_linux"),
                patch.object(app, "detect_wireless_interfaces", return_value=[self.iface]),
                patch.object(app, "discover_wifi", return_value=aps),
                patch.object(app, "report_folder", return_value=folder),
                patch.object(app, "fingerprint_selected", return_value=outcome) as probe,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                app.wireless_recon()
            probe.assert_called_once()
            self.assertEqual(aps[1]["assessment"], "NOT_TESTED")
            report = json.loads((folder / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(report["status"], "restore_failed" if restore_failed else "cancelled")


class SystemSetupTests(unittest.TestCase):
    def test_os_detection_does_not_treat_all_linux_as_kali(self):
        with (
            patch.object(app.sys, "platform", "linux"),
            patch.object(
                app.platform,
                "freedesktop_os_release",
                return_value={"ID": "kali", "PRETTY_NAME": "Kali GNU/Linux"},
            ),
        ):
            self.assertEqual(app.operating_system()["id"], "kali")
        with patch.object(app.sys, "platform", "win32"):
            self.assertEqual(app.operating_system()["family"], "windows")
        with patch.object(app.sys, "platform", "darwin"):
            self.assertEqual(app.operating_system()["family"], "unsupported")

    def test_setup_uses_apt_and_isolated_venv_with_exact_interpreter(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(app, "BASE", Path(directory)),
            patch.object(
                app,
                "operating_system",
                return_value={"family": "linux", "id": "kali", "name": "Kali"},
            ),
            patch.object(app.os, "geteuid", return_value=1000, create=True),
            patch.object(app.shutil, "which", return_value="/usr/bin/tool"),
            patch.object(app.subprocess, "run") as run,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(app.setup_environment(), 0)
            calls = [c.args[0] for c in run.call_args_list]
            self.assertEqual(calls[0], ["sudo", "--", "apt-get", "update"])
            self.assertIn("firmware-mediatek", calls[1])
            self.assertEqual(calls[2][:3], [app.sys.executable, "-m", "venv"])
            self.assertEqual(calls[3][0], str(Path(directory) / ".venv/bin/python"))
            self.assertNotIn("--break-system-packages", calls[3])

    def test_linux_elevation_preserves_explicit_scope_and_venv(self):
        with (
            patch.object(app, "require_tools"),
            patch.object(app.subprocess, "run", return_value=Mock(returncode=0)) as run,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(app.linux_elevated_wireless("Lab ' & $()", "02:00:00:00:00:01"), 0)
        arguments = run.call_args.args[0]
        self.assertEqual(arguments[:3], ["sudo", "--", app.sys.executable])
        self.assertEqual(arguments[-4:], ["--ssid", "Lab ' & $()", "--bssid", "02:00:00:00:00:01"])


if __name__ == "__main__":
    unittest.main()
