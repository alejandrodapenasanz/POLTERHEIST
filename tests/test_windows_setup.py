"""Automatic radio setup, rollback and UAC use synthetic adapters only."""

import contextlib
import ctypes
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import script as app

GUID = "12345678-1234-5678-9abc-123456789abc"


class WindowsSetupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp.name)
        self.ap = dict(app.new_ap("02:00:00:00:00:01", "Lab"), id=1, channel=6, frequency_mhz=2437)
        self.iface = dict(
            name=GUID,
            guid=GUID,
            display_name="Lab adapter",
            backend="windows",
            mode="managed",
            capabilities=["managed", "monitor"],
            connected=True,
            connected_ssid="Lab",
        )

    def tearDown(self):
        self.temp.cleanup()

    @contextlib.contextmanager
    def radio(self, mode="managed", profile="Lab", fail=None, modes="managed, monitor"):
        hardware = {"mode": mode, "modes": modes, "channel": "36", "freq": "5180"}
        wlan = Mock()
        wlan.connected_profile.return_value = profile

        def helper(guid, setting, value=None):
            self.assertEqual(guid, GUID)
            if value is not None:
                hardware[setting] = str(value)
                if (setting, value) == fail:
                    raise RuntimeError("simulated driver failure")
            return hardware[setting]

        with (
            patch.object(app.sys, "platform", "win32"),
            patch.object(app, "windows_is_admin", return_value=True),
            patch.object(app, "wlan_helper", side_effect=helper) as calls,
            patch.object(app, "WindowsWlan", return_value=contextlib.nullcontext(wlan)),
        ):
            yield hardware, wlan, calls

    def test_prepares_then_restores_mode_and_previous_connection(self):
        state = {}
        with self.radio() as (hardware, wlan, calls):
            with app.prepared_windows_monitor(self.ap, self.iface, self.folder, state):
                self.assertEqual(hardware["mode"], "monitor")
                self.assertEqual(hardware["channel"], "6")
                saved = json.loads((self.folder / "radio_setup.json").read_text(encoding="utf-8"))
                self.assertEqual(saved["original_profile"], "Lab")
                self.assertTrue(saved["prepared"])
            self.assertEqual(hardware["mode"], "managed")
            wlan.connect_profile.assert_called_once_with(GUID, "Lab")
        self.assertTrue(state["restored"])
        self.assertEqual(
            [c.args[1:] for c in calls.call_args_list if len(c.args) == 3],
            [("mode", "monitor"), ("channel", 6), ("mode", "managed")],
        )

    def test_partial_setup_failure_and_capture_cancellation_restore_connection(self):
        for failure in [("mode", "monitor"), ("channel", 6), None]:
            with self.subTest(failure=failure), self.radio(fail=failure) as (hardware, wlan, _):
                state = {}
                with self.assertRaises((RuntimeError, KeyboardInterrupt)):
                    with app.prepared_windows_monitor(self.ap, self.iface, self.folder, state):
                        raise KeyboardInterrupt()
                self.assertEqual(hardware["mode"], "managed")
                self.assertTrue(state["restored"])
                wlan.connect_profile.assert_called_once_with(GUID, "Lab")

    def test_existing_monitor_frequency_restored_without_joining_network(self):
        state = {}
        with self.radio(mode="monitor") as (hardware, wlan, _):
            with app.prepared_windows_monitor(self.ap, self.iface, self.folder, state):
                hardware["freq"] = "2437"
            self.assertEqual(hardware["mode"], "monitor")
            self.assertEqual(hardware["freq"], "5180")
            wlan.connected_profile.assert_not_called()
            wlan.connect_profile.assert_not_called()
        self.assertTrue(state["restored"])

    def test_restoration_failure_is_saved_not_reported_as_success(self):
        state = {}
        with self.radio(fail=("mode", "managed")):
            with app.prepared_windows_monitor(self.ap, self.iface, self.folder, state):
                pass
        self.assertFalse(state["restored"])
        self.assertIn("driver failure", state["restore_error"])
        self.assertEqual(json.loads((self.folder / "radio_setup.json").read_text()), state)

    def test_unsupported_driver_never_changes_radio(self):
        with self.radio(modes="managed") as (_, wlan, calls):
            with self.assertRaisesRegex(RuntimeError, "monitor no disponible"):
                with app.prepared_windows_monitor(self.ap, self.iface, self.folder, {}):
                    self.fail("unsupported radio must not be used")
        self.assertTrue(all(len(c.args) == 2 for c in calls.call_args_list))
        wlan.connected_profile.assert_not_called()
        wlan.connect_profile.assert_not_called()

    def test_disconnected_adapter_does_not_join_any_network_afterwards(self):
        with self.radio(profile=None) as (_, wlan, _):
            with app.prepared_windows_monitor(self.ap, self.iface, self.folder, {}):
                pass
        wlan.connect_profile.assert_not_called()

    def test_unsupported_workflow_has_one_table_no_bssid_list_or_manual_prompt(self):
        iface = dict(self.iface, capabilities=["managed"])
        output = io.StringIO()
        with (
            patch.object(app.sys, "platform", "win32"),
            patch.object(app, "detect_wireless_interfaces", return_value=[iface]),
            patch.object(app, "discover_wifi", return_value=[self.ap]),
            patch.object(app, "report_folder", return_value=self.folder),
            patch.object(app, "wlan_helper_path", return_value="helper.exe"),
            patch.object(app, "windows_elevated_wireless") as elevate,
            patch.object(app, "fingerprint_selected") as probe,
            patch("builtins.input", side_effect=["1"]) as prompt,
            contextlib.redirect_stdout(output),
        ):
            app.wireless_recon()
        elevate.assert_not_called()
        probe.assert_not_called()
        prompt.assert_not_called()
        self.assertEqual(output.getvalue().count("WIRELESS RESULTS"), 1)
        self.assertNotIn("[1] " + self.ap["bssid"], output.getvalue())
        self.assertNotIn("Prepara manualmente", output.getvalue())
        self.assertIn("modos disponibles = managed", output.getvalue())

    def test_candidate_prefers_disconnected_capable_adapter(self):
        spare = dict(self.iface, name="spare", connected=False)
        incapable = dict(spare, name="incapable", capabilities=["managed"])
        selected = app.windows_monitor_candidate([self.iface, incapable, spare], self.iface)
        self.assertIs(selected, spare)

    def test_windows_workflow_selects_radio_automatically_but_respects_authorization(self):
        for authorized in (False, True):
            ap = dict(self.ap)
            iface = dict(self.iface, connected_ssid="Lab" if authorized else None)
            original = {
                "target": {"ssid": ap["ssid"], "bssid": ap["bssid"]},
                "assessment": "PATCHED_HOSTAPD",
            }
            outcome = {
                "classification": "PATCHED_HOSTAPD",
                "original": original,
                "error": None,
                "limitations": [],
                "radio_setup": {"restored": True},
            }
            with (
                self.subTest(authorized=authorized),
                patch.object(app.sys, "platform", "win32"),
                patch.object(app, "detect_wireless_interfaces", return_value=[iface]),
                patch.object(app, "discover_wifi", return_value=[ap]),
                patch.object(app, "report_folder", return_value=self.folder),
                patch.object(app, "wlan_helper_path", return_value="helper.exe"),
                patch.object(app, "windows_is_admin", return_value=True),
                patch.object(app, "fingerprint_selected", return_value=outcome) as probe,
                patch(
                    "builtins.input",
                    side_effect=["1", "AUTORIZO " + ap["bssid"] if authorized else ""],
                ),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                app.wireless_recon()
            if authorized:
                probe.assert_called_once_with(
                    ap,
                    iface,
                    [iface],
                    self.folder / "targets" / ap["bssid"].replace(":", ""),
                    authorized=True,
                )
            else:
                probe.assert_not_called()
            report = json.loads((self.folder / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(
                report["assessment"], "PATCHED_HOSTAPD" if authorized else "NOT_TESTED"
            )

    def test_capable_adapter_requests_elevation_before_discovery(self):
        with (
            patch.object(app.sys, "platform", "win32"),
            patch.object(app, "detect_wireless_interfaces", return_value=[self.iface]),
            patch.object(app, "windows_is_admin", return_value=False),
            patch.object(app, "windows_elevated_wireless", return_value=0) as elevate,
            patch.object(app, "discover_wifi") as discover,
        ):
            self.assertEqual(app.wireless_recon(), 0)
        elevate.assert_called_once_with(None, None)
        discover.assert_not_called()

    def test_refresh_replaces_visible_table_only_on_supported_terminal(self):
        for enabled in (False, True):
            output = io.StringIO()
            with (
                patch.object(app, "terminal_control_available", return_value=enabled),
                contextlib.redirect_stdout(output),
            ):
                app.show_wifi([self.ap], refresh=True)
            self.assertEqual("\033[2J\033[H" in output.getvalue(), enabled)


class WindowsElevationTests(unittest.TestCase):
    def test_uac_uses_exact_python_script_and_preserves_exit_code(self):
        shell, kernel = Mock(), Mock()

        def launch(pointer):
            request = pointer._obj
            self.assertEqual(request.verb, "runas")
            self.assertEqual(request.file, app.sys.executable)
            self.assertIn("script.py", request.parameters)
            self.assertIn("--windows-elevated", request.parameters)
            request.process = 123
            return 1

        def exit_code(handle, pointer):
            pointer._obj.value = 7
            return 1

        shell.ShellExecuteExW.side_effect = launch
        kernel.WaitForSingleObject.side_effect = [258, 0]
        kernel.GetExitCodeProcess.side_effect = exit_code
        with (
            patch.object(ctypes, "WinDLL", side_effect=[shell, kernel], create=True),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(app.windows_elevated_wireless(), 7)
        kernel.CloseHandle.assert_called_once_with(123)

    def test_uac_denial_does_not_wait_or_run_another_command(self):
        shell, kernel = Mock(), Mock()
        shell.ShellExecuteExW.return_value = 0
        with (
            patch.object(ctypes, "WinDLL", side_effect=[shell, kernel], create=True),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            with self.assertRaisesRegex(RuntimeError, "elevación UAC"):
                app.windows_elevated_wireless()
        kernel.WaitForSingleObject.assert_not_called()
        kernel.CloseHandle.assert_not_called()


if __name__ == "__main__":
    unittest.main()
