"""Windows Native Wi-Fi and Npcap regression tests, with synthetic radio data."""

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
BSSID = "02:00:00:00:00:01"
RSN = bytes.fromhex("0100000fac040100000fac040200000fac02000fac080000")
WPS = bytes.fromhex("0050f20410210003") + b"Lab"


def element(identifier, body):
    return bytes([identifier, len(body)]) + body


def bss_fixture(items=None):
    if items is None:
        items = [(b"Lab", BSSID, element(48, RSN) + element(221, WPS))]
    entries = []
    evidence = bytearray()
    size = ctypes.sizeof(app.WinBssEntry)
    for index, (ssid, bssid, ies) in enumerate(items):
        item = app.WinBssEntry()
        item.ssid.length = len(ssid)
        item.ssid.data[: len(ssid)] = ssid
        item.bssid[:] = bytes.fromhex(bssid.replace(":", ""))
        item.rssi = -48
        item.quality = 85
        item.frequency_khz = 2437000
        item.capability = 0x11
        item.in_reg_domain = 1
        item.ie_offset = (len(items) - index) * size + len(evidence)
        item.ie_size = len(ies)
        entries.append(bytes(item))
        evidence.extend(ies)
    total = 8 + len(items) * size + len(evidence)
    return (
        total.to_bytes(4, "little")
        + len(items).to_bytes(4, "little")
        + b"".join(entries)
        + evidence
    )


def interface_fixture(state=4):
    item = app.WinInterface()
    item.guid = app.WinGUID.from_text(GUID)
    item.state = state
    text = "Adaptador Wi-Fi de prueba".encode("utf-16-le")
    ctypes.memmove(ctypes.addressof(item) + app.WinInterface.description.offset, text, len(text))
    return (1).to_bytes(4, "little") + bytes(4) + bytes(item)


class WindowsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp.name)
        self.output = io.StringIO()
        self.capture = contextlib.redirect_stdout(self.output)
        self.capture.__enter__()

    def tearDown(self):
        self.capture.__exit__(None, None, None)
        self.temp.cleanup()

    def test_structure_sizes_match_windows_abi(self):
        self.assertEqual(ctypes.sizeof(app.WinBssEntry), 360)
        self.assertEqual(app.WinBssEntry.ie_offset.offset, 352)
        self.assertEqual(ctypes.sizeof(app.WinInterface), 532)
        self.assertEqual(ctypes.sizeof(app.WinGUID), 16)

    def test_native_bss_extracts_wps_manufacturer_security_and_dbm(self):
        ap = app.parse_windows_bss(bss_fixture())[0]
        self.assertEqual(ap["ssid"], "Lab")
        self.assertEqual(ap["bssid"], BSSID)
        self.assertEqual(ap["channel"], 6)
        self.assertEqual(ap["frequency_mhz"], 2437)
        self.assertEqual(ap["signal_dbm"], -48)
        self.assertEqual(ap["signal_percent"], 85)
        self.assertEqual(ap["wps"], "Detected")
        self.assertEqual(ap["manufacturer_evidence"][0]["value"], "Lab")
        self.assertEqual(ap["security"], "WPA2-PSK/WPA3-SAE")
        self.assertEqual(ap["assessment"], "NOT_TESTED")

    def test_native_bss_multiple_bssids_and_unicode_ssids(self):
        data = bss_fixture(
            [
                ("Café".encode(), BSSID, element(48, RSN)),
                ("Café".encode(), "02:00:00:00:00:02", b""),
            ]
        )
        aps = app.parse_windows_bss(data)
        self.assertEqual([ap["ssid"] for ap in aps], ["Café", "Café"])
        self.assertEqual([ap["id"] for ap in aps], [1, 2])
        self.assertTrue(all(ap["wps"] == "Unknown" for ap in aps))

    def test_native_bss_rejects_invalid_offsets_and_lengths(self):
        for field, value in [("ie_offset", 1), ("ie_size", 0xFFFFFFFF)]:
            raw = bytearray(bss_fixture())
            offset = 8 + getattr(app.WinBssEntry, field).offset
            raw[offset : offset + 4] = value.to_bytes(4, "little")
            with self.assertRaises(ValueError):
                app.parse_windows_bss(bytes(raw))
        for raw in (b"", bss_fixture()[:-1], bytes(4) + b"\xff" * 4):
            with self.assertRaises(ValueError):
                app.parse_windows_bss(raw)

    def test_malformed_ies_do_not_become_open_or_wps(self):
        ap = app.new_ap(BSSID)
        app.information_element_security(ap, b"\xdd\xff\x00", 0)
        self.assertEqual(ap["security"], "Unknown")
        self.assertEqual(ap["wps"], "Unknown")
        self.assertTrue(ap["discovery_warnings"])

    def test_open_wpa_and_truncated_rsn(self):
        for ies, expected in [
            (b"", "OPEN"),
            (element(221, bytes.fromhex("0050f201")), "WPA"),
            (element(48, b"\0"), "RSN (AKM unknown)"),
        ]:
            ap = app.new_ap(BSSID)
            app.information_element_security(ap, ies, 0)
            self.assertEqual(ap["security"], expected)

    def test_native_interface_uses_guid_not_localized_description(self):
        iface = app.parse_windows_interfaces(interface_fixture())[0]
        self.assertEqual(iface["guid"], GUID)
        self.assertEqual(iface["name"], GUID)
        self.assertEqual(iface["display_name"], "Adaptador Wi-Fi de prueba")
        self.assertEqual(iface["capture_name"], "\\Device\\NPF_{" + GUID.upper() + "}")
        self.assertFalse(iface["connected"])
        self.assertTrue(app.parse_windows_interfaces(interface_fixture(1))[0]["connected"])
        self.assertTrue(app.parse_windows_interfaces(interface_fixture(3))[0]["connected"])

    def test_native_discovery_preserves_original_buffer(self):
        raw = bss_fixture()
        wlan = Mock()
        wlan.scan.return_value = "Cache warning"
        wlan.bss.return_value = raw
        with patch.object(app, "WindowsWlan", return_value=contextlib.nullcontext(wlan)):
            limits = []
            aps = app.discover_windows_wifi({"guid": GUID, "mode": "managed"}, self.folder, limits)
        self.assertEqual((self.folder / "windows_bss.bin").read_bytes(), raw)
        self.assertEqual(
            json.loads((self.folder / "windows_discovery.json").read_text())[0]["bssid"], BSSID
        )
        self.assertEqual(limits[0], "Cache warning")
        self.assertEqual(len(aps), 1)

    def test_windows_dispatch_does_not_require_linux_utilities(self):
        with (
            patch.object(app.sys, "platform", "win32"),
            patch.object(app, "detect_windows_interfaces", return_value=[]) as native,
            patch.object(app, "require_tools") as require,
        ):
            self.assertEqual(app.detect_wireless_interfaces(), [])
        native.assert_called_once()
        require.assert_not_called()
        with patch.object(app, "discover_windows_wifi", return_value=[]) as discover:
            self.assertEqual(app.discover_wifi({"backend": "windows"}, [], self.folder, []), [])
        discover.assert_called_once()

    def test_windows_error_guidance(self):
        self.assertIn("Ubicación", str(app.windows_wlan_error(5, "WlanScan")))
        self.assertIn("WlanSvc", str(app.windows_wlan_error(1062, "WlanOpenHandle")))

    def test_helper_missing_has_actionable_error(self):
        with patch.object(app, "wlan_helper_path", return_value=None):
            with self.assertRaisesRegex(RuntimeError, "Npcap.*raw 802.11"):
                app.wlan_helper(GUID, "mode")

    def test_helper_mode_changes_not_allowed(self):
        with (
            patch.object(app, "wlan_helper_path", return_value="helper.exe"),
            patch.object(app, "run_quiet") as run,
        ):
            with self.assertRaises(ValueError):
                app.wlan_helper(GUID, "mode", "monitor")
            with self.assertRaises(ValueError):
                app.wlan_helper("bad;command", "mode")
        run.assert_not_called()

    def test_discovery_without_npcap_still_available(self):
        wlan = Mock()
        wlan.interfaces.return_value = app.parse_windows_interfaces(interface_fixture())
        with (
            patch.object(app, "WindowsWlan", return_value=contextlib.nullcontext(wlan)),
            patch.object(app, "wlan_helper_path", return_value=None),
        ):
            interfaces = app.detect_windows_interfaces()
        self.assertEqual(interfaces[0]["mode"], "managed")
        self.assertIn("nativo", interfaces[0]["monitor_note"])

    def test_npcap_monitor_is_detected_read_only(self):
        wlan = Mock()
        wlan.interfaces.return_value = app.parse_windows_interfaces(interface_fixture())
        with (
            patch.object(app, "WindowsWlan", return_value=contextlib.nullcontext(wlan)),
            patch.object(app, "wlan_helper_path", return_value="helper.exe"),
            patch.object(
                app, "wlan_helper", side_effect=["monitor", "managed, monitor", "6"]
            ) as helper,
        ):
            iface = app.detect_windows_interfaces()[0]
        self.assertEqual(iface["mode"], "monitor")
        self.assertEqual(iface["channel"], 6)
        self.assertTrue(all(len(call.args) == 2 for call in helper.call_args_list))

    def test_wpscan_cli_alias(self):
        with patch.object(app, "wireless_recon") as wireless:
            self.assertEqual(app.main(["--wpscan"]), 0)
        wireless.assert_called_once_with()

    def test_npcap_transport_restores_upstream_on_cancellation(self):
        upstream = Mock()
        original = (upstream.sendp, upstream.AsyncSniffer, upstream.set_channel)
        socket = Mock()
        iface = {"name": GUID, "guid": GUID}
        with patch.object(app, "open_windows_monitor_socket", return_value=socket):
            with self.assertRaises(KeyboardInterrupt):
                with app.windows_upstream_transport(upstream, iface, {"channel": 6}):
                    upstream.sendp("packet", iface=GUID, verbose=False)
                    upstream.AsyncSniffer(iface=GUID, store=False)
                    raise KeyboardInterrupt()
        self.assertEqual((upstream.sendp, upstream.AsyncSniffer, upstream.set_channel), original)
        self.assertEqual(
            original[0].call_args.kwargs["iface"], "\\Device\\NPF_{" + GUID.upper() + "}"
        )
        self.assertIs(original[0].call_args.kwargs["socket"], socket)
        self.assertTrue(original[1].call_args.kwargs["monitor"])
        socket.close.assert_called_once()

    def test_npcap_transport_rejects_interface_or_channel_changes(self):
        upstream = Mock()
        socket = Mock()
        iface = {"name": GUID, "guid": GUID}
        with (
            patch.object(app, "open_windows_monitor_socket", return_value=socket),
            patch.object(app, "wlan_helper", side_effect=["monitor", "6"]) as helper,
        ):
            with app.windows_upstream_transport(upstream, iface, {"channel": 6}):
                upstream.set_channel(GUID, 6)
                with self.assertRaises(RuntimeError):
                    upstream.set_channel(GUID, 11)
                with self.assertRaises(RuntimeError):
                    upstream.sendp("packet", iface="other")
                with self.assertRaises(RuntimeError):
                    upstream.AsyncSniffer(iface="other")
        self.assertTrue(all(len(call.args) == 2 for call in helper.call_args_list))

    def test_denied_windows_fingerprint_does_nothing(self):
        with (
            patch.object(app, "require_windows_monitor") as check,
            patch.object(app, "load_upstream") as load,
        ):
            result = app.fingerprint_selected(
                {}, {"backend": "windows"}, [], self.folder, authorized=False
            )
        check.assert_not_called()
        load.assert_not_called()
        self.assertEqual(result["classification"], "NOT_TESTED")

    def test_windows_monitor_requirements_checked_before_sockets(self):
        windll = Mock()
        windll.shell32.IsUserAnAdmin.return_value = 1
        ap = app.parse_windows_bss(bss_fixture())[0]
        iface = {"name": GUID, "guid": GUID, "connected": False}
        with (
            patch.object(app.sys, "platform", "win32"),
            patch.object(ctypes, "windll", windll, create=True),
            patch.object(app, "wlan_helper", side_effect=["monitor", "6"]),
        ):
            app.require_windows_monitor(ap, iface)
        for changed_ap, changed_iface in [
            (dict(ap, frequency_mhz=5180), iface),
            (ap, dict(iface, connected=True)),
            (dict(ap, in_reg_domain=False), iface),
        ]:
            with (
                patch.object(app.sys, "platform", "win32"),
                patch.object(ctypes, "windll", windll, create=True),
            ):
                with self.assertRaises(RuntimeError):
                    app.require_windows_monitor(changed_ap, changed_iface)

    def test_non_administrator_and_wrong_mode_are_rejected(self):
        windll = Mock()
        windll.shell32.IsUserAnAdmin.return_value = 0
        ap = app.parse_windows_bss(bss_fixture())[0]
        iface = {"guid": GUID, "connected": False}
        with (
            patch.object(app.sys, "platform", "win32"),
            patch.object(ctypes, "windll", windll, create=True),
        ):
            with self.assertRaisesRegex(RuntimeError, "administrador"):
                app.require_windows_monitor(ap, iface)
            windll.shell32.IsUserAnAdmin.return_value = 1
            with patch.object(app, "wlan_helper", side_effect=["managed", "6"]):
                with self.assertRaisesRegex(RuntimeError, "manualmente"):
                    app.require_windows_monitor(ap, iface)

    def test_windows_fingerprint_uses_unmodified_decisions_and_evidence(self):
        upstream = app.load_upstream()
        ap = app.parse_windows_bss(bss_fixture())[0]
        iface = {"backend": "windows", "name": GUID, "guid": GUID}
        target = upstream.Observation("Lab", BSSID, 6, -48, wps_advertised=True)
        backend = Mock()
        backend.probe_first_fragment.return_value = upstream.TransactionOutcome(
            upstream.ResponseKind.REJECTED, False, None
        )
        with (
            patch.object(app, "require_windows_monitor"),
            patch.object(app, "windows_upstream_transport", return_value=contextlib.nullcontext()),
            patch.object(app, "observe_selected", return_value=target),
            patch.object(
                app,
                "restricted_backend",
                return_value=Mock(return_value=contextlib.nullcontext(backend)),
            ),
        ):
            result = app.fingerprint_selected(ap, iface, [], self.folder, authorized=True)
        self.assertEqual(result["classification"], "LIKELY_VULNERABLE")
        self.assertFalse(result["original"]["transactions"][0]["cleanup_sent"])
        self.assertTrue((self.folder / "upstream_result.json").exists())
        self.assertTrue((self.folder / "fingerprint.pcap").exists())
        backend.probe_first_fragment.assert_called_once_with(target, 0, b"", recover=False)

    def test_windows_fingerprint_cancellation_preserves_artifact(self):
        with (
            patch.object(app, "require_windows_monitor"),
            patch.object(app, "windows_upstream_transport", return_value=contextlib.nullcontext()),
            patch.object(app, "observe_selected", side_effect=KeyboardInterrupt),
        ):
            result = app.fingerprint_windows(
                app.parse_windows_bss(bss_fixture())[0], {}, self.folder, authorized=True
            )
        self.assertEqual(result["classification"], "INCONCLUSIVE")
        self.assertTrue((self.folder / "fingerprint.pcap").exists())

    def test_interrupted_backend_startup_closes_capture(self):
        upstream = app.load_upstream()
        target = upstream.Observation("Lab", BSSID, 6, -48)
        backend = app.restricted_backend(upstream)(GUID, target, Mock())
        with (
            patch.object(upstream, "set_channel"),
            patch.object(backend, "_start_capture", side_effect=KeyboardInterrupt),
            patch.object(backend, "_stop_capture") as stop,
        ):
            with self.assertRaises(KeyboardInterrupt):
                with backend:
                    self.fail("capture startup must fail")
        stop.assert_called_once()

    def test_ethernet_capture_rejected(self):
        socket = Mock()
        socket.pcap_fd.datalink.return_value = 1
        conf = Mock(use_pcap=True, L2socket=Mock(return_value=socket))
        with patch("scapy.config.conf", conf):
            with self.assertRaisesRegex(RuntimeError, "Radiotap"):
                app.open_windows_monitor_socket("fixture")
        socket.close.assert_called_once()


class NativeApiTests(unittest.TestCase):
    @contextlib.contextmanager
    def client(self, raw=None, notification=7):
        dll = Mock()
        callback = []
        raw = bss_fixture() if raw is None else raw
        buffer = ctypes.create_string_buffer(raw)

        def register(handle, source, ignore, function, context, reserved, previous):
            if source:
                callback.append(function)
            return 0

        def scan(*args):
            if notification is not None:
                message = app.WinNotification(
                    source=8, code=notification, guid=app.WinGUID.from_text(GUID)
                )
                callback[-1](ctypes.pointer(message), None)
            return 0

        def bss(*args):
            args[-1]._obj.value = ctypes.addressof(buffer)
            return 0

        dll.WlanOpenHandle.return_value = 0
        dll.WlanRegisterNotification.side_effect = register
        dll.WlanScan.side_effect = scan
        dll.WlanGetNetworkBssList.side_effect = bss
        with (
            patch.object(app.sys, "platform", "win32"),
            patch.object(ctypes, "WinDLL", return_value=dll, create=True),
            patch.object(ctypes, "WINFUNCTYPE", ctypes.CFUNCTYPE, create=True),
        ):
            with app.WindowsWlan() as wlan:
                yield wlan, dll
        dll.WlanCloseHandle.assert_called_once()

    def test_notification_completion_and_unregistration(self):
        with self.client() as (wlan, dll):
            self.assertIsNone(wlan.scan(GUID))
            self.assertEqual(dll.WlanRegisterNotification.call_args.args[1], 0)
            self.assertEqual(wlan.bss(GUID), bss_fixture())
            dll.WlanFreeMemory.assert_called_once()

    def test_notification_failure_and_timeout_identify_cache(self):
        for notification in (8, None):
            with self.client(notification=notification) as (wlan, dll):
                self.assertIn("caché", wlan.scan(GUID, timeout=0))
                self.assertEqual(dll.WlanRegisterNotification.call_args.args[1], 0)

    def test_access_denied_unregisters_and_no_bss_read(self):
        with self.client() as (wlan, dll):
            dll.WlanScan.side_effect = None
            dll.WlanScan.return_value = 5
            with self.assertRaisesRegex(RuntimeError, "Ubicación"):
                wlan.scan(GUID)
            self.assertEqual(dll.WlanRegisterNotification.call_args.args[1], 0)
            dll.WlanGetNetworkBssList.assert_not_called()

    def test_invalid_native_buffer_is_freed(self):
        with self.client(raw=bytes(8)) as (wlan, dll):
            with self.assertRaises(ValueError):
                wlan.bss(GUID)
            dll.WlanFreeMemory.assert_called_once()


if __name__ == "__main__":
    unittest.main()
