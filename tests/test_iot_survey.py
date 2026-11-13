"""SIMULATED radio/session fixtures; no physical scans, pairing or installations."""

import asyncio
import contextlib
import io
import ipaddress
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from tv_control import cli, survey
from tv_control.bluetooth import Bluetooth, advertisement
from tv_control.connections import Connections, select_iot_devices
from tv_control.discovery import Discovery
from tv_control.models import Config, Device, Endpoint
from tv_control.network import Network
from tv_control.wireless import WirelessScan

LAN = Network("SIMULATED", "192.0.2.10", ipaddress.IPv4Network("192.0.2.0/24"))
CONFIG = Config(ble_timeout=0.1, p2p_timeout=1, discovery_timeout=0.1, connect_timeout=0.1)


def ble():
    return Endpoint(
        "Bluetooth LE",
        "ble:default:02:00:00:00:00:01",
        "",
        0,
        "SIMULATED BLE",
        details={"transport": "ble", "adapter": "default", "ble_address": "02:00:00:00:00:01"},
    )


class Base(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.output = self.enterContext(contextlib.redirect_stdout(io.StringIO()))


class BluetoothTests(Base):
    def runtime(self):
        self.raw_device = SimpleNamespace(address="02:00:00:00:00:01", name="SIMULATED BLE")
        self.data = SimpleNamespace(
            local_name=None,
            service_uuids=["0000180f-0000-1000-8000-00805f9b34fb", "invalid"],
            manufacturer_data={1: b"SIMULATED"},
            rssi=-55,
        )
        owner = self

        class Scanner:
            def __init__(self, detection_callback, **kwargs):
                self.callback = detection_callback
                self.kwargs = kwargs
                self.stopped = False
                owner.scanner = self

            async def start(self):
                self.callback(owner.raw_device, owner.data)

            async def stop(self):
                self.stopped = True

        class Client:
            def __init__(self, device, **kwargs):
                self.device, self.kwargs = device, kwargs
                self.is_connected = False
                self.services = [SimpleNamespace(uuid="SIMULATED service")]
                owner.client = self

            async def connect(self):
                self.is_connected = True

            async def disconnect(self):
                self.is_connected = False

        runtime = Bluetooth(CONFIG, Scanner, Client, platform="win32")
        self.addCleanup(runtime.close)
        return runtime

    def test_scan_scopes_identity_and_stops_scanner(self):
        runtime = self.runtime()
        (endpoint,) = runtime.scan("default")
        self.assertTrue(self.scanner.stopped)
        self.assertEqual(endpoint.uid, ble().uid)
        self.assertEqual(len(endpoint.details["service_uuids"]), 1)
        self.assertFalse(endpoint.controllable)
        self.assertEqual(endpoint.ip, "")

    def test_connect_uses_discovered_device_without_pairing_or_writes(self):
        runtime = self.runtime()
        (endpoint,) = runtime.scan("default")
        self.assertIn("CONNECTED", runtime.connect(endpoint))
        self.assertIs(self.client.device, self.raw_device)
        self.assertFalse(self.client.kwargs["pair"])
        self.assertTrue(runtime.connected(endpoint.uid))
        self.assertEqual(endpoint.details["gatt_services"], ["SIMULATED service"])
        runtime.disconnect_all()
        self.assertFalse(self.client.is_connected)

    def test_active_gatt_connection_prevents_competing_scan(self):
        runtime = self.runtime()
        (endpoint,) = runtime.scan("default")
        runtime.connect(endpoint)
        with self.assertRaisesRegex(RuntimeError, "active"):
            runtime.scan("default")

    def test_expired_device_is_not_re_scanned_implicitly(self):
        runtime = self.runtime()
        with self.assertRaisesRegex(ValueError, "expired"):
            runtime.connect(ble())

    def test_event_loop_closes_and_timeout_cancels_pending_task(self):
        runtime = self.runtime()
        with self.assertRaises(TimeoutError):
            runtime.call(lambda: asyncio.sleep(10), 0.02)
        thread = runtime.thread
        runtime.close()
        self.assertFalse(thread.is_alive())

    def test_advertising_name_never_becomes_a_verified_device_type(self):
        runtime = self.runtime()
        self.data.local_name = "SIMULATED Smart Lock"
        endpoint = advertisement(self.raw_device, self.data, "hci0")
        self.assertIn("type unknown", endpoint.kind)
        self.assertIn("ble:hci0:", endpoint.uid)
        runtime.close()


class SurveyTests(Base):
    def app(self):
        discovery = Discovery(None, CONFIG, [])
        bluetooth = Mock()
        bluetooth.connected.return_value = False
        bluetooth.adapters.return_value = ["default"]
        bluetooth.scan.return_value = [ble()]
        return SimpleNamespace(
            root=self.root,
            network=None,
            network_error="SIMULATED no LAN",
            discovery=discovery,
            bluetooth=bluetooth,
            scan=Mock(),
        )

    def test_no_lan_still_runs_p2p_and_ble(self):
        app = self.app()
        engine = Mock()
        adapter = SimpleNamespace(interface="wlan0", phy="phy0", eligible=True, reasons=[])
        engine.adapters.return_value = [
            adapter,
            SimpleNamespace(interface="wlan1", phy="phy0", eligible=True, reasons=[]),
        ]
        endpoint = Endpoint(
            "Wi-Fi Direct",
            "SIMULATED P2P",
            "",
            0,
            details={"transport": "p2p", "interface": "wlan0", "fresh": True},
        )
        result = WirelessScan(
            {"interface": "wlan0", "backend": "networkmanager"},
            started=True,
            endpoints=[endpoint],
            state="COMPLETED",
            fresh_count=1,
        )
        engine.scan.return_value = result
        with patch.object(survey, "WirelessDiscovery", return_value=engine):
            survey.survey(app)
        engine.scan.assert_called_once()
        self.assertTrue(engine.scan.call_args.kwargs["confirmed"])
        app.bluetooth.scan.assert_called_once_with("default")
        self.assertEqual(sum(d.available for d in app.discovery.devices.values()), 2)

    def test_unavailable_wifi_backend_does_not_hide_ble_results(self):
        app = self.app()
        engine = Mock()
        engine.adapters.side_effect = RuntimeError("SIMULATED unsupported platform")
        with patch.object(survey, "WirelessDiscovery", return_value=engine):
            survey.survey(app)
        self.assertEqual(len(app.discovery.devices), 1)
        self.assertTrue(any(r["status"] == "UNAVAILABLE" for r in app.discovery.results))

    def test_any_ble_library_error_is_reported_and_stale_rows_are_disabled(self):
        app = self.app()
        app.discovery.merge([ble()])
        app.bluetooth.scan.side_effect = Exception("SIMULATED BLE API error")
        engine = Mock()
        engine.adapters.return_value = []
        with patch.object(survey, "WirelessDiscovery", return_value=engine):
            survey.survey(app)
        self.assertFalse(app.discovery.devices[1].available)
        self.assertIn("SIMULATED BLE API error", self.output.getvalue())

    def test_cancelled_p2p_stops_before_starting_ble(self):
        app = self.app()
        engine = Mock()
        engine.adapters.side_effect = KeyboardInterrupt
        with patch.object(survey, "WirelessDiscovery", return_value=engine):
            survey.survey(app)
        app.bluetooth.scan.assert_not_called()
        self.assertTrue(any(r["status"] == "CANCELLED" for r in app.discovery.results))

    def test_lan_refresh_preserves_ble_scope(self):
        registry = Discovery(LAN, CONFIG, [])
        registry.merge([ble()])
        registry.scan()
        self.assertTrue(registry.devices[1].available)


class ConnectionTests(Base):
    def test_selection_validates_whole_list_before_connecting(self):
        devices = [Device(1, [ble()]), Device(2, [ble()], available=False)]
        self.assertEqual(select_iot_devices(devices), [devices[0]])
        self.assertEqual(select_iot_devices(devices, "1"), [devices[0]])
        for text in ("1,2", "1,99", "1,1", "1;2", "", "1,", "١"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                select_iot_devices(devices, text)

    def test_all_includes_unsupported_devices_with_explicit_result(self):
        hub = Connections(LAN, CONFIG, Mock())
        device = Device(1, [Endpoint("Wi-Fi Direct", "P2P", "", 0, details={"transport": "p2p"})])
        self.assertEqual(hub.connect(device)["state"], "UNSUPPORTED")

    def test_cast_connection_does_not_start_media_and_is_closed(self):
        hub = Connections(LAN, CONFIG, Mock())
        endpoint = Endpoint("Google Cast", "SIMULATED", "192.0.2.20", 8009, controllable=True)
        backend = Mock()
        with patch.dict(
            "tv_control.connections.BACKENDS", {"Google Cast": Mock(return_value=backend)}
        ):
            result = hub.connect(Device(1, [endpoint]))
        self.assertEqual(result["state"], "CONNECTED")
        backend.play.assert_not_called()
        hub.close()
        backend.disconnect.assert_called_once()
        self.assertEqual(result["state"], "DISCONNECTED")

    def test_failed_connection_cleans_up_and_does_not_claim_success(self):
        hub = Connections(LAN, CONFIG, Mock())
        endpoint = Endpoint("DLNA", "SIMULATED", "192.0.2.20", 80, controllable=True)
        backend = Mock()
        backend.connect.side_effect = RuntimeError("SIMULATED rejected")
        with patch.dict("tv_control.connections.BACKENDS", {"DLNA": Mock(return_value=backend)}):
            result = hub.connect(Device(1, [endpoint]))
        self.assertEqual(result["state"], "CONNECTION FAILED")
        backend.disconnect.assert_called_once()
        self.assertEqual(hub.sessions, {})

    def test_tcp_is_never_reported_as_authenticated_session(self):
        hub = Connections(LAN, CONFIG, Mock())
        endpoint = Endpoint(
            "HTTP", "SIMULATED", "192.0.2.20", 80, details={"service_transport": "tcp"}
        )
        with patch(
            "tv_control.connections.check_connections", return_value=[{"status": "TCP REACHABLE"}]
        ):
            result = hub.connect(Device(1, [endpoint]))
        self.assertEqual(result["state"], "TCP ONLY / CLOSED")
        self.assertEqual(hub.route(Device(1, [endpoint]))[1], "LIMITED*")

    def test_menu_scans_then_table_then_connect_all_or_ids(self):
        with patch.object(cli, "detect_network", return_value=LAN):
            app = cli.Application(self.root)
        self.addCleanup(app.close)
        ordering = []
        with (
            patch.object(app, "discover_all", side_effect=lambda: ordering.append("scan")),
            patch.object(app, "show_devices", side_effect=lambda: ordering.append("table")),
            patch.object(
                app, "connect_iots", side_effect=lambda *args: ordering.append(args)
            ) as connect,
            patch("builtins.input", side_effect=["1", "2", "1,3", "0"]),
        ):
            app.run()
        self.assertEqual(ordering, ["scan", "table", (), ("1,3",)])
        self.assertEqual(connect.call_count, 2)

    def test_connect_all_keeps_successes_after_one_device_rejects(self):
        with patch.object(cli, "detect_network", return_value=LAN):
            app = cli.Application(self.root)
        self.addCleanup(app.close)
        endpoints = [
            Endpoint("Google Cast", "SIMULATED-1", "192.0.2.20", 8009, controllable=True),
            Endpoint("Google Cast", "SIMULATED-2", "192.0.2.21", 8009, controllable=True),
        ]
        app.discovery.merge(endpoints)
        rejected, accepted = Mock(), Mock()
        rejected.connect.side_effect = RuntimeError("SIMULATED rejection")
        with patch.dict(
            "tv_control.connections.BACKENDS",
            {"Google Cast": Mock(side_effect=[rejected, accepted])},
        ):
            app.connect_iots()
        self.assertEqual(app.connections.records[1]["state"], "CONNECTION FAILED")
        self.assertEqual(app.connections.records[2]["state"], "CONNECTED")
        accepted.play.assert_not_called()

    def test_cleanup_failure_still_closes_other_resources_and_log(self):
        app = cli.Application.__new__(cli.Application)
        app.manager, app.connections, app.bluetooth, app.handler = (Mock() for _ in range(4))
        app.manager.close.side_effect = RuntimeError("SIMULATED cleanup failure")
        with self.assertRaisesRegex(RuntimeError, "cleanup failure"):
            app.close()
        app.connections.close.assert_called_once()
        app.bluetooth.close.assert_called_once()
        app.handler.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
