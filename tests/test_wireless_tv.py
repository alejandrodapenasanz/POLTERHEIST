"""H4 fixtures are SIMULATED. No test scans a radio, pairs or starts receiver playback."""

import contextlib
import io
import ipaddress
import json
import logging
import subprocess
import sys
import tempfile
import threading
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from tv_control import cli, p2p, wireless_cli
from tv_control.discovery import Discovery
from tv_control.discovery_backends import DiscoveryBackend
from tv_control.media import MediaLibrary
from tv_control.miracast import LocalPresentation, MiracastAdapter
from tv_control.models import Config, Endpoint
from tv_control.network import Network
from tv_control.wfd import mac_address, parse_wfd, peer_endpoint
from tv_control.wireless import PhyLease, WirelessDiscovery, WirelessScan
from tv_control.wireless_bus import Busctl, CommandRunner, WirelessError, decode_reply, error_code

CONFIG = Config(p2p_timeout=1, discovery_timeout=0.1)
LAN = Network("SIMULATED LAN", "192.0.2.10", ipaddress.IPv4Network("192.0.2.0/24"))
SINK = list(bytes.fromhex("00000600111c4400c8"))
SOURCE = list(bytes.fromhex("00000600101c4400c8"))
BUSY_SINK = list(bytes.fromhex("00000600011c4400c8"))
COMBINATIONS = "* #{ managed } <= 1, #{ P2P-client, P2P-GO } <= 1, total <= 2, #channels <= 1"
IW = """phy#0
    Unnamed/non-netdev interface
        type P2P-device
    Interface wlan0
        type managed
phy#1
    Interface wlan1
        type managed
"""
PHY = """Wiphy phy0
    Supported interface modes:
         * managed
         * P2P-device
         * P2P-client
         * P2P-GO
    valid interface combinations:
         * #{ managed } <= 1, #{ P2P-client, P2P-GO } <= 1, total <= 2, #channels <= 1
Wiphy phy1
    Supported interface modes:
         * managed
"""


def adapter(interface="wlan0", phy="phy0", backend="networkmanager"):
    return p2p.Adapter(
        interface,
        phy,
        "managed",
        {
            "modes": ["managed", "P2P-device", "P2P-client", "P2P-GO"],
            "modes_reported": True,
            "interface_combinations": COMBINATIONS,
        },
        control_path="/org/freedesktop/NetworkManager/Devices/2",
        physical_path="/org/freedesktop/NetworkManager/Devices/1",
        backend=backend,
        eligible=True,
    )


def peer(address="02:00:00:00:00:01", wfd=SINK, seen=1001, name="SIMULATED WFD RECEIVER"):
    return {"Name": name, "HwAddress": address, "WfdIEs": wfd, "LastSeen": seen}


def endpoint(**kwargs):
    return peer_endpoint(peer(**kwargs), adapter(), "networkmanager", "/simulated/peer1", True)


def reply(signature, value):
    return json.dumps({"type": signature, "data": [value]})


class QuietTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.output = self.enterContext(contextlib.redirect_stdout(io.StringIO()))
        self.enterContext(contextlib.redirect_stderr(io.StringIO()))
        self.enterContext(patch.object(logging.getLogger("tv_control.wireless"), "exception"))


class WFDTests(QuietTest):
    def test_primary_secondary_dual_role_and_source_are_separate(self):
        for role, label in enumerate(("SOURCE", "PRIMARY_SINK", "SECONDARY_SINK", "DUAL_ROLE")):
            payload = bytearray(SINK)
            payload[4] = 0x10 | role
            result = parse_wfd(payload)
            self.assertEqual(result["role"], label)
            self.assertEqual(result["sink"], role != 0)
            self.assertTrue(result["session_available"])
            self.assertEqual(result["rtsp_port"], 7236)

    def test_busy_reserved_availability_and_no_wfd_are_not_ready(self):
        self.assertFalse(parse_wfd(BUSY_SINK)["session_available"])
        reserved = bytearray(SINK)
        reserved[4] = 0x21
        self.assertIsNone(parse_wfd(reserved)["session_available"])
        for absent in (None, [], b"", ""):
            self.assertEqual(parse_wfd(absent)["status"], "NOT_ADVERTISED")

    def test_truncated_duplicate_or_malformed_wfd_never_claims_receiver(self):
        malformed = [
            SINK[:-1],
            SINK + SINK,
            [-1],
            [True],
            "not-hex",
            "0",
            [0, 0, 8, *SINK[3:]],
            b"x" * 4097,
        ]
        for value in malformed:
            with self.subTest(value=str(value)[:60]):
                result = parse_wfd(value)
                self.assertEqual(result["status"], "MALFORMED")
                self.assertFalse(result["sink"])

    def test_unknown_subelement_skipped_but_never_used_as_device_info(self):
        unknown = bytes.fromhex("0900021122")
        self.assertEqual(parse_wfd(unknown)["status"], "DEVICE_INFO_MISSING")
        self.assertTrue(parse_wfd(unknown + bytes(SINK))["sink"])

    def test_mac_validation_accepts_exact_unicast_only(self):
        self.assertEqual(mac_address([2, 0, 0, 0, 0, 1]), "02:00:00:00:00:01")
        for value in (
            "00:00:00:00:00:00",
            "ff:ff:ff:ff:ff:ff",
            "01:00:00:00:00:01",
            "02:00:00",
            "$(command)",
            [True] * 6,
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                mac_address(value)

    def test_receiver_classification_records_evidence_without_guessing_model(self):
        found = endpoint()
        self.assertEqual(found.protocol, "Wi-Fi Direct")
        self.assertFalse(found.controllable)
        self.assertEqual(found.ip, "")
        self.assertEqual(found.manufacturer, "Unknown")
        self.assertEqual(found.model, "Unknown")
        self.assertEqual(found.details["classification"], "WFD CAPABLE")
        self.assertTrue(found.observed_at)
        self.assertIn("NOT PAIRED", found.authentication)

    def test_tv_name_alone_does_not_make_a_peer_a_wfd_sink(self):
        found = endpoint(name="Samsung Miracast TV SIMULATED", wfd=[])
        self.assertEqual(found.details["classification"], "P2P ONLY")
        self.assertFalse(found.details["wfd"]["sink"])

    def test_supplicant_byte_address_and_cached_status(self):
        found = peer_endpoint(
            {"DeviceName": "SIMULATED", "DeviceAddress": [2, 0, 0, 0, 0, 1], "IEs": SINK},
            adapter(backend="supplicant"),
            "supplicant",
            "/simulated/peer1",
            False,
        )
        self.assertTrue(found.details["wfd"]["sink"])
        self.assertIn("CACHED", found.note)


class BusTests(QuietTest):
    def test_typed_json_arrays_and_variants(self):
        self.assertEqual(
            decode_reply(reply("ao", ["/simulated/peer1"]), "ao"), ["/simulated/peer1"]
        )
        self.assertEqual(
            decode_reply(reply("a{sv}", {"Name": {"type": "s", "data": "SIMULATED"}}), "a{sv}"),
            {"Name": "SIMULATED"},
        )
        self.assertEqual(decode_reply(reply("ay", SINK), "ay"), SINK)

    def test_bad_signature_or_path_is_rejected(self):
        for raw in (
            "invalid",
            reply("s", "wrong type"),
            reply("ao", ["/bad;command"]),
            '{"type":"ao","data":[]}',
        ):
            with self.subTest(raw=raw), self.assertRaises(WirelessError):
                decode_reply(raw, "ao")

    def test_calls_cannot_activate_services_or_prompt_for_elevation(self):
        runner = Mock(return_value=reply("v", {"type": "b", "data": True}))
        bus = Busctl(runner)
        self.assertTrue(bus.get(p2p.NM, p2p.NM_ROOT, p2p.NM, "WirelessEnabled", "b"))
        argv = runner.call_args.args[0]
        self.assertIn("--auto-start=no", argv)
        self.assertIn("--allow-interactive-authorization=no", argv)
        self.assertNotIn("sudo", argv)
        self.assertIn("call", argv)
        self.assertEqual(argv[-4:], ["Get", "ss", p2p.NM, "WirelessEnabled"])

    def test_start_stop_use_correct_nm_and_supplicant_keys(self):
        runner = Mock(return_value="")
        bus = Busctl(runner)
        for backend, method, key in (
            (p2p.NetworkManagerP2P(bus), "StartFind", "timeout"),
            (p2p.SupplicantP2P(bus), "Find", "Timeout"),
        ):
            backend.start(adapter(backend=backend.name), 15)
            self.assertEqual(runner.call_args.args[0][-6:], [method, "a{sv}", "1", key, "i", "15"])
            backend.stop(adapter(backend=backend.name))
            self.assertEqual(runner.call_args.args[0][-1], "StopFind")

    def test_error_categories_are_explicit(self):
        expected = {
            "AccessDenied": "PERMISSION_DENIED",
            "operation already running": "ADAPTER_BUSY",
            "ServiceUnknown": "SERVICE_UNAVAILABLE",
            "UnknownMethod": "UNSUPPORTED_API",
            "other": "DBUS_ERROR",
        }
        for text, code in expected.items():
            self.assertEqual(error_code(text), code)

    def test_real_command_runner_timeout_and_output_limit(self):
        runner = CommandRunner()
        self.assertEqual(
            runner([sys.executable, "-c", "print('SIMULATED TOOL')"]).strip(), "SIMULATED TOOL"
        )
        with self.assertRaisesRegex(WirelessError, "TIMEOUT"):
            runner([sys.executable, "-c", "import time; time.sleep(10)"], timeout=0.1)
        with self.assertRaisesRegex(WirelessError, "OUTPUT_LIMIT"):
            runner([sys.executable, "-c", "print('x' * 300000)"])
        with self.assertRaisesRegex(WirelessError, "DEPENDENCY_MISSING"):
            runner(["polterheist-fixture-no-such-tool"])

    def test_cancel_before_command_has_no_process_side_effect(self):
        event = threading.Event()
        event.set()
        with patch("subprocess.Popen") as spawn, self.assertRaisesRegex(WirelessError, "CANCELLED"):
            CommandRunner()([sys.executable], cancel=event)
        spawn.assert_not_called()


class AdapterTests(QuietTest):
    def radio(self, connected=False, output=IW, phy=PHY):
        def runner(argv, **kwargs):
            if argv == ["iw", "dev"]:
                return output
            if argv == ["iw", "phy"]:
                return phy
            if argv[-1] == "link":
                return (
                    "Connected to 02:00:00:00:00:02 (on wlan0)\n\tfreq: 2412\n"
                    if connected
                    else "Not connected.\n"
                )
            raise AssertionError("Unexpected or mutating radio command: " + repr(argv))

        return p2p.LocalRadio(runner, "linux", self.root)

    def test_inventory_distinguishes_phys_and_unsupported_adapters(self):
        backend = Mock(name="SIMULATED")
        backend.name = "networkmanager"
        backend.controls.return_value = {
            "wlan0": {"path": "/simulated/p2p0", "physical": "/simulated/wifi0"},
            "wlan1": {"path": "/simulated/p2p1", "physical": "/simulated/wifi1"},
        }
        found = self.radio().inventory(backend)
        self.assertEqual([item.phy for item in found], ["phy0", "phy1"])
        self.assertTrue(found[0].eligible)
        self.assertFalse(found[1].eligible)
        self.assertIn("P2P_UNSUPPORTED", found[1].reasons[0])

    def test_windows_fails_before_reading_hardware_or_dbus(self):
        runner, backend = Mock(), Mock()
        with self.assertRaisesRegex(WirelessError, "PLATFORM_UNSUPPORTED"):
            p2p.LocalRadio(runner, "win32").inventory(backend)
        runner.assert_not_called()
        backend.controls.assert_not_called()

    def test_single_channel_limit_is_retained_without_assuming_multichannel(self):
        result = p2p.concurrency_support(COMBINATIONS, ["managed", "P2P-client"])
        self.assertTrue(result["supported"])
        self.assertEqual(result["channel_limits"], [1])
        self.assertFalse(
            p2p.concurrency_support(COMBINATIONS, ["managed", "managed", "P2P-client"])["supported"]
        )
        self.assertIsNone(p2p.concurrency_support("unknown", ["managed"])["supported"])

    def test_connected_managed_wifi_requires_advertised_coexistence(self):
        radio = self.radio(connected=True)
        snapshot = radio.snapshot(adapter())
        self.assertEqual(snapshot["links"]["wlan0"]["frequency"], 2412)
        unknown = replace(adapter(), capabilities={"modes": ["managed", "P2P-client"]})
        with self.assertRaisesRegex(WirelessError, "ADAPTER_BUSY"):
            radio.snapshot(unknown)

    def test_monitor_ap_or_existing_p2p_group_blocks_scan(self):
        for mode in ("monitor", "AP", "P2P-client", "P2P-GO"):
            radio = self.radio(
                output=IW.replace("phy#1", "    Interface extra0\n        type " + mode + "\nphy#1")
            )
            with self.subTest(mode=mode), self.assertRaisesRegex(WirelessError, "ADAPTER_BUSY"):
                radio.snapshot(adapter())

    def test_nm_mapping_uses_interface_not_similar_mac(self):
        bus = Mock()
        bus.call.return_value = reply(
            "ao", ["/simulated/wifi0", "/simulated/p2p0", "/simulated/other"]
        )
        bus.properties.side_effect = [
            {"Interface": "wlan0", "DeviceType": 2},
            {"Interface": "p2p-dev-wlan0", "DeviceType": 30},
            {"Interface": "p2p-dev-wlan9", "DeviceType": 30},
        ]
        controls = p2p.NetworkManagerP2P(bus).controls(["wlan0", "wlan1"])
        self.assertEqual(
            controls, {"wlan0": {"path": "/simulated/p2p0", "physical": "/simulated/wifi0"}}
        )

    def test_nm_existing_connection_is_never_disconnected(self):
        bus = Mock()
        bus.get.return_value = True
        bus.properties.side_effect = [
            {"Interface": "wlan0", "State": 100, "ActiveConnection": "/active/wifi"},
            {
                "Interface": "p2p-dev-wlan0",
                "Managed": True,
                "State": 100,
                "ActiveConnection": "/active/p2p",
            },
        ]
        with self.assertRaisesRegex(WirelessError, "ADAPTER_BUSY"):
            p2p.NetworkManagerP2P(bus).snapshot(adapter())
        bus.call.assert_not_called()

    def test_supplicant_selects_exact_p2p_control_interface(self):
        bus = Mock()
        bus.get.side_effect = [
            ["p2p"],
            ["/simulated/physical", "/simulated/control"],
            "wlan0",
            "p2p-dev-wlan0",
        ]
        controls = p2p.SupplicantP2P(bus).controls(["wlan0"])
        self.assertEqual(controls["wlan0"]["path"], "/simulated/control")

    def test_unavailable_services_and_permissions_do_not_fallback(self):
        bus = Mock()
        bus.call.side_effect = WirelessError("SERVICE_UNAVAILABLE", "SIMULATED")
        with self.assertRaisesRegex(WirelessError, "NETWORKMANAGER_UNAVAILABLE"):
            p2p.NetworkManagerP2P(bus).controls(["wlan0"])
        bus.get.side_effect = WirelessError("SERVICE_UNAVAILABLE", "SIMULATED")
        with self.assertRaisesRegex(WirelessError, "SUPPLICANT_UNAVAILABLE"):
            p2p.SupplicantP2P(bus).controls(["wlan0"])
        bus.get.side_effect = WirelessError("PERMISSION_DENIED", "SIMULATED")
        with self.assertRaisesRegex(WirelessError, "PERMISSION_DENIED"):
            p2p.SupplicantP2P(bus).controls(["wlan0"])

    def test_supplicant_peer_data_and_group_guard(self):
        bus = Mock()
        bus.get.return_value = "p2p-dev-wlan0"
        bus.properties.return_value = {"Group": "/simulated/group", "Role": "GO"}
        with self.assertRaisesRegex(WirelessError, "ADAPTER_BUSY"):
            p2p.SupplicantP2P(bus).snapshot(adapter(backend="supplicant"))
        bus.call.assert_not_called()


class SimulatedBusIntegrationTests(QuietTest):
    def run_backend(self, name):
        active, calls = False, []
        physical, control, remote = "/simulated/wifi0", "/simulated/p2p0", "/simulated/peer1"

        def properties(values):
            return reply(
                "a{sv}",
                {
                    key: {
                        "type": "b"
                        if type(value) is bool
                        else "i"
                        if type(value) is int
                        else "ay"
                        if isinstance(value, list)
                        else "s",
                        "data": value,
                    }
                    for key, value in values.items()
                },
            )

        def runner(argv, **kwargs):
            nonlocal active
            if argv == ["iw", "dev"]:
                return IW
            if argv == ["iw", "phy"]:
                return PHY
            if argv[:2] == ["iw", "dev"] and argv[-1] == "link":
                return "Not connected.\n"
            self.assertEqual(argv[0], "busctl")
            call = argv[argv.index("call") :]
            calls.append(call)
            _, service, path, interface, method, *args = call
            if method in ("StartFind", "Find"):
                self.assertEqual(
                    args,
                    ["a{sv}", "1", "timeout" if name == "networkmanager" else "Timeout", "i", "1"],
                )
                active = True
                return ""
            if method == "StopFind":
                active = False
                return ""
            if method == "GetDevices":
                return reply("ao", [physical, control])
            if method == "Get":
                prop = args[-1]
                value_type, value = {
                    "WirelessEnabled": ("b", True),
                    "Capabilities": ("as", ["p2p"]),
                    "Interfaces": ("ao", [control]),
                    "Ifname": ("s", "p2p-dev-wlan0"),
                    "State": ("s", "inactive"),
                    "Peers": ("ao", [remote] if active else []),
                }[prop]
                return reply("v", {"type": value_type, "data": value})
            self.assertEqual(method, "GetAll")
            target_interface = args[-1]
            if path == remote:
                return properties(
                    peer()
                    if name == "networkmanager"
                    else {
                        "DeviceName": "SIMULATED WFD RECEIVER",
                        "DeviceAddress": [2, 0, 0, 0, 0, 1],
                        "IEs": SINK,
                    }
                )
            if target_interface == p2p.WPA_P2P:
                return properties({"Role": "device", "Group": "/"})
            return properties(
                {
                    "Interface": "wlan0" if path == physical else "p2p-dev-wlan0",
                    "DeviceType": 2 if path == physical else 30,
                    "State": 30,
                    "Managed": True,
                    "ActiveConnection": "/",
                }
            )

        bus = Busctl(runner)
        backend = p2p.NetworkManagerP2P(bus) if name == "networkmanager" else p2p.SupplicantP2P(bus)
        radio = p2p.LocalRadio(runner, "linux", self.root)
        engine = WirelessDiscovery(
            self.root, replace(CONFIG, p2p_backend=name), radio, backend, boot_clock=lambda: 1000
        )
        selected = next(item for item in engine.adapters() if item.eligible)
        result = engine.scan(selected, confirmed=True)
        self.assertEqual(result.state, "COMPLETED")
        self.assertTrue(result.state_preserved)
        self.assertTrue(result.endpoints[0].details["wfd"]["sink"])
        self.assertFalse(active)
        mutations = [call[4] for call in calls if call[4] not in ("Get", "GetAll", "GetDevices")]
        self.assertEqual(
            mutations, ["StartFind" if name == "networkmanager" else "Find", "StopFind"]
        )

    def test_simulated_nm_json_through_adapter_inventory_scan_and_cleanup(self):
        self.run_backend("networkmanager")

    def test_simulated_supplicant_json_through_adapter_inventory_scan_and_cleanup(self):
        self.run_backend("supplicant")


class FakeTime:
    def __init__(self):
        self.now, self.cancelled = 0, False

    def clock(self):
        return self.now

    def wait(self, duration):
        self.now += duration
        return self.cancelled

    def is_set(self):
        return self.cancelled

    def set(self):
        self.cancelled = True


class SimulatedBackend:
    name = "networkmanager"

    def __init__(self, peers=None):
        self.started, self.starts, self.stops = False, 0, 0
        self.records = [("/simulated/peer1", peer())] if peers is None else peers
        self.before = []
        self.start_error = self.stop_error = self.poll_error = None
        self.on_poll = lambda: None

    def start(self, adapter, duration):
        self.starts += 1
        if self.start_error:
            raise self.start_error
        self.started = True

    def stop(self, adapter):
        self.stops += 1
        if self.stop_error:
            raise self.stop_error
        self.started = False

    def snapshot(self, adapter):
        return {"group": "/", "active_connection": "/", "state": "SIMULATED IDLE"}

    def peers(self, adapter, deadline, limit):
        if not self.started:
            return self.before
        self.on_poll()
        if self.poll_error:
            raise self.poll_error
        return self.records[:limit]


class StateTests(QuietTest):
    def engine(self, backend=None):
        radio = Mock()
        radio.snapshot.return_value = {"state": "SIMULATED original managed link"}
        self.fake_time = FakeTime()
        self.backend = backend or SimulatedBackend()
        self.engine_value = WirelessDiscovery(
            self.root, CONFIG, radio, self.backend, self.fake_time.clock, lambda: 1000
        )
        return self.engine_value

    def scan(self, engine):
        return engine.scan(
            adapter(backend=self.backend.name), confirmed=True, cancel=self.fake_time
        )

    def test_finite_scan_stops_and_verifies_original_state(self):
        result = self.scan(self.engine())
        self.assertEqual(result.state, "COMPLETED")
        self.assertEqual(result.fresh_count, 1)
        self.assertTrue(result.state_preserved)
        self.assertTrue(result.stop_confirmed)
        self.assertEqual((self.backend.starts, self.backend.stops), (1, 1))
        self.assertEqual(
            result.history, ["CHECKING", "STARTING", "DISCOVERING", "STOPPING", "COMPLETED"]
        )
        self.assertEqual(json.loads(result.export(self.root).read_text())["state"], "COMPLETED")

    def test_no_peer_result_is_explicit(self):
        result = self.scan(self.engine(SimulatedBackend([])))
        self.assertEqual(result.state, "NO_PEERS")
        self.assertEqual(result.endpoints, [])

    def test_no_confirmation_means_no_query_or_scan(self):
        engine = self.engine()
        with self.assertRaisesRegex(WirelessError, "CONFIRMATION_REQUIRED"):
            engine.scan(adapter())
        engine.radio.snapshot.assert_not_called()
        self.assertEqual(self.backend.starts, 0)

    def test_pre_cancelled_request_never_starts_or_stops_radio(self):
        engine = self.engine()
        self.fake_time.set()
        result = self.scan(engine)
        self.assertEqual(result.state, "CANCELLED")
        self.assertEqual((self.backend.starts, self.backend.stops), (0, 0))

    def test_event_cancellation_stops_only_owned_discovery(self):
        engine = self.engine()
        self.backend.on_poll = self.fake_time.set
        result = self.scan(engine)
        self.assertEqual(result.state, "CANCELLED")
        self.assertEqual(self.backend.stops, 1)
        self.assertTrue(result.state_preserved)

    def test_keyboard_interrupt_always_runs_cleanup(self):
        engine = self.engine()
        self.backend.poll_error = KeyboardInterrupt()
        result = self.scan(engine)
        self.assertEqual(result.state, "CANCELLED")
        self.assertTrue(result.stop_confirmed)

    def test_timeout_after_start_runs_stop_and_records_error(self):
        engine = self.engine()
        self.backend.poll_error = WirelessError("TIMEOUT", "SIMULATED peer query timeout")
        result = self.scan(engine)
        self.assertEqual(result.error_code, "TIMEOUT")
        self.assertTrue(result.stop_confirmed)

    def test_uncertain_start_timeout_attempts_cleanup(self):
        engine = self.engine()
        self.backend.start_error = WirelessError("TIMEOUT", "SIMULATED lost reply")
        result = self.scan(engine)
        self.assertEqual(result.state, "ERROR")
        self.assertEqual(self.backend.stops, 1)

    def test_rejected_start_does_not_stop_another_discovery(self):
        for code in ("PERMISSION_DENIED", "ADAPTER_BUSY", "UNSUPPORTED_API"):
            with self.subTest(code=code):
                engine = self.engine()
                self.backend.start_error = WirelessError(code, "SIMULATED rejection")
                result = self.scan(engine)
                self.assertEqual(result.error_code, code)
                self.assertEqual(self.backend.stops, 0)

    def test_cleanup_failure_never_claims_restoration(self):
        engine = self.engine()
        self.backend.stop_error = WirelessError("PERMISSION_DENIED", "SIMULATED cleanup denial")
        result = self.scan(engine)
        self.assertEqual(result.state, "CLEANUP_UNVERIFIED")
        self.assertFalse(result.stop_confirmed)
        self.assertTrue(result.warnings)

    def test_external_link_change_is_reported_without_reconnect(self):
        engine = self.engine()
        engine.radio.snapshot.side_effect = [
            {"state": "SIMULATED original"},
            {"state": "SIMULATED external change"},
        ]
        result = self.scan(engine)
        self.assertEqual(result.state, "CLEANUP_UNVERIFIED")
        self.assertFalse(result.state_preserved)
        self.assertEqual(self.backend.starts, 1)
        self.assertEqual(self.backend.stops, 1)

    def test_old_nm_last_seen_is_not_a_fresh_detection(self):
        backend = SimulatedBackend([("/simulated/peer1", peer(seen=900))])
        result = self.scan(self.engine(backend))
        self.assertEqual(result.state, "CACHE_ONLY")
        self.assertEqual(result.fresh_count, 0)
        self.assertEqual(result.cached_count, 1)

    def test_same_second_unchanged_nm_cache_is_not_fresh(self):
        backend = SimulatedBackend([("/simulated/peer1", peer(seen=1000))])
        backend.before = list(backend.records)
        result = self.scan(self.engine(backend))
        self.assertEqual(result.state, "CACHE_ONLY")

    def test_refreshed_nm_last_seen_promotes_a_cached_peer(self):
        backend = SimulatedBackend([("/simulated/peer1", peer(seen=1001))])
        backend.before = [("/simulated/peer1", peer(seen=999))]
        result = self.scan(self.engine(backend))
        self.assertEqual(result.state, "COMPLETED")

    def test_unchanged_supplicant_cache_stays_cached(self):
        backend = SimulatedBackend(
            [
                (
                    "/simulated/peer1",
                    {"DeviceName": "SIMULATED", "DeviceAddress": [2, 0, 0, 0, 0, 1], "IEs": SINK},
                )
            ]
        )
        backend.name, backend.before = "supplicant", list(backend.records)
        result = self.scan(self.engine(backend))
        self.assertEqual(result.state, "CACHE_ONLY")

    def test_phy_lock_blocks_competing_operation_and_releases(self):
        with PhyLease(self.root, "phy0"):
            with self.assertRaisesRegex(WirelessError, "ADAPTER_BUSY"):
                with PhyLease(self.root, "phy0"):
                    pass
        with PhyLease(self.root, "phy0"):
            pass


class InventoryTests(QuietTest):
    def result(self, items, interface="wlan0", started=True):
        return WirelessScan(
            {"interface": interface, "backend": "networkmanager"},
            endpoints=items,
            started=started,
            state="COMPLETED",
        )

    def test_same_name_or_similar_mac_does_not_merge_p2p_peers(self):
        engine = Discovery(LAN, CONFIG)
        engine.add_wireless(self.result([endpoint(), endpoint(address="02:00:00:00:00:02")]))
        self.assertEqual(len(engine.devices), 2)
        self.assertTrue(all(not device.controllable for device in engine.devices.values()))

    def test_classification_update_preserves_id(self):
        engine = Discovery(LAN, CONFIG)
        engine.add_wireless(self.result([endpoint(wfd=[])]))
        engine.add_wireless(self.result([endpoint()]))
        self.assertEqual(len(engine.devices), 1)
        self.assertEqual(engine.devices[1].primary.details["classification"], "WFD CAPABLE")

    def test_same_peer_on_different_adapters_preserves_each_observation(self):
        engine = Discovery(LAN, CONFIG)
        second = peer_endpoint(
            peer(), adapter("wlan1", "phy1"), "networkmanager", "/simulated/peer1", True
        )
        engine.add_wireless(self.result([endpoint()]))
        engine.add_wireless(self.result([second], "wlan1"))
        self.assertEqual(len(engine.devices), 2)
        engine.add_wireless(self.result([]))
        self.assertFalse(engine.devices[1].available)
        self.assertTrue(engine.devices[2].available)

    def test_lan_refresh_preserves_radio_and_radio_refresh_preserves_lan(self):
        ip = Endpoint("Google Cast", "simulated-cast", "192.0.2.1", 8009, controllable=True)
        engine = Discovery(LAN, CONFIG, [DiscoveryBackend("cast", "SIMULATED", lambda *args: [ip])])
        engine.add_wireless(self.result([endpoint()]))
        engine.scan()
        self.assertTrue(engine.devices[1].available)
        engine.add_wireless(self.result([]))
        self.assertTrue(any(d.controllable for d in engine.devices.values()))

    def test_cached_or_failed_scan_never_enables_receiver(self):
        engine = Discovery(None, CONFIG)
        cached = endpoint()
        cached.details["fresh"] = False
        engine.add_wireless(self.result([cached]))
        self.assertFalse(engine.devices[1].available)
        engine.add_wireless(self.result([], started=False))
        self.assertFalse(engine.devices[1].available)
        with self.assertRaisesRegex(ValueError, "IPv4"):
            engine.scan()


class IntegrationTests(QuietTest):
    def test_application_opens_without_lan_and_closes_safely(self):
        with patch.object(cli, "detect_network", side_effect=RuntimeError("SIMULATED no LAN")):
            app = cli.Application(self.root)
        self.addCleanup(app.close)
        self.assertIsNone(app.network)
        self.assertIsNone(app.manager.server)
        with patch("builtins.input", return_value="0"):
            app.run()
        self.assertIn("Wi-Fi Direct", self.output.getvalue())

    def test_wireless_menu_does_not_scan_without_confirmation(self):
        app = SimpleNamespace(root=self.root, discovery=Mock(config=CONFIG))
        engine = Mock()
        engine.adapters.return_value = [adapter()]
        engine.config = CONFIG
        with (
            patch.object(wireless_cli, "WirelessDiscovery", return_value=engine),
            patch("builtins.input", side_effect=["1", ""]),
        ):
            wireless_cli.discover(app)
        engine.scan.assert_not_called()

    def test_new_options_preserve_existing_target_menu(self):
        app = object.__new__(cli.Application)
        app.show_devices = Mock()
        with (
            patch("builtins.input", side_effect=["8", "9", "10", "0"]),
            patch.object(wireless_cli, "discover") as scan,
            patch.object(wireless_cli, "receivers") as sinks,
            patch.object(wireless_cli, "prepare") as prepare,
        ):
            self.assertIsNone(app.targets())
        for action in (scan, sinks, prepare):
            action.assert_called_once_with(app)

    def test_p2p_configuration_is_bounded_and_never_auto_enables_scan(self):
        for values in (
            {"p2p_timeout": 0},
            {"p2p_timeout": 1000},
            {"p2p_timeout": True},
            {"p2p_backend": "shell"},
        ):
            with self.subTest(values=values), self.assertRaises(ValueError):
                Config(**values)
        self.assertNotIn("p2p", CONFIG.discovery_backends)

    def test_miracast_preparation_does_not_claim_connection_or_spawn_tools(self):
        adapter_ = MiracastAdapter(self.root, CONFIG, platform="linux", which=lambda tool: None)
        with patch("subprocess.Popen") as spawn:
            plan = adapter_.prepare(endpoint())
            self.assertFalse(plan.session_verified)
            self.assertFalse(plan.media_verified_on_receiver)
            self.assertTrue(any("DEPENDENCY_MISSING" in reason for reason in plan.blockers))
            with self.assertRaisesRegex(WirelessError, "CONFIRMATION_REQUIRED"):
                adapter_.connect(plan)
            with self.assertRaisesRegex(WirelessError, "MIRACAST_NOT_ACTIVATED"):
                adapter_.connect(plan, confirmed=True)
        spawn.assert_not_called()
        self.assertEqual(
            json.loads(plan.export(self.root).read_text())["state"], "PREPARATION_ONLY"
        )

    def test_source_only_or_busy_receiver_cannot_be_treated_as_ready(self):
        adapter_ = MiracastAdapter(
            self.root, CONFIG, platform="linux", which=lambda tool: "/SIMULATED/" + tool
        )
        for payload, code in ((SOURCE, "WFD_UNSUPPORTED"), (BUSY_SINK, "ADAPTER_BUSY")):
            plan = adapter_.prepare(endpoint(wfd=payload))
            self.assertTrue(any(code in error for error in plan.blockers))
            self.assertFalse(plan.session_verified)

    def test_local_presentation_confirmation_and_cleanup(self):
        library = MediaLibrary(self.root, CONFIG)
        path = library.folder / "SIMULATED.mp4"
        path.write_bytes(b"SIMULATED MEDIA")
        library.inspect = Mock(return_value=SimpleNamespace(path=path))
        player = LocalPresentation(library)
        self.addCleanup(player.stop)
        with self.assertRaisesRegex(WirelessError, "CONFIRMATION_REQUIRED"):
            player.start(path)
        library.inspect.assert_not_called()
        process = Mock()
        process.poll.return_value = None
        with (
            patch("shutil.which", return_value="/SIMULATED/ffplay"),
            patch("subprocess.Popen", return_value=process) as spawn,
        ):
            player.start(path, confirmed=True)
        self.assertEqual(player.state, "LOCAL_PRESENTATION_ONLY")
        argv = spawn.call_args.args[0]
        self.assertIn("-loop", argv)
        self.assertIn("-fs", argv)
        self.assertEqual(argv[-1], str(path))
        player.stop()
        process.terminate.assert_called_once()
        self.assertIsNone(player.output)

    def test_local_player_failure_is_reported_and_resources_are_closed(self):
        library = MediaLibrary(self.root, CONFIG)
        player = LocalPresentation(library)
        player.process = Mock()
        player.process.poll.return_value = 2
        player.output = tempfile.TemporaryFile()
        with self.assertRaisesRegex(WirelessError, "STREAMING_FAILED"):
            player.poll()
        self.assertIsNone(player.process)
        self.assertIsNone(player.output)

    def test_local_player_termination_timeout_escalates_only_own_process(self):
        player = LocalPresentation(MediaLibrary(self.root, CONFIG))
        process = Mock()
        process.poll.return_value = None
        process.wait.side_effect = [subprocess.TimeoutExpired("SIMULATED player", 2), None]
        player.process = process
        player.stop()
        process.kill.assert_called_once()


if __name__ == "__main__":
    unittest.main()
