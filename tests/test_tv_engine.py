"""H2/H3: synthetic hardware fixtures and an explicitly simulated local DIAL receiver."""

import contextlib
import io
import ipaddress
import json
import logging
import socket
import sys
import tempfile
import threading
import unittest
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import script
from tv_control import cli, hardware, scopes
from tv_control.discovery import Discovery
from tv_control.discovery_backends import DiscoveryBackend
from tv_control.manager import Manager
from tv_control.models import Config, Device, Endpoint
from tv_control.network import Network, checked_url
from tv_control.protocols import airplay, dlna

LAN = Network("SIMULATED-LAN", "192.0.2.10", ipaddress.IPv4Network("192.0.2.0/24"))
CONFIG = Config(discovery_timeout=0.1, request_timeout=0.5)
IW = """phy#0
    Unnamed/non-netdev interface
        type P2P-device
    Interface wlan0
        type managed
"""
PHY = """Wiphy phy0
    Supported interface modes:
         * managed
         * P2P-client
         * P2P-GO
         * P2P-device
    Band 1:
        Frequencies:
            * 2412 MHz [1] (20.0 dBm)
            * 5180 MHz [36] (20.0 dBm)
            * 5955 MHz [1] (disabled)
    valid interface combinations:
         * #{ managed } <= 1, #{ P2P-client, P2P-GO } <= 1, total <= 2, #channels <= 1
"""
DIAL_XML = b"""<root xmlns="urn:schemas-upnp-org:device-1-0"><device>
<deviceType>urn:dial-multiscreen-org:device:dialreceiver:1</deviceType>
<friendlyName>SIMULATED DIAL RECEIVER</friendlyName><UDN>uuid:simulated-dial</UDN>
<modelName>Test fixture</modelName><manufacturer>Test suite</manufacturer>
<serviceList><service><serviceType>urn:dial-multiscreen-org:service:dial:1</serviceType>
</service></serviceList></device></root>"""


class QuietTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.enterContext(contextlib.redirect_stdout(io.StringIO()))
        self.enterContext(contextlib.redirect_stderr(io.StringIO()))
        self.enterContext(patch.object(logging.getLogger("tv_control.discovery"), "exception"))


class HardwareTests(QuietTest):
    def test_iw_parsing_preserves_non_netdev_and_concurrency_limits(self):
        interfaces = hardware.parse_iw_devices(IW)
        self.assertEqual(interfaces[0]["type"], "P2P-device")
        self.assertEqual(interfaces[1]["name"], "wlan0")
        phy = hardware.parse_phys(PHY)["phy0"]
        self.assertEqual(phy["bands"], ["2.4 GHz", "5 GHz", "6 GHz"])
        self.assertTrue(phy["frequencies"][-1]["disabled"])
        self.assertIn("P2P-client", phy["modes"])
        self.assertIn("#channels <= 1", phy["interface_combinations"])

    def test_linux_diagnosis_only_queries_and_does_not_claim_miracast_session(self):
        calls = []

        def runner(argv):
            calls.append(argv)
            output = IW if argv == ["iw", "dev"] else PHY if argv == ["iw", "phy"] else ""
            return hardware.Probe(argv, "OK" if output else "MISSING", output)

        report = hardware.collect(runner, platform="linux", sysfs=self.root, environ={})
        self.assertTrue(report["wifi"][1]["p2p"]["P2P-client"])
        self.assertFalse(report["wfd"]["session_verified"])
        self.assertFalse(report["desktop"]["capture_started"])
        for call in calls:
            self.assertFalse(
                set(call)
                & {
                    "StartDiscovery",
                    "StartFind",
                    "scan",
                    "connect",
                    "pair",
                    "set",
                    "stop",
                    "restart",
                }
            )
            if call[0] == "busctl":
                self.assertIn("--auto-start=no", call)

    def test_missing_tools_leave_capabilities_unknown(self):
        report = hardware.collect(
            lambda argv: hardware.Probe(argv, "MISSING"), platform="linux", sysfs=self.root
        )
        self.assertEqual(report["wifi"], [])
        self.assertIsNone(report["wfd"]["supplicant_p2p_advertised"])
        self.assertEqual(report["h264_encoders"], [])

    def test_incomplete_phy_output_does_not_assert_p2p_is_unsupported(self):
        def runner(argv):
            output = (
                IW if argv == ["iw", "dev"] else "Wiphy phy0\n" if argv == ["iw", "phy"] else ""
            )
            return hardware.Probe(argv, "OK", output)

        report = hardware.collect(runner, platform="linux", sysfs=self.root)
        self.assertIsNone(report["wifi"][1]["p2p"]["P2P-client"])

    def test_chipset_ids_and_modalias_are_read_from_simulated_sysfs(self):
        device = self.root / "class" / "net" / "wlan0" / "device"
        device.mkdir(parents=True)
        (device / "vendor").write_text("0x1234\n")
        (device / "device").write_text("0xabcd\n")
        (device / "modalias").write_text("pci:SIMULATED\n")
        result = hardware.chipset("wlan0", self.root)
        self.assertEqual(result["chipset_id"], "0x1234:0xabcd")
        self.assertEqual(result["modalias"], "pci:SIMULATED")
        self.assertEqual(result["driver"], "Unknown")

    def test_permission_failure_is_reported_without_install_or_elevation(self):
        with patch.object(
            hardware.subprocess, "Popen", side_effect=PermissionError("simulated access denied")
        ):
            result = hardware.ReadOnlyRunner()([sys.executable, "--version"])
        self.assertEqual(result.status, "ERROR")
        self.assertIn("access denied", result.error)

    def test_windows_report_never_fabricates_linux_evidence(self):
        runner = Mock()
        report = hardware.collect(runner, platform="win32")
        runner.assert_not_called()
        self.assertFalse(report["linux_supported"])
        self.assertTrue(any("Kali/Linux" in line for line in report["limitations"]))

    def test_bluez_variants_ignore_remote_devices(self):
        raw = json.dumps(
            {
                "data": [
                    {
                        "/org/bluez/hci0": {
                            "org.bluez.Adapter1": {
                                "Name": {"type": "s", "data": "SIMULATED ADAPTER"},
                                "Powered": {"type": "b", "data": True},
                                "UUIDs": {
                                    "type": "as",
                                    "data": ["0000110a-0000-1000-8000-00805f9b34fb"],
                                },
                            }
                        },
                        "/org/bluez/hci0/dev_00": {"org.bluez.Device1": {}},
                    }
                ]
            }
        )
        self.assertEqual(len(hardware.bluez_adapters(raw)), 1)
        self.assertTrue(hardware.bluez_adapters(raw)[0]["powered"])
        for malformed in ("invalid", "{}", '{"data":[null]}'):
            self.assertEqual(hardware.bluez_adapters(malformed), [])

    def test_runner_reports_missing_budget_error_timeout_and_truncation(self):
        runner = hardware.ReadOnlyRunner(timeout=0.2, budget=5, output_limit=32)
        self.assertEqual(runner(["polterheist-no-such-tool"]).status, "MISSING")
        self.assertEqual(runner([sys.executable, "-c", "raise SystemExit(2)"]).status, "ERROR")
        self.assertEqual(
            runner([sys.executable, "-c", "import time; time.sleep(5)"]).status, "TIMEOUT"
        )
        result = runner([sys.executable, "-c", "print('x' * 10000)"])
        self.assertEqual(result.status, "TRUNCATED")
        self.assertEqual(len(result.output), 32)
        self.assertEqual(hardware.ReadOnlyRunner(budget=0)([sys.executable]).status, "SKIPPED")

    def test_cli_diagnostics_runs_independently_of_network_selection(self):
        with (
            patch.object(script, "tv_diagnostics", return_value=0) as run,
            patch.object(cli, "detect_network") as detect,
        ):
            self.assertEqual(script.main(["--tv-diagnostics"]), 0)
            run.assert_called_once()
            detect.assert_not_called()
        with self.assertRaises(SystemExit):
            script.main(["--tv-diagnostics", "--setup"])


class ScopeTests(QuietTest):
    def test_small_cidr_expands_and_large_scope_is_rejected_before_probing(self):
        self.assertEqual(scopes.expand_scope("192.0.2.0/30"), ("192.0.2.1", "192.0.2.2"))
        for scope in (
            "0.0.0.0/0",
            "192.0.2.0/24",
            "192.0.2.3/30",
            "::1",
            "127.0.0.1",
            "224.0.0.1",
            "0.0.0.0",
            "bad;command",
            "999.3.4.5",
        ):
            with self.subTest(scope=scope), self.assertRaises(ValueError):
                scopes.expand_scope(scope)

    def test_dns_is_resolved_once_deduplicated_and_pinned(self):
        resolver = Mock(return_value=["192.0.2.2", "192.0.2.1", "192.0.2.2"])
        self.assertEqual(
            scopes.expand_scope("tv.example", resolver=resolver), ("192.0.2.1", "192.0.2.2")
        )
        resolver.assert_called_once_with("tv.example")
        with self.assertRaises(ValueError):
            scopes.expand_scope("tv.example", max_hosts=1, resolver=resolver)

    def test_route_selection_does_not_send_packets_and_scopes_urls_to_peer(self):
        sock = Mock()
        sock.getsockname.return_value = ("198.51.100.10", 48000)
        with patch.object(socket, "socket") as factory:
            factory.return_value.__enter__.return_value = sock
            target = scopes.route_to("198.51.100.4")
        sock.send.assert_not_called()
        sock.sendto.assert_not_called()
        self.assertTrue(target.accepts("198.51.100.4"))
        self.assertFalse(target.accepts("198.51.100.5"))
        checked_url("http://198.51.100.4:8008/device", "198.51.100.4", target)
        with self.assertRaises(ValueError):
            checked_url("http://198.51.100.5/device", "198.51.100.4", target)

    def test_resolver_timeout_is_bounded(self):
        released = threading.Event()
        with patch.object(socket, "getaddrinfo", side_effect=lambda *a: (released.wait(1), [])[1]):
            try:
                with self.assertRaises(TimeoutError):
                    scopes.resolve_hostname("tv.example", timeout=0.01)
            finally:
                released.set()


class BonjourTests(QuietTest):
    def info(self, service=airplay.SERVICES[0]):
        return SimpleNamespace(
            name="SIMULATED RECEIVER." + service,
            port=7000,
            properties={b"model": b"Fixture", b"pw": b"true", b"secret": b"omit"},
            parsed_addresses=lambda: ["192.0.2.1", "fe80::1234"],
        )

    def test_airplay_keeps_ipv6_metadata_and_separate_auth_evidence(self):
        endpoint = airplay.from_service(self.info(), LAN, airplay.SERVICES[0])
        self.assertFalse(endpoint.controllable)
        self.assertIn("fe80::1234", endpoint.addresses)
        self.assertNotIn("secret", endpoint.details["advertised_txt"])
        self.assertIn("PASSWORD", endpoint.authentication)
        self.assertNotIn("READY", endpoint.note.upper())

    def test_raop_remains_audio_only_and_outside_subnet_is_ignored(self):
        info = self.info(airplay.SERVICES[1])
        endpoint = airplay.from_service(info, LAN, airplay.SERVICES[1])
        self.assertEqual(endpoint.kind, "Audio receiver")
        self.assertFalse(endpoint.controllable)
        info.parsed_addresses = lambda: ["198.51.100.1"]
        self.assertIsNone(airplay.from_service(info, LAN, airplay.SERVICES[1]))

    def test_bonjour_browser_is_closed_after_discovery(self):
        import zeroconf

        zc, browser = Mock(), Mock()
        zc.get_service_info.return_value = self.info()

        def create(zc, services, listener):
            listener.add_service(zc, services[0], "SIMULATED RECEIVER")
            return browser

        with (
            patch.object(zeroconf, "Zeroconf", return_value=zc),
            patch.object(zeroconf, "ServiceBrowser", side_effect=create),
        ):
            found = airplay.discover(LAN, CONFIG)
        self.assertEqual(len(found), 1)
        browser.cancel.assert_called_once()
        zc.close.assert_called_once()


class EngineTests(QuietTest):
    def endpoint(self, ip="192.0.2.1"):
        return Endpoint(
            "Google Cast", "simulated", ip, 8009, "SIMULATED RECEIVER", controllable=True
        )

    def test_registry_isolates_failures_and_disabled_backends(self):
        disabled = Mock()
        backends = [
            DiscoveryBackend(
                "cast", "Cast fixture", Mock(side_effect=TimeoutError("fixture timeout"))
            ),
            DiscoveryBackend("upnp", "UPnP fixture", Mock(return_value=[self.endpoint()])),
            DiscoveryBackend("airplay", "Disabled fixture", disabled),
        ]
        engine = Discovery(LAN, replace(CONFIG, discovery_backends=("cast", "upnp")), backends)
        engine.scan()
        self.assertEqual(len(engine.devices), 1)
        self.assertEqual({r["status"] for r in engine.results}, {"ERROR", "DETECTED"})
        disabled.assert_not_called()

    def test_directed_requires_confirmation_and_does_not_enable_routed_playback(self):
        target = scopes.DirectedNetwork(
            "SIMULATED ROUTE", LAN.ip, ipaddress.IPv4Network("198.51.100.1/32"), "198.51.100.1"
        )
        probe = Mock(return_value=[self.endpoint(target.peer)])
        engine = Discovery(LAN, CONFIG, [DiscoveryBackend("cast", "Fixture", probe, True)])
        with self.assertRaises(ValueError):
            engine.scan_directed([target])
        probe.assert_not_called()
        engine.scan_directed([target], confirmed=True)
        self.assertFalse(engine.devices[1].controllable)
        self.assertIn("return route unverified", engine.devices[1].primary.note)

    def test_no_response_invalidates_old_scoped_device_but_preserves_others(self):
        target = scopes.DirectedNetwork("SIMULATED ROUTE", LAN.ip, LAN.subnet, "192.0.2.1")
        engine = Discovery(
            LAN, CONFIG, [DiscoveryBackend("cast", "Fixture", lambda *args: [], True)]
        )
        engine.merge([self.endpoint(), replace(self.endpoint("192.0.2.2"), uid="other")])
        engine.scan_directed([target], confirmed=True)
        self.assertFalse(engine.devices[1].available)
        self.assertTrue(engine.devices[2].available)

    def test_out_of_scope_backend_results_are_rejected(self):
        engine = Discovery(
            LAN,
            CONFIG,
            [DiscoveryBackend("cast", "Fixture", lambda *args: [self.endpoint("198.51.100.1")])],
        )
        self.assertEqual(engine.scan(), [])

    def test_cancellation_discards_queued_targets(self):
        calls = []

        def probe(network, config, target):
            calls.append(target)
            if len(calls) == 1:
                raise KeyboardInterrupt
            threading.Event().wait(0.1)
            return []

        config = replace(CONFIG, directed_workers=1)
        engine = Discovery(LAN, config, [DiscoveryBackend("cast", "SIMULATED", probe, True)])
        networks = [
            scopes.DirectedNetwork("SIMULATED", LAN.ip, LAN.subnet, f"192.0.2.{i}")
            for i in range(20, 36)
        ]
        with self.assertRaises(KeyboardInterrupt):
            engine.scan_directed(networks, confirmed=True)
        self.assertLess(len(calls), len(networks))
        self.assertEqual(engine.devices, {})

    def test_export_contains_evidence_and_serializes_protocol_sets(self):
        engine = Discovery(LAN, CONFIG)
        endpoint = self.endpoint()
        endpoint.details["actions"] = {"Play", "Stop"}
        engine.merge([endpoint])
        report = json.loads(engine.export(self.root).read_text(encoding="utf-8"))
        self.assertEqual(
            report["devices"][0]["endpoints"][0]["details"]["actions"], ["Play", "Stop"]
        )
        self.assertTrue(report["limitations"])

    def test_config_rejects_unknown_or_unbounded_backends_and_scope(self):
        for kwargs in (
            {"discovery_backends": ["miracast"]},
            {"discovery_backends": "cast"},
            {"discovery_backends": []},
            {"discovery_backends": ["cast", "cast"]},
            {"directed_max_hosts": 100000},
            {"directed_workers": True},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                Config(**kwargs)

    def test_single_playback_requires_confirmation_before_any_side_effect(self):
        receiver = Device(1, [self.endpoint()])
        manager = Manager(self.root, LAN, CONFIG)
        self.addCleanup(manager.close)
        with patch.object(manager.library, "inspect") as inspect:
            with self.assertRaisesRegex(ValueError, "confirmation"):
                manager.start([receiver], self.root / "not-opened.mp4")
            inspect.assert_not_called()
        with patch("builtins.input", return_value=""):
            self.assertFalse(cli.confirm_playback([receiver]))
        with patch("builtins.input", return_value="y"):
            self.assertTrue(cli.confirm_playback([receiver]))

    def test_directed_cli_cancellation_never_runs_discovery(self):
        app = object.__new__(cli.Application)
        app.discovery = Mock()
        app.discovery.prepare_scope.return_value = [SimpleNamespace(ip=LAN.ip, peer="192.0.2.1")]
        with patch("builtins.input", side_effect=["192.0.2.1", ""]):
            app.directed()
        app.discovery.scan_directed.assert_not_called()


class DialTests(QuietTest):
    def describe(self, xml=DIAL_XML, application_url="http://192.0.2.1/apps/"):
        def request(*args, response_headers=None, **kwargs):
            if response_headers is not None:
                response_headers["application-url"] = application_url
            return 200, xml

        with patch.object(dlna, "local_request", side_effect=request):
            return dlna.describe(
                "http://192.0.2.1/device.xml", "192.0.2.1", LAN, CONFIG, include_other=True
            )

    def test_dial_identity_does_not_imply_media_control(self):
        endpoint = self.describe()[0]
        self.assertEqual(endpoint.protocol, "DIAL")
        self.assertEqual(endpoint.reachability, "HTTP REACHABLE")
        self.assertFalse(endpoint.controllable)
        self.assertIn("application_url", endpoint.details)

    def test_dial_service_and_renderer_are_both_preserved(self):
        xml = DIAL_XML.replace(
            b"urn:dial-multiscreen-org:device:dialreceiver:1",
            b"urn:schemas-upnp-org:device:MediaRenderer:1",
        )
        self.assertEqual({endpoint.protocol for endpoint in self.describe(xml)}, {"DIAL", "DLNA"})

    def test_foreign_application_url_is_never_followed(self):
        endpoint = self.describe(application_url="http://198.51.100.1/apps/")[0]
        self.assertNotIn("application_url", endpoint.details)
        self.assertTrue(any("Rejected" in evidence for evidence in endpoint.evidence))

    def test_generic_upnp_device_is_not_classified_as_tv(self):
        xml = DIAL_XML.replace(
            b"urn:dial-multiscreen-org:device:dialreceiver:1",
            b"urn:schemas-upnp-org:device:InternetGatewayDevice:1",
        ).replace(
            b"urn:dial-multiscreen-org:service:dial:1",
            b"urn:schemas-upnp-org:service:WANIPConnection:1",
        )
        endpoint = self.describe(xml)[0]
        self.assertEqual(endpoint.protocol, "UPnP")
        self.assertFalse(endpoint.controllable)
        self.assertIn("not necessarily a TV", endpoint.kind)

    def test_simulated_ssdp_and_dial_http_receiver_end_to_end(self):
        requests = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(self.path)
                self.send_response(200)
                self.send_header(
                    "Application-URL", f"http://127.0.0.1:{self.server.server_port}/apps/"
                )
                self.send_header("Content-Length", str(len(DIAL_XML)))
                self.end_headers()
                self.wfile.write(DIAL_XML)

            def log_message(self, *args):
                pass

        class SimulatedNetwork(Network):
            # Only this fixture permits loopback receivers; production never does.
            def accepts(self, ip):
                return ip == "127.0.0.1"

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.bind(("127.0.0.1", 0))
        udp.settimeout(2)
        self.addCleanup(udp.close)

        def ssdp_simulator():
            packet, peer = udp.recvfrom(16384)
            if packet.startswith(b"M-SEARCH"):
                udp.sendto(
                    (
                        f"HTTP/1.1 200 OK\r\nST: urn:dial-multiscreen-org:service:dial:1\r\n"
                        f"USN: uuid:simulated-dial\r\nLOCATION: http://127.0.0.1:{server.server_port}/device.xml\r\n\r\n"
                    ).encode(),
                    peer,
                )

        responder = threading.Thread(target=ssdp_simulator, daemon=True)
        responder.start()
        local = SimulatedNetwork(
            "SIMULATED LOOPBACK", "127.0.0.1", ipaddress.IPv4Network("127.0.0.0/8")
        )
        with patch.object(dlna, "SSDP", udp.getsockname()):
            found = dlna.discover(local, replace(CONFIG, discovery_timeout=0.3, request_timeout=1))
        responder.join(timeout=2)
        self.assertFalse(responder.is_alive())
        self.assertEqual([endpoint.protocol for endpoint in found], ["DIAL"])
        self.assertEqual(requests, ["/device.xml"])
        self.assertFalse(found[0].controllable)


if __name__ == "__main__":
    unittest.main()
