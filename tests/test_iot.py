"""SIMULATED advertisements and loopback servers; never scans a physical LAN."""

import contextlib
import io
import ipaddress
import json
import logging
import socket
import ssl
import tempfile
import threading
import unittest
import xml.etree.ElementTree as ET
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import script
from tv_control import cli, iot
from tv_control.discovery import Discovery, select_devices
from tv_control.discovery_backends import DiscoveryBackend, builtins
from tv_control.models import Config, Device, Endpoint
from tv_control.network import Network
from tv_control.protocols import coap, iot_mdns, mqtt, onvif
from tv_control.security import assess

LAN = Network("SIMULATED", "192.0.2.10", ipaddress.IPv4Network("192.0.2.0/24"))
CONFIG = Config(discovery_timeout=0.1, request_timeout=0.1, connect_timeout=0.5)
LOOPBACK = SimpleNamespace(ip="127.0.0.1", accepts=lambda ip: ip == "127.0.0.1")


def service(kind="_hap._tcp.local.", properties=None, addresses=None, name="SIMULATED device"):
    return SimpleNamespace(
        port=54321,
        name=name + "." + kind,
        properties=properties or {},
        parsed_addresses=lambda: addresses if addresses is not None else ["192.0.2.20"],
    )


def mdns(kind="_hap._tcp.local.", **kwargs):
    return iot_mdns.from_service(service(kind, **kwargs), LAN, kind)


def reply(
    identifier="urn:uuid:SIMULATED-request",
    url="http://192.0.2.20/onvif/device_service",
    namespace="http://www.onvif.org/ver10/network/wsdl",
    scopes=True,
):
    scope = (
        "onvif://www.onvif.org/name/SIMULATED%20Camera onvif://www.onvif.org/hardware/TEST-MODEL"
        if scopes
        else ""
    )
    return f'''<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
      xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
      xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:dn="{namespace}">
      <s:Header><a:RelatesTo>{identifier}</a:RelatesTo>
      <a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches</a:Action></s:Header>
      <s:Body><d:ProbeMatches><d:ProbeMatch>
      <a:EndpointReference><a:Address>urn:uuid:SIMULATED-camera</a:Address></a:EndpointReference>
      <d:Types>dn:NetworkVideoTransmitter</d:Types><d:Scopes>{scope}</d:Scopes>
      <d:XAddrs>{url}</d:XAddrs></d:ProbeMatch></d:ProbeMatches></s:Body></s:Envelope>'''.encode()


class QuietTest(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.output = self.enterContext(contextlib.redirect_stdout(io.StringIO()))
        self.enterContext(patch.object(logging.getLogger("tv_control.discovery"), "exception"))


class MdnsTests(QuietTest):
    def test_homekit_category_provides_type_without_claiming_control(self):
        for category, expected in (
            ("5", "Light"),
            ("7", "Smart plug / outlet"),
            ("10", "Sensor"),
            ("17", "Camera"),
            ("31", "Television"),
        ):
            with self.subTest(category=category):
                endpoint = mdns(properties={b"ci": category.encode(), b"md": b"SIMULATED model"})
                self.assertEqual(iot.device_type(endpoint), expected)
                self.assertFalse(endpoint.controllable)
                self.assertIn("PAIRING", iot.access(endpoint))
                self.assertEqual(endpoint.manufacturer, "Unknown")

    def test_unknown_category_and_tv_name_do_not_fabricate_device_type(self):
        endpoint = mdns(properties={b"ci": b"999"}, name="Samsung TV SIMULATED")
        self.assertEqual(iot.device_type(endpoint), "HomeKit accessory")
        endpoint = mdns("_http._tcp.local.", name="SIMULATED Camera")
        self.assertIn("unknown", iot.device_type(endpoint))
        self.assertIn("WEB INTERFACE", iot.access(endpoint))
        self.assertEqual(endpoint.details["web_url"], "http://192.0.2.20:54321/")

    def test_printer_shelly_esphome_and_broker_are_distinct(self):
        for service_type, expected in (
            ("_ipp._tcp.local.", "Printer"),
            ("_shelly._tcp.local.", "Smart home"),
            ("_esphomelib._tcp.local.", "IoT node"),
            ("_mqtt._tcp.local.", "broker"),
            ("_home-assistant._tcp.local.", "hub"),
        ):
            with self.subTest(service=service_type):
                endpoint = mdns(service_type)
                self.assertIn(expected, iot.device_type(endpoint))
                self.assertFalse(endpoint.controllable)

    def test_matter_dns_label_does_not_trigger_tcp_or_claim_access(self):
        for service_type in ("_matter._tcp.local.", "_matterc._udp.local.", "_matterd._udp.local."):
            endpoint = mdns(service_type)
            self.assertEqual(iot.tcp_candidates(Device(1, [endpoint]), LAN), {})
            self.assertIn("CREDENTIALS", endpoint.authentication)

    def test_txt_secrets_are_not_exported(self):
        endpoint = mdns(
            properties={
                b"ci": b"5",
                b"password": b"SECRET",
                b"token": b"SECRET",
                b"md": b"x" * 1024,
            }
        )
        self.assertNotIn("SECRET", json.dumps(endpoint.details))
        self.assertEqual(len(endpoint.model), 256)

    def test_invalid_ports_names_and_foreign_ipv4_are_rejected(self):
        for port in (0, -1, 65536, True, "80"):
            info = service()
            info.port = port
            self.assertIsNone(iot_mdns.from_service(info, LAN, "_hap._tcp.local."))
        self.assertIsNone(mdns(addresses=["198.51.100.10", "fe80::10"]))
        self.assertIsNone(mdns(addresses=["127.0.0.1", "224.0.0.1"]))
        self.assertIsNone(mdns("_unknown._tcp.local."))
        info = service()
        info.name = "wrong suffix"
        self.assertIsNone(iot_mdns.from_service(info, LAN, "_hap._tcp.local."))

    def test_ipv6_only_observation_survives_inventory_without_control(self):
        endpoint = mdns("_matterc._udp.local.", addresses=["fe80::1234"])
        self.assertEqual(endpoint.ip, "")
        self.assertIn("IPv6", iot.access(endpoint))
        backend = DiscoveryBackend("iot_mdns", "SIMULATED", lambda *_: [endpoint])
        registry = Discovery(LAN, CONFIG, [backend])
        registry.scan()
        self.assertEqual(len(registry.devices), 1)
        self.assertEqual(iot.tcp_candidates(registry.devices[1], LAN), {})

    def test_browser_is_bounded_handles_removal_and_always_closes(self):
        # SIMULATED DNS-SD transport. Full regression separately loads the installed library.
        zeroconf = SimpleNamespace(
            Zeroconf=Mock(), ServiceBrowser=Mock(), IPVersion=SimpleNamespace(V4Only=4)
        )
        zc, browser = Mock(), Mock()
        zc.get_service_info.side_effect = [service(), service(name="SIMULATED removed")]

        def create(zc, services, listener):
            listener.add_service(zc, services[0], "first")
            listener.add_service(zc, services[0], "removed")
            listener.remove_service(zc, services[0], "removed")
            return browser

        with (
            patch.dict("sys.modules", {"zeroconf": zeroconf}),
            patch.object(zeroconf, "Zeroconf", return_value=zc),
            patch.object(zeroconf, "ServiceBrowser", side_effect=create),
        ):
            found = iot_mdns.discover(LAN, CONFIG)
        self.assertEqual(len(found), 1)
        browser.cancel.assert_called_once()
        zc.close.assert_called_once()

    def test_zeroconf_closes_if_browser_creation_fails(self):
        zeroconf = SimpleNamespace(
            Zeroconf=Mock(), ServiceBrowser=Mock(), IPVersion=SimpleNamespace(V4Only=4)
        )
        zc = Mock()
        with (
            patch.dict("sys.modules", {"zeroconf": zeroconf}),
            patch.object(zeroconf, "Zeroconf", return_value=zc),
            patch.object(zeroconf, "ServiceBrowser", side_effect=OSError("SIMULATED")),
        ):
            with self.assertRaises(OSError):
                iot_mdns.discover(LAN, CONFIG)
        zc.close.assert_called_once()


class OnvifTests(QuietTest):
    def test_camera_is_classified_by_advertisement_not_authenticated(self):
        (endpoint,) = onvif.from_packet(reply(), "192.0.2.20", LAN, "urn:uuid:SIMULATED-request")
        self.assertEqual(endpoint.name, "SIMULATED Camera")
        self.assertEqual(endpoint.model, "TEST-MODEL")
        self.assertEqual(endpoint.port, 80)
        self.assertIn("Camera", iot.device_type(endpoint))
        self.assertFalse(endpoint.controllable)
        self.assertIn("CREDENTIALS", endpoint.authentication)

    def test_unsolicited_foreign_or_non_onvif_responses_are_ignored(self):
        self.assertEqual(onvif.from_packet(reply(), "192.0.2.20", LAN, "different request"), [])
        self.assertEqual(
            onvif.from_packet(reply(), "198.51.100.20", LAN, "urn:uuid:SIMULATED-request"), []
        )
        packet = reply(namespace="https://example.invalid/fake", scopes=False)
        self.assertEqual(
            onvif.from_packet(packet, "192.0.2.20", LAN, "urn:uuid:SIMULATED-request"), []
        )

    def test_untrusted_urls_cannot_change_target_or_expose_credentials(self):
        for url in (
            "http://198.51.100.1/a",
            "http://name.local/a",
            "http://user:secret@192.0.2.20/a",
            "file:///a",
            "http://192.0.2.20:0/a",
            "http://192.0.2.20:65536/a",
        ):
            with self.subTest(url=url):
                self.assertEqual(
                    onvif.from_packet(
                        reply(url=url), "192.0.2.20", LAN, "urn:uuid:SIMULATED-request"
                    ),
                    [],
                )

    def test_https_advertisement_preserves_actual_port(self):
        (endpoint,) = onvif.from_packet(
            reply(url="https://192.0.2.20/onvif"), "192.0.2.20", LAN, "urn:uuid:SIMULATED-request"
        )
        self.assertEqual(endpoint.port, 443)

    def test_oversized_and_entity_packets_are_rejected(self):
        self.assertEqual(onvif.from_packet(b"x" * 65536, "192.0.2.20", LAN, "id"), [])
        with self.assertRaises(ValueError):
            onvif.from_packet(b'<!DOCTYPE a [<!ENTITY x "bad">]><a/>', "192.0.2.20", LAN, "id")

    def test_real_udp_loopback_probe_and_correlated_response(self):
        server = self.enterContext(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        server.bind(("127.0.0.1", 0))
        server.settimeout(2)
        received = []

        def serve():
            packet, address = server.recvfrom(65536)
            received.append(packet)
            identifier = ET.fromstring(packet).findtext(
                f"{{{onvif.SOAP}}}Header/{{{onvif.WSA}}}MessageID"
            )
            server.sendto(reply(identifier, "http://127.0.0.1/onvif"), address)

        worker = threading.Thread(target=serve)
        worker.start()
        try:
            with patch.object(onvif, "DESTINATION", server.getsockname()):
                found = onvif.discover(LOOPBACK, replace(CONFIG, discovery_timeout=0.3))
        finally:
            worker.join(timeout=3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(len(found), 1)
        self.assertIn(b"Probe", received[0])


class ConnectionTests(QuietTest):
    def test_tcp_reachable_does_not_promote_control_or_authentication(self):
        server = self.enterContext(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        server.settimeout(1)
        endpoint = mdns()
        endpoint.ip, endpoint.port = server.getsockname()
        (result,) = iot.check_connections(Device(1, [endpoint]), LOOPBACK, CONFIG, confirmed=True)
        accepted, _ = server.accept()
        with accepted:
            accepted.settimeout(1)
            self.assertEqual(accepted.recv(1), b"")
        self.assertEqual(result["status"], "TCP REACHABLE")
        self.assertFalse(endpoint.controllable)
        self.assertIn("PAIRING", iot.access(endpoint))

    def test_checks_require_selection_and_skip_out_of_scope_or_stale(self):
        device = Device(1, [mdns()])
        with patch.object(iot.socket, "socket") as create:
            with self.assertRaises(ValueError):
                iot.check_connections(device, LAN, CONFIG)
            device.available = False
            with self.assertRaises(ValueError):
                iot.check_connections(device, LAN, CONFIG, confirmed=True)
            device.available = True
            device.primary.ip = "198.51.100.1"
            self.assertEqual(iot.check_connections(device, LAN, CONFIG, confirmed=True), [])
            create.assert_not_called()

    def test_connection_refusal_is_recorded_without_login_or_retries(self):
        channel = Mock()
        channel.__enter__ = Mock(return_value=channel)
        channel.__exit__ = Mock(return_value=False)
        channel.connect.side_effect = ConnectionRefusedError("SIMULATED refusal")
        with patch.object(iot.socket, "socket", return_value=channel):
            (result,) = iot.check_connections(Device(1, [mdns()]), LAN, CONFIG, confirmed=True)
        self.assertEqual(result["status"], "TCP UNREACHABLE")
        channel.connect.assert_called_once()
        channel.send.assert_not_called()
        channel.__exit__.assert_called_once()

    def test_connection_check_has_four_port_limit_and_deduplicates(self):
        endpoints = [replace(mdns(), port=5000 + i) for i in range(6)]
        endpoints.append(replace(endpoints[0]))
        with patch.object(iot.socket, "socket") as create:
            results = iot.check_connections(Device(1, endpoints), LAN, CONFIG, confirmed=True)
        self.assertEqual(create.call_count, 4)
        self.assertEqual(len(results), 6)
        self.assertEqual(sum(r["status"] == "NOT CHECKED" for r in results), 2)


class CoapTests(QuietTest):
    TOKEN = b"TEST"

    def packet(
        self,
        code=69,
        options=b"\xc1\x28",
        payload=b'</temperature>;rt="temperature-c";title="SIMULATED, sensor"',
    ):
        return (
            b"\x54"
            + bytes([code])
            + b"\x00\x21"
            + self.TOKEN
            + options
            + (b"\xff" + payload if payload else b"")
        )

    def test_directory_resource_is_evidence_not_control_permission(self):
        endpoint = coap.from_packet(self.packet(), "192.0.2.20", 5683, LAN, self.TOKEN)
        self.assertEqual(endpoint.details["resources"][0]["target"], "/temperature")
        self.assertEqual(
            endpoint.details["resources"][0]["attributes"]["title"], "SIMULATED, sensor"
        )
        self.assertFalse(endpoint.controllable)
        self.assertIn("AUTH UNKNOWN", endpoint.authentication)
        self.assertEqual(iot.tcp_candidates(Device(1, [endpoint]), LAN), {})

    def test_unauthorized_directory_is_reported_without_retry(self):
        endpoint = coap.from_packet(self.packet(129, b"", b""), "192.0.2.20", 5683, LAN, self.TOKEN)
        self.assertIn("REQUIRES AUTHORIZATION", endpoint.authentication)
        self.assertEqual(endpoint.details["resources"], [])

    def test_unrelated_truncated_oversized_and_invalid_options_are_rejected(self):
        packets = [
            b"",
            self.packet().replace(self.TOKEN, b"NONE"),
            self.packet()[:6],
            b"x" * 16385,
            self.packet(options=b"\xf0"),
            self.packet(options=b"\xcd"),
            self.packet(options=b"\xc1\x28\xff", payload=b""),
        ]
        for packet in packets:
            with self.subTest(packet=packet[:12]), self.assertRaises(ValueError):
                coap.parse_response(packet, self.TOKEN)

    def test_partial_block_and_malformed_directory_never_become_complete(self):
        endpoint = coap.from_packet(
            self.packet(options=b"\xc1\x28\xb1\x08", payload=b'</temperature>;title="partial'),
            "192.0.2.20",
            5683,
            LAN,
            self.TOKEN,
        )
        self.assertTrue(endpoint.details["directory_partial"])
        self.assertTrue(endpoint.details["directory_error"])
        self.assertEqual(endpoint.details["resources"], [])

    def test_foreign_peer_is_ignored_before_parsing(self):
        self.assertIsNone(coap.from_packet(b"invalid", "198.51.100.1", 5683, LAN, self.TOKEN))

    def test_real_loopback_discovery_sends_only_directory_get(self):
        server = self.enterContext(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        server.bind(("127.0.0.1", 0))
        server.settimeout(2)
        requests = []

        def serve():
            packet, address = server.recvfrom(16384)
            requests.append(packet)
            server.sendto(self.packet().replace(self.TOKEN, packet[4:8]), address)

        worker = threading.Thread(target=serve)
        worker.start()
        try:
            with patch.object(coap, "DESTINATION", server.getsockname()):
                found = coap.discover(LOOPBACK, replace(CONFIG, discovery_timeout=0.3))
        finally:
            worker.join(timeout=3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(len(found), 1)
        self.assertEqual(requests[0][0:2], b"\x54\x01")
        self.assertEqual(requests[0][8:], b"\xbb.well-known\x04core\x61\x28")


class MqttTests(QuietTest):
    def session(self, response=b"\x20\x02\x00\x00", delay=0):
        server = self.enterContext(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        server.settimeout(2)
        observed, failures = [], []

        def serve():
            try:
                connection, _ = server.accept()
                with connection:
                    connection.settimeout(2)
                    header = connection.recv(2)
                    body = b""
                    while len(body) < header[1]:
                        chunk = connection.recv(header[1] - len(body))
                        if not chunk:
                            break
                        body += chunk
                    observed.append(header + body)
                    if delay:
                        threading.Event().wait(delay)
                    for value in response:
                        connection.sendall(bytes([value]))
                    observed.append(connection.recv(2))
            except OSError as error:
                failures.append(error)

        worker = threading.Thread(target=serve)
        worker.start()
        endpoint = mdns("_mqtt._tcp.local.")
        endpoint.ip, endpoint.port = server.getsockname()
        try:
            result = mqtt.check(endpoint, LOOPBACK, CONFIG, confirmed=True)
        finally:
            worker.join(timeout=3)
        self.assertFalse(worker.is_alive())
        return endpoint, result, observed, failures

    def test_real_loopback_connect_and_disconnect_without_publish(self):
        endpoint, result, packets, failures = self.session()
        self.assertEqual(failures, [])
        self.assertEqual(result["return_code"], 0)
        self.assertTrue(result["disconnect_sent"])
        self.assertFalse(result["credentials_sent"])
        self.assertEqual(packets[0][2:12], b"\x00\x04MQTT\x04\x02\x00\x0a")
        self.assertEqual(packets[1], b"\xe0\x00")
        self.assertFalse(endpoint.controllable)

    def test_rejection_is_reported_without_retry_or_publish(self):
        _, result, packets, failures = self.session(b"\x20\x02\x00\x05")
        self.assertEqual(result["status"], "NOT AUTHORIZED")
        self.assertEqual(packets[1], b"")
        self.assertEqual(failures, [])

    def test_invalid_connack_does_not_count_as_accepted(self):
        _, result, _, _ = self.session(b"\x20\x02\x01\x00")
        self.assertEqual(result["status"], "CHECK FAILED")
        self.assertIsNone(result["return_code"])

    def test_deadline_closes_connection_without_infinite_wait(self):
        _, result, _, _ = self.session(delay=0.7)
        self.assertEqual(result["status"], "CHECK FAILED")
        self.assertFalse(result["disconnect_sent"])

    def test_tls_verification_failure_never_falls_back_to_plaintext(self):
        endpoint = mdns("_secure-mqtt._tcp.local.")
        channel, context = Mock(), Mock()
        context.wrap_socket.side_effect = ssl.SSLCertVerificationError(
            "SIMULATED invalid certificate"
        )
        with (
            patch.object(mqtt.socket, "socket", return_value=channel),
            patch.object(mqtt.ssl, "create_default_context", return_value=context) as create,
        ):
            result = mqtt.check(endpoint, LAN, CONFIG, confirmed=True)
        self.assertEqual(result["status"], "TLS FAILED")
        self.assertFalse(result["tls_verified"])
        create.assert_called_once_with()
        channel.connect.assert_called_once()
        channel.sendall.assert_not_called()
        channel.close.assert_called_once()

    def test_no_selection_or_foreign_target_has_no_side_effects(self):
        endpoint = mdns("_mqtt._tcp.local.")
        with patch.object(mqtt.socket, "socket") as create:
            with self.assertRaises(ValueError):
                mqtt.check(endpoint, LAN, CONFIG)
            endpoint.ip = "198.51.100.1"
            with self.assertRaises(ValueError):
                mqtt.check(endpoint, LAN, CONFIG, confirmed=True)
            create.assert_not_called()

    def test_security_report_does_not_claim_cve_or_topic_access(self):
        endpoint, _, _, _ = self.session()
        report = assess(Device(1, [endpoint]))
        self.assertEqual(report["findings"][0]["kind"], "EXPOSURE")
        self.assertFalse(report["cve_matching_performed"])
        self.assertFalse(report["exploit_executed"])
        self.assertIn("not tested", report["findings"][0]["meaning"])

    def test_empty_findings_do_not_certify_security(self):
        report = assess(Device(1, [mdns()]))
        self.assertEqual(report["findings"], [])
        self.assertIn("No findings does not mean", report["limitations"][0])


class InventoryAndMenuTests(QuietTest):
    def test_registry_defaults_and_legacy_config_both_work(self):
        self.assertEqual({b.key for b in builtins()}, set(Config().discovery_backends))
        config = replace(CONFIG, discovery_backends=("cast", "upnp", "airplay"))
        self.assertEqual(len(Discovery(LAN, config).enabled()), 3)

    def test_upnp_type_is_used_and_name_alone_is_not(self):
        endpoint = Endpoint(
            "UPnP",
            "SIMULATED",
            "192.0.2.20",
            80,
            "SIMULATED Television",
            details={"device_type": "urn:schemas-upnp-org:device:BinaryLight:1"},
        )
        self.assertEqual(iot.device_type(endpoint), "Light")
        endpoint.details.clear()
        self.assertIn("unknown", iot.device_type(endpoint))

    def test_only_media_receivers_can_enter_existing_playback_flow(self):
        device = Device(1, [mdns()])
        media = Device(
            2, [Endpoint("DLNA", "SIMULATED-media", "192.0.2.21", 8000, controllable=True)]
        )
        self.assertEqual(select_devices([device, media]), [media])
        with self.assertRaises(ValueError):
            select_devices([device, media], "1")

    def test_generic_same_ip_web_does_not_hide_specific_iot_type(self):
        registry = Discovery(LAN, CONFIG)
        registry.merge([mdns(properties={b"ci": b"7"}), mdns("_http._tcp.local.")])
        self.assertEqual(len(registry.devices), 1)
        info = iot.summary(registry.devices[1])
        self.assertEqual(info["type"], "Smart plug / outlet")
        self.assertEqual(len(info["connection"]), 2)

    def test_export_contains_iot_type_and_explicit_connection_state(self):
        registry = Discovery(LAN, CONFIG)
        registry.merge([mdns(properties={b"ci": b"10"})])
        document = json.loads(registry.export(self.root).read_text(encoding="utf-8"))
        self.assertEqual(document["devices"][0]["iot_summary"]["type"], "Sensor")
        self.assertFalse(document["devices"][0]["iot_summary"]["control_available"])

    def application(self):
        with patch.object(cli, "detect_network", return_value=LAN):
            app = cli.Application(self.root)
        self.addCleanup(app.close)
        return app

    def test_entering_iot_menu_surveys_once_before_connection_options(self):
        app = self.application()
        with patch.object(app, "discover_all") as scan, patch("builtins.input", return_value="0"):
            app.run()
        scan.assert_called_once_with()
        self.assertIn("[1] Connect to all detected devices", self.output.getvalue())

    def test_detect_all_action_lists_type_and_connection_options(self):
        app = self.application()
        app.discovery.merge([mdns(properties={b"ci": b"5"})])
        with patch.object(app, "discover_all") as scan, patch("builtins.input", side_effect=["0"]):
            app.run()
        scan.assert_called_once_with()
        self.assertIn("Light", self.output.getvalue())
        self.assertIn("PAIRING", self.output.getvalue())
        self.assertIn("Connect / control", self.output.getvalue())

    def test_connectivity_action_is_manual_and_selected_by_id(self):
        app = self.application()
        app.discovery.merge([mdns()])
        with (
            patch.object(app, "discover_all"),
            patch.object(cli, "check_connections", return_value=[]) as check,
            patch("builtins.input", side_effect=["6", "1", "0"]),
        ):
            app.run()
        check.assert_called_once_with(
            app.discovery.devices[1], LAN, app.discovery.config, confirmed=True
        )

    def test_new_command_and_legacy_alias_enter_same_application(self):
        for flag in ("--iot-scan", "--tv-control"):
            with patch.object(script, "tv_control", return_value=None) as action:
                self.assertEqual(script.main([flag]), 0)
            action.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
