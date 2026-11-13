"""English CLI matching the existing application; no vendor APIs in menu code."""

import atexit
import json
import logging
from dataclasses import asdict, replace
from logging.handlers import RotatingFileHandler
from pathlib import Path

from .bluetooth import Bluetooth
from .connections import Connections, select_iot_devices
from .discovery import Discovery, select_devices
from .iot import access, check_connections, device_type, summary
from .manager import Manager
from .models import Config, safe_text
from .network import detect_network

_application = None


def configure_logging(root):
    folder = Path(root) / "reports" / "tv_control"
    folder.mkdir(parents=True, exist_ok=True)
    handler = RotatingFileHandler(
        folder / "tv_control.log", maxBytes=2_000_000, backupCount=2, encoding="utf-8"
    )
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    for name in ("tv_control", "pychromecast", "zeroconf"):
        logger = logging.getLogger(name)
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG if name == "tv_control" else logging.WARNING)
        logger.propagate = False
    return handler


def confirm_playback(devices):
    print(f"\n  You are about to start playback on {len(devices)} devices.")
    for device in devices:
        print(f"  [{device.id}] {safe_text(device.primary.name)} / {device.primary.ip}")
    return input("  Continue? [y/N]: ").strip().lower() == "y"


class Application:
    def __init__(self, root):
        self.root = Path(root)
        self.config = Config.load(root)
        self.network_error = ""
        try:
            self.network = detect_network(self.config.bind_ip)
        except RuntimeError as error:
            self.network = None
            self.network_error = str(error)
        self.discovery = Discovery(self.network, self.config)
        self.manager = Manager(root, self.network, self.config)
        self.bluetooth = Bluetooth(self.config)
        self.connections = Connections(self.network, self.config, self.bluetooth)
        self.handler = configure_logging(root)
        self.selected = []
        self.source = None

    def show_devices(self):
        print("\nDETECTED IoT DEVICES / SERVICES")
        print(
            "  ID  DEVICE                    TYPE                       ADDRESS                  CONNECT"
        )
        print("  " + "-" * 105)
        for device in self.discovery.devices.values():
            e = device.primary
            info = summary(device)
            address = (
                e.ip
                or e.details.get("p2p_address")
                or e.details.get("ble_address")
                or next(iter(e.addresses), "Unknown")
            )
            _, possible, reason = self.connections.route(device)
            print(
                f"  {device.id:<3} {safe_text(e.name)[:25]:25} {safe_text(info['type'])[:26]:26} {safe_text(address)[:24]:24} {possible}"
            )
            print("      " + safe_text(reason))
            print("      Protocols: " + safe_text(", ".join(info["protocols"])))
            print("      Connect / control: " + safe_text(" | ".join(info["connection"])))
            if len(device.endpoints) > 1:
                print("      Same-host grouping is provisional; physical identity is unverified.")
            for endpoint in device.endpoints:
                check = endpoint.details.get("connection_check")
                if check:
                    print(
                        f"      {safe_text(endpoint.protocol)}: {check['status']} ({check['observed_at']}); authentication unverified"
                    )
        count = sum(d.available for d in self.discovery.devices.values())
        print(f"  [+] {count} current devices/service groups; type based on advertisements.")
        if not self.discovery.devices:
            print("  No devices currently observed. Check radio/permission results and rescan.")
        print(
            "  * Connection can be attempted; success and authentication require a real response."
        )
        print("  Detection does not guarantee connectivity or control. Inspect an ID for details.")

    def scan(self, target=None):
        if self.network is None:
            raise ValueError(
                "No selected IPv4 LAN: " + self.network_error + "; use Wi-Fi Direct discovery"
            )
        print(
            f"  Discovering on {safe_text(self.network.name)}: {self.network.ip} / {self.network.subnet} ..."
        )
        print("  Enabled backends: " + ", ".join(self.discovery.config.discovery_backends))
        print("  Finds responding supported services on this LAN; silent devices may not appear.")
        self.discovery.scan(target)
        for warning in self.discovery.warnings:
            print("  [!] " + safe_text(warning))
        print("  Discovery report: " + str(self.discovery.export(self.root)))

    def discover_all(self):
        from .survey import survey

        self.bluetooth.config = self.discovery.config
        print("\n  Surveying LAN, Wi-Fi Direct and Bluetooth LE. Ctrl+C keeps partial results.")
        survey(self)

    def connect_iots(self, text=None):
        devices = select_iot_devices(list(self.discovery.devices.values()), text)
        if not devices:
            print("  No current devices to connect. Rescan first.")
            return
        print("  Attempting selected connections; no media playback or actuator commands.")
        for device in devices:
            result = self.connections.connect(device)
            print(f"  [{device.id}] {safe_text(device.primary.name)}: {result['state']}")
            print(
                "      "
                + safe_text(result["detail"])
                + (" — " + safe_text(result["error"]) if result["error"] else "")
            )
        print("  Connection report: " + str(self.discovery.export(self.root)))

    def directed(self):
        scope = input("  Authorized IPv4 / hostname / small CIDR [ENTER to cancel]: ").strip()
        if not scope:
            return
        networks = self.discovery.prepare_scope(scope)
        print("  Explicit scope (protocol probes, no pairing or playback):")
        for network in networks:
            print(f"    {network.ip} -> {network.peer}")
        if input("  Confirm this authorized scope? [y/N]: ").strip().lower() != "y":
            print("  Directed discovery cancelled.")
            return
        self.discovery.scan_directed(
            networks,
            confirmed=True,
            progress=lambda result: print(
                f"  {result['scope']} / {result['backend']}: {result['status']} ({result['elapsed_seconds']}s)"
            ),
        )
        for warning in self.discovery.warnings:
            print("  [!] " + safe_text(warning))
        print("  Discovery report: " + str(self.discovery.export(self.root)))

    def choose_device(self):
        identifier = input("  Device ID [ENTER to cancel]: ").strip()
        if not identifier:
            return
        if (
            not identifier.isascii()
            or not identifier.isdigit()
            or int(identifier) not in self.discovery.devices
        ):
            raise ValueError("Unknown device ID")
        return self.discovery.devices[int(identifier)]

    def inspect(self):
        device = self.choose_device()
        if device is None:
            return
        print("\nIoT CONNECTION OPTIONS")
        for endpoint in device.endpoints:
            print(f"  {safe_text(endpoint.protocol)} | {safe_text(device_type(endpoint))}")
            print("    " + safe_text(access(endpoint, device.available)))
            print("    Authentication: " + safe_text(endpoint.authentication))
            if endpoint.details.get("web_url"):
                print("    Advertised web address: " + safe_text(endpoint.details["web_url"]))
            if endpoint.controllable:
                print("    Use Media control to select content and confirm playback.")
        print(
            json.dumps(
                {**asdict(device), "iot_summary": summary(device)},
                ensure_ascii=True,
                indent=2,
                default=lambda value: sorted(value) if isinstance(value, set) else str(value),
            )
        )
        print("  Pairing and credentials are not tested by discovery or TCP checks.")

    def check_connection(self):
        print(
            "  Check up to four advertised TCP ports on one selected device; no login or control commands."
        )
        device = self.choose_device()
        if device is None:
            return
        results = check_connections(device, self.network, self.discovery.config, confirmed=True)
        if not results:
            print(
                "  No supported IPv4 TCP service to check. UDP, Matter and P2P require their own controller."
            )
        for result in results:
            print(
                f"  {result['ip']}:{result['port']}: {result['status']} "
                + safe_text(result["error"])
            )
        print("  TCP reachability does not establish login, pairing or permission to control.")
        print("  Connection evidence: " + str(self.discovery.export(self.root)))

    def configure_backends(self):
        print("  Available: cast, upnp, airplay, iot_mdns, onvif, coap")
        print("  Enabled: " + ", ".join(self.discovery.config.discovery_backends))
        names = input("  Comma-separated names [ENTER to keep]: ").strip()
        if names:
            config = replace(
                self.discovery.config,
                discovery_backends=tuple(name.strip() for name in names.split(",")),
            )
            self.discovery.config = config
            print("  Discovery configuration updated for this session. Refresh to apply.")
        print("  P2P backend: " + self.discovery.config.p2p_backend)
        backend = input("  P2P backend: networkmanager / supplicant [ENTER to keep]: ").strip()
        if backend:
            self.discovery.config = replace(self.discovery.config, p2p_backend=backend)
            print("  P2P discovery remains manual; no scan was started.")

    def check_mqtt(self):
        from .protocols import mqtt

        print(
            "  MQTT check: one temporary session without credentials; no subscription or publication."
        )
        device = self.choose_device()
        if device is None:
            return
        if not device.available:
            raise ValueError("Device is stale; repeat discovery first")
        endpoints = [e for e in device.endpoints if e.protocol in ("MQTT", "MQTT TLS")]
        if not endpoints:
            raise ValueError("This device has no advertised MQTT service")
        for index, endpoint in enumerate(endpoints, 1):
            print(f"  [{index}] {endpoint.protocol} {endpoint.ip}:{endpoint.port}")
        choice = input("  MQTT endpoint to test [0 Cancel]: ").strip()
        if choice in ("", "0"):
            return
        if not choice.isascii() or not choice.isdigit() or not 1 <= int(choice) <= len(endpoints):
            raise ValueError("Invalid MQTT endpoint")
        result = mqtt.check(
            endpoints[int(choice) - 1], self.network, self.discovery.config, confirmed=True
        )
        print(json.dumps(result, indent=2, ensure_ascii=True))
        print("  Session acceptance does not establish topic permissions or IoT control.")
        print("  Connection evidence: " + str(self.discovery.export(self.root)))

    def security_report(self):
        from .security import assess

        device = self.choose_device()
        if device is None:
            return
        print(json.dumps(assess(device), indent=2, ensure_ascii=True))
        print("  Security observations: " + str(self.discovery.export(self.root)))

    def targets(self):
        while True:
            self.show_devices()
            print(
                "\nSELECT TARGET DEVICES\n  [1] Connect to all detected media receivers\n"
                "  [2] Connect to specific receivers\n  [3] Refresh discovery\n"
                "  [4] Directed discovery by IP / hostname / CIDR\n"
                "  [5] Inspect capabilities\n  [6] Hardware diagnostics\n"
                "  [7] Configure discovery backends\n  [8] Wi-Fi Direct discovery\n"
                "  [9] Miracast receivers (WFD advertisements)\n"
                "  [10] Prepare Miracast / local presentation\n  [0] Back"
            )
            choice = input("  > ").strip()
            try:
                if choice == "0":
                    return None
                if choice == "3":
                    self.scan()
                elif choice == "4":
                    self.directed()
                elif choice == "5":
                    self.inspect()
                elif choice == "6":
                    from .hardware import run

                    run(self.root)
                elif choice == "7":
                    self.configure_backends()
                elif choice in ("8", "9", "10"):
                    from . import wireless_cli

                    {
                        "8": wireless_cli.discover,
                        "9": wireless_cli.receivers,
                        "10": wireless_cli.prepare,
                    }[choice](self)
                elif choice in ("1", "2"):
                    ids = None
                    if choice == "2":
                        ids = input(
                            "  Enter media receiver IDs (comma-separated), or 0 to go back: "
                        ).strip()
                        if ids == "0":
                            continue
                    return select_devices(list(self.discovery.devices.values()), ids)
                else:
                    print("  Invalid option.")
            except (ValueError, RuntimeError, OSError) as error:
                logging.getLogger(__name__).warning(
                    "TV selection action %s failed: %s", choice, error
                )
                print("  [!] " + safe_text(error))

    def media(self):
        while True:
            print("\nMEDIA SELECTION\n  [1] Image\n  [2] Video\n  [0] Back")
            choice = input("  > ").strip()
            if choice == "0":
                return None
            if choice not in ("1", "2"):
                print("  Invalid option.")
                continue
            kind = "image" if choice == "1" else "video"
            files = self.manager.library.list(kind)
            print(f"\nAVAILABLE {kind.upper()}S (project media/)")
            for index, path in enumerate(files, 1):
                print(f"  [{index}] {safe_text(path.name)}")
            if not files:
                print("  No files found. Copy media into the project's media/ directory.")
                continue
            answer = input("  Select file [0 Back]: ").strip()
            if answer == "0":
                continue
            try:
                if (
                    not answer.isascii()
                    or not answer.isdigit()
                    or not 1 <= int(answer) <= len(files)
                ):
                    raise ValueError("Invalid file ID")
                source = files[int(answer) - 1]
                self.manager.library.inspect(source)
                return source
            except (ValueError, RuntimeError, OSError) as error:
                print("  [!] " + safe_text(error))

    def start(self, devices, source):
        if source is None or not confirm_playback(devices):
            print("  Playback cancelled.")
            return False
        self.manager.start(devices, source, confirmed=True)
        self.selected, self.source = devices, source
        print(
            "  Preparing media and connecting independently. Use Playback status to follow progress."
        )
        return True

    def status(self):
        print("\nCASTING STATUS")
        for session in self.manager.sessions.values():
            suffix = f" - {safe_text(session.error)}" if session.error else ""
            print(
                f"  [{session.device.id}] {safe_text(session.endpoint.name)}: {session.state}{suffix}"
            )
        count = len(self.manager.sessions)
        started = sum(
            s.state in ("PLAYING", "PAUSED", "BUFFERING") for s in self.manager.sessions.values()
        )
        failed = sum(s.state == "ERROR" for s in self.manager.sessions.values())
        print(f"  Successfully started: {started}/{count} | Failed: {failed}/{count}")

    def controls(self):
        while True:
            print(
                f"\nTV PLAYBACK CONTROL\n  Selected devices: {len(self.selected)}\n"
                f"  Active sessions: {len(self.manager.active)}\n"
                f"  Media: {safe_text(self.source.name) if self.source else '-'}"
            )
            print(
                "  [1] Playback status\n  [2] Pause\n  [3] Resume\n  [4] Stop playback\n"
                "  [5] Change media\n  [6] Change target receivers\n  [7] Refresh device status\n  [0] Back"
            )
            choice = input("  > ").strip()
            try:
                if choice == "0":
                    if not self.manager.active:
                        return
                    print(
                        "  Playback is still active.\n  [1] Stop playback and return\n"
                        "  [2] Keep playback running and return\n  [0] Cancel"
                    )
                    answer = input("  > ").strip()
                    if answer == "1":
                        self.manager.stop()
                        self.status()
                        return
                    if answer == "2":
                        print(
                            "  Playback and HTTP remain active until stopped or POLTERHEIST exits."
                        )
                        return
                elif choice == "1":
                    self.status()
                elif choice in ("2", "3", "7"):
                    self.manager.command({"2": "pause", "3": "resume", "7": "refresh"}[choice])
                    print(
                        "  Request queued per receiver; Playback status shows results and unsupported operations."
                    )
                elif choice == "4":
                    self.manager.stop()
                    self.status()
                elif choice == "5":
                    self.start(self.selected, self.media())
                elif choice == "6":
                    devices = self.targets()
                    if devices:
                        self.start(devices, self.source or self.media())
                else:
                    print("  Invalid option.")
            except (ValueError, RuntimeError, OSError) as error:
                print("  [!] " + safe_text(error))

    def run(self):
        print("\nIoT SCANNING — Discovery & Control")
        print("  Use devices and networks you own or are authorized to inspect/control.")
        try:
            if getattr(self, "network", None) is None:
                print(
                    "  IP discovery unavailable: "
                    + safe_text(getattr(self, "network_error", "No LAN selected"))
                )
                print("  Wi-Fi Direct discovery and hardware diagnostics remain available.")
            self.discover_all()
            self.show_devices()
            while True:
                print(
                    "\n  [1] Connect to all detected devices\n"
                    "  [2] Connect to selected devices (IDs separated by commas)\n"
                    "  [3] Rescan all available transports\n"
                    "  [4] Inspect device / connection options\n"
                    "  [5] Media control (TVs / media receivers)\n"
                    "  [6] Check selected device connectivity\n"
                    "  [7] Hardware diagnostics\n"
                    "  [8] Configure discovery backends\n"
                    "  [9] Disconnect IoT connections\n"
                    "  [10] Check MQTT session access\n"
                    "  [11] Security observations\n  [0] Back"
                )
                choice = input("  > ").strip()
                try:
                    if choice == "0":
                        self.connections.close()
                        if self.manager.active:
                            print(
                                "  Media sessions remain active until stopped or POLTERHEIST exits."
                            )
                        return
                    if choice == "1":
                        self.connect_iots()
                    elif choice == "2":
                        identifiers = input("  Device IDs (e.g. 1,3,5) [0 Cancel]: ").strip()
                        if identifiers not in ("", "0"):
                            self.connect_iots(identifiers)
                    elif choice == "3":
                        self.discover_all()
                        self.show_devices()
                    elif choice == "4":
                        self.inspect()
                    elif choice == "5":
                        self.connections.close()
                        if self.manager.sessions:
                            self.controls()
                            continue
                        devices = self.targets()
                        if devices:
                            source = self.media()
                            if source and self.start(devices, source):
                                self.controls()
                    elif choice == "6":
                        self.check_connection()
                    elif choice == "7":
                        from .hardware import run

                        run(self.root)
                    elif choice == "8":
                        self.configure_backends()
                    elif choice == "9":
                        self.connections.close()
                        print("  Owned IoT connections closed.")
                    elif choice == "10":
                        self.check_mqtt()
                    elif choice == "11":
                        self.security_report()
                    else:
                        print("  Invalid option.")
                except (ValueError, RuntimeError, OSError) as error:
                    logging.getLogger(__name__).warning("IoT action %s failed: %s", choice, error)
                    print("  [!] " + safe_text(error))
        except (KeyboardInterrupt, EOFError):
            print("\n  Cancelling IoT/media operations and releasing resources.")
            self.manager.close()
            self.connections.close()

    def close(self):
        failures = []
        try:
            for resource in (self.manager, self.connections, self.bluetooth):
                try:
                    resource.close()
                except Exception as error:
                    failures.append(str(error))
        finally:
            for name in ("tv_control", "pychromecast", "zeroconf"):
                logging.getLogger(name).removeHandler(self.handler)
            self.handler.close()
        if failures:
            raise RuntimeError("Resource cleanup unconfirmed: " + "; ".join(failures))


def run(root):
    global _application
    if _application is None:
        _application = Application(root)
    _application.run()


def shutdown():
    global _application
    if _application:
        _application.close()
        _application = None


atexit.register(shutdown)
