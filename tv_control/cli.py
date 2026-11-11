"""English CLI matching the existing application; no vendor APIs in menu code."""

import atexit
import json
import logging
from dataclasses import asdict, replace
from logging.handlers import RotatingFileHandler
from pathlib import Path

from .discovery import Discovery, select_devices
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
        self.network = detect_network(self.config.bind_ip)
        self.discovery = Discovery(self.network, self.config)
        self.manager = Manager(root, self.network, self.config)
        self.handler = configure_logging(root)
        self.selected = []
        self.source = None

    def show_devices(self):
        print("\nUNIVERSAL TV DISCOVERY — H3")
        print("  ID  DEVICE                    IP               PROTOCOL / STATUS")
        print("  " + "-" * 85)
        for device in self.discovery.devices.values():
            e = device.primary
            protocols = ", ".join(x.protocol for x in device.endpoints)
            state = (
                "UNAVAILABLE"
                if not device.available
                else "COMPATIBLE BACKEND; SESSION UNTESTED"
                if device.controllable
                else "DISCOVERED ONLY"
            )
            print(f"  {device.id:<3} {safe_text(e.name)[:25]:25} {e.ip:16} {protocols} / {state}")
            print(
                f"      {safe_text(e.manufacturer)} | {safe_text(e.model)} | {safe_text(e.kind)} | port {e.port}"
            )
            if len(device.endpoints) > 1:
                print("      Same-host grouping is provisional; physical identity is unverified.")
            for endpoint in device.endpoints:
                print(f"      {endpoint.protocol}: {safe_text(endpoint.note)}")
                print(
                    f"        Source: {safe_text(', '.join(endpoint.sources))} | {safe_text(endpoint.reachability)}"
                )
                print(
                    f"        Evidence: {safe_text(endpoint.confidence)} | Authentication: {safe_text(endpoint.authentication)}"
                )
        count = sum(d.available for d in self.discovery.devices.values())
        print(f"  [+] {count} devices/services detected (UPnP devices are not necessarily TVs)")

    def scan(self, target=None):
        print(
            f"  Discovering on {safe_text(self.network.name)}: {self.network.ip} / {self.network.subnet} ..."
        )
        self.discovery.scan(target)
        for warning in self.discovery.warnings:
            print("  [!] " + safe_text(warning))
        print("  Discovery report: " + str(self.discovery.export(self.root)))

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

    def inspect(self):
        identifier = input("  Device ID [ENTER to cancel]: ").strip()
        if not identifier:
            return
        if (
            not identifier.isascii()
            or not identifier.isdigit()
            or int(identifier) not in self.discovery.devices
        ):
            raise ValueError("Unknown device ID")
        device = self.discovery.devices[int(identifier)]
        print(
            json.dumps(
                asdict(device),
                ensure_ascii=True,
                indent=2,
                default=lambda value: sorted(value) if isinstance(value, set) else str(value),
            )
        )
        print(
            "  Detection, transport reachability and a verified media session are separate states."
        )

    def configure_backends(self):
        print("  Available: cast, upnp, airplay (AirPlay/RAOP discovery only)")
        print("  Enabled: " + ", ".join(self.discovery.config.discovery_backends))
        names = input("  Comma-separated names [ENTER to keep]: ").strip()
        if names:
            config = replace(
                self.discovery.config,
                discovery_backends=tuple(name.strip() for name in names.split(",")),
            )
            self.discovery.config = config
            print("  Discovery configuration updated for this session. Refresh to apply.")

    def targets(self):
        while True:
            self.show_devices()
            print(
                "\nSELECT TARGET DEVICES\n  [1] Connect to all detected media receivers\n"
                "  [2] Connect to specific receivers\n  [3] Refresh discovery\n"
                "  [4] Directed discovery by IP / hostname / CIDR\n"
                "  [5] Inspect capabilities\n  [6] Hardware diagnostics\n"
                "  [7] Configure discovery backends\n  [0] Back"
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
                elif choice in ("1", "2"):
                    ids = None
                    if choice == "2":
                        ids = input("  Enter TV IDs (comma-separated), or 0 to go back: ").strip()
                        if ids == "0":
                            continue
                    return select_devices(list(self.discovery.devices.values()), ids)
                else:
                    print("  Invalid option.")
            except (ValueError, RuntimeError, OSError) as error:
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
                "  [5] Change media\n  [6] Change target TVs\n  [7] Refresh device status\n  [0] Back"
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
        print("\nTV CONTROL - Smart TV Discovery & Media Casting")
        print("  Use only receivers you own or are authorized to control.")
        try:
            if self.manager.sessions:
                self.controls()
                return
            self.scan()
            while True:
                devices = self.targets()
                if devices is None:
                    return
                source = self.media()
                if source and self.start(devices, source):
                    self.controls()
                    return
        except (KeyboardInterrupt, EOFError):
            print("\n  Cancelling TV sessions and releasing resources.")
            self.manager.close()

    def close(self):
        self.manager.close()
        for name in ("tv_control", "pychromecast", "zeroconf"):
            logging.getLogger(name).removeHandler(self.handler)
        self.handler.close()


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
