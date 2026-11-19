"""Adaptive detect -> prepare -> transfer -> execute workflow and observable session lifecycle."""

import argparse
import atexit
import datetime
import errno
import json
import logging
import shutil
import socket
import time
from dataclasses import dataclass
from pathlib import Path

from . import payload_adapters as adapters
from . import payload_assets, payload_detection, payload_native, payload_schedule
from .http_server import MediaServer
from .media import Media
from .models import Config, safe_text
from .payload_build import build_tools, find_adb
from .payload_content import EXTENSIONS, content_info

JOBS = []
STRATEGIES = (
    "auto",
    "cast-html",
    "samsung-html",
    "webos-html",
    "android-app",
    "webos-app",
    "tizen-app",
    "roku-app",
    "cast-media",
    "dlna",
    "airplay",
)
OFFLINE_STRATEGIES = {
    "cast-html",
    "samsung-html",
    "webos-html",
    "android-app",
    "webos-app",
    "tizen-app",
    "roku-app",
}


def settings_for(root, target):
    path = Path(root) / "config/tv_payload.json"
    if not path.exists():
        return {}
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or set(document) - {
        "devices",
        "default_target",
        "default_media",
    }:
        raise ValueError("Invalid config/tv_payload.json; see the example")
    devices = document.get("devices", {})
    if not isinstance(devices, dict):
        raise ValueError("TV Payload devices must be a mapping of IP addresses")
    settings = devices.get(target, {})
    allowed = {
        "samsung_token",
        "webos_client_key",
        "webos_device",
        "tizen_certificate",
        "roku_password",
        "roku_replace_dev",
        "adb_port",
    }
    if not isinstance(settings, dict) or set(settings) - allowed:
        raise ValueError("Unknown TV Payload device setting")
    for key, value in settings.items():
        if key == "roku_replace_dev":
            valid = type(value) is bool
        elif key == "adb_port":
            valid = type(value) is int and 1 <= value <= 65535
        else:
            valid = isinstance(value, str) and len(value) <= 8192
        if not valid:
            raise ValueError("Invalid TV Payload setting: " + key)
    from app_logging import register_secrets

    register_secrets(settings.values())
    return settings


@dataclass
class Option:
    strategy: str
    endpoint: object
    ready: bool
    reason: str
    kind: str

    def document(self):
        return {
            "strategy": self.strategy,
            "ready": self.ready,
            "reason": self.reason,
            "payload_type": self.kind,
        }


def options(root, profile, settings):
    result = []
    by_protocol = {e.protocol: e for e in profile.endpoints}
    cast = by_protocol.get("Google Cast")
    if cast and cast.details.get("cast_type") != "audio":
        result.append(
            Option(
                "cast-html",
                cast,
                True,
                "Launch DashCast and load the generated HTML program; receiver availability is tested at runtime",
                "HTML/JavaScript",
            )
        )
    samsung = by_protocol.get("Samsung Remote")
    if samsung:
        result.append(
            Option(
                "samsung-html",
                samsung,
                bool(settings.get("samsung_token")),
                "Samsung browser requires a previously paired token",
                "HTML/JavaScript",
            )
        )
    webos = by_protocol.get("webOS")
    # LG UPnP identification plus the developer API remains a candidate, not an OS assertion.
    lg = next(
        (e for e in profile.endpoints if e.manufacturer.lower() in ("lg", "lg electronics")), None
    )
    if webos or (lg and (settings.get("webos_client_key") or settings.get("webos_device"))):
        webos = webos or lg
        result.append(
            Option(
                "webos-html",
                webos,
                bool(settings.get("webos_client_key")),
                "webOS browser requires a previously paired client key",
                "HTML/JavaScript",
            )
        )
        ready = bool(settings.get("webos_device")) and all(
            shutil.which(t)
            for t in ("ares-setup-device", "ares-package", "ares-install", "ares-launch")
        )
        result.append(
            Option(
                "webos-app",
                webos,
                ready,
                "Needs configured webOS SDK alias, Developer Mode and device SSH key",
                "webOS IPK",
            )
        )
    if samsung:
        ready = bool(settings.get("tizen_certificate")) and all(
            shutil.which(t) for t in ("tizen", "sdb")
        )
        result.append(
            Option(
                "tizen-app",
                samsung,
                ready and 26101 in profile.ports,
                "Needs Tizen SDK, certificate profile and authorized SDB developer connection",
                "Signed Tizen WGT",
            )
        )
    roku = by_protocol.get("Roku ECP")
    if roku:
        ready = bool(settings.get("roku_password")) and settings.get("roku_replace_dev") is True
        result.append(
            Option(
                "roku-app",
                roku,
                ready and roku.details.get("developer_enabled") == "true",
                "Needs Roku developer mode/password and permission to replace its developer slot",
                "BrightScript/SceneGraph ZIP",
            )
        )
    adb_port = settings.get("adb_port", 5555)
    if adb_port in profile.ports or "Android TV Remote" in by_protocol or "ADB TLS" in by_protocol:
        try:
            find_adb(root)
            build_tools(root)
            ready = adb_port in profile.ports
        except RuntimeError:
            ready = False
        result.append(
            Option(
                "android-app",
                None,
                ready,
                "Needs an Android TV ADB session already authorized, JDK and Android SDK; TCP alone is not proof",
                "Android APK",
            )
        )
    if cast and cast.details.get("cast_type") != "audio":
        result.append(
            Option(
                "cast-media",
                cast,
                False,
                "Requires a PC media server",
                "Receiver media (not uploaded code)",
            )
        )
    for endpoint in profile.endpoints:
        if endpoint.protocol == "DLNA" and endpoint.controllable:
            result.append(
                Option(
                    "dlna",
                    endpoint,
                    True,
                    "Use the advertised renderer; JPEG direct or supported MP4 conversion",
                    "Receiver media (not uploaded code)",
                )
            )
    airplay = by_protocol.get("AirPlay")
    if airplay:
        result.append(
            Option(
                "airplay",
                airplay,
                False,
                "Requires a PC media server",
                "AirPlay video",
            )
        )
    for plan in result:
        if plan.strategy not in OFFLINE_STRATEGIES:
            plan.ready = False
            plan.reason = "Excluded from Payload: this route depends on the PC serving media. Use Media control instead."
    # Prefer installed, local packages when their existing authorization/tools are available.
    result.sort(
        key=lambda p: (
            not p.ready,
            p.strategy not in OFFLINE_STRATEGIES,
            p.strategy.endswith("-html"),
        )
    )
    return result


def show_detection(profile, plans):
    print("\n[1/2] TV DETECTION")
    print(
        f"  {profile.target} | {safe_text(profile.family)} | local interface {profile.network.ip}"
    )
    for endpoint in profile.endpoints:
        print(
            f"  {safe_text(endpoint.manufacturer)} / {safe_text(endpoint.model)} / {safe_text(endpoint.protocol)}"
        )
    for plan in plans:
        status = "READY TO TRY" if plan.ready else "NEEDS SETUP"
        if plan.strategy not in OFFLINE_STRATEGIES:
            status = "EXCLUDED"
        print(f"  {status}: {plan.strategy} — {plan.kind}")
        print("    " + plan.reason)
    if not plans:
        print(
            "  No supported execution route advertised. No compatible payload can be sent automatically."
        )


def write_report(root, report, prefix="session"):
    folder = Path(root) / "reports/tv_payload"
    folder.mkdir(parents=True, exist_ok=True)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    path = folder / f"{prefix}_{stamp}.json"
    path.write_text(
        json.dumps(report, indent=2, default=lambda x: sorted(x) if isinstance(x, set) else str(x))
        + "\n",
        encoding="utf-8",
    )
    return path


class PayloadJob:
    def __init__(self, root, profile, plans, settings, config=None):
        self.root, self.profile, self.plans, self.settings = Path(root), profile, plans, settings
        self.config = config or Config(connect_timeout=30)
        self.adapter = None
        self.server = None
        self.report_path = None
        JOBS.append(self)
        self.report = {
            "schema": 2,
            "detection": profile.document(),
            "plan": [p.document() for p in plans],
            "attempts": [],
            "state": "DETECTED",
            "visual_confirmation": False,
            "persistent": False,
        }

    def save(self):
        if self.report_path is None:
            self.report_path = write_report(self.root, self.report)
        else:
            self.report_path.write_text(
                json.dumps(
                    self.report,
                    indent=2,
                    default=lambda x: sorted(x) if isinstance(x, set) else str(x),
                )
                + "\n",
                encoding="utf-8",
            )

    def start(self, source, strategy="auto", confirmed=False, schedule=None):
        if not confirmed:
            raise ValueError("Confirm sending and executing the TV Payload")
        if strategy not in STRATEGIES:
            raise ValueError("Unknown payload strategy")
        self.schedule = schedule
        self.folder = payload_assets.prepare(self.root, source, schedule=schedule)
        self.report["schedule"] = schedule
        logging.getLogger(__name__).info(
            "Payload start: target=%s strategy=%s schedule=%s",
            self.profile.target,
            strategy,
            schedule,
        )
        self.report["artifact_directory"] = str(self.folder)
        self.report["source"] = str(source)
        candidates = [
            p
            for p in self.plans
            if p.ready and p.strategy in OFFLINE_STRATEGIES and strategy in ("auto", p.strategy)
        ]
        if not candidates:
            self.report["state"] = "NEEDS_SETUP" if self.plans else "UNSUPPORTED_OR_UNREACHABLE"
            # Leave platform source packages ready even when developer authorization is absent.
            for platform, route in (
                ("webos", "webos-app"),
                ("tizen", "tizen-app"),
                ("roku", "roku-app"),
            ):
                if any(p.strategy == route for p in self.plans):
                    payload_assets.native_sources(self.folder, platform)
            self.save()
            raise RuntimeError(
                "No ready execution route. See the detection/setup report: " + str(self.report_path)
            )
        print("\n[2/2] PREPARE, SEND AND EXECUTE")
        for plan in candidates:
            print("  Trying " + plan.strategy + " ...")
            attempt = {"strategy": plan.strategy, "payload_type": plan.kind, "state": "STARTING"}
            self.report["attempts"].append(attempt)
            try:
                result = self.execute(plan, source)
                if result.get("requires_host"):
                    raise RuntimeError("Payload must not depend on the PC after transfer")
                attempt.update(state=result["state"])
                self.report.update(result, strategy=plan.strategy)
                # Fully loaded HTML/Blob media and native packages need no remaining host process.
                self.cleanup()
                self.report["host_session"] = "CLOSED_AFTER_TRANSFER"
                self.save()
                logging.getLogger(__name__).info(
                    "Payload transferred: %s; %s",
                    result["state"],
                    payload_schedule.describe(schedule),
                )
                return self.report
            except Exception as error:
                logging.getLogger(__name__).exception("Payload route failed: %s", plan.strategy)
                # Authentication values and URLs are not included in reports.
                detail = str(error)
                for secret in self.settings.values():
                    if isinstance(secret, str) and secret:
                        detail = detail.replace(secret, "[redacted]")
                attempt.update(state="FAILED", error=detail[:1200])
                print("    " + safe_text(detail[:400]))
                self.cleanup()
        self.report["state"] = "FAILED"
        self.save()
        raise RuntimeError("All eligible payload routes failed; report: " + str(self.report_path))

    def execute(self, plan, source):
        if plan.strategy not in OFFLINE_STRATEGIES:
            raise ValueError("This route requires a PC media server and is excluded from Payload")
        if plan.strategy == "android-app":
            from .payload import deploy

            result = deploy(
                self.root,
                self.profile.target,
                source,
                self.settings.get("adb_port", 5555),
                confirmed=True,
                schedule=getattr(self, "schedule", None),
            )
            return {
                "state": result["status"],
                "persistent": True,
                "artifact": result["apk"],
                "requires_host": False,
                "offline_scope": "installed local package",
            }
        if plan.strategy in ("webos-app", "tizen-app", "roku-app"):
            result = getattr(payload_native, plan.strategy.split("-")[0])(
                self.profile.target, self.folder, self.settings
            )
            return dict(result, requires_host=False, offline_scope="installed local package")
        self.server = MediaServer(
            self.profile.network.ip, self.config.http_port, (self.root / ".cache/tv_control",)
        )
        receipt_file = self.folder / "receipt.txt"
        receipt_file.write_text("loaded", encoding="ascii")
        receipt_media = Media(receipt_file, "text/plain", False)
        try:
            receipt = self.server.publish(receipt_media, self.profile.target)
        except RuntimeError as error:
            cause = error.__cause__
            if not isinstance(cause, OSError) or cause.errno not in (errno.EADDRINUSE, 10048):
                raise
            # Media control may already serve other TVs on the default port.
            self.server.close()
            self.server = MediaServer(
                self.profile.network.ip, 0, (self.root / ".cache/tv_control",)
            )
            receipt = self.server.publish(receipt_media, self.profile.target)
        html = payload_assets.write_html(self.folder, receipt)
        url = self.server.publish(
            Media(html, "text/html; charset=utf-8", False), self.profile.target
        )
        if plan.strategy == "cast-html":
            self.adapter = adapters.CastHTML(plan.endpoint, self.config)
        else:
            cls = adapters.SamsungHTML if plan.strategy == "samsung-html" else adapters.WebOSHTML
            self.adapter = cls(plan.endpoint, self.config, self.settings)
        self.adapter.launch(url)
        deadline = time.monotonic() + self.config.connect_timeout
        while time.monotonic() < deadline:
            if self.server.requests(url) and self.server.requests(receipt):
                return {
                    "state": "HTML_EXECUTION_CONFIRMED",
                    "program_execution": True,
                    "evidence": "TV fetched the complete embedded program and sent its media-ready JavaScript receipt",
                    "persistent": False,
                    "requires_host": False,
                    "offline_scope": "loaded TV browser process; survives PC disconnect, not TV app closure/reboot",
                    "content_kind": content_info(self.folder)["kind"],
                }
            time.sleep(0.1)
        raise TimeoutError(
            "No HTML execution receipt from TV (authorization, receiver availability or HTTP reachability)"
        )

    def cleanup(self):
        errors = []
        if self.adapter:
            try:
                self.adapter.close()
            except Exception as error:
                errors.append(str(error))
            self.adapter = None
        if self.server:
            self.server.close()
            self.server = None
        if errors:
            self.report["cleanup_errors"] = errors

    def close(self):
        self.cleanup()
        self.report.setdefault("host_session", "CLOSED")
        if self in JOBS:
            JOBS.remove(self)
        self.save()


def shutdown():
    while JOBS:
        JOBS.pop().close()


atexit.register(shutdown)


def inspect(root, target, port=5555):
    settings = settings_for(root, target)
    if port != 5555:
        settings["adb_port"] = port
    profile = payload_detection.detect(target, adb_port=settings.get("adb_port", 5555))
    plans = options(root, profile, settings)
    show_detection(profile, plans)
    path = write_report(
        root, {"detection": profile.document(), "plan": [p.document() for p in plans]}, "detection"
    )
    print("  Detection report: " + str(path))
    return profile, plans, settings


def run(root, wait=False, schedule=None, interactive=True):
    print("\nTV Payload — Automatic detection and offline image/video deployment")
    if interactive:
        schedule = payload_schedule.prompt()
    print("  " + payload_schedule.describe(schedule))
    if schedule:
        print("  Keep the TV viewer open. Back/Escape on the TV cancels the schedule.")
    target = automatic_target(root)
    source = automatic_source(root)
    profile, plans, settings = inspect(root, target)
    print("  Content: " + safe_text(source.name))
    job = PayloadJob(root, profile, plans, settings)
    try:
        job.start(source, confirmed=True, schedule=schedule)
        print("  " + job.report["state"] + " | " + str(job.report_path))
        print(
            "  Transfer complete. The TV has the content; the PC server and connection are closed."
        )
    finally:
        job.close()


def defaults(root):
    path = Path(root) / "config/tv_payload.json"
    data = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    if not isinstance(data, dict):
        raise ValueError("Invalid TV Payload configuration")
    for key in ("default_target", "default_media"):
        if key in data and not isinstance(data[key], str):
            raise ValueError("Invalid TV Payload setting: " + key)
    return data


def automatic_source(root, selected=None):
    value = selected or defaults(root).get("default_media")
    if value:
        path = Path(value)
        return path if path.is_absolute() else Path(root) / path
    preferred = Path(root) / "media/image.jpg"
    if preferred.is_file():
        return preferred
    files = sorted(
        p
        for p in (Path(root) / "media").glob("*")
        if p.is_file() and p.suffix.lower() in EXTENSIONS
    )
    if len(files) != 1:
        raise ValueError(
            "Set default_media in config/tv_payload.json or provide --media when media/ has multiple/no files"
        )
    return files[0]


def automatic_target(root, selected=None):
    value = selected or defaults(root).get("default_target")
    if value:
        return value
    from concurrent.futures import ThreadPoolExecutor

    from .network import detect_network
    from .protocols import dlna, google_cast

    config = Config.load(root)
    bind_ip = config.bind_ip
    if not bind_ip:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("1.1.1.1", 53))  # Route lookup only; no packet sent.
            bind_ip = sock.getsockname()[0]
    network = detect_network(bind_ip)
    addresses = set()
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(module.discover, network, config) for module in (google_cast, dlna)]
        for future in futures:
            try:
                for endpoint in future.result():
                    if (
                        endpoint.protocol in ("Google Cast", "DLNA", "DIAL")
                        and endpoint.details.get("cast_type") != "audio"
                    ):
                        addresses.add(endpoint.ip)
            except (OSError, RuntimeError, ImportError, ValueError):
                pass
    if len(addresses) != 1:
        raise ValueError(
            "No unique TV detected; set default_target in config/tv_payload.json or provide --target"
        )
    return addresses.pop()


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Detect TV capabilities and send/execute an adapted payload"
    )
    parser.add_argument("--target", help="TV IPv4 on the same LAN")
    parser.add_argument(
        "--image",
        "--media",
        dest="image",
        help="Local image/video; defaults to configured media or media/image.jpg",
    )
    parser.add_argument("--port", type=int, default=5555, help="Optional preauthorized ADB port")
    parser.add_argument("--strategy", choices=STRATEGIES, default="auto")
    parser.add_argument("--detect-only", action="store_true")
    parser.add_argument("--at", help="Start at HH:MM local time or ISO date/time")
    parser.add_argument(
        "--every", type=float, help="Repeat every X minutes, first run after X minutes"
    )
    parser.add_argument(
        "--show-seconds",
        type=float,
        default=10,
        help="Image display seconds per repeat (default 10)",
    )
    parser.add_argument(
        "--prepare-only",
        action="store_true",
        help="Generate HTML and native source archives without sending",
    )
    parser.add_argument(
        "--build-only", action="store_true", help="Build the Android APK only (legacy option)"
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Compatibility flag; Payload never asks for a sending confirmation",
    )
    parser.add_argument(
        "--duration",
        type=float,
        default=0,
        help="Compatibility option; the host always disconnects after complete payload transfer",
    )
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parent.parent
    from app_logging import configure_logging

    configure_logging(root)
    if not 0 <= args.duration <= 86400:
        parser.error("--duration must be between 0 and 86400")
    job = None
    try:
        schedule = payload_schedule.create(args.at, args.every, args.show_seconds)
        print(payload_schedule.describe(schedule))
        if args.detect_only:
            target = automatic_target(root, args.target)
            profile, _, _ = inspect(root, target, args.port)
            return 0 if profile.endpoints else 1
        source = automatic_source(root, args.image)
        if args.build_only:
            from .payload_build import build_apk

            print("APK ready: " + str(build_apk(root, source, schedule=schedule)))
            return 0
        if args.prepare_only:
            folder = payload_assets.prepare(root, source, schedule=schedule)
            for platform in ("webos", "tizen", "roku"):
                payload_assets.native_sources(folder, platform)
            print("HTML and native source packages ready: " + str(folder))
            return 0
        target = automatic_target(root, args.target)
        profile, plans, settings = inspect(root, target, args.port)
        job = PayloadJob(root, profile, plans, settings)
        report = job.start(source, args.strategy, confirmed=True, schedule=schedule)
        print(report["state"] + " | " + str(job.report_path))
        print("PC disconnected from the payload. The complete content is on the TV.")
        return 0
    except (OSError, ValueError, RuntimeError, ImportError) as error:
        logging.getLogger(__name__).exception("Payload failed")
        print("[!] " + safe_text(error))
        return 1
    except (KeyboardInterrupt, EOFError):
        return 130
    finally:
        if job:
            job.close()
