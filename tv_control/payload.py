"""Offline Android TV image/video application: build, install and launch via authorized ADB."""

import datetime
import hashlib
import ipaddress
import json
import re
import socket
from pathlib import Path

from .network import detect_network
from .payload_build import COMPONENT, PACKAGE, build_apk, find_adb, run_command
from .payload_content import validate_source
from .scopes import route_to


class TVPayload:
    def __init__(self, root, target, port=5555):
        self.root = Path(root).resolve()
        self.target = str(ipaddress.IPv4Address(target))
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("ADB port must be between 1 and 65535")
        route = route_to(self.target)
        self.network = detect_network(route.ip)
        self.network.target(self.target)
        self.port = port
        self.serial = f"{self.target}:{port}"
        self.installed = False
        self.launch_acknowledged = False

    def adb(self, *arguments, timeout=30):
        return run_command([find_adb(self.root), "-s", self.serial, *arguments], timeout)

    def connect(self):
        # Fail promptly without starting an ADB server when TV installation access is disabled.
        try:
            with socket.create_connection(
                (self.target, self.port), timeout=3, source_address=(self.network.ip, 0)
            ):
                pass
        except OSError as error:
            raise RuntimeError(
                f"ADB is unavailable at {self.serial}. The TV must already have network debugging "
                "enabled and trust this computer for unattended installation. Google Cast cannot "
                "install Android apps. The APK is ready for later installation."
            ) from error
        # A new `adb connect` can raise an authorization dialog on the TV.
        # Payload only reuses a transport the developer tools already trust.
        devices = run_command([find_adb(self.root), "devices"], timeout=10)
        if not re.search(r"^" + re.escape(self.serial) + r"\s+device\b", devices, re.MULTILINE):
            raise RuntimeError(
                "ADB is not authorized or already connected for this TV. Payload does not "
                "start a new debugging authorization; an existing device session is required."
            )
        try:
            state = self.adb("get-state", timeout=10)
        except RuntimeError as error:
            raise RuntimeError(
                "The TV has not authorized this computer for ADB. Unattended installation "
                "requires an existing authorization. " + str(error)
            ) from error
        if state.strip() != "device":
            raise RuntimeError("ADB receiver is not ready: " + state)
        features = self.adb("shell", "pm", "list", "features")
        if "feature:android.software.leanback" not in features.splitlines():
            raise RuntimeError("The connected device does not advertise Android TV support")

    def install(self, apk):
        self.connect()
        output = self.adb("install", "-r", str(apk), timeout=120)
        if "Success" not in output.splitlines():
            raise RuntimeError("TV Payload installation failed: " + output)
        self.installed = True
        installed = self.adb("shell", "pm", "path", PACKAGE)
        if not any(line.startswith("package:") for line in installed.splitlines()):
            raise RuntimeError("Android did not confirm the installed TV Payload package")
        output = self.adb("shell", "am", "start", "-W", "-n", COMPONENT)
        if not re.search(r"^Status:\s*ok\s*$", output, re.MULTILINE):
            raise RuntimeError("TV Payload is installed, but launch was not confirmed: " + output)
        self.launch_acknowledged = True
        activities = self.adb("shell", "dumpsys", "activity", "activities")
        foreground = any(
            PACKAGE + "/" in line
            and re.search(r"(?:mResumedActivity|topResumedActivity|ResumedActivity)\s*[:=]", line)
            for line in activities.splitlines()
        )
        return {
            "status": "FOREGROUND_CONFIRMED" if foreground else "LAUNCH_ACKNOWLEDGED",
            "installed": True,
            "launch_acknowledged": True,
            "foreground_confirmed": foreground,
            "visual_confirmation": False,
        }


def deploy(root, target, source, port=5555, *, confirmed=False, apk=None):
    if not confirmed:
        raise ValueError("Confirm installation before deploying TV Payload")
    root = Path(root).resolve()
    source = validate_source(root, source)
    apk = build_apk(root, source) if apk is None else Path(apk).resolve(strict=True)
    report = {
        "recorded_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "target": target,
        "port": port,
        "package": PACKAGE,
        "source": str(source),
        "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "apk": str(apk),
        "apk_sha256": hashlib.sha256(apk.read_bytes()).hexdigest(),
        "status": "NOT_INSTALLED",
        "installed": False,
        "launch_acknowledged": False,
        "visual_confirmation": False,
    }
    folder = root / "reports/tv_payload"
    folder.mkdir(parents=True, exist_ok=True)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    report_path = folder / f"deployment_{stamp}.json"
    receiver = None
    try:
        receiver = TVPayload(root, target, port)
        report.update(receiver.install(apk))
        return report
    except (ValueError, RuntimeError, OSError) as error:
        report.update(status="FAILED", error=str(error))
        if receiver:
            report.update(
                installed=receiver.installed, launch_acknowledged=receiver.launch_acknowledged
            )
        raise
    finally:
        report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print("  Deployment report: " + str(report_path))


def run(root, wait=False):
    from .payload_runtime import run as adaptive_run

    return adaptive_run(root, wait=wait)


def main(argv=None):
    from .payload_runtime import main as adaptive_main

    return adaptive_main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
