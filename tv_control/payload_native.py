"""Native TV deployment through configured developer tools, never through guessed privileges."""

import json
import re
import shutil
import urllib.error
import urllib.request
import uuid
from pathlib import Path

from .network import parse_xml
from .payload_assets import native_sources
from .payload_build import run_command


def tool(name):
    found = shutil.which(name)
    if not found:
        raise RuntimeError(f"{name} is not installed or not on PATH")
    return found


def sdk_command(name, *args):
    executable = tool(name)
    # Windows SDK batch wrappers must never interpret shell metacharacters in paths/settings.
    if Path(executable).suffix.lower() in (".cmd", ".bat") and any(
        any(c in str(arg) for c in '&|<>^%!"\r\n') for arg in (executable, *args)
    ):
        raise ValueError("SDK batch wrapper arguments contain unsupported shell characters")
    return run_command([executable, *args], timeout=120)


def name(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", value):
        raise ValueError("Invalid SDK device/profile name")
    return value


def webos(target, folder, settings):
    alias = name(settings.get("webos_device", ""))
    configured = json.loads(sdk_command("ares-setup-device", "--listfull"))
    entries = configured if isinstance(configured, list) else configured.get("devices", [])
    entry = next((item for item in entries if item.get("name") == alias), None)
    if not entry or entry.get("deviceinfo", {}).get("ip", entry.get("host")) != target:
        raise ValueError("webOS SDK alias must resolve to the selected TV IP in ares-setup-device")
    native_sources(folder, "webos")
    sdk_command("ares-package", folder / "webos", "--outdir", folder)
    packages = list(folder.glob("org.polterheist.tvpayload_*.ipk"))
    if len(packages) != 1:
        raise RuntimeError("webOS packaging did not produce one expected IPK")
    sdk_command("ares-install", "--device", alias, packages[0])
    sdk_command("ares-launch", "--device", alias, "org.polterheist.tvpayload")
    running = sdk_command("ares-launch", "--device", alias, "--running")
    if "org.polterheist.tvpayload" not in running:
        raise RuntimeError("webOS did not report the installed app as running")
    return {
        "state": "NATIVE_APP_RUNNING",
        "artifact": str(packages[0]),
        "persistent": True,
        "note": "webOS developer installations depend on the Developer Mode session lifetime",
    }


def tizen(target, folder, settings):
    certificate = name(settings.get("tizen_certificate", ""))
    serial = target + ":26101"
    # Reuse an existing device session; a new connection may prompt on the TV.
    devices = sdk_command("sdb", "devices")
    if not re.search(r"^" + re.escape(serial) + r"\s+device\b", devices, re.MULTILINE):
        raise RuntimeError("Samsung SDB did not establish an authorized device session")
    native_sources(folder, "tizen")
    sdk_command("tizen", "build-web", "--", folder / "tizen")
    built = folder / "tizen/.buildResult"
    sdk_command("tizen", "package", "-t", "wgt", "-s", certificate, "--", built)
    packages = list(built.glob("*.wgt"))
    if len(packages) != 1:
        raise RuntimeError("Tizen signing did not produce one WGT")
    sdk_command("tizen", "install", "-s", serial, "-n", packages[0].name, "--", built)
    output = sdk_command("tizen", "run", "-s", serial, "-p", "PolterTV01.Payload")
    if "successfully launched" not in output.lower():
        raise RuntimeError("Tizen did not acknowledge launching TV Payload")
    return {"state": "NATIVE_LAUNCH_ACKNOWLEDGED", "artifact": str(packages[0]), "persistent": True}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def roku(target, folder, settings):
    password = settings.get("roku_password")
    if not password or settings.get("roku_replace_dev") is not True:
        raise ValueError(
            "Roku needs its developer password and explicit permission to replace its one developer slot"
        )
    archive = native_sources(folder, "roku")
    manager = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    manager.add_password(None, f"http://{target}/", "rokudev", password)
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), NoRedirect(), urllib.request.HTTPDigestAuthHandler(manager)
    )
    boundary = uuid.uuid4().hex
    body = (
        (
            f'--{boundary}\r\nContent-Disposition: form-data; name="mysubmit"\r\n\r\nInstall\r\n'
            f'--{boundary}\r\nContent-Disposition: form-data; name="archive"; filename="payload.zip"\r\n'
            "Content-Type: application/zip\r\n\r\n"
        ).encode()
        + archive.read_bytes()
        + f"\r\n--{boundary}--\r\n".encode()
    )
    request = urllib.request.Request(
        f"http://{target}/plugin_install",
        data=body,
        headers={"Content-Type": "multipart/form-data; boundary=" + boundary},
    )
    with opener.open(request, timeout=30) as response:
        text = response.read(1024 * 1024).decode("utf-8", "replace").lower()
    if "install success" not in text and "identical to previous" not in text:
        raise RuntimeError("Roku developer installer did not confirm installation")
    with opener.open(
        urllib.request.Request(f"http://{target}:8060/launch/dev", data=b""), timeout=10
    ):
        pass
    with opener.open(f"http://{target}:8060/query/active-app", timeout=10) as response:
        info = parse_xml(response.read(1024 * 1024))
    app = info.find("app")
    if app is None or app.get("id") != "dev" or (app.text or "").strip() != "TV Payload":
        raise RuntimeError("Roku did not report TV Payload as the active application")
    return {"state": "NATIVE_APP_RUNNING", "artifact": str(archive), "persistent": True}
