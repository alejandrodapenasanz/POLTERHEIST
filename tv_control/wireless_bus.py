"""Bounded argv execution and typed busctl calls; no service activation or elevation."""

import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time

LOG = logging.getLogger(__name__)


class WirelessError(RuntimeError):
    def __init__(self, code, message):
        self.code = code
        super().__init__(f"{code}: {message}")


def error_code(message):
    text = message.lower()
    if any(
        word in text
        for word in (
            "accessdenied",
            "permission denied",
            "not authorized",
            "notauthorized",
            "authentication required",
        )
    ):
        return "PERMISSION_DENIED"
    if any(word in text for word in ("busy", "in progress", "already running")):
        return "ADAPTER_BUSY"
    if any(
        word in text
        for word in (
            "serviceunknown",
            "namehasnoowner",
            "not provided by any",
            "failed to connect to bus",
        )
    ):
        return "SERVICE_UNAVAILABLE"
    if any(
        word in text
        for word in ("unknownmethod", "unknownproperty", "unknowninterface", "not supported")
    ):
        return "UNSUPPORTED_API"
    return "DBUS_ERROR"


class CommandRunner:
    def __call__(self, argv, timeout=3, cancel=None):
        executable = shutil.which(argv[0])
        if not executable:
            raise WirelessError(
                "DEPENDENCY_MISSING",
                f"{argv[0]} is not installed/on PATH; no installation attempted",
            )
        if cancel is not None and cancel.is_set():
            raise WirelessError("CANCELLED", "Request cancelled before execution")
        # Regular temporary files avoid PIPE deadlocks; size is checked while running.
        with tempfile.TemporaryFile() as output:
            try:
                process = subprocess.Popen(
                    [executable, *argv[1:]],
                    stdin=subprocess.DEVNULL,
                    stdout=output,
                    stderr=subprocess.STDOUT,
                    shell=False,
                    env=dict(os.environ, LC_ALL="C", LANG="C"),
                )
            except PermissionError as error:
                raise WirelessError("PERMISSION_DENIED", str(error)) from error
            except OSError as error:
                raise WirelessError("PROCESS_ERROR", str(error)) from error
            deadline = time.monotonic() + timeout
            try:
                while process.poll() is None:
                    if cancel is not None and cancel.is_set():
                        raise WirelessError("CANCELLED", "Request cancelled")
                    if time.monotonic() >= deadline:
                        raise WirelessError("TIMEOUT", "Bounded command timed out")
                    if os.fstat(output.fileno()).st_size > 262144:
                        raise WirelessError("OUTPUT_LIMIT", "Command output exceeded 256 KiB")
                    time.sleep(0.02)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=2)
            output.seek(0)
            raw = output.read(262145)
            if len(raw) > 262144:
                raise WirelessError("OUTPUT_LIMIT", "Command output exceeded 256 KiB")
        text = raw.decode("utf-8", "replace")
        if process.returncode:
            LOG.debug("Wireless command %r failed: %s", argv, text[:4000])
            raise WirelessError(error_code(text), text.strip()[:1000] or "Command failed")
        return text


def object_path(path):
    if (
        not isinstance(path, str)
        or len(path) > 512
        or not re.fullmatch(r"/(?:[A-Za-z0-9_]+(?:/[A-Za-z0-9_]+)*)?", path)
    ):
        raise WirelessError("INVALID_RESPONSE", "Invalid D-Bus object path")
    return path


def decode_reply(text, signature):
    try:
        document = json.loads(text)
        if (
            document["type"] != signature
            or not isinstance(document["data"], list)
            or len(document["data"]) != 1
        ):
            raise ValueError("signature/arity")
        value = document["data"][0]
        if signature == "a{sv}":
            if not isinstance(value, dict):
                raise ValueError("dictionary")
            return {
                key: variant["data"]
                for key, variant in value.items()
                if isinstance(variant, dict) and "type" in variant and "data" in variant
            }
        if signature == "ao":
            if not isinstance(value, list) or len(value) > 256:
                raise ValueError("object array limit")
            return [object_path(path) for path in value]
        return value
    except (ValueError, KeyError, TypeError) as error:
        raise WirelessError("INVALID_RESPONSE", "Unexpected busctl JSON response") from error


class Busctl:
    def __init__(self, runner=None, timeout=3):
        self.runner = runner or CommandRunner()
        self.timeout = timeout

    def _run(self, args, timeout=None, user=False):
        limit = self.timeout if timeout is None else max(0.05, min(timeout, self.timeout))
        return self.runner(
            [
                "busctl",
                "--user" if user else "--system",
                "--auto-start=no",
                "--allow-interactive-authorization=no",
                "--json=short",
                f"--timeout={limit}",
                *args,
            ],
            timeout=limit + 0.2,
        )

    def get(self, service, path, interface, prop, signature, **kwargs):
        # busctl documents --auto-start/interactive flags for `call`, not
        # get-property. Use Properties.Get explicitly so reads cannot activate
        # NetworkManager/supplicant as a side effect.
        variant = decode_reply(
            self._run(
                [
                    "call",
                    service,
                    object_path(path),
                    "org.freedesktop.DBus.Properties",
                    "Get",
                    "ss",
                    interface,
                    prop,
                ],
                **kwargs,
            ),
            "v",
        )
        if (
            not isinstance(variant, dict)
            or variant.get("type") != signature
            or "data" not in variant
        ):
            raise WirelessError("INVALID_RESPONSE", "Unexpected D-Bus property variant")
        return decode_reply(json.dumps({"type": signature, "data": [variant["data"]]}), signature)

    def properties(self, service, path, interface, **kwargs):
        return decode_reply(
            self._run(
                [
                    "call",
                    service,
                    object_path(path),
                    "org.freedesktop.DBus.Properties",
                    "GetAll",
                    "s",
                    interface,
                ],
                **kwargs,
            ),
            "a{sv}",
        )

    def call(self, service, path, interface, method, signature=None, args=(), **kwargs):
        argv = ["call", service, object_path(path), interface, method]
        if signature:
            argv.extend([signature, *map(str, args)])
        return self._run(argv, **kwargs)
