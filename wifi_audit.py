"""WPA/WPA2-Personal dictionary audits using external Aircrack-ng tools."""

import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from app_logging import register_secrets

LOGGER = logging.getLogger("polterheist.wifi_password")
REASONS = {
    "RECOVERED": "A candidate matched the selected network's authentication evidence.",
    "NOT_RECOVERED": "The dictionary was exhausted. This does not establish network security.",
    "NO_HANDSHAKE": "No usable WPA/WPA2-PSK handshake for this SSID/BSSID was found.",
    "TIMEOUT": "The time limit expired; the dictionary was not exhausted.",
    "CANCELLED": "Interrupted by the operator; available evidence was preserved.",
    "ERROR": "Aircrack-ng failed. Check the executable, capture and dictionary compatibility.",
    "RESTORE_FAILED": "The original Wi-Fi state could not be restored; inspect radio_setup.json.",
}


def target_values(ssid, bssid):
    if not isinstance(ssid, str) or not 1 <= len(ssid.encode("utf-8")) <= 32 or "\0" in ssid:
        raise ValueError("An exact SSID of 1 to 32 UTF-8 bytes is required.")
    if not isinstance(bssid, str) or not re.fullmatch(
        r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", bssid
    ):
        raise ValueError("A BSSID in AA:BB:CC:DD:EE:FF format is required.")
    bssid = bssid.lower()
    if int(bssid[:2], 16) & 1 or bssid == "00:00:00:00:00:00":
        raise ValueError("The BSSID must identify one access point.")
    return ssid, bssid


def input_file(value):
    path = Path(value).expanduser().resolve(strict=True)
    if not path.is_file() or not path.stat().st_size:
        raise ValueError("Choose a nonempty regular file.")
    with path.open("rb") as source:
        if source.read(2) == b"\x1f\x8b":
            raise ValueError("Decompress the .gz file before using it.")
    return path


def psk_supported(security):
    # Discovery must identify PSK explicitly; an ambiguous 'WPA2' is not sufficient.
    return bool(re.search(r"\bPSK\b", security.upper()))


def scoped_capture(app, source, destination, ssid, bssid):
    """Restrict imported captures before passing both -b and -e (which match by OR)."""
    from scapy.all import EAPOL, Dot11, Dot11Elt, PcapReader, PcapWriter, RadioTap
    from scapy.error import Scapy_Exception

    counts = {"beacons": 0, "eapol_frames": 0}
    security_modes = set()
    try:
        with (
            source.open("rb") as stream,
            PcapReader(stream) as reader,
            PcapWriter(str(destination), sync=True, linktype=127) as writer,
        ):
            with app.Spinner("Selecting authentication evidence for " + bssid):
                for packet in reader:
                    if not packet.haslayer(Dot11):
                        continue
                    frame = packet[Dot11]
                    if frame.type == 0 and frame.subtype in {5, 8}:
                        if (frame.addr3 or "").lower() != bssid:
                            continue
                        element = packet.getlayer(Dot11Elt)
                        while element is not None:
                            if element.ID == 0:
                                observed = bytes(element.info)
                                if observed and observed != ssid.encode("utf-8"):
                                    raise ValueError(
                                        "The selected SSID does not match this BSSID's capture."
                                    )
                            if element.ID == 48:
                                body = bytes(element)[2 : 2 + int(element.len)]
                                try:
                                    security_modes.update(
                                        app.security_from_akms(app.rsn_akms(body))
                                    )
                                except ValueError:
                                    security_modes.add("RSN (AKM unknown)")
                            element = element.payload.getlayer(Dot11Elt)
                        counts["beacons"] += 1
                    elif frame.type == 2 and packet.haslayer(EAPOL):
                        direction = int(frame.FCfield) & 3
                        address = {0: frame.addr3, 1: frame.addr1, 2: frame.addr2}.get(direction)
                        if (address or "").lower() != bssid:
                            continue
                        counts["eapol_frames"] += 1
                    else:
                        continue
                    if not packet.haslayer(RadioTap):
                        wrapped = RadioTap() / packet[Dot11]
                        wrapped.time = packet.time
                        packet = wrapped
                    writer.write(packet)
    except (Scapy_Exception, EOFError) as error:
        raise ValueError("Unable to read an 802.11 PCAP/PCAPNG capture.") from error
    if security_modes and not any(psk_supported(mode) for mode in security_modes):
        raise ValueError("Unsupported captured authentication: " + "/".join(sorted(security_modes)))
    return counts


def execute(app, command, label, timeout, *, stdin=None):
    """Drain bounded output in memory: raw Aircrack output can contain passwords."""
    tail = bytearray()
    with app.Spinner(label) as activity:
        process = subprocess.Popen(
            command,
            stdin=stdin if stdin is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=dict(os.environ, LC_ALL="C", LANG="C"),
            start_new_session=(os.name == "posix"),
        )

        def drain():
            while chunk := process.stdout.read(4096):
                tail.extend(chunk)
                del tail[:-65536]

        reader = threading.Thread(target=drain, daemon=True)
        reader.start()
        timed_out = False
        try:
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
            activity.failed = not timed_out and process.returncode not in (0, 1)
        finally:
            app.stop_process(process)
            reader.join(timeout=5)
            process.stdout.close()
        return process.returncode, tail.decode("utf-8", errors="replace"), timed_out


def crack(app, capture, wordlist, ssid, bssid, timeout):
    """Return a report-safe result and, separately, the recovered secret."""
    binary = shutil.which("aircrack-ng")
    if not binary:
        raise RuntimeError(
            "aircrack-ng is missing. Run setup.sh on Kali or add the executable to PATH."
        )
    with tempfile.TemporaryDirectory(prefix="polterheist-aircrack-") as temporary:
        key_file = Path(temporary) / "recovered.key"
        command = [
            binary,
            "-a",
            "2",
            "-q",
            "-b",
            bssid,
            "-e",
            ssid,
            "-w",
            "-",
            "-l",
            str(key_file),
            str(capture),
        ]
        # stdin also supports dictionary paths containing commas, which -w PATH cannot.
        with wordlist.open("rb") as candidates:
            code, output, timed_out = execute(
                app,
                command,
                "Aircrack-ng / checking candidates (Ctrl+C cancels)",
                timeout,
                stdin=candidates,
            )
        secret = (
            key_file.read_text(encoding="utf-8", errors="replace") if key_file.exists() else None
        )
        if secret:
            register_secrets([secret])
        if timed_out:
            status, secret = "TIMEOUT", None
        elif code == 0 and secret:
            status = "RECOVERED"
        elif re.search(r"(?m)^KEY NOT FOUND\s*$", output) and code == 1:
            status, secret = "NOT_RECOVERED", None
        elif any(
            message in output
            for message in (
                "No valid WPA handshakes found",
                "No matching network found",
                "Got no data packets from target network",
                "doesn't seem encrypted",
            )
        ):
            status, secret = "NO_HANDSHAKE", None
        else:
            status, secret = "ERROR", None
        return {"status": status, "exit_code": code, "reason": REASONS[status]}, secret


def capture_live(app, target, preferred, folder, report, seconds):
    app.require_linux(root=True)
    app.require_tools("airodump-ng", "iw", "ip", "nmcli")
    interfaces = app.detect_wireless_interfaces()
    radio = app.linux_radio_candidate(interfaces, preferred, target)
    state = report["radio_setup"] = {}
    with app.prepared_linux_monitor(target, radio, interfaces, folder, state) as (ready, _):
        print(
            "  Waiting for a normal connection from one of your devices; reconnect it manually if needed."
        )
        prefix = folder / "capture"
        command = [
            shutil.which("airodump-ng"),
            "--bssid",
            target["bssid"],
            "--channel",
            str(target["channel"]),
            "--write",
            str(prefix),
            "--output-format",
            "pcap",
            "--write-interval",
            "1",
            ready["name"],
        ]
        code, _, timed_out = execute(
            app, command, f"Passive capture / {seconds}s (Ctrl+C cancels)", seconds
        )
        report["capture_exit_code"] = code
        if not timed_out:
            raise RuntimeError(
                "Airodump-ng exited before the capture deadline; check the adapter and driver."
            )
    if state.get("restore_error"):
        raise RuntimeError(REASONS["RESTORE_FAILED"])
    return input_file(folder / "capture-01.cap")


def audit(
    app, folder, report, target, wordlist, timeout, *, source=None, preferred=None, seconds=120
):
    """Persist every terminal outcome, including cancellation and restoration failure."""
    started = time.monotonic()
    report.update(
        status="running", target=dict(target), started_at=app.utc_now(), timeout_seconds=timeout
    )
    if os.name == "posix":
        folder.chmod(0o700)
    secret = None
    try:
        ssid, bssid = target_values(target["ssid"], target["bssid"])
        wordlist = input_file(wordlist)
        app.require_tools("aircrack-ng")
        report["wordlist"] = {"path": str(wordlist), "bytes": wordlist.stat().st_size}
        app.write_wireless_report(folder, report)
        if source is None:
            if not psk_supported(target.get("security", "")):
                raise ValueError(
                    "Live auditing requires an explicitly observed WPA/WPA2-PSK mode; SAE/EAP/unknown modes are not supported."
                )
            report["capture_seconds"] = seconds
            source = capture_live(app, target, preferred, folder, report, seconds)
        source = input_file(source)
        report["source_capture"] = str(source)
        selected = folder / "authentication.cap"
        report["capture_evidence"] = scoped_capture(app, source, selected, ssid, bssid)
        if not report["capture_evidence"]["eapol_frames"]:
            report.update(status="NO_HANDSHAKE", reason=REASONS["NO_HANDSHAKE"])
        else:
            result, secret = crack(app, selected, wordlist, ssid, bssid, timeout)
            report.update(result)
    except (KeyboardInterrupt, EOFError):
        report.update(status="CANCELLED", reason=REASONS["CANCELLED"])
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        report.update(status="ERROR", reason=app.safe_text(error))
    finally:
        if report.get("radio_setup", {}).get("restore_error"):
            report.update(status="RESTORE_FAILED", reason=REASONS["RESTORE_FAILED"])
        report.update(
            finished_at=app.utc_now(), elapsed_seconds=round(time.monotonic() - started, 3)
        )
        app.write_wireless_report(folder, report)
        LOGGER.info("Wi-Fi password audit finished: %s; report=%s", report["status"], folder)
    print("  " + report["status"] + ": " + app.safe_text(report.get("reason", "")))
    if secret and report["status"] == "RECOVERED":
        print("  Recovered password: " + app.safe_text(secret))
        print("  The password is displayed here only; it is not stored in reports or logs.")
    print("  Report and evidence: " + str(folder))
    return (
        130
        if report["status"] == "CANCELLED"
        else 1
        if report["status"] in {"ERROR", "RESTORE_FAILED"}
        else 0
    )


def number(prompt, default, maximum):
    value = input(f"  {prompt} [{default}]: ").strip()
    try:
        result = int(value) if value else default
    except ValueError as error:
        raise ValueError("Enter a whole number of seconds.") from error
    if not 1 <= result <= maximum:
        raise ValueError(f"Choose between 1 and {maximum} seconds.")
    return result


def wizard(app, ssid=None, bssid=None, mode="menu"):
    print("\n  WPA/WPA2-PERSONAL PASSWORD AUDIT / AIRCRACK-NG")
    print("  Select your own network or an authorized capture. WPS support is not required.")
    if mode == "menu":
        label = "  [1] Capture on Kali/Linux and check a dictionary"
        if not sys.platform.startswith("linux"):
            label = app.tint(label + " [UNAVAILABLE: requires Kali/Linux]", "\033[91m")
        elif not shutil.which("airodump-ng"):
            label = app.tint(label + " [UNAVAILABLE: airodump-ng is not installed]", "\033[91m")
        else:
            label = app.startup_check.annotate("monitor", label, color=app.COLOR)
        print(label)
        print("  [2] Check an existing capture (no Wi-Fi adapter needed)")
        print("  [q] Back")
        while True:
            choice = input("  > ").strip().lower()
            if choice == "q":
                return 0
            if choice in {"1", "2"}:
                mode = "live" if choice == "1" else "file"
                break
            print("  Invalid option.")
    if mode == "live":
        app.require_linux()
        if os.geteuid() != 0:
            app.require_tools("sudo")
            command = [
                "sudo",
                "--",
                sys.executable,
                str(app.BASE / "script.py"),
                "--aircrack",
                "live",
            ]
            for flag, value in (("--ssid", ssid), ("--bssid", bssid)):
                if value is not None:
                    command.extend([flag, value])
            print("  Linux will request sudo privileges to prepare and restore the adapter.")
            return subprocess.run(command, check=False).returncode
    app.require_tools("aircrack-ng")
    source = preferred = target = None
    seconds = 120
    if mode == "file":
        source = input_file(input("  Capture path (.cap/.pcap/.pcapng): ").strip().strip('"'))
        ssid = ssid if ssid is not None else input("  Exact SSID: ")
        bssid = bssid if bssid is not None else input("  BSSID: ").strip()
        ssid, bssid = target_values(ssid, bssid)
        target = {
            "ssid": ssid,
            "bssid": bssid,
            "security": "WPA/WPA2-PSK (capture must contain compatible evidence)",
        }
    wordlist = input_file(input("  Dictionary path (one candidate per line): ").strip().strip('"'))
    timeout = number("Dictionary time limit in seconds", 600, 86400)
    if mode == "live":
        seconds = number("Capture duration in seconds", 120, 3600)
    folder = app.report_folder("wifi_password")
    if os.name == "posix":
        folder.chmod(0o700)
    report = {
        "tool": "POLTERHEIST",
        "version": app.VERSION,
        "mode": mode,
        "status": "preparing",
        "technical_limitations": [],
    }
    try:
        if mode == "live":
            app.require_tools("airodump-ng", "iw", "ip", "nmcli")
            interfaces = app.detect_wireless_interfaces()
            if not interfaces:
                raise RuntimeError("No Wi-Fi interfaces detected.")
            connected = [interface for interface in interfaces if interface.get("connected")]
            preferred = connected[0] if connected else interfaces[0]
            ssid = ssid if ssid is not None else preferred.get("connected_ssid")
            if not ssid:
                ssid = input("  Exact SSID of your network: ")
            if bssid:
                _, bssid = target_values(ssid, bssid)
            aps = app.discover_wifi(preferred, interfaces, folder, report["technical_limitations"])
            targets = [
                ap for ap in aps if ap["ssid"] == ssid and (bssid is None or ap["bssid"] == bssid)
            ]
            if not targets:
                raise RuntimeError("The selected SSID/BSSID was not observed.")
            app.show_wifi(targets)
            target = (
                targets[0] if len(targets) == 1 else app.select_item(targets, "BSSID", key="bssid")
            )
            if target is None:
                raise KeyboardInterrupt
        report["authorization"] = {
            "source": "operator_selected_network",
            "ssid": target["ssid"],
            "bssid": target["bssid"],
        }
        print("  Selected: " + app.safe_text(repr(target["ssid"])) + " / " + target["bssid"])
        return audit(
            app,
            folder,
            report,
            target,
            wordlist,
            timeout,
            source=source,
            preferred=preferred,
            seconds=seconds,
        )
    except (KeyboardInterrupt, EOFError):
        report.update(status="CANCELLED", reason=REASONS["CANCELLED"])
        return 130
    except (OSError, ValueError, RuntimeError) as error:
        report.update(status="ERROR", reason=app.safe_text(error))
        raise
    finally:
        app.write_wireless_report(folder, report)
