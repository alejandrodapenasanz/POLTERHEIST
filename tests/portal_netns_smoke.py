"""Root-only CI integration in three isolated network namespaces; no external traffic."""

import json
import os
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import script as app  # noqa: E402


def run(args, namespace=None, check=True, **kwargs):
    command = (["ip", "netns", "exec", namespace] if namespace else []) + args
    result = subprocess.run(command, text=True, capture_output=True, timeout=20, **kwargs)
    if check and result.returncode:
        raise RuntimeError(f"{command}: {result.stdout} {result.stderr}")
    return result


def main():
    if not sys.platform.startswith("linux") or os.geteuid() != 0:
        raise RuntimeError("This isolated integration test requires Linux/root.")
    suffix = uuid.uuid4().hex[:8]
    gateway, client, upstream = [f"pt-{name}-{suffix}" for name in ("gw", "client", "up")]
    processes, namespaces, host_links = [], [], []
    config = {"mode": "router", "lan": "portal0", "wan": "uplink0", "network": "10.77.0.0/24"}
    table = "polterheist_123456abcdef"
    with tempfile.TemporaryDirectory(prefix="polterheist-netns-") as directory:
        folder = Path(directory)
        logfile = (folder / "services.log").open("w")
        try:
            for ns in (gateway, client, upstream):
                run(["ip", "netns", "add", ns])
                namespaces.append(ns)
                run(["ip", "link", "set", "lo", "up"], ns)
            pairs = [
                (gateway, "portal0", client, "client0"),
                (gateway, "uplink0", upstream, "server0"),
            ]
            for index, (left, left_name, right, right_name) in enumerate(pairs):
                a, b = f"pa{index}{suffix}", f"pb{index}{suffix}"
                run(["ip", "link", "add", a, "type", "veth", "peer", "name", b])
                host_links.extend((a, b))
                for name, ns, renamed in ((a, left, left_name), (b, right, right_name)):
                    run(["ip", "link", "set", name, "netns", ns])
                    run(["ip", "link", "set", name, "name", renamed], ns)
                    run(["ip", "link", "set", renamed, "up"], ns)
            for ns, name, address in (
                (gateway, "portal0", "10.77.0.1/24"),
                (gateway, "uplink0", "198.18.0.1/24"),
                (client, "client0", "10.77.0.2/24"),
                (upstream, "server0", "198.18.0.2/24"),
            ):
                run(["ip", "address", "add", address, "dev", name], ns)
            run(["ip", "route", "add", "default", "via", "10.77.0.1"], client)
            run(["ip", "route", "add", "10.77.0.0/24", "via", "198.18.0.1"], upstream)
            run(["sysctl", "-w", "net.ipv4.ip_forward=1"], gateway)
            run(["nft", "add", "table", "inet", "fixture_keep"], gateway)
            run(
                ["nft", "--check", "--file", "-"],
                gateway,
                input=app.portal_nft_rules(config, table),
            )

            # Verify both profiles with NetworkManager's real keyfile parser, offline.
            for mode in ("wifi", "router"):
                cfg = dict(
                    config, mode=mode, ssid="Portal ñ;=", password="fixture-password", channel=6
                )
                profile = app.portal_profile(cfg, str(uuid.uuid4()))
                run(
                    ["nmcli", "--offline", "connection", "modify", "connection.id", "Fixture"],
                    input=profile,
                )

            origin_code = """
import http.server, threading, sys
from pathlib import Path
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.end_headers(); self.wfile.write(b"ORIGIN_FIXTURE")
    def log_message(self, *args): pass
servers = [http.server.ThreadingHTTPServer(("198.18.0.2", p), Handler) for p in (80, 8443)]
for s in servers: threading.Thread(target=s.serve_forever, daemon=True).start()
Path(sys.argv[1]).write_text("ready")
threading.Event().wait()
"""
            gateway_code = """
import sys, json
from pathlib import Path
import script as app
config = json.loads(sys.argv[1]); table = sys.argv[2]
app.portal_nft(app.portal_nft_rules(config, table))
access = app.PortalAccess(config["network"], lambda ip: app.portal_identity("portal0", ip),
    lambda ip, mac, seconds: app.portal_grant(table, ip, mac, seconds), seconds=10)
server = app.PortalServer(("10.77.0.1", 8080), "Fixture portal", access)
Path(sys.argv[3]).write_text("ready")
server.serve_forever()
"""
            for ns, code, arguments in (
                (upstream, origin_code, [str(folder / "origin.ready")]),
                (gateway, gateway_code, [json.dumps(config), table, str(folder / "portal.ready")]),
            ):
                processes.append(
                    subprocess.Popen(
                        ["ip", "netns", "exec", ns, sys.executable, "-u", "-c", code, *arguments],
                        stdout=logfile,
                        stderr=subprocess.STDOUT,
                        cwd=app.BASE,
                    )
                )
            deadline = time.monotonic() + 10
            while not all((folder / name).exists() for name in ("origin.ready", "portal.ready")):
                if any(p.poll() is not None for p in processes) or time.monotonic() > deadline:
                    raise RuntimeError((folder / "services.log").read_text())
                time.sleep(0.1)

            request_code = """
import http.client, json, sys
options = json.loads(sys.argv[1])
c = http.client.HTTPConnection(options["host"], options["port"], timeout=1)
try:
    c.request(options.get("method", "GET"), options.get("path", "/"), options.get("body"),
        {"Content-Type":"application/x-www-form-urlencoded"})
    r=c.getresponse(); print(json.dumps({"status":r.status,"body":r.read().decode()}))
except (OSError, http.client.HTTPException) as e:
    print(json.dumps({"blocked":type(e).__name__}))
finally: c.close()
"""

            def request(host="198.18.0.2", port=80, **options):
                payload = json.dumps(dict(host=host, port=port, **options))
                return json.loads(run([sys.executable, "-c", request_code, payload], client).stdout)

            import re
            from urllib.parse import urlencode

            captured = request()
            assert captured["status"] == 302 and "ORIGIN_FIXTURE" not in captured["body"], captured
            page = request("10.77.0.1", 8080)
            assert page["status"] == 200, page
            token = re.search(r'name="token" value="([^"]+)"', page["body"])[1]
            assert "blocked" in request(port=8443), "Unauthenticated non-HTTP traffic escaped"
            forged = request(
                "10.77.0.1", 8080, method="POST", path="/accept", body="accept=yes&token=forged"
            )
            assert forged["status"] == 403, forged
            accepted = request(
                "10.77.0.1",
                8080,
                method="POST",
                path="/accept",
                body=urlencode({"accept": "yes", "token": token}),
            )
            assert accepted["status"] == 303, accepted
            assert request()["body"] == "ORIGIN_FIXTURE", "Authenticated HTTP did not pass"
            assert request(port=8443)["body"] == "ORIGIN_FIXTURE", "Authenticated TCP did not pass"
            time.sleep(11)
            assert "blocked" in request(port=8443), "Expired client retained Internet access"
            assert request()["status"] == 302, "Expired HTTP did not return to portal"
            assert 'name="token"' in request("10.77.0.1", 8080)["body"]
            run(["nft", "delete", "table", "inet", table], gateway)
            run(["nft", "list", "table", "inet", "fixture_keep"], gateway)
            assert (
                run(["nft", "list", "table", "inet", table], gateway, check=False).returncode != 0
            )
            # Exercise actual NetworkManager loading, shared DHCP/NAT, and rollback
            # on the isolated gateway using a private D-Bus (never the host daemon).
            processes[1].terminate()
            processes[1].wait(timeout=5)
            run(["ip", "address", "del", "10.77.0.1/24", "dev", "portal0"], gateway)
            run(["ip", "route", "add", "default", "via", "198.18.0.2"], gateway)
            bus_address = "unix:path=" + str(folder / "bus")
            environment = dict(
                os.environ, DBUS_SYSTEM_BUS_ADDRESS=bus_address, XDG_RUNTIME_DIR=directory
            )
            processes.append(
                subprocess.Popen(
                    [
                        "ip",
                        "netns",
                        "exec",
                        gateway,
                        "dbus-daemon",
                        "--session",
                        "--nofork",
                        "--address=" + bus_address,
                    ],
                    env=environment,
                    stdout=logfile,
                    stderr=subprocess.STDOUT,
                )
            )
            deadline = time.monotonic() + 10
            while not (folder / "bus").exists():
                if time.monotonic() > deadline:
                    raise RuntimeError("Private test D-Bus did not start")
                time.sleep(0.1)
            (folder / "empty").mkdir()
            (folder / "NetworkManager.conf").write_text(
                "[main]\nplugins=keyfile\nno-auto-default=*\ndns=none\nrc-manager=unmanaged\n"
                "auth-polkit=root-only\nhostname-mode=none\n"
                "[device-portal]\nmatch-device=interface-name:portal0\nmanaged=1\n"
                "[device-uplink]\nmatch-device=interface-name:uplink0\nmanaged=0\n"
            )
            processes.append(
                subprocess.Popen(
                    [
                        "ip",
                        "netns",
                        "exec",
                        gateway,
                        "unshare",
                        "--mount",
                        "--propagation",
                        "private",
                        sys.executable,
                        "-c",
                        # udev does not follow moved interfaces into netns. A private,
                        # read-only /sys lets NM use its container/netlink backend.
                        "import os, subprocess, sys; "
                        "subprocess.run(['mount', '--bind', '/sys', '/sys'], check=True); "
                        "subprocess.run(['mount', '-o', 'remount,bind,ro', '/sys'], check=True); "
                        "os.execvp(sys.argv[1], sys.argv[1:])",
                        "NetworkManager",
                        "--debug",
                        "--config=" + str(folder / "NetworkManager.conf"),
                        "--config-dir=" + str(folder / "empty"),
                        "--system-config-dir=" + str(folder / "empty"),
                        "--intern-config=" + str(folder / "intern.conf"),
                        "--pid-file=" + str(folder / "nm.pid"),
                        "--state-file=" + str(folder / "nm.state"),
                    ],
                    env=environment,
                    stdout=logfile,
                    stderr=subprocess.STDOUT,
                )
            )
            deadline = time.monotonic() + 15
            while True:
                probe = run(
                    ["nmcli", "-g", "GENERAL.NM-MANAGED", "device", "show", "portal0"],
                    gateway,
                    env=environment,
                    check=False,
                )
                if probe.returncode == 0 and probe.stdout.strip() in {"yes", "no"}:
                    break
                if processes[-1].poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError(
                        probe.stdout + probe.stderr + (folder / "services.log").read_text()
                    )
                time.sleep(0.2)
            lifecycle_code = """
import sys, json, socket, errno
from pathlib import Path
import script as app
config = json.loads(sys.argv[1]); folder = Path(sys.argv[2])
with app.portal_network(config, folder) as (table, state):
    assert state["status"] == "active"
    assert app.linux_nm_state(config["lan"])[1] == state["connection_uuid"]
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        try: probe.bind(("10.77.0.1", 53))
        except OSError as error: assert error.errno == errno.EADDRINUSE
        else: raise AssertionError("Shared DNS was not listening")
assert state["restored"], state
assert app.linux_nm_state(config["lan"])[1] is None
print("PASS: real NetworkManager activation, shared DNS, and verified cleanup")
"""
            lifecycle = subprocess.run(
                [
                    "ip",
                    "netns",
                    "exec",
                    gateway,
                    sys.executable,
                    "-c",
                    lifecycle_code,
                    json.dumps(config),
                    directory,
                ],
                env=environment,
                text=True,
                capture_output=True,
                timeout=90,
                cwd=app.BASE,
            )
            if lifecycle.returncode:
                raise RuntimeError(
                    lifecycle.stdout + lifecycle.stderr + (folder / "services.log").read_text()
                )
            print(lifecycle.stdout.strip())
            print(
                "PASS: real isolated routing, captive HTTP, denied TCP, token validation, access, expiry, scoped cleanup, and NetworkManager profile parsing"
            )
        finally:
            for process in processes:
                process.terminate()
            for process in processes:
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            logfile.close()
            for ns in reversed(namespaces):
                run(["ip", "netns", "delete", ns], check=False)
            for name in host_links:
                run(["ip", "link", "delete", name], check=False)


if __name__ == "__main__":
    main()
