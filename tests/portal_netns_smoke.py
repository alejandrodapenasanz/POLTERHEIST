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

            page = request()
            assert page["status"] == 200 and "ORIGIN_FIXTURE" not in page["body"], page
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
            assert 'name="token"' in request()["body"], "Expired HTTP did not return to portal"
            run(["nft", "delete", "table", "inet", table], gateway)
            run(["nft", "list", "table", "inet", "fixture_keep"], gateway)
            assert (
                run(["nft", "list", "table", "inet", table], gateway, check=False).returncode != 0
            )
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
