"""Explicit MQTT 3.1.1 session checks; no subscribe, publish or persistent session."""

import datetime
import secrets
import socket
import ssl
import time

REASONS = {
    0: "ANONYMOUS SESSION ACCEPTED",
    1: "PROTOCOL VERSION REJECTED",
    2: "CLIENT IDENTIFIER REJECTED",
    3: "SERVER UNAVAILABLE",
    4: "CREDENTIALS REQUIRED / REJECTED",
    5: "NOT AUTHORIZED",
}


def connect_packet(client_id):
    encoded = client_id.encode("ascii")
    if not 1 <= len(encoded) <= 23 or not client_id.isalnum():
        raise ValueError("MQTT test identifier must be 1-23 alphanumeric characters")
    # Protocol v3.1.1, clean session, no user/password, no will, ten-second keepalive.
    body = b"\x00\x04MQTT\x04\x02\x00\x0a" + len(encoded).to_bytes(2, "big") + encoded
    return b"\x10" + bytes([len(body)]) + body


def check(endpoint, network, config, confirmed=False):
    if not confirmed:
        raise ValueError("Select an MQTT endpoint explicitly before attempting a session")
    if (
        network is None
        or not network.accepts(endpoint.ip)
        or endpoint.protocol not in ("MQTT", "MQTT TLS")
        or type(endpoint.port) is not int
        or not 1 <= endpoint.port <= 65535
    ):
        raise ValueError("Select an advertised MQTT IPv4 service on the selected LAN")
    result = {
        "protocol": "MQTT 3.1.1",
        "ip": endpoint.ip,
        "port": endpoint.port,
        "status": "NOT CHECKED",
        "return_code": None,
        "error": "",
        "tls": endpoint.protocol == "MQTT TLS",
        "tls_verified": False,
        "credentials_sent": False,
        "publish_tested": False,
        "subscribe_tested": False,
        "disconnect_sent": False,
        "observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
    deadline = time.monotonic() + min(5, config.connect_timeout)
    channel = None

    def remaining():
        value = deadline - time.monotonic()
        if value <= 0:
            raise TimeoutError("MQTT check deadline exceeded")
        return value

    try:
        channel = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        channel.settimeout(remaining())
        channel.bind((network.ip, 0))
        channel.connect((endpoint.ip, endpoint.port))
        if result["tls"]:
            channel.settimeout(remaining())
            channel = ssl.create_default_context().wrap_socket(channel, server_hostname=endpoint.ip)
            result["tls_verified"] = True
        # Random unique ID prevents taking over an existing client's session.
        channel.settimeout(remaining())
        channel.sendall(connect_packet("ph" + secrets.token_hex(10)))
        response = b""
        while len(response) < 4:
            channel.settimeout(remaining())
            chunk = channel.recv(4 - len(response))
            if not chunk:
                raise ValueError("Broker closed before a complete CONNACK")
            response += chunk
        if response[:2] != b"\x20\x02" or response[2] != 0 or response[3] not in REASONS:
            raise ValueError("Invalid MQTT 3.1.1 CONNACK for a clean session")
        result.update(status=REASONS[response[3]], return_code=response[3])
        if response[3] == 0:
            channel.settimeout(remaining())
            channel.sendall(b"\xe0\x00")
            result["disconnect_sent"] = True
    except ssl.SSLError as error:
        result.update(status="TLS FAILED", error=str(error)[:300])
    except (OSError, ValueError) as error:
        result.update(status="CHECK FAILED", error=str(error)[:300])
    finally:
        if channel is not None:
            channel.close()
    endpoint.details["mqtt_check"] = result
    # A temporary connection does not establish topic permissions or a control adapter.
    return result
