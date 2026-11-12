"""Parse advertised WFD subelements, not names or guessed vendor capabilities."""

import datetime
import re

from .models import Endpoint


def mac_address(value):
    if (
        isinstance(value, list)
        and len(value) == 6
        and all(type(x) is int and 0 <= x <= 255 for x in value)
    ):
        value = ":".join(f"{x:02x}" for x in value)
    if not isinstance(value, str) or not re.fullmatch(
        r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}", value
    ):
        raise ValueError("Invalid P2P device address")
    raw = bytes.fromhex(value.replace(":", ""))
    if not any(raw) or raw[0] & 1:
        raise ValueError("P2P device address must be unicast")
    return value.lower()


def parse_wfd(value):
    result = {
        "status": "NOT_ADVERTISED",
        "sink": False,
        "role": "UNKNOWN",
        "session_available": None,
        "rtsp_port": None,
        "raw_hex": "",
    }
    if value in (None, [], b"", ""):
        return result
    try:
        if isinstance(value, str):
            if not re.fullmatch(r"[0-9a-fA-F]{2,8192}", value) or len(value) % 2:
                raise ValueError("Invalid WFD hex")
            data = bytes.fromhex(value)
        elif isinstance(value, (bytes, bytearray)):
            data = bytes(value)
        elif isinstance(value, list) and all(type(x) is int and 0 <= x <= 255 for x in value):
            data = bytes(value)
        else:
            raise ValueError("Invalid WFD byte array")
        if len(data) > 4096:
            raise ValueError("WFD payload too large")
        result["raw_hex"] = data.hex()
        # NM WfdIEs and supplicant Peer.IEs contain raw WFD subelements.
        # Each is an ID byte followed by a big-endian 16-bit payload length.
        offset, device_info = 0, None
        while offset < len(data):
            if offset + 3 > len(data):
                raise ValueError("Truncated WFD header")
            identifier, size = data[offset], int.from_bytes(data[offset + 1 : offset + 3], "big")
            offset += 3
            if offset + size > len(data):
                raise ValueError("Truncated WFD payload")
            if identifier == 0:
                if size != 6 or device_info is not None:
                    raise ValueError("Invalid/duplicate WFD Device Information")
                device_info = data[offset : offset + size]
            offset += size
        if device_info is None:
            result["status"] = "DEVICE_INFO_MISSING"
            return result
        flags = int.from_bytes(device_info[:2], "big")
        role = flags & 3
        availability = (flags >> 4) & 3
        result.update(
            status="ADVERTISED",
            role=("SOURCE", "PRIMARY_SINK", "SECONDARY_SINK", "DUAL_ROLE")[role],
            sink=role in (1, 2, 3),
            session_available=availability == 1 if availability in (0, 1) else None,
            rtsp_port=int.from_bytes(device_info[2:4], "big"),
            device_info_flags=flags,
            max_throughput_mbps=int.from_bytes(device_info[4:6], "big"),
        )
        return result
    except ValueError as error:
        result.update(status="MALFORMED", error=str(error))
        return result


def peer_endpoint(properties, adapter, backend, path, fresh):
    nm = backend == "networkmanager"
    address = mac_address(properties.get("HwAddress") if nm else properties.get("DeviceAddress"))
    wfd = parse_wfd(properties.get("WfdIEs") if nm else properties.get("IEs"))
    state = (
        "WFD CAPABLE"
        if wfd["sink"]
        else "WFD SOURCE ONLY"
        if wfd["role"] == "SOURCE"
        else "P2P ONLY"
    )
    if wfd["sink"] and wfd["session_available"] is False:
        state = "WFD SINK BUSY (advertised)"
    if not fresh:
        state = "CACHED; " + state
    return Endpoint(
        "Wi-Fi Direct",
        f"p2p:{adapter.interface}:{address}",
        "",
        0,
        str(properties.get("Name" if nm else "DeviceName") or "Unknown")[:256],
        str(properties.get("Model" if nm else "ModelName") or "Unknown")[:256],
        str(properties.get("Manufacturer") or "Unknown")[:256],
        kind="Wi-Fi Display receiver (advertised)"
        if wfd["sink"]
        else "P2P peer (device type unverified)",
        note=state + "; pairing and streaming untested",
        controllable=False,
        details={
            "transport": "p2p",
            "p2p_address": address,
            "interface": adapter.interface,
            "phy": adapter.phy,
            "backend": backend,
            "peer_path": path,
            "adapter_path": adapter.control_path,
            "wfd": wfd,
            "fresh": fresh,
            "classification": state,
            "last_seen_boottime": properties.get("LastSeen") if nm else None,
        },
        sources=[backend + " P2P D-Bus"],
        reachability="RADIO ADVERTISEMENT; NO IP LINK"
        if fresh
        else "CACHED PEER; PRESENCE UNVERIFIED",
        confidence="ADVERTISED; NOT SESSION VERIFIED",
        authentication="NOT PAIRED / NOT AUTHORIZED BY RECEIVER",
        evidence=[
            "Exact P2P device address scoped to selected local interface",
            "WFD Device Information subelement"
            if wfd["sink"]
            else "No valid receiving role established",
        ],
        observed_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    )
