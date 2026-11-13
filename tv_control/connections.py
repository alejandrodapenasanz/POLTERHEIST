"""Selected IoT connection attempts with explicit protocol/transport semantics."""

import datetime
import re

from .iot import check_connections, tcp_candidates
from .manager import BACKENDS
from .protocols import mqtt


def select_iot_devices(devices, text=None):
    candidates = {d.id: d for d in devices}
    if text is None:
        return [d for d in devices if d.available]
    if len(text) > 512 or not re.fullmatch(r"\s*[0-9]+\s*(,\s*[0-9]+\s*)*", text):
        raise ValueError("Enter device IDs separated by commas, for example 1,3,5")
    identifiers = [int(part.strip()) for part in text.split(",")]
    if len(set(identifiers)) != len(identifiers):
        raise ValueError("Duplicate IDs are not allowed")
    for identifier in identifiers:
        if identifier not in candidates or not candidates[identifier].available:
            raise ValueError(f"Device {identifier} is unknown or stale; rescan first")
    return [candidates[i] for i in identifiers]


class Connections:
    def __init__(self, network, config, bluetooth):
        self.network, self.config, self.bluetooth = network, config, bluetooth
        self.sessions = {}
        self.records = {}

    def route(self, device):
        if not device.available:
            return None, "NO", "Stale/unavailable"
        for endpoint in device.endpoints:
            if endpoint.details.get("transport") == "ble":
                return endpoint, "YES*", "GATT; pairing/access unverified"
            if self.network and self.network.accepts(endpoint.ip):
                if endpoint.controllable and endpoint.protocol in BACKENDS:
                    return endpoint, "YES*", "Media protocol; authorization unverified"
                if endpoint.protocol in ("MQTT", "MQTT TLS"):
                    return endpoint, "LIMITED*", "MQTT handshake; session is then closed"
        if self.network and tcp_candidates(device, self.network):
            return device.primary, "LIMITED*", "TCP reachability only; no authenticated controller"
        return None, "NO", "No implemented connection adapter"

    def connect(self, device):
        endpoint, possible, reason = self.route(device)
        record = {
            "device_id": device.id,
            "state": "UNSUPPORTED",
            "detail": reason,
            "protocol": endpoint.protocol if endpoint else "",
            "error": "",
            "recorded_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        if possible == "NO":
            device.primary.details["iot_connection"] = record
            self.records[device.id] = record
            return record
        backend = None
        try:
            if endpoint.details.get("transport") == "ble":
                record.update(state="CONNECTED", detail=self.bluetooth.connect(endpoint))
            elif endpoint.controllable and endpoint.protocol in BACKENDS:
                old = self.sessions.pop(device.id, None)
                if old:
                    old.disconnect()
                backend = BACKENDS[endpoint.protocol](endpoint, self.network, self.config)
                backend.connect()
                self.sessions[device.id] = backend
                record.update(
                    state="CONNECTED" if endpoint.protocol == "Google Cast" else "PROTOCOL READY",
                    detail="No media started; use Media control to choose content",
                )
            elif endpoint.protocol in ("MQTT", "MQTT TLS"):
                result = mqtt.check(endpoint, self.network, self.config, confirmed=True)
                record.update(
                    state="SESSION VERIFIED / CLOSED"
                    if result["return_code"] == 0 and result["disconnect_sent"]
                    else "NOT CONNECTED",
                    detail=result["status"],
                    error=result["error"],
                )
            else:
                results = check_connections(device, self.network, self.config, confirmed=True)
                reachable = any(r["status"] == "TCP REACHABLE" for r in results)
                record.update(
                    state="TCP ONLY / CLOSED" if reachable else "NOT CONNECTED",
                    detail="Transport check; authentication and control unverified",
                )
        except Exception as error:
            if backend:
                try:
                    backend.disconnect()
                except Exception:
                    pass
            record.update(state="CONNECTION FAILED", error=str(error))
        except BaseException:
            if backend:
                backend.disconnect()
            raise
        endpoint.details["iot_connection"] = record
        self.records[device.id] = record
        return record

    def close(self):
        failures = []
        for identifier, backend in list(self.sessions.items()):
            try:
                backend.disconnect()
            except Exception as error:
                failures.append(str(error))
            finally:
                self.sessions.pop(identifier, None)
        try:
            self.bluetooth.disconnect_all()
        except Exception as error:
            failures.append(str(error))
        if failures:
            raise RuntimeError("Disconnect unconfirmed: " + "; ".join(failures))
        for record in self.records.values():
            if record["state"] in ("CONNECTED", "PROTOCOL READY"):
                record["state"] = "DISCONNECTED"
