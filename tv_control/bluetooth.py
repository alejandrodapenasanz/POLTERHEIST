"""Owned BLE scanning/GATT sessions on one persistent asyncio loop (Bleak 3)."""

import asyncio
import concurrent.futures
import datetime
import logging
import re
import sys
import threading
import uuid
from pathlib import Path

from .models import Endpoint

LOG = logging.getLogger(__name__)


def advertisement(device, data, adapter):
    address = str(device.address)
    if not re.fullmatch(r"[A-Za-z0-9:._-]{1,128}", address):
        raise ValueError("Invalid BLE device identifier")
    services = []
    for value in list(data.service_uuids or [])[:64]:
        try:
            services.append(str(uuid.UUID(value)))
        except (ValueError, TypeError, AttributeError):
            continue
    manufacturer = {
        str(key): bytes(value)[:256].hex()
        for key, value in list((data.manufacturer_data or {}).items())[:16]
        if type(key) is int and 0 <= key <= 65535 and isinstance(value, (bytes, bytearray))
    }
    return Endpoint(
        "Bluetooth LE",
        f"ble:{adapter}:{address.lower()}",
        "",
        0,
        str(data.local_name or device.name or "Unknown BLE peripheral")[:256],
        kind="BLE peripheral (type unknown)",
        note="GATT connection can be attempted; advertising does not prove connectability or authorization",
        details={
            "transport": "ble",
            "adapter": adapter,
            "ble_address": address,
            "service_uuids": services,
            "manufacturer_data": manufacturer,
            "rssi": data.rssi if type(data.rssi) is int else None,
            "fresh": True,
        },
        sources=["Bluetooth LE advertisement"],
        reachability="RADIO ADVERTISEMENT; GATT UNTESTED",
        authentication="UNKNOWN; PAIRING NOT ATTEMPTED",
        evidence=["Exact BLE address scoped to local adapter; private addresses may rotate"],
        observed_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    )


class Bluetooth:
    def __init__(self, config, scanner_factory=None, client_factory=None, platform=None):
        self.config = config
        self.scanner_factory, self.client_factory = scanner_factory, client_factory
        self.platform = platform or sys.platform
        self.loop = self.thread = None
        self.devices, self.clients = {}, {}

    def adapters(self):
        if self.platform.startswith("linux"):
            adapters = sorted(p.name for p in Path("/sys/class/bluetooth").glob("hci[0-9]*"))
            return adapters or ["default"]
        if self.platform == "win32":
            return ["default"]
        raise RuntimeError("BLE backend supports Linux/Windows in this application")

    def _factories(self):
        if self.scanner_factory is None or self.client_factory is None:
            try:
                from bleak import BleakClient, BleakScanner
            except ImportError as error:
                raise RuntimeError(
                    "BLE dependency unavailable; install requirements through setup.sh on Kali"
                ) from error
            self.scanner_factory = self.scanner_factory or BleakScanner
            self.client_factory = self.client_factory or BleakClient

    def _start_loop(self):
        if self.loop:
            return
        self._factories()
        self.loop = asyncio.new_event_loop()
        ready = threading.Event()

        def worker():
            asyncio.set_event_loop(self.loop)
            ready.set()
            try:
                self.loop.run_forever()
            finally:
                tasks = asyncio.all_tasks(self.loop)
                for task in tasks:
                    task.cancel()
                if tasks:
                    self.loop.run_until_complete(asyncio.wait(tasks, timeout=6))
                self.loop.close()

        self.thread = threading.Thread(target=worker, name="iot-ble", daemon=True)
        self.thread.start()
        ready.wait(timeout=2)

    def call(self, factory, timeout):
        self._start_loop()
        future = asyncio.run_coroutine_threadsafe(factory(), self.loop)
        try:
            return future.result(timeout=timeout)
        except (concurrent.futures.TimeoutError, KeyboardInterrupt):
            future.cancel()
            raise

    def scan(self, adapter):
        return self.call(lambda: self._scan(adapter), self.config.ble_timeout + 13)

    async def _scan(self, adapter):
        found = {}
        if self.clients:
            raise RuntimeError(
                "BLE scan deferred while owned GATT sessions are active; disconnect and rescan"
            )
        self.devices = {uid: value for uid, value in self.devices.items() if value[1] != adapter}

        def detected(device, data):
            if len(found) >= self.config.max_devices:
                return
            try:
                endpoint = advertisement(device, data, adapter)
                found[endpoint.uid] = endpoint
                self.devices[endpoint.uid] = (device, adapter)
            except (ValueError, TypeError, AttributeError):
                LOG.debug("Malformed BLE advertisement ignored", exc_info=True)

        kwargs = {"bluez": {"adapter": adapter}} if adapter != "default" else {}
        scanner = self.scanner_factory(detection_callback=detected, **kwargs)
        try:
            await asyncio.wait_for(scanner.start(), timeout=5)
            await asyncio.sleep(self.config.ble_timeout)
        finally:
            await asyncio.wait_for(scanner.stop(), timeout=5)
        return list(found.values())

    def connect(self, endpoint):
        return self.call(lambda: self._connect(endpoint), self.config.connect_timeout + 7)

    async def _connect(self, endpoint):
        if endpoint.uid not in self.devices:
            raise ValueError("BLE observation expired; rescan before connecting")
        existing = self.clients.get(endpoint.uid)
        if existing and existing.is_connected:
            return "GATT CONNECTED"
        if existing:
            await asyncio.wait_for(existing.disconnect(), timeout=5)
            self.clients.pop(endpoint.uid, None)
        device, adapter = self.devices[endpoint.uid]
        kwargs = {"bluez": {"adapter": adapter}} if adapter != "default" else {}
        client = self.client_factory(
            device, pair=False, timeout=self.config.connect_timeout, **kwargs
        )
        try:
            await asyncio.wait_for(client.connect(), timeout=self.config.connect_timeout)
            if not client.is_connected:
                raise RuntimeError("BLE server did not accept a GATT connection")
            endpoint.details["gatt_services"] = [str(s.uuid) for s in list(client.services)[:64]]
            self.clients[endpoint.uid] = client
            return "GATT CONNECTED; protected reads/writes untested"
        except BaseException:
            try:
                await asyncio.wait_for(client.disconnect(), timeout=5)
            except Exception:
                LOG.warning("BLE disconnect after failed connection unconfirmed", exc_info=True)
            raise

    def connected(self, uid):
        client = self.clients.get(uid)
        return bool(client and client.is_connected)

    async def _disconnect_all(self):
        clients, self.clients = list(self.clients.values()), {}
        if clients:
            results = await asyncio.gather(
                *(asyncio.wait_for(c.disconnect(), timeout=5) for c in clients),
                return_exceptions=True,
            )
            if any(isinstance(r, BaseException) for r in results):
                raise RuntimeError("One or more BLE disconnects could not be confirmed")

    def disconnect_all(self):
        if self.loop:
            self.call(self._disconnect_all, 7)

    def close(self):
        if self.loop is None:
            return
        try:
            self.disconnect_all()
        finally:
            self.loop.call_soon_threadsafe(self.loop.stop)
            self.thread.join(timeout=8)
            if self.thread.is_alive():
                raise RuntimeError("BLE event loop did not finish cleanup")
            self.loop = self.thread = None
