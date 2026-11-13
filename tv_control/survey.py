"""One explicit user selection surveys all implemented, available transports."""

from .models import safe_text
from .wireless import WirelessDiscovery


def survey(app):
    discovery = app.discovery
    discovery.results, discovery.warnings = [], []
    for device in discovery.devices.values():
        device.available = any(
            e.details.get("transport") == "ble" and app.bluetooth.connected(e.uid)
            for e in device.endpoints
        )

    def record(backend, scope, status, error="", count=0):
        result = {
            "backend": backend,
            "scope": scope,
            "status": status,
            "error": error,
            "count": count,
        }
        discovery.results.append(result)
        print(
            f"  {backend} / {safe_text(scope)}: {status}"
            + (" — " + safe_text(error) if error else "")
        )

    try:
        if app.network:
            try:
                app.scan()
            except (RuntimeError, OSError) as error:
                record("LAN", "IPv4", "ERROR", str(error))
        else:
            record("LAN", "IPv4", "UNAVAILABLE", app.network_error)
        print(
            "  Wi-Fi Direct: scanning eligible PHYs; existing connections will not be disconnected."
        )
        print("  Close other P2P discovery apps before this automatic survey.")
        engine = WirelessDiscovery(app.root, discovery.config)
        try:
            adapters = engine.adapters()
        except (RuntimeError, OSError) as error:
            adapters = []
            record("p2p", "radio", "UNAVAILABLE", str(error))
        if not adapters and not any(r["backend"] == "p2p" for r in discovery.results):
            record("p2p", "radio", "UNAVAILABLE", "No physical Wi-Fi adapters")
        scanned = set()
        for adapter in adapters:
            if not adapter.eligible:
                record("p2p", adapter.interface, "SKIPPED", "; ".join(adapter.reasons))
                continue
            if adapter.phy in scanned:
                record(
                    "p2p",
                    adapter.interface,
                    "SKIPPED",
                    "PHY already surveyed via another interface",
                )
                continue
            scanned.add(adapter.phy)
            try:
                result = engine.scan(
                    adapter, confirmed=True, progress=lambda state: print("  P2P: " + state)
                )
                discovery.add_wireless(result)
                result.export(app.root)
                record("p2p", adapter.interface, result.state, result.error, result.fresh_count)
                for warning in result.warnings:
                    print("  [!] " + safe_text(warning))
                if result.state == "CANCELLED" or result.error_code == "CANCELLED":
                    raise KeyboardInterrupt
            except (RuntimeError, OSError) as error:
                record("p2p", adapter.interface, "ERROR", str(error))
        try:
            for adapter in app.bluetooth.adapters():
                print("  Bluetooth LE: " + safe_text(adapter))
                try:
                    endpoints = app.bluetooth.scan(adapter)
                    discovery.replace_scope(
                        endpoints,
                        lambda e: (
                            e.details.get("transport") == "ble"
                            and e.details.get("adapter") == adapter
                        ),
                    )
                    record(
                        "ble",
                        adapter,
                        "DETECTED" if endpoints else "NO RESPONSE",
                        count=len(endpoints),
                    )
                except Exception as error:
                    record("ble", adapter, "UNAVAILABLE", str(error))
        except (RuntimeError, OSError) as error:
            record("ble", "radio", "UNAVAILABLE", str(error))
    except KeyboardInterrupt:
        record(
            "survey",
            "all",
            "CANCELLED",
            "Partial observations retained; discovery cleanup requested",
        )
    finally:
        print("  Other RF families (Zigbee/Thread/Z-Wave/SDR) have no discovery adapter yet.")
        print("  Survey report: " + str(discovery.export(app.root)))
