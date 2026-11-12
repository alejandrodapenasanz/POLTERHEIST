"""Explicit radio actions and Miracast preparation in the existing TV menu."""

import json
from dataclasses import asdict

from .miracast import LocalPresentation, MiracastAdapter
from .models import safe_text
from .wireless import WirelessDiscovery
from .wireless_bus import WirelessError


def discover(app):
    engine = WirelessDiscovery(app.root, app.discovery.config)
    adapters = engine.adapters()
    if not adapters:
        print("  P2P_UNSUPPORTED: no physical Wi-Fi interface reported by iw.")
        return
    print("\nWI-FI DIRECT ADAPTERS")
    for index, adapter in enumerate(adapters, 1):
        print(
            f"  [{index}] {safe_text(adapter.interface)} / {adapter.phy} / {safe_text(adapter.driver)} / {safe_text(adapter.chipset_id)}"
        )
        print(
            "      "
            + (
                "P2P API available; link/coexistence checked before scan"
                if adapter.eligible
                else safe_text("; ".join(adapter.reasons))
            )
        )
        print(
            "      Interface combinations: "
            + safe_text(adapter.capabilities.get("interface_combinations") or "Unknown")
        )
    choice = input("  Physical adapter number [0 Back]: ").strip()
    if choice in ("", "0"):
        return
    if not choice.isascii() or not choice.isdigit() or not 1 <= int(choice) <= len(adapters):
        raise ValueError("Invalid adapter selection")
    adapter = adapters[int(choice) - 1]
    if not adapter.eligible:
        raise WirelessError("P2P_UNSUPPORTED", "; ".join(adapter.reasons))
    print(
        f"  Active P2P search on {safe_text(adapter.interface)} for up to {engine.config.p2p_timeout}s."
    )
    print("  This sends discovery frames. It does not pair, connect or play media.")
    print(
        "  Close other P2P discovery/casting apps first; the API does not expose discovery ownership."
    )
    if (
        input("  Confirm authorized discovery and exclusive use of this adapter? [y/N]: ")
        .strip()
        .lower()
        != "y"
    ):
        print("  Wireless discovery cancelled.")
        return
    result = engine.scan(adapter, confirmed=True, progress=lambda state: print("  P2P: " + state))
    app.discovery.add_wireless(result)
    print(
        f"  {result.state}: {result.fresh_count} fresh peers; {result.cached_count} cached entries."
    )
    print(
        f"  StopFind acknowledged: {result.stop_confirmed} | Original state verified: {result.state_preserved}"
    )
    if result.error:
        print("  [!] " + safe_text(result.error))
    for warning in result.warnings:
        print("  [!] " + safe_text(warning))
    print("  Wireless evidence: " + str(result.export(app.root)))
    print("  Inventory: " + str(app.discovery.export(app.root)))


def receivers(app):
    found = []
    print("\nMIRACAST CANDIDATES (advertisements, not verified sessions)")
    for device in app.discovery.devices.values():
        endpoint = device.primary
        if endpoint.details.get("transport") == "p2p" and endpoint.details.get("wfd", {}).get(
            "sink"
        ):
            found.append(device)
            print(
                f"  [{device.id}] {safe_text(endpoint.name)} | {endpoint.details['p2p_address']} | {safe_text(endpoint.details['interface'])} | {safe_text(endpoint.note)}"
            )
            if not device.available:
                print("      Unavailable/stale: run Wi-Fi Direct discovery again.")
    if not found:
        print(
            "  No WFD sinks in the inventory. P2P-only/source-only peers are not Miracast receivers."
        )
    return found


def prepare(app):
    candidates = {device.id: device for device in receivers(app)}
    if not candidates:
        return
    choice = input("  Receiver ID to prepare [0 Back]: ").strip()
    if choice in ("", "0"):
        return
    if not choice.isascii() or not choice.isdigit() or int(choice) not in candidates:
        raise ValueError("Invalid WFD receiver ID")
    receiver = candidates[int(choice)]
    if not receiver.available:
        raise WirelessError("STALE_OBSERVATION", "Rediscover this receiver before preparation")
    adapter = MiracastAdapter(app.root, app.config)
    plan = adapter.prepare(receiver.primary)
    print(json.dumps(asdict(plan), indent=2, ensure_ascii=True))
    print("  Miracast activation is pending stack review/authorization and physical validation.")
    print("  No P2P group, capture, pairing, firewall or route change has been requested.")
    print("  [1] Select image/video for local presentation preparation\n  [0] Save plan and return")
    if input("  > ").strip() == "1":
        source = app.media()
        if source:
            plan = adapter.prepare(receiver.primary, source)
            print("  Selected media: " + safe_text(plan.media))
            print(
                "  A local full-screen player can supply content to a separately authorized screen-mirroring session."
            )
            if input("  Open LOCAL presentation only? [y/N]: ").strip().lower() == "y":
                player = LocalPresentation(app.manager.library)
                try:
                    player.start(source, confirmed=True)
                    print(
                        "  Local presentation only. No Miracast session was established by POLTERHEIST."
                    )
                    input("  ENTER to stop local presentation: ")
                    player.poll()
                finally:
                    player.stop()
    print("  Miracast preparation plan: " + str(plan.export(app.root)))
