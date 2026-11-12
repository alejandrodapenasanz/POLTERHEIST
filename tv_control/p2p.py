"""Real NetworkManager/supplicant discovery adapters; never create a P2P group."""

import re
import sys
import time
from collections import Counter
from dataclasses import dataclass, field

from .hardware import chipset, parse_iw_devices, parse_phys
from .wireless_bus import Busctl, CommandRunner, WirelessError, decode_reply

NM = "org.freedesktop.NetworkManager"
NM_ROOT = "/org/freedesktop/NetworkManager"
NM_DEVICE = NM + ".Device"
NM_P2P = NM_DEVICE + ".WifiP2P"
WPA = "fi.w1.wpa_supplicant1"
WPA_ROOT = "/fi/w1/wpa_supplicant1"
WPA_IFACE = WPA + ".Interface"
WPA_P2P = WPA_IFACE + ".P2PDevice"


@dataclass
class Adapter:
    interface: str
    phy: str
    mode: str
    capabilities: dict
    driver: str = "Unknown"
    chipset_id: str = "Unknown"
    control_path: str = ""
    physical_path: str = ""
    backend: str = "networkmanager"
    eligible: bool = False
    reasons: list[str] = field(default_factory=list)


def valid_interface(name):
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,32}", name):
        raise WirelessError(
            "INVALID_INTERFACE", "Select a physical interface from the adapter inventory"
        )
    return name


def concurrency_support(text, modes):
    """Only claim compatibility when a complete iw combination covers every mode."""
    combinations = []
    for block in re.split(r"(?:^|\n)\s*\*\s+", text):
        groups = [
            (set(x.strip() for x in group.split(",")), int(limit))
            for group, limit in re.findall(r"#\{\s*([^}]+)\}\s*<=\s*(\d+)", block)
        ]
        total = re.search(r"total\s*<=\s*(\d+)", block)
        channels = re.search(r"#channels\s*<=\s*(\d+)", block)
        if groups and total and channels:
            combinations.append((groups, int(total[1]), int(channels[1])))
    if not combinations:
        return {"supported": None, "channel_limits": []}
    counts = Counter(modes)
    compatible = []
    for groups, total, channels in combinations:
        covered = set().union(*(group for group, _ in groups))
        if (
            set(counts) <= covered
            and sum(counts.values()) <= total
            and all(sum(counts[mode] for mode in group) <= limit for group, limit in groups)
        ):
            compatible.append(channels)
    return {"supported": bool(compatible), "channel_limits": sorted(set(compatible))}


class NetworkManagerP2P:
    name = "networkmanager"

    def __init__(self, bus=None):
        self.bus = bus or Busctl()

    def controls(self, interfaces):
        try:
            paths = decode_reply(self.bus.call(NM, NM_ROOT, NM, "GetDevices"), "ao")
        except WirelessError as error:
            if error.code == "SERVICE_UNAVAILABLE":
                raise WirelessError(
                    "NETWORKMANAGER_UNAVAILABLE",
                    "NetworkManager system D-Bus service is unavailable",
                ) from error
            raise
        devices, deadline = [], time.monotonic() + 15
        for path in paths[:64]:
            if time.monotonic() >= deadline:
                raise WirelessError(
                    "TIMEOUT", "NetworkManager adapter inventory exceeded 15 seconds"
                )
            properties = self.bus.properties(
                NM, path, NM_DEVICE, timeout=deadline - time.monotonic()
            )
            devices.append((path, properties))
        result = {}
        for interface in interfaces:
            physical = next(
                (
                    path
                    for path, p in devices
                    if p.get("Interface") == interface and p.get("DeviceType") == 2
                ),
                "",
            )
            matches = [
                (path, p)
                for path, p in devices
                if p.get("DeviceType") == 30
                and p.get("Interface") in ("p2p-dev-" + interface, interface)
            ]
            # Interface-name mapping follows NM's P2P device convention; no MAC guessing.
            if len(matches) == 1 and physical:
                result[interface] = {"path": matches[0][0], "physical": physical}
        return result

    def snapshot(self, adapter):
        radio = self.bus.get(NM, NM_ROOT, NM, "WirelessEnabled", "b")
        physical = self.bus.properties(NM, adapter.physical_path, NM_DEVICE)
        p2p = self.bus.properties(NM, adapter.control_path, NM_DEVICE)
        if not radio:
            raise WirelessError("ADAPTER_BUSY", "Wi-Fi is disabled; no radio setting was changed")
        if physical.get("Interface") != adapter.interface or p2p.get("Interface") not in (
            adapter.interface,
            "p2p-dev-" + adapter.interface,
        ):
            raise WirelessError(
                "ADAPTER_CHANGED", "Adapter identity changed; refresh the inventory"
            )
        if p2p.get("Managed") is not True or p2p.get("State") not in (20, 30):
            raise WirelessError(
                "ADAPTER_BUSY", "P2P device is unmanaged, connecting or already in a session"
            )
        if p2p.get("ActiveConnection", "/") != "/":
            raise WirelessError("ADAPTER_BUSY", "P2P device already has an active connection")
        return {
            "physical_state": physical.get("State"),
            "physical_connection": physical.get("ActiveConnection"),
            "p2p_state": p2p.get("State"),
            "p2p_connection": p2p.get("ActiveConnection"),
            "radio_enabled": radio,
        }

    def start(self, adapter, duration):
        self.bus.call(
            NM, adapter.control_path, NM_P2P, "StartFind", "a{sv}", (1, "timeout", "i", duration)
        )

    def stop(self, adapter):
        self.bus.call(NM, adapter.control_path, NM_P2P, "StopFind")

    def peers(self, adapter, deadline, limit):
        paths = self.bus.get(
            NM,
            adapter.control_path,
            NM_P2P,
            "Peers",
            "ao",
            timeout=max(0.05, deadline - time.monotonic()),
        )
        found = []
        for path in paths[:limit]:
            if time.monotonic() >= deadline:
                break
            try:
                properties = self.bus.properties(
                    NM, path, NM + ".WifiP2PPeer", timeout=deadline - time.monotonic()
                )
                found.append((path, properties))
            except WirelessError as error:
                if error.code not in ("DBUS_ERROR", "UNSUPPORTED_API"):
                    raise
                # A peer can disappear between the Peers property and GetAll.
        return found


class SupplicantP2P:
    name = "supplicant"

    def __init__(self, bus=None):
        self.bus = bus or Busctl()

    def controls(self, interfaces):
        try:
            capabilities = self.bus.get(WPA, WPA_ROOT, WPA, "Capabilities", "as")
            paths = self.bus.get(WPA, WPA_ROOT, WPA, "Interfaces", "ao")
        except WirelessError as error:
            if error.code == "SERVICE_UNAVAILABLE":
                raise WirelessError(
                    "SUPPLICANT_UNAVAILABLE", "wpa_supplicant D-Bus service is unavailable"
                ) from error
            raise
        if "p2p" not in capabilities:
            raise WirelessError("P2P_UNSUPPORTED", "wpa_supplicant does not advertise P2P")
        devices, deadline = {}, time.monotonic() + 15
        for path in paths[:32]:
            if time.monotonic() >= deadline:
                raise WirelessError("TIMEOUT", "Supplicant adapter inventory exceeded 15 seconds")
            name = self.bus.get(
                WPA, path, WPA_IFACE, "Ifname", "s", timeout=deadline - time.monotonic()
            )
            devices[name] = path
        return {
            interface: {
                "path": devices.get("p2p-dev-" + interface) or devices[interface],
                "physical": devices.get(interface, ""),
            }
            for interface in interfaces
            if "p2p-dev-" + interface in devices or interface in devices
        }

    def snapshot(self, adapter):
        name = self.bus.get(WPA, adapter.control_path, WPA_IFACE, "Ifname", "s")
        if name not in (adapter.interface, "p2p-dev-" + adapter.interface):
            raise WirelessError("ADAPTER_CHANGED", "Supplicant interface changed; refresh adapters")
        properties = self.bus.properties(WPA, adapter.control_path, WPA_P2P)
        group = properties.get("Group", "/")
        role = properties.get("Role", "")
        if group != "/" or role.lower() in ("go", "client"):
            raise WirelessError("ADAPTER_BUSY", "Supplicant reports an existing P2P group")
        state = self.bus.get(WPA, adapter.control_path, WPA_IFACE, "State", "s")
        if state in (
            "associating",
            "associated",
            "authenticating",
            "4way_handshake",
            "group_handshake",
        ):
            raise WirelessError("ADAPTER_BUSY", "Supplicant is negotiating another connection")
        config = properties.get("P2PDeviceConfig", {})
        # Keep only non-secret settings useful to verify that discovery did not alter them.
        config = (
            {
                key: value
                for key, value in config.items()
                if key in ("DeviceName", "GOIntent", "ListenChannel", "OperChannel")
            }
            if isinstance(config, dict)
            else {}
        )
        return {"group": group, "role": role, "state": state, "config": config}

    def start(self, adapter, duration):
        self.bus.call(
            WPA, adapter.control_path, WPA_P2P, "Find", "a{sv}", (1, "Timeout", "i", duration)
        )

    def stop(self, adapter):
        self.bus.call(WPA, adapter.control_path, WPA_P2P, "StopFind")

    def peers(self, adapter, deadline, limit):
        paths = self.bus.get(
            WPA,
            adapter.control_path,
            WPA_P2P,
            "Peers",
            "ao",
            timeout=max(0.05, deadline - time.monotonic()),
        )
        found = []
        for path in paths[:limit]:
            if time.monotonic() >= deadline:
                break
            try:
                found.append(
                    (
                        path,
                        self.bus.properties(
                            WPA, path, WPA + ".Peer", timeout=deadline - time.monotonic()
                        ),
                    )
                )
            except WirelessError as error:
                if error.code not in ("DBUS_ERROR", "UNSUPPORTED_API"):
                    raise
        return found


class LocalRadio:
    def __init__(self, runner=None, platform=None, sysfs="/sys"):
        self.runner = runner or CommandRunner()
        self.platform = sys.platform if platform is None else platform
        self.sysfs = sysfs

    def require_linux(self):
        if not self.platform.startswith("linux"):
            raise WirelessError(
                "PLATFORM_UNSUPPORTED",
                "Wi-Fi Direct requires physical Linux; this host is " + self.platform,
            )

    def inventory(self, backend):
        self.require_linux()
        devices = parse_iw_devices(self.runner(["iw", "dev"]))
        phys = parse_phys(self.runner(["iw", "phy"]))
        physical = [
            d for d in devices if d["name"] != "(non-netdev)" and d["type"] != "P2P-device"
        ][:16]
        if not physical:
            return []
        controls = backend.controls([d["name"] for d in physical])
        adapters = []
        for device in physical:
            info = chipset(device["name"], self.sysfs)
            capability = phys.get(device["phy"], {})
            adapter = Adapter(
                device["name"],
                device["phy"],
                device["type"],
                capability,
                driver=info["driver"],
                chipset_id=info["chipset_id"],
                backend=backend.name,
            )
            if not capability.get("modes_reported"):
                adapter.reasons.append(
                    "DRIVER_UNSUPPORTED: iw did not report usable interface modes"
                )
            elif not {"P2P-client", "P2P-GO"} & set(capability.get("modes", [])):
                adapter.reasons.append(
                    "P2P_UNSUPPORTED: driver advertises neither P2P-client nor P2P-GO"
                )
            if device["type"] != "managed":
                adapter.reasons.append(
                    "ADAPTER_BUSY: select an existing managed physical interface"
                )
            if control := controls.get(device["name"]):
                adapter.control_path, adapter.physical_path = control["path"], control["physical"]
            else:
                adapter.reasons.append(
                    "P2P_UNSUPPORTED: no unambiguous P2P API for this physical interface"
                )
            adapter.eligible = not adapter.reasons
            adapters.append(adapter)
        return adapters

    def snapshot(self, adapter):
        self.require_linux()
        valid_interface(adapter.interface)
        devices = parse_iw_devices(self.runner(["iw", "dev"]))
        physical = next((d for d in devices if d["name"] == adapter.interface), None)
        if not physical or physical["phy"] != adapter.phy or physical["type"] != "managed":
            raise WirelessError("ADAPTER_CHANGED", "Selected physical interface/PHY changed")
        shared = [d for d in devices if d["phy"] == adapter.phy]
        if len(shared) > 16:
            raise WirelessError(
                "ADAPTER_BUSY", "Too many interfaces share this PHY for a bounded discovery request"
            )
        if any(d["type"] not in ("managed", "P2P-device") for d in shared):
            raise WirelessError(
                "ADAPTER_BUSY",
                "PHY has an AP, monitor, P2P group or another active mode; no interfaces changed",
            )
        links, deadline = {}, time.monotonic() + 10
        for device in shared:
            if device["type"] != "managed":
                continue
            if time.monotonic() >= deadline:
                raise WirelessError("TIMEOUT", "Interface link checks exceeded ten seconds")
            raw = self.runner(
                ["iw", "dev", valid_interface(device["name"]), "link"],
                timeout=min(3, deadline - time.monotonic()),
            )
            connected = re.search(r"(?im)^Connected to ([0-9a-f:]{17})", raw)
            frequency = re.search(r"(?m)^\s*freq:\s*(\d+)", raw)
            if not connected and "Not connected" not in raw:
                raise WirelessError(
                    "STATE_UNAVAILABLE", "Could not establish managed interface link state"
                )
            links[device["name"]] = {
                "bssid": connected[1].lower() if connected else "",
                "frequency": int(frequency[1]) if frequency else None,
            }
        modes = [d["type"] for d in shared if d["type"] != "P2P-device"]
        combinations = adapter.capabilities.get("interface_combinations", "")
        concurrency = [
            concurrency_support(combinations, [*modes, role])
            for role in ("P2P-client", "P2P-GO")
            if role in adapter.capabilities.get("modes", [])
        ]
        if any(link["bssid"] for link in links.values()) and not any(
            c["supported"] is True for c in concurrency
        ):
            raise WirelessError(
                "ADAPTER_BUSY",
                "Managed/P2P coexistence is absent or unknown; select a free adapter. No disconnect attempted",
            )
        return {
            "interfaces": sorted((d["name"], d["type"]) for d in shared),
            "links": links,
            "concurrency": concurrency,
        }
