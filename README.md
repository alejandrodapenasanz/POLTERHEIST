# POLTERHEIST

Inventory and assessment for networks you own or are authorized to test: **LAN reconnaissance on Kali/Linux, Wi-Fi/WPS on Linux and Windows, a captive portal on Kali/Linux, and local TV media casting**. Menus, diagnostics, report explanations, and the portal page are in English.

```text
[0] WHO AM I?
[1] LAN RECON
[2] WIRELESS RECON
[3] CAPTIVE PORTAL
[4] TV CONTROL — Smart TV Discovery & Media Casting

[q] EXIT
```

The application entry point and existing workflows live in **`script.py`**, organized into functions. `POLTERHEIST.py` is a compatibility entry point. The independent **`tv_control/`** package provides media discovery and playback. The external detector remains in `vendor/` to preserve its original code, license, and provenance.

## Kali installation

Boot Kali, connect to your Wi-Fi, and open the repository. Python **3.11 or newer** is required.

```bash
git clone https://github.com/alejandrodapenasanz/POLTERHEIST.git
cd POLTERHEIST
python3 script.py --setup
.venv/bin/python script.py --check
.venv/bin/python script.py --wireless
```

The script detects Windows/Linux and reads `/etc/os-release` to identify Kali. Setup installs Linux tools with APT, includes `firmware-mediatek` on Kali, and creates a virtual environment with Scapy 2.7.0 without changing system Python. An environment copied from the other OS is preserved; setup uses `.venv-linux` or `.venv-windows` instead and prints the executable path. Installation needs Internet access. Firmware updates may require a reboot.

Wireless assessment requests `sudo` automatically when needed, preserving the virtual environment interpreter. It uses the **connected SSID**, discovers its BSSIDs, runs the original fingerprint detector, and displays **one `WIRELESS RESULTS` table** with `ASSESSMENT` on the right. Other observed networks remain `NOT_TESTED`.

Radio setup and restoration are automatic. Using the connected adapter temporarily interrupts that connection; a compatible disconnected radio is preferred when available. Open the menu with `.venv/bin/python script.py`; LAN reconnaissance requires root.

To specify another authorized network or restrict assessment to one BSSID:

```bash
.venv/bin/python script.py --wireless --ssid 'My Wi-Fi'
.venv/bin/python script.py --wireless --ssid 'My Wi-Fi' --bssid aa:bb:cc:dd:ee:ff
```

Without a connected network or `--ssid`, discovery runs without active fingerprinting. Each BSSID receives its own result; assessments are not copied between radios sharing an SSID.

## TV Control

Choose **4**, or run `.venv/bin/python script.py --tv-control`. Discovery includes **Google Cast, DLNA/UPnP, DIAL, AirPlay and RAOP**, with separate evidence for advertisements, reachability and playback support. Directed discovery accepts a confirmed IPv4, hostname or small CIDR, including routed networks. Playback remains Cast/DLNA on the selected LAN and requires explicit confirmation for every session, including a single receiver.

Put PNG/JPEG/WEBP images and MP4/MKV/MOV/WEBM videos in **this repository's `media/` directory**, not the operating system's `/media`. FFprobe validates the content and codecs. Cast images become cached 720p H.264 MP4 clips; compatible videos play directly and other videos use conservative conversion. DLNA uses advertised generic image/MP4 formats; unsupported or profile-specific formats are reported explicitly. Playback repeats, with independent status, pause, resume, stop, media changes and target changes. Devices must be owned by you or authorized for control.

Kali `--setup` installs FFmpeg/ffprobe and the venv requirements (PyChromecast, zeroconf and ifaddr). TV Control needs no root privileges. Its HTTP server binds only the selected local IPv4 address on port **8765**, serves selected files through opaque URLs with byte ranges, and closes after the last session. Returning to the main menu can preserve playback; exiting POLTERHEIST stops it.

Run `.venv/bin/python script.py --tv-diagnostics` for read-only Kali hardware diagnostics, even without a LAN. It checks Wi-Fi/P2P, driver/chipset IDs, BlueZ, encoders and desktop capture prerequisites without scanning radios, pairing, capturing or changing system configuration.

TV Control now adds **8 — Wi-Fi Direct discovery**, **9 — Miracast receiver advertisements** and **10 — Miracast preparation/local presentation**. Linux discovery uses NetworkManager or an explicitly selected wpa_supplicant D-Bus backend, with adapter/PHY selection, a confirmed finite search and cleanup verification. It works without a shared router or selected IPv4 LAN when the hardware/APIs support P2P. A generic P2P peer is never classified as a WFD sink by name alone. No Miracast connection or receiver playback is claimed: external-stack activation remains pending review and physical validation.

See **[H4 usage, dependencies, test record and Kali commands](docs/tv_engine/H4_VALIDATION.md)**, **[H4 research](docs/tv_engine/H4_RESEARCH.md)** and **[roadmap](ROADMAP.md)**. Earlier deliverables: [H1 matrices](docs/tv_engine/RESEARCH.md), [architecture](docs/tv_engine/ARCHITECTURE.md), [H2/H3 validation](docs/tv_engine/VALIDATION.md) and [TV Control guide](docs/TV_CONTROL.md). AirPlay/RAOP/DIAL remain discovery only. Automated tests use labeled fixtures and loopback simulators; physical Kali/TV compatibility remains unverified.

## Wi-Fi and WPS on Windows

From PowerShell with Python 3.11 or newer:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe script.py --check
.\.venv\Scripts\python.exe script.py --wpscan
```

`--wpscan`, `--wireless`, `--fingerprint`, and menu option **2** run the automatic workflow for the connected SSID. `--ssid` specifies another authorized scope; `--bssid` restricts it to one radio. Here, `wpscan` means Wi-Fi WPS, not the WordPress scanner. Native discovery requires no WSL, `iw`, Nmap, or `arp-scan`.

### Assessments

The final table retains the exact assessment labels from [`qkaiser/broadcom-wps`](https://github.com/qkaiser/broadcom-wps#assessments):

| ASSESSMENT | Meaning |
| --- | --- |
| `LIKELY_VULNERABLE` | Rejection consistent with Broadcom WPS Monitor; likely vulnerable. |
| `PATCHED_HOSTAPD` | hostapd-style ACK and Broadcom evidence in the advertisement; a Broadcom device using hostapd. |
| `NO_BROADCOM_FINGERPRINT` | hostapd-style ACK without Broadcom evidence in the advertisement. |
| `INCONCLUSIVE` | No classifiable response; inspect the detector warning. Unknown upstream results also map here. |
| `NOT_TESTED` | POLTERHEIST status: the test did not start or the network is outside scope. The reason is reported. |
| `ERROR` | POLTERHEIST status: execution failed or evidence did not match the target. |

Only `LIKELY_VULNERABLE` is a positive finding, and it **does not confirm exploitation or RCE**. Missing responses, missing WPS advertisements, and unsupported drivers are not evidence that a network is safe. Negative assessments concern this detector, not overall device security.

Explanations, implementation estimates, responses, health, and warnings are saved to `reports/wireless/<scan_id>/targets/<BSSID_without_colons>/fingerprint.json`. The scan's `report.json` includes all results and paths. A single target also gets a top-level `fingerprint.json`. Original `upstream_result.json` and PCAP files are preserved per BSSID. Vendor, WPS presence, or WPA settings alone cannot support a vulnerability conclusion; matching upstream SSID/BSSID evidence is required.

### Native discovery and active fingerprinting

Discovery uses **Windows Native Wi-Fi** (`wlanapi.dll`) for BSSID, SSID, frequency/channel, RSSI, quality, and WPS/RSN/WPA information elements. It does not parse localized `netsh` output. Original BSS bytes and information elements are preserved. Discovery works on a normal connected adapter, requests a standard Windows refresh, and waits for completion. Windows may send discovery probes or return cached data; cache limitations are reported. Discovery does not change mode or disconnect the adapter.

For **error 5 / access denied**, enable **Location** in Settings > Privacy & security > Location for the application/terminal. For **error 1062**, check **WLAN AutoConfig (`WlanSvc`)**. [Microsoft documentation](https://learn.microsoft.com/en-us/windows/win32/nativewifi/wi-fi-access-location-changes).

Active fingerprinting additionally requires [Npcap](https://npcap.com/#download) with **Support raw 802.11 traffic (and monitor mode) for wireless adapters**, administrator privileges, and a driver/adapter supporting monitor capture and 802.11 injection. Npcap is not bundled or automatically installed. Listing networks does not demonstrate injection support. With a compatible adapter, POLTERHEIST requests normal UAC elevation; Windows requires the user to accept the dialog.

The Windows transport supports **active testing on 2.4 GHz**. Use Linux for active 5 GHz testing; the detector does not support 6 GHz. Npcap must deliver Radiotap/802.11 frames, and the exact target must be observed on its frequency before transmission. Reception/injection failures are not treated as negative findings.

Setup saves the original mode and connection profile name, enables monitor mode, sets the channel, and verifies it. Completion, errors, and Ctrl+C trigger restoration and reconnection to the original profile, checked against Windows' confirmation. An adapter originally in monitor mode returns to its original frequency. Passwords are not read. `radio_setup.json` records restoration errors, which are also displayed. Forced termination can prevent cleanup.

**A Windows driver advertising only `managed` cannot perform this fingerprint**, even with Npcap installed. The result remains `NOT_TESTED`, without modifying the radio. `--check` lists supported modes. To query the driver directly:

```powershell
$wifiGuid = 'ADAPTER-GUID'
$wlanHelper = "$env:SystemRoot\System32\Npcap\WlanHelper.exe"
& $wlanHelper $wifiGuid modes
```

For recovery after forced termination, an administrator can restore normal mode:

```powershell
& $wlanHelper $wifiGuid mode managed
```

Transport is restricted to the authorized BSSID and blocks deauthentication/disassociation. Only platform capture/transmit and channel control are adapted; upstream files and detection decisions remain unchanged. [Npcap requirements](https://npcap.com/guide/npcap-devguide.html#npcap-feature-dot11).

## Captive portal

On Kali/Linux, run `python3 script.py --setup` to install NetworkManager, `dnsmasq-base`, and nftables. Open `.venv/bin/python script.py` and choose **3**, or run `.venv/bin/python script.py --portal`.

The wizard offers:

1. **Create Wi-Fi:** choose an SSID and WPA2 password. Requires a free Wi-Fi interface supporting **AP** mode on a permitted 2.4 GHz channel. Monitor mode is unnecessary. SSIDs accept 1-32 UTF-8 bytes; passwords require 8-63 ASCII characters.
2. **Use a router as an access point:** connect one of its **LAN** ports to the Linux client Ethernet interface. Configure AP/bridge mode, disable its DHCP, and remove any other Internet uplink. The router keeps its configured Wi-Fi name. POLTERHEIST does not configure vendor administration panels.
3. **Local preview (`v`):** works on Windows and Linux at `http://127.0.0.1:8080`. It does not create Wi-Fi or change other devices' access.

### Automatic interface fallback

The selected mode is a preference. The wizard checks **every free candidate interface**, skipping the Internet uplink, interfaces with addresses or active connections, bridge members, bridges such as `docker0`, and incompatible radios. Wi-Fi candidates must be managed, support AP mode, have a dedicated PHY, and offer a permitted channel.

It tries compatible interfaces in the selected mode first. If none is usable, it tries the other mode: **Create Wi-Fi** or **External router/AP**. The selected mode/interface is printed. An external AP still needs to be connected/configured and confirmed by typing `AP`; Wi-Fi creation asks for the SSID and password. If an interface becomes unavailable during the final read-only checks, the next candidate is tried automatically.

If neither mode has a usable interface, the wizard reports:

```text
[!] No usable network interface is available for the captive portal.
```

Cancellation stops the wizard. Firewall conflicts, invalid configuration, and activation/cleanup failures retain their own errors instead of being disguised as missing interfaces. Fallback does not create hardware or take over occupied interfaces.

Detailed diagnostics do not change the network:

```bash
sudo .venv/bin/python script.py --portal-check
```

### Topology and VirtualBox

Both real portal modes make Linux the **gateway** and require **two independent interfaces**: an Internet uplink and a free client interface. Simultaneous Wi-Fi client and AP operation on the same radio is not implemented.

```text
Internet / upstream router
            |
      Internet interface
     Linux + POLTERHEIST
       client interface
            |
    new Wi-Fi OR router/AP
            |
          clients
```

Different router vendors work because Linux controls the gateway. **Running POLTERHEIST as another client on the existing Wi-Fi does not force other clients through it.** Place the client AP behind this gateway. If the existing router is your only Internet router, use an additional AP or create a new Wi-Fi network from the PC.

**Kali in VirtualBox:** bridging over Windows Wi-Fi gives Kali virtual Ethernet, not the radio. Another virtual Ethernet adapter cannot broadcast an SSID. Physical Wi-Fi inside a VM requires an AP-capable USB Wi-Fi adapter passed to the guest. Alternatively, boot Kali Live directly and use Ethernet or phone USB tethering for Internet, leaving Wi-Fi free for the AP. Actual AP support depends on the driver. Host-only/internal networks support virtual client labs, not physical Wi-Fi. [VirtualBox networking](https://docs.oracle.com/en/virtualization/virtualbox/7.1/user/networkingdetails.html).

A PC with Wi-Fi and Ethernet can use an external router/AP without another Wi-Fi adapter:

1. Shut down Kali normally. Keep the Internet adapter and enable **Adapter 2 > Bridged Adapter** in VirtualBox, selecting the PC's dedicated **physical Ethernet**. A disabled adapter cannot be enabled while the VM is running.
2. Connect Ethernet to a **LAN** port on the dedicated AP. Disable that AP's DHCP and other Internet uplink. Keep the upstream Internet router on the Internet side.
3. Start Kali and run `sudo .venv/bin/python script.py --portal-check`. Existing Docker or other firewall rules also block this version; use a dedicated installation without that conflict.
4. Choose **3 > 2**. The wizard checks the free client interfaces. Devices must connect to the dedicated AP to pass through the portal.

### Access and restoration

Before acceptance, DHCP, DNS, and the portal are available. HTTP redirects to the portal; other Internet traffic is blocked. **Accept and connect** grants a one-hour session bound to the client's IP/MAC; acceptance is required again after expiry. The page requests no accounts or passwords. HTTPS is not decrypted or impersonated. Use client captive-portal detection or the HTTP address printed by the program; automatic opening depends on the client OS.

NetworkManager creates a temporary connection with DHCP, DNS, and NAT. POLTERHEIST adds its own nftables table without deleting unrelated rules. Startup rejects existing `input/forward` firewall hooks or overlapping subnets. IPv6 is disabled for clients and blocked in forwarding. IP/MAC binding manages sessions; it does not establish a person's identity.

**Ctrl+C** removes the temporary connection and restores the verifiable interface and IPv4 forwarding state. Cleanup is also attempted after errors and SIGTERM. If restoration fails, the nftables guard remains and the reason is reported. Forced shutdown/SIGKILL can prevent cleanup; `reports/portal/<session>/network.json` identifies the session's connection UUID and table for recovery. Do not flush the entire firewall. Reports exclude the Wi-Fi password; its derived key exists in a temporary root-only connection file during the session.

Windows preview is also available directly:

```powershell
.\.venv\Scripts\python.exe script.py --portal-preview
```

Portal and fingerprinting are separate workflows; do not run both on the same radio. Physical AP operation and driver restoration still need validation with the target hardware.

## Profile and LAN reconnaissance

WHO AM I edits name/alias, specialization, biography, GitHub, LinkedIn, website, and contact. `config/profile.json` starts empty or can be copied from `config/profile.example.json`. ENTER keeps a value; `-` clears it. The local profile is excluded from Git.

LAN discovery combines ARP/Nmap, deduplicated IPs, MACs, sources, and vendor evidence. Local computer and gateway identification are explicit. OS/type estimates have separate confidence from vendor estimates; locally administered MACs reduce OUI confidence. Apple does not imply iPhone, and Cisco IOS does not imply iOS.

Stable IDs support all IPs, all non-mobile IPs, or custom selection. Automatic selections exclude LOCAL; custom selection can include it. Unknown devices remain in the non-mobile selection. Scanning covers TCP ports **1-65535**, versions, NSE `default or vuln`, CVE references, CSV/JSON/XML, and original logs. **Ghost Mode** uses `-T2 --max-rate 50`; **Hunter Mode** uses `-T3`. Both generate detectable traffic, and some NSE scripts can be intrusive. Network authorization is requested before scanning.

LAN scope is the default route's IPv4 subnet, limited to 4096 addresses. OS fingerprints are estimates and CVE references do not confirm vulnerability. Progress/ETA describes Nmap's current phase rather than an invented overall percentage. Full scans can take a long time.

## Wireless implementation and recovery

Linux uses `iw` to enumerate interfaces, PHYs, drivers, mode, connection, capabilities, and frequencies. Only the chosen radio is prepared/restored; NetworkManager continues managing other interfaces. Windows uses Native Wi-Fi for discovery and WlanHelper for setup/restoration.

| Interface | Discovery | Limitations |
| --- | --- | --- |
| Managed | `iw dev IFACE scan passive`, then `nmcli device wifi list` if needed | nmcli may use cached data and does not expose WPS or RSSI in dBm here. |
| Dedicated monitor | Passive tcpdump beacon/probe-response capture over supported frequencies | Requires root, initial channel, and a dedicated radio; restores frequency on exit/cancel. |
| Windows managed | `WlanScan` + `WlanGetNetworkBssList` | May require Location permission; WPS/security depend on available information elements. |

The table shows ID, SSID, BSSID, channel, security, WPS, signal, and assessment. WPA/WPA2/WPA3, PSK/SAE, mixed modes, OWE, and open networks are shown when supported by evidence. Unknown AKMs remain uncertain. NetworkManager percentages are never converted to dBm. **WPS is independent of WPA2/WPA3.** `Detected` requires observed WPS elements; `Unknown` does not mean absent. Hidden SSIDs can be listed, but fingerprinting requires an exact observed SSID.

Virtual Ethernet cannot capture 802.11 frames. A VM needs USB Wi-Fi passthrough and a guest driver supporting monitor capture/injection. Advertised monitor support does not guarantee reception/injection. Check `iw dev`, `iw phy`, `rfkill list`, and firmware/driver messages.

Linux saves mode, frequency, UP/DOWN state, NetworkManager management, and connection UUID. It releases only the selected interface from NetworkManager and uses `iw ... set monitor otherbss control`, then sets/verifies frequency. The original state/connection is restored on exit/cancel; failures are recorded in `radio_setup.json` and stop further tests. [Upstream setup](https://github.com/qkaiser/broadcom-wps#broadcom-sdk-fingerprinter).

After forced termination, restore an originally managed interface manually, replacing `wlan1`:

```bash
sudo ip link set dev wlan1 down
sudo iw dev wlan1 set type managed
sudo ip link set dev wlan1 up
sudo nmcli device set wlan1 managed yes
```

Linux rejects channel changes/testing on shared PHYs, even when other interfaces are disconnected. Active fingerprinting also rejects disabled/no-IR/DFS channels and 6 GHz. The regulatory domain is not changed. Windows verifies monitor mode/channel before capture. Discovery can list 6 GHz when the hardware exposes it.

### WPSplinter integration

The project imports [`qkaiser/broadcom-wps`](https://github.com/qkaiser/broadcom-wps/tree/3cb3ef77d6b71e8441a51668c7e2b919608180f9) by **Quentin Kaiser**, pinned to **`3cb3ef77d6b71e8441a51668c7e2b919608180f9`**, under the MIT license. Reference: [One Parser, Two Bugs](https://quentinkaiser.be/security/2026/10/16/one-parser-two-bugs/).

SHA-256 verifies the original detector. Its SSID-only launcher is not used because it could choose another BSSID with the same name. `fingerprint_target` and `decide_assessment` remain unchanged. Each target is passively re-observed on its channel before the active exchange.

Transport pins the BSSID and blocks deauthentication/disassociation. Upstream normally deauthenticates to close its own test session; blocking it is recorded as `cleanup_sent=false`. An explicit response can retain its classification while upstream reports `target_health=DEGRADED`. Temporary AP state may persist until timeout; cleanup is not claimed to have succeeded. The application does not extract credentials, run arbitrary payloads, or open shells.

## Reports

```text
reports/
  lan/<UTC_timestamp_microseconds_id>/
    report.json, report.csv, discovery.json, identification.json, selection.json
    discovery_*.log, discovery_nmap.xml, identify_*.xml, identify_*.log
    scan_*.xml, scan_*.log, scan_*_status.json, results.json
  wireless/<UTC_timestamp_microseconds_id>/
    report.json, discovery.json, iw_scan.log or nmcli_scan.log
    windows_bss.bin, windows_discovery.json  # native Windows evidence
    fingerprint.json                       # summary for a single target
    discovery_*MHz.pcap and .log            # monitor capture, when available
    targets/<BSSID_without_colons>/
      report.json, fingerprint.json
      radio_setup.json                     # Linux/Windows setup and restoration
      upstream_result.json, fingerprint.pcap
  portal/<UTC_timestamp_microseconds_id>/
    config.json, network.json              # no password; lifecycle state
```

Reports include version, UTC time, target, authorization, sources, classification, limitations, and available evidence. Wireless reports preserve security, channel, signal, WPS, available vendor identity, upstream output, and evidence hashes. Original JSON/PCAP evidence is not rewritten to alter conclusions. Each run uses a new folder. Ctrl+C preserves available evidence; interrupted operations receive no invented results. Truncated XML is preserved even when parsing fails.

Reports, captures, real profiles, and virtual environments are excluded from Git. Network names, device-provided text, and original external-tool evidence are preserved as received, regardless of language.

## Tests

```bash
.venv/bin/python -m unittest discover -s tests -v
```

Portal tests cover real loopback HTTP, forms, IP/MAC-bound single-use tokens, expiry, restoration, and interface fallback. They exercise unusable first adapters, both modes, exhausted candidates, and failures that must not trigger another attempt. The `portal-gateway` CI job uses three isolated Linux network namespaces for real redirection, blocked traffic, acceptance, access, expiry, and preservation of unrelated rules. It also checks real NetworkManager profile parsing and activation/restoration with private D-Bus. Tests do not connect to physical Wi-Fi or modify a user's router.

Offline tests cover menus/profiles, LAN discovery, selection, vendor/OS estimates, services/CVEs, security parsing, SSID escaping, authorization, **real upstream decisions with simulated responses**, transport guards, evidence, and cancellation. Captures are synthetic fixtures. With Nmap installed, a real Nmap test inspects a temporary HTTP server on **127.0.0.1**; this does not validate full-port scans, ARP, OS fingerprinting, or vulnerability NSE on real devices.

GitHub Actions runs Linux/Windows with Python 3.11/3.13, installs Nmap on Linux, and separately runs setup/check/tests in official `kalilinux/kali-rolling`. Radio tests simulate partial failures, cancellation, reconnection, unsupported drivers, regulatory constraints, Windows UAC, and Npcap adaptation. Native discovery/profile reading has been checked on a MediaTek MT7921 in Windows. Active monitor reception/injection, regulatory behavior, restoration, and physical AP fingerprinting still need compatible hardware validation. Automated tests do not transmit Wi-Fi traffic.

References: [iw](https://wireless.docs.kernel.org/en/latest/en/users/documentation/iw.html), [nmcli](https://networkmanager.dev/docs/api/latest/nmcli.html), and [Nmap output](https://nmap.org/book/man-output.html).
