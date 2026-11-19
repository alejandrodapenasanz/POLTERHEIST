# Wi-Fi password audit with Aircrack-ng

Open **2 — WIRELESS RECON / WPS & Aircrack-ng**, then **2 — WPA/WPA2 password audit**.
The first submenu option keeps the existing WPS fingerprint detector. Password auditing
is independent of WPS and does not require the router to advertise WPS.

Direct entry:

```bash
python3 POLTERHEIST.py --aircrack
python3 POLTERHEIST.py --aircrack live --ssid 'My Wi-Fi'
python3 POLTERHEIST.py --aircrack file
```

`--bssid` optionally restricts the selected SSID to one access point. The original
`--wpscan`, `--wireless` and `--fingerprint` commands still open the WPS detector.

## Capture on Kali/Linux

Run `bash setup.sh` to install the Aircrack-ng suite, including `airodump-ng`.
The wizard requests sudo when necessary and asks for your dictionary, a dictionary
time limit (default 600 seconds) and a capture duration (default 120 seconds).
It defaults to the connected SSID; otherwise enter your exact network name. If the
network has multiple BSSIDs, select the one to assess.

A dedicated radio supporting monitor mode is required. The workflow uses the existing
radio setup/restoration code and its 2.4/5 GHz channel restrictions; shared PHYs,
disabled/no-IR/DFS channels and 6 GHz are currently excluded. Selecting the connected
adapter temporarily disconnects it. Its original mode, channel, link state and
NetworkManager connection are restored before dictionary checking starts. Restoration
failure stops the workflow and is recorded in `radio_setup.json`.

Airodump-ng captures the selected BSSID/channel for the requested duration. During
that window, connect or manually reconnect one of your devices to your router to
produce authentication traffic. The capture is passive and sends no deauthentication
frames. Capturing packets alone does not guarantee a usable handshake.

The live workflow requires discovery to explicitly identify PSK authentication. Pure
WPA3-SAE, Enterprise/EAP, open networks, WEP and unknown authentication are unsupported.
On a WPA2/WPA3 transition network, only the WPA2-PSK path is evaluated.

## Use an existing capture

Select **Check an existing capture** and provide a PCAP/PCAPNG file containing 802.11
frames, its exact SSID/BSSID, and a text dictionary with one candidate per line.
Decompress `.gz` dictionaries first. File analysis requires no radio, monitor mode,
Npcap or administrator privileges. On Windows, an executable named `aircrack-ng.exe`
must be available on PATH and permitted by the local application-control policy.

The original capture is read only. POLTERHEIST creates `authentication.cap` containing
only the selected BSSID's beacons/probe responses and EAPOL frames. This also prevents
Aircrack-ng from selecting another radio with the same SSID. An observed SSID mismatch
or an explicitly incompatible RSN authentication mode is rejected before cracking.

## Results and evidence

The activity indicator shows elapsed time. **Ctrl+C** stops the child process and
preserves the report; a live capture also restores the adapter. Time limits distinguish
an interrupted search from an exhausted dictionary.

| Result | Meaning |
| --- | --- |
| `RECOVERED` | Aircrack-ng successfully verified a dictionary candidate. |
| `NOT_RECOVERED` | The supplied dictionary was exhausted; this does not establish that the network is secure. |
| `NO_HANDSHAKE` | No usable authentication evidence for the selected network was available. |
| `TIMEOUT` | The dictionary search reached its time limit. |
| `CANCELLED` | The operator interrupted the operation. |
| `ERROR` | Missing tools, unsupported authentication, unreadable files or a tool failure. |
| `RESTORE_FAILED` | Restoring the original network state failed. |

Reports, capture evidence and SHA-256 artifact hashes are saved under
`reports/wifi_password/<run>/`, excluded from Git. Linux run directories are private
to their owner. A recovered password is displayed in the terminal, registered for
log redaction, and omitted from reports. Aircrack-ng's temporary key file is removed
on exit; raw cracking output and candidate strings are not written to logs.

## Validation

Offline regressions cover BSSID isolation, authentication compatibility, success and
failure classification, cancellation, time limits, process cleanup, radio restoration
and secret handling. A synthetic WPA2 M1/M2 exchange has a real MIC calculated from
a known fixture password. The integration test checks that password and a dictionary
without it using the actual Aircrack-ng binary whenever it is available. Linux and
Kali CI install the binary; no test transmits Wi-Fi traffic.

The downloaded official Windows 1.7 binary was blocked by local application control
during development. Physical capture and restoration on Kali with a real router and
compatible adapter remain pending; automated tests do not close that validation.

References: [Aircrack-ng authentication and dictionary support](https://www.aircrack-ng.org/doku.php?id=aircrack-ng),
[Airodump-ng capture options](https://www.aircrack-ng.org/doku.php?id=airodump-ng),
[official downloads](https://www.aircrack-ng.org/downloads.html).
