# TV Control

Main menu option **4** is now **IoT Scanning** and starts LAN/P2P/BLE discovery automatically. Choose **5 — Media control** inside it for the TV functionality documented here. Existing main options 0–3 and both entry points remain available. `--iot-scan` and legacy `--tv-control` open the same IoT menu. See the [IoT guide](IOT_CONTROL.md). The CLI uses English, matching POLTERHEIST. Use only receivers that you own or have authorization to control.

The H1/H2/H3 extension adds read-only hardware diagnostics and multiprotocol discovery. H4 adds explicit Wi-Fi Direct discovery and WFD classification through Linux D-Bus APIs. See the [ordered roadmap](../ROADMAP.md) for Kali validation and subsequent development. Miracast activation/receiver playback remain preparation only. No dependencies are installed or system configuration changed automatically.

## Install and run on Kali

From the repository root, `bash setup.sh` creates/reuses the Linux environment and runs the menu. Use `bash setup.sh --install-system` to explicitly include APT prerequisites or `bash setup.sh --run-only` for subsequent runs without installation. The manual equivalent for a new `.venv` is:

```bash
sudo apt update
sudo apt install -y python3-venv ffmpeg
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
ffmpeg -version
ffprobe -version
.venv/bin/python script.py
```

Choose **4**. Alternatively, use `.venv/bin/python script.py --tv-control` or `.venv/bin/python POLTERHEIST.py --tv-control`. The existing `python3 script.py --setup` also installs FFmpeg and all project dependencies. If setup reports `.venv-linux/bin/python` because the repository contains a Windows venv, use that executable instead. Do not use global pip or sudo to run TV Control.

Python dependencies: **PyChromecast 14.1.1**, **zeroconf 0.154.0**, **ifaddr 0.2.0**. ifaddr enumerates interface addresses and subnet prefixes; it is also a zeroconf dependency. DLNA uses standard-library HTTP/XML/SOAP and adds no UPnP package. FFmpeg must include `libx264` and the AAC encoder. On Windows, install FFmpeg/ffprobe separately and add their directory to PATH; discovery/playback also use the normal local interface there.

## Files and configuration

```text
POLTERHEIST/
  script.py                        # main menu and lazy TV entry point
  POLTERHEIST.py                    # compatibility entry point
  tv_control/
    cli.py                         # discovery, selection and playback menus
    discovery.py                   # stable IDs, deduplication, selection
    discovery_backends.py          # independent discovery adapter registry
    scopes.py                      # bounded, confirmed routed target scopes
    hardware.py                    # read-only Kali hardware diagnosis
    p2p.py, wireless_bus.py         # physical adapters and Linux P2P D-Bus APIs
    wireless.py, wfd.py             # bounded radio discovery and WFD evidence
    wireless_cli.py, miracast.py    # manual radio UI, preparation, local presentation
    models.py, network.py           # configuration and local network scope
    manager.py                     # independent receiver workers
    media.py, http_server.py        # validation, conversion and HTTP Range
    protocols/base.py              # common backend contract
    protocols/google_cast.py       # mDNS / Google Cast
    protocols/dlna.py               # SSDP / UPnP AVTransport
    protocols/airplay.py            # AirPlay / RAOP observations only
  media/                           # put local images and videos here
  .cache/tv_control/                # generated MP4 files, reused by content hash
  config/tv_control.example.json
  config/tv_control.json            # optional local configuration
  reports/tv_control/tv_control.log # rotating technical log
  tests/test_tv_control.py
  tests/test_tv_engine.py           # H2/H3 fixtures and simulated DIAL receiver
  tests/test_wireless_tv.py         # H4 labeled fixtures and state/cleanup tests
```

User media, cache, local configuration and logs are excluded from Git. `media/` is created if missing. Only files immediately inside that directory are listed. URLs contain random tokens, not absolute paths. Symlinks outside approved directories are rejected. Selected file contents are revalidated when prepared; an extension alone does not establish the format. Images are decoded for validation, and videos are checked with ffprobe. Video corruption discovered during playback is reported by the receiver; probing is not a full-file video decode.

To change settings:

```bash
cp config/tv_control.example.json config/tv_control.json
```

| Setting | Default | Meaning |
| --- | --- | --- |
| `bind_ip` | `""` | Automatically select the IPv4 multicast route's interface; set a local interface address to override. |
| `http_port` | `8765` | Port for the local media server. |
| `discovery_timeout` | `5` | Seconds collecting mDNS/SSDP responses. |
| `request_timeout` | `5` | Per receiver request timeout; UPnP description resolution has a shared budget of four times this value after SSDP collection. |
| `connect_timeout` | `10` | Cast connection and playback acknowledgment timeout. |
| `poll_interval` | `2` | Seconds between per-device playback checks. |
| `retries` | `2` | Additional connection attempts or consecutive status/loop error attempts, limited to 0–3. |
| `max_devices` | `32` | Discovery response cap, limited to 1–64 per protocol. |
| `conversion_timeout` | `600` | Maximum seconds for each conversion, up to 7200. |
| `auto_convert` | `true` | Convert when required. With `false`, report incompatible content without converting. |
| `discovery_backends` | `["cast", "upnp", "airplay", "iot_mdns", "onvif", "coap"]` | Enabled discovery adapters; custom older lists remain unchanged. |
| `directed_max_hosts` | `16` | Maximum explicit targets, configurable from 1 to 64; CIDR size is checked before expansion. |
| `directed_workers` | `4` | Concurrent directed protocol probes, configurable from 1 to 8. |
| `p2p_backend` | `"networkmanager"` | Explicit radio backend; alternative `"supplicant"`. Never auto-starts a scan. |
| `p2p_timeout` | `15` | Requested finite P2P search duration, integer 1–60 seconds. |

Configuration is read on first opening TV Control in the process. Restart after editing the file; the discovery menu can change enabled backends for the current session. Interface selection does not change network configuration. Multicast discovery and playback use one selected IPv4 LAN. Directed discovery accepts a confirmed small IPv4/hostname/CIDR scope and can inspect routed targets, which remain discovery-only outside that LAN. Each target receives one unicast SSDP search and a query to the known Cast device-information endpoint on port 8008. No arbitrary port ranges are scanned. Receivers that disable these mechanisms may still require multicast. Hostnames are resolved once and subsequent requests use pinned literal IPs. IPv6 in Bonjour records is retained as metadata; IPv6-only discovery/transport is not implemented.

## Discovery and selection

Opening the feature shows the IoT menu. **Detect all IoT devices** queries enabled protocols, including `_googlecast._tcp.local.`, `_airplay._tcp.local.`, `_raop._tcp.local.` and SSDP device descriptions. These are active protocol queries, not passive radio listening. No playback occurs during discovery. The historical TV-only example below illustrates media endpoints; the current inventory also shows IoT types and connection options:

```text
UNIVERSAL TV DISCOVERY — H3
  ID  DEVICE                    IP               PROTOCOL / STATUS
  1   tv-coneja                 192.168.1.159    Google Cast / COMPATIBLE BACKEND; SESSION UNTESTED
      Unknown | MiTV-MSSP2 | TV (advertised model) | port 8009
  2   Living Room               192.168.1.160    DLNA / COMPATIBLE BACKEND; SESSION UNTESTED
```

Manufacturer/model fields remain unknown when absent. TV labels based on a model containing “TV” are advertised-name inferences, not verified hardware identity. Audio-only Cast receivers and partial identities are discovery-only for this image/video module. `COMPATIBLE BACKEND; SESSION UNTESTED` means a backend and its required advertised capabilities are available; connection, format and playback acceptance remain separate. AirPlay, RAOP, DIAL and generic UPnP observations are discovery-only. RAOP is labeled audio-only; generic UPnP devices are not automatically labeled TVs. Password requirements are shown only when explicitly advertised; other authentication remains unknown.

The registry merges matching protocol identities and provisionally groups same-IP cross-protocol observations, preserves IDs across rediscovery/IP changes when identities match, and marks missing receivers unavailable. Distinct same-protocol identities on one IP stay separate. Same-host grouping is explicitly unverified physical identity. A device advertising Cast and DLNA prefers Cast; intelligent correlation/fallback is deferred to H7. Each scan writes evidence, per-backend results, errors and timestamps to `reports/tv_control/discovery_*.json`.

Within **Media control**, choose **1** for all currently controllable IP receivers, or **2** and enter `1,3`. Empty input, invalid/duplicate IDs and unavailable/discovery-only receivers are rejected. **3** refreshes IP, **4** confirms an IP/hostname/CIDR scope, **5** inspects evidence, **6** runs hardware diagnostics, **7** configures discovery backends, **8** starts separately confirmed Wi-Fi Direct discovery, **9** lists advertised WFD sinks, **10** prepares Miracast/local presentation and **0** returns. With no selected IPv4 interface, the radio/diagnostic menus remain usable and IP playback is unavailable. IP refresh preserves wireless observations; radio refresh affects only its selected interface.

Selecting targets does not play anything. Choose **Image** or **Video**, then a numbered local file. Before every start or change of playback, including a single receiver, confirm the listed devices:

```text
You are about to start playback on 3 devices.
Continue? [y/N]:
```

Only `y` (case insensitive) accepts. ENTER cancels and preserves existing playback. Sessions prepare/connect independently; use **Playback status** to follow `PREPARING`, `CONNECTING`, `STARTING`, `PLAYING`, `PAUSED`, `RETRYING`, `ERROR` or `INTERRUPTED`. A failing receiver does not stop another receiver.

## Playback and controls

| Control | Behavior |
| --- | --- |
| Playback status | Show cached per-device state and individual errors. |
| Pause / Resume | Queue an operation on each active session; unsupported operations are explicitly reported. |
| Stop playback | Cancel preparation, stop only media still owned by the session, disconnect and release HTTP resources. |
| Change media | Choose a different local image/video without rediscovery; confirm the target selection again. |
| Change target TVs | Reuse the discovery registry, refresh if needed, then start the selected content on the new set after confirmation. |
| Refresh device status | Queue immediate protocol status queries. |
| Back | Choose Stop and return, Keep running and return, or Cancel. |

Commands are asynchronous; check Playback status for results. Keeping playback while returning to the main menu retains both the workers and HTTP server. Reopening option 4 returns to their controls. Exiting POLTERHEIST or Ctrl+C in TV Control closes sessions. In direct `--tv-control` mode, returning exits the process, so use the main menu to keep playback running. Forced process termination cannot guarantee receiver cleanup.

Receivers already busy with other content are reported as busy; stop that content using the receiver before retrying. POLTERHEIST checks the current content URL before pause/resume/stop/repeat, using a unique URL for each session. If another sender or the remote changes content, that session ends instead of taking it back. Protocol state queries and commands are separate operations, so they cannot provide an atomic ownership guarantee against simultaneous changes by another controller. Authorization/pairing failures are reported; they are never bypassed.

## Implemented media/protocol behavior

**Google Cast:** mDNS discovery through zeroconf; connections and media commands through PyChromecast. Images become ten-second, 1280×720, 30fps H.264 Main/yuv420p MP4 clips with letterboxing, faststart and a bounded bitrate. The original aspect ratio is preserved. Repeated selection reuses a conversion when source content and encoding parameters match. PNG/JPEG/WEBP inputs are supported; animated image formats are not promised.

Compatible H.264/yuv420p MP4 up to level 4.1, 1080p/30fps with AAC-LC stereo (or no audio), and VP8/Vorbis WebM up to 1080p/30fps, can play directly. Other video codecs/containers use the 720p H.264/AAC conversion policy. Capabilities beyond this conservative policy are not probed through a custom receiver app, so a more capable TV may receive a converted file unnecessarily. DRM/protected files, subtitle tracks, audio-only files and HDR preservation are not supported.

Cast requests native one-item queue repetition. A receiver explicitly rejecting queue commands falls back to ordinary media loading and client-side restart on `FINISHED`. Persistent errors stop the session; repetition is not an infinite retry policy. A receiver that drops the content identity at EOF cannot safely be restarted and is treated as interrupted.

**DLNA/UPnP AV:** SSDP discovers `MediaRenderer` devices; device/SCPD XML establishes `AVTransport` actions. `SetAVTransportURI`, `Play`, `Stop`, `GetMediaInfo` and `GetTransportInfo` must be advertised for control. Optional Pause, position queries and native repeat are used when advertised. `ConnectionManager.GetProtocolInfo` supplies Sink formats. Generic advertised image MIME types play natively. Generic HTTP MP4 support permits conservative H.264/AAC playback or conversion. MIME advertisement is not a guarantee of codec acceptance: playback acknowledgment/errors are checked separately. Renderers that advertise only restrictive `DLNA.ORG_PN` profiles are rejected for media preparation because profile-specific negotiation/encoding is not implemented. An unadvertised image format can fall back to MP4 only when that generic support is advertised.

DLNA native repeat is preferred. Without it, a stopped transport is restarted only with near-end position/duration evidence. Renderers lacking both repeat and useful position reporting may play once and end with `INTERRUPTED`. Very short clips can finish between status polls; use longer clips or a shorter polling interval. Stop near EOF can be ambiguous in UPnP, which lacks a distinct completion reason. Native still-image persistence depends on renderer behavior. These are protocol limitations, not synchronized multi-TV playback: no exact synchronization or gapless client-side looping is promised.

**Discovery only:** AirPlay/RAOP via Bonjour, DIAL via SSDP/description/Application-URL, and generic UPnP services. No app launch, PIN exchange, media command or video capability is inferred from these observations.

**Wireless discovery:** H4 uses existing NM/supplicant P2P APIs; a valid advertised WFD receiving role makes a Miracast candidate, not a connected session. Cached entries and source-only peers remain distinct. The Miracast preparation adapter reports dependencies and unapproved effects. Optional local ffplay presentation is explicitly local; no external casting process is started.

**Planned, not implemented:** Miracast connection/receiver playback, LG webOS/Samsung/Roku control, AirPlay/RAOP playback and external controller integrations. Automatic IP discovery uses `DiscoveryBackend`; radio discovery has a separate explicit lifecycle so a LAN refresh cannot activate radios. Control adapters separately implement `protocols/base.py`. Unsupported operations remain explicit. The CLI contains no direct Cast or SOAP calls.

## Network and troubleshooting

| Symptom | Check |
| --- | --- |
| No devices | Same LAN/subnet; receiver awake; multicast mDNS UDP 5353 and SSDP UDP 1900; no AP/client isolation. Try directed discovery or configure `bind_ip` for the correct adapter. |
| Incorrect interface | Set `bind_ip` to an existing local IPv4 address, especially with VPNs, virtual adapters or several LANs. VM NAT usually prevents discovery; use a suitable bridged lab network. |
| Receiver unavailable/IP changed | Refresh discovery. Stable identities retain their IDs. New connections have bounded timeouts. |
| Authorization denied | Accept the normal TV authorization/pairing prompt or enable the receiver's supported Cast/DLNA feature. No authentication bypass is provided. |
| Busy receiver | Stop the other app/content on the receiver before starting this session. |
| `ffmpeg`/`ffprobe` missing | `sudo apt install ffmpeg`; verify both commands are on PATH. |
| Conversion/corrupt-file error | Check the actual file with ffprobe/ffmpeg and inspect the technical log. Try a valid PNG or H.264/AAC MP4. |
| Port occupied | Set a free `http_port` in local configuration and restart POLTERHEIST. |
| Playback never acknowledged/buffering | Allow the configured TCP HTTP port from the selected TV IPs on the selected interface. Check client isolation, host firewall and receiver format support. The module does not modify firewall rules. |
| DLNA discovered only | AVTransport or ownership/status actions are missing or the device description could not be read. Media servers are not playback receivers. |
| DLNA incompatible format/profile | The receiver did not advertise a supported generic format. Profile-specific negotiation and vendor codecs are not implemented. Prefer its Cast backend if available. |
| Pause/resume unsupported | The backend reports this instead of claiming success; use Stop. |
| Content changed externally | `INTERRUPTED` is intentional; select/start again only when authorized. |

HTTP binds only the chosen IPv4 address, supports concurrent GET/HEAD and single byte ranges (including suffix ranges), and restricts each random URL to its selected receiver IP. There is no directory listing or upload endpoint. Unknown paths, traversal attempts and other clients get 404. UPnP URLs must use HTTP and the responding receiver's literal IP within the selected scope; redirects, embedded credentials, other-host URLs, DTD/entities and oversized XML are rejected. This excludes some HTTPS/hostname-based UPnP devices. HTTP/1.0 and HTTP/1.1 responses retain an absolute timeout. Logs rotate under `reports/tv_control/`; no traceback is printed for ordinary CLI errors.

## Automated and manual validation

```bash
.venv/bin/python -m unittest discover -s tests -p 'test_tv_control.py' -v
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python -m pip install ruff==0.17.3
.venv/bin/python -m ruff check script.py POLTERHEIST.py tv_control tests
.venv/bin/python -m ruff format --check script.py POLTERHEIST.py tv_control tests
```

Protocol tests use fixtures/mocks, while HTTP tests open actual loopback sockets. The FFmpeg integration tests run real conversions when FFmpeg/ffprobe are installed and otherwise explicitly skip. No automated test discovers or controls lab TVs. CI includes the new package in lint checks; the Kali setup job installs FFmpeg.

Manual reference device: the lab Xiaomi **tv-coneja**, model **MiTV-MSSP2**, previously reported at **192.168.1.159** with ports 8008, 8009 and 8443. Its prior successful PyChromecast/image-to-MP4 test is user-provided context, **not a hardware test of this implementation**. Its name/address are not hardcoded in module logic.

1. Connect Kali and the awake Xiaomi to the same authorized lab LAN. Stop other Cast content on the TV.
2. Install dependencies above. Put a PNG/JPEG/WEBP image and a short video in the repository's `media/` directory. For a synthetic sample video: `ffmpeg -f lavfi -i testsrc2=size=640x360:rate=30 -t 12 -c:v libx264 -pix_fmt yuv420p -movflags +faststart media/test.mp4`.
3. Open the main menu, choose **4** and find `tv-coneja` by its actual discovered ID. If absent, try directed discovery with the TV's **current** IPv4 address. Do not assume its earlier address is unchanged.
4. Choose specific IDs and select only the Xiaomi. Choose Image, then the file. Check `PLAYING`, correct aspect ratio, and continued display for at least 30 seconds (several clip lengths).
5. Pause and resume if supported. Change media to the sample video and observe at least three complete loops. Check that compatible MP4 is served directly and that image conversion is reused on a second selection.
6. Return with Keep running, reopen option 4 and verify the same session is controllable. Stop and verify HTTP closes when the last session releases its file.
7. With additional **authorized** receivers, select multiple IDs. Verify ENTER cancels the confirmation; then explicitly accept and check independent playback. Disconnect one receiver and verify the others continue.
8. While playing, use the TV/another authorized sender to change content. Verify POLTERHEIST marks its session interrupted and does not stop or replace the new content. Verify Ctrl+C stops only owned sessions and exits conversion/HTTP workers.
9. Test a physical DLNA renderer separately, recording its advertised actions/formats and actual playback/loop behavior. Passing Cast tests does not establish DLNA hardware compatibility.

Protocol references: [PyChromecast](https://github.com/home-assistant-libs/pychromecast), [Google Cast supported media](https://developers.google.com/cast/docs/media), [Cast media messages](https://developers.google.com/cast/docs/media/messages), [UPnP AVTransport](https://upnp.org/specs/av/UPnP-av-AVTransport-v1-Service.pdf), [UPnP ConnectionManager](https://www.upnp.org/specs/av/UPnP-av-ConnectionManager-v3-Service-20101231.pdf), [FFmpeg documentation](https://ffmpeg.org/documentation.html).
