# TV Payload

TV Payload prepares and transfers a complete image/video viewer, then closes the PC's
HTTP server and control connection. The television renders its own copy of the content.
Selecting the menu option first offers immediate or scheduled playback, then runs both
steps without asking for an IP, strategy or sending confirmation:

1. **Detect:** identify the target's advertised protocols, model and available transports.
2. **Send and execute:** select an eligible offline runtime, build its viewer, upload,
   launch and check execution evidence. Try another eligible route if the first fails.

An installed native package is preferred when its tools and authorization are available.
Otherwise a supported browser loads a self-contained HTML/JavaScript viewer. The browser
holds the image as embedded data or the entire video in a local Blob. It needs no PC after
loading. **Browser content lasts while that TV application remains open; this is not an
installation that survives TV application closure, eviction or a reboot.** Installed
packages contain their own local media, subject to each platform's development lifetime.

Cast media streaming, DLNA, AirPlay and Miracast do not satisfy the offline payload
contract and cannot be selected as fallbacks. The separate Media control option retains
its streaming functionality.

## Use

Open **IoT Scanning → TV Payload (12)**, **Media control → TV Payload (11)** in receiver
selection, or **TV playback controls → TV Payload (8)**. Direct entry skips the IoT survey:

```powershell
.\.venv\Scripts\python.exe POLTERHEIST.py --tv-payload
# The same automatic workflow without the main application:
.\.venv\Scripts\python.exe -m tv_control.payload
# Override configured content/target, still with no confirmation prompt:
.\.venv\Scripts\python.exe -m tv_control.payload --target 192.168.1.159 --media media/video.mp4
# Read-only detection, without launching or installing:
.\.venv\Scripts\python.exe -m tv_control.payload --target 192.168.1.159 --detect-only
# Review generated HTML and native source archives without sending:
.\.venv\Scripts\python.exe -m tv_control.payload --prepare-only --media media/image.jpg
# Build an Android APK without contacting a TV:
.\.venv\Scripts\python.exe -m tv_control.payload --build-only
```

Linux uses the environment's Python with the same arguments. `--image` remains an alias
for `--media`. `--yes` is optional and has no effect; there is no sending prompt.
`--duration` is accepted for compatibility, but the PC always disconnects after transfer.

## Scheduled playback

The interactive menu offers **Now**, **Start at a time**, and **Every X minutes**.
For direct use without a scheduling prompt:

```bash
python3 POLTERHEIST.py --tv-payload --at 20:30
python3 POLTERHEIST.py --tv-payload --every 5 --show-seconds 10
python3 -m tv_control.payload --media media/video.mp4 --at 20:30 --every 15
python3 -m tv_control.payload --prepare-only --at '2026-11-20T20:30:00+01:00'
```

`HH:MM` selects the next occurrence in the PC's local timezone; an ISO date/time can
include an explicit UTC offset. The schedule is transferred as a UTC timestamp, so the
TV and PC clocks must be correct. A past explicit date is rejected. Without `--at`, the
first repeat occurs after X minutes; `--at` and `--every` can be combined in the CLI.
The standalone module without scheduling flags retains immediate continuous playback.

A single scheduled start displays the image continuously or loops the video. Repeating
schedules show each image for `--show-seconds` (default 10), or play the video once, then
wait on a black screen. A video/image is not interrupted when it outlasts its interval;
missed occurrences are skipped. The viewer displays the next execution while waiting.
If transfer finishes after the requested start, it begins when the media is ready.

Schedules run **on the TV**, including HTML, webOS/Tizen, Roku and Android packages;
the PC disconnects once media loading is confirmed, even if playback is hours away.
Keep the viewer in the foreground. This does not wake a sleeping TV, open the viewer
after reboot, or overlay other TV applications. **Back/Escape on the TV, or closing the
viewer, cancels the current scheduled session**. Reopening an installed package loads its
packaged schedule again. Transfer reports contain the schedule; they do not claim that
a future playback has already been observed.

The workspace's ignored `config/tv_payload.json` selects `192.168.1.159` and
`media/image.jpg`. Other installations can copy `config/tv_payload.example.json`:

```json
{
  "default_target": "192.168.1.159",
  "default_media": "media/image.jpg",
  "devices": {}
}
```

With no configured target, discovery selects a unique Cast/DLNA/DIAL receiver on the
default LAN. Multiple or absent receivers produce an explicit configuration error; the
tool does not guess which TV to replace. Directed detection of a configured IP also
recognizes the other families below. With no configured media, `media/image.jpg` is
preferred, otherwise a single supported file in `media/` is selected.

JPEG/PNG/WEBP images are validated, oriented using EXIF, flattened on black and resized
to fit 1920×1080 without stretching. MP4/MKV/MOV/WEBM videos are inspected and, when needed,
converted to H.264/AAC MP4. The source files are preserved. Video repeats automatically;
browser video starts muted to satisfy autoplay restrictions. HTML payloads accept up to
16 MiB of prepared media; larger media requires a native package. Image input is limited
to 50 MiB/40 megapixels and video input to 512 MiB. All input must be in project `media/`.

## Compatibility

There is no universal installation interface across all televisions. A manufacturer name
or an open port does not prove that an application can run. These adapters are implemented;
physical compatibility with every model or firmware has **not** been established.

| Platform / examples | Automatic route | Conditions and limits |
| --- | --- | --- |
| Google Cast / Chromecast; compatible Xiaomi, Sony, TCL, Philips, Vizio, etc. | `cast-html`: load the generated viewer through DashCast | Cast must accept launching DashCast, a third-party receiver. Its availability and internet bootstrap can affect launch. Complete content remains in the loaded TV process after PC disconnection. |
| Android TV / Google TV | `android-app`: compile, sign, install and launch APK with local media | Existing authorized ADB connection, JDK and Android SDK. An open ADB port alone does not establish authorization. |
| Amazon Fire TV with Android TV features | Android APK if actual ADB capability checks pass; otherwise independently advertised browser protocol | Existing authorization required. Fire branding alone does not establish Android compatibility, including newer non-Android devices. |
| Samsung Tizen | `samsung-html` browser or `tizen-app` signed WGT | Valid existing remote token, or configured Tizen SDK/certificate and authorized SDB. Browser APIs vary by model/year. |
| LG webOS | `webos-html` browser or `webos-app` IPK | Valid existing client key, or configured SDK alias/SSH key and Developer Mode. Alias must match the selected IP. Developer installations depend on the Developer Mode lifetime. |
| Roku TV / Roku OS, including Roku-based TCL/Hisense | `roku-app`: upload and run BrightScript/SceneGraph ZIP | Existing developer mode/password, ECP access and configuration allowing replacement of the one developer channel. |
| Apple TV / tvOS and AirPlay-only televisions | Detect and report | No offline deployment adapter; AirPlay streaming is excluded. |
| DLNA-only televisions | Detect and report | DLNA renderer support does not provide an offline program-installation API; excluded from Payload. |
| Sony BRAVIA | ScalarWebAPI identity plus independently verified Cast/Android capabilities | Use those capabilities if available. Identity alone is insufficient. |
| Philips Saphi / Titan / JointSpace / Android variants | JointSpace identity plus independently verified execution capabilities | No proprietary JointSpace arbitrary-program uploader is implemented. |
| Panasonic Viera / my Home Screen, Hisense VIDAA, LG NetCast, Samsung Orsay, TiVo, other proprietary/legacy televisions | Use Cast if actually advertised and usable, otherwise report unsupported | No native offline uploader for these runtimes. DIAL alone launches known apps; it does not upload arbitrary programs. |
| Miracast-only, cloud-only, hospitality-locked, non-smart or unreachable displays | Report unsupported/unreachable | No compatible offline route is assumed. |

The workflow contains no PIN-pairing wizard and does not ask the user to accept sending.
Native/browser vendor routes require **existing, valid authorization**. A locked receiver
cannot be made compatible by selecting Payload. Firmware can reject or renew a previously
saved authorization; absence of TV-side prompts cannot be guaranteed across every vendor.
ADB and SDB adapters only reuse a session already listed as authorized by the SDK; they
do not initiate a new debugging connection that could display an authorization request.
The Xiaomi Cast route was tested without asking the user to authorize on the TV.

## Tools and existing authorizations

Install `requirements.txt`. Per-IP entries under `devices` in `config/tv_payload.json`
can hold existing settings. The file is ignored by Git; credentials are omitted/redacted
from reports:

* `samsung_token`: existing Samsung remote authorization.
* `webos_client_key`: existing LG browser/control authorization.
* `webos_device`: existing webOS SDK alias; `ares-setup-device --listfull` must report the
  target IP. The ares setup/package/install/launch commands must be on PATH.
* `tizen_certificate`: existing Tizen certificate profile, with `tizen` and `sdb` on PATH
  and an authorized TV transport at port 26101.
* `roku_password`: developer password for `rokudev`; `roku_replace_dev: true` explicitly
  permits replacing the current developer channel.
* `adb_port`: optional existing wireless ADB connection port, not a pairing port.

Android builds use JDK 17+, SDK platform 35 and Build Tools 35.0.0:

```text
sdkmanager "platform-tools" "platforms;android-35" "build-tools;35.0.0"
```

Use `JAVA_HOME`, `ANDROID_HOME`/`ANDROID_SDK_ROOT`, standard Android Studio locations or
`.cache/tv_control/android/tools/`. Preserve `.cache/tv_control/android/tv-payload.keystore`
for app updates. Video preparation needs FFmpeg/ffprobe on PATH or in
`.cache/tv_control/tools/ffmpeg/<build>/bin/`. The menu does not download SDKs, set up
vendor accounts, alter firewall settings or create pairing sessions.

## Evidence and tests

Reports live in `reports/tv_payload/`; generated viewers/source archives in
`.cache/tv_control/payloads/`; signed Android APKs in `.cache/tv_control/android/`.

* `HTML_EXECUTION_CONFIRMED`: the selected TV fetched the HTML and its JavaScript sent a
  receipt after decoding the image or loading the fully embedded video. Scheduled
  playback acknowledges loading before its start time.
* Native states record installation/launch acknowledgements and available foreground or
  active-app checks. These are distinct from a photograph or user confirmation.
* `requires_host: false` and `host_session: CLOSED_AFTER_TRANSFER` indicate successful
  transfer followed by local server/control shutdown. The TV application is left open.
* `NEEDS_SETUP`, `UNSUPPORTED_OR_UNREACHABLE`, `FAILED` do not claim successful execution.

HTTP serves random routes only to the selected TV IP. No media URLs remain necessary
after a successful payload load. Interruptions and failed attempts close local resources.

On **2026-11-17**, detection identified `192.168.1.159` as Xiaomi `MiTV-MSSP2` with
Android TV Remote, DIAL and Google Cast. `media/image.jpg` was sent via `cast-html`.
The TV sent the media-ready receipt, the PC process exited, port 8765 was verified closed,
and a later read-only query showed the receiver session still active. The user then
confirmed seeing `image.jpg`. Evidence:
`reports/tv_payload/session_20261117T183952727684Z.json` and
`reports/tv_payload/post_disconnect.json`.

Tests cover protocol/SDK fixtures, CLI entry points, exclusion of streaming,
fallbacks, local HTTP receipt checks, real Android compilation/signing and Chromium
image/video execution. The real browser tests close HTTP, disable browser networking and
verify that the video continues through a complete loop. Samsung/LG/Roku hardware
and native APK execution on a TV have not been tested here.

On **2026-11-19**, the same Xiaomi MiTV-MSSP2 passed live Cast HTML checks for a timed
image start, two image repetitions and two complete video repetitions, plus cancellation,
after the content HTTP server had closed. A separate test-only collector received viewer
events and decoded-frame counts. The user also confirmed seeing the image and moving
colour video. A final uninstrumented PayloadTV image transfer succeeded. Cast media
playback, pause, resume, repeat and stop passed with the normal configuration.

These checks exposed and fixed stale DashCast sessions between payloads and an ordinary
request timeout incorrectly covering a cold Cast media receiver launch. Evidence and
remaining platform limits: [TV/Windows validation](VALIDATION_2026-11-19.md).

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -p 'test_tv*.py'
# Optional real toolchain/browser checks:
$env:TV_PAYLOAD_BUILD_TEST = '1'
$env:TV_PAYLOAD_OFFLINE_TEST = '1'
.\.venv\Scripts\python.exe -m unittest discover -s tests -p 'test_tv_payload*.py'
```

References: [Cast receivers](https://developers.google.com/cast/docs/web_receiver),
[DashCast receiver source](https://github.com/madmod/dashcast/blob/master/receiver.html),
[Samsung TV development](https://developer.samsung.com/smarttv/develop/getting-started/using-sdk/tv-device.html),
[webOS Developer Mode](https://webostv.developer.lge.com/develop/getting-started/developer-mode-app),
[Roku development setup](https://developer.roku.com/develop/getting-started/setup-guide).
