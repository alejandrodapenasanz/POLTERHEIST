# Windows and TV validation — 2026-11-19

Environment: Windows, Python 3.13.15, project virtual environment, and a physical
Xiaomi MiTV-MSSP2 exposing Android TV Remote, DIAL and Google Cast.

## Verified behavior

| Check | Result |
| --- | --- |
| PayloadTV image at a specified time | Receiver reported the image becoming visible at the scheduled start. |
| Repeating image | Two appearances, 20 seconds apart, each visible for 5 seconds. |
| Repeating video | Two complete 6-second playbacks, 20 seconds apart; 288 decoded frames reported. |
| Schedule cancellation | No further appearance after cancellation. |
| Content independence | Media HTTP server and its port closed before scheduled playback. |
| Ordinary Cast controls | Play, pause, resume, repetition and stop acknowledged by the physical receiver. |
| Visual confirmation | The image and moving colour video were confirmed on the TV; a final uninstrumented PayloadTV transfer also succeeded. |
| Cleanup | Test viewer stopped and content port closed. |
| Windows diagnostics | Native WLAN available; the installed MediaTek MT7921 driver exposes managed mode only. Bluetooth adapter and LE enumerator reported healthy by Windows. |
| Local portal preview | HTTP 200 on loopback, expected page content, and clean shutdown. |
| Logging | Persistent JSON records contain startup, hardware results, actions and exception traces. Rotation and redaction regressions pass. |

The scheduled tests added a temporary event observer to generated HTML. Its separate
HTTP endpoint collected visibility, playback and decoded-frame events, without serving
media. The content server closed normally after transfer. The PC itself was not powered
off during these measurements. Real Chromium tests separately disabled browser networking
and verified playback after closing the content server.

PayloadTV runs the transferred content and schedule on the TV while the viewer remains
open. Closing the viewer or rebooting the TV ends the browser session. Ordinary Cast
media control serves media from the PC and requires that PC to remain available.

## Corrections verified on the TV

- Restart a previous DashCast session before sending a replacement payload: the TV
  could retain an advertised namespace after navigating away from its URL handler.
- Give Cast media receiver startup a separate `launch_timeout` (30 seconds by default)
  before applying the ordinary media request timeout. Play/pause/resume/stop passed with
  the default configuration after this correction.

## Automated checks

- Full suite after corrections: **462 tests, OK, 12 skipped** for platform requirements
  or opt-in integrations.
- Opt-in PayloadTV integration suite: **64 tests, OK, no skips**, using real Chromium,
  FFmpeg, and Android APK compilation/signature verification.
- Ruff, `pip check`, Bash syntax validation and `git diff --check`: passed.

The logs and detailed receiver reports are local artifacts under `reports/` and are
excluded from Git. This summary records their results without requiring those files
to be available in a checkout.

## Test video

The moving colour pattern was generated locally with FFmpeg's `testsrc2` filter:

```bash
ffmpeg -f lavfi -i testsrc2=size=640x360:rate=24 -t 6 -an -c:v libx264 -profile:v baseline -pix_fmt yuv420p -movflags +faststart media/test-video.mp4
```

## Remaining physical validation

- Kali installation and ownership repair with and without sudo.
- Kali radios, AP, monitor/injection, Wi-Fi Direct and BLE.
- APK execution on Android TV: ADB was unavailable; compilation/signing was verified
  locally but the APK was not installed on this TV.
- Other receiver families, DLNA-only receivers, multiple TVs, physical network loss,
  TV reboot, and the Back button on each remote control.
