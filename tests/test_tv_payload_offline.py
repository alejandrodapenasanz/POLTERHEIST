"""Opt-in real Chromium/FFmpeg/Android integration, with the serving PC disconnected."""

import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
import urllib.request
import zipfile
from pathlib import Path

from PIL import Image

from tv_control import payload_assets, payload_build, payload_schedule
from tv_control.http_server import MediaServer
from tv_control.media import Media, MediaLibrary
from tv_control.models import Config

ROOT = Path(__file__).resolve().parent.parent


@unittest.skipUnless(
    os.environ.get("TV_PAYLOAD_OFFLINE_TEST") == "1", "Optional real offline viewer test"
)
class OfflineViewerTests(unittest.TestCase):
    def setUp(self):
        self.source_dir = Path(self.enterContext(tempfile.TemporaryDirectory(dir=ROOT / "media")))

    def video(self):
        source = self.source_dir / "fixture.mp4"
        MediaLibrary(ROOT, Config())._run(
            "ffmpeg",
            [
                "-v",
                "error",
                "-nostdin",
                "-y",
                "-f",
                "lavfi",
                "-i",
                "testsrc2=size=160x90:rate=10",
                "-t",
                "3",
                "-an",
                "-c:v",
                "libx264",
                "-profile:v",
                "baseline",
                "-pix_fmt",
                "yuv420p",
                "-movflags",
                "+faststart",
                str(source),
            ],
            30,
        )
        return source

    def browser(self):
        import websocket

        binary = (
            os.environ.get("TV_PAYLOAD_CHROME")
            or shutil.which("chromium")
            or shutil.which("google-chrome")
        )
        if not binary:
            binary = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
        if not Path(binary).is_file():
            self.fail("Set TV_PAYLOAD_CHROME to an installed Chromium/Chrome executable")
        profile = Path(self.enterContext(tempfile.TemporaryDirectory()))
        process = subprocess.Popen(
            [
                binary,
                "--headless=new",
                "--disable-gpu",
                "--no-first-run",
                "--no-default-browser-check",
                "--remote-debugging-port=0",
                "--user-data-dir=" + str(profile),
                "about:blank",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )

        def close():
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

        self.addCleanup(close)
        deadline = time.monotonic() + 15
        port_file = profile / "DevToolsActivePort"
        while not port_file.exists() and time.monotonic() < deadline:
            time.sleep(0.1)
        self.assertTrue(port_file.exists(), "Headless browser did not start")
        port = int(port_file.read_text().splitlines()[0])
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(f"http://127.0.0.1:{port}/json", timeout=5) as response:
            targets = json.load(response)
        target = next(item for item in targets if item["type"] == "page")
        ws = websocket.create_connection(
            target["webSocketDebuggerUrl"], suppress_origin=True, timeout=10
        )
        self.addCleanup(ws.close)
        sequence = 0

        def call(method, **params):
            nonlocal sequence
            sequence += 1
            ws.send(json.dumps({"id": sequence, "method": method, "params": params}))
            while True:
                response = json.loads(ws.recv())
                if response.get("id") == sequence:
                    if "error" in response:
                        self.fail(str(response["error"]))
                    return response.get("result", {})

        return call

    def assert_offline_playback(self, source, video=False):
        folder = payload_assets.prepare(ROOT, source)
        server = MediaServer("127.0.0.1", 0, (folder,))
        self.addCleanup(server.close)
        receipt_file = folder / "receipt.txt"
        receipt_file.write_text("ready")
        receipt = server.publish(Media(receipt_file, "text/plain", False), "127.0.0.1")
        html = payload_assets.write_html(folder, receipt)
        url = server.publish(Media(html, "text/html", False), "127.0.0.1")
        call = self.browser()
        call("Page.navigate", url=url)
        deadline = time.monotonic() + 15
        while not server.requests(receipt) and time.monotonic() < deadline:
            time.sleep(0.1)
        self.assertGreater(
            server.requests(receipt), 0, "The JavaScript media-ready receipt did not arrive"
        )
        server.close()
        self.assertFalse(server.running)
        call("Network.enable")
        call(
            "Network.emulateNetworkConditions",
            offline=True,
            latency=0,
            downloadThroughput=0,
            uploadThroughput=0,
        )

        def evaluate(expression):
            response = call("Runtime.evaluate", expression=expression, returnByValue=True)
            self.assertNotIn("exceptionDetails", response)
            return response["result"].get("value")

        if video:
            frames = "document.getElementById('picture').getVideoPlaybackQuality().totalVideoFrames"
            before = evaluate(frames)
            time.sleep(4)  # Cross a full loop with HTTP shut down and networking disabled.
            self.assertGreater(evaluate(frames), before + 15)
            self.assertTrue(
                evaluate(
                    "(function(){var v=document.getElementById('picture');return !v.paused && !v.error && v.src.indexOf('blob:')===0;})()"
                )
            )
        else:
            self.assertTrue(
                evaluate(
                    "(function(){var p=document.getElementById('picture');return p.complete && p.naturalWidth===160 && p.src.indexOf('data:')===0;})()"
                )
            )

    def test_image_decoded_after_server_closes_and_browser_goes_offline(self):
        source = self.source_dir / "fixture.jpg"
        Image.new("RGB", (160, 90), "blue").save(source)
        self.assert_offline_playback(source)

    def test_video_loops_after_server_closes_and_browser_goes_offline(self):
        self.assert_offline_playback(self.video(), video=True)

    def test_native_video_packages_include_all_media_locally(self):
        source = self.video()
        folder = payload_assets.prepare(ROOT, source)
        for platform in ("webos", "tizen", "roku"):
            with zipfile.ZipFile(payload_assets.native_sources(folder, platform)) as package:
                self.assertEqual(package.read("video.mp4"), source.read_bytes())
                if platform != "roku":
                    self.assertIn(b'p.src="video.mp4"', package.read("index.html"))
        apk = payload_build.build_apk(ROOT, source)
        with zipfile.ZipFile(apk) as package:
            self.assertEqual(package.read("assets/video.mp4"), source.read_bytes())
            self.assertEqual(json.loads(package.read("assets/content.json"))["kind"], "video")
            self.assertTrue(package.read("classes.dex").startswith(b"dex\n"))

    def check_scheduled_playback(self, video):
        source = self.video() if video else self.source_dir / "fixture.jpg"
        if not video:
            Image.new("RGB", (160, 90), "blue").save(source)
        schedule = payload_schedule.create(every=1, show_seconds=1)
        folder = payload_assets.prepare(ROOT, source, schedule=schedule)
        server = MediaServer("127.0.0.1", 0, (folder,))
        self.addCleanup(server.close)
        receipt_file = folder / "receipt.txt"
        receipt_file.write_text("ready")
        receipt = server.publish(Media(receipt_file, "text/plain", False), "127.0.0.1")
        url = server.publish(
            Media(payload_assets.write_html(folder, receipt), "text/html", False), "127.0.0.1"
        )
        call = self.browser()
        call("Page.navigate", url=url)
        deadline = time.monotonic() + 15
        while not server.requests(receipt) and time.monotonic() < deadline:
            time.sleep(0.1)
        self.assertGreater(
            server.requests(receipt), 0, "Future playback must not delay transfer receipt"
        )
        server.close()
        call("Network.enable")
        call(
            "Network.emulateNetworkConditions",
            offline=True,
            latency=0,
            downloadThroughput=0,
            uploadThroughput=0,
        )

        def evaluate(expression):
            result = call("Runtime.evaluate", expression=expression, returnByValue=True)
            self.assertNotIn("exceptionDetails", result)
            return result["result"].get("value")

        visible = "document.getElementById('picture').style.visibility"
        self.assertEqual(evaluate(visible), "hidden")
        if video:
            self.assertTrue(evaluate("document.getElementById('picture').paused"))
        for cycle in (0, 1):
            now = schedule["start_at"] + cycle * schedule["every_ms"] + 100
            evaluate("Date.now=function(){return " + str(now) + ";}")
            time.sleep(0.6)
            self.assertEqual(evaluate(visible), "visible")
            if video:
                self.assertFalse(evaluate("document.getElementById('picture').paused"))
                time.sleep(3.5)
            else:
                evaluate("Date.now=function(){return " + str(now + 1100) + ";}")
                time.sleep(0.6)
            self.assertEqual(evaluate(visible), "hidden")
        evaluate("window.cancelPayloadSchedule()")
        evaluate("Date.now=function(){return " + str(schedule["start_at"] + 10000000) + ";}")
        time.sleep(0.6)
        self.assertEqual(evaluate(visible), "hidden")

    def test_scheduled_image_repeats_and_cancels_with_pc_offline(self):
        self.check_scheduled_playback(False)

    def test_scheduled_video_repeats_and_cancels_with_pc_offline(self):
        self.check_scheduled_playback(True)

    def test_scheduled_android_package_is_compiled_signed_and_embeds_timing(self):
        source = self.source_dir / "scheduled.jpg"
        Image.new("RGB", (160, 90), "blue").save(source)
        schedule = payload_schedule.create(every=2)
        with zipfile.ZipFile(payload_build.build_apk(ROOT, source, schedule=schedule)) as package:
            self.assertEqual(json.loads(package.read("assets/schedule.json")), schedule)
            self.assertTrue(package.read("classes.dex").startswith(b"dex\n"))


if __name__ == "__main__":
    unittest.main()
