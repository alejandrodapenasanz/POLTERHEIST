"""Schedule validation, packaging and CLI propagation without contacting receivers."""

import datetime as dt
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from PIL import Image

from tv_control import payload_assets, payload_runtime, payload_schedule


class ScheduleTests(unittest.TestCase):
    def test_interval_and_absolute_start(self):
        now = dt.datetime(2026, 11, 19, 9, tzinfo=dt.timezone.utc)
        value = payload_schedule.create(every=5, show_seconds=12, now=now)
        self.assertEqual(value["start_at"], int(now.timestamp() * 1000) + 300000)
        self.assertEqual(value["image_ms"], 12000)
        value = payload_schedule.create("2026-11-19T12:00:00+02:00", every=10, now=now)
        self.assertEqual(value["start_at"], int(now.timestamp() * 1000) + 3600000)
        self.assertEqual(value["every_ms"], 600000)
        self.assertIsNone(payload_schedule.create(now=now))

    def test_local_hour_uses_next_occurrence(self):
        now = dt.datetime.now().astimezone().replace(hour=23, minute=59, second=59)
        value = payload_schedule.create("01:00", now=now)
        first = dt.datetime.fromtimestamp(value["start_at"] / 1000).astimezone()
        self.assertEqual(first.date(), now.date() + dt.timedelta(days=1))
        self.assertEqual((first.hour, first.minute), (1, 0))

    def test_invalid_input_cannot_send_or_create_a_busy_loop(self):
        for minutes in (0, -1, float("nan"), float("inf"), 0.0001):
            with self.subTest(minutes=minutes), self.assertRaises(ValueError):
                payload_schedule.create(every=minutes)
        for at in ("25:61", "not a date", "2000-01-01T00:00:00Z"):
            with self.subTest(at=at), self.assertRaises(ValueError):
                payload_schedule.create(at)
        with self.assertRaises(ValueError):
            payload_schedule.create(every=1, show_seconds=float("nan"))

    def test_all_generated_native_sources_carry_schedule(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "media").mkdir()
            source = root / "media/image.jpg"
            Image.new("RGB", (16, 16), "red").save(source)
            schedule = payload_schedule.create(every=2)
            folder = payload_assets.prepare(root, source, schedule=schedule)
            self.assertEqual(payload_schedule.load(folder), schedule)
            for platform in ("webos", "tizen", "roku"):
                with zipfile.ZipFile(payload_assets.native_sources(folder, platform)) as archive:
                    name = "components/PayloadScene.xml" if platform == "roku" else "index.html"
                    text = archive.read(name).decode()
                    self.assertIn(str(schedule["start_at"] // 1000), text)
                    self.assertIn("cancel", text)

    def test_cli_passes_schedule_to_deployment(self):
        with (
            patch.object(payload_runtime, "automatic_source", return_value=Path("media/image.jpg")),
            patch.object(payload_runtime, "automatic_target", return_value="192.0.2.20"),
            patch.object(payload_runtime, "inspect", return_value=(object(), [], {})),
            patch.object(payload_runtime, "PayloadJob") as job,
        ):
            job.return_value.start.return_value = {"state": "SCHEDULED"}
            self.assertEqual(payload_runtime.main(["--every", "5"]), 0)
            self.assertEqual(
                job.return_value.start.call_args.kwargs["schedule"]["every_ms"], 300000
            )

    def test_interactive_schedule_can_cancel_before_detection(self):
        with (
            patch("builtins.input", return_value="0"),
            patch.object(payload_runtime, "inspect") as inspect,
        ):
            with self.assertRaises(EOFError):
                payload_runtime.run(Path("."))
            inspect.assert_not_called()
