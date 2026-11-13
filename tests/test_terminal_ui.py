"""Real terminal rendering and keyboard handling with synthetic input only."""

import asyncio
import contextlib
import io
import os
import unittest
from unittest.mock import patch

from prompt_toolkit.data_structures import Size
from prompt_toolkit.input import create_pipe_input
from prompt_toolkit.output import DummyOutput

import script
from terminal_ui import LOOP_FRAMES, AnimatedMenu, Ghost, animation_available


class GhostTests(unittest.TestCase):
    def test_motion_is_periodic_and_stays_inside_fixed_bounds(self):
        ghost = Ghost(script.BANNER)
        frames = [ghost.frame(index, 38, 16) for index in range(LOOP_FRAMES)]
        self.assertGreater(len(set(frames)), 40)
        for frame in frames:
            self.assertEqual(len(frame), 16)
            self.assertTrue(all(len(row) == 38 for row in frame))
            self.assertTrue(any(row.strip() for row in frame))
        self.assertEqual(frames[0], ghost.frame(LOOP_FRAMES, 38, 16))

    def test_ascii_and_compact_frames_remain_available(self):
        ghost = Ghost(script.BANNER)
        for height in (6, 10, 16):
            frame = ghost.frame(20, 28, height, unicode=False)
            self.assertTrue("".join(frame).isascii())
            self.assertTrue(any(row.strip() for row in frame))
        self.assertEqual(ghost.frame(0, 0, 0), ())

    def test_animation_requires_interactive_input_and_output(self):
        with (
            patch.dict(os.environ, {"TERM": "xterm", "POLTERHEIST_NO_ANIMATION": "0"}),
            patch("terminal_ui.sys.stdin.isatty", return_value=True),
            patch("terminal_ui.sys.stdout.isatty", return_value=True),
        ):
            self.assertTrue(animation_available())
            self.assertFalse(animation_available(disabled=True))
            with patch("terminal_ui.sys.stdin.isatty", return_value=False):
                self.assertFalse(animation_available())
            with patch("terminal_ui.sys.stdout.isatty", return_value=False):
                self.assertFalse(animation_available())
            with patch.dict(os.environ, {"TERM": "dumb"}):
                self.assertFalse(animation_available())
            with patch.dict(os.environ, {"POLTERHEIST_NO_ANIMATION": "1"}):
                self.assertFalse(animation_available())


class ResizableOutput(DummyOutput):
    def __init__(self):
        self.size = Size(rows=30, columns=80)

    def get_size(self):
        return self.size


class AnimatedInputTests(unittest.IsolatedAsyncioTestCase):
    async def test_refresh_keeps_typed_text_and_cursor_then_enter_selects(self):
        with create_pipe_input() as keyboard:
            menu = AnimatedMenu(script.BANNER, script.VERSION, input=keyboard, output=DummyOutput())
            frames = []
            menu.application.after_render += lambda _: frames.append(menu.art())
            task = asyncio.create_task(menu.application.run_async())
            try:
                keyboard.send_text("14")
                await asyncio.sleep(0.3)
                self.assertEqual(menu.field.text, "14")
                self.assertEqual(menu.field.buffer.cursor_position, 2)
                self.assertGreater(len(frames), 1)
                self.assertNotEqual(frames[0], frames[-1])
                # Move left, delete the first character, then submit option 4.
                keyboard.send_text("\x1b[D\x7f\r")
                self.assertEqual(await asyncio.wait_for(task, 3), "4")
            finally:
                if not task.done():
                    task.cancel()
                    with contextlib.suppress(asyncio.CancelledError):
                        await task
            self.assertFalse(menu.application.is_running)

    async def test_invalid_option_keeps_menu_open_and_accepts_corrected_choice(self):
        with create_pipe_input() as keyboard:
            menu = AnimatedMenu(script.BANNER, script.VERSION, input=keyboard, output=DummyOutput())
            task = asyncio.create_task(menu.application.run_async())
            keyboard.send_text("invalid\r")
            await asyncio.sleep(0.15)
            self.assertFalse(task.done())
            self.assertIn("Choose 0-4", menu.notice)
            keyboard.send_text("Q\r")
            self.assertEqual(await asyncio.wait_for(task, 3), "q")

    async def test_ctrl_c_and_eof_exit_without_leaving_animation_running(self):
        for key, error in (("\x03", KeyboardInterrupt), ("\x04", EOFError)):
            with self.subTest(key=key), create_pipe_input() as keyboard:
                menu = AnimatedMenu(
                    script.BANNER, script.VERSION, input=keyboard, output=DummyOutput()
                )
                keyboard.send_text(key)
                with self.assertRaises(error):
                    await menu.application.run_async()
                self.assertFalse(menu.application.is_running)

    async def test_resize_preserves_input_and_restores_art_when_space_returns(self):
        with create_pipe_input() as keyboard:
            output = ResizableOutput()
            menu = AnimatedMenu(script.BANNER, script.VERSION, input=keyboard, output=output)
            task = asyncio.create_task(menu.application.run_async())
            keyboard.send_text("2")
            await asyncio.sleep(0.15)
            output.size = Size(rows=18, columns=30)
            menu.application.invalidate()
            await asyncio.sleep(0.15)
            self.assertEqual(menu.art_size(), (0, 0))
            self.assertEqual(menu.field.text, "2")
            output.size = Size(rows=30, columns=80)
            menu.application.invalidate()
            await asyncio.sleep(0.15)
            self.assertGreater(menu.art_size()[1], 0)
            self.assertEqual(menu.field.text, "2")
            keyboard.send_text("\r")
            self.assertEqual(await asyncio.wait_for(task, 3), "2")

    def test_reentering_menu_starts_with_empty_input(self):
        with create_pipe_input() as keyboard:
            menu = AnimatedMenu(script.BANNER, script.VERSION, input=keyboard, output=DummyOutput())
            for choice in ("0", "q"):
                keyboard.send_text(choice + "\r")
                self.assertEqual(menu.read_choice(), choice)
                self.assertFalse(menu.application.is_running)


class MainMenuIntegrationTests(unittest.TestCase):
    def test_animated_menu_stops_for_workflow_and_reappears_after_return(self):
        with (
            patch.object(script, "animation_available", return_value=True),
            patch.object(script, "AnimatedMenu") as menu_class,
            patch.object(script, "who_am_i") as profile,
            patch("builtins.input", side_effect=AssertionError("Animated menu owns input")),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            menu = menu_class.return_value
            menu.read_choice.side_effect = ["0", "q"]
            self.assertEqual(script.main([]), 0)
            profile.assert_called_once_with()
            self.assertEqual(menu.read_choice.call_count, 2)
            self.assertEqual(output.getvalue(), "")

    def test_explicit_static_option_and_missing_dependency_keep_existing_menu(self):
        for missing in (True, False):
            with (
                self.subTest(missing=missing),
                patch.object(script, "animation_available", return_value=missing) as available,
                patch.object(script, "AnimatedMenu", side_effect=ImportError),
                patch("builtins.input", return_value="q"),
                contextlib.redirect_stdout(io.StringIO()) as output,
            ):
                self.assertEqual(script.main([] if missing else ["--no-animation"]), 0)
                self.assertIn("[0] WHO AM I?", output.getvalue())
                available.assert_called_once_with(not missing)

    def test_direct_workflows_do_not_open_animated_menu(self):
        with (
            patch.object(script, "animation_available") as available,
            patch.object(script, "wireless_recon", return_value=0),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(script.main(["--wireless"]), 0)
            available.assert_not_called()


if __name__ == "__main__":
    unittest.main()
