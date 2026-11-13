"""Animated main menu. Network workflows keep their existing line-oriented UI."""

import math
import os
import sys
import time
from functools import lru_cache

FPS = 12
LOOP_FRAMES = 72
MENU_ITEMS = (
    ("0", "WHO AM I?"),
    ("1", "LAN RECON"),
    ("2", "WIRELESS RECON"),
    ("3", "CAPTIVE PORTAL"),
    ("4", "IoT SCANNING - Discovery & Control"),
    ("q", "EXIT"),
)
# Unicode Braille encodes a 2 x 4 dot matrix in each terminal cell.
DOTS = ((0, 0, 1), (0, 1, 2), (0, 2, 4), (1, 0, 8), (1, 1, 16), (1, 2, 32), (0, 3, 64), (1, 3, 128))


def animation_available(disabled=False):
    return (
        not disabled
        and os.environ.get("POLTERHEIST_NO_ANIMATION", "").lower() in ("", "0", "false", "no")
        and os.environ.get("TERM") != "dumb"
        and sys.stdin.isatty()
        and sys.stdout.isatty()
    )


class Ghost:
    """Move the existing logo at dot resolution, retaining its shape and eyes."""

    def __init__(self, banner):
        # The original banner ends with a stationary baseline and wordmark.
        rows = banner.strip("\n").splitlines()[:-2]
        self.width = max(map(len, rows)) * 2
        self.height = len(rows) * 4
        self.pixels = set()
        for y, row in enumerate(rows):
            for x, char in enumerate(row):
                value = ord(char) - 0x2800
                if 0 <= value <= 255:
                    for dx, dy, bit in DOTS:
                        if value & bit:
                            self.pixels.add((2 * x + dx, 4 * y + dy))

    @lru_cache(maxsize=LOOP_FRAMES * 3)
    def frame(self, index, width=36, height=12, unicode=True):
        """A fixed-size frame; every point is sampled from the original artwork."""
        if width <= 0 or height <= 0:
            return ()
        phase = 2 * math.pi * (index % LOOP_FRAMES) / LOOP_FRAMES
        pixel_width, pixel_height = width * 2, height * 4
        scale = min((pixel_width - 12) / self.width, (pixel_height - 8) / self.height)
        if scale <= 0:
            return tuple(" " * width for _ in range(height))
        left = (pixel_width - self.width * scale) / 2 + 3 * math.sin(phase)
        top = (pixel_height - self.height * scale) / 2 + 2 * math.sin(phase * 2)
        pixels = set()
        for y in range(pixel_height):
            source_y = (y - top) / scale
            depth = max(0, source_y / self.height)
            # The head barely sways; the tail drifts like a sheet in a breeze.
            wave = 2.2 * depth**2 * math.sin(phase * 2 - depth * 5)
            for x in range(pixel_width):
                source_x = (x - left - wave) / scale
                if (math.floor(source_x), math.floor(source_y)) in self.pixels:
                    pixels.add((x, y))
        rows = []
        for y in range(height):
            row = []
            for x in range(width):
                value = sum(bit for dx, dy, bit in DOTS if (2 * x + dx, 4 * y + dy) in pixels)
                if unicode:
                    row.append(chr(0x2800 + value) if value else " ")
                else:
                    row.append(" .:-=+*#@"[value.bit_count()])
            rows.append("".join(row))
        return tuple(rows)


class AnimatedMenu:
    """One renderer owns both the moving logo and the editable input line."""

    def __init__(self, banner, version, *, input=None, output=None):
        # Optional at runtime: old installations can still use the static menu.
        from prompt_toolkit.application import Application
        from prompt_toolkit.filters import Condition
        from prompt_toolkit.key_binding import KeyBindings
        from prompt_toolkit.layout import ConditionalContainer, HSplit, Layout, Window
        from prompt_toolkit.layout.controls import FormattedTextControl
        from prompt_toolkit.output import ColorDepth
        from prompt_toolkit.styles import Style
        from prompt_toolkit.widgets import TextArea

        self.ghost = Ghost(banner)
        self.started = time.monotonic()
        self.notice = ""
        try:
            "\u28ff".encode(sys.stdout.encoding or "utf-8")
            self.unicode = True
        except (UnicodeError, LookupError):
            self.unicode = False
        self.field = TextArea(multiline=False, height=1, prompt="  > ", wrap_lines=False)
        bindings = KeyBindings()

        @bindings.add("enter")
        def accept(event):
            choice = self.field.text.strip().lower()
            if choice in {key for key, _ in MENU_ITEMS}:
                event.app.exit(result=choice)
            else:
                self.notice = "  Choose 0-4, or q to exit."
                self.field.text = ""

        @bindings.add("c-c")
        def interrupt(event):
            event.app.exit(exception=KeyboardInterrupt())

        @bindings.add("c-d")
        def eof(event):
            event.app.exit(exception=EOFError())

        art = Window(
            FormattedTextControl(self.art),
            height=lambda: self.art_size()[1],
            wrap_lines=False,
            dont_extend_height=True,
        )
        menu = []
        for key, label in MENU_ITEMS:
            if key == "q":
                menu.append(("", "\n"))
            menu.extend([("class:key", f"  [{key}] "), ("class:menu", label + "\n")])
        menu[-1] = (menu[-1][0], menu[-1][1].rstrip("\n"))
        layout = HSplit(
            [
                ConditionalContainer(art, filter=Condition(lambda: self.art_size()[1] > 0)),
                Window(
                    FormattedTextControl([("class:title", "  P O L T E R H E I S T")]),
                    height=1,
                    wrap_lines=False,
                ),
                Window(
                    FormattedTextControl([("class:muted", f"  WATCHING THE WIRE / v{version}")]),
                    height=1,
                    wrap_lines=False,
                ),
                Window(height=1),
                Window(FormattedTextControl(menu), height=7, wrap_lines=False),
                Window(height=1),
                self.field,
                Window(
                    FormattedTextControl(
                        lambda: [("class:hint", self.notice or "  Select an option + ENTER")]
                    ),
                    height=1,
                    wrap_lines=False,
                ),
            ]
        )
        no_color = bool(os.environ.get("NO_COLOR"))
        self.application = Application(
            layout=Layout(layout, focused_element=self.field),
            key_bindings=bindings,
            style=Style.from_dict(
                {}
                if no_color
                else {
                    "ghost": "#7cffa6",
                    "ghost.tail": "#3bbf83",
                    "title": "bold #b6ffd1",
                    "key": "#7cffa6",
                    "menu": "#d0e0d8",
                    "muted": "#81968c",
                    "hint": "#81968c",
                }
            ),
            color_depth=ColorDepth.DEPTH_1_BIT if no_color else None,
            full_screen=False,
            erase_when_done=False,
            refresh_interval=1 / FPS,
            min_redraw_interval=1 / FPS,
            input=input,
            output=output,
        )

    def art_size(self):
        size = self.application.output.get_size()
        # Leave room for the menu/input and one spare terminal row. Small
        # terminals keep the menu; enlarging them brings the ghost back.
        height = min(16, max(0, size.rows - 14))
        if size.columns < 32 or height < 6:
            return 0, 0
        return min(38, size.columns - 4), height

    def art(self):
        width, height = self.art_size()
        index = int((time.monotonic() - self.started) * FPS) % LOOP_FRAMES
        rows = self.ghost.frame(index, width, height, self.unicode)
        fragments = []
        for y, row in enumerate(rows):
            style = "class:ghost" if y < height * 0.65 else "class:ghost.tail"
            fragments.append((style, "  " + row + ("\n" if y < height - 1 else "")))
        return fragments

    def read_choice(self):
        self.field.text = ""
        self.notice = ""
        return self.application.run()
