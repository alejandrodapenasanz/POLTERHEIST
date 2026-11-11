"""Local-file validation, conservative codec policy and cached FFmpeg conversion."""

import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path

from .models import Unsupported

LOG = logging.getLogger(__name__)
IMAGES = {".png": "png", ".jpg": "mjpeg", ".jpeg": "mjpeg", ".webp": "webp"}
VIDEOS = {
    ".mp4": "video/mp4",
    ".mov": "video/quicktime",
    ".mkv": "video/x-matroska",
    ".webm": "video/webm",
}
MIME = {"png": "image/png", "mjpeg": "image/jpeg", "webp": "image/webp"}
FILTER = (
    "scale=1280:720:force_original_aspect_ratio=decrease:force_divisible_by=2:out_range=tv,"
    "pad=1280:720:(ow-iw)/2:(oh-ih)/2,setsar=1"
)
ENCODING = [
    "-vf",
    FILTER,
    "-r",
    "30",
    "-c:v",
    "libx264",
    "-profile:v",
    "main",
    "-level:v",
    "3.1",
    "-pix_fmt",
    "yuv420p",
    "-color_range",
    "tv",
    "-crf",
    "23",
    "-maxrate",
    "4M",
    "-bufsize",
    "8M",
    "-movflags",
    "+faststart",
]


@dataclass(frozen=True)
class Media:
    path: Path
    mime: str
    image: bool
    duration: float = 0
    video: dict = None
    audio: tuple = ()


def confined(path, roots):
    resolved = Path(path).resolve(strict=True)
    if not resolved.is_file() or not any(
        resolved.is_relative_to(root.absolute()) for root in roots
    ):
        raise ValueError("Media file must be inside the project's media directory or TV cache")
    return resolved


class MediaLibrary:
    def __init__(self, root, config):
        self.folder = Path(root) / "media"
        self.cache = Path(root) / ".cache" / "tv_control"
        self.folder.mkdir(parents=True, exist_ok=True)
        self.cache.mkdir(parents=True, exist_ok=True)
        if any(
            not folder.resolve().is_relative_to(Path(root).resolve())
            for folder in (self.folder, self.cache)
        ):
            raise ValueError("Media/cache directories must remain inside the project")
        self.config = config
        self._lock = threading.Lock()
        self._local = threading.local()

    @property
    def roots(self):
        return (self.folder, self.cache)

    def list(self, kind):
        extensions = IMAGES if kind == "image" else VIDEOS
        files = []
        for path in self.folder.iterdir():
            if path.suffix.lower() in extensions:
                try:
                    confined(path, (self.folder,))
                except (OSError, ValueError):
                    continue
                files.append(path)
        return sorted(files, key=lambda p: p.name.casefold())

    def _run(self, binary, arguments, timeout):
        executable = shutil.which(binary)
        if not executable:
            raise RuntimeError(f"{binary} not installed; on Kali run: sudo apt install ffmpeg")
        self._check_cancelled()
        process = subprocess.Popen(
            [executable, *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        deadline = time.monotonic() + timeout
        try:
            while True:
                self._check_cancelled()
                if time.monotonic() >= deadline:
                    raise RuntimeError(f"{binary} timed out")
                try:
                    stdout, stderr = process.communicate(timeout=0.2)
                    break
                except subprocess.TimeoutExpired:
                    pass
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.communicate(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate()
        if process.returncode:
            LOG.error("%s failed: %s", binary, stderr.decode("utf-8", "replace")[-4000:])
            raise ValueError(
                f"{binary} failed: corrupt/unsupported file or conversion error; see TV log"
            )
        return stdout

    def _check_cancelled(self):
        event = getattr(self._local, "cancel", None)
        if event is not None and event.is_set():
            raise InterruptedError("Media preparation cancelled")

    def inspect(self, path):
        path = confined(path, self.roots)
        # Restrict demuxers to local input; a renamed playlist cannot fetch remote content.
        raw = self._run(
            "ffprobe",
            [
                "-v",
                "error",
                "-protocol_whitelist",
                "file,pipe",
                "-format_whitelist",
                "image2,png_pipe,jpeg_pipe,webp_pipe,mov,matroska,webm",
                "-show_streams",
                "-show_format",
                "-of",
                "json",
                str(path),
            ],
            30,
        )
        data = json.loads(raw)
        streams = data.get("streams", [])
        video = next(
            (
                s
                for s in streams
                if s.get("codec_type") == "video"
                and not s.get("disposition", {}).get("attached_pic")
            ),
            None,
        )
        if video is None or not video.get("width") or not video.get("height"):
            raise ValueError("File has no decodable image/video stream")
        if video["width"] * video["height"] > 100_000_000:
            raise ValueError("Media dimensions exceed the 100-megapixel safety limit")
        ext = path.suffix.lower()
        image = ext in IMAGES
        if image:
            if video.get("codec_name") != IMAGES[ext]:
                raise ValueError("Image extension does not match its actual format")
            # Decode the image, not just the header; corrupted files must not be cached.
            self._run(
                "ffmpeg",
                [
                    "-v",
                    "error",
                    "-xerror",
                    "-protocol_whitelist",
                    "file,pipe",
                    "-i",
                    str(path),
                    "-frames:v",
                    "1",
                    "-f",
                    "null",
                    "-",
                ],
                30,
            )
            mime = MIME[IMAGES[ext]]
        else:
            formats = set(data.get("format", {}).get("format_name", "").split(","))
            expected = {".mp4": "mp4", ".mov": "mov", ".mkv": "matroska", ".webm": "webm"}
            if ext not in expected or expected[ext] not in formats:
                raise ValueError("Video extension does not match a supported container")
            if ext == ".webm" and (
                video.get("codec_name") not in ("vp8", "vp9", "av1")
                or any(
                    s.get("codec_name") not in ("vorbis", "opus")
                    for s in streams
                    if s.get("codec_type") == "audio"
                )
            ):
                raise ValueError("WEBM extension does not match its actual codecs")
            mime = VIDEOS[ext]
        duration = float(data.get("format", {}).get("duration") or 0)
        return Media(
            path,
            mime,
            image,
            duration,
            video,
            tuple(s for s in streams if s.get("codec_type") == "audio"),
        )

    @staticmethod
    def baseline(media):
        video = media.video or {}
        try:
            fps = float(Fraction(video.get("avg_frame_rate", "0")))
        except (ValueError, ZeroDivisionError):
            fps = 0
        return (
            not media.image
            and media.mime == "video/mp4"
            and video.get("codec_name") == "h264"
            and video.get("pix_fmt") == "yuv420p"
            and video.get("profile") in ("Constrained Baseline", "Baseline", "Main", "High")
            and 0 < video.get("level", 999) <= 41
            and video.get("width", 9999) <= 1920
            and video.get("height", 9999) <= 1080
            and 0 < fps <= 30
            and all(
                a.get("codec_name") == "aac"
                and a.get("profile") == "LC"
                and a.get("channels", 999) <= 2
                for a in media.audio
            )
        )

    @staticmethod
    def webm_compatible(media):
        video = media.video or {}
        try:
            fps = float(Fraction(video.get("avg_frame_rate", "0")))
        except (ValueError, ZeroDivisionError):
            return False
        return (
            media.mime == "video/webm"
            and video.get("codec_name") == "vp8"
            and video.get("pix_fmt") == "yuv420p"
            and video.get("width", 9999) <= 1920
            and video.get("height", 9999) <= 1080
            and 0 < fps <= 30
            and all(
                a.get("codec_name") == "vorbis" and a.get("channels", 999) <= 2 for a in media.audio
            )
        )

    def prepare(self, source, endpoint, cancel=None):
        self._local.cancel = cancel
        self._check_cancelled()
        media = self.inspect(source)
        if endpoint.protocol == "Google Cast":
            if self.baseline(media) or self.webm_compatible(media):
                return media
            return self.convert(media)
        sinks = [entry.split(":", 3) for entry in endpoint.details.get("sink", [])]
        advertised = [entry for entry in sinks if len(entry) == 4 and entry[0] == "http-get"]
        # A MIME match cannot override a restrictive DLNA profile. Unknown profile
        # requirements are refused instead of assuming the renderer accepts our encoder.
        generic = [entry for entry in advertised if not re.search(r"DLNA\.ORG_PN=", entry[3], re.I)]
        if media.image and any(entry[2] == media.mime for entry in generic):
            return media
        # Generic HTTP video/mp4 is attempted conservatively; actual acceptance is
        # confirmed by playback status, never inferred from a successful SOAP request.
        mp4 = any(entry[2] in ("video/mp4", "*") for entry in generic)
        if not mp4:
            raise Unsupported(
                "DLNA receiver has not advertised generic HTTP MP4 support; profile-specific formats are not implemented"
            )
        if self.baseline(media):
            return media
        return self.convert(media)

    def convert(self, media):
        if not self.config.auto_convert:
            raise Unsupported("Conversion needed; enable auto_convert in config/tv_control.json")
        with self._lock:
            digest = hashlib.sha256()
            with media.path.open("rb") as source:
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    self._check_cancelled()
                    digest.update(chunk)
            digest.update(json.dumps([ENCODING, media.image, "aac-lc-stereo-128k", 10, 1]).encode())
            output = self.cache / (digest.hexdigest() + ".mp4")
            if output.exists():
                try:
                    cached = self.inspect(output)
                    if self.baseline(cached):
                        return cached
                except (ValueError, OSError):
                    LOG.debug("Invalid cached conversion; regenerating", exc_info=True)
            temporary = output.with_name(output.stem + "." + uuid.uuid4().hex + ".mp4")
            args = ["-v", "error", "-xerror", "-nostdin", "-y", "-protocol_whitelist", "file,pipe"]
            if media.image:
                args += ["-f", "image2", "-pattern_type", "none", "-loop", "1", "-framerate", "30"]
            args += ["-i", str(media.path), "-map", "0:v:0"]
            if media.image:
                args += ["-t", "10", "-an", "-tune", "stillimage"]
            else:
                args += [
                    "-map",
                    "0:a:0?",
                    "-c:a",
                    "aac",
                    "-profile:a",
                    "aac_low",
                    "-ac",
                    "2",
                    "-b:a",
                    "128k",
                ]
            args += [*ENCODING, "-threads", "2", str(temporary)]
            try:
                self._run("ffmpeg", args, self.config.conversion_timeout)
                converted = self.inspect(temporary)
                if not self.baseline(converted):
                    raise ValueError("Converted media failed compatibility validation")
                os.replace(temporary, output)
            finally:
                temporary.unlink(missing_ok=True)
            return Media(
                output, "video/mp4", False, converted.duration, converted.video, converted.audio
            )
