"""Prepare content that is fully copied into the TV viewer, never a streaming URL."""

import json
import shutil
from pathlib import Path

from .media import IMAGES, VIDEOS, MediaLibrary, confined
from .models import Config
from .payload_build import validate_image

EXTENSIONS = set(IMAGES) | set(VIDEOS)


def validate_source(root, source):
    path = confined(source, (Path(root).resolve() / "media",))
    if path.suffix.lower() in IMAGES:
        return validate_image(root, path)
    if path.suffix.lower() not in VIDEOS:
        raise ValueError("Choose an image or MP4/MKV/MOV/WEBM video from project media/")
    if not 0 < path.stat().st_size <= 512 * 1024 * 1024:
        raise ValueError("Video payload input must be between 1 byte and 512 MiB")
    return path


def prepare_content(root, source, folder):
    source = validate_source(root, source)
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    if source.suffix.lower() in IMAGES:
        from PIL import Image, ImageOps

        with Image.open(source) as original:
            image = ImageOps.exif_transpose(original).convert("RGBA")
            image.thumbnail((1920, 1080), Image.Resampling.LANCZOS)
            background = Image.new("RGB", image.size, "black")
            background.paste(image, mask=image.getchannel("A"))
            background.save(folder / "image.jpg", quality=95)
        content = {"kind": "image", "file": "image.jpg", "mime": "image/jpeg"}
    else:
        library = MediaLibrary(root, Config())
        media = library.inspect(source)
        if media.image:
            raise ValueError("Video input does not contain a video")
        if not library.baseline(media):
            media = library.convert(media)
        shutil.copyfile(media.path, folder / "video.mp4")
        content = {"kind": "video", "file": "video.mp4", "mime": "video/mp4"}
    (folder / "content.json").write_text(json.dumps(content), encoding="utf-8")
    return content


def content_info(folder):
    path = Path(folder) / "content.json"
    return (
        json.loads(path.read_text(encoding="utf-8"))
        if path.exists()
        else {"kind": "image", "file": "image.jpg", "mime": "image/jpeg"}
    )
