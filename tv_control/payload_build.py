"""Build the small offline Android TV viewer using local JDK/Android SDK tools."""

import hashlib
import os
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path

from .media import confined

PACKAGE = "org.polterheist.tvpayload"
COMPONENT = PACKAGE + "/.ImageActivity"


def run_command(arguments, timeout=60):
    try:
        result = subprocess.run(
            [str(arg) for arg in arguments],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(f"{Path(arguments[0]).name} timed out after {timeout}s") from error
    output = (result.stdout + "\n" + result.stderr).strip()
    if result.returncode:
        raise RuntimeError(f"{Path(arguments[0]).name} failed: {output[-3000:]}")
    return output


def sdk_roots(root):
    candidates = [
        os.environ.get("ANDROID_SDK_ROOT"),
        os.environ.get("ANDROID_HOME"),
        Path.home() / "AppData/Local/Android/Sdk",
        Path.home() / "Android/Sdk",
        Path.home() / "Library/Android/sdk",
        Path(root) / ".cache/tv_control/android/tools",
    ]
    return [Path(path) for path in candidates if path and Path(path).is_dir()]


def find_adb(root):
    name = "adb.exe" if os.name == "nt" else "adb"
    found = shutil.which("adb")
    if found:
        return Path(found)
    for folder in sdk_roots(root):
        for relative in (f"platform-tools/{name}", f"adb/platform-tools/{name}"):
            path = folder / relative
            if path.is_file():
                return path
    raise RuntimeError("ADB is missing. Install Android Platform Tools; see docs/TV_PAYLOAD.md")


def build_tools(root):
    suffix = ".exe" if os.name == "nt" else ""
    java_homes = [Path(os.environ["JAVA_HOME"])] if os.environ.get("JAVA_HOME") else []
    if shutil.which("javac"):
        java_homes.append(Path(shutil.which("javac")).resolve().parent.parent)
    java_homes.extend(sorted((Path(root) / ".cache/tv_control/android/tools/jdk").glob("*")))
    java_home = next(
        (
            home
            for home in java_homes
            if all((home / "bin" / (n + suffix)).is_file() for n in ("java", "javac", "keytool"))
        ),
        None,
    )
    if java_home is None:
        raise RuntimeError("JDK 17+ is required to build TV Payload; see docs/TV_PAYLOAD.md")
    for sdk in sdk_roots(root):
        platforms = list(sdk.glob("platforms/android-35/android.jar"))
        platforms.extend(sdk.glob("platform/*/android.jar"))
        builds = list(sdk.glob("build-tools/35.0.0"))
        builds.extend(sdk.glob("build-tools/android-*"))
        for folder in builds:
            if platforms and all(
                (folder / file).is_file()
                for file in (
                    "aapt2" + suffix,
                    "zipalign" + suffix,
                    "lib/d8.jar",
                    "lib/apksigner.jar",
                )
            ):
                return java_home / "bin", folder, platforms[0]
    raise RuntimeError(
        "Android SDK platform 35 and Build Tools 35.0.0 are required; see docs/TV_PAYLOAD.md"
    )


def validate_image(root, source):
    try:
        from PIL import Image
    except ImportError as error:
        raise RuntimeError("Pillow is required: install requirements.txt in the venv") from error
    path = confined(source, (Path(root).resolve() / "media",))
    if path.suffix.lower() not in (".jpg", ".jpeg", ".png", ".webp"):
        raise ValueError("Choose a JPEG, PNG or WEBP image from the project's media/ directory")
    if path.stat().st_size > 50 * 1024 * 1024:
        raise ValueError("Image must be at most 50 MB")
    try:
        with Image.open(path) as image:
            if (
                image.format not in ("JPEG", "PNG", "WEBP")
                or image.width * image.height > 40_000_000
            ):
                raise ValueError("Choose a JPEG, PNG or WEBP image of at most 40 megapixels")
            image.verify()
    except Image.DecompressionBombError as error:
        raise ValueError("Choose an image of at most 40 megapixels") from error
    return path


def build_apk(root, source, schedule=None):
    from .payload_content import prepare_content, validate_source

    root = Path(root).resolve()
    source = validate_source(root, source)

    java_bin, build, platform = build_tools(root)
    suffix = ".exe" if os.name == "nt" else ""
    cache = root / ".cache/tv_control/android"
    cache.mkdir(parents=True, exist_ok=True)
    code = root / "tv_payload"
    key = cache / "tv-payload.keystore"
    if not key.exists():
        run_command(
            [
                java_bin / ("keytool" + suffix),
                "-genkeypair",
                "-keystore",
                key,
                "-storepass",
                "android",
                "-keypass",
                "android",
                "-alias",
                "tv-payload",
                "-keyalg",
                "RSA",
                "-keysize",
                "2048",
                "-validity",
                "10000",
                "-dname",
                "CN=POLTERHEIST TV Payload",
                "-noprompt",
            ]
        )
    with tempfile.TemporaryDirectory(prefix="build-", dir=cache) as directory:
        work = Path(directory)
        assets, classes, dex = (work / name for name in ("assets", "classes", "dex"))
        for folder in (assets, classes, dex):
            folder.mkdir()
        prepare_content(root, source, assets)
        if schedule:
            from .payload_schedule import save

            save(assets, schedule)
        resources, unsigned, aligned = (
            work / name for name in ("resources.zip", "unsigned.apk", "aligned.apk")
        )
        run_command([build / ("aapt2" + suffix), "compile", "--dir", code / "res", "-o", resources])
        run_command(
            [
                build / ("aapt2" + suffix),
                "link",
                "-o",
                unsigned,
                "-I",
                platform,
                "--manifest",
                code / "AndroidManifest.xml",
                "-A",
                assets,
                resources,
            ]
        )
        run_command(
            [
                java_bin / ("javac" + suffix),
                "-encoding",
                "UTF-8",
                "-source",
                "8",
                "-target",
                "8",
                "-bootclasspath",
                platform,
                "-d",
                classes,
                *sorted((code / "src").rglob("*.java")),
            ]
        )
        run_command(
            [
                java_bin / ("java" + suffix),
                "-cp",
                build / "lib/d8.jar",
                "com.android.tools.r8.D8",
                "--release",
                "--min-api",
                "23",
                "--lib",
                platform,
                "--output",
                dex,
                *sorted(classes.rglob("*.class")),
            ]
        )
        with zipfile.ZipFile(unsigned, "a", zipfile.ZIP_DEFLATED) as archive:
            archive.write(dex / "classes.dex", "classes.dex")
        run_command([build / ("zipalign" + suffix), "-f", "4", unsigned, aligned])
        signer = [java_bin / ("java" + suffix), "-jar", build / "lib/apksigner.jar"]
        signed = work / "TV-Payload.apk"
        run_command(
            [
                *signer,
                "sign",
                "--ks",
                key,
                "--ks-key-alias",
                "tv-payload",
                "--ks-pass",
                "pass:android",
                "--key-pass",
                "pass:android",
                "--out",
                signed,
                aligned,
            ]
        )
        run_command([*signer, "verify", "--verbose", signed])
        # A content-specific artifact preserves previous builds for review/reinstallation.
        digest = hashlib.sha256(signed.read_bytes()).hexdigest()[:16]
        output = cache / f"TV-Payload-{digest}.apk"
        shutil.copyfile(signed, output)
    return output
