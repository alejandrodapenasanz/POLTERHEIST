"""Generate offline image/video viewers and platform-specific application packages."""

import base64
import json
import uuid
import zipfile
from pathlib import Path

from . import payload_schedule
from .payload_content import content_info, prepare_content


def prepare(root, source, schedule=None):
    folder = Path(root).resolve() / ".cache/tv_control/payloads" / uuid.uuid4().hex
    folder.mkdir(parents=True)
    content = prepare_content(root, source, folder)
    payload_schedule.save(folder, schedule)
    write_html(folder, embedded=(folder / content["file"]).stat().st_size <= 16 * 1024 * 1024)
    return folder


def write_html(folder, receipt_url="", embedded=True, output_folder=None):
    content = content_info(folder)
    schedule = payload_schedule.load(folder)
    source = folder / content["file"]
    if embedded and source.stat().st_size > 16 * 1024 * 1024:
        raise ValueError("Browser payload exceeds 16 MiB; a native TV package is required")
    data = base64.b64encode(source.read_bytes()).decode("ascii") if embedded else ""
    video = content["kind"] == "video"
    if video:
        element = '<video id="picture" autoplay loop muted playsinline preload="auto"></video>'
        if schedule:
            element = '<video id="picture" muted playsinline preload="auto" style="visibility:hidden"></video>'
        if embedded:
            initialize = (
                """var raw=atob("""
                + json.dumps(data)
                + """);var bytes=new Uint8Array(raw.length);
for(var i=0;i<raw.length;i++){bytes[i]=raw.charCodeAt(i);}
window.payloadBlob=new Blob([bytes],{type:'video/mp4'});
p.src=URL.createObjectURL(window.payloadBlob);"""
            )
        else:
            initialize = 'p.src="video.mp4";'
        initialize += (
            "p.onplaying=ready;var play=p.play();if(play&&play.catch)play.catch(function(){});"
        )
        check = "p.readyState<2||p.paused"
        if schedule:
            initialize = (
                initialize.split("p.onplaying=ready;")[0] + "p.onloadeddata=ready;p.load();"
            )
            check = "p.readyState<2"
    else:
        element = (
            '<img id="picture" alt="TV Payload" src="'
            + ("data:image/jpeg;base64," + data if embedded else "image.jpg")
            + '">'
        )
        initialize = "p.onload=ready;if(p.complete)ready();"
        check = "!p.naturalWidth"
        if schedule:
            element = element.replace("<img ", '<img style="visibility:hidden" ')
    # No fonts, scripts or image assets are fetched from third parties. ES5 supports older TVs.
    html = (
        """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>TV Payload</title>
<style>html,body{margin:0;width:100%;height:100%;overflow:hidden;background:#000}
img,video{position:absolute;top:0;bottom:0;left:0;right:0;margin:auto;max-width:100%;max-height:100%}</style>
</head><body>"""
        + element
        + """
<script>(function(){var p=document.getElementById('picture'),sent=false;
function ready(){if(sent||"""
        + check
        + """)return;sent=true;"""
        + (
            "installSchedule(p," + json.dumps(schedule) + "," + str(video).lower() + ");"
            if schedule
            else ""
        )
        + """
setTimeout(function(){var receipt="""
        + json.dumps(receipt_url)
        + """;
if(receipt){window.payloadReceipt=new Image();window.payloadReceipt.src=receipt;}},100);}
"""
        + (payload_schedule.JAVASCRIPT if schedule else "")
        + initialize
        + """})();</script></body></html>"""
    )
    path = (output_folder or folder) / "index.html"
    path.write_text(html, encoding="utf-8")
    return path


def native_sources(folder, platform):
    """Build reviewable webOS/Tizen/Roku source archives; signing/deployment is separate."""
    destination = folder / platform
    destination.mkdir(exist_ok=True)
    content = content_info(folder)
    if platform in ("webos", "tizen"):
        write_html(folder, embedded=False, output_folder=destination)
        (destination / content["file"]).write_bytes((folder / content["file"]).read_bytes())
        from PIL import Image

        if content["kind"] == "image":
            with Image.open(folder / "image.jpg") as image:
                image.resize((80, 80)).save(destination / "icon.png")
        else:
            Image.new("RGB", (80, 80), "#ffb44b").save(destination / "icon.png")
        if platform == "webos":
            info = {
                "id": "org.polterheist.tvpayload",
                "version": "1.0.0",
                "vendor": "POLTERHEIST",
                "type": "web",
                "main": "index.html",
                "title": "TV Payload",
                "icon": "icon.png",
            }
            (destination / "appinfo.json").write_text(json.dumps(info), encoding="utf-8")
        else:
            (destination / "config.xml").write_text(
                """<?xml version="1.0" encoding="UTF-8"?>
<widget xmlns="http://www.w3.org/ns/widgets" xmlns:tizen="http://tizen.org/ns/widgets"
id="https://polterheist.local/tvpayload" version="1.0.0" viewmodes="maximized">
<tizen:application id="PolterTV01.Payload" package="PolterTV01" required_version="2.3"/>
<content src="index.html"/><name>TV Payload</name><icon src="icon.png"/>
<tizen:profile name="tv-samsung"/><tizen:setting screen-orientation="landscape"/>
</widget>""",
                encoding="utf-8",
            )
    elif platform == "roku":
        (destination / "source").mkdir(exist_ok=True)
        (destination / "components").mkdir(exist_ok=True)
        (destination / content["file"]).write_bytes((folder / content["file"]).read_bytes())
        (destination / "manifest").write_text(
            "title=TV Payload\nmajor_version=1\nminor_version=0\nbuild_version=0\nui_resolutions=hd\n",
            encoding="utf-8",
        )
        (destination / "source/main.brs").write_text(
            """sub Main()
    screen = CreateObject("roSGScreen")
    port = CreateObject("roMessagePort")
    screen.SetMessagePort(port)
    screen.CreateScene("PayloadScene")
    screen.Show()
    while true
        message = wait(0, port)
        if type(message) = "roSGScreenEvent" and message.IsScreenClosed() then return
    end while
end sub
""",
            encoding="utf-8",
        )
        (destination / "components/PayloadScene.xml").write_text(
            """<?xml version="1.0" encoding="utf-8"?>
<component name="PayloadScene" extends="Scene"><children>
<Rectangle width="1280" height="720" color="0x000000FF"/>
<Poster width="1280" height="720" loadDisplayMode="scaleToFit" uri="pkg:/image.jpg"/>
</children></component>""",
            encoding="utf-8",
        )
        if content["kind"] == "video":
            (destination / "components/PayloadScene.xml").write_text(
                """<?xml version="1.0" encoding="utf-8"?>
<component name="PayloadScene" extends="Scene"><script type="text/brightscript"><![CDATA[
sub init()
    m.player=m.top.findNode("player")
    content=CreateObject("roSGNode","ContentNode")
    content.url="pkg:/video.mp4"
    content.streamFormat="mp4"
    m.player.content=content
    m.player.observeField("state","changed")
    m.player.control="play"
end sub
sub changed()
    if m.player.state="finished" then m.player.control="play"
end sub
]]></script><children><Video id="player" width="1280" height="720"/></children></component>""",
                encoding="utf-8",
            )
    else:
        raise ValueError("Unknown native package platform")
    schedule = payload_schedule.load(folder)
    if platform == "roku" and schedule:
        (destination / "components/PayloadScene.xml").write_text(
            payload_schedule.roku_scene(schedule, content["kind"] == "video"), encoding="utf-8"
        )
    archive = folder / ("TV-Payload-" + platform + ".zip")
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as output:
        for path in sorted(destination.rglob("*")):
            if path.is_file():
                output.write(path, path.relative_to(destination).as_posix())
    return archive
