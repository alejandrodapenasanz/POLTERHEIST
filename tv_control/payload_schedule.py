"""A portable receiver-side schedule: UTC milliseconds and an optional interval."""

import datetime as dt
import json
import math
import re
from pathlib import Path


def create(at=None, every=None, show_seconds=10, *, now=None):
    now = now or dt.datetime.now().astimezone()
    if now.tzinfo is None:
        raise ValueError("Schedule clock must include a timezone")
    if at is not None and not at:
        raise ValueError("Start time is required")
    if not math.isfinite(float(show_seconds)) or not 1 <= float(show_seconds) <= 86400:
        raise ValueError("Image display duration must be between 1 and 86400 seconds")
    interval = 0
    if every is not None:
        minutes = float(every)
        if not math.isfinite(minutes) or not 1 / 60 <= minutes <= 525600:
            raise ValueError("Repeat interval must be between 1 second and one year (in minutes)")
        interval = round(minutes * 60000)
    if not at and not interval:
        return None
    if at:
        if re.fullmatch(r"\d{2}:\d{2}", at):
            hour, minute = map(int, at.split(":"))
            local = now.astimezone()
            start = dt.datetime.combine(local.date(), dt.time(hour, minute)).astimezone()
            if start <= now:
                start = dt.datetime.combine(
                    local.date() + dt.timedelta(days=1), dt.time(hour, minute)
                ).astimezone()
        else:
            try:
                start = dt.datetime.fromisoformat(at).astimezone()
            except ValueError as error:
                raise ValueError(
                    "Start time must be HH:MM or an ISO date/time with optional UTC offset"
                ) from error
            if start <= now:
                raise ValueError("Start date/time must be in the future")
    else:
        start = now + dt.timedelta(milliseconds=interval)
    return {
        "start_at": round(start.timestamp() * 1000),
        "every_ms": interval,
        "image_ms": round(float(show_seconds) * 1000),
    }


def describe(schedule):
    if not schedule:
        return "Immediate continuous playback"
    start = (
        dt.datetime.fromtimestamp(schedule["start_at"] / 1000)
        .astimezone()
        .isoformat(timespec="seconds")
    )
    repeat = (
        f"; every {schedule['every_ms'] / 60000:g} minutes"
        if schedule["every_ms"]
        else "; one start"
    )
    return "Next execution: " + start + repeat


def save(folder, schedule):
    if schedule:
        (Path(folder) / "schedule.json").write_text(json.dumps(schedule), encoding="utf-8")


def load(folder):
    path = Path(folder) / "schedule.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def prompt():
    print(
        "\n  PLAYBACK SCHEDULE\n  [1] Now (continuous)\n  [2] Start at a time\n  [3] Every X minutes\n  [0] Cancel"
    )
    choice = input("  > [1]: ").strip() or "1"
    if choice == "0":
        raise EOFError("Schedule cancelled")
    if choice == "1":
        return None
    if choice not in ("2", "3"):
        raise ValueError("Choose 0, 1, 2 or 3")
    at = input("  Start (HH:MM local time or ISO date/time): ").strip() if choice == "2" else None
    if choice == "2" and not at:
        raise ValueError("Start time is required")
    every = input("  Repeat every how many minutes: ").strip() if choice == "3" else None
    seconds = (
        input("  Seconds per image [10]; videos play once per interval: ").strip() or "10"
        if every
        else 10
    )
    return create(at, every, seconds)


# ES5 for older TV browsers. Loading/receipt is independent of playback time.
# Single-shot schedules play continuously after their start; recurring schedules
# show one image for image_ms, or play a video once, then wait on a black screen.
JAVASCRIPT = r"""
function installSchedule(p, schedule, video) {
    var next=schedule.start_at, active=false, ended=0, fired=false, cancelled=false;
    p.style.visibility='hidden';
    if(video){p.autoplay=false;p.loop=false;p.pause();}
    var status=document.createElement('div');
    status.style.cssText='position:absolute;bottom:16px;left:16px;color:#aaa;font:16px sans-serif';
    document.body.appendChild(status);
    function hide(){active=false;p.style.visibility='hidden';if(video)p.pause();}
    function tick(){
        if(cancelled)return;
        var now=Date.now();
        if(active&&!video&&schedule.every_ms&&now>=ended)hide();
        if(!active&&(!fired||schedule.every_ms)&&now>=next){
            active=true;fired=true;ended=now+schedule.image_ms;p.style.visibility='visible';
            if(schedule.every_ms)next+= (Math.floor((now-next)/schedule.every_ms)+1)*schedule.every_ms;
            if(video){p.currentTime=0;p.loop=!schedule.every_ms;var play=p.play();if(play&&play.catch)play.catch(function(){status.textContent='Press OK to enable playback';});}
        }
        if(active&&schedule.every_ms&&now>=next)next+=(Math.floor((now-next)/schedule.every_ms)+1)*schedule.every_ms;
        if(!active)status.textContent='Next: '+new Date(next).toLocaleString()+' | Back/Escape: cancel';
        else status.textContent='';
    }
    if(video)p.addEventListener('ended',function(){if(schedule.every_ms)hide();});
    var timer=setInterval(tick,250);
    window.cancelPayloadSchedule=function(){cancelled=true;clearInterval(timer);hide();status.textContent='Schedule cancelled';};
    document.addEventListener('keydown',function(e){
        if(e.keyCode===27||e.keyCode===8||e.keyCode===461||e.keyCode===10009){e.preventDefault();window.cancelPayloadSchedule();}
        if(e.keyCode===13&&active&&video)p.play();
    });
    window.addEventListener('pagehide',window.cancelPayloadSchedule);
    tick();
}
"""


def roku_scene(schedule, video):
    """SceneGraph timer stays with the foreground channel; Back closes the channel."""
    initialization = (
        """
    content=CreateObject("roSGNode","ContentNode")
    content.url="pkg:/video.mp4"
    content.streamFormat="mp4"
    m.player.content=content
    m.player.observeField("state","changed")
"""
        if video
        else ""
    )
    return (
        """<?xml version="1.0" encoding="utf-8"?>
<component name="PayloadScene" extends="Scene"><script type="text/brightscript"><![CDATA[
sub init()
    m.player=m.top.findNode("player")
    m.status=m.top.findNode("status")
    m.next=START_TIME
    m.interval=INTERVAL
    m.imageSeconds=IMAGE_SECONDS
    m.active=false
    m.fired=false
    m.video=IS_VIDEO
    INITIALIZATION
    m.clock=m.top.findNode("clock")
    m.clock.observeField("fire","tick")
    m.clock.control="start"
    tick()
end sub
sub hide()
    m.active=false
    m.player.visible=false
end sub
sub changed()
    if m.player.state="finished"
        if m.interval>0 then hide() else m.player.control="play"
    end if
end sub
sub tick()
    date=CreateObject("roDateTime")
    now=date.AsSeconds()
    if m.active and not m.video and m.interval>0 and now>=m.hideAt then hide()
    if not m.active and (not m.fired or m.interval>0) and now>=m.next
        m.active=true
        m.fired=true
        m.hideAt=now+m.imageSeconds
        m.player.visible=true
        if m.interval>0 then m.next=m.next+(Int((now-m.next)/m.interval)+1)*m.interval
        if m.video then m.player.control="play"
    end if
    if m.active and m.interval>0 and now>=m.next then m.next=m.next+(Int((now-m.next)/m.interval)+1)*m.interval
    if m.active
        m.status.text=""
    else
        date.FromSeconds(m.next)
        m.status.text="Next (UTC): "+date.ToISOString()+" | Back: cancel"
    end if
end sub
]]></script><children>
<Rectangle width="1280" height="720" color="0x000000FF"/>
PLAYER
<Label id="status" translation="[16,660]" width="1248"/>
<Timer id="clock" duration="1" repeat="true"/>
</children></component>""".replace("START_TIME", str(schedule["start_at"] // 1000) + "#")
        .replace("INTERVAL", str(schedule["every_ms"] / 1000))
        .replace("IMAGE_SECONDS", str(schedule["image_ms"] / 1000))
        .replace("IS_VIDEO", str(video).lower())
        .replace("INITIALIZATION", initialization)
        .replace(
            "PLAYER",
            '<Video id="player" visible="false" width="1280" height="720"/>'
            if video
            else '<Poster id="player" visible="false" width="1280" height="720" loadDisplayMode="scaleToFit" uri="pkg:/image.jpg"/>',
        )
    )
