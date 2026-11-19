"""Shared rotating JSON logs with session IDs, exception traces and secret filtering."""

import datetime
import logging
import os
import re
import sys
import threading
import uuid
from logging.handlers import RotatingFileHandler
from pathlib import Path

_handler = None
_secrets = frozenset()
_lock = threading.RLock()
_previous_thread_hook = None


def register_secrets(values):
    global _secrets
    with _lock:
        _secrets = _secrets.union(value for value in values if isinstance(value, str) and value)


def redact(text):
    # Immutable snapshot avoids acquiring the configuration lock inside a handler.
    for value in sorted(_secrets, key=len, reverse=True):
        text = text.replace(value, "[redacted]")
    text = re.sub(
        r"""(?i)((?:password|token|client_key|secret|authorization)["'\s]*[:=]\s*)(["'])(.*?)\2""",
        r'\1"[redacted]"',
        text,
    )
    text = re.sub(
        r"(?i)((?:password|token|client_key|secret|authorization)[\"\s]*[:=]\s*)[^\s,;]+",
        r"\1[redacted]",
        text,
    )
    return re.sub(r"(https?://)[^/\s:@]+:[^/\s@]+@", r"\1[redacted]@", text)


class JsonFormatter(logging.Formatter):
    def __init__(self, session):
        super().__init__()
        self.session = session

    def format(self, record):
        import json

        entry = {
            "time": datetime.datetime.fromtimestamp(
                record.created, datetime.timezone.utc
            ).isoformat(),
            "session": self.session,
            "pid": record.process,
            "level": record.levelname,
            "module": record.name,
            "message": redact(record.getMessage()),
        }
        if record.exc_info:
            entry["exception"] = redact(self.formatException(record.exc_info))
        return json.dumps(entry, ensure_ascii=True)


def configure_logging(root):
    global _handler, _previous_thread_hook
    with _lock:
        if _handler is not None:
            return Path(_handler.baseFilename)
        preferred = Path(os.environ.get("POLTERHEIST_LOG_DIR", Path(root) / "reports/logs"))
        fallback = Path.home() / ".local/state/polterheist/logs"
        for folder in dict.fromkeys((preferred, fallback)):
            try:
                folder.mkdir(parents=True, exist_ok=True)
                # Separate processes cannot race while rotating the same file.
                path = folder / f"polterheist-{os.getpid()}.jsonl"
                handler = RotatingFileHandler(
                    path, maxBytes=5_000_000, backupCount=3, encoding="utf-8"
                )
                if os.name != "nt":
                    path.chmod(0o600)
                handler.setFormatter(JsonFormatter(uuid.uuid4().hex))
                # Limit previous process logs too, not just rotation of this process.
                previous = sorted(
                    folder.glob("polterheist-*.jsonl*"),
                    key=lambda p: p.stat().st_mtime,
                    reverse=True,
                )
                for old in previous[20:]:
                    if old != path:
                        try:
                            old.unlink()
                        except OSError:
                            pass
                _handler = handler
                if _previous_thread_hook is None:
                    _previous_thread_hook = threading.excepthook
                    threading.excepthook = log_thread_error
                logger = logging.getLogger()
                logger.addHandler(handler)
                logger.setLevel(logging.INFO)
                for name in ("polterheist", "tv_control"):
                    logging.getLogger(name).setLevel(logging.DEBUG)
                logging.getLogger("polterheist").info(
                    "Logging started; Python %s; platform %s", sys.version.split()[0], sys.platform
                )
                return path
            except OSError:
                continue
        print(
            "[!] Unable to create persistent logs in the project or user directory.",
            file=sys.stderr,
        )
        return None


def close_logging():
    global _handler, _previous_thread_hook
    with _lock:
        if _handler:
            logging.getLogger().removeHandler(_handler)
            _handler.close()
            _handler = None
        if _previous_thread_hook is not None:
            threading.excepthook = _previous_thread_hook
            _previous_thread_hook = None


def log_thread_error(args):
    logging.getLogger("polterheist.thread").error(
        "Unhandled worker error: %s",
        args.thread.name if args.thread else "unknown",
        exc_info=(args.exc_type, args.exc_value, args.exc_traceback),
    )
    if _previous_thread_hook:
        _previous_thread_hook(args)
