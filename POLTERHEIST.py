#!/usr/bin/env python3
"""Launch the application with the Linux environment prepared by setup.sh."""

import os
import sys
from pathlib import Path


def main(argv=None):
    arguments = list(sys.argv[1:] if argv is None else argv)
    if sys.platform.startswith("linux"):
        project = Path(__file__).resolve().parent
        # Keep the same order as setup.sh. Do not resolve bin/python: it may be
        # a symlink to the system interpreter, which would bypass the venv.
        for name in ("venv", ".venv", ".venv-linux", "venv-linux"):
            environment = project / name
            python = environment / "bin/python"
            if not (environment / "pyvenv.cfg").is_file() or not os.access(python, os.X_OK):
                continue
            if Path(sys.prefix).resolve() != environment.resolve():
                try:
                    os.execv(
                        str(python), [str(python), str(project / "POLTERHEIST.py"), *arguments]
                    )
                except OSError as error:
                    print(
                        f"Unable to start {python}: {error}. Rerun bash setup.sh.", file=sys.stderr
                    )
                    return 1
            break

    from script import main as run_application

    return run_application(arguments)


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.exit(main())
