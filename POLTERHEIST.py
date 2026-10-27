#!/usr/bin/env python3
"""Entrada compatible: toda la aplicacion esta en script.py."""

import sys

from script import main

if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.exit(main())
