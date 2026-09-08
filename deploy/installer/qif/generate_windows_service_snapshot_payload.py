#!/usr/bin/env python3
"""Embed the readable Windows service snapshot helper into controlscript.js."""

from __future__ import annotations

import base64
import gzip
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "windows_service_snapshot.cs"
CONTROL = ROOT / "controlscript.js"
MARKER = re.compile(rb'(?m)^    var sourceGzipBase64 = "[^"]*";$')


def payload() -> str:
    return base64.b64encode(gzip.compress(SOURCE.read_bytes(), mtime=0)).decode("ascii")


def main() -> None:
    control = CONTROL.read_bytes()
    replacement = ('    var sourceGzipBase64 = "' + payload() + '";').encode("ascii")
    updated, count = MARKER.subn(replacement, control)
    if count != 1:
        raise SystemExit(f"expected one embedded payload marker, found {count}")
    CONTROL.write_bytes(updated)


if __name__ == "__main__":
    main()
