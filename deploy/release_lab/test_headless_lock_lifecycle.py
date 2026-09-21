"""POSIX-only lock lifecycle checks using isolated temporary paths.

These tests exercise the no-clobber/inode-fenced protocol without invoking the
headless installer, touching system state, or using the production lock path.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest


LOCK_SCRIPT = r'''#!/usr/bin/env bash
set -eu
lock=$1
mode=$2
if [[ -L "$lock" || -d "$lock" || -e "$lock" ]]; then exit 4; fi
set -o noclobber
if ! exec 9>"$lock"; then set +o noclobber; exit 4; fi
set +o noclobber
LOCK_CREATED=1
LOCK_IDENTITY="$(stat -c '%d:%i' -- "$lock")"
flock -n 9
trap 'if [[ "$LOCK_CREATED" -eq 1 && -e "$lock" && ! -L "$lock" && "$(stat -c "%d:%i" -- "$lock")" == "$LOCK_IDENTITY" ]]; then rm -f -- "$lock"; fi' EXIT
if [[ "$mode" == hold ]]; then sleep 0.5; fi
'''


@pytest.mark.skipif(os.name == "nt" or shutil.which("bash") is None or shutil.which("flock") is None,
                    reason="POSIX bash/flock is required for the isolated lock lifecycle test")
def test_noclobber_flock_and_inode_cleanup_are_concurrent_safe(tmp_path: Path) -> None:
    script = tmp_path / "lock-probe.sh"
    script.write_text(LOCK_SCRIPT, encoding="utf-8")
    script.chmod(0o700)
    lock = tmp_path / "update.lock"

    lock.write_text("foreign-owner\n", encoding="utf-8")
    stale = subprocess.run([str(script), str(lock), "once"], check=False)
    assert stale.returncode == 4
    assert lock.read_text(encoding="utf-8") == "foreign-owner\n"
    lock.unlink()

    owner = subprocess.Popen([str(script), str(lock), "hold"])
    try:
        deadline = time.monotonic() + 2
        while not lock.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert lock.exists()
        contender = subprocess.run([str(script), str(lock), "once"], check=False)
        assert contender.returncode == 4
        assert lock.exists()
    finally:
        assert owner.wait(timeout=3) == 0
    assert not lock.exists()
