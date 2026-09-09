from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parent


def test_linux_gui_session_helper_selects_active_lab_x11(tmp_path: Path) -> None:
    bash = shutil.which("bash")
    if bash is None or os.name == "nt":
        return
    source = (ROOT / "guest_runners" / "linux-release-lab.sh").read_text(encoding="utf-8")
    match = re.search(r"  gui_session_proof\(\) \{\n(.*?)\n  \}\n  gui_session_json=", source, re.DOTALL)
    assert match, "GUI session helper was not found"
    helper = "gui_session_proof() {\n" + match.group(1) + "\n}\n"
    fake_loginctl = tmp_path / "loginctl"
    fake_loginctl.write_text(
        """#!/bin/sh
if [ "$1" = list-sessions ]; then
  printf '%s\n' '1 998 gdm seat0 -' '2 1001 lab seat0 -' '3 1002 other seat0 -' '4 1001 lab seat0 -'
  exit 0
fi
if [ "$1" = show-user ]; then
  printf '1001\n'; exit 0
fi
session=$2
property=$4
case "$session:$property" in
  2:Type) printf 'x11\n' ;; 2:Active) printf 'yes\n' ;; 2:State) printf 'active\n' ;; 2:Class) printf 'user\n' ;;
  4:Type) printf 'x11\n' ;; 4:Active) printf 'no\n' ;; 4:State) printf 'closing\n' ;; 4:Class) printf 'user\n' ;;
  *) exit 1 ;;
esac
""",
        encoding="utf-8",
    )
    fake_loginctl.chmod(0o755)
    env = dict(os.environ)
    env["PATH"] = str(tmp_path) + os.pathsep + env.get("PATH", "")
    result = subprocess.run(
        [bash, "-c", helper + "gui_session_proof"],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    assert result.returncode == 0, result.stderr
    assert '"session":"2"' in result.stdout
    assert '"uid":"1001"' in result.stdout
    assert '"user":"lab"' in result.stdout
