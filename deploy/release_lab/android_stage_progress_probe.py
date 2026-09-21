"""Read-only progress probe for the active bounded nested Android stage."""
import json, sys
from pathlib import Path

sys.path.insert(0, "/mnt/c/Users/ivano/PycharmProjects/amnezia-client")
from deploy.release_lab.lab import QgaClient

run = "androidnested0913u"
receipts = Path("/var/lib/amnezia-release-lab/receipts") / run
attempts = sorted((p for p in receipts.iterdir() if p.is_dir()), key=lambda p: p.stat().st_mtime)
if not attempts:
    raise SystemExit("no active receipt directory")
nonce = attempts[-1].name
socket_path = Path("/var/lib/amnezia-release-lab/runs") / run / "linux-headless-x64/qga.sock"
qga = QgaClient(socket_path, timeout=10)
root = f"/var/lib/amnezia-release-lab/nested/{run}/{nonce}"
result = qga.guest_exec_wait("/usr/bin/find", [root, "-maxdepth", "3", "-type", "f", "-printf", "%p|%s\n"], timeout=20)
lines = str(result.get("stdout", "")).splitlines()
print(json.dumps({"nonce": nonce, "exitcode": result.get("exitcode"), "files": lines[-30:]}, separators=(",", ":")))
