"""Pure fixture interop: execute extracted Python validators, never the installer."""
from pathlib import Path
import json
import re
import subprocess
import sys

journal, backup, installer = sys.argv[1:]
source = Path(installer).read_text()
backup_block = source.split('python3 - "$TRANSACTION_JOURNAL" "$backup_dir"', 1)[1].split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
read_block = source.split('read_transaction_journal() {', 1)[1].split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
# Only the fixture policy's root differs from the production path allowlist.
read_block = read_block.replace('r"/var/lib/amnezia/', 'r"' + re.escape(str(Path(journal).parent)) + '/')
for block, args in ((read_block, [journal]), (backup_block, [journal, backup])):
    result = subprocess.run([sys.executable, "-c", block, *args], capture_output=True)
    if result.returncode:
        raise SystemExit("Python reference rejected native fixture: " + result.stderr.decode())
writer = source.split('write_transaction_journal() {', 1)[1].split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
state = json.loads(Path(journal).read_text())
arguments = [journal] + [state[k] for k in ("phase", "mode", "backupDir", "serviceTarget", "serviceEnabled", "serviceActive")]
arguments += ["true" if state[k] else "false" for k in ("groupPresent", "groupCreated")]
result = subprocess.run([sys.executable, "-c", writer, *arguments], capture_output=True)
if result.returncode:
    raise SystemExit("Python reference writer failed on fixture")
# Prove reference rejects changed bytes too; restore before native revalidation.
path = Path(backup) / "amneziad"
original = path.read_bytes()
try:
    path.write_bytes(b"tampered")
    rejected = subprocess.run([sys.executable, "-c", backup_block, journal, backup], capture_output=True)
    if rejected.returncode == 0:
        raise SystemExit("Python reference accepted tampered backup")
finally:
    path.write_bytes(original)
# Exercise the actual shell dispatch functions without running the installer.
# A native failure must return directly, never execute the reference fallback.
root = Path(journal).parent
stub = root / "owned-failing-helper"
stub.write_text("#!/bin/sh\nexit 7\n")
stub.chmod(0o700)
marker = root / "python-fallback-ran"
functions = "\n".join(name + "() {" + source.split(name + "() {", 1)[1].split(next_name + "() {", 1)[0]
                       for name, next_name in (("write_transaction_journal", "restore_transaction_file"),
                                               ("read_transaction_journal", "recover_transaction"),
                                               ("verify_recovery_backup", "verify_active_health")))
helper_wrapper = "run_native_helper() {" + source.split("run_native_helper() {", 1)[1].split("\n}", 1)[0] + "\n}\n"
script = helper_wrapper + functions + '''
NATIVE_HELPER="$1"
NATIVE_HELPER_ARGS=(--provisioning-fs)
TRANSACTION_JOURNAL="$2"
FALLBACK_MARKER="$3"
python3() { touch "$FALLBACK_MARKER"; return 99; }
write_transaction_journal prepared
test "$?" -eq 7 || exit 1
read_transaction_journal
test "$?" -eq 7 || exit 1
if test "$(id -u)" -eq 0; then
    verify_recovery_backup "$4"
    test "$?" -eq 7 || exit 1
fi
'''
result = subprocess.run(["bash", "-c", script, "fixture", str(stub), journal, str(marker), backup], capture_output=True)
if result.returncode or marker.exists():
    raise SystemExit("authenticated native failure fell through to Python")
