"""Verify real logger stdout separately from Qt's message handler."""
import pathlib
import subprocess
import sys
import tempfile

with tempfile.TemporaryDirectory(prefix="amnezia-log-unit-") as directory:
    log = pathlib.Path(directory) / "qtest.txt"
    result = subprocess.run([sys.argv[1], "emptyPathNeverOpensAndBacksOff",
                             "-o", str(log) + ",txt"], capture_output=True, text=True)
    if result.returncode:
        print(log.read_text() if log.exists() else result.stderr)
        raise SystemExit(result.returncode)
    output = result.stdout + result.stderr
    assert output.count("path_not_ready") == 1, output
    assert "No file name specified" not in output, output
    print("12 empty-path attempts: one state warning, zero QFile empty opens")
