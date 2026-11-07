"""Regression: reject nonregular input before a blocking FIFO open.

Run only the new verify-only producer, never a packaged installer or daemon.
Every attempt remains below the supplied build-test evidence directory.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

binary = Path(sys.argv[1])
root = Path(sys.argv[2])
root.mkdir(parents=True, exist_ok=True)
work = Path(tempfile.mkdtemp(prefix='file-types-', dir=root))
(work / 'tmp').mkdir(mode=0o700)
inputs = {'--manifest': work / 'manifest.json', '--public-key': work / 'public.pem',
          '--provisioning': work / 'archive.tar.gz'}
for path in inputs.values():
    path.write_bytes(b'explicit inert invalid-data fixture')
rows = []
for option in inputs:
    fifo = work / (option.removeprefix('--') + '.fifo')
    os.mkfifo(fifo, 0o600)
    current = dict(inputs)
    current[option] = fifo
    receipt = work / (option.removeprefix('--') + '.receipt.json')
    argv = [str(binary), '--expected-public-key-sha256', '0' * 64, '--receipt-out', str(receipt)]
    for key, path in current.items():
        argv.extend([key, str(path)])
    proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env={'PATH': '/usr/bin:/bin', 'TMPDIR': str(work / 'tmp'), 'LANG': 'C', 'LC_ALL': 'C'})
    timed_out = False
    try:
        stdout, stderr = proc.communicate(timeout=2)
    except subprocess.TimeoutExpired:
        timed_out = True
        proc.kill()
        stdout, stderr = proc.communicate(timeout=2)
    (work / (option.removeprefix('--') + '.stdout')).write_bytes(stdout)
    (work / (option.removeprefix('--') + '.stderr')).write_bytes(stderr)
    rows.append({'option': option, 'argv': argv, 'native_exit': proc.returncode, 'timed_out': timed_out,
                 'passed': not timed_out and proc.returncode == 1 and not receipt.exists()})
passed = all(x['passed'] for x in rows)
result = {'native_exit': 0 if passed else 1, 'cases': rows,
          'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
          'scope': 'owned FIFO data only; verify-only executable, no installer/product/service execution'}
(work / 'RESULT.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps({'passed': passed, 'count': len(rows), 'evidence': str(work / 'RESULT.json')}))
raise SystemExit(result['native_exit'])
