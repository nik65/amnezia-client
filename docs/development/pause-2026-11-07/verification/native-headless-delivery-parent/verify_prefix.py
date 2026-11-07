"""Execute only the actual extracted verifier prefix, before installer main.

Root install semantics are an explicit UID1000 metadata model. Compiled artifact
is input data only; reaching a post-gate sentinel never executes the verifier.
"""
import argparse
from datetime import datetime, timezone
import hashlib, json, os
from pathlib import Path
import re, shutil, subprocess, sys

p = argparse.ArgumentParser()
p.add_argument('--subject', type=Path, required=True)
p.add_argument('--artifact', type=Path, required=True)
p.add_argument('--expected-artifact-sha256', required=True)
p.add_argument('--out', type=Path, required=True)
p.add_argument('--suite', choices=['exit-status', 'static-format', 'all'], default='all')
p.add_argument('--fail-work', action='store_true')
a = p.parse_args()
assert os.geteuid() != 0
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(a.artifact) == a.expected_artifact_sha256
assert 0 < a.artifact.stat().st_size <= 8 * 1024 * 1024
a.out.mkdir(mode=0o700, parents=True, exist_ok=False)
bin_dir = a.out / 'bin'; bin_dir.mkdir(mode=0o700)
fixture = Path(__file__).resolve().with_name('dynamic_fixture.c')
pins = {str(f): sha(f) for f in [a.subject, a.artifact, Path(__file__).resolve(), fixture]}
s = a.subject.read_text()
function = re.search(r'(bootstrap_stage_helper\(\) \{.*?\n\})\n', s, re.S).group(1)
start = s.index('if [[ -e "$SOURCE_PACKAGE_ROOT/$NATIVE_VERIFIER_NAME"')
end = s.index('\nif ! python3 ', start)
block = s[start:end]
# No installer statement, pretransaction trap, packaged invocation, Python
# fallback or recovery entry is evaluated by this extracted test.
driver = 'set -euo pipefail\ndeclare -A BOOTSTRAP_HELPERS=()\nNATIVE_VERIFIER_NAME="amnezia-verify-provisioning-native"\nBOOTSTRAP_VERIFIER=""\n' + function + '\n' + block + '\nprintf "NEXT_BOUNDARY:%s\\n" "$BOOTSTRAP_VERIFIER"\n'
(a.out / 'extracted-prefix.sh').write_text(driver)
stub = r'''#!/usr/bin/python3
import os,shutil,subprocess,sys
from pathlib import Path
root=Path(os.environ['PREFIX_CASE']).resolve()
def own(value):
 p=Path(value).resolve()
 if not p.is_relative_to(root):raise SystemExit('owned fixture path escape')
 return p
name=Path(sys.argv[0]).name
args=sys.argv[1:]
if name=='install':
 if args[0]=='-d':own(args[-1]).mkdir(mode=0o700,parents=True,exist_ok=True)
 else:
  source,target=own(args[-2]),own(args[-1]);shutil.copyfile(source,target)
  os.chmod(target,0o600 if '0600' in args else 0o755)
 raise SystemExit(0)
if name=='readelf':
 own(args[-1])
 if os.environ['PREFIX_MODE']=='program-table-failure' and '-l' in args:raise SystemExit(23)
 command=['/usr/bin/readelf',*args]
else:raise SystemExit('unknown modeled boundary')
r=subprocess.run(command,stdin=subprocess.DEVNULL,capture_output=True,timeout=5)
sys.stdout.buffer.write(r.stdout);sys.stderr.buffer.write(r.stderr);raise SystemExit(r.returncode)
'''
(bin_dir / 'stub.py').write_text(stub); (bin_dir / 'stub.py').chmod(0o700)
for name in ['install', 'readelf']: (bin_dir / name).symlink_to(bin_dir / 'stub.py')
for name in ['awk', 'sha256sum', 'grep', 'chmod']: (bin_dir / name).symlink_to('/usr/bin/' + name)
modes = ['good']
if a.suite in ['exit-status', 'all']: modes += ['bad-pin', 'malformed-header', 'program-table-failure']
if a.suite in ['static-format', 'all']: modes += ['dynamic-object']
record = dict(startedUtc=datetime.now(timezone.utc).isoformat(), subjectSha256=pins[str(a.subject)], inputs=pins, cases=[], componentPass=False,
    allFunctionsPass=False, releasePass=False, published=False,
    scope='Actual extracted helper function + U verifier gate only; UID1000 real private files and inert root-install metadata. readelf reads owned artifact data. No installer main, packaged ELF, root/guest/service/SSH/ADB/socket/network/VPN execution.')
code = 1
try:
    if 'dynamic-object' in modes:
        proc = subprocess.run(['/usr/bin/cc', '-shared', '-fPIC', str(fixture), '-o', str(a.out / 'dynamic.so')], stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
        (a.out / 'compile-dynamic.stderr').write_bytes(proc.stderr)
        assert proc.returncode == 0
    for mode in modes:
        case = a.out / mode; case.mkdir(mode=0o700)
        source, private = case / 'source', case / 'private'
        source.mkdir(mode=0o700); private.mkdir(mode=0o700)
        data = (a.out / 'dynamic.so').read_bytes() if mode == 'dynamic-object' else a.artifact.read_bytes()
        if mode == 'malformed-header': data = b'not an ELF; inert data only\n'
        target = source / 'amnezia-verify-provisioning-native'; target.write_bytes(data)
        digest = hashlib.sha256(data).hexdigest()
        sums = (digest + '  amnezia-verify-provisioning-native\n').encode()
        (source / 'SHA256SUMS').write_bytes(sums)
        pin = hashlib.sha256(sums).hexdigest() if mode != 'bad-pin' else '0' * 64
        env = dict(PATH=str(bin_dir), LC_ALL='C', LANG='C', HOME=str(private), TMPDIR=str(private), PREFIX_CASE=str(case), PREFIX_MODE=mode,
            SOURCE_PACKAGE_ROOT=str(source), PRIVATE_INPUTS_ROOT=str(private), BOOTSTRAP_HELPER_DIR=str(private / 'bootstrap-helper'), EXPECTED_CHECKSUMS_SHA256=pin)
        proc = subprocess.run(['/bin/bash', '--noprofile', '--norc', '-c', driver], env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=15)
        (case / 'stdout').write_bytes(proc.stdout); (case / 'stderr').write_bytes(proc.stderr)
        reached = b'NEXT_BOUNDARY:' in proc.stdout
        passed = (proc.returncode == 0 and reached) if mode == 'good' else (proc.returncode != 0 and not reached)
        item = dict(case=mode, nativeExit=proc.returncode, nextBoundaryReached=reached, passed=passed)
        record['cases'].append(item); print(json.dumps(item), flush=True)
    code = 0 if all(row['passed'] for row in record['cases']) else 1
    if a.fail_work and code == 0:
        failed = subprocess.run([sys.executable, '-I', '-B', '-c', 'raise SystemExit(23)'], stdin=subprocess.DEVNULL, capture_output=True, timeout=5)
        record['failedWorkNativeExit'] = failed.returncode
        assert failed.returncode == 23
        code = failed.returncode
    record['componentPass'] = code == 0
except Exception as error: record.update(exceptionType=type(error).__name__, exception=str(error))
finally:
    record['inputsUnchanged'] = all(sha(Path(path)) == digest for path, digest in pins.items())
    if not record['inputsUnchanged']: record['componentPass'] = False; code = 1
    record.update(nativeExit=code, finishedUtc=datetime.now(timezone.utc).isoformat())
    with (a.out / 'RESULT.json').open('x') as f: f.write(json.dumps(record, indent=2) + '\n')
print(json.dumps(dict(nativeExit=code, componentPass=record['componentPass'], result=str(a.out / 'RESULT.json'))))
raise SystemExit(code)
