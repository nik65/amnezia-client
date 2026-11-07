"""Actual inert N --validate-package against U's real produced archive/receipt.

Only fixed validated archive member names are copied as data into a fresh owned
fixture. No tar extraction API, packaged program, host probe or installer runs.
"""
import argparse
from datetime import datetime, timezone
import hashlib, json, os
from pathlib import Path
import subprocess, tarfile

p = argparse.ArgumentParser()
p.add_argument('--binary', type=Path, required=True)
p.add_argument('--source', type=Path, required=True)
p.add_argument('--variant', choices=['legacy', 'new'], required=True)
p.add_argument('--out', type=Path, required=True)
p.add_argument('--fail-work', action='store_true')
a = p.parse_args()
assert os.geteuid() != 0
a.out.mkdir(mode=0o700, parents=True, exist_ok=False)
package = a.out / 'package'; package.mkdir(mode=0o700)
sha = lambda f: hashlib.sha256(f.read_bytes()).hexdigest()
archive = a.source / ('bundle-' + a.variant) / 'provisioning.tar.gz'
key = a.source / ('bundle-' + a.variant) / 'update-public-key.pem'
receipt = a.source / ('receipt-' + a.variant + '.json')
identity = json.loads(receipt.read_text())
assert sha(archive) == identity['archiveSha256'] and sha(key) == identity['publicKeySha256']
pins = {str(f): sha(f) for f in [a.binary, archive, key, receipt, Path(__file__).resolve()]}
record = dict(startedUtc=datetime.now(timezone.utc).isoformat(), inputs=pins, variant=a.variant, componentPass=False,
    allFunctionsPass=False, releasePass=False, published=False, scope='Actual N inert main metadata-validation mode; own nonroot regular-file archive data. No stage-root/privilege/rootFS/host probe/process/network/installer/product execution.')
code = 1
try:
    expected = {'headless-package/' + name for name in identity['packageFiles']}
    with tarfile.open(archive, 'r:gz') as tar:
        members = [m for m in tar.getmembers() if m.name not in ['headless-package', 'headless-package/']]
        assert len(members) == len(expected) and {m.name for m in members} == expected
        for m in members:
            assert m.isreg() and 0 < m.size <= 8 * 1024 * 1024
            name = m.name.split('/'); assert len(name) == 2 and name[0] == 'headless-package' and name[1] not in ['', '.', '..']
            data = tar.extractfile(m).read(8 * 1024 * 1024 + 1); assert len(data) == m.size
            f = package / name[1]; f.write_bytes(data); f.chmod(m.mode)
    argv = [str(a.binary), '--validate-package', '--package-root', str(package), '--public-key', str(key), '--receipt', str(receipt),
        '--ubuntu-id', 'ubuntu', '--ubuntu-version-id', '24.04', '--ubuntu-codename', 'noble',
        '--expected-public-key-sha256', identity['publicKeySha256'], '--expected-package-manifest-sha256', identity['packageManifestSha256'],
        '--expected-checksums-sha256', identity['checksumsSha256'], '--expected-signed-manifest-sha256', identity['manifestSha256'], '--receipt-out', str(a.out / 'metadata-receipt.json')]
    private = a.out / 'private-tmp'; private.mkdir(mode=0o700)
    env = dict(PATH='/usr/bin:/bin', LC_ALL='C', LANG='C', HOME=str(private), TMPDIR=str(private))
    proc = subprocess.run(argv, env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=15)
    (a.out / 'subject.stdout').write_bytes(proc.stdout); (a.out / 'subject.stderr').write_bytes(proc.stderr)
    record.update(argv=argv, actualNativeExit=proc.returncode)
    if proc.returncode != 0: raise RuntimeError('actual metadata consumer refuses the required produced package')
    output = json.loads((a.out / 'metadata-receipt.json').read_text())
    assert output['structuralValidated'] is True and output['hostProbesExecuted'] is False and output['releaseAccepted'] is False
    assert output['packageFiles'] == identity['packageFiles']
    code = 0
    if a.fail_work:
        failed = subprocess.run(['/usr/bin/python3', '-I', '-B', '-c', 'raise SystemExit(23)'], stdin=subprocess.DEVNULL, capture_output=True, timeout=5)
        assert failed.returncode == 23
        record['failedWorkNativeExit'] = failed.returncode; code = failed.returncode
    record['componentPass'] = code == 0
except Exception as error: record.update(exceptionType=type(error).__name__, exception=str(error))
finally:
    record['inputsUnchanged'] = all(sha(Path(path)) == digest for path, digest in pins.items())
    if not record['inputsUnchanged']: code = 1; record['componentPass'] = False
    record.update(nativeExit=code, finishedUtc=datetime.now(timezone.utc).isoformat())
    with (a.out / 'RESULT.json').open('x') as f: f.write(json.dumps(record, indent=2) + '\n')
print(json.dumps(dict(nativeExit=code, actualNativeExit=record.get('actualNativeExit'), componentPass=record['componentPass'], result=str(a.out / 'RESULT.json'))))
raise SystemExit(code)
