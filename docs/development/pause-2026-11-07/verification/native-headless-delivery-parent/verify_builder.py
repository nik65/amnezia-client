"""Actual package builder under an inert, exact-shaped CMake boundary.

The installer is copied into the archive, never sourced/launched. Daemon/CLI
members are explicitly synthetic TEST data, not application build evidence.
"""
import argparse
from datetime import datetime, timezone
import hashlib, json, os
from pathlib import Path
import shutil, subprocess, tarfile

p = argparse.ArgumentParser()
p.add_argument('--builder', type=Path, required=True)
p.add_argument('--installer', type=Path, required=True)
p.add_argument('--verifier', type=Path, required=True)
p.add_argument('--out', type=Path, required=True)
p.add_argument('--with-role', action='store_true')
p.add_argument('--fail-work', action='store_true')
a = p.parse_args()
assert os.geteuid() != 0
a.out.mkdir(mode=0o700, parents=True, exist_ok=False)
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
pins = {str(f): sha(f) for f in [a.builder, a.installer, a.verifier, Path(__file__).resolve()]}
root = a.out / 'subject'; scripts = root / 'deploy/headless'; scripts.mkdir(mode=0o700, parents=True)
(root / 'headless').mkdir(mode=0o700)
shutil.copyfile(a.builder, scripts / 'build_headless_release.sh'); shutil.copyfile(a.installer, scripts / 'install_headless.sh')
private = a.out / 'private-tmp'; private.mkdir(mode=0o700)
bin_dir = a.out / 'bin'; bin_dir.mkdir(mode=0o700)
cmake = r'''#!/usr/bin/python3
import os,sys
from pathlib import Path
root=Path(os.environ['BUILDER_FIXTURE_ROOT']).resolve();args=sys.argv[1:]
version='1.0.0.42';build=str(root/('build-headless-release-'+version))
with (root/'cmake-calls.log').open('a') as log:log.write(repr(args)+'\n')
if args[:2]==['-S',str(root/'headless')]:
 assert args==['-S',str(root/'headless'),'-B',build,'-DCMAKE_BUILD_TYPE=Release','-DCMAKE_INSTALL_PREFIX=/usr/local','-DBUILD_TESTING=OFF','-DHEADLESS_BUILD_VERSION='+version,'-DAMNEZIA_HEADLESS_EMBED_AWG3=ON','-DAMNEZIA_HEADLESS_AWG3_RESOURCE_DIRECTORY='+str(root/'headless')]
elif args==['--build',build,'--target','amneziad','amnezia-cli','--parallel','2']:pass
elif args==['--install',build,'--prefix','/usr/local','--strip']:
 stage=Path(os.environ['DESTDIR']).resolve();tmp=Path(os.environ['TMPDIR']).resolve();assert stage.is_relative_to(tmp)
 for name in ['amneziad','amnezia-cli']:
  f=stage/'usr/local/bin'/name;f.parent.mkdir(parents=True,exist_ok=True);f.write_bytes(b'TEST-APPLICATION-DATA-ONLY\n');f.chmod(0o755)
 f=stage/'usr/local/lib/systemd/system/amneziad.service';f.parent.mkdir(parents=True,exist_ok=True);f.write_bytes(b'[Unit]\nDescription=TEST DATA ONLY\n');f.chmod(0o644)
else:raise SystemExit('unexpected CMake external-boundary shape')
'''
(bin_dir / 'cmake').write_text(cmake); (bin_dir / 'cmake').chmod(0o700)
env = dict(PATH=str(bin_dir) + ':/usr/bin:/bin', HOME=str(private), TMPDIR=str(private), TMP=str(private), TEMP=str(private), LC_ALL='C', LANG='C',
    BUILDER_FIXTURE_ROOT=str(root), AMNEZIA_HEADLESS_AWG3_RESOURCE_DIRECTORY=str(root / 'headless'), CMAKE_BUILD_PARALLEL_LEVEL='2', SOURCE_DATE_EPOCH='0')
if a.with_role: env['AMNEZIA_HEADLESS_NATIVE_VERIFIER'] = str(a.verifier)
record = dict(startedUtc=datetime.now(timezone.utc).isoformat(), inputs=pins, withRole=a.with_role, componentPass=False,
    allFunctionsPass=False, releasePass=False, published=False, scope='Whole actual package builder; only CMake compilation/install boundary modeled with explicit TEST-data daemon/CLI. Installer/verifier copied as data, never executed. No real product build/root/guest/network/SSH/ADB/service/VPN/publication.')
code = 1
try:
    argv = ['/bin/bash', '--noprofile', '--norc', str(scripts / 'build_headless_release.sh'), '1.0.0.42', str(a.out / 'artifacts')]
    proc = subprocess.run(argv, env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=45)
    (a.out / 'builder.stdout').write_bytes(proc.stdout); (a.out / 'builder.stderr').write_bytes(proc.stderr)
    record.update(argv=argv, builderNativeExit=proc.returncode)
    assert proc.returncode == 0, 'actual builder failed'
    archive = a.out / 'artifacts/AmneziaHeadless_1.0.0.42_linux_x64_provisioning.tar.gz'
    wanted = {'install_headless.sh', 'amneziad', 'amnezia-cli', 'amneziad.service', 'package-manifest.json', 'runtime-dependencies.json', 'runtime-dependencies.txt', 'SHA256SUMS'}
    if a.with_role: wanted.add('amnezia-verify-provisioning-native')
    with tarfile.open(archive, 'r:gz') as tar:
        members = [m for m in tar.getmembers() if m.name not in ['headless-package', 'headless-package/']]
        assert len(members) == len(wanted) and {m.name for m in members} == {'headless-package/' + n for n in wanted}, 'producer omitted or added an unexpected role/member'
        data = {}; modes = {}
        for m in members:
            assert m.isreg() and 0 < m.size <= 8 * 1024 * 1024
            name = m.name.split('/'); assert len(name) == 2
            data[name[1]] = tar.extractfile(m).read(8 * 1024 * 1024 + 1); modes[name[1]] = m.mode
            assert len(data[name[1]]) == m.size
    assert hashlib.sha256(data['install_headless.sh']).hexdigest() == pins[str(a.installer)], 'packaged installer is not the selected prefix source'
    manifest = json.loads(data['package-manifest.json'])
    rows = dict((line[66:], line[:64]) for line in data['SHA256SUMS'].decode().splitlines())
    assert set(rows) == wanted - {'SHA256SUMS'}
    assert all(hashlib.sha256(data[name]).hexdigest() == digest for name, digest in rows.items())
    if a.with_role:
        role = manifest['nativeVerifier']; assert set(role) == {'path','sha256','size'}
        assert role == dict(path='amnezia-verify-provisioning-native',sha256=pins[str(a.verifier)],size=a.verifier.stat().st_size)
        assert modes[role['path']] == 0o755 and rows[role['path']] == role['sha256']
    else: assert 'nativeVerifier' not in manifest
    assert not list(private.iterdir()), 'builder leaked an owned staging directory'
    record['archive'] = dict(path=str(archive), sha256=sha(archive), size=archive.stat().st_size, memberCount=len(members), selectedInstallerSha256=pins[str(a.installer)])
    code = 0
    if a.fail_work:
        failed = subprocess.run(['/usr/bin/python3', '-I', '-B', '-c', 'raise SystemExit(23)'], stdin=subprocess.DEVNULL, capture_output=True, timeout=5)
        assert failed.returncode == 23; record['failedWorkNativeExit'] = failed.returncode; code = failed.returncode
    record['componentPass'] = code == 0
except Exception as error: record.update(exceptionType=type(error).__name__, exception=str(error))
finally:
    record['inputsUnchanged'] = all(sha(Path(path)) == digest for path, digest in pins.items())
    if not record['inputsUnchanged']: code = 1; record['componentPass'] = False
    record.update(nativeExit=code, finishedUtc=datetime.now(timezone.utc).isoformat())
    with (a.out / 'RESULT.json').open('x') as f: f.write(json.dumps(record, indent=2) + '\n')
print(json.dumps(dict(nativeExit=code, componentPass=record['componentPass'], archive=record.get('archive'), error=record.get('exception'))))
raise SystemExit(code)
