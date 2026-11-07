"""Actual N/W entry: signed archive -> receipt -> full stage -> metadata, IO modeled only for uid0 root."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile

p = argparse.ArgumentParser()
p.add_argument('--subject', type=Path, required=True)
p.add_argument('--source-manifest', type=Path)
p.add_argument('--production-dir', type=Path)
p.add_argument('--legacy-matrix', type=Path)
p.add_argument('--signed-context', type=Path, required=True)
p.add_argument('--role-archive', type=Path, required=True)
p.add_argument('--legacy-archive', type=Path, required=True)
p.add_argument('--out', type=Path, required=True)
p.add_argument('--fail-work', action='store_true')
a = p.parse_args()
assert os.geteuid() != 0
os.umask(0o077)
a.out.mkdir(mode=0o700, parents=True, exist_ok=False)
private = a.out / 'private-tmp'; private.mkdir(mode=0o700)
here = Path(__file__).resolve().parent
root = Path('/home/ivano/codex-amnezia-upstream-20261104')
q = here.parent
fence = a.source_manifest or q / 'native-headless-authority-parent/MATERIALIZED_PRODUCT_SOURCE_MANIFEST.json'
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
now = lambda: datetime.now(timezone.utc).isoformat()
inputs = {}; code = 1
result = dict(startedUtc=now(), commands=[], componentPass=False, allFunctionsPass=False, releasePass=False, published=False,
    scope='Actual inert N main --stage-inputs/--validate-package plus real archive receipt. Only lstat uid of exact dev/ino-pinned owned private directory modeled0; real process uid/filesystem remains1000. Full actual copy/hash/checksum/auth/cleanup exercised. No packaged/static product/installer/host probe/service/network/namespace/root wrapper/guest/phone execution.')
env = dict(PATH='/usr/bin:/bin', HOME=str(a.out), TMPDIR=str(private), LANG='C', LC_ALL='C')
os.environ.update(env)

class WorkFailure(Exception): pass

def pin(path):
    inputs[str(path)] = sha(path)

def run(label, argv, expected=0, extra=None):
    with (a.out / (label + '.stdout')).open('xb') as stdout, (a.out / (label + '.stderr')).open('xb') as stderr:
        proc = subprocess.run(argv, env=dict(env, **(extra or {})), stdin=subprocess.DEVNULL,
                              stdout=stdout, stderr=stderr, timeout=120)
    result['commands'].append(dict(label=label, argv=argv, nativeExit=proc.returncode, expectedExit=expected))
    print(label, proc.returncode, flush=True)
    if expected is not None: assert proc.returncode == expected, (label, proc.returncode, expected)
    return proc.returncode

def fixed_data(archive, receipt, target):
    target.mkdir(mode=0o700)
    expected = {'headless-package/' + name for name in receipt['packageFiles']}
    with tarfile.open(archive, 'r:gz') as tar:
        members = [member for member in tar.getmembers() if member.name not in ('headless-package', 'headless-package/')]
        assert len(members) == len(expected) and {member.name for member in members} == expected
        for member in members:
            assert member.isfile() and 0 < member.size <= 8 * 1024 * 1024
            name = member.name.removeprefix('headless-package/')
            assert '/' not in name and name not in ('', '.', '..')
            data = tar.extractfile(member).read(member.size + 1); assert len(data) == member.size
            path = target / name; path.write_bytes(data); path.chmod(member.mode)

def pins_argv(identity):
    return ['--expected-public-key-sha256', identity['publicKeySha256'],
        '--expected-package-manifest-sha256', identity['packageManifestSha256'],
        '--expected-checksums-sha256', identity['checksumsSha256'],
        '--expected-signed-manifest-sha256', identity['manifestSha256']]

def stage(label, package, identity, receipt, key, model=True, race=False, mode=0o700, expected=0):
    destination = a.out / (label + '-private'); destination.mkdir(mode=mode); destination.chmod(mode)
    metadata = destination.lstat()
    context = {}
    if model:
        context = dict(W_PRIVATE_MODEL_ROOT=str(destination), W_PRIVATE_MODEL_DEV=str(metadata.st_dev),
                       W_PRIVATE_MODEL_INO=str(metadata.st_ino))
    if race: context['W_ROLE_SWAP_PATH'] = str(package / 'amnezia-verify-provisioning-native')
    stage_receipt = a.out / (label + '.stage.json')
    argv = [str(binary), '--stage-inputs', '--source-root', str(package), '--private-root', str(destination),
        '--public-key', str(key), '--verified-receipt', str(receipt), *pins_argv(identity), '--receipt-out', str(stage_receipt)]
    status = run(label, argv, expected, context)
    return status, destination, stage_receipt

try:
    pin(fence)
    for row in json.loads(fence.read_text()):
        path = root / row['path']; assert sha(path) == row['sha256'], row['path']; inputs[str(path)] = row['sha256']
    for folder in ['src', 'tests']:
        for path in sorted((a.subject / folder).iterdir()):
            if path.is_file(): pin(path)
    for path in [Path(__file__).resolve(), here / 'stage_io_model.cpp', Path('/usr/bin/c++').resolve(),
                 root / '.git/index', Path('/mnt/c/Users/ivano/PycharmProjects/amnezia-client/.git/index'),
                 a.role_archive, a.legacy_archive, a.signed_context / 'owned-TEST-public.pem']:
        pin(path)
    binary = a.out / 'inert-native-main'
    source = (a.production_dir or a.subject / 'src') / 'bootstrap_n.cpp'
    flags = ['-std=c++17', '-O2', '-Wall', '-Wextra', '-DAMNEZIA_BOOTSTRAP_TEST_BOUNDARY']
    if a.production_dir:
        assert a.production_dir == root / 'deploy/headless/native/provisioning_verifier'
        for name in ['bootstrap_n.cpp', 'preauth_modes.cpp', 'host_runtime.inc', 'verify_provisioning.cpp']:
            actual = a.production_dir / name
            assert actual.read_text() == (a.subject / 'src' / name).read_text(), name
            pin(actual)
        # Quote fallback supplies only the test-boundary include; real source
        # sibling includes resolve first in the actual production directory.
        flags += ['-iquote', str(a.subject / 'src')]
    dep = a.out / 'main.d'
    run('compiler-dependencies', ['/usr/bin/c++', *flags, '-M', '-MF', str(dep), str(source)])
    dependencies = [Path(token) for token in shlex.split(dep.read_text().replace('\\\n', ' ').split(':', 1)[1])]
    for path in dependencies: pin(path)
    if a.production_dir:
        required = {a.production_dir / name for name in ['bootstrap_n.cpp', 'preauth_modes.cpp', 'host_runtime.inc', 'verify_provisioning.cpp']}
        assert required <= set(dependencies)
    run('compile-inert-main', ['/usr/bin/c++', *flags, str(source), str(here / 'stage_io_model.cpp'),
        '-Wl,--wrap=lstat', '-lcrypto', '-lz', '-o', str(binary)])
    pin(binary)
    canonical_path = root / 'deploy/headless/verify_provisioning_bundle.py'; pin(canonical_path)
    spec = importlib.util.spec_from_file_location('canonical_receipt', canonical_path)
    canonical = importlib.util.module_from_spec(spec); spec.loader.exec_module(canonical)
    key = a.signed_context / 'owned-TEST-public.pem'
    fixtures = {}
    for name, archive in [('legacy8', a.legacy_archive), ('role9', a.role_archive)]:
        manifest = a.signed_context / ('manifest-' + name) / 'manifest.json'; pin(manifest)
        receipt = a.out / (name + '.receipt.json')
        run('verify-archive-' + name, [str(binary), '--manifest', str(manifest), '--public-key', str(key),
            '--expected-public-key-sha256', sha(key), '--provisioning', str(archive), '--receipt-out', str(receipt)])
        identity = json.loads(receipt.read_text())
        python_identity = canonical.verify_manifest_and_bundle(manifest, key, archive, sha(key))
        assert identity == python_identity, (name, identity, python_identity)
        package = a.out / (name + '-source'); fixed_data(archive, identity, package)
        fixtures[name] = (package, identity, receipt)
        status, refused, _ = stage('uid1000-refused-' + name, package, identity, receipt, key, model=False, expected=1)
        assert list(refused.iterdir()) == []
        status, target, out = stage('full-stage-' + name, package, identity, receipt, key)
        staged = json.loads(out.read_text()); assert staged['privateRootUid'] == 0 and staged['staged'] is True
        assert staged['packageFiles'] == identity['packageFiles']
        assert set(path.name for path in (target / 'package').iterdir()) == set(identity['packageFiles'])
        if name == 'role9':
            role = json.loads((package / 'package-manifest.json').read_text())['nativeVerifier']
            assert staged['nativeVerifier'] == role and sha(target / 'package'/role['path']) == role['sha256']
        metadata = a.out / (name + '.metadata.json')
        run('validate-staged-' + name, [str(binary), '--validate-package', '--package-root', str(target / 'package'),
            '--public-key', str(target / 'update-public-key.pem'), '--receipt', str(target / 'verified-receipt.json'),
            '--ubuntu-id', 'ubuntu', '--ubuntu-version-id', '24.04', '--ubuntu-codename', 'noble',
            *pins_argv(identity), '--receipt-out', str(metadata)])
        doc = json.loads(metadata.read_text())
        assert doc['structuralValidated'] and not doc['hostProbesExecuted'] and not doc['releaseAccepted']
        assert doc['packageFiles'] == identity['packageFiles']
        if name == 'role9':
            role_file = target / 'package/amnezia-verify-provisioning-native'
            role_file.chmod(0o4755)
            special = a.out / 'role-mode4755.metadata.json'
            run('validate-role-mode4755', [str(binary), '--validate-package', '--package-root', str(target / 'package'),
                '--public-key', str(target / 'update-public-key.pem'), '--receipt', str(target / 'verified-receipt.json'),
                '--ubuntu-id', 'ubuntu', '--ubuntu-version-id', '24.04', '--ubuntu-codename', 'noble',
                *pins_argv(identity), '--receipt-out', str(special)], expected=1)
            assert not special.exists()
            role_file.chmod(0o755)
    package, identity, receipt = fixtures['role9']
    race_source = a.out / 'race-source'; shutil.copytree(package, race_source)
    declared = json.loads((race_source / 'package-manifest.json').read_text())['nativeVerifier']
    status, target, out = stage('full-stage-role-source-swap', race_source, identity, receipt, key, race=True, expected=None)
    marker = (a.out / 'full-stage-role-source-swap.stderr').read_text()
    assert 'MODEL_ROLE_SWAP_BEFORE_COPY' in marker, marker
    observed = dict(actualStageExit=status, stagedReceiptExists=out.exists(), roleDeclaredSha256=declared['sha256'])
    staged_role = target / 'package/amnezia-verify-provisioning-native'
    if staged_role.exists(): observed['actualStagedSha256'] = sha(staged_role)
    result['raceObservation'] = observed
    assert status != 0 and not out.exists() and not (target / 'package').exists(), observed
    for name, change in [('wrong-mode', lambda path: path.chmod(0o644)),
                         ('mode4755', lambda path: path.chmod(0o4755)),
                         ('mode2755', lambda path: path.chmod(0o2755)),
                         ('mode1755', lambda path: path.chmod(0o1755)),
                         ('wrong-bytes', lambda path: path.write_bytes(b'UNAUTHENTICATED-DATA'))]:
        altered = a.out / (name + '-source'); shutil.copytree(package, altered)
        change(altered / 'amnezia-verify-provisioning-native')
        status, target, out = stage('stage-' + name, altered, identity, receipt, key, expected=1)
        assert not out.exists() and not (target / 'package').exists()
    stage('stage-root-mode0755', package, identity, receipt, key, mode=0o755, expected=1)
    if a.legacy_matrix:
        pin(a.legacy_matrix)
        legacy_cases = json.loads(a.legacy_matrix.read_text())['cases']
        assert len(legacy_cases) == 17
        legacy_results = []
        for case in legacy_cases:
            args = case['argv'][1:]
            golden = None
            if '--receipt-out' in args:
                index = args.index('--receipt-out') + 1
                original = Path(args[index])
                if case['expected_exit'] == 0:
                    pin(original); golden = original.read_bytes()
                args[index] = str(a.out / ('legacy-' + case['name'] + '.receipt.json'))
            for value in args:
                path = Path(value)
                if path.is_absolute() and path.exists() and stat.S_ISREG(path.lstat().st_mode): pin(path)
            status = run('legacy-' + case['name'], [str(binary), *args], expected=case['expected_exit'])
            if golden is not None:
                assert Path(args[index]).read_bytes() == golden, case['name']
            legacy_results.append(dict(name=case['name'], actualExit=status, expectedExit=case['expected_exit'],
                                       goldenByteIdentical=golden is not None))
        result['legacyCases'] = legacy_results
    if a.fail_work:
        status = run('actual-deliberate-failed-work', ['/usr/bin/python3', '-I', '-B', '-c', 'raise SystemExit(23)'], expected=None)
        assert status == 23
        raise WorkFailure('actual stage-review runner deliberate work subprocess exited23')
    code = 0; result['componentPass'] = True
except WorkFailure as error:
    result.update(exceptionType=type(error).__name__, exception=str(error)); code = 23
except Exception as error:
    result.update(exceptionType=type(error).__name__, exception=str(error)); code = 1
finally:
    changed = [path for path, digest in inputs.items() if not Path(path).is_file() or sha(Path(path)) != digest]
    if changed: code = 1; result['componentPass'] = False
    result.update(nativeExit=code, inputsUnchanged=not changed, changedInputs=changed, inputCount=len(inputs), finishedUtc=now())
    (a.out / 'INPUTS_BEFORE.json').write_text(json.dumps(inputs, indent=2) + '\n')
    (a.out / 'RESULT.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: result[key] for key in ['nativeExit', 'componentPass', 'inputsUnchanged', 'inputCount', 'raceObservation', 'exception'] if key in result}))
sys.exit(code)
