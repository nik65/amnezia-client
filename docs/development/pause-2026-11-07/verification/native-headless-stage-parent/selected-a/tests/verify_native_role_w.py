#!/usr/bin/env python3
"""W derivative: nativeVerifier role consumer through actual --validate-package
and --stage-inputs source path, with shared strict role binding, exact root/FD/
size/auth preservation and owned UID0-metadata-model stage checks.

Real role/legacy archives are U-produced fixed-member fixtures; only the exact
declared member names are copied as data.  No tar-wide extraction, packaged
ELF, installer, host probe, root wrapper, namespace, service or network.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile

p = argparse.ArgumentParser()
p.add_argument('--source', type=Path, required=True)
p.add_argument('--old-binary', type=Path, required=True)
p.add_argument('--out', type=Path, required=True)
p.add_argument('--fail-work', action='store_true')
a = p.parse_args()
assert os.geteuid() != 0
a.out.mkdir(mode=0o700, parents=True, exist_ok=False)
build = a.out / 'build'; build.mkdir(mode=0o700)
private = a.out / 'private-tmp'; private.mkdir(mode=0o700)
sha = lambda f: hashlib.sha256(Path(f).read_bytes()).hexdigest()

U = Path('/home/ivano/amnezia-product-50318-q/native-headless-delivery-u/attempt-u-20261107T140937')
MATRIX = Path('/home/ivano/amnezia-product-50318-q/native-verifier-integrated-matrix-a/RESULT.json')
PARENT_BUILD = Path('/home/ivano/amnezia-product-50318-q/native-headless-runtime-parent/critical-b/build')
HOOK = Path('/mnt/c/Users/ivano/PycharmProjects/amnezia-client/dist/diagnostics/upstream-5106-continuation-a/final-build-readiness-q/native-headless-runtime-parent/fd_swap_hook.cpp')
BIN = build / 'bootstrap-main-test'
cases = []

def record(name, ok, detail):
    cases.append({'case': name, 'ok': bool(ok), 'detail': detail})
    print(('PASS ' if ok else 'FAIL ') + name + ' :: ' + detail, flush=True)

def pin_inputs():
    pins = {}
    for folder in ['src', 'tests']:
        for f in sorted((a.source / folder).iterdir()):
            if f.is_file(): pins[str(f)] = sha(f)
    for f in [a.old_binary, U / 'bundle-new/provisioning.tar.gz',
              U / 'bundle-new/update-public-key.pem', U / 'receipt-new.json',
              U / 'bundle-legacy/provisioning.tar.gz',
              U / 'bundle-legacy/update-public-key.pem', U / 'receipt-legacy.json',
              MATRIX, HOOK, Path('/usr/bin/c++').resolve()]:
        pins[str(f)] = sha(f)
    return pins

pins = pin_inputs()
config = a.out / 'openssl-empty.cnf'; config.write_text('openssl_conf = openssl_init\n[openssl_init]\n')
ENV = dict(PATH='/usr/bin:/bin', LC_ALL='C', LANG='C', HOME=str(private), TMPDIR=str(private),
           TMP=str(private), TEMP=str(private), OPENSSL_CONF=str(config))
CXX = ['/usr/bin/c++', '-std=c++17', '-O2', '-Wall', '-Wextra']

def run(label, command, expected=0, env=None, timeout=180):
    item = {'label': label, 'argv': [str(x) for x in command], 'expectedExit': expected}
    proc = subprocess.run([str(x) for x in command], env=env or ENV, stdin=subprocess.DEVNULL,
                          capture_output=True, timeout=timeout)
    (a.out / (label + '.stdout')).write_bytes(proc.stdout)
    (a.out / (label + '.stderr')).write_bytes(proc.stderr)
    item.update(nativeExit=proc.returncode)
    record(label, proc.returncode == expected,
           f"exit={proc.returncode} expected={expected} err={proc.stderr.decode(errors='replace')[:180]!r}")
    return proc, item

def extract_fixed(archive, identity, dest):
    dest.mkdir(mode=0o700)
    expected = {'headless-package/' + name for name in identity['packageFiles']}
    with tarfile.open(archive, 'r:gz') as tar:
        members = [m for m in tar.getmembers() if m.name not in ('headless-package', 'headless-package/')]
        assert len(members) == len(expected) and {m.name for m in members} == expected
        for m in members:
            assert m.isreg() and 0 < m.size <= 8 * 1024 * 1024
            parts = m.name.split('/'); assert len(parts) == 2 and parts[0] == 'headless-package' and parts[1] not in ('', '.', '..')
            data = tar.extractfile(m).read(8 * 1024 * 1024 + 1); assert len(data) == m.size
            f = dest / parts[1]; f.write_bytes(data); f.chmod(m.mode)

def validate_argv(package, receipt, key, receipt_out, binary=BIN):
    identity = json.loads(Path(receipt).read_text())
    return [str(binary), '--validate-package', '--package-root', str(package), '--public-key', str(key),
            '--receipt', str(receipt), '--ubuntu-id', 'ubuntu', '--ubuntu-version-id', '24.04',
            '--ubuntu-codename', 'noble',
            '--expected-public-key-sha256', identity['publicKeySha256'],
            '--expected-package-manifest-sha256', identity['packageManifestSha256'],
            '--expected-checksums-sha256', identity['checksumsSha256'],
            '--expected-signed-manifest-sha256', identity['manifestSha256'],
            '--receipt-out', str(receipt_out)]

def run_validate(package, receipt, key, label, expected=0):
    out = a.out / (label + '.metadata.json')
    proc, item = run(label, validate_argv(package, receipt, key, out), expected)
    doc = json.loads(out.read_text()) if out.exists() else None
    return proc, doc, item

code = 1
try:
    # ---------- compile the reviewed N closure + W delta ----------
    run('compiler-version', ['/usr/bin/c++', '--version'])
    run('build-main-test', CXX + ['-DAMNEZIA_BOOTSTRAP_TEST_BOUNDARY', '-o', BIN,
                                  str(a.source / 'src/bootstrap_n.cpp'), '-lcrypto', '-lz'])
    run('build-transport', CXX + ['-DAMNEZIA_BOOTSTRAP_TRANSPORT_DRIVER', '-o', build / 'bootstrap-transport',
                                  str(a.source / 'src/bootstrap_n.cpp'), '-lcrypto', '-lz'])
    run('build-native-static', CXX + ['-static', '-o', build / 'bootstrap-native',
                                      str(a.source / 'src/bootstrap_n.cpp'), '-lcrypto', '-lz'])
    model = build / 'native-role-model'
    run('build-role-model', CXX + ['-o', model, str(a.source / 'tests/native_role_model.cpp'), '-lcrypto', '-lz'])
    for name in ['probe-fixture', 'k-red']:
        shutil.copyfile(PARENT_BUILD / name, build / name); (build / name).chmod(0o700)

    # ---------- exact U fixtures (fixed member set only) ----------
    new_identity = json.loads((U / 'receipt-new.json').read_text())
    legacy_identity = json.loads((U / 'receipt-legacy.json').read_text())
    role_master = a.out / 'role-master'; legacy_master = a.out / 'legacy-master'
    extract_fixed(U / 'bundle-new/provisioning.tar.gz', new_identity, role_master)
    extract_fixed(U / 'bundle-legacy/provisioning.tar.gz', legacy_identity, legacy_master)
    assert len(new_identity['packageFiles']) == 9 and len(legacy_identity['packageFiles']) == 8
    role_mode = (role_master / 'amnezia-verify-provisioning-native').stat().st_mode & 0o777
    record('fixture-role-nine-members-mode0755',
           role_mode == 0o755 and len(list(role_master.iterdir())) == 9,
           f"mode={oct(role_mode)} members={len(list(role_master.iterdir()))}")
    record('fixture-legacy-eight-members', len(list(legacy_master.iterdir())) == 8,
           f"members={len(list(legacy_master.iterdir()))}")

    # ---------- actual full caller GREEN: role archive metadata ----------
    key_new = U / 'bundle-new/update-public-key.pem'
    proc, doc, _ = run_validate(role_master, U / 'receipt-new.json', key_new, 'validate-role-green', 0)
    manifest = json.loads((role_master / 'package-manifest.json').read_text())
    role = manifest['nativeVerifier']
    ok = (proc.returncode == 0 and doc is not None and doc.get('structuralValidated') is True and
          doc.get('hostProbesExecuted') is False and doc.get('releaseAccepted') is False and
          doc.get('packageFiles') == new_identity['packageFiles'] and
          doc.get('nativeVerifier') == {'path': 'amnezia-verify-provisioning-native',
                                        'sha256': role['sha256'], 'size': role['size']})
    record('validate-role-metadata-structural-only', ok,
           f"exit={proc.returncode} role={doc.get('nativeVerifier') if doc else None}")

    # ---------- legacy unchanged ----------
    proc, doc, _ = run_validate(legacy_master, U / 'receipt-legacy.json',
                                U / 'bundle-legacy/update-public-key.pem', 'validate-legacy-green', 0)
    ok = (proc.returncode == 0 and doc is not None and doc.get('packageFiles') == legacy_identity['packageFiles'] and
          'nativeVerifier' not in doc and doc.get('structuralValidated') is True)
    record('validate-legacy-unchanged', ok,
           f"exit={proc.returncode} files={len(doc.get('packageFiles', [])) if doc else None}")

    # ---------- role negatives through actual --validate-package ----------
    def fresh(name):
        d = a.out / name; d.mkdir(mode=0o700)
        pkg = d / 'package'; shutil.copytree(role_master, pkg)
        pkg.chmod(0o700)
        for f in pkg.iterdir(): f.chmod((role_master / f.name).stat().st_mode & 0o777)
        m = json.loads((pkg / 'package-manifest.json').read_text())
        r = json.loads((U / 'receipt-new.json').read_text())
        return d, pkg, m, r

    def rewrite_sums(pkg):
        rows = []
        for f in sorted(pkg.iterdir()):
            if f.name == 'SHA256SUMS': continue
            rows.append(sha(f) + '  ' + f.name + '\n')
        (pkg / 'SHA256SUMS').write_text(''.join(rows))

    def finish(name, d, pkg, m, r, expect=1, rewrite=True):
        (pkg / 'package-manifest.json').write_text(json.dumps(m, sort_keys=True, separators=(',', ':')))
        if rewrite: rewrite_sums(pkg)
        r['packageManifestSha256'] = sha(pkg / 'package-manifest.json')
        r['checksumsSha256'] = sha(pkg / 'SHA256SUMS')
        (d / 'receipt.json').write_text(json.dumps(r))
        proc, _, _ = run_validate(pkg, d / 'receipt.json', key_new, name, expect)
        return proc

    def mutate_field(name, field, value):
        d, pkg, m, r = fresh(name)
        m['nativeVerifier'] = dict(m['nativeVerifier']); m['nativeVerifier'][field] = value
        finish(name, d, pkg, m, r)

    mutate_field('neg-role-wrong-path', 'path', 'amnezia-verifier')
    mutate_field('neg-role-boolean-size', 'size', True)
    mutate_field('neg-role-uppercase-sha', 'sha256', role['sha256'].upper())
    mutate_field('neg-role-zero-size', 'size', 0)
    mutate_field('neg-role-oversize', 'size', 8388609)
    d, pkg, m, r = fresh('neg-role-extra-key'); m['nativeVerifier']['mode'] = '0755'; finish('neg-role-extra-key', d, pkg, m, r)
    d, pkg, m, r = fresh('neg-role-mode-0644')
    (pkg / 'amnezia-verify-provisioning-native').chmod(0o644)
    finish('neg-role-mode-0644', d, pkg, m, r)
    d, pkg, m, r = fresh('neg-role-size-binding')
    with (pkg / 'amnezia-verify-provisioning-native').open('ab') as f: f.write(b'x')
    rewrite_sums(pkg); m['nativeVerifier']['sha256'] = sha(pkg / 'amnezia-verify-provisioning-native')
    finish('neg-role-size-binding', d, pkg, m, r)
    d, pkg, m, r = fresh('neg-role-hash-binding')
    f = pkg / 'amnezia-verify-provisioning-native'; data = bytearray(f.read_bytes()); data[0] ^= 0xFF; f.write_bytes(bytes(data))
    rewrite_sums(pkg)
    finish('neg-role-hash-binding', d, pkg, m, r)
    d, pkg, m, r = fresh('neg-role-checksums-row-missing')
    lines = [line for line in (pkg / 'SHA256SUMS').read_text().splitlines(True) if 'amnezia-verify-provisioning-native' not in line]
    (pkg / 'SHA256SUMS').write_text(''.join(lines)); finish('neg-role-checksums-row-missing', d, pkg, m, r, rewrite=False)
    d, pkg, m, r = fresh('neg-role-symlink')
    target = d / 'verifier-copy'; shutil.copyfile(pkg / 'amnezia-verify-provisioning-native', target); target.chmod(0o755)
    (pkg / 'amnezia-verify-provisioning-native').unlink()
    (pkg / 'amnezia-verify-provisioning-native').symlink_to(target)
    finish('neg-role-symlink', d, pkg, m, r)
    d, pkg, m, r = fresh('neg-role-missing')
    (pkg / 'amnezia-verify-provisioning-native').unlink(); finish('neg-role-missing', d, pkg, m, r)
    d, pkg, m, r = fresh('neg-role-undeclared')
    shutil.copyfile(legacy_master / 'package-manifest.json', pkg / 'package-manifest.json')
    m = json.loads((pkg / 'package-manifest.json').read_text())
    r = json.loads((U / 'receipt-legacy.json').read_text()); rewrite_sums(pkg)
    finish('neg-role-undeclared', d, pkg, m, r)

    # ---------- actual --stage-inputs entry: exact root gate stays pre-entry ----------
    stage_private = a.out / 'stage-private'; stage_private.mkdir(mode=0o700)
    proc, _ = run('stage-actual-uid1000-root-gate',
                  [str(BIN), '--stage-inputs', '--source-root', str(legacy_master),
                   '--private-root', str(stage_private), '--public-key', str(U / 'bundle-legacy/update-public-key.pem'),
                   '--verified-receipt', str(U / 'receipt-legacy.json'),
                   '--expected-public-key-sha256', legacy_identity['publicKeySha256'],
                   '--expected-package-manifest-sha256', legacy_identity['packageManifestSha256'],
                   '--expected-checksums-sha256', legacy_identity['checksumsSha256'],
                   '--expected-signed-manifest-sha256', legacy_identity['manifestSha256']], 1)
    record('stage-actual-refuses-uid1000-root-preentry', b'root-owned' in proc.stderr,
           proc.stderr.decode(errors='replace')[:200].strip())

    # ---------- UID0 metadata model + shared role stage checks ----------
    model_work = a.out / 'model-work'; model_work.mkdir(mode=0o700)
    proc, _ = run('stage-role-uid0-metadata-model', [str(model), str(model_work)], 0, timeout=60)
    model_text = (a.out / 'stage-role-uid0-metadata-model.stdout').read_text()
    record('stage-role-model-all-checks', 'FAILURES 0' in model_text and 'MODEL_uid0_0700_dir_accepted' in model_text,
           model_text.splitlines()[-1] if model_text.splitlines() else '')

    # ---------- preauth FD nonblocking class RED -> GREEN ----------
    # RED control is compiled from the immutable reviewed N closure with only
    # the two O_NONBLOCK tokens removed (the demonstrated pre-fix class).  The
    # parent prebuilt driver already carried the fixed flags, so it is not used
    # as the RED authority.
    red_root = a.out / 'red-root'; (red_root / 'src').mkdir(parents=True)
    shutil.copytree(a.source / 'src', red_root / 'src', dirs_exist_ok=True)
    shutil.copytree(a.source / 'tests', red_root / 'tests')
    red_text = (red_root / 'src/preauth_modes.cpp').read_text()
    assert red_text.count('O_CLOEXEC | O_NONBLOCK') == 2
    (red_root / 'src/preauth_modes.cpp').write_text(red_text.replace('O_CLOEXEC | O_NONBLOCK', 'O_CLOEXEC'))
    red_bin = build / 'bootstrap-red-control'
    run('build-red-flag-control', CXX + ['-DAMNEZIA_BOOTSTRAP_TEST_BOUNDARY', '-o', red_bin,
                                         str(red_root / 'src/bootstrap_n.cpp'), '-lcrypto', '-lz'])
    run('build-fd-hook', ['/usr/bin/c++', '-std=c++17', '-shared', '-fPIC', str(HOOK), '-ldl', '-o', str(a.out / 'hook.so')], 0)

    def fd_guard(label, binary, which, expect_nonblock):
        d = a.out / label; d.mkdir(mode=0o700); pkg = d / 'package'
        identity = new_identity if which == 'new' else legacy_identity
        extract_fixed(U / ('bundle-' + which + '/provisioning.tar.gz'), identity, pkg)
        receipt = d / ('receipt-' + which + '.json')
        receipt.write_bytes((U / ('receipt-' + which + '.json')).read_bytes())
        log = d / 'open-flags'
        env = dict(ENV, TMPDIR=str(d), HOME=str(d), LD_PRELOAD=str(a.out / 'hook.so'),
                   N_FD_PROBE_TARGET=str(pkg / 'package-manifest.json'), N_FD_PROBE_LOG=str(log))
        proc = subprocess.run(validate_argv(pkg, receipt, U / ('bundle-' + which + '/update-public-key.pem'), d / 'meta.json', binary=binary),
                              env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=15)
        (d / 'subject.stderr').write_bytes(proc.stderr)
        observed = log.read_text() if log.exists() else ''
        fifo = stat.S_ISFIFO((pkg / 'package-manifest.json').lstat().st_mode)
        record(label, proc.returncode != 0 and fifo and ('nonblock=%d' % expect_nonblock) in observed,
               f"exit={proc.returncode} fifo={fifo} open={observed.strip()}")
        if fifo: (pkg / 'package-manifest.json').unlink()

    fd_guard('fd-guard-red-prefix-control', red_bin, 'legacy', 0)
    fd_guard('fd-guard-green-role-archive', BIN, 'new', 1)

    for mode, expect_nonblock in [('fd-read', 1), ('fd-copy', 1)]:
        d = a.out / ('model-' + mode); d.mkdir(mode=0o700)
        probe = d / 'probe.bin'; probe.write_bytes(b'probe bytes\n'); probe.chmod(0o600)
        log = d / 'open-flags'
        env = dict(ENV, TMPDIR=str(d), HOME=str(d), LD_PRELOAD=str(a.out / 'hook.so'),
                   N_FD_PROBE_TARGET=str(probe), N_FD_PROBE_LOG=str(log))
        proc = subprocess.run([str(model), str(probe), mode], env=env, stdin=subprocess.DEVNULL,
                              capture_output=True, timeout=15)
        observed = log.read_text() if log.exists() else ''
        fifo = stat.S_ISFIFO(probe.lstat().st_mode)
        record('model-stage-' + mode, proc.returncode == 0 and fifo and ('nonblock=%d' % expect_nonblock) in observed,
               f"exit={proc.returncode} fifo={fifo} open={observed.strip()} out={proc.stdout.decode(errors='replace').strip()}")
        if fifo: probe.unlink()

    # ---------- legacy 17 fixture matrix against the new compiled artifact ----------
    matrix = json.loads(MATRIX.read_text())
    legacy_cases = matrix['cases']; assert len(legacy_cases) == 17
    passed = 0
    for item in legacy_cases:
        argv = [str(BIN)] + [str(x) for x in item['argv'][1:]]
        if '--receipt-out' in argv:
            argv[argv.index('--receipt-out') + 1] = str(a.out / ('matrix-' + item['name'] + '.receipt.json'))
        proc = subprocess.run(argv, env=ENV, stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
        (a.out / ('matrix-' + item['name'] + '.stderr')).write_bytes(proc.stderr)
        if proc.returncode == item['expected_exit']: passed += 1
        else: print('MATRIX-MISMATCH', item['name'], proc.returncode, item['expected_exit'], flush=True)
    record('legacy-17-fixture-matrix', passed == 17, f"matched={passed}/17")

    # ---------- N 26 functional + 4 baseline characterizations ----------
    n_env = dict(ENV, AMNEZIA_N_BUILD_ROOT=str(build), AMNEZIA_N_WORK_ROOT=str(a.out / 'n-work'))
    run('n-regressions-26-plus-4', [sys.executable, '-I', '-B', str(a.source / 'tests/run_n.py')], 0, env=n_env, timeout=300)
    summary = json.loads((a.out / 'test-results.json').read_text())
    red = [row for row in summary['results'] if row['case'].startswith('RED_')]
    record('n-regression-count-scope', summary['cases'] == 30 and summary['failures'] == 0 and len(red) == 4,
           f"cases={summary['cases']} failures={summary['failures']} red={len(red)}")

    # ---------- compiled static artifact inspected, never launched ----------
    run('static-elf-inspect', ['/usr/bin/readelf', '-h', '-l', '-d', str(build / 'bootstrap-native')], 0)
    binary = (build / 'bootstrap-native').read_bytes()
    phoff = int.from_bytes(binary[32:40], 'little'); phentsize = int.from_bytes(binary[54:56], 'little')
    phcount = int.from_bytes(binary[56:58], 'little')
    ptypes = [int.from_bytes(binary[phoff + i * phentsize: phoff + i * phentsize + 4], 'little') for i in range(phcount)]
    record('static-no-interp-no-dynamic', binary[:5] == b'\x7fELF\x02' and 2 not in ptypes and 3 not in ptypes,
           f"size={len(binary)} sha256={sha(build / 'bootstrap-native')}")
    record('static-never-launched', True, 'readelf -h -l -d only; no execution of bootstrap-native')

    # ---------- actual failed work preserved ----------
    if a.fail_work:
        run('actual-failed-work', [sys.executable, '-I', '-B', '-c', 'raise SystemExit(23)'], 23)

    compiled = {name: sha(build / name) for name in ['bootstrap-main-test', 'bootstrap-transport', 'bootstrap-native', 'native-role-model']}
    code = 0
except Exception as error:
    record('harness-exception', False, f"{type(error).__name__}: {error}")
    compiled = {}
finally:
    changed = {str(path): digest for path, digest in pins.items() if not Path(path).is_file() or sha(path) != digest}
    record('inputs-unchanged', not changed, f"changed={list(changed)[:4]}")
    component = code == 0 and all(row['ok'] for row in cases)
    result = dict(startedUtc=None, finishedUtc=datetime.now(timezone.utc).isoformat(),
                  scope='W derivative: actual N inert main preauth metadata/stage role consumer, shared strict nativeVerifier binding, '
                        'UID0 metadata model for root-gated stage, owned UID1000 data only. Static product ELF compiled/inspected NOT executed; '
                        'no installer/packaged ELF/host probe/root wrapper/namespace/service/network action.',
                  inputs=pins, cases=cases, caseCount=len(cases), passCount=sum(1 for row in cases if row['ok']),
                  compiledArtifacts=compiled,
                  artifact=dict(path=str(build / 'bootstrap-native'), sha256=compiled.get('bootstrap-native'),
                                size=(build / 'bootstrap-native').stat().st_size, executed=False, staticFormat=True),
                  componentPass=component, allFunctionsPass=False, releasePass=False, published=False,
                  nativeExit=(0 if component else 1))
    (a.out / 'RESULT.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(dict(result=str(a.out / 'RESULT.json'), nativeExit=result['nativeExit'],
                          componentPass=component, passCount=result['passCount'], caseCount=len(cases))))
    raise SystemExit(result['nativeExit'])
