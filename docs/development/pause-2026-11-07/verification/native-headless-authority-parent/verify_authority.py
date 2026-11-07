"""Parent V authority/actual-decoder review. All products/archives remain data."""
import argparse
import copy
from datetime import datetime, timezone
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tarfile

p = argparse.ArgumentParser()
p.add_argument('--source', type=Path, required=True)
p.add_argument('--subject', type=Path, required=True)
p.add_argument('--role-archive', type=Path, required=True)
p.add_argument('--legacy-archive', type=Path, required=True)
p.add_argument('--artifact', type=Path, required=True)
p.add_argument('--out', type=Path, required=True)
p.add_argument('--manifest', type=Path)
p.add_argument('--baseline-root', type=Path)
p.add_argument('--fail-work', action='store_true')
a = p.parse_args()
baseline_root = a.baseline_root or a.source
os.umask(0o077)
a.out.mkdir(mode=0o700, parents=True, exist_ok=False)
tmp = a.out / 'private-tmp'; tmp.mkdir(mode=0o700)
qt = Path('/home/ivano/Qt/6.10.1/gcc_64')
here = Path(__file__).resolve().parent
q = here.parent
fence = a.manifest or q / 'native-maintenance-integration-parent/MATERIALIZED_PRODUCT_SOURCE_MANIFEST.json'
sha = lambda data: hashlib.sha256(data).hexdigest()
now = lambda: datetime.now(timezone.utc).isoformat()
inputs = {}; checks = []; code = 1
result = dict(startedUtc=now(), commands=[], componentPass=False, allFunctionsPass=False, releasePass=False, published=False,
    scope='Local canonical authority/signer/verifier; actual parseManifest and actual verifyTrustedKey bodies with only fixed-anchor QFileInfo/QFile IO inert and storage constructor excluded; complete real decoder/bootstrapper TUs compile separately. No actual /etc key read, installer/product, network/SSH/service/guest/phone/publication execution.')
env = dict(PATH='/usr/bin:/bin', HOME=str(a.out), TMPDIR=str(tmp), LANG='C', LC_ALL='C', LD_LIBRARY_PATH=str(qt / 'lib'))
os.environ.update(env)  # Imported canonical signing helpers also use tempfile in this process.
class WorkFailure(Exception): pass

def read(path):
    inputs[str(path)] = sha(path.read_bytes())
    return path.read_text()

def filecopy(path, destination):
    inputs[str(path)] = sha(path.read_bytes())
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(path, destination)

def load(name, path):
    read(path)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module

def run(label, argv, cwd=None, expected=0, timeout=120):
    started = now()
    with (a.out / (label + '.stdout')).open('xb') as out, (a.out / (label + '.stderr')).open('xb') as err:
        try: status = subprocess.run(argv, cwd=cwd, env=env, stdout=out, stderr=err, timeout=timeout).returncode
        except subprocess.TimeoutExpired: status = 124
    result['commands'].append(dict(label=label, argv=argv, cwd=str(cwd) if cwd else None,
                                   nativeExit=status, expectedExit=expected, startedUtc=started, finishedUtc=now()))
    if status != expected: raise AssertionError(label + ': exit=' + str(status))
    print(label, status, flush=True)
    return status

def check(name, fn, accepted=True, signature_failure=False):
    try: value = fn(); actual = True; error = ''
    except SystemExit as exc: value = None; actual = False; error = str(exc)
    except subprocess.CalledProcessError as exc:
        if (not signature_failure or exc.returncode != 1
                or Path(exc.cmd[0]).name != 'openssl' or exc.cmd[1] != 'pkeyutl'
                or '-verify' not in exc.cmd):
            raise
        value = None; actual = False; error = 'OpenSSL signature verification native exit 1'
    # Programming/setup exceptions are never counted as desired refusal.
    checks.append(dict(name=name, passed=actual == accepted, observedAccepted=actual, error=error))
    assert actual == accepted, checks[-1]
    return value

def bind_dependencies(label, source_path, include_flags):
    dep = a.out / (label + '.d')
    run(label + '-dependencies', ['/usr/bin/c++', '-std=c++17', '-fPIC', '-M', '-MF', str(dep),
                                  str(source_path), *include_flags])
    for token in shlex.split(dep.read_text().replace('\\\n', ' ').split(':', 1)[1]):
        path = Path(token)
        inputs[str(path)] = sha(path.read_bytes())

def package(files, modes, path, symlink=False):
    with tarfile.open(path, 'w:gz') as tar:
        for name, data in files.items():
            member = tarfile.TarInfo('headless-package/' + name)
            member.mode = modes[name]; member.mtime = 1700000000
            if symlink and name == VERIFIER:
                member.type = tarfile.SYMTYPE; member.linkname = 'amneziad'; tar.addfile(member)
            else:
                member.size = len(data); tar.addfile(member, io.BytesIO(data))

def variant(name, modifier=None, symlink=False):
    files = dict(base_files); modes = dict(base_modes); pm = json.loads(files['package-manifest.json'])
    if modifier: modifier(files, modes, pm)
    files['package-manifest.json'] = (json.dumps(pm, sort_keys=True, separators=(',', ':')) + '\n').encode()
    files['SHA256SUMS'] = ''.join(sha(data) + '  ' + key + '\n' for key, data in files.items() if key != 'SHA256SUMS').encode()
    path = a.out / ('fixture-' + name + '.tar.gz')
    package(files, modes, path, symlink)
    return path

try:
    rows = json.loads(read(fence))
    for row in rows:
        path = a.source / row['path']; assert sha(path.read_bytes()) == row['sha256'], row['path']
        inputs[str(path)] = row['sha256']
    for path in [a.source / '.git/index', Path('/mnt/c/Users/ivano/PycharmProjects/amnezia-client/.git/index'),
                 Path(__file__).resolve(), here / 'parse_driver.cpp', Path('/usr/bin/c++').resolve(),
                 Path('/usr/bin/openssl').resolve(), qt / 'lib/libQt6Core.so.6', qt / 'lib/libQt6Network.so.6']:
        inputs[str(path)] = sha(path.read_bytes())
    source = a.out / 'source'
    rels = ['deploy/selfhosted_updates/make_manifest.py', 'client/core/controllers/selfhosted/headlessProvisioning.h',
            'headless/headlessUpdateManager.cpp']
    for rel in rels: filecopy(a.subject / rel, source / rel)
    filecopy(a.source / 'deploy/headless/make_headless_manifest.py', source / 'deploy/headless/make_headless_manifest.py')
    canonical = load('authority_baseline', baseline_root / rels[0])
    selected = load('authority_selected', source / rels[0])
    VERIFIER = 'amnezia-verify-provisioning-native'; HELPER = 'amnezia-headless-fs'; VERSION = '1.0.0.42'
    for path in [a.role_archive, a.legacy_archive, a.artifact]: inputs[str(path)] = sha(path.read_bytes())
    check('baseline-rejects-actual-parent-role', lambda: canonical.inspect_headless_provisioning(a.role_archive, VERSION), False)
    old_legacy = check('baseline-legacy-control', lambda: canonical.inspect_headless_provisioning(a.legacy_archive, VERSION))
    role_receipt = check('selected-actual-parent-role', lambda: selected.inspect_headless_provisioning(a.role_archive, VERSION))
    assert role_receipt['files'][-1] == VERIFIER and len(role_receipt['files']) == 9
    assert check('selected-legacy-control', lambda: selected.inspect_headless_provisioning(a.legacy_archive, VERSION)) == old_legacy
    # Fixed, bounded read as data only. No extract/extractall or packaged execution.
    base_files = {}; base_modes = {}
    with tarfile.open(a.role_archive, 'r:gz') as tar:
        members = [member for member in tar.getmembers() if not member.isdir()]
        assert len(members) == 9
        for member in members:
            assert member.isfile() and 0 <= member.size <= 8 * 1024 * 1024
            name = member.name.removeprefix('headless-package/')
            assert '/' not in name and name in role_receipt['files'] and name not in base_files
            base_files[name] = tar.extractfile(member).read(member.size + 1)
            assert len(base_files[name]) == member.size
            base_modes[name] = member.mode
    def helper(files, modes, pm):
        files[HELPER] = b'OWNED-TEST-HELPER-DATA'; modes[HELPER] = 0o755; pm['nativeHelper'] = HELPER
    def helper_only(files, modes, pm):
        helper(files, modes, pm); files.pop(VERIFIER); modes.pop(VERIFIER); pm.pop('nativeVerifier')
    helper9 = variant('helper9', helper_only); both10 = variant('both10', helper)
    for name, path in [('helper9', helper9), ('both10', both10)]:
        check('selected-' + name, lambda path=path: selected.inspect_headless_provisioning(path, VERSION))
    assert canonical.inspect_headless_provisioning(helper9, VERSION) == selected.inspect_headless_provisioning(helper9, VERSION)
    negative_roles = [('extra', lambda v: v.update(extra=True)), ('missing', lambda v: v.pop('size')),
        ('wrong-path', lambda v: v.update(path='amnezia-cli')), ('uppercase-sha', lambda v: v.update(sha256=v['sha256'].upper())),
        ('bool-size', lambda v: v.update(size=True)), ('zero-size', lambda v: v.update(size=0)),
        ('negative-size', lambda v: v.update(size=-1)), ('float-size', lambda v: v.update(size=1.0)),
        ('oversize', lambda v: v.update(size=8388609)), ('wrong-size', lambda v: v.update(size=1)),
        ('wrong-sha', lambda v: v.update(sha256='0' * 64))]
    for name, mutate in negative_roles:
        def modify(files, modes, pm, mutate=mutate): mutate(pm['nativeVerifier'])
        path = variant(name, modify)
        check('reject-role-' + name, lambda path=path: selected.inspect_headless_provisioning(path, VERSION), False)
    mutations = [
        ('null', lambda f, m, p: p.update(nativeVerifier=None)),
        ('non-object', lambda f, m, p: p.update(nativeVerifier='invalid')),
        ('mode0644', lambda f, m, p: m.update({VERIFIER: 0o644})),
        ('setuid', lambda f, m, p: m.update({VERIFIER: 0o4755})),
        ('member-bytes', lambda f, m, p: f.update({VERIFIER: b'TAMPERED'})),
        ('undeclared', lambda f, m, p: p.pop('nativeVerifier')),
        ('missing-member', lambda f, m, p: (f.pop(VERIFIER), m.pop(VERIFIER))),
    ]
    for name, mutate in mutations:
        path = variant(name, mutate)
        check('reject-member-' + name, lambda path=path: selected.inspect_headless_provisioning(path, VERSION), False)
    link = variant('symlink', symlink=True)
    check('reject-member-symlink', lambda: selected.inspect_headless_provisioning(link, VERSION), False)
    key = a.out / 'owned-TEST-private.pem'; public = a.out / 'owned-TEST-public.pem'
    run('keygen', ['/usr/bin/openssl', 'genpkey', '-algorithm', 'ED25519', '-out', str(key)])
    run('public-key', ['/usr/bin/openssl', 'pkey', '-in', str(key), '-pubout', '-out', str(public)])
    manifests = {}
    for name, archive in [('legacy8', a.legacy_archive), ('helper9', helper9), ('role9', a.role_archive), ('both10', both10)]:
        out = a.out / ('manifest-' + name)
        run('produce-' + name, ['/usr/bin/python3', '-I', '-B', str(source / 'deploy/headless/make_headless_manifest.py'),
            '--version', VERSION, '--base-url', 'http://127.0.0.1:8080', '--private-key', str(key),
            '--artifact', str(a.artifact), '--provisioning', str(archive), '--out-dir', str(out)])
        manifests[name] = out / 'manifest.json'
        check('canonical-verify-' + name, lambda path=manifests[name]: selected.verify_manifest(path, key, VERSION, {'linux-headless-x64'}, False))
    check('baseline-manifest-rejects-role', lambda: canonical.verify_manifest(manifests['role9'], key, VERSION, {'linux-headless-x64'}, False), False)
    def signed(name, mutation):
        payload, _, _ = selected.decode_manifest_envelope(manifests['role9'].read_bytes())
        mutation(payload)
        raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()
        envelope = dict(schema='amnezia-selfhosted-update-v1', signatureAlgorithm='Ed25519',
                        payload=selected.b64url(raw), signature=selected.sign_payload(key, raw))
        context = a.out / ('signed-' + name)
        shutil.copytree(manifests['role9'].parent, context)
        path = context / 'manifest.json'; path.write_text(json.dumps(envelope) + '\n'); return path
    bad_order = signed('bad-order', lambda body: body['headlessProvisioning']['packageFiles'].reverse())
    check('reject-real-signed-wrong-order', lambda: selected.verify_manifest(bad_order, key, VERSION, {'linux-headless-x64'}, False), False)
    bad_sig = json.loads(manifests['role9'].read_text()); sig = bad_sig['signature']
    bad_sig['signature'] = ('A' if sig[0] != 'A' else 'B') + sig[1:]
    bad_sig_context = a.out / 'bad-signature-context'
    shutil.copytree(manifests['role9'].parent, bad_sig_context)
    bad_sig_path = bad_sig_context / 'manifest.json'; bad_sig_path.write_text(json.dumps(bad_sig))
    check('reject-signature', lambda: selected.verify_manifest(bad_sig_path, key, VERSION, {'linux-headless-x64'}, False),
          False, signature_failure=True)
    assert 'signature' in checks[-1]['error'].lower(), checks[-1]
    tampered_output = a.out / 'post-sign-provisioning-tamper'
    shutil.copytree(manifests['role9'].parent, tampered_output)
    provisioning_copies = list((tampered_output / 'files/artifacts').glob('*/AmneziaHeadless_1.0.0.42_linux_x64_provisioning.tar.gz'))
    assert len(provisioning_copies) == 1
    altered = bytearray(provisioning_copies[0].read_bytes()); altered[0] ^= 1
    provisioning_copies[0].write_bytes(altered)
    check('reject-provisioning-bytes-after-signing',
          lambda: selected.verify_manifest(tampered_output / 'manifest.json', key, VERSION, {'linux-headless-x64'}, False), False)
    # Compile the actual whole decoder TU, independently of function isolation below.
    cpp = source / 'headless/headlessUpdateManager.cpp'
    includes = ['-I' + str(source / 'client'), '-I' + str(a.source / 'headless'), '-I' + str(qt / 'include'),
                '-I' + str(qt / 'include/QtCore'), '-I' + str(qt / 'include/QtNetwork')]
    bind_dependencies('whole-decoder', cpp, includes)
    run('whole-decoder-api', ['/usr/bin/c++', '-std=c++17', '-fPIC', '-c', str(cpp), *includes,
                             '-o', str(a.out / 'whole-decoder.o')])
    # The other real consumer uses a quoted sibling include: copy that unchanged
    # TU beside the selected header and keep its actual product compile command.
    bootstrap_rel = 'client/core/controllers/selfhosted/selfHostedUpdateBootstrapper.cpp'
    filecopy(a.source / bootstrap_rel, source / bootstrap_rel)
    db = Path('/home/ivano/amnezia-product-50318-q/product-linux-build-c/build/compile_commands.json')
    compile_rows = json.loads(read(db))
    row, = [item for item in compile_rows if item['file'] == str(a.source / bootstrap_rel)]
    argv = shlex.split(row['command'])
    argv[argv.index('-c') + 1] = str(source / bootstrap_rel)
    argv[argv.index('-o') + 1] = str(a.out / 'whole-bootstrapper.o')
    argv[1:1] = ['-I' + str(source / 'client')]
    argv += ['-iquote', str((a.source / bootstrap_rel).parent), '-MD', '-MF', str(a.out / 'whole-bootstrapper.d')]
    run('whole-bootstrapper-api', argv, cwd=row['directory'])
    for token in shlex.split((a.out / 'whole-bootstrapper.d').read_text().replace('\\\n', ' ').split(':', 1)[1]):
        path = Path(token)
        if not path.is_absolute(): path = Path(row['directory']) / path
        inputs[str(path)] = sha(path.read_bytes())
    contract_rel = 'client/tests/headless_provisioning_contract/tst_headless_provisioning_contract.cpp'
    if (a.subject / contract_rel).is_file():
        filecopy(a.subject / contract_rel, source / contract_rel)
        unit = source / contract_rel
        common = ['-std=c++17', '-fPIC', '-I' + str(qt / 'include'), '-I' + str(qt / 'include/QtCore')]
        for lane, headers, expected in [('baseline', baseline_root / 'client', 1), ('selected', source / 'client', 0)]:
            binary = a.out / ('contract-' + lane)
            run('contract-compile-' + lane, ['/usr/bin/c++', *common, '-I' + str(headers), str(unit),
                '-L' + str(qt / 'lib'), '-lQt6Core', '-Wl,-rpath,' + str(qt / 'lib'), '-o', str(binary)])
            run('contract-' + lane, [str(binary)], expected=expected)
        unit_rel = 'headless/tests/tst_headless_updates.cpp'
        filecopy(a.subject / unit_rel, source / unit_rel)
        unit = source / unit_rel
        unit_flags = includes + ['-I' + str(qt / 'include/QtTest'), '-I' + str(a.out),
                                 '-DAMNEZIA_HEADLESS_VERSION="1.0.0.42"']
        moc = qt / 'libexec/moc'; inputs[str(moc)] = sha(moc.read_bytes())
        run('headless-unit-moc', [str(moc), *unit_flags, str(unit), '-o', str(a.out / 'tst_headless_updates.moc')])
        bind_dependencies('headless-unit', unit, unit_flags)
        run('headless-unit-api', ['/usr/bin/c++', '-std=c++17', '-fPIC', '-c', str(unit), *unit_flags,
                                  '-o', str(a.out / 'tst_headless_updates.o')])
    cpp_text = read(cpp)
    def method(signature):
        start = cpp_text.index(signature); end = cpp_text.index('\n}', start) + 2
        return cpp_text[start:end] + '\n'
    prefix = cpp_text[:cpp_text.index('HeadlessUpdateManager::HeadlessUpdateManager(')]
    body = prefix + '\n#define QFileInfo anchor_model::FileInfo\n#define QFile anchor_model::File\n'
    body += method('QString HeadlessUpdateManager::trustedUpdatePublicKeyPath()')
    body += method('bool HeadlessUpdateManager::verifyTrustedKey(')
    body += '\n#undef QFile\n#undef QFileInfo\n'
    for signature in ['HeadlessUpdateResult HeadlessUpdateManager::parseManifest(',
                      'bool HeadlessUpdateManager::verifyEnvelope(', 'bool HeadlessUpdateManager::decodeStrict(',
                      'bool HeadlessUpdateManager::validVersion(', 'bool HeadlessUpdateManager::validSha256(',
                      'bool HeadlessUpdateManager::validArtifactUrl(']:
        body += method(signature)
    body += '''
// Fixture storage constructor only: no initialization/GC/runner or host IO occurs.
HeadlessUpdateManager::HeadlessUpdateManager(std::shared_ptr<CommandRunner> runner,
    QString statePath, QString installDirectory, bool requireRootOwnedFiles)
    : m_runner(std::move(runner)), m_statePath(std::move(statePath)),
      m_installDirectory(std::move(installDirectory)), m_requireRootOwnedFiles(requireRootOwnedFiles) {}
} // namespace amnezia::headless
'''
    (a.out / 'actual_decoder.inc').write_text(body)
    filecopy(here / 'parse_driver.cpp', a.out / 'parse_driver.cpp')
    bind_dependencies('actual-parser', a.out / 'parse_driver.cpp', includes + ['-I' + str(a.out)])
    run('actual-parser-compile', ['/usr/bin/c++', '-std=c++17', '-O0', '-fPIC', '-ffunction-sections', '-fdata-sections',
        str(a.out / 'parse_driver.cpp'), *includes, '-I' + str(a.out), '-Wl,--gc-sections',
        '-L' + str(qt / 'lib'), '-lQt6Network', '-lQt6Core', '-lcrypto', '-Wl,-rpath,' + str(qt / 'lib'),
        '-o', str(a.out / 'actual-parser')])
    for name, path in manifests.items():
        run('parse-' + name, [str(a.out / 'actual-parser'), str(path), str(public), 'update_available', 'good', '1.0.0.41'])
    for name, path, expected, model, current in [
        ('legacy-noop', manifests['legacy8'], 'no_update', 'good', VERSION),
        ('role-noop', manifests['role9'], 'no_update', 'good', VERSION),
        ('signed-order', bad_order, 'invalid_manifest', 'good', '1.0.0.41'),
        ('order-before-noop', bad_order, 'invalid_manifest', 'good', VERSION),
        ('bad-signature', bad_sig_path, 'signature_invalid', 'good', '1.0.0.41')]:
        run('parse-' + name, [str(a.out / 'actual-parser'), str(path), str(public), expected, model, current])
    for mode in ['wrong-owner', 'writable', 'symlink', 'not-regular', 'wrong-path', 'partial-read', 'changed-key', 'oversize', 'open-failed']:
        run('anchor-' + mode, [str(a.out / 'actual-parser'), str(manifests['role9']), str(public), 'signature_invalid', mode, '1.0.0.41'])
    # The same actual decoder/anchor-IO fixture reaches the canonical missing
    # behavior, rather than treating an isolated header boolean as the RED.
    baseline_text = read(baseline_root / 'headless/headlessUpdateManager.cpp')
    baseline_prefix = baseline_text[:baseline_text.index('HeadlessUpdateManager::HeadlessUpdateManager(')]
    baseline_body = body.replace(prefix, baseline_prefix, 1)
    for signature in ['QString HeadlessUpdateManager::trustedUpdatePublicKeyPath()',
                      'bool HeadlessUpdateManager::verifyTrustedKey(',
                      'HeadlessUpdateResult HeadlessUpdateManager::parseManifest(',
                      'bool HeadlessUpdateManager::verifyEnvelope(', 'bool HeadlessUpdateManager::decodeStrict(',
                      'bool HeadlessUpdateManager::validVersion(', 'bool HeadlessUpdateManager::validSha256(',
                      'bool HeadlessUpdateManager::validArtifactUrl(']:
        start = baseline_text.index(signature); end = baseline_text.index('\n}', start) + 2
        selected_method = method(signature)
        assert baseline_body.count(selected_method) == 1
        baseline_body = baseline_body.replace(selected_method, baseline_text[start:end] + '\n', 1)
    baseline_dir = a.out / 'baseline-decoder'; baseline_dir.mkdir(mode=0o700)
    (baseline_dir / 'actual_decoder.inc').write_text(baseline_body)
    filecopy(here / 'parse_driver.cpp', baseline_dir / 'parse_driver.cpp')
    run('baseline-parser-compile', ['/usr/bin/c++', '-std=c++17', '-O0', '-fPIC', '-ffunction-sections', '-fdata-sections',
        str(baseline_dir / 'parse_driver.cpp'), *includes, '-Wl,--gc-sections',
        '-L' + str(qt / 'lib'), '-lQt6Network', '-lQt6Core', '-lcrypto', '-Wl,-rpath,' + str(qt / 'lib'),
        '-o', str(baseline_dir / 'actual-parser')])
    for name, expected in [('legacy8', 'update_available'), ('role9', 'invalid_manifest')]:
        run('baseline-parse-' + name, [str(baseline_dir / 'actual-parser'), str(manifests[name]), str(public),
                                       expected, 'good', '1.0.0.41'])
    if a.fail_work: raise WorkFailure('deliberate work-body failure through this actual authority/decoder runner')
    code = 0; result['componentPass'] = True
except WorkFailure as error:
    result.update(exceptionType=type(error).__name__, exception=str(error)); code = 23
except Exception as error:
    result.update(exceptionType=type(error).__name__, exception=str(error)); code = 1
finally:
    changed = [path for path, digest in inputs.items() if not Path(path).is_file() or sha(Path(path).read_bytes()) != digest]
    if changed: code = 1; result['componentPass'] = False
    result.update(nativeExit=code, inputsUnchanged=not changed, changedInputs=changed, inputCount=len(inputs),
                  checks=checks, finishedUtc=now())
    (a.out / 'INPUTS_BEFORE.json').write_text(json.dumps(inputs, indent=2) + '\n')
    (a.out / 'RESULT.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: result[key] for key in ['nativeExit', 'componentPass', 'inputsUnchanged', 'inputCount', 'exception'] if key in result}))
sys.exit(code)
