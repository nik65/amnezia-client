"""Build the actual candidate CMake verifier; inspect only, never run it."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys

p = argparse.ArgumentParser()
p.add_argument('--source-manifest', type=Path, required=True)
p.add_argument('--out', type=Path, required=True)
p.add_argument('--reuse-build', type=Path)
p.add_argument('--fail-work', action='store_true')
a = p.parse_args()
assert os.geteuid() != 0
os.umask(0o077)
a.out.mkdir(parents=True, mode=0o700, exist_ok=False)
private = a.out / 'private-tmp'; private.mkdir(mode=0o700)
root = Path('/home/ivano/codex-amnezia-upstream-20261104')
source = root / 'deploy/headless/native/provisioning_verifier'
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
now = lambda: datetime.now(timezone.utc).isoformat()
env = dict(PATH='/usr/bin:/bin', HOME=str(a.out), TMPDIR=str(private), LANG='C', LC_ALL='C', GIT_OPTIONAL_LOCKS='0')
os.environ.update(env)
inputs = {}; labels = set(); code = 1
result = dict(startedUtc=now(), commands=[], componentPass=False, allFunctionsPass=False, releasePass=False,
              published=False, scope='Actual standalone candidate CMake target, compile/link/readelf only. No execution of resulting product or installer, no host probe, root wrapper, guest, phone, service, network or VPN operation.')

class WorkError(Exception):
    def __init__(self, label, status):
        super().__init__(label + ' native exit ' + str(status)); self.status = status

def pin(path):
    assert path.is_file(), path
    digest = sha(path)
    if str(path) in inputs: assert inputs[str(path)] == digest, path
    inputs[str(path)] = digest

def run(label, argv, timeout=180):
    assert label not in labels, label
    labels.add(label)
    started = now()
    with (a.out / (label + '.stdout')).open('xb') as stdout, (a.out / (label + '.stderr')).open('xb') as stderr:
        process = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, env=env, timeout=timeout)
    result['commands'].append(dict(label=label, argv=argv, cwd=str(Path.cwd()), env=env,
                                   startedUtc=started, finishedUtc=now(), nativeExit=process.returncode))
    print(label, process.returncode, flush=True)
    if process.returncode: raise WorkError(label, process.returncode)
    return (a.out / (label + '.stdout')).read_text()

try:
    pin(a.source_manifest); pin(Path(__file__).resolve())
    manifest = json.loads(a.source_manifest.read_text())
    names = {row['path'] for row in manifest}
    required = {str(path.relative_to(root)) for path in [source / 'CMakeLists.txt', source / 'verify_provisioning.cpp',
        source / 'bootstrap_n.cpp', source / 'preauth_modes.cpp', source / 'host_runtime.inc']}
    assert required <= names and len(names) == len(manifest)
    for row in manifest:
        path = root / row['path']; assert sha(path) == row['sha256'] and path.stat().st_size == row['size'], path; pin(path)
    for path in [root / '.git/index', Path('/mnt/c/Users/ivano/PycharmProjects/amnezia-client/.git/index'),
                 Path('/usr/bin/cmake'), Path('/usr/bin/ninja'), Path('/usr/bin/c++'), Path('/usr/bin/readelf'),
                 Path('/usr/bin/as'), Path('/usr/bin/ld'), Path('/usr/bin/python3')]:
        pin(path); pin(path.resolve())
    if a.reuse_build:
        pin(a.reuse_build)
        old = json.loads(a.reuse_build.read_text())
        assert old['nativeExit'] == 0 and old['componentPass'] and old['inputsUnchanged']
        assert old['manifestSha256'] == sha(a.source_manifest)
        old_inputs = a.reuse_build.parent / 'INPUTS_BEFORE.json'; pin(old_inputs)
        for path, digest in json.loads(old_inputs.read_text()).items():
            assert sha(Path(path)) == digest, path; pin(Path(path))
        artifact = Path(old['artifact']['path'])
        assert sha(artifact) == old['artifact']['sha256']
        result['reusedBuildReceipt'] = dict(path=str(a.reuse_build), sha256=sha(a.reuse_build),
                                          originalBuildContext=old['commands'])
    else:
        run('compiler-version', ['/usr/bin/c++', '--version'])
        run('cmake-version', ['/usr/bin/cmake', '--version'])
        build = a.out / 'build'
        run('cmake-configure', ['/usr/bin/cmake', '-S', str(source), '-B', str(build), '-G', 'Ninja',
             '-DCMAKE_BUILD_TYPE=Release', '-DBUILD_TESTING=OFF', '-DCMAKE_EXPORT_COMPILE_COMMANDS=ON'])
        for path in [build / 'CMakeCache.txt', build / 'build.ninja', build / 'CMakeFiles/rules.ninja',
                     build / 'compile_commands.json']:
            pin(path)
        commands = json.loads((build / 'compile_commands.json').read_text())
        assert len(commands) == 1 and Path(commands[0]['file']) == source / 'bootstrap_n.cpp', commands
        tokens = shlex.split(commands[0]['command'])
        filtered = []; index = 0
        while index < len(tokens):
            if tokens[index] == '-o': index += 2
            elif tokens[index] == '-c': index += 1
            else: filtered.append(tokens[index]); index += 1
        deps = a.out / 'compiler-dependencies.d'
        run('compiler-dependencies', [*filtered, '-M', '-MF', str(deps)])
        dependency_paths = [Path(value) for value in shlex.split(deps.read_text().replace('\\\n', ' ').split(':', 1)[1])]
        assert {source / name for name in ['bootstrap_n.cpp', 'preauth_modes.cpp', 'verify_provisioning.cpp', 'host_runtime.inc']} <= set(dependency_paths)
        for path in dependency_paths: pin(path)
        # Bind actual static link inputs before building, including the compiler's CRT/runtime.
        cache = (build / 'CMakeCache.txt').read_text()
        for line in cache.splitlines():
            if line and not line.startswith(('#', '//')) and '=' in line:
                value = line.split('=', 1)[1]
                if value.startswith('/') and Path(value).is_file() and (value.endswith(('.a', '.o')) or '/bin/' in value):
                    pin(Path(value)); pin(Path(value).resolve())
        for name in ['libstdc++.a', 'libgcc.a', 'libgcc_eh.a', 'libc.a', 'libm.a', 'libdl.a', 'libpthread.a', 'liblto_plugin.so',
                     'crt1.o', 'crti.o', 'crtn.o', 'crtbeginT.o', 'crtend.o']:
            value = run('link-input-' + name.replace('.', '-'), ['/usr/bin/c++', '-print-file-name=' + name]).strip()
            path = Path(value); assert path.is_absolute() and path.is_file(), (name, value); pin(path); pin(path.resolve())
            if path.stat().st_size < 4096:
                text = path.read_bytes().decode('ascii', errors='ignore')
                if 'GROUP' in text:
                    for member in re.findall(r'/[^\s()]+\.a', text):
                        pin(Path(member)); pin(Path(member).resolve())
        for name in ['cc1plus', 'collect2']:
            path = Path(run('compiler-tool-' + name, ['/usr/bin/c++', '-print-prog-name=' + name]).strip())
            assert path.is_absolute() and path.is_file(); pin(path); pin(path.resolve())
        run('cmake-build', ['/usr/bin/cmake', '--build', str(build), '--target', 'amnezia-verify-provisioning-native', '--parallel', '2', '--verbose'], timeout=300)
        artifact = build / 'amnezia-verify-provisioning-native'
        result['compileCommands'] = commands
    pin(artifact)
    header = run('readelf-header', ['/usr/bin/readelf', '-hW', str(artifact)])
    programs = run('readelf-programs', ['/usr/bin/readelf', '-lW', str(artifact)])
    dynamic = run('readelf-dynamic', ['/usr/bin/readelf', '-dW', str(artifact)])
    assert 'ELF64' in header and re.search(r'Type:\s+EXEC\b', header) and 'Advanced Micro Devices X86-64' in header
    assert 'INTERP' not in programs and 'DYNAMIC' not in programs and 'There is no dynamic section' in dynamic
    assert 0 < artifact.stat().st_size <= 8 * 1024 * 1024
    result['artifact'] = dict(path=str(artifact), size=artifact.stat().st_size, sha256=sha(artifact), executed=False,
                              staticElf64X86_64=True, notFinalDelivery=True)
    if a.fail_work: run('actual-deliberate-failed-work', ['/usr/bin/python3', '-I', '-B', '-c', 'raise SystemExit(23)'])
    code = 0; result['componentPass'] = True
except WorkError as error:
    result.update(exceptionType=type(error).__name__, exception=str(error)); code = error.status
except Exception as error:
    result.update(exceptionType=type(error).__name__, exception=str(error)); code = 1
finally:
    changed = [path for path, digest in inputs.items() if not Path(path).is_file() or sha(Path(path)) != digest]
    if changed: code = 1; result['componentPass'] = False
    result.update(nativeExit=code, inputCount=len(inputs), inputsUnchanged=not changed, changedInputs=changed,
                  manifestSha256=sha(a.source_manifest), finishedUtc=now())
    (a.out / 'INPUTS_BEFORE.json').write_text(json.dumps(inputs, indent=2) + '\n')
    (a.out / 'RESULT.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key:result[key] for key in ['nativeExit', 'componentPass', 'inputCount', 'inputsUnchanged', 'artifact', 'exception'] if key in result}), flush=True)
sys.exit(code)
