"""Final R integration gate: canonical full APIs and fresh inert fixture builds."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import sys

p = argparse.ArgumentParser()
p.add_argument('--source', type=Path, required=True)
p.add_argument('--manifest', type=Path, required=True)
p.add_argument('--review', type=Path, required=True)
p.add_argument('--delta', type=Path, required=True)
p.add_argument('--out', type=Path, required=True)
p.add_argument('--suite', choices=['all', 'failedwork'], default='all')
a = p.parse_args()
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
now = lambda: datetime.now(timezone.utc).isoformat()
a.out.mkdir(mode=0o700, parents=True, exist_ok=False)
tmp = a.out / 'private-tmp'; tmp.mkdir(mode=0o700)
conf = a.out / 'openssl-empty.cnf'; conf.write_text('')
qt = Path('/home/ivano/Qt/6.10.1/gcc_64')
env = dict(PATH='/usr/bin:/bin', HOME=str(a.out), TMPDIR=str(tmp), LANG='C', LC_ALL='C',
           LD_LIBRARY_PATH=str(qt / 'lib'), OPENSSL_CONF=str(conf))
result = dict(startedUtc=now(), suite=a.suite, commands=[], componentPass=False,
              allFunctionsPass=False, releasePass=False, published=False,
              scope='Canonical complete controller/application TUs compile only. Freshly built inert R actual-core bridge and M caller safety matrix execute. Root metadata/SSH cleanup remain models; no product/app/installer/SSH/network/service/guest/phone execution.')
inputs = {}; code = 1

def read(path):
    inputs[str(path)] = sha(path)
    return path.read_text()

def copy(path, dest):
    inputs[str(path)] = sha(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(path, dest)

def run(label, argv, cwd=None, timeout=180):
    started = now()
    with (a.out / (label + '.stdout')).open('xb') as out, (a.out / (label + '.stderr')).open('xb') as err:
        try: status = subprocess.run(argv, cwd=cwd, env=env, stdout=out, stderr=err, timeout=timeout).returncode
        except subprocess.TimeoutExpired: status = 124
    result['commands'].append(dict(label=label, argv=argv, cwd=str(cwd) if cwd else None,
        nativeExit=status, startedUtc=started, finishedUtc=now()))
    print(label, status, flush=True)
    return status

def require(status, label):
    if status: raise RuntimeError(label + ' exit=' + str(status))

try:
    review_result = json.loads(read(a.review / 'RESULT.json'))
    delta_result = json.loads(read(a.delta / 'RESULT.json'))
    assert review_result['componentPass'] and delta_result['componentPass']
    rows = json.loads(read(a.manifest))
    for row in rows:
        path = a.source / row['path']
        assert sha(path) == row['sha256'], row['path']
        inputs[str(path)] = row['sha256']
    result['sourceManifest'] = dict(path=str(a.manifest), sha256=sha(a.manifest), count=len(rows))
    for path in [a.source / '.git/index',
                 Path('/mnt/c/Users/ivano/PycharmProjects/amnezia-client/.git/index'),
                 Path(__file__).resolve(), Path('/usr/bin/c++').resolve(),
                 Path('/usr/bin/cmake').resolve(), qt / 'lib/libQt6Core.so.6']:
        inputs[str(path)] = sha(path)
    db = Path('/home/ivano/amnezia-product-50318-q/product-linux-build-c/build/compile_commands.json')
    commands = json.loads(read(db))
    for rel in ['client/core/controllers/selfhosted/installController.cpp', 'client/amneziaApplication.cpp']:
        row, = [item for item in commands if item['file'] == str(a.source / rel)]
        label = 'canonical-api-' + Path(rel).stem
        obj = a.out / (label + '.o'); dep = a.out / (label + '.d')
        argv = shlex.split(row['command'])
        argv[argv.index('-o') + 1] = str(obj)
        argv += ['-MD', '-MF', str(dep)]
        require(run(label, argv, row['directory']), label)
        deps = shlex.split(dep.read_text().replace('\\\n', ' ').split(':', 1)[1])
        for value in deps:
            path = Path(value)
            if not path.is_absolute(): path = Path(row['directory']) / path
            inputs[str(path)] = sha(path)
        result.setdefault('compiledObjects', []).append(dict(path=str(obj), sha256=sha(obj), dependencies=len(deps)))
    cpp = read(a.source / 'client/core/controllers/selfhosted/installController.cpp')
    start = cpp.index('ErrorCode InstallController::maintainAwgMigrationControls(')
    end = cpp.index('ErrorCode InstallController::prepareAwgMigration(', start)
    method = cpp[start:end].rstrip() + '\n'
    expected_method = read(a.review / 'backend/method_green.inc').rstrip() + '\n'
    assert method == expected_method
    # Fresh builds use the actual integrated method and physical headers.
    backend = a.out / 'backend'; backend.mkdir(mode=0o700)
    for name in ['fixture_backend.cpp', 'tests_backend.cpp', 'method_red.inc', 'native.rcc', 'legacy.rcc', 'CMakeLists.txt']:
        copy(a.review / 'backend' / name, backend / name)
    (backend / 'method_green.inc').write_text(method)
    safety = a.out / 'safety'; safety.mkdir(mode=0o700)
    for name in ['fixture.cpp', 'tests.cpp', 'CMakeLists.txt']:
        copy(a.delta / name, safety / name)
    (safety / 'method.inc').write_text(method)
    for dest in [backend, safety]:
        copy(a.source / 'client/core/controllers/selfhosted/awgMaintenanceReceipt.h', dest / 'awgMaintenanceReceipt.h')
        copy(a.source / 'client/core/utils/awgMaintenanceCommand.h', dest / 'awgMaintenanceCommand.h')
    for name in ['native.rcc', 'legacy.rcc']: copy(backend / name, safety / name)
    for label, folder in [('backend', backend), ('safety', safety)]:
        build = folder / 'build'
        require(run('configure-' + label, ['/usr/bin/cmake', '-S', str(folder), '-B', str(build),
                                          '-DCMAKE_PREFIX_PATH=' + str(qt)]), 'configure-' + label)
        require(run('build-' + label, ['/usr/bin/cmake', '--build', str(build), '-j1'], timeout=240), 'build-' + label)
    env['AWG_FIXTURE_RES'] = str(backend)
    red = run('actual-core-red', [str(backend / 'build/awg_backend_red')], timeout=20)
    argv = [str(backend / 'build/awg_backend_green')]
    if a.suite == 'failedwork': argv.append('--fail-work')
    selected = run('actual-core-selected', argv, timeout=20)
    env['AWG_FIXTURE_RES'] = str(safety)
    guard = run('caller-safety-matrix', [str(safety / 'build/awg_maintenance_caller_parent_m')], timeout=20)
    assert red == 1, red
    assert selected == (23 if a.suite == 'failedwork' else 0), selected
    assert guard == 0, guard
    code = selected
    result['componentPass'] = code == 0
except Exception as error:
    result.update(exceptionType=type(error).__name__, exception=str(error)); code = 1
finally:
    changed = [path for path, digest in inputs.items() if not Path(path).is_file() or sha(Path(path)) != digest]
    if changed: code = 1; result['componentPass'] = False
    result.update(inputsUnchanged=not changed, changedInputs=changed, inputCount=len(inputs),
                  nativeExit=code, finishedUtc=now())
    (a.out / 'INPUTS_BEFORE.json').write_text(json.dumps(inputs, indent=2) + '\n')
    (a.out / 'RESULT.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: result[key] for key in ['nativeExit', 'componentPass', 'inputsUnchanged', 'inputCount', 'exception'] if key in result}))
sys.exit(code)
