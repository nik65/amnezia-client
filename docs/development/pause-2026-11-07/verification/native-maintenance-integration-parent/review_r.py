"""Bounded parent review of R. Only inert fixtures execute; product TUs compile only."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys

p = argparse.ArgumentParser()
p.add_argument('--source', type=Path, required=True)
p.add_argument('--out', type=Path, required=True)
p.add_argument('--suite', choices=['all', 'failedwork'], default='all')
a = p.parse_args()
here = Path(__file__).resolve().parent
q = here.parent
r = q / 'native-controller-backend-r/backend'
j = q / 'native-controller-maintenance-j/attempt-20261107T091953Z/patched'
m = q / 'native-controller-maintenance-parent/attempt-20261107T132500Z/green'
qt = Path('/home/ivano/Qt/6.10.1/gcc_64')
manifest = Path('/home/ivano/amnezia-product-50318-q/native-cleanup-integrated-a/critical-a/MATERIALIZED_PRODUCT_SOURCE_MANIFEST.json')
db = Path('/home/ivano/amnezia-product-50318-q/product-linux-build-c/build/compile_commands.json')
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
now = lambda: datetime.now(timezone.utc).isoformat()
a.out.mkdir(parents=True, mode=0o700, exist_ok=False)
tmp = a.out / 'private-tmp'; tmp.mkdir(mode=0o700)
conf = a.out / 'openssl-empty.cnf'; conf.write_text('')
env = dict(PATH='/usr/bin:/bin', LANG='C', LC_ALL='C', HOME=str(a.out), TMPDIR=str(tmp),
           LD_LIBRARY_PATH=str(qt / 'lib'), OPENSSL_CONF=str(conf))
result = dict(startedUtc=now(), suite=a.suite, commands=[], componentPass=False,
              allFunctionsPass=False, releasePass=False, published=False,
              scope='Actual Qt method -> typed inert SSH -> actual parseRequest/runMaintenance/journal/validators/filesystem. Root metadata and SSH cleanup are models. Product controller and application TUs compile only; no product/app/installer/SSH/network/guest/phone execution.')
inputs = {}
code = 1

def read(path):
    inputs[str(path)] = sha(path)
    return path.read_text()

def copy(path, dest):
    inputs[str(path)] = sha(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(path, dest)

def replace_once(text, old, new):
    assert text.count(old) == 1, (old[:90], text.count(old))
    return text.replace(old, new, 1)

def write(dest, text):
    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open('x') as f: f.write(text)

def run(label, argv, cwd=None, timeout=180):
    started = now()
    with (a.out / (label + '.stdout')).open('xb') as out, (a.out / (label + '.stderr')).open('xb') as err:
        try:
            status = subprocess.run(argv, cwd=cwd, env=env, stdout=out, stderr=err, timeout=timeout).returncode
        except subprocess.TimeoutExpired:
            status = 124
    result['commands'].append(dict(label=label, argv=list(map(str, argv)), cwd=str(cwd) if cwd else None,
                                   nativeExit=status, startedUtc=started, finishedUtc=now()))
    print(label, status, flush=True)
    return status

def require(status, label):
    if status: raise RuntimeError(label + ' failed exit=' + str(status))

try:
    rows = json.loads(read(manifest))
    drift = [row['path'] for row in rows if sha(a.source / row['path']) != row['sha256']]
    assert not drift, drift
    result['sourceFence'] = dict(path=str(manifest), sha256=sha(manifest), count=len(rows))
    for row in rows: inputs[str(a.source / row['path'])] = row['sha256']
    windows_repo = next(parent for parent in q.parents if (parent / '.git/index').is_file())
    for index_path in [a.source / '.git/index', windows_repo / '.git/index']:
        inputs[str(index_path)] = sha(index_path)
    for tool in ['/usr/bin/c++', '/usr/bin/cmake', '/usr/bin/ld', '/usr/bin/python3']:
        path = Path(tool).resolve(); inputs[str(path)] = sha(path)
    inputs[str(Path(__file__).resolve())] = sha(Path(__file__).resolve())
    product = a.out / 'product'
    cpp_rel = 'client/core/controllers/selfhosted/installController.cpp'
    header_rel = 'client/core/controllers/selfhosted/installController.h'
    receipt_rel = 'client/core/controllers/selfhosted/awgMaintenanceReceipt.h'
    command_rel = 'client/core/utils/awgMaintenanceCommand.h'
    app_rel = 'client/amneziaApplication.cpp'
    base_cpp = read(a.source / cpp_rel)
    start = base_cpp.index('ErrorCode InstallController::maintainAwgMigrationControls(')
    end = base_cpp.index('ErrorCode InstallController::prepareAwgMigration(', start)
    method = read(r / 'method_green.inc')
    write(product / cpp_rel, base_cpp[:start] + method.rstrip() + '\n\n' + base_cpp[end:])
    header = replace_once(read(a.source / header_rel), '#include "core/utils/errorCodes.h"',
                          '#include "core/utils/errorCodes.h"\n#include "awgMaintenanceReceipt.h"')
    header = replace_once(header, 'const QString &expectedJournalSha256,\n            QJsonObject &result);',
                          'const QString &expectedJournalSha256,\n            const AwgMaintenance::Selection &selection, QJsonObject &result);')
    write(product / header_rel, header)
    copy(j / 'awgMaintenanceReceipt.h', product / receipt_rel)
    copy(j / 'awgMaintenanceCommand.h', product / command_rel)
    app = replace_once(read(a.source / app_rel),
        '                error = InstallController::maintainAwgMigrationControls(admin->credentials(), source,',
        '                AwgMaintenance::Selection selection;\n'
        '                selection.nativeControlVariant = selected.value("nativeControlVariant").toString();\n'
        '                selection.currentControlSha256 = selected.value("currentControlSha256").toString();\n'
        '                error = InstallController::maintainAwgMigrationControls(admin->credentials(), source,')
    app = replace_once(app, 'selected.value("expectedJournalSha256").toString(), receipt);',
                       'selected.value("expectedJournalSha256").toString(), selection, receipt);')
    write(product / app_rel, app)
    result['selectedProductFiles'] = {rel: sha(product / rel) for rel in [cpp_rel, header_rel, receipt_rel, command_rel, app_rel]}
    # Critical API smoke: actual complete translation units, not projected class declarations.
    commands = json.loads(read(db))
    for rel in [cpp_rel, app_rel]:
        row, = [row for row in commands if row['file'] == str(a.source / rel)]
        argv = shlex.split(row['command'])
        label = 'full-api-' + Path(rel).stem
        obj = a.out / (label + '.o')
        dep = a.out / (label + '.d')
        argv[argv.index('-o') + 1] = str(obj)
        argv[argv.index('-c') + 1] = str(product / rel)
        argv[1:1] = ['-I' + str(product / 'client')]
        # Original transitive quoted headers can find the original controller
        # before -I. Bind the complete selected header first, not a projection.
        if rel == app_rel:
            argv += ['-include', str(product / header_rel)]
        argv += ['-iquote', str((a.source / rel).parent), '-MD', '-MF', str(dep)]
        require(run(label, argv, row['directory']), label)
        dep_text = dep.read_text().replace('\\\n', ' ').split(':', 1)[1]
        dependencies = [Path(v) for v in shlex.split(dep_text)]
        for path in dependencies:
            path = path if path.is_absolute() else Path(row['directory']) / path
            inputs[str(path)] = sha(path)
        result.setdefault('compiledObjects', []).append(dict(path=str(obj), sha256=sha(obj), dependencies=len(dependencies)))
    # R real-backend harness: preserve its guards, replace only typed IO mechanics.
    fixture = read(r / 'fixture_backend.cpp')
    fixture = replace_once(fixture, 'inline Outcome run(const QStringList &argvList)\n{',
        'std::string deliveredRecipe(const std::filesystem::path &virtualRecipe);\n'
        'inline Outcome run(const QStringList &argvList)\n{')
    fixture = replace_once(fixture, '        request.root = fixture->root;',
        '        const std::string recipeBytes = deliveredRecipe(request.recipeDirectory);\n'
        '        awgfix::write(fixture->recipe / "awg-feed", recipeBytes);\n'
        '        request.root = fixture->root;')
    fixture = replace_once(fixture, 'QByteArray sha; };', 'QByteArray sha; QByteArray bytes; };')
    fixture = replace_once(fixture, 'e.sha = sha(bytes); model::fs.insert(name, e);',
                           'e.sha = sha(bytes); e.bytes = bytes; model::fs.insert(name, e);')
    fixture = replace_once(fixture, 'e.sha = source->sha; model::fs.insert(paths.at(i), e);',
                           'e.sha = source->sha; e.bytes = source->bytes; model::fs.insert(paths.at(i), e);')
    fixture += '''
namespace backend {
std::string deliveredRecipe(const std::filesystem::path &virtualRecipe) {
    const auto it = model::fs.constFind(QString::fromStdString(virtualRecipe.string()) + QStringLiteral("/awg-feed"));
    if (it == model::fs.constEnd() || it->dir || it->bytes.isEmpty()
        || SshSession::sha(it->bytes) != it->sha)
        throw std::runtime_error("typed SSH recipe was not delivered by actual upload/install");
    return std::string(it->bytes.constData(), size_t(it->bytes.size()));
}
}
'''
    tests = read(r / 'tests_backend.cpp')
    tests, header_count = re.subn(r'#include "[^"\n]*/(awgMaintenance(?:Command|Receipt)\.h)"',
                                 r'#include "\1"', tests)
    assert tests.count('#include "awgMaintenanceCommand.h"') == 1
    assert tests.count('#include "awgMaintenanceReceipt.h"') == 1
    tests = replace_once(tests,
        '    const QString base = QStringLiteral("/tmp/awg-backend-r-%1").arg(QCoreApplication::applicationPid());\n'
        '    QDir().mkpath(base);\n'
        '    QFile::setPermissions(base, QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner);\n'
        '    qputenv("TMPDIR", base.toUtf8());',
        '    const QString base = qEnvironmentVariable("TMPDIR");\n'
        '    if (base.isEmpty() || !QDir(base).exists()) return 90;')
    # Recipe input must be delivered by actual caller uploads, not independently preseeded by the case.
    lines = tests.splitlines(keepends=True)
    removed = [line for line in lines if 'awgfix::write(fixture.recipe / "awg-feed", selectedBytes);' in line]
    assert len(removed) == 4, removed
    tests = ''.join(line for line in lines if line not in removed)
    tests = replace_once(tests, '    return failures ? 1 : 0;',
        '    if (failures) return 1;\n'
        '    return app.arguments().contains(QStringLiteral("--fail-work")) ? 23 : 0;')
    work = a.out / 'backend'; work.mkdir(mode=0o700)
    write(work / 'fixture_backend.cpp', fixture)
    write(work / 'tests_backend.cpp', tests)
    for name in ['method_red.inc', 'method_green.inc', 'native.rcc', 'legacy.rcc']:
        copy(r / name, work / name)
    # The includes refer to the exact private selected API, not a stale J copy.
    for name, rel in [('awgMaintenanceCommand.h', command_rel), ('awgMaintenanceReceipt.h', receipt_rel)]:
        copy(product / rel, work / name)
    fixture_path = work / 'fixture_backend.cpp'
    fixture_text = fixture_path.read_text()
    fixture_text = fixture_text.replace(str(j / 'awgMaintenanceReceipt.h'), 'awgMaintenanceReceipt.h')
    fixture_text = fixture_text.replace(str(j / 'awgMaintenanceCommand.h'), 'awgMaintenanceCommand.h')
    fixture_path.write_text(fixture_text)
    cmake = read(r / 'CMakeLists.txt')
    write(work / 'CMakeLists.txt', cmake)
    build = a.out / 'build'
    require(run('configure', ['/usr/bin/cmake', '-S', str(work), '-B', str(build), '-DCMAKE_PREFIX_PATH=' + str(qt)]), 'configure')
    require(run('build-fixtures', ['/usr/bin/cmake', '--build', str(build), '-j1'], timeout=240), 'build')
    env['AWG_FIXTURE_RES'] = str(work)
    red = run('actual-backend-red', [str(build / 'awg_backend_red')], timeout=20)
    green_argv = [str(build / 'awg_backend_green')]
    if a.suite == 'failedwork': green_argv.append('--fail-work')
    green = run('actual-backend-green', green_argv, timeout=20)
    result['baselineNativeExit'] = red
    result['selectedNativeExit'] = green
    assert red == 1, red
    expected = 23 if a.suite == 'failedwork' else 0
    assert green == expected, green
    code = green
    result['componentPass'] = code == 0
except Exception as error:
    result.update(exceptionType=type(error).__name__, exception=str(error))
    code = 1
finally:
    changed = [path for path, digest in inputs.items() if not Path(path).is_file() or sha(Path(path)) != digest]
    result['inputsUnchanged'] = not changed
    result['changedInputs'] = changed
    if changed:
        code = 1; result['componentPass'] = False
    result.update(nativeExit=code, finishedUtc=now(), inputCount=len(inputs))
    (a.out / 'INPUTS_BEFORE.json').write_text(json.dumps(inputs, indent=2) + '\n')
    (a.out / 'RESULT.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: result[key] for key in ['nativeExit', 'componentPass', 'inputsUnchanged',
        'inputCount', 'exception'] if key in result}), flush=True)
sys.exit(code)
