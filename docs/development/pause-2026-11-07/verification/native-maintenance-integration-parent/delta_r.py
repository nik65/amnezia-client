"""R cleanup delta against M's caller safety matrix, with corrected real-backend contract."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys

p = argparse.ArgumentParser()
p.add_argument('--review', type=Path, required=True)
p.add_argument('--out', type=Path, required=True)
a = p.parse_args()
q = Path(__file__).resolve().parent.parent
m = q / 'native-controller-maintenance-parent/attempt-20261107T132500Z/green'
r = q / 'native-controller-backend-r/backend'
qt = Path('/home/ivano/Qt/6.10.1/gcc_64')
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
a.out.mkdir(parents=True, mode=0o700, exist_ok=False)
inputs = {}
result = dict(startedUtc=datetime.now(timezone.utc).isoformat(), commands=[], componentPass=False,
    allFunctionsPass=False, releasePass=False, published=False,
    scope='Typed inert SSH caller safety regression only. Real backend behavior is independently exercised in the parent R review. Prior two invalid mandatory-distinct assertions are replaced by strict same-byte no-op checks; original history remains intact.')
code = 1

def read(path):
    inputs[str(path)] = sha(path)
    return path.read_text()

def write(name, text):
    with (a.out / name).open('x') as f: f.write(text)

def change(text, old, new):
    assert text.count(old) == 1, (old[:80], text.count(old))
    return text.replace(old, new, 1)

def run(label, argv):
    with (a.out / (label + '.stdout')).open('xb') as out, (a.out / (label + '.stderr')).open('xb') as err:
        status = subprocess.run(argv, env=env, stdout=out, stderr=err, timeout=120).returncode
    result['commands'].append(dict(label=label, argv=argv, nativeExit=status))
    print(label, status, flush=True)
    return status

try:
    review = json.loads(read(a.review / 'RESULT.json'))
    assert review['componentPass'] and review['inputsUnchanged']
    fixture = read(m / 'fixture.cpp')
    begin = fixture.index('            if (flags.value(QStringLiteral("--native-control-sha256"))')
    end = fixture.index('            if (mode == QStringLiteral("nativefail")', begin)
    removed = fixture[begin:end]
    assert 'native_control_replacement_sha256_mismatch' in removed
    fixture = fixture[:begin] + fixture[end:]
    anchor = '            const bool pending = mode == QStringLiteral("pending");'
    fixture = change(fixture, anchor, '''            // Typed IO model only: footprint corroborated by actual runMaintenance in R.
            // Same-byte native maintenance is a strict no-op, not a failure.
            if (flags.value(QStringLiteral("--native-control-sha256"))
                    != flags.value(QStringLiteral("--native-control-replacement-sha256"))) {
                const QString staging = flags.value(QStringLiteral("--control-staging-directory"));
                const QString digest = flags.value(QStringLiteral("--native-control-replacement-sha256"));
                const QString context = staging + QStringLiteral("/context-") + digest;
                model::mkdirp(context, 0, 0, 0700);
                for (const QString &path : {staging + QStringLiteral("/awg-feed-") + digest + QStringLiteral(".bin"),
                        context + QStringLiteral("/awg-feed"), context + QStringLiteral("/Dockerfile"),
                        context + QStringLiteral("/image.iid")}) {
                    model::Entry file; file.uid = 0; file.gid = 0; file.mode = 0500;
                    file.ino = model::nextIno++; model::fs.insert(path, file);
                }
            }
''' + anchor)
    write('fixture.cpp', fixture)
    tests = read(m / 'tests.cpp')
    tests = change(tests,
        '&& hasExactRemoval({QStringLiteral("rm"), QStringLiteral("-f"), QStringLiteral("--"), helperPath, recipePath})',
        '&& hasExactRemoval({QStringLiteral("rm"), QStringLiteral("-f"), QStringLiteral("--"), helperPath, recipePath,\n'
        '              stagingPath + QStringLiteral("/awg-feed-") + feed + QStringLiteral(".bin"),\n'
        '              stagingPath + QStringLiteral("/context-") + feed + QStringLiteral("/awg-feed"),\n'
        '              stagingPath + QStringLiteral("/context-") + feed + QStringLiteral("/Dockerfile"),\n'
        '              stagingPath + QStringLiteral("/context-") + feed + QStringLiteral("/image.iid")})\n'
        '          && hasExactRemoval({QStringLiteral("rmdir"), QStringLiteral("--"),\n'
        '              stagingPath + QStringLiteral("/context-") + feed})')
    tests = change(tests,
        'check(QStringLiteral("equal_current_replacement_not_accepted"),\n          equalError != ErrorCode::NoError && model::execs == 1);',
        'check(QStringLiteral("equal_current_replacement_real_noop_accepted"),\n          equalError == ErrorCode::NoError && model::execs == 1);')
    tests = change(tests,
        'check(QStringLiteral("equal_current_replacement_retains_recovery_inputs"),\n          equalReplacement.value(QStringLiteral("retainedDirectory")).toString() == dirPath);',
        'check(QStringLiteral("equal_current_replacement_noop_cleanup_complete"),\n          !equalReplacement.contains(QStringLiteral("retainedDirectory")) && !model::fs.contains(dirPath));')
    write('tests.cpp', tests)
    for name in ['awgMaintenanceCommand.h', 'awgMaintenanceReceipt.h', 'native.rcc', 'legacy.rcc']:
        source = a.review / 'backend' / name
        inputs[str(source)] = sha(source)
        (a.out / name).write_bytes(source.read_bytes())
    write('method.inc', read(r / 'method_green.inc'))
    write('CMakeLists.txt', read(m / 'CMakeLists.txt'))
    env = dict(PATH='/usr/bin:/bin', HOME=str(a.out), LANG='C', LC_ALL='C',
               LD_LIBRARY_PATH=str(qt / 'lib'), AWG_FIXTURE_RES=str(a.out))
    code = run('configure', ['/usr/bin/cmake', '-S', str(a.out), '-B', str(a.out / 'build'),
                             '-DCMAKE_PREFIX_PATH=' + str(qt)])
    if code == 0: code = run('build', ['/usr/bin/cmake', '--build', str(a.out / 'build'), '-j1'])
    if code == 0: code = run('caller-safety-delta', [str(a.out / 'build/awg_maintenance_caller_parent_m')])
    result['componentPass'] = code == 0
except Exception as error:
    result.update(exceptionType=type(error).__name__, exception=str(error)); code = 1
finally:
    changed = [path for path, digest in inputs.items() if sha(Path(path)) != digest]
    result.update(inputsUnchanged=not changed, changedInputs=changed,
                  nativeExit=code, finishedUtc=datetime.now(timezone.utc).isoformat())
    if changed: result['componentPass'] = False; code = 1; result['nativeExit'] = code
    (a.out / 'INPUTS_BEFORE.json').write_text(json.dumps(inputs, indent=2) + '\n')
    (a.out / 'RESULT.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: result[key] for key in ['nativeExit', 'componentPass', 'inputsUnchanged', 'exception'] if key in result}))
sys.exit(code)
