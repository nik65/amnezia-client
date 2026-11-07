"""Corroborate actual host-probe input role, without OS probes."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

p = argparse.ArgumentParser()
p.add_argument('--stage-attempt', type=Path, required=True)
p.add_argument('--out', type=Path, required=True)
p.add_argument('--fail-work', action='store_true')
a = p.parse_args()
assert os.geteuid() != 0
os.umask(0o077)
a.out.mkdir(mode=0o700, parents=True, exist_ok=False)
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
inputs = {}; cases = []; status = 1
result = dict(componentPass=False, releasePass=False, allFunctionsPass=False, published=False,
    scope='Existing actual canonical inert main only. All dpkg execs mapped to one owned pure argv-checking worker; PATH presence checked against owned non-executed placeholder files. Not real host/runtime/dependency acceptance.')

def pin(path): inputs[str(path)] = sha(path)

def invoke(label, argv, expected, env):
    with (a.out/(label+'.stdout')).open('xb') as out, (a.out/(label+'.stderr')).open('xb') as err:
        proc = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=out, stderr=err, env=env, timeout=40)
    cases.append(dict(label=label, argv=argv, nativeExit=proc.returncode, expectedExit=expected))
    print(label, proc.returncode, flush=True)
    assert proc.returncode == expected, (label, proc.returncode, expected)
    return (a.out/(label+'.stdout')).read_text()

try:
    pin(Path(__file__).resolve())
    pin(a.stage_attempt/'RESULT.json'); pin(a.stage_attempt/'INPUTS_BEFORE.json')
    previous = json.loads((a.stage_attempt/'RESULT.json').read_text())
    assert previous['componentPass'] and previous['nativeExit']==0
    for path, digest in json.loads((a.stage_attempt/'INPUTS_BEFORE.json').read_text()).items():
        assert sha(Path(path))==digest, path; pin(Path(path))
    binary = a.stage_attempt/'inert-native-main'; pin(binary)
    raw_runtime = a.stage_attempt/'full-stage-role9-private/package/runtime-dependencies.json'; pin(raw_runtime)
    runtime = json.loads(raw_runtime.read_text())
    release = next(x for x in runtime['releases'] if x['versionId']=='24.04')
    names = sorted({name for package in release['packages'] for name in package['alternatives']})
    minima = sorted({package['minimum'] for package in release['packages']})
    cpp = '#include <iostream>\n#include <set>\n#include <string>\nint main(int n,char**v){\n'
    cpp += 'const std::set<std::string> packages={'+','.join(json.dumps(x) for x in names)+'};\n'
    cpp += 'const std::set<std::string> minima={'+','.join(json.dumps(x) for x in minima)+'};\n'
    cpp += 'if(n==3 && std::string(v[1])=="query" && packages.count(v[2])){std::cout<<"install ok installed\\t99.0\\n";return 0;}\n'
    cpp += 'if(n==5 && std::string(v[1])=="compare" && std::string(v[2])=="99.0" && std::string(v[3])=="ge" && minima.count(v[4]))return 0;\n'
    cpp += 'if(n==2 && std::string(v[1])=="arch"){std::cout<<"amd64\\n";return 0;} return 23;}\n'
    source = a.out/'owned-probe-worker.cpp'; source.write_text(cpp); pin(source)
    worker = a.out/'owned-probe-worker'
    env=dict(PATH='/usr/bin:/bin',HOME=str(a.out),TMPDIR=str(a.out),LANG='C',LC_ALL='C')
    invoke('compile-owned-worker',['/usr/bin/c++','-std=c++17','-O2',str(source),'-o',str(worker)],0,env)
    pin(worker)
    bin_dir=a.out/'command-presence';bin_dir.mkdir(mode=0o700)
    command_names=set(runtime['commands']['required'])
    for mode in runtime['commands']['backendModes']: command_names.update(mode['alternatives'])
    for name in command_names:
        assert name and '/' not in name and name not in ('.','..')
        path=bin_dir/name;path.write_bytes(b'INERT PRESENCE DATA - NEVER EXECUTED');path.chmod(0o700)
    for name in ['legacy8','role9']:
        package=a.stage_attempt/('full-stage-'+name+'-private/package')
        actual=package/'runtime-dependencies.json';pin(actual)
        assert actual.read_bytes()==raw_runtime.read_bytes()
        log=a.out/(name+'.logical-argv.log')
        case_env=dict(env,PATH=str(bin_dir),AMNEZIA_TEST_WORKER=str(worker),AMNEZIA_TEST_BOUNDARY_LOG=str(log))
        output=invoke('raw-runtime-'+name,[str(binary),'--probe-host','--runtime-manifest',str(actual),
             '--ubuntu-version-id','24.04','--ubuntu-codename','noble'],0,case_env)
        doc=json.loads(output);assert doc['hostProbesPassed'] and doc['hostProbesExecuted'] and not doc['releaseAccepted']
        rows=log.read_text().splitlines();assert len(rows)==2*len(release['packages'])+1
        meta=a.stage_attempt/(name+'.metadata.json');pin(meta)
        wrong_log=a.out/(name+'.wrong-metadata.log')
        wrong_env=dict(case_env,AMNEZIA_TEST_BOUNDARY_LOG=str(wrong_log))
        invoke('metadata-wrong-input-'+name,[str(binary),'--probe-host','--runtime-manifest',str(meta),
            '--ubuntu-version-id','24.04','--ubuntu-codename','noble'],22,wrong_env)
        assert not wrong_log.exists()
        assert 'runtime-dependencies.json has an invalid exact key set' in (a.out/('metadata-wrong-input-'+name+'.stderr')).read_text()
    result['conclusion']='Both actual staged raw runtime manifests pass unchanged; both preauth metadata documents refuse22 before process IO. No demonstrated new-verifier-role host consumer gap. Installer must hand off authenticated staged runtime-dependencies.json, not metadata JSON. No production schema widening justified.'
    if a.fail_work:
        with (a.out/'actual-failed-work.stdout').open('xb') as stdout, (a.out/'actual-failed-work.stderr').open('xb') as stderr:
            child=subprocess.run(['/usr/bin/python3','-I','-B','-c','raise SystemExit(23)'],env=env,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,timeout=10)
        assert child.returncode==23
        result['actualFailedWorkExit']=child.returncode;status=23
    else: status=0;result['componentPass']=True
except Exception as error:
    result.update(exceptionType=type(error).__name__,exception=str(error));status=1
finally:
    changed=[path for path,digest in inputs.items() if not Path(path).is_file() or sha(Path(path))!=digest]
    if changed:status=1;result['componentPass']=False
    result.update(nativeExit=status,inputsUnchanged=not changed,changedInputs=changed,inputCount=len(inputs),cases=cases,
                  finishedUtc=datetime.now(timezone.utc).isoformat())
    (a.out/'INPUTS_BEFORE.json').write_text(json.dumps(inputs,indent=2)+'\n')
    (a.out/'RESULT.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({key:result[key] for key in ['nativeExit','componentPass','inputsUnchanged','inputCount','conclusion','exception'] if key in result}))
sys.exit(status)
