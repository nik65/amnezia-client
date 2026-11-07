"""Run exact installer stage/remap/metadata guards, never an installer."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

p=argparse.ArgumentParser()
p.add_argument('--subject',type=Path,required=True)
p.add_argument('--stage-attempt',type=Path,required=True)
p.add_argument('--probe-attempt',type=Path,required=True)
p.add_argument('--out',type=Path,required=True)
p.add_argument('--fail-work',action='store_true')
a=p.parse_args()
assert os.geteuid()!=0
os.umask(0o077)
a.out.mkdir(mode=0o700,parents=True,exist_ok=False)
sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
inputs={};cases=[];code=1
result=dict(componentPass=False,allFunctionsPass=False,releasePass=False,published=False,
 scope='Exact source stage guard/heredoc, actual path reassignment and metadata guard/heredoc in fresh Bash. Not whole installer and not prefix/root/OS identity/ELF/runtime/activation acceptance. Native invokes existing canonical inert main; exact private dir uid0-lstat MODEL, real uid1000FS. dpkg calls -> owned pure typed worker, PATH presence placeholders never executed. Legacy Python boundary refused before execution.')

def pin(path): inputs[str(path)]=sha(path)

def between(text,start,end):
    assert text.count(start)==1,(start,text.count(start))
    index=text.index(start);finish=text.index(end,index)
    return text[index:finish]

def definitions(text):
    blocks=[]
    for name in ['y_stage_inputs','y_consume_stage_inputs','y_validate_package','y_probe_host','y_consume_metadata']:
        start=name+'() {\n'
        if start in text:
            index=text.index(start);end=text.index('\n}\n',index)+3;blocks.append(text[index:end])
    return '\n'.join(blocks)

def invoke(label,bash,env,expected):
    with (a.out/(label+'.stdout')).open('xb') as stdout,(a.out/(label+'.stderr')).open('xb') as stderr:
        proc=subprocess.run(['/bin/bash','--noprofile','--norc',str(bash)],stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,env=env,timeout=45)
    cases.append(dict(label=label,argv=['/bin/bash','--noprofile','--norc',str(bash)],nativeExit=proc.returncode,expectedExit=expected))
    print(label,proc.returncode,flush=True)
    if expected is not None: assert proc.returncode==expected,(label,proc.returncode,expected,(a.out/(label+'.stderr')).read_text())
    return proc.returncode

try:
    for path in [Path(__file__).resolve(),a.subject,a.stage_attempt/'RESULT.json',a.stage_attempt/'INPUTS_BEFORE.json',
                 a.probe_attempt/'RESULT.json',a.probe_attempt/'INPUTS_BEFORE.json',Path('/bin/bash')]: pin(path)
    for attempt in [a.stage_attempt,a.probe_attempt]:
        previous=json.loads((attempt/'RESULT.json').read_text());assert previous['nativeExit']==0 and previous['componentPass']
        for path,digest in json.loads((attempt/'INPUTS_BEFORE.json').read_text()).items():
            assert sha(Path(path))==digest,path;pin(Path(path))
    text=a.subject.read_text()
    stage_start=('if [[ -n "$BOOTSTRAP_VERIFIER" ]]; then\n    y_consume_stage_inputs\n' if 'y_consume_stage_inputs\n' in text else 'if ! python3 - "$SOURCE_PACKAGE_ROOT" "$PRIVATE_INPUTS_ROOT" "$PUBLIC_KEY" "$VERIFIED_RECEIPT"')
    stage=between(text,stage_start,'if [[ "$(sha256sum "$PACKAGE_ROOT/package-manifest.json"')
    metadata_start=('if [[ -n "$BOOTSTRAP_VERIFIER" ]]; then\n    y_consume_metadata\n' if 'y_consume_metadata\n' in text else 'if ! PACKAGE_VERSION="$(python3 - "$PACKAGE_ROOT" "$VERSION_ID" "$VERSION_CODENAME"')
    metadata=between(text,metadata_start,'if ! (cd "$PACKAGE_ROOT" && sha256sum --strict --check SHA256SUMS); then')
    # These spans retain complete original fallback heredocs as inert data.
    assert 'PACKAGE_ROOT="$PRIVATE_INPUTS_ROOT/package"' in stage and 'PUBLIC_KEY="$PRIVATE_INPUTS_ROOT/update-public-key.pem"' in stage
    assert 'VERIFIED_RECEIPT="$PRIVATE_INPUTS_ROOT/verified-receipt.json"' in stage
    harness=a.out/'actual-selected-guards.sh'
    harness.write_text('set -euo pipefail\npython3(){ printf "DENIED_LEGACY_PYTHON\\n" >&2; return 91; }\n'+definitions(text)+'\n'+stage+'\n'+metadata+'\nprintf "REACHED_NEXT_CHECK:%s\\n" "$PACKAGE_VERSION"\n')
    pin(harness)
    binary=a.stage_attempt/'inert-native-main';worker=a.probe_attempt/'owned-probe-worker'
    identity_path=a.stage_attempt/'role9.receipt.json';pin(identity_path);identity=json.loads(identity_path.read_text())
    presence=a.probe_attempt/'command-presence'
    for path in presence.iterdir(): assert stat.S_ISREG(path.lstat().st_mode);pin(path)
    for name,expected,wrong_pin in [('valid-declared-role',0,False),('wrong-key-pin-stops',3,True)]:
        work=a.out/name;work.mkdir(mode=0o700)
        private=work/'private';private.mkdir(mode=0o700);info=private.lstat()
        log=work/'logical-argv.log'
        env=dict(PATH=str(presence),HOME=str(work),TMPDIR=str(work),LANG='C',LC_ALL='C',
          BOOTSTRAP_VERIFIER=str(binary),SOURCE_PACKAGE_ROOT=str(a.stage_attempt/'role9-source'),PRIVATE_INPUTS_ROOT=str(private),
          PUBLIC_KEY=str(a.stage_attempt/'full-stage-role9-private/update-public-key.pem'),VERIFIED_RECEIPT=str(identity_path),
          EXPECTED_KEY_SHA256='0'*64 if wrong_pin else identity['publicKeySha256'],EXPECTED_MANIFEST_SHA256=identity['packageManifestSha256'],
          EXPECTED_CHECKSUMS_SHA256=identity['checksumsSha256'],EXPECTED_SIGNED_MANIFEST_SHA256=identity['manifestSha256'],
          ID='ubuntu',VERSION_ID='24.04',VERSION_CODENAME='noble',W_PRIVATE_MODEL_ROOT=str(private),W_PRIVATE_MODEL_DEV=str(info.st_dev),
          W_PRIVATE_MODEL_INO=str(info.st_ino),AMNEZIA_TEST_WORKER=str(worker),AMNEZIA_TEST_BOUNDARY_LOG=str(log))
        # Baseline is evaluated with exactly the same desired successful input.
        status=invoke(name,harness,env,None if name=='valid-declared-role' else expected)
        if name=='valid-declared-role':
            result['actualPositiveExit']=status
            assert status==0,dict(actualExit=status,stderr=(a.out/(name+'.stderr')).read_text())
            assert 'DENIED_LEGACY_PYTHON' not in (a.out/(name+'.stderr')).read_text()
            assert 'REACHED_NEXT_CHECK:'+identity['version'] in (a.out/(name+'.stdout')).read_text()
            assert (private/'package').is_dir() and (private/'update-public-key.pem').is_file() and (private/'verified-receipt.json').is_file()
            assert log.exists() and log.read_text().strip()
            result['positiveStagedFiles']=sorted(path.name for path in (private/'package').iterdir())
            assert result['positiveStagedFiles']==sorted(identity['packageFiles'])
        else:
            assert not log.exists() and not (private/'package').exists()
            assert 'REACHED_NEXT_CHECK:' not in (a.out/(name+'.stdout')).read_text()
            assert 'DENIED_LEGACY_PYTHON' not in (a.out/(name+'.stderr')).read_text()
    if a.fail_work:
        process=subprocess.run(['/usr/bin/python3','-I','-B','-c','raise SystemExit(23)'],stdin=subprocess.DEVNULL,capture_output=True,timeout=10)
        (a.out/'actual-failed-work.stdout').write_bytes(process.stdout);(a.out/'actual-failed-work.stderr').write_bytes(process.stderr)
        assert process.returncode==23;result['actualFailedWorkExit']=23;code=23
    else:code=0;result['componentPass']=True
except Exception as error:
    result.update(exceptionType=type(error).__name__,exception=str(error));code=1
finally:
    changed=[path for path,digest in inputs.items() if not Path(path).is_file() or sha(Path(path))!=digest]
    if changed:code=1;result['componentPass']=False
    result.update(nativeExit=code,inputCount=len(inputs),inputsUnchanged=not changed,changedInputs=changed,cases=cases,finishedUtc=datetime.now(timezone.utc).isoformat())
    (a.out/'INPUTS_BEFORE.json').write_text(json.dumps(inputs,indent=2)+'\n')
    (a.out/'RESULT.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({key:result[key] for key in ['nativeExit','componentPass','inputsUnchanged','inputCount','actualPositiveExit','exception'] if key in result}))
sys.exit(code)
