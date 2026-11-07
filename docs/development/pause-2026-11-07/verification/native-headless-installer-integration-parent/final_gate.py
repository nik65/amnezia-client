"""Final bounded source/fixture gate for the two reviewed shell integrations."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

p=argparse.ArgumentParser()
p.add_argument('--source',type=Path,required=True)
p.add_argument('--manifest',type=Path,required=True)
p.add_argument('--applied',type=Path,required=True)
p.add_argument('--attempt-root',type=Path,required=True)
p.add_argument('--prior-build',type=Path,required=True)
p.add_argument('--out',type=Path,required=True)
p.add_argument('--fail-work',action='store_true')
a=p.parse_args()
assert os.geteuid()!=0
os.umask(0o077)
a.out.mkdir(mode=0o700,parents=True,exist_ok=False)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
inputs={};code=1
result=dict(startedUtc=datetime.now(timezone.utc).isoformat(),componentPass=False,allFunctionsPass=False,releasePass=False,published=False,
  scope='Two exact reviewed shell-source integrations and fresh actual canonical package-builder/guard-span source smoke. CMake TESTdaemon/CLI, exact UID0-dir metadata and OSprobe MODELS remain explicit. Not whole installer/root activation/recovery/host probes/app/runtime/release acceptance. No installer/static/product/guest/phone/network/service execution.',
  admission='NOT_ADMITTED',runtimeAcceptance='NOT_RUN',commands=[],attempts={})

def pin(path):inputs[str(path)]=sha(path)

try:
    for path in [Path(__file__).resolve(),a.manifest,a.applied,a.source/'.git/index',
      Path('/mnt/c/Users/ivano/PycharmProjects/amnezia-client/.git/index')]:pin(path)
    applied=json.loads(a.applied.read_text());rows=json.loads(a.manifest.read_text())
    assert len(rows)==2635 and sha(a.manifest)==applied['sourceManifest']['sha256']
    for row in rows:
        path=a.source/row['path'];pin(path)
        assert sha(path)==row['sha256'] and path.stat().st_size==row['size'],row['path']
    allowed=set(applied['allowedDelta'])
    assert allowed=={'deploy/headless/install_headless.sh','deploy/headless/build_headless_release.sh'}
    for rel,entry in applied['allowedDelta'].items():
        assert sha(a.source/rel)==entry['selectedSha256']
        selected=Path(entry['selectedSourcePath'].replace('C:\\','/mnt/c/').replace('C:/','/mnt/c/').replace('\\','/'))
        assert selected.read_bytes()==(a.source/rel).read_bytes();pin(selected)
    # The old artifact retains its original0830 build provenance. Exactly the
    # two unrelated shell source-fence rows changed; actual native CMake/CPP,
    # compiler dependencies, linked archives, tools and args remain unchanged.
    old=json.loads((a.prior_build/'INPUTS_BEFORE.json').read_text());changed={}
    for value,digest in old.items():
        path=Path(value);actual=sha(path)
        if actual!=digest:changed[str(path)]=dict(beforeSha256=digest,afterSha256=actual)
        pin(path)
    assert set(changed)=={str(a.source/rel) for rel in allowed},changed
    build=json.loads((a.prior_build/'RESULT.json').read_text());pin(a.prior_build/'RESULT.json');pin(a.prior_build/'INPUTS_BEFORE.json')
    artifact=Path(build['artifact']['path']);assert sha(artifact)==build['artifact']['sha256'];pin(artifact)
    result.update(unchangedNativeArtifact=build['artifact'],nativeArtifactFreshRebuild=False,
      nativeArtifactOriginalBuildManifestSha256=build['manifestSha256'],
      explicitOldBuildSourceFenceDelta=changed,nativeCMakeCppDependenciesLinkInputsUnchanged=True,
      newSourceManifestSha256=sha(a.manifest),declaredSourceFileCount=len(rows),unrelatedSourceRowsPreserved=2633)
    expected={'canonical-builder-role-a':0,'canonical-builder-legacy-a':0,'canonical-builder-failedwork-a':23,
      'canonical-stage-a':0,'canonical-probe-a':0,'canonical-consumer-a':0,'canonical-consumer-failedwork-a':23}
    for label,status in expected.items():
        directory=a.attempt_root/label;path=directory/'RESULT.json';pin(path);row=json.loads(path.read_text())
        assert row['nativeExit']==status and row['componentPass']==(status==0) and row['inputsUnchanged'],label
        pins=json.loads((directory/'INPUTS_BEFORE.json').read_text()) if (directory/'INPUTS_BEFORE.json').is_file() else row['inputs']
        for value,digest in pins.items():assert sha(Path(value))==digest,(label,value);pin(Path(value))
        result['attempts'][label]=dict(path=str(path),sha256=sha(path),nativeExit=status,componentPass=row['componentPass'],inputCount=len(pins))
    role=json.loads((a.attempt_root/'canonical-builder-role-a/RESULT.json').read_text())['archive']
    legacy=json.loads((a.attempt_root/'canonical-builder-legacy-a/RESULT.json').read_text())['archive']
    assert role['sha256']=='fbf2b36c1e49b654e62ef2841eb0b4b980bf51d265213ff043e74639a963728a'
    assert legacy['sha256']=='976e05e2dd6231d227ec66c398782244e0bf1a93ea43fe7aed1d78bb53de9e9c'
    result.update(rolePackage=role,legacyPackage=legacy)
    for rel in sorted(allowed):
        argv=['/bin/bash','--noprofile','--norc','-n',str(a.source/rel)]
        proc=subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,timeout=5)
        result['commands'].append(dict(argv=argv,nativeExit=proc.returncode));assert proc.returncode==0
    indexes=dict(candidate=sha(a.source/'.git/index'),canonical=sha(Path('/mnt/c/Users/ivano/PycharmProjects/amnezia-client/.git/index')))
    assert indexes=={'candidate':'3e5142545f4ff71fad593b63010998e3fcc45901b84c5f6197d491c704c9368b',
      'canonical':'01347bedcda9626cced1629915c32e65b2eddbd36ebf78880fafc4b84dfdb9c4'}
    result['rawIndexes']=indexes
    code=0
    if a.fail_work:
        with (a.out/'actual-failed-work.stdout').open('xb') as stdout,(a.out/'actual-failed-work.stderr').open('xb') as stderr:
            work=subprocess.run(['/usr/bin/python3','-I','-B','-c','raise SystemExit(23)'],stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,timeout=5)
        code=work.returncode;assert code==23;result['actualFailedWorkNativeExit']=code
except Exception as error:
    result.update(exceptionType=type(error).__name__,exception=str(error));code=1
finally:
    changed_inputs=[value for value,digest in inputs.items() if not Path(value).is_file() or sha(Path(value))!=digest]
    if changed_inputs and code==0:code=1
    result.update(nativeExit=code,componentPass=code==0,inputsUnchanged=not changed_inputs,changedInputs=changed_inputs,
      inputCount=len(inputs),finishedUtc=datetime.now(timezone.utc).isoformat())
    (a.out/'INPUTS_BEFORE.json').write_text(json.dumps(inputs,indent=2)+'\n')
    (a.out/'RESULT.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({key:result[key] for key in ['nativeExit','componentPass','inputCount','inputsUnchanged',
      'newSourceManifestSha256','explicitOldBuildSourceFenceDelta','exception'] if key in result}))
sys.exit(code)
