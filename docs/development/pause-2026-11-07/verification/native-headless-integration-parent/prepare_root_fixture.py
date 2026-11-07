"""Materialize private exact component/data inputs, not an execution plan."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys

p=argparse.ArgumentParser()
p.add_argument('--out',type=Path,required=True)
a=p.parse_args()
assert os.geteuid()!=0
os.umask(0o077)
a.out.mkdir(mode=0o700,parents=True,exist_ok=False)
tmp=a.out/'private-tmp';tmp.mkdir(mode=0o700)
os.environ.update(TMPDIR=str(tmp),LANG='C',LC_ALL='C')
root=Path('/home/ivano/codex-amnezia-upstream-20261104')
q=Path('/mnt/c/Users/ivano/PycharmProjects/amnezia-client/dist/diagnostics/upstream-5106-continuation-a/final-build-readiness-q')
linux=Path('/home/ivano/amnezia-product-50318-q')
build=linux/'native-headless-integration-parent/cmake-build-a'
context=linux/'native-headless-authority-parent/integrated-g'
archive=linux/'native-headless-delivery-parent/builder-role-green-a/artifacts/AmneziaHeadless_1.0.0.42_linux_x64_provisioning.tar.gz'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
inputs={};code=1
result=dict(kind='private-headless-component-data-snapshot-not-runtime-plan',componentPass=False,releasePass=False,
            allFunctionsPass=False,published=False,startedUtc=datetime.now(timezone.utc).isoformat())

def pin(path):inputs[str(path)]=sha(path)

try:
    for path in [Path(__file__).resolve(),build/'RESULT.json',build/'INPUTS_BEFORE.json']:pin(path)
    br=json.loads((build/'RESULT.json').read_text());assert br['nativeExit']==0 and br['componentPass'] and br['inputsUnchanged']
    for path,digest in json.loads((build/'INPUTS_BEFORE.json').read_text()).items():
        assert sha(Path(path))==digest,path;pin(Path(path))
    artifact=Path(br['artifact']['path']);assert sha(artifact)=='9e11222529593f8276a5202e4e8569e54ca8383a84152aa438eea5c38171792a'
    manifest=context/'manifest-role9/manifest.json';key=context/'owned-TEST-public.pem'
    for path in [artifact,archive,manifest,key]:pin(path)
    assert sha(archive)=='68d0e40032d7e6c66634f2d0ceb66a70d63d1b9f74699d5ec21c0ac71a51e99b'
    for path in [root/'deploy/headless/verify_provisioning_bundle.py',root/'deploy/selfhosted_updates/make_manifest.py']:pin(path)
    validator=root/'deploy/headless/verify_provisioning_bundle.py'
    spec=importlib.util.spec_from_file_location('owned_snapshot_receipt',validator)
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    identity=mod.verify_manifest_and_bundle(manifest,key,archive,sha(key))
    assert identity['verified'] is True and identity['packageVersion']=='1.0.0.42' and len(identity['packageFiles'])==9
    records={}
    for label,path in [('componentExecutable',artifact),('signedProvisioningData',archive),('signedManifestData',manifest),('ownedTESTPublicKeyData',key)]:
        target=a.out/path.name
        fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        try:
            data=path.read_bytes();left=memoryview(data)
            while left:
                count=os.write(fd,left);assert count>0;left=left[count:]
            os.fsync(fd);assert (os.fstat(fd).st_mode & 0o7777)==0o600
        finally:os.close(fd)
        assert sha(target)==sha(path) and target.lstat().st_uid==os.geteuid()
        records[label]=dict(path=str(target),sha256=sha(target),size=target.stat().st_size,mode='0600',uid=os.geteuid())
    result.update(records=records,canonicalReceipt=identity,sourceBinding=br['manifestSha256'],
      scope='Private0700 host-owned UID1000 DATA snapshot, files0600. Actual canonical Python signature/archive verifier; no component/static/product/installer execution, no guest/control/state/nonce creation. Fixture1.0.0.42 has TESTdaemon/CLI and oldcc5verifier data only, NEVER execute packaged members. Only separately admitted componentExecutable9e11 may run later inside verified owned guest. Not final app/release bytes or new trust authority.',
      admission='NOT_ADMITTED',runtimeAcceptance='NOT_RUN',componentPass=True)
    code=0
except Exception as error:
    result.update(exceptionType=type(error).__name__,exception=str(error));code=1
finally:
    changed=[path for path,digest in inputs.items() if not Path(path).is_file() or sha(Path(path))!=digest]
    if changed:code=1;result['componentPass']=False
    result.update(nativeExit=code,inputsUnchanged=not changed,changedInputs=changed,inputCount=len(inputs),finishedUtc=datetime.now(timezone.utc).isoformat())
    (a.out/'INPUTS_BEFORE.json').write_text(json.dumps(inputs,indent=2)+'\n')
    (a.out/'RESULT.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({key:result[key] for key in ['nativeExit','componentPass','inputCount','inputsUnchanged','records','exception'] if key in result}))
sys.exit(code)
