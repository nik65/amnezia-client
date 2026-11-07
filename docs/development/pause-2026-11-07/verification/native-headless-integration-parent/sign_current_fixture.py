"""Sign exact builder fixtures locally; all archived programs stay inert data."""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

p=argparse.ArgumentParser()
p.add_argument('--source',type=Path,required=True)
p.add_argument('--source-manifest',type=Path,required=True)
p.add_argument('--builder-role',type=Path,required=True)
p.add_argument('--builder-legacy',type=Path,required=True)
p.add_argument('--builder-control',type=Path,required=True)
p.add_argument('--component-build',type=Path,required=True)
p.add_argument('--out',type=Path,required=True)
p.add_argument('--fail-work',action='store_true')
a=p.parse_args()
assert os.geteuid()!=0
os.umask(0o077)
a.out.mkdir(mode=0o700,parents=True,exist_ok=False)
private=a.out/'private-tmp';private.mkdir(mode=0o700)
env=dict(PATH='/usr/bin:/bin',HOME=str(a.out),TMPDIR=str(private),LANG='C',LC_ALL='C')
os.environ.update(env)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
now=lambda:datetime.now(timezone.utc).isoformat()
inputs={};code=1
key=a.out/'owned-TEST-private.pem';public=a.out/'owned-TEST-public.pem'
result=dict(startedUtc=now(),commands=[],componentPass=False,allFunctionsPass=False,releasePass=False,published=False,
  admission='NOT_ADMITTED',runtimeAcceptance='NOT_RUN',
  scope='Actual reviewed package-builder artifacts with exact current native component bytes and reviewed Y installer, actual canonical local manifest producer/Ed25519 verifier. CMake alone produced explicit TEST daemon/CLI data. Packaged installer/component/member programs never executed; no guest, root wrapper, app, service, network, SSH, ADB or publication. Not final app/release bytes.')

def pin(path):
    value=sha(path)
    assert str(path) not in inputs or inputs[str(path)]==value
    inputs[str(path)]=value
    return value

def command(label,argv,expected=0):
    started=now()
    with (a.out/(label+'.stdout')).open('xb') as out,(a.out/(label+'.stderr')).open('xb') as err:
        proc=subprocess.run(argv,env=env,stdin=subprocess.DEVNULL,stdout=out,stderr=err,timeout=30)
    result['commands'].append(dict(label=label,argv=argv,nativeExit=proc.returncode,expectedExit=expected,startedUtc=started,finishedUtc=now()))
    if expected is not None:assert proc.returncode==expected,(label,proc.returncode)
    return proc.returncode

def producer_record(folder):
    pin(folder/'RESULT.json')
    record=json.loads((folder/'RESULT.json').read_text())
    assert record['nativeExit']==0 and record['componentPass'] and record['inputsUnchanged']
    for path,digest in record['inputs'].items():assert pin(Path(path))==digest,path
    archive=Path(record['archive']['path'])
    assert pin(archive)==record['archive']['sha256']
    return record,archive

try:
    for path in [Path(__file__).resolve(),a.source_manifest,a.source/'.git/index',
      Path('/mnt/c/Users/ivano/PycharmProjects/amnezia-client/.git/index'),Path('/usr/bin/openssl').resolve(),Path('/usr/bin/python3').resolve()]:pin(path)
    for row in json.loads(a.source_manifest.read_text()):assert pin(a.source/row['path'])==row['sha256'],row['path']
    pin(a.component_build/'RESULT.json');pin(a.component_build/'INPUTS_BEFORE.json')
    component=json.loads((a.component_build/'RESULT.json').read_text())
    assert component['nativeExit']==0 and component['componentPass'] and component['inputsUnchanged']
    for path,digest in json.loads((a.component_build/'INPUTS_BEFORE.json').read_text()).items():assert pin(Path(path))==digest,path
    executable=Path(component['artifact']['path']);assert pin(executable)==component['artifact']['sha256']
    role,role_archive=producer_record(a.builder_role)
    legacy,legacy_archive=producer_record(a.builder_legacy)
    control,control_archive=producer_record(a.builder_control)
    assert legacy_archive.read_bytes()==control_archive.read_bytes(),'optional-role absence changes legacy bytes'
    assert role['withRole'] and not legacy['withRole'] and not control['withRole']
    assert role['archive']['selectedInstallerSha256']==legacy['archive']['selectedInstallerSha256']==control['archive']['selectedInstallerSha256']
    artifact=a.builder_role/'artifacts/AmneziaHeadless_1.0.0.42_linux_x64.tar.gz';pin(artifact)
    canonical=a.source/'deploy/headless/verify_provisioning_bundle.py';pin(canonical)
    spec=importlib.util.spec_from_file_location('current_fixture_receipt',canonical)
    verifier=importlib.util.module_from_spec(spec);spec.loader.exec_module(verifier)
    command('owned-TEST-keygen',['/usr/bin/openssl','genpkey','-algorithm','ED25519','-out',str(key)])
    command('owned-TEST-public',['/usr/bin/openssl','pkey','-in',str(key),'-pubout','-out',str(public)])
    assert key.lstat().st_mode & 0o7777==0o600 and public.lstat().st_mode & 0o7777==0o600
    records={}
    for name,archive,count in [('legacy8',legacy_archive,8),('role9',role_archive,9)]:
        directory=a.out/('manifest-'+name)
        command('canonical-produce-'+name,['/usr/bin/python3','-I','-B',str(a.source/'deploy/headless/make_headless_manifest.py'),
          '--version','1.0.0.42','--base-url','http://127.0.0.1:8080','--private-key',str(key),
          '--artifact',str(artifact),'--provisioning',str(archive),'--out-dir',str(directory)])
        identity=verifier.verify_manifest_and_bundle(directory/'manifest.json',public,archive,sha(public))
        assert identity['verified'] is True and identity['packageVersion']=='1.0.0.42' and len(identity['packageFiles'])==count
        envelope=json.loads((directory/'manifest.json').read_text())
        payload=json.loads(base64.urlsafe_b64decode(envelope['payload']+'='*(-len(envelope['payload'])%4)))
        assert payload['autoInstall'] is False and payload['platforms']['linux-headless-x64']['autoInstall'] is False
        records[name]=dict(manifestPath=str(directory/'manifest.json'),manifestSha256=sha(directory/'manifest.json'),
          archivePath=str(archive),archiveSha256=sha(archive),canonicalReceipt=identity)
        (a.out/(name+'.canonical-receipt.json')).write_text(json.dumps(identity,sort_keys=True,separators=(',',':'))+'\n')
    # Keep the complete colocal artifact tree, so refusal must reach real crypto.
    tampered=a.out/'manifest-role9-bad-signature';shutil.copytree(a.out/'manifest-role9',tampered)
    bad=json.loads((tampered/'manifest.json').read_text());signature=bytearray(base64.b64decode(bad['signature']));signature[0]^=1
    bad['signature']=base64.b64encode(signature).decode();(tampered/'manifest.json').write_text(json.dumps(bad)+'\n')
    try:verifier.verify_manifest_and_bundle(tampered/'manifest.json',public,role_archive,sha(public))
    except SystemExit as error:
        assert str(error)=='signed update manifest signature verification failed'
        cause=error.__cause__
        assert isinstance(cause,subprocess.CalledProcessError)
        assert cause.returncode==1 and Path(cause.cmd[0]).name=='openssl' and 'pkeyutl' in cause.cmd and '-verify' in cause.cmd
        result['badSignatureNativeExit']=cause.returncode
    else:raise AssertionError('canonical verifier accepted altered signature')
    result.update(fixtures=records,componentArtifact=component['artifact'],sourceManifestSha256=sha(a.source_manifest),
      publicKey=dict(path=str(public),sha256=sha(public),size=public.stat().st_size),
      optionalRoleAbsentLegacyByteIdentical=True,legacyArchiveSha256=sha(legacy_archive),
      selectedInstallerSha256=role['archive']['selectedInstallerSha256'])
    code=0
    if a.fail_work:
        code=command('deliberately-failed-work',['/usr/bin/python3','-I','-B','-c','raise SystemExit(23)'],expected=None)
        assert code==23;result['failedWorkNativeExit']=code
except (Exception,SystemExit) as error:
    result.update(exceptionType=type(error).__name__,exception=str(error));code=1
finally:
    cleanup_error=None
    try:
        if key.exists():key.unlink()
    except Exception as error:cleanup_error=str(error)
    changed=[path for path,digest in inputs.items() if not Path(path).is_file() or sha(Path(path))!=digest]
    if changed or cleanup_error:
        if code==0:code=1
    result.update(nativeExit=code,componentPass=code==0,inputsUnchanged=not changed,changedInputs=changed,
      inputCount=len(inputs),ownedTESTPrivateKeyRemoved=not key.exists(),cleanupError=cleanup_error,finishedUtc=now())
    (a.out/'INPUTS_BEFORE.json').write_text(json.dumps(inputs,indent=2)+'\n')
    (a.out/'RESULT.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:result[k] for k in ['nativeExit','componentPass','inputCount','inputsUnchanged','optionalRoleAbsentLegacyByteIdentical','badSignatureNativeExit','ownedTESTPrivateKeyRemoved','exception'] if k in result}))
sys.exit(code)
