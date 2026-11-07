"""Aggregate immutable component attempts using native Linux path semantics."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

p=argparse.ArgumentParser()
p.add_argument('--attempt-root',type=Path,required=True)
p.add_argument('--q',type=Path,required=True)
p.add_argument('--out',type=Path,required=True)
a=p.parse_args()
root=a.attempt_root
sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
names={'builder-current-role-a':0,'builder-current-legacy-a':0,'builder-control-legacy-a':0,
 'signed-current-b':0,'signed-current-failedwork-b':23,'stage-current-a':0,'stage-current-failedwork-a':23,
 'consumer-current-a':0,'consumer-current-failedwork-a':23}
records={}
for name,expected in names.items():
    target=root/name/'RESULT.json';row=json.loads(target.read_text())
    assert row['nativeExit']==expected and row['componentPass']==(expected==0) and row['inputsUnchanged'],name
    pins=json.loads((root/name/'INPUTS_BEFORE.json').read_text()) if (root/name/'INPUTS_BEFORE.json').is_file() else row['inputs']
    changed=[path for path,digest in pins.items() if sha(Path(path))!=digest]
    assert not changed,(name,changed)
    records[name]=dict(path=str(target),sha256=sha(target),nativeExit=row['nativeExit'],componentPass=row['componentPass'],
      inputCount=len(pins),currentInputsUnchanged=True)
sig=json.loads((root/'signed-current-b/RESULT.json').read_text())
pkg=json.loads((root/'builder-current-role-a/RESULT.json').read_text())
legacy=json.loads((root/'builder-current-legacy-a/RESULT.json').read_text())
control=json.loads((root/'builder-control-legacy-a/RESULT.json').read_text())
assert legacy['archive']['sha256']==control['archive']['sha256'] and sig['optionalRoleAbsentLegacyByteIdentical'] and sig['badSignatureNativeExit']==1
indexes={'canonical':sha(Path('/mnt/c/Users/ivano/PycharmProjects/amnezia-client/.git/index')),
 'candidate':sha(Path('/home/ivano/codex-amnezia-upstream-20261104/.git/index'))}
assert indexes=={'canonical':'01347bedcda9626cced1629915c32e65b2eddbd36ebf78880fafc4b84dfdb9c4',
 'candidate':'3e5142545f4ff71fad593b63010998e3fcc45901b84c5f6197d491c704c9368b'}
manifest=a.q/'native-headless-integration-parent/MATERIALIZED_PRODUCT_SOURCE_MANIFEST.json'
assert sha(manifest)=='0830d940be4d89245fc695e7d8d3dffca5eb897b25bd8199449338941890d722'
report=dict(scope='Current static9e11 packaged as DATA with reviewed Y installer through actual U builder -> actual canonical signer/verifier -> actual canonical inert-main archive/stage/metadata -> exact actual Y guard/path-remap/probe span. CMake TESTdaemon/CLI and UID0-directory/OSprobe MODELS explicitly exclude actual app/root/runtime; never launch installer, packaged/static component or TESTmembers here. No product or canonical source changes.',
 createdUtc=datetime.now(timezone.utc).isoformat(),componentPass=True,allFunctionsPass=False,releasePass=False,published=False,
 sourceManifest=dict(path=str(manifest),sha256=sha(manifest),fileCount=len(json.loads(manifest.read_text()))),rawIndexes=indexes,
 attempts=records,rolePackage=pkg['archive'],legacyArchiveSha256=legacy['archive']['sha256'],legacyOptionalRoleAbsentByteIdentical=True,
 signatureFixtures=sig['fixtures'],publicKey=sig['publicKey'],currentArtifact=sig['componentArtifact'],
 admission='NOT_ADMITTED',guestStarted=False,runtimeAcceptance='NOT_RUN',
 remaining=['BB existing-controller explicit headless kind/role staging/strict guest receipts','actual fresh owned Linux root staging and cleanup',
 'Z initial installer helperkind/ELF/recovery cutover not accepted/integrated','AA independently authenticated automatic CURRENT not accepted',
 'final static6pair/app/sign/fresh106/fourplatform/provisioning/peer/data-plane/manual-client publication'],
 preservedSetupFailures={'signed-current-a':dict(nativeExit=1,reason='negative fixture expected direct CalledProcessError but actual canonical bundle wrapper raises SystemExit with native CalledProcessError cause; no production crypto defect'),
 'signed-current-failedwork-a':dict(nativeExit=1,reason='same setup, failed body not reached')},
 metadataAudit='Native Linux paths required: Windows UNC cannot reliably resolve /usr/bin/c++ alternatives symlink; failed Windows-only preaggregation did not create or modify report/evidence.')
with a.out.open('x') as file:file.write(json.dumps(report,indent=2)+'\n')
print(json.dumps(dict(reportPath=str(a.out),reportSha256=sha(a.out),roleArchive=pkg['archive'],
 legacyArchiveSha256=legacy['archive']['sha256'],sourceFileCount=report['sourceManifest']['fileCount'],signaturePublicKey=sig['publicKey'],
 nativeExits={key:value['nativeExit'] for key,value in records.items()})))
