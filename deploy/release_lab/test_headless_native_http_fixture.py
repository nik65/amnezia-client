import base64,hashlib,json
from pathlib import Path
import pytest
from deploy.release_lab.headless_native_fixture_server import artifact_path
from deploy.release_lab.headless_native_http_fixture import HeadlessNativeHttpFixture,HeadlessHttpFixtureError
from deploy.release_lab.test_headless_native_acceptance import plan

def signed(platform='linux-headless-x64',sha='a'*64,name='headless.tar.gz',size=17):
 payload={"platforms":{platform:{"url":f"files/artifacts/{sha}/{name}","sha256":sha,"size":size,"format":"amnezia-headless-tar-v1"}}};return {"payload":base64.b64encode(json.dumps(payload).encode()).decode().rstrip('='),"signature":"sig"}
def test_manifest_parser_requires_exact_linux_headless_label_and_hash_path():
 assert artifact_path(signed(),"a"*64,17).endswith('/headless.tar.gz')
 with pytest.raises(SystemExit):artifact_path(signed('android-arm64-v8a'),"a"*64,17)
 with pytest.raises(SystemExit):artifact_path(signed(sha='b'*64),"a"*64,17)
 with pytest.raises(SystemExit):artifact_path(signed(size=18),"a"*64,17)
def test_parser_accepts_exact_published13_signed_linux_headless_record():
 manifest=Path(__file__).with_name('fixtures')/'headless_manifest_published_5_0_3_13.json'
 assert hashlib.sha256(manifest.read_bytes()).hexdigest()=='75c41ab23a9f880d35bc7181736bbc11850b3878009207220a0ac3c9be763211'
 doc=json.loads(manifest.read_text(encoding='utf-8'));assert doc['signatureAlgorithm']=='Ed25519';payload=json.loads(base64.urlsafe_b64decode(doc['payload']+'='*(-len(doc['payload'])%4)));row=payload['platforms']['linux-headless-x64'];assert payload['version']=='5.0.3.13' and row['format']=='amnezia-headless-tar-v1'
 assert artifact_path(doc,row['sha256'],row['size'])=='/'+row['url']
class Q:
 def __init__(self,key_sha):self.key_sha=key_sha;self.files={}
 def write_file(self,path,data):self.files[path]=data
 def guest_exec_wait(self,path,args,timeout):return {"stdout":json.dumps({"path":"/etc/amnezia/update-public-key.pem","sha256":self.key_sha,"size":100,"uid":0,"gid":1000,"amnezia_gid":1000,"mode":416,"protected_ancestors":True,"regular":True,"same_fd_identity":True})}
def vm():return {"pid":2,"proc_start_time":3,"uuid":"u","qmp_socket":"/var/lib/amnezia-release-lab/qmp","qga_socket":"/var/lib/amnezia-release-lab/qga"}
def test_adapter_stages_exact_helper_and_rechecks_authoritative_vm(tmp_path):
 p=plan();source=tmp_path/'server.py';source.write_text('server') ;q=Q(p.candidate.key_sha256);f=HeadlessNativeHttpFixture(q,p,vm(),vm,manifest_guest_path='/var/lib/amnezia-release-lab/fixture/manifest.json',artifact_guest_path='/var/lib/amnezia-release-lab/fixture/headless.tar.gz',request_log='/var/lib/amnezia-release-lab/fixture/requests.jsonl',server_source=source)
 assert q.files[f.script_path]==b'server' and f._trust()['sha256']==p.candidate.key_sha256
def test_adapter_rejects_changed_vm_or_wrong_trust(tmp_path):
 p=plan();source=tmp_path/'server.py';source.write_text('server');changed=lambda:{**vm(),"pid":9}
 with pytest.raises(HeadlessHttpFixtureError,match='snapshot'):HeadlessNativeHttpFixture(Q(p.candidate.key_sha256),p,vm(),changed,manifest_guest_path='/var/lib/amnezia-release-lab/fixture/manifest.json',artifact_guest_path='/var/lib/amnezia-release-lab/fixture/headless.tar.gz',request_log='/var/lib/amnezia-release-lab/fixture/requests.jsonl',server_source=source)
 f=HeadlessNativeHttpFixture(Q('0'*64),p,vm(),vm,manifest_guest_path='/var/lib/amnezia-release-lab/fixture/manifest.json',artifact_guest_path='/var/lib/amnezia-release-lab/fixture/headless.tar.gz',request_log='/var/lib/amnezia-release-lab/fixture/requests.jsonl',server_source=source)
 with pytest.raises(HeadlessHttpFixtureError,match='trust'):f._trust()
