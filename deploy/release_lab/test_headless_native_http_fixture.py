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
def test_parser_accepts_exact_final3_signed_linux_headless_record():
 manifest=Path(__file__).parents[2]/'dist'/'full-release-5.0.1.39-20260913-final3'/'updates'/'manifest.json'
 assert hashlib.sha256(manifest.read_bytes()).hexdigest()=='22d4afde046b2a187fd44c2bf96226ff22299973db111926b6c9e4f8c904c914'
 doc=json.loads(manifest.read_text(encoding='utf-8'));payload=json.loads(base64.urlsafe_b64decode(doc['payload']+'='*(-len(doc['payload'])%4)));row=payload['platforms']['linux-headless-x64']
 assert artifact_path(doc,row['sha256'],row['size'])=='/'+row['url']
class Q:
 def __init__(self,key_sha):self.key_sha=key_sha;self.files={}
 def write_file(self,path,data):self.files[path]=data
 def guest_exec_wait(self,path,args,timeout):return {"stdout":json.dumps({"path":"/etc/amnezia/update-public-key.pem","sha256":self.key_sha,"size":100,"uid":0,"mode":384})}
def vm():return {"pid":2,"proc_start_time":3,"uuid":"u","qmp_socket":"/var/lib/amnezia-release-lab/qmp","qga_socket":"/var/lib/amnezia-release-lab/qga"}
def test_adapter_stages_exact_helper_and_rechecks_authoritative_vm(tmp_path):
 p=plan();source=tmp_path/'server.py';source.write_text('server') ;q=Q(p.candidate.key_sha256);f=HeadlessNativeHttpFixture(q,p,vm(),vm,manifest_guest_path='/var/lib/amnezia-release-lab/fixture/manifest.json',artifact_guest_path='/var/lib/amnezia-release-lab/fixture/headless.tar.gz',request_log='/var/lib/amnezia-release-lab/fixture/requests.jsonl',server_source=source)
 assert q.files[f.script_path]==b'server' and f._trust()['sha256']==p.candidate.key_sha256
def test_adapter_rejects_changed_vm_or_wrong_trust(tmp_path):
 p=plan();source=tmp_path/'server.py';source.write_text('server');changed=lambda:{**vm(),"pid":9}
 with pytest.raises(HeadlessHttpFixtureError,match='snapshot'):HeadlessNativeHttpFixture(Q(p.candidate.key_sha256),p,vm(),changed,manifest_guest_path='/var/lib/amnezia-release-lab/fixture/manifest.json',artifact_guest_path='/var/lib/amnezia-release-lab/fixture/headless.tar.gz',request_log='/var/lib/amnezia-release-lab/fixture/requests.jsonl',server_source=source)
 f=HeadlessNativeHttpFixture(Q('0'*64),p,vm(),vm,manifest_guest_path='/var/lib/amnezia-release-lab/fixture/manifest.json',artifact_guest_path='/var/lib/amnezia-release-lab/fixture/headless.tar.gz',request_log='/var/lib/amnezia-release-lab/fixture/requests.jsonl',server_source=source)
 with pytest.raises(HeadlessHttpFixtureError,match='trust'):f._trust()
