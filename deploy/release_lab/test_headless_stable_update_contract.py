import ast,base64,copy,importlib.util,json,pathlib,pytest
try: from headless_native_acceptance import *
except ImportError: from deploy.release_lab.headless_native_acceptance import *
HERE=pathlib.Path(__file__).resolve().parent
REPO=next(p for p in HERE.parents if (p/'deploy/release_lab/test_headless_native_acceptance.py').exists())
spec=importlib.util.spec_from_file_location('contract_fixture',REPO/'deploy/release_lab/test_headless_native_acceptance.py');fx=importlib.util.module_from_spec(spec);spec.loader.exec_module(fx)
def observed_update():
 p=fx.plan();u=fx.update();r=u['raw_sources']
 r['stable_state']=fx.raw(UPDATE_STATE,{'version':2,'state':'no_update','lastAppliedVersion':p.candidate.version,'lastError':''})
 r['after_doctor']=fx.raw('cli:doctor',{'ok':True,'result':{'ready':True,'updates':{'state':'no_update','lastAppliedVersion':p.candidate.version,'lastError':''}}})
 r['pending_state']=fx.raw(UPDATE_STATE,{'version':2,'state':'restart_pending','lastAppliedVersion':p.candidate.version})
 r['pending_journal']=fx.raw(UPDATE_JOURNAL,{'phase':'restart_pending','candidateHashes':{'amneziad':p.candidate.amneziad_sha256,'amnezia-cli':p.candidate.cli_sha256},'candidateSizes':{'amneziad':p.candidate.amneziad_size,'amnezia-cli':p.candidate.cli_size}})
 return u
def test_post_ack_no_update_exact_chain_accepts():validate_update_receipt(fx.plan(),observed_update(),fx.http())
def test_existing_updated_chain_unchanged():validate_update_receipt(fx.plan(),fx.update(),fx.http())
@pytest.mark.parametrize('key,field,bad', [('stable_state','lastError','failed'),('pending_state','lastAppliedVersion','5.0.0'),('pending_journal','candidateHashes',{}),('pending_journal','candidateSizes',{})])
def test_no_update_transaction_negatives(key,field,bad):
 u=observed_update();r=u['raw_sources'];obj=json.loads(base64.b64decode(r[key]['bytes_b64']));obj[field]=bad;r[key]=fx.raw(r[key]['path'],obj)
 with pytest.raises(HeadlessAcceptanceError):validate_update_receipt(fx.plan(),u,fx.http())
@pytest.mark.parametrize('field,bad',[('state','failed'),('lastAppliedVersion','5.0.0'),('lastError','failed')])
def test_no_update_doctor_negatives(field,bad):
 u=observed_update();obj=json.loads(base64.b64decode(u['raw_sources']['after_doctor']['bytes_b64']));obj['result']['updates'][field]=bad;u['raw_sources']['after_doctor']=fx.raw('cli:doctor',obj)
 with pytest.raises(HeadlessAcceptanceError):validate_update_receipt(fx.plan(),u,fx.http())
def test_no_update_wrong_binary_still_rejected():
 u=observed_update();u['after']['amneziad_sha256']='0'*64
 with pytest.raises(HeadlessAcceptanceError):validate_update_receipt(fx.plan(),u,fx.http())
def test_both_drivers_only_update_predicate_extended():
 for name in ['linux_headless_driver.py','headless_native_e2e_driver.py']:
  source=(HERE/name).read_text();assert "_state(x,'stable_state') in {'updated','no_update'}" in source;assert "_state(x,'stable_state')=='rolled_back'" in source

def test_mixed_snapshot_no_update_doctor_gets_full_guards():
 u=observed_update();u['raw_sources']['stable_state']=fx.raw(UPDATE_STATE,{'version':2,'state':'updated','lastAppliedVersion':fx.plan().candidate.version,'lastError':''});validate_update_receipt(fx.plan(),u,fx.http())
 obj=json.loads(base64.b64decode(u['raw_sources']['after_doctor']['bytes_b64']));obj['result']['ready']=False;u['raw_sources']['after_doctor']=fx.raw('cli:doctor',obj)
 with pytest.raises(HeadlessAcceptanceError):validate_update_receipt(fx.plan(),u,fx.http())
def test_late_exact_manifest_recheck_is_not_a_second_download():
 h=fx.http();h['requests'].append({**h['requests'][0],'observed_at':'2026-09-13T10:00:50Z'});validate_http_receipt(fx.plan(),h)
@pytest.mark.parametrize('kind',['hash','peer','order','artifact','path','eof'])
def test_late_request_negatives(kind):
 h=fx.http();row={**h['requests'][0],'observed_at':'2026-09-13T10:00:50Z'}
 if kind=='hash':row['sha256']='0'*64
 elif kind=='peer':row['peer']='10.8.1.11'
 elif kind=='order':row['observed_at']='2026-09-13T09:59:59Z'
 elif kind=='artifact':row={**h['requests'][1],'observed_at':row['observed_at']}
 elif kind=='path':row['path']='/wrong'
 else:row['eof']=False
 h['requests'].append(row)
 with pytest.raises(HeadlessAcceptanceError):validate_http_receipt(fx.plan(),h)
def test_actual_collect_keeps_original_raw_before_validation(tmp_path,monkeypatch):
 import datetime,sys
 spec=importlib.util.spec_from_file_location('deploy.release_lab._staged_http',HERE/'headless_native_http_fixture.py');mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);mod.validate_http_receipt=validate_http_receipt
 server=object.__new__(mod.HeadlessNativeHttpFixture);server.plan=fx.plan();server.reset_receipt={};server.prevalidation_archive=tmp_path;server.log='/fixture.log';server.pid=40;server.ticks=400;server.trust={}
 raw={'rows':copy.deepcopy(fx.http()['requests'])}
 for row in raw['rows']:row['observed_at']=datetime.datetime.fromisoformat(row['observed_at'].replace('Z','+00:00')).timestamp()
 raw['rows'][0]['sha256']='0'*64;original=copy.deepcopy(raw);server._json=lambda *a,**k:raw
 with pytest.raises(HeadlessAcceptanceError):server.collect()
 files=list(tmp_path.glob('*private.json'));assert len(files)==1
 saved=json.loads(files[0].read_bytes());assert json.loads(base64.b64decode(saved['bytes_base64']))==original
