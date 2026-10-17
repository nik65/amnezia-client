import copy
import hashlib
import json
from pathlib import Path
import pytest
from deploy.release_lab.windows_installed_payload_contract import PATHS, checked_plan, validate, strict_json
from deploy.release_lab.prepare_windows_payload_lab import patch_controller, patch_adapter


def valid():
    artifact=dict(sha256='a'*64,size=10)
    files={k:dict(sha256=chr(98+i)*64,size=20+i) for i,k in enumerate(PATHS)}
    args=dict(run_id='run',case_id='thin-upgrade',vm_id='vm',parent_sha256='d'*64,artifact=artifact,role='candidate',version='5.0.3.11',nonce='e'*48,files=files)
    value=dict(action='installed-payload',run_id='run',case_id='thin-upgrade',vm_id='vm',parent_sha256='d'*64,
        artifact_sha256=artifact['sha256'],artifact_size=10,artifact_role='candidate',version='5.0.3.11',nonce='e'*48,
        transport='hyperv-powershell-direct',origin='guest',injected=False,read_only=True,
        files={k:dict(path=p,**files[k],file_version='5.0.3.11',product_version='5.0.3.11') for k,p in PATHS.items()},
        service=dict(name='AmneziaVPN-service',state='Running',image_path=PATHS['service'],pid=123,start_ticks=456))
    return value,args


def test_valid_is_read_only():
    value,args=valid();before=copy.deepcopy(value)
    assert validate(value,**args)==before and value==before


@pytest.mark.parametrize('key', ['run_id','case_id','vm_id','parent_sha256','artifact_sha256','artifact_size','artifact_role','version','nonce','transport','origin','injected','read_only'])
def test_foreign_or_stale_top_identity_rejected(key):
    value,args=valid();value[key]='foreign'
    with pytest.raises(ValueError):validate(value,**args)


@pytest.mark.parametrize('name', list(PATHS))
@pytest.mark.parametrize('field', ['path','sha256','size','file_version','product_version'])
def test_installed_payload_mismatch_rejected(name,field):
    value,args=valid();value['files'][name][field]='foreign'
    with pytest.raises(ValueError):validate(value,**args)


@pytest.mark.parametrize('field', ['name','state','image_path','pid','start_ticks'])
def test_service_identity_rejected(field):
    value,args=valid();value['service'][field]=True
    with pytest.raises(ValueError):validate(value,**args)


def test_plan_requires_exact_bytes_artifacts_file_set(tmp_path):
    _,args=valid();a=args['artifact'];plan=dict(schema=1,version='5.0.3.11',artifacts={a['sha256']:dict(artifact_size=a['size'],files=args['files'])})
    path=tmp_path/'plan.json';path.write_text(json.dumps(plan));sha=hashlib.sha256(path.read_bytes()).hexdigest()
    assert checked_plan(path,sha,[a])==plan
    with pytest.raises(ValueError):checked_plan(path,'0'*64,[a])
    with pytest.raises(ValueError):checked_plan(path,sha,[dict(a,sha256='f'*64)])
    for raw in ('{"a":1,"a":2}','{}{}','{"a":NaN}'):
        with pytest.raises(ValueError):strict_json(raw)


def test_frozen_overlay_hooks_are_precleanup_and_no_fixture():
    source=Path('dist/release-candidate-5.0.3.11-2197-final-20261017/source-freeze/source/deploy/release_lab')
    if not source.exists():pytest.skip('immutable local b292 source unavailable')
    controller=patch_controller((source/'lab.py').read_text(encoding='utf-8-sig'))
    compile(controller,'generated-lab.py','exec')
    assert 'windows_netstack_fixture_contract as' not in controller
    stage=controller.index('current_phase = "installed-payload:" + stage_name')
    assert stage<controller.index('case_receipts.append(',stage)<controller.index('finally:',stage)
    ui=controller.index('"candidate-outer-interactive", outer_candidate')
    assert ui<controller.index('checkpoint_profile["interactive_receipt"]',ui)<controller.index('finally:',ui)
    action=Path('deploy/release_lab/windows_host/installed_payload_action.ps1').read_text()
    adapter=patch_adapter((source/'windows_host/hyperv_adapter.ps1').read_text(encoding='utf-8-sig'),action)
    assert '$payloadChild=Read-Child $RunsRoot $RunId $ParentRoot $CaseId' in adapter
    assert 'Invoke-OwnedNetstackFixture' not in adapter
