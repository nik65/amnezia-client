"""Selector/registration guards exercised without any guest resources."""
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from . import lab
from .coordinated_headless_registration import CAPABILITY, capability_payload, register, stage_hashes, write_capability
from .coordinated_acquisition_contract import derive_stage_hashes
from .test_headless_native_acceptance import plan


def test_selector_is_exclusive_and_binds_every_advertised_artifact_and_helper(tmp_path):
    controller = SimpleNamespace(root=tmp_path)
    run = {'run_id': 'new-run', 'manifest': {'sha256': 'a' * 64}, 'outer_artifact': {'sha256': 'b' * 64},
           'artifacts': {'one': {'sha256': 'c' * 64, 'size': 2}, 'two': {'sha256': 'd' * 64, 'size': 3}},
           'semantic_helper_records': {'runtime': {'sha256': 'e' * 64, 'size': 4}}}
    (tmp_path / 'runs' / 'new-run').mkdir(parents=True)
    record = write_capability(controller, run)
    assert lab.artifact_record(Path(record['path'])) == record
    assert json.loads(Path(record['path']).read_bytes()) == capability_payload(run)
    assert len(capability_payload(run)['candidate_artifacts']) == 2
    with pytest.raises(FileExistsError): write_capability(controller, run)


@pytest.mark.parametrize('capability,artifacts', [('invented', {}), (True, {}), (CAPABILITY, {})])
def test_create_rejects_unknown_or_unbound_capability_before_admission(tmp_path, capability, artifacts):
    controller = lab.LabController(tmp_path, test_mode=True)
    with pytest.raises(lab.LabError):
        controller.create('candidate', artifacts, headless_capability=capability)
    assert not controller.load_state().get('runs')


def test_registration_rejects_fake_controller_before_any_runtime_operation():
    with pytest.raises(lab.LabError, match='canonical live'):
        register(object(), 'run', object(), {}, object(), {})


def test_registration_rejects_test_mode_without_starting_guest(tmp_path):
    controller = lab.LabController(tmp_path, test_mode=True)
    with pytest.raises(lab.LabError, match='canonical live'):
        register(controller, 'run', object(), {}, object(), {})


def test_registration_stage_commitments_match_export_contract():
    semantic = {'update': {'a': 1}, 'candidate_reboot': {'b': 2}, 'cleanup': {'c': 3},
                'coordinated_rollback': {'raw_sources': {'held_record': {'sha256': 'd' * 64},
                                                        'resumed_record': {'sha256': 'e' * 64}},
                                         'held_reboot': {'boot': 'actual'}}}
    original = b'{"ordinary":1}\n'
    assert stage_hashes(semantic, original) == derive_stage_hashes(original, plan(), semantic)


def test_all_new_runtime_helpers_are_pinned_once():
    names = ('headless_coordinated_rollback_acceptance.py', 'headless_coordinated_rollback_collector.py',
             'headless_coordinated_rollback_driver.py', 'headless_coordinated_http_fixture.py',
             'coordinated_headless_registration.py', 'coordinated_linux_live_acquisition.py',
             'coordinated_acquisition_contract.py', 'coordinated_release_acceptance.py')
    for name in names:
        assert lab.SEMANTIC_HELPER_RELATIVES.count('deploy/release_lab/' + name) == 1


def test_changed_coordinated_runtime_is_rejected_by_real_helper_closure(tmp_path, monkeypatch):
    name = 'deploy/release_lab/headless_coordinated_rollback_collector.py'
    path = tmp_path / name; path.parent.mkdir(parents=True); path.write_bytes(b'original-reviewed-source')
    monkeypatch.setattr(lab, 'repo_root', lambda: tmp_path)
    monkeypatch.setattr(lab, 'SEMANTIC_HELPER_RELATIVES', (name,))
    records = {name: lab.artifact_record(path)}
    lab.validate_semantic_helper_records(records)
    path.write_bytes(b'changed-source')
    with pytest.raises(lab.LabError, match='changed after plan'): lab.validate_semantic_helper_records(records)
