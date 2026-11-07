"""Inert selector/dispatch tests; no guest or acquisition proof is fabricated."""
import json
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from . import coordinated_linux_live_acquisition as module
from .android_real_device_acquisition import file_record
from .linux_live_acquisition import LinuxLiveProducer
from .trusted_acquisition_export import TrustedAcquisitionError


def selector(tmp_path, monkeypatch):
    root = tmp_path / 'lab'
    directory = root / 'runs' / 'coordinated-test'
    directory.mkdir(parents=True)
    run = {'headless_capability': module.CAPABILITY,
           'manifest': {'sha256': 'a' * 64}, 'outer_artifact': {'sha256': 'b' * 64},
           'artifacts': {'linux-headless-x64': {'sha256': 'c' * 64, 'size': 17}},
           'semantic_helper_records': {'fixed-helper': {'sha256': 'd' * 64, 'size': 21}}}
    value = {'schema': 1, 'run_id': 'coordinated-test', 'capability': module.CAPABILITY,
             'manifest_sha256': run['manifest']['sha256'], 'outer_sha256': run['outer_artifact']['sha256'],
             'candidate_artifacts': run['artifacts'], 'semantic_helpers': run['semantic_helper_records']}
    path = directory / 'headless-capability.json'
    path.write_text(json.dumps(value))
    run['headless_capability_record'] = file_record(path)
    monkeypatch.setattr(LinuxLiveProducer, '_binding', lambda self, context: run)
    producer = module.CoordinatedLinuxLiveProducer(SimpleNamespace(root=root), 'coordinated-test')
    return producer, run, path


def test_exact_preselected_record_binds_all_artifacts_and_helpers(tmp_path, monkeypatch):
    producer, run, _ = selector(tmp_path, monkeypatch)
    assert producer._binding(object()) is run
    assert producer.target == 'linux-headless-coordinated'
    assert 'rollback' not in module.SEMANTICS


@pytest.mark.parametrize('field', ['headless_capability', 'headless_capability_record'])
def test_missing_or_legacy_selector_rejected_before_guest_work(tmp_path, monkeypatch, field):
    producer, run, _ = selector(tmp_path, monkeypatch)
    run.pop(field)
    with pytest.raises(TrustedAcquisitionError): producer._binding(object())


def test_rehashed_record_cannot_hide_changed_signed_context(tmp_path, monkeypatch):
    producer, run, path = selector(tmp_path, monkeypatch)
    value = json.loads(path.read_bytes())
    value['candidate_artifacts']['linux-headless-x64']['sha256'] = 'e' * 64
    path.write_text(json.dumps(value))
    run['headless_capability_record'] = file_record(path)
    with pytest.raises(TrustedAcquisitionError, match='closure differs'): producer._binding(object())


def test_boolean_cannot_substitute_integer_selector_schema(tmp_path, monkeypatch):
    producer, run, path = selector(tmp_path, monkeypatch)
    value = json.loads(path.read_bytes()); value['schema'] = True
    path.write_text(json.dumps(value)); run['headless_capability_record'] = file_record(path)
    with pytest.raises(TrustedAcquisitionError, match='closure differs'): producer._binding(object())


def test_physical_selector_changed_or_symlink_rejected(tmp_path, monkeypatch):
    producer, run, path = selector(tmp_path, monkeypatch)
    path.write_text(path.read_text() + ' ')
    with pytest.raises(TrustedAcquisitionError, match='record changed'): producer._binding(object())


def test_instance_plugin_cannot_replace_fixed_lifecycle():
    producer = module.CoordinatedLinuxLiveProducer(object(), 'run')
    producer._acquire_once = lambda context: {'passed': True}
    with pytest.raises(TrustedAcquisitionError, match='fixed coordinated producer'):
        producer.acquire(object())


def test_subclass_cannot_replace_fixed_producer_dispatch():
    class Replacement(module.CoordinatedLinuxLiveProducer): pass
    with pytest.raises(TrustedAcquisitionError, match='fixed coordinated producer'):
        Replacement(object(), 'run').acquire(object())


def test_actual_inherited_lifecycle_dispatches_new_target_before_guest_start(monkeypatch):
    from .lab import LabController
    controller = object.__new__(LabController)
    controller.dry_run = False; controller.test_mode = False
    events = []
    @contextmanager
    def session(name):
        events.append(name)
        yield
    controller.mutation_session = session
    class CheckedStop(RuntimeError): pass
    def once(self, context):
        events.append(self.target)
        raise CheckedStop('inert dispatch boundary before any guest operation')
    monkeypatch.setattr(module.CoordinatedLinuxLiveProducer, '_acquire_once', once)
    with pytest.raises(CheckedStop):
        module.CoordinatedLinuxLiveProducer(controller, 'inert-run').acquire(object())
    assert events == ['trusted-linux-acquisition-lifecycle', module.TARGET]


def test_actual_producer_uses_real_registration_signature_and_inherited_cleanup(tmp_path, monkeypatch):
    """Real producer/lifecycle/register wrapper with inert guest boundaries."""
    from . import lab, coordinated_headless_registration, headless_coordinated_rollback_driver
    from .test_headless_native_acceptance import plan
    controller = object.__new__(lab.LabController)
    controller.root = tmp_path; controller.dry_run = False; controller.test_mode = False
    events = []
    @contextmanager
    def session(name): yield
    controller.mutation_session = session
    source = tmp_path / 'source'; source.write_bytes(b'inert-source')
    record = file_record(source)
    vm = {'qmp_socket': str(tmp_path / 'missing-qmp'), 'qga_socket': str(tmp_path / 'missing-qga')}
    state = {}
    run = {'profiles': {module.PROFILE: state}, 'artifacts': {'linux-headless-x64': record},
           'baseline_version': '5.0.3.13', 'candidate_version': '5.0.3.14',
           'profile_records': {'one': record}, 'runner_records': {'one': record},
           'semantic_helper_records': {'one': record}, 'headless_capability_record': record}
    controller.get_run = lambda run_id: run
    def start(*args): state['vm'] = vm; events.append('start')
    controller.start = start
    controller.guest_probe = lambda *args: events.append('probe')
    controller.run_steps = lambda *args: events.append('steps')
    controller.collect = lambda *args: events.append('collect')
    controller.archive_guest_evidence = lambda *args: events.append('archive')
    controller.owned_vm = lambda *args: vm
    def reset(*args): state['vm'] = None; events.append('reset'); return {'reset': 'inert'}
    controller.reset = reset
    monkeypatch.setattr(module.CoordinatedLinuxLiveProducer, '_binding', lambda self, context: run)
    monkeypatch.setattr(module.CoordinatedLinuxLiveProducer, '_wait_for_boot', lambda *args: events.append('boot'))
    monkeypatch.setattr(lab, 'validate_receipt', lambda *args, **kwargs: None)
    ordinary = {'raw_receipt': b'{}', 'state': 'acquired-not-accepted'}
    monkeypatch.setattr(module, 'acquire_linux_receipt', lambda *args: ordinary)
    semantic = {'cleanup': {'inert': True}}
    driver = SimpleNamespace(plan=plan(), run=lambda: semantic)
    monkeypatch.setattr(headless_coordinated_rollback_driver, 'build_coordinated_headless_driver', lambda *args: driver)
    actual_context = SimpleNamespace(binding=lambda: {'inert': 'binding'})
    def registration(actual_controller, run_id, native_plan, actual_semantic, context, capture):
        assert actual_controller is controller and run_id == 'inert-run'
        assert native_plan is driver.plan and actual_semantic is semantic
        assert context is actual_context and capture is ordinary
        events.append('register-five-arguments')
        return {'inert': 'registration-not-acceptance'}
    monkeypatch.setattr(coordinated_headless_registration, 'register', registration)
    result = module.CoordinatedLinuxLiveProducer(controller, 'inert-run').acquire(actual_context)
    assert events == ['start', 'boot', 'probe', 'steps', 'collect', 'archive', 'register-five-arguments', 'reset']
    assert result['target'] == module.TARGET
    assert set(result['semantics']) == module.SEMANTICS and 'rollback' not in result['semantics']
