"""Inert orchestration tests. These do not constitute guest acceptance."""
from types import SimpleNamespace

import pytest

from . import headless_coordinated_rollback_driver as module
from .test_headless_native_acceptance import plan


def configured(tmp_path, monkeypatch, fail=None):
    events = []
    def event(name, result=None):
        events.append(name)
        if fail == name:
            raise RuntimeError(name)
        return result if result is not None else {}
    class Observation:
        def __init__(self, *args, **kwargs): pass
        def __enter__(self): event('observer-arm'); return self
        def collect(self): return event('pending', {})
        def __exit__(self, *args): event('observer-close')
    monkeypatch.setattr(module, 'PendingObservation', Observation)
    monkeypatch.setattr(module, 'validate_update_receipt', lambda *args: event('validate-update'))
    native = SimpleNamespace(
        identity=lambda release, label: event('identity-' + label),
        cli_json=lambda *args: event('doctor'),
        stage_profile=lambda: event('enable-real-profile', {'profile_store': {}}),
        collect_update_stable=lambda: {},
        wait_for=lambda *args, **kwargs: event('stable'),
        build_update_receipt=lambda **kwargs: event('build-update', {'update': 'original'}),
        raw_absence=lambda path: event('candidate-journal-absence'),
        _common_receipt=lambda operation, stamp: {'operation': operation})
    preexisting = SimpleNamespace(
        plan=plan(),  # dataclass inert orchestration fixture, never acceptance
        prepare_and_connect=lambda: event('connect'),
        crash_and_restart=lambda *args: event('crash-restart'),
        promote_systemd_baseline=lambda *args: event('promote'),
        cleanup=lambda *args: event('network-cleanup'),
        boot_id=lambda *args: 'boot-1')
    server = SimpleNamespace(
        start=lambda: event('http-start'), reset=lambda: event('http-reset'),
        collect=lambda: event('http-initial', {'http': 'original'}),
        snapshot_start=lambda: event('http-boot-ready'),
        ledger=lambda: event('ledger', {'epochs': ['boot-1', 'boot-2', 'boot-3']}),
        cleanup=lambda: event('http-cleanup'), abort=lambda: event('http-abort'))
    server.expected_sources = lambda: {'source': 'inert-test-source'}
    coordinated = SimpleNamespace(
        close=lambda: event('archive-close'),
        archive_original=lambda name, value: event('retain-' + name.split('-', 2)[-1]),
        raw_absence=lambda path: event('candidate-journal-absence'),
        stage_disabled_owned_profile=lambda: event('disabled-profile'),
        trigger_and_wait_held=lambda *args: event('rollback-held', {
            'rollback_process': {}, 'coordinator_process': {}, 'raw_sources': {'held_record': {}}}),
        reboot_held=lambda *args: event('held-reboot', {'held_reboot': {}, 'raw_sources': {}}),
        resume_and_collect=lambda *args: event('explicit-resume', {'resume_process': {}, 'raw_sources': {}}))
    collector = SimpleNamespace(reboot_and_collect=lambda *args: event(
        'candidate-reboot', {'boot_id_before': 'boot-1', 'boot_id_after': 'boot-2', 'raw_sources': {}}))
    driver = module.CoordinatedHeadlessDriver(
        plan(), native, server, preexisting, collector, tmp_path, coordinated=coordinated,
        candidate_validator=lambda *args: event('validate-candidate-reboot'),
        held_validator=lambda *args: event('validate-held'),
        held_reboot_validator=lambda *args: event('validate-held-reboot'),
        validator=lambda *args, **kwargs: event('validate-coordinated', {'authority': 'retained14Coordinator'}))
    driver._archive = lambda name, value: event('archive-' + name, tmp_path / (name + '.json'))
    return driver, events


def test_distinct_chain_closes_network_before_update_and_keeps_feed_across_reboots(tmp_path, monkeypatch):
    driver, events = configured(tmp_path, monkeypatch)
    result = driver.run()
    assert events.index('disabled-profile') < events.index('network-cleanup') < events.index('enable-real-profile')
    assert events.index('observer-arm') < events.index('enable-real-profile') < events.index('pending')
    assert events.index('candidate-reboot') < events.index('rollback-held') < events.index('held-reboot')
    assert events.index('candidate-reboot') < events.index('validate-candidate-reboot') < events.index('rollback-held')
    assert events.index('ledger') < events.index('candidate-reboot')
    assert events.index('held-reboot') < events.index('explicit-resume') < max(i for i, item in enumerate(events) if item == 'ledger')
    assert events.index('held-reboot') < events.index('validate-held-reboot') < events.index('explicit-resume')
    assert events.index('rollback-held') < events.index('validate-held') < events.index('held-reboot')
    assert events.count('http-boot-ready') == 2
    assert events.index('validate-coordinated') < events.index('http-cleanup')
    assert 'http-abort' not in events
    assert result['capability'] == 'headless-coordinated-rollback-with-pause'
    assert result['legacy_native_rollback_pass'] is False and result['trustedExport'] is False
    assert not {'rollback', 'reboot'}.intersection(result)


@pytest.mark.parametrize('failure', ['http-start', 'candidate-reboot', 'rollback-held',
                                     'validate-candidate-reboot', 'validate-held', 'held-reboot', 'validate-held-reboot',
                                     'explicit-resume', 'ledger', 'validate-coordinated'])
def test_failure_stops_owned_http_and_preserves_primary(tmp_path, monkeypatch, failure):
    driver, events = configured(tmp_path, monkeypatch, failure)
    with pytest.raises(RuntimeError, match=failure):
        driver.run()
    assert events.count('http-abort') == 1
    assert events.count('network-cleanup') == 1
    assert 'archive-coordinated-failure' in events


def test_early_failure_retires_preexisting_fixture(tmp_path, monkeypatch):
    driver, events = configured(tmp_path, monkeypatch, 'promote')
    with pytest.raises(RuntimeError, match='promote'):
        driver.run()
    assert events.count('network-cleanup') == 1
    assert 'http-start' not in events


def test_cleanup_failure_is_not_accepted(tmp_path, monkeypatch):
    driver, events = configured(tmp_path, monkeypatch, 'http-cleanup')
    with pytest.raises(RuntimeError, match='http-cleanup'):
        driver.run()
    assert events.count('http-abort') == 1


def test_archive_error_cannot_replace_original_or_skip_cleanup(tmp_path, monkeypatch):
    driver, events = configured(tmp_path, monkeypatch, 'rollback-held')
    def archive(name, value):
        if name == 'coordinated-failure': raise OSError('archive failed')
        return tmp_path / name
    driver._archive = archive
    with pytest.raises(RuntimeError, match='rollback-held') as error:
        driver.run()
    assert any('archive unavailable' in note for note in error.value.__notes__)
    assert 'http-abort' in events


@pytest.mark.parametrize('timeout', [True, 0, 601, 1.5])
def test_invalid_deadlines_never_touch_fixture(tmp_path, monkeypatch, timeout):
    driver, events = configured(tmp_path, monkeypatch)
    with pytest.raises(ValueError): driver.run(update_timeout=timeout)
    assert events == []
