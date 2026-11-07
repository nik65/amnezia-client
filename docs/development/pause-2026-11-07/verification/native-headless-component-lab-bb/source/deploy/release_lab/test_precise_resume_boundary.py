"""Synthetic pure boundary tests, never guest acceptance."""
import importlib.util
from pathlib import Path

import pytest
from deploy.release_lab import test_headless_coordinated_rollback_acceptance as fixtures

spec=importlib.util.spec_from_file_location('deploy.release_lab._staged_precise_resume',
    Path(__file__).with_name('headless_coordinated_rollback_acceptance.py'))
staged=importlib.util.module_from_spec(spec);spec.loader.exec_module(staged)


@pytest.fixture
def chain(monkeypatch):
    value=fixtures.chain.__wrapped__(monkeypatch)
    value[1]['resume_process'].update(invoked_at='2026-09-13T10:06:50.200000Z',
        observed_at='2026-09-13T10:06:50.800000Z')
    return value


def validate(chain):
    p,receipt,update,reboot,http=chain
    return staged.validate_coordinated_rollback_chain(p,receipt,update,reboot,http,
        expected_http_sources=fixtures.PINS)


def request(chain,seconds):
    p,receipt,*_=chain
    epoch=receipt['held_http']['epochs'][2]
    epoch['transcript']['rows']=[dict(method='GET',path=p.fixture.artifact_path,status=200,
        observed_at=fixtures.stamp('10:06:50')+seconds)]
    fixtures.rebind_transcript(epoch)


def test_full_valid_chain(chain):assert validate(chain)['runtime_evidence_validated'] is True


def test_fractional_get_before_invocation_rejected(chain):
    request(chain,0.1)
    with pytest.raises(staged.HeadlessAcceptanceError,match='artifact GET while held'):validate(chain)


@pytest.mark.parametrize('fraction',[0.2,0.5,0.9])
def test_get_at_or_after_invocation_allowed_even_before_observation(chain,fraction):
    request(chain,fraction)
    assert validate(chain)['runtime_evidence_validated'] is True


@pytest.mark.parametrize('field,value',[
    ('invoked_at',None),('invoked_at',True),('invoked_at',1),
    ('invoked_at','2026-09-13T10:06:50Z'),
    ('observed_at','2026-09-13T10:06:50Z'),
    ('invoked_at','2026-09-13T10:06:50.900000Z'),
    ('invoked_at','2026-09-13T10:04:05.000000Z'),
    ('observed_at','2026-09-13T10:08:00.000001Z'),
])
def test_missing_type_precision_and_chronology_rejected(chain,field,value):
    chain[1]['resume_process'][field]=value
    with pytest.raises(staged.HeadlessAcceptanceError,match='resume'):validate(chain)


def test_missing_invocation_rejected(chain):
    del chain[1]['resume_process']['invoked_at']
    with pytest.raises(staged.HeadlessAcceptanceError,match='resume invoked_at'):validate(chain)


def test_fast_child_terminal_before_pid_observation_is_causal(chain):
    chain[1]['resume_process']['observed_at']='2026-09-13T10:07:00.500000Z'
    # Original synthetic terminal is 10:07; final receipt is 10:08. The parent
    # may observe a still-live process after it has already written terminal.
    assert validate(chain)['runtime_evidence_validated'] is True


def test_invocation_after_terminal_rejected(chain):
    chain[1]['resume_process'].update(invoked_at='2026-09-13T10:07:00.100000Z',
        observed_at='2026-09-13T10:07:00.500000Z')
    with pytest.raises(staged.HeadlessAcceptanceError,match='resume chronology'):validate(chain)


def test_observation_after_actual_final_collection_rejected(chain):
    chain[1]['resume_process']['observed_at']='2026-09-13T10:08:00.000001Z'
    with pytest.raises(staged.HeadlessAcceptanceError,match='resume chronology'):validate(chain)
