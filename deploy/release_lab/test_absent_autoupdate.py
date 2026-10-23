"""Staged pure validator regressions; synthetic receipts are not acceptance."""
import base64
from copy import deepcopy
import importlib.util
from pathlib import Path

import pytest
from deploy.release_lab import test_headless_coordinated_rollback_acceptance as fixtures

spec=importlib.util.spec_from_file_location('deploy.release_lab._staged_absent_autoupdate',
    Path(__file__).with_name('headless_coordinated_rollback_acceptance.py'))
staged=importlib.util.module_from_spec(spec);spec.loader.exec_module(staged)


@pytest.fixture
def chain(monkeypatch):
    return fixtures.chain.__wrapped__(monkeypatch)


def profiles(chain,original):
    p,receipt,update,reboot,http=chain
    paused=deepcopy(original)
    for row in paused['profiles']:
        if row.get('autoUpdate',False) is True:row['autoUpdate']=False
    sources=receipt['raw_sources']
    sources['original_profiles']=fixtures.raw(staged.FIXED_STORE,original)
    sources['paused_profiles']=fixtures.raw(staged.FIXED_STORE,paused)
    held=fixtures.decode(sources['held_record'])
    held.update(originalProfilesBase64=sources['original_profiles']['bytes_b64'],
        originalProfilesSha256=sources['original_profiles']['sha256'],
        pausedProfilesSha256=sources['paused_profiles']['sha256'],
        pausedProfileCount=sum(row.get('autoUpdate',False) is True for row in original['profiles']))
    sources['held_record']=fixtures.raw(staged.RECORD,held)
    return paused


def check(chain):
    p,receipt,update,reboot,http=chain
    return staged.validate_coordinated_held(p,receipt,reboot,update,http)


def test_missing_defaults_false_and_exact_shape_preserved(chain):
    original=dict(version=1,unknown='сохраняется',profiles=[dict(id='compat1'),dict(id='compat2',unknown={'keep':42}),dict(id='feed',autoUpdate=True)])
    paused=profiles(chain,original)
    assert check(chain)['held_snapshot_validated'] is True
    assert paused['profiles'][:2] == original['profiles'][:2]
    assert all('autoUpdate' not in row for row in paused['profiles'][:2])
    assert paused['profiles'][2]['autoUpdate'] is False


@pytest.mark.parametrize('value',[None,'false',0,1,[],{}])
def test_explicit_nonboolean_rejected(chain,value):
    profiles(chain,dict(version=1,profiles=[dict(id='compat',autoUpdate=value),dict(id='feed',autoUpdate=True)]))
    with pytest.raises(staged.HeadlessAcceptanceError,match='typed profile'):check(chain)


def test_bool_version_rejected(chain):
    profiles(chain,dict(version=True,profiles=[dict(id='feed',autoUpdate=True)]))
    with pytest.raises(staged.HeadlessAcceptanceError,match='original profile store'):check(chain)


def test_duplicate_ids_rejected(chain):
    profiles(chain,dict(version=1,profiles=[dict(id='same'),dict(id='same',autoUpdate=True)]))
    with pytest.raises(staged.HeadlessAcceptanceError,match='pause/nonpolicy'):check(chain)


def test_absent_cannot_be_serialized_as_explicit_false(chain):
    profiles(chain,dict(version=1,profiles=[dict(id='compat'),dict(id='feed',autoUpdate=True)]))
    sources=chain[1]['raw_sources'];paused=fixtures.decode(sources['paused_profiles'])
    paused['profiles'][0]['autoUpdate']=False
    sources['paused_profiles']=fixtures.raw(staged.FIXED_STORE,paused)
    with pytest.raises(staged.HeadlessAcceptanceError,match='pause/nonpolicy'):check(chain)
