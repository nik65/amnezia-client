import hashlib
from pathlib import Path

import pytest

from deploy.release_lab import linux_gui_payload as payload


def setup_payload(tmp_path, monkeypatch):
    candidate = tmp_path / 'candidate.run'
    candidate.write_bytes(b'inert-installer')
    tools = []
    for name in ('devtool', '7z'):
        path = tmp_path / name
        path.write_bytes(name.encode())
        tools.append((path, hashlib.sha256(path.read_bytes()).hexdigest()))
    monkeypatch.setattr(payload, 'TOOLS', tuple(tools))
    calls = []
    def run(args, **kwargs):
        calls.append(args)
        if args[1] == 'dump':
            archive = Path(args[3]) / 'metadata/AmneziaVPN/5.0.3.14bin.7z'
            archive.parent.mkdir(parents=True)
            archive.write_bytes(b'archive')
        else:
            assert args[1:3] == ['e', '-so']
            assert args[-1] == 'bin/AmneziaVPN'
            kwargs['stdout'].write(b'\x7fELF' + b'x' * 1024)
    monkeypatch.setattr(payload.subprocess, 'run', run)
    return candidate, payload._record(candidate), tools, calls


def test_derives_from_actual_bytes_using_inert_tools(tmp_path, monkeypatch):
    candidate, record, tools, calls = setup_payload(tmp_path, monkeypatch)
    result = payload.derive_gui_payload(record, '5.0.3.14')
    assert result['binary_sha256'] == hashlib.sha256(b'\x7fELF' + b'x' * 1024).hexdigest()
    assert result['installer_executed'] is False
    assert [entry[0] for entry in calls] == [str(pair[0]) for pair in tools]
    assert all(entry[0] != str(candidate) for entry in calls)


@pytest.mark.parametrize('field,value', [('sha256', '0' * 64), ('size', 99)])
def test_changed_candidate_rejected_before_tools(tmp_path, monkeypatch, field, value):
    _, record, _, calls = setup_payload(tmp_path, monkeypatch)
    record[field] = value
    with pytest.raises(payload.GuiPayloadError, match='candidate bytes differ'):
        payload.derive_gui_payload(record, '5.0.3.14')
    assert not calls


def test_unapproved_tool_rejected(tmp_path, monkeypatch):
    _, record, tools, calls = setup_payload(tmp_path, monkeypatch)
    tools[0][0].write_bytes(b'changed')
    with pytest.raises(payload.GuiPayloadError, match='tool hash differs'):
        payload.derive_gui_payload(record, '5.0.3.14')
    assert not calls


def test_candidate_replacement_during_inspection_rejected(tmp_path, monkeypatch):
    candidate, record, _, _ = setup_payload(tmp_path, monkeypatch)
    original = payload.subprocess.run
    def run(*args, **kwargs):
        original(*args, **kwargs)
        candidate.write_bytes(b'changed-during-dump')
    monkeypatch.setattr(payload.subprocess, 'run', run)
    with pytest.raises(payload.GuiPayloadError, match='changed during derivation'):
        payload.derive_gui_payload(record, '5.0.3.14')


def test_invalid_version_never_runs_tools(tmp_path, monkeypatch):
    _, record, _, calls = setup_payload(tmp_path, monkeypatch)
    with pytest.raises(payload.GuiPayloadError, match='invalid release version'):
        payload.derive_gui_payload(record, '../../evil')
    assert not calls
