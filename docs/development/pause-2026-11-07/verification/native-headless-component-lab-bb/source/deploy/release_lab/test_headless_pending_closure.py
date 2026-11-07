"""The new observer is part of the existing exact semantic-helper fence."""
from pathlib import Path
import pytest
from deploy.release_lab import lab

def test_pending_observer_is_bound_and_mutation_rejected(tmp_path,monkeypatch):
    observer='deploy/release_lab/headless_pending_observer.py'
    assert lab.SEMANTIC_HELPER_RELATIVES.count(observer)==1
    source=Path(__file__).with_name('headless_pending_observer.py').read_bytes()
    for relative in lab.SEMANTIC_HELPER_RELATIVES:
        path=tmp_path/relative;path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(source if relative==observer else b'inert exact helper fixture')
    monkeypatch.setattr(lab,'repo_root',lambda:tmp_path)
    records={relative:lab.artifact_record(tmp_path/relative) for relative in lab.SEMANTIC_HELPER_RELATIVES}
    lab.validate_semantic_helper_records(records)
    missing=dict(records);missing.pop(observer)
    with pytest.raises(lab.LabError,match='closure'):lab.validate_semantic_helper_records(missing)
    (tmp_path/observer).write_bytes(source+b'\n# changed after plan\n')
    with pytest.raises(lab.LabError,match='changed after plan'):lab.validate_semantic_helper_records(records)
