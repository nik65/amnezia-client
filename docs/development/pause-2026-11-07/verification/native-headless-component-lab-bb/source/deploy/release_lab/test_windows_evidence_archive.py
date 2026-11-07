from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

try:
    from windows_evidence_archive import WindowsEvidenceArchiveError, archive_exact_file, validate_archive_record
except ImportError:
    from deploy.release_lab.windows_evidence_archive import WindowsEvidenceArchiveError, archive_exact_file, validate_archive_record


def _archive(root: Path, source: Path, **overrides):
    content = source.read_bytes()
    args = {
        "expected_sha256": hashlib.sha256(content).hexdigest(), "expected_size": len(content),
        "kind": "app-window", "vm_id": "{11111111-1111-1111-1111-111111111111}",
        "case_id": "outer-interactive", "attempt_nonce": "attempt-1",
    }
    args.update(overrides)
    return archive_exact_file(root, source, root / "exports" / "run" / "windows-x64", **args)


def test_archive_creates_missing_owned_tree_and_revalidates(tmp_path: Path) -> None:
    root = tmp_path / "state"; root.mkdir()
    source = tmp_path / "source.png"; source.write_bytes(b"png-evidence" * 500)
    record = _archive(root, source)
    assert Path(record["path"]).is_file()
    assert validate_archive_record(root, record, kind="app-window", vm_id=record["vm_id"], case_id="outer-interactive", attempt_nonce="attempt-1") == record


def test_archive_mismatch_removes_temporary_and_reservation(tmp_path: Path) -> None:
    root = tmp_path / "state"; root.mkdir()
    source = tmp_path / "source.png"; source.write_bytes(b"actual")
    with pytest.raises(WindowsEvidenceArchiveError, match="mismatch"):
        _archive(root, source, expected_sha256="0" * 64)
    archive_dir = root / "exports" / "run" / "windows-x64"
    assert archive_dir.is_dir() and list(archive_dir.iterdir()) == []
    with pytest.raises(WindowsEvidenceArchiveError, match="mismatch"):
        _archive(root, source, expected_size=len(source.read_bytes()) + 1)
    assert list(archive_dir.iterdir()) == []


def test_archive_never_overwrites_same_attempt(tmp_path: Path) -> None:
    root = tmp_path / "state"; root.mkdir()
    source = tmp_path / "source.png"; source.write_bytes(b"first")
    first = _archive(root, source)
    source.write_bytes(b"second")
    with pytest.raises(WindowsEvidenceArchiveError, match="already exists"):
        _archive(root, source)
    assert Path(first["path"]).read_bytes() == b"first"


def test_archive_rejects_escape_and_symlink_tree(tmp_path: Path) -> None:
    root = tmp_path / "state"; root.mkdir()
    source = tmp_path / "source.png"; source.write_bytes(b"evidence")
    with pytest.raises(WindowsEvidenceArchiveError, match="escapes"):
        archive_exact_file(root, source, tmp_path / "outside", expected_sha256=hashlib.sha256(b"evidence").hexdigest(), expected_size=8, kind="uac", vm_id="vm", case_id="outer-interactive", attempt_nonce="attempt-1")
    target = root / "real"; target.mkdir()
    link = root / "exports"
    try:
        link.symlink_to(target, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("directory symlinks unavailable")
    with pytest.raises(WindowsEvidenceArchiveError, match="symlink"):
        _archive(root, source)


def test_gate_revalidation_detects_tampering_and_forged_identity(tmp_path: Path) -> None:
    root = tmp_path / "state"; root.mkdir()
    source = tmp_path / "source.png"; source.write_bytes(b"trusted")
    record = _archive(root, source)
    Path(record["path"]).write_bytes(b"tampered")
    with pytest.raises(WindowsEvidenceArchiveError, match="exceeds|no longer matches"):
        validate_archive_record(root, record, kind="app-window", vm_id=record["vm_id"], case_id="outer-interactive", attempt_nonce="attempt-1")
    forged = {**record, "kind": True}
    with pytest.raises(WindowsEvidenceArchiveError, match="identity mismatch"):
        validate_archive_record(root, forged, kind="app-window", vm_id=record["vm_id"], case_id="outer-interactive", attempt_nonce="attempt-1")
    forged = {**record, "size": False}
    with pytest.raises(WindowsEvidenceArchiveError, match="hash/size"):
        validate_archive_record(root, forged, kind="app-window", vm_id=record["vm_id"], case_id="outer-interactive", attempt_nonce="attempt-1")
