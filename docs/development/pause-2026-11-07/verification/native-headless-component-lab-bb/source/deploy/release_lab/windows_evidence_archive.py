"""Immutable, hash-bound archival of exported Windows guest evidence."""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import stat
from pathlib import Path
from typing import Mapping


SHA256_RE = re.compile(r"[0-9a-f]{64}")
SAFE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}")
COPY_CHUNK = 1024 * 1024


class WindowsEvidenceArchiveError(RuntimeError):
    pass


def _owned_path(root: Path, child: Path, label: str) -> Path:
    root = Path(os.path.abspath(str(root)))
    child = Path(os.path.abspath(str(child)))
    if not root.is_dir() or root.is_symlink():
        raise WindowsEvidenceArchiveError("owned archive root is missing or symlinked")
    try:
        relative = child.relative_to(root)
    except ValueError as exc:
        raise WindowsEvidenceArchiveError(f"{label} escapes the owned archive root") from exc
    if not relative.parts:
        raise WindowsEvidenceArchiveError(f"{label} cannot be the archive root")
    current = root
    for part in relative.parts:
        current = current / part
        if current.exists() and current.is_symlink():
            raise WindowsEvidenceArchiveError(f"{label} contains a symlink")
    return child


def _mkdir_owned(root: Path, directory: Path) -> Path:
    directory = _owned_path(root, directory, "archive directory")
    relative = directory.relative_to(Path(os.path.abspath(str(root))))
    current = Path(os.path.abspath(str(root)))
    for part in relative.parts:
        current = current / part
        try:
            current.mkdir()
        except FileExistsError:
            pass
        if current.is_symlink() or not current.is_dir():
            raise WindowsEvidenceArchiveError("archive directory is not an owned regular directory tree")
    return directory


def _regular_source(path: Path) -> Path:
    path = Path(os.path.abspath(str(path)))
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise WindowsEvidenceArchiveError("evidence source is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise WindowsEvidenceArchiveError("evidence source must be a regular non-symlink file")
    return path


def _safe_id(label: str, value: str) -> str:
    if not SAFE_ID_RE.fullmatch(value):
        raise WindowsEvidenceArchiveError(f"invalid {label}")
    return value


def archive_exact_file(
    owned_root: Path,
    source: Path,
    archive_dir: Path,
    *,
    expected_sha256: str,
    expected_size: int,
    kind: str,
    vm_id: str,
    case_id: str,
    attempt_nonce: str,
) -> dict:
    """Create one immutable evidence file and return its verified record.

    A zero-byte exclusive reservation prevents a concurrent or repeated attempt
    from replacing earlier evidence.  The complete file is written to a unique
    sibling and atomically replaces only that reservation.
    """
    if not SHA256_RE.fullmatch(expected_sha256) or isinstance(expected_size, bool) or expected_size <= 0:
        raise WindowsEvidenceArchiveError("expected evidence hash/size is invalid")
    kind = _safe_id("evidence kind", kind)
    case_id = _safe_id("case id", case_id)
    attempt_nonce = _safe_id("attempt nonce", attempt_nonce)
    if not vm_id or len(vm_id) > 128:
        raise WindowsEvidenceArchiveError("invalid VM id")
    source = _regular_source(source)
    archive_dir = _mkdir_owned(Path(owned_root), Path(archive_dir))
    vm_tag = hashlib.sha256(vm_id.encode("utf-8")).hexdigest()[:16]
    suffix = source.suffix.lower() if source.suffix.lower() in {".png", ".json", ".log", ".txt"} else ".bin"
    destination = _owned_path(Path(owned_root), archive_dir / f"{kind}-{attempt_nonce}-{vm_tag}{suffix}", "archive destination")
    temporary = _owned_path(Path(owned_root), archive_dir / f".{destination.name}.tmp.{os.getpid()}.{secrets.token_hex(8)}", "archive temporary")

    reserved = False
    try:
        reserve_fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(reserve_fd)
        reserved = True
    except FileExistsError as exc:
        raise WindowsEvidenceArchiveError("immutable evidence destination already exists") from exc

    digest = hashlib.sha256()
    observed_size = 0
    try:
        output_fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with source.open("rb") as input_stream, os.fdopen(output_fd, "wb") as output_stream:
            while True:
                chunk = input_stream.read(COPY_CHUNK)
                if not chunk:
                    break
                observed_size += len(chunk)
                if observed_size > expected_size:
                    raise WindowsEvidenceArchiveError("evidence source exceeds the expected size")
                digest.update(chunk)
                output_stream.write(chunk)
            output_stream.flush()
            os.fsync(output_stream.fileno())
        if observed_size != expected_size or digest.hexdigest() != expected_sha256:
            raise WindowsEvidenceArchiveError("evidence source hash/size mismatch")
        os.replace(temporary, destination)
        reserved = False
        try:
            directory_fd = os.open(archive_dir, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError:
            # Directory fsync is unavailable on some Windows filesystems; the
            # atomic file replacement and file fsync still completed.
            pass
    except Exception:
        try:
            temporary.unlink(missing_ok=True)
        finally:
            if reserved:
                destination.unlink(missing_ok=True)
        raise

    record = {
        "path": str(destination),
        "sha256": expected_sha256,
        "size": expected_size,
        "kind": kind,
        "vm_id": vm_id,
        "case_id": case_id,
        "attempt_nonce": attempt_nonce,
    }
    return validate_archive_record(Path(owned_root), record, kind=kind, vm_id=vm_id, case_id=case_id, attempt_nonce=attempt_nonce)


def validate_archive_record(
    owned_root: Path,
    record: Mapping,
    *,
    kind: str,
    vm_id: str,
    case_id: str,
    attempt_nonce: str,
) -> dict:
    """Reopen and rehash an immutable archive before the final gate."""
    expected_identity = {"kind": kind, "vm_id": vm_id, "case_id": case_id, "attempt_nonce": attempt_nonce}
    if any(record.get(key) != value for key, value in expected_identity.items()):
        raise WindowsEvidenceArchiveError("archive record identity mismatch")
    sha256 = record.get("sha256")
    size = record.get("size")
    if not SHA256_RE.fullmatch(str(sha256 or "")) or isinstance(size, bool) or not isinstance(size, int) or size <= 0:
        raise WindowsEvidenceArchiveError("archive record hash/size is invalid")
    raw_path = record.get("path")
    if not isinstance(raw_path, str) or not Path(raw_path).is_absolute():
        raise WindowsEvidenceArchiveError("archive record path is not absolute")
    path = _owned_path(Path(owned_root), Path(raw_path), "archived evidence")
    path = _regular_source(path)
    digest = hashlib.sha256()
    observed_size = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(COPY_CHUNK), b""):
            observed_size += len(chunk)
            if observed_size > size:
                raise WindowsEvidenceArchiveError("archived evidence exceeds its recorded size")
            digest.update(chunk)
    if observed_size != size or digest.hexdigest() != sha256:
        raise WindowsEvidenceArchiveError("archived evidence no longer matches its record")
    return dict(record)
