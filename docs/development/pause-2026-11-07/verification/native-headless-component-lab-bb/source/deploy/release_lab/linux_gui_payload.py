"""Derive the installed GUI ELF identity without executing an installer.

Only the fixed Qt IFW metadata dumper and 7-Zip reader run on the lab host.
No receipt supplied by a caller can substitute for reading candidate bytes.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import re
import subprocess
import tempfile

TOOLS = (
    (Path('/mnt/c/Users/ivano/PycharmProjects/amnezia-client/dist/diagnostics/acceptance-50314-20261022/inert-tools/devtool'),
     '5f5a17dfc0ab67cc62d4be2a52937d60e874e84048f9a126cd45a7ca12f2e963'),
    (Path('/usr/lib/7zip/7z'),
     'b2a12fa672bc38fc33af43a99fa499533253236feb30e4f755a73fb64f01861d'),
)


class GuiPayloadError(RuntimeError):
    pass


def _record(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise GuiPayloadError('regular payload/tool file required')
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return {'path': str(path.absolute()), 'sha256': digest.hexdigest(), 'size': path.stat().st_size}


def derive_gui_payload(artifact, version):
    """Hash exactly bin/AmneziaVPN from a fresh dump of the bound .run."""
    if not isinstance(version, str) or not re.fullmatch(r'[0-9]+(?:\.[0-9]+){3}', version):
        raise GuiPayloadError('invalid release version')
    candidate = _record(artifact['path'])
    if any(candidate[key] != artifact[key] for key in ('sha256', 'size')):
        raise GuiPayloadError('candidate bytes differ before inert inspection')
    tools = [_record(path) for path, _ in TOOLS]
    if any(record['sha256'] != expected for record, (_, expected) in zip(tools, TOOLS)):
        raise GuiPayloadError('fixed inert inspection tool hash differs')
    with tempfile.TemporaryDirectory(prefix='amnezia-gui-inert-') as scratch:
        root = Path(scratch)
        dump = root / 'dump'
        subprocess.run([str(TOOLS[0][0]), 'dump', candidate['path'], str(dump)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=180)
        archive = dump / 'metadata' / 'AmneziaVPN' / (version + 'bin.7z')
        archive_record = _record(archive)
        if any(parent.is_symlink() for parent in archive.parents):
            raise GuiPayloadError('inert archive parent is a symlink')
        binary = root / 'application.elf'
        with binary.open('xb') as output:
            subprocess.run([str(TOOLS[1][0]), 'e', '-so', str(archive), 'bin/AmneziaVPN'],
                           check=True, stdout=output, stderr=subprocess.PIPE, timeout=120)
        if not 1024 <= binary.stat().st_size <= 256 * 1024 * 1024:
            raise GuiPayloadError('GUI ELF size outside bounds')
        with binary.open('rb') as stream:
            if stream.read(4) != b'\x7fELF':
                raise GuiPayloadError('GUI payload is not ELF')
        result = _record(binary)
        if _record(artifact['path']) != candidate or [_record(path) for path, _ in TOOLS] != tools:
            raise GuiPayloadError('candidate or inspection tools changed during derivation')
    return {'artifact': candidate, 'tools': tools, 'archive_sha256': archive_record['sha256'],
            'installed_relative_path': 'bin/AmneziaVPN', 'binary_sha256': result['sha256'],
            'binary_size': result['size'], 'installer_executed': False}
