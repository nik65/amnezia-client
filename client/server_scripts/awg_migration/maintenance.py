"""Explicit administrator maintenance of one existing migration's control helpers."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

from journal import Journal, CONTROL_LISTENER_PROBE
from ready_validation import validate_existing_target

ROOT = Path('/opt/amnezia/awg-migration')


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, timeout=180).stdout


def verify_loaded(journal, expected, runner):
    for _, helper, role in journal.control_helpers():
        runner('docker', 'exec', helper['Id'], 'python', '-c', CONTROL_LISTENER_PROBE)
        probe = ('import json,pathlib; r=json.loads(pathlib.Path("/migration/control-loaded-' + role + '.json").read_text()); '
                 'assert r["role"]==' + repr(role) + '; '
                 'assert r["hashes"]==' + repr(expected) + '; '
                 'assert r["processStart"]==pathlib.Path("/proc/1/stat").read_text().split()[21]')
        runner('docker', 'exec', helper['Id'], 'python', '-c', probe)


def maintain(source, generation, expected_journal_sha256, recipe_directory=None,
             root=ROOT, runner=run):
    if (source not in ('amnezia-awg', 'amnezia-awg2')
            or type(generation) is not int or not 1 <= generation <= 9007199254740991
            or not isinstance(expected_journal_sha256, str)
            or not re.fullmatch('[a-f0-9]{64}', expected_journal_sha256)):
        raise ValueError('maintenance request')
    # Import lazily so platform-independent tests can inspect request guards.
    import fcntl
    root = Path(root)
    directory = root / source / str(generation)
    # Never create a scope, generation, lock, VPN, or collector in maintenance.
    if root.is_symlink() or directory.parent.is_symlink() or directory.is_symlink():
        raise ValueError('maintenance path')
    lock_path = root / '.prepare.lock'
    if lock_path.is_symlink():
        raise ValueError('maintenance lock')
    with open(lock_path, 'r+') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        journal_path = directory / 'transaction.json'
        if journal_path.is_symlink() or (directory / 'ready.json').is_symlink():
            raise ValueError('maintenance state')
        raw = journal_path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected_journal_sha256:
            raise ValueError('maintenance journal changed')
        value = json.loads(raw)
        if value.get('nativeFeedSha256') is not None:
            # Native runtime/loaded-FD maintenance is not implemented. Never
            # replace its source pair with a legacy-only recipe or weaken its gate.
            raise ValueError('native_feed_existing_generation_requires_maintenance')
        ready = json.loads((directory / 'ready.json').read_bytes())
        if (value.get('phase') != 'ready' or value.get('source') != source
                or 'controlMaintenance' in value
                or type(value.get('request', {}).get('generation')) is not int
                or value.get('request', {}).get('generation') != generation
                or ready.get('containerId') != source
                or type(ready.get('generation')) is not int
                or ready['generation'] != generation
                or ready.get('targetContainer') != value.get('target')):
            raise ValueError('maintenance scope binding')
        for name in ('transaction.json', 'ready.json', 'awg0.conf', 'awg0.native.conf',
                     'signing.pem', 'start.sh', 'service.py', 'target.py', 'grants.sqlite3'):
            path = directory / name
            if path.is_symlink() or not path.is_file():
                raise ValueError('maintenance required state')
        backup = directory / '.control-maintenance'
        if backup.is_symlink() or (backup.exists() and not backup.is_dir()):
            raise ValueError('maintenance backup path')
        if backup.exists() and any(path.is_symlink() or not path.is_file() for path in backup.iterdir()):
            raise ValueError('maintenance backup state')
        journal = Journal(directory, runner, value)
        journal.control_helpers()
        journal.protected_control_state(require_native=True)
        validate_existing_target(directory, value, ready, runner)
        recipe_directory = Path(recipe_directory or Path(__file__).parent)
        candidate = {name: hashlib.sha256((recipe_directory / name).read_bytes()).hexdigest()
                     for name in ('service.py', 'target.py')}
        if candidate == journal.control_hashes():
            # Journal's legacy no-op pins the recipe; validate first so a
            # missing/stale startup proof cannot mutate even that metadata.
            verify_loaded(journal, candidate, runner)
        def validate():
            journal.protected_control_state(require_native=True)
            validate_existing_target(directory, journal.value, ready, runner)
        journal.maintain_controls(recipe_directory, validate=validate)
        # A no-op recipe still needs proof of bytes loaded by both current PID1s.
        expected = journal.control_hashes()
        verify_loaded(journal, expected, runner)
        return {'maintained': True, 'source': source, 'generation': generation,
                'controlHashes': expected, 'loaded': True,
                'journalSha256': hashlib.sha256(journal_path.read_bytes()).hexdigest()}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', required=True)
    parser.add_argument('--generation', required=True, type=int)
    parser.add_argument('--expected-journal-sha256', required=True)
    args = parser.parse_args()
    try:
        if os.geteuid() != 0:
            raise ValueError('administrator required')
        print(json.dumps(maintain(args.source, args.generation, args.expected_journal_sha256),
                         separators=(',', ':')))
    except Exception:
        # Private subprocess output and server configuration never enter client logs.
        print(json.dumps({'maintained': False, 'reason': 'migration_control_maintenance_failed'}))
        raise SystemExit(1)
