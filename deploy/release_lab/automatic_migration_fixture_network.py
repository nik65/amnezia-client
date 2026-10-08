"""Explicit guest-egress contract for automatic-migration diagnostics only."""
import hashlib
import json

NETWORK = ('-netdev', 'user,id=labnet,restrict=off', '-device',
           'e1000,netdev=labnet,id=labnet-device')
POLICY = {'schema': 1, 'profile': 'server-router',
          'network': 'qemu-user-guest-egress-no-host-forward',
          'acceptance': False}


def bind(run_id, lane, policy_path, profile_record, golden_hash):
    if lane != 'publisher-diagnostic' or not run_id:
        raise ValueError('WAN fixture requires a diagnostic run')
    if policy_path.is_symlink() or json.loads(policy_path.read_text()) != POLICY:
        raise ValueError('WAN fixture policy changed')
    return {'run_id': run_id, 'lane': lane, **POLICY,
            'policy_path': str(policy_path),
            'policy_sha256': hashlib.sha256(policy_path.read_bytes()).hexdigest(),
            'profile_sha256': profile_record['sha256'], 'golden_sha256': golden_hash}


def validate(run, profile_id, policy_path, profile_path, golden_path, marker_path=None):
    record = run.get('automatic_migration_wan')
    if record is None:
        return False
    if profile_id != 'server-router':
        return False  # Ordinary product lanes always keep their original network.
    if run.get('lane') != 'publisher-diagnostic':
        raise ValueError('WAN fixture cannot enter candidate/release lanes')
    expected = bind(run['run_id'], run['lane'], policy_path,
                    {'sha256': hashlib.sha256(profile_path.read_bytes()).hexdigest()},
                    json.loads(golden_path.read_text())['base_sha256'])
    if record != expected:
        raise ValueError('WAN fixture immutable binding changed')
    if marker_path is not None:
        if marker_path.is_symlink() or not marker_path.is_file():
            raise ValueError('WAN fixture overlay marker missing')
        marker = json.loads(marker_path.read_text())
        overlay = marker_path.parent / 'overlay.qcow2'
        if marker != {'run_id': run['run_id'], 'profile': profile_id, 'overlay': str(overlay)}:
            raise ValueError('WAN fixture overlay ownership changed')
    return True
