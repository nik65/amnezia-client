"""Read-only existing-generation configuration and native target attestation.

This module never imports preparation or changes engines, routes or generation state.
"""
import hashlib
import ipaddress
from pathlib import Path
import re

PARAMS = ('Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'S3', 'S4', 'H1', 'H2', 'H3', 'H4',
          'HeaderProtectionKey', 'ContentPaddingAddition', 'RekeyAfterTime',
          'RekeyTimeout', 'RejectAfterTime', 'KeepaliveTimeout',
          'MaxHandshakeAttempts', 'RandomTrailers', 'DisableCookies')
KEY = re.compile(r'^[A-Za-z0-9+/]{43}=$')


def parse_config(raw):
    interface, peers, current = {}, [], None
    for line in raw.decode().splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if line == '[Interface]':
            if interface:
                raise ValueError('duplicate interface')
            current = interface
        elif line == '[Peer]':
            current = {}
            peers.append(current)
        elif current is None or '=' not in line:
            raise ValueError('configuration syntax')
        else:
            key, value = (part.strip() for part in line.split('=', 1))
            if key in current or '\n' in value:
                raise ValueError('duplicate configuration key')
            current[key] = value
    if not peers or not KEY.fullmatch(interface.get('PrivateKey', '')):
        raise ValueError('missing identity')
    if not set(interface) <= set(PARAMS) | {'PrivateKey', 'Address', 'ListenPort', 'MTU', 'PostUp', 'PostDown', 'SaveConfig', 'DNS', 'I1', 'I2', 'I3', 'I4', 'I5'}:
        raise ValueError('unknown interface key')
    network = ipaddress.ip_interface(interface['Address'])
    if network.version != 4:
        raise ValueError('only IPv4 isolation supported')
    seen = set()
    for peer in peers:
        if set(peer) - {'PublicKey', 'PresharedKey', 'AllowedIPs', 'PersistentKeepalive'}:
            raise ValueError('unsupported peer field')
        if not KEY.fullmatch(peer.get('PublicKey', '')) or peer['PublicKey'] in seen:
            raise ValueError('peer identity')
        seen.add(peer['PublicKey'])
        if 'PresharedKey' in peer and not KEY.fullmatch(peer['PresharedKey']):
            raise ValueError('PSK')
        address = ipaddress.ip_interface(peer['AllowedIPs'])
        if address.version != 4 or address.network.prefixlen != 32 or address.ip not in network.network or address.ip == network.ip:
            raise ValueError('ambiguous peer route')
    ips = [ipaddress.ip_interface(peer['AllowedIPs']).ip for peer in peers]
    if len(set(ips)) != len(ips):
        raise ValueError('duplicate peer address')
    return interface, peers



def validate_ready_target(run, state, source_interface, source_peers, target_interface, target_peers, automatic):
    """Ready reuse must still observe the actual configured endpoint and peers."""
    if (target_interface['PrivateKey'] != source_interface['PrivateKey']
            or target_interface['Address'] != source_interface['Address']
            or target_peers != source_peers
            or any(target_interface.get(key) != value for key, value in state['parameters'].items())):
        raise ValueError('migration_ready_drift')
    target = state['targetContainer']
    rows = run('docker', 'exec', target, 'awg', 'show', 'awg0', 'dump').decode().strip().splitlines()
    if (len(rows) != len(source_peers) + 1 or len(rows[0].split('\t')) < 3
            or rows[0].split('\t')[1] != state['serverPublicKey']
            or rows[0].split('\t')[2] != target_interface['ListenPort']):
        raise ValueError('migration_ready_drift')
    observed = {row.split('\t')[0]: row.split('\t') for row in rows[1:]}
    if set(observed) != {peer['PublicKey'] for peer in source_peers}:
        raise ValueError('migration_ready_drift')
    for peer in source_peers:
        row = observed[peer['PublicKey']]
        if len(row) < 4 or row[1] != peer.get('PresharedKey', '(none)') or row[3] != peer['AllowedIPs']:
            raise ValueError('migration_ready_drift')
    accepted = {}
    for line in run('docker', 'exec', target, 'awg', 'showconf', 'awg0').decode().splitlines():
        if '=' in line:
            key, value = (part.strip() for part in line.split('=', 1))
            if key in state['parameters']:
                if key in ('RandomTrailers', 'DisableCookies'):
                    value = {'false': '0', 'true': '1', 'off': '0', 'on': '1'}.get(value, value)
                accepted[key] = value
    # Official tools omit ContentPaddingAddition when its native default is 0.
    # Do not supply defaults for any capability/identity or nonzero setting.
    if state['parameters'].get('ContentPaddingAddition') == '0':
        accepted.setdefault('ContentPaddingAddition', '0')
    if accepted != state['parameters']:
        raise ValueError('migration_ready_drift')
    if automatic:
        from trusted_image import BINARY_SHA256
        live = run('docker', 'exec', target, 'sh', '-c',
                   'set -eu; engine=$(cat /migration/engine.pid); '
                   'case "$engine" in ""|*[!0-9]*) exit 1;; esac; '
                   'kill -0 "$engine"; sha256sum "/proc/$engine/exe"').decode().split()
        if len(live) != 2 or live[0] != BINARY_SHA256:
            raise ValueError('migration_ready_drift')



def validate_existing_target(directory, value, ready, runner):
    """Require the existing source/target contract before control-only maintenance."""
    directory = Path(directory)
    source = value['source']
    if source not in ('amnezia-awg', 'amnezia-awg2'):
        raise ValueError('migration_ready_drift')
    target = value['target']
    target_id = value['containers'][target]['id']
    request = value['request']
    if (not target_id or ready.get('containerId') != source
            or ready.get('targetContainer') != target
            or ready.get('generation') != request['generation']
            or ready.get('endpoint') != str(request['host']) + ':' + str(request['port'])):
        raise ValueError('migration_ready_drift')
    source_path = '/opt/amnezia/awg/' + ('wg0.conf' if source == 'amnezia-awg' else 'awg0.conf')
    raw = runner('docker', 'exec', value['sourceId'], 'cat', source_path)
    if hashlib.sha256(raw).hexdigest() != value['sourceDigest']:
        raise ValueError('migration_ready_drift')
    source_interface, source_peers = parse_config(raw)
    config = directory / 'awg0.conf'
    if config.is_symlink() or not config.is_file():
        raise ValueError('migration_ready_drift')
    target_raw = config.read_bytes()
    if runner('docker', 'exec', target_id, 'cat', '/migration/awg0.conf') != target_raw:
        raise ValueError('migration_ready_drift')
    target_interface, target_peers = parse_config(target_raw)
    if target_interface['ListenPort'] != str(request['port']):
        raise ValueError('migration_ready_drift')
    mapping = ready.get('peers', {})
    if set(mapping) != {peer['PublicKey'] for peer in source_peers}:
        raise ValueError('migration_ready_drift')
    for peer in source_peers:
        item = mapping[peer['PublicKey']]
        address = str(ipaddress.ip_interface(peer['AllowedIPs']).ip)
        if (item.get('sourceIp') != address or item.get('targetIp') != address
                or item.get('clientAddress') != peer['AllowedIPs']):
            raise ValueError('migration_ready_drift')
    # The journal never persisted an automatic-mode flag. Maintenance therefore
    # always requires the approved live native engine proof, without inferring
    # mode or converting an unknown/manual engine into a supported one.
    native_state = dict(ready, targetContainer=target_id)
    validate_ready_target(runner, native_state, source_interface, source_peers,
                          target_interface, target_peers, True)
