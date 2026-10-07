"""Invoked only by the authenticated self-hosted administrator client.

Creates a separate Docker network namespace; never changes the old VPN Device.
All command output stays private. Success means provisioned, not client acceptance.
"""
import argparse
import fcntl
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import tempfile
import time
from journal import Journal, inspect as inspect_container
from policy import namespace_snapshot, firewall_script, client_policy_epoch, mtu

ROOT = Path('/opt/amnezia/awg-migration')
COLLECTOR_ROOT = Path('/opt/amnezia/client-logs')
PARAMS = ('Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'S3', 'S4', 'H1', 'H2', 'H3', 'H4',
          'HeaderProtectionKey', 'ContentPaddingAddition', 'RekeyAfterTime',
          'RekeyTimeout', 'RejectAfterTime', 'KeepaliveTimeout',
          'MaxHandshakeAttempts', 'RandomTrailers', 'DisableCookies')
KEY = re.compile(r'^[A-Za-z0-9+/]{43}=$')


def run(*args, input=None):
    return subprocess.run(args, input=input, check=True, capture_output=True, timeout=180).stdout


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
    ips = [peer['AllowedIPs'] for peer in peers]
    if len(set(ips)) != len(ips):
        raise ValueError('duplicate peer address')
    return interface, peers


def atomic(path, value):
    tmp = path.with_suffix('.tmp')
    with open(tmp, 'w', encoding='utf-8') as stream:
        os.fchmod(stream.fileno(), 0o600)
        json.dump(value, stream, separators=(',', ':'), sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(tmp, path)


def prepare(args):
    if os.geteuid() != 0 or args.source not in ('amnezia-awg', 'amnezia-awg2'):
        raise ValueError('administrator/source required')
    if not re.fullmatch(r'[a-zA-Z0-9./:_-]+@sha256:[a-f0-9]{64}', args.image):
        raise ValueError('AWG3 immutable image required')
    if not re.fullmatch(r'[A-Za-z0-9.-]{1,253}', args.host) or not 1024 <= args.port <= 65535 or not 1 <= args.generation <= 9007199254740991:
        raise ValueError('request')
    config_path = '/opt/amnezia/awg/' + ('wg0.conf' if args.source == 'amnezia-awg' else 'awg0.conf')
    raw = run('docker', 'exec', args.source, 'cat', config_path)
    interface, peers = parse_config(raw)
    source_iface = 'wg0' if args.source == 'amnezia-awg' else 'awg0'
    owned_comments = []
    source_root = ROOT / args.source
    if source_root.exists():
        # Recover incomplete phases before generation or listener collision checks.
        for journal_path in sorted(source_root.glob('*/transaction.json')):
            journal = Journal(journal_path.parent, run)
            if journal.value['phase'] != 'ready':
                journal.cleanup()
                shutil.rmtree(journal_path.parent)
            else:
                owned_comments.append(journal.value['owner'])
    snapshot = namespace_snapshot(run, args.source, interface, source_iface, owned_comments)
    epoch = client_policy_epoch()
    if args.preflight:
        return {'eligible': True, 'mtu': snapshot['mtu'], 'namespacePolicy': 'validated_standard_awg', 'clientPolicyEpoch': epoch}
    if int(interface['ListenPort']) == args.port:
        raise ValueError('distinct endpoint required')
    scope = args.source
    directory = ROOT / scope / str(args.generation)
    if (directory / 'transaction.json').exists():
        journal = Journal(directory, run)
        if journal.value['phase'] == 'ready':
            request = {'image': args.image, 'host': args.host, 'port': args.port, 'generation': args.generation}
            if journal.value['request'] != request or journal.value['sourceDigest'] != hashlib.sha256(raw).hexdigest():
                raise ValueError('same generation request drift')
            journal.recover_ready()
            state = json.loads((directory / 'ready.json').read_text())
            target_interface, target_peers = parse_config((directory / 'awg0.conf').read_bytes())
            if namespace_snapshot(run, state['targetContainer'], target_interface, 'awg0', [journal.value['owner']]) != snapshot:
                raise ValueError('ready_namespace_policy_or_mtu_changed')
            if state['expiresAt'] < int(time.time()) + 86400:
                state['expiresAt'] = int(time.time()) + 30 * 86400
                atomic(directory / 'ready.json', state)
            return journal.value['receipt']
    if directory.parent.exists():
        generations = [int(path.name) for path in directory.parent.iterdir() if path.is_dir() and path.name.isdecimal()]
        if generations and args.generation <= max(generations):
            raise ValueError('generation must increase')
    if directory.exists():
        raise ValueError('generation already exists; never overwrite')
    target = scope + '-migration-' + str(args.generation)
    collector = target + '-control'
    for name in (target, collector, target + '-source-control', target + '-logs', target + '-feeds'):
        if subprocess.run(['docker', 'container', 'inspect', name], capture_output=True).returncode == 0:
            raise ValueError('container name collision')
    # A previous generation listener must be renewed explicitly, never stopped here.
    listeners = run('docker', 'exec', args.source, 'cat', '/proc/net/tcp').decode()
    if any(line.split()[1].endswith(':46A2') for line in listeners.splitlines()[1:]):
        raise ValueError('source control port already bound')
    directory.mkdir(parents=True, mode=0o700)
    committed = False
    source_rules = False
    ownership = secrets.token_hex(16)
    source_observed = inspect_container(run, args.source)
    journal = Journal(directory, run, {'owner': ownership, 'phase': 'preparing', 'containers': {},
            'source': args.source, 'sourceId': source_observed['Id'], 'sourceIface': source_iface,
            'sourceRules': False, 'sourceDigest': hashlib.sha256(raw).hexdigest(),
            'target': target, 'sourceEpoch': source_observed['State'].get('StartedAt'),
            'request': {'image': args.image, 'host': args.host, 'port': args.port, 'generation': args.generation}})
    journal.save()
    try:
        signer = directory.parent / 'signing.pem'
        if not signer.exists():
            run('openssl', 'genpkey', '-algorithm', 'Ed25519', '-out', str(signer))
            os.chmod(signer, 0o600)
        shutil.copyfile(signer, directory / 'signing.pem')
        os.chmod(directory / 'signing.pem', 0o600)
        public_der = run('openssl', 'pkey', '-in', str(directory / 'signing.pem'), '-pubout', '-outform', 'DER')
        public = base64.b64encode(public_der[-32:]).decode()
        server_key = run('docker', 'exec', '-i', args.source,
                         'sh', '-c', 'command -v awg >/dev/null && awg pubkey || wg pubkey',
                         input=(interface['PrivateKey'] + '\n').encode()).decode().strip()
        if not KEY.fullmatch(server_key):
            raise ValueError('server key')
        parameters = {'Jc': '4', 'Jmin': '10', 'Jmax': '50', 'S1': '16', 'S2': '16',
                      'S3': '16', 'S4': '16', 'H1': '1', 'H2': '2', 'H3': '3', 'H4': '4',
                      'HeaderProtectionKey': base64.b64encode(secrets.token_bytes(32)).decode(),
                      'ContentPaddingAddition': '0', 'RekeyAfterTime': '120', 'RekeyTimeout': '5',
                      'RejectAfterTime': '180', 'KeepaliveTimeout': '10',
                      'MaxHandshakeAttempts': '20', 'RandomTrailers': 'false', 'DisableCookies': 'false'}
        # Only explicit fields: discard original shell PostUp/PostDown hooks.
        target_interface = {'PrivateKey': interface['PrivateKey'], 'Address': interface['Address'],
                            'ListenPort': str(args.port), 'MTU': str(snapshot['mtu']), **parameters}
        text = '[Interface]\n' + ''.join(f'{key} = {value}\n' for key, value in target_interface.items())
        for peer in peers:
            text += '\n[Peer]\n' + ''.join(f'{key} = {value}\n' for key, value in peer.items())
        (directory / 'awg0.conf').write_text(text)
        os.chmod(directory / 'awg0.conf', 0o600)
        shutil.copyfile(Path(__file__).with_name('service.py'), directory / 'service.py')
        shutil.copyfile(Path(__file__).with_name('target.py'), directory / 'target.py')
        shutil.copyfile(Path(__file__).with_name('policy.py'), directory / 'policy.py')
        shutil.copyfile(Path(__file__).with_name('feeds.py'), directory / 'feeds.py')
        # Reproduce the validated source namespace rules, not arbitrary shell hooks.
        (directory / 'start.sh').write_text('#!/bin/sh\nset -eu\nawg-quick up /migration/awg0.conf\n' + firewall_script(snapshot) +
                f'iptables -I INPUT 1 -p tcp --dport 18082 -m comment --comment {ownership} -j REJECT\n' +
                f'iptables -I INPUT 1 -i awg0 -p tcp --dport 18082 -m comment --comment {ownership} -j ACCEPT\n' +
                f'iptables -t nat -A PREROUTING -i awg0 -d 172.29.172.251/32 -p tcp --dport 18082 -m comment --comment {ownership} -j REDIRECT --to-ports 18082\n' +
                'while :; do awg show awg0 latest-handshakes > /migration/handshakes.tsv.tmp; mv /migration/handshakes.tsv.tmp /migration/handshakes.tsv; sleep 2; done\n')
        run('docker', 'pull', args.image)
        target_image_id = run('docker', 'image', 'inspect', '--format', '{{.Id}}', args.image).decode().strip()
        journal.plan(target, target_image_id)
        run('docker', 'run', '-d', '--name', target, '--label', 'amnezia.migration.scope=' + scope,
            '--label', 'amnezia.migration.owner=' + ownership,
            '--label', 'amnezia.migration.generation=' + str(args.generation), '--cap-add', 'NET_ADMIN',
            '--device', '/dev/net/tun', '--sysctl', 'net.ipv4.ip_forward=1', '--restart', 'unless-stopped',
            '--log-driver', 'none', '-p', f'{args.port}:{args.port}/udp', '-v', str(directory) + ':/migration:rw',
            '--entrypoint', 'sh', args.image, '/migration/start.sh')
        journal.record(target)
        # Preserve the existing private DNS/routing-policy bridge reachability.
        run('docker', 'network', 'connect', 'amnezia-dns-net', target)
        for attempt in range(20):
            try:
                result = run('docker', 'exec', target, 'awg', 'show', 'awg0', 'dump').decode()
                rows = result.strip().splitlines()
                if len(rows) == len(peers) + 1 and rows[0].split('\t')[1] == server_key:
                    break
            except subprocess.SubprocessError:
                pass
            time.sleep(1)
        else:
            raise ValueError('AWG3 readiness failed')
        accepted = {}
        for line in run('docker', 'exec', target, 'awg', 'showconf', 'awg0').decode().splitlines():
            if '=' in line:
                key, value = (part.strip() for part in line.split('=', 1))
                if key in ('HeaderProtectionKey', 'S1', 'S2', 'S3', 'S4'):
                    accepted[key] = value
        if any(accepted.get(key) != parameters[key] for key in ('HeaderProtectionKey', 'S1', 'S2', 'S3', 'S4')):
            raise ValueError('AWG3 header protection capability not observed')
        target_snapshot = namespace_snapshot(run, target, target_interface, 'awg0', [ownership])
        if target_snapshot != snapshot:
            raise ValueError('effective_namespace_policy_or_mtu_changed')
        observed = {row.split('\t')[0]: row.split('\t') for row in rows[1:]}
        if set(observed) != {peer['PublicKey'] for peer in peers}:
            raise ValueError('peer coverage')
        for peer in peers:
            if observed[peer['PublicKey']][3] != peer['AllowedIPs'] or observed[peer['PublicKey']][1] != peer.get('PresharedKey', '(none)'):
                raise ValueError('peer preservation')
        mapping = {peer['PublicKey']: {'sourceIp': str(ipaddress.ip_interface(peer['AllowedIPs']).ip),
                   'targetIp': str(ipaddress.ip_interface(peer['AllowedIPs']).ip), 'clientAddress': peer['AllowedIPs'],
                   'clientId': hashlib.sha256((scope + '\t' + peer['PublicKey']).encode()).hexdigest()} for peer in peers}
        state = {'schema': 1, 'serverPublicKey': server_key, 'containerId': scope, 'generation': args.generation,
                 'expiresAt': int(time.time()) + 30 * 86400, 'signingPublicKey': public,
                 'endpoint': f'{args.host}:{args.port}', 'parameters': parameters, 'peers': mapping,
                 'challengeAddress': '172.29.172.251', 'challengePort': 18082, 'targetContainer': target}
        # Build private control image with OpenSSL; pin its base, never publish a release.
        dockerfile = 'FROM python:3.12-alpine@sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df\nRUN apk add --no-cache openssl\n'
        # Build context contains only the Dockerfile, never VPN/signing keys.
        with tempfile.TemporaryDirectory() as build_context:
            Path(build_context, 'Dockerfile').write_text(dockerfile)
            run('docker', 'build', '-t', target + '-control-image', build_context)
        atomic(directory / 'ready.json', state)
        log_image = 'python:3.12-alpine@sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df'
        log_image_id = run('docker', 'image', 'inspect', '--format', '{{.Id}}', log_image).decode().strip()
        feed_ports = [str(port) for port in (17864, 17865) if any('--dport ' + str(port) + ' ' in rule for rule in snapshot['nat'])]
        if feed_ports:
            journal.plan(target + '-feeds', log_image_id)
            run('docker', 'run', '-d', '--name', target + '-feeds', '--log-driver', 'none', '--restart', 'unless-stopped',
                '--label', 'amnezia.migration.owner=' + ownership, '--network', 'container:' + target,
                '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
                '-e', 'AMNEZIA_FEED_PORTS=' + ','.join(feed_ports), '-e', 'PYTHONDONTWRITEBYTECODE=1',
                '-v', str(directory) + ':/migration:ro', '-v', '/opt/amnezia/server-routing-rules:/routing:ro',
                '-v', '/opt/amnezia/client-updates:/updates:ro', '--entrypoint', 'python', log_image, '/migration/feeds.py')
            journal.record(target + '-feeds')
            for port in feed_ports:
                feed_file = Path('/opt/amnezia/server-routing-rules/rules.json') if port == '17864' else Path('/opt/amnezia/client-updates/manifest.json')
                expected_feed_hash = hashlib.sha256(feed_file.read_bytes()).hexdigest()
                feed_path = '/rules.json' if port == '17864' else '/manifest.json'
                probe_feed = 'import hashlib,urllib.request; print(hashlib.sha256(urllib.request.urlopen("http://127.0.0.1:' + port + feed_path + '",timeout=5).read()).hexdigest())'
                for attempt in range(10):
                    try:
                        if run('docker', 'exec', target + '-feeds', 'python', '-c', probe_feed).decode().strip() == expected_feed_hash:
                            break
                    except subprocess.SubprocessError:
                        pass
                    time.sleep(1)
                else:
                    raise ValueError('target_client_feed_readiness_failed')
        journal.plan(target + '-logs', log_image_id)
        run('docker', 'run', '-d', '--name', target + '-logs', '--log-driver', 'none', '--restart', 'unless-stopped',
            '--label', 'amnezia.migration.owner=' + ownership,
            '--network', 'container:' + target, '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
            '-e', 'AMNEZIA_CLIENT_LOGS_BOOTSTRAP=1', '-e', 'AMNEZIA_CLIENT_LOGS_SCOPE=' + scope,
            '-v', str(COLLECTOR_ROOT) + ':/data:rw', '--entrypoint', 'python',
            'python:3.12-alpine@sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df', '/data/collector.py')
        journal.record(target + '-logs')
        control_image_id = run('docker', 'image', 'inspect', '--format', '{{.Id}}', target + '-control-image').decode().strip()
        journal.plan(collector, control_image_id)
        run('docker', 'run', '-d', '--name', collector, '--log-driver', 'none', '--restart', 'unless-stopped',
            '--label', 'amnezia.migration.owner=' + ownership,
            '--network', 'container:' + target, '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
            '-v', str(directory) + ':/migration:rw', '--entrypoint', 'python', target + '-control-image', '/migration/target.py')
        journal.record(collector)
        probe = 'import socket; s=socket.create_connection(("127.0.0.1",18082),timeout=2);s.close()'
        for attempt in range(10):
            try:
                run('docker', 'exec', collector, 'python', '-c', probe)
                break
            except subprocess.SubprocessError:
                time.sleep(1)
        else:
            raise ValueError('candidate control listener unavailable')
        if epoch is not None:
            probe_epoch = 'import json,urllib.request; p=json.load(urllib.request.urlopen("http://172.29.172.253:17864/rules.json",timeout=5))["policy"]; print(json.dumps({k:p[k] for k in ("revision","contentSha256")}))'
            if json.loads(run('docker', 'exec', collector, 'python', '-c', probe_epoch)) != epoch:
                raise ValueError('client_policy_feed_epoch_changed')
        if client_policy_epoch() != epoch:
            raise ValueError('source_client_policy_feed_epoch_changed')
        if run('docker', 'exec', args.source, 'cat', config_path) != raw:
            raise ValueError('source configuration changed')
        # Activate old-namespace private migration endpoint only after target startup.
        source_rules = True
        journal.value['sourceRules'] = True
        journal.save('activating')
        run('docker', 'exec', '-i', args.source, 'sh', '-c',
            'set -e; iptables -I INPUT 1 -p tcp --dport 18082 -m comment --comment ' + ownership + ' -j REJECT; iptables -I INPUT 1 -i ' +
            ('wg0' if scope == 'amnezia-awg' else 'awg0') + ' -p tcp --dport 18082 -m comment --comment ' + ownership + ' -j ACCEPT; ' +
            'iptables -t nat -A PREROUTING -i ' + ('wg0' if scope == 'amnezia-awg' else 'awg0') +
            ' -d 172.29.172.251/32 -p tcp --dport 18082 -m comment --comment ' + ownership + ' -j REDIRECT --to-ports 18082')
        journal.plan(target + '-source-control', control_image_id)
        run('docker', 'run', '-d', '--name', target + '-source-control', '--log-driver', 'none', '--restart', 'unless-stopped',
            '--label', 'amnezia.migration.owner=' + ownership,
            '--network', 'container:' + args.source, '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
            '-e', 'AMNEZIA_MIGRATION_ROLE=source', '-e', 'AMNEZIA_MIGRATION_SCOPE=' + scope,
            '-v', str(directory) + ':/migration:rw', '-v', str(COLLECTOR_ROOT) + ':/logs:ro',
            '--entrypoint', 'python', target + '-control-image', '/migration/target.py')
        journal.record(target + '-source-control')
        for attempt in range(10):
            try:
                run('docker', 'exec', target + '-source-control', 'python', '-c', probe)
                break
            except subprocess.SubprocessError:
                time.sleep(1)
        else:
            raise ValueError('source control listener unavailable')
        receipt = {'prepared': True, 'generation': args.generation, 'peerCount': len(peers),
                'serverPublicKey': server_key, 'signingPublicKey': public, 'legacyRetained': True}
        journal.value['receipt'] = receipt
        journal.value['targetEpoch'] = journal.owned(target)['State'].get('StartedAt')
        journal.save('ready')
        committed = True
        return receipt
    finally:
        if not committed:
            journal.cleanup()
            shutil.rmtree(directory)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', required=True)
    parser.add_argument('--image', required=True)
    parser.add_argument('--host', required=True)
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--generation', type=int, required=True)
    parser.add_argument('--preflight', action='store_true')
    try:
        args = parser.parse_args()
        if os.geteuid() != 0 or args.source not in ('amnezia-awg', 'amnezia-awg2'):
            raise ValueError('administrator/source required')
        if args.preflight:
            # Preflight performs only read-only checks; no collector/VPN mutation.
            # Recovery is deliberately deferred to the actual operator prepare call.
            config_path = '/opt/amnezia/awg/' + ('wg0.conf' if args.source == 'amnezia-awg' else 'awg0.conf')
            interface, peers = parse_config(run('docker', 'exec', args.source, 'cat', config_path))
            comments = []
            for path in (ROOT / args.source).glob('*/transaction.json'):
                comments.append(json.loads(path.read_text())['owner'])
            snapshot = namespace_snapshot(run, args.source, interface, 'wg0' if args.source == 'amnezia-awg' else 'awg0', comments)
            print(json.dumps({'eligible': True, 'mtu': snapshot['mtu'], 'clientPolicyEpoch': client_policy_epoch()}))
            raise SystemExit(0)
        ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
        with open(ROOT / '.prepare.lock', 'a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            print(json.dumps(prepare(args), separators=(',', ':')))
    except Exception as error:
        # Private subprocess stdout/stderr/configuration must never reach client logs.
        eligibility_reasons = {'unsupported_namespace_hook', 'unsupported_namespace_firewall',
            'unsupported_namespace_ip_rule', 'unsupported_namespace_default_policy',
            'unsupported_namespace_egress', 'unsupported_mtu', 'source_mtu_drift',
            'unsupported_namespace_route',
            'managed_client_policy_not_ready', 'managed_client_policy_not_versioned'}
        reason = str(error) if isinstance(error, ValueError) and str(error) in eligibility_reasons else 'migration_preparation_failed'
        print(json.dumps({'prepared': False, 'eligible': False, 'reason': reason}))
        raise SystemExit(1)
