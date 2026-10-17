"""Owned Linux packaged-GUI migration scenario. Never invoke on a host.

The controller establishes guest ownership and stages signed-payload bindings.
This helper creates only fixture network namespaces and private GUI settings.
It never installs a backend, edits product settings, or calls headless scenario().
"""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import signal
import socket
import sqlite3
import stat
import subprocess
import sys
import time

MANDATORY_CHECKS = ('installed_product_binding', 'real_mapped_gui', 'bootstrap_staged',
                    'natural_disconnect', 'graceful_relaunch', 'native_trial',
                    'nonce_proof', 'profile_cas', 'acknowledged', 'rollback_no_ack',
                    'rollback_profile_preserved', 'cleanup')
SCHEMA = 'amnezia.release-lab.awg-gui.v1'


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def command(argv, *, data=None, ns=None, check=True):
    args = (['ip', 'netns', 'exec', ns] if ns else []) + [str(x) for x in argv]
    result = subprocess.run(args, input=data, capture_output=True, timeout=20)
    if check and result.returncode:
        # Deliberately suppress argv, stdout and stderr: import/config holds keys.
        raise RuntimeError('fixture command failed: ' + Path(str(argv[0])).name)
    return result


def wait(probe, label, timeout=90):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        value = probe()
        if value:
            return value
        time.sleep(0.25)
    raise RuntimeError('bounded wait: ' + label)


def write(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(value.encode() if isinstance(value, str) else value)


def replace_owned(path, value):
    temporary = path.with_name(path.name + '.next')
    write(temporary, value)
    os.replace(temporary, path)


def product_binding(expected):
    required = {'/opt/AmneziaVPN/bin/AmneziaVPN', '/opt/AmneziaVPN/bin/AmneziaVPN-service'}
    if not isinstance(expected, dict) or not required.issubset(expected):
        raise RuntimeError('signed installed product binding missing')
    for name, binding in expected.items():
        path = Path(name)
        if not path.is_absolute() or not str(path).startswith('/opt/AmneziaVPN/'):
            raise RuntimeError('unexpected installed product path')
        for item in list(path.parents)[:-1]:
            info = item.lstat()
            if item.is_symlink() or info.st_uid or info.st_mode & 0o022:
                raise RuntimeError('unsafe installed product ownership')
        info = path.lstat()
        if binding.get('type') == 'symlink':
            target = binding.get('target')
            if not stat.S_ISLNK(info.st_mode) or info.st_uid or os.readlink(path) != target:
                raise RuntimeError('installed product symlink differs')
            resolved = path.resolve(strict=True)
            if not str(resolved).startswith('/opt/AmneziaVPN/') or str(resolved) not in expected or expected[str(resolved)].get('type') == 'symlink':
                raise RuntimeError('installed product symlink closure missing')
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_size != binding['size'] or sha(path) != binding['sha256']:
            raise RuntimeError('installed product bytes differ from signed payload')
        if info.st_uid or info.st_mode & 0o022:
            raise RuntimeError('installed product file ownership differs')
    return expected


def guard(plan):
    if os.geteuid() or plan.get('schema') != SCHEMA or plan.get('profile') != 'linux-x64-gui':
        raise RuntimeError('owned GUI Linux guest required')
    run = plan['runId']
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,95}', run):
        raise RuntimeError('invalid run')
    marker = 'amnezia-release-lab:' + run + ':linux-x64-gui'
    if plan['marker'] != marker or Path('/tmp/amnezia-release-lab-marker').read_text().strip() != marker:
        raise RuntimeError('guest marker mismatch')
    if Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower() != plan['uuid'].lower():
        raise RuntimeError('guest UUID mismatch')
    root = Path('/var/lib/amnezia-release-lab') / ('gui-migration-' + run)
    if str(root) != plan['root'] or root.resolve() != root:
        raise RuntimeError('fixture root mismatch')
    info = root.lstat()
    if info.st_uid or info.st_mode & 0o077 or not stat.S_ISDIR(info.st_mode):
        raise RuntimeError('fixture root ownership')
    names = {'amneziawg-go', 'awg', 'awg-quick', 'legacy-amneziawg-go', 'legacy-awg',
             'legacy-musl', 'service.py', 'native_guest.py', 'guest.py', 'observer.py', 'gui_window.py'}
    if set(plan['files']) != names:
        raise RuntimeError('fixture asset set differs')
    for name, digest in plan['files'].items():
        path = root / name
        info = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid or info.st_mode & 0o022 or sha(path) != digest:
            raise RuntimeError('fixture asset differs')
    if plan.get('guiUser') != 'lab' or plan.get('guiBinary') != '/opt/AmneziaVPN/bin/AmneziaVPN':
        raise RuntimeError('unsupported GUI identity')
    product_binding(plan['expectedProductFiles'])
    return root


def import_profile(peer_key, peer_pub, server_pub, psk, client_id, token, legacy, address):
    client = dict(legacy, hostName='10.233.1.2', port=51821, client_ip=address + '/32',
                  client_priv_key=peer_key, client_pub_key=peer_pub, server_pub_key=server_pub,
                  psk_key=psk, allowed_ips=['172.29.172.251/32', '172.29.172.252/32'],
                  persistent_keep_alive='1', mtu='1420')
    native = '[Interface]\nPrivateKey = ' + peer_key + '\nAddress = ' + address + '/32\nMTU = 1420\n'
    native += ''.join(key + ' = ' + value + '\n' for key, value in legacy.items())
    native += '[Peer]\nPublicKey = ' + server_pub + '\nPresharedKey = ' + psk + '\nEndpoint = 10.233.1.2:51821\nAllowedIPs = 172.29.172.251/32, 172.29.172.252/32\nPersistentKeepalive = 1\n'
    client['config'] = native
    return {'format_version': 1, 'description': 'owned GUI migration fixture', 'hostName': '10.233.1.2',
            'defaultContainer': 'amnezia-awg2', 'dns1': '172.29.172.251', 'dns2': '172.29.172.252',
            'containers': [{'container': 'amnezia-awg2', 'awg': dict(legacy, port='51821', transport_proto='udp', last_config=json.dumps(client))}],
            'clientLogs': {'clientId': client_id, 'token': token, 'enabled': False}}


class Scenario:
    def __init__(self, plan, root):
        self.plan, self.root = plan, root
        self.window = load_module('gui_window', root / 'gui_window.py')
        self.observer = load_module('observer', root / 'observer.py')
        self.session = self.window.active_x11_session()
        self.account = pwd.getpwnam('lab')
        if self.session['uid'] != self.account.pw_uid or self.window.exact_binary_pids(self.account.pw_uid):
            raise RuntimeError('fresh GUI ownership unavailable')
        self.processes, self.namespaces, self.links = [], [], []
        self.runtime_created = None
        self.gui = None
        self.service_identity = self.service()
        self.evidence = {'desktopDaemon': self.service_identity, 'guiProcesses': [], 'phases': {}}
        self.checks = {name: False for name in MANDATORY_CHECKS}
        self.checks['installed_product_binding'] = True

    def service(self):
        health = self.window.service_health()
        identity = self.window.proc_identity(int(health['main_pid']))
        if identity['exe'] != '/opt/AmneziaVPN/bin/AmneziaVPN-service' or identity['uid'] != 0:
            raise RuntimeError('desktop daemon identity differs')
        if identity['installed_binary_sha256'] != self.plan['expectedProductFiles'][identity['exe']]['sha256']:
            raise RuntimeError('desktop daemon bytes differ')
        return identity

    def spawn(self, argv, ns=None):
        args = (['ip', 'netns', 'exec', ns] if ns else []) + [str(x) for x in argv]
        process = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.processes.append(process)
        return process

    def private_environment(self, label):
        base = Path(self.account.pw_dir) / ('.awg-gui-' + self.plan['attemptNonce'] + '-' + label)
        # Product secret store requires the actual HOME prefix and private,
        # account-owned ancestry. Never seed or write a product profile/journal.
        if not re.fullmatch(r'[A-Za-z0-9._-]{16,128}', self.plan['attemptNonce']):
            raise RuntimeError('invalid attempt nonce')
        home = Path(self.account.pw_dir)
        info = home.lstat()
        if home.is_symlink() or info.st_uid != self.account.pw_uid or info.st_mode & 0o022:
            raise RuntimeError('GUI home ownership')
        base.mkdir(mode=0o700)
        os.chown(base, self.account.pw_uid, self.account.pw_gid)
        for name in ('config', 'data', 'cache'):
            directory = base / name
            directory.mkdir(mode=0o700)
            os.chown(directory, self.account.pw_uid, self.account.pw_gid)
        self.base = base
        self.env = ['runuser', '-u', 'lab', '--', 'env', 'HOME=' + str(home),
                    'DISPLAY=' + self.session['display'], 'XAUTHORITY=' + self.session['xauthority'],
                    'XDG_CONFIG_HOME=' + str(base / 'config'), 'XDG_DATA_HOME=' + str(base / 'data'),
                    'XDG_CACHE_HOME=' + str(base / 'cache')]

    def launch(self, profile=None):
        if self.window.exact_binary_pids(self.account.pw_uid):
            raise RuntimeError('GUI already exists')
        args = [self.plan['guiBinary']]
        if profile is not None:
            args += ['--import', json.dumps(profile, separators=(',', ':'))]
        args += ['--connect', '0']
        self.spawn(self.env + args)
        def mapped():
            pids = self.window.exact_binary_pids(self.account.pw_uid)
            if len(pids) != 1:
                return None
            identity = self.window.proc_identity(next(iter(pids)))
            self.gui = identity  # retain exact cleanup identity before window readiness
            windows = self.window.mapped_windows(identity['pid'], self.session)
            if len(windows) == 1:
                self.gui = identity
                return identity
        identity = wait(mapped, 'real packaged GUI mapped window')
        self.evidence['guiProcesses'].append(identity)
        self.checks['real_mapped_gui'] = True
        return identity

    def stop_gui(self):
        if self.gui is None:
            return
        self.window.signal_exact_process(self.gui, signal.SIGTERM)
        wait(lambda: not self.window.same_process(self.gui), 'graceful GUI exit', 30)
        self.gui = None

    def disconnect(self):
        command(self.env + [self.plan['guiBinary'], '--disconnect'])
        def disconnected():
            reply = command(self.env + [self.plan['guiBinary'], '--status', '--json'], check=False)
            if reply.returncode:
                return False
            state = json.loads(reply.stdout)
            return state.get('schema') == 'amnezia.operator.status.v1' and state.get('stateFresh') is True and state.get('state') == 'disconnected'
        wait(disconnected, 'real operator disconnect')
        self.checks['natural_disconnect'] = True

    def observe(self):
        # Actual data-plane packets, never synthetic observations/handshakes.
        command(['ping', '-c', '1', '-W', '1', '172.29.172.252'], check=False)
        settings = list((self.base / 'config').rglob('*.conf'))
        stores = list((self.base / 'data').rglob('awg-migration-secrets'))
        if len(settings) != 1 or len(stores) != 1:
            return None
        try:
            return self.observer.snapshot(settings[0], stores[0], self.account.pw_uid, self.account.pw_dir)
        except (FileNotFoundError, KeyError):
            return None

    def journal_state(self, states):
        value = self.observe()
        return value if value and value['journal'].get('state') in states else None

    def phase(self, name, value):
        self.evidence['phases'][name] = self.observer.public_summary(value)

    def native_trial(self, peer, started):
        path = Path('/run/amneziawg/amn0.sock')
        info = path.lstat()
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0:
            raise RuntimeError('real desktop backend socket unavailable')
        with socket.socket(socket.AF_UNIX) as stream:
            stream.settimeout(5)
            stream.connect(str(path))
            stream.sendall(b'get=1\n\n')
            raw = b''
            while not raw.endswith(b'\n\n'):
                chunk = stream.recv(65536)
                if not chunk or len(raw) + len(chunk) > 65536:
                    raise RuntimeError('native observation incomplete')
                raw += chunk
        fields = dict(line.split(b'=', 1) for line in raw.splitlines() if b'=' in line)
        expected = {key.lower().encode(): value.encode() for key, value in self.target.items() if key != 'HeaderProtectionKey'}
        expected[b'header_protection_key'] = base64.b64decode(self.target['HeaderProtectionKey']).hex().encode()
        if any(fields.get(key) != value for key, value in expected.items()):
            raise RuntimeError('actual desktop backend target parameters differ')
        if fields.get(b'public_key') != base64.b64decode(self.server_pub).hex().encode():
            raise RuntimeError('actual desktop backend peer differs')
        handshake = int(fields.get(b'last_handshake_time_sec', b'0'))
        if handshake < started or int(fields.get(b'rx_bytes', b'0')) <= 0 or int(fields.get(b'tx_bytes', b'0')) <= 0:
            raise RuntimeError('actual desktop backend fresh traffic missing')
        return {'freshHandshake': True, 'parametersMatch': True, 'peerMatches': True,
                'uapi_sha256': hashlib.sha256(raw).hexdigest()}

    def network_snapshot(self, observation):
        status = command(self.env + [self.plan['guiBinary'], '--status', '--json'], check=False)
        if status.returncode:
            return None
        state = json.loads(status.stdout)
        if state.get('stateFresh') is not True or state.get('state') != 'connected':
            return None
        client = json.loads(observation['profile']['containers'][0]['awg']['last_config'])
        address = client['client_ip'].split('/')[0]
        route = json.loads(command(['ip', '-j', 'route', 'get', '172.29.172.251']).stdout)
        if len(route) != 1 or not route[0].get('dev'):
            return None
        device = route[0]['dev']
        interfaces = json.loads(command(['ip', '-j', 'address', 'show', 'dev', device]).stdout)
        if len(interfaces) != 1:
            return None
        interface = interfaces[0]
        if address not in [item.get('local') for item in interface['addr_info']] or interface['mtu'] != int(client['mtu']):
            return None
        # Read actual resolved state, not a desired profile field. Missing
        # resolver visibility is a HOLD rather than inferred DNS acceptance.
        dns_reply = command(['resolvectl', 'dns', device], check=False)
        if dns_reply.returncode:
            raise RuntimeError('actual per-link DNS unavailable')
        dns = dns_reply.stdout.decode().split(':', 1)[-1].split()
        expected_dns = [observation['profile']['dns1'], observation['profile']['dns2']]
        if dns != expected_dns:
            return None
        if command(['ping', '-I', device, '-c', '1', '-W', '2', '172.29.172.252'], check=False).returncode:
            return None
        return {'device': device, 'address': address, 'mtu': interface['mtu'], 'dns': dns,
                'routes': [item['dst'] for item in json.loads(command(['ip', '-j', 'route', 'show', 'dev', device]).stdout)]}

    def setup(self):
        root = self.root
        runtime = Path('/run/amneziawg')
        if runtime.exists() or runtime.is_symlink():
            info = runtime.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid or info.st_mode & 0o077 or any(runtime.iterdir()):
                raise RuntimeError('foreign legacy runtime present')
        else:
            runtime.mkdir(mode=0o700)
            self.runtime_created = (runtime.stat().st_dev, runtime.stat().st_ino)
        for name in ('amneziawg-go', 'awg', 'awg-quick', 'legacy-amneziawg-go', 'legacy-awg', 'legacy-musl'):
            (root / name).chmod(0o700)
        control = root / 'control'
        control.mkdir(mode=0o700)
        self.token = secrets.token_hex(32)
        write(root / 'token', self.token)
        command(['openssl', 'genpkey', '-algorithm', 'ED25519', '-out', control / 'signing.pem'])
        os.chmod(control / 'signing.pem', 0o600)
        der = command(['openssl', 'pkey', '-in', control / 'signing.pem', '-pubout', '-outform', 'DER']).stdout
        self.server_key, self.server_pub = self.keypair()
        self.legacy = {'Jc': '4', 'Jmin': '10', 'Jmax': '50', 'S1': '16', 'S2': '16',
                       'H1': '1', 'H2': '2', 'H3': '3', 'H4': '4'}
        self.target = dict(self.legacy, S3='16', S4='16', HeaderProtectionKey=base64.b64encode(secrets.token_bytes(32)).decode())
        self.ready = {'serverPublicKey': self.server_pub, 'containerId': 'amnezia-awg2',
                      'generation': 1, 'expiresAt': int(time.time()) + 3600,
                      'signingPublicKey': base64.b64encode(der[-32:]).decode(),
                      'endpoint': '10.233.2.2:51822', 'parameters': self.target,
                      'challengeAddress': '172.29.172.251', 'challengePort': 18082, 'peers': {}}
        write(control / 'ready.json', json.dumps(self.ready))
        tag = hashlib.sha256(self.plan['attemptNonce'].encode()).hexdigest()[:7]
        for number, role in enumerate(('source', 'target'), 1):
            ns, host, peer = 'amgui-' + tag + '-' + role, 'agh' + str(number) + tag, 'agn' + str(number) + tag
            if Path('/run/netns', ns).exists() or command(['ip', 'link', 'show', host], check=False).returncode == 0:
                raise RuntimeError('fixture namespace collision')
            command(['ip', 'netns', 'add', ns])
            self.namespaces.append((ns, Path('/run/netns', ns).stat().st_ino))
            command(['ip', 'link', 'add', host, 'type', 'veth', 'peer', 'name', peer])
            self.links.append((host, Path('/sys/class/net', host, 'ifindex').read_text()))
            command(['ip', 'link', 'set', peer, 'netns', ns])
            for argv in (['ip', 'addr', 'add', f'10.233.{number}.1/30', 'dev', host], ['ip', 'link', 'set', host, 'up']):
                command(argv)
            for argv in (['ip', 'addr', 'add', f'10.233.{number}.2/30', 'dev', peer],
                         ['ip', 'link', 'set', peer, 'up'], ['ip', 'link', 'set', 'lo', 'up'],
                         ['ip', 'addr', 'add', '172.29.172.251/32', 'dev', 'lo'],
                         ['ip', 'addr', 'add', '172.29.172.252/32', 'dev', 'lo']):
                command(argv, ns=ns)
            device = 'amsrc' if number == 1 else 'amtgt'
            self.spawn([root / ('legacy-amneziawg-go' if number == 1 else 'amneziawg-go'), '-f', device], ns)
            wait(lambda: command(['ip', 'link', 'show', device], ns=ns, check=False).returncode == 0, 'native fixture interface', 10)
            parameters = self.legacy if number == 1 else self.target
            config = '[Interface]\nPrivateKey = ' + self.server_key + f'\nListenPort = {51820 + number}\n'
            config += ''.join(key + ' = ' + value + '\n' for key, value in parameters.items())
            path = root / (device + '.conf')
            write(path, config)
            command(self.tool(number) + ['setconf', device, path], ns=ns)
            command(['ip', 'addr', 'add', '10.244.0.1/32', 'dev', device], ns=ns)
            command(['ip', 'link', 'set', device, 'mtu', '1420', 'up'], ns=ns)
            # Reuse only existing fixture's server() component, never scenario().
            self.spawn(['/usr/bin/python3', root / 'guest.py', '--server', root, ns, device, role], ns)

    def tool(self, number):
        return [self.root / 'legacy-musl', self.root / 'legacy-awg'] if number == 1 else [self.root / 'awg']

    def keypair(self):
        key = command([self.root / 'awg', 'genkey']).stdout.strip()
        public = command([self.root / 'awg', 'pubkey'], data=key).stdout.strip()
        return key.decode(), public.decode()

    def peer(self, suffix, failure=False):
        private, public = self.keypair()
        self.last_peer = public
        psk = command([self.root / 'awg', 'genpsk']).stdout.strip()
        address = '10.244.0.' + str(suffix)
        client_id = hashlib.sha256(('amnezia-awg2\t' + public).encode()).hexdigest()
        for number, (ns, _) in enumerate(self.namespaces, 1):
            device = 'amsrc' if number == 1 else 'amtgt'
            command(self.tool(number) + ['set', device, 'peer', public, 'preshared-key', '/dev/stdin', 'allowed-ips', address + '/32'], data=psk, ns=ns)
            command(['ip', 'route', 'add', address + '/32', 'dev', device], ns=ns)
        self.ready['peers'][public] = {'sourceIp': address, 'targetIp': address, 'clientAddress': address + '/32', 'clientId': client_id}
        self.ready.update(generation=2 if failure else 1, endpoint='10.233.2.2:51829' if failure else '10.233.2.2:51822')
        replace_owned(self.root / 'control' / 'ready.json', json.dumps(self.ready))
        return import_profile(private, public, self.server_pub, psk.decode(), client_id, self.token, self.legacy, address)

    def execute(self):
        self.setup()
        self.private_environment('commit')
        self.launch(self.peer(2))
        success_peer = self.last_peer
        staged = wait(lambda: self.journal_state({'staged'}), 'real GUI bootstrap and stage', 180)
        self.phase('staged', staged)
        before = staged['profile_sha256']
        if staged['journal'].get('sourceHash') != before:
            raise RuntimeError('staged profile source binding')
        self.checks['bootstrap_staged'] = True
        self.disconnect()
        first_pid = self.gui['pid']
        self.stop_gui()
        trial_started = int(time.time())
        second = self.launch()
        self.checks['graceful_relaunch'] = second['pid'] != first_pid
        committed = wait(lambda: self.journal_state({'committed'}), 'actual GUI nonce proof CAS ACK', 180)
        journal = committed['journal']
        self.phase('committed', committed)
        self.evidence['challengeReceipt_sha256'] = self.observer.canonical_hash(journal.get('challengeReceipt', {}))
        self.checks['profile_cas'] = journal.get('sourceHash') == before and journal.get('candidateHash') == committed['profile_sha256'] and before != committed['profile_sha256']
        self.checks['nonce_proof'] = bool(journal.get('challengeReceipt'))
        with sqlite3.connect('file:' + str(self.root / 'control' / 'grants.sqlite3') + '?mode=ro', uri=True) as db:
            count = db.execute('SELECT count(*) FROM grants WHERE peer=? AND generation=1 AND proved=1 AND ack=1', (success_peer,)).fetchone()[0]
            self.evidence['provedAckCount'] = count
            self.checks['acknowledged'] = count == 1
        # The real controller commits only after fresh native AWG3 key/parameter
        # digests and traffic proof; additionally retain server native handshake.
        target = (self.root / 'control' / 'handshakes-target.tsv').read_text()
        peer = journal.get('offer', {}).get('peerPublicKey')
        handshakes = [line.split() for line in target.splitlines()]
        self.checks['native_trial'] = any(len(row) == 2 and row[0] == peer and int(row[1]) > 0 for row in handshakes) and self.checks['acknowledged']
        self.evidence['nativeBackend'] = self.native_trial(peer, trial_started)
        self.disconnect()
        self.stop_gui()
        self.private_environment('rollback')
        self.launch(self.peer(3, True))
        failure_peer = self.last_peer
        staged = wait(lambda: self.journal_state({'staged'}), 'rollback bootstrap', 180)
        self.phase('rollback_staged', staged)
        preserved = staged['profile_sha256']
        source_network = wait(lambda: self.network_snapshot(staged), 'real source route DNS MTU and traffic')
        self.disconnect()
        self.stop_gui()
        self.launch()
        rolled = wait(lambda: self.journal_state({'rolled_back', 'recovery_required'}), 'real unreachable trial rollback', 180)
        self.phase('rolled_back', rolled)
        fallback_network = wait(lambda: self.network_snapshot(rolled), 'legacy fallback route DNS MTU and traffic')
        self.evidence['sourceNetwork'] = source_network
        self.evidence['fallbackNetwork'] = fallback_network
        self.checks['rollback_profile_preserved'] = rolled['profile_sha256'] == preserved and source_network == fallback_network
        with sqlite3.connect('file:' + str(self.root / 'control' / 'grants.sqlite3') + '?mode=ro', uri=True) as db:
            count = db.execute('SELECT count(*) FROM grants WHERE ack=1').fetchone()[0]
            self.evidence['ackCountAfterRollback'] = count
            failed_peer_ack = db.execute('SELECT count(*) FROM grants WHERE peer=? AND ack=1', (failure_peer,)).fetchone()[0]
            self.evidence['rollbackPeerAckCount'] = failed_peer_ack
            self.checks['rollback_no_ack'] = count == 1 and failed_peer_ack == 0
        self.disconnect()
        self.stop_gui()

    def cleanup(self):
        # No arbitrary PID/name kill. Popen.wait/poll preserves child ownership;
        # GUI termination additionally uses pidfd and exact exe/start-ticks.
        if self.gui is not None:
            try:
                self.disconnect()
            finally:
                self.stop_gui()
        for process in reversed(self.processes):
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=10)
        for name, index in reversed(self.links):
            path = Path('/sys/class/net', name, 'ifindex')
            if path.exists():
                if path.read_text() != index:
                    raise RuntimeError('fixture link ownership changed')
                command(['ip', 'link', 'delete', name])
        for ns, inode in reversed(self.namespaces):
            path = Path('/run/netns', ns)
            if path.stat().st_ino != inode:
                raise RuntimeError('fixture namespace ownership changed')
            command(['ip', 'netns', 'delete', ns])
        if self.runtime_created is not None:
            runtime = Path('/run/amneziawg')
            info = runtime.lstat()
            if (info.st_dev, info.st_ino) != self.runtime_created:
                raise RuntimeError('legacy runtime ownership changed')
            runtime.rmdir()
        if self.window.exact_binary_pids(self.account.pw_uid):
            raise RuntimeError('GUI remains after cleanup')
        self.checks['cleanup'] = True
        if self.service() != self.service_identity:
            self.checks['cleanup'] = False
            raise RuntimeError('desktop daemon changed during GUI scenario')


def main(argv):
    os.umask(0o077)
    for name in ('NOTIFY_SOCKET', 'WATCHDOG_PID', 'WATCHDOG_USEC', 'WG_TUN_FD', 'WG_UAPI_FD', 'WG_TUN_NAME_FILE'):
        os.environ.pop(name, None)
    if len(argv) > 1 and argv[1] == '--server':
        plan = json.loads((Path(argv[2]) / 'plan.json').read_text())
        guard(plan)
        module = load_module('native_guest', Path(argv[2]) / 'native_guest.py')
        module.server(Path(argv[2]), argv[3], argv[4], argv[5])
        return 0
    plan = json.loads(Path(argv[1]).read_text())
    root = guard(plan)
    scenario = None
    error = None
    try:
        scenario = Scenario(plan, root)
        scenario.execute()
    except Exception as exc:
        # Never serialize exception content from JSON/import/crypto libraries.
        error = type(exc).__name__
    finally:
        try:
            if scenario is not None:
                scenario.cleanup()
        except Exception as exc:
            error = 'cleanup:' + type(exc).__name__
    after = {}
    try:
        after = product_binding(plan['expectedProductFiles'])
    except Exception:
        error = 'installed_product_changed'
    checks = scenario.checks if scenario is not None else {name: False for name in MANDATORY_CHECKS}
    receipt = {key: plan[key] for key in ('runId', 'profile', 'marker', 'uuid', 'attemptNonce')}
    receipt.update(schema=SCHEMA, origin='guest', transport='qga', injected=False,
                   passed=error is None and all(checks.values()), checks=checks,
                   productFilesAfter=after, cleanupConfirmed=checks['cleanup'], error=error)
    receipt['evidence'] = scenario.evidence if scenario is not None else {}
    write(root / 'receipt.json', json.dumps(receipt, sort_keys=True))
    return 0 if receipt['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
