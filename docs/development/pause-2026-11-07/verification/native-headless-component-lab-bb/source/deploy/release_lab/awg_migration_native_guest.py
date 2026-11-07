"""Guest-only native AWG migration acceptance. Never invoke on a workstation.

The controller stages this exact helper after QMP/PID/UUID/QGA ownership checks.
All keys are generated inside the disposable guest and never enter its receipt.
Handshake feed is derived exclusively from the pinned actual native AWG tool.
"""
import base64
import grp
import hashlib
import http.server
import importlib.util
import json
import os
from pathlib import Path
import secrets
import socket
import sqlite3
import stat
import subprocess
import sys
import threading
import time
import traceback


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write(path, data, mode=0o600):
    path = Path(path)
    if path.is_symlink():
        raise RuntimeError('fixture write symlink')
    with path.open('wb') as stream:
        stream.write(data.encode() if isinstance(data, str) else data)
    path.chmod(mode)


def command(args, *, data=None, ns=None, check=True, timeout=15):
    argv = (['ip', 'netns', 'exec', ns] if ns else []) + [str(x) for x in args]
    p = subprocess.run(argv, input=data, capture_output=True, timeout=timeout)
    if check and p.returncode:
        # Never include stdout/stderr: native config operations contain keys.
        raise RuntimeError('guest command failed: ' + Path(argv[-len(args)]).name + ':' + str(p.returncode))
    return p


def guard(plan):
    if os.geteuid() != 0 or plan['profile'] != 'linux-headless-x64':
        raise RuntimeError('root owned Linux guest required')
    if Path('/tmp/amnezia-release-lab-marker').read_text().strip() != plan['marker']:
        raise RuntimeError('guest marker')
    expected = 'amnezia-release-lab:' + plan['runId'] + ':' + plan['profile']
    if plan['marker'] != expected or Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower() != plan['uuid'].lower():
        raise RuntimeError('guest run/UUID')
    root = Path(plan['root'])
    if root != Path('/var/lib/amnezia-release-lab') / ('migration-' + plan['runId']):
        raise RuntimeError('guest root path')
    st = root.lstat()
    if root.is_symlink() or root.resolve() != root or st.st_uid or st.st_mode & 0o077:
        raise RuntimeError('guest private root ownership')
    for name, expected_hash in plan['files'].items():
        path = root / name
        if path.is_symlink() or path.stat().st_uid or sha(path) != expected_hash:
            raise RuntimeError('guest artifact bytes')
    if not plan.get('goldenSha256') or len(plan['goldenSha256']) != 64:
        raise RuntimeError('golden byte identity')
    return root


def awg_command(root, legacy=False):
    return [root / 'legacy-musl', root / 'legacy-awg'] if legacy else [root / 'awg']


def server(root, namespace, interface, role):
    """Production dispatcher with actual native handshake observation."""
    spec = importlib.util.spec_from_file_location('migration_service', root / 'service.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    state_dir = root / 'control'
    token = (root / 'token').read_text()
    ready = json.loads((state_dir / 'ready.json').read_text())
    native = awg_command(root, role == 'source' and (root / 'legacy-awg').is_file())

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            # This server is already inside the network namespace; every feed
            # update comes from the real target device, never a test timestamp.
            probe = command(native + ['show', interface, 'latest-handshakes'])
            write(state_dir / ('handshakes-' + role + '.tsv'), probe.stdout)
            # Service reads the target feed for target-only proof. Source never
            # uses handshake authorization and must not overwrite that feed.
            if role == 'target':
                write(state_dir / 'handshakes.tsv', probe.stdout)

            def authenticate():
                current = json.loads((state_dir / 'ready.json').read_text())
                client = self.headers.get('X-Amnezia-Client-Id')
                if self.headers.get('X-Amnezia-Log-Token') == token and any(p['clientId'] == client for p in current['peers'].values()):
                    return client
                self.send_error(403)
                return None

            module.MigrationService(str(state_dir), role, ready['containerId']).dispatch(self, authenticate)

    http.server.HTTPServer(('172.29.172.251', 18082), Handler).serve_forever()


def scenario(plan):
    root = guard(plan)
    legacy_names = ['legacy-amneziawg-go', 'legacy-awg', 'legacy-musl'] if plan.get('schema') == 2 else []
    for name in ['amneziad', 'amnezia-cli', 'amneziawg-go', 'awg', *legacy_names]:
        elf = (root / name).read_bytes()
        if elf[:5] != b'\x7fELF\x02' or elf[18:20] != b'\x3e\x00':
            raise RuntimeError('native fixture requires Linux x86_64 ELF')
    try:
        group = grp.getgrnam('amnezia').gr_gid
    except KeyError:
        command(['/usr/sbin/groupadd', '--system', 'amnezia'])
        group = grp.getgrnam('amnezia').gr_gid
    os.umask(0o077)
    runtime = Path('/run/amnezia/awg3')
    if runtime.exists():
        if runtime.is_symlink() or runtime.stat().st_uid or runtime.stat().st_mode & 0o077 or any(runtime.iterdir()):
            raise RuntimeError('private native runtime already owned')
    else:
        runtime.mkdir(mode=0o700, parents=True)
    for name in ['amneziad', 'amnezia-cli', 'amneziawg-go', 'awg', 'awg-quick', *legacy_names]:
        (root / name).chmod(0o700)
    if command(['ip', 'link', 'show', 'amn0'], check=False).returncode == 0:
        raise RuntimeError('candidate interface already exists')
    tag = hashlib.sha256(plan['runId'].encode()).hexdigest()[:6]
    namespaces = ['amgs' + tag, 'amgt' + tag]
    for ns in namespaces:
        if any(row.split()[0] == ns for row in command(['ip', 'netns', 'list']).stdout.decode().splitlines()):
            raise RuntimeError('fixture namespace exists')
    processes = []
    created = []
    installed = []
    receipt = {'sourceMode': 'Go3 legacy-compatible AWG params; old2.1 binary not tested',
               'productionDockerProvisioning': 'not tested', 'checks': {}}
    legacy_runtime = None
    if legacy_names:
        legacy_runtime = Path('/run/amneziawg')
        if os.path.lexists(legacy_runtime):
            raise RuntimeError('legacy socket directory already exists; never reuse foreign state')
        legacy_runtime.mkdir(mode=0o700)
        legacy_runtime_identity = (legacy_runtime.stat().st_dev, legacy_runtime.stat().st_ino)
        receipt['sourceMode'] = 'real official 0.2.19 engine and tools; protocol2.1 attribution unproven'
        receipt['legacyProvenance'] = plan['legacyReceipt']
    env = os.environ.copy()
    env.update(PATH=str(root) + ':/usr/sbin:/usr/bin:/sbin:/bin', WG_QUICK_USERSPACE_IMPLEMENTATION=str(root / 'amneziawg-go'))
    for name in ['NOTIFY_SOCKET', 'WATCHDOG_PID', 'WATCHDOG_USEC', 'WG_TUN_FD', 'WG_UAPI_FD']:
        env.pop(name, None)
    os.environ.update(env)

    def spawn(args, ns=None):
        p = subprocess.Popen((['ip', 'netns', 'exec', ns] if ns else []) + [str(x) for x in args], env=env,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        processes.append(p)
        return p

    def cli(*args):
        p = command([root / 'amnezia-cli', '--socket', str(root / 'daemon.sock'), '--json', *args], check=False,
                    timeout=125 if args[0] in ('connect', 'disconnect') else 15)
        try:
            value = json.loads(p.stdout)
        except ValueError:
            stderr = p.stderr.decode(errors='replace').lower()
            reason = 'response_timeout' if 'daemon response failed' in stderr and 'timed out' in stderr else 'non_json_response'
            if 'cannot connect' in stderr: reason = 'ipc_connect_failed'
            raise RuntimeError('daemon IPC ' + args[0] + ': exit=' + str(p.returncode)
                               + ', stdoutBytes=' + str(len(p.stdout)) + ', reason=' + reason) from None
        if p.returncode or value.get('ok') is not True:
            code = value.get('error', {}).get('code', 'unknown')
            if not isinstance(code, str) or not code.replace('_', '').isalnum() or len(code) > 80:
                code = 'redacted'
            raise RuntimeError('daemon IPC rejected ' + args[0] + ': exit=' + str(p.returncode) + ', code=' + code)
        return value['result']

    def wait(test, label, seconds=80):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            value = test()
            if value:
                return value
            time.sleep(.25)
        raise RuntimeError('deadline: ' + label)

    def genkey():
        key = command([root / 'awg', 'genkey']).stdout.strip()
        pub = command([root / 'awg', 'pubkey'], data=key).stdout.strip()
        return key.decode(), pub.decode()

    legacy = {'Jc': '0', 'Jmin': '0', 'Jmax': '0', 'S1': '0', 'S2': '0', 'S3': '0', 'S4': '0',
              'H1': '1', 'H2': '2', 'H3': '3', 'H4': '4'}
    if legacy_names:
        # Exact legacy shape already accepted by the real official 0.2.19
        # Docker source fixture; do not infer its engine's Go3-zero defaults.
        legacy = {'Jc': '4', 'Jmin': '10', 'Jmax': '50', 'S1': '16', 'S2': '16',
                  'H1': '1', 'H2': '2', 'H3': '3', 'H4': '4'}
    target = {**legacy, 'S1': '16', 'S2': '16', 'S3': '16', 'S4': '16',
              'HeaderProtectionKey': base64.b64encode(secrets.token_bytes(32)).decode()}
    server_key, server_pub = genkey()
    peer_key, peer_pub = genkey()
    psk = command([root / 'awg', 'genpsk']).stdout.strip().decode()
    control = root / 'control'; control.mkdir(mode=0o700)
    token = secrets.token_hex(32); write(root / 'token', token)
    client_id = hashlib.sha256(('amnezia-awg2\t' + peer_pub).encode()).hexdigest()
    write(root / 'credentials.json', json.dumps({'enabled': False, 'clientLogs': {'token': token, 'clientId': client_id}}))
    command(['openssl', 'genpkey', '-algorithm', 'ED25519', '-out', control / 'signing.pem'])
    os.chmod(control / 'signing.pem', 0o600)
    der = command(['openssl', 'pkey', '-in', control / 'signing.pem', '-pubout', '-outform', 'DER']).stdout
    ready = {'serverPublicKey': server_pub, 'containerId': 'amnezia-awg2', 'generation': 1,
             'expiresAt': int(time.time()) + 3600, 'signingPublicKey': base64.b64encode(der[-32:]).decode(),
             'endpoint': '10.233.2.2:51822', 'parameters': target,
             'challengeAddress': '172.29.172.251', 'challengePort': 18082,
             'peers': {peer_pub: {'sourceIp': '10.244.0.2', 'targetIp': '10.244.0.2',
                                'clientAddress': '10.244.0.2/32', 'clientId': client_id}}}
    write(control / 'ready.json', json.dumps(ready))
    configs = root / 'profiles'; configs.mkdir(mode=0o700)
    state = root / 'state'; state.mkdir(mode=0o700)
    staging = root / 'staging'; staging.mkdir(mode=0o700)
    original = '[Interface]\nPrivateKey = ' + peer_key + '\nAddress = 10.244.0.2/32\nMTU = 1420\n'
    original += ''.join(k + ' = ' + v + '\n' for k, v in legacy.items())
    original += '[Peer]\nPublicKey = ' + server_pub + '\nPresharedKey = ' + psk + '\nEndpoint = 10.233.1.2:51821\nAllowedIPs = 172.29.172.251/32, 172.29.172.252/32\nPersistentKeepalive = 1\n'
    config = configs / 'amn0.conf'; write(config, original, 0o640)
    os.chown(config, 0, group)
    profile = {'id': 'native-migration', 'name': 'native migration', 'protocol': 'amneziawg',
               'configPath': str(config), 'interfaceName': 'amn0', 'routingMode': 'only-forward',
               'forwardRoutes': ['172.29.172.251/32', '172.29.172.252/32'],
               'dnsServers': ['172.29.172.251'], 'dnsDomains': ['~migration.lab']}
    write(state / 'profiles.json', json.dumps({'version': 1, 'profiles': [profile]}))
    original_hash = sha(config)
    try:
        # Privileged production lookup intentionally ignores ambient PATH.
        # Install only absent exact fixture bytes into its existing trusted root;
        # never replace a distro/guest helper or relax the production lookup.
        trusted = Path('/usr/local/bin')
        for parent in (Path('/usr'), Path('/usr/local'), trusted):
            st = parent.lstat()
            if parent.is_symlink() or not parent.is_dir() or st.st_uid or st.st_mode & 0o022:
                raise RuntimeError('untrusted guest helper parent')
        for name in ('awg', 'awg-quick', 'amneziawg-go'):
            helper_path = trusted / name
            fd = os.open(helper_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o755)
            with os.fdopen(fd, 'wb') as stream:
                stream.write((root / name).read_bytes())
                stream.flush(); os.fsync(stream.fileno()); os.fchmod(stream.fileno(), 0o755)
            st = helper_path.lstat()
            installed.append((helper_path, st.st_dev, st.st_ino, sha(root / name)))
            if st.st_uid or helper_path.is_symlink() or sha(helper_path) != sha(root / name):
                raise RuntimeError('guest helper exact bytes mismatch')
        for i, ns in enumerate(namespaces, 1):
            host, peer, device = 'agh' + str(i) + tag, 'agn' + str(i) + tag, ['amsrc', 'amtgt'][i-1]
            if command(['ip', 'link', 'show', host], check=False).returncode == 0:
                raise RuntimeError('fixture veth exists')
            command(['ip', 'netns', 'add', ns]); created.append((ns, host))
            command(['ip', 'link', 'add', host, 'type', 'veth', 'peer', 'name', peer])
            command(['ip', 'link', 'set', peer, 'netns', ns])
            command(['ip', 'addr', 'add', f'10.233.{i}.1/30', 'dev', host])
            command(['ip', 'link', 'set', host, 'up'])
            command(['ip', 'addr', 'add', f'10.233.{i}.2/30', 'dev', peer], ns=ns)
            command(['ip', 'link', 'set', peer, 'up'], ns=ns)
            command(['ip', 'link', 'set', 'lo', 'up'], ns=ns)
            command(['ip', 'addr', 'add', '172.29.172.251/32', 'dev', 'lo'], ns=ns)
            command(['ip', 'addr', 'add', '172.29.172.252/32', 'dev', 'lo'], ns=ns)
            backend = root / ('legacy-amneziawg-go' if i == 1 and legacy_names else 'amneziawg-go')
            native_tool = awg_command(root, i == 1 and bool(legacy_names))
            spawn([backend, '-f', device], ns=ns)
            wait(lambda: command(['ip', 'link', 'show', device], ns=ns, check=False).returncode == 0, 'native server creation', 10)
            params = legacy if i == 1 else target
            server_config = '[Interface]\nPrivateKey = ' + server_key + f'\nListenPort = {51820+i}\n'
            server_config += ''.join(k + ' = ' + v + '\n' for k, v in params.items())
            server_config += '[Peer]\nPublicKey = ' + peer_pub + '\nPresharedKey = ' + psk + '\nAllowedIPs = 10.244.0.2/32\n'
            write(root / (device + '.conf'), server_config)
            command(native_tool + ['setconf', device, root / (device + '.conf')], ns=ns)
            command(['ip', 'addr', 'add', '10.244.0.1/32', 'dev', device], ns=ns)
            command(['ip', 'link', 'set', device, 'mtu', '1420', 'up'], ns=ns)
            command(['ip', 'route', 'add', '10.244.0.2/32', 'dev', device], ns=ns)
            spawn(['/usr/bin/python3', root / 'guest.py', '--server', root, ns, device, ['source', 'target'][i-1]], ns=ns)
        daemon = spawn([root / 'amneziad', '--socket', root / 'daemon.sock', '--store', state / 'profiles.json',
                        '--config-root', configs, '--require-root-owned-config', '--staging-root', staging,
                        '--remote-log-config', root / 'credentials.json'])
        wait(lambda: (root / 'daemon.sock').exists() and daemon.poll() is None, 'daemon startup', 10)
        cli('connect', profile['id'])
        command(['ping', '-I', 'amn0', '-c', '1', '-W', '2', '172.29.172.251'])
        before = command([root / 'awg', 'show', 'amn0', 'latest-handshakes']).stdout
        journal = state / 'awg-migrations' / hashlib.sha256(profile['id'].encode()).hexdigest() / 'journal.json'
        staged = wait(lambda: json.loads(journal.read_text()) if journal.exists() and json.loads(journal.read_text()).get('phase') == 'staged' else None, 'stage over old native tunnel')
        assert sha(config) == original_hash
        assert command([root / 'awg', 'show', 'amn0', 'endpoints']).stdout.decode().strip().endswith('10.233.1.2:51821')
        receipt['checks']['stagedActiveLegacyUnchanged'] = True
        write(root / 'validated-steps.json', json.dumps(receipt))
        cli('disconnect')
        attempt = int(time.time())
        cli('connect', profile['id'])
        committed = wait(lambda: json.loads(journal.read_text()) if json.loads(journal.read_text()).get('phase') == 'committed' else None, 'candidate commit', 20)
        assert committed.get('ackPending') is False
        with sqlite3.connect(control / 'grants.sqlite3') as db:
            assert db.execute('SELECT count(*) FROM grants WHERE proved=1 AND ack=1').fetchone()[0] == 1
        # Go candidate observation reads its own real UAPI; no synthetic proof.
        s = socket.socket(socket.AF_UNIX); s.settimeout(3); s.connect('/run/amnezia/awg3/amn0.sock'); s.sendall(b'get=1\n\n')
        native = b''
        while not native.endswith(b'\n\n'):
            part = s.recv(65536)
            if not part or len(native) > 65536:
                raise RuntimeError('candidate UAPI incomplete/oversized')
            native += part
        s.close()
        assert ('header_protection_key=' + base64.b64decode(target['HeaderProtectionKey']).hex()).encode() in native
        observed = [int(row.split(b'=')[1]) for row in native.splitlines() if row.startswith(b'last_handshake_time_sec=')]
        assert observed and max(observed) >= attempt
        command(['ping', '-I', 'amn0', '-M', 'do', '-s', '1300', '-c', '2', '-W', '2', '172.29.172.252'])
        assert sha(config) == original_hash and config.stat().st_gid == group and config.stat().st_mode & 0o777 == 0o640
        receipt['checks'].update(native3ParametersAndFreshHandshake=True, boundLargePacketTraffic=True, serverProofAndAck=True, trustedAmnezia0640=True)
        write(root / 'validated-steps.json', json.dumps(receipt))
        cli('disconnect')
        receipt['checks']['ownedDisconnect'] = command(['ip', 'link', 'show', 'amn0'], check=False).returncode != 0
        receipt['checks']['sourceProfileAndPskUnchanged'] = sha(config) == original_hash
        write(root / 'validated-steps.json', json.dumps(receipt))
        daemon.terminate(); daemon.wait(timeout=5)
        # A new real peer/offer with an unreachable candidate UDP port proves
        # actual fallback. Neither application journal nor proof is injected.
        fail_key, fail_pub = genkey()
        fail_id = hashlib.sha256(('amnezia-awg2\t' + fail_pub).encode()).hexdigest()
        fail_psk = command([root / 'awg', 'genpsk']).stdout.strip().decode()
        command(awg_command(root, bool(legacy_names)) + ['set', 'amsrc', 'peer', fail_pub, 'preshared-key', '/dev/stdin',
                 'allowed-ips', '10.244.0.3/32'], data=fail_psk.encode(), ns=namespaces[0])
        command(['ip', 'route', 'add', '10.244.0.3/32', 'dev', 'amsrc'], ns=namespaces[0])
        ready['peers'][fail_pub] = {'sourceIp': '10.244.0.3', 'targetIp': '10.244.0.3',
                                    'clientAddress': '10.244.0.3/32', 'clientId': fail_id}
        ready.update(generation=2, endpoint='10.233.2.2:51829')
        write(control / 'ready.json', json.dumps(ready))
        write(root / 'credentials-failure.json', json.dumps({'enabled': False, 'clientLogs': {'token': token, 'clientId': fail_id}}))
        fail_configs = root / 'profiles-failure'; fail_configs.mkdir(mode=0o700)
        fail_state = root / 'state-failure'; fail_state.mkdir(mode=0o700)
        fail_config = fail_configs / 'amn0.conf'
        failure_original = original.replace(peer_key, fail_key).replace(psk, fail_psk).replace('10.244.0.2/32', '10.244.0.3/32')
        write(fail_config, failure_original, 0o640); os.chown(fail_config, 0, group)
        fail_hash = sha(fail_config)
        fail_profile = {**profile, 'id': 'native-failure', 'configPath': str(fail_config)}
        write(fail_state / 'profiles.json', json.dumps({'version': 1, 'profiles': [fail_profile]}))
        # The preceding daemon removes its own socket at exit; no foreign
        # socket unlink is performed by this helper.
        wait(lambda: not (root / 'daemon.sock').exists(), 'owned socket shutdown', 5)
        fail_daemon = spawn([root / 'amneziad', '--socket', root / 'daemon.sock', '--store', fail_state / 'profiles.json',
                             '--config-root', fail_configs, '--require-root-owned-config', '--staging-root', staging,
                             '--remote-log-config', root / 'credentials-failure.json'])
        wait(lambda: (root / 'daemon.sock').exists() and fail_daemon.poll() is None, 'failure daemon startup', 10)
        cli('connect', fail_profile['id'])
        command(['ping', '-I', 'amn0', '-c', '1', '-W', '2', '172.29.172.251'])
        fail_journal = fail_state / 'awg-migrations' / hashlib.sha256(fail_profile['id'].encode()).hexdigest() / 'journal.json'
        wait(lambda: fail_journal.exists() and json.loads(fail_journal.read_text()).get('phase') == 'staged', 'failure authentic stage')
        routes_before = command(['ip', '-json', 'route', 'show', 'dev', 'amn0']).stdout
        dns_before = command(['resolvectl', 'dns', 'amn0']).stdout.decode().partition(':')[2].strip()
        domains_before = command(['resolvectl', 'domain', 'amn0']).stdout.decode().partition(':')[2].strip()
        mtu_before = json.loads(command(['ip', '-json', 'link', 'show', 'amn0']).stdout)[0]['mtu']
        cli('disconnect'); cli('connect', fail_profile['id'])
        rolled = json.loads(fail_journal.read_text())
        assert rolled['phase'] == 'rolled_back' and rolled['highestGeneration'] == 2
        assert command([root / 'awg', 'show', 'amn0', 'endpoints']).stdout.decode().strip().endswith('10.233.1.2:51821')
        command(['ping', '-I', 'amn0', '-M', 'do', '-s', '1300', '-c', '2', '-W', '2', '172.29.172.252'])
        assert sha(fail_config) == fail_hash
        assert command(['ip', '-json', 'route', 'show', 'dev', 'amn0']).stdout == routes_before
        assert command(['resolvectl', 'dns', 'amn0']).stdout.decode().partition(':')[2].strip() == dns_before
        assert command(['resolvectl', 'domain', 'amn0']).stdout.decode().partition(':')[2].strip() == domains_before
        assert json.loads(command(['ip', '-json', 'link', 'show', 'amn0']).stdout)[0]['mtu'] == mtu_before
        assert profile['forwardRoutes'] == fail_profile['forwardRoutes'] and profile['dnsServers'] == fail_profile['dnsServers']
        receipt['forcedFailureRollback'] = True
        receipt['checks'].update(failedGenerationWatermark=True, rollbackProfilePskRoutesDnsMtuPreserved=True)
        write(root / 'validated-steps.json', json.dumps(receipt))
        cli('disconnect')
        return receipt
    finally:
        for p in reversed(processes):
            if p.poll() is None:
                p.terminate()
                try:
                    p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    p.kill(); p.wait(timeout=5)
        for ns, host in reversed(created):
            command(['ip', 'link', 'del', host], check=False)
            command(['ip', 'netns', 'del', ns], check=False)
        for target, device, inode, expected in reversed(installed):
            st = target.lstat()
            if target.is_symlink() or st.st_uid or (st.st_dev, st.st_ino) != (device, inode) or sha(target) != expected:
                raise RuntimeError('guest helper cleanup ownership changed')
            target.unlink()
        if legacy_runtime is not None:
            observed = legacy_runtime.lstat()
            if not stat.S_ISDIR(observed.st_mode) or (observed.st_dev, observed.st_ino) != legacy_runtime_identity:
                raise RuntimeError('legacy socket directory identity changed')
            remaining = list(legacy_runtime.iterdir())
            for entry in remaining:
                st = entry.lstat()
                if entry.name != 'amsrc.sock' or st.st_uid or not stat.S_ISSOCK(st.st_mode):
                    raise RuntimeError('legacy socket cleanup ownership changed')
                entry.unlink()
            legacy_runtime.rmdir()


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--server':
        server(Path(sys.argv[2]), *sys.argv[3:6])
    else:
        plan = json.loads(Path(sys.argv[1]).read_text())
        receipt = {'origin': 'guest', 'transport': 'qga', **{k: plan[k] for k in ('runId', 'marker', 'uuid')}, 'passed': False}
        try:
            receipt.update(scenario(plan))
            receipt['passed'] = all(receipt['checks'].values()) and receipt.get('forcedFailureRollback') is True
        except Exception as error:
            receipt['error'] = type(error).__name__ + ': ' + str(error)
            receipt['failureFrames'] = [{'function': frame.name, 'line': frame.lineno}
                                       for frame in traceback.extract_tb(error.__traceback__)
                                       if Path(frame.filename).name == Path(__file__).name]
            checkpoint = Path(plan['root']) / 'validated-steps.json'
            if checkpoint.exists() and not checkpoint.is_symlink() and checkpoint.stat().st_uid == 0:
                verified = json.loads(checkpoint.read_text()).get('checks', {})
                if isinstance(verified, dict) and all(isinstance(value, bool) for value in verified.values()):
                    receipt['validatedSteps'] = verified
        print(json.dumps(receipt, sort_keys=True))
