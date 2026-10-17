"""Durable ownership journal. Recovery addresses immutable owned Docker IDs only."""
import json
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time

# Verify the actual control PID1 owns the listening socket. Namespace INPUT
# permits VPN peers only, so loopback TCP health connections are rejected.
CONTROL_LISTENER_PROBE = ('import os,pathlib; '
    'cmd=pathlib.Path("/proc/1/cmdline").read_bytes().split(bytes([0])); '
    'assert b"/migration/target.py" in cmd; '
    'owned={os.readlink(p) for p in pathlib.Path("/proc/1/fd").iterdir()}; '
    'rows=[line.split() for line in pathlib.Path("/proc/net/tcp").read_text().splitlines()[1:]]; '
    'assert any(row[1]=="00000000:46A2" and row[3]=="0A" and '
    '"socket:["+row[9]+"]" in owned for row in rows)')

# Exact reviewed predecessors, not a TOFU adoption of whatever is installed.
# b0921b650 source; and the existing gen1 pair read by the administrator on
# 2026-10-17 16:51:46Z. Historical bytes must match as a coherent pair.
CONTROL_BASELINES = (
    {'service.py': '88254af95c85b49ee2bc0d1d6d981ee401e0be0c5bddce1d0c4462245419ae3e',
     'target.py': '1ed03cc1fc41c6bbd87c58bcb207bcfa6d38d6501987d2a6a9d8faf469617d32'},
    {'service.py': 'ed640e5fcbba634a6963d43e207ffaf672704d37044fdb186fd27d61351c6eb2',
     'target.py': '1ed03cc1fc41c6bbd87c58bcb207bcfa6d38d6501987d2a6a9d8faf469617d32'},
)
CONTROL_FILES = ('service.py', 'target.py')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def durable_bytes(path, raw):
    """Same-directory atomic write, verified before and after replacement."""
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    tmp = Path(temporary)
    with os.fdopen(fd, 'wb') as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    if tmp.read_bytes() != raw:
        raise ValueError('control maintenance staged readback')
    os.replace(tmp, path)
    if path.read_bytes() != raw:
        raise ValueError('control maintenance readback')
    fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic(path, value):
    tmp = path.with_suffix('.tmp')
    with open(tmp, 'w') as stream:
        os.fchmod(stream.fileno(), 0o600)
        json.dump(value, stream, separators=(',', ':'), sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(tmp, path)
    if os.name != 'nt':
        fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def inspect(run, identity):
    try:
        values = json.loads(run('docker', 'inspect', identity))
    except subprocess.CalledProcessError as error:
        message = (error.stderr or b'').decode(errors='replace').lower()
        if 'no such object' in message or 'no such container' in message:
            return None
        raise ValueError('ownership inspection unavailable') from error
    except (ValueError, TypeError):
        raise ValueError('invalid ownership inspection')
    if len(values) != 1:
        raise ValueError('ambiguous ownership')
    return values[0]


class Journal:
    def __init__(self, directory, run, value=None):
        self.directory, self.run = Path(directory), run
        self.path = self.directory / 'transaction.json'
        self.value = value if value is not None else json.loads(self.path.read_text())
        if not re.fullmatch('[a-f0-9]{32}', self.value['owner']):
            raise ValueError('journal owner')

    def save(self, phase=None):
        if phase:
            self.value['phase'] = phase
        atomic(self.path, self.value)

    def plan(self, name, image):
        self.value['containers'][name] = {'image': image, 'id': None}
        self.save('creating')

    def owned(self, name):
        expected = self.value['containers'][name]
        observed = inspect(self.run, expected['id'] or name)
        if observed is None:
            return None
        if (observed['Config'].get('Labels', {}).get('amnezia.migration.owner') != self.value['owner']
                or observed['Image'] != expected['image']
                or (expected['id'] and observed['Id'] != expected['id'])
                or observed['Name'] != '/' + name):
            raise ValueError('ownership collision; human review required')
        return observed

    def record(self, name):
        observed = self.owned(name)
        if observed is None:
            raise ValueError('created container not found')
        self.value['containers'][name]['id'] = observed['Id']
        self.save()

    def control_helpers(self):
        """Validate immutable ownership AND the mounted recipe/namespace binding."""
        source = inspect(self.run, self.value['sourceId'])
        target = self.owned(self.value['target'])
        if (source is None or source['Id'] != self.value['sourceId']
                or source['Name'] != '/' + self.value['source'] or target is None
                or not source['State']['Running'] or not target['State']['Running']
                or source['State']['StartedAt'] != self.value['sourceEpoch']
                or target['State']['StartedAt'] != self.value['targetEpoch']):
            raise ValueError('control maintenance parent drift')
        result = []
        for suffix, parent, role in (('-control', target, 'target'),
                                     ('-source-control', source, 'source')):
            name = self.value['target'] + suffix
            helper = self.owned(name)
            expected_id = self.value['containers'][name]['id']
            if helper is None or not expected_id or helper['Id'] != expected_id:
                raise ValueError('control maintenance missing helper')
            mounts = helper.get('Mounts', [])
            migration = [m for m in mounts if m.get('Destination') == '/migration']
            logs = [m for m in mounts if m.get('Destination') == '/logs']
            host = helper.get('HostConfig', {})
            environment = helper.get('Config', {}).get('Env') or []
            if not isinstance(environment, list) or any(not isinstance(item, str) or '=' not in item for item in environment):
                raise ValueError('control maintenance helper environment')
            values = {}
            for item in environment:
                key, value = item.split('=', 1)
                if key in ('AMNEZIA_MIGRATION_ROLE', 'AMNEZIA_MIGRATION_SCOPE'):
                    if key in values:
                        raise ValueError('control maintenance duplicate helper environment')
                    values[key] = value
            effective_role = values.get('AMNEZIA_MIGRATION_ROLE', 'target')
            effective_scope = values.get('AMNEZIA_MIGRATION_SCOPE') or self.value['source']
            if (effective_role != role or effective_scope != self.value['source']
                    or (role == 'source' and values.get('AMNEZIA_MIGRATION_SCOPE') != self.value['source'])):
                raise ValueError('control maintenance helper role/scope')
            if (host.get('NetworkMode') != 'container:' + parent['Id']
                    or host.get('Privileged') is not False
                    or len(migration) != 1 or migration[0].get('Type') != 'bind'
                    or migration[0].get('Source') != str(self.directory)
                    or migration[0].get('RW') is not True
                    or len(logs) != 1 or logs[0].get('Type') != 'bind'
                    or logs[0].get('Source') != '/opt/amnezia/client-logs'
                    or logs[0].get('RW') is not False
                    or helper.get('Config', {}).get('Entrypoint') != ['python']
                    or helper.get('Config', {}).get('Cmd') != ['/migration/target.py']):
                raise ValueError('control maintenance helper binding')
            result.append((name, helper, role))
        return result

    def control_hashes(self):
        return {name: digest((self.directory / name).read_bytes()) for name in CONTROL_FILES}

    def protected_control_state(self, require_native=False):
        # Grant DB and handshake files are intentionally live; this path never
        # opens them for writing or attempts to restore concurrent client work.
        names = ('awg0.conf', 'ready.json', 'signing.pem', 'start.sh')
        native = self.directory / 'awg0.native.conf'
        # Legacy/manual preparation never creates the automatic native recipe.
        # Protect it when present; the automatic-only entry can require it.
        if require_native or native.exists() or native.is_symlink():
            names += ('awg0.native.conf',)
        if any((self.directory / name).is_symlink() or not (self.directory / name).is_file() for name in names):
            raise ValueError('control maintenance protected state missing')
        return {name: digest((self.directory / name).read_bytes()) for name in names}

    def check_loaded_controls(self, expected_hashes):
        """Read-only proof of both current owned PID1s, including no-op recipes."""
        for _, helper, role in self.control_helpers():
            self.check_loaded_helper(helper, role, expected_hashes)

    def check_loaded_helper(self, helper, role, expected_hashes):
        self.run('docker', 'exec', helper['Id'], 'python', '-c', CONTROL_LISTENER_PROBE)
        probe = ('import json,pathlib; r=json.loads(pathlib.Path("/migration/control-loaded-' + role + '.json").read_text()); '
                 'assert r["role"]==' + repr(role) + '; '
                 'assert r["hashes"]==' + repr(expected_hashes) + '; '
                 'assert r["processStart"]==pathlib.Path("/proc/1/stat").read_text().split()[21]')
        self.run('docker', 'exec', helper['Id'], 'python', '-c', probe)

    def check_control_state(self, protected):
        if self.protected_control_state() != protected:
            raise ValueError('control maintenance protected state drift')
        config = '/opt/amnezia/awg/' + ('wg0.conf' if self.value['source'] == 'amnezia-awg' else 'awg0.conf')
        raw = self.run('docker', 'exec', self.value['sourceId'], 'cat', config)
        if digest(raw) != self.value['sourceDigest']:
            raise ValueError('control maintenance source configuration drift')

    def restart_controls(self, expected_hashes, loaded_receipt):
        # Verify the complete pair before EACH mutation; never operate by name.
        original = self.control_helpers()
        for name, old, role in original:
            current = {n: h for n, h, _ in self.control_helpers()}[name]
            if current['Id'] != old['Id']:
                raise ValueError('control maintenance helper replaced')
            self.run('docker', 'restart', old['Id'])
            for attempt in range(10):
                try:
                    fresh = self.owned(name)
                    if (fresh is None or not fresh['State']['Running']
                            or fresh['State']['StartedAt'] == current['State']['StartedAt']):
                        raise ValueError('control maintenance process not replaced')
                    if loaded_receipt:
                        self.check_loaded_helper(fresh, role, expected_hashes)
                    else:
                        self.run('docker', 'exec', old['Id'], 'python', '-c', CONTROL_LISTENER_PROBE)
                    break
                except (subprocess.SubprocessError, ValueError):
                    if attempt == 9:
                        raise
                    time.sleep(1)
        self.control_helpers()

    def recover_control_maintenance(self):
        """Any interrupted activation rolls back, including after both imports."""
        transaction = self.value.get('controlMaintenance')
        if not transaction:
            return
        self.control_helpers()
        self.check_control_state(transaction['protected'])
        old, new = transaction['old'], transaction['new']
        current = self.control_hashes()
        if any(current[name] not in (old[name], new[name]) for name in CONTROL_FILES):
            raise ValueError('control maintenance recovery file drift')
        backups = self.directory / '.control-maintenance'
        raw = {name: (backups / name).read_bytes() for name in CONTROL_FILES}
        if {name: digest(value) for name, value in raw.items()} != old:
            raise ValueError('control maintenance backup drift')
        for name in CONTROL_FILES:
            durable_bytes(self.directory / name, raw[name])
        self.restart_controls(old, transaction['oldLoadedReceipt'])
        self.check_control_state(transaction['protected'])
        self.value['controlRecipe'] = old
        self.value['controlLoadedReceipt'] = transaction['oldLoadedReceipt']
        self.value['controlMaintenanceResult'] = 'rolled_back'
        del self.value['controlMaintenance']
        self.save()

    def maintain_controls(self, recipe_directory, validate=None):
        """Refresh only control Python; VPN endpoint and durable grant state stay put."""
        self.recover_control_maintenance()
        self.control_helpers()
        protected = self.protected_control_state()
        self.check_control_state(protected)
        old = self.control_hashes()
        pinned = self.value.get('controlRecipe')
        if old != pinned and (pinned is not None or old not in CONTROL_BASELINES):
            raise ValueError('control maintenance unknown baseline')
        raw = {name: (Path(recipe_directory) / name).read_bytes() for name in CONTROL_FILES}
        new = {name: digest(value) for name, value in raw.items()}
        if new == old:
            # No TOFU: installed bytes still require a pin or reviewed predecessor.
            self.check_loaded_controls(old)
            self.check_control_state(protected)
            if validate:
                validate()
            self.value['controlRecipe'] = old
            self.value['controlLoadedReceipt'] = True
            self.save()
            return
        backup = self.directory / '.control-maintenance'
        backup.mkdir(mode=0o700, exist_ok=True)
        for name in CONTROL_FILES:
            durable_bytes(backup / name, (self.directory / name).read_bytes())
        transaction = {'old': old, 'new': new, 'protected': protected,
            'oldLoadedReceipt': self.value.get('controlLoadedReceipt', False)}
        self.value['controlMaintenance'] = transaction
        self.save()
        try:
            for name in CONTROL_FILES:
                durable_bytes(self.directory / name, raw[name])
            self.restart_controls(new, True)
            self.check_control_state(protected)
            if validate:
                validate()
            if self.control_hashes() != new:
                raise ValueError('control maintenance final readback')
            self.value['controlRecipe'] = new
            self.value['controlLoadedReceipt'] = True
            self.value['controlMaintenanceResult'] = 'updated'
            del self.value['controlMaintenance']
            self.save()
        except BaseException:
            # Persisted intent remains until exact old bytes AND processes return.
            # A later normal admin invocation repeats the same rollback safely.
            self.value['controlMaintenance'] = transaction
            self.save()
            self.recover_control_maintenance()
            raise

    def recover_ready(self):
        # No old VPN operations. Only the journal-owned parallel helpers resume.
        for name in self.value['containers']:
            observed = self.owned(name)
            if observed is None:
                raise ValueError('ready component missing; human review required')
            if not observed['State']['Running']:
                self.run('docker', 'start', observed['Id'])
        # A restarted parent has a new netns even when its Docker ID is stable.
        # Rejoin only journal-owned helpers; never restart the old VPN parent.
        source = inspect(self.run, self.value['sourceId'])
        if source is None or source['Name'] != '/' + self.value['source']:
            raise ValueError('source namespace replaced')
        if self.value.get('sourceRules'):
            self.ensure_source_rules()
        source_epoch = source['State'].get('StartedAt')
        parent = self.value.get('target')
        target = self.owned(parent) if parent else None
        target_epoch = target['State'].get('StartedAt') if target else None
        for name in self.value['containers']:
            observed = self.owned(name)
            if name.endswith('-source-control') and source_epoch != self.value.get('sourceEpoch'):
                self.run('docker', 'restart', observed['Id'])
            elif name != parent and not name.endswith('-source-control') and target_epoch != self.value.get('targetEpoch'):
                self.run('docker', 'restart', observed['Id'])
            if name.endswith('-source-control'):
                probe = CONTROL_LISTENER_PROBE
                for attempt in range(10):
                    try:
                        self.run('docker', 'exec', observed['Id'], 'python', '-c', probe)
                        break
                    except subprocess.SubprocessError:
                        time.sleep(1)
                else:
                    raise ValueError('source control listener not ready')
        self.value.update(sourceEpoch=source_epoch, targetEpoch=target_epoch)
        self.save('ready')

    def ensure_source_rules(self):
        owner, iface = self.value['owner'], self.value['sourceIface']
        source = inspect(self.run, self.value['sourceId'])
        if source is None or source['Name'] != '/' + self.value['source']:
            raise ValueError('source namespace replaced')
        rules = [('-I INPUT 1', f'-p tcp --dport 18082 -m comment --comment {owner} -j REJECT'),
                 ('-I INPUT 1', f'-i {iface} -p tcp --dport 18082 -m comment --comment {owner} -j ACCEPT'),
                 ('-t nat -A PREROUTING', f'-i {iface} -d 172.29.172.251/32 -p tcp --dport 18082 -m comment --comment {owner} -j REDIRECT --to-ports 18082')]
        for insertion, rule in rules:
            check = insertion.replace('-I INPUT 1', '-C INPUT').replace('-A PREROUTING', '-C PREROUTING')
            self.run('docker', 'exec', self.value['sourceId'], 'sh', '-c',
                     'iptables ' + check + ' ' + rule + ' 2>/dev/null || iptables ' + insertion + ' ' + rule)
            # Read back every exact owned rule before claiming readiness.
            self.run('docker', 'exec', self.value['sourceId'], 'sh', '-c', 'iptables ' + check + ' ' + rule)

    def cleanup(self):
        for name in reversed(list(self.value['containers'])):
            observed = self.owned(name)
            if observed is not None:
                self.run('docker', 'rm', '-f', observed['Id'])
        if self.value.get('sourceRules'):
            source = inspect(self.run, self.value['sourceId'])
            if source is None or source['Name'] != '/' + self.value['source']:
                raise ValueError('source namespace replaced')
            owner, iface = self.value['owner'], self.value['sourceIface']
            rules = [f'iptables -D INPUT -p tcp --dport 18082 -m comment --comment {owner} -j REJECT',
                     f'iptables -D INPUT -i {iface} -p tcp --dport 18082 -m comment --comment {owner} -j ACCEPT',
                     f'iptables -t nat -D PREROUTING -i {iface} -d 172.29.172.251/32 -p tcp --dport 18082 -m comment --comment {owner} -j REDIRECT --to-ports 18082']
            for rule in rules:
                # A phase can stop between any two rule insertions.
                self.run('docker', 'exec', self.value['sourceId'], 'sh', '-c', rule + ' 2>/dev/null || true')
        self.save('aborted')
