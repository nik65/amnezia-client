"""Durable ownership journal. Recovery addresses immutable owned Docker IDs only."""
import json
import os
from pathlib import Path
import re
import subprocess
import time


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
                probe = 'import socket; s=socket.create_connection(("127.0.0.1",18082),timeout=2);s.close()'
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
