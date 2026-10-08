#!/usr/bin/env python3
"""Reconcile one publication-bound collector; never restart its VPN parent."""
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

SCOPES = {'amnezia-awg2': 'awg0', 'amnezia-awg': 'wg0',
          'amnezia-wireguard': 'wg0', 'amnezia-openvpn': 'tun0'}
IMAGE = 'python:3.12-alpine@sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df'
ROOT = Path('/opt/amnezia/client-logs')
LABEL = 'org.amnezia.client-logs.route'


def command(args):
    return subprocess.run(args, check=True, capture_output=True, timeout=15).stdout


def inspect(container):
    value = json.loads(command(['docker', 'inspect', container]))
    if len(value) != 1:
        raise ValueError('container identity')
    return value[0]


def protected_json(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
            raise ValueError('metadata ownership')
        return json.loads(stream.read(4097))


def validate_binding(binding):
    scope = binding.get('scope')
    if (set(binding) != {'schema', 'scope', 'sourceId', 'collectorId'}
            or binding['schema'] != 1 or scope not in SCOPES
            or not all(re.fullmatch('[0-9a-f]{64}', binding[key]) for key in ('sourceId', 'collectorId'))):
        raise ValueError('binding')


def validate(source, collector, binding):
    validate_binding(binding)
    scope = binding['scope']
    if (source['Id'] != binding['sourceId'] or source['Name'] != '/' + scope
            or not source['State']['Running'] or source['State']['Pid'] <= 0
            or collector['Id'] != binding['collectorId']
            or collector['Name'] != '/amnezia-client-logs-' + scope
            or collector['Config']['Image'] != IMAGE
            or collector['Config'].get('Labels', {}).get(LABEL) != scope
            or collector['HostConfig']['NetworkMode'] != 'container:' + binding['sourceId']):
        raise ValueError('publication identity')
    mounts = [item for item in collector['Mounts'] if item['Destination'] == '/data']
    if len(mounts) != 1 or mounts[0]['Source'] != str(ROOT) or not mounts[0]['RW']:
        raise ValueError('collector data')


def namespace(container):
    pid = container['State']['Pid']
    if not container['State']['Running'] or pid <= 0:
        return None
    return os.readlink('/proc/%d/ns/net' % pid)


def reconcile(binding):
    validate_binding(binding)
    source, collector = inspect(binding['sourceId']), inspect(binding['collectorId'])
    validate(source, collector, binding)
    epoch = (source['State']['StartedAt'], namespace(source))
    if namespace(collector) != epoch[1]:
        command(['docker', 'restart', binding['collectorId']])
        collector = inspect(binding['collectorId'])
    fresh_source = inspect(binding['sourceId'])
    validate(fresh_source, collector, binding)
    if (fresh_source['State']['StartedAt'], namespace(fresh_source)) != epoch or namespace(collector) != epoch[1]:
        raise ValueError('namespace drift')
    # Collector PID1 owns the listener; no HTTP request, registration or token access.
    probe = "import os; s={os.readlink('/proc/1/fd/'+n)[8:-1] for n in os.listdir('/proc/1/fd') if os.path.islink('/proc/1/fd/'+n) and os.readlink('/proc/1/fd/'+n).startswith('socket:[')}; assert b'/data/collector.py' in open('/proc/1/cmdline','rb').read(); assert any(p[1]=='00000000:45CA' and p[3]=='0A' and p[9] in s for p in (l.split() for l in open('/proc/net/tcp').readlines()[1:]))"
    for attempt in range(10):
        try:
            command(['docker', 'exec', binding['collectorId'], 'python', '-c', probe])
            break
        except subprocess.CalledProcessError:
            if attempt == 9:
                raise ValueError('collector listener')
            time.sleep(1)
    rule = ['PREROUTING', '-i', SCOPES[binding['scope']], '-d', '172.29.172.251/32',
            '-p', 'tcp', '--dport', '17866', '-j', 'REDIRECT', '--to-ports', '17866']
    prefix = ['docker', 'exec', binding['sourceId'], 'iptables', '-t', 'nat']
    check = subprocess.run(prefix + ['-C'] + rule, capture_output=True, timeout=15)
    if check.returncode == 1:
        if (inspect(binding['sourceId'])['State']['StartedAt'], namespace(inspect(binding['sourceId']))) != epoch:
            raise ValueError('source epoch')
        command(prefix + ['-A'] + rule)
    elif check.returncode != 0:
        raise ValueError('rule check')
    try:
        command(prefix + ['-C'] + rule)
        final_source, final_collector = inspect(binding['sourceId']), inspect(binding['collectorId'])
        validate(final_source, final_collector, binding)
        if (final_source['State']['StartedAt'], namespace(final_source)) != epoch or namespace(final_collector) != epoch[1]:
            raise ValueError('final namespace drift')
    except Exception:
        # Roll back only this attempt's addition, and only in the very same namespace.
        if check.returncode == 1:
            try:
                observed = inspect(binding['sourceId'])
                if observed['Id'] == binding['sourceId'] and (observed['State']['StartedAt'], namespace(observed)) == epoch:
                    command(prefix + ['-D'] + rule)
            except Exception:
                pass
        raise


def main():
    if os.geteuid() != 0 or len(sys.argv) not in (2, 3) or sys.argv[1] not in SCOPES:
        raise ValueError('scope')
    scope = sys.argv[1]
    root_info = ROOT.lstat()
    if not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != 0 or root_info.st_mode & 0o077:
        raise ValueError('directory ownership')
    descriptor = os.open(ROOT / ('route-' + scope + '.lock'),
                         os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'a') as lock:
        info = os.fstat(lock.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
            raise ValueError('lock ownership')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        path = ROOT / ('route-' + scope + '.json')
        if len(sys.argv) == 3:
            if sys.argv[2] != '--bind':
                raise ValueError('operation')
            source, collector = inspect(scope), inspect('amnezia-client-logs-' + scope)
            binding = {'schema': 1, 'scope': scope, 'sourceId': source['Id'], 'collectorId': collector['Id']}
            validate(source, collector, binding)
            reconcile(binding)
            temporary = path.with_suffix('.tmp')
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                with os.fdopen(descriptor, 'w') as stream:
                    json.dump(binding, stream, sort_keys=True)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, path)
            finally:
                temporary.unlink(missing_ok=True)
        else:
            reconcile(protected_json(path))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('collector route reconciliation refused', file=sys.stderr)
        sys.exit(1)
