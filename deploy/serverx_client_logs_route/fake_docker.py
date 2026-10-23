#!/usr/bin/python3
"""Owned test fixture. Never calls Docker or touches a real process namespace."""
import json
import pathlib
import sys

root = pathlib.Path(__file__).parent
path = root / 'state.json'
s = json.loads(path.read_text())
a = sys.argv[1:]
s['calls'].append(a)


def save(code=0, output=''):
    path.write_text(json.dumps(s))
    if output:
        print(output)
    raise SystemExit(code)


def find(value):
    return next((c for c in s['containers'] if c['Id'] == value or c['Name'] == '/' + value), None)


def process(c, namespace):
    p = root / 'proc' / str(c['State']['Pid'])
    (p / 'ns').mkdir(parents=True, exist_ok=True)
    (p / 'net').mkdir(exist_ok=True)
    (p / 'fd').mkdir(exist_ok=True)
    n = p / 'ns/net'
    n.unlink(missing_ok=True)
    n.symlink_to(namespace)
    (p / 'cmdline').write_bytes(b'python\0/data/collector.py\0')
    (p / 'net/tcp').write_text('0: 00000000:45CA 00000000:0000 0A 0 0 0 0 0 12345\n')
    f = p / 'fd/3'
    f.unlink(missing_ok=True)
    f.symlink_to('socket:[12345]')


if a[0] == 'inspect':
    c = find(a[1])
    save(0 if c else 1, json.dumps([c]) if c else '')
if a[:2] == ['ps', '-a']:
    name = a[a.index('--filter') + 1].removeprefix('name=^/').removesuffix('$')
    c = find(name)
    save(output=c['Id'][:12] if c else '')
if a[0] == 'exec':
    c = find(a[1])
    if not c:
        save(1)
    if a[2:] == ['awg', 'show', 'awg0', 'public-key']:
        s['key_reads'] = s.get('key_reads', 0) + 1
        if s.get('race_at_key_read') == s['key_reads']:
            c['State']['StartedAt'] = 'changed'
        save(output=s['public_key'])
    if a[2:5] == ['iptables', '-t', 'nat']:
        op = a[5]
        if op == '-C':
            exists = s.get('owned_rule', False) if '--comment' in a else (s.get('foreign_plain', False) or (s['rule'] and not s.get('owned_rule', False)))
            save(0 if exists else 1)
        if op == '-A':
            s['rule'] = True
            s['owned_rule'] = '--comment' in a
            if s.get('foreign_rule_after_add'):
                s['foreign_plain'] = True
            if s.get('uncertain_add'):
                save(1)
            if s.get('source_restart_after_add'):
                find('amnezia-awg2')['State']['StartedAt'] = 'source-changed-after-add'
            if s.get('collector_restart_after_add'):
                target = find(s['active'])
                target['State']['Pid'] += 200
                target['State']['StartedAt'] = 'collector-changed'
                process(target, s['source_ns'])
            save()
        if op == '-D':
            s['owned_rule'] = False
            s['rule'] = s.get('foreign_plain', False)
            save()
if a[0] == 'restart':
    c = find(a[1])
    if not c or c['Name'] == '/amnezia-awg2':
        save(99)
    c['State']['Running'] = True
    c['State']['Pid'] += 100
    c['State']['StartedAt'] = 'collector-restarted'
    process(c, s['source_ns'])
    save(output=c['Id'])
if a[0] == 'run':
    name = a[a.index('--name') + 1]
    if find(name):
        save(1)
    c = json.loads(json.dumps(s['template']))
    c['Id'] = 'c' * 64
    c['Name'] = '/' + name
    c['Config']['Labels'] = {'org.amnezia.serverx-diagnostic-route': 'awg2-v1'}
    c['HostConfig']['NetworkMode'] = a[a.index('--network') + 1]
    c['State']['Pid'] = 333
    c['State']['StartedAt'] = 'candidate-started'
    process(c, s['source_ns'])
    s['containers'].append(c)
    save(output=c['Id'])
if a[:2] == ['rm', '-f']:
    c = find(a[2])
    if not c or c['Name'] == '/amnezia-awg2':
        save(99)
    s['containers'].remove(c)
    save(output=c['Id'])
if a[0] == 'rename':
    c = find(a[1])
    if not c or find(a[2]):
        save(1)
    c['Name'] = '/' + a[2]
    save()
save(98)
