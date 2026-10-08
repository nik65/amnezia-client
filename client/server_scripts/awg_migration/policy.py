"""Typed standard AWG namespace policy; arbitrary shell hooks are ineligible."""
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import shlex


def mtu(value):
    if not re.fullmatch(r'[0-9]{3,4}', str(value)) or not 576 <= int(value) <= 9000:
        raise ValueError('unsupported_mtu')
    return int(value)


def standard_filter(iface, network):
    return [f'-A INPUT -i {iface} -j ACCEPT', f'-A FORWARD -i {iface} -j ACCEPT',
            f'-A OUTPUT -o {iface} -j ACCEPT',
            f'-A FORWARD -s {network} -i {iface} -o eth0 -j ACCEPT',
            f'-A FORWARD -s {network} -i {iface} -o eth1 -j ACCEPT',
            '-A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT']


def normalize(rule, iface):
    tokens = shlex.split(rule)
    tokens = ['awg0' if item in (iface, '%i') else item for item in tokens]
    # iptables emits options in canonical order independent of insertion spelling.
    if '--state' in tokens:
        position = tokens.index('--state') + 1
        tokens[position] = ','.join(sorted(tokens[position].split(',')))
    if '--ctstate' in tokens:
        position = tokens.index('--ctstate') + 1
        tokens[position] = ','.join(sorted(tokens[position].split(',')))
    return ' '.join(tokens)


def validate_hooks(interface, iface):
    network = str(ipaddress.ip_interface(interface['Address']).network)
    allowed = {normalize(rule, iface) for rule in standard_filter(iface, network)}
    allowed |= {normalize(f'-A FORWARD -i {iface} -o {eth} -j ACCEPT', iface) for eth in ('eth0', 'eth1')}
    for name, operation in (('PostUp', '-A'), ('PostDown', '-D')):
        for command in interface.get(name, '').split(';'):
            if not command.strip():
                continue
            tokens = shlex.split(command)
            if not tokens or tokens.pop(0) != 'iptables' or operation not in tokens:
                raise ValueError('unsupported_namespace_hook')
            tokens[tokens.index(operation)] = '-A'
            if tokens[:2] == ['-t', 'nat']:
                tokens = tokens[2:]
                allowed_nat = {normalize(f'-A POSTROUTING -s {network} -o {eth} -j MASQUERADE', iface) for eth in ('eth0', 'eth1')}
                allowed_nat |= {normalize(f'-A POSTROUTING -o {eth} -j MASQUERADE', iface) for eth in ('eth0', 'eth1')}
                if normalize(' '.join(tokens), iface) not in allowed_nat:
                    raise ValueError('unsupported_namespace_hook')
            elif normalize(' '.join(tokens), iface) not in allowed:
                raise ValueError('unsupported_namespace_hook')


def docker_dns_rules(lines):
    """Recognize the complete Docker-owned IPv4 embedded resolver NAT group.

    Listener ports belong to each Docker namespace and must not be replayed in
    another namespace. Everything outside the complete typed group remains
    subject to the ordinary operator policy allowlist.
    """
    chains = {'DOCKER_OUTPUT', 'DOCKER_POSTROUTING'}
    group = [line for line in lines if chains.intersection(shlex.split(line))]
    if not group:
        return lines, False
    fixed = {'-N DOCKER_OUTPUT', '-N DOCKER_POSTROUTING',
             '-A OUTPUT -d 127.0.0.11/32 -j DOCKER_OUTPUT',
             '-A POSTROUTING -d 127.0.0.11/32 -j DOCKER_POSTROUTING'}
    if len(group) != 8 or len(set(group)) != 8 or not fixed.issubset(group):
        raise ValueError('unsupported_namespace_firewall')
    destinations, sources = {}, {}
    for line in group:
        if line in fixed:
            continue
        destination = re.fullmatch(
            r'-A DOCKER_OUTPUT -d 127\.0\.0\.11/32 -p (tcp|udp) -m \1 --dport 53 -j DNAT --to-destination 127\.0\.0\.11:([0-9]+)', line)
        source = re.fullmatch(
            r'-A DOCKER_POSTROUTING -s 127\.0\.0\.11/32 -p (tcp|udp) -m \1 --sport ([0-9]+) -j SNAT --to-source :53', line)
        match, ports = (destination, destinations) if destination else (source, sources)
        if not match or match.group(1) in ports or not 1024 <= int(match.group(2)) <= 65535:
            raise ValueError('unsupported_namespace_firewall')
        ports[match.group(1)] = int(match.group(2))
    if set(destinations) != {'tcp', 'udp'} or sources != destinations:
        raise ValueError('unsupported_namespace_firewall')
    return [line for line in lines if line not in group], True


def namespace_snapshot(run, container, interface, iface, owned_comments=()):
    validate_hooks(interface, iface)
    network = str(ipaddress.ip_interface(interface['Address']).network)
    link = run('docker', 'exec', container, 'ip', '-o', 'link', 'show', 'dev', iface).decode()
    match = re.search(r'\bmtu ([0-9]+)\b', link)
    if not match:
        raise ValueError('source_mtu_unobserved')
    effective_mtu = mtu(match.group(1))
    if 'MTU' in interface and mtu(interface['MTU']) != effective_mtu:
        raise ValueError('source_mtu_drift')
    rules = run('docker', 'exec', container, 'ip', 'rule', 'show').decode().strip().splitlines()
    expected = {0: 'local', 32766: 'main', 32767: 'default'}
    for rule in rules:
        match = re.fullmatch(r'\s*(\d+):\s+from all lookup (local|main|default)\s*', rule)
        if not match or expected.pop(int(match.group(1)), None) != match.group(2):
            raise ValueError('unsupported_namespace_ip_rule')
    if expected:
        raise ValueError('incomplete_namespace_ip_rules')
    allowed_filter = {normalize(rule, iface) for rule in standard_filter(iface, network)}
    allowed_filter.add(normalize('-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT', iface))
    allowed_filter |= {normalize(f'-A FORWARD -i {iface} -o {eth} -j ACCEPT', iface) for eth in ('eth0', 'eth1')}
    allowed_nat = {normalize(f'-A POSTROUTING -s {network} -o {eth} -j MASQUERADE', iface) for eth in ('eth0', 'eth1')}
    allowed_nat |= {normalize(f'-A POSTROUTING -o {eth} -j MASQUERADE', iface) for eth in ('eth0', 'eth1')}
    for port, host in ((17864, '172.29.172.253'), (17865, '172.29.172.252'), (17866, '172.29.172.251')):
        allowed_nat.add(normalize(f'-A PREROUTING -d {host}/32 -i {iface} -p tcp -m tcp --dport {port} -j REDIRECT --to-ports {port}', iface))
    snapshot = {'mtu': effective_mtu, 'filter': [], 'nat': [], 'egress': {}, 'dockerDns': False}
    for table in ('raw', 'mangle'):
        for line in run('docker', 'exec', container, 'iptables', '-t', table, '-S').decode().splitlines():
            if not line.startswith('-P ') or line.split()[-1] != 'ACCEPT':
                raise ValueError('unsupported_namespace_firewall')
    for table, allowed in (('filter', allowed_filter), ('nat', allowed_nat)):
        raw = run('docker', 'exec', container, 'iptables', '-t', table, '-S').decode().splitlines()
        if table == 'nat':
            raw, snapshot['dockerDns'] = docker_dns_rules(raw)
        for line in raw:
            if line.startswith('-P '):
                if line.split()[-1] != 'ACCEPT':
                    raise ValueError('unsupported_namespace_default_policy')
                continue
            tokens = shlex.split(line)
            if '--comment' in tokens and tokens[tokens.index('--comment') + 1] in owned_comments:
                if '18082' in tokens:
                    continue
            normalized = normalize(line, iface)
            if normalized not in allowed:
                raise ValueError('unsupported_namespace_firewall')
            snapshot[table].append(normalized)
        snapshot[table].sort()
    routes = []
    for line in run('docker', 'exec', container, 'ip', 'route', 'show', 'table', 'main').decode().splitlines():
        tokens = shlex.split(line)
        if len(tokens) == 5 and tokens[:2] == ['default', 'via'] and tokens[3] == 'dev' and tokens[4] in ('eth0', 'eth1'):
            gateway = str(ipaddress.IPv4Address(tokens[2]))
            routes.append('default via ' + gateway + ' dev ' + tokens[4])
        elif len(tokens) == 9 and tokens[1] == 'dev' and tokens[3:7] == ['proto', 'kernel', 'scope', 'link'] and tokens[7] == 'src':
            route_network = str(ipaddress.IPv4Network(tokens[0]))
            ipaddress.IPv4Address(tokens[8])
            if tokens[2] not in (iface, 'eth0', 'eth1') or (tokens[2] == iface and route_network != network):
                raise ValueError('unsupported_namespace_route')
            routes.append(route_network + ' dev ' + ('awg0' if tokens[2] == iface else tokens[2]))
        else:
            raise ValueError('unsupported_namespace_route')
    snapshot['routes'] = sorted(routes)
    for address in ('1.1.1.1', '8.8.8.8', '172.29.172.254', '172.29.172.253'):
        route = run('docker', 'exec', container, 'ip', 'route', 'get', address).decode()
        match = re.search(r'\bdev (eth[01])\b', route)
        if not match:
            raise ValueError('unsupported_namespace_egress')
        snapshot['egress'][address] = match.group(1)
    return snapshot


def firewall_script(snapshot):
    commands = []
    for table in ('filter', 'nat'):
        commands += ['iptables -t ' + table + ' ' + rule for rule in snapshot[table]]
    return '\n'.join(commands) + '\n'


def client_policy_epoch():
    directory = Path('/opt/amnezia/server-routing-rules')
    if not directory.exists():
        return None
    path = directory / 'rules.json'
    if not path.exists():
        raise ValueError('managed_client_policy_not_ready')
    value = json.loads(path.read_text())
    policy = value.get('policy', {})
    if type(policy.get('revision')) is not int or not re.fullmatch(r'sha256:[a-f0-9]{64}', policy.get('contentSha256', '')):
        raise ValueError('managed_client_policy_not_versioned')
    return {'revision': policy['revision'], 'contentSha256': policy['contentSha256']}
