"""Offline topology contract corpus: fake-runner legacy versus native private CLI.

Every native case starts the supplied standalone helper once. The oracle can only
return fixture bytes; it never executes Docker, sockets, or production commands.
Malformed-input tightening is reported separately from ordinary compatibility.
"""
import argparse
import copy
import hashlib
import importlib
import ipaddress
import json
from pathlib import Path
import subprocess
import sys


sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
prepare = importlib.import_module('prepare')


def dumps(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'))


def fixture(single=False, bridge_default=False):
    endpoints, addresses, networks = {}, [], {}
    roles = [('bridge', 'eth0', '172.17.0.0/16', '172.17.0.2', '172.17.0.1')] if single else [
        ('amnezia-dns-net', 'eth1' if bridge_default else 'eth0', '172.29.172.0/24', '172.29.172.2', '172.29.172.1'),
        ('bridge', 'eth0' if bridge_default else 'eth1', '172.17.0.0/16', '172.17.0.2', '172.17.0.1')]
    gateway = None
    for name, iface, subnet, address, gw in roles:
        prefix = ipaddress.IPv4Network(subnet).prefixlen
        endpoints[name] = {'NetworkID': name + '-id', 'IPAddress': address,
                           'Gateway': gw, 'IPPrefixLen': prefix}
        addresses.append({'ifname': iface, 'addr_info': [
            {'family': 'inet', 'local': address, 'prefixlen': prefix}]})
        networks[name] = [{'Name': name, 'Id': name + '-id', 'Driver': 'bridge',
            'Scope': 'local', 'Internal': False, 'EnableIPv6': False,
            'IPAM': {'Config': [{'Subnet': subnet, 'Gateway': gw}]}}]
        if iface == 'eth0':
            gateway = gw
    return {'version': '29.0.0', 'container': [{'NetworkSettings': {'Networks': endpoints}}],
            'addresses': addresses, 'routes': [{'dst': 'default', 'dev': 'eth0', 'gateway': gateway}],
            'networks': networks}


def request(values):
    return {'op': 'validate', 'version': values['version'],
            'container': dumps(values['container']), 'addresses': dumps(values['addresses']),
            'routes': dumps(values['routes']),
            'networks': {name: dumps(rows) for name, rows in values['networks'].items()}}


class UnexpectedOracleCommand(RuntimeError):
    pass


def legacy(payload):
    def run(*args):
        if args == ('docker', 'version', '--format', '{{.Server.Version}}'):
            return payload['version'].encode()
        if args == ('docker', 'inspect', 'fixture-source'):
            return payload['container'].encode()
        if args == ('docker', 'exec', 'fixture-source', 'ip', '-j', '-4', 'address', 'show'):
            return payload['addresses'].encode()
        if args == ('docker', 'exec', 'fixture-source', 'ip', '-j', '-4', 'route', 'show', 'default'):
            return payload['routes'].encode()
        if args[:3] == ('docker', 'network', 'inspect') and len(args) == 4:
            return payload['networks'][args[3]].encode()
        raise UnexpectedOracleCommand('oracle attempted an unrecognized command')
    try:
        binding = {}
        function = getattr(prepare, 'legacy_source_network_options', None) or prepare.source_network_options
        options = function(run, 'fixture-source', binding)
        return {'options': options, 'binding': binding}
    except UnexpectedOracleCommand:
        raise
    except Exception:
        return None


def legacy_names(container):
    # This is the exact discovery-only subset of the imported full validator:
    # discovery intentionally has no Docker version/address/route input.
    try:
        rows = json.loads(container)
        if len(rows) != 1:
            return None
        endpoints = rows[0].get('NetworkSettings', {}).get('Networks', {})
        if set(endpoints) not in ({'bridge'}, {'bridge', 'amnezia-dns-net'}):
            return None
        return sorted(endpoints)
    except Exception:
        return None


def corpus():
    cases = []
    def add(name, values, category='compat'):
        cases.append((name, category, request(values)))
    def change(name, action, single=False, category='compat'):
        values = fixture(single=single)
        action(values)
        add(name, values, category)
    add('dual-dns-default', fixture())
    add('dual-bridge-default', fixture(bridge_default=True))
    add('single-bridge', fixture(single=True))
    change('address-order-reversed', lambda v: v['addresses'].reverse())
    change('endpoint-order-reversed', lambda v: v['container'][0]['NetworkSettings'].__setitem__(
        'Networks', dict(reversed(list(v['container'][0]['NetworkSettings']['Networks'].items())))))
    change('network-map-order-reversed', lambda v: v.__setitem__('networks', dict(reversed(list(v['networks'].items())))))
    change('loopback-and-inet6-ignored', lambda v: v['addresses'].insert(0,
        {'ifname': 'lo', 'addr_info': [{'family': 'inet', 'local': '127.0.0.1', 'prefixlen': 8},
                                     {'family': 'inet6', 'local': '::1', 'prefixlen': 128}]}))
    def extras(v):
        v['container'][0].update(Config={'Env': ['OWNED_FIXTURE=1']}, State={'Running': True})
        for endpoint in v['container'][0]['NetworkSettings']['Networks'].values():
            endpoint.update(MacAddress='02:00:00:00:00:01', DNSNames=['fixture'])
        for rows in v['networks'].values():
            rows[0].update(Labels={}, Options={}, Containers={})
    change('ordinary-docker-extra-fields-ignored', extras)
    for field in ('Internal', 'EnableIPv6'):
        change('optional-absent-' + field,
            lambda v, field=field: [rows[0].pop(field) for rows in v['networks'].values()])
        change('optional-null-' + field,
            lambda v, field=field: [rows[0].__setitem__(field, None) for rows in v['networks'].values()])
    for version in ('28.0.0', '29.1.2-ce.1', '29.1.2+build_7', '028.000.000',
                    '9' * 128 + '.0.0', '27.9.9', '28.0', '28.0.0-rc+build', '28.0.0/', '', '28.0.0 extra'):
        change('version-' + hashlib.sha256(version.encode()).hexdigest()[:10],
               lambda v, version=version: v.__setitem__('version', version))
    for cp in range(0x110000):
        char = chr(cp)
        if char.isspace():
            change('version-whitespace-' + format(cp, 'x'),
                   lambda v, char=char: v.__setitem__('version', char + '29.0.0' + char))
    for subnet in ('172.17.0.0/016', '172.17.0.0/255.255.0.0', '172.17.0.0/0.0.255.255',
                   '0.0.0.0/0', '0.0.0.0/1', '0.0.0.0/127.255.255.255',
                   '128.0.0.0/1', '128.0.0.0/127.255.255.255',
                   '172.17.0.0/31', '172.17.0.0/32', '172.17.0.0',
                   '172.17.0.2/16', '172.17.0.0/255.0.255.0', ' 172.17.0.0/16', '172.17.0.0/16 '):
        def subnet_change(v, subnet=subnet):
            v['networks']['bridge'][0]['IPAM']['Config'][0]['Subnet'] = subnet
            try:
                prefix = ipaddress.IPv4Network(subnet).prefixlen
            except ValueError:
                prefix = 16
            v['container'][0]['NetworkSettings']['Networks']['bridge']['IPPrefixLen'] = prefix
            v['addresses'][0]['addr_info'][0]['prefixlen'] = prefix
        change('subnet-' + hashlib.sha256(subnet.encode()).hexdigest()[:10], subnet_change, single=True)
    def point_to_point(v):
        endpoint = v['container'][0]['NetworkSettings']['Networks']['bridge']
        endpoint.update(IPAddress='172.17.0.0', Gateway='172.17.0.1', IPPrefixLen=31)
        v['networks']['bridge'][0]['IPAM']['Config'] = [{'Subnet': '172.17.0.0/31', 'Gateway': '172.17.0.1'}]
        v['addresses'][0]['addr_info'] = [{'family': 'inet', 'local': '172.17.0.0', 'prefixlen': 31}]
    change('valid-31-endpoints', point_to_point, single=True)
    def unicode_id(v):
        v['container'][0]['NetworkSettings']['Networks']['bridge']['NetworkID'] = 'fixture-café-😀'
        v['networks']['bridge'][0]['Id'] = 'fixture-café-😀'
    change('unicode-id-preserved', unicode_id)
    invalid = {
        'extra-network': lambda v: v['container'][0]['NetworkSettings']['Networks'].__setitem__('other', {}),
        'empty-endpoints': lambda v: v['container'][0]['NetworkSettings'].__setitem__('Networks', {}),
        'container-count-zero': lambda v: v.__setitem__('container', []),
        'container-count-two': lambda v: v['container'].append(copy.deepcopy(v['container'][0])),
        'two-defaults': lambda v: v['routes'].append(copy.deepcopy(v['routes'][0])),
        'zero-defaults': lambda v: v.__setitem__('routes', []),
        'wrong-dst': lambda v: v['routes'][0].__setitem__('dst', '0.0.0.0/0'),
        'unknown-default-interface': lambda v: v['routes'][0].__setitem__('dev', 'eth2'),
        'wrong-default-gateway': lambda v: v['routes'][0].__setitem__('gateway', '172.17.0.1'),
        'duplicate-interface-address-row': lambda v: v['addresses'].append(copy.deepcopy(v['addresses'][0])),
        'same-interface-for-both': lambda v: v['addresses'][1].__setitem__('ifname', 'eth0'),
        'unknown-interface': lambda v: v['addresses'][0].__setitem__('ifname', 'eth2'),
        'wrong-driver': lambda v: v['networks']['bridge'][0].__setitem__('Driver', 'host'),
        'wrong-scope': lambda v: v['networks']['bridge'][0].__setitem__('Scope', 'swarm'),
        'internal-true': lambda v: v['networks']['bridge'][0].__setitem__('Internal', True),
        'ipv6-true': lambda v: v['networks']['bridge'][0].__setitem__('EnableIPv6', True),
        'wrong-name': lambda v: v['networks']['bridge'][0].__setitem__('Name', 'other'),
        'wrong-network-id': lambda v: v['networks']['bridge'][0].__setitem__('Id', 'other'),
        'duplicate-network-id': lambda v: (v['networks']['bridge'][0].__setitem__('Id', 'amnezia-dns-net-id'),
            v['container'][0]['NetworkSettings']['Networks']['bridge'].__setitem__('NetworkID', 'amnezia-dns-net-id')),
        'two-ipam-configs': lambda v: v['networks']['bridge'][0]['IPAM']['Config'].append(
            copy.deepcopy(v['networks']['bridge'][0]['IPAM']['Config'][0])),
        'mismatched-ipam-gateway': lambda v: v['networks']['bridge'][0]['IPAM']['Config'][0].__setitem__('Gateway', '172.17.0.3'),
        'address-is-gateway': lambda v: v['container'][0]['NetworkSettings']['Networks']['bridge'].__setitem__('IPAddress', '172.17.0.1'),
        'address-outside-subnet': lambda v: v['container'][0]['NetworkSettings']['Networks']['bridge'].__setitem__('IPAddress', '192.0.2.2'),
        'gateway-outside-subnet': lambda v: v['container'][0]['NetworkSettings']['Networks']['bridge'].__setitem__('Gateway', '192.0.2.1'),
        'address-prefix-mismatch': lambda v: v['addresses'][1]['addr_info'][0].__setitem__('prefixlen', 24),
        'endpoint-prefix-string': lambda v: v['container'][0]['NetworkSettings']['Networks']['bridge'].__setitem__('IPPrefixLen', '16'),
        'endpoint-address-whitespace': lambda v: v['container'][0]['NetworkSettings']['Networks']['bridge'].__setitem__('IPAddress', '172.17.0.2 '),
    }
    for name, action in invalid.items():
        change(name, action)
    # Discovery-only cases have their own old endpoint-subset oracle.
    for name, values in [('names-dual', fixture()), ('names-single', fixture(single=True))]:
        cases.append((name, 'compat', {'op': 'networks', 'container': dumps(values['container'])}))
    for name, value in [('names-empty', []), ('names-object', {}), ('names-null', None),
                        ('names-unknown', [{'NetworkSettings': {'Networks': {'foreign': {}}}}])]:
        cases.append((name, 'compat', {'op': 'networks', 'container': dumps(value)}))
    # Malformed values below intentionally reject legacy falsey/type-confused
    # data. Record the old outcome without demanding malformed acceptance parity.
    for field in ('Internal', 'EnableIPv6'):
        for malformed in (0, '', [], {}):
            change('strict-' + field + '-' + type(malformed).__name__,
                lambda v, field=field, malformed=malformed: v['networks']['bridge'][0].__setitem__(field, malformed),
                category='strict')
    change('strict-float-prefix', lambda v: v['container'][0]['NetworkSettings']['Networks']['bridge'].__setitem__('IPPrefixLen', 16.0), category='strict')
    def boolean_prefix(v):
        v['networks']['bridge'][0]['IPAM']['Config'][0]['Subnet'] = '0.0.0.0/0'
        v['container'][0]['NetworkSettings']['Networks']['bridge']['IPPrefixLen'] = False
        v['addresses'][0]['addr_info'][0]['prefixlen'] = False
    change('strict-boolean-prefix', boolean_prefix, single=True, category='strict')
    for field, address in (('IPAddress', '172.17.0.2'), ('Gateway', '172.17.0.1')):
        change('strict-numeric-ipv4-' + field,
            lambda v, field=field, address=address: v['container'][0]['NetworkSettings']['Networks']['bridge'].__setitem__(field, int(ipaddress.IPv4Address(address))),
            category='strict')
    def numeric_id(v):
        v['container'][0]['NetworkSettings']['Networks']['bridge']['NetworkID'] = 7
        v['networks']['bridge'][0]['Id'] = 7
    change('strict-numeric-network-id', numeric_id, category='strict')
    def nul_id(v):
        v['container'][0]['NetworkSettings']['Networks']['bridge']['NetworkID'] = 'bridge-id\0suffix'
        v['networks']['bridge'][0]['Id'] = 'bridge-id\0suffix'
    change('strict-nul-network-id', nul_id, category='strict')
    base = request(fixture())
    def raw_change(name, key, value):
        payload = copy.deepcopy(base);payload[key] = value
        cases.append((name, 'strict', payload))
    raw_change('strict-duplicate-inner-key', 'container', base['container'].replace('"NetworkSettings":', '"NetworkSettings":{},"NetworkSettings":', 1))
    raw_change('strict-escaped-nul-key', 'container', base['container'].replace('"NetworkSettings":', '"bad\\u0000key":0,"NetworkSettings":', 1))
    for value in ('NaN', 'Infinity', '-Infinity'):
        raw_change('strict-nonfinite-' + value, 'container', base['container'].replace('"NetworkSettings":', '"ignored":'+value+',"NetworkSettings":', 1))
    for key in ('container', 'addresses', 'routes'):
        for malformed in (None, [], {}, True, 7):
            raw_change('strict-outertype-' + key + '-' + type(malformed).__name__, key, malformed)
    raw_change('strict-outer-networkmap-list', 'networks', [])
    raw_change('strict-outer-version-number', 'version', 29)
    extra_network = copy.deepcopy(base['networks']);extra_network['foreign'] = '[]'
    raw_change('strict-extra-observed-network', 'networks', extra_network)
    deep = 0
    for depth in range(34):
        deep = {'nested': deep}
    deep_container = fixture()['container'];deep_container[0]['ignored'] = deep
    raw_change('strict-depth-limit', 'container', dumps(deep_container))
    raw_change('strict-inner-lone-surrogate', 'container',
        base['container'].replace('"NetworkSettings":', '"ignored":"\\ud800","NetworkSettings":', 1))
    cases += [
        ('strict-invalid-outer-utf8', 'strict', b'{"op":"networks","container":"\xff"}'),
        ('strict-outer-lone-surrogate', 'strict', b'{"op":"networks","container":"\\ud800"}'),
        ('strict-raw-outer-nul', 'strict', b'{"op":"networks","container":"\0"}'),
        ('strict-duplicate-outer-op', 'strict', b'{"op":"networks","op":"networks","container":' + dumps(dumps(fixture(single=True)['container'])).encode() + b'}'),
        ('strict-invalid-raw-container-json', 'strict', {'op': 'networks', 'container': '[private-fixture'}),
        ('strict-unknown-operation', 'strict', {'op': 'private-fixture'}),
    ]
    return cases


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('binary', help='owned standalone helper; never a product application')
    parser.add_argument('--result', type=Path)
    args = parser.parse_args()
    rows = []
    for name, category, payload in corpus():
        if isinstance(payload, bytes):
            raw = payload;expected = None
        else:
            raw = dumps(payload).encode()
            expected = legacy_names(payload['container']) if payload.get('op') == 'networks' else legacy(payload)
        process = subprocess.run([args.binary, '--network-json'], input=raw,
                                 capture_output=True, timeout=12)
        try:
            value = json.loads(process.stdout)
        except Exception:
            raise AssertionError(name + ': non-JSON native response') from None
        assert process.stderr == b'', name + ': private runtime wrote stderr'
        rejected = process.returncode == 2 and value == {'error': 'unsupported_source_network_topology'}
        if category == 'strict' or expected is None:
            assert rejected, name + ': native did not fail closed with fixed error'
        else:
            assert process.returncode == 0 and value == {'result': expected}, name + ': native/legacy result mismatch'
        rows.append({'case': name, 'category': category, 'legacy_accepted': expected is not None,
                     'native_accepted': process.returncode == 0,
                     'input_sha256': hashlib.sha256(raw).hexdigest()})
    summary = {'cases': len(rows), 'compatibility_cases': sum(r['category'] == 'compat' for r in rows),
               'strict_malformed_cases': sum(r['category'] == 'strict' for r in rows),
               'legacy_accepted': sum(r['legacy_accepted'] for r in rows),
               'native_accepted': sum(r['native_accepted'] for r in rows),
               'all_passed': True, 'actual_docker_network_calls': 0,
               'helper_sha256': hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
               'oracle_source_sha256': hashlib.sha256(Path(prepare.__file__).read_bytes()).hexdigest(),
               'case_results': rows}
    if args.result:
        args.result.parent.mkdir(parents=True, exist_ok=True)
        args.result.write_text(json.dumps(summary, indent=2), encoding='utf8')
    print(json.dumps({k: v for k, v in summary.items() if k != 'case_results'}, indent=2))


if __name__ == '__main__':
    main()
