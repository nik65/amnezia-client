"""Offline stopped-container metadata oracle/parity; no Docker/network execution.

Only the supplied owned helper is executed, once per case, in --network-json mode.
The imported legacy oracle receives a fixture-only runner that rejects any new
command shape. Strict malformed cases are separate from compatibility cases.
"""
import argparse
import copy
import hashlib
import importlib
import json
from pathlib import Path
import subprocess
import sys


sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
prepare = importlib.import_module('prepare')
ZERO_EPOCH = '0001-01-01T00:00:00Z'
INACTIVE_FIELDS = ('EndpointID', 'IPAddress', 'Gateway', 'GlobalIPv6Address', 'IPv6Gateway')
IFNAME = 'com.docker.network.endpoint.ifname'


def dumps(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'))


def rebuild(values):
    """Build otherwise consistent fixture metadata for a requested binding."""
    values['container'] = [{'Id': values['identity'],
        'State': {'Status': 'created', 'Pid': 0, 'Running': False, 'StartedAt': ZERO_EPOCH},
        'HostConfig': {'NetworkMode': 'bridge'},
        'NetworkSettings': {'Networks': {name: {'NetworkID': '',
            'DriverOpts': {IFNAME: role['interface']}, 'GwPriority': int(role['default'])}
            for name, role in values['binding'].items()}}}]
    values['networks'] = {name: [{'Id': role['networkId']}]
                          for name, role in values['binding'].items()}
    return values


def fixture(dual=False, bridge_default=False):
    if dual:
        binding = {'amnezia-dns-net': {'networkId': 'dns-id',
            'interface': 'eth1' if bridge_default else 'eth0', 'default': not bridge_default},
            'bridge': {'networkId': 'bridge-id', 'interface': 'eth0' if bridge_default else 'eth1',
                       'default': bridge_default}}
    else:
        binding = {'bridge': {'networkId': 'bridge-id', 'interface': 'eth0', 'default': True}}
    return rebuild({'identity': 'owned-created-id', 'binding': binding})


def payload(values):
    return {'op': 'stopped', 'identity': values['identity'], 'binding': values['binding'],
        'container': dumps(values['container']),
        'networks': {name: dumps(rows) for name, rows in values['networks'].items()}}


class UnexpectedOracleCommand(RuntimeError):
    pass


def legacy(request):
    function = getattr(prepare, 'legacy_verify_stopped_target_networks', None)
    if function is None:
        raise RuntimeError('legacy_verify_stopped_target_networks is not available yet')
    def runner(*args):
        if args == ('docker', 'inspect', request['identity']):
            return request['container'].encode()
        if args[:3] == ('docker', 'network', 'inspect') and len(args) == 4:
            return request['networks'][args[3]].encode()
        raise UnexpectedOracleCommand('unexpected oracle command; no external command executed')
    try:
        function(runner, request['identity'], request['binding'])
        return True
    except UnexpectedOracleCommand:
        raise
    except Exception:
        return False


def corpus():
    cases = []
    def add(name, values, category='compat'):
        cases.append((name, category, payload(values)))
    def change(name, action, dual=False, category='compat'):
        value = fixture(dual=dual);action(value);add(name, value, category)
    def endpoint(value, name='bridge'):
        return value['container'][0]['NetworkSettings']['Networks'][name]
    add('single-bridge-created', fixture())
    add('dual-dns-default', fixture(dual=True))
    add('dual-bridge-default', fixture(dual=True, bridge_default=True))
    change('binding-order-reversed', lambda v: v.__setitem__('binding', dict(reversed(list(v['binding'].items())))), dual=True)
    change('endpoint-order-reversed', lambda v: v['container'][0]['NetworkSettings'].__setitem__('Networks',
        dict(reversed(list(v['container'][0]['NetworkSettings']['Networks'].items())))), dual=True)
    change('global-map-order-reversed', lambda v: v.__setitem__('networks', dict(reversed(list(v['networks'].items())))), dual=True)
    change('all-network-ids-assigned', lambda v: [endpoint(v, name).__setitem__('NetworkID', role['networkId'])
        for name, role in v['binding'].items()], dual=True)
    change('mixed-network-ids', lambda v: endpoint(v).__setitem__('NetworkID', v['binding']['bridge']['networkId']), dual=True)
    for field in INACTIVE_FIELDS:
        for empty in (None, ''):
            change('inactive-' + field + '-' + ('null' if empty is None else 'empty'),
                lambda v, field=field, empty=empty: endpoint(v).__setitem__(field, empty))
    for empty in (None, ''):
        change('all-inactive-fields-' + ('null' if empty is None else 'empty'),
            lambda v, empty=empty: [endpoint(v, name).__setitem__(field, empty)
                for name in v['binding'] for field in INACTIVE_FIELDS], dual=True)
    def extras(v):
        v['container'][0].update(Config={'Env': ['OWNED_FIXTURE=1']}, Name='/owned-fixture')
        v['container'][0]['State'].update(ExitCode=0, Error='')
        endpoint(v).update(MacAddress='02:00:00:00:00:01', IPPrefixLen=16, Aliases=['owned-fixture'])
        v['networks']['bridge'][0].update(Name='bridge', Driver='bridge', Scope='local', Labels={})
    change('ordinary-extra-fields-ignored', extras)
    def unicode_ids(v):
        v['identity'] = 'owned-café-😀';v['binding']['bridge']['networkId'] = 'bridge-café-😀';rebuild(v)
        endpoint(v)['NetworkID'] = v['binding']['bridge']['networkId']
    change('unicode-identities', unicode_ids)
    for state in ('running', 'exited', 'paused', 'dead', 'created '):
        change('wrong-state-' + state.strip(), lambda v, state=state: v['container'][0]['State'].__setitem__('Status', state))
    for pid in (-1, 1, 100):
        change('nonzero-pid-' + str(pid), lambda v, pid=pid: v['container'][0]['State'].__setitem__('Pid', pid))
    change('running-true', lambda v: v['container'][0]['State'].__setitem__('Running', True))
    for stamp in ('2026-01-01T00:00:00Z', '0001-01-01T00:00:00.000000000Z', '', None):
        change('wrong-epoch-' + hashlib.sha256(str(stamp).encode()).hexdigest()[:8],
            lambda v, stamp=stamp: v['container'][0]['State'].__setitem__('StartedAt', stamp))
    for mode in ('host', 'none', 'default', 'container:other', ''):
        change('wrong-mode-' + mode, lambda v, mode=mode: v['container'][0]['HostConfig'].__setitem__('NetworkMode', mode))
    change('wrong-container-id', lambda v: v['container'][0].__setitem__('Id', 'foreign-id'))
    change('container-empty', lambda v: v.__setitem__('container', []))
    change('container-multiple', lambda v: v['container'].append(copy.deepcopy(v['container'][0])))
    for field in ('State', 'HostConfig', 'NetworkSettings'):
        change('missing-container-' + field, lambda v, field=field: v['container'][0].pop(field))
    change('missing-endpoint', lambda v: v['container'][0]['NetworkSettings']['Networks'].pop('bridge'))
    change('extra-endpoint', lambda v: v['container'][0]['NetworkSettings']['Networks'].__setitem__('foreign', {}))
    change('wrong-driver-interface', lambda v: endpoint(v)['DriverOpts'].__setitem__(IFNAME, 'eth1'))
    change('extra-driver-option', lambda v: endpoint(v)['DriverOpts'].__setitem__('foreign', 'option'))
    change('missing-driver-options', lambda v: endpoint(v).pop('DriverOpts'))
    for priority in (0, 2, -1):
        change('wrong-priority-' + str(priority), lambda v, priority=priority: endpoint(v).__setitem__('GwPriority', priority))
    change('foreign-endpoint-network-id', lambda v: endpoint(v).__setitem__('NetworkID', 'foreign-id'))
    change('missing-endpoint-network-id', lambda v: endpoint(v).pop('NetworkID'))
    change('null-endpoint-network-id', lambda v: endpoint(v).__setitem__('NetworkID', None))
    for field in INACTIVE_FIELDS:
        change('active-' + field, lambda v, field=field: endpoint(v).__setitem__(field,
            '2001:db8::1' if 'IPv6' in field else '192.0.2.1'))
    change('foreign-global-network-id', lambda v: v['networks']['bridge'][0].__setitem__('Id', 'foreign-id'))
    change('missing-global-network', lambda v: v['networks'].pop('bridge'))
    change('global-inspect-empty', lambda v: v['networks'].__setitem__('bridge', []))
    change('global-inspect-multiple', lambda v: v['networks']['bridge'].append(copy.deepcopy(v['networks']['bridge'][0])))
    # Type confusion / otherwise-invalid expected bindings are deliberately
    # stronger native validation, separate from compatible Docker metadata.
    for malformed in (None, 0, '', [], {}):
        change('strict-running-' + type(malformed).__name__,
            lambda v, malformed=malformed: v['container'][0]['State'].__setitem__('Running', malformed), category='strict')
    change('strict-missing-running', lambda v: v['container'][0]['State'].pop('Running'), category='strict')
    for malformed in (False, 0.0, '0'):
        change('strict-pid-' + type(malformed).__name__,
            lambda v, malformed=malformed: v['container'][0]['State'].__setitem__('Pid', malformed), category='strict')
    for malformed in (True, 1.0, '1'):
        change('strict-priority-' + type(malformed).__name__,
            lambda v, malformed=malformed: endpoint(v).__setitem__('GwPriority', malformed), category='strict')
    for field in INACTIVE_FIELDS:
        for malformed in (False, 0, [], {}):
            change('strict-inactive-' + field + '-' + type(malformed).__name__,
                lambda v, field=field, malformed=malformed: endpoint(v).__setitem__(field, malformed), category='strict')
    def changed_binding(name, action, dual=False):
        value = fixture(dual=dual);action(value);rebuild(value);add(name, value, 'strict')
    for malformed in (1, 1.0, '1'):
        changed_binding('strict-default-' + type(malformed).__name__,
            lambda v, malformed=malformed: v['binding']['bridge'].__setitem__('default', malformed))
    changed_binding('strict-defaults-zero', lambda v: [r.__setitem__('default', False) for r in v['binding'].values()], dual=True)
    changed_binding('strict-defaults-two', lambda v: [r.__setitem__('default', True) for r in v['binding'].values()], dual=True)
    changed_binding('strict-duplicate-interface', lambda v: v['binding']['bridge'].__setitem__('interface', 'eth0'), dual=True)
    changed_binding('strict-duplicate-network-id', lambda v: v['binding']['bridge'].__setitem__('networkId', 'dns-id'), dual=True)
    changed_binding('strict-unknown-interface', lambda v: v['binding']['bridge'].__setitem__('interface', 'eth2'))
    changed_binding('strict-single-eth1', lambda v: v['binding']['bridge'].__setitem__('interface', 'eth1'))
    changed_binding('strict-empty-role-id', lambda v: v['binding']['bridge'].__setitem__('networkId', ''))
    changed_binding('strict-numeric-role-id', lambda v: v['binding']['bridge'].__setitem__('networkId', 7))
    changed_binding('strict-nul-role-id', lambda v: v['binding']['bridge'].__setitem__('networkId', 'id\0suffix'))
    changed_binding('strict-dns-only', lambda v: v.__setitem__('binding', {'amnezia-dns-net': v['binding']['bridge']}))
    changed_binding('strict-foreign-name', lambda v: v.__setitem__('binding', {'foreign': v['binding']['bridge']}))
    changed_binding('strict-empty-binding', lambda v: v.__setitem__('binding', {}))
    for invalid in (None, [], {'bridge': None}, {'bridge': []}):
        change('strict-binding-shape-' + hashlib.sha256(dumps(invalid).encode()).hexdigest()[:8],
            lambda v, invalid=invalid: v.__setitem__('binding', invalid), category='strict')
    for field in ('networkId', 'interface', 'default'):
        change('strict-role-missing-' + field, lambda v, field=field: v['binding']['bridge'].pop(field), category='strict')
    change('strict-role-extra-field', lambda v: v['binding']['bridge'].__setitem__('extra', 'fixture'), category='strict')
    for identity in (7, False, '', 'id\0suffix'):
        changed_binding('strict-identity-' + hashlib.sha256(dumps(identity).encode()).hexdigest()[:8],
            lambda v, identity=identity: v.__setitem__('identity', identity))
    base = payload(fixture())
    def raw_change(name, field, value):
        request = copy.deepcopy(base);request[field] = value;cases.append((name, 'strict', request))
    raw_change('strict-duplicate-container-id', 'container', base['container'].replace('"Id":', '"Id":"foreign","Id":', 1))
    raw_change('strict-escaped-nul-key', 'container', base['container'].replace('"Id":', '"ignored\\u0000key":0,"Id":', 1))
    duplicate_global = copy.deepcopy(base['networks'])
    duplicate_global['bridge'] = duplicate_global['bridge'].replace('"Id":', '"Id":"foreign","Id":', 1)
    raw_change('strict-duplicate-global-id', 'networks', duplicate_global)
    for value in ('NaN', 'Infinity', '-Infinity'):
        raw_change('strict-nonfinite-' + value, 'container', base['container'].replace('"Id":', '"ignored":'+value+',"Id":', 1))
    for field in ('container', 'networks'):
        for wrong in (None, [], True, 7):
            raw_change('strict-outer-' + field + '-' + type(wrong).__name__, field, wrong)
    extras = copy.deepcopy(base['networks']);extras['foreign'] = '[]'
    raw_change('strict-extra-global-map', 'networks', extras)
    deep = 0
    for depth in range(34):
        deep = {'nested': deep}
    container = fixture()['container'];container[0]['ignored'] = deep
    raw_change('strict-depth-limit', 'container', dumps(container))
    raw_change('strict-inner-lone-surrogate', 'container', base['container'].replace('"Id":', '"ignored":"\\ud800","Id":', 1))
    request = copy.deepcopy(base);request['extra'] = 'fixture';cases.append(('strict-extra-outer-key', 'strict', request))
    duplicate_outer = dumps(base).replace('"op":"stopped"', '"op":"stopped","op":"stopped"', 1).encode()
    cases.extend([('strict-duplicate-outer-op', 'strict', duplicate_outer),
        ('strict-invalid-outer-utf8', 'strict', b'{"op":"stopped","identity":"\xff"}'),
        ('strict-outer-lone-surrogate', 'strict', b'{"op":"stopped","identity":"\\ud800"}'),
        ('strict-raw-outer-nul', 'strict', b'{"op":"stopped","identity":"\0"}')])
    return cases


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('binary', help='owned standalone helper, never product app')
    parser.add_argument('--result', type=Path)
    args = parser.parse_args()
    if not callable(getattr(prepare, 'legacy_verify_stopped_target_networks', None)):
        raise RuntimeError('imported stopped metadata oracle not available')
    rows = []
    for name, category, request in corpus():
        raw = request if isinstance(request, bytes) else dumps(request).encode()
        expected = legacy(request) if isinstance(request, dict) else None
        process = subprocess.run([args.binary, '--network-json'], input=raw,
                                 capture_output=True, timeout=12)
        try:
            result = json.loads(process.stdout)
        except Exception:
            raise AssertionError(name + ': native result is not JSON') from None
        assert process.stderr == b'', name + ': native wrote private stderr'
        rejected = process.returncode == 2 and result == {'error': 'unsupported_source_network_topology'}
        if category == 'strict' or not expected:
            assert rejected, name + ': malformed/mismatched metadata not rejected with fixed error'
        else:
            assert process.returncode == 0 and isinstance(result, dict) and set(result) == {'result'} and result['result'] is True, name + ': native/legacy acceptance mismatch'
        rows.append({'case': name, 'category': category, 'legacy_accepted': expected,
            'native_accepted': process.returncode == 0, 'input_sha256': hashlib.sha256(raw).hexdigest()})
    summary = {'cases': len(rows), 'compatibility_cases': sum(r['category'] == 'compat' for r in rows),
        'strict_malformed_cases': sum(r['category'] == 'strict' for r in rows),
        'legacy_accepted': sum(r['legacy_accepted'] is True for r in rows),
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
