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
import selectors
import signal
import shutil
import stat
import struct
import subprocess
import tempfile
import time
from journal import Journal, inspect as inspect_container, CONTROL_LISTENER_PROBE, CONTROL_FILES, digest
from policy import namespace_snapshot, firewall_script, client_policy_epoch, mtu
from ready_validation import PARAMS, KEY, parse_config, validate_ready_target

ROOT = Path('/opt/amnezia/awg-migration')
COLLECTOR_ROOT = Path('/opt/amnezia/client-logs')


def run(*args, input=None):
    return subprocess.run(args, input=input, check=True, capture_output=True, timeout=180).stdout



def load_native_feed(args):
    """Capture authenticated static ELF before any prepare/recovery mutation."""
    path = getattr(args, 'native_feed', '')
    expected = getattr(args, 'native_feed_sha256', '')
    if not path and not expected:
        return None
    if not path or not re.fullmatch('[a-f0-9]{64}', expected):
        raise ValueError('native_feed_invalid')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != 0
                or stat.S_IMODE(info.st_mode) != 0o755 or not 64 <= info.st_size <= 32 * 1024 ** 2):
            raise ValueError('native_feed_invalid')
        chunks, remaining = [], info.st_size
        while remaining:
            chunk = os.read(fd, min(remaining, 128 * 1024))
            if not chunk:
                raise ValueError('native_feed_invalid')
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b''.join(chunks)
        after = os.fstat(fd)
        if (os.read(fd, 1) or (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                or hashlib.sha256(raw).hexdigest() != expected):
            raise ValueError('native_feed_invalid')
    finally:
        os.close(fd)
    # Native delivery is static ELF64/LE, never the host's dynamic loader.
    machine = {'x86_64': 62, 'aarch64': 183}.get(os.uname().machine)
    if (raw[:7] != b'\x7fELF\x02\x01\x01' or machine is None
            or struct.unpack_from('<H', raw, 18)[0] != machine
            or struct.unpack_from('<H', raw, 16)[0] != 2):
        raise ValueError('native_feed_invalid')
    offset = struct.unpack_from('<Q', raw, 32)[0]
    size, count = struct.unpack_from('<HH', raw, 54)
    if (size != 56 or not 1 <= count <= 128 or offset < 64 or offset + size * count > len(raw)
            or raw[7] not in (0, 3) or raw[8] != 0 or struct.unpack_from('<I', raw, 20)[0] != 1
            or struct.unpack_from('<H', raw, 52)[0] != 64):
        raise ValueError('native_feed_invalid')
    entry = struct.unpack_from('<Q', raw, 24)[0]
    executable_entry = False
    page = 65536 if machine == 183 else 4096
    for i in range(count):
        kind, flags, file_offset, address, _, file_size, memory_size, alignment = struct.unpack_from(
            '<IIQQQQQQ', raw, offset + i * size)
        if kind in (2, 3) or file_offset + file_size > len(raw) or file_size > memory_size:
            raise ValueError('native_feed_invalid')
        if kind == 1:
            if (address + memory_size > 0xffffffffffffffff or file_offset % page != address % page
                    or (alignment > 1 and (alignment & (alignment - 1)
                        or file_offset % alignment != address % alignment))):
                raise ValueError('native_feed_invalid')
            if flags & 1 and address <= entry < address + file_size:
                executable_entry = True
    if not executable_entry:
        raise ValueError('native_feed_invalid')
    return raw


class NativePolicy:
    """Run the exact captured ELF through an immutable anonymous executable."""
    def __init__(self, raw):
        self.raw = raw

    def request(self, op, **values):
        payload = json.dumps(dict(op=op, **values), separators=(',', ':')).encode()
        allowed = {'unsupported_namespace_hook', 'unsupported_namespace_firewall',
                   'unsupported_namespace_ip_rule', 'unsupported_namespace_default_policy',
                   'unsupported_namespace_egress', 'unsupported_mtu', 'source_mtu_drift',
                   'source_mtu_unobserved', 'incomplete_namespace_ip_rules',
                   'unsupported_namespace_route', 'managed_client_policy_not_ready',
                   'managed_client_policy_not_versioned', 'policy_source_untrusted'}
        return self._invoke(payload, '--policy-json', 1024 ** 2,
                            'native_policy_rejected', allowed)

    def _invoke(self, payload, mode, output_limit, failure, allowed, input_limit=1024 ** 2, deadline_seconds=45):
        if (not isinstance(payload, bytes) or len(payload) > input_limit
                or type(deadline_seconds) is not int or deadline_seconds not in (45, 330)
                or (deadline_seconds == 330 and mode != '--trusted-image-json')):
            raise ValueError(failure)
        fd = os.memfd_create('amnezia-native', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        try:
            with os.fdopen(os.dup(fd), 'wb') as stream:
                stream.write(self.raw)
                stream.flush()
            os.fchmod(fd, 0o500)
            seals = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS, seals)
            if fcntl.fcntl(fd, fcntl.F_GET_SEALS) != seals:
                raise ValueError(failure)
            with tempfile.TemporaryFile() as request:
                request.write(payload)
                request.seek(0)
                process = subprocess.Popen(['/proc/self/fd/' + str(fd), mode],
                    stdin=request, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    pass_fds=(fd,), start_new_session=True,
                    env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
                output = bytearray()
                stderr_size = 0
                deadline = time.monotonic() + deadline_seconds
                try:
                    with selectors.DefaultSelector() as ready:
                        ready.register(process.stdout, selectors.EVENT_READ)
                        ready.register(process.stderr, selectors.EVENT_READ)
                        while ready.get_map():
                            remaining = deadline - time.monotonic()
                            if remaining <= 0:
                                raise ValueError(failure)
                            for key, events in ready.select(min(remaining, 0.1)):
                                chunk = os.read(key.fileobj.fileno(), 16384)
                                if not chunk:
                                    ready.unregister(key.fileobj)
                                elif key.fileobj is process.stdout:
                                    output.extend(chunk)
                                    if len(output) > output_limit:
                                        raise ValueError(failure)
                                else:
                                    stderr_size += len(chunk)
                                    if stderr_size > 65536:
                                        raise ValueError(failure)
                    process.wait(timeout=max(0.001, deadline - time.monotonic()))
                    response = json.loads(output)
                except BaseException:
                    # Own isolated helper and its read-only Docker children only.
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait()
                    raise
                finally:
                    process.stdout.close()
                    process.stderr.close()
            if isinstance(response, dict) and set(response) == {'error'} and process.returncode == 2:
                error = response['error']
                raise ValueError(error if isinstance(error, str) and error in allowed else failure)
            if process.returncode or not isinstance(response, dict) or set(response) != {'result'}:
                raise ValueError(failure)
            return response['result']
        except (OSError, subprocess.SubprocessError, json.JSONDecodeError, UnicodeDecodeError):
            raise ValueError(failure) from None
        finally:
            os.close(fd)

    def source_config(self, runner, source):
        # Fixed read-only C++ observer; caller's legacy runner is never used.
        failure = 'native_source_config_rejected'
        if type(source) is not str or source not in ('amnezia-awg', 'amnezia-awg2'):
            raise ValueError(failure)
        payload = json.dumps({'op': 'read', 'source': source}, separators=(',', ':')).encode()
        value = self._invoke(payload, '--source-config-json', 8 * 1024 ** 2,
                             failure, {failure}, input_limit=8192)
        if not isinstance(value, dict) or set(value) != {'raw'} or not isinstance(value['raw'], str):
            raise ValueError(failure)
        try:
            raw = value['raw'].encode('utf8')
        except UnicodeError:
            raise ValueError(failure) from None
        if not raw or len(raw) > 1024 ** 2:
            raise ValueError(failure)
        return raw

    def policy_epoch_capability(self):
        failure = 'native_policy_epoch_rejected'
        value = self._invoke(b'', '--policy-epoch-capability', 4096,
                             failure, {failure}, input_limit=0)
        if (not isinstance(value, dict) or set(value) != {'policyEpochVersion'}
                or type(value['policyEpochVersion']) is not int or value['policyEpochVersion'] != 1):
            raise ValueError(failure)

    def source_config_capability(self):
        failure = 'native_source_config_rejected'
        value = self._invoke(b'{"op":"capability"}', '--source-config-json', 8 * 1024 ** 2,
                             failure, {failure}, input_limit=8192)
        if (not isinstance(value, dict) or set(value) != {'sourceConfigVersion'}
                or type(value['sourceConfigVersion']) is not int or value['sourceConfigVersion'] != 1):
            raise ValueError(failure)

    def network_topology(self, runner, source, binding=None):
        # Native observers use only fixed read-only commands in bounded C++.
        # The legacy runner is retained in the callable signature, never used.
        failure = 'unsupported_source_network_topology'
        payload = json.dumps({'op': 'snapshot', 'container': source}, separators=(',', ':')).encode()
        result = self._invoke(payload, '--network-json', 16384, failure,
                              {failure}, input_limit=8 * 1024 ** 2)
        if (not isinstance(result, dict) or set(result) != {'options', 'binding'}
                or not isinstance(result['options'], list) or not isinstance(result['binding'], dict)
                or set(result['binding']) not in ({'bridge'}, {'bridge', 'amnezia-dns-net'})):
            raise ValueError(failure)
        names = sorted(result['binding'])
        interfaces, network_ids, defaults, expected_options = set(), set(), 0, []
        for name in names:
            role = result['binding'][name]
            if (not isinstance(role, dict) or set(role) != {'networkId', 'interface', 'default'}
                    or not isinstance(role['networkId'], str) or not role['networkId']
                    or len(role['networkId']) > 1024 or '\0' in role['networkId']
                    or role['interface'] not in ('eth0', 'eth1') or type(role['default']) is not bool
                    or role['interface'] in interfaces or role['networkId'] in network_ids):
                raise ValueError(failure)
            interfaces.add(role['interface'])
            network_ids.add(role['networkId'])
            defaults += int(role['default'])
            expected_options.extend(['--network',
                f"name={name},driver-opt=com.docker.network.endpoint.ifname={role['interface']},gw-priority={int(role['default'])}"])
        if (interfaces != ({'eth0'} if len(names) == 1 else {'eth0', 'eth1'})
                or defaults != 1 or result['options'] != expected_options):
            raise ValueError(failure)
        if binding is not None:
            binding.update(result['binding'])
        return result['options']

    def verify_stopped_networks(self, runner, identity, binding):
        failure = 'unsupported_source_network_topology'
        if (not isinstance(binding, dict)
                or set(binding) not in ({'bridge'}, {'bridge', 'amnezia-dns-net'})):
            raise ValueError(failure)
        payload = json.dumps({'op': 'stopped-snapshot', 'identity': identity,
                              'binding': binding}, separators=(',', ':')).encode()
        result = self._invoke(payload, '--network-json', 16384, failure,
                              {failure}, input_limit=8 * 1024 ** 2)
        if result is not True:
            raise ValueError(failure)

    def network_capability(self):
        failure = 'unsupported_source_network_topology'
        value = self._invoke(b'{"op":"capability"}', '--network-json', 16384,
                             failure, {failure}, input_limit=8 * 1024 ** 2)
        if (not isinstance(value, dict) or set(value) != {'observerVersion'}
                or type(value['observerVersion']) is not int or value['observerVersion'] != 1):
            raise ValueError(failure)

    def control_capability(self):
        payload = json.dumps({'role': 'target', 'scope': 'amnezia-awg',
            'path': '/native-control-capability', 'peerAddress': '127.0.0.1',
            'body': '{}', 'headers': {'content-length': '2'},
            'authenticatedClient': None}, separators=(',', ':')).encode()
        value = self._invoke(payload, '--control-json', 4096,
                             'native_control_rejected', set(), input_limit=256 * 1024)
        if (not isinstance(value, dict)
                or value != {'handled': False, 'status': 403, 'body': '', 'authenticate': False}
                or type(value.get('handled')) is not bool
                or type(value.get('authenticate')) is not bool
                or type(value.get('status')) is not int):
            raise ValueError('native_control_rejected')


    def parse_config(self, raw):
        # Raw config travels only over private stdin/stdout of the captured helper.
        # JSON escaping may require six output bytes per input byte.
        allowed = {'invalid UTF-8', 'missing field', 'configuration address',
                   'configuration syntax', 'duplicate interface',
                   'duplicate configuration key', 'missing identity',
                   'unknown interface key', 'only IPv4 isolation supported',
                   'unsupported peer field', 'peer identity', 'PSK',
                   'ambiguous peer route', 'duplicate peer address'}
        value = self._invoke(raw, '--config-json', 8 * 1024 ** 2,
                             'native_config_rejected', allowed)
        if (not isinstance(value, dict) or set(value) != {'interface', 'peers'}
                or not isinstance(value['interface'], dict)
                or not isinstance(value['peers'], list) or not value['peers']):
            raise ValueError('native_config_rejected')
        for fields in [value['interface'], *value['peers']]:
            if (not isinstance(fields, dict)
                    or any(not isinstance(k, str) or not isinstance(v, str)
                           for k, v in fields.items())):
                raise ValueError('native_config_rejected')
        return value['interface'], value['peers']


    def server_key_capability(self):
        failure = 'native_generation_rejected'
        value = self._invoke(b'{"op":"server-key-capability"}', '--generate-config-json', 4096,
                             failure, set(), input_limit=8 * 1024 ** 2)
        if (not isinstance(value, dict) or set(value) != {'serverKeyVersion'}
                or type(value['serverKeyVersion']) is not int or value['serverKeyVersion'] != 1):
            raise ValueError(failure)

    def server_public_key(self, raw):
        failure = 'native_generation_rejected'
        if not isinstance(raw, bytes) or len(raw) > 1024 ** 2:
            raise ValueError(failure)
        try:
            payload = json.dumps({'op':'server-key','source':raw.decode('utf8')}, separators=(',', ':')).encode()
        except (UnicodeError, TypeError, ValueError):
            raise ValueError(failure) from None
        value = self._invoke(payload, '--generate-config-json', 4096, failure, set(), input_limit=8 * 1024 ** 2)
        if not isinstance(value, str) or not KEY.fullmatch(value):
            raise ValueError(failure)
        return value

    def peer_mapping_capability(self):
        failure = 'native_generation_rejected'
        value = self._invoke(b'{"op":"capability"}', '--generate-config-json', 4096,
                             failure, set(), input_limit=8 * 1024 ** 2)
        if (not isinstance(value, dict) or set(value) != {'peerMappingVersion'}
                or type(value['peerMappingVersion']) is not int or value['peerMappingVersion'] != 1):
            raise ValueError(failure)

    def peer_mapping(self, raw, scope):
        failure = 'native_generation_rejected'
        if not isinstance(raw, bytes) or len(raw) > 1024 ** 2 or scope not in ('amnezia-awg', 'amnezia-awg2'):
            raise ValueError(failure)
        try:
            payload = json.dumps({'op': 'peer-mapping', 'scope': scope, 'source': raw.decode('utf8')},
                                 separators=(',', ':')).encode()
        except (UnicodeError, TypeError, ValueError):
            raise ValueError(failure) from None
        value = self._invoke(payload, '--generate-config-json', 16 * 1024 ** 2 + 1,
                             failure, set(), input_limit=8 * 1024 ** 2)
        if (not isinstance(value, dict) or not value
                or any(not isinstance(key, str) or not KEY.fullmatch(key)
                       or not isinstance(item, dict)
                       or set(item) != {'sourceIp', 'targetIp', 'clientAddress', 'clientId'}
                       or any(not isinstance(v, str) for v in item.values())
                       or item['sourceIp'] != item['targetIp']
                       or not re.fullmatch('[a-f0-9]{64}', item['clientId'])
                       for key, item in value.items())):
            raise ValueError(failure)
        return value

    def generate_config(self, raw, port, mtu):
        failure = 'native_generation_rejected'
        if (not isinstance(raw, bytes) or len(raw) > 1024 ** 2
                or type(port) is not int or not 1024 <= port <= 65535
                or type(mtu) is not int or not 576 <= mtu <= 9000):
            raise ValueError(failure)
        try:
            payload = json.dumps({'source': raw.decode('utf8'), 'port': port, 'mtu': mtu},
                                 separators=(',', ':')).encode()
        except (UnicodeError, ValueError, TypeError):
            raise ValueError(failure) from None
        value = self._invoke(payload, '--generate-config-json', 16 * 1024 ** 2 + 1,
                             failure, set(), input_limit=8 * 1024 ** 2)
        if (not isinstance(value, dict)
                or set(value) != {'parameters', 'interface', 'config', 'nativeConfig'}):
            raise ValueError(failure)
        parameters, interface = value['parameters'], value['interface']
        if (not isinstance(parameters, dict) or set(parameters) != set(PARAMS)
                or not isinstance(interface, dict)
                or set(interface) != set(PARAMS) | {'PrivateKey', 'Address', 'ListenPort', 'MTU'}
                or any(not isinstance(v, str) for v in parameters.values())
                or any(not isinstance(v, str) for v in interface.values())
                or any(interface[k] != v for k, v in parameters.items())
                or interface['ListenPort'] != str(port) or interface['MTU'] != str(mtu)):
            raise ValueError(failure)
        try:
            key = parameters['HeaderProtectionKey']
            decoded = base64.b64decode(key, validate=True)
            if len(decoded) != 32 or base64.b64encode(decoded).decode() != key:
                raise ValueError(failure)
            for field in ('config', 'nativeConfig'):
                if not isinstance(value[field], str) or not 0 < len(value[field].encode('utf8')) <= 1024 ** 2:
                    raise ValueError(failure)
        except (UnicodeError, ValueError):
            raise ValueError(failure) from None
        return parameters, interface, value['config'], value['nativeConfig']


    def ready_target(self, source, target, ready, expected, automatic):
        if (not isinstance(source, bytes) or not isinstance(target, bytes)
                or len(source) > 1024 ** 2 or len(target) > 1024 ** 2):
            raise ValueError('native_ready_rejected')
        try:
            payload = json.dumps({'source': source.decode('utf8'), 'target': target.decode('utf8'),
                                  'ready': ready, 'expected': expected, 'automatic': automatic},
                                 separators=(',', ':')).encode()
        except (UnicodeError, TypeError, ValueError):
            raise ValueError('native_ready_rejected') from None
        result = self._invoke(payload, '--ready-json', 4096, 'native_ready_rejected',
                              {'migration_ready_drift', 'native_ready_not_observed',
                               'native_ready_identity_drift'}, input_limit=16 * 1024 ** 2)
        if result is not True:
            raise ValueError('native_ready_rejected')


    def resolve_trusted_image(self, ignored_runner):
        from trusted_image import IMAGE
        # Only the fixed native catalog may choose the image or operation budgets.
        # Pull can take180s; info/inspect/probes share the remaining bounded budget.
        result = self._invoke(b'{"op":"resolve"}', '--trusted-image-json', 4096,
            'native_trusted_image_rejected', {'unsupported_server_architecture',
            'image_fetch_unavailable', 'trusted_image_unavailable'},
            input_limit=4096, deadline_seconds=330)
        if not isinstance(result, str) or result != IMAGE:
            raise ValueError('native_trusted_image_rejected')
        return result


    def automatic_request(self, op, output_limit=4096, **values):
        try:
            payload = json.dumps(dict(op=op, **values), separators=(',', ':')).encode()
        except (UnicodeError, TypeError, ValueError):
            raise ValueError('native_automatic_rejected') from None
        allowed = {'udp_inventory_unavailable', 'migration_udp_port_unavailable',
                   'migration_endpoint_unsupported', 'migration_journal_conflict',
                   'migration_ready_drift'}
        return self._invoke(payload, '--automatic-json', output_limit,
                            'native_automatic_rejected', allowed, input_limit=8 * 1024 ** 2)

    def occupied_udp_ports(self, ignored_runner):
        ports = self.automatic_request('inventory', output_limit=1024 ** 2)
        if (not isinstance(ports, list)
                or any(type(port) is not int or not 0 <= port <= 65535 for port in ports)
                or ports != sorted(set(ports))):
            raise ValueError('native_automatic_rejected')
        return set(ports)

    def plan_automatic(self, root, source, host, image, raw, source_port, occupied):
        if not isinstance(raw, bytes) or len(raw) > 1024 ** 2:
            raise ValueError('native_automatic_rejected')
        try:
            source_config = raw.decode('utf8')
        except UnicodeError:
            raise ValueError('native_automatic_rejected') from None
        request = self.automatic_request('plan', root=str(root), source=source,
            host=host, image=image, raw=source_config, sourcePort=source_port,
            occupied=sorted(occupied))
        if (not isinstance(request, dict) or set(request) != {'host', 'image', 'port', 'generation'}
                or request['host'] != host or request['image'] != image
                or type(request['port']) is not int or not 1024 <= request['port'] <= 65535
                or type(request['generation']) is not int
                or not 1 <= request['generation'] <= 9007199254740991):
            raise ValueError('native_automatic_rejected')
        return request

    def verify_automatic_port(self, port):
        if self.automatic_request('verify-port', port=port) is not True:
            raise ValueError('native_automatic_rejected')


    def snapshot(self, ignored_runner, container, interface, iface, owned_comments=()):
        return self.request('snapshot', container=container,
                            interface={key: value for key, value in interface.items()
                                       if key in ('Address', 'MTU', 'PostUp', 'PostDown')},
                            iface=iface, ownedComments=list(owned_comments))

    def firewall(self, snapshot):
        return self.request('firewall', snapshot=snapshot)

    def epoch(self):
        return self.request('epoch')

    def mtu(self, value):
        return self.request('mtu', value=str(value))


def legacy_source_config(run, source):
    path = '/opt/amnezia/awg/' + ('wg0.conf' if source == 'amnezia-awg' else 'awg0.conf')
    return run('docker', 'exec', source, 'cat', path)


def source_config_function(raw):
    return legacy_source_config if raw is None else NativePolicy(raw).source_config


def config_function(raw):
    # No bundle keeps legacy behavior; explicit native errors never fall back.
    return parse_config if raw is None else NativePolicy(raw).parse_config


def candidate_identity(journal, target):
    # Journal.owned already checks the recorded ID, image, name and owner label.
    observed = journal.owned(target)
    try:
        pin = {'id': observed['Id'], 'name': observed['Name'], 'image': observed['Image'],
               'owner': journal.value['owner'], 'startedAt': observed['State']['StartedAt']}
        valid = (observed['State']['Running'] is True
                 and re.fullmatch('[a-f0-9]{64}', pin['id'])
                 and re.fullmatch('/amnezia-awg2?-migration-[1-9][0-9]{0,15}', pin['name'])
                 and pin['name'] == '/' + target
                 and re.fullmatch('sha256:[a-f0-9]{64}', pin['image'])
                 and re.fullmatch('[a-f0-9]{32}', pin['owner'])
                 and isinstance(pin['startedAt'], str) and 0 < len(pin['startedAt']) <= 128
                 and '\0' not in pin['startedAt'])
    except (KeyError, TypeError, AttributeError):
        valid = False
    if not valid:
        raise ValueError('candidate_target_identity_changed')
    return pin


def candidate_readiness(run, journal, ready, source_raw, target_raw, native_feed, automatic):
    target = ready['targetContainer']
    pin = candidate_identity(journal, target)
    pinned_ready = dict(ready, targetContainer=pin['id'])
    if native_feed is None:
        source_interface, source_peers = parse_config(source_raw)
        target_interface, target_peers = parse_config(target_raw)
    else:
        native = NativePolicy(native_feed)

    def check():
        if native_feed is None:
            if candidate_identity(journal, target) != pin:
                raise ValueError('candidate_target_identity_changed')
            try:
                validate_ready_target(run, pinned_ready, source_interface, source_peers,
                                      target_interface, target_peers, automatic)
            except UnicodeDecodeError:
                raise ValueError('migration_ready_drift') from None
            if candidate_identity(journal, target) != pin:
                raise ValueError('candidate_target_identity_changed')
        else:
            # Native checks the original ID/owner/image/epoch before and after
            # observation itself, with bounded read-only process IO.
            native.ready_target(source_raw, target_raw, pinned_ready, pin, automatic)

    return check, pin


def wait_candidate_ready(check):
    # A pending bounded helper call may finish after this scheduling deadline.
    deadline = time.monotonic() + 60
    for attempt in range(20):
        if time.monotonic() >= deadline:
            break
        try:
            check()
            return
        except ValueError as error:
            if str(error) not in ('migration_ready_drift', 'native_ready_not_observed'):
                raise
        except subprocess.SubprocessError:
            pass
        remaining = deadline - time.monotonic()
        if attempt < 19 and remaining > 0:
            time.sleep(min(1, remaining))
    raise ValueError('AWG3 readiness failed')


def image_function(raw):
    if raw is None:
        from trusted_image import resolve_image
        return resolve_image
    return NativePolicy(raw).resolve_trusted_image


def automatic_functions(raw):
    # Native selection uses the captured helper for all planner/inventory/probe
    # operations. Trusted image resolution and the transaction journal are separate.
    if raw is None:
        from automatic import occupied_udp_ports, plan, verify_port_available
        return occupied_udp_ports, plan, verify_port_available
    native = NativePolicy(raw)
    return native.occupied_udp_ports, native.plan_automatic, native.verify_automatic_port


def policy_functions(raw):
    if raw is None:
        return namespace_snapshot, firewall_script, client_policy_epoch, mtu
    native = NativePolicy(raw)
    return native.snapshot, native.firewall, native.epoch, native.mtu


def install_native_feed(directory, raw):
    if raw is None:
        return None
    destination = directory / 'awg-feed'
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o700)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fchmod(stream.fileno(), 0o755)
        os.fsync(stream.fileno())
    return destination


def start_feed(run, journal, directory, target, owner, image, image_id, ports, native_path=None):
    """One authoritative journal entry and namespace for either explicit recipe."""
    name = target + '-feeds'
    mounts = ['-v', '/opt/amnezia/server-routing-rules:/routing:ro',
              '-v', '/opt/amnezia/client-updates:/updates:ro']
    if native_path is None:
        from feeds import feed_mounts
        mounts = feed_mounts(directory)
        entry = ['--entrypoint', 'python', image, '/app/feeds.py']
    else:
        mounts = ['-v', str(native_path) + ':/app/awg-feed:ro', *mounts]
        entry = ['--entrypoint', '/app/awg-feed', image, '--serve']
    journal.plan(name, image_id)
    run('docker', 'run', '-d', '--name', name, '--log-driver', 'none', '--restart', 'unless-stopped',
        '--label', 'amnezia.migration.owner=' + owner, '--network', 'container:' + target,
        '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
        '-e', 'AMNEZIA_FEED_PORTS=' + ','.join(ports), *mounts, *entry)
    journal.record(name)


def control_loaded_probe(role, expected_hashes, native_sha256=None):
    if native_sha256 is None:
        return CONTROL_LISTENER_PROBE
    if (role not in ('source', 'target') or not isinstance(expected_hashes, dict)
            or set(expected_hashes) != set(CONTROL_FILES)
            or any(not isinstance(value, str) or not re.fullmatch('[a-f0-9]{64}', value)
                   for value in expected_hashes.values())
            or not isinstance(native_sha256, str)
            or not re.fullmatch('[a-f0-9]{64}', native_sha256)):
        raise ValueError('native_control_rejected')
    # The receipt is bound to this actual PID1, the loaded source pair and the
    # immutable executable descriptor retained by that same process.
    return CONTROL_LISTENER_PROBE + "; import fcntl,hashlib,json,stat; " + (
        'r=json.loads(pathlib.Path("/migration/control-loaded-' + role + '.json").read_text()); '
        'assert r["role"]==' + repr(role) + '; '
        'assert r["hashes"]==' + repr(expected_hashes) + '; '
        'assert r["processStart"]==pathlib.Path("/proc/1/stat").read_text().split()[21]; '
        'n=r["nativeControl"]; '
        'assert type(n) is dict and set(n)=={"sha256","fd","protocol"}; '
        'assert n["sha256"]==' + repr(native_sha256) + ' and n["protocol"]=="control-json-v1"; '
        'assert type(n["fd"]) is int and 2<n["fd"]<1048576; '
        'p=pathlib.Path("/proc/1/fd/"+str(n["fd"])); '
        'required=fcntl.F_SEAL_SEAL|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_GROW|fcntl.F_SEAL_WRITE\n'
        'with p.open("rb") as executable:\n'
        ' info=os.fstat(executable.fileno())\n'
        ' assert stat.S_ISREG(info.st_mode) and 64<=info.st_size<=32*1024**2\n'
        ' assert fcntl.fcntl(executable.fileno(),fcntl.F_GET_SEALS)==required\n'
        ' assert hashlib.file_digest(executable,"sha256").hexdigest()==' + repr(native_sha256))


def check_feed(run, name, port, expected, native):
    kind, path = ('routing', '/rules.json') if port == '17864' else ('updates', '/manifest.json')
    if native:
        run('docker', 'exec', name, '/app/awg-feed', '--check-feed', kind, port, expected)
        return True
    probe = ('import hashlib,urllib.request; print(hashlib.sha256(urllib.request.urlopen('
             '"http://127.0.0.1:' + port + path + '",timeout=5).read()).hexdigest())')
    return run('docker', 'exec', name, 'python', '-c', probe).decode().strip() == expected


def source_network_options(run, source, binding=None, native=None):
    if native is not None:
        return NativePolicy(native).network_topology(run, source, binding)
    return legacy_source_network_options(run, source, binding)


def network_function(native):
    return source_network_options if native is None else NativePolicy(native).network_topology


def legacy_source_network_options(run, source, binding=None):
    """Clone only observed bridge endpoint roles; never rename the source."""
    version = run('docker', 'version', '--format', '{{.Server.Version}}').decode().strip()
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9_.-]+)?', version) or int(version.split('.')[0]) < 28:
        raise ValueError('unsupported_source_network_topology')
    containers = json.loads(run('docker', 'inspect', source))
    if len(containers) != 1:
        raise ValueError('unsupported_source_network_topology')
    endpoints = containers[0].get('NetworkSettings', {}).get('Networks', {})
    if set(endpoints) not in ({'bridge'}, {'bridge', 'amnezia-dns-net'}):
        raise ValueError('unsupported_source_network_topology')
    addresses = json.loads(run('docker', 'exec', source, 'ip', '-j', '-4', 'address', 'show'))
    routes = json.loads(run('docker', 'exec', source, 'ip', '-j', '-4', 'route', 'show', 'default'))
    if len(routes) != 1 or routes[0].get('dst') != 'default' or routes[0].get('dev') not in ('eth0', 'eth1'):
        raise ValueError('unsupported_source_network_topology')
    options, interfaces, network_ids, default_count = [], set(), set(), 0
    for name in sorted(endpoints):
        endpoint = endpoints[name]
        network = json.loads(run('docker', 'network', 'inspect', name))
        if len(network) != 1:
            raise ValueError('unsupported_source_network_topology')
        network = network[0]
        configs = network.get('IPAM', {}).get('Config', [])
        if (network.get('Name') != name or network.get('Driver') != 'bridge'
                or network.get('Scope') != 'local' or network.get('Internal')
                or network.get('EnableIPv6') or len(configs) != 1
                or not endpoint.get('NetworkID') or endpoint['NetworkID'] != network.get('Id')
                or endpoint['NetworkID'] in network_ids):
            raise ValueError('unsupported_source_network_topology')
        network_ids.add(endpoint['NetworkID'])
        subnet = ipaddress.IPv4Network(configs[0]['Subnet'])
        address = ipaddress.IPv4Address(endpoint['IPAddress'])
        gateway = ipaddress.IPv4Address(endpoint['Gateway'])
        if (address not in subnet or gateway not in subnet or address == gateway
                or str(gateway) != configs[0].get('Gateway')
                or endpoint.get('IPPrefixLen') != subnet.prefixlen):
            raise ValueError('unsupported_source_network_topology')
        matches = [row['ifname'] for row in addresses
                   if any(item.get('family') == 'inet' and item.get('local') == str(address)
                          and item.get('prefixlen') == subnet.prefixlen for item in row.get('addr_info', []))]
        if len(matches) != 1 or matches[0] not in ('eth0', 'eth1') or matches[0] in interfaces:
            raise ValueError('unsupported_source_network_topology')
        iface = matches[0]
        interfaces.add(iface)
        default = routes[0].get('dev') == iface
        if default and routes[0].get('gateway') != str(gateway):
            raise ValueError('unsupported_source_network_topology')
        default_count += int(default)
        if binding is not None:
            binding[name] = {'networkId': endpoint['NetworkID'], 'interface': iface, 'default': default}
        options.extend(['--network', f'name={name},driver-opt=com.docker.network.endpoint.ifname={iface},gw-priority={int(default)}'])
    expected_interfaces = {'eth0'} if len(endpoints) == 1 else {'eth0', 'eth1'}
    if interfaces != expected_interfaces or default_count != 1:
        raise ValueError('unsupported_source_network_topology')
    return options


def verify_stopped_target_networks(run, identity, binding, native=None):
    if native is not None:
        return NativePolicy(native).verify_stopped_networks(run, identity, binding)
    return legacy_verify_stopped_target_networks(run, identity, binding)


def legacy_verify_stopped_target_networks(run, identity, binding):
    observed = json.loads(run('docker', 'inspect', identity))
    endpoints = observed[0].get('NetworkSettings', {}).get('Networks', {}) if len(observed) == 1 else {}
    state = observed[0].get('State', {}) if len(observed) == 1 else {}
    if (set(endpoints) != set(binding)
            or observed[0].get('Id') != identity or state.get('Status') != 'created'
            or state.get('Pid') != 0 or state.get('Running')
            or state.get('StartedAt') != '0001-01-01T00:00:00Z'
            or observed[0].get('HostConfig', {}).get('NetworkMode') != 'bridge'):
        raise ValueError('unsupported_source_network_topology')
    for name, role in binding.items():
        endpoint = endpoints[name]
        global_network = json.loads(run('docker', 'network', 'inspect', name))
        if (len(global_network) != 1 or global_network[0].get('Id') != role['networkId']
                or endpoint.get('DriverOpts') != {'com.docker.network.endpoint.ifname': role['interface']}
                or endpoint.get('GwPriority') != int(role['default'])
                or endpoint.get('NetworkID') not in ('', role['networkId'])
                or any(endpoint.get(field) for field in ('EndpointID', 'IPAddress', 'Gateway', 'GlobalIPv6Address', 'IPv6Gateway'))):
            raise ValueError('unsupported_source_network_topology')


def start_target_networks(run, journal, target, source, binding, native=None):
    read_network = network_function(native)
    # The mixed default/user-defined bridge combination cannot be passed to
    # docker create together. Attach while stopped, after recording owned ID.
    journal.record(target)
    identity = journal.value['containers'][target]['id']
    if 'amnezia-dns-net' in binding:
        role = binding['amnezia-dns-net']
        run('docker', 'network', 'connect', '--driver-opt',
            'com.docker.network.endpoint.ifname=' + role['interface'],
            '--gw-priority', str(int(role['default'])), 'amnezia-dns-net', identity)
    current_binding = {}
    read_network(run, source, current_binding)
    if current_binding != binding:
        raise ValueError('unsupported_source_network_topology')
    verify_stopped_target_networks(run, identity, binding, native)
    run('docker', 'start', identity)
    # start.sh waits for an owned approval file: no engine/config/firewall yet.
    current_binding, live_binding = {}, {}
    read_network(run, source, current_binding)
    read_network(run, identity, live_binding)
    if current_binding != binding or live_binding != binding:
        raise ValueError('unsupported_source_network_topology')



def transient_failure_reason(error):
    if isinstance(error, (subprocess.CalledProcessError, subprocess.TimeoutExpired)):
        if isinstance(error.cmd, (list, tuple)) and list(error.cmd[:2]) in (['docker', 'pull'], ['docker', 'build']):
            return 'migration_dependency_unavailable'
    elif isinstance(error, BlockingIOError):
        return 'migration_busy'
    return None


def atomic(path, value):
    tmp = path.with_suffix('.tmp')
    with open(tmp, 'w', encoding='utf-8') as stream:
        os.fchmod(stream.fileno(), 0o600)
        json.dump(value, stream, separators=(',', ':'), sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(tmp, path)


def native_config(interface, peers):
    """Serialize only the native UAPI fields, keeping identity and peer keys."""
    # The official awg tools accept on/off or 0/1, unlike Go's UAPI booleans.
    interface = dict(interface)
    for key in ('RandomTrailers', 'DisableCookies'):
        if interface.get(key) in ('false', 'true'):
            interface[key] = '1' if interface[key] == 'true' else '0'
    text = '[Interface]\n' + ''.join(f'{key} = {value}\n' for key, value in interface.items()
                                      if key not in ('Address', 'MTU'))
    for peer in peers:
        text += '\n[Peer]\n' + ''.join(f'{key} = {value}\n' for key, value in peer.items())
    return text


def legacy_generate_config(raw, port, mtu):
    """Legacy-only serializer; explicit native selection never calls this path."""
    interface, peers = parse_config(raw)
    parameters = {'Jc': '4', 'Jmin': '10', 'Jmax': '50', 'S1': '16', 'S2': '16',
                  'S3': '16', 'S4': '16', 'H1': '1', 'H2': '2', 'H3': '3', 'H4': '4',
                  'HeaderProtectionKey': base64.b64encode(secrets.token_bytes(32)).decode(),
                  'ContentPaddingAddition': '0', 'RekeyAfterTime': '120', 'RekeyTimeout': '5',
                  'RejectAfterTime': '180', 'KeepaliveTimeout': '10',
                  'MaxHandshakeAttempts': '20', 'RandomTrailers': '0', 'DisableCookies': '0'}
    target_interface = {'PrivateKey': interface['PrivateKey'], 'Address': interface['Address'],
                        'ListenPort': str(port), 'MTU': str(mtu), **parameters}
    text = '[Interface]\n' + ''.join(f'{key} = {value}\n' for key, value in target_interface.items())
    for peer in peers:
        text += '\n[Peer]\n' + ''.join(f'{key} = {value}\n' for key, value in peer.items())
    return parameters, target_interface, text, native_config(target_interface, peers)


def generation_function(raw):
    return legacy_generate_config if raw is None else NativePolicy(raw).generate_config


def check_collector_policy_epoch(runner, collector, epoch, native_feed):
    if epoch is None:
        return
    if native_feed is not None:
        failure = 'client_policy_feed_epoch_changed'
        if (not isinstance(epoch, dict) or set(epoch) != {'revision', 'contentSha256'}
                or type(epoch['revision']) is not int or not 1 <= epoch['revision'] <= 9007199254740991
                or not isinstance(epoch['contentSha256'], str)
                or not re.fullmatch(r'sha256:[a-f0-9]{64}', epoch['contentSha256'])):
            raise ValueError(failure)
        try:
            output = runner('docker', 'exec', collector, '/app/awg-feed', '--check-policy-epoch',
                            str(epoch['revision']), epoch['contentSha256'])
        except (OSError, subprocess.SubprocessError):
            raise ValueError(failure) from None
        if output != b'':
            raise ValueError(failure)
        return
    probe_epoch = 'import json,urllib.request; p=json.load(urllib.request.urlopen("http://172.29.172.253:17864/rules.json",timeout=5))["policy"]; print(json.dumps({k:p[k] for k in ("revision","contentSha256")}))'
    if json.loads(runner('docker', 'exec', collector, 'python', '-c', probe_epoch)) != epoch:
        raise ValueError('client_policy_feed_epoch_changed')


def prepare(args):
    if os.geteuid() != 0 or args.source not in ('amnezia-awg', 'amnezia-awg2'):
        raise ValueError('administrator/source required')
    native_feed = load_native_feed(args)
    if native_feed is not None:
        NativePolicy(native_feed).control_capability()
        NativePolicy(native_feed).network_capability()
        NativePolicy(native_feed).source_config_capability()
        NativePolicy(native_feed).policy_epoch_capability()
        NativePolicy(native_feed).peer_mapping_capability()
        NativePolicy(native_feed).server_key_capability()
    parse_configuration = config_function(native_feed)
    read_source_config = source_config_function(native_feed)
    read_network = network_function(native_feed)
    snapshot_policy, firewall_policy, epoch_policy, mtu_policy = policy_functions(native_feed)
    if getattr(args, 'automatic', False):
        occupied_udp_ports, plan, verify_port_available = automatic_functions(native_feed)
        resolve_image = image_function(native_feed)
        raw = read_source_config(run, args.source)
        interface, _ = parse_configuration(raw)
        comments = [json.loads(path.read_text())['owner']
                    for path in (ROOT / args.source).glob('*/transaction.json')]
        snapshot_policy(run, args.source, interface, 'wg0' if args.source == 'amnezia-awg' else 'awg0', comments)
        epoch_policy()
        image = resolve_image(run)
        request = plan(ROOT, args.source, args.host, image, raw, int(interface['ListenPort']), occupied_udp_ports(run))
        args.image, args.port, args.generation = request['image'], request['port'], request['generation']
    if not re.fullmatch(r'[a-zA-Z0-9./:_-]+@sha256:[a-f0-9]{64}', args.image):
        raise ValueError('AWG3 immutable image required')
    if not re.fullmatch(r'[A-Za-z0-9.-]{1,253}', args.host) or not 1024 <= args.port <= 65535 or not 1 <= args.generation <= 9007199254740991:
        raise ValueError('request')
    raw = read_source_config(run, args.source)
    interface, peers = parse_configuration(raw)
    source_iface = 'wg0' if args.source == 'amnezia-awg' else 'awg0'
    if native_feed is not None and (ROOT / args.source / str(args.generation) / 'transaction.json').exists():
        # Explicit native selection never silently recovers, migrates recipes or
        # reports native success for an existing un-attested feed generation.
        raise ValueError('native_feed_existing_generation_requires_maintenance')
    owned_comments = []
    source_root = ROOT / args.source
    if source_root.exists():
        # Recover incomplete phases before generation or listener collision checks.
        for journal_path in sorted(source_root.glob('*/transaction.json')):
            journal = Journal(journal_path.parent, run)
            if journal.value.get('nativeFeedSha256') is not None:
                raise ValueError('native_feed_existing_generation_requires_maintenance')
            if journal.value['phase'] != 'ready':
                journal.cleanup()
                shutil.rmtree(journal_path.parent)
            else:
                owned_comments.append(journal.value['owner'])
    snapshot = snapshot_policy(run, args.source, interface, source_iface, owned_comments)
    network_binding = {}
    network_options = read_network(run, args.source, network_binding)
    epoch = epoch_policy()
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
            # An interrupted control refresh remains a ready VPN generation;
            # rollback its code before ordinary reuse, never generic cleanup.
            journal.recover_control_maintenance()
            state = json.loads((directory / 'ready.json').read_text())
            target_identity = journal.value['containers'][state['targetContainer']]['id']
            observed = inspect_container(run, target_identity)
            endpoints = observed.get('NetworkSettings', {}).get('Networks', {}) if observed else {}
            if (state.get('networkBinding') != network_binding or set(endpoints) != set(network_binding)
                    or any(endpoints[name].get('NetworkID') != role['networkId'] for name, role in network_binding.items())):
                raise ValueError('unsupported_source_network_topology')
            if not observed['State']['Running']:
                approval = directory / 'network-approved'
                approval.unlink(missing_ok=True)
                run('docker', 'start', target_identity)
                resumed_binding, current_source_binding = {}, {}
                read_network(run, target_identity, resumed_binding)
                read_network(run, args.source, current_source_binding)
                if resumed_binding != network_binding or current_source_binding != network_binding:
                    raise ValueError('unsupported_source_network_topology')
                atomic(approval, {'approved': True})
            else:
                running_binding = {}
                read_network(run, target_identity, running_binding)
                if running_binding != network_binding:
                    raise ValueError('unsupported_source_network_topology')
            journal.recover_ready()
            target_binding = {}
            read_network(run, state['targetContainer'], target_binding)
            if state.get('networkBinding') != network_binding or target_binding != network_binding:
                raise ValueError('unsupported_source_network_topology')
            target_interface, target_peers = parse_configuration((directory / 'awg0.conf').read_bytes())
            if snapshot_policy(run, state['targetContainer'], target_interface, 'awg0', [journal.value['owner']]) != snapshot:
                raise ValueError('ready_namespace_policy_or_mtu_changed')
            validate_ready_target(run, state, interface, peers, target_interface, target_peers,
                                  getattr(args, 'automatic', False))
            journal.maintain_controls(Path(__file__).parent)
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
        if inspect_container(run, name) is not None:
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
            'nativeFeedSha256': args.native_feed_sha256 if native_feed is not None else None,
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
        if native_feed is not None:
            server_key = NativePolicy(native_feed).server_public_key(raw)
        else:
            server_key = run('docker', 'exec', '-i', args.source,
                             'sh', '-c', 'command -v awg >/dev/null && awg pubkey || wg pubkey',
                             input=(interface['PrivateKey'] + '\n').encode()).decode().strip()
            if not KEY.fullmatch(server_key):
                raise ValueError('server key')
        parameters, target_interface, text, native_text = generation_function(native_feed)(
            raw, args.port, snapshot['mtu'])
        if (target_interface['PrivateKey'] != interface['PrivateKey']
                or target_interface['Address'] != interface['Address']):
            raise ValueError('native_generation_rejected')
        (directory / 'awg0.conf').write_text(text, encoding='utf8')
        os.chmod(directory / 'awg0.conf', 0o600)
        if getattr(args, 'automatic', False):
            (directory / 'awg0.native.conf').write_text(native_text, encoding='utf8')
            os.chmod(directory / 'awg0.native.conf', 0o600)
        shutil.copyfile(Path(__file__).with_name('service.py'), directory / 'service.py')
        shutil.copyfile(Path(__file__).with_name('target.py'), directory / 'target.py')
        shutil.copyfile(Path(__file__).with_name('policy.py'), directory / 'policy.py')
        if native_feed is None:
            shutil.copyfile(Path(__file__).with_name('feeds.py'), directory / 'feeds.py')
        native_feed_path = install_native_feed(directory, native_feed)
        # Reproduce the validated source namespace rules, not arbitrary shell hooks.
        startup = 'awg-quick up /migration/awg0.conf\n'
        if getattr(args, 'automatic', False):
            from trusted_image import BINARY_SHA256
            address = str(ipaddress.IPv4Interface(interface['Address']))
            startup = (
                f'test "$(sha256sum /usr/bin/amneziawg-go | cut -d " " -f 1)" = {BINARY_SHA256}\n'
                '/usr/bin/amneziawg-go -f awg0 >/dev/null 2>&1 &\n'
                'engine=$!\nprintf "%s\\n" "$engine" > /migration/engine.pid\n'
                'trap "kill $engine 2>/dev/null || true" EXIT INT TERM\n'
                'attempt=0\nwhile ! awg show awg0 >/dev/null 2>&1; do\n'
                '  kill -0 "$engine"\n  attempt=$((attempt + 1))\n  test "$attempt" -lt 20\n  sleep 1\ndone\n'
                'awg setconf awg0 /migration/awg0.native.conf\n'
                f'ip address add {address} dev awg0\n'
                f'ip link set dev awg0 mtu {snapshot["mtu"]} up\n')
        approval = directory / 'network-approved'
        approval.unlink(missing_ok=True)
        network_barrier = 'attempt=0\nwhile ! test -f /migration/network-approved; do\n  attempt=$((attempt + 1))\n  test "$attempt" -lt 60\n  sleep 1\ndone\n'
        (directory / 'start.sh').write_text('#!/bin/sh\nset -eu\n' + network_barrier + startup + firewall_policy(snapshot) +
                f'iptables -I INPUT 1 -p tcp --dport 18082 -m comment --comment {ownership} -j REJECT\n' +
                f'iptables -I INPUT 1 -i awg0 -p tcp --dport 18082 -m comment --comment {ownership} -j ACCEPT\n' +
                f'iptables -t nat -A PREROUTING -i awg0 -d 172.29.172.251/32 -p tcp --dport 18082 -m comment --comment {ownership} -j REDIRECT --to-ports 18082\n' +
                ('while :; do kill -0 "$engine"; awg show awg0 latest-handshakes > /migration/handshakes.tsv.tmp; mv /migration/handshakes.tsv.tmp /migration/handshakes.tsv; sleep 2; done\n'
                 if getattr(args, 'automatic', False) else
                 'while :; do awg show awg0 latest-handshakes > /migration/handshakes.tsv.tmp; mv /migration/handshakes.tsv.tmp /migration/handshakes.tsv; sleep 2; done\n'))
        if not getattr(args, 'automatic', False):
            run('docker', 'pull', args.image)
        target_image_id = run('docker', 'image', 'inspect', '--format', '{{.Id}}', args.image).decode().strip()
        journal.plan(target, target_image_id)
        if getattr(args, 'automatic', False):
            if args.port in occupied_udp_ports(run):
                raise ValueError('migration_udp_port_unavailable')
            verify_port_available(args.port)
        run('docker', 'create', '--name', target, '--label', 'amnezia.migration.scope=' + scope,
            '--label', 'amnezia.migration.owner=' + ownership,
            '--label', 'amnezia.migration.generation=' + str(args.generation), '--cap-add', 'NET_ADMIN',
            '--device', '/dev/net/tun', '--sysctl', 'net.ipv4.ip_forward=1', '--restart', 'unless-stopped',
            '--log-driver', 'none', '-p', f'{args.port}:{args.port}/udp', '-v', str(directory) + ':/migration:rw',
            '--network', next(network_options[n + 1] for n in range(0, len(network_options), 2)
                              if network_options[n + 1].startswith('name=bridge,')),
            '--entrypoint', 'sh', args.image, '/migration/start.sh')
        start_target_networks(run, journal, target, args.source, network_binding, native_feed)
        atomic(approval, {'approved': True})
        check_candidate_ready, pinned_target = candidate_readiness(
            run, journal, {'targetContainer': target, 'serverPublicKey': server_key,
                           'parameters': parameters}, raw, text.encode(), native_feed,
            getattr(args, 'automatic', False))
        wait_candidate_ready(check_candidate_ready)
        current_binding, target_binding = {}, {}
        read_network(run, args.source, current_binding)
        read_network(run, target, target_binding)
        if current_binding != network_binding or target_binding != network_binding:
            raise ValueError('unsupported_source_network_topology')
        target_snapshot = snapshot_policy(run, target, target_interface, 'awg0', [ownership])
        if target_snapshot != snapshot:
            raise ValueError('effective_namespace_policy_or_mtu_changed')
        if native_feed is not None:
            mapping = NativePolicy(native_feed).peer_mapping(raw, scope)
        else:
            mapping = {peer['PublicKey']: {'sourceIp': str(ipaddress.ip_interface(peer['AllowedIPs']).ip),
                       'targetIp': str(ipaddress.ip_interface(peer['AllowedIPs']).ip), 'clientAddress': peer['AllowedIPs'],
                       'clientId': hashlib.sha256((scope + '\t' + peer['PublicKey']).encode()).hexdigest()} for peer in peers}
        state = {'networkBinding': network_binding, 'schema': 1, 'serverPublicKey': server_key, 'containerId': scope, 'generation': args.generation,
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
            start_feed(run, journal, directory, target, ownership, log_image, log_image_id,
                       feed_ports, native_feed_path)
            for port in feed_ports:
                feed_file = Path('/opt/amnezia/server-routing-rules/rules.json') if port == '17864' else Path('/opt/amnezia/client-updates/manifest.json')
                expected_feed_hash = hashlib.sha256(feed_file.read_bytes()).hexdigest()
                for attempt in range(10):
                    try:
                        if check_feed(run, target + '-feeds', port, expected_feed_hash, native_feed is not None):
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
        control_mounts = [] if native_feed_path is None else [
            '-v', str(native_feed_path) + ':/app/awg-feed:ro',
            '-e', 'AMNEZIA_CONTROL_NATIVE_SHA256=' + args.native_feed_sha256]
        control_hashes = {name: digest((directory / name).read_bytes()) for name in CONTROL_FILES}
        journal.plan(collector, control_image_id)
        run('docker', 'run', '-d', '--name', collector, '--log-driver', 'none', '--restart', 'unless-stopped',
            '--label', 'amnezia.migration.owner=' + ownership,
            '--network', 'container:' + target, '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
            *control_mounts, '-v', str(directory) + ':/migration:rw', '-v', str(COLLECTOR_ROOT) + ':/logs:ro',
            '--entrypoint', 'python', target + '-control-image', '/migration/target.py')
        journal.record(collector)
        # INPUT deliberately permits only VPN peers, so a loopback connection
        # would be rejected. Require the actual PID1 control listener's socket,
        # rather than weakening the namespace firewall for a health probe.
        probe = control_loaded_probe('target', control_hashes,
            args.native_feed_sha256 if native_feed is not None else None)
        for attempt in range(10):
            try:
                run('docker', 'exec', collector, 'python', '-c', probe)
                break
            except subprocess.SubprocessError:
                time.sleep(1)
        else:
            raise ValueError('candidate control listener unavailable')
        check_collector_policy_epoch(run, collector, epoch, native_feed)
        if epoch_policy() != epoch:
            raise ValueError('source_client_policy_feed_epoch_changed')
        if read_source_config(run, args.source) != raw:
            raise ValueError('source configuration changed')
        check_candidate_ready()
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
            *control_mounts, '-v', str(directory) + ':/migration:rw', '-v', str(COLLECTOR_ROOT) + ':/logs:ro',
            '--entrypoint', 'python', target + '-control-image', '/migration/target.py')
        journal.record(target + '-source-control')
        probe = control_loaded_probe('source', control_hashes,
            args.native_feed_sha256 if native_feed is not None else None)
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
        check_candidate_ready()
        journal.value['receipt'] = receipt
        journal.value['targetEpoch'] = pinned_target['startedAt']
        journal.value['controlRecipe'] = {name: digest((directory / name).read_bytes()) for name in CONTROL_FILES}
        journal.value['controlLoadedReceipt'] = True
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
    parser.add_argument('--image', default='')
    parser.add_argument('--host', required=True)
    parser.add_argument('--port', type=int, default=0)
    parser.add_argument('--generation', type=int, default=0)
    parser.add_argument('--automatic', action='store_true')
    parser.add_argument('--preflight', action='store_true')
    parser.add_argument('--native-feed', default='')
    parser.add_argument('--native-feed-sha256', default='')
    try:
        args = parser.parse_args()
        if os.geteuid() != 0 or args.source not in ('amnezia-awg', 'amnezia-awg2'):
            raise ValueError('administrator/source required')
        captured_native = load_native_feed(args)
        parse_configuration = config_function(captured_native)
        read_source_config = source_config_function(captured_native)
        read_network = network_function(captured_native)
        snapshot_policy, firewall_policy, epoch_policy, mtu_policy = policy_functions(captured_native)
        if args.preflight:
            # Preflight performs only read-only checks; no collector/VPN mutation.
            # Recovery is deliberately deferred to the actual operator prepare call.
            interface, peers = parse_configuration(read_source_config(run, args.source))
            comments = []
            for path in (ROOT / args.source).glob('*/transaction.json'):
                comments.append(json.loads(path.read_text())['owner'])
            snapshot = snapshot_policy(run, args.source, interface, 'wg0' if args.source == 'amnezia-awg' else 'awg0', comments)
            read_network(run, args.source)
            print(json.dumps({'eligible': True, 'mtu': snapshot['mtu'], 'clientPolicyEpoch': epoch_policy()}))
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
            'unsupported_namespace_route', 'unsupported_source_network_topology',
            'managed_client_policy_not_ready', 'managed_client_policy_not_versioned',
            'trusted_image_unavailable', 'image_fetch_unavailable', 'unsupported_server_architecture',
            'native_source_config_rejected', 'native_feed_invalid', 'native_feed_existing_generation_requires_maintenance',
            'migration_endpoint_unsupported', 'migration_udp_port_unavailable',
            'udp_inventory_unavailable', 'migration_journal_conflict', 'migration_ready_drift'}
        reason = str(error) if isinstance(error, ValueError) and str(error) in eligibility_reasons else 'migration_preparation_failed'
        # Unknown tool, policy, identity and Docker run failures do not retry.
        reason = transient_failure_reason(error) or reason
        print(json.dumps({'prepared': False, 'eligible': False, 'reason': reason}))
        raise SystemExit(1)
