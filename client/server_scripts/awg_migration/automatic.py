"""Administrator-only automatic planning, executed under the preparation lock."""
import hashlib
import json
import os
import stat
import re
import socket


def occupied_udp_ports(run):
    # Docker NAT publications need not have a userspace listener in ss.
    ports = set()
    for line in run('ss', '-H', '-uan').decode().splitlines():
        columns = line.split()
        if len(columns) < 5:
            raise ValueError('udp_inventory_unavailable')
        endpoint = columns[4] if columns[0] in ('udp', 'udp6') else columns[3]
        port = endpoint.rsplit(':', 1)[-1]
        if port.isdecimal():
            ports.add(int(port))
    identities = run('docker', 'ps', '-q').decode().split()
    if identities:
        for container in json.loads(run('docker', 'inspect', *identities)):
            for protocol, bindings in (container.get('NetworkSettings', {}).get('Ports') or {}).items():
                if protocol.endswith('/udp'):
                    for binding in bindings or []:
                        ports.add(int(binding['HostPort']))
    return ports


def select_port(occupied, source_port):
    # A stable preference prevents new allocations on every poll/retry.
    for port in range(51821, 65536):
        if port != source_port and port not in occupied:
            return port
    raise ValueError('migration_udp_port_unavailable')



MAX_JOURNAL_BYTES = 1024 * 1024


def _read_transaction(path):
    """Read one stable regular journal without following links or opening FIFOs."""
    descriptor = None
    try:
        before_path = path.lstat()
        if not stat.S_ISREG(before_path.st_mode) or before_path.st_size > MAX_JOURNAL_BYTES:
            raise ValueError('migration_journal_conflict')
        flags = os.O_RDONLY | getattr(os, 'O_CLOEXEC', 0)
        flags |= getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_size > MAX_JOURNAL_BYTES
                or (before.st_dev, before.st_ino) != (before_path.st_dev, before_path.st_ino)):
            raise ValueError('migration_journal_conflict')
        chunks, count = [], 0
        while True:
            block = os.read(descriptor, min(65536, MAX_JOURNAL_BYTES + 1 - count))
            if not block:
                break
            chunks.append(block)
            count += len(block)
            if count > MAX_JOURNAL_BYTES:
                raise ValueError('migration_journal_conflict')
        after = os.fstat(descriptor)
        after_path = path.lstat()
        def signature(value):
            return (value.st_dev, value.st_ino, value.st_mode, value.st_size,
                    value.st_mtime_ns, value.st_ctime_ns)
        if (signature(before) != signature(after) or signature(after) != signature(after_path)
                or count != after.st_size):
            raise ValueError('migration_journal_conflict')
        def unique_object(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError('migration_journal_conflict')
                result[key] = value
            return result
        def invalid_constant(_):
            raise ValueError('migration_journal_conflict')
        journal = json.loads(b''.join(chunks).decode('utf-8'),
                             object_pairs_hook=unique_object, parse_constant=invalid_constant)
        if not isinstance(journal, dict):
            raise ValueError('migration_journal_conflict')
        return journal
    except (OSError, UnicodeError, ValueError):
        raise ValueError('migration_journal_conflict') from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def plan(root, source, host, image, raw, source_port, occupied):
    if ':' in host or not re.fullmatch(r'[A-Za-z0-9.-]{1,253}', host):
        raise ValueError('migration_endpoint_unsupported')
    scope = root / source
    existing = sorted((p for p in scope.iterdir() if p.is_dir() and p.name.isdecimal()),
                      key=lambda p: int(p.name)) if scope.exists() else []
    ready = []
    for directory in existing:
        transaction = directory / 'transaction.json'
        if not transaction.exists():
            raise ValueError('migration_journal_conflict')
        journal = _read_transaction(transaction)
        if journal.get('phase') != 'ready':
            # prepare() owns recovery; retain this generation for its retry.
            continue
        ready.append((directory, journal))
    if ready:
        if len(ready) != 1:
            raise ValueError('migration_journal_conflict')
        directory, journal = ready[0]
        request = journal['request']
        generation = request.get('generation')
        if (type(generation) is not int or not 1 <= generation <= 9007199254740991
                or directory.name != str(generation)):
            raise ValueError('migration_journal_conflict')
        if (request['image'] != image or request['host'] != host
                or journal['sourceDigest'] != hashlib.sha256(raw).hexdigest()):
            # Never create another endpoint or rotate identity silently.
            raise ValueError('migration_ready_drift')
        return dict(request)
    # Automatic rollout starts generation 1 only; never silently rotate offers.
    generation = 1
    if len(existing) > 1 or (existing and existing[0].name != '1'):
        raise ValueError('migration_journal_conflict')
    return {'host': host, 'image': image, 'port': select_port(occupied, source_port), 'generation': generation}


def verify_port_available(port):
    # Best-effort last check; Docker's atomic publish handles a subsequent race.
    sockets = []
    try:
        for family, address in ((socket.AF_INET, '0.0.0.0'), (socket.AF_INET6, '::')):
            sock = socket.socket(family, socket.SOCK_DGRAM)
            sockets.append(sock)
            if family == socket.AF_INET6:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            sock.bind((address, port))
    except OSError as error:
        raise ValueError('migration_udp_port_unavailable') from error
    finally:
        for sock in sockets:
            sock.close()
