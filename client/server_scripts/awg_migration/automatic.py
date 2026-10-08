"""Administrator-only automatic planning, executed under the preparation lock."""
import hashlib
import json
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
        journal = json.loads(transaction.read_text())
        if journal.get('phase') != 'ready':
            # prepare() owns recovery; retain this generation for its retry.
            continue
        ready.append(journal)
    if ready:
        if len(ready) != 1:
            raise ValueError('migration_journal_conflict')
        journal = ready[0]
        request = journal['request']
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
