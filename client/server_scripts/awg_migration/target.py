"""Dedicated control listener sharing only a VPN container's network namespace."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import json
import os
from pathlib import Path
import secrets
import threading
import types

# Load the exact source bytes, bypassing old timestamp-based .pyc caches.
# The private startup receipt binds the imported recipe to this PID1 lifetime.
service_source = Path('/migration/service.py').read_bytes()
target_source = Path('/migration/target.py').read_bytes()
service_module = types.ModuleType('service')
service_module.__file__ = '/migration/service.py'
exec(compile(service_source, service_module.__file__, 'exec'), service_module.__dict__)
MigrationService = service_module.MigrationService

scope = os.environ.get('AMNEZIA_MIGRATION_SCOPE', '')
if not scope:
    with open('/migration/ready.json', encoding='utf-8') as stream:
        scope = json.load(stream)['containerId']
service = MigrationService('/migration', os.environ.get('AMNEZIA_MIGRATION_ROLE', 'target'), scope)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def authenticate(self):
        client = self.headers.get('X-Amnezia-Client-Id', '')
        token = self.headers.get('X-Amnezia-Log-Token', '')
        if len(client) != 64 or not token or len(token) > 512 or not token.isascii():
            raise ValueError('authentication')
        with open('/logs/tokens.tsv', encoding='utf-8') as stream:
            for line in stream:
                parts = line.rstrip('\n').split('\t')
                if len(parts) >= 2 and parts[0] == client and secrets.compare_digest(parts[1], token):
                    return client
        raise ValueError('authentication')

    def do_POST(self):
        self.connection.settimeout(10)
        if not service.dispatch(self, self.authenticate):
            self.send_error(404)


class Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 16

    def __init__(self, *args):
        self.slots = threading.BoundedSemaphore(16)
        super().__init__(*args)

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()

    def verify_request(self, request, address):
        # Only mapped VPN peer IPs; external bridge/loopback requests fail closed.
        try:
            with open('/migration/ready.json', encoding='utf-8') as stream:
                state = json.load(stream)
            field = 'sourceIp' if service.role == 'source' else 'targetIp'
            return address[0] in {peer[field] for peer in state['peers'].values()}
        except (OSError, ValueError, KeyError):
            return False


server = Server(('0.0.0.0', 18082), Handler)
role = service.role
receipt = {'role': role, 'processStart': Path('/proc/self/stat').read_text().split()[21],
           'hashes': {'service.py': hashlib.sha256(service_source).hexdigest(),
                      'target.py': hashlib.sha256(target_source).hexdigest()}}
path = Path('/migration/control-loaded-' + role + '.json')
temporary = path.with_suffix('.tmp')
with open(temporary, 'w', encoding='utf-8') as stream:
    os.fchmod(stream.fileno(), 0o600)
    json.dump(receipt, stream, sort_keys=True)
    stream.flush()
    os.fsync(stream.fileno())
os.replace(temporary, path)
server.serve_forever()
