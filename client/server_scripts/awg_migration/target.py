"""Dedicated control listener sharing only a VPN container's network namespace."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import json
import os
import secrets
import threading
from service import MigrationService

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


Server(('0.0.0.0', 18082), Handler).serve_forever()
