"""Private, peer-bound AWG migration control plane; never a public update feed."""
import base64
import selectors
import signal
import struct
from contextlib import closing, contextmanager
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import sqlite3
import stat
import subprocess
import tempfile
import time

KEY = re.compile(r"^[A-Za-z0-9+/]{43}=$")
NONCE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
PARAMETERS = frozenset(('Jc', 'Jmin', 'Jmax', 'S1', 'S2', 'S3', 'S4',
                       'H1', 'H2', 'H3', 'H4', 'HeaderProtectionKey',
                       'ContentPaddingAddition', 'RekeyAfterTime', 'RekeyTimeout',
                       'RejectAfterTime', 'KeepaliveTimeout', 'MaxHandshakeAttempts',
                       'RandomTrailers', 'DisableCookies', 'I1', 'I2', 'I3', 'I4', 'I5'))


def canonical(value):
    return json.dumps(value, separators=(',', ':'), sort_keys=True).encode('utf-8')


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON field')
        result[key] = value
    return result


def signer_material(directory, public_key):
    path = os.path.join(directory, 'signing.pem')
    if os.path.islink(path):
        raise ValueError('signer ownership')
    with open(path, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode)
                or (os.name == 'posix' and (info.st_uid != os.geteuid() or info.st_mode & 0o077))):
            raise ValueError('signer ownership')
        secret = stream.read(8193)
    if not 32 <= len(secret) <= 8192:
        raise ValueError('signer material')
    observed = subprocess.run(['openssl', 'pkey', '-pubout', '-outform', 'DER'],
                              input=secret, check=True, capture_output=True, timeout=5).stdout
    if (len(observed) != 44 or observed[:12] != bytes.fromhex('302a300506032b6570032100')
            or base64.b64encode(observed[-32:]).decode() != public_key):
        raise ValueError('signer identity')
    return secret


def bootstrap_grant(secret, scope, server, peer, client, fingerprint, generation,
                    nonce, challenge, issued, expires):
    binding = canonical({'domain': 'amnezia-awg-migration-bootstrap-grant-v1',
                         'scope': scope, 'server': server, 'peer': peer, 'client': client,
                         'fingerprint': fingerprint, 'generation': generation, 'nonce': nonce,
                         'challenge': challenge, 'issued': issued, 'expires': expires})
    return base64.urlsafe_b64encode(hmac.new(secret, binding, hashlib.sha384).digest()).decode().rstrip('=')


@contextmanager
def grant_database(path):
    # sqlite's connection context controls transactions but does not close it.
    # Keep rollback/commit inside explicit lifetime ownership on every exit path.
    with closing(sqlite3.connect(path, timeout=5)) as connection:
        with connection:
            yield connection


def sign(payload, directory):
    raw = canonical(payload)
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, 'payload')
        with open(path, 'wb') as stream:
            stream.write(raw)
        signature = subprocess.run(
            ['openssl', 'pkeyutl', '-sign', '-rawin', '-inkey',
             os.path.join(directory, 'signing.pem'), '-in', path],
            check=True, capture_output=True, timeout=5).stdout
    if len(signature) != 64:
        raise ValueError('signature')
    return {'payload': base64.b64encode(raw).decode(),
            'signature': base64.b64encode(signature).decode()}


class NativeControl:
    """Private captured-helper transport; HTTP and authentication stay with PID1."""
    def __init__(self):
        self.fd, self.sha256, self.directory = -1, '', '/migration'

    @classmethod
    def capture(cls, path, expected_sha256, directory='/migration'):
        failure = 'native_control_rejected'
        if os.name != 'posix' or not hasattr(os, 'memfd_create'):
            raise ValueError(failure)
        import fcntl
        if not isinstance(expected_sha256, str) or not re.fullmatch('[a-f0-9]{64}', expected_sha256):
            raise ValueError(failure)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) != 0o755 or not 64 <= info.st_size <= 32 * 1024 ** 2):
                raise ValueError(failure)
            chunks, remaining = [], info.st_size
            while remaining:
                chunk = os.read(fd, min(remaining, 128 * 1024))
                if not chunk:
                    raise ValueError(failure)
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b''.join(chunks)
            after = os.fstat(fd)
            if (os.read(fd, 1) or (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
                    != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                    or hashlib.sha256(raw).hexdigest() != expected_sha256):
                raise ValueError(failure)
        finally:
            os.close(fd)
        machine = {'x86_64': 62, 'aarch64': 183}.get(os.uname().machine)
        if (raw[:7] != b'\x7fELF\x02\x01\x01' or machine is None
                or struct.unpack_from('<H', raw, 18)[0] != machine
                or struct.unpack_from('<H', raw, 16)[0] != 2):
            raise ValueError(failure)
        offset = struct.unpack_from('<Q', raw, 32)[0]
        size, count = struct.unpack_from('<HH', raw, 54)
        if (size != 56 or not 1 <= count <= 128 or offset < 64 or offset + size * count > len(raw)
                or raw[7] not in (0, 3) or raw[8] != 0 or struct.unpack_from('<I', raw, 20)[0] != 1
                or struct.unpack_from('<H', raw, 52)[0] != 64):
            raise ValueError(failure)
        entry = struct.unpack_from('<Q', raw, 24)[0]
        executable_entry = False
        page = 65536 if machine == 183 else 4096
        for i in range(count):
            kind, flags, file_offset, address, _, file_size, memory_size, alignment = struct.unpack_from(
                '<IIQQQQQQ', raw, offset + i * size)
            if kind in (2, 3) or file_offset + file_size > len(raw) or file_size > memory_size:
                raise ValueError(failure)
            if kind == 1:
                if (address + memory_size > 0xffffffffffffffff or file_offset % page != address % page
                        or (alignment > 1 and (alignment & (alignment - 1)
                            or file_offset % alignment != address % alignment))):
                    raise ValueError(failure)
                if flags & 1 and address <= entry < address + file_size:
                    executable_entry = True
        if not executable_entry:
            raise ValueError(failure)
        self = cls()
        self.fd = os.memfd_create('amnezia-control', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        try:
            with os.fdopen(os.dup(self.fd), 'wb') as stream:
                stream.write(raw)
                stream.flush()
            os.fchmod(self.fd, 0o500)
            seals = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE
            fcntl.fcntl(self.fd, fcntl.F_ADD_SEALS, seals)
            if fcntl.fcntl(self.fd, fcntl.F_GET_SEALS) != seals:
                raise ValueError(failure)
            self.sha256, self.directory = expected_sha256, str(directory)
            self.capability()
            return self
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def receipt(self):
        return {'sha256': self.sha256, 'fd': self.fd, 'protocol': 'control-json-v1'}

    def capability(self):
        value = self.dispatch('target', 'amnezia-awg', '/native-control-capability', '127.0.0.1',
                              {'content-length': '2'}, b'{}', lambda: None)
        if value != {'handled': False, 'status': 403, 'body': '', 'authenticate': False}:
            raise ValueError('native_control_rejected')

    def _invoke(self, request):
        failure = 'native_control_rejected'
        try:
            payload = json.dumps(request, separators=(',', ':')).encode()
            if len(payload) > 256 * 1024 or self.fd < 0:
                raise ValueError(failure)
            with tempfile.TemporaryFile() as stream:
                stream.write(payload)
                stream.seek(0)
                process = subprocess.Popen(['/proc/self/fd/' + str(self.fd), '--control-json'],
                    stdin=stream, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    pass_fds=(self.fd,), start_new_session=True, cwd=self.directory,
                    env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
                output, errors = bytearray(), 0
                deadline = time.monotonic() + 45
                try:
                    with selectors.DefaultSelector() as ready:
                        ready.register(process.stdout, selectors.EVENT_READ)
                        ready.register(process.stderr, selectors.EVENT_READ)
                        while ready.get_map():
                            remaining = deadline - time.monotonic()
                            if remaining <= 0:
                                raise ValueError(failure)
                            for key, unused in ready.select(min(remaining, 0.1)):
                                chunk = os.read(key.fileobj.fileno(), 16384)
                                if not chunk:
                                    ready.unregister(key.fileobj)
                                elif key.fileobj is process.stdout:
                                    output.extend(chunk)
                                    if len(output) > 16 * 1024 ** 2 + 1:
                                        raise ValueError(failure)
                                else:
                                    errors += len(chunk)
                                    if errors > 65536:
                                        raise ValueError(failure)
                    process.wait(timeout=max(0.001, deadline - time.monotonic()))
                    response = json.loads(output)
                except BaseException:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait()
                    raise
                finally:
                    process.stdout.close()
                    process.stderr.close()
            if process.returncode or not isinstance(response, dict) or set(response) != {'result'}:
                raise ValueError(failure)
            result = response['result']
            if (not isinstance(result, dict) or set(result) != {'handled', 'status', 'body', 'authenticate'}
                    or type(result['handled']) is not bool or type(result['authenticate']) is not bool
                    or type(result['status']) is not int or result['status'] not in (200, 403)
                    or not isinstance(result['body'], str)
                    or len(result['body'].encode('utf8')) > 8 * 1024 ** 2
                    or (result['authenticate'] and (not result['handled'] or result['status'] != 403 or result['body']))
                    or (result['status'] == 403 and result['body'])
                    or (not result['handled'] and (result['body'] or result['authenticate'] or result['status'] != 403))):
                raise ValueError(failure)
            return result
        except (OSError, subprocess.SubprocessError, UnicodeError, json.JSONDecodeError):
            raise ValueError(failure) from None

    def dispatch(self, role, scope, path, peer_address, headers, raw_body, authenticate):
        if not isinstance(raw_body, bytes) or not 0 < len(raw_body) <= 16384:
            raise ValueError('native_control_rejected')
        request = {'role': role, 'scope': scope, 'path': path, 'peerAddress': peer_address,
                   'headers': headers, 'body': raw_body.decode('utf8'), 'authenticatedClient': None}
        result = self._invoke(request)
        if result['authenticate']:
            client = authenticate()
            if client is None:
                return None
            if not isinstance(client, str) or not re.fullmatch('[a-f0-9]{64}', client):
                raise ValueError('native_control_rejected')
            request['authenticatedClient'] = client
            result = self._invoke(request)
            if result['authenticate']:
                raise ValueError('native_control_rejected')
        return result


class MigrationService:
    def __init__(self, directory, role, scope, native=None):
        self.directory, self.role, self.scope = directory, role, scope
        self.native = native

    def dispatch(self, handler, authenticate):
        if not handler.path.startswith('/migration/v1/'):
            return False
        try:
            if self.native is None:
                self.handle(handler, authenticate)
            else:
                self.handle_native(handler, authenticate)
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError,
                sqlite3.Error):
            handler.send_error(403)
        return True

    def handle_native(self, handler, authenticate):
        headers = {}
        relevant = {'content-length', 'transfer-encoding', 'x-amnezia-migration-grant'}
        for name, value in handler.headers.items():
            key = name.lower()
            if key in relevant:
                if key in headers:
                    raise ValueError('duplicate header')
                headers[key] = value
        size = int(headers.get('content-length', '-1'))
        if not 0 < size <= 16384:
            raise ValueError('body size')
        response = self.native.dispatch(self.role, self.scope, handler.path,
            handler.client_address[0], headers, handler.rfile.read(size), authenticate)
        if response is None:
            return
        if not response['handled'] or response['status'] != 200:
            handler.send_error(403)
            return
        raw = response['body'].encode('utf8')
        handler.send_response(200)
        handler.send_header('Content-Type', 'application/json')
        handler.send_header('Cache-Control', 'no-store')
        handler.send_header('Content-Length', str(len(raw)))
        handler.end_headers()
        handler.wfile.write(raw)

    def handle(self, handler, authenticate):
        if handler.headers.get('Transfer-Encoding'):
            raise ValueError('transfer encoding')
        size = int(handler.headers.get('Content-Length', '-1'))
        if not 0 < size <= 16384:
            raise ValueError('body size')
        body = json.loads(handler.rfile.read(size), object_pairs_hook=unique_object)
        if not isinstance(body, dict) or type(body.get('schema')) is not int or body['schema'] != 1:
            raise ValueError('schema')
        with open(os.path.join(self.directory, 'ready.json'), encoding='utf-8') as stream:
            state = json.load(stream)
        now = int(time.time())
        target_outbox = self.role == 'target' and handler.path in ('/migration/v1/renew', '/migration/v1/ack')
        if (state['expiresAt'] <= now and not target_outbox) or state['containerId'] != self.scope:
            raise ValueError('inactive')
        peer = body['peerPublicKey']
        if not isinstance(peer, str) or not KEY.fullmatch(peer):
            raise ValueError('peer')
        mapping = state['peers'][peer]
        source = str(ipaddress.ip_address(handler.client_address[0]))
        expected = mapping['sourceIp'] if self.role == 'source' else mapping['targetIp']
        if source != expected:
            raise ValueError('source')
        path = handler.path
        expected_fields = {
            '/migration/v1/bootstrap': {'schema', 'peerPublicKey', 'sourceFingerprint', 'nonce'},
            '/migration/v1/offer': {'schema', 'peerPublicKey', 'sourceFingerprint', 'nonce'},
            '/migration/v1/challenge': {'schema', 'peerPublicKey', 'generation', 'grant', 'nonce'},
            '/migration/v1/ack': {'schema', 'peerPublicKey', 'generation', 'grant', 'challengeReceipt'},
            '/migration/v1/renew': {'schema', 'peerPublicKey', 'generation', 'grant', 'nonce', 'challengeReceipt'},
        }
        if path not in expected_fields or set(body) != expected_fields[path]:
            raise ValueError('request fields')
        with grant_database(os.path.join(self.directory, 'grants.sqlite3')) as db:
            db.execute('CREATE TABLE IF NOT EXISTS grants (digest TEXT PRIMARY KEY, peer TEXT, fingerprint TEXT, generation INTEGER, expires INTEGER, challenge TEXT, proved INTEGER DEFAULT 0, ack INTEGER DEFAULT 0, issued INTEGER, proofExpires INTEGER)')
            if 'proofExpires' not in {value[1] for value in db.execute('PRAGMA table_info(grants)')}:
                db.execute('ALTER TABLE grants ADD COLUMN proofExpires INTEGER')
                db.execute('UPDATE grants SET proofExpires=expires')
            columns = {value[1] for value in db.execute('PRAGMA table_info(grants)')}
            for column in ('bootstrapNonceHash', 'bootstrapClient'):
                if column not in columns:
                    db.execute('ALTER TABLE grants ADD COLUMN ' + column + ' TEXT')
            db.execute('CREATE TABLE IF NOT EXISTS renewalNonces (digest TEXT PRIMARY KEY)')
            if path == '/migration/v1/bootstrap' and self.role == 'source':
                client = authenticate()
                if client is None:
                    return
                if client != mapping['clientId']:
                    raise ValueError('client')
                nonce, fingerprint = body['nonce'], body['sourceFingerprint']
                if not NONCE.fullmatch(nonce) or not re.fullmatch('[a-f0-9]{64}', fingerprint):
                    raise ValueError('binding')
                db.execute('DELETE FROM grants WHERE expires < ? AND proved=0', (now,))
                nonce_hash = hashlib.sha256(nonce.encode()).hexdigest()
                rows = db.execute('SELECT digest,expires,proved,ack,challenge,issued FROM grants '
                                  'WHERE peer=? AND fingerprint=? AND generation=? AND bootstrapNonceHash=? AND bootstrapClient=?',
                                  (peer, fingerprint, state['generation'], nonce_hash, client)).fetchall()
                if len(rows) > 1:
                    raise ValueError('bootstrap conflict')
                secret = signer_material(self.directory, state['signingPublicKey'])
                if rows:
                    digest, expiry, proved, ack, challenge, issued = rows[0]
                    if proved or ack or expiry <= now:
                        raise ValueError('bootstrap replay')
                else:
                    count = db.execute('SELECT count(*) FROM grants WHERE peer=? AND expires>?', (peer, now)).fetchone()[0]
                    if count >= 32:
                        raise ValueError('grant limit')
                    expiry, issued, challenge = min(now + 86400, state['expiresAt']), now, secrets.token_urlsafe(32)
                grant = bootstrap_grant(secret, self.scope, state['serverPublicKey'], peer, client,
                                        fingerprint, state['generation'], nonce, challenge, issued, expiry)
                observed_digest = hashlib.sha256(grant.encode()).hexdigest()
                if rows:
                    if not secrets.compare_digest(observed_digest, digest):
                        raise ValueError('bootstrap signer drift')
                else:
                    db.execute('INSERT INTO grants(digest,peer,fingerprint,generation,expires,challenge,issued,proofExpires,bootstrapNonceHash,bootstrapClient) VALUES(?,?,?,?,?,?,?,?,?,?)',
                               (observed_digest, peer, fingerprint, state['generation'], expiry,
                                challenge, issued, expiry, nonce_hash, client))
                response = {'schema': 1, 'serverPublicKey': state['serverPublicKey'],
                            'containerId': self.scope, 'peerPublicKey': peer,
                            'sourceFingerprint': fingerprint, 'nonce': nonce,
                            'grant': grant, 'signingPublicKey': state['signingPublicKey'],
                            'generation': state['generation'], 'expiresAt': expiry}
            else:
                grant = handler.headers.get('X-Amnezia-Migration-Grant', body.get('grant', ''))
                if 'grant' in body and body['grant'] != grant:
                    raise ValueError('ambiguous grant')
                if not isinstance(grant, str) or not NONCE.fullmatch(grant):
                    raise ValueError('grant')
                digest = hashlib.sha256(grant.encode()).hexdigest()
                row = db.execute('SELECT peer,fingerprint,generation,expires,challenge,proved,issued,proofExpires FROM grants WHERE digest=?', (digest,)).fetchone()
                renewing = path == '/migration/v1/renew' and self.role == 'target'
                if not row or row[0] != peer or row[2] != state['generation'] or (row[3] <= now and not renewing):
                    raise ValueError('grant binding')
                common = {'schema': 1, 'serverPublicKey': state['serverPublicKey'], 'containerId': self.scope,
                          'peerPublicKey': peer, 'generation': row[2], 'expiresAt': row[3]}
                if path == '/migration/v1/offer' and self.role == 'source':
                    nonce = body['nonce']
                    if not NONCE.fullmatch(nonce) or body['sourceFingerprint'] != row[1]:
                        raise ValueError('offer binding')
                    common.update(sourceFingerprint=row[1], nonce=nonce,
                                  target={'endpoint': state['endpoint'], 'clientAddress': mapping['clientAddress'], 'parameters': state['parameters']},
                                  challenge={'address': state['challengeAddress'], 'port': state['challengePort'], 'nonce': row[4]})
                    response = sign(common, self.directory)
                elif path in ('/migration/v1/challenge', '/migration/v1/ack', '/migration/v1/renew') and self.role == 'target':
                    if type(body['generation']) is not int or body['generation'] != row[2]:
                        raise ValueError('generation')
                    with open(os.path.join(self.directory, 'handshakes.tsv'), encoding='utf-8') as stream:
                        handshake = dict(line.strip().split('\t') for line in stream).get(peer, '0')
                    handshake = int(handshake)
                    if not max(now - 120, row[6] - 5) <= handshake <= now + 5:
                        raise ValueError('handshake')
                    if path.endswith('/challenge'):
                        if body['nonce'] != row[4]:
                            raise ValueError('challenge')
                        # Renewal extends grant delivery, not the original proof
                        # lifetime. Keep regenerated receipts identical to the
                        # proof binding accepted by ack/renew and stored clients.
                        common.update(nonce=row[4], targetAddress=mapping['targetIp'], expiresAt=row[7])
                        response = sign(common, self.directory)
                        db.execute('UPDATE grants SET proved=1 WHERE digest=?', (digest,))
                    else:
                        if not row[5]:
                            raise ValueError('unproved')
                        # Compare receipt to the exact signed payload expected for this grant.
                        common.update(nonce=row[4], targetAddress=mapping['targetIp'], expiresAt=row[7])
                        if body['challengeReceipt'] != sign(common, self.directory):
                            raise ValueError('receipt')
                        if renewing:
                            if authenticate() != mapping['clientId'] or not NONCE.fullmatch(body['nonce']):
                                raise ValueError('renew authentication')
                            db.execute('INSERT INTO renewalNonces(digest) VALUES(?)',
                                (hashlib.sha256((peer + '\t' + body['nonce']).encode()).hexdigest(),))
                            active = db.execute('SELECT count(*) FROM grants WHERE peer=? AND expires>?', (peer, now)).fetchone()[0]
                            if active >= 32:
                                raise ValueError('grant limit')
                            new_grant = secrets.token_urlsafe(48)
                            expiry = now + 86400
                            db.execute('INSERT INTO grants(digest,peer,fingerprint,generation,expires,challenge,issued,proofExpires,proved) VALUES(?,?,?,?,?,?,?,?,1)',
                                (hashlib.sha256(new_grant.encode()).hexdigest(), peer, row[1], row[2], expiry, row[4], row[6], row[7]))
                            target = {'endpoint': state['endpoint'], 'clientAddress': mapping['clientAddress'], 'parameters': state['parameters']}
                            response = sign({'schema': 1, 'serverPublicKey': state['serverPublicKey'],
                                'peerPublicKey': peer, 'containerId': self.scope, 'generation': row[2],
                                'nonce': body['nonce'], 'grant': new_grant, 'sourceFingerprint': row[1],
                                'targetHash': hashlib.sha256(canonical(target)).hexdigest(), 'expiresAt': expiry}, self.directory)
                        else:
                            db.execute('UPDATE grants SET ack=1 WHERE digest=?', (digest,))
                            response = {'schema': 1, 'ok': True, 'acknowledged': True, 'generation': row[2]}
                else:
                    raise ValueError('role/path')
            raw = canonical(response)
            db.commit()
        handler.send_response(200)
        handler.send_header('Content-Type', 'application/json')
        handler.send_header('Cache-Control', 'no-store')
        handler.send_header('Content-Length', str(len(raw)))
        handler.end_headers()
        handler.wfile.write(raw)
