"""Private, peer-bound AWG migration control plane; never a public update feed."""
import base64
from contextlib import closing, contextmanager
import hashlib
import ipaddress
import json
import os
import re
import secrets
import sqlite3
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


class MigrationService:
    def __init__(self, directory, role, scope):
        self.directory, self.role, self.scope = directory, role, scope

    def dispatch(self, handler, authenticate):
        if not handler.path.startswith('/migration/v1/'):
            return False
        try:
            self.handle(handler, authenticate)
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError,
                sqlite3.Error):
            handler.send_error(403)
        return True

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
                grant = secrets.token_urlsafe(48)
                db.execute('DELETE FROM grants WHERE expires < ? AND proved=0', (now,))
                count = db.execute('SELECT count(*) FROM grants WHERE peer=? AND expires>?', (peer, now)).fetchone()[0]
                if count >= 32:
                    raise ValueError('grant limit')
                expiry = min(now + 86400, state['expiresAt'])
                db.execute('INSERT INTO grants(digest,peer,fingerprint,generation,expires,challenge,issued,proofExpires) VALUES(?,?,?,?,?,?,?,?)',
                           (hashlib.sha256(grant.encode()).hexdigest(), peer, fingerprint,
                            state['generation'], expiry, secrets.token_urlsafe(32), now, expiry))
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
                        common.update(nonce=row[4], targetAddress=mapping['targetIp'])
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
