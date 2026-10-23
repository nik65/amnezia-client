"""Loopback black-box contract tests for the standalone native Linux collector.

Tests/build tooling deliberately remains Python. No production server, Docker,
VPN, installed application or user log source is accessed.
"""
import hashlib
import http.client
import json
import os
from pathlib import Path
import signal
import socket
import sqlite3
import subprocess
import tempfile
import time
import unittest

BINARY = os.environ.get('AMNEZIA_NATIVE_COLLECTOR')
CLIENT = 'a' * 64
TOKEN = 'fixture-token'
BATCH = 'b' * 64

@unittest.skipUnless(BINARY, 'set AMNEZIA_NATIVE_COLLECTOR to the freshly built Linux binary')
class NativeCollectorNetworkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='amnezia-native-network-')
        self.root = Path(self.temp.name)
        (self.root/'tokens.tsv').write_text(CLIENT+'\t'+TOKEN+'\n')
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0)); self.port = sock.getsockname()[1]
        self.log = (self.root/'process.log').open('wb')
        self.process = subprocess.Popen([BINARY, '--root', str(self.root), '--bind', '127.0.0.1', '--port', str(self.port)], stdout=self.log, stderr=self.log)
        deadline = time.monotonic()+10
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                self.fail('owned collector exited at startup')
            try:
                with socket.create_connection(('127.0.0.1', self.port), timeout=.2): break
            except OSError: time.sleep(.02)
        else: self.fail('owned collector did not listen')

    def tearDown(self):
        self.process.terminate()
        try: self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill(); self.process.wait(); self.fail('collector did not stop/join its owned workers')
        self.log.close(); self.temp.cleanup()

    def headers(self, batch=BATCH):
        return {'X-Amnezia-Client-Id': CLIENT, 'X-Amnezia-Log-Token': TOKEN, 'X-Amnezia-Batch-Id': batch}

    def request(self, method='POST', path='/logs', body=b'fixture log\n', headers=None):
        connection=http.client.HTTPConnection('127.0.0.1',self.port,timeout=5)
        try:
            connection.request(method,path,body=body,headers=headers if headers is not None else self.headers())
            response=connection.getresponse();return response.status,{key.lower(): value for key, value in response.getheaders()},response.read()
        finally: connection.close()

    def test_health_authentication_and_no_ack_on_rejection(self):
        status,_,body=self.request('GET','/healthz',b'',{})
        self.assertEqual(status,200);self.assertEqual(json.loads(body),{'status':'ok','collectorVersion':3})
        headers=self.headers();headers['X-Amnezia-Log-Token']='wrong'
        status,reply,_=self.request(headers=headers)
        self.assertEqual(status,403);self.assertNotIn('x-amnezia-batch-accepted',reply)
        self.assertEqual(len(list((self.root/'logs').rglob('*.log'))),0)

    def test_auth_streaming_duplicates_malformed_and_atomic_replacement(self):
        token_file = self.root/'tokens.tsv'
        # Runtime lookup historically ignores incomplete rows and extra columns.
        token_file.write_text('malformed\n'+CLIENT+'\told\n'+CLIENT+'\t'+TOKEN+'\textra\n'+CLIENT+'\t\n')
        self.assertEqual(self.request()[0], 204)
        replacement = self.root/'tokens.new'
        replacement.write_text(CLIENT+'\treplacement-secret\n')
        replacement.replace(token_file)
        self.assertEqual(self.request()[0], 403)
        token_file.write_text(CLIENT+'\t'+TOKEN+'\n'+CLIENT+'\t'+'x'*514+'\n')
        self.assertEqual(self.request()[0], 403)
        token_file.unlink()
        token_file.symlink_to(self.root/'process.log')
        self.assertEqual(self.request()[0], 503)
        token_file.unlink()
        token_file.write_text(CLIENT+'\t'+TOKEN+'\n')
        self.assertEqual(self.request()[0], 204)
        self.log.flush()
        output=(self.root/'process.log').read_bytes()
        self.assertNotIn(TOKEN.encode(), output)
        self.assertNotIn(b'replacement-secret', output)

    def test_durable_ack_same_batch_conflict_and_receipt_after_prune(self):
        body=b'original bytes\n';status,headers,_=self.request(body=body)
        self.assertEqual(status,204);self.assertEqual(headers['x-amnezia-batch-accepted'],'1');self.assertEqual(headers['x-amnezia-batch-id'],BATCH)
        with sqlite3.connect(self.root/'batch-receipts.sqlite3') as db:
            row=db.execute('SELECT body_sha256,body_length FROM batch_receipts WHERE client_id=? AND batch_id=?',(CLIENT,BATCH)).fetchone()
        self.assertEqual(row,(hashlib.sha256(body).hexdigest(),len(body)))
        status,headers,_=self.request(body=body);self.assertEqual(status,204);self.assertEqual(headers['x-amnezia-batch-replayed'],'1')
        status,headers,_=self.request(body=b'conflicting bytes\n');self.assertEqual(status,409);self.assertNotIn('x-amnezia-batch-accepted',headers)
        for path in (self.root/'logs').rglob('*.log'):path.unlink()
        status,headers,_=self.request(body=body);self.assertEqual(status,204);self.assertEqual(headers['x-amnezia-batch-replayed'],'1')
        self.assertEqual(len(list((self.root/'logs').rglob('*.log'))),0)

    def test_unauthenticated_large_body_rejected_before_read(self):
        with socket.create_connection(('127.0.0.1',self.port),timeout=2) as sock:
            sock.settimeout(2)
            sock.sendall(('POST /logs HTTP/1.1\r\nHost: loopback\r\nContent-Length: 15728640\r\nX-Amnezia-Client-Id: '+CLIENT+'\r\nX-Amnezia-Log-Token: wrong\r\nX-Amnezia-Batch-Id: '+BATCH+'\r\n\r\n').encode())
            reply=sock.recv(4096)
        self.assertIn(b' 403 ',reply)

    def test_short_body_cannot_commit_or_ack(self):
        with socket.create_connection(('127.0.0.1',self.port),timeout=2) as sock:
            sock.sendall(('POST /logs HTTP/1.1\r\nHost: loopback\r\nContent-Length: 10\r\nX-Amnezia-Client-Id: '+CLIENT+'\r\nX-Amnezia-Log-Token: '+TOKEN+'\r\nX-Amnezia-Batch-Id: '+BATCH+'\r\n\r\nshort').encode());sock.shutdown(socket.SHUT_WR);reply=sock.recv(4096)
        self.assertNotIn(b'x-amnezia-batch-accepted',reply)
        self.assertEqual(len(list((self.root/'logs').rglob('*.log'))),0)
        with sqlite3.connect(self.root/'batch-receipts.sqlite3') as db:self.assertEqual(db.execute('SELECT count(*) FROM batch_receipts').fetchone()[0],0)

    def test_duplicate_framing_and_transfer_encoding_rejected(self):
        for framing in ('Content-Length: 1\r\nContent-Length: 1\r\n','Transfer-Encoding: chunked\r\n','Content-Length: -1\r\n'):
            with socket.create_connection(('127.0.0.1',self.port),timeout=2) as sock:
                sock.sendall(('POST /logs HTTP/1.1\r\nHost: loopback\r\n'+framing+'\r\n').encode());sock.shutdown(socket.SHUT_WR);reply=sock.recv(4096)
            self.assertNotIn(b' 204 ',reply);self.assertNotIn(b'x-amnezia-batch-accepted',reply)
        self.assertEqual(len(list((self.root/'logs').rglob('*.log'))),0)

    def test_batch_validation_empty_and_oversize(self):
        headers=self.headers();headers.pop('X-Amnezia-Batch-Id');self.assertEqual(self.request(headers=headers)[0],428)
        self.assertEqual(self.request(body=b'')[0],413)
        headers=self.headers('../escape');self.assertEqual(self.request(headers=headers)[0],400)
        self.assertEqual(self.request('POST','/bootstrap',b'',{})[0],404)

if __name__=='__main__':unittest.main()
