"""No-guest regressions for privately retained failed QGA command bodies."""
import base64
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from .lab import LabError, QgaClient, QgaGuestExecutionError


class QgaFailureCaptureTests(unittest.TestCase):
    def execute(self, response):
        client = QgaClient(Path('/unused-owned-qga.sock'))
        with patch.object(client, 'guest_exec', return_value={'pid': 17}), \
                patch.object(client, 'request', return_value=response):
            return client.guest_exec_wait('/bin/fixture', [])

    def test_nonzero_preserves_original_response_without_text_disclosure(self):
        secret = b'Authorization: Bearer private-token\x00\xff'
        response = {'return': {'exited': True, 'exitcode': 23,
                    'out-data': base64.b64encode(secret).decode(),
                    'err-data': base64.b64encode(b'private stderr').decode(),
                    'out-truncated': True}, 'id': 991}
        with self.assertRaises(QgaGuestExecutionError) as caught:
            self.execute(response)
        error = caught.exception
        self.assertIsInstance(error, LabError)
        capture = error.private_failure_capture()
        self.assertEqual(json.loads(capture['body']), response)
        self.assertEqual(base64.b64decode(json.loads(capture['body'])['return']['out-data']), secret)
        self.assertFalse(capture['truncated'])
        self.assertEqual(capture['original_size'], len(capture['body']))
        self.assertEqual(capture['original_sha256'], hashlib.sha256(capture['body']).hexdigest())
        for public in (str(error), repr(error), repr(error.args)):
            self.assertNotIn('private-token', public)
            self.assertNotIn(response['return']['out-data'], public)
            self.assertNotIn(response['return']['err-data'], public)
        response['id'] = 1
        self.assertEqual(json.loads(error.private_failure_capture()['body'])['id'], 991)
        capture['body'] = b'changed'
        self.assertNotEqual(error.private_failure_capture()['body'], b'changed')

    def test_oversized_capture_has_explicit_bound_and_full_body_digest(self):
        response = {'return': {'exited': True, 'exitcode': 2,
                               'out-data': 'A' * (QgaGuestExecutionError.PRIVATE_CAPTURE_LIMIT + 127)}}
        raw = json.dumps(response, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
        with self.assertRaises(QgaGuestExecutionError) as caught:
            self.execute(response)
        capture = caught.exception.private_failure_capture()
        self.assertTrue(capture['truncated'])
        self.assertEqual(capture['body'], raw[:capture['limit']])
        self.assertEqual(capture['captured_size'], capture['limit'])
        self.assertEqual(capture['original_size'], len(raw))
        self.assertEqual(capture['original_sha256'], hashlib.sha256(raw).hexdigest())

    def test_untrusted_exitcode_never_enters_exception_text(self):
        with self.assertRaises(QgaGuestExecutionError) as caught:
            self.execute({'return': {'exited': True, 'exitcode': 'secret-code'}})
        self.assertNotIn('secret-code', repr(caught.exception))
        self.assertIn('exit_code=invalid', str(caught.exception))
        self.assertEqual(json.loads(caught.exception.private_failure_capture()['body'])['return']['exitcode'], 'secret-code')

    def test_success_api_unchanged(self):
        stderr = base64.b64encode(b'warning').decode()
        self.assertEqual(self.execute({'return': {'exited': True, 'exitcode': 0,
                         'out-data': base64.b64encode('ok\u2603'.encode()).decode(),
                         'err-data': stderr}}),
                         {'pid': 17, 'exitcode': 0, 'stdout': 'ok\u2603', 'stderr': stderr})


if __name__ == '__main__':
    unittest.main()
