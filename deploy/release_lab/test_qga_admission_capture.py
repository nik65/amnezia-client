"""Admission failures retain original private QGA envelopes; no guests used."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from .lab import LabController, LabError, QgaClient, QgaGuestAdmissionError, QgaGuestExecutionError
from .linux_live_acquisition import LinuxLiveProducer


class QgaAdmissionCaptureTests(unittest.TestCase):
    def admit(self, response):
        client = QgaClient(Path('/unused-owned-qga.sock'))
        with patch.object(client, 'request', return_value=response) as request:
            try:
                return client.guest_exec('/private/executable-token', ['private-argument-token'])
            finally:
                self.assertEqual(request.call_count, 1)

    def test_malformed_envelopes_and_missing_or_invalid_pid_remain_failures(self):
        responses = [None, [], 'private-error-token', 17,
                     {}, {'error': {'desc': 'private-error-token'}},
                     {'return': None}, {'return': []}, {'return': 'private-error-token'},
                     {'return': {}}, {'return': {'pid': True}}, {'return': {'pid': False}},
                     {'return': {'pid': 0}}, {'return': {'pid': -1}},
                     {'return': {'pid': 'private-error-token'}}, {'return': {'pid': 3.0}}]
        for response in responses:
            with self.subTest(response=response):
                with self.assertRaises(QgaGuestAdmissionError) as raised:
                    self.admit(response)
                error = raised.exception
                self.assertIsInstance(error, LabError)
                self.assertIsInstance(error, QgaGuestExecutionError)
                capture = error.private_failure_capture()
                self.assertEqual(json.loads(capture['body']), response)
                self.assertEqual(capture['phase'], 'guest-exec-admission')
                for public in (str(error), repr(error), repr(error.args)):
                    for secret in ('private-error-token', 'private-executable-token',
                                   '/private/executable-token', 'private-argument-token'):
                        self.assertNotIn(secret, public)

    def test_contradictory_error_and_valid_pid_never_start_status_polling(self):
        client = QgaClient(Path('/unused-owned-qga.sock'))
        response = {'return': {'pid': 17}, 'error': {'desc': 'private-error-token'}}
        with patch.object(client, 'request', return_value=response) as request:
            with self.assertRaises(QgaGuestAdmissionError) as raised:
                client.guest_exec_wait('/private/executable-token', [])
        self.assertEqual(request.call_count, 1)
        self.assertEqual(json.loads(raised.exception.private_failure_capture()['body']), response)
        self.assertNotIn('private-error-token', repr(raised.exception))

    def test_exact_original_envelope_retained_immutably(self):
        response = {'return': {'missing-pid': 'private-body'}, 'id': 41,
                    'error': {'class': 'private-class', 'desc': 'private-description'}}
        with self.assertRaises(QgaGuestAdmissionError) as raised:
            self.admit(response)
        capture = raised.exception.private_failure_capture()
        raw = json.dumps(response, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
        self.assertEqual(capture['body'], raw)
        self.assertEqual(capture['original_sha256'], hashlib.sha256(raw).hexdigest())
        self.assertFalse(capture['truncated'])
        response['id'] = 0
        self.assertEqual(json.loads(raised.exception.private_failure_capture()['body'])['id'], 41)

    def test_oversized_admission_capture_retains_explicitly_bounded_prefix(self):
        response = {'error': {'desc': 'private-' * 200000}}
        raw = json.dumps(response, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
        with self.assertRaises(QgaGuestAdmissionError) as raised:
            self.admit(response)
        capture = raised.exception.private_failure_capture()
        self.assertTrue(capture['truncated'])
        self.assertEqual(capture['captured_size'], capture['limit'])
        self.assertEqual(capture['body'], raw[:capture['limit']])
        self.assertEqual(capture['original_size'], len(raw))
        self.assertEqual(capture['original_sha256'], hashlib.sha256(raw).hexdigest())
        self.assertNotIn('private-', repr(raised.exception))

    def test_success_payload_identity_and_wait_result_are_unchanged(self):
        payload = {'pid': 17, 'extension': 'preserved'}
        self.assertIs(self.admit({'return': payload, 'id': 7}), payload)
        client = QgaClient(Path('/unused-owned-qga.sock'))
        responses = [{'return': {'pid': 17}},
                     {'return': {'exited': True, 'exitcode': 0, 'out-data': 'b2s=', 'err-data': ''}}]
        with patch.object(client, 'request', side_effect=responses) as request:
            self.assertEqual(client.guest_exec_wait('/bin/fixture', []),
                             {'pid': 17, 'exitcode': 0, 'stdout': 'ok', 'stderr': ''})
        self.assertEqual(request.call_count, 2)

    def test_wait_does_not_poll_after_real_admission_failure(self):
        client = QgaClient(Path('/unused-owned-qga.sock'))
        response = {'return': {}, 'id': 'original-admission'}
        with patch.object(client, 'request', return_value=response) as request:
            with self.assertRaises(QgaGuestAdmissionError) as raised:
                client.guest_exec_wait('/bin/fixture', [])
        self.assertEqual(request.call_count, 1)
        self.assertEqual(json.loads(raised.exception.private_failure_capture()['body']), response)

    @unittest.skipUnless(os.name == 'posix', 'Linux descriptor-relative private archive')
    def test_existing_producer_archives_admission_before_reset_and_reraises(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'runs/run-1/linux-headless-x64').mkdir(parents=True)
            controller = LabController(root)
            producer = LinuxLiveProducer(controller, 'run-1', target='linux-headless')
            producer._start_attempted = True
            response = {'return': {}, 'error': {'desc': 'private-admission-description'}}
            failure = QgaGuestAdmissionError(response)
            producer._acquire_once = Mock(side_effect=failure)
            producer._wait_for_boot = Mock()
            controller.get_run = Mock(return_value={'profiles': {'linux-headless-x64': {
                'vm': {'pid': 123}, 'evidence_archive': {'already': True}}}})
            controller.owned_vm = Mock()
            controller.archive_guest_evidence = Mock()
            def reset(*args):
                archive = producer._private_failure_archive
                self.assertEqual(json.loads((archive/'response.private.json').read_bytes()), response)
                metadata = json.loads((archive/'metadata.private.json').read_bytes())
                self.assertEqual(metadata['phase'], 'guest-exec-admission')
                self.assertFalse(metadata['release_pass'])
            controller.reset = Mock(side_effect=reset)
            with self.assertRaises(QgaGuestAdmissionError) as raised:
                producer.acquire(object())
            self.assertIs(raised.exception, failure)
            controller.reset.assert_called_once()
            controller.archive_guest_evidence.assert_not_called()


if __name__ == '__main__':
    unittest.main()
