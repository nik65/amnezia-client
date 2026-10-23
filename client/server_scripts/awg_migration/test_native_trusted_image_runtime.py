"""Captured native image catalog: inert Docker fixture, no pull/run/network effects."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import prepare
import trusted_image
from test_native_ready_runtime import PrepareHarness

FIXTURE = os.environ.get('AWG_IMAGE_TEST_BIN')


class ImageSelectionAndProtocol(unittest.TestCase):
    def test_legacy_selection_explicit(self):
        self.assertIs(prepare.image_function(None), trusted_image.resolve_image)

    def test_native_exact_image_and_private_fixed_request(self):
        adapter = prepare.NativePolicy(b'owned-test-bytes')
        with mock.patch.object(adapter, '_invoke', return_value=trusted_image.IMAGE) as invoke:
            self.assertEqual(adapter.resolve_trusted_image(None), trusted_image.IMAGE)
        args, values = invoke.call_args
        self.assertEqual(args[:4], (b'{"op":"resolve"}', '--trusted-image-json', 4096,
                                    'native_trusted_image_rejected'))
        self.assertEqual(values, {'input_limit': 4096, 'deadline_seconds': 330})
        self.assertEqual(args[4], {'unsupported_server_architecture', 'image_fetch_unavailable',
                                   'trusted_image_unavailable'})
        for value in (None, True, 1, {}, [trusted_image.IMAGE], 'other@sha256:' + 'a' * 64,
                      trusted_image.IMAGE + '\0', trusted_image.IMAGE + '\n'):
            with self.subTest(value=value):
                with mock.patch.object(adapter, '_invoke', return_value=value):
                    with self.assertRaisesRegex(ValueError, '^native_trusted_image_rejected$'):
                        adapter.resolve_trusted_image(None)

    def test_deadline_protocol_rejects_invalid_values_before_execution(self):
        for deadline in (True, None, 0, -1, 46, 331, 330.0):
            with self.subTest(deadline=deadline):
                with mock.patch.object(prepare.os, 'memfd_create', side_effect=AssertionError('execution reached')):
                    with self.assertRaisesRegex(ValueError, '^owned-rejection$'):
                        prepare.NativePolicy(b'owned')._invoke(b'{}', '--trusted-image-json',
                            4096, 'owned-rejection', set(), deadline_seconds=deadline)
        for mode in ('--policy-json', '--automatic-json', '--ready-json', '--config-json'):
            with self.subTest(mode=mode):
                with mock.patch.object(prepare.os, 'memfd_create', side_effect=AssertionError('execution reached')):
                    with self.assertRaisesRegex(ValueError, '^owned-rejection$'):
                        prepare.NativePolicy(b'owned')._invoke(b'{}', mode, 4096,
                            'owned-rejection', set(), deadline_seconds=330)


@unittest.skipUnless(FIXTURE, 'owned standalone catalog fixture required')
class CapturedImage(unittest.TestCase):
    def setUp(self):
        self.raw = Path(FIXTURE).read_bytes()

    def test_actual_native_resolver_never_uses_parent_or_python(self):
        with mock.patch.object(trusted_image, 'resolve_image', side_effect=AssertionError('Python fallback')):
            resolver = prepare.image_function(self.raw)
            self.assertEqual(resolver(mock.Mock(side_effect=AssertionError('parent Docker'))), trusted_image.IMAGE)

    def test_actual_whole_prepare_native_image_before_planning(self):
        with tempfile.TemporaryDirectory() as name:
            harness = PrepareHarness(Path(name), self.raw)
            actual_image = prepare.NativePolicy.resolve_trusted_image
            actual_automatic = prepare.NativePolicy.automatic_request
            order = []

            def image(adapter, runner):
                order.append('trusted-image')
                return actual_image(adapter, runner)

            def automatic(adapter, operation, **values):
                order.append(operation)
                return actual_automatic(adapter, operation, **values)

            with mock.patch.object(prepare.NativePolicy, 'resolve_trusted_image', autospec=True, side_effect=image), \
                 mock.patch.object(prepare.NativePolicy, 'automatic_request', autospec=True, side_effect=automatic):
                self.assertTrue(harness.execute(True)['prepared'])
            self.assertEqual(order, ['trusted-image', 'inventory', 'plan', 'inventory', 'verify-port'])
            self.assertEqual(harness.journal.value['request']['image'], trusted_image.IMAGE)
            self.assertFalse(harness.journal.cleaned)

    def test_native_image_failure_stops_before_plan_and_journal(self):
        for error in ('native_trusted_image_rejected', 'trusted_image_unavailable',
                      'unsupported_server_architecture', 'image_fetch_unavailable'):
            with self.subTest(error=error):
                with tempfile.TemporaryDirectory() as name:
                    harness = PrepareHarness(Path(name), self.raw)
                    with mock.patch.object(prepare.NativePolicy, 'resolve_trusted_image',
                            side_effect=ValueError(error)), \
                         mock.patch.object(prepare.NativePolicy, 'automatic_request',
                            side_effect=AssertionError('planning reached after image failure')):
                        with self.assertRaisesRegex(ValueError, '^' + error + '$'):
                            harness.execute(True)
                    self.assertIsNone(harness.journal)
                    self.assertFalse(harness.activation)
                    self.assertFalse(any(call[:2] == ('docker', 'create') for call in harness.calls))


if __name__ == '__main__':
    unittest.main()
