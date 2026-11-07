"""Interrupted publisher attempts retain truthful cleanup state; no guest."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from . import publisher_controller as pc
from .test_publisher_controller import FakeController, FakeOps


class PublisherCancellationTests(unittest.TestCase):
    def cancelled(self, error, cleanup_failure=False):
        with tempfile.TemporaryDirectory(prefix='amnezia-publisher-cancel-') as scratch:
            run = {'run_id': 'owned-test', 'lane': 'publisher-diagnostic',
                   'outer_artifact': {'sha256': 'a' * 64}, 'manifest': {'sha256': 'b' * 64}}
            events = []
            controller = FakeController(Path(scratch), run)
            controller.capture_hyperv_failure = Mock()

            class Ops(FakeOps):
                def publish_once(self, *args):
                    raise error

                def cleanup(self, *args):
                    result = super().cleanup(*args)
                    if cleanup_failure:
                        raise RuntimeError('synthetic cleanup failure')
                    return result

            with self.assertRaises(type(error)) as caught:
                pc.ControllerPublisher(controller, Ops(events)).run('owned-test')
            self.assertIs(caught.exception, error)
            self.assertEqual(events[-1], 'cleanup')
            controller.capture_hyperv_failure.assert_not_called()
            return controller.saved['runs']['owned-test']['publication_attempt']

    def test_keyboard_interrupt_is_failed_cleaned(self):
        attempt = self.cancelled(KeyboardInterrupt('synthetic owned cancellation'))
        self.assertEqual(attempt['state'], 'failed-cleaned')
        self.assertTrue(attempt['cleanup']['child_reset'])

    def test_system_exit_is_failed_cleaned(self):
        attempt = self.cancelled(SystemExit('synthetic operator exit'))
        self.assertEqual(attempt['state'], 'failed-cleaned')

    def test_cleanup_failure_keeps_original_interrupt(self):
        attempt = self.cancelled(KeyboardInterrupt('synthetic cancellation'), cleanup_failure=True)
        self.assertEqual(attempt['state'], 'cleanup-failed')
        self.assertIn('synthetic cleanup failure', attempt['cleanup_error'])


if __name__ == '__main__':
    unittest.main()
