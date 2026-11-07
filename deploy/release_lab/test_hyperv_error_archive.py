"""Pure mocked native adapter failures; never invoke a bridge or a guest."""
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from deploy.release_lab import lab


class AdapterArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='amnezia-adapter-error-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        if os.name == 'posix':
            self.root.chmod(0o700)
        self.result = subprocess.CompletedProcess(['inert'], 1, b'private-sensitive-stdout', b'private-sensitive-stderr')

    def call(self, result=None):
        controller = object.__new__(lab.LabController)
        controller.root = self.root
        controller.dry_run = False
        controller.test_mode = True
        controller._mutation_lock_depth = 0
        with patch.object(lab, 'hyperv_adapter_source', return_value=Path('inert-adapter')), \
             patch.object(lab, 'windows_path_for_wsl', side_effect=str), \
             patch.object(Path, 'is_file', return_value=True), \
             patch.object(lab.os, 'access', return_value=True), \
             patch.object(lab.subprocess, 'run', return_value=result or self.result) as native:
            with self.assertRaises(lab.LabError) as raised:
                controller.hyperv_call('seed-profile', run_id='owned-test-run', CaseId='publisher-clean')
            native.assert_called_once()
        self.assertNotIn('private-sensitive', str(raised.exception))
        return str(raised.exception)

    @unittest.skipUnless(os.name == 'posix', 'private raw archive requires POSIX authority')
    def test_nonzero_exact_bytes_permissions_and_binding(self):
        error = self.call()
        self.assertIn('exit_code=1', error)
        files = list(self.root.glob('exports/owned-test-run/private-adapter-errors/*/metadata.json'))
        self.assertEqual(len(files), 1)
        meta = json.loads(files[0].read_text())
        self.assertEqual((meta['run_id'], meta['case_id'], meta['action']), ('owned-test-run', 'publisher-clean', 'seed-profile'))
        for label in ('stdout', 'stderr'):
            path = files[0].parent / (label + '.bin')
            self.assertEqual(path.read_bytes(), getattr(self.result, label))
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(files[0].parent.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(files[0].parent.parent.stat().st_mode), 0o700)
        self.assertNotIn('stdin', meta)

    @unittest.skipUnless(os.name == 'posix', 'private raw archive requires POSIX authority')
    def test_invalid_json_and_nonobject_preserved(self):
        for output, expected in ((b'private-sensitive-invalid', 'non-JSON'), (b'[]', 'non-object')):
            self.assertIn(expected, self.call(subprocess.CompletedProcess([], 0, output, b'')))
        self.assertEqual(len(list(self.root.glob('exports/owned-test-run/private-adapter-errors/*/metadata.json'))), 2)

    @unittest.skipUnless(os.name == 'posix', 'private raw archive requires POSIX authority')
    def test_oversize_is_metadata_only_never_silent_truncation(self):
        self.call(subprocess.CompletedProcess([], 1, b'x' * 131073, b'exact-bounded'))
        meta_path = next(self.root.glob('exports/owned-test-run/private-adapter-errors/*/metadata.json'))
        metadata = json.loads(meta_path.read_text())
        self.assertFalse(metadata['streams']['stdout']['persisted'])
        self.assertEqual(metadata['streams']['stdout']['size'], 131073)
        self.assertFalse((meta_path.parent / 'stdout.bin').exists())
        self.assertEqual((meta_path.parent / 'stderr.bin').read_bytes(), b'exact-bounded')

    def test_archive_failure_preserves_original_failure_without_secret(self):
        with patch.object(Path, 'mkdir', side_effect=OSError('private-sensitive-exception')):
            error = self.call()
        self.assertIn('exit_code=1', error)
        self.assertIn('archive=unavailable', error)

    def test_windows_fallback_does_not_persist_raw(self):
        with patch.object(lab.os, 'name', 'nt'):
            value = lab._archive_hyperv_failure(self.root, run_id='owned-test-run', action='seed-profile', case_id='publisher-clean', result=self.result)
        self.assertEqual(value, 'archive=unavailable-platform')
        self.assertEqual(list(self.root.iterdir()), [])

    @unittest.skipUnless(os.name == 'posix', 'private raw archive requires POSIX authority')
    def test_identity_and_link_rejection(self):
        value = lab._archive_hyperv_failure(self.root, run_id='../escape', action='seed-profile', case_id='publisher-clean', result=self.result)
        self.assertEqual(value, 'archive=unavailable-identity')
        (self.root / 'exports').symlink_to(self.root, target_is_directory=True)
        value = lab._archive_hyperv_failure(self.root, run_id='owned-test-run', action='seed-profile', case_id='publisher-clean', result=self.result)
        self.assertEqual(value, 'archive=unavailable-path')


if __name__ == '__main__':
    unittest.main()
