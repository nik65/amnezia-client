"""Hermetic bundle/ownership rejection regressions; no guests/native commands."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from .awg_migration_native import ROLES, validate_bundle, run
from .lab import LabError


class MigrationNativeContractTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        files = {}
        for name in ROLES:
            (self.root / name).write_bytes(name.encode())
            files[name] = hashlib.sha256(name.encode()).hexdigest()
        self.plan = {'schema': 1, 'sourceCommit': 'a' * 40, 'files': files,
                     'goReceipt': {'sourceArchiveSha256': 'a95853baa25d438a3e92ea5207bd315e3a45143b5209488ebf7f0b44e2e2bcc3',
                                   'sha256': files['amneziawg-go'], 'socketDirectory': '/run/amnezia/awg3/amneziawg'},
                     'toolsReceipt': {'revision': 'ee0f0a9aa34ff0a0da4b3433b9512781cfe02843',
                                      'RUNSTATEDIR': '/run/amnezia/awg3',
                                      'archiveSha256': '19b52a13b014b9ca3cf74226436ce657ac42ba4c83d1eeca9ee48a339aa1abe6'}}
        self.save()

    def tearDown(self):
        self.tmp.cleanup()

    def save(self):
        (self.root / 'bundle.json').write_text(json.dumps(self.plan))

    def test_changed_actual_binary_bytes_rejected(self):
        validate_bundle(self.root)
        (self.root / 'amneziad').write_bytes(b'changed')
        with self.assertRaises(LabError):
            validate_bundle(self.root)

    def test_symlink_helper_rejected(self):
        (self.root / 'guest.py').unlink()
        (self.root / 'guest.py').symlink_to(self.root / 'service.py')
        with self.assertRaises(LabError):
            validate_bundle(self.root)

    def test_tool_provenance_mismatch_rejected(self):
        self.plan['toolsReceipt']['RUNSTATEDIR'] = '/var/run'
        self.save()
        with self.assertRaises(LabError):
            validate_bundle(self.root)

    def test_dry_run_rejected_before_any_vm_action(self):
        class Dry:
            dry_run = True
            test_mode = False
        with self.assertRaises(LabError):
            run(Dry(), 'fixture-test', self.root, self.root / 'out.json')


if __name__ == '__main__':
    unittest.main()
