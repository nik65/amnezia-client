"""Exercise actual PowerShell receipt producer against strict publisher consumer."""
import copy
import json
import os
import shutil
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from deploy.release_lab import publisher_controller as module


class ReceiptActionTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt" and shutil.which("powershell.exe"), "requires Windows PowerShell")
    def test_actual_producer_and_strict_missing_wrong_action(self):
        runner_dir = Path(__file__).parent / 'guest_runners'
        with tempfile.TemporaryDirectory(prefix='amnezia-wire-action-') as tmp:
            subprocess.run(['powershell.exe', '-NoProfile', '-File', str(runner_dir / 'test_windows_receipt_action.ps1'),
                            '-OutputDirectory', tmp], check=True, capture_output=True)
            receipt = json.loads((Path(tmp) / 'reinstall.json').read_text(encoding='utf-8-sig'))
        run = {'baseline_version': receipt['baseline_version'], 'candidate_version': receipt['candidate_version']}
        artifact = {'sha256': receipt['artifact_sha256'], 'size': receipt['artifact_size']}
        class Controller:
            def get_run(self, run_id):
                return run
            def hyperv_call(self, action, **kwargs):
                if action == 'collect':
                    return {'action': 'collect'}
                assert action == 'run' and kwargs['GuestAction'] == 'reinstall'
                return {'action': 'run', 'result': {'transport': 'hyperv-powershell-direct', 'origin': 'guest',
                    'injected': False, 'vm_id': 'owned-test-vm', 'readback': {'receipt': json.dumps(current)}}}
        ops = object.__new__(module.ConcretePublisherOps)
        ops.controller = Controller()
        ops._child_record = {'vm_id': 'owned-test-vm'}
        for label in ('actual', 'missing', 'wrong'):
            current = copy.deepcopy(receipt)
            if label == 'missing':
                del current['action']
            elif label == 'wrong':
                current['action'] = 'update'
            with self.subTest(label=label), patch.object(module, 'windows_path_for_wsl', side_effect=str):
                result = ops.run_outer_reinstall(receipt['run_id'], receipt['case_id'], artifact)
                self.assertIs(result['passed'], label == 'actual')


if __name__ == '__main__':
    unittest.main()
