"""Exercise the whole owned console function with inert CIM/consent mocks."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


@unittest.skipUnless(os.name == 'nt', 'Windows PowerShell function test requires Windows')
class ConsoleProviderTests(unittest.TestCase):
    def test_actual_console_function_returns_one_bound_object_and_rejects_bad_capture(self):
        folder = Path(__file__).resolve().parent
        with tempfile.TemporaryDirectory(prefix='amnezia-full-console-contract-') as scratch:
            result = subprocess.run(
                ['powershell.exe', '-NoProfile', '-NonInteractive', '-File',
                 str(folder / 'windows_host/test_owned_consent_console.ps1'),
                 '-Adapter', str(folder / 'windows_host/hyperv_adapter.ps1'),
                 '-Scratch', scratch],
                capture_output=True, text=True, check=False, timeout=45,
            )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('"status":"PASS"', result.stdout)
        self.assertIn('"fullFunctionCases":14', result.stdout)
        self.assertIn('"captureReturnObjects":1', result.stdout)
        self.assertIn('"allCimCallsMocked":true', result.stdout)


if __name__ == '__main__':
    unittest.main()
