"""Test key bridge scoping without credentials, guests, or application controls."""
import base64
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch
from deploy.release_lab.publisher_controller import ConcretePublisherOps

VARIABLE = 'AMNEZIA_LAB_PUBLISHER_KEY_B64'
WINDOWS_PS = Path('/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe')


class KeyEnvironmentTests(unittest.TestCase):
    def test_target_only_export_and_restore_on_success_and_failure(self):
        for existing in (None, '', 'OTHER/p:THIRD/lw',
                         'OTHER/p:amnezia_lab_publisher_key_b64/pl:THIRD/u',
                         VARIABLE + '/u:OTHER/l:' + VARIABLE + '/p'):
            for raises in (False, True):
                for old_key in (None, 'previous-inert-value'):
                    with self.subTest(wslenv=existing, raises=raises, old_key=old_key):
                        env = {'WSLENV': existing} if existing is not None else {}
                        if old_key is not None:
                            env[VARIABLE] = old_key

                        class Controller:
                            def hyperv_call(self, action, **kwargs):
                                self.observed = os.environ['WSLENV']
                                self.key = os.environ[VARIABLE]
                                self.call = (action, kwargs)
                                if raises:
                                    raise RuntimeError('inert failure')
                                return {'passed': True}

                        ops = object.__new__(ConcretePublisherOps)
                        ops.controller = Controller()
                        with patch.dict(os.environ, env, clear=True):
                            if raises:
                                with self.assertRaisesRegex(RuntimeError, 'inert failure'):
                                    ops._with_publisher_key('inert', 'publish', run_id='inert')
                            else:
                                self.assertEqual(ops._with_publisher_key('inert', 'publish', run_id='inert'), {'passed': True})
                            self.assertEqual(os.environ.get('WSLENV'), existing)
                            self.assertEqual(os.environ.get(VARIABLE), old_key)
                        observed = ops.controller.observed.split(':')
                        self.assertEqual([entry for entry in observed if entry.split('/')[0].upper() == VARIABLE], [VARIABLE + '/w'])
                        self.assertEqual([entry for entry in observed if entry.split('/')[0].upper() != VARIABLE],
                                         [entry for entry in (existing or '').split(':') if entry and entry.split('/')[0].upper() != VARIABLE])
                        self.assertEqual(ops.controller.key, base64.b64encode(b'inert').decode())
                        self.assertEqual(ops.controller.call, ('publish', {'run_id': 'inert', 'credential': True}))

    @unittest.skipUnless(os.name == 'posix' and WINDOWS_PS.is_file(), 'requires WSL Windows PowerShell bridge')
    def test_actual_windows_child_receives_only_inert_public_token(self):
        class Controller:
            def hyperv_call(self, *args, **kwargs):
                result = subprocess.run([str(WINDOWS_PS), '-NoProfile', '-NonInteractive', '-Command',
                    "if($env:AMNEZIA_LAB_PUBLISHER_KEY_B64 -ceq 'aW5lcnQtcHVibGljLWJyaWRnZS1wcm9iZQ=='){'PRESENT'}else{'ABSENT'}"],
                    capture_output=True, check=True, timeout=20)
                return result.stdout.decode('utf-8-sig').strip()

        ops = object.__new__(ConcretePublisherOps)
        ops.controller = Controller()
        # Keep unrelated WSL configuration and replace only the target entry.
        with patch.dict(os.environ):
            os.environ.pop(VARIABLE, None)
            os.environ['WSLENV'] = ':'.join(entry for entry in os.environ.get('WSLENV', '').split(':')
                                           if entry and entry.split('/')[0].upper() != VARIABLE)
            self.assertEqual(ops._with_publisher_key('inert-public-bridge-probe', 'seed-profile', run_id='inert'), 'PRESENT')


if __name__ == '__main__':
    unittest.main()
