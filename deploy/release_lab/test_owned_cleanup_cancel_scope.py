"""Actual sibling lab.py function; inert signal/time mocks, no processes or VMs."""
from pathlib import Path
import ast
import contextlib
import signal
import time
import unittest
from unittest import mock

SOURCE = Path(__file__).with_name('lab.py')

class OwnedCleanupCancelScopeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tree = ast.parse(SOURCE.read_text(encoding='utf-8-sig'))
        found = [n for n in cls.tree.body if isinstance(n, ast.FunctionDef) and n.name == 'owned_cleanup_cancel_scope']
        if len(found) != 1:
            raise AssertionError('unique real canonical cleanup function required')
        namespace = {'contextlib': contextlib, 'time': time}
        exec(compile(ast.fix_missing_locations(ast.Module(body=found, type_ignores=[])), str(SOURCE), 'exec'), namespace)
        cls.scope = staticmethod(namespace['owned_cleanup_cancel_scope'])

    def test_only_actual_reset_subprocess_has_scope(self):
        controller = next(n for n in self.tree.body if isinstance(n, ast.ClassDef) and n.name == 'LabController')
        method = next(n for n in controller.body if isinstance(n, ast.FunctionDef) and n.name == 'hyperv_call')
        scopes = [n for n in ast.walk(method) if isinstance(n, ast.With)
                  and any(isinstance(item.context_expr, ast.IfExp) and isinstance(item.context_expr.body, ast.Call)
                          and isinstance(item.context_expr.body.func, ast.Name)
                          and item.context_expr.body.func.id == 'owned_cleanup_cancel_scope' for item in n.items)]
        self.assertEqual(len(scopes), 1)
        branch = scopes[0].items[0].context_expr
        self.assertEqual(ast.dump(branch.test), ast.dump(ast.parse('action == "reset"', mode='eval').body))
        self.assertEqual(ast.dump(branch.orelse), ast.dump(ast.parse('contextlib.nullcontext()', mode='eval').body))
        runs = [n for n in ast.walk(scopes[0]) if isinstance(n, ast.Call)
                and isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name)
                and n.func.value.id == 'subprocess' and n.func.attr == 'run']
        self.assertEqual(len(runs), 1)
        self.assertEqual(next(k.value.value for k in runs[0].keywords if k.arg == 'timeout'), 960)

    def test_first_cancel_is_immediate_and_does_not_replace_handler(self):
        with mock.patch.object(signal, 'signal') as install:
            with self.assertRaisesRegex(KeyboardInterrupt, 'first cancellation'):
                with self.scope():
                    raise KeyboardInterrupt('first cancellation')
            install.assert_not_called()

    def test_repeated_cancel_during_existing_interrupt_is_deferred_and_restored(self):
        original_handler = object()
        active = {'handler': original_handler}
        def install(kind, handler):
            self.assertEqual(kind, signal.SIGINT)
            active['handler'] = handler
        with mock.patch.object(signal, 'getsignal', return_value=original_handler), mock.patch.object(signal, 'signal', side_effect=install), mock.patch.object(time, 'monotonic', return_value=100):
            with self.assertRaisesRegex(KeyboardInterrupt, '^original$'):
                try:
                    raise KeyboardInterrupt('original')
                finally:
                    with self.scope():
                        self.assertTrue(callable(active['handler']))
                        active['handler'](signal.SIGINT, None)
                        self.assertIsNot(active['handler'], original_handler)
            self.assertIs(active['handler'], original_handler)

    def test_deadline_and_exception_restore_handler(self):
        original_handler = object()
        handlers = []
        with mock.patch.object(signal, 'getsignal', return_value=original_handler), mock.patch.object(signal, 'signal', side_effect=lambda _, h: handlers.append(h)), mock.patch.object(time, 'monotonic', side_effect=[100, 100.02]):
            with self.assertRaisesRegex(KeyboardInterrupt, 'deadline'):
                try:
                    raise KeyboardInterrupt('original')
                finally:
                    with self.scope(.01):
                        handlers[-1](signal.SIGINT, None)
            self.assertIs(handlers[-1], original_handler)

    def test_invalid_bounds_fail_before_signal_mutation(self):
        with mock.patch.object(signal, 'signal') as install:
            for value in (0, -1, 121, True, '120'):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    with self.scope(value):
                        self.fail('invalid scope entered')
            install.assert_not_called()

if __name__ == '__main__':
    unittest.main()
