"""Real sibling fixture generator/contract; no helper execution or sockets."""
from pathlib import Path
import ast
import contextlib
import copy
import importlib.util
import io
import json
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent

def source_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

class FixtureFramingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = source_module('realFixtureContract', ROOT / 'windows_netstack_fixture_contract.py')
        tree = ast.parse((ROOT / 'test_windows_netstack_fixture_independent.py').read_text(encoding='utf-8-sig'))
        functions = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'valid']
        if len(functions) != 1:
            raise AssertionError('unique actual independent receipt fixture required')
        namespace = {}
        exec(compile(ast.fix_missing_locations(ast.Module(body=functions, type_ignores=[])), '<actual-independent-fixture>', 'exec'), namespace)
        cls.valid = staticmethod(namespace['valid'])

    def test_generated_profile_and_responder_mode_agree(self):
        generator = source_module('realFixtureGenerator', ROOT / 'windows_netstack_fixture' / 'prepare_capsule.py')
        with tempfile.TemporaryDirectory(prefix='owned-framing-test-') as folder:
            base = Path(folder)
            helper, observer = base / 'inert-helper', base / 'inert-observer'
            helper.write_bytes(b'not executable'); observer.write_bytes(b'not executable')
            output = base / 'synthetic'
            with contextlib.redirect_stdout(io.StringIO()):
                generator.prepare(output, helper, observer, 'a'*64, 'b'*64)
            config = json.loads((output / 'config.json').read_bytes())
            self.assertIs(config['client_random_trailers'], False)
            profile = json.loads((output / 'profile-template.json').read_bytes())
            last = json.loads(profile['containers'][0]['awg']['last_config'])
            self.assertNotIn('RandomTrailers', last)
            for key in ('I1', 'I2', 'I3', 'I4', 'I5'):
                self.assertNotIn(key, last)
                self.assertNotIn(key + ' =', last['config'])
            self.assertNotIn('RandomTrailers', last['config'])

    def test_matching_original_receipt_is_accepted_without_rewrite(self):
        value, binding = self.valid()
        original = copy.deepcopy(value)
        self.assertEqual(self.contract.validate_observed(value, **binding), original)
        self.assertEqual(value, original)

    def test_responder_framing_is_required_exact_false_in_both_originals(self):
        for record in ('lease', 'terminal'):
            for wrong in (True, 0, 'false', None):
                with self.subTest(record=record, wrong=wrong):
                    value, binding = self.valid()
                    value[record]['fixture_client_random_trailers'] = wrong
                    with self.assertRaises(ValueError):
                        self.contract.validate_observed(value, **binding)
            value, binding = self.valid()
            del value[record]['fixture_client_random_trailers']
            with self.assertRaises(ValueError):
                self.contract.validate_observed(value, **binding)

    def test_actual_client_framing_required_before_and_after(self):
        for phase in ('native_before', 'native_after'):
            for wrong in ('1', 0, False, None, ['0'], ''):
                with self.subTest(phase=phase, wrong=wrong):
                    value, binding = self.valid()
                    value['observation'][phase]['random_trailers'] = wrong
                    with self.assertRaises(ValueError):
                        self.contract.validate_observed(value, **binding)
            value, binding = self.valid()
            del value['observation'][phase]['random_trailers']
            with self.assertRaises(ValueError):
                self.contract.validate_observed(value, **binding)

if __name__ == '__main__':
    unittest.main()
