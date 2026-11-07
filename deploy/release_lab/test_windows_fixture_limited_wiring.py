"""Offline exact helper closure/binding; no compiler, socket, application or VM."""
import contextlib
import ast
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest


def load(path,name):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


class LimitedFixtureWiring(unittest.TestCase):
    def test_prepare_exact_assets_and_bound_hashes(self):
        directory=Path(__file__).parent/'windows_netstack_fixture'
        prepare=load(directory/'prepare_capsule.py','fixture_prepare')
        contract=load(Path(__file__).with_name('windows_netstack_fixture_contract.py'),'fixture_contract')
        with tempfile.TemporaryDirectory(prefix='fixture-limited-wiring-') as tmp:
            root=Path(tmp);assets=[]
            for name in ('helper.exe','observer.ps1','runner.ps1','controller.ps1','capture.cs'):
                path=root/name;path.write_bytes(('inert '+name).encode());assets.append(path)
            output=root/'prepared'
            with contextlib.redirect_stdout(io.StringIO()):
                prepare.prepare(output,assets[0],assets[1],'a'*64,'b'*64,limited_runner=assets[2],limited_controller=assets[3],operator_capture=assets[4])
            manifest=output/'manifest.json';pin=hashlib.sha256(manifest.read_bytes()).hexdigest()
            value=contract.checked_manifest(manifest,pin,'a'*64)
            self.assertEqual(set(value['files']),set(contract.FILES))
            self.assertEqual(len(value['files']),10)
            self.assertEqual(json.loads((output/'config.json').read_text())['ttl_seconds'],280)
            bound,_,_,_=contract.bind_manifest(value,root/'bound',run_id='owned-fixture-test',case_id='outer-clean',vm_id='12345678-1234-1234-1234-123456789abc')
            bound_value=json.loads(bound.read_text());plan=json.loads(Path(bound_value['files']['observer_plan']['path']).read_text())
            for key in ('limited_runner','limited_controller','operator_capture'):
                name=contract.FILES[key]
                self.assertEqual(plan['files'][name],value['files'][key]['sha256'])
            assets[2].write_bytes(b'changed support')
            with self.assertRaisesRegex(ValueError,'source bytes changed'):
                contract.checked_manifest(manifest,pin,'a'*64)

    def test_both_actual_adapter_sources_have_exact_helper_set(self):
        directory=Path(__file__).parent
        expected=('limited_runner','limited_controller','operator_capture')
        for path in (directory/'windows_netstack_fixture/adapter_action.ps1',directory/'windows_host/hyperv_adapter.ps1'):
            source=path.read_text(encoding='utf-8-sig')
            line=next(x for x in source.splitlines() if '$names=[ordered]@{helper=' in x)
            self.assertTrue(all(name+'=' in line for name in expected))
            self.assertIn('New-TimeSpan -Seconds 250',source)

    def test_full_observation_contract_rejects_missing_or_false_limited_proof(self):
        directory=Path(__file__).parent
        contract=load(directory/'windows_netstack_fixture_contract.py','limited_contract')
        path=directory/'test_windows_netstack_fixture_independent.py'
        node=next(node for node in ast.parse(path.read_text(encoding='utf-8-sig')).body if isinstance(node,ast.FunctionDef) and node.name=='valid')
        scope={}
        exec(compile(ast.fix_missing_locations(ast.Module(body=[node],type_ignores=[])),str(path),'exec'),scope)
        value,binding=scope['valid']()
        contract.validate_observed(value,**binding)
        for field,bad in (('limited_gui_operator',False),('limited_gui_operator',1),('limited_started_proof_sha256','wrong'),('limited_started_proof_sha256',None)):
            changed=copy.deepcopy(value);changed['observation'][field]=bad
            with self.subTest(field=field,bad=bad),self.assertRaisesRegex(ValueError,'LIMITED'):
                contract.validate_observed(changed,**binding)
        changed=copy.deepcopy(value);del changed['observation']['limited_gui_operator']
        with self.assertRaisesRegex(ValueError,'LIMITED'):
            contract.validate_observed(changed,**binding)


if __name__=='__main__':unittest.main()
