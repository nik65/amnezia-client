"""Actual cleanup producer with strict mocked relay-stop consumer; no host actions."""
from pathlib import Path
import ast,types,unittest
from typing import Mapping,Any

class CleanupContract(unittest.TestCase):
    def method(self):
        source=Path(__file__).with_name('publisher_controller.py')
        tree=ast.parse(source.read_text(encoding='utf-8-sig'))
        cls=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='ConcretePublisherOps')
        fn=next(n for n in cls.body if isinstance(n,ast.FunctionDef) and n.name=='cleanup')
        ns=dict(Mapping=Mapping,Any=Any,PublisherError=RuntimeError,windows_path_for_wsl=str,sha256_file=lambda _:('c'*64,1))
        exec(compile(ast.fix_missing_locations(ast.Module(body=[fn],type_ignores=[])),str(source),'exec'),ns)
        return ns['cleanup']

    def exercise(self,pin,consumer_pin):
        calls=[]
        def consume(action,**kw):
            calls.append((action,kw))
            if action!='relays-stop' or kw.get('RelayHelperSha256')!=consumer_pin or kw.get('RelayHelperPath')!='owned/relay.exe' or kw.get('RelayGuestTaskSha256')!='c'*64:
                raise RuntimeError('strict relay consumer rejected helper binding')
            return dict(relays_stopped=True,relay_registry_unregistered=True)
        obj=types.SimpleNamespace(_relays_started=True,_key=None,_child_started=False,_server_started=False,_attempt_nonce='0'*48,
            RELAY_HELPER_SHA256=pin,controller=types.SimpleNamespace(hyperv_call=consume),
            _relay_helper_paths=lambda:('owned/relay.exe','owned/supervisor.exe','owned/task.ps1'))
        return self.method()(obj,'ordinary-lab-run_42','publisher-clean'),calls

    def test_exact_canonical_and_capsule_pins_forwarded(self):
        for pin in ('6ecc6aedcddaf005b4ff3116d0758d710f69b5cc3473318f51a67c722fb73824',
                    '9d16001db13bbdee38d36cc7ab2f8d0e95e15c46d7a0dfa2a729aee5b3a942bc'):
            result,calls=self.exercise(pin,pin)
            self.assertTrue(result['relays_stopped']);self.assertEqual(len(calls),1)
            self.assertEqual(calls[0][1]['RelayHelperSha256'],pin)

    def test_missing_hash_rejected(self):
        with self.assertRaises(RuntimeError):self.exercise('', 'a'*64)

    def test_wrong_hash_rejected(self):
        with self.assertRaises(RuntimeError):self.exercise('b'*64,'a'*64)

if __name__=='__main__':unittest.main()
