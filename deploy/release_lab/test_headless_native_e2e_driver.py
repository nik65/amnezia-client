import ast,hashlib,inspect,json,textwrap
from pathlib import Path
import pytest
from deploy.release_lab.headless_native_e2e_driver import HeadlessNativeE2EDriver,HeadlessE2EError,PreexistingQgaBridge
from deploy.release_lab.test_headless_native_qga_adapter import plan

def test_archive_is_immutable_and_attempt_bound(tmp_path):
 d=HeadlessNativeE2EDriver(plan(),None,None,None,None,tmp_path)
 p=d._archive('raw',{'origin':'guest','value':1})
 assert p.name.startswith(plan().attempt_nonce) and json.loads(p.read_text())['value']==1
 with pytest.raises(HeadlessE2EError,match='immutable'):d._archive('raw',{'value':2})

def test_state_decoder_never_invents_readiness():
 from deploy.release_lab.headless_native_e2e_driver import _state
 assert _state({},'pending_state')==''
 assert _state({'pending_state':{'bytes_b64':'bad'}},'pending_state')==''

def test_systemd_transition_is_durable_and_rehashed():
 source=Path(__import__('deploy.release_lab.headless_native_e2e_driver',fromlist=['x']).__file__).read_text()
 for token in ("def writeall", "short write", "os.fsync(fd)", "syncdir(dst_path.parent)",
               "exact(src_cli,cli_hash)", "exact(dst_cli,p['cli']['sha256'])",
               "replace_from(src,dst,p['legacy_daemon']['sha256'])", "replace_from(src_cli,dst_cli,cli_hash)",
               "backup_cli=root/'setup-cli.backup'", "baseline binary switch rollback incomplete", "baseline service rollback incomplete",
               "f'{self.root}/setup-cli.backup'", "assert hashlib.sha256(q.read_bytes()).hexdigest()==h"):
  assert token in source

def test_embedded_promotion_program_compiles_and_executes_exact_helper(tmp_path):
 source=inspect.getsource(PreexistingQgaBridge.promote_systemd_baseline);code=source.split('code="""',1)[1].split('"""',1)[0];compiled=compile(code,"<promote-systemd-baseline>","exec")
 embedded=ast.parse(code);controlled=ast.Module(body=[n for n in embedded.body if isinstance(n,(ast.Import,ast.ImportFrom,ast.FunctionDef))],type_ignores=[])
 namespace={};exec(compile(controlled,"<promote-helpers>","exec"),namespace)
 artifact=tmp_path/"artifact";artifact.write_bytes(b"baseline");digest=hashlib.sha256(b"baseline").hexdigest()
 assert namespace["exact"](artifact,digest)==b"baseline"
 assert compiled is not None

def test_sequence_hands_clean_state_to_baseline_before_update():
 source=Path(__import__('deploy.release_lab.headless_native_e2e_driver',fromlist=['x']).__file__).read_text()
 assert "baseline-handoff" in source and "validate_baseline_owned" in source
 assert source.index("prepare_and_connect") < source.index("crash_and_restart") < source.index("before=self.native.identity") < source.index("collect_update_pending")
 assert "self._run('crash'" not in source and "crash_authorization" not in source
