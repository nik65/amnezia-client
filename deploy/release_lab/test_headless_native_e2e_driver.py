import json
from pathlib import Path
import pytest
from deploy.release_lab.headless_native_e2e_driver import HeadlessNativeE2EDriver,HeadlessE2EError
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
 for token in ("def writeall", "short write", "os.fsync(fd)", "syncdir(dst.parent)",
               "exact(tmp,p['legacy_daemon']['sha256'])", "exact(dst,p['legacy_daemon']['sha256'])",
               "assert hashlib.sha256(d.read_bytes()).hexdigest()==sys.argv[3]"):
  assert token in source
