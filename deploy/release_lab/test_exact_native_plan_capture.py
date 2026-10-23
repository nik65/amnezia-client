"""Staged diagnostic ordering only; no VM/guest/build operations."""
import importlib.util,sys,unittest
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
sys.path.insert(0,str(Path.cwd()))
from deploy.release_lab.headless_native_acceptance import NativeUpdatePlan,OuterBinding,ReleaseBytes,Fixture
def release(version,char):return ReleaseBytes(version,char*64,100,chr(ord(char)+1)*64,200,chr(ord(char)+2)*64,30,chr(ord(char)+3)*64,20,'f'*64)
def plan():return NativeUpdatePlan('run-1','native-update','nonce-1234567890','2026-09-13T10:00:00Z',OuterBinding(10,20,'11111111-1111-1111-1111-111111111111','/var/lib/amnezia-release-lab/r/qmp','/var/lib/amnezia-release-lab/r/qga'),release('5.0.1.38','a'),release('5.0.1.39','b'),Fixture('http://10.8.1.253:17864',('10.8.1.0/24',),'nonce-1234567890','/manifest.json','/files/candidate.tar.gz'))
SOURCE=Path(__file__).with_name('headless_coordinated_rollback_driver.py')
spec=importlib.util.spec_from_file_location('deploy.release_lab._staged_exact_plan_driver',SOURCE);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
class Capture(unittest.TestCase):
 def driver(self):
  events=[];driver=object.__new__(module.CoordinatedHeadlessDriver);driver.plan=plan();driver.archive_root=Path('/unused-private-test-root')
  driver.coordinated=SimpleNamespace(archive_original=Mock(side_effect=lambda name,value:events.append(('retain',name,value))),close=Mock(side_effect=lambda:events.append(('close',))))
  stop=RuntimeError('controlled no-guest stop')
  driver.preexisting=SimpleNamespace(prepare_and_connect=Mock(side_effect=lambda:(_ for _ in ()).throw(stop)))
  driver.server=SimpleNamespace(start=Mock(),abort=Mock());driver._archive=Mock();module.capture_server_reset_failure=Mock()
  return driver,events,stop
 def test_exact_asdict_plan_retained_before_first_guest_action(self):
  driver,events,stop=self.driver()
  def prepare():
   self.assertEqual(events,[('retain',driver.plan.attempt_nonce+'-exact-native-plan',asdict(driver.plan))]);raise stop
  driver.preexisting.prepare_and_connect.side_effect=prepare
  with self.assertRaises(RuntimeError) as caught:driver.run()
  self.assertIs(caught.exception,stop);driver.coordinated.close.assert_called_once();self.assertEqual(events[-1],('close',));driver.server.start.assert_not_called()
 def test_archive_failure_prevents_guest_actions_and_preserves_primary(self):
  driver,events,_=self.driver();primary=PermissionError('private archive write failed');driver.coordinated.archive_original.side_effect=primary
  with self.assertRaises(PermissionError) as caught:driver.run()
  self.assertIs(caught.exception,primary);driver.preexisting.prepare_and_connect.assert_not_called();driver.server.start.assert_not_called();driver.server.abort.assert_not_called();driver.coordinated.close.assert_called_once()
 def test_archive_and_secondary_failure_keep_original_and_close(self):
  driver,events,_=self.driver();primary=PermissionError('private plan archive');driver.coordinated.archive_original.side_effect=primary;driver._archive.side_effect=ValueError('failure archive unavailable');driver.coordinated.close.side_effect=OSError('close unavailable')
  with self.assertRaises(PermissionError) as caught:driver.run()
  self.assertIs(caught.exception,primary);driver.coordinated.close.assert_called_once();driver.preexisting.prepare_and_connect.assert_not_called();self.assertTrue(any('archive' in note for note in primary.__notes__));self.assertTrue(any('close' in note for note in primary.__notes__))
if __name__=='__main__':unittest.main()
