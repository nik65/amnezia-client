import ast,hashlib,json,os,re,subprocess,sys,tempfile,unittest
from pathlib import Path
from datetime import datetime,timezone
from unittest.mock import Mock
SOURCE=Path(__file__).with_name('headless_coordinated_rollback_collector.py');tree=ast.parse(SOURCE.read_text());scope={}
for node in tree.body:
 if isinstance(node,ast.Assign) and any(isinstance(target,ast.Name) and target.id=='IO_COMMON' for target in node.targets):exec(compile(ast.Module(body=[node],type_ignores=[]),'staged','exec'),scope)
 if isinstance(node,ast.FunctionDef) and node.name=='process_program':exec(compile(ast.Module(body=[node],type_ignores=[]),'staged','exec'),scope)
PROGRAM=scope['process_program']()
class Ordering(unittest.TestCase):
 def test_timestamp_is_adjacent_before_popen_and_not_identity_observation(self):
  self.assertIn("invoked_at=",PROGRAM);self.assertEqual(PROGRAM.count('invoked_at='),1)
  self.assertRegex(PROGRAM,r"invoked_at=.*timespec='microseconds'.*\n p=subprocess.Popen")
  self.assertIn("'invoked_at':invoked_at,'observed_at':",PROGRAM)
  self.assertNotIn("timespec='seconds'",PROGRAM)
@unittest.skipUnless(os.name=='posix' and os.getuid()==0,'actual root POSIX inert process')
class Actual(unittest.TestCase):
 def test_real_process_timestamp_bounds_guest_child_action_and_identity(self):
  with tempfile.TemporaryDirectory(dir='/root') as name:
   root=Path(name);exe=str(Path(sys.executable).resolve());action=root/'action.json';code="import datetime,pathlib,time;time.sleep(.05);pathlib.Path("+repr(str(action))+").write_text(datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='microseconds').replace('+00:00','Z'));print('{}')";argv=[exe,'-c',code]
   program=PROGRAM.replace('root=context(run,case,nonce)','root=pathlib.Path('+repr(name)+')');a=program.index('allowed=');b=program.index('\n',a);program=program[:a]+'allowed='+repr([argv,['unselected']])+program[b:]
   digest=hashlib.sha256(Path(exe).read_bytes()).hexdigest();response=subprocess.run([sys.executable,'-c',program,json.dumps(argv),digest,str(root/'output-rollback'),'run','case','nonce'],capture_output=True,timeout=5,check=True)
   process=json.loads(response.stdout)['process'];invoked=datetime.fromisoformat(process['invoked_at'].replace('Z','+00:00'));observed=datetime.fromisoformat(process['observed_at'].replace('Z','+00:00'));acted=datetime.fromisoformat(action.read_text().replace('Z','+00:00'))
   self.assertLessEqual(invoked,observed);self.assertLessEqual(invoked,acted);self.assertRegex(process['invoked_at'],r'\.\d{6}Z$');self.assertRegex(process['observed_at'],r'\.\d{6}Z$')
   self.assertEqual(process['argv'],argv);self.assertEqual(process['exe_sha256'],digest);self.assertEqual(process['uid_slots'],[0,0,0,0]);self.assertEqual(process['exit_code'],0);self.assertGreater(process['pid'],0);self.assertGreater(process['start_ticks'],0)
if __name__=='__main__':unittest.main()
