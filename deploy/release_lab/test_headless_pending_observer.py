"""Actual observer + READ_SET on disposable root-owned POSIX fixture files."""
import ast,base64,copy,hashlib,json,os,pathlib,re,shutil,subprocess,tempfile,time,unittest
from types import SimpleNamespace
import pytest
pytestmark=pytest.mark.skipif(os.name!='posix' or getattr(os,'geteuid',lambda:1)()!=0, reason='actual root-owned POSIX observer fixtures')
HERE=pathlib.Path(__file__).resolve().parent
ROOT=HERE.parents[1]
MODULE=HERE/'headless_pending_observer.py'
def constant(path,name):
 tree=ast.parse(path.read_text())
 return ast.literal_eval(next(n.value for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id==name for t in n.targets)))
WATCH=constant(MODULE,'WATCH');CONTROL=constant(MODULE,'CONTROL')
from deploy.release_lab import headless_native_qga_adapter as _adapter
READ_SET=constant(pathlib.Path(_adapter.__file__),'READ_SET')

class ObserverTests(unittest.TestCase):
 def setUp(self):
  self.base=pathlib.Path(tempfile.mkdtemp(prefix='pending-test-',dir='/root'));self.root=self.base/'observer'
  self.state=self.base/'state';self.journal=self.base/'journal';self.identity=None
  self.nonce='fixture-nonce-123456789';self.phase='rollback_restart_pending'
 def control(self,op,**extra):
  p=dict(op=op,root=str(self.root),nonce=self.nonce,phase=self.phase,**extra)
  r=subprocess.run(['/usr/bin/python3','-c',CONTROL,json.dumps(p)],capture_output=True,text=True,timeout=12)
  if r.returncode:raise RuntimeError(r.stderr.strip())
  return json.loads(r.stdout)
 def arm(self,timeout=2):
  spec={'files':{'pending_state':str(self.state),'pending_journal':str(self.journal)},'absent':{}}
  p=dict(root=str(self.root),nonce=self.nonce,phase=self.phase,timeout=timeout,read_set=READ_SET,spec=spec)
  self.identity=self.control('arm',watch=WATCH,watch_args=p)
 def write_pending(self):
  for p,value in [(self.state,{'version':2,'state':self.phase}),(self.journal,{'phase':self.phase})]:
   p.write_text(json.dumps(value));p.chmod(0o600)
 def capture(self):
  end=time.monotonic()+3
  while time.monotonic()<end:
   v=self.control('read')
   if v:return v
   time.sleep(.01)
  self.fail('capture absent')
 def tearDown(self):
  if self.identity:self.control('stop',identity=self.identity)
  shutil.rmtree(self.base)
 def test_fast_trigger_capture_survives_journal_retirement(self):
  self.arm();self.write_pending()
  # Trigger returns only after a fast real capture, then removes source journal.
  value=self.capture();self.journal.unlink();self.state.write_text('{"state":"rolled_back"}')
  reread=self.control('read');self.assertEqual(value,reread)
  import base64
  for row in value['records'].values():
   b=base64.b64decode(row['bytes_b64']);self.assertEqual(hashlib.sha256(b).hexdigest(),row['sha256']);self.assertEqual(row['mode'],'0600')
  self.assertEqual((self.root/'capture.json').stat().st_mode&0o777,0o400)
 def test_actual_full_roundtrip_root_and_service_groups(self):
  for gid in [0,988]:
   with self.subTest(gid=gid):
    self.root=self.base/('observer-gid-'+str(gid));self.arm()
    # Publish genuine 0600 root:service-group files atomically, as the product does.
    for p,obj in [(self.state,{'state':self.phase}),(self.journal,{'phase':self.phase})]:
     tmp=p.with_suffix('.new');tmp.write_text(json.dumps(obj));os.chown(tmp,0,gid);os.chmod(tmp,0o600);os.replace(tmp,p)
    value=self.capture()
    tree=ast.parse(MODULE.read_text());tree.body=[n for n in tree.body if not isinstance(n,ast.ImportFrom)]
    ns=dict(UPDATE_STATE=str(self.state),UPDATE_JOURNAL=str(self.journal),ID_RE=re.compile('[A-Za-z0-9][A-Za-z0-9._-]{0,95}'),READ_SET=READ_SET,HeadlessNativeQgaError=RuntimeError)
    exec(compile(tree,str(MODULE),'exec'),ns)
    obj=ns['PendingObservation'](SimpleNamespace(plan=SimpleNamespace(attempt_nonce=self.nonce)),self.phase,1)
    obj._control=lambda op,**kwargs:self.control('read',identity=self.identity)
    self.assertEqual(obj.collect(),value['records'])
    for row in value['records'].values():self.assertEqual(row['gid'],gid)
    self.control('stop',identity=self.identity);self.identity=None
    self.state.unlink();self.journal.unlink()
 def test_preexisting_pending_refused(self):
  self.write_pending()
  with self.assertRaisesRegex(RuntimeError,'exited before ready'):self.arm()
 def test_no_pending_expires(self):
  self.arm(.1);time.sleep(.2)
  self.assertIn('expired without capture',self.control('read')['failure']['error'])
 def test_wrong_phase_never_manufactured(self):
  self.arm(.15);self.phase='restart_pending';self.write_pending();time.sleep(.2)
  self.assertIn('expired without capture',self.control('read')['failure']['error'])
 def test_symlink_capture_rejected(self):
  self.arm();(self.root/'capture.json').symlink_to(self.state)
  with self.assertRaises(RuntimeError):self.control('read')
 def test_post_ready_real_read_set_failure_is_retained_promptly(self):
  self.arm();self.state.write_text('{}');self.state.chmod(0o666)
  end=time.monotonic()+2;value={}
  while time.monotonic()<end:
   value=self.control('read',identity=self.identity)
   if value:break
   time.sleep(.01)
  self.assertEqual(value['failure']['error_type'],'RuntimeError')
  self.assertEqual(value['failure']['error'],'READ_SET exit: observation file identity')
  self.assertEqual((self.root/'failure.json').stat().st_mode&0o777,0o400)
 def test_post_ready_death_without_record_fails_promptly(self):
  self.arm();self.control('stop',identity=self.identity)
  value=self.control('read',identity=self.identity)
  self.assertIn('died without capture',value['failure']['error']);self.assertEqual(value['failure']['identity'],self.identity)
 def test_capture_published_between_first_read_and_exit_check_wins(self):
  self.arm();self.write_pending();captured=self.capture();self.control('stop',identity=self.identity)
  # Execute actual CONTROL with only first raw(capture) lookup fault-injected.
  patched=CONTROL.replace("value=completed()\n", "original=completed;calls=[0]\n  def first_missing():\n   calls[0]+=1\n   return None if calls[0]==1 else original()\n  completed=first_missing\n  value=completed()\n",1)
  args=dict(op='read',root=str(self.root),nonce=self.nonce,phase=self.phase,identity=self.identity)
  r=subprocess.run(['/usr/bin/python3','-c',patched,json.dumps(args)],capture_output=True,text=True,timeout=5)
  self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(json.loads(r.stdout),captured)
 def test_existing_observer_directory_refused(self):
  self.root.mkdir()
  with self.assertRaises(RuntimeError):self.arm()
 def test_failed_arm_escalates_and_reaps_unresponsive_owned_child(self):
  bad_watch="import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(30)"
  start=time.monotonic()
  with self.assertRaisesRegex(RuntimeError,'readiness deadline'):
   self.control('arm',watch=bad_watch,watch_args={})
  self.assertLess(time.monotonic()-start,10)
  # The parent uses Popen.wait after SIGKILL; no owned child remains to stop.
 def test_changed_process_identity_does_not_signal(self):
  self.arm();bad=dict(self.identity,ticks=self.identity['ticks']+1)
  with self.assertRaisesRegex(RuntimeError,'incarnation changed'):self.control('stop',identity=bad)
  self.assertTrue(pathlib.Path('/proc',str(self.identity['pid'])).exists())
 def test_symlink_parent_refused_before_creating_directory(self):
  target=self.base/'target';target.mkdir();link=self.base/'link';link.symlink_to(target,target_is_directory=True)
  self.root=link/'observer'
  with self.assertRaisesRegex(RuntimeError,'directory identity'):self.arm()
  self.assertFalse((target/'observer').exists())
 def test_actual_staged_driver_arms_before_each_trigger(self):
  for filename,classname in [('linux_headless_driver.py','PreparedHeadlessDriver'),('headless_native_e2e_driver.py','HeadlessNativeE2EDriver')]:
   driver=MODULE.with_name(filename)
   tree=ast.parse(driver.read_text());cls=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name==classname)
   run=next(n for n in cls.body if isinstance(n,ast.FunctionDef) and n.name=='run')
   blocks=[n for n in ast.walk(run) if isinstance(n,ast.With)]
   self.assertEqual(len(blocks),2)
   self.assertIn('stage_profile()',ast.unparse(blocks[0].body[0]));self.assertIn('observation.collect()',ast.unparse(blocks[0].body[1]))
   self.assertIn('trigger_rollback(',ast.unparse(blocks[1].body[0]));self.assertIn('observation.collect()',ast.unparse(blocks[1].body[1]))

class HostRecordTests(unittest.TestCase):
 def setUp(self):
  tree=ast.parse(MODULE.read_text());tree.body=[n for n in tree.body if not isinstance(n,ast.ImportFrom)]
  ns=dict(UPDATE_STATE='/state',UPDATE_JOURNAL='/journal',ID_RE=re.compile('[A-Za-z0-9][A-Za-z0-9._-]{0,95}'),READ_SET=READ_SET,HeadlessNativeQgaError=RuntimeError)
  exec(compile(tree,str(MODULE),'exec'),ns);self.cls=ns['PendingObservation']
  self.obj=self.cls(SimpleNamespace(plan=SimpleNamespace(attempt_nonce='fixture-nonce-123456789')),'restart_pending',1)
  records={}
  for key,path,obj in [('pending_state','/state',{'state':'restart_pending'}),('pending_journal','/journal',{'phase':'restart_pending'})]:
   b=json.dumps(obj).encode();records[key]=dict(origin='guest',transport='qga',path=path,uid=0,gid=0,mode='0600',size=len(b),sha256=hashlib.sha256(b).hexdigest(),bytes_b64=base64.b64encode(b).decode())
  self.value=dict(nonce=self.obj.nonce,phase=self.obj.phase,records=records)
  self.obj._control=lambda op,**kwargs:self.value
 def test_exact_original_records_returned(self):self.assertEqual(self.obj.collect(),self.value['records'])
 def test_original_record_negatives(self):
  for field,value in [('path','/wrong'),('uid',1000),('uid',False),('mode','0666'),('size',True),('sha256','0'*64),('origin','host')]:
   original=copy.deepcopy(self.value)
   self.value['records']['pending_state'][field]=value
   with self.subTest(field=field),self.assertRaises(RuntimeError):self.obj.collect()
   self.value=original
 def test_actual_read_set_root_service_group_preserved(self):
  with tempfile.TemporaryDirectory(dir='/root') as temp:
   paths={'pending_state':str(pathlib.Path(temp)/'state'),'pending_journal':str(pathlib.Path(temp)/'journal')}
   for key,path in paths.items():
    pathlib.Path(path).write_bytes(base64.b64decode(self.value['records'][key]['bytes_b64']))
    os.chown(path,0,988);os.chmod(path,0o600)
   result=subprocess.run(['/usr/bin/python3','-c',READ_SET,json.dumps({'files':paths,'absent':{}})],capture_output=True,text=True,timeout=3)
   self.assertEqual(result.returncode,0,result.stderr)
   records=json.loads(result.stdout)['records'];self.value['records']=records
   globals_=self.cls._collect.__globals__;old=(globals_['UPDATE_STATE'],globals_['UPDATE_JOURNAL'])
   globals_['UPDATE_STATE'],globals_['UPDATE_JOURNAL']=paths['pending_state'],paths['pending_journal']
   try:
    self.assertEqual(self.obj.collect(),records)
    for row in records.values():self.assertEqual(row['gid'],988);self.assertEqual(row['mode'],'0600')
   finally:globals_['UPDATE_STATE'],globals_['UPDATE_JOURNAL']=old
 def test_invalid_group_metadata_rejected(self):
  for gid in [True,-1,None,'988',988.0]:
   self.value['records']['pending_state']['gid']=gid
   with self.subTest(gid=gid),self.assertRaises(RuntimeError):self.obj.collect()
 def test_nonce_rejected(self):
  self.value['nonce']='foreign'
  with self.assertRaises(RuntimeError):self.obj.collect()
 def test_arm_timeout_covers_full_cleanup(self):
  budgets=[];self.obj.native._json=lambda *args:budgets.append(args[-1])
  self.obj._control=self.cls._control.__get__(self.obj)
  self.obj._control('arm');self.obj._control('stop');self.assertEqual(budgets,[15,10])

if __name__=='__main__':unittest.main(verbosity=2)
