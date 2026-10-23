"""Actual nonvisual predicate, bounded host protocol, POSIX private-file/child fixtures."""
import contextlib
import base64,copy,hashlib,json,os,signal,subprocess,tempfile,time,unittest,types
from pathlib import Path
from unittest.mock import Mock,patch
from .linux_gui_fixture import LinuxGuiFixture,LinuxGuiFixtureError
from .linux_desktop_readiness import DesktopReadinessTracker,DesktopObservationError
from .test_linux_desktop_readiness import sample,BOOT
from .guest_helpers import linux_gui_continuous as guest

def exercise_host_transaction(test,changed=False,crash=False,stale=False,incomplete=False):
 fixture=LinuxGuiFixture(test.controller,'run-14');fixture._setup_done=True
 test.run['profiles']['linux-x64-gui']['steps']=[{'id':n,'passed':True} for n in ('probe','reinstall','update','service-health')]
 rows=[]
 for stamp in range(0,40001,5000):
  o=sample(stamp);o.pop('pixels');rows.append({'schema':'linux-desktop-live-probe-v1','observation':o,'xres':{'dpms':{'level':0}}})
 final=rows[-1]['observation']
 if changed:final['shell']['start_ticks']=101;final['wm']['owner_start_ticks']=101
 if crash:final['crash_history']['events']=[{'boot_id':BOOT,'monotonic_ms':39000,'component':'gnome-shell','event':'crash','pid':80,'start_ticks':100}]
 if incomplete:final['crash_history']['complete_since_boot']=False
 data=b''.join(json.dumps(r).encode()+b'\n' for r in rows);capture={};calls=[]
 def control(operation,payload=None):
  calls.append(operation)
  if operation=='status':
   return {'phase':'sealed' if capture else 'sampling','worker':{'pid':555},'dwellSpanMs':35000,'latestDPMS':{'level':0},'rawSize':len(data),'observations':[r['observation'] for r in rows],'capture':capture}
  if operation=='clock':return {'beforeMs':1000 if stale else 36000,'bootID':BOOT,'sequence':8}
  if operation=='capture':capture.update(payload,afterMs=1001 if stale else 37000);return dict(capture)
  if operation=='archive':return {'offset':payload['offset'],'size':len(data),'data':base64.b64encode(data[payload['offset']:payload['offset']+32768]).decode()}
  raise AssertionError(operation)
 fixture._continuous_control=Mock(side_effect=control);fixture._live_fence=Mock();fixture.qga.guest_exec=Mock(return_value={'pid':555})
 def screenshot(command,args):
  test.assertEqual(command,'screendump');Path(args['filename']).write_bytes(b'P6\n1 1\n255\nabc');return {'return':{}}
 with patch('deploy.release_lab.lab.QmpClient') as qmp,patch('deploy.release_lab.linux_gui_fixture.time.sleep'):
  qmp.return_value.request.side_effect=screenshot
  result=fixture.wait_after_steps()
 test.assertTrue(result['diagnosticOnly']);test.assertTrue(result['decision']['ready_for_root_visual_review'])
 test.assertEqual(result['decision']['pixel_binding'][-1],37000)
 test.assertEqual(calls[:3],['status','clock','capture'])
 test.assertTrue((fixture.archive/'continuous-raw.jsonl').is_file())
 return fixture

class NonvisualTests(unittest.TestCase):
 def feed(self,tracker):
  for t in (0,10000,20000,30000):
   o=sample(t);o.pop('pixels');result=tracker.observe_nonvisual(o)
  return result
 def test_real_nonvisual_dwell_never_visual_ready_and_no_pixel_binding(self):
  t=DesktopReadinessTracker();r=self.feed(t)
  self.assertFalse(r.ready_for_root_visual_review);self.assertIsNone(r.pixel_binding);self.assertEqual(r.reason,'fresh-pixel-capture-required')
  o=sample(35000);o['pixels']['captured_monotonic_ms']=34000
  self.assertTrue(t.observe(o).ready_for_root_visual_review)
 def test_stale_capture_and_gap_stay_rejected(self):
  t=DesktopReadinessTracker();self.feed(t);o=sample(35000);o['pixels']['captured_monotonic_ms']=0
  self.assertFalse(t.observe(o).ready_for_root_visual_review)
  o=sample(50001);self.assertEqual(t.observe(o).reason,'dwelling')
 def test_nonvisual_refuses_pixels_and_preserves_crash_taint_across_pending_gap(self):
  t=DesktopReadinessTracker()
  with self.assertRaises(DesktopObservationError):t.observe_nonvisual(sample())
  o=sample(1000);o.pop('pixels');o['crash_history']['events']=[{'boot_id':BOOT,'monotonic_ms':900,'component':'gnome-shell','event':'crash','pid':80,'start_ticks':100}]
  t.observe_nonvisual(o);t.break_continuity()
  self.assertEqual(self.feed(t).reason,'desktop-crash-or-restart-since-boot')

class HostProtocolTests(unittest.TestCase):
 def setUp(self):
  from .test_linux_gui_fixture import GuiFixtureTests
  GuiFixtureTests.setUp(self)
 def test_actual_host_batch_keeps_full_closure_entry_exit_and_genuine_capture(self):exercise_host_transaction(self)
 def test_crash_during_capture_or_incomplete_history_or_stale_png_fail(self):
  for kwargs in ({'crash':True},{'incomplete':True},{'stale':True}):
   with self.subTest(kwargs=kwargs),self.assertRaises(LinuxGuiFixtureError):exercise_host_transaction(self,**kwargs)
 def test_lost_live_ownership_prevents_control_or_stop_commands(self):
  f=LinuxGuiFixture(self.controller,'run-14');f._resident_pid=555;f._live_fence=Mock(side_effect=LinuxGuiFixtureError('ownership lost'));f.qga.guest_exec_wait=Mock()
  with self.assertRaises(LinuxGuiFixtureError):f._continuous_control('stop')
  f.qga.guest_exec_wait.assert_not_called()
 def test_close_reaps_exact_async_guest_pid_and_preserves_nonzero(self):
  for exitcode in (0,1):
   f=LinuxGuiFixture(self.controller,'run-14');f._resident_pid=555;f._live_fence=Mock();f._continuous_control=Mock();f.qga.request=Mock(return_value={'return':{'exited':True,'exitcode':exitcode}})
   if exitcode:
    with self.assertRaises(LinuxGuiFixtureError):f.close()
   else:f.close();self.assertIsNone(f._resident_pid)
   f.qga.request.assert_called_once_with('guest-exec-status',{'pid':555})

class FailureCaptureTests(unittest.TestCase):
 def setUp(self):
  from .test_linux_gui_fixture import GuiFixtureTests
  GuiFixtureTests.setUp(self)
 def test_failed_worker_raw_and_exact_exit_response_retained_before_cleanup(self):
  f=LinuxGuiFixture(self.controller,'run-14');f._resident_pid=555;f._live_fence=Mock()
  raw=b'{"actual":"prior journal evidence"}\n';calls=[]
  def control(operation,payload=None):
   calls.append(operation)
   if operation=='stop':return {'alreadyExited':True}
   if operation=='status':return {'phase':'failed','rawSize':len(raw)}
   if operation=='archive':return {'offset':0,'size':len(raw),'data':base64.b64encode(raw).decode()}
   raise AssertionError(operation)
  f._continuous_control=Mock(side_effect=control)
  response={'return':{'exited':True,'exitcode':1,'out-data':base64.b64encode(b'actual final crash raw').decode()}}
  f.qga.request=Mock(return_value=response);primary=RuntimeError('original actual crash')
  f._capture_continuous_failure(primary)
  self.assertEqual((f.archive/'continuous-failure-raw.partial.jsonl').read_bytes(),raw)
  self.assertEqual(json.loads((f.archive/'continuous-failure-exit.json').read_bytes()),response)
  self.assertFalse(json.loads((f.archive/'continuous-failure-capture.json').read_bytes())['partial'])
  self.assertEqual(calls,['stop','status','archive']);self.assertEqual(str(primary),'original actual crash')
 def test_failure_capture_budget_or_ownership_loss_preserves_primary(self):
  for lost in (False,True):
   f=LinuxGuiFixture(self.controller,'run-14');f._resident_pid=555;f._live_fence=Mock(side_effect=LinuxGuiFixtureError('lost') if lost else None)
   f._continuous_control=Mock(side_effect=TimeoutError('bounded read failure'));primary=RuntimeError('original')
   f._capture_continuous_failure(primary)
   self.assertEqual(str(primary),'original');self.assertTrue(primary.__notes__)
   if lost:f._continuous_control.assert_not_called()
   self.assertTrue(json.loads((f.archive/'continuous-failure-capture.json').read_bytes())['partial'])
 def test_expired_transaction_budget_rejects_before_guest_command(self):
  f=LinuxGuiFixture(self.controller,'run-14');f._continuous_deadline=0.001;f._live_fence=Mock();f.qga.guest_exec_wait=Mock()
  with self.assertRaisesRegex(LinuxGuiFixtureError,'deadline'):f._continuous_control('archive',{'offset':0})
  f.qga.guest_exec_wait.assert_not_called();f._live_fence.assert_not_called()

@unittest.skipUnless(os.name=='posix' and os.geteuid()==0,'root-owned POSIX fixture')
class PrivateWorkerTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name);self.root.chmod(0o700)
  self.patch=patch.multiple(guest,root=str(self.root),run='test',profile='linux-x64-gui',nonce='a'*48,create=True);self.patch.start();self.addCleanup(self.patch.stop)
  (self.root/'marker').write_text(json.dumps({'run_id':'test','profile':'linux-x64-gui','nonce':'a'*48},sort_keys=True));(self.root/'marker').chmod(0o600)
 def test_actual_private_atomic_files_bounds_symlink_and_nonce_refusal(self):
  guest.write('state.json',{'value':1});self.assertEqual(json.loads(guest.read('state.json')),{'value':1});self.assertEqual((self.root/'state.json').stat().st_mode&0o777,0o600)
  (self.root/'link').symlink_to(self.root/'state.json')
  with self.assertRaises(OSError):guest.read('link')
  with self.assertRaises(RuntimeError):guest.write('large.json',{'value':'x'*65536})
  (self.root/'marker').write_text('foreign')
  with self.assertRaises(RuntimeError):guest.write('foreign.json',{})
 def test_actual_owned_processgroup_is_terminated_and_reaped(self):
  child=subprocess.Popen(['/usr/bin/sleep','20'],start_new_session=True);binding=guest.identity(child.pid)
  guest.child_cleanup(child,binding);self.assertIsNotNone(child.returncode)
  self.assertFalse(Path('/proc',str(child.pid)).exists())
 def run_worker(self,fail=False,oversize=False,startup_budget=False):
  clock={'value':0.0};counter={'value':-5000};children=[];original_popen=subprocess.Popen;original_write=guest.write
  shell={'pid':80,'start_ticks':100,'exe':'/usr/bin/gnome-shell','uid':1000,'state':'S'}
  env={b'GALLIUM_DRIVER':b'softpipe',b'DISPLAY':b':0',b'XAUTHORITY':b'/run/user/1000/gdm/Xauthority'}
  def command(args,**kw):
   if args[0]=='pgrep':return b'80'
   if 'gdbus' in args:
    if startup_budget:clock['value']+=min(5,kw['timeout']);self.assertLessEqual(clock['value'],180)
    method=args[args.index('--method')+1]
    if method.endswith('IsInhibited'):return b'(true,)'
    if method.endswith('GetInhibitors'):
     if startup_budget:return repr(tuple('/org/gnome/SessionManager/Inhibitor'+str(n) for n in range(32))).encode()
     return b"([objectpath '/org/gnome/SessionManager/Inhibitor2'],)"
    if method.endswith('GetAppId'):return repr(('foreign' if startup_budget else 'amnezia-release-lab-'+('a'*48),)).encode()
   if '/usr/bin/python3' in args:return json.dumps({'dpms':{'level':0},'identityGap':None,'localPID':80}).encode()
   raise AssertionError(args)
  def observe(source):
   if fail:raise RuntimeError('original actual observer failure')
   counter['value']+=5000;o=sample(counter['value']);o.pop('pixels')
   return {'schema':'linux-desktop-live-probe-v1','journal_base64':'x'*(950001 if oversize else 1),'observation':o,'xres':{'dpms':{'level':0}}}
  def popen(args,**kw):
   self.assertIn('gnome-session-inhibit',args);self.assertIn('--inhibit',args);self.assertEqual(args[-1],str(guest.LEASE))
   c=original_popen(['/usr/bin/sleep','20'],start_new_session=True);children.append(c);return c
  def write(name,value):
   original_write(name,value)
   if name=='continuous-state.json' and value.get('phase')=='sampling' and value.get('dwellSpanMs',0)>=35000:
    original_write('continuous-capture.json',{'beforeMs':36000,'afterMs':37000,'bootID':BOOT,'sequence':8,'sha256':'a'*64,'size':100})
   if name=='continuous-state.json' and value.get('phase')=='sealed':original_write('continuous-stop.json',{'nonce':'a'*48})
  module=types.SimpleNamespace(command=command,observe=observe,process_identity=lambda pid:(shell,env),shell_identity_stable=lambda a,b:a==b)
  with patch.dict('sys.modules',{'inert_continuous_support':module}),patch.object(guest.subprocess,'Popen',side_effect=popen),patch.object(guest,'program_hash',return_value='a'*64),patch.object(guest,'write',side_effect=write),patch.object(guest.time,'sleep'),(patch.object(guest.time,'monotonic',side_effect=lambda:clock['value']) if startup_budget else contextlib.nullcontext()):
   try:guest.worker('from inert_continuous_support import command,observe,process_identity,shell_identity_stable','pinned XRes')
   finally:
    for c in children:
     self.assertIsNotNone(c.poll());self.assertFalse(Path('/proc',str(c.pid)).exists())
  return json.loads(guest.read('continuous-state.json'))

 def test_inhibitor_many_paths_retries_share_original_180s_budget(self):
  with self.assertRaisesRegex(RuntimeError,'180s command budget'):self.run_worker(startup_budget=True)
  saved=json.loads(guest.read('continuous-state.json'));self.assertEqual(saved['phase'],'failed');self.assertTrue(saved['inhibitorReaped'])

 def test_actual_worker_full_inert_protocol_retains_real_samples_and_reaps(self):
  result=self.run_worker();self.assertEqual(result['phase'],'stopped');self.assertTrue(result['inhibitorReaped'])
  raw=(self.root/'continuous-raw.jsonl').read_bytes();rows=[json.loads(v) for v in raw.splitlines()]
  self.assertEqual(rows[-1]['observation']['monotonic_ms'],40000);self.assertEqual(result['capture']['afterMs'],37000)
  self.assertEqual(result['inhibitor']['appID'],'amnezia-release-lab-'+('a'*48));self.assertEqual(len(rows),9)
 def test_actual_worker_observer_failure_keeps_original_and_cleanup(self):
  with self.assertRaisesRegex(RuntimeError,'original actual observer failure'):self.run_worker(fail=True)
  saved=json.loads(guest.read('continuous-state.json'));self.assertEqual(saved['phase'],'failed');self.assertTrue(saved['inhibitorReaped'])
 def test_actual_worker_raw_bound_rejects_before_large_write_and_reaps(self):
  with self.assertRaisesRegex(RuntimeError,'archive bounds'):self.run_worker(oversize=True)
  self.assertEqual((self.root/'continuous-raw.jsonl').stat().st_size,0)

 def test_actual_worker_cleanup_failure_does_not_mask_primary(self):
  original=guest.child_cleanup
  def cleanup(child,binding):original(child,binding);raise RuntimeError('secondary cleanup observation')
  with patch.object(guest,'child_cleanup',side_effect=cleanup),self.assertRaisesRegex(RuntimeError,'original actual observer failure'):
   self.run_worker(fail=True)
  saved=json.loads(guest.read('continuous-state.json'));self.assertEqual(saved['cleanupErrorType'],'RuntimeError');self.assertEqual(saved['phase'],'failed')

 def test_private_failure_state_write_cannot_mask_actual_observer_error(self):
  original=guest.write
  def write(name,value):
   if name=='continuous-state.json' and value.get('phase')=='failed':raise OSError('inert fsync failure')
   return original(name,value)
  with patch.object(guest,'write',side_effect=write),self.assertRaisesRegex(RuntimeError,'original actual observer failure') as caught:self.run_worker(fail=True)
  self.assertTrue(any('failure state unavailable' in n for n in caught.exception.__notes__))

 def test_actual_control_clock_capture_nonce_sequence_and_bounds(self):
  state={'phase':'sampling','worker':{'pid':123},'sampleCount':8}
  with patch.object(guest,'verified_state',return_value=state),patch.object(guest,'tick',side_effect=[36000,37000]):
   before=guest.control('clock',{});ack=guest.control('capture',{**before,'sha256':'a'*64,'size':100})
  self.assertEqual(ack['beforeMs'],36000);self.assertEqual(ack['afterMs'],37000)
  (self.root/'continuous-capture.json').unlink()
  for change in ({'sequence':9},{'sha256':'bad'},{'size':0}):
   with patch.object(guest,'verified_state',return_value=state),patch.object(guest,'tick',return_value=37000),self.assertRaises(RuntimeError):
    guest.control('capture',{**before,'sha256':'a'*64,'size':100,**change})
  with patch.object(guest,'verified_state',return_value=state),patch.object(guest,'tick',return_value=46001),self.assertRaises(RuntimeError):guest.control('capture',{**before,'sha256':'a'*64,'size':100})
  self.assertFalse((self.root/'continuous-capture.json').exists())

 def test_actual_control_archive_chunk_bounds_and_symlink(self):
  data=b'x'*70000;(self.root/'continuous-raw.jsonl').write_bytes(data);(self.root/'continuous-raw.jsonl').chmod(0o600)
  state={'phase':'sealed','rawSize':len(data)}
  with patch.object(guest,'verified_state',return_value=state):
   first=guest.control('archive',{'offset':0});last=guest.control('archive',{'offset':65536})
   self.assertEqual(len(base64.b64decode(first['data'])),32768);self.assertEqual(base64.b64decode(last['data']),data[65536:])
   for offset in (-1,len(data)+1,True):
    with self.assertRaises(RuntimeError):guest.control('archive',{'offset':offset})
   (self.root/'continuous-raw.jsonl').unlink();(self.root/'continuous-raw.jsonl').symlink_to(self.root/'marker')
   with self.assertRaises(OSError):guest.control('archive',{'offset':0})

 def test_actual_worker_pid_start_program_nonce_argv_validation(self):
  program='import time;time.sleep(20)'
  child=subprocess.Popen(['/usr/bin/python3','-c',program,'test','linux-x64-gui','a'*48,'observe','worker'])
  self.addCleanup(lambda:child.poll() is None and (child.kill(),child.wait()))
  record=guest.identity(child.pid)
  state={'phase':'sampling','worker':record,'nonce':'a'*48,'run':'test','programSHA256':'a'*64}
  guest.write('continuous-state.json',state)
  with patch.object(guest,'program_hash',return_value='a'*64):self.assertEqual(guest.verified_state()['worker'],record)
  for key,value in (('start','wrong'),('uid',1000)):
   broken=copy.deepcopy(state);broken['worker'][key]=value;guest.write('continuous-state.json',broken)
   with patch.object(guest,'program_hash',return_value='a'*64),self.assertRaises(RuntimeError):guest.verified_state()
  broken=copy.deepcopy(state);broken['nonce']='b'*48;guest.write('continuous-state.json',broken)
  with patch.object(guest,'program_hash',return_value='a'*64),self.assertRaises(RuntimeError):guest.verified_state()
  guest.write('continuous-state.json',state)
  with patch.object(guest,'program_hash',side_effect=lambda pid:'b'*64 if pid==child.pid else 'a'*64),self.assertRaises(RuntimeError):guest.verified_state()

 def test_foreign_pid_start_refuses_signal(self):
  child=subprocess.Popen(['/usr/bin/sleep','20'],start_new_session=True);self.addCleanup(lambda:child.poll() is None and (child.kill(),child.wait()))
  record=guest.identity(child.pid);record['start']='foreign'
  with self.assertRaises(RuntimeError):guest.child_cleanup(child,record)
  self.assertIsNone(child.poll())

if __name__=='__main__':unittest.main()
