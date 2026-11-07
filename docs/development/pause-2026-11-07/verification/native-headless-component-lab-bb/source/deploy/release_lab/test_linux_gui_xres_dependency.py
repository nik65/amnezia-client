"""Actual dependency guard/file operations; package commands are inert fixtures."""
from pathlib import Path
import base64,contextlib,io,json,os,stat,tempfile,types,unittest
from unittest.mock import Mock,patch
from .guest_helpers import linux_gui_xres_dependency as guest

@unittest.skipUnless(os.name=='posix' and os.geteuid()==0,'actual root-owned private descriptor fixtures')
class DependencyTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name);self.root.chmod(0o700)
  self.tmp=self.root/'tmp';self.tmp.mkdir(mode=0o1777);self.tmp.chmod(0o1777);self.canonical=self.tmp/'amnezia-release-lab-marker'
  self.run='owned-xres-test';self.profile='linux-x64-gui';self.nonce='a'*48
  (self.root/'marker').write_text(json.dumps({'run_id':self.run,'profile':self.profile,'nonce':self.nonce},sort_keys=True));(self.root/'marker').chmod(0o600)
  self.canonical.write_text('amnezia-release-lab:'+self.run+':'+self.profile);self.canonical.chmod(0o600)
  self.original_open=os.open
  def mapped_open(path,flags,*args,**kw):
   if str(path)=='/tmp':path=self.tmp
   if str(path)=='/run/amnezia-release-lab-fixture-'+self.nonce:path=self.root
   if str(path)=='/tmp/amnezia-release-lab-marker':path=self.canonical
   return self.original_open(path,flags,*args,**kw)
  self.mapper=patch.object(guest.os,'open',side_effect=mapped_open);self.mapper.start();self.addCleanup(self.mapper.stop)
  package=Path(__file__).resolve().parents[2]/'dist/release-lab-fixtures/gui-xres-noble-amd64-20261023/libxres1_1.2.1-1build1_amd64.deb'
  self.encoded=base64.b64encode(package.read_bytes()).decode()

 def test_actual_private_context_refuses_wrong_marker_owner_and_symlink(self):
  fd=guest.context(self.run,self.profile,self.nonce);os.close(fd)
  self.canonical.write_text('foreign-run')
  with self.assertRaises(RuntimeError):guest.context(self.run,self.profile,self.nonce)
  self.canonical.write_text('amnezia-release-lab:'+self.run+':'+self.profile)
  os.chown(self.root,1000,1000)
  with self.assertRaises(RuntimeError):guest.context(self.run,self.profile,self.nonce)
  os.chown(self.root,0,0);(self.root/'marker').unlink();(self.root/'marker').symlink_to(self.canonical)
  with self.assertRaises(OSError):guest.context(self.run,self.profile,self.nonce)

 def test_qga_0666_marker_replaced_with_fresh_private_inode(self):
  self.canonical.chmod(0o666);old=self.canonical.stat().st_ino
  writable=self.original_open(self.canonical,os.O_WRONLY)
  try:
   evidence={};fd=guest.context(self.run,self.profile,self.nonce,evidence);os.close(fd)
   self.assertEqual(evidence['beforeMode'],'0o666');self.assertTrue(evidence['replaced']);self.assertEqual(evidence['beforeInode'],old);self.assertEqual(evidence['afterInode'],self.canonical.stat().st_ino)
   self.assertNotEqual(old,self.canonical.stat().st_ino)
   self.assertEqual(stat.S_IMODE(self.canonical.stat().st_mode),0o600)
   os.write(writable,b'foreign old inode')
   self.assertEqual(self.canonical.read_text(),'amnezia-release-lab:'+self.run+':'+self.profile)
  finally:os.close(writable)
  self.assertEqual(list(self.tmp.iterdir()),[self.canonical])

 def test_wrong_bytes_symlink_hardlink_and_parent_refuse_replacement(self):
  expected=self.canonical.read_bytes()
  self.canonical.chmod(0o666);self.canonical.write_bytes(expected+b'\n')
  with self.assertRaises(RuntimeError):guest.context(self.run,self.profile,self.nonce)
  self.canonical.write_bytes(expected);os.link(self.canonical,self.tmp/'link')
  with self.assertRaises(RuntimeError):guest.context(self.run,self.profile,self.nonce)
  (self.tmp/'link').unlink();self.tmp.chmod(0o777)
  with self.assertRaises(RuntimeError):guest.context(self.run,self.profile,self.nonce)
  self.tmp.chmod(0o1777);self.canonical.unlink();self.canonical.symlink_to(self.root/'marker')
  with self.assertRaises(OSError):guest.context(self.run,self.profile,self.nonce)

 def test_marker_path_race_refused_and_private_staging_cleaned(self):
  self.canonical.chmod(0o666);original_stat=os.stat
  def raced(path,*args,**kwargs):
   if path=='amnezia-release-lab-marker':
    self.canonical.unlink();self.canonical.write_text('foreign')
   return original_stat(path,*args,**kwargs)
  with patch.object(guest.os,'stat',side_effect=raced),self.assertRaises(RuntimeError):guest.context(self.run,self.profile,self.nonce)
  self.assertEqual(self.canonical.read_text(),'foreign')
  self.assertEqual(list(self.tmp.iterdir()),[self.canonical])

 def test_staging_collision_never_removes_existing_directory(self):
  self.canonical.chmod(0o666);foreign=self.tmp/('.amnezia-marker-'+('00'*24));foreign.mkdir(mode=0o700)
  (foreign/'foreign').write_text('preserve')
  with patch.object(guest.os,'urandom',return_value=bytes(24)),self.assertRaises(FileExistsError):guest.context(self.run,self.profile,self.nonce)
  self.assertEqual((foreign/'foreign').read_text(),'preserve')

 def test_context_failure_keeps_partial_report_before_original_error(self):
  output=io.StringIO()
  with patch.object(guest,'context',side_effect=RuntimeError('marker failure')),contextlib.redirect_stdout(output),self.assertRaisesRegex(RuntimeError,'marker failure'):
   guest.ensure_dependency(self.run,self.profile,self.nonce,self.encoded,'','')
  saved=json.loads(output.getvalue());self.assertEqual(saved['errorStage'],'owned-marker-context');self.assertNotIn('verified',saved)

 def test_wrong_package_never_calls_context_or_subprocess(self):
  with patch.object(guest,'context') as context:
   with self.assertRaises(RuntimeError):guest.ensure_dependency(self.run,self.profile,self.nonce,base64.b64encode(b'wrong').decode(),'','')
   context.assert_not_called()

 def execute(self,*,bad_post=False,install_fails=False,already=False,wrong_pid=False):
  calls=[];counts={'loader':0,'status':0};identity={'pid':1262,'uid':1000,'exe':'/usr/bin/gnome-shell','start_ticks':100,'state':'S'}
  valid={'findLibrary':'libXRes.so.1','cdllLoaded':True,'fileSHA256':guest.LIBRARY_SHA256,'mappedPaths':[guest.LIBRARY]}
  env={b'GALLIUM_DRIVER':b'softpipe',b'DISPLAY':b':0',b'XAUTHORITY':b'/run/user/1000/gdm/Xauthority'}
  def command(args,**kw):
   calls.append(args);self.assertLessEqual(kw['timeout'],30);self.assertEqual(kw['limit'],8192)
   if args[0]=='dpkg-query':
    counts['status']+=1;return (('install ok installed\t'+guest.PACKAGE_VERSION+'\tamd64') if already or counts['status']>1 else '').encode()
   if args[:2]==['/usr/bin/python3','-c']:
    counts['loader']+=1
    return json.dumps(valid if already or (counts['loader']>1 and not bad_post) else {'findLibrary':None,'cdllLoaded':False}).encode()
   if args[:2]==['dpkg','--install']:
    self.assertEqual(args[2],'/run/amnezia-release-lab-fixture-'+self.nonce+'/libxres1.deb')
    if install_fails:raise RuntimeError('inert install failure')
    return b'inert standard-package install'
   if args[0]=='pgrep':return b'1262\n'
   if args[0]=='runuser':return json.dumps({'identityGap':None,'localPID':999 if wrong_pid else 1262}).encode()
   raise AssertionError(args)
  support=types.SimpleNamespace(command=command,process_identity=lambda pid:(identity,env),shell_identity_stable=lambda a,b:a==b)
  with patch.object(guest,'configure_session_policy',side_effect=lambda execute,prefix,deadline,report:report.update({'inertPolicy':True})), patch.dict('sys.modules',{'inert_xres_support':support}), patch.object(guest,'install_attempt',side_effect=lambda args,timeout:{'exitcode':0,'timeout':False,'overflow':False,'stdout':command(args,timeout=timeout,limit=8192),'stderr':b''}):
   result=guest.ensure_dependency(self.run,self.profile,self.nonce,self.encoded,'from inert_xres_support import command,process_identity,shell_identity_stable','inert pinned XRes')
  return result,calls

 def test_exact_package_written_private_then_loader_and_actual_pid_proof(self):
  result,calls=self.execute();self.assertTrue(result['verified']);self.assertTrue(result['installedExactPackage'])
  self.assertEqual(stat.S_IMODE((self.root/'libxres1.deb').stat().st_mode),0o600)
  self.assertEqual(len([c for c in calls if c[0]=='dpkg']),1)
 def test_already_exact_loader_still_checks_package_and_pid_without_install(self):
  result,calls=self.execute(already=True);self.assertTrue(result['verified']);self.assertFalse(result['installedExactPackage']);self.assertFalse(any(c[0]=='dpkg' for c in calls))
 def test_failed_postloader_never_claims_success(self):
  output=io.StringIO()
  with contextlib.redirect_stdout(output),self.assertRaises(RuntimeError):self.execute(bad_post=True)
  saved=json.loads(output.getvalue());self.assertFalse(saved['loaderAfter']['cdllLoaded']);self.assertNotIn('verified',saved)
 def test_install_failure_retains_before_diagnostics(self):
  output=io.StringIO()
  with contextlib.redirect_stdout(output),self.assertRaises(RuntimeError):self.execute(install_fails=True)
  self.assertIn('loaderBefore',json.loads(output.getvalue()))
 def test_wrong_actual_xres_pid_stays_failure(self):
  output=io.StringIO()
  with contextlib.redirect_stdout(output),self.assertRaises(RuntimeError):self.execute(wrong_pid=True)
  self.assertNotIn('verified',json.loads(output.getvalue()))

if __name__=='__main__':unittest.main()
