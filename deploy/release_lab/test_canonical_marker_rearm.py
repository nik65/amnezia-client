import ast,json,hashlib,os,sys,subprocess,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
SOURCE=Path(__file__).with_name('headless_coordinated_rollback_collector.py');tree=ast.parse(SOURCE.read_text())
program=next(ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='CANONICAL_MARKER_REARM' for t in n.targets))
@unittest.skipUnless(os.name=='posix' and os.getuid()==0,'actual root POSIX files')
class Guest(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(dir='/root');self.parent=Path(self.temp.name);self.parent.chmod(0o1777);self.path=self.parent/'amnezia-release-lab-marker';self.boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
  self.program=program.replace("os.open('tmp',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=root)","os.open("+repr(str(self.parent))+",os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)").replace("os.open('/tmp',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)","os.open("+repr(str(self.parent))+",os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)")
 def tearDown(self):self.temp.cleanup()
 def run_guest(self,boot=None,ok=True):
  response=subprocess.run([sys.executable,'-c',self.program,'a14','linux-headless-x64',boot or self.boot],capture_output=True,timeout=5)
  if ok:self.assertEqual(response.returncode,0,response.stderr.decode());return json.loads(response.stdout)
  self.assertNotEqual(response.returncode,0);return response
 def test_create600_exact_and_existing_reuse_same_inode_for_both_boot_calls(self):
  old=os.umask(0)
  try:
   first=self.run_guest();second=self.run_guest()
   self.assertTrue(first['created']);self.assertFalse(second['created']);self.assertEqual(first['ino'],second['ino'])
   self.assertEqual(self.path.read_bytes(),b'amnezia-release-lab:a14:linux-headless-x64');self.assertEqual(self.path.stat().st_mode&0o777,0o600)
  finally:os.umask(old)
 def test_wrong_boot_does_not_create_marker(self):
  self.run_guest('wrong',False);self.assertFalse(self.path.exists())
 def test_foreign_bytes_mode_uid_hardlink_symlink_directory_never_overwritten(self):
  for mutation in ('content','mode','uid','hardlink','symlink','directory'):
   with self.subTest(mutation=mutation):
    for p in self.parent.iterdir():
     if p.is_dir() and not p.is_symlink():p.rmdir()
     else:p.unlink()
    self.run_guest()
    if mutation=='content':self.path.write_bytes(b'foreign')
    elif mutation=='mode':self.path.chmod(0o666)
    elif mutation=='uid':os.chown(self.path,12345,0)
    elif mutation=='hardlink':os.link(self.path,self.parent/'other')
    elif mutation=='symlink':self.path.rename(self.parent/'other');self.path.symlink_to(self.parent/'other')
    else:self.path.unlink();self.path.mkdir()
    before=self.path.lstat();self.run_guest(ok=False);after=self.path.lstat();self.assertEqual(before.st_ino,after.st_ino)
 def test_wrong_parent_mode_rejected_before_create(self):
  self.parent.chmod(0o777);self.run_guest(ok=False);self.assertFalse(self.path.exists())
class Ordering(unittest.TestCase):
 def collector(self,receipt):
  base=type('Base',(),{'reboot_and_collect':Mock(return_value=receipt)})
  original=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='CoordinatedRebootCollector')
  method=next(n for n in original.body if isinstance(n,ast.FunctionDef) and n.name=='reboot_and_collect')
  node=ast.ClassDef(name=original.name,bases=original.bases,keywords=[],body=[method],decorator_list=[])
  scope={'OwnedRebootCollector':base,'CANONICAL_MARKER_REARM':program,'hashlib':hashlib,'json':json,'CoordinatedCollectionError':RuntimeError}
  exec(compile(ast.fix_missing_locations(ast.Module(body=[node],type_ignores=[])),'staged','exec'),scope)
  instance=scope['CoordinatedRebootCollector']();instance.plan=SimpleNamespace(run_id='a14');instance._check=Mock();instance.native=Mock()
  return instance,base
 def test_superclass_failure_never_rearms_and_standardbase_unchanged(self):
  instance,base=self.collector({});base.reboot_and_collect.side_effect=ValueError('nonce failed')
  with self.assertRaises(ValueError):instance.reboot_and_collect('old',object())
  instance.native._exec.assert_not_called()
 def test_same_boot_never_rearms(self):
  instance,_=self.collector({'boot_id_after':'old'})
  with self.assertRaises(RuntimeError):instance.reboot_and_collect('old',object())
  instance.native._exec.assert_not_called()
 def test_newboot_only_exact_evidence_and_original_fields_preserved(self):
  original={'boot_id_before':'old','boot_id_after':'new','after_raw':{'actual':1},'raw_sources':{'persistent_marker':{'nonce':'actual'}}};instance,base=self.collector(original)
  data=b'amnezia-release-lab:a14:linux-headless-x64';proof={'boot_id':'new','run_id':'a14','profile_id':'linux-headless-x64','path':'/tmp/amnezia-release-lab-marker','sha256':hashlib.sha256(data).hexdigest(),'size':len(data),'uid':0,'gid':0,'mode':0o600,'nlink':1}
  instance.native._exec.return_value={'exitcode':0,'stdout':json.dumps(proof)};result=instance.reboot_and_collect('old',object())
  self.assertEqual(result['after_raw'],original['after_raw']);self.assertEqual(result['raw_sources']['persistent_marker'],original['raw_sources']['persistent_marker']);self.assertNotIn('canonical_marker_rearm',original['raw_sources'])
  self.assertEqual(result['raw_sources']['canonical_marker_rearm'],proof)
  for key,value in [('boot_id','old'),('uid',False),('mode',0o666),('sha256','bad')]:
   instance.native._exec.return_value={'exitcode':0,'stdout':json.dumps({**proof,key:value})}
   with self.assertRaises(RuntimeError):instance.reboot_and_collect('old',object())
 def test_nonzero_and_boolean_exit_cannot_accept_valid_json(self):
  for code in (1,False):
   instance,_=self.collector({'boot_id_after':'new','raw_sources':{}});instance.native._exec.return_value={'exitcode':code,'stdout':'{}'}
   with self.assertRaisesRegex(RuntimeError,'guest command failed'):instance.reboot_and_collect('old',object())
 def test_both_reboots_and_http_cleanup_share_marker_gate(self):
  collector=SOURCE.read_text();driver=Path('deploy/release_lab/headless_coordinated_rollback_driver.py').read_text();http=Path('deploy/release_lab/headless_coordinated_http_fixture.py').read_text()
  self.assertIn('reboot = CoordinatedRebootCollector(',driver);self.assertIn('old.native, reboot,',driver)
  self.assertIn('self.reboot.reboot_and_collect(',collector);self.assertIn('action=sys.argv[2];marker(cfg)',http)
if __name__=='__main__':unittest.main()
