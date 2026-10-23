"""Actual POSIX temporary files, inert fake QGA only; no release guest."""
import ast,hashlib,json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import Mock
SOURCE=Path(__file__).with_name('linux_headless_driver.py')
tree=ast.parse(SOURCE.read_text());program=next(ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='PROTECTED_INPUT_PROGRAM' for t in n.targets))
NONCE='a'*48
@unittest.skipUnless(os.name=='posix' and os.getuid()==0,'actual root POSIX fixture descriptors')
class Inputs(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(dir='/root');self.parent=Path(self.temp.name);os.chmod(self.parent,0o700)
  self.names=[NONCE+'-manifest.json',NONCE+'-candidate.tar.gz'];self.body=b'exact signed bytes';self.expected={n:{'size':len(self.body),'sha256':hashlib.sha256(self.body).hexdigest()} for n in self.names}
  self.program=program.replace("parent!='/var/lib/amnezia-release-lab/fixture'",'parent!='+repr(str(self.parent)))
 def tearDown(self):self.temp.cleanup()
 def run_action(self,action,pins=None,ok=True):
  result=subprocess.run([sys.executable,'-c',self.program,action,NONCE,str(self.parent),json.dumps(self.expected),json.dumps(pins or {})],capture_output=True,timeout=5)
  if ok:self.assertEqual(result.returncode,0,result.stderr.decode());return json.loads(result.stdout)
  self.assertNotEqual(result.returncode,0);return result
 def prepare(self):
  pins=self.run_action('prepare')
  for name in self.names:
   with open(self.parent/name,'wb') as stream:stream.write(self.body)
  return pins
 def test_old_new_file_open_w_is_0666_but_precreate_preserves_0600(self):
  old=os.umask(0)
  try:
   path=self.parent/'legacy';path.open('wb').close();self.assertEqual(path.stat().st_mode&0o777,0o666)
   pins=self.prepare();self.run_action('verify',pins)
   self.assertTrue(all((self.parent/n).stat().st_mode&0o777==0o600 for n in self.names))
  finally:os.umask(old)
 def test_hash_size_mode_uid_link_symlink_and_foreign_inode_rejected(self):
  for mutation in ('hash','size','mode','uid','link','symlink','foreign'):
   with self.subTest(mutation=mutation):
    for p in self.parent.iterdir():p.unlink()
    pins=self.prepare();path=self.parent/self.names[0]
    if mutation=='hash':path.write_bytes(b'X'*len(self.body))
    elif mutation=='size':path.write_bytes(b'x')
    elif mutation=='mode':path.chmod(0o666)
    elif mutation=='uid':path.chown(12345,0) if hasattr(path,'chown') else os.chown(path,12345,0)
    elif mutation=='link':os.link(path,self.parent/'extra')
    elif mutation=='symlink':path.rename(self.parent/'extra');path.symlink_to(self.parent/'extra')
    else:path.rename(self.parent/'extra');path.write_bytes(self.body);path.chmod(0o600)
    self.run_action('verify',pins,False)
 def test_exclusive_prepare_does_not_overwrite_and_partial_cleanup_is_owned(self):
  second=self.parent/self.names[1];second.write_bytes(b'foreign')
  self.run_action('prepare',ok=False)
  self.assertFalse((self.parent/self.names[0]).exists());self.assertEqual(second.read_bytes(),b'foreign')
 def test_cleanup_deletes_owned_and_refuses_foreign_swap(self):
  pins=self.prepare();first=self.parent/self.names[0];first.rename(self.parent/'old');first.write_bytes(b'foreign');first.chmod(0o600)
  self.run_action('cleanup',pins,False);self.assertEqual(first.read_bytes(),b'foreign')
  first.unlink();(self.parent/'old').rename(first);self.run_action('cleanup',pins)
  self.assertFalse(first.exists());self.assertFalse((self.parent/self.names[1]).exists())
 def test_private_parent_and_symlink_ancestor_rejected(self):
  self.parent.chmod(0o755);self.run_action('prepare',ok=False)
  self.parent.chmod(0o700)
  link=self.parent/'link';link.symlink_to(self.parent,target_is_directory=True)
  modified=self.program.replace('parent!='+repr(str(self.parent)),'parent!='+repr(str(link)))
  result=subprocess.run([sys.executable,'-c',modified,'prepare',NONCE,str(link),json.dumps(self.expected),'{}'],capture_output=True,timeout=5)
  self.assertNotEqual(result.returncode,0)
class Host(unittest.TestCase):
 def test_legacy_default_false_and_only_coordinated_opts_in(self):
  source=SOURCE.read_text();ast.parse(source)
  self.assertIn('*,protected_fixture_inputs=False',source)
  self.assertIn('protected_fixture_inputs=True',SOURCE.with_name('headless_coordinated_rollback_driver.py').read_text())
 def test_write_failure_keeps_primary_and_attempts_owned_cleanup(self):
  node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='_write_protected_fixture_inputs')
  scope={'Path':Path,'hashlib':hashlib,'json':json,'PROTECTED_INPUT_PROGRAM':program,'HeadlessDriverError':RuntimeError}
  exec(compile(ast.Module(body=[node],type_ignores=[]),'staged-host','exec'),scope)
  qga=Mock();qga.guest_exec_wait.side_effect=[{'exitcode':0,'stdout':'{"parent":[],"files":{}}'},OSError('secondary')]
  primary=ValueError('primary write');qga.write_file.side_effect=primary
  with self.assertRaises(ValueError) as caught:scope['_write_protected_fixture_inputs'](qga,Mock(),NONCE,'/fixed',[(NONCE+'-manifest.json',b'a'),(NONCE+'-candidate.tar.gz',b'b')])
  self.assertIs(caught.exception,primary);self.assertEqual(qga.guest_exec_wait.call_args.args[1][2],'cleanup')
  self.assertIn('OSError',primary.__notes__[0])
if __name__=='__main__':unittest.main()
