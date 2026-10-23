"""Real POSIX descriptor tests. Only fresh root-owned /tmp fixtures are used."""
import ast
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import shutil
import stat
import sys
import unittest
from unittest.mock import patch

SOURCE=Path(__file__).with_name('linux_headless_driver.py')
PROGRAM=next(ast.literal_eval(node.value) for node in ast.parse(SOURCE.read_text()).body if isinstance(node,ast.Assign) and any(isinstance(x,ast.Name) and x.id=='PIN_STAGED_HELPER' for x in node.targets))
DATA=b'controlled inert helper fixture\n'


@unittest.skipUnless(os.name=="posix" and hasattr(os,"geteuid") and os.geteuid()==0, "requires POSIX root for isolated mode/owner syscall tests")
class DescriptorStaging(unittest.TestCase):
    def setUp(self):
        self.assertEqual(os.geteuid(),0,'run only as WSL root; no user/production paths')
        self.nonce=secrets.token_hex(24);self.root=Path('/tmp')/('amnezia-headless-helper-'+self.nonce)
        self.root.mkdir(mode=0o700);self.paths=[self.root]
        self.helper=self.root/'helper.py';self.helper.write_bytes(DATA);self.helper.chmod(0o666)
        self.digest=hashlib.sha256(DATA).hexdigest()
        self.addCleanup(self.cleanup_fixture)

    def cleanup_fixture(self):
        for path in reversed(self.paths):
            if str(path.parent)!='/tmp' or not path.name.startswith('amnezia-headless-helper-'):raise RuntimeError('refusing nonfixture cleanup')
            if path.is_symlink():path.unlink()
            elif path.exists():shutil.rmtree(path)

    def execute(self,*,digest=None,size=None,path=None,nonce=None):
        argv=['<inert-staging-program>',str(path or self.helper),digest or self.digest,str(len(DATA) if size is None else size),nonce or self.nonce]
        output=io.StringIO()
        with patch.object(sys,'argv',argv),contextlib.redirect_stdout(output):exec(compile(PROGRAM,'<staging-program>','exec'),{})
        return json.loads(output.getvalue())

    def test_real_0666_file_becomes0600_with_exact_same_inode_and_bytes(self):
        before=self.helper.stat();result=self.execute();after=self.helper.stat()
        self.assertEqual((before.st_dev,before.st_ino),(after.st_dev,after.st_ino))
        self.assertEqual(stat.S_IMODE(after.st_mode),0o600);self.assertEqual(self.helper.read_bytes(),DATA)
        self.assertEqual(result['mode'],'0600');self.assertEqual(result['sha256'],self.digest)
        self.assertTrue(result['same_descriptor_verified'])

    def test_already_private_file_remains_valid(self):
        self.helper.chmod(0o600);self.assertEqual(self.execute()['mode'],'0600')

    def test_current_source_helper_bytes_become_private(self):
        original=SOURCE.parent/'headless_preexisting_fixture_guest.py'
        data=original.read_bytes();digest=hashlib.sha256(data).hexdigest()
        self.assertEqual(digest,'2583eeb9a72195f274c60360e68d412e4840fe9cc8dd8e71b8c31d2b328f1bbd')
        self.assertEqual(len(data),64685)
        self.helper.write_bytes(data);self.helper.chmod(0o666)
        result=self.execute(digest=digest,size=len(data))
        self.assertEqual(result['mode'],'0600');self.assertEqual(self.helper.read_bytes(),data)

    def test_wrong_hash_has_no_permission_mutation(self):
        with patch.object(os,'fchmod',wraps=os.fchmod) as chmod,self.assertRaises(SystemExit):self.execute(digest='f'*64)
        chmod.assert_not_called();self.assertEqual(stat.S_IMODE(self.helper.stat().st_mode),0o666)

    def test_wrong_size_has_no_permission_mutation(self):
        with patch.object(os,'fchmod',wraps=os.fchmod) as chmod,self.assertRaises(SystemExit):self.execute(size=len(DATA)+1)
        chmod.assert_not_called();self.assertEqual(stat.S_IMODE(self.helper.stat().st_mode),0o666)

    def test_nonroot_owner_rejected_without_chmod(self):
        os.chown(self.helper,65534,65534)
        with patch.object(os,'fchmod',wraps=os.fchmod) as chmod,self.assertRaises(SystemExit):self.execute()
        chmod.assert_not_called();self.assertEqual(stat.S_IMODE(self.helper.stat().st_mode),0o666)

    def test_symlink_file_target_never_chmodded(self):
        target=self.root/'target';self.helper.rename(target);self.helper.symlink_to(target)
        with patch.object(os,'fchmod',wraps=os.fchmod) as chmod,self.assertRaises(OSError):self.execute()
        chmod.assert_not_called();self.assertEqual(stat.S_IMODE(target.stat().st_mode),0o666)

    def test_hardlink_file_rejected_without_chmod(self):
        target=self.root/'second-link';os.link(self.helper,target)
        with patch.object(os,'fchmod',wraps=os.fchmod) as chmod,self.assertRaises(SystemExit):self.execute()
        chmod.assert_not_called();self.assertEqual(stat.S_IMODE(target.stat().st_mode),0o666)

    def test_fifo_rejected_without_blocking_or_chmod(self):
        self.helper.unlink();os.mkfifo(self.helper,0o666);self.helper.chmod(0o666)
        with patch.object(os,'fchmod',wraps=os.fchmod) as chmod,self.assertRaises(SystemExit):self.execute()
        chmod.assert_not_called();self.assertTrue(stat.S_ISFIFO(self.helper.lstat().st_mode))

    def test_world_writable_parent_rejected_without_chmod(self):
        self.root.chmod(0o777)
        with patch.object(os,'fchmod',wraps=os.fchmod) as chmod,self.assertRaises(SystemExit):self.execute()
        chmod.assert_not_called();self.assertEqual(stat.S_IMODE(self.helper.stat().st_mode),0o666)

    def test_symlink_parent_rejected_without_touching_target(self):
        target=self.root.with_name(self.root.name+'-owned-target');self.root.rename(target);self.paths.append(target);self.root.symlink_to(target,target_is_directory=True)
        with patch.object(os,'fchmod',wraps=os.fchmod) as chmod,self.assertRaises(OSError):self.execute()
        chmod.assert_not_called();self.assertEqual(stat.S_IMODE((target/'helper.py').stat().st_mode),0o666)

    def test_nonpinned_path_rejected_before_open_or_chmod(self):
        with patch.object(os,'fchmod',wraps=os.fchmod) as chmod,self.assertRaises(SystemExit):self.execute(path=self.root/'other.py')
        chmod.assert_not_called()

    def test_path_swap_during_fchmod_is_rejected_and_replacement_untouched(self):
        original_fchmod=os.fchmod;saved=self.root/'verified-original'
        def swap(fd,mode):
            self.helper.rename(saved);self.helper.write_bytes(DATA);self.helper.chmod(0o666);original_fchmod(fd,mode)
        with patch.object(os,'fchmod',side_effect=swap),self.assertRaisesRegex(SystemExit,'path changed'):self.execute()
        self.assertEqual(stat.S_IMODE(self.helper.stat().st_mode),0o666)
        self.assertEqual(stat.S_IMODE(saved.stat().st_mode),0o600)

    def test_parent_swap_during_fchmod_is_rejected(self):
        original_fchmod=os.fchmod;saved=self.root.with_name(self.root.name+'-verified-original');self.paths.append(saved)
        def swap(fd,mode):
            self.root.rename(saved);self.root.mkdir(mode=0o700);self.helper.write_bytes(DATA);self.helper.chmod(0o666);original_fchmod(fd,mode)
        with patch.object(os,'fchmod',side_effect=swap),self.assertRaisesRegex(SystemExit,'parent changed'):self.execute()
        self.assertEqual(stat.S_IMODE(self.helper.stat().st_mode),0o666)

    def test_same_fd_is_verified_and_chmodded_only_once(self):
        original_open=os.open;opened=[]
        def observe(path,flags,*args,**kwargs):
            fd=original_open(path,flags,*args,**kwargs)
            if path=='helper.py':opened.append(fd)
            return fd
        with patch.object(os,'open',side_effect=observe),patch.object(os,'fchmod',wraps=os.fchmod) as chmod,patch.object(os,'read',wraps=os.read) as read:
            self.execute()
        self.assertEqual(len(opened),1);chmod.assert_called_once_with(opened[0],0o600)
        self.assertGreaterEqual(read.call_count,2)
        self.assertEqual({call.args[0] for call in read.call_args_list},{opened[0]})


if __name__=='__main__':unittest.main(verbosity=2)
