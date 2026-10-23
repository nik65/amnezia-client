"""Actual CLI argv tests, only owned temp paths and private Unix sockets."""
from pathlib import Path
import json, os, socket, subprocess, sys, tempfile, threading, unittest

CLI = str(Path(sys.argv.pop(1)).resolve())

class CliFs(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.file = self.root/'file with spaces;$(false)'
        self.file.write_bytes(b'owned')
    def tearDown(self): self.tmp.cleanup()
    def run_cli(self, *args):
        return subprocess.run([CLI, *map(str,args)], capture_output=True, timeout=5)
    def test_exact_shift_and_no_shell(self):
        self.assertEqual(self.run_cli('--provisioning-fs','fsync-file',self.file).returncode,0)
        self.assertEqual(self.run_cli('--provisioning-fs','fsync-directory',self.root).returncode,0)
        for args in [(),('unknown',),('fsync-file',),('fsync-file',str(self.file),'extra'),('--version',)]:
            self.assertNotEqual(self.run_cli('--provisioning-fs',*args).returncode,0)
    def test_filesystem_rejections(self):
        link=self.root/'link';link.symlink_to(self.file)
        fifo=self.root/'fifo';os.mkfifo(fifo)
        for path in [link,fifo,self.root/'missing',self.root]:
            self.assertNotEqual(self.run_cli('--provisioning-fs','fsync-file',path).returncode,0)
    def test_native_elf(self):
        data=bytearray(20);data[:6]=b'\x7fELF\x02\x01';data[18:20]=(62).to_bytes(2,'little')
        self.file.write_bytes(data)
        self.assertEqual(self.run_cli('--provisioning-fs','verify-elf64-x86-64',self.file).returncode,0)
        data[18]=0;self.file.write_bytes(data)
        self.assertNotEqual(self.run_cli('--provisioning-fs','verify-elf64-x86-64',self.file).returncode,0)
    def test_journal_bad_arity_never_mutates(self):
        self.assertNotEqual(self.run_cli('--provisioning-fs','journal-write').returncode,0)
        self.assertNotEqual(self.run_cli('--provisioning-fs','journal-unknown').returncode,0)
    def test_normal_version_help_and_unknown_unchanged(self):
        version=self.run_cli('--version')
        self.assertEqual(version.returncode,0);self.assertIn(b'5.0.3.14',version.stdout)
        self.assertEqual(self.run_cli('--help').returncode,0)
        self.assertEqual(self.run_cli('unknown').returncode,2)
        self.assertNotEqual(self.run_cli('--provisioning-fs-typo','fsync-file',self.file).returncode,0)
    def test_normal_status_uses_only_owned_socket(self):
        path=str(self.root/'private.sock');listener=socket.socket(socket.AF_UNIX);listener.bind(path);listener.listen(1)
        seen=[]
        def serve():
            connection,_=listener.accept()
            with connection:
                frame=b''
                while b'\n' not in frame: frame+=connection.recv(65536)
                request=json.loads(frame);seen.append(request)
                connection.sendall((json.dumps({'ok':True,'result':{'state':'owned-fixture'}})+'\n').encode())
        thread=threading.Thread(target=serve,daemon=True);thread.start()
        try:
            result=self.run_cli('--socket',path,'status');thread.join(2)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn(b'owned-fixture',result.stdout);self.assertEqual(len(seen),1)
            self.assertEqual(seen[0]['command'],'status')
        finally: listener.close()

if __name__=='__main__': unittest.main()
