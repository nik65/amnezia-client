"""Only privilege-rejection paths; never dispatch a valid root coordinator action."""
import json, os, subprocess, sys, unittest
BINARY=sys.argv.pop(1)
class Dispatch(unittest.TestCase):
    def test_reject_invalid_argv_before_storage(self):
        for args in ([],['unknown'],['status','extra']):
            p=subprocess.run([BINARY,'--rollback-coordinator',*args],capture_output=True,timeout=3)
            self.assertEqual(p.returncode,2)
    @unittest.skipUnless(os.name=='posix','POSIX privilege fixture')
    def test_unprivileged_never_touches_fixed_storage(self):
        def drop():
            if os.geteuid()==0:
                os.setgroups([]);os.setgid(65534);os.setuid(65534)
        for verb in ('status','run','resume'):
            p=subprocess.run([BINARY,'--rollback-coordinator',verb],capture_output=True,timeout=3,preexec_fn=drop)
            self.assertEqual(p.returncode,1)
            self.assertFalse(json.loads(p.stderr)['ok'])
if __name__=='__main__':unittest.main()
