"""Actual private-file producer -> transport-free validator regressions."""
from copy import deepcopy
import hashlib
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from . import headless_preexisting_fixture as contract
from .headless_preexisting_fixture_guest import GuestError,strace_shard_summary

TARGET={'pid':250,'start_ticks':123,'exe_sha256':'a'*64}
SCOPE=['execve','exit','exit_group','write']


@unittest.skipUnless(os.name=='posix' and getattr(os,'geteuid',lambda:1)()==0,'actual root-owned private files require POSIX root')
class StraceContractTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);os.chmod(self.root,0o700)

    def shard(self,pid,body):
        path=self.root/f'pre-disconnect-strace.{pid}';path.write_bytes(body);path.chmod(0o600)
        return path

    def produce(self):
        shards,coverage=strace_shard_summary(self.root,'pre-disconnect-strace',TARGET,TARGET)
        return {'available':True,'reason':'attached','scope':list(SCOPE),'duration_limit_seconds':30,'shards':shards,'coverage':coverage}

    def validate(self,trace):
        contract.validate_strace_evidence(str(self.root),TARGET,trace)

    def test_empty_leader_and_real_worker_syscalls_accepted_without_daemon_exit(self):
        self.shard(250,b'')
        body=b'write(7, "disconnect request\\n", 19) = 19\n'
        self.shard(251,body)
        trace=self.produce();self.validate(trace)
        self.assertEqual(trace['shards'][0]['size'],0)
        self.assertEqual(trace['shards'][0]['sha256'],hashlib.sha256(b'').hexdigest())
        self.assertEqual(trace['coverage']['files'][1]['syscalls']['write'],1)
        self.assertEqual(trace['coverage']['files'][1]['process_exits'],[])
        self.assertEqual(trace['shards'][1]['sha256'],hashlib.sha256(body).hexdigest())

    def test_thread_exit_alone_is_legitimate_scoped_coverage(self):
        self.shard(250,b'');self.shard(251,b'exit(0) = ?\n+++ exited with 0 +++\n')
        trace=self.produce();self.validate(trace)
        self.assertEqual(trace['coverage']['files'][1]['syscalls']['exit'],1)
        self.assertEqual(trace['coverage']['files'][1]['process_exits'],[0])

    def test_all_empty_or_only_unscoped_text_rejected(self):
        self.shard(250,b'');self.shard(251,b'')
        with self.assertRaises(contract.FixtureError):self.validate(self.produce())
        self.shard(251,b'--- SIGTERM {si_signo=SIGTERM} ---\n')
        with self.assertRaises(contract.FixtureError):self.validate(self.produce())

    def test_actual_wrong_target_and_unsafe_files_rejected(self):
        path=self.shard(250,b'write(1, "x", 1) = 1\n')
        with self.assertRaises(GuestError):
            strace_shard_summary(self.root,'pre-disconnect-strace',TARGET,{**TARGET,'start_ticks':124})
        path.chmod(0o666)
        with self.assertRaises(GuestError):self.produce()
        path.chmod(0o600);os.chown(path,1234,0)
        with self.assertRaises(GuestError):self.produce()
        os.chown(path,0,0);path.unlink();os.mkfifo(path)
        with self.assertRaises(GuestError):self.produce()
        path.unlink();path.symlink_to('/dev/null')
        with self.assertRaises(OSError):self.produce()

    def test_metadata_bool_negative_path_hash_uid_mode_and_identity_rejected(self):
        self.shard(250,b'');self.shard(251,b'write(1, "x", 1) = 1\n')
        original=self.produce()
        for field,value in (('size',-1),('size',False),('uid',True),('uid',1),('gid',1),('mode',0o644),('sha256','invalid'),('sha256','b'*64),('path',str(self.root)+'/../escape')):
            bad=deepcopy(original);bad['shards'][0][field]=value
            with self.subTest(field=field,value=value),self.assertRaises(contract.FixtureError):self.validate(bad)
        for field,value in (('pid',251),('pid',True),('start_ticks',True),('exe_sha256','b'*64)):
            bad=deepcopy(original);bad['coverage']['target_after'][field]=value
            with self.subTest(target_field=field),self.assertRaises(contract.FixtureError):self.validate(bad)
        for value in (-1,True):
            bad=deepcopy(original);bad['coverage']['files'][1]['syscalls']['write']=value
            with self.assertRaises(contract.FixtureError):self.validate(bad)
        bad=deepcopy(original);bad['coverage']['files'][1]['source']=dict(bad['coverage']['files'][1]['source']);bad['coverage']['files'][1]['source']['sha256']='b'*64
        with self.assertRaises(contract.FixtureError):self.validate(bad)

    def test_unavailable_remains_honest_optional_diagnostic(self):
        for reason in ('strace-unavailable','ptrace-attach-unavailable','ptrace-identity-drift'):
            contract.validate_strace_evidence(str(self.root),TARGET,{'available':False,'reason':reason,'scope':list(SCOPE),'duration_limit_seconds':30,'shards':[]})

    def test_protected_state_and_receipt_still_require_positive_size(self):
        self.shard(250,b'');self.shard(251,b'write(1, "x", 1) = 1\n')
        trace=self.produce();connected={'daemon':TARGET,'server_public_key':'test'};plan=SimpleNamespace(owned_root=str(self.root))
        pointer={'path':str(self.root/'protected.json'),'uid':0,'gid':0,'mode':0o600,'size':10,'sha256':'b'*64}
        diagnostic={'schema':1,'target':TARGET,'strace':trace,'state':dict(pointer),'receipt':dict(pointer)}
        receipt={'schema':1,'operation':'headless-preexisting-baseline-owned','origin':'guest','transport':'qga',
                 'connected_receipt_sha256':contract._sha(connected),'setup_disconnect':{'state':'disconnected','interface_absent':True,'routes_clean':True,'dns_clean':True,'recovery_required':False,'pre_disconnect_diagnostic':diagnostic},'systemd_terminal':{}}
        with patch.object(contract,'validate_connected',return_value={**connected,'server_public_key':'test'}),patch.object(contract,'build_contract',return_value={}),patch.object(contract,'_validate_baseline_config'):
            for field in ('state','receipt'):
                diagnostic[field]['size']=0
                with self.assertRaisesRegex(contract.FixtureError,'protected state missing'):
                    contract.validate_baseline_owned(plan,connected,receipt)
                diagnostic[field]['size']=10
            with self.assertRaisesRegex(contract.FixtureError,'graceful service terminal invalid'):
                contract.validate_baseline_owned(plan,connected,receipt)


if __name__=='__main__':unittest.main()
