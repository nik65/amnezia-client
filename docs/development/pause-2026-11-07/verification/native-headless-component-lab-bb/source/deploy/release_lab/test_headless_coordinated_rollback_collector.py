"""No-VM collector tests: real temp descriptors, bounded fake-QGA transport."""
import base64
import contextlib
from dataclasses import replace
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import tempfile
import threading
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from . import headless_coordinated_rollback_collector as module
from . import headless_coordinated_rollback_acceptance as acceptance
from .headless_native_acceptance import UPDATE_JOURNAL,UPDATE_STATE,FIXED_STORE


def bare(archive):
    collector=object.__new__(module.CoordinatedRollbackCollector)
    collector.archive=Path(archive);collector.plan=SimpleNamespace(attempt_nonce='a'*48)
    collector._lock=threading.Lock();collector._sequence=0;collector._check=Mock()
    collector._archive_fd=module._directory_fd(archive)
    return collector


class ChunkQga:
    def __init__(self,body):self.body=body;self.position=0;self.counts=[];self.closed=False
    def request(self,name,args):
        if name=='guest-file-open':return {'return':7}
        if name=='guest-file-close':self.closed=True;return {'return':{}}
        self.counts.append(args['count']);chunk=self.body[self.position:self.position+args['count']];self.position+=len(chunk)
        return {'return':{'count':len(chunk),'buf-b64':base64.b64encode(chunk).decode(),'eof':self.position==len(self.body)}}


@unittest.skipUnless(os.name=='posix','real private archive directory descriptors require POSIX')
class CollectorTests(unittest.TestCase):
    def test_archive_failure_closes_guest_handle_and_preserves_primary(self):
        with tempfile.TemporaryDirectory() as name:
            collector=bare(name);collector.qga=Mock();collector.qga.request.side_effect=[{'return':7},OSError('secondary close')]
            primary=PermissionError('archive failure');collector._archive_file=Mock(side_effect=primary)
            record={'size':1,'sha256':'0'*64,'physical_path':'/var/lib/amnezia/.release-lab-coordinated-'+'a'*48+'/capture-test'}
            with self.assertRaises(PermissionError) as caught:collector._pull(record)
            self.assertIs(caught.exception,primary)
            self.assertEqual(collector.qga.request.call_args_list[-1].args,('guest-file-close',{'handle':7}))
            self.assertEqual(collector.qga.request.call_count,2)

    def test_late_phase_read_cannot_pass_held_or_resumed(self):
        for phase in ('held','resumed'):
            with tempfile.TemporaryDirectory() as name:
                collector=bare(name);clock=[0.0];budgets=[]
                def reading(*args,**kwargs):
                    budgets.append(kwargs['timeout']);clock[0]=2.0
                    return {'bytes_b64':base64.b64encode(json.dumps({'phase':phase}).encode()).decode()}
                collector._read=reading
                with patch.object(module.time,'monotonic',side_effect=lambda:clock[0]),self.assertRaisesRegex(module.CoordinatedCollectionError,'deadline'):
                    collector._wait_record(phase,1)
                self.assertEqual(budgets,[1.0])

    def test_read_propagates_remaining_deadline(self):
        with tempfile.TemporaryDirectory() as name:
            collector=bare(name);clock=[0.0];collector._initialize=Mock();collector._args=Mock(return_value=[]);record={'size':1}
            def executing(*args):clock[0]=.25;return record
            collector._exec=Mock(side_effect=executing);collector._pull=Mock(return_value={'actual':True});collector.archive_original=Mock()
            with patch.object(module.time,'monotonic',side_effect=lambda:clock[0]):collector._read('profiles',timeout=1)
            self.assertEqual(collector._exec.call_args.args[-1],1)
            self.assertEqual(collector._pull.call_args.kwargs['deadline'],1)

    def test_marker_program_restores_parent_directory_fsync(self):
        collector=object.__new__(module.CoordinatedRebootCollector);collector.plan=SimpleNamespace(attempt_nonce='a'*48);collector._check=Mock()
        collector.native=Mock();collector.native.raw_file.return_value={'sha256':'x','size':2}
        collector._json=Mock(return_value={'sha256':'x','size':2})
        collector.stage_persistent_marker()
        program=collector._json.call_args.args[0]
        self.assertIn('try:os.fsync(parent)',program)
        self.assertIn('parent=directory(str(pathlib.PurePosixPath(path).parent))',program)

    def test_unit_command_live_output_bound_on_actual_child(self):
        program=module.UNIT_PROGRAM
        function=program[program.index('def command(args):'):program.index("name='amnezia-rollback-coordinator.service'")]
        scope={'os':os,'subprocess':subprocess};exec(function,scope)
        with self.assertRaisesRegex(RuntimeError,'unit output bound'):
            scope['command']([sys.executable,'-c',"import sys;sys.stdout.write('x'*2000000)"])
        result=scope['command']([sys.executable,'-c',"print('disabled')"])
        self.assertEqual(result['stdout'],'disabled\n');self.assertEqual(result['exit_code'],0)

    @unittest.skipUnless(os.getuid()==0,'actual observed root UID test')
    def test_actual_process_observer_records_root_uid_slots(self):
        program=module.process_program()
        with tempfile.TemporaryDirectory(dir='/root') as name:
            program=program.replace('root=context(run,case,nonce)','root=pathlib.Path('+repr(name)+')')
            begin=program.index('allowed=');end=program.index('\n',begin)
            program=program[:begin]+"allowed=[['/usr/bin/sleep','0.1'],['unselected']]"+program[end:]
            output=str(Path(name)/'output-rollback');digest=hashlib.sha256(Path('/usr/bin/sleep').read_bytes()).hexdigest()
            response=subprocess.run([sys.executable,'-c',program,json.dumps(['/usr/bin/sleep','0.1']),digest,output,'run','case','nonce'],capture_output=True,timeout=5,check=True)
            identity=json.loads(response.stdout)['process']
            self.assertEqual(identity['uid_slots'],[0,0,0,0]);self.assertEqual(identity['exit_code'],0)
            self.assertIn('observed_at',identity)

    def test_actual_large_json_uses_bounded_qga_chunks_and_full_private_capture(self):
        body=json.dumps({'unknown': '\u2603'*450000}).encode()
        self.assertGreater(len(body),1048576)
        with tempfile.TemporaryDirectory() as name:
            collector=bare(name);collector.qga=ChunkQga(body)
            record={'size':len(body),'sha256':hashlib.sha256(body).hexdigest(),'physical_path':'/var/lib/amnezia/.release-lab-coordinated-'+'a'*48+'/capture-test'}
            result=collector._pull(record)
            self.assertEqual(base64.b64decode(result['bytes_b64']),body)
            self.assertTrue(collector.qga.closed)
            self.assertLessEqual(max(collector.qga.counts),65536)
            self.assertEqual(next(Path(name).glob('*.bin')).read_bytes(),body)

    def test_stream_mismatch_and_secondary_close_failure_keep_primary(self):
        with tempfile.TemporaryDirectory() as name:
            collector=bare(name);collector.qga=ChunkQga(b'actual')
            record={'size':6,'sha256':'0'*64,'physical_path':'/var/lib/amnezia/.release-lab-coordinated-'+'a'*48+'/capture-test'}
            with self.assertRaisesRegex(module.CoordinatedCollectionError,'hash/size'):collector._pull(record)
            original=ValueError('actual stream failure')
            collector.qga=Mock()
            collector.qga.request.side_effect=[{'return':7},original,OSError('close failure')]
            with self.assertRaises(ValueError) as caught:collector._pull(record)
            self.assertIs(caught.exception,original)
            self.assertIn('OSError',original.__notes__[0])

    def test_private_archive_crosses_old_one_mib_and_explicit_bound_fails_closed(self):
        with tempfile.TemporaryDirectory() as name:
            collector=bare(name);value={'original':'x'*1100000}
            record=collector.archive_original('original',value)
            self.assertEqual(json.loads(Path(record['path']).read_bytes()),value)
            self.assertEqual(hashlib.sha256(Path(record['path']).read_bytes()).hexdigest(),record['sha256'])
            with patch.object(module,'ARCHIVE_LIMIT',32),self.assertRaises(module.CoordinatedCollectionError):collector.archive_original('too-large',value)

    def test_private_archive_ancestor_swap_never_redirects_original_bytes(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name);parent=root/'parent';parent.mkdir();leaf=parent/'private';leaf.mkdir(mode=0o700)
            target=root/'attacker';target.mkdir();collector=bare(leaf);original=os.open;swapped=False
            def opening(path,flags,*args,**kwargs):
                nonlocal swapped
                if not swapped and str(path).endswith('.json') and kwargs.get('dir_fd')==collector._archive_fd:
                    swapped=True;parent.rename(root/'moved');parent.symlink_to(target,target_is_directory=True)
                return original(path,flags,*args,**kwargs)
            with patch.object(os,'open',side_effect=opening),self.assertRaises((OSError,module.CoordinatedCollectionError)):
                collector.archive_original('private',{'secret':'original private bytes'})
            self.assertFalse(list(target.iterdir()))
            captured=list((root/'moved'/'private').iterdir())
            self.assertEqual(len(captured),1)
            self.assertEqual(json.loads(captured[0].read_bytes()),{'secret':'original private bytes'})
            self.assertEqual(captured[0].stat().st_mode&0o777,0o600)

    def test_archive_symlink_ancestor_is_rejected_before_any_private_write(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name);target=root/'target';target.mkdir();(root/'link').symlink_to(target,target_is_directory=True)
            with self.assertRaises(OSError):module._directory_fd(root/'link')
            self.assertFalse(list(target.iterdir()))

    def test_fixed_process_observer_keeps_original_files_and_only_exact_verbs(self):
        code=module.process_program();compile(code,'fixed-process','exec')
        self.assertIn("--rollback-coordinator','resume'",code)
        self.assertNotIn('output.unlink',code)
        self.assertIn("'observed_at'",code)
        compile(module.observation_program(),'held-observation','exec')
        self.assertNotIn("get('final13')",module.observation_program())

    def test_reboot_marker_reuses_exact_bytes_in_new_class_without_monkeypatch(self):
        collector=object.__new__(module.CoordinatedRebootCollector)
        collector.plan=SimpleNamespace(attempt_nonce='nonce-1234567890');collector._check=Mock()
        data=(json.dumps({'attempt_nonce':collector.plan.attempt_nonce},separators=(',',':'))+'\n').encode()
        record={'path':'/var/lib/amnezia/release-lab-native-'+collector.plan.attempt_nonce+'.json','sha256':hashlib.sha256(data).hexdigest(),'size':len(data)}
        collector._json=Mock(return_value=record);collector.native=Mock();collector.native.raw_file.return_value=record
        self.assertEqual(collector.stage_persistent_marker(),record)
        collector.stage_persistent_marker()
        self.assertEqual(collector.native.raw_file.call_count,2)
        collector.native.raw_file.return_value={**record,'sha256':'f'*64}
        with self.assertRaises(module.CoordinatedCollectionError):collector.stage_persistent_marker()

    def test_outcome_source_paths_and_driver_exports_match_contract(self):
        self.assertIn(UPDATE_STATE,module.IO_COMMON)
        self.assertIn(UPDATE_JOURNAL,module.IO_COMMON)
        self.assertIn(FIXED_STORE,module.IO_COMMON)
        self.assertIn('guest-exec-outcome',module.IO_PROGRAM)
        self.assertIn('systemctl:amnezia-rollback-coordinator.service',module.IO_PROGRAM)
        importlib.import_module('deploy.release_lab.headless_coordinated_rollback_driver')
        for name in ('stage_disabled_owned_profile','trigger_and_wait_held','reboot_held','resume_and_collect','raw_absence','archive_original'):
            self.assertTrue(callable(getattr(module.CoordinatedRollbackCollector,name)))

    def test_public_rollback_never_multiplexes_optional_qga_process_watcher(self):
        with tempfile.TemporaryDirectory() as name:
            collector=bare(name);collector._read=Mock(return_value={'original':'actual captured bytes'})
            collector._run=Mock(return_value=({'pid':25},{'actual':'stdout'}));collector._wait_record=Mock()
            collector.read_snapshot=Mock(return_value={});collector._unit_state=Mock(return_value={'unit':'actual command outcome'})
            with patch.object(threading,'Thread',side_effect=AssertionError('parallel QGA forbidden')):
                self.assertIsNone(collector.trigger_and_wait_held()['coordinator_process'])
            collector._run.reset_mock()
            with self.assertRaises(module.CoordinatedCollectionError):collector.trigger_and_wait_held(timeout=True)
            collector._run.assert_not_called()

    def test_actual_doctor_pipe_is_bounded_and_failed_bytes_retained_under_qga_limit(self):
        code=module.observation_program();code=code[code.index('import os,selectors,signal,time,base64'):code.index('again=proc.')]
        original="args=['/usr/local/bin/amnezia-cli','--socket','/run/amnezia/amneziad.sock','--json','doctor']"
        replacement='args='+repr([sys.executable,'-c',"print('x'*2000000)"])
        self.assertEqual(code.count(original),1);code=code.replace(original,replacement)
        output=io.StringIO()
        with contextlib.redirect_stdout(output),self.assertRaises(RuntimeError):exec(code,{'subprocess':subprocess,'json':json})
        captured=output.getvalue().encode();self.assertLess(len(captured),1048576)
        value=json.loads(captured);self.assertTrue(value['truncated'])
        self.assertLessEqual(len(base64.b64decode(value['stdout_base64']))+len(base64.b64decode(value['stderr_base64'])),524288)


@unittest.skipUnless(os.name=='posix' and getattr(os,'geteuid',lambda:1)()==0,'actual protected descriptors require root POSIX fixtures')
class DescriptorTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir='/root');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);os.chmod(self.root,0o700)
        self.scope={};exec(module.IO_COMMON,self.scope)

    def snapshot(self,path,mode,logical,label='one',metadata=False,kind='file',inspected=None):
        return self.scope['snapshot'](str(path),mode,64*1024*1024,logical,self.root,label,kind,inspected,metadata)

    def test_real_profile_bytes_unknown_fields_and_typed_gid_preserved(self):
        path=self.root/'profiles';body=b'{"version":1,"unknown":"\\u2603","profiles":[{"id":"a","autoUpdate":true,"other":[1,2]}]}\n'
        path.write_bytes(body);path.chmod(0o600);os.chown(path,0,1234)
        record=self.snapshot(path,0o600,FIXED_STORE)
        self.assertEqual(record['gid'],1234)
        self.assertEqual(Path(record['physical_path']).read_bytes(),body)
        record['bytes_b64']=base64.b64encode(body).decode()
        self.assertEqual(acceptance.raw(record,FIXED_STORE),body)

    def test_real_large_retained_elf_like_bytes_are_lean_metadata_not_qga_payload(self):
        path=self.root/'retained';body=b'\x7fELF'+b'x'*2000000;path.write_bytes(body);path.chmod(0o500)
        record=self.snapshot(path,0o500,module.RETAINED,metadata=True)
        self.assertNotIn('bytes_b64',record);self.assertNotIn('physical_path',record)
        self.assertLess(len(json.dumps(record)),2048)
        self.assertEqual(record['sha256'],hashlib.sha256(body).hexdigest())
        plan=SimpleNamespace(candidate=SimpleNamespace(cli_sha256=record['sha256'],cli_size=len(body)))
        acceptance.executable_metadata(record,plan)

    def test_actual_descriptor_rejects_mode_uid_symlink_and_hardlink(self):
        path=self.root/'file';path.write_bytes(b'original');path.chmod(0o644)
        with self.assertRaises(RuntimeError):self.snapshot(path,0o600,FIXED_STORE)
        path.chmod(0o600);os.chown(path,1234,0)
        with self.assertRaises(RuntimeError):self.snapshot(path,0o600,FIXED_STORE)
        os.chown(path,0,0);linked=self.root/'link';os.link(path,linked)
        with self.assertRaises(RuntimeError):self.snapshot(path,0o600,FIXED_STORE)
        linked.unlink();path.unlink();path.symlink_to('/dev/null')
        with self.assertRaises(OSError):self.snapshot(path,0o600,FIXED_STORE)

    def test_real_racy_descriptor_never_confers_stable_proof(self):
        path=self.root/'file';path.write_bytes(b'original');path.chmod(0o600)
        original=os.read;changed=False
        def read(fd,count):
            nonlocal changed
            data=original(fd,count)
            if not changed and data:
                changed=True;path.rename(self.root/'old');path.write_bytes(b'changed!');path.chmod(0o600)
            return data
        with patch.object(os,'read',side_effect=read),self.assertRaises(self.scope['Transition']):self.snapshot(path,0o600,FIXED_STORE)

    def test_source_parent_swap_rejects_even_identical_replacement_bytes(self):
        parent=self.root/'source';parent.mkdir(mode=0o700);path=parent/'file';path.write_bytes(b'original');path.chmod(0o600)
        original=os.read;changed=False
        def read(fd,count):
            nonlocal changed
            data=original(fd,count)
            if not changed and data:
                changed=True;parent.rename(self.root/'old-parent');parent.mkdir(mode=0o700);path.write_bytes(b'original');path.chmod(0o600)
            return data
        with patch.object(os,'read',side_effect=read),self.assertRaises(self.scope['Transition']):self.snapshot(path,0o600,FIXED_STORE)

    def test_actual_guest_outcomes_decode_without_fabricated_product_file_stat(self):
        path=self.root/'outcome';body=b'{"exists":false}';path.write_bytes(body);path.chmod(0o600)
        record=self.snapshot(path,0o600,UPDATE_JOURNAL+'.absence',kind='guest-lstat-outcome',inspected=UPDATE_JOURNAL)
        record['bytes_b64']=base64.b64encode(body).decode()
        acceptance.absence(record,UPDATE_JOURNAL,'actual absent source')
        self.assertEqual(record['source_path'],str(path))
        self.assertNotEqual(record['source_path'],record['inspected_path'])
        command=self.root/'command';body=b'{"enabled":"disabled"}';command.write_bytes(body);command.chmod(0o600)
        record=self.snapshot(command,0o600,'systemctl:amnezia-rollback-coordinator.service',label='two',kind='guest-exec-outcome')
        record['bytes_b64']=base64.b64encode(body).decode()
        self.assertEqual(acceptance.raw_outcome(record,record['path'])['enabled'],'disabled')


if __name__=='__main__':unittest.main()
