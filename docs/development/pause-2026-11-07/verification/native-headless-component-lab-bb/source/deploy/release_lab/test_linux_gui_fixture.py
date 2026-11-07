import base64
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from .lab import LabController, QgaGuestExecutionError
from .linux_gui_fixture import LinuxGuiFixture, LinuxGuiFixtureError, SOURCES, XRES_PACKAGE
from .guest_helpers import linux_gui_readiness_probe as guest


class GuiFixtureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.controller = LabController(Path(self.temp.name))
        self.controller.assert_mutation_context = Mock()
        self.controller._mutation_lock_depth = 1
        self.controller._mutation_lock_fd = 123
        root = Path(__file__).resolve().parents[2]
        records = {name:{'path':str(root/name), 'size':(root/name).stat().st_size,
                         'sha256':hashlib.sha256((root/name).read_bytes()).hexdigest()} for name in SOURCES}
        profile = root/'deploy/release_lab/profiles/linux-x64-gui.json'
        self.run = {'semantic_helper_records':records, 'profiles':{'linux-x64-gui':{'steps':[]}},
                    'profile_records':{'linux-x64-gui':{'path':str(profile), 'size':profile.stat().st_size,
                        'sha256':hashlib.sha256(profile.read_bytes()).hexdigest()}}}
        self.vm = {'qga_socket':'/unused/qga', 'qmp_socket':'/unused/qmp', 'pid':12}
        self.controller.get_run = Mock(side_effect=lambda _: self.run)
        self.controller.owned_vm = Mock(side_effect=lambda *_:dict(self.vm))

    def test_lock_and_source_closure_fail_before_guest_effects(self):
        self.controller._mutation_lock_fd = None
        with self.assertRaises(LinuxGuiFixtureError):
            LinuxGuiFixture(self.controller, 'run-14')
        self.assertFalse((Path(self.temp.name)/'exports').exists())
        self.controller._mutation_lock_fd = 123
        self.run['semantic_helper_records'].pop(SOURCES[-1])
        with self.assertRaises(LinuxGuiFixtureError):
            LinuxGuiFixture(self.controller, 'run-14')

    def test_actual_create_plan_binds_exact_new_helper_closure(self):
        from . import lab
        candidate = Path(self.temp.name)/'inert.run'
        candidate.write_bytes(b'inert candidate test bytes')
        original_record = lab.artifact_record
        def record(path):
            if 'release-lab-fixtures' in str(path) and Path(path).resolve() != (lab.repo_root()/XRES_PACKAGE).resolve():
                return original_record(candidate)
            return original_record(path)
        controller = LabController(Path(self.temp.name)/'plan')
        controller.assert_mutation_context = Mock()  # Inert plan only, no start.
        with patch.object(lab, 'artifact_record', side_effect=record), \
                patch.object(lab, 'validate_signed_manifest'), \
                patch.object(lab, 'validate_android_vulkan_records'), \
                patch.object(lab, 'validate_android_host_dependency_records'), \
                patch.object(lab, 'validate_android_wayland_records'):
            run = controller.create('candidate', {'linux-x64':candidate}, outer_artifact=candidate,
                                    run_id='inert-plan', manifest=candidate, manifest_public_key=candidate,
                                    baseline_artifacts={'linux-x64':candidate}, baseline_version='5.0.3.13', candidate_version='5.0.3.14')
        records = run['semantic_helper_records']
        lab.validate_semantic_helper_records(records)
        for name in SOURCES:
            self.assertEqual(records[name], original_record(Path(lab.repo_root())/name))
        changed = dict(records)
        changed.pop(SOURCES[-1])
        with self.assertRaises(lab.LabError):
            lab.validate_semantic_helper_records(changed)

    def test_changed_live_identity_blocks_configuration(self):
        fixture = LinuxGuiFixture(self.controller, 'run-14')
        fixture.qga = Mock()
        self.vm['pid'] = 99
        with self.assertRaises(LinuxGuiFixtureError):
            fixture.configure_before_login()
        fixture.qga.guest_exec_wait.assert_not_called()

    def test_failed_guest_helper_rethrows_original_private_qga_capture(self):
        fixture = LinuxGuiFixture(self.controller, 'run-14')
        fixture.qga = Mock()
        error = QgaGuestExecutionError({'return':{'exitcode':9, 'out-data':base64.b64encode(b'private raw log').decode()}})
        fixture.qga.guest_exec_wait.side_effect = error
        with self.assertRaises(QgaGuestExecutionError) as caught:
            fixture.configure_before_login()
        self.assertIs(caught.exception, error)
        self.assertIn(b'cHJpdmF0ZSByYXcgbG9n', error.private_failure_capture()['body'])

    def test_setup_has_fixed_binding_and_no_caller_hook(self):
        fixture = LinuxGuiFixture(self.controller, 'run-14')
        fixture.qga = Mock()
        fixture.qga.guest_exec_wait.return_value = {'exitcode':0, 'stdout':json.dumps({'GL_RENDERER':'softpipe', 'setting':'GALLIUM_DRIVER=softpipe', 'otherExperimentSettingsChanged':False,
            'offlineNetworkBoot':{'plannedNIC':'none','interfaces':['lo'],'runtimeOnly':True,'unit':'systemd-networkd-wait-online.service','readback':{'Job':'','LoadState':'masked','ActiveState':'inactive'}}})}
        fixture.configure_before_login()
        executable, args = fixture.qga.guest_exec_wait.call_args_list[0].args
        self.assertEqual(executable, '/usr/bin/python3')
        self.assertEqual(args[2:6], ['run-14', 'linux-x64-gui', fixture.nonce, 'setup'])
        self.assertIn("systemctl','start','amnezia-lab-gui.service", args[1])
        with self.assertRaises(LinuxGuiFixtureError):
            fixture.configure_before_login()

    def test_canonical_step_contract_required_before_readiness(self):
        fixture = LinuxGuiFixture(self.controller, 'run-14')
        fixture._setup_done = True
        for steps in ([], [{'id':'probe', 'passed':True}],
                      [{'id':name,'passed':name!='update'} for name in ('probe','reinstall','update','service-health')]):
            self.run['profiles']['linux-x64-gui']['steps'] = steps
            with self.assertRaises(LinuxGuiFixtureError):
                fixture.wait_after_steps()

    def test_actual_producer_orders_fixture_around_canonical_steps(self):
        from .linux_live_acquisition import LinuxLiveProducer
        events = []
        class StopAfterReadiness(Exception):
            pass
        controller = LabController(Path(self.temp.name)/'producer')
        controller.start = Mock(side_effect=lambda *_:events.append('start'))
        controller.guest_probe = Mock(side_effect=lambda *_:events.append('probe'))
        controller.run_steps = Mock(side_effect=lambda *_,**kw:events.append('canonical-'+','.join(kw['selected'])))
        def collect(*_):
            events.append('collect')
            raise StopAfterReadiness()
        controller.collect = Mock(side_effect=collect)
        producer = LinuxLiveProducer(controller, 'run-14', target='linux-gui')
        producer._binding = Mock(return_value={'profiles':{'linux-x64-gui':{}}})
        producer._wait_for_boot = Mock(side_effect=lambda *_:events.append('wait-boot'))
        fixture = Mock()
        fixture.configure_before_login.side_effect = lambda:events.append('setup-softpipe')
        fixture.ensure_xres_dependency_after_probe.side_effect = lambda:events.append('xres-dependency')
        fixture.wait_after_steps.side_effect = lambda:events.append('strict-readiness')
        context = Mock()
        with patch('deploy.release_lab.linux_gui_fixture.LinuxGuiFixture', return_value=fixture), \
                patch('deploy.release_lab.linux_gui_payload.derive_gui_payload', return_value={'binary_sha256':'a'*64}), \
                self.assertRaises(StopAfterReadiness):
            producer._acquire_once(context)
        self.assertEqual(events, ['start','wait-boot','probe','setup-softpipe','canonical-probe','xres-dependency','canonical-reinstall,update,service-health','strict-readiness','collect'])

    def test_actual_dependency_failure_prevents_remaining_steps_and_cleans_owned_guest(self):
        from .linux_live_acquisition import LinuxLiveProducer
        controller = LabController(Path(self.temp.name)/'dependency-failure')
        controller.start = Mock(); controller.guest_probe = Mock(); controller.run_steps = Mock()
        controller.archive_guest_evidence = Mock(side_effect=OSError('secondary archive failure'))
        controller.reset = Mock(); controller.owned_vm = Mock(return_value={'pid':123})
        controller.get_run = Mock(return_value={'profiles':{'linux-x64-gui':{'vm':{'pid':123}}}})
        producer = LinuxLiveProducer(controller,'run-14',target='linux-gui')
        producer._binding = Mock(return_value={'profiles':{'linux-x64-gui':{}}})
        producer._wait_for_boot = Mock()
        fixture = Mock(); primary = RuntimeError('actual dependency postcondition failed')
        fixture.ensure_xres_dependency_after_probe.side_effect = primary
        with patch('deploy.release_lab.linux_gui_fixture.LinuxGuiFixture',return_value=fixture), \
                patch('deploy.release_lab.linux_gui_payload.derive_gui_payload',return_value={'binary_sha256':'a'*64}), \
                self.assertRaisesRegex(RuntimeError,'actual dependency postcondition failed'):
            producer.acquire(Mock())
        controller.run_steps.assert_called_once_with('run-14','linux-x64-gui',selected=['probe'])
        controller.reset.assert_called_once_with('run-14','linux-x64-gui')
        fixture.wait_after_steps.assert_not_called()
        self.assertTrue(any('archive unavailable' in note for note in primary.__notes__))

    @unittest.skipUnless(os.name == 'posix', 'controller pixel paths are Linux-owned')
    def test_final_capture_revalidates_desktop_identity_before_return(self):
        from .test_linux_gui_continuous import exercise_host_transaction
        exercise_host_transaction(self)
        with self.assertRaises(LinuxGuiFixtureError):exercise_host_transaction(self, changed=True)

    def test_real_kernel_llvmpipe_crash_and_restart_detected(self):
        self.assertTrue(guest.journal_crashes([{'MESSAGE':'gnome-shell[1225]: segfault at 0 in llvmpipe AVX2 gather'}])[0])
        self.assertTrue(guest.journal_crashes([{'MESSAGE':'GNOME Shell started'},{'MESSAGE':'GNOME Shell started'}])[0])
        self.assertTrue(guest.journal_crashes([{'MESSAGE':'Process dumped', 'COREDUMP_COMM':'gnome-shell'}])[0])
        self.assertEqual(guest.journal_crashes([{'MESSAGE':'GNOME Shell started'}]), (False,1))
        with self.assertRaises(RuntimeError):
            guest.journal_crashes([{'MESSAGE':['malformed']}])

    @unittest.skipUnless(os.name == 'posix', 'actual bounded pipe tests require POSIX')
    def test_actual_bounded_command_keeps_original_failure_bytes(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(RuntimeError):
            guest.command([sys.executable,'-c',"import sys;print('private-output');print('private-error',file=sys.stderr);sys.exit(9)"])
        raw = json.loads(output.getvalue())
        self.assertEqual(base64.b64decode(raw['stdout_base64']), b'private-output\n')
        self.assertEqual(base64.b64decode(raw['stderr_base64']), b'private-error\n')
        self.assertFalse(raw['truncated'])
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(RuntimeError):
            guest.command([sys.executable,'-c',"print('x'*4096)"],limit=64)
        raw = json.loads(output.getvalue())
        self.assertTrue(raw['truncated'])
        self.assertLessEqual(sum(len(base64.b64decode(raw[key])) for key in ('stdout_base64','stderr_base64')),64)

    @unittest.skipUnless(os.name == 'posix' and getattr(os, 'geteuid', lambda:1)() == 0,
                         'actual root-owned marker fixtures require POSIX root')
    def test_actual_marker_program_rejects_wrong_bytes_symlink_and_fifo(self):
        from .linux_gui_fixture import FIXTURE_BINDING
        # Only redirect the two fixed filesystem roots into NEW inert temp
        # fixtures. All production marker validation code executes unchanged.
        nonce = 'a'*48
        private_prefix = str(Path(self.temp.name)/'fixture-')
        marker = Path(self.temp.name)/'canonical-marker'
        program = FIXTURE_BINDING.replace("'/run/amnezia-release-lab-fixture-'", repr(private_prefix)).replace("'/tmp/amnezia-release-lab-marker'", repr(str(marker)))
        def execute(phase):
            return subprocess.run([sys.executable,'-c',program,'run-14','linux-x64-gui',nonce,phase], capture_output=True, timeout=2)
        self.assertEqual(execute('setup').returncode,0)
        marker.write_bytes(b'amnezia-release-lab:run-14:linux-x64-gui')
        self.assertEqual(execute('observe').returncode,0)
        marker.write_bytes(b'wrong marker')
        self.assertNotEqual(execute('observe').returncode,0)
        marker.unlink()
        marker.symlink_to(Path(private_prefix+nonce)/'marker')
        self.assertNotEqual(execute('observe').returncode,0)
        marker.unlink()
        os.mkfifo(marker)
        self.assertNotEqual(execute('observe').returncode,0)


if __name__ == '__main__':
    unittest.main()
