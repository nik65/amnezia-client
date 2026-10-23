"""Only mocks and temporary files. Never invokes systemctl or touches network."""
import ast,hashlib,json
from pathlib import Path
import tempfile,types,unittest
from unittest.mock import Mock,patch
from . import linux_gui_fixture as host
from .guest_helpers import linux_gui_softpipe_setup as guest

class OfflineBoot(unittest.TestCase):
    def interfaces(self,names):return patch.object(guest,'Path',lambda _:types.SimpleNamespace(iterdir=lambda:[types.SimpleNamespace(name=n) for n in names]))
    def test_no_network_interface_refusal_before_command(self):
        with self.interfaces(['lo','ens3']),patch.object(guest,'run_phase') as run:
            with self.assertRaisesRegex(RuntimeError,'non-loopback'):guest.offline_boot(Mock(),planned_nic_none=True)
            run.assert_not_called()
    def test_missing_planned_offline_refuses_before_probe_or_command(self):
        with patch.object(guest,'Path') as path,patch.object(guest,'run_phase') as run:
            with self.assertRaisesRegex(RuntimeError,'planned NIC none'):guest.offline_boot(Mock(),planned_nic_none=False)
            path.assert_not_called();run.assert_not_called()
    def test_runtime_mask_scoped_and_job_readback_required(self):
        def phase(journal,name,args,**kwargs):
            if name=='offline-network':self.assertEqual(args,['systemctl','mask','--runtime','--now','systemd-networkd-wait-online.service']);return ''
            self.assertEqual(name,'offline-network-readback');return 'LoadState=masked\nActiveState=inactive\nSubState=dead\nJob=\n'
        with self.interfaces(['lo']),patch.object(guest,'run_phase',side_effect=phase):
            result=guest.offline_boot(Mock(),planned_nic_none=True)
        self.assertTrue(result['runtimeOnly']);self.assertEqual(result['interfaces'],['lo']);self.assertEqual(result['readback']['Job'],'')
    def test_pending_job_not_hidden_as_success(self):
        with self.interfaces(['lo']),patch.object(guest,'run_phase',side_effect=['','LoadState=masked\nActiveState=inactive\nJob=67\n']):
            with self.assertRaisesRegex(RuntimeError,'did not unblock'):guest.offline_boot(Mock(),planned_nic_none=True)
    def test_unblock_only_after_environment_readback_before_graphical(self):
        tree=ast.parse(Path(guest.__file__).read_text());setup=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='setup')
        calls=sorted((n.lineno,ast.unparse(n)) for n in ast.walk(setup) if isinstance(n,ast.Call))
        env=next(line for line,text in calls if "'environment'" in text and text.startswith('run_phase('));boot=next(line for line,text in calls if text.startswith('offline_boot('));graph=next(line for line,text in calls if "'start-graphical'" in text and text.startswith('run_phase('))
        self.assertLess(env,boot);self.assertLess(boot,graph);self.assertLess(sum(guest.PHASE_LIMITS.values())+20,guest.SETUP_OUTER_TIMEOUT)
    def profile(self,config):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup);root=Path(temporary.name)/'deploy/release_lab';(root/'profiles').mkdir(parents=True);path=root/'profiles/linux-x64-gui.json';path.write_text(json.dumps(config))
        record={'path':str(path),'size':path.stat().st_size,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
        return root,{'profile_records':{'linux-x64-gui':record}}
    def test_canonical_plan_profile_none_passes(self):
        root,run=self.profile({'id':'linux-x64-gui','backend':'qemu-linux','nic':'none'})
        with patch.object(host,'__file__',str(root/'linux_gui_fixture.py')):self.assertEqual(host.offline_profile_record(run),run['profile_records']['linux-x64-gui'])
    def test_profile_nic_present_or_identity_mismatch_refused(self):
        for config in [{'id':'linux-x64-gui','backend':'qemu-linux','nic':'user'},{'id':'other','backend':'qemu-linux','nic':'none'}]:
            root,run=self.profile(config)
            with patch.object(host,'__file__',str(root/'linux_gui_fixture.py')):
                with self.assertRaises(host.LinuxGuiFixtureError):host.offline_profile_record(run)
    def test_profile_stale_bytes_refused(self):
        root,run=self.profile({'id':'linux-x64-gui','backend':'qemu-linux','nic':'none'});(root/'profiles/linux-x64-gui.json').write_text('{}')
        with patch.object(host,'__file__',str(root/'linux_gui_fixture.py')):
            with self.assertRaisesRegex(host.LinuxGuiFixtureError,'source changed'):host.offline_profile_record(run)

if __name__=='__main__':unittest.main()
