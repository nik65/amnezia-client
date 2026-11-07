from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parent

def source(name):
    return (ROOT / name).read_text(encoding='utf-8-sig')

class LimitedFixtureSourceTests(unittest.TestCase):
    def test_observer_uses_limited_broker_preserves_privileged_native(self):
        text = source('product_observer.ps1')
        self.assertIn("function Status([string]$app){return RequestLimited 'status'}", text)
        self.assertIn('$gui=StartLimitedGui $root $plan $args', text)
        self.assertNotIn('$gui=Start-Process $app', text)
        self.assertIn('function Native', text)
        self.assertIn('limited_gui_operator=$true', text)
        self.assertIn("limited_started_proof_sha256=(Hash (Join-Path $script:limited.output 'started.json'))", text)
        self.assertIn('try{CloseLimited}catch{$failure=$true}', text)
        self.assertIn('if($failure){exit 1}', text)
    def test_observer_hash_checks_before_loading_controller(self):
        text = source('product_observer.ps1')
        names = ('limited_interactive_runner.ps1','limited_interactive_controller.ps1','BoundedOperatorCapture.cs')
        for name in names: self.assertIn(name, text)
        self.assertLess(text.index('staged limited source changed'), text.index(". (Join-Path $root 'limited_interactive_controller.ps1')"))
    def test_controller_manifest_copy_and_task_ownership(self):
        text=source('limited_interactive_controller.ps1')
        for fragment in ('[IO.FileMode]::CreateNew','limited copied source differs','operator_capture_sha256=$plan.files.', '-LogonType Interactive -RunLevel Limited','native_exit-isnot[int]', 'limited task cleanup pending', 'limited task failed'):
            self.assertIn(fragment,text)
        self.assertLess(text.index('$script:limited=[ordered]'),text.index('Start-ScheduledTask -TaskName $name'))
    def test_runner_pins_capture_and_retains_access_checks(self):
        text=source('limited_interactive_runner.ps1')
        self.assertIn('limited interactive token required', text)
        self.assertIn('0x000D0116',text);self.assertIn('0x000D0156',text)
        self.assertIn('OwnedPathAccess',text)
        self.assertLess(text.index('limited operator capture source differs'),text.index('Add-Type -TypeDefinition ([IO.File]::ReadAllText($capturePath))'))
        self.assertNotIn('public static class BoundedOwnedOperator',text)
        for fragment in ("InvokeLimitedOperator 'disconnect'",'fresh disconnected state unconfirmed','graceful_application_quit=$false','owned_gui_exited=$true'):
            self.assertIn(fragment,text)
    def test_capture_retains_native_exit_and_bounds(self):
        text=source('BoundedOperatorCapture.cs')
        for fragment in ('ExitCodeAvailable','18000','65536','RedirectStandardOutput','RedirectStandardError','WaitForExit','OwnedChildExited'):
            self.assertIn(fragment,text)
    def test_sources_have_no_release_specific_paths(self):
        for name in ('limited_interactive_runner.ps1','limited_interactive_controller.ps1','BoundedOperatorCapture.cs'):
            text=source(name)
            for forbidden in ('release-50318','w18-','limited-native-g','5.0.3.18'):
                self.assertNotIn(forbidden,text)

if __name__=='__main__': unittest.main()
