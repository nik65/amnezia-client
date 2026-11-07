"""Inert session policy and capture lock regressions; no DBus/guest commands."""
import importlib.util
import io
import json
from pathlib import Path
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT=Path(__file__).parent

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

DEP=load('lock_dependency','guest_helpers/linux_gui_xres_dependency.py')
WIN=load('lock_window','guest_helpers/linux_gui_window_evidence.py')
SESSION={'session_id':'2','uid':1000,'user':'lab','display':':0','xauthority':'/run/user/1000/gdm/Xauthority'}

class Commands:
    def __init__(self,locked=True):self.locked=locked;self.calls=[];self.values={('org.gnome.desktop.session','idle-delay'):'uint32 300',('org.gnome.desktop.screensaver','lock-enabled'):'true'};self.foreign=False;self.unlock_works=True;self.writable=True
    def __call__(self,argv,**unused):
        self.calls.append(argv)
        if argv[:2]==['loginctl','list-sessions']:value='2 1000 lab seat0 tty2'
        elif argv[:2]==['loginctl','show-session']:
            key=argv[3][2:];value={'Type':'x11','Active':'yes','State':'active','Class':'user','User':'1001' if self.foreign else '1000','LockedHint':'yes' if self.locked else 'no'}[key]
        elif argv[:2]==['loginctl','unlock-session']:
            if self.unlock_works:self.locked=False
            value=''
        elif 'gsettings' in argv:
            pos=argv.index('gsettings');action,schema,key=argv[pos+1:pos+4]
            if action=='writable':value='true' if self.writable else 'false'
            elif action=='get':value=self.values[(schema,key)]
            else:self.values[(schema,key)]=argv[-1];value=''
        elif 'gdbus' in argv:
            assert argv[argv.index('--dest')+1]=='org.gnome.Shell.ScreenShield'
            value='(true,)' if self.locked else '(false,)'
        else:raise AssertionError(argv)
        return value.encode()

class SessionLockTests(unittest.TestCase):
    def test_early_already_locked_policy_unlocks_exact_session(self):
        c=Commands();r=DEP.configure_session_policy(c,['runuser','-u','lab','--'],time.monotonic()+10)
        self.assertTrue(r['unlockRequested']);self.assertEqual(r['before']['lockedHint'],'yes');self.assertEqual(r['after']['lockedHint'],'no')
        self.assertIn(['loginctl','unlock-session','2'],c.calls)
        self.assertEqual(c.values[('org.gnome.desktop.session','idle-delay')],'uint32 0')
        self.assertEqual(c.values[('org.gnome.desktop.screensaver','lock-enabled')],'false')
    def test_unlocked_does_not_send_unlock(self):
        c=Commands(False);r=DEP.configure_session_policy(c,[],time.monotonic()+10)
        self.assertFalse(r['unlockRequested']);self.assertFalse(any(x[:2]==['loginctl','unlock-session'] for x in c.calls))
    def test_foreign_session_no_mutation(self):
        c=Commands();c.foreign=True
        with self.assertRaises(RuntimeError):DEP.configure_session_policy(c,[],time.monotonic()+10)
        self.assertFalse(any('gsettings' in x or x[:2]==['loginctl','unlock-session'] for x in c.calls))
    def test_nonwritable_refuses_unlock(self):
        c=Commands();c.writable=False
        with self.assertRaises(RuntimeError):DEP.configure_session_policy(c,[],time.monotonic()+10)
        self.assertFalse(any(x[:2]==['loginctl','unlock-session'] for x in c.calls))
    def test_unlock_failure_remains_failure(self):
        c=Commands();c.unlock_works=False
        with patch.object(DEP.time,'sleep'):
            with self.assertRaisesRegex(RuntimeError,'remains locked'):DEP.configure_session_policy(c,[],time.monotonic()+10)
    def test_unlock_budget_not_extended(self):
        c=Commands();c.unlock_works=False
        with self.assertRaisesRegex(RuntimeError,'budget'):DEP.configure_session_policy(c,[],time.monotonic()-1)
    def test_strict_guard_rejects_lock_returning_between_capture_checks(self):
        c=Commands(False)
        def actual(argv,timeout):return {'stdout':c(argv),'stderr':'','exitcode':0,'overflow':False,'timeout':False}
        with patch.object(WIN,'status_attempt',side_effect=actual):
            self.assertFalse(WIN.require_unlocked_session(SESSION,time.monotonic()+10)['screenSaverActive'])
            c.locked=True
            with self.assertRaisesRegex(WIN.EvidenceError,'locked'):WIN.require_unlocked_session(SESSION,time.monotonic()+10)
    def test_screenshield_can_reject_even_logind_false(self):
        c=Commands(False)
        def actual(argv,timeout):return {'stdout':b'(true,)' if 'gdbus' in argv else c(argv),'exitcode':0}
        with patch.object(WIN,'status_attempt',side_effect=actual):
            with self.assertRaisesRegex(WIN.EvidenceError,'obscures'):WIN.require_unlocked_session(SESSION,time.monotonic()+10)
    def test_unknown_or_truncated_dbus_fails_closed(self):
        with patch.object(WIN,'status_attempt',return_value={'stdout':'','exitcode':0,'overflow':True}):
            with self.assertRaises(WIN.EvidenceError):WIN.require_unlocked_session(SESSION,time.monotonic()+10)

    def test_each_nonzero_readback_names_only_the_failed_command(self):
        labels=['loginctl-show-session-'+k for k in ('Type','Active','State','Class','User','LockedHint')]+['gnome-screensaver-GetActive']
        for failed,label in enumerate(labels):
            with self.subTest(command=label):
                c=Commands(False);calls=[]
                def actual(argv,timeout):
                    calls.append(argv)
                    if len(calls)==failed+1:
                        return {'stdout':b'private-output','stderr':b'private-error','exitcode':3,'timeout':False,'overflow':False}
                    return {'stdout':c(argv),'stderr':b'','exitcode':0}
                with patch.object(WIN,'status_attempt',side_effect=actual):
                    with self.assertRaises(WIN.SessionLockReadbackError) as caught:
                        WIN.require_unlocked_session(SESSION,time.monotonic()+60)
                diag=caught.exception.diagnostics
                self.assertEqual(diag['command_id'],label);self.assertEqual(diag['exitcode'],3)
                self.assertEqual(len(calls),failed+1)
                self.assertNotIn('private-output',json.dumps(diag));self.assertNotIn('private-error',json.dumps(diag))
                self.assertNotIn('argv',diag)

    def test_timeout_keeps_same_bounded_budget_and_does_not_retry(self):
        with patch.object(WIN,'status_attempt',return_value={'stdout':b'','stderr':b'','exitcode':0,'timeout':True}) as attempt:
            with self.assertRaises(WIN.SessionLockReadbackError) as caught:
                WIN.require_unlocked_session(SESSION,time.monotonic()+60)
        diag=caught.exception.diagnostics
        self.assertTrue(diag['timeout']);self.assertEqual(diag['exitcode'],0)
        self.assertEqual(diag['requested_timeout_ms'],5000);attempt.assert_called_once()

    def test_overflow_diagnostics_are_bounded_without_stream_contents(self):
        raw={'stdout':b'x'*1000000,'stderr':b'y'*1000000,'exitcode':0,'overflow':True}
        with patch.object(WIN,'status_attempt',return_value=raw):
            with self.assertRaises(WIN.SessionLockReadbackError) as caught:
                WIN.require_unlocked_session(SESSION,time.monotonic()+60)
        diag=caught.exception.diagnostics
        self.assertTrue(diag['overflow']);self.assertEqual(diag['stdout']['bytes'],1000000)
        self.assertLess(len(json.dumps(diag)),1500)

    def test_unknown_successful_dbus_readback_still_rejected(self):
        c=Commands(False)
        def actual(argv,timeout):return {'stdout':b'()' if 'gdbus' in argv else c(argv),'exitcode':0}
        with patch.object(WIN,'status_attempt',side_effect=actual):
            with self.assertRaisesRegex(WIN.EvidenceError,'obscures') as caught:
                WIN.require_unlocked_session(SESSION,time.monotonic()+60)
        self.assertNotIsInstance(caught.exception,WIN.SessionLockReadbackError)

    def test_unknown_logind_identity_never_reaches_screensaver_check(self):
        c=Commands(False);c.foreign=True
        def actual(argv,timeout):return {'stdout':c(argv),'exitcode':0}
        with patch.object(WIN,'status_attempt',side_effect=actual):
            with self.assertRaisesRegex(WIN.EvidenceError,'locked or changed'):
                WIN.require_unlocked_session(SESSION,time.monotonic()+60)
        self.assertFalse(any('gdbus' in argv for argv in c.calls))

    def test_failure_json_retains_safe_diagnostics_and_remains_failure(self):
        error=WIN.SessionLockReadbackError('gnome-screensaver-GetActive',
            {'stdout':b'private-output','stderr':b'GDBus.Error:org.freedesktop.DBus.Error.NoReply private-token','exitcode':1},5,.25)
        args=SimpleNamespace(action='unlocked',timeout=10,dwell=0,run_id='run16',profile=WIN.PROFILE,attempt_nonce='nonce')
        stream=io.StringIO()
        with patch.object(WIN,'parser',return_value=SimpleNamespace(parse_args=lambda:args)),patch.object(WIN,'validate_common',return_value=(None,None)),patch.object(WIN,'unlocked',side_effect=error),patch.object(WIN.sys,'stdout',stream):
            self.assertEqual(WIN.main(),1)
        value=json.loads(stream.getvalue())
        self.assertEqual(value['status'],'FAIL');self.assertTrue(value['diagnosticOnly'])
        self.assertEqual(value['run_id'],'run16');self.assertEqual(value['phase'],'unlocked')
        self.assertEqual(value['lock_readback_failure']['dbus_error_names'],['org.freedesktop.DBus.Error.NoReply'])
        self.assertNotIn('private-token',stream.getvalue());self.assertNotIn('private-output',stream.getvalue())

    def test_driver_locked_precapture_never_requests_qmp(self):
        import sys
        repo=next(x for x in Path(__file__).resolve().parents if (x/'deploy/release_lab/lab.py').is_file())
        sys.path.insert(0,str(repo))
        driver=load('deploy.release_lab._lock_staged_driver','linux_gui_driver.py')
        from deploy.release_lab import lab
        from types import SimpleNamespace
        fake=SimpleNamespace(launch={'owned':True},collect=None,_execute=lambda action:(_ for _ in ()).throw(WIN.EvidenceError('locked')))
        with patch.object(lab,'QmpClient') as qmp:
            with self.assertRaisesRegex(WIN.EvidenceError,'locked'):driver.LinuxGuiDriver.capture_and_collect(fake)
        qmp.assert_not_called()

    def test_driver_precapture_and_helper_postcapture_guards(self):
        import ast
        source=(ROOT/'linux_gui_driver.py').read_text();tree=ast.parse(source)
        method=next(n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name=='capture_and_collect')
        guard=next(n.lineno for n in ast.walk(method) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='_execute' and n.args and isinstance(n.args[0],ast.Constant) and n.args[0].value=='unlocked')
        qmp=next(n.lineno for n in ast.walk(method) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='request')
        self.assertLess(guard,qmp)
        source=(ROOT/'guest_helpers/linux_gui_window_evidence.py').read_text();tree=ast.parse(source)
        for name in ('launch','collect'):
            method=next(n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name==name)
            self.assertTrue(any(isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='require_unlocked_session' for n in ast.walk(method)))

if __name__=='__main__':unittest.main()
