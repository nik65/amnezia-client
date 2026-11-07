"""Read-only journal parser and inert full-observe regression; no VM/services."""
import base64,contextlib,io,json,os,subprocess,unittest
from unittest.mock import Mock,patch
from .guest_helpers import linux_gui_readiness_probe as guest

BOOT='f2551ecf-0238-41af-b688-77c49e55489c'
HEX='f2551ecf023841afb68877c49e55489c'

class ReadinessProbe(unittest.TestCase):
    def test_actual_bounded_xres_reply_survives_pending_and_parse_or_identity_failure(self):
        shell={'pid':1262,'start_ticks':100,'exe':'/usr/bin/gnome-shell','uid':1000,'state':'S'}
        env={b'GALLIUM_DRIVER':b'softpipe',b'DISPLAY':b':0',b'XAUTHORITY':b'/run/user/1000/gdm/Xauthority'}
        for reply,error in [(b'{"identityGap":"xres-no-local-pid","localPID":null}',False),
                            (b'not JSON',True),(b'{"identityGap":null,"localPID":999}',True)]:
            with self.subTest(reply=reply):
                def command(args,**kwargs):
                    if args[0]=='journalctl':return (json.dumps({'_BOOT_ID':HEX,'MESSAGE':'GNOME Shell started'})+'\n').encode()
                    if args[0]=='pgrep':return b'1262\n'
                    if 'gnome-session-initialized.target' in args:return b'active\n'
                    if '/usr/bin/python3' in args:
                        self.assertEqual(kwargs['limit'],32768)
                        return reply
                    raise AssertionError(args)
                printed=io.StringIO()
                with patch.object(guest,'Path',return_value=Mock(read_text=lambda:BOOT)),patch.object(guest,'command',side_effect=command),patch.object(guest,'process_identity',return_value=(shell,env)),contextlib.redirect_stdout(printed):
                    if error:
                        with self.assertRaises((RuntimeError,json.JSONDecodeError)):guest.observe('inert-xres-source')
                        result=json.loads(printed.getvalue())
                    else:
                        result=guest.observe('inert-xres-source')
                        self.assertEqual(result['pending_reason'],'wm-initialization-pending')
                        self.assertEqual(result['xres']['identityGap'],'xres-no-local-pid')
                self.assertEqual(base64.b64decode(result['xres_reply_base64']),reply)
                self.assertIsNone(result['observation'])

    def test_canonical_boot_identity_normalized_only_for_journalctl(self):
        self.assertEqual(guest.journal_boot_selector(BOOT),HEX)
        with self.assertRaises((ValueError,RuntimeError)):guest.journal_boot_selector('not-a-boot')
        with self.assertRaises(RuntimeError):guest.journal_boot_selector(HEX)

    @unittest.skipUnless(os.name=='posix','actual journalctl parser test requires POSIX')
    def test_actual_journalctl_parser_rejects_uuid_accepts_hex(self):
        # This boot is a saved guest ID, not a fabricated host boot. The accepted
        # selector may correctly report no matching journal; that is not PASS.
        try:
            bad=subprocess.run(['journalctl','--boot='+BOOT,'--no-pager','-n','0'],capture_output=True,timeout=3)
            good=subprocess.run(['journalctl','--boot='+guest.journal_boot_selector(BOOT),'--no-pager','-n','0'],capture_output=True,timeout=3)
        except FileNotFoundError:self.skipTest('journalctl unavailable')
        self.assertIn(b'Failed to parse boot descriptor',bad.stderr)
        self.assertNotIn(b'Failed to parse boot descriptor',good.stderr)
        self.assertIn(good.returncode,(0,1))

    def test_full_observe_retains_uuid_and_allows_healthy_scheduler_transition(self):
        identities=[{'pid':1262,'start_ticks':100,'exe':'/usr/bin/gnome-shell','uid':1000,'state':state} for state in ['R','S']]
        env={b'GALLIUM_DRIVER':b'softpipe',b'DISPLAY':b':0',b'XAUTHORITY':b'/run/user/1000/gdm/Xauthority'}
        calls=[]
        def command(args,**kwargs):
            calls.append(args)
            if args[0]=='journalctl':
                self.assertEqual(args[1],'--boot='+HEX)
                return (json.dumps({'_BOOT_ID':HEX,'MESSAGE':'GNOME Shell started'})+'\n').encode()
            if args[0]=='pgrep':return b'1262\n'
            if 'gnome-session-initialized.target' in args:return b'active\n'
            if '/usr/bin/python3' in args:return b'{"identityGap":null,"localPID":1262}'
            if args[:2]==['loginctl','list-sessions']:return b'1 1000 lab seat0 tty2\n'
            if args[:2]==['loginctl','show-session']:return b'Type=x11\nActive=yes\nState=active\nClass=user\nUser=1000\n'
            raise AssertionError(args)
        with patch.object(guest,'Path',return_value=Mock(read_text=lambda:BOOT)),patch.object(guest,'command',side_effect=command),patch.object(guest,'process_identity',side_effect=[(v,env) for v in identities]):
            result=guest.observe('inert-xres-source')
        self.assertEqual(result['boot_id'],BOOT);self.assertEqual(result['observation']['boot_id'],BOOT)
        self.assertEqual(result['observation']['shell']['state'],'R');self.assertEqual(result['observation']['wm']['owner_pid'],1262)
        self.assertEqual(len(calls),6)

    def test_scheduler_state_is_not_identity_but_death_and_pid_reuse_fail(self):
        before={'pid':1262,'start_ticks':100,'exe':'/usr/bin/gnome-shell','uid':1000,'state':'R'}
        self.assertTrue(guest.shell_identity_stable(before,{**before,'state':'S'}))
        for delta in [{'pid':1263},{'start_ticks':101},{'exe':'/bin/other'},{'uid':0},{'state':'Z'},{'state':'T'},{'state':'D'}]:
            with self.subTest(delta=delta):self.assertFalse(guest.shell_identity_stable(before,{**before,**delta}))

if __name__=='__main__':unittest.main()
