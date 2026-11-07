import base64, inspect, json, os, pathlib, socket
from types import SimpleNamespace
import pytest

from deploy.release_lab import headless_preexisting_fixture_guest as guest
from deploy.release_lab.headless_preexisting_fixture import BinaryIdentity,FixturePlan

def plan_dict():
    return {"run_id":"compat-run","profile":"linux-headless-x64","nonce":"1"*48,"controller_nonce":"2"*48,"runtime_uid":1000,
      "owned_root":"/var/lib/amnezia-release-lab/runs/compat-run/fixture","socket_path":"/run/amnezia/amneziad.sock",
      "cli":{"path":"/usr/bin/amnezia-cli","sha256":"a"*64},"setup_daemon":{"path":"/usr/bin/amneziad","sha256":"b"*64},
      "legacy_daemon":{"path":"/var/lib/amnezia-release-lab/artifacts/amneziad-5.0.1.38","sha256":"c"*64},"setup_version":"5.0.1.39","legacy_version":"5.0.1.38"}

def test_load_plan_and_entrypoints_are_exact(tmp_path):
    path=tmp_path/"plan.json"; path.write_text(json.dumps(plan_dict()))
    p=guest.load_plan(str(path)); assert isinstance(p,FixturePlan) and p.legacy_version=="5.0.1.38"
    source=inspect.getsource(guest.entry)
    for action in ("prepare","connect-collect","crash","legacy-start","baseline-handoff","cleanup"): assert action in source
    with pytest.raises(guest.GuestError,match="deadline"): guest.entry(["connect-collect","--plan",str(path),"--deadline","2"])

def test_prepare_uses_real_netns_wireguard_http_and_never_emits_private_keys():
    source=inspect.getsource(guest.prepare)
    for fragment in ('"netns","add"','"type","veth"','"type","wireguard"','"/usr/bin/wg","set"','"http.server"','PersistentKeepalive = 5','p.routed_test_prefix'):
        assert fragment in source
    assert 'write_private(root/"secrets/server.key"' in source and 'write_private(root/"secrets/client.key"' in source
    assert '"server_key":server_key' not in source and '"client_key":client_key' not in source
    assert "stdout=log,stderr=log,start_new_session=True" in source
    assert '"--bind",p.routed_test_server.split(\'/\',1)[0]' in source
    assert "baseline_config=" in source and 'Table = off' in source and "_stage_config(p,p.baseline_config_path" in source

def test_connect_collect_invokes_product_cli_and_raw_kernel_wg_receipts():
    source=inspect.getsource(guest.connect_collect)
    assert 'for key in ("import","connect")' in source
    assert 'for key in ("doctor","list")' in source
    for text in ('"latest-handshakes"','"transfer"','"route","show","table","51821"','"rule","show"','GET /policy.json HTTP/'):
        assert text in source
    assert '["/usr/sbin/ip","-4","-j","route","get",target]' in source
    assert '["/usr/bin/ping","-n","-c","1","-W","3","-I",p.wg_interface,target]' in source
    assert '.splitlines() if line.strip()]' in source
    assert "p.managed_receipts" in source and "main_pid()" in source

def test_failed_disconnect_keeps_command_output_only_in_protected_receipt(tmp_path,monkeypatch):
    argv=["/usr/bin/amnezia-cli","--socket","/run/amnezia/amneziad.sock","--json","disconnect"]
    stdout='{"error":"private-stdout-token","message":"disconnect detail"}'
    stderr='{"error":"private-stderr-token","code":"backend_failed"}'
    def fake_run(command,timeout,**kwargs):
        if command[0]=="/usr/bin/amnezia-cli":
            assert command==argv and timeout==60 and kwargs=={"ok":False}
            return {"argv":command,"rc":1,"stdout":stdout,"stderr":stderr,
                    "stdout_sha256":guest.hashlib.sha256(stdout.encode()).hexdigest(),
                    "stderr_sha256":guest.hashlib.sha256(stderr.encode()).hexdigest()}
        assert command[:2]==["/usr/bin/journalctl","-u"] and timeout==20 and kwargs=={"ok":False}
        return {"argv":command,"rc":0,"stdout":"amneziad healthy\n","stderr":"",
                "stdout_sha256":guest.hashlib.sha256(b"amneziad healthy\n").hexdigest(),
                "stderr_sha256":guest.hashlib.sha256(b"").hexdigest()}
    monkeypatch.setattr(guest,"run",fake_run)
    with pytest.raises(guest.CliFailure) as raised:
        guest.run_cli(argv,"disconnect",tmp_path)
    diagnostic=raised.value.diagnostic
    assert diagnostic["stage"]=="disconnect" and diagnostic["argv"]==argv and diagnostic["rc"]==1
    assert diagnostic["stdout"]["size"]==len(stdout.encode()) and diagnostic["stderr"]["size"]==len(stderr.encode())
    assert "private-stdout-token" not in json.dumps(diagnostic) and "private-stderr-token" not in json.dumps(diagnostic)
    protected=json.loads((tmp_path/"cli-failure-disconnect.protected.json").read_text())
    assert base64.b64decode(protected["stdout_b64"]).decode()==stdout
    assert base64.b64decode(protected["stderr_b64"]).decode()==stderr

def test_exact_kill_revalidates_full_identity(monkeypatch):
    identity={"pid":55,"start_ticks":9,"exe":"/owned/x","exe_sha256":"a"*64,"uid":0,"cmdline_sha256":"b"*64}
    signals=[]; monkeypatch.setattr(guest,"proc_id",lambda _:dict(identity)); monkeypatch.setattr(guest.os,"kill",lambda pid,sig:signals.append((pid,sig)))
    guest.exact_kill(identity); assert signals==[(55,getattr(guest.signal,"SIGKILL",9))]
    monkeypatch.setattr(guest,"proc_id",lambda _:{**identity,"start_ticks":10})
    with pytest.raises(guest.GuestError,match="start_ticks"): guest.exact_kill(identity)

def test_retirement_race_preserves_replaced_canonical_and_protected_recovery(tmp_path):
    source=tmp_path/"routing-controller.json"; source.write_bytes(b"original")
    identity=(source.stat().st_dev,source.stat().st_ino); retiring=tmp_path/".routing-controller.json.retiring"; source.rename(retiring)
    source.write_bytes(b"foreign")
    expected={"path":str(source),"sha256":guest.hashlib.sha256(b"original").hexdigest()}
    with pytest.raises(guest.GuestError,match="protected recovery"):
        guest._rollback_managed_receipts(tmp_path,[(source,retiring,expected,identity)],"postrename identity drift")
    assert source.read_bytes()==b"foreign" and retiring.read_bytes()==b"original"
    recovery=tmp_path/"managed-receipt-retirement-recovery.json"
    assert recovery.is_file()
    if os.name=="posix": assert recovery.stat().st_mode & 0o777 == 0o600

def test_cleanup_requires_legacy_identity_and_official_disconnect_before_network_delete():
    source=inspect.getsource(guest.cleanup)
    assert 'legacy identity absent; refusing' in source
    assert '"--json","disconnect"' in source
    assert 'result.get("state")!="disconnected"' in source
    assert 'exact_kill(identity)' in source
    assert '["/usr/sbin/ip","netns","del",p.netns]' in source
    assert 'netns_inode' in source and 'network cleanup incomplete' in source

def test_crash_requires_controller_archive_path_hash_and_nonce():
    source=inspect.getsource(guest.crash)
    assert 'controller_archive_path' in source and 'controller_archive_sha256' in source
    assert '/var/lib/amnezia-release-lab/receipts/' in source
    assert 'controller_nonce' in source and 'durable connected receipt hash mismatch' in source
    assert 'Restart=no' in source and '"daemon-reload"' in source
    assert 'effective!="no"' in source and 'current daemon restarted' in source
    assert 'remove_stale_control_socket' in source and 'MainPID' in source
    unit=(pathlib.Path(__file__).resolve().parents[2]/"headless"/"amneziad.service.in").read_text()
    assert "RuntimeDirectory=amnezia" in unit and "RuntimeDirectoryMode=0750" in unit and "Group=amnezia" in unit

def test_baseline_handoff_uses_product_disconnect_graceful_stop_and_own_only_forward_connect():
    source=inspect.getsource(guest.baseline_handoff)
    for token in ('"--json","disconnect"','"/usr/bin/systemctl","stop","amneziad.service"','"ActiveState":"inactive"','for key in ("import","connect")','c["baseline_cli"][key]','"routed_probe"'):
      assert token in source
    assert "exact_kill" not in source and "managed-routes.json" not in source
    assert 'run_cli([p.cli.path,"--socket",p.socket_path,"--json","disconnect"],"disconnect",root)' in source
    assert 'status=parse_cli(run(c["baseline_cli"]["status"],10))' in source
    assert 'status=parse_cli(run_cli(c["baseline_cli"]["status"],"status",root))' in source
    assert 'for key in ("doctor","list"):cli[key]=parse_cli(run_cli(c["baseline_cli"][key],key,root))' in source

@pytest.mark.skipif(os.name!="posix" or os.geteuid()!=0,reason="requires root POSIX socket identity")
def test_stale_control_socket_is_removed_but_live_wrong_and_replaced_are_rejected(tmp_path,monkeypatch):
    tmp_path.chmod(0o750)
    managed=(tmp_path/"managed-routes.json",tmp_path/"routing-controller.json")
    for item in managed: item.write_bytes(b"state")
    path=tmp_path/"amneziad.sock"
    stale=socket.socket(socket.AF_UNIX);stale.bind(str(path));stale.close();path.chmod(0o660)
    result=guest.remove_stale_control_socket(str(path),os.getgid(),tuple(map(str,managed)))
    assert result["removed"] is True and result["managed_before"]==result["managed_after"] and not path.exists()
    live=socket.socket(socket.AF_UNIX);live.bind(str(path));live.listen(1);path.chmod(0o660)
    with pytest.raises(guest.GuestError,match="not proven stale"): guest.remove_stale_control_socket(str(path),os.getgid(),tuple(map(str,managed)))
    live.close();path.unlink()
    wrong=socket.socket(socket.AF_UNIX);wrong.bind(str(path));wrong.close();path.chmod(0o600)
    with pytest.raises(guest.GuestError,match="identity mismatch"): guest.remove_stale_control_socket(str(path),os.getgid(),tuple(map(str,managed)))
    path.unlink()
    first=socket.socket(socket.AF_UNIX);first.bind(str(path));first.close();path.chmod(0o660);real_stat=os.stat;calls={"n":0}
    def changed_stat(name,*args,**kwargs):
      value=real_stat(name,*args,**kwargs)
      if name==path.name and kwargs.get("dir_fd") is not None:
        calls["n"]+=1
        if calls["n"]==2:
          fields={key:getattr(value,key) for key in ("st_dev","st_ino","st_ctime_ns","st_mode","st_uid","st_gid")};fields["st_ctime_ns"]+=1
          return SimpleNamespace(**fields)
      return value
    monkeypatch.setattr(guest.os,"stat",changed_stat)
    with pytest.raises(guest.GuestError,match="identity changed"): guest.remove_stale_control_socket(str(path),os.getgid(),tuple(map(str,managed)))
    assert path.exists()

def test_private_write_is_exclusive_nofollow_and_0600(tmp_path):
    path=tmp_path/"secret"; guest.write_private(path,b"secret")
    assert path.read_bytes()==b"secret"
    if os.name=="posix": assert (path.stat().st_mode&0o777)==0o600
    with pytest.raises(FileExistsError): guest.write_private(path,b"replace")
    assert "O_NOFOLLOW" in inspect.getsource(guest.write_private)
