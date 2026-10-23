import copy
import hashlib
import json

import pytest

from deploy.release_lab.windows_netstack_fixture_contract import FILES, checked_manifest, strict_json, validate_observed, bind_manifest


def test_manifest_rehashes_every_staged_file_and_exact_candidate(tmp_path):
    files = {}
    for key, name in FILES.items():
        path = tmp_path / name
        path.write_bytes(key.encode())
        files[key] = {"path": str(path), "sha256": hashlib.sha256(key.encode()).hexdigest(), "size": len(key)}
    value = {"schema": 1, "candidate_artifact_sha256": "a" * 64, "installed_exe_sha256": "b" * 64, "files": files}
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(value))
    sha = hashlib.sha256(path.read_bytes()).hexdigest()
    assert checked_manifest(path, sha, "a" * 64) == value
    with pytest.raises(ValueError):
        checked_manifest(path, sha, "c" * 64)
    (tmp_path / FILES["helper"]).write_bytes(b"changed")
    with pytest.raises(ValueError):
        checked_manifest(path, sha, "a" * 64)
    path.write_text("{}")
    with pytest.raises(ValueError):
        checked_manifest(path, sha, "a" * 64)


def test_private_json_rejects_duplicates_and_trailing():
    for text in ('{"a":1,"a":2}', '{}{}', '{} trailing', '{"a":NaN}', '{"a":Infinity}'):
        with pytest.raises(ValueError):
            strict_json(text)


def test_capsule_and_actual_child_binding_without_any_guest(tmp_path, capsys):
    from deploy.release_lab.windows_netstack_fixture.prepare_capsule import prepare
    helper, observer = tmp_path/'fixture.exe', tmp_path/'observer.ps1'
    helper.write_bytes(b'offline-placeholder-never-executed')
    observer.write_bytes(b'offline-placeholder-never-executed')
    output=tmp_path/'private-input'
    prepare(output, helper, observer, 'a'*64, 'b'*64)
    receipt=json.loads(capsys.readouterr().out)
    value=checked_manifest(receipt['manifest'], receipt['sha256'], 'a'*64)
    original=(output/'config.json').read_bytes()
    bound, sha, nonce, token=bind_manifest(value,tmp_path/'bound',run_id='fresh',case_id='outer-clean',vm_id='12345678-1234-1234-1234-123456789abc')
    verified=checked_manifest(bound,sha,'a'*64)
    config=strict_json((tmp_path/'bound'/'config.json').read_bytes())
    assert config['vm_id']=='12345678-1234-1234-1234-123456789abc'
    assert config['nonce']==nonce and len(token)==48
    assert config['routes_sha256']==verified['files']['routes']['sha256']
    assert (output/'config.json').read_bytes()==original
    assert len(strict_json((output/'expected-routes.json').read_bytes()))==5
    with pytest.raises(FileExistsError):
        bind_manifest(value,tmp_path/'bound',run_id='fresh',case_id='outer-clean',vm_id=config['vm_id'])


def test_guest_proof_rejects_forged_identity_and_cleanup():
    binding = dict(run_id="run", case_id="outer-clean", vm_id="vm", nonce="nonce", task_token="task",
                   parent_sha256="parent", artifact_sha256="artifact", manifest_sha256="manifest", helper_sha256="helper", routes_sha256="routes")
    value = dict(action="netstack-fixture", run_id="run", case_id="outer-clean", vm_id="vm", nonce="nonce",
                 task_token="task", parent_sha256="parent", candidate_artifact_sha256="artifact",
                 transport="hyperv-powershell-direct", origin="guest", injected=False,
                 production_journal=False, migration_pass=False, runtime_pass=False, manifest_sha256="manifest",
                 cleanup=dict(helper_process_absent=True, helper_udp_ports_absent=True,
                              observer_task_removed=True, observer_process_absent=True),
                 observation=dict(run_id="run", case_id="outer-clean", vm_id="vm", nonce="nonce", task_token="task",
                                  capability_observed=True, production_journal=False, runtime_pass=False, migration_pass=False, feed_sha256="routes"))
    lease = dict(run_id="run", case_id="outer-clean", vm_id="vm", nonce="nonce", exe_sha256="helper", routes_sha256="routes",
                 production_journal=False, runtime_pass=False, pid=123, process_start_unix_ns=1000, source_udp_port=1234, target_udp_port=1235, ready=True)
    value.update(lease=lease, terminal=dict(lease, terminal_state="closed_by_owned_process"))
    value["observation"].update(known_nonce_proved=True, gui_visible=True, route_shape="synthetic-windows-dataplane-v1", fixture_prefix_count=1266,
        native_before=dict(last_handshake_time_sec="1", rx_bytes="2", tx_bytes="3"),
        native_after=dict(last_handshake_time_sec="1", rx_bytes="4", tx_bytes="5"),
        before=dict(routes=["a"], **{k: dict(pid=100, start_ticks=1000, exe="app.exe") for k in ("gui", "service", "tunnel")}),
        after=dict(routes=["a"], **{k: dict(pid=100, start_ticks=1000, exe="app.exe") for k in ("gui", "service", "tunnel")}))
    assert validate_observed(value, **binding) == value
    mutations = [lambda v, k=k: v.__setitem__(k, "foreign") for k in ("run_id", "case_id", "vm_id", "nonce", "task_token", "parent_sha256", "candidate_artifact_sha256")]
    mutations += [lambda v: v.__setitem__("injected", True), lambda v: v.__setitem__("runtime_pass", True),
                  lambda v: v["cleanup"].__setitem__("helper_process_absent", False),
                  lambda v: v["cleanup"].__setitem__("helper_udp_ports_absent", False),
                  lambda v: v["cleanup"].__setitem__("observer_task_removed", False),
                  lambda v: v["cleanup"].__setitem__("helper_process_absent", 1),
                  lambda v: v["lease"].__setitem__("exe_sha256", "foreign"),
                  lambda v: v["terminal"].__setitem__("pid", 124),
                  lambda v: v["observation"].__setitem__("migration_pass", True),
                  lambda v: v["observation"].__setitem__("task_token", "stale")]
    for mutate in mutations:
        candidate = copy.deepcopy(value)
        mutate(candidate)
        with pytest.raises(ValueError):
            validate_observed(candidate, **binding)
