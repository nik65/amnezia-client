"""Freeze a minimal ordinary installer lab overlay; never starts guests or products."""
import argparse
import hashlib
import json
import re
import shutil
from pathlib import Path

BASE_CONTROLLER_SHA = 'b29226e77847ddff3f3d6695174cf7291f9b09f29d1f58fa6be414892f7ba223'
BASE_ADAPTER_SHA = '8ffb2ee33e63228af146f1cf7ac1d3699be9788c4ab7d127143465cbaea58321'


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('frozen payload overlay anchor changed')
    return text.replace(old, new, 1)


METHOD = '''    def observe_windows_payload(self, run_id, case_id, stage_name, artifact, role, version, vm_id, parent_sha256):
        if getattr(self, "_installed_payload_plan", None) is None:
            return None
        nonce = secrets.token_hex(24)
        value = self.hyperv_call("installed-payload", run_id=run_id, CaseId=case_id, credential=True,
            ExpectedSha256=artifact["sha256"], ArtifactSize=artifact["size"], ExpectedArtifactRole=role,
            ExpectedVersion=version, AttemptNonce=nonce)
        installed_payload.validate(value, run_id=run_id, case_id=case_id, vm_id=vm_id,
            parent_sha256=parent_sha256, artifact=artifact, role=role, version=version, nonce=nonce,
            files=self._installed_payload_plan["artifacts"][artifact["sha256"]]["files"])
        export = self.root / "exports" / run_id / "windows-x64" / case_id / (stage_name + "-" + nonce + "-installed-payload.json")
        if export.exists():
            raise LabError("installed payload observation already archived; use fresh case/run")
        immutable_json_dump(export, value)
        checkpoint = self.get_run(run_id)
        profile = checkpoint["profiles"]["windows-x64"]
        profile.setdefault("installed_payload_observations", []).append(dict(stage=stage_name, case_id=case_id,
            evidence=value, archive=str(export), plan_sha256=self._installed_payload_plan_sha256))
        state=self.load_state(); state["runs"][run_id]=checkpoint; self.save_state(state)
        return value

'''


def patch_controller(text):
    text = replace_once(text, 'from urllib.parse import unquote, urlparse', '''from urllib.parse import unquote, urlparse
try:
    import windows_installed_payload_contract as installed_payload
except ImportError:
    from . import windows_installed_payload_contract as installed_payload''')
    old = '    @mutation_operation\n    def run_steps(self, run_id: str, profile_id: str, selected: Iterable[str] | None = None, preserve_failed_guest: bool = False) -> dict[str, Any]:'
    text = replace_once(text, old, METHOD + old.replace('preserve_failed_guest: bool = False)', 'preserve_failed_guest: bool = False, installed_payload_plan: Path | None = None, installed_payload_plan_sha256: str | None = None)'))
    anchor = '        if self.uses_hyperv(planned_run, profile_id):\n            if preserve_failed_guest'
    text = replace_once(text, anchor, '''        self._installed_payload_plan = None
        if installed_payload_plan is not None or installed_payload_plan_sha256 is not None:
            if (not installed_payload_plan or not installed_payload_plan_sha256 or self.dry_run
                    or profile_id != "windows-x64" or not self.uses_hyperv(planned_run, profile_id)):
                raise LabError("installed payload observer requires actual Hyper-V Windows run and frozen plan")
            expected_artifacts = [planned_run["artifacts"][artifact_id], baseline,
                planned_run["outer_artifact"], planned_run["baseline_outer_artifact"]]
            self._installed_payload_plan = installed_payload.checked_plan(installed_payload_plan,
                installed_payload_plan_sha256, expected_artifacts)
            self._installed_payload_plan_sha256 = installed_payload_plan_sha256
        if self.uses_hyperv(planned_run, profile_id):
            if preserve_failed_guest''')
    anchor = '                        case_steps.append({"stage": stage_name, "action": action, "passed": True, "guest_receipt": receipt, "vm_id": result.get("vm_id"), "parent_sha256": result.get("parent_sha256")})'
    text = replace_once(text, anchor, '''                        current_phase = "installed-payload:" + stage_name
                        self.observe_windows_payload(run_id, case_id, stage_name, selected_artifact, selected_role,
                            expected_version, str(result["vm_id"]), result["parent_sha256"])
''' + anchor)
    anchor = '                checkpoint_profile["interactive_receipt"] = interactive_receipt'
    text = replace_once(text, anchor, '''                self.observe_windows_payload(run_id, interactive_case, "candidate-outer-interactive", outer_candidate,
                    "candidate", str(planned_run["candidate_version"]), expected_vm_id, app_window["parent_sha256"])
                checkpoint_run = self.get_run(run_id)
                checkpoint_profile = checkpoint_run["profiles"][profile_id]
''' + anchor)
    # Final state reload below already preserves the separate observation list.
    text = replace_once(text, '            command.add_argument("--preserve-failed-guest", action="store_true")', '''            command.add_argument("--preserve-failed-guest", action="store_true")
            command.add_argument("--installed-payload-plan", type=Path)
            command.add_argument("--installed-payload-plan-sha256")''')
    text = replace_once(text, '        elif args.command == "run": result = controller.run_steps(args.run_id, args.profile, args.step or None, args.preserve_failed_guest)', '''        elif args.command == "run":
            payload_args = {}
            if args.installed_payload_plan is not None or args.installed_payload_plan_sha256 is not None:
                payload_args = dict(installed_payload_plan=args.installed_payload_plan, installed_payload_plan_sha256=args.installed_payload_plan_sha256)
            result = controller.run_steps(args.run_id, args.profile, args.step or None, args.preserve_failed_guest, **payload_args)''')
    return text


def patch_adapter(text, action):
    text = replace_once(text, "'relays-stop','publish')]", "'relays-stop','publish','installed-payload')]")
    anchor = 'if ($null -eq $child) { $child = Read-Child $RunsRoot $RunId $ParentRoot $CaseId }'
    text = replace_once(text, anchor, action + '\n' + anchor + '''
if ($Action -eq 'installed-payload') {
    $payloadChild=Read-Child $RunsRoot $RunId $ParentRoot $CaseId
    Emit (Read-OwnedInstalledPayload $payloadChild $RunId $CaseId $ExpectedSha256 $ArtifactSize $ExpectedArtifactRole $ExpectedVersion $AttemptNonce); exit 0
}''')
    return text


COPY_TREES = ('deploy/release_lab', 'deploy/selfhosted_updates')


def input_paths(source):
    """Enumerate every consumed byte; keys include their independent authority root."""
    own = Path(__file__).resolve().parent
    paths = {}
    for directory in COPY_TREES:
        root = source / directory
        if not root.is_dir():
            raise ValueError('missing input tree: ' + directory)
        for path in root.rglob('*'):
            if '__pycache__' in path.parts or path.suffix == '.pyc':
                continue
            if path.is_symlink():
                raise ValueError('symlink input refused: ' + str(path))
            if path.is_file():
                paths['source:' + path.relative_to(source).as_posix()] = path
    for name in ('windows_installed_payload_contract.py', 'windows_host/installed_payload_action.ps1'):
        paths['overlay:' + name] = own / name
    fixture_root = own.parents[1] / 'dist/release-lab-fixtures'
    dependencies=['android-cvd-vulkan-noble-amd64-20260913.tar.gz']
    dependencies += ['android-cvd-vulkan-noble-amd64-20260913/'+name for name in
        ('bundle-manifest.json','verifier-receipt.json','libvulkan1_1.3.275.0-1build1_amd64.deb')]
    dependencies += ['android-cvd-host-dependencies-noble-amd64-20260913/'+name for name in
        ('bundle-manifest.json','verifier-receipt.json','ubuntu-keyring.gpg','noble-InRelease','noble-Packages',
         'noble-updates-InRelease','noble-updates-Packages','noble-security-InRelease','noble-security-Packages',
         'google-keyring.gpg','google-cuttlefish-InRelease','google-cuttlefish-Packages',
         'wayland-verifier-receipt.json','android-cvd-wayland-supplement-3b2a227c.tar')]
    for relative in dependencies:
        paths['fixture:' + relative] = fixture_root / relative
    return paths


def file_record(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError('missing or nonregular input: ' + str(path))
    data = path.read_bytes()
    return dict(sha256=hashlib.sha256(data).hexdigest(), size=len(data))


def checked_inputs(paths, manifest_path, expected_sha256):
    try:
        from .windows_installed_payload_contract import strict_json
    except ImportError:
        from windows_installed_payload_contract import strict_json
    raw = manifest_path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError('input manifest SHA256 mismatch')
    manifest = strict_json(raw.decode('utf-8'))
    if (not isinstance(manifest, dict) or set(manifest) != {'schema', 'scope', 'files'}
            or type(manifest['schema']) is not int or manifest['schema'] != 1
            or manifest['scope'] != 'ordinary-payload-generator-inputs'):
        raise ValueError('invalid input manifest schema/scope')
    records = manifest.get('files')
    if not isinstance(records, dict) or set(records) != set(paths):
        raise ValueError('input manifest does not cover exact full input set')
    for key, path in paths.items():
        record = records[key]
        if (not isinstance(record, dict) or set(record) != {'sha256', 'size'}
                or not isinstance(record['sha256'], str)
                or re.fullmatch(r'[0-9a-f]{64}', record['sha256']) is None
                or type(record['size']) is not int or record['size'] < 0):
            raise ValueError('invalid input manifest record: ' + key)
        if file_record(path) != record:
            raise ValueError('input drift: ' + key)
    return records


def prepare(source, output, input_manifest, input_manifest_sha256):
    source, output = Path(source), Path(output)
    paths = input_paths(source)
    records = checked_inputs(paths, Path(input_manifest), input_manifest_sha256)
    lab = source / 'deploy/release_lab'
    controller = lab / 'lab.py'; adapter = lab / 'windows_host/hyperv_adapter.ps1'
    if file_record(controller)['sha256'] != BASE_CONTROLLER_SHA or file_record(adapter)['sha256'] != BASE_ADAPTER_SHA:
        raise ValueError('ordinary base controller/adapter is not immutable b292 closure')
    # Precompute transformed bytes only from the manifest-verified inputs.
    own = Path(__file__).resolve().parent
    def verified_text(key):
        data = paths[key].read_bytes()
        if dict(sha256=hashlib.sha256(data).hexdigest(), size=len(data)) != records[key]:
            raise ValueError('input drift while transforming: ' + key)
        return data.decode('utf-8-sig').replace('\r\n', '\n').replace('\r', '\n')
    generated = {
        'deploy/release_lab/lab.py': patch_controller(verified_text('source:deploy/release_lab/lab.py')).encode('utf-8'),
        'deploy/release_lab/windows_host/hyperv_adapter.ps1': patch_adapter(
            verified_text('source:deploy/release_lab/windows_host/hyperv_adapter.ps1'),
            verified_text('overlay:windows_host/installed_payload_action.ps1')).encode('utf-8-sig'),
    }
    checked_inputs(input_paths(source), Path(input_manifest), input_manifest_sha256)
    output.mkdir(parents=True, exist_ok=False)
    expected_output = {}
    for key, path in paths.items():
        authority, relative = key.split(':', 1)
        if authority == 'source': destination = relative
        elif authority == 'fixture': destination = 'dist/release-lab-fixtures/' + relative
        elif relative == 'windows_installed_payload_contract.py': destination = 'deploy/release_lab/' + relative
        else: continue  # fragment is consumed into the transformed adapter only
        target = output / destination
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
        expected_output[destination] = records[key]
    for relative, data in generated.items():
        (output / relative).write_bytes(data)
        expected_output[relative] = dict(sha256=hashlib.sha256(data).hexdigest(), size=len(data))
    checked_inputs(input_paths(source), Path(input_manifest), input_manifest_sha256)
    actual_output = {p.relative_to(output).as_posix(): file_record(p)
                     for p in output.rglob('*') if p.is_file()}
    if actual_output != expected_output:
        raise ValueError('copied output does not match verified full input closure')
    records = [dict(path=name, **record) for name, record in sorted(actual_output.items())]
    manifest=dict(schema=1,scope='ordinary-installer-read-only-installed-payload-overlay',base_controller_sha256=BASE_CONTROLLER_SHA,
        base_adapter_sha256=BASE_ADAPTER_SHA,input_manifest_sha256=input_manifest_sha256,
        product_source_changed=False,guest_executed=False,files=records)
    path=output/'LAB_TOOLING_FREEZE.json';path.write_text(json.dumps(manifest,indent=2)+'\n')
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--input-manifest',type=Path,required=True);p.add_argument('--input-manifest-sha256',required=True)
    a=p.parse_args();path,sha=prepare(a.source,a.output,a.input_manifest,a.input_manifest_sha256);print(json.dumps(dict(manifest=str(path.resolve()),sha256=sha,guest_executed=False)))
