"""Fixed four-test capability for an owned disposable Hyper-V control child.

No producer registration or release PASS. Never executes a Windows binary on
this controller host. Native commands live only in the pinned guest helper.
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path, PureWindowsPath
import re
import secrets

TESTS = ('operator_command_tests.exe', 'privileged_ipc_security_tests.exe',
         'selfhosted_update_policy_tests.exe', 'windows_privileged_pipe_reuse_tests.exe')
SCHEMA = 'amnezia.native-windows-tests.v1'
RECEIPT = 'amnezia.native-windows-tests-receipt.v1'
RELATIVES = ('deploy/release_lab/native_windows_tests.py',
             'deploy/release_lab/windows_host/native_test_guest.ps1',
             'deploy/release_lab/windows_netstack_fixture/BoundedOperatorCapture.cs')
SHA = re.compile(r'[0-9a-f]{64}')


def _record(path):
    path = Path(path).absolute()
    if path.is_symlink() or not path.is_file():
        raise ValueError('native-test input must be a regular file')
    with path.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    return {'path': str(path), 'sha256': digest, 'size': path.stat().st_size}


def _local_windows_path(value):
    if not isinstance(value, str) or not re.match(r'^[A-Za-z]:[\\/]', value):
        return False
    path = PureWindowsPath(value)
    return path.is_absolute() and '..' not in path.parts and '\x00' not in value


def validate_manifest(value, *, candidate_sha256, version):
    expected = {'schema', 'candidate_sha256', 'candidate_version', 'compile_source_commit',
                'source_root', 'review_capsule', 'files'}
    if not isinstance(value, dict) or set(value) != expected or value['schema'] != SCHEMA:
        raise ValueError('native-test manifest shape')
    if value['candidate_sha256'] != candidate_sha256 or value['candidate_version'] != version:
        raise ValueError('native-test candidate binding')
    if not re.fullmatch(r'[0-9a-f]{40}', value['compile_source_commit']):
        raise ValueError('native-test source commit')
    if not _local_windows_path(value['source_root']):
        raise ValueError('native-test source root')
    capsule = value['review_capsule']
    if (not isinstance(capsule, dict) or set(capsule) != {'path', 'sha256', 'size'}
            or not _local_windows_path(capsule['path'])
            or not SHA.fullmatch(capsule['sha256']) or type(capsule['size']) is not int
            or not 0 < capsule['size'] <= 2 * 1024 * 1024):
        raise ValueError('native-test review capsule')
    rows = value['files']
    if not isinstance(rows, list) or not 4 <= len(rows) <= 64:
        raise ValueError('native-test file bound')
    names, exes, size = set(), set(), 0
    for row in rows:
        if not isinstance(row, dict) or set(row) != {'name', 'source', 'sha256', 'size'}:
            raise ValueError('native-test file shape')
        name = row['name']
        if (not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,119}', name)
                or name.casefold() in names or not SHA.fullmatch(row['sha256'])
                or type(row['size']) is not int or not 0 < row['size'] <= 128 * 1024 * 1024
                or not _local_windows_path(row['source'])
                or PureWindowsPath(row['source']).name != name):
            raise ValueError('native-test unsafe or duplicate file')
        if name in TESTS:
            exes.add(name)
        elif not name.endswith('.dll'):
            raise ValueError('native-test executable not allowlisted')
        names.add(name.casefold()); size += row['size']
    if exes != set(TESTS) or size > 512 * 1024 * 1024:
        raise ValueError('native-test executable closure or total bound')
    return value


def validate_receipt(value, *, run_id, vm_id, nonce, manifest_sha256):
    if (not isinstance(value, dict) or value.get('schema') != RECEIPT
            or value.get('run_id') != run_id or value.get('case_id') != 'control'
            or value.get('vm_id') != vm_id or value.get('attempt_nonce') != nonce
            or value.get('manifest_sha256') != manifest_sha256
            or value.get('marker_verified') is not True
            or value.get('files_unchanged') is not True or value.get('input_access_protected') is not True
            or value.get('passed') is not True):
        raise ValueError('native-test receipt ownership/input binding')
    token = value.get('token') or {}
    if (token.get('local') is not True or token.get('interactive') is not True
            or token.get('network') is not False or token.get('system') is not False
            or token.get('administrator') is not False or token.get('same_explorer') is not True
            or type(token.get('session_id')) is not int or token['session_id'] <= 0):
        raise ValueError('native-test receipt requires limited local interactive token')
    results = value.get('results')
    if not isinstance(results, list) or [row.get('name') for row in results] != list(TESTS):
        raise ValueError('native-test exact four results required')
    for row in results:
        if (type(row.get('native_exit')) is not int or row['native_exit'] != 0
                or row.get('started') is not True or row.get('drain_completed') is not True
                or row.get('owned_child_exited') is not True or row.get('timed_out') is not False
                or row.get('output_limit_exceeded') is not False or row.get('capture_failure') != ''
                or row.get('skip_count') != 0 or type(row.get('assertions')) is not int or row['assertions'] <= 0
                or row.get('failures') != 0 or row.get('files_unchanged') is not True or row.get('passed') is not True):
            raise ValueError('native-test capture or assertion failure')
        stdout = base64.b64decode(row['stdout_b64'], validate=True)
        stderr = base64.b64decode(row['stderr_b64'], validate=True)
        if len(stdout) > 4 * 65536 or len(stderr) > 4 * 65536:
            raise ValueError('native-test output bounds')
        text = stdout.decode('utf-8', errors='strict') + '\n' + stderr.decode('utf-8', errors='strict')
        summary = re.findall(r'^PASS: ([1-9][0-9]*) assertions, 0 failures\r?$', text, re.MULTILINE)
        if (len(summary) != 1 or int(summary[0]) != row['assertions']
                or re.search(r'\b(?:QSKIP|SKIP|Skipped)\b|^FAIL\b', text, re.MULTILINE)):
            raise ValueError('native-test original output does not prove nonvacuous no-skip success')
    return value


def validate_original_capture(capture):
    original = capture['original']
    rows = original.get('captures')
    allowed = {'receipt.json', 'failure.json'} | {name + '.capture.json' for name in TESTS}
    if not isinstance(rows, list) or len(rows) > 6:
        raise ValueError('native-test original output closure')
    seen, total, receipt_bytes = set(), 0, None
    for row in rows:
        if not isinstance(row, dict) or set(row) != {'name', 'size', 'sha256', 'bytes_b64'}:
            raise ValueError('native-test original output record')
        if row['name'] not in allowed or row['name'] in seen or type(row['size']) is not int:
            raise ValueError('native-test original output identity')
        data = base64.b64decode(row['bytes_b64'], validate=True)
        if len(data) != row['size'] or len(data) > 4 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != row['sha256']:
            raise ValueError('native-test original output bytes differ')
        total += len(data); seen.add(row['name'])
        if row['name'] == 'receipt.json': receipt_bytes = data
    if total > 8 * 1024 * 1024 or receipt_bytes is None:
        raise ValueError('native-test original receipt missing/bounds')
    if base64.b64decode(original['receipt_bytes_b64'], validate=True) != receipt_bytes:
        raise ValueError('native-test original receipt readbacks differ')
    if json.loads(receipt_bytes) != capture['receipt']:
        raise ValueError('native-test parsed receipt differs from original bytes')


def acquire(controller, run_id, *, manifest_path, expected_manifest_sha256):
    """One fresh run's control child; canonical start/probe/reset only."""
    from . import lab
    from .windows_credential_preparation import PreparedWindowsController
    if type(controller) is not PreparedWindowsController or controller.dry_run or controller.test_mode:
        raise lab.LabError('native tests require exact production prepared Windows controller')
    with controller.mutation_session('native-windows-tests'):
        controller.assert_mutation_context()
        run = controller.get_run(run_id)
        profile = run['profiles']['windows-x64']
        if (run.get('dry_run') or run.get('test_mode') or run.get('windows_backend') != 'hyperv'
                or profile.get('vm') or profile.get('hyperv_cases') or run.get('native_windows_tests')):
            raise lab.LabError('native tests require a fresh unspent Hyper-V run')
        controller.verify_acquisition_provenance(run_id)
        manifest_record = _record(manifest_path)
        if manifest_record['sha256'] != expected_manifest_sha256 or manifest_record['size'] > 128 * 1024:
            raise lab.LabError('native-test manifest bytes/bounds differ')
        manifest = validate_manifest(json.loads(Path(manifest_path).read_bytes()),
            candidate_sha256=run['artifacts']['windows-x64']['sha256'], version=run['candidate_version'])
        source = {relative: _record(lab.repo_root() / relative) for relative in RELATIVES}
        if _record(lab.hyperv_adapter_source()) != run['hyperv_records']['adapter']:
            raise lab.LabError('native-test adapter changed after create')
        windows_paths = {record['path']: lab.windows_path_for_wsl(Path(record['path']))
                         for record in (manifest_record, source[RELATIVES[1]], source[RELATIVES[2]])}
        attempt_nonce = secrets.token_hex(24)
        plan = {'manifest': manifest_record, 'source': source, 'attempt_nonce': attempt_nonce,
                'candidate': run['artifacts']['windows-x64'], 'run_id': run_id, 'case_id': 'control'}
        plan_path = lab.ensure_owned_child(controller.root,
            controller.root / 'runs' / run_id / 'native-windows-tests-plan.json', 'native test plan')
        lab.immutable_json_dump(plan_path, plan)
        state = controller.load_state(); state['runs'][run_id]['native_windows_tests'] = {
            'plan': _record(plan_path), 'state': 'planned', 'release_passed': False}; controller.save_state(state)
        started = False
        primary = None
        result = None
        try:
            started = True  # Includes partial canonical spawn intents requiring guarded reset.
            controller.start(run_id, 'windows-x64')
            controller.guest_probe(run_id, 'windows-x64')
            controller.hyperv_call('prepare-interactive', run_id=run_id, CaseId='control', credential=True)
            current = controller.get_run(run_id)
            vm_id = current['profiles']['windows-x64']['vm']['vm_id']
            for record in source.values():
                if _record(record['path']) != record: raise lab.LabError('native-test helper changed before capture')
            capture = controller.hyperv_call('native-tests', run_id=run_id, CaseId='control', credential=True,
                ChildVmId=vm_id, AttemptNonce=attempt_nonce,
                NativeManifestPath=windows_paths[manifest_record['path']],
                NativeManifestSha256=manifest_record['sha256'],
                NativeHelperPath=windows_paths[source[RELATIVES[1]]['path']],
                NativeHelperSha256=source[RELATIVES[1]]['sha256'],
                NativeCapturePath=windows_paths[source[RELATIVES[2]]['path']],
                NativeCaptureSha256=source[RELATIVES[2]]['sha256'])
            archive = lab.ensure_owned_child(controller.root,
                controller.root / 'runs' / run_id / 'native-windows-tests-capture.json', 'native test capture')
            lab.immutable_json_dump(archive, capture)  # Preserve original failures before validation/reset.
            if (capture.get('transport') != 'hyperv-powershell-direct' or capture.get('origin') != 'guest'
                    or capture.get('injected') is not False or capture.get('vm_id') != vm_id
                    or capture.get('host_bindings_unchanged') is not True
                    or capture.get('session_cleanup_confirmed') is not True
                    or capture.get('session_cleanup_failure') != ''
                    or capture.get('receipt_parse_failure') != ''
                    or type(capture.get('original', {}).get('task_exit')) is not int
                    or capture['original']['task_exit'] != 0
                    or capture['original'].get('task_started') is not True
                    or capture['original'].get('task_completed') is not True
                    or capture['original'].get('task_removed') is not True
                    or capture['original'].get('task_failure') != ''):
                raise lab.LabError('native-test capture transport binding')
            validate_original_capture(capture)
            receipt = validate_receipt(capture['receipt'], run_id=run_id, vm_id=vm_id,
                nonce=attempt_nonce, manifest_sha256=manifest_record['sha256'])
            if _record(manifest_record['path']) != manifest_record:
                raise lab.LabError('native-test manifest changed after capture')
            for record in source.values():
                if _record(record['path']) != record: raise lab.LabError('native-test helper changed after capture')
            result = {'native_tests_passed': True, 'release_passed': False, 'run_id': run_id,
                      'capture': _record(archive), 'results': receipt['results']}
            return result
        except BaseException as error:
            primary = error
            raise
        finally:
            if started:
                try:
                    cleanup = controller.reset(run_id, 'windows-x64')
                    final = controller.get_run(run_id)['profiles']['windows-x64']
                    if final.get('vm') is not None or final.get('status') != 'reset':
                        raise lab.LabError('native-test canonical cleanup incomplete')
                    if result is not None: result['cleanup'] = cleanup
                except BaseException as cleanup:
                    if primary is not None: primary.add_note('native-test owned cleanup incomplete: ' + type(cleanup).__name__)
                    else: raise
