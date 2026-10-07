"""Run the dedicated AWG migration scenario only through lab.py owned QMP/QGA.

No native network command or product binary is executed by this controller.
The immutable bundle supplies the reviewed guest helper and pinned native bytes.
This is migration evidence, not an updater/publication/release gate.
"""
import argparse
import hashlib
import json
import re
import tarfile
from pathlib import Path

from .lab import LabController, LabError, QgaClient, QmpClient, require_qmp_return, load_profiles, golden_readiness, artifact_record, validate_signed_manifest

PROFILE = 'linux-headless-x64'
ROLES = frozenset(('amneziad', 'amnezia-cli', 'amneziawg-go', 'awg', 'awg-quick', 'service.py', 'guest.py'))


def validate_bundle(directory):
    directory = Path(directory).resolve()
    plan = json.loads((directory / 'bundle.json').read_text())
    if set(plan) != {'schema', 'sourceCommit', 'files', 'goReceipt', 'toolsReceipt'} or plan['schema'] != 1:
        raise LabError('migration bundle schema')
    if not re.fullmatch(r'[0-9a-f]{40}', plan['sourceCommit']) or set(plan['files']) != ROLES:
        raise LabError('migration bundle roles/source')
    for name, expected in plan['files'].items():
        path = directory / name
        if path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise LabError('migration bundle bytes: ' + name)
    if plan['goReceipt']['sourceArchiveSha256'] != 'a95853baa25d438a3e92ea5207bd315e3a45143b5209488ebf7f0b44e2e2bcc3':
        raise LabError('migration Go source pin')
    if plan['toolsReceipt']['revision'] != 'ee0f0a9aa34ff0a0da4b3433b9512781cfe02843':
        raise LabError('migration tools source pin')
    if (plan['goReceipt']['sha256'] != plan['files']['amneziawg-go']
        or plan['goReceipt']['socketDirectory'] != '/run/amnezia/awg3/amneziawg'
        or plan['toolsReceipt']['RUNSTATEDIR'] != '/run/amnezia/awg3'
        or plan['toolsReceipt']['archiveSha256'] != '19b52a13b014b9ca3cf74226436ce657ac42ba4c83d1eeca9ee48a339aa1abe6'):
        raise LabError('migration helper/tool provenance')
    return plan


def run(controller, run_id, bundle, output):
    if controller.dry_run or controller.test_mode or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}', run_id):
        raise LabError('real owned migration run required')
    contract = validate_bundle(bundle)
    with controller.mutation_session('awg-migration-native'):
        vm = controller.owned_vm(run_id, PROFILE)
        planned = controller.get_run(run_id)
        for role in ('manifest', 'manifest_public_key'):
            if artifact_record(Path(planned[role]['path'])) != planned[role]:
                raise LabError('migration planned signed input changed: ' + role)
        validate_signed_manifest(Path(planned['manifest']['path']), Path(planned['manifest_public_key']['path']),
                                 version=planned['candidate_version'], artifacts=planned['artifacts'])
        # The signed lab plan, not a host bundle manifest, selects product bytes.
        record = planned['artifacts'][PROFILE]
        archive = Path(record['path'])
        if archive.is_symlink() or archive.stat().st_size != record['size'] or hashlib.sha256(archive.read_bytes()).hexdigest() != record['sha256']:
            raise LabError('planned migration product archive changed')
        with tarfile.open(archive) as product:
            members = product.getmembers()
            if {m.name for m in members} != {'amneziad', 'amnezia-cli'} or len(members) != 2 or not all(m.isfile() for m in members):
                raise LabError('planned migration product archive layout')
            for name in ('amneziad', 'amnezia-cli'):
                if hashlib.sha256(product.extractfile(name).read()).hexdigest() != contract['files'][name]:
                    raise LabError('migration bundle differs from signed product: ' + name)
        qmp = QmpClient(Path(vm['qmp_socket']))
        require_qmp_return(qmp.request('query-status'), 'query-status')
        uuid = require_qmp_return(qmp.request('query-uuid'), 'query-uuid')['return']['UUID']
        if uuid.lower() != vm['uuid'].lower():
            raise LabError('migration QMP UUID mismatch')
        qga = QgaClient(Path(vm['qga_socket']))
        # lab.start/probe does not stage the run marker; mirror lab.run's
        # staging, but initialize only an absent marker after native guest UUID.
        marker_setup = """import os,pathlib,sys
assert os.geteuid()==0
assert pathlib.Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower()==sys.argv[1].lower()
p=pathlib.Path('/tmp/amnezia-release-lab-marker'); expected=sys.argv[2].encode()
if os.path.lexists(p):
 assert not p.is_symlink() and p.is_file() and p.stat().st_uid==0 and p.read_bytes().strip()==expected
else:
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  assert os.write(fd,expected)==len(expected); os.fsync(fd)
 finally: os.close(fd)
"""
        controller.owned_vm(run_id, PROFILE)
        marker_result = qga.guest_exec_wait('/usr/bin/python3', ['-c', marker_setup, uuid, f'amnezia-release-lab:{run_id}:{PROFILE}'], timeout=30)
        if marker_result.get('exitcode') != 0:
            raise LabError('migration guest marker initialization failed')
        marker = qga.read_file('/tmp/amnezia-release-lab-marker').decode().strip()
        if marker != f'amnezia-release-lab:{run_id}:{PROFILE}':
            raise LabError('migration guest marker mismatch')
        profile = load_profiles()[PROFILE]
        ready, reason = golden_readiness(controller.root, profile)
        if not ready:
            raise LabError(reason)
        golden = json.loads((controller.root / profile['golden_readiness']).read_text())['base_sha256']
        root = f'/var/lib/amnezia-release-lab/migration-{run_id}'
        # A fresh private root is mandatory; never reuse another fixture state.
        setup = """import os,pathlib,sys
parent=pathlib.Path('/var/lib/amnezia-release-lab')
if os.path.lexists(parent):
 assert parent.is_dir() and not parent.is_symlink() and parent.resolve()==parent and parent.stat().st_uid==0 and not parent.stat().st_mode&0o022
else: parent.mkdir(mode=0o700)
p=pathlib.Path(sys.argv[1]); assert p.parent==parent
os.mkdir(p,0o700); assert p.stat().st_uid==0
"""
        result = qga.guest_exec_wait('/usr/bin/python3', ['-c', setup, root], timeout=30)
        if result.get('exitcode') != 0:
            raise LabError('migration private root creation failed')
        plan = {**contract, 'runId': run_id, 'profile': PROFILE, 'marker': marker,
                'uuid': uuid, 'root': root, 'goldenSha256': golden}
        for name in sorted(ROLES):
            # owned_vm is revalidated before every guest write and execution.
            controller.owned_vm(run_id, PROFILE)
            qga.write_file(root + '/' + name, (Path(bundle) / name).read_bytes())
        # Do not trust an unverified helper to attest to its own bytes: verify
        # its actual QGA readback before it can execute or inspect native keys.
        controller.owned_vm(run_id, PROFILE)
        if hashlib.sha256(qga.read_file(root + '/guest.py')).hexdigest() != contract['files']['guest.py']:
            raise LabError('migration staged helper readback differs')
        qga.write_file(root + '/plan.json', (json.dumps(plan, sort_keys=True) + '\n').encode())
        controller.owned_vm(run_id, PROFILE)
        result = qga.guest_exec_wait('/usr/bin/python3', [root + '/guest.py', root + '/plan.json'], timeout=300)
        try:
            receipt = json.loads(result['stdout'])
        except (ValueError, KeyError) as error:
            raise LabError('migration guest receipt missing') from error
        if (receipt.get('origin'), receipt.get('transport'), receipt.get('runId'), receipt.get('marker'), receipt.get('uuid')) != ('guest', 'qga', run_id, marker, uuid):
            raise LabError('migration guest receipt binding')
        receipt['controllerBinding'] = {k: vm[k] for k in ('pid', 'uuid', 'proc_start_time', 'qmp_socket', 'qga_socket')}
        receipt['bundleHash'] = hashlib.sha256((Path(bundle) / 'bundle.json').read_bytes()).hexdigest()
        target = Path(output)
        if target.exists():
            raise LabError('migration receipt destination exists')
        target.write_text(json.dumps(receipt, sort_keys=True, indent=2) + '\n')
        if result.get('exitcode') != 0 or receipt.get('passed') is not True:
            raise LabError('migration failed: ' + receipt.get('error', 'guest assertion'))
        mandatory = {'stagedActiveLegacyUnchanged', 'native3ParametersAndFreshHandshake', 'boundLargePacketTraffic',
                     'serverProofAndAck', 'trustedAmnezia0640', 'ownedDisconnect', 'sourceProfileAndPskUnchanged',
                     'failedGenerationWatermark', 'rollbackProfilePskRoutesDnsMtuPreserved'}
        if set(receipt.get('checks', {})) != mandatory or any(receipt['checks'][k] is not True for k in mandatory) or receipt.get('forcedFailureRollback') is not True:
            raise LabError('migration mandatory native evidence incomplete')
        return receipt


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--run-id', required=True)
    p.add_argument('--bundle', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    print(json.dumps(run(LabController(Path('/var/lib/amnezia-release-lab')), args.run_id, args.bundle, args.output), sort_keys=True))


if __name__ == '__main__':
    main()
