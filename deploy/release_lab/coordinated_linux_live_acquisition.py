"""Distinct coordinated headless producer; legacy Linux/Android authority stays intact."""
from __future__ import annotations

import base64
from dataclasses import asdict
import json
from pathlib import Path

from .android_real_device_acquisition import file_record
from .linux_live_acquisition import LinuxLiveProducer
from .live_acquisition import acquire_linux_receipt
from .trusted_acquisition_export import TrustedAcquisitionError, canonical, utc_now, utc_text

CAPABILITY = 'headless-coordinated-rollback-with-pause-v1'
TARGET = 'linux-headless-coordinated'
PROFILE = 'linux-headless-x64'
SEMANTICS = {'steps', 'update', 'candidateReboot', 'coordinatedRollback', 'heldReboot', 'resume', 'cleanup'}


class CoordinatedLinuxLiveProducer(LinuxLiveProducer):
    """Reuse only unchanged ownership/boot/failure-cleanup helpers.

    The inherited lifecycle calls this fixed class' ``_acquire_once``. There
    is no callback, imported PASS file, legacy rollback registration or issuer.
    """

    def __init__(self, controller, run_id):
        super().__init__(controller, run_id, target='linux-headless')
        self.target = TARGET

    def acquire(self, context):
        # The shared lifecycle intentionally remains byte-for-byte historical.
        # Do not permit instance-supplied methods to replace its fixed dispatch.
        allowed = {'controller', 'run_id', 'target', 'binary_sha', '_used', '_start_attempted', '_gui_payload'}
        if type(self) is not CoordinatedLinuxLiveProducer or set(vars(self)) != allowed:
            raise TrustedAcquisitionError('fixed coordinated producer instance required')
        return LinuxLiveProducer.acquire(self, context)

    def _binding(self, context):
        run = super()._binding(context)
        from .lab import artifact_record, ensure_owned_child
        if run.get('headless_capability') != CAPABILITY:
            raise TrustedAcquisitionError('coordinated capability must be selected before execution')
        record = run.get('headless_capability_record')
        if not isinstance(record, dict) or not isinstance(record.get('path'), str):
            raise TrustedAcquisitionError('immutable coordinated capability record missing')
        expected_path = ensure_owned_child(self.controller.root,
            self.controller.root / 'runs' / self.run_id / 'headless-capability.json', 'headless capability')
        if Path(record['path']) != expected_path or artifact_record(expected_path) != record:
            raise TrustedAcquisitionError('coordinated capability record changed')
        expected = {
            'schema': 1, 'run_id': self.run_id, 'capability': CAPABILITY,
            'manifest_sha256': run['manifest']['sha256'],
            'outer_sha256': run['outer_artifact']['sha256'],
            'candidate_artifacts': {key: {'sha256': value['sha256'], 'size': value['size']}
                                    for key, value in run['artifacts'].items()},
            'semantic_helpers': {key: {'sha256': value['sha256'], 'size': value['size']}
                                 for key, value in run['semantic_helper_records'].items()},
        }
        if canonical(json.loads(expected_path.read_bytes())) != canonical(expected):
            raise TrustedAcquisitionError('coordinated capability context or helper closure differs')
        return run

    def _acquire_once(self, context):
        from . import lab, linux_live_acquisition
        from .lab import validate_receipt
        from .headless_coordinated_rollback_driver import build_coordinated_headless_driver
        if self._used:
            raise TrustedAcquisitionError('coordinated producer is single-use')
        self._used = True
        controller = self.controller
        started = utc_text(utc_now())
        with controller.mutation_session('trusted-coordinated-linux-acquisition'):
            run = self._binding(context)
            state = run.get('profiles', {}).get(PROFILE, {})
            if state.get('steps') or state.get('evidence_archive') or state.get('evidence') or state.get('vm'):
                raise TrustedAcquisitionError('coordinated acquisition requires a fresh profile')
            self._start_attempted = True
            controller.start(self.run_id, PROFILE)
            self._wait_for_boot(PROFILE)
            controller.guest_probe(self.run_id, PROFILE)
            controller.run_steps(self.run_id, PROFILE)
            controller.collect(self.run_id, PROFILE)
            ordinary = acquire_linux_receipt(controller, self.run_id, PROFILE)
            run = self._binding(context)
            validate_receipt(json.loads(ordinary['raw_receipt']), run_id=self.run_id, profile_id=PROFILE,
                artifact=run['artifacts']['linux-headless-x64'], baseline_version=run['baseline_version'],
                candidate_version=run['candidate_version'], expected_role='candidate')
            controller.archive_guest_evidence(self.run_id, PROFILE)
            driver = build_coordinated_headless_driver(controller, self.run_id, context)
            semantic = driver.run()
            registration = controller.register_headless_coordinated_semantic(
                self.run_id, driver.plan, semantic, context, ordinary)
            self._binding(context)
            binding = controller.owned_vm(self.run_id, PROFILE)
            reset = controller.reset(self.run_id, PROFILE)
            current = controller.get_run(self.run_id)['profiles'][PROFILE]
            overlay = controller.root / 'runs' / self.run_id / PROFILE / 'overlay.qcow2'
            if (current.get('vm') is not None or overlay.exists()
                    or any(Path(binding[key]).exists() for key in ('qmp_socket', 'qga_socket'))):
                raise TrustedAcquisitionError('coordinated owned guest cleanup incomplete')
            run = self._binding(context)
            sources = [file_record(Path(__file__).absolute()), file_record(Path(lab.__file__).absolute()),
                       file_record(Path(linux_live_acquisition.__file__).absolute())]
            sources.extend(record for name in ('profile_records', 'runner_records', 'semantic_helper_records')
                           for record in run[name].values())
            sources.append(run['headless_capability_record'])
            sources = list({record['path']: record for record in sources}.values())
            capture = {'schema': 1, 'runId': self.run_id, 'profileId': PROFILE,
                       'binding': context.binding(), 'capability': CAPABILITY,
                       'ordinary': {key: value for key, value in ordinary.items() if key != 'raw_receipt'},
                       'original_receipt': base64.b64encode(ordinary['raw_receipt']).decode(),
                       'plan': asdict(driver.plan), 'semantic': semantic, 'registration': registration}
            return {'target': TARGET, 'runId': self.run_id, 'profileId': PROFILE,
                    'startedAt': started, 'completedAt': utc_text(utc_now()),
                    'binding': context.binding(), 'capability': CAPABILITY,
                    'rawCapture': canonical(capture),
                    'cleanupCapture': canonical({'semantic_cleanup': semantic['cleanup'], 'owned_reset': reset,
                        'overlay_absent': True, 'qmp_absent': True, 'qga_absent': True}),
                    'semantics': {name: True for name in SEMANTICS}, 'provenance': sources}
