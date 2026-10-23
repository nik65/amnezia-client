"""Owned-guest coordinated rollback chain, distinct from legacy native rollback.

This module neither signs nor registers acceptance. Its only successful result
is evidence accepted by the separate coordinated contract. The legacy driver,
rollback validator and reboot validator remain unchanged.
"""
from __future__ import annotations

from dataclasses import asdict, replace
from pathlib import Path

from .headless_native_acceptance import Fixture, UPDATE_JOURNAL, receipt_sha256, validate_update_receipt
from .headless_native_e2e_driver import (
    HeadlessNativeE2EDriver, _now, _state,
    capture_server_reset_failure,
)
from .headless_pending_observer import PendingObservation


class CoordinatedHeadlessDriver(HeadlessNativeE2EDriver):
    """Exercise genuine update, both reboots, pause/rollback and explicit resume.

    ``coordinated`` collects fixed guest paths and real process observations.
    ``server`` owns its persistent, boot-ordered private HTTP fixture. Neither
    object may synthesize the transient legacy13 daemon acknowledgement.
    """

    def __init__(self, *args, coordinated, validator=None, candidate_validator=None, held_validator=None,
                 held_reboot_validator=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.coordinated = coordinated
        self.validator = validator
        self.candidate_validator = candidate_validator
        self.held_validator = held_validator
        self.held_reboot_validator = held_reboot_validator

    def _retain(self, name, value):
        # The retained executable and exact private policy can legitimately be
        # larger than the old one-MiB native observation envelope. The separate
        # collector streams a bounded, complete private copy; truncation fails.
        self.coordinated.archive_original(self.plan.attempt_nonce + '-' + name, value)
        return value

    def run(self, *, update_timeout=600, rollback_timeout=300, reboot_timeout=300):
        for timeout in (update_timeout, rollback_timeout, reboot_timeout):
            if type(timeout) is not int or not 0 < timeout <= 600:
                raise ValueError('coordinated driver deadline invalid')
        self.plan.validate()
        primary = None
        fixture_started = server_started = False
        try:
            self._retain('exact-native-plan', asdict(self.plan))
            connected = self.preexisting.prepare_and_connect()
            fixture_started = True
            connected_archive = self._archive('coordinated-preexisting-connected', connected)
            legacy = self.preexisting.crash_and_restart(connected, connected_archive)
            self._archive('coordinated-baseline-owned', legacy)
            self.preexisting.promote_systemd_baseline(legacy)
            # The old connected fixture cannot survive a reboot. Retire it
            # before enabling the real updater, using its normal owned cleanup.
            # A disabled nonce profile satisfies that cleanup's exact URL fence;
            # the normal stage_profile below subsequently enables the updater.
            disabled = self.coordinated.stage_disabled_owned_profile()
            self._retain('disabled-bootstrap-profile', disabled)
            network_cleanup = self.preexisting.cleanup({})
            fixture_started = False
            self._archive('coordinated-network-cleanup', network_cleanup)

            self.server.prevalidation_archive = self.archive_root
            server_started = True  # partial start still requires owned cleanup
            self.server.start()
            self.server.reset()
            before = self.native.identity(self.plan.baseline, 'baseline-before')
            boot = self.preexisting.boot_id(legacy)
            doctor = self.native.cli_json(
                ['/usr/local/bin/amnezia-cli', '--socket', '/run/amnezia/amneziad.sock', '--json', 'doctor'],
                'cli:doctor')
            with PendingObservation(self.native, 'restart_pending', update_timeout,
                                    failure_archive=self.archive_root) as observation:
                staged = self.native.stage_profile()
                pending = observation.collect()
            stable = self.native.wait_for(
                self.native.collect_update_stable,
                lambda value: _state(value, 'stable_state') in {'updated', 'no_update'},
                timeout=update_timeout, label='coordinated native update stable')
            after = self.native.identity(self.plan.candidate, 'candidate-after')
            http = self.server.collect()
            update = self.native.build_update_receipt(
                before_raw=before, after_raw=after, boot_id=boot,
                raw_sources={'before_doctor': doctor, 'profile_store': staged['profile_store'],
                             **pending, **stable}, http_receipt=http, observed_at=_now())
            self._retain('coordinated-update', update)
            validate_update_receipt(self.plan, update, http)
            self._archive('coordinated-update', update)
            # Persist this exact candidate incarnation before the boot changes
            # it; the final epoch contract selects this identity, never the
            # first daemon the fixture happened to observe during setup.
            self._retain('coordinated-update-http-epoch', self.server.ledger())

            # Keep the owned profile enabled and the signed feed genuinely
            # reachable. This is not the old rollback's unsafe feed workaround.
            observed_candidate = self.collector.reboot_and_collect(boot, self.plan.candidate, reboot_timeout)
            candidate_reboot = {
                **self.native._common_receipt('headless-coordinated-candidate-reboot', _now()),
                **observed_candidate}
            candidate_reboot['raw_sources']['retired_journal'] = self.coordinated.raw_absence(UPDATE_JOURNAL)
            candidate_reboot['prior_receipt_sha256'] = receipt_sha256(update)
            self._retain('coordinated-candidate-reboot', candidate_reboot)
            self.server.snapshot_start()
            if self.candidate_validator is None:
                from .headless_coordinated_rollback_acceptance import validate_coordinated_candidate_reboot
                validate_coordinated_candidate_reboot(self.plan, candidate_reboot, update)
            else:
                self.candidate_validator(self.plan, candidate_reboot, update)
            held = self.coordinated.trigger_and_wait_held(rollback_timeout)
            self._retain('coordinated-held', held)
            receipt = self.native._common_receipt('headless-coordinated-rollback-with-pause', _now())
            receipt.update({
                'candidate_reboot_sha256': receipt_sha256(candidate_reboot),
                'rollback_process': held['rollback_process'],
                'coordinator_process': held.get('coordinator_process'),
                'raw_sources': held['raw_sources'],
            })
            self._retain('coordinated-held-proof', receipt)
            if self.held_validator is None:
                from .headless_coordinated_rollback_acceptance import validate_coordinated_held
                validate_coordinated_held(self.plan, receipt, candidate_reboot, update, http)
            else:
                self.held_validator(self.plan, receipt, candidate_reboot, update, http)
            held_reboot = self.coordinated.reboot_held(
                candidate_reboot['boot_id_after'], held, reboot_timeout)
            self._retain('coordinated-held-reboot', held_reboot)
            self.server.snapshot_start()
            receipt.update({'held_reboot': held_reboot['held_reboot'],
                            'raw_sources': {**held['raw_sources'], **held_reboot['raw_sources']}})
            if self.held_reboot_validator is None:
                from .headless_coordinated_rollback_acceptance import validate_coordinated_held_reboot
                validate_coordinated_held_reboot(self.plan, receipt, candidate_reboot)
            else:
                self.held_reboot_validator(self.plan, receipt, candidate_reboot)
            resumed = self.coordinated.resume_and_collect(held)
            self._retain('coordinated-resumed', resumed)
            ledger = self.server.ledger()
            self._retain('coordinated-ledger', ledger)

            receipt.update({
                'observed_at': _now(),
                'held_reboot': held_reboot['held_reboot'],
                'resume_process': resumed['resume_process'],
                'raw_sources': {**held['raw_sources'], **held_reboot['raw_sources'], **resumed['raw_sources']},
                'held_http': ledger,
                'retained_resumed_record': True,
            })
            self._retain('coordinated-chain', receipt)
            if self.validator is None:
                from .headless_coordinated_rollback_acceptance import validate_coordinated_rollback_chain
                validator = validate_coordinated_rollback_chain
            else:
                validator = self.validator
            expected_http_sources = self.server.expected_sources()
            validation = validator(self.plan, receipt, update, candidate_reboot, http,
                                   expected_http_sources=expected_http_sources)
            cleanup = self.server.cleanup()
            server_started = False
            cleanup['preexisting_cleanup'] = network_cleanup
            self._retain('coordinated-cleanup', cleanup)
            self._archive('coordinated-chain-reference', {
                'receipt_sha256': receipt_sha256(receipt),
                'capability': 'headless-coordinated-rollback-with-pause',
                'legacy_native_rollback_pass': False})
            self._archive('coordinated-cleanup', cleanup)
            return {'capability': 'headless-coordinated-rollback-with-pause',
                    'legacy_native_rollback_pass': False, 'trustedExport': False,
                    'http': http, 'update': update, 'candidate_reboot': candidate_reboot,
                    'coordinated_rollback': receipt, 'validation': validation, 'cleanup': cleanup,
                    'expected_http_sources': expected_http_sources,
                    'preexisting': {'plan': asdict(self.preexisting.plan), 'connected': connected,
                                    'baseline': legacy, 'network_cleanup': network_cleanup}}
        except BaseException as error:
            primary = error
            capture_server_reset_failure(self.server, self.archive_root, self.plan.attempt_nonce, error)
            try:
                self._archive('coordinated-failure', {'error_type': type(error).__name__,
                              'error': str(error), 'observed_at': _now()})
            except BaseException as archive_error:
                error.add_note('coordinated failure archive unavailable: ' + type(archive_error).__name__)
            raise
        finally:
            if primary is not None:
                if server_started:
                    try:
                        self.server.abort()
                    except BaseException as cleanup_error:
                        primary.add_note('coordinated HTTP cleanup unavailable: ' + type(cleanup_error).__name__)
                if fixture_started:
                    try:
                        self.preexisting.cleanup({})
                    except BaseException as cleanup_error:
                        primary.add_note('preexisting cleanup unavailable: ' + type(cleanup_error).__name__)
            try:
                self.coordinated.close()
            except BaseException as close_error:
                if primary is None:
                    raise
                primary.add_note('private coordinated archive close unavailable: ' + type(close_error).__name__)


def build_coordinated_headless_driver(controller, run_id, context):
    """Reuse exact canonical ownership/context staging, without old dispatch."""
    from .linux_headless_driver import build_headless_driver
    from .headless_coordinated_http_fixture import CoordinatedHeadlessHttpFixture, derive_endpoint
    from .headless_coordinated_rollback_collector import CoordinatedRollbackCollector, CoordinatedRebootCollector
    old = build_headless_driver(controller, run_id, context, protected_fixture_inputs=True)
    endpoint = derive_endpoint(old.plan.attempt_nonce)
    fixture = Fixture(endpoint, (endpoint.split('//', 1)[1].split(':', 1)[0] + '/32',),
                      old.plan.attempt_nonce, old.plan.fixture.manifest_path, old.plan.fixture.artifact_path)
    plan = replace(old.plan, fixture=fixture)
    plan.validate()
    old.native.plan = plan
    reboot = CoordinatedRebootCollector(old.native.qga, plan, old.native, old.native.snapshot,
                                        process_fence=old.collector.process_fence)
    old.preexisting.native_manifest_url = endpoint + fixture.manifest_path
    server = CoordinatedHeadlessHttpFixture(
        old.native, plan, manifest_guest_path=old.server.manifest,
        artifact_guest_path=old.server.artifact, archive_root=old.archive_root)
    coordinated = CoordinatedRollbackCollector(
        old.native.qga, plan, old.native, reboot, old.native.snapshot, old.archive_root)
    return CoordinatedHeadlessDriver(plan, old.native, server, old.preexisting, reboot,
                                     Path(old.archive_root), coordinated=coordinated)
