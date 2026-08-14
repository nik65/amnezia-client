from __future__ import annotations

import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]


def source(relative: str) -> str:
    return (REPO_ROOT / relative).read_text(encoding="utf-8")


def function_body(text: str, signature: str) -> str:
    start = text.index(signature)
    brace = text.index("{", start)
    depth = 0
    for index in range(brace, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[brace : index + 1]
    raise AssertionError(f"unterminated function: {signature}")


class ThreadingSourceContracts(unittest.TestCase):
    def test_ui_snapshot_controllers_never_block_on_worker(self) -> None:
        route_inspector = source("client/core/controllers/routeInspectorController.cpp")
        uploader = source("client/core/controllers/remoteLogUploader.cpp")

        self.assertNotIn("BlockingQueuedConnection", route_inspector)
        self.assertNotIn("BlockingQueuedConnection", uploader)
        self.assertIn("requestBoundedQueuedSnapshot", route_inspector)
        self.assertIn("requestBoundedQueuedSnapshot", uploader)
        self.assertNotIn("vpnConnection->serverIndex()", route_inspector)
        self.assertNotIn("vpnConnection->serverIndex()", uploader)
        self.assertIn("snapshot.serverId = vpnConnection->serverId()", route_inspector)
        self.assertIn("snapshot.serverId = vpnConnection->serverId()", uploader)
        self.assertIn("appliedSiteRouteMode", route_inspector)
        self.assertIn("runtime_route_mode_diverged", route_inspector)
        self.assertIn("vpn_snapshot_timeout", route_inspector)
        self.assertIn("recordFailure(ErrorCategory::Timeout)", uploader)
        self.assertIn("const ConnectionSnapshot &snapshot) const", uploader)
        self.assertIn(
            "m_currentConnectionContextGeneration != m_connectionContextGeneration",
            uploader,
        )
        self.assertNotIn("currentConnectionSnapshot()", uploader)

    def test_remote_log_failures_use_only_opaque_target_labels(self) -> None:
        uploader = source("client/core/controllers/remoteLogUploader.cpp")

        self.assertIn("targetIdentity(target).left(12)", uploader)
        self.assertIn("targetIdentity(m_currentTarget).left(12)", uploader)
        self.assertIn("errorCategoryName(category)", uploader)
        self.assertNotIn("reply->errorString()", uploader)
        self.assertNotIn("<< target.serverId", uploader)
        self.assertNotIn("<< m_currentTarget.serverId", uploader)
        self.assertNotIn("<< m_currentTarget.endpoint", uploader)

    def test_desktop_upload_health_requires_every_expected_source(self) -> None:
        uploader = source("client/core/controllers/remoteLogUploader.cpp")
        header = source("client/core/controllers/remoteLogUploader.h")
        collect = function_body(uploader, "QList<RemoteLogUploader::LogPayload> RemoteLogUploader::collectPayloads()")
        upload = function_body(uploader, "void RemoteLogUploader::uploadWithSnapshot(")
        finish = function_body(uploader, "void RemoteLogUploader::finishUpload()")

        self.assertIn("m_collectionAllExpectedSourcesReadable", header)
        self.assertIn("bool clientSourceReadable = false", collect)
        self.assertIn("bool serviceSourceReadable = false", collect)
        self.assertIn(
            "clientSourceReadable && serviceSourceReadable", collect
        )
        completeness_check = upload.index(
            "!m_collectionAllExpectedSourcesReadable"
        )
        privacy_gate = upload.index("m_retryPersistenceFailClosed")
        privacy_failure = upload.index(
            "recordFailure(ErrorCategory::Source)", privacy_gate
        )
        source_failure = upload.index(
            "recordFailure(ErrorCategory::Source)", completeness_check
        )
        upload_started = upload.index("m_uploadInProgress = true")
        self.assertLess(privacy_gate, privacy_failure)
        self.assertLess(privacy_failure, completeness_check)
        self.assertLess(completeness_check, source_failure)
        self.assertLess(source_failure, upload_started)
        self.assertIn("if (m_batchHadFailure)", finish)
        self.assertIn("remoteLogBatchCanBecomeHealthy", finish)
        self.assertIn("m_collectionAllExpectedSourcesReadable", finish)
        self.assertIn("m_collectionHasPendingStateScan", finish)

    def test_managed_route_mutation_is_worker_owned_and_bound(self) -> None:
        controller = source("client/core/controllers/connectionController.cpp")
        vpn = source("client/vpnConnection.cpp")

        self.assertNotIn(
            "m_vpnConnection->updateManagedSplitTunnelRoutes", controller
        )
        self.assertNotIn("m_vpnConnection->", controller)
        self.assertIn("managedRouteReconcileRequested", controller)
        self.assertIn("Qt::QueuedConnection", controller)
        reconcile = function_body(
            vpn, "void VpnConnection::reconcileManagedSplitTunnelRoutes("
        )
        self.assertIn("expectedConnectionEpoch == m_connectionEpoch", reconcile)
        self.assertIn("expectedServerId == m_serverId", reconcile)
        self.assertIn("generation > m_latestManagedRouteReconcileGeneration", reconcile)
        self.assertIn("QThread::currentThread() != thread()", reconcile)
        self.assertIn("const bool modeValid", reconcile)
        self.assertIn("updateManagedSplitTunnelRoutes", reconcile)
        self.assertIn(
            "waitForFinished(incrementalManagedRouteIpcTimeoutMs)", vpn
        )

    def test_deferred_managed_route_reconnect_is_not_acknowledged_as_applied(self) -> None:
        header = source("client/vpnConnection.h")
        vpn = source("client/vpnConnection.cpp")
        controller = source("client/core/controllers/connectionController.cpp")
        update = function_body(
            vpn,
            "VpnConnection::ManagedRouteUpdateResult VpnConnection::updateManagedSplitTunnelRoutes(",
        )
        reconcile = function_body(
            vpn, "void VpnConnection::reconcileManagedSplitTunnelRoutes("
        )
        acknowledgement = function_body(
            controller, "void ConnectionController::onManagedRouteReconciled("
        )

        self.assertIn("enum class ManagedRouteUpdateResult", header)
        self.assertIn("ReconnectRequired", header)
        self.assertIn("ReconnectDeferred", header)
        pending = update[update.index("if (m_pendingClientSplitRouteLookups > 0)") :]
        pending = pending[: pending.index("QStringList protectedHosts")]
        self.assertIn("m_reconnectAfterClientRouteResolution = true", pending)
        self.assertIn("m_deferredManagedRouteReconnectTimer.start()", pending)
        self.assertIn(
            "return ManagedRouteUpdateResult::ReconnectDeferred", pending
        )
        self.assertNotIn("reconnectToVpn", pending)

        self.assertIn(
            "const bool updated = updateResult == ManagedRouteUpdateResult::Updated",
            reconcile,
        )
        self.assertIn(
            "bool reconnectScheduled = updateResult == ManagedRouteUpdateResult::ReconnectDeferred",
            reconcile,
        )
        update_result = reconcile.index(
            "const bool updated = updateResult == ManagedRouteUpdateResult::Updated"
        )
        base_invalidation = reconcile.index(
            "invalidateAuthoritativeManagedRouteBase()", update_result
        )
        immediate_reconnect = reconcile.index(
            "if (updateResult == ManagedRouteUpdateResult::ReconnectRequired)",
            base_invalidation,
        )
        reconnect_marked = reconcile.index(
            "reconnectScheduled = true", immediate_reconnect
        )
        acknowledgement_emit = reconcile.index(
            "emit managedSplitTunnelRoutesReconciled", reconnect_marked
        )
        queued_reconnect = reconcile.index(
            "scheduleManagedRouteReconnect(", acknowledgement_emit
        )
        reconnect_schedule = function_body(
            vpn, "void VpnConnection::scheduleManagedRouteReconnect("
        )
        epoch_guard = reconnect_schedule.index(
            "expectedConnectionEpoch != m_connectionEpoch"
        )
        server_guard = reconnect_schedule.index(
            "expectedServerId != m_serverId", epoch_guard
        )
        self.assertLess(update_result, base_invalidation)
        self.assertLess(base_invalidation, immediate_reconnect)
        self.assertLess(immediate_reconnect, reconnect_marked)
        self.assertLess(reconnect_marked, acknowledgement_emit)
        self.assertLess(acknowledgement_emit, queued_reconnect)
        self.assertLess(epoch_guard, server_guard)
        self.assertNotIn("reconnectToVpn()", reconcile)
        self.assertIn("m_managedRouteReconnectGate.request", reconnect_schedule)
        self.assertIn(
            "generation, expectedConnectionEpoch, expectedServerId,\n"
            "            true, updated, reconnectScheduled",
            reconcile,
        )
        stale_pending_guard = acknowledgement.index(
            "generation != m_pendingManagedRouteReconcileGeneration"
        )
        applied_snapshot_commit = acknowledgement.index(
            "m_confirmedManagedRouteMode = appliedMode"
        )
        self.assertLess(stale_pending_guard, applied_snapshot_commit)
        self.assertLess(
            acknowledgement.index(
                "const bool reconciliationConfirmed = requestAccepted && updated"
            ),
            applied_snapshot_commit,
        )
        self.assertLess(
            acknowledgement.index("m_hasConfirmedManagedRouteState = false"),
            acknowledgement.index("m_managedRouteIncrementalBlocked = true"),
        )

    def test_central_remote_calls_and_shutdown_are_bounded(self) -> None:
        vpn = source("client/vpnConnection.cpp")
        application = source("client/amneziaApplication.cpp")
        destructor = function_body(
            application, "AmneziaApplication::~AmneziaApplication()"
        )

        self.assertIn("waitForFinished(killSwitchIpcTimeoutMs)", vpn)
        self.assertIn("waitForFinished(dnsFlushIpcTimeoutMs)", vpn)
        self.assertIn("waitForFinished(clearSavedRoutesIpcTimeoutMs)", vpn)
        self.assertNotIn("BlockingQueuedConnection", destructor)
        self.assertNotIn(".terminate(", destructor)
        self.assertIn("shutdownForApplicationExit", destructor)
        self.assertIn("vpnWorkerShutdownTimeoutMs", destructor)
        self.assertIn("m_vpnConnection->thread() != destructionThread", destructor)
        self.assertIn("qFatal", destructor)
        shutdown = function_body(
            vpn, "void VpnConnection::shutdownForApplicationExit("
        )
        self.assertIn("m_vpnProtocol.clear()", shutdown)
        self.assertIn("moveToThread(destructionThread)", shutdown)
        self.assertIn("workerThread->quit()", shutdown)

    def test_snapshot_helper_has_no_sync_wait_or_stack_result_capture(self) -> None:
        helper = source("client/core/utils/boundedQueuedSnapshot.h")

        self.assertNotIn("BlockingQueuedConnection", helper)
        self.assertNotIn("QSemaphore", helper)
        self.assertNotIn("setInterval(1)", helper)
        self.assertIn("std::make_shared", helper)
        self.assertIn("cancelled", helper)
        self.assertIn("QFutureWatcher", helper)
        self.assertIn("QPromise", helper)
        self.assertIn("QPointer<Target>", helper)
        self.assertIn("resolved.exchange", helper)
        self.assertIn("promiseFinished.exchange", helper)
        self.assertIn("finishPromise();", helper)
        self.assertIn("promiseMutex", helper)
        self.assertLess(helper.index("watcher->deleteLater()"), helper.index("(*completionPtr)"))
        self.assertIn("std::optional", helper)


if __name__ == "__main__":
    unittest.main()
