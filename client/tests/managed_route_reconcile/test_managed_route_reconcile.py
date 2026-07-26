from __future__ import annotations

import dataclasses
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


@dataclasses.dataclass(frozen=True)
class Desired:
    routes: tuple[str, ...]
    content: str


@dataclasses.dataclass
class Request:
    request_id: int
    epoch: int
    expected_revision: int
    old: Desired
    new: Desired


class ControllerModel:
    """Small deterministic oracle for the production controller protocol."""

    def __init__(self) -> None:
        self.epoch = 1
        self.revision = 0
        self.confirmed: Desired | None = None
        self.blocked = True
        self.in_flight: Request | None = None
        self.coalesced: Desired | None = None
        self.next_id = 0
        self.full_rebuild_requested = False

    def connected_base(self, desired: Desired, revision: int, confirmed: bool) -> Request | None:
        if self.in_flight is not None and self.coalesced is None:
            self.coalesced = self.in_flight.new
        self.in_flight = None
        self.revision = revision
        if not confirmed:
            self.confirmed = None
            self.blocked = True
            self.full_rebuild_requested = True
            return None
        self.confirmed = desired
        self.blocked = False
        self.full_rebuild_requested = False
        if self.coalesced is None:
            return None
        newest = self.coalesced
        self.coalesced = None
        return self.request(newest)

    def request(self, desired: Desired) -> Request | None:
        if self.in_flight is not None or self.blocked or self.confirmed is None:
            self.coalesced = desired
            return None
        if desired == self.confirmed:
            return None
        self.next_id += 1
        self.in_flight = Request(
            self.next_id, self.epoch, self.revision, self.confirmed, desired
        )
        return self.in_flight

    def acknowledge(
        self,
        request_id: int,
        epoch: int,
        outcome: str,
        applied_revision: int,
        applied: Desired | None = None,
    ) -> Request | None:
        pending = self.in_flight
        if pending is None or pending.request_id != request_id or epoch != self.epoch:
            return None
        self.in_flight = None
        if outcome == "updated":
            # The worker ACK owns the exact normalized runtime state. The raw
            # desired request can include routes removed during normalization.
            self.confirmed = applied or pending.new
            self.revision = applied_revision
            self.blocked = False
            if self.coalesced is not None:
                newest = self.coalesced
                self.coalesced = None
                return self.request(newest)
            return None
        if self.coalesced is None:
            self.coalesced = pending.new
        self.confirmed = None
        self.blocked = True
        return None

    def change_epoch(self) -> None:
        if self.in_flight is not None and self.coalesced is None:
            self.coalesced = self.in_flight.new
        self.epoch += 1
        self.in_flight = None
        self.confirmed = None
        self.blocked = True


class WorkerModel:
    """Oracle for receipt/base and shutdown fail-closed behavior."""

    def __init__(self) -> None:
        self.revision = 1
        self.base: tuple[str, ...] | None = None
        self.dns_generation = 4
        self.deferred_timer_active = True
        self.teardown_confirmed = True

    def initial_add(self, expected: int, returned: int) -> bool:
        self.revision += 1
        if returned != expected or not self.teardown_confirmed:
            self.base = None
            return False
        self.base = tuple(f"route-{index}" for index in range(expected))
        return True

    def reconcile(self, expected_revision: int, expected_base: tuple[str, ...]) -> str:
        if self.base is None:
            return "reconnect"
        if expected_revision != self.revision or expected_base != self.base:
            self.base = None
            self.revision += 1
            return "reconnect"
        return "updated"

    def restart_after_teardown(
        self,
        desired: tuple[str, ...],
        tracked_count: int,
        removed_count: int,
    ) -> bool:
        self.base = None
        self.revision += 1
        self.teardown_confirmed = removed_count == tracked_count
        if not self.teardown_confirmed:
            return False
        self.base = desired
        self.revision += 1
        return True

    def shutdown(self) -> None:
        self.dns_generation += 1
        self.deferred_timer_active = False
        self.base = None


class ManagedRouteBehaviorTests(unittest.TestCase):
    def test_partial_initial_add_and_base_mismatch_never_confirm(self) -> None:
        worker = WorkerModel()
        self.assertFalse(worker.initial_add(expected=3, returned=2))
        self.assertIsNone(worker.base)

        controller = ControllerModel()
        self.assertIsNone(
            controller.connected_base(Desired(("A",), "a"), worker.revision, False)
        )
        self.assertTrue(controller.blocked)
        self.assertTrue(controller.full_rebuild_requested)
        self.assertIsNone(controller.request(Desired(("B",), "b")))
        self.assertEqual(controller.coalesced, Desired(("B",), "b"))

        worker.base = ("A",)
        self.assertEqual(worker.reconcile(worker.revision - 1, ("A",)), "reconnect")
        self.assertIsNone(worker.base)

    def test_a_to_b_to_c_is_serialized_and_coalesced(self) -> None:
        controller = ControllerModel()
        a = Desired(("A",), "a")
        b = Desired(("A", "B"), "b")
        c = Desired(("A", "B", "C"), "c")
        controller.connected_base(a, revision=7, confirmed=True)

        first = controller.request(b)
        self.assertIsNotNone(first)
        self.assertEqual(first.expected_revision, 7)
        self.assertIsNone(controller.request(c))
        self.assertEqual(controller.coalesced, c)

        second = controller.acknowledge(first.request_id, 1, "updated", 8)
        self.assertIsNotNone(second)
        self.assertEqual(second.old, b)
        self.assertEqual(second.new, c)
        self.assertEqual(second.expected_revision, 8)
        self.assertEqual(controller.confirmed, b)

        self.assertIsNone(controller.acknowledge(second.request_id, 1, "updated", 9))
        self.assertEqual(controller.confirmed, c)

    def test_deferred_result_stays_unknown_until_new_confirmed_base(self) -> None:
        controller = ControllerModel()
        a = Desired(("A",), "a")
        b = Desired(("A", "B"), "b")
        c = Desired(("C",), "c")
        controller.connected_base(a, revision=3, confirmed=True)
        pending = controller.request(b)

        self.assertIsNone(controller.acknowledge(pending.request_id, 1, "deferred", 4))
        self.assertIsNone(controller.confirmed)
        self.assertTrue(controller.blocked)
        self.assertIsNone(controller.request(c))
        self.assertEqual(controller.coalesced, c)

        controller.change_epoch()
        next_request = controller.connected_base(b, revision=5, confirmed=True)
        self.assertIsNotNone(next_request)
        self.assertEqual(next_request.old, b)
        self.assertEqual(next_request.new, c)

    def test_reconnect_required_never_projects_pending_desired_as_applied(self) -> None:
        controller = ControllerModel()
        a = Desired(("A",), "a")
        b = Desired(("B",), "b")
        controller.connected_base(a, revision=11, confirmed=True)
        pending = controller.request(b)

        self.assertIsNone(
            controller.acknowledge(pending.request_id, 1, "reconnect", 12)
        )
        self.assertIsNone(controller.confirmed)
        self.assertTrue(controller.blocked)
        self.assertEqual(controller.coalesced, b)
        self.assertEqual(controller.coalesced, b)

    def test_late_ack_is_epoch_safe_and_shutdown_invalidates_async_state(self) -> None:
        controller = ControllerModel()
        a = Desired(("A",), "a")
        b = Desired(("B",), "b")
        controller.connected_base(a, revision=2, confirmed=True)
        old_request = controller.request(b)
        controller.change_epoch()

        self.assertIsNone(
            controller.acknowledge(old_request.request_id, old_request.epoch, "updated", 3)
        )
        self.assertIsNone(controller.confirmed)
        self.assertTrue(controller.blocked)

        worker = WorkerModel()
        worker.base = ("A",)
        worker.shutdown()
        self.assertEqual(worker.dns_generation, 5)
        self.assertFalse(worker.deferred_timer_active)
        self.assertIsNone(worker.base)

    def test_new_base_receipt_does_not_drop_pending_or_newer_desired(self) -> None:
        controller = ControllerModel()
        a = Desired(("A",), "a")
        b = Desired(("B",), "b")
        c = Desired(("C",), "c")
        controller.connected_base(a, revision=2, confirmed=True)
        controller.request(b)

        next_request = controller.connected_base(a, revision=3, confirmed=True)
        self.assertIsNotNone(next_request)
        self.assertEqual(next_request.new, b)

        controller.request(c)
        newest_request = controller.connected_base(b, revision=4, confirmed=True)
        self.assertIsNotNone(newest_request)
        self.assertEqual(newest_request.new, c)

    def test_a_plus_b_to_a_requires_full_teardown_receipt_before_new_base(self) -> None:
        worker = WorkerModel()
        worker.base = ("A", "B")

        self.assertTrue(
            worker.restart_after_teardown(("A",), tracked_count=2, removed_count=2)
        )
        self.assertEqual(worker.base, ("A",))
        self.assertTrue(worker.teardown_confirmed)

    def test_partial_teardown_keeps_restarted_base_unknown(self) -> None:
        worker = WorkerModel()
        worker.base = ("A", "B")

        self.assertFalse(
            worker.restart_after_teardown(("A",), tracked_count=2, removed_count=1)
        )
        self.assertIsNone(worker.base)
        self.assertFalse(worker.teardown_confirmed)
        self.assertFalse(worker.initial_add(expected=1, returned=1))
        self.assertIsNone(worker.base)

    def test_controller_commits_normalized_ack_not_raw_pending_request(self) -> None:
        controller = ControllerModel()
        a = Desired(("A",), "a")
        raw_b = Desired(("A", "protected-host"), "b")
        normalized_b = Desired(("A",), "b")
        controller.connected_base(a, revision=5, confirmed=True)
        pending = controller.request(raw_b)

        self.assertIsNone(
            controller.acknowledge(
                pending.request_id,
                pending.epoch,
                "updated",
                6,
                applied=normalized_b,
            )
        )
        self.assertEqual(controller.confirmed, normalized_b)
        self.assertNotEqual(controller.confirmed, raw_b)


class ManagedRouteSourceContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.controller = source("client/core/controllers/connectionController.cpp")
        cls.vpn = source("client/vpnConnection.cpp")
        cls.vpn_header = source("client/vpnConnection.h")
        cls.policy_header = source("client/core/utils/managedRoutePolicy.h")

    def test_controller_commits_only_acknowledged_or_connected_base(self) -> None:
        acknowledgement = function_body(
            self.controller, "void ConnectionController::onManagedRouteReconciled("
        )
        base_ready = function_body(
            self.controller, "void ConnectionController::onManagedRouteBaseReady("
        )
        sync = function_body(
            self.controller, "void ConnectionController::syncServerRoutingRules()"
        )

        self.assertIn("requestAccepted && updated", acknowledgement)
        self.assertIn("m_confirmedManagedRouteMode = appliedMode", acknowledgement)
        self.assertIn("m_confirmedManagedSplitTunnelIps = appliedRoutes", acknowledgement)
        self.assertNotIn("m_confirmedManagedRouteMode = m_pendingManagedRouteMode", acknowledgement)
        self.assertNotIn("m_confirmedManagedSplitTunnelIps = m_pendingManagedRouteIps", acknowledgement)
        self.assertIn("m_confirmedManagedRouteMode = mode", base_ready)
        self.assertNotIn("m_serversRepository->effectiveSiteRouteMode", sync)
        self.assertNotIn("m_hasAppliedManagedRouteState", self.controller)
        self.assertNotIn("m_appliedManagedRouteMode", self.controller)

    def test_one_in_flight_and_latest_desired_are_separate(self) -> None:
        dispatch = function_body(
            self.controller,
            "void ConnectionController::dispatchManagedRouteReconciliation(",
        )
        preserve = function_body(
            self.controller,
            "void ConnectionController::preserveLatestManagedRouteDesired(",
        )
        acknowledgement = function_body(
            self.controller, "void ConnectionController::onManagedRouteReconciled("
        )

        self.assertIn("if (m_managedRouteReconcileInFlight)", dispatch)
        self.assertIn("preserveLatestManagedRouteDesired(desired)", dispatch)
        self.assertIn("m_managedRouteReconcileInFlight = true", dispatch)
        self.assertIn("m_coalescedManagedRouteDesired = desired", preserve)
        self.assertIn("managedRouteConnectionSnapshotPrepared", preserve)
        self.assertIn("m_coalescedManagedRouteDesired.valid", acknowledgement)
        self.assertIn("preservePendingManagedRouteDesired()", self.controller)
        self.assertLess(
            acknowledgement.index("clearPendingManagedRouteReconciliation()"),
            acknowledgement.rindex("dispatchManagedRouteReconciliation"),
        )

    def test_worker_rejects_expected_base_without_repository_reads(self) -> None:
        reconcile = function_body(
            self.vpn, "void VpnConnection::reconcileManagedSplitTunnelRoutes("
        )
        update = function_body(
            self.vpn,
            "VpnConnection::ManagedRouteUpdateResult VpnConnection::updateManagedSplitTunnelRoutes(",
        )
        append_config = function_body(
            self.vpn, "void VpnConnection::appendSplitTunnelingConfig()"
        )

        self.assertIn("expectedBaseRevision == m_authoritativeManagedRouteBaseRevision", reconcile)
        self.assertIn("normalizedExpectedOld == m_authoritativeManagedRoutes", reconcile)
        self.assertIn("if (!baseMatches)", reconcile)
        self.assertIn("invalidateAuthoritativeManagedRouteBase()", reconcile)
        self.assertNotIn("m_serversRepository", reconcile)
        self.assertNotIn("m_appSettingsRepository", reconcile)
        self.assertNotIn("m_serversRepository", update)
        self.assertNotIn("m_appSettingsRepository", update)
        self.assertIn("mode, oldRoutes, localSites, protectedHosts", update)
        self.assertIn("mode, newRoutes, localSites, protectedHosts", update)
        self.assertIn("m_preparedManagedRoutes", append_config)
        self.assertIn("m_preparedLocalSites", append_config)
        self.assertNotIn("m_serversRepository", append_config)
        self.assertNotIn("managedVpnSitesForRouting", append_config)
        self.assertNotIn("SecureServersRepository", self.vpn_header)
        self.assertNotIn("SecureAppSettingsRepository", self.vpn_header)
        self.assertNotIn("m_serversRepository", self.vpn)
        self.assertNotIn("m_appSettingsRepository", self.vpn)
        self.assertNotIn("setRepositories", self.vpn)
        self.assertNotIn("setRepositories", self.vpn_header)

    def test_worker_dns_uses_immutable_snapshot_and_never_repersists_ui_rules(self) -> None:
        add_routes = function_body(self.vpn, "void VpnConnection::addSitesRoutes(")
        controller_config = function_body(
            self.controller, "QJsonObject ConnectionController::createConnectionConfiguration("
        )

        self.assertIn("const QVariantMap localSitesSnapshot", add_routes)
        self.assertIn("m_startupLocalSites", add_routes)
        self.assertNotIn("m_preparedLocalSites", add_routes)
        self.assertNotIn("vpnSites(", add_routes)
        self.assertNotIn("addVpnSite(", add_routes)
        self.assertNotIn("Repository", add_routes)
        self.assertIn("configKey::appSplitTunnelType", controller_config)
        self.assertIn("configKey::splitTunnelApps", controller_config)

    def test_worker_constructor_and_start_context_are_repository_free(self) -> None:
        application = source("client/amneziaApplication.cpp")
        core = source("client/core/controllers/coreController.cpp")
        header = source("client/core/controllers/connectionController.h")

        self.assertIn("new VpnConnection()", application)
        self.assertNotIn("setRepositories", core)
        self.assertIn(
            "openConnectionRequested(const QString &serverId, int serverIndex",
            header,
        )
        self.assertIn("int serverIndex", self.vpn_header)

    def test_initial_receipt_is_bounded_and_partial_count_is_unknown(self) -> None:
        receipt = function_body(self.vpn, "bool addTrustedRoutesWithReceipt(")
        add_routes = function_body(self.vpn, "void VpnConnection::addSitesRoutes(")

        self.assertIn("waitForFinished(incrementalManagedRouteIpcTimeoutMs)", receipt)
        self.assertIn("reply.returnValue() == routes.size()", receipt)
        receipt_call = add_routes.index("addTrustedRoutesWithReceipt(gw, managedOnlyRoutes)")
        confirmed_insert = add_routes.index("activeManagedRoutes->insert(route)", receipt_call)
        unknown = add_routes.index("*managedAddsConfirmed = false", receipt_call)
        publish = add_routes.index("publishManagedRouteBase")
        self.assertLess(receipt_call, confirmed_insert)
        self.assertLess(receipt_call, unknown)
        self.assertLess(unknown, publish)
        initial_setup = add_routes[: add_routes.index("const auto startManagedRoutes")]
        self.assertIn("m_startupManagedRoutes", initial_setup)
        self.assertNotIn("m_preparedManagedRoutes", initial_setup)
        self.assertNotIn("managedVpnSitesForRouting", initial_setup)

    def test_protocol_startup_receipts_the_immutable_startup_snapshot(self) -> None:
        state_changed = function_body(
            self.vpn, "void VpnConnection::onConnectionStateChanged("
        )
        append_config = function_body(
            self.vpn, "void VpnConnection::appendSplitTunnelingConfig()"
        )
        publish_base = function_body(
            self.vpn, "void VpnConnection::publishManagedRouteBase("
        )
        prepare_snapshot = function_body(
            self.vpn, "void VpnConnection::prepareManagedRouteConnectionSnapshot("
        )
        open_connection = function_body(
            self.controller, "ErrorCode ConnectionController::openConnection("
        )

        self.assertIn("m_startupManagedRouteServerId = m_serverId", append_config)
        self.assertIn("m_startupManagedRouteMode = routeMode", append_config)
        self.assertIn("m_startupManagedRoutes = startupManagedRoutes", append_config)
        self.assertIn("m_startupLocalSites", append_config)
        self.assertIn("m_startupManagedRoutes", state_changed)
        self.assertIn("m_startupLocalSites", state_changed)
        self.assertNotIn("m_preparedManagedRoutes", state_changed)
        self.assertNotIn("m_preparedLocalSites", state_changed)
        self.assertIn("mode, managedRoutes, localSites, protectedHosts", publish_base)
        self.assertNotIn("m_preparedManagedRoute", publish_base)
        self.assertIn(
            "generation < m_latestPreparedManagedRouteSnapshotGeneration",
            prepare_snapshot,
        )
        self.assertIn("serverId != m_preparedManagedRouteServerId", prepare_snapshot)
        self.assertLess(
            open_connection.index("++m_managedRouteReconcileGeneration"),
            open_connection.index("prepareManagedRouteConnectionSnapshot(serverId)"),
        )

    def test_deferred_late_ack_and_shutdown_fail_closed(self) -> None:
        acknowledgement = function_body(
            self.controller, "void ConnectionController::onManagedRouteReconciled("
        )
        update = function_body(
            self.vpn,
            "VpnConnection::ManagedRouteUpdateResult VpnConnection::updateManagedSplitTunnelRoutes(",
        )
        shutdown = function_body(
            self.vpn, "void VpnConnection::shutdownForApplicationExit("
        )
        disconnect = function_body(self.vpn, "void VpnConnection::disconnectFromVpn()")

        self.assertIn("generation != m_pendingManagedRouteReconcileGeneration", acknowledgement)
        self.assertIn("connectionEpoch != m_cachedConnectionEpoch", acknowledgement)
        self.assertIn("m_managedRouteIncrementalBlocked = true", acknowledgement)
        self.assertIn("return ManagedRouteUpdateResult::ReconnectDeferred", update)
        self.assertIn("invalidateAllSplitRouteResolutions()", shutdown)
        self.assertIn("++m_connectionEpoch", shutdown)
        self.assertIn("m_checkTimer.stop()", shutdown)
        self.assertIn("invalidateAllSplitRouteResolutions()", disconnect)
        self.assertLess(
            shutdown.index("clearSavedRoutesWithReceipt()"),
            shutdown.index("disconnectSlots()"),
        )
        self.assertLess(
            shutdown.index("if (disconnectVpn)"),
            shutdown.index("clearSavedRoutesWithReceipt()"),
        )

        dns_reconnect = self.vpn.index(
            "local DNS resolution completed; reconnecting to apply deferred managed policy safely"
        )
        dns_reconnect = self.vpn[dns_reconnect : dns_reconnect + 1200]
        self.assertIn("expectedConnectionEpoch == m_connectionEpoch", dns_reconnect)
        self.assertIn("expectedServerId == m_serverId", dns_reconnect)

    def test_restored_android_connection_is_not_a_route_receipt(self) -> None:
        state_changed = function_body(
            self.vpn, "void VpnConnection::onConnectionStateChanged("
        )
        restore = function_body(
            self.vpn, "void VpnConnection::restoreConnection("
        )
        connect = function_body(
            self.vpn, "void VpnConnection::connectToVpn("
        )
        reconnect = function_body(
            self.vpn, "void VpnConnection::reconnectToVpn()"
        )

        self.assertIn("m_connectionRestoredWithoutStartup = true", restore)
        self.assertIn("m_connectionRestoredWithoutStartup = false", connect)
        self.assertGreaterEqual(
            reconnect.count("m_connectionRestoredWithoutStartup = false"), 2
        )
        self.assertIn(
            "protocolStartupConfirmsManagedBase = !m_connectionRestoredWithoutStartup",
            state_changed,
        )
        self.assertIn("else if (m_connectionRestoredWithoutStartup)", state_changed)
        restored_branch = state_changed[
            state_changed.index("else if (m_connectionRestoredWithoutStartup)") :
        ]
        restored_branch = restored_branch[: restored_branch.index("#if defined(Q_OS_IOS)")]
        self.assertNotIn("publishManagedRouteBase", restored_branch)
        self.assertNotIn("reconnectToVpn", restored_branch)
        self.assertNotIn("stop()", restored_branch)
        self.assertIn("waiting for natural reconnect", restored_branch)

    def test_reconnect_teardown_precedes_protocol_stop_and_gates_base(self) -> None:
        reconnect = function_body(self.vpn, "void VpnConnection::reconnectToVpn()")
        connect = function_body(self.vpn, "void VpnConnection::connectToVpn(")
        publish_base = function_body(
            self.vpn, "void VpnConnection::publishManagedRouteBase("
        )

        teardown = reconnect.rindex("clearSavedRoutesWithReceipt()")
        self.assertLess(teardown, reconnect.index("disconnectSlots()", teardown))
        self.assertLess(teardown, reconnect.index("m_vpnProtocol->stop()", teardown))
        self.assertLess(
            connect.index("clearSavedRoutesWithReceipt()"),
            connect.index("m_vpnProtocol->stop()"),
        )
        self.assertIn("m_startupRouteTeardownConfirmed", publish_base)

    def test_route_registries_retain_failed_rows_and_ack_existing_route_safely(self) -> None:
        windows = source("service/server/router_win.cpp")
        linux = source("service/server/router_linux.cpp")
        mac = source("service/server/router_mac.cpp")
        mac_helper = source("service/server/helper_route_mac.c")
        windows_clear = function_body(windows, "bool RouterWin::clearSavedRoutes()")
        linux_clear = function_body(linux, "bool RouterLinux::clearSavedRoutes()")
        mac_clear = function_body(mac, "bool RouterMac::clearSavedRoutes()")

        self.assertIn("ERROR_OBJECT_ALREADY_EXISTS", windows)
        self.assertIn("trackManagedRoute(ipWithMask, ipfrow)", windows)
        self.assertIn("m_ipForwardRows.erase(i)", windows_clear)
        self.assertIn("++i", windows_clear)
        self.assertIn("return m_ipForwardRows.isEmpty()", windows_clear)
        self.assertNotIn("m_addedRoutes.clear()", linux_clear)
        self.assertIn("m_addedRoutes.erase(route)", linux_clear)
        self.assertIn("return m_addedRoutes.isEmpty()", linux_clear)
        self.assertNotIn("m_addedRoutes.clear()", mac_clear)
        self.assertIn("m_addedRoutes.erase(route)", mac_clear)
        self.assertIn("return m_addedRoutes.isEmpty()", mac_clear)
        self.assertIn("oerrno == ESRCH", mac_helper)

    def test_ack_contains_exact_normalized_mode_and_routes(self) -> None:
        reconcile = function_body(
            self.vpn, "void VpnConnection::reconcileManagedSplitTunnelRoutes("
        )
        acknowledgement = function_body(
            self.controller, "void ConnectionController::onManagedRouteReconciled("
        )

        self.assertIn("int appliedMode", self.vpn_header)
        self.assertIn("const QStringList &appliedRoutes", self.vpn_header)
        self.assertIn("m_authoritativeManagedRouteMode", reconcile)
        self.assertIn("m_authoritativeManagedRoutes", reconcile)
        self.assertIn("canonicalAppliedRoutes == appliedRoutes", acknowledgement)
        self.assertIn("m_confirmedManagedRouteMode = appliedMode", acknowledgement)
        self.assertIn("m_confirmedManagedSplitTunnelIps = appliedRoutes", acknowledgement)

    def test_receipts_bind_exact_policy_identity_epoch_and_server(self) -> None:
        reconcile = function_body(
            self.vpn, "void VpnConnection::reconcileManagedSplitTunnelRoutes("
        )
        runtime_snapshot = function_body(
            self.vpn, "VpnConnection::managedRouteRuntimeSnapshot() const"
        )
        acknowledgement = function_body(
            self.controller, "void ConnectionController::onManagedRouteReconciled("
        )
        base_ready = function_body(
            self.controller, "void ConnectionController::onManagedRouteBaseReady("
        )

        self.assertIn("expectedPolicyRevision", self.vpn_header)
        self.assertIn("expectedPolicyContentHash", self.vpn_header)
        self.assertIn("desiredPolicyRevision", self.vpn_header)
        self.assertIn("desiredPolicyContentHash", self.vpn_header)
        self.assertIn(
            "expectedConnectionEpoch\n                    == m_authoritativeManagedRouteConnectionEpoch",
            reconcile,
        )
        self.assertIn(
            "expectedServerId == m_authoritativeManagedRouteServerId", reconcile
        )
        self.assertIn(
            "expectedPolicyRevision\n                    == m_authoritativeManagedRoutePolicyRevision",
            reconcile,
        )
        self.assertIn(
            "expectedPolicyContentHash\n                    == m_authoritativeManagedRoutePolicyContentHash",
            reconcile,
        )
        self.assertIn("desiredPolicyRevision", reconcile)
        self.assertIn("desiredPolicyContentHash", reconcile)
        self.assertIn("m_authoritativeManagedRouteConnectionEpoch", runtime_snapshot)
        self.assertIn("m_authoritativeManagedRouteServerId", runtime_snapshot)
        self.assertIn("isCanonicalPolicyIdentity", runtime_snapshot)
        self.assertIn(
            "appliedPolicyRevision == m_pendingManagedRoutePolicyRevision",
            acknowledgement,
        )
        self.assertIn(
            "appliedPolicyContentHash == m_pendingManagedRouteContentHash",
            acknowledgement,
        )
        self.assertIn("m_confirmedManagedPolicyRevision = policyRevision", base_ready)
        self.assertIn("m_confirmedManagedContentHash = policyContentHash", base_ready)
        self.assertIn("inline bool isCanonicalPolicyIdentity", self.policy_header)
        self.assertIn("revision.trimmed() == revision", self.policy_header)
        self.assertIn("inline QString effectiveRevision", self.policy_header)


if __name__ == "__main__":
    unittest.main()
