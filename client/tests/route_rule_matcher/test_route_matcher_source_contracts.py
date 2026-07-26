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


class RouteMatcherSourceContracts(unittest.TestCase):
    def test_route_inspector_uses_shared_resolved_matcher(self) -> None:
        inspector = source("client/core/controllers/routeInspectorController.cpp")

        self.assertIn('#include "core/utils/routeRuleMatcher.h"', inspector)
        self.assertIn("routeRuleMatcher::normalizeTarget(host)", inspector)
        self.assertIn("routeRuleMatcher::matchRules(", inspector)
        self.assertIn(
            "routeRuleMatcher::DomainMatchPolicy::RequireResolvedIpv4", inspector
        )
        for duplicate in (
            "struct NormalizedTarget",
            "struct RuleMatch",
            "bool addressMatchesRoute(",
            "QStringList storedRouteTokens(",
            "QString normalizedDomainRule(",
            "QString privacySafeRule(",
            "quint32 ipv4Mask(",
            "bool parseIpv4Route(",
            "bool routeOverlapsIpv4Range(",
            "bool isRoutableClientRoute(",
            "void considerMatch(",
            "void inspectRules(",
        ):
            self.assertNotIn(duplicate, inspector)

    def test_operator_uses_shared_policy_only_matcher_and_schema_adapter(self) -> None:
        application = source("client/amneziaApplication.cpp")
        explain = function_body(
            application,
            "AmneziaApplication::operatorRoutesExplain(const QString &hostInput) const",
        )

        self.assertIn('#include "core/utils/routeRuleMatcher.h"', application)
        self.assertIn("routeRuleMatcher::normalizeTarget(", explain)
        self.assertIn("routeRuleMatcher::InputPolicy::BareHostOrAddress", explain)
        self.assertIn("routeRuleMatcher::matchRules(", explain)
        self.assertIn("routeRuleMatcher::DomainMatchPolicy::PolicyOnly", explain)
        self.assertIn("match.configuredRule", explain)
        self.assertIn("match.matchedValue", explain)
        self.assertIn("match.matchedValueTruncated", explain)
        self.assertIn("matchResult.coverageComplete", explain)
        self.assertIn('QStringLiteral("route_rule_coverage_truncated")', explain)
        self.assertIn('QStringLiteral("server-managed")', explain)
        self.assertIn("operatorMode::assessRouteRuntime", explain)
        self.assertIn("managedSnapshot.installedRoutes", explain)
        self.assertIn("snapshotAuthoritative", explain)
        self.assertIn("serverEpochMatches", explain)
        self.assertIn("policyIdentityMatches", explain)
        self.assertIn('QStringLiteral("osRouteVerified"), false', explain)
        self.assertIn("local route installation is unconfirmed", explain)
        self.assertNotIn("managedVpnSitesForRouting", explain)
        self.assertNotIn("appSettings.vpnSites", explain)
        self.assertIn('QStringLiteral("matchedValueTruncated")', explain)
        self.assertIn("boundedOperatorField(\n            matchedRule", explain)
        for duplicate in (
            "bool normalizeOperatorHost(",
            "quint32 operatorIpv4Mask(",
            "bool operatorRouteOverlapsRange(",
            "bool operatorRuntimeSupportsRoute(",
            "bool addressMatchesSubnet(",
            "bool hostMatchesRule(",
            "bool mappedAddressMatches(",
        ):
            self.assertNotIn(duplicate, application)

    def test_route_inspector_uses_confirmed_installed_snapshot_and_dns_coverage(self) -> None:
        header = source("client/core/controllers/routeInspectorController.h")
        inspector = source("client/core/controllers/routeInspectorController.cpp")
        vpn_header = source("client/vpnConnection.h")
        qml = source("client/ui/qml/Pages2/PageRouteInspector.qml")

        self.assertIn("maximumProcessedDnsAddresses = 64", header)
        self.assertIn("maximumDisplayedAddressesPerFamily = 16", header)
        self.assertIn("addresses.size() > maximumProcessedDnsAddresses", header)
        self.assertIn("managedRouteRuntimeSnapshot()", vpn_header)
        self.assertIn("vpnConnection->managedRouteRuntimeSnapshot()", inspector)
        self.assertIn("installedManagedRoutes", inspector)
        self.assertIn("managedRoutePolicyRevision", header)
        self.assertIn("managedRoutePolicyContentHash", header)
        self.assertIn("runtimePolicyIdentityMatches", inspector)
        self.assertIn("runtimeServerBindingMatches", inspector)
        self.assertIn("installedSnapshotAuthoritative", inspector)
        self.assertIn("local_route_receipt_unavailable", inspector)
        self.assertIn("const QVariantMap localRules = !runtimeConnected", inspector)
        self.assertIn("runtimeRouteTransitionPending", inspector)
        self.assertIn("dns_addresses_truncated_unexamined", inspector)
        self.assertIn("route_rule_coverage_truncated", inspector)
        self.assertIn("authoritativeManagedRouteSnapshot", qml)
        self.assertIn("runtimeApplied", qml)
        self.assertIn("runtimeRouteModeDiverged", qml)
        self.assertNotIn("Connected-policy estimate", qml)

    def test_shared_api_exposes_policy_only_and_bounded_value(self) -> None:
        header = source("client/core/utils/routeRuleMatcher.h")
        implementation = source("client/core/utils/routeRuleMatcher.cpp")

        self.assertIn("enum class InputPolicy", header)
        self.assertIn("BareHostOrAddress", header)
        self.assertIn("enum class DomainMatchPolicy", header)
        self.assertIn("PolicyOnly", header)
        self.assertIn("QString configuredRule", header)
        self.assertIn("QString matchedValue", header)
        self.assertIn("bool matchedValueTruncated", header)
        self.assertIn("bool coverageComplete", header)
        self.assertIn("maximumRulesPerSource", header)
        self.assertIn("maximumRawStoredValueLength", header)
        self.assertIn("maximumMatchedValueLength", header)
        self.assertIn("matchedValue.left(maximumMatchedValueLength)", implementation)
        self.assertNotIn(".split(separator", implementation)
        self.assertIn("inspectedRules >= maximumRulesPerSource", implementation)
        self.assertIn("rawValue.left(maximumRawStoredValueLength)", implementation)
        self.assertIn("score == best.score", implementation)
        self.assertIn('source == QStringLiteral("local")', implementation)

    def test_guardian_recovery_requires_ui_action_and_epoch_bound_ack(self) -> None:
        health_header = source(
            "client/core/controllers/connectionHealthController.h"
        )
        core = source("client/core/controllers/coreController.cpp")
        fleet = source("client/ui/qml/Pages2/PageFleetCenter.qml")

        self.assertIn("requestPendingRecovery", health_header)
        self.assertIn("recoveryActionRequested", health_header)
        self.assertIn("expectedRecoveryEpoch", health_header)
        self.assertIn(
            "&ConnectionHealthController::recoverySuggested", core
        )
        self.assertIn(
            "&ConnectionHealthController::recoveryActionRequested", core
        )
        self.assertIn("m_guardianSuggestedConnectionEpoch", core)
        self.assertIn("guardianRecoveryDeadlineMs", core)
        self.assertIn("acknowledgeRecoveryResult(", core)
        self.assertIn("managedRouteRuntimeSnapshot()", core)
        self.assertIn("tunnelPathVerified", core)
        self.assertIn("applicationUsesVpnDataPath", core)
        self.assertIn('QStringLiteral("org.amnezia.vpn")', core)
        self.assertIn(
            "m_guardianNetworkManager = new QNetworkAccessManager(this)", core
        )
        self.assertIn(
            "m_guardianNetworkManager->setProxy(QNetworkProxy::NoProxy)", core
        )
        self.assertIn("m_guardianNetworkManager->proxyFactory()", core)
        self.assertIn(
            "m_guardianNetworkManager->proxy().type()", core
        )
        self.assertIn("QNetworkProxy::NoProxy", core)
        self.assertNotIn("amnApp->networkManager()", core)
        health = source(
            "client/core/controllers/connectionHealthController.cpp"
        )
        self.assertIn("proxyPathVerifiedDirect", health)
        self.assertIn("networkManager->proxyFactory()", health)
        self.assertIn("networkManager->proxy().type()", health)
        self.assertLess(
            health.index("proxyPathVerifiedDirect"),
            health.index("networkManager->head(request)"),
        )
        self.assertIn('QStringLiteral("probe_app_route_unverified")', core)
        self.assertIn('QStringLiteral("probe_tunnel_path_unverified")', core)
        self.assertIn('QStringLiteral("probe_proxy_path_unverified")', core)
        self.assertLess(
            core.index('QStringLiteral("probe_app_route_unverified")'),
            core.index("startConnectivityProbe("),
        )
        self.assertLess(
            core.index('QStringLiteral("probe_proxy_path_unverified")'),
            core.index("startConnectivityProbe("),
        )
        self.assertLess(
            core.index("m_guardianNetworkManager->proxyFactory()"),
            core.index("startConnectivityProbe("),
        )
        self.assertIn(
            "guardianRunSuggestedRecoveryButton", fleet
        )
        self.assertIn("requestPendingRecovery()", fleet)


if __name__ == "__main__":
    unittest.main()
