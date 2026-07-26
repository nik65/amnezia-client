pragma ComponentBehavior: Bound

import QtQuick
import QtQuick.Layouts

import SortFilterProxyModel 0.2

import Style 1.0

import "../Controls2"
import "../Controls2/TextTypes"
import "../Config"

PageType {
    id: root

    objectName: "routeInspectorPage"
    Accessible.role: Accessible.Pane
    Accessible.name: qsTr("Route Inspector")

    // Keep the controller optional: mobile or reduced builds can still show a
    // bounded exact-match preview from the models already exposed to QML.
    property var ipSplitTunnelingUiController: IpSplitTunnelingController
    property var sitesController: SitesController
    property var connectionUiController: ConnectionController
    property var runtimeInspectorController: typeof RouteInspectorController !== "undefined" ? RouteInspectorController : null
    property var localSitesModel: IpSplitTunnelingModel
    property var managedSitesModel: ManagedExceptSitesModel

    property bool allowRuleMutation: true

    property string targetInput: ""
    property string inspectedTarget: ""
    property string resultDecision: qsTr("Enter a website or IP address")
    property string resultModeOverride: ""
    property string resultSource: qsTr("Current client policy")
    property string resultStatus: qsTr("Ready")
    property string resultInspectionBasis: "policyPreview"
    property string resultExplanation: qsTr("Route Inspector previews saved policy or, when available, evaluates a confirmed client route receipt. It does not inspect the operating system route table.")
    property bool resultPending: false
    property bool resultFromIntegration: false
    property int resultGeneration: 0
    property string activeRuntimeRequestId: ""
    property string routeReportJson: ""
    property string pendingRuleTarget: ""
    property int pendingRuleMode: routeMode.allSites

    readonly property int currentRouteMode: root.readCurrentRouteMode()
    readonly property bool splitTunnelingEnabled: root.readSplitTunnelingEnabled()
    property bool managedForceEnabled: false
    readonly property bool connectionActive: root.readConnectionActive()
    readonly property string normalizedInput: root.normalizeTarget(root.targetInput)
    readonly property bool inspectedTargetIsIpv6: root.inspectedTarget.indexOf(":") >= 0
    readonly property string exactTargetPattern: "^" + root.escapeRegularExpression(root.inspectedTarget) + "$"
    readonly property bool hasLocalMatch: root.inspectedTarget !== "" && localExactModel.count > 0
    readonly property bool hasManagedMatch: root.inspectedTarget !== "" && managedExactModel.count > 0
    readonly property bool hasLocalRefreshApi: root.hasMethod(root.ipSplitTunnelingUiController, "updateModel") || root.hasMethod(root.sitesController, "reloadDefaultManagedSites")
    readonly property bool canReloadSavedPolicy: root.hasLocalRefreshApi
    readonly property bool canAddCurrentRule: root.allowRuleMutation && root.isSafeRuleTarget(root.normalizedInput) && root.normalizedInput === root.inspectedTarget && !root.connectionActive && !root.resultPending && root.pendingRuleTarget === "" && root.splitTunnelingEnabled && root.currentRouteMode !== routeMode.allSites && !root.hasLocalMatch && !(root.currentRouteMode === routeMode.allExceptSites && root.hasManagedMatch) && root.hasMethod(root.ipSplitTunnelingUiController, "addSite")

    signal inspectionRequested(string target, int generation)
    signal localPolicyReloadRequested(string target)
    signal ruleAddDispatched(string target, int routeMode)
    signal inputValidationFailed(string message)
    signal resultAnnouncementRequested(string message)

    QtObject {
        id: routeMode

        readonly property int allSites: 0
        readonly property int onlyForwardSites: 1
        readonly property int allExceptSites: 2
    }

    function hasMethod(controller, methodName) {
        if (!controller) {
            return false;
        }

        try {
            return typeof controller[methodName] === "function";
        } catch (error) {
            return false;
        }
    }

    function normalizeTarget(value) {
        var target = String(value || "").trim();
        if (target === "") {
            return "";
        }

        target = target.replace(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, "");
        var pathStart = target.search(/[\/?#]/);
        if (pathStart >= 0) {
            target = target.substring(0, pathStart);
        }

        var credentialsEnd = target.lastIndexOf("@");
        if (credentialsEnd >= 0) {
            target = target.substring(credentialsEnd + 1);
        }

        if (target.charAt(0) === "[") {
            var bracketEnd = target.indexOf("]");
            if (bracketEnd > 0) {
                target = target.substring(1, bracketEnd);
            }
        } else {
            var firstColon = target.indexOf(":");
            var lastColon = target.lastIndexOf(":");
            if (firstColon > 0 && firstColon === lastColon) {
                var possiblePort = target.substring(lastColon + 1);
                if (/^[0-9]+$/.test(possiblePort)) {
                    target = target.substring(0, lastColon);
                }
            }
        }

        target = target.toLowerCase();
        while (target.length > 0 && target.charAt(target.length - 1) === ".") {
            target = target.substring(0, target.length - 1);
        }
        return target;
    }

    function isValidTarget(target) {
        if (target === "" || target.length > 2048 || /[\s\x00-\x1f\x7f]/.test(target)) {
            return false;
        }
        return true;
    }

    function isSafeRuleTarget(target) {
        if (target === "" || target.length > 253 || /[\s\x00-\x1f\x7f]/.test(target)) {
            return false;
        }

        if (/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/.test(target)) {
            var octets = target.split(".");
            for (var octetIndex = 0; octetIndex < octets.length; ++octetIndex) {
                if (Number(octets[octetIndex]) > 255) {
                    return false;
                }
            }
            return true;
        }

        if (target.indexOf(":") >= 0) {
            // The current split-tunneling editor and runtime install IPv4
            // site routes only. Keep IPv6 inspection read-only.
            return false;
        }

        var labels = target.split(".");
        if (labels.length < 2) {
            return false;
        }
        for (var labelIndex = 0; labelIndex < labels.length; ++labelIndex) {
            var label = labels[labelIndex];
            if (label === "" || label.length > 63 || label.charAt(0) === "-" || label.charAt(label.length - 1) === "-") {
                return false;
            }
            if (!/^[A-Za-z0-9\u0080-\uFFFF-]+$/.test(label)) {
                return false;
            }
        }
        return true;
    }

    function escapeRegularExpression(value) {
        var escaped = "";
        var specialCharacters = "\\^$.*+?()[]{}|";
        for (var index = 0; index < value.length; ++index) {
            var character = value.charAt(index);
            if (specialCharacters.indexOf(character) >= 0) {
                escaped += "\\";
            }
            escaped += character;
        }
        return escaped;
    }

    function readCurrentRouteMode() {
        try {
            if (root.ipSplitTunnelingUiController && typeof root.ipSplitTunnelingUiController.routeMode !== "undefined") {
                return Number(root.ipSplitTunnelingUiController.routeMode);
            }
        } catch (error) {
            // The policy UI remains useful with a future injected controller.
        }
        return routeMode.allSites;
    }

    function readSplitTunnelingEnabled() {
        try {
            return root.ipSplitTunnelingUiController && root.ipSplitTunnelingUiController.isSplitTunnelingEnabled === true;
        } catch (error) {
            return false;
        }
    }

    function readManagedForceEnabled() {
        if (!root.hasMethod(root.sitesController, "isDefaultManagedSplitTunnelingForceEnabled")) {
            return false;
        }

        try {
            return root.sitesController.isDefaultManagedSplitTunnelingForceEnabled() === true;
        } catch (error) {
            return false;
        }
    }

    function readConnectionActive() {
        try {
            return root.connectionUiController && (root.connectionUiController.isConnected === true || root.connectionUiController.isConnectionInProgress === true);
        } catch (error) {
            return false;
        }
    }

    function currentModeText() {
        if (!root.splitTunnelingEnabled) {
            return root.managedForceEnabled ? qsTr("Server-managed bypass rules") : qsTr("All traffic through VPN");
        }

        if (root.currentRouteMode === routeMode.onlyForwardSites) {
            return qsTr("VPN only for listed sites");
        }
        if (root.currentRouteMode === routeMode.allExceptSites) {
            return qsTr("VPN for all sites except listed");
        }
        return qsTr("All traffic through VPN");
    }

    function connectionStatusText() {
        try {
            if (root.connectionUiController && typeof root.connectionUiController.connectionStateText === "string" && root.connectionUiController.connectionStateText !== "") {
                return root.connectionUiController.connectionStateText;
            }
        } catch (error) {
            // Fall back to the stable boolean property below.
        }
        return root.connectionActive ? qsTr("Connected") : qsTr("Disconnected");
    }

    function resetResultForInspection() {
        root.resultDecision = qsTr("Checking saved policy...");
        root.resultModeOverride = "";
        root.resultSource = qsTr("Current client policy");
        root.resultStatus = qsTr("Inspecting");
        root.resultInspectionBasis = "runtimeSnapshotPending";
        root.resultExplanation = qsTr("Reading a confirmed client route receipt when available; otherwise only saved policy can be previewed.");
        root.resultPending = true;
        root.resultFromIntegration = false;
    }

    function inspectTarget() {
        var target = root.normalizedInput;
        if (!root.isValidTarget(target)) {
            root.inputValidationFailed(qsTr("Enter a valid website or IP address"));
            return;
        }

        root.inspectedTarget = target;
        root.activeRuntimeRequestId = "";
        root.routeReportJson = "";
        root.resultGeneration += 1;
        var generation = root.resultGeneration;
        root.resetResultForInspection();

        var runtimeHandled = root.dispatchRuntimeInspection(target);
        root.inspectionRequested(target, generation);

        if (runtimeHandled) {
            return;
        }

        // Let proxy models observe inspectedTarget before reading their counts.
        // An integration result delivered synchronously cancels this fallback.
        Qt.callLater(function () {
            if (generation === root.resultGeneration && root.resultPending) {
                root.applyPolicyPreview(target);
            }
        });
    }

    function resultMapValue(result, key, fallbackValue) {
        if (!result) {
            return fallbackValue;
        }
        try {
            var value = result[key];
            return typeof value === "undefined" || value === null ? fallbackValue : value;
        } catch (error) {
            return fallbackValue;
        }
    }

    function runtimeModeText(result) {
        var runtimeApplied = root.resultMapValue(result, "runtimeApplied", false) === true;
        var mode = Number(root.resultMapValue(
                              result,
                              runtimeApplied ? "appliedRouteMode" : "routeMode",
                              routeMode.allSites));
        if (mode === routeMode.onlyForwardSites) {
            return qsTr("VPN only for listed sites");
        }
        if (mode === routeMode.allExceptSites) {
            return qsTr("VPN for all sites except listed");
        }
        return qsTr("All traffic through VPN");
    }

    function runtimeSourceText(source) {
        if (source === "local") {
            return qsTr("Local split tunneling rule");
        }
        if (source === "managed") {
            return qsTr("Server-managed rule");
        }
        if (source === "multiple") {
            return qsTr("Multiple route sources");
        }
        if (source === "tunnelSafety") {
            return qsTr("Tunnel safety override");
        }
        if (source === "runtimeUnknown") {
            return qsTr("Installed route state unavailable");
        }
        return qsTr("Default route");
    }

    function runtimeMatchTypeText(matchType) {
        if (matchType === "domain") {
            return qsTr("domain");
        }
        if (matchType === "resolvedAddress") {
            return qsTr("resolved address");
        }
        if (matchType === "address") {
            return qsTr("IP address");
        }
        return qsTr("rule");
    }

    function runtimeDecisionText(decision) {
        if (decision === "direct") {
            return qsTr("Outside VPN");
        }
        if (decision === "vpn") {
            return qsTr("Through VPN");
        }
        if (decision === "mixed") {
            return qsTr("Mixed route by address");
        }
        return qsTr("Installed route state unavailable");
    }

    function runtimeErrorText(errorCode) {
        if (errorCode === "dns_host_not_found") {
            return qsTr("DNS could not find this host");
        }
        if (errorCode === "dns_no_addresses") {
            return qsTr("DNS returned no usable addresses");
        }
        if (errorCode === "dns_lookup_failed") {
            return qsTr("DNS lookup failed");
        }
        if (errorCode === "dns_lookup_timeout") {
            return qsTr("DNS lookup timed out");
        }
        if (errorCode === "route_configuration_unavailable") {
            return qsTr("Routing configuration is unavailable");
        }
        if (errorCode === "scoped_ipv6_not_supported") {
            return qsTr("Scoped IPv6 addresses are not supported");
        }
        return qsTr("The target could not be inspected");
    }

    function joinedResultList(value) {
        if (!value) {
            return "";
        }
        try {
            if (typeof value.join === "function") {
                return value.join(", ");
            }
        } catch (error) {
            // Fall through to a bounded string representation.
        }
        return String(value);
    }

    function resultListContains(value, expectedValue) {
        if (!value) {
            return false;
        }
        try {
            return typeof value.indexOf === "function" && value.indexOf(expectedValue) >= 0;
        } catch (error) {
            return false;
        }
    }

    function applyRuntimeInspectionResult(result) {
        if (!result) {
            return false;
        }

        var requestId = String(root.resultMapValue(result, "requestId", ""));
        if (root.activeRuntimeRequestId !== "" && requestId !== "" && requestId !== root.activeRuntimeRequestId) {
            return false;
        }
        if (requestId !== "") {
            root.activeRuntimeRequestId = requestId;
        }

        var state = String(root.resultMapValue(result, "state", "error"));
        var source = String(root.resultMapValue(result, "source", "default"));
        var decision = String(root.resultMapValue(result, "decision", "vpn"));
        var matchedRule = String(root.resultMapValue(result, "matchedRule", ""));
        var matchType = String(root.resultMapValue(result, "matchType", ""));
        var warnings = root.resultMapValue(result, "warnings", null);
        var runtimeApplied = root.resultMapValue(result, "runtimeApplied", false) === true;
        var inspectionBasis = String(root.resultMapValue(result, "inspectionBasis", "runtimeSnapshotUnavailable"));
        var routeModeDiverged = root.resultMapValue(result, "runtimeRouteModeDiverged", false) === true;
        var managedRouteDiverged = root.resultMapValue(result, "runtimeManagedRouteDiverged", false) === true;
        var dnsProcessingTruncated = root.resultMapValue(result, "dnsProcessingTruncated", false) === true;
        var ipv6SplitRouteUnknown = decision === "unknown" && root.resultListContains(warnings, "ipv6_split_rules_not_installed");
        var localRouteReceiptUnavailable = decision === "unknown" && root.resultListContains(warnings, "local_route_receipt_unavailable");
        var ipv4 = root.joinedResultList(root.resultMapValue(result, "resolvedIpv4", null));
        var ipv6 = root.joinedResultList(root.resultMapValue(result, "resolvedIpv6", null));
        var explanationParts = [];

        root.resultGeneration += 1;
        root.resultModeOverride = root.runtimeModeText(result);
        root.resultSource = root.runtimeSourceText(source);
        root.resultInspectionBasis = inspectionBasis;
        root.resultFromIntegration = true;

        if (state === "resolving") {
            root.resultDecision = qsTr("Resolving DNS...");
            root.resultStatus = qsTr("Resolving DNS");
            root.resultExplanation = qsTr("Looking up current A and AAAA records before evaluating route rules.");
            root.resultPending = true;
            return true;
        }

        if (state === "error") {
            root.resultDecision = root.runtimeErrorText(String(root.resultMapValue(result, "error", "")));
            root.resultStatus = qsTr("Inspection failed");
            root.resultPending = false;
            explanationParts.push(qsTr("The saved policy context is shown above, but a DNS-aware decision could not be completed."));
        } else {
            root.resultDecision = root.runtimeDecisionText(decision);
            if (decision === "unknown") {
                root.resultStatus = qsTr("Runtime state unavailable");
            } else if (runtimeApplied
                       && inspectionBasis === "authoritativeManagedRouteSnapshot") {
                root.resultStatus = qsTr("Confirmed client route snapshot");
            } else if (inspectionBasis === "policyPreview") {
                root.resultStatus = qsTr("Saved policy preview");
            } else {
                root.resultStatus = qsTr("Runtime policy result");
            }
            root.resultPending = false;

            if (decision === "unknown") {
                if (routeModeDiverged || managedRouteDiverged
                    || inspectionBasis === "runtimePolicyDiverged") {
                    explanationParts.push(qsTr("The installed route snapshot and the current desired policy diverge, so no definitive route is reported."));
                } else if (inspectionBasis === "runtimeRouteTransitionPending") {
                    explanationParts.push(qsTr("Managed routes are being reconciled or a bounded reconnect is pending. The route remains unknown until a new installation receipt arrives."));
                } else if (inspectionBasis === "runtimeRouteSnapshotUnconfirmed") {
                    explanationParts.push(qsTr("The connected tunnel has no confirmed managed-route installation receipt."));
                } else if (dnsProcessingTruncated) {
                    explanationParts.push(qsTr("DNS returned more addresses than the bounded inspector can examine, so the aggregate route is unknown."));
                } else if (ipv6SplitRouteUnknown) {
                    explanationParts.push(qsTr("At least one resolved IPv6 address has an unknown route because this client installs split-tunneling site routes for IPv4 only."));
                } else if (localRouteReceiptUnavailable) {
                    explanationParts.push(qsTr("No confirmed managed route matched, and local desktop routes have no exact installation receipt. The route therefore remains unknown."));
                } else {
                    explanationParts.push(qsTr("A definitive route could not be determined from the current runtime state."));
                }
            } else if (matchedRule !== "") {
                explanationParts.push(qsTr("Matched %1: %2.").arg(root.runtimeMatchTypeText(matchType)).arg(matchedRule));
            } else {
                explanationParts.push(qsTr("No saved rule matched; the effective mode selected the default route."));
            }
        }

        if (ipv4 !== "") {
            explanationParts.push(qsTr("IPv4: %1.").arg(ipv4));
        }
        if (ipv6 !== "") {
            explanationParts.push(qsTr("IPv6: %1.").arg(ipv6));
        }

        var policy = root.resultMapValue(result, "policy", null);
        if (policy) {
            var revision = String(root.resultMapValue(policy, "revision", ""));
            if (revision !== "") {
                explanationParts.push(qsTr("Managed policy revision: %1.").arg(revision));
            }
            if (root.resultMapValue(policy, "expired", false) === true) {
                explanationParts.push(qsTr("The managed policy is expired."));
            }
            var trustState = String(root.resultMapValue(policy, "trustState", "unsigned"));
            if (trustState === "unsigned") {
                explanationParts.push(qsTr("Managed policy trust: unsigned. Its digest and revision do not authenticate the publisher."));
            } else {
                explanationParts.push(qsTr("Managed policy trust: %1.").arg(trustState));
            }
            if (root.resultMapValue(policy, "contentMatchesDeclaration", true) !== true) {
                explanationParts.push(qsTr("The saved managed routes do not match the policy content digest and are inactive."));
            }
        }

        var ineffectiveReason = String(root.resultMapValue(result, "policyIneffectiveReason", ""));
        if (ineffectiveReason === "lifecycle_metadata_invalid") {
            explanationParts.push(qsTr("Managed policy lifecycle metadata is invalid, so the policy is inactive."));
        } else if (ineffectiveReason === "legacy_content_invalid") {
            explanationParts.push(qsTr("The legacy managed route set failed current safety limits and is inactive."));
        } else if (ineffectiveReason === "content_digest_mismatch" && !policy) {
            explanationParts.push(qsTr("The managed route content digest does not match, so the policy is inactive."));
        }

        if (runtimeApplied
            && inspectionBasis === "authoritativeManagedRouteSnapshot") {
            var installedRevision = String(root.resultMapValue(
                                               result,
                                               "managedRouteSnapshotRevision",
                                               ""));
            explanationParts.push(
                        installedRevision !== ""
                         ? qsTr("This result uses confirmed client managed-route receipt revision %1 and resolved DNS addresses; it does not query the operating system route table.").arg(installedRevision)
                         : qsTr("This result uses a confirmed client managed-route receipt and resolved DNS addresses; it does not query the operating system route table."));
        } else if (inspectionBasis === "policyPreview") {
            explanationParts.push(qsTr("The VPN is disconnected, so this is a saved-policy preview rather than a runtime route claim."));
        } else {
            explanationParts.push(qsTr("No definitive installed-route receipt is available; the operating system route table was not queried."));
        }
        root.resultExplanation = explanationParts.join(" ");
        root.resultAnnouncementRequested(root.resultDecision + ". " + root.resultStatus);
        return true;
    }

    function dispatchRuntimeInspection(target) {
        if (!root.hasMethod(root.runtimeInspectorController, "inspectHost")) {
            return false;
        }

        try {
            return root.applyRuntimeInspectionResult(root.runtimeInspectorController.inspectHost(target));
        } catch (error) {
            return false;
        }
    }

    function storeRouteReport(json) {
        var report = String(json || "");
        if (report === "" || report.length > 256 * 1024) {
            return false;
        }

        try {
            var parsed = JSON.parse(report);
            var requestId = String(root.resultMapValue(parsed, "requestId", ""));
            if (root.activeRuntimeRequestId !== "" && requestId !== "" && requestId !== root.activeRuntimeRequestId) {
                return false;
            }
            root.routeReportJson = JSON.stringify(parsed, null, 2);
            return true;
        } catch (error) {
            return false;
        }
    }

    function copyRouteReport() {
        if (root.routeReportJson === "") {
            return;
        }
        GC.copyToClipBoard(root.routeReportJson);
        PageController.showNotificationMessage(qsTr("Route report copied"));
    }

    function applyPolicyPreview(target) {
        if (target !== root.inspectedTarget) {
            return;
        }

        var localMatch = root.hasLocalMatch;
        var managedMatch = root.hasManagedMatch;
        var decision = qsTr("Likely through VPN");
        var source = qsTr("Default route");
        var explanation = "";

        if (!root.splitTunnelingEnabled) {
            if (root.managedForceEnabled && managedMatch) {
                decision = qsTr("Likely outside VPN");
                source = qsTr("Server-managed rule");
                explanation = qsTr("The target exactly matches a server-managed bypass entry that is enforced while local split tunneling is disabled.");
            } else {
                explanation = root.managedForceEnabled ? qsTr("No matching server-managed bypass entry was found, so the default VPN route applies.") : qsTr("Site-based split tunneling is disabled, so the default VPN route applies.");
            }
        } else if (root.currentRouteMode === routeMode.onlyForwardSites) {
            if (localMatch) {
                source = qsTr("Local split tunneling rule");
                explanation = qsTr("The target exactly matches a local entry and this mode sends listed sites through the VPN.");
            } else {
                decision = qsTr("Likely outside VPN");
                explanation = qsTr("No matching local entry was found and this mode sends only listed sites through the VPN.");
            }
        } else if (root.currentRouteMode === routeMode.allExceptSites) {
            if (managedMatch) {
                decision = qsTr("Likely outside VPN");
                source = qsTr("Server-managed rule");
                explanation = qsTr("The target exactly matches a server-managed bypass entry.");
            } else if (localMatch) {
                decision = qsTr("Likely outside VPN");
                source = qsTr("Local split tunneling rule");
                explanation = qsTr("The target exactly matches a local bypass entry.");
            } else {
                explanation = qsTr("No matching bypass entry was found, so the default VPN route applies.");
            }
        } else {
            explanation = qsTr("The current policy sends all site traffic through the VPN.");
        }

        root.resultDecision = decision;
        root.resultModeOverride = "";
        root.resultSource = source;
        root.resultStatus = qsTr("Limited policy preview");
        root.resultInspectionBasis = "policyPreview";
        root.resultExplanation = explanation + " " + qsTr("Only exact saved entries were checked because the runtime inspector is unavailable. DNS resolution and subnet matches may change this result.");
        root.resultPending = false;
        root.resultFromIntegration = false;
        root.resultAnnouncementRequested(root.resultDecision + ". " + root.resultStatus);
    }

    // Integration hook: a runtime inspector may replace the local preview.
    // Returns false when a late result belongs to a target that is no longer shown.
    function setInspectionResult(target, decision, mode, source, status, explanation) {
        var normalizedTarget = root.normalizeTarget(target);
        if (normalizedTarget === "" || (normalizedTarget !== root.inspectedTarget && String(target) !== root.inspectedTarget)) {
            return false;
        }

        root.resultGeneration += 1;
        root.resultDecision = String(decision || qsTr("Route unavailable"));
        root.resultModeOverride = String(mode || "");
        root.resultSource = String(source || qsTr("Runtime inspector"));
        root.resultStatus = String(status || qsTr("Complete"));
        root.resultInspectionBasis = "externalIntegration";
        root.resultExplanation = String(explanation || qsTr("The runtime inspector did not provide additional details."));
        root.resultPending = false;
        root.resultFromIntegration = true;
        root.resultAnnouncementRequested(root.resultDecision + ". " + root.resultStatus);
        return true;
    }

    function reloadSavedPolicyModels() {
        var refreshed = false;

        if (root.hasMethod(root.ipSplitTunnelingUiController, "updateModel")) {
            try {
                root.ipSplitTunnelingUiController.updateModel();
                refreshed = true;
            } catch (error) {
                // Continue so another available source can still be refreshed.
            }
        }

        if (root.hasMethod(root.sitesController, "reloadDefaultManagedSites")) {
            try {
                root.sitesController.reloadDefaultManagedSites();
                refreshed = true;
            } catch (error) {
                // The local split-tunneling model above may still be reloaded.
            }
        }
        return refreshed;
    }

    function reloadSavedPolicy() {
        if (!root.canReloadSavedPolicy) {
            return;
        }

        root.reloadSavedPolicyModels();
        root.localPolicyReloadRequested(root.inspectedTarget);

        if (root.inspectedTarget !== "") {
            root.resultStatus = qsTr("Reloading saved policy");
            Qt.callLater(function () {
                root.inspectTarget();
            });
        } else {
            root.resultStatus = qsTr("Saved policy reloaded");
        }
    }

    function addCurrentRule() {
        if (!root.canAddCurrentRule) {
            return;
        }

        var target = root.normalizedInput;
        try {
            root.ipSplitTunnelingUiController.addSite(target);
            root.ruleAddDispatched(target, root.currentRouteMode);
            root.resultStatus = qsTr("Rule update requested");
        } catch (error) {
            PageController.showErrorMessage(qsTr("Could not add the route rule"));
        }
    }

    SortFilterProxyModel {
        id: localExactModel

        sourceModel: IpSplitTunnelingModel
        filters: [
            AnyOf {
                RegExpFilter {
                    roleName: "url"
                    pattern: root.exactTargetPattern
                    caseSensitivity: Qt.CaseInsensitive
                }
                RegExpFilter {
                    roleName: "ip"
                    pattern: root.exactTargetPattern
                    caseSensitivity: Qt.CaseInsensitive
                }
            }
        ]
    }

    SortFilterProxyModel {
        id: managedExactModel

        sourceModel: ManagedExceptSitesModel
        filters: [
            AnyOf {
                RegExpFilter {
                    roleName: "url"
                    pattern: root.exactTargetPattern
                    caseSensitivity: Qt.CaseInsensitive
                }
                RegExpFilter {
                    roleName: "ip"
                    pattern: root.exactTargetPattern
                    caseSensitivity: Qt.CaseInsensitive
                }
            }
        ]
    }

    Connections {
        objectName: "routeInspectorRuntimeConnections"
        target: root.runtimeInspectorController
        ignoreUnknownSignals: true

        function onInspectionReady(result) {
            root.applyRuntimeInspectionResult(result);
        }

        function onRoutesExplainJsonReady(json) {
            root.storeRouteReport(json);
        }
    }

    Connections {
        objectName: "routeInspectorSplitTunnelingConnections"
        target: root.ipSplitTunnelingUiController
        ignoreUnknownSignals: true

        function onFinished(message) {
            PageController.showNotificationMessage(message);
            root.reloadSavedPolicyModels();
            if (root.inspectedTarget !== "") {
                Qt.callLater(function () {
                    root.inspectTarget();
                });
            }
        }

        function onErrorOccurred(errorMessage) {
            PageController.showErrorMessage(errorMessage);
        }

        function onRouteModeChanged() {
            if (root.inspectedTarget !== "") {
                root.inspectTarget();
            }
        }

        function onIsSplitTunnelingEnabledChanged() {
            if (root.inspectedTarget !== "") {
                root.inspectTarget();
            }
        }
    }

    Connections {
        objectName: "routeInspectorManagedSitesConnections"
        target: root.sitesController
        ignoreUnknownSignals: true

        function onManagedSplitTunnelingForceChanged() {
            root.managedForceEnabled = root.readManagedForceEnabled();
            if (root.inspectedTarget !== "") {
                root.inspectTarget();
            }
        }
    }

    BackButtonType {
        id: backButton

        objectName: "routeInspectorBackButton"
        anchors.top: parent.top
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.topMargin: 20 + PageController.safeAreaTopMargin

        onActiveFocusChanged: {
            if (backButton.enabled && backButton.activeFocus) {
                listView.positionViewAtBeginning();
            }
        }
    }

    ListViewType {
        id: listView

        objectName: "routeInspectorListView"
        anchors.top: backButton.bottom
        anchors.bottom: parent.bottom
        anchors.left: parent.left
        anchors.right: parent.right

        model: 1

        header: ColumnLayout {
            width: listView.width

            BaseHeaderType {
                Layout.fillWidth: true
                Layout.leftMargin: 16
                Layout.rightMargin: 16

                headerText: qsTr("Route Inspector")
                descriptionText: qsTr("Inspect a confirmed client route receipt when available, or preview saved split tunneling policy. The operating system route table is not queried.")
            }
        }

        delegate: ColumnLayout {
            width: listView.width
            spacing: 16

            TextFieldWithHeaderType {
                id: hostField

                objectName: "routeInspectorHostField"
                Accessible.role: Accessible.EditableText
                Accessible.name: qsTr("Website or IP address")
                Accessible.description: qsTr("Enter a target to inspect its saved routing policy")

                Layout.fillWidth: true
                Layout.topMargin: 16
                Layout.leftMargin: 16
                Layout.rightMargin: 16

                headerText: qsTr("Website or IP address")
                subtitleText: qsTr("For example: example.com or 203.0.113.10")
                checkEmptyText: true
                textField.objectName: "routeInspectorHostInput"
                textField.placeholderText: qsTr("example.com")
                textField.inputMethodHints: Qt.ImhUrlCharactersOnly | Qt.ImhNoAutoUppercase | Qt.ImhNoPredictiveText
                textField.onTextChanged: root.targetInput = textField.text
                textField.onAccepted: root.inspectTarget()

                Component.onCompleted: textField.text = root.targetInput

                Connections {
                    target: root

                    function onInputValidationFailed(message) {
                        hostField.errorText = message;
                    }
                }
            }

            BasicButtonType {
                id: inspectButton

                objectName: "routeInspectorInspectButton"
                Accessible.name: qsTr("Inspect route")
                Accessible.description: qsTr("Preview the current route policy for the entered target")

                Layout.fillWidth: true
                Layout.leftMargin: 16
                Layout.rightMargin: 16

                text: root.resultPending ? qsTr("Inspecting…") : qsTr("Inspect route")
                leftImageSource: "qrc:/images/controls/search.svg"
                enabled: !root.resultPending
                clickedFunc: root.inspectTarget
            }

            DividerType {
                Layout.fillWidth: true
            }

            Header2Type {
                Layout.fillWidth: true
                Layout.leftMargin: 16
                Layout.rightMargin: 16

                headerText: qsTr("Current context")
            }

            Rectangle {
                id: contextCard

                objectName: "routeInspectorContextCard"
                Accessible.role: Accessible.StaticText
                Accessible.name: qsTr("Mode: %1. Source: %2. Status: %3.").arg(root.resultModeOverride !== "" ? root.resultModeOverride : root.currentModeText()).arg(root.resultSource).arg(root.connectionStatusText())

                Layout.fillWidth: true
                Layout.leftMargin: 16
                Layout.rightMargin: 16
                implicitHeight: contextContent.implicitHeight + 32

                color: AmneziaStyle.color.onyxBlack
                radius: 16

                ColumnLayout {
                    id: contextContent

                    anchors.fill: parent
                    anchors.margins: 16
                    spacing: 12

                    LabelTextType {
                        text: qsTr("Mode")
                    }

                    ParagraphTextType {
                        id: modeValue

                        objectName: "routeInspectorModeValue"
                        Layout.fillWidth: true
                        text: root.resultModeOverride !== "" ? root.resultModeOverride : root.currentModeText()
                    }

                    DividerType {
                        Layout.fillWidth: true
                    }

                    LabelTextType {
                        text: qsTr("Source")
                    }

                    ParagraphTextType {
                        id: sourceValue

                        objectName: "routeInspectorSourceValue"
                        Layout.fillWidth: true
                        text: root.resultSource
                    }

                    DividerType {
                        Layout.fillWidth: true
                    }

                    LabelTextType {
                        text: qsTr("VPN status")
                    }

                    ParagraphTextType {
                        id: statusValue

                        objectName: "routeInspectorStatusValue"
                        Layout.fillWidth: true
                        text: root.connectionStatusText()
                    }
                }
            }

            Header2Type {
                Layout.fillWidth: true
                Layout.leftMargin: 16
                Layout.rightMargin: 16

                headerText: qsTr("Result")
            }

            Rectangle {
                id: resultCard

                objectName: "routeInspectorResultCard"
                Accessible.role: Accessible.StaticText
                Accessible.name: root.resultDecision + ". " + root.resultExplanation

                Layout.fillWidth: true
                Layout.leftMargin: 16
                Layout.rightMargin: 16
                implicitHeight: resultContent.implicitHeight + 32

                color: AmneziaStyle.color.translucentRichBrown
                border.color: AmneziaStyle.color.richBrown
                border.width: 1
                radius: 16

                ColumnLayout {
                    id: resultContent

                    anchors.fill: parent
                    anchors.margins: 16
                    spacing: 8

                    Header2TextType {
                        id: resultDecision

                        objectName: "routeInspectorDecisionValue"
                        Layout.fillWidth: true
                        text: root.resultDecision
                    }

                    LabelTextType {
                        id: resultState

                        objectName: "routeInspectorResultStatus"
                        Layout.fillWidth: true
                        text: root.resultStatus
                        color: AmneziaStyle.color.goldenApricot
                    }

                    ParagraphTextType {
                        id: resultExplanation

                        objectName: "routeInspectorExplanation"
                        Layout.fillWidth: true
                        text: root.resultExplanation
                        color: AmneziaStyle.color.paleGray
                    }
                }
            }

            BasicButtonType {
                id: copyReportButton

                objectName: "routeInspectorCopyReportButton"
                Accessible.name: qsTr("Copy route report")
                Accessible.description: qsTr("Copy the route diagnostic report as JSON")

                visible: root.routeReportJson !== ""
                Layout.fillWidth: true
                Layout.leftMargin: 16
                Layout.rightMargin: 16

                text: qsTr("Copy route report")
                leftImageSource: "qrc:/images/controls/copy.svg"
                defaultColor: AmneziaStyle.color.onyxBlack
                hoveredColor: AmneziaStyle.color.slateGray
                pressedColor: AmneziaStyle.color.charcoalGray
                textColor: AmneziaStyle.color.paleGray
                leftImageColor: AmneziaStyle.color.paleGray
                borderColor: AmneziaStyle.color.slateGray
                borderWidth: 1
                clickedFunc: root.copyRouteReport
            }

            BasicButtonType {
                id: refreshButton

                objectName: "routeInspectorRefreshButton"
                Accessible.name: qsTr("Reload saved route policy")
                Accessible.description: qsTr("Reload the route policy already stored on this device")

                visible: root.canReloadSavedPolicy
                Layout.fillWidth: true
                Layout.leftMargin: 16
                Layout.rightMargin: 16

                text: qsTr("Reload saved policy")
                leftImageSource: "qrc:/images/controls/refresh-cw.svg"
                defaultColor: AmneziaStyle.color.onyxBlack
                hoveredColor: AmneziaStyle.color.slateGray
                pressedColor: AmneziaStyle.color.charcoalGray
                textColor: AmneziaStyle.color.paleGray
                leftImageColor: AmneziaStyle.color.paleGray
                borderColor: AmneziaStyle.color.slateGray
                borderWidth: 1
                clickedFunc: root.reloadSavedPolicy
            }

            BasicButtonType {
                id: addRuleButton

                objectName: "routeInspectorAddRuleButton"
                Accessible.name: root.currentRouteMode === routeMode.onlyForwardSites ? qsTr("Route this target through VPN") : qsTr("Bypass VPN for this target")
                Accessible.description: qsTr("Add the inspected target to the current local split tunneling list")

                visible: root.canAddCurrentRule
                Layout.fillWidth: true
                Layout.leftMargin: 16
                Layout.rightMargin: 16

                text: root.currentRouteMode === routeMode.onlyForwardSites ? qsTr("Route this target through VPN") : qsTr("Bypass VPN for this target")
                leftImageSource: "qrc:/images/controls/plus.svg"
                clickedFunc: root.addCurrentRule
            }

            ParagraphTextType {
                objectName: "routeInspectorMutationHint"
                visible: root.inspectedTarget !== "" && root.connectionActive
                Layout.fillWidth: true
                Layout.leftMargin: 16
                Layout.rightMargin: 16
                text: qsTr("Disconnect the VPN before changing split tunneling rules.")
                color: AmneziaStyle.color.mutedGray
            }

            ParagraphTextType {
                objectName: "routeInspectorIpv6MutationHint"
                visible: root.inspectedTargetIsIpv6 && !root.connectionActive && root.splitTunnelingEnabled && root.currentRouteMode !== routeMode.allSites
                Layout.fillWidth: true
                Layout.leftMargin: 16
                Layout.rightMargin: 16
                text: qsTr("IPv6 targets can be inspected, but this client currently adds split-tunneling site rules for IPv4 only.")
                color: AmneziaStyle.color.mutedGray
            }

            Item {
                Layout.fillWidth: true
                Layout.preferredHeight: 24 + PageController.safeAreaBottomMargin
            }
        }
    }

    Component.onCompleted: {
        root.managedForceEnabled = root.readManagedForceEnabled();
        root.reloadSavedPolicyModels();
    }
}
