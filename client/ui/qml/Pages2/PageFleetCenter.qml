pragma ComponentBehavior: Bound

import QtQuick
import QtQuick.Layouts

import PageEnum 1.0
import Style 1.0

import "../Controls2"
import "../Config"

PageType {
    id: root

    // Diagnostics controllers are optional on platforms/builds where their
    // runtime dependencies are not available. Keep one exact context name per
    // controller so API drift is visible instead of being hidden by aliases.
    readonly property var connectionHealthController: {
        if (typeof ConnectionHealthController !== "undefined") {
            return ConnectionHealthController;
        }
        return null;
    }

    readonly property var remoteLogHealthController: {
        if (typeof RemoteLogHealthUiController !== "undefined") {
            return RemoteLogHealthUiController;
        }
        return null;
    }

    readonly property var updateController: {
        if (typeof UpdateController !== "undefined") {
            return UpdateController;
        }
        return null;
    }

    property int optionalDataRevision: 0
    property string doctorReportJson: ""
    property bool doctorReportTruncated: false
    property bool rollbackConfirmationArmed: false

    readonly property int maximumDoctorReportLength: 256 * 1024

    readonly property bool hasConfiguredServer: ServersUiController.defaultServerId !== ""
    readonly property bool internetAvailable: NetworkReachabilityController.hasInternetAccess
    readonly property bool canManageApiDevices: root.hasConfiguredServer && ServersUiController.isDefaultServerFromApi
    readonly property bool canManageSelfHostedClients: root.hasConfiguredServer && !ServersUiController.isDefaultServerFromApi && ServersUiController.isServerHasWriteAccess(ServersUiController.defaultServerId)

    readonly property string connectionHeadline: {
        if (ConnectionController.isConnectionInProgress) {
            return ConnectionController.connectionStateText;
        }
        return ConnectionController.isConnected ? qsTr("VPN connected") : qsTr("VPN disconnected");
    }

    readonly property string connectionDetails: {
        var details = [];
        if (root.hasConfiguredServer) {
            details.push(ServersUiController.defaultServerName);
        }
        var protocol = root.protocolDisplayName();
        if (protocol !== "") {
            details.push(protocol);
        }
        if (details.length === 0) {
            return qsTr("Choose a server to start protecting this device");
        }
        return details.join(" \u00b7 ");
    }

    readonly property string healthSummary: {
        var revision = root.optionalDataRevision;
        if (!root.connectionHealthController) {
            return ConnectionController.isConnected ? qsTr("Tunnel is up. End-to-end health checks are not available yet.") : qsTr("Connect to start monitoring tunnel health.");
        }
        var healthState = String(root.connectionHealthController.healthStateName || "");
        var reason = String(root.connectionHealthController.lastReason || "");
        if (healthState !== "") {
            var summary = root.displayToken(healthState);
            if (reason !== "" && reason !== "not_observed") {
                summary += " \u00b7 " + root.displayToken(reason);
            }
            return summary;
        }
        return qsTr("Health has not been observed yet");
    }

    readonly property string lastRecoveryReason: {
        var revision = root.optionalDataRevision;
        if (!root.connectionHealthController) {
            return qsTr("No recovery data");
        }
        var pendingAction = String(root.connectionHealthController.pendingRecoveryAction || "");
        if (pendingAction !== "" && pendingAction !== "none") {
            return qsTr("Suggested recovery: %1").arg(root.displayToken(pendingAction));
        }
        return qsTr("No recovery recommendation pending");
    }

    readonly property string lastRecoveryDetails: {
        var revision = root.optionalDataRevision;
        var events = root.connectionHealthController ? root.connectionHealthController.flightRecorder : [];
        if (events && typeof events.length !== "undefined" && events.length > 0) {
            var latestEvent = null;
            for (var index = events.length - 1; index >= 0; --index) {
                var candidate = events[index];
                if (candidate && String(candidate.category || "") === "recovery") {
                    latestEvent = candidate;
                    break;
                }
            }
            if (latestEvent === null) {
                return qsTr("No recovery recommendation has been recorded yet");
            }
            var category = String(latestEvent.category || qsTr("event"));
            var outcome = String(latestEvent.outcome || qsTr("observed"));
            var timestamp = latestEvent.timestamp || null;
            var summary = qsTr("Latest: %1 \u00b7 %2").arg(root.displayToken(category)).arg(root.displayToken(outcome));
            if (timestamp !== null) {
                var formattedTimestamp = root.formatDateTime(timestamp);
                if (formattedTimestamp !== "") {
                    summary += " \u00b7 " + formattedTimestamp;
                }
            }
            return summary;
        }
        return root.connectionHealthController ? qsTr("Guardian recovery events will appear here") : qsTr("Guardian timeline will appear when health monitoring is enabled");
    }

    readonly property string remoteLogStatus: {
        var revision = root.optionalDataRevision;
        if (Qt.platform.os === "android" && root.remoteLogHealthController && Number(root.remoteLogHealthController.state) === 100) {
            return qsTr("Android VPN service uploader status is not exposed here");
        }
        return root.remoteLogHealthController ? String(root.remoteLogHealthController.stateLabel) : qsTr("Waiting for uploader health data");
    }

    readonly property string remoteLogDetails: {
        var revision = root.optionalDataRevision;
        var details = [];
        var lastSuccess = root.remoteLogHealthController ? root.remoteLogHealthController.lastSuccess : null;
        if (lastSuccess !== null) {
            var formattedLastSuccess = root.formatDateTime(lastSuccess);
            if (formattedLastSuccess !== "") {
                details.push(qsTr("Last delivered: %1").arg(formattedLastSuccess));
            }
        }
        var pendingBytes = root.remoteLogHealthController ? Number(root.remoteLogHealthController.pendingBytes) : 0;
        if (pendingBytes > 0) {
            details.push(qsTr("Pending: %1").arg(root.formatByteCount(pendingBytes)));
        }
        var lastError = root.remoteLogHealthController ? String(root.remoteLogHealthController.lastErrorLabel || "") : "";
        if (lastError !== "") {
            details.push(lastError);
        }
        if (details.length > 0) {
            return details.join("\n");
        }
        if (Qt.platform.os === "android" && root.remoteLogHealthController && Number(root.remoteLogHealthController.state) === 100) {
            return qsTr("Diagnostics may still be uploaded by the Android VPN service; this page cannot confirm delivery or retry state.");
        }
        return root.remoteLogHealthController ? qsTr("No successful delivery reported yet") : qsTr("Open logging settings for local log controls");
    }

    readonly property bool remoteLogsHealthy: {
        var revision = root.optionalDataRevision;
        return root.remoteLogHealthController ? root.remoteLogHealthController.healthy : false;
    }

    readonly property bool canRetryRemoteLogs: root.remoteLogHealthController ? root.remoteLogHealthController.retryAvailable : false
    readonly property bool canRunDoctor: root.connectionHealthController !== null
    readonly property bool rollbackAvailable: root.updateController ? root.updateController.rollbackAvailable : false

    readonly property string updatePolicyHeadline: {
        var revision = root.optionalDataRevision;
        if (!root.updateController) {
            return qsTr("Safe update status unavailable");
        }

        var disposition = String(root.updateController.releasePolicyDisposition || "none");
        if (disposition === "paused") {
            return qsTr("Release rollout paused");
        }
        if (disposition === "expired") {
            return qsTr("Signed release policy expired");
        }
        if (disposition === "version_ineligible") {
            return qsTr("This app version is outside release eligibility");
        }
        if (disposition === "cohort_ineligible") {
            return qsTr("This device is outside the release cohort");
        }

        var channel = String(root.updateController.releaseChannel || "").trim();
        if (channel !== "") {
            return qsTr("Release channel: %1").arg(root.displayToken(channel));
        }

        var pendingReceipt = root.updateController.pendingHealthReceipt || {};
        channel = String(pendingReceipt.channel || "").trim();
        if (channel !== "") {
            return qsTr("Installed from channel: %1").arg(root.displayToken(channel));
        }

        var lastReceipt = root.updateController.lastHealthReceipt || {};
        channel = String(lastReceipt.channel || "").trim();
        if (channel !== "") {
            return qsTr("Last receipt channel: %1").arg(root.displayToken(channel));
        }
        return qsTr("No signed release channel recorded");
    }

    readonly property string updatePolicyDetails: {
        var revision = root.optionalDataRevision;
        if (!root.updateController) {
            return qsTr("This build does not expose fleet update policy data.");
        }

        var generation = Number(root.updateController.releasePolicyGeneration || 0);
        if (generation > 0) {
            return qsTr("Observed signed policy generation: %1").arg(generation);
        }

        var pendingReceipt = root.updateController.pendingHealthReceipt || {};
        generation = Number(pendingReceipt.policyGeneration || 0);
        if (generation > 0) {
            return qsTr("Installed policy generation: %1").arg(generation);
        }

        var lastReceipt = root.updateController.lastHealthReceipt || {};
        generation = Number(lastReceipt.policyGeneration || 0);
        if (generation > 0) {
            return qsTr("Last completed policy generation: %1").arg(generation);
        }
        return qsTr("No rollout policy generation recorded");
    }

    readonly property string updateHealthHeadline: {
        var revision = root.optionalDataRevision;
        if (!root.updateController) {
            return qsTr("Update startup status unavailable");
        }
        var pendingReceipt = root.updateController.pendingHealthReceipt || {};
        if (String(pendingReceipt.rollbackRequestedAt || "") !== "") {
            return qsTr("Rollback installer handed off");
        }
        if (root.updateController.rollbackAvailable) {
            return qsTr("Update startup check failed; rollback available");
        }
        if (String(pendingReceipt.healthState || "") === "failed") {
            return qsTr("Update startup check failed");
        }
        if (root.updateController.healthConfirmationPending) {
            return qsTr("Update startup confirmation pending");
        }

        var lastReceipt = root.updateController.lastHealthReceipt || {};
        var status = String(lastReceipt.status || "");
        if (status === "healthy") {
            return qsTr("Last update passed startup readiness");
        }
        if (status === "rolled_back") {
            return qsTr("Last update rolled back");
        }
        if (status === "failed") {
            return qsTr("Last update startup check failed");
        }
        return qsTr("No update startup result recorded");
    }

    readonly property string updateHealthDetails: {
        var revision = root.optionalDataRevision;
        if (!root.updateController) {
            return qsTr("Startup receipts and rollback actions are not available.");
        }

        var pendingReceipt = root.updateController.pendingHealthReceipt || {};
        var targetVersion = String(pendingReceipt.targetVersion || "");
        var deadline = root.formatDateTime(pendingReceipt.deadlineAt || null);
        var rollbackRequestedAt = root.formatDateTime(pendingReceipt.rollbackRequestedAt || null);
        if (String(pendingReceipt.rollbackRequestedAt || "") !== "") {
            var requestedRollbackVersion = String(pendingReceipt.rollbackVersion || "");
            if (requestedRollbackVersion !== "" && rollbackRequestedAt !== "") {
                return qsTr("Rollback %1 was handed to the platform installer at %2.").arg(requestedRollbackVersion).arg(rollbackRequestedAt);
            }
            return requestedRollbackVersion !== "" ? qsTr("Rollback %1 was handed to the platform installer.").arg(requestedRollbackVersion) : qsTr("The rollback was handed to the platform installer.");
        }
        if (root.updateController.rollbackAvailable) {
            var rollbackMetadata = root.updateController.rollbackActionMetadata || {};
            var rollbackVersion = String(rollbackMetadata.rollbackVersion || "");
            if (String(pendingReceipt.rollbackLastErrorAt || "") !== "") {
                return rollbackVersion !== "" ? qsTr("The previous rollback start failed. Rollback %1 can be retried.").arg(rollbackVersion) : qsTr("The previous rollback start failed and can be retried.");
            }
            if (targetVersion !== "" && rollbackVersion !== "") {
                return qsTr("Version %1 failed its startup gate. Rollback %2 is available.").arg(targetVersion).arg(rollbackVersion);
            }
            return qsTr("The startup gate failed and a rollback action is ready.");
        }
        if (String(pendingReceipt.healthState || "") === "failed") {
            var unavailableAction = root.updateController.rollbackActionMetadata || {};
            var unavailableReason = String(unavailableAction.reason || "");
            if (unavailableReason === "installer_busy") {
                return qsTr("The startup gate failed; rollback is temporarily unavailable while the installer is busy.");
            }
            if (unavailableReason === "already_running_rollback_version") {
                return qsTr("The rollback version is already running; waiting for its startup receipt.");
            }
            if (unavailableReason === "no_verified_rollback_artifact") {
                return targetVersion !== "" ? qsTr("Version %1 failed its startup gate; no eligible rollback artifact is available.").arg(targetVersion) : qsTr("The startup gate failed; no eligible rollback artifact is available.");
            }
            return targetVersion !== "" ? qsTr("Version %1 failed its startup gate; rollback is not currently actionable.").arg(targetVersion) : qsTr("The startup gate failed; rollback is not currently actionable.");
        }
        if (root.updateController.healthConfirmationPending) {
            if (targetVersion !== "" && deadline !== "") {
                return qsTr("Waiting for version %1 until %2.").arg(targetVersion).arg(deadline);
            }
            if (targetVersion !== "") {
                return qsTr("Waiting for version %1 to confirm startup readiness.").arg(targetVersion);
            }
            return qsTr("Waiting for the installed version to confirm startup readiness.");
        }

        var lastReceipt = root.updateController.lastHealthReceipt || {};
        var details = [];
        targetVersion = String(lastReceipt.targetVersion || "");
        if (targetVersion !== "") {
            details.push(qsTr("Version %1").arg(targetVersion));
        }
        var observedAt = root.formatDateTime(lastReceipt.observedAt || null);
        if (observedAt !== "") {
            details.push(observedAt);
        }
        var reason = String(lastReceipt.reason || "");
        if (reason !== "") {
            details.push(root.displayToken(reason));
        }
        return details.length > 0 ? details.join(" \u00b7 ") : qsTr("No startup receipt has been recorded yet.");
    }

    readonly property string rollbackActionText: {
        var revision = root.optionalDataRevision;
        if (!root.updateController || !root.updateController.rollbackAvailable) {
            return qsTr("Review rollback");
        }
        var metadata = root.updateController.rollbackActionMetadata || {};
        var rollbackVersion = String(metadata.rollbackVersion || "");
        return rollbackVersion !== "" ? qsTr("Review rollback to %1").arg(rollbackVersion) : qsTr("Review rollback");
    }

    function displayToken(value) {
        var normalized = String(value || "").replace(/_/g, " ").trim();
        if (normalized === "") {
            return "";
        }
        return normalized.charAt(0).toUpperCase() + normalized.slice(1);
    }

    function formatByteCount(value) {
        var bytes = Math.max(0, Number(value) || 0);
        if (bytes < 1024) {
            return qsTr("%1 B").arg(Math.round(bytes));
        }
        if (bytes < 1024 * 1024) {
            return qsTr("%1 KiB").arg((bytes / 1024).toFixed(1));
        }
        return qsTr("%1 MiB").arg((bytes / (1024 * 1024)).toFixed(1));
    }

    function rollbackConfirmationDescription() {
        if (!root.updateController) {
            return "";
        }
        var metadata = root.updateController.rollbackActionMetadata || {};
        var action = String(metadata.action || "");
        if (action === "open_external_artifact") {
            return qsTr("Amnezia will open the approved rollback source outside the app. Check the destination, then complete the platform installer manually.");
        }
        return qsTr("Amnezia will download the rollback package, verify its checksum, and launch the platform installer. The app may close during installation.");
    }

    function requestPendingRollback() {
        if (!root.updateController || !root.updateController.rollbackAvailable) {
            PageController.showErrorMessage(qsTr("Rollback is no longer available"));
            return;
        }

        var metadata = root.updateController.rollbackActionMetadata || {};
        var rollbackVersion = String(metadata.rollbackVersion || "");
        var header = rollbackVersion !== "" ? qsTr("Roll back to version %1?").arg(rollbackVersion) : qsTr("Start rollback?");
        showQuestionDrawer(header, root.rollbackConfirmationDescription(), qsTr("Start rollback"), qsTr("Cancel"), function () {
            root.rollbackConfirmationArmed = true;
            root.executeConfirmedRollback();
        }, function () {
            root.rollbackConfirmationArmed = false;
        });
    }

    function executeConfirmedRollback() {
        if (!root.rollbackConfirmationArmed) {
            return;
        }
        root.rollbackConfirmationArmed = false;

        if (!root.updateController || !root.updateController.rollbackAvailable) {
            PageController.showErrorMessage(qsTr("Rollback is no longer available"));
            return;
        }

        try {
            if (root.updateController.runPendingRollback()) {
                PageController.showNotificationMessage(qsTr("Rollback action started"));
            } else {
                PageController.showErrorMessage(qsTr("Could not start rollback"));
            }
        } catch (error) {
            PageController.showErrorMessage(qsTr("Could not start rollback"));
        }
    }

    function openDoctorReport() {
        if (!root.canRunDoctor) {
            PageController.showNotificationMessage(qsTr("Connection doctor is not available"));
            return;
        }

        try {
            var report = String(root.connectionHealthController.doctorJson(true) || "{}");
            try {
                report = JSON.stringify(JSON.parse(report), null, 2);
            } catch (parseError) {
                // The backend already returns JSON. If a future backend returns text,
                // show it as inert text instead of trying to evaluate it.
            }

            root.doctorReportTruncated = report.length > root.maximumDoctorReportLength;
            root.doctorReportJson = root.doctorReportTruncated ? report.slice(0, root.maximumDoctorReportLength) + "\n\n" + qsTr("Report truncated for display") : report;
            doctorReportDrawer.openTriggered();
        } catch (error) {
            root.doctorReportJson = "";
            root.doctorReportTruncated = false;
            PageController.showErrorMessage(qsTr("Unable to read the connection doctor report"));
        }
    }

    function copyDoctorReport() {
        if (root.doctorReportJson === "") {
            return;
        }
        GC.copyToClipBoard(root.doctorReportJson);
        PageController.showNotificationMessage(qsTr("Doctor report copied"));
    }

    function formatDateTime(value) {
        if (value === null || typeof value === "undefined" || String(value) === "") {
            return "";
        }
        try {
            var parsed = value instanceof Date ? value : new Date(value);
            if (!isNaN(parsed.getTime())) {
                return Qt.formatDateTime(parsed, "yyyy-MM-dd HH:mm");
            }
        } catch (error) {}
        return "";
    }

    function protocolDisplayName() {
        var protocol = ServersUiController.isDefaultServerFromApi ? ServersUiController.defaultServerServiceProtocol : ServersUiController.defaultServerDefaultContainerName;
        switch (String(protocol).toLowerCase()) {
        case "awg":
            return "AmneziaWG";
        case "vless":
            return "VLESS";
        case "wireguard":
            return "WireGuard";
        case "openvpn":
            return "OpenVPN";
        default:
            return protocol || "";
        }
    }

    function openClientManagement() {
        ServersUiController.setProcessedServerId(ServersUiController.defaultServerId);
        if (root.canManageApiDevices) {
            SubscriptionUiController.updateApiDevicesModel();
            PageController.goToPage(PageEnum.PageSettingsApiDevices);
            return;
        }
        if (root.canManageSelfHostedClients) {
            PageController.goToPage(PageEnum.PageShare);
        }
    }

    Connections {
        target: root.connectionHealthController
        ignoreUnknownSignals: true

        function onHealthSnapshotChanged() {
            root.optionalDataRevision += 1;
        }
        function onFlightRecorderChanged() {
            root.optionalDataRevision += 1;
        }
        function onRecoveryPolicyChanged() {
            root.optionalDataRevision += 1;
        }
    }

    Connections {
        target: root.remoteLogHealthController
        ignoreUnknownSignals: true

        function onStateChanged() {
            root.optionalDataRevision += 1;
        }
        function onLastSuccessChanged() {
            root.optionalDataRevision += 1;
        }
        function onPendingBytesChanged() {
            root.optionalDataRevision += 1;
        }
        function onLastErrorCategoryChanged() {
            root.optionalDataRevision += 1;
        }
        function onNextRetryAtChanged() {
            root.optionalDataRevision += 1;
        }
    }

    Connections {
        target: root.updateController
        ignoreUnknownSignals: true

        function onReleasePolicyChanged() {
            root.optionalDataRevision += 1;
        }
        function onUpdateHealthReceiptChanged() {
            root.optionalDataRevision += 1;
        }
        function onRollbackAvailabilityChanged() {
            root.optionalDataRevision += 1;
            if (!root.rollbackAvailable) {
                root.rollbackConfirmationArmed = false;
            }
        }
    }

    ListViewType {
        id: listView
        objectName: "fleetCenterListView"

        anchors.fill: parent
        anchors.bottomMargin: PageController.safeAreaBottomMargin

        // Keep one zero-height delegate so the ListView creates and scrolls its header.
        model: 1

        delegate: Item {
            width: listView.width
            height: 0
        }

        header: ColumnLayout {
            width: listView.width
            spacing: 0

            BackButtonType {
                objectName: "fleetCenterBackButton"

                Layout.fillWidth: true
                Layout.topMargin: 20 + PageController.safeAreaTopMargin

                onFocusChanged: {
                    if (activeFocus) {
                        listView.positionViewAtBeginning();
                    }
                }
            }

            BaseHeaderType {
                Layout.fillWidth: true
                Layout.leftMargin: 16
                Layout.rightMargin: 16
                Layout.bottomMargin: 16

                headerText: qsTr("Fleet Center")
                descriptionText: qsTr("Connection cockpit, recovery history and current-device operations in one place.")
            }

            WarningType {
                objectName: "connectionStatusCard"

                Layout.fillWidth: true
                Layout.leftMargin: 16
                Layout.rightMargin: 16
                Layout.bottomMargin: 16

                backGroundColor: ConnectionController.isConnected ? AmneziaStyle.color.translucentRichBrown : AmneziaStyle.color.onyxBlack
                imageColor: ConnectionController.isConnected ? AmneziaStyle.color.goldenApricot : AmneziaStyle.color.mutedGray
                iconPath: ConnectionController.isConnected ? "qrc:/images/controls/check.svg" : "qrc:/images/controls/radio.svg"
                textString: root.connectionHeadline + "\n" + root.connectionDetails
                textFormat: Text.PlainText

                Accessible.role: Accessible.StaticText
                Accessible.name: root.connectionHeadline + ". " + root.connectionDetails
            }

            LabelWithImageType {
                Layout.fillWidth: true
                Layout.leftMargin: 16
                Layout.rightMargin: 16
                Layout.bottomMargin: 16

                imageSource: "qrc:/images/controls/globe-2.svg"
                leftText: qsTr("System connectivity hint")
                rightText: root.internetAvailable ? qsTr("Reachable") : qsTr("Not reported")
            }

            BasicButtonType {
                objectName: "fleetCenterConnectionButton"

                Layout.fillWidth: true
                Layout.leftMargin: 16
                Layout.rightMargin: 16
                Layout.bottomMargin: 24

                enabled: root.hasConfiguredServer && !ConnectionController.isPreparing
                text: ConnectionController.isPreparing ? qsTr("Preparing...") : (ConnectionController.isConnected || ConnectionController.isConnectionInProgress ? qsTr("Disconnect") : qsTr("Connect"))
                leftImageSource: "qrc:/images/controls/radio.svg"
                defaultColor: ConnectionController.isConnected ? AmneziaStyle.color.goldenApricot : AmneziaStyle.color.paleGray

                clickedFunc: function () {
                    ConnectionController.connectButtonClicked();
                }
            }

            DividerType {}

            Header2Type {
                Layout.fillWidth: true
                Layout.leftMargin: 16
                Layout.rightMargin: 16
                Layout.topMargin: 24
                Layout.bottomMargin: 8

                headerText: qsTr("Safe fleet updates")
                descriptionText: qsTr("Signed rollout policy, post-install startup receipts, and guarded rollback.")
            }

            LabelWithButtonType {
                objectName: "safeUpdatePolicySummary"

                Layout.fillWidth: true

                text: root.updatePolicyHeadline
                descriptionText: root.updatePolicyDetails
                leftImageSource: "qrc:/images/controls/download.svg"
                isLeftImageHoverEnabled: false
                isFocusable: false
                clickedFunction: null

                Accessible.role: Accessible.StaticText
                Accessible.name: text + ". " + descriptionText
            }

            DividerType {}

            LabelWithButtonType {
                objectName: "safeUpdateHealthSummary"

                Layout.fillWidth: true

                text: root.updateHealthHeadline
                descriptionText: root.updateHealthDetails
                leftImageSource: root.rollbackAvailable ? "qrc:/images/controls/alert-circle.svg" : "qrc:/images/controls/history.svg"
                leftImageColor: root.rollbackAvailable ? AmneziaStyle.color.vibrantRed : AmneziaStyle.color.mutedGray
                isLeftImageHoverEnabled: false
                isFocusable: false
                clickedFunction: null

                Accessible.role: Accessible.StaticText
                Accessible.name: text + ". " + descriptionText
            }

            BasicButtonType {
                objectName: "safeUpdateRollbackButton"

                visible: root.rollbackAvailable
                Layout.fillWidth: true
                Layout.leftMargin: 16
                Layout.rightMargin: 16
                Layout.topMargin: 8
                Layout.bottomMargin: 24

                text: root.rollbackActionText
                leftImageSource: "qrc:/images/controls/refresh-cw.svg"
                defaultColor: AmneziaStyle.color.vibrantRed

                clickedFunc: function () {
                    root.requestPendingRollback();
                }
            }

            DividerType {}

            Header2Type {
                Layout.fillWidth: true
                Layout.leftMargin: 16
                Layout.rightMargin: 16
                Layout.topMargin: 24
                Layout.bottomMargin: 8

                headerText: qsTr("Guardian")
                descriptionText: qsTr("Tunnel state, bounded origin reachability checks, and recovery recommendations.")
            }

            LabelWithButtonType {
                objectName: "guardianHealthSummary"

                Layout.fillWidth: true

                text: qsTr("Connection health")
                descriptionText: root.healthSummary
                leftImageSource: "qrc:/images/controls/gauge.svg"
                isLeftImageHoverEnabled: false
                isFocusable: false
                clickedFunction: null

                Accessible.role: Accessible.StaticText
                Accessible.name: text + ". " + descriptionText
            }

            DividerType {}

            LabelWithButtonType {
                objectName: "guardianRecoveryTimeline"

                Layout.fillWidth: true

                text: root.lastRecoveryReason
                descriptionText: root.lastRecoveryDetails
                leftImageSource: "qrc:/images/controls/history.svg"
                isLeftImageHoverEnabled: false
                isFocusable: false
                clickedFunction: null

                Accessible.role: Accessible.StaticText
                Accessible.name: text + ". " + descriptionText
            }

            BasicButtonType {
                objectName: "runConnectionDoctorButton"

                visible: root.canRunDoctor
                Layout.fillWidth: true
                Layout.leftMargin: 16
                Layout.rightMargin: 16
                Layout.topMargin: 8
                Layout.bottomMargin: 24

                text: qsTr("Open connection doctor")
                leftImageSource: "qrc:/images/controls/gauge.svg"

                clickedFunc: function () {
                    root.openDoctorReport();
                }
            }

            DividerType {}

            Header2Type {
                Layout.fillWidth: true
                Layout.leftMargin: 16
                Layout.rightMargin: 16
                Layout.topMargin: 24
                Layout.bottomMargin: 8

                headerText: qsTr("This device")
                descriptionText: qsTr("Remote diagnostics delivery and the saved managed-route policy for this device.")
            }

            LabelWithButtonType {
                objectName: "remoteLogHealthSummary"

                Layout.fillWidth: true

                text: root.remoteLogStatus
                descriptionText: root.remoteLogDetails
                leftImageSource: root.remoteLogsHealthy ? "qrc:/images/controls/file-check-2.svg" : "qrc:/images/controls/file-cog-2.svg"
                leftImageColor: root.remoteLogsHealthy ? AmneziaStyle.color.goldenApricot : AmneziaStyle.color.mutedGray
                isLeftImageHoverEnabled: false
                rightImageSource: "qrc:/images/controls/chevron-right.svg"

                clickedFunction: function () {
                    PageController.goToPage(PageEnum.PageSettingsLogging);
                }

                Accessible.role: Accessible.Button
                Accessible.name: text + ". " + descriptionText
                Accessible.onPressAction: clickedFunction()
            }

            BasicButtonType {
                objectName: "retryRemoteLogsButton"

                visible: root.canRetryRemoteLogs
                Layout.fillWidth: true
                Layout.leftMargin: 16
                Layout.rightMargin: 16
                Layout.topMargin: 8
                Layout.bottomMargin: 16

                text: qsTr("Retry diagnostics delivery")
                leftImageSource: "qrc:/images/controls/refresh-cw.svg"
                defaultColor: AmneziaStyle.color.transparent
                hoveredColor: AmneziaStyle.color.translucentWhite
                pressedColor: AmneziaStyle.color.sheerWhite
                textColor: AmneziaStyle.color.paleGray
                borderWidth: 1

                clickedFunc: function () {
                    if (root.remoteLogHealthController) {
                        root.remoteLogHealthController.retryNow();
                        PageController.showNotificationMessage(qsTr("Diagnostics delivery retry requested"));
                    }
                }
            }

            DividerType {}

            LabelWithButtonType {
                objectName: "managedPolicySummary"

                Layout.fillWidth: true

                text: qsTr("Route policy")
                descriptionText: qsTr("Inspect and edit local and server-managed split tunneling rules")
                leftImageSource: "qrc:/images/controls/split-tunneling.svg"
                isLeftImageHoverEnabled: false
                rightImageSource: "qrc:/images/controls/chevron-right.svg"

                clickedFunction: function () {
                    PageController.goToPage(PageEnum.PageSettingsSplitTunneling);
                }

                Accessible.role: Accessible.Button
                Accessible.name: text + ". " + descriptionText
                Accessible.onPressAction: clickedFunction()
            }

            DividerType {}

            Header2Type {
                Layout.fillWidth: true
                Layout.leftMargin: 16
                Layout.rightMargin: 16
                Layout.topMargin: 24
                Layout.bottomMargin: 8

                headerText: qsTr("Clients")
                descriptionText: qsTr("Manage devices using the selected server.")
            }

            LabelWithButtonType {
                objectName: "fleetClientManagementButton"

                visible: root.canManageApiDevices || root.canManageSelfHostedClients
                Layout.fillWidth: true

                text: root.canManageApiDevices ? qsTr("Active devices") : qsTr("Manage VPN clients")
                descriptionText: root.canManageApiDevices ? qsTr("Review devices connected to this subscription") : qsTr("Create, revoke and inspect client access")
                leftImageSource: "qrc:/images/controls/monitor.svg"
                rightImageSource: "qrc:/images/controls/chevron-right.svg"

                clickedFunction: function () {
                    root.openClientManagement();
                }

                Accessible.role: Accessible.Button
                Accessible.name: text + ". " + descriptionText
                Accessible.onPressAction: clickedFunction()
            }

            WarningType {
                visible: !root.canManageApiDevices && !root.canManageSelfHostedClients

                Layout.fillWidth: true
                Layout.leftMargin: 16
                Layout.rightMargin: 16
                Layout.topMargin: 8
                Layout.bottomMargin: 24

                iconPath: "qrc:/images/controls/info.svg"
                imageColor: AmneziaStyle.color.mutedGray
                textString: root.hasConfiguredServer ? qsTr("Client management requires server administrator access.") : qsTr("Choose a server to manage its clients.")

                Accessible.role: Accessible.StaticText
                Accessible.name: textString
            }

            Item {
                Layout.preferredHeight: 16
            }
        }
    }

    DrawerType2 {
        id: doctorReportDrawer
        objectName: "doctorReportDrawer"

        parent: root
        anchors.fill: parent
        expandedHeight: Math.min(root.height, Math.max(320, root.height * 0.86))

        expandedStateContent: Item {
            implicitHeight: doctorReportDrawer.expandedHeight

            ColumnLayout {
                anchors.fill: parent
                spacing: 0

                BackButtonType {
                    Layout.fillWidth: true
                    Layout.topMargin: 16

                    backButtonFunction: function () {
                        doctorReportDrawer.closeTriggered();
                    }
                }

                Header2Type {
                    Layout.fillWidth: true
                    Layout.leftMargin: 16
                    Layout.rightMargin: 16
                    Layout.topMargin: 8
                    Layout.bottomMargin: 16

                    headerText: qsTr("Connection doctor")
                    descriptionText: qsTr("Privacy-safe diagnostic snapshot from this device.")
                }

                WarningType {
                    visible: root.doctorReportTruncated

                    Layout.fillWidth: true
                    Layout.leftMargin: 16
                    Layout.rightMargin: 16
                    Layout.bottomMargin: 12

                    iconPath: "qrc:/images/controls/alert-circle.svg"
                    textString: qsTr("The report was too large and has been truncated for display and copying.")
                }

                TextAreaType {
                    objectName: "doctorReportTextArea"

                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    Layout.minimumHeight: 160
                    Layout.leftMargin: 16
                    Layout.rightMargin: 16

                    text: root.doctorReportJson
                    textArea.readOnly: true
                    textArea.selectByMouse: true
                    textArea.wrapMode: Text.WrapAnywhere

                    Accessible.role: Accessible.StaticText
                    Accessible.name: qsTr("Connection doctor report")
                }

                BasicButtonType {
                    objectName: "copyDoctorReportButton"

                    Layout.fillWidth: true
                    Layout.leftMargin: 16
                    Layout.rightMargin: 16
                    Layout.topMargin: 16
                    Layout.bottomMargin: 16 + PageController.safeAreaBottomMargin

                    enabled: root.doctorReportJson !== ""
                    text: qsTr("Copy report")
                    leftImageSource: "qrc:/images/controls/copy.svg"

                    clickedFunc: function () {
                        root.copyDoctorReport();
                    }
                }
            }
        }
    }
}
