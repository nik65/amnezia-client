import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Dialogs

import QtCore

import SortFilterProxyModel 0.2

import PageEnum 1.0
import ContainerProps 1.0
import Style 1.0

import "./"
import "../Controls2"
import "../Controls2/TextTypes"
import "../Config"
import "../Components"

PageType {
    id: root

    property var isServerFromTelegramApi: ServersUiController.isServerFromApi(ServersUiController.defaultServerId)

    property bool pageEnabled
    property bool defaultManagedSplitTunnelingForceEnabled: false

    readonly property var routeModes: [
        { type: 1, segmentName: qsTr("Via VPN"), name: qsTr("Only the sites listed here will be accessed through the VPN") },
        { type: 2, segmentName: qsTr("Directly"), name: qsTr("Addresses from the list should not be accessed via VPN") }
    ]

    readonly property int routeModeIndex: IpSplitTunnelingController.routeMode === 2 ? 1 : 0

    function reloadDefaultManagedRules() {
        SitesController.reloadDefaultManagedSites()
        root.defaultManagedSplitTunnelingForceEnabled = SitesController.isDefaultManagedSplitTunnelingForceEnabled()
    }

    function isManagedExceptListVisible() {
        if (proxyManagedExceptSitesModel.count === 0) {
            return false
        }
        if (!IpSplitTunnelingController.isSplitTunnelingEnabled) {
            return root.defaultManagedSplitTunnelingForceEnabled
        }
        return root.routeModeIndex === 1
    }

    Component.onCompleted: {
        root.reloadDefaultManagedRules()
        if (ConnectionController.isConnected) {
            PageController.showNotificationMessage(qsTr("Cannot change split tunneling settings during active connection"))
            root.pageEnabled = false
        } else if (ServersUiController.isDefaultServerDefaultContainerHasSplitTunneling) {
            PageController.showNotificationMessage(qsTr("Default server does not support split tunneling function"))
            root.pageEnabled = false
        } else {
            root.pageEnabled = true
        }
    }

    Connections {
        target: ServersUiController

        function onDefaultServerIdChanged() {
            root.reloadDefaultManagedRules()
        }
    }

    Connections {
        target: ConnectionController

        function onServerRoutingRulesChanged(serverIndex) {
            // The ID-based UI exposes no default index. Reload only the current
            // default through SitesController, regardless of the event's index.
            root.reloadDefaultManagedRules()
        }
    }

    Connections {
        target: SitesController

        function onManagedSplitTunnelingForceChanged() {
            root.defaultManagedSplitTunnelingForceEnabled = SitesController.isDefaultManagedSplitTunnelingForceEnabled()
        }
    }

    Connections {
        target: IpSplitTunnelingController

        function onFinished(message) {
            PageController.showNotificationMessage(message)
        }

        function onErrorOccurred(errorMessage) {
            PageController.showErrorMessage(errorMessage)
        }
    }

    ListViewType {
        id: listView

        anchors.top: parent.top
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.bottom: addSitePanel.top

        SortFilterProxyModel {
            id: proxyManagedExceptSitesModel
            sourceModel: ManagedExceptSitesModel
            filters: [
                AnyOf {
                    RegExpFilter {
                        roleName: "url"
                        pattern: ".*" + addSitePanel.textField.text + ".*"
                        caseSensitivity: Qt.CaseInsensitive
                    }
                    RegExpFilter {
                        roleName: "ip"
                        pattern: ".*" + addSitePanel.textField.text + ".*"
                        caseSensitivity: Qt.CaseInsensitive
                    }
                }
            ]
        }

        SortFilterProxyModel {
            id: proxyIpSplitTunnelingModel
            sourceModel: IpSplitTunnelingModel
            filters: [
                AnyOf {
                    RegExpFilter {
                        roleName: "url"
                        pattern: ".*" + addSitePanel.textField.text + ".*"
                        caseSensitivity: Qt.CaseInsensitive
                    }
                    RegExpFilter {
                        roleName: "ip"
                        pattern: ".*" + addSitePanel.textField.text + ".*"
                        caseSensitivity: Qt.CaseInsensitive
                    }
                }
            ]
        }

        model: (root.isManagedExceptListVisible() ? proxyManagedExceptSitesModel.count : 0)
               + proxyIpSplitTunnelingModel.count

        header: ColumnLayout {
            width: listView.width

            z: 2

            spacing: 0

            onHeightChanged: {
                if (!listView.moving) {
                    Qt.callLater(listView.positionViewAtBeginning)
                }
            }

            NavigationBarType {
                id: navigationBar

                Layout.fillWidth: true

                title: qsTr("Split tunneling")
            }

            ListItemType {
                Layout.fillWidth: true
                Layout.leftMargin: 16
                Layout.rightMargin: 16

                enabled: root.pageEnabled

                text: qsTr("Split tunneling")

                onClicked: {
                    splitTunnelingSwitch.toggle()
                    splitTunnelingSwitch.toggled()
                }

                SwitchType {
                    id: splitTunnelingSwitch

                    focusPolicy: Qt.NoFocus

                    checked: IpSplitTunnelingController.isSplitTunnelingEnabled

                    onToggled: IpSplitTunnelingController.toggleSplitTunneling(checked)
                }
            }

            SegmentedControlType {
                id: modeSelector

                Layout.fillWidth: true
                Layout.topMargin: 24
                Layout.leftMargin: 16
                Layout.rightMargin: 16

                enabled: root.pageEnabled

                model: root.routeModes.map(function(mode) { return mode.segmentName })
                currentIndex: root.routeModeIndex

                onActivated: function(index) {
                    if (IpSplitTunnelingController.routeMode !== root.routeModes[index].type) {
                        IpSplitTunnelingController.routeMode = root.routeModes[index].type
                    }
                }

                Connections {
                    target: IpSplitTunnelingController

                    function onRouteModeChanged() {
                        modeSelector.currentIndex = root.routeModeIndex
                    }
                }
            }

            BodyTextType {
                Layout.fillWidth: true
                Layout.topMargin: 8
                Layout.leftMargin: 16
                Layout.rightMargin: 16
                Layout.bottomMargin: 24

                text: root.routeModes[modeSelector.currentIndex].name
                color: AmneziaStyle.color.textSecondary
            }

            Header2Type {
                Layout.fillWidth: true
                Layout.leftMargin: 16
                Layout.rightMargin: 16
                Layout.topMargin: 8
                Layout.bottomMargin: 4

                visible: root.isManagedExceptListVisible()

                headerText: qsTr("Managed by server")
            }

            Label {
                Layout.fillWidth: true
                Layout.leftMargin: 16
                Layout.rightMargin: 16
                Layout.bottomMargin: 8

                visible: root.isManagedExceptListVisible()

                wrapMode: Text.WordWrap
                color: AmneziaStyle.color.textSecondary
                text: qsTr("Server-managed rules are locked. They are used only when this server is active and the current split tunneling mode applies this list.")
            }
        }

        delegate: Loader {
            id: rowLoader

            enabled: root.pageEnabled

            width: listView.width
            height: item ? item.implicitHeight : 0

            readonly property bool managedListVisible: root.isManagedExceptListVisible()
            readonly property int managedRows: managedListVisible ? proxyManagedExceptSitesModel.count : 0
            readonly property int managedModelIndex: index
            readonly property int localModelIndex: index - managedRows

            sourceComponent: managedListVisible && index < managedRows
                             ? managedRuleDelegate
                             : localRuleDelegate

            function syncItemIndexes() {
                if (!item) {
                    return
                }

                item.managedModelIndex = managedModelIndex
                item.localModelIndex = localModelIndex
            }

            onLoaded: syncItemIndexes()
            onManagedModelIndexChanged: syncItemIndexes()
            onLocalModelIndexChanged: syncItemIndexes()
        }

        Component {
            id: managedRuleDelegate

            ListItemType {
                width: listView.width

                property int managedModelIndex: -1
                property int localModelIndex: -1

                readonly property var managedRule: managedModelIndex >= 0 && managedModelIndex < proxyManagedExceptSitesModel.count
                                                   ? proxyManagedExceptSitesModel.get(managedModelIndex)
                                                   : null

                enabled: false
                interactive: false

                text: managedRule ? (managedRule.url || "") : ""
                subtitle: managedRule ? (managedRule.ip || "") : ""
            }
        }

        Component {
            id: localRuleDelegate

            ListItemType {
                id: site

                width: listView.width

                property int managedModelIndex: -1
                property int localModelIndex: -1

                readonly property var localRule: localModelIndex >= 0 && localModelIndex < proxyIpSplitTunnelingModel.count
                                                 ? proxyIpSplitTunnelingModel.get(localModelIndex)
                                                 : null

                text: localRule ? (localRule.url || "") : ""
                subtitle: localRule ? (localRule.ip || "") : ""
                trailingIconSource: "qrc:/images/controls/trash.svg"

                onClicked: {
                    var headerText = qsTr("Remove ") + (localRule ? (localRule.url || "") : "") + "?"
                    var yesButtonText = qsTr("Continue")
                    var noButtonText = qsTr("Cancel")

                    var yesButtonFunction = function() {
                        IpSplitTunnelingController.removeSite(proxyIpSplitTunnelingModel.mapToSource(localModelIndex))
                    }
                    var noButtonFunction = function() {}

                    Dialogs.askQuestion(headerText, "", yesButtonText, noButtonText, yesButtonFunction, noButtonFunction)
                }
            }
        }
    }

    AddSitePanel {
        id: addSitePanel

        anchors.left: parent.left
        anchors.right: parent.right
        anchors.bottom: parent.bottom
        anchors.bottomMargin: addSitePanel.textField.activeFocus ? 0 : PageController.imeHeight

        enabled: root.pageEnabled
        placeholderText: qsTr("website or IP")
        moreButtonAccessibleName: qsTr("Additional options")

        onAddClicked: function(text) {
            PageController.showBusyIndicator(true)
            IpSplitTunnelingController.addSite(text)
            PageController.showBusyIndicator(false)
        }

        onMoreClicked: {
            moreActionsMenu.openAbove(addSitePanel.moreButton)
        }
    }

    PopupMenuType {
        id: moreActionsMenu

        PopupMenuItemType {
            id: addImportedSitesButton

            text: qsTr("Add imported sites to existing ones")

            onClicked: {
                moreActionsMenu.close()
                root.selectImportFile(false)
            }
        }

        PopupMenuItemType {
            id: replaceSitesButton

            text: qsTr("Replace site list")

            onClicked: {
                moreActionsMenu.close()
                root.selectImportFile(true)
            }
        }

        PopupMenuItemType {
            id: exportSitesButton

            text: qsTr("Save site list")

            onClicked: {
                moreActionsMenu.close()
                var fileName = ""
                if (GC.isMobile()) {
                    fileName = "amnezia_sites.json"
                } else {
                    fileName = SystemController.getFileName(qsTr("Save sites"),
                                                            qsTr("Sites files (*.json)"),
                                                            StandardPaths.standardLocations(StandardPaths.DocumentsLocation) + "/amnezia_sites",
                                                            true,
                                                            ".json")
                }
                if (fileName !== "") {
                    PageController.showBusyIndicator(true)
                    IpSplitTunnelingController.exportSites(fileName)
                    PageController.showBusyIndicator(false)
                }
            }
        }

        PopupMenuSeparatorType {}

        PopupMenuItemType {
            id: clearSitesButton

            text: qsTr("Clear site list")
            destructive: true

            onClicked: {
                moreActionsMenu.close()
                var headerText = qsTr("Clear site list?")
                var descriptionText = qsTr("All sites will be removed from list.")
                var yesButtonText = qsTr("Continue")
                var noButtonText = qsTr("Cancel")

                var yesButtonFunction = function() {
                    PageController.showBusyIndicator(true)
                    IpSplitTunnelingController.removeSites()
                    PageController.showBusyIndicator(false)
                }
                var noButtonFunction = function() {
                }

                Dialogs.askQuestion(headerText, descriptionText, yesButtonText, noButtonText, yesButtonFunction, noButtonFunction)
            }
        }
    }

    function selectImportFile(replaceExistingSites) {
        var fileName = SystemController.getFileName(qsTr("Open sites file"),
                                                    qsTr("Sites files (*.json)"))
        if (fileName !== "") {
            root.importSites(fileName, replaceExistingSites)
        }
    }

    function importSites(fileName, replaceExistingSites) {
        PageController.showBusyIndicator(true)
        IpSplitTunnelingController.importSites(fileName, replaceExistingSites)
        PageController.showBusyIndicator(false)
    }
}
