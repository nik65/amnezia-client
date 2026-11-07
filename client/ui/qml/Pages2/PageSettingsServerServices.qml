import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

import SortFilterProxyModel 0.2

import PageEnum 1.0
import ContainerProps 1.0
import ContainersModelFilters 1.0
import Style 1.0

import "./"
import "../Controls2"
import "../Controls2/TextTypes"
import "../Config"
import "../Components"

PageType {
    id: root

    readonly property int installedServicesCount: proxyContainersModel.count

    SettingsContainersListView {
        id: settingsContainersListView

        anchors.fill: parent

        Connections {
            target: ServersUiController

            function onProcessedServerIdChanged() {
                settingsContainersListView.updateContainersModelFilters()
            }
        }

        function updateContainersModelFilters() {
            if (ServersUiController.isProcessedServerHasWriteAccess()) {
                proxyContainersModel.filters = ContainersModelFilters.getWriteAccessServicesListFilters()
            } else {
                proxyContainersModel.filters = ContainersModelFilters.getReadAccessServicesListFilters()
            }
        }

        model: SortFilterProxyModel {
            id: proxyContainersModel
            sourceModel: ContainersModel
            sorters: [
                RoleSorter { roleName: "isInstalled"; sortOrder: Qt.DescendingOrder }
            ]
        }

        footer: ColumnLayout {
            width: settingsContainersListView.width
            visible: ServersUiController.isProcessedServerHasWriteAccess()
            height: visible ? implicitHeight : 0
            ListItemType {
                Layout.fillWidth: true
                text: qsTr("Server routing rules")
                subtitle: qsTr("Configure domains and IPs that this server adds to client split tunneling")
                trailingIconSource: "qrc:/images/controls/chevron-right.svg"
                onClicked: PageController.goToPage(PageEnum.PageSettingsServerManagedSplitTunneling)
            }
        }

        Component.onCompleted: updateContainersModelFilters()
    }
}
