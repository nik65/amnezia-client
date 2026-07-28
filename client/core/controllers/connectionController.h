#ifndef CONNECTIONCONTROLLER_H
#define CONNECTIONCONTROLLER_H

#include <QObject>
#include <QJsonObject>
#include <QPair>
#include <QStringList>
#include <QTimer>
#include <QUrl>
#include <QVariantMap>
#include <memory>

#include "core/utils/containerEnum.h"
#include "core/utils/containers/containerUtils.h"
#include "core/utils/protocolEnum.h"
#include "core/utils/errorCodes.h"
#include "core/utils/routeModes.h"
#include "core/utils/commonStructs.h"
#include "core/repositories/secureServersRepository.h"
#include "core/repositories/secureAppSettingsRepository.h"
#include "core/protocols/vpnProtocol.h"
#include "vpnConnection.h"

using namespace amnezia;

class ConnectionController : public QObject
{
    Q_OBJECT

public:
    explicit ConnectionController(SecureServersRepository* serversRepository,
                                 SecureAppSettingsRepository* appSettingsRepository,
                                 VpnConnection* vpnConnection,
                                 QObject* parent = nullptr);
    ~ConnectionController() = default;

    ErrorCode prepareConnection(const QString &serverId,
                               QJsonObject& vpnConfiguration,
                               DockerContainer& container);

    ErrorCode isConnectionSupported(const QString &serverId) const;

    ErrorCode openConnection(const QString &serverId);

    void closeConnection();

#ifdef Q_OS_ANDROID
    void restoreConnection(Vpn::ConnectionState state, int serverIndex);
#endif

    void onKillSwitchModeChanged(bool enabled);
    void onManagedSplitTunnelingRulesPublished(int serverIndex);

    ErrorCode lastConnectionError() const;

    bool isConnected() const;
    void setConnectionState(Vpn::ConnectionState state);

    QJsonObject createConnectionConfiguration(int serverIndex,
                                             const QPair<QString, QString> &dns,
                                             bool isApiConfig,
                                             const QString &hostName,
                                             const QString &description,
                                             int configVersion,
                                             const ContainerConfig &containerConfig,
                                             DockerContainer container);

    bool isServiceReady() const;

    bool isContainerSupported(DockerContainer container) const;

signals:
    void connectionStateChanged(Vpn::ConnectionState state);
    void serverRoutingRulesChanged(int serverIndex);
    void openConnectionRequested(const QString &serverId, int serverIndex,
                                 DockerContainer container,
                                 const QJsonObject &vpnConfiguration);
    void closeConnectionRequested();
    void killSwitchModeChangedRequested(bool enabled);
    void managedRouteConnectionSnapshotPrepared(quint64 generation,
                                                 const QString &serverId,
                                                 int mode,
                                                 const QStringList &managedRoutes,
                                                 const QString &policyRevision,
                                                 const QString &policyContentHash,
                                                 const QVariantMap &localSites);
    void managedRouteReconcileRequested(quint64 generation,
                                        quint64 connectionEpoch,
                                         const QString &serverId,
                                         quint64 expectedBaseRevision,
                                         const QString &expectedPolicyRevision,
                                         const QString &expectedPolicyContentHash,
                                         int mode,
                                         const QStringList &oldRoutes,
                                         const QStringList &newRoutes,
                                         const QString &desiredPolicyRevision,
                                         const QString &desiredPolicyContentHash,
                                         const QVariantMap &localSites);
    void managedRouteFullRebuildRequested(quint64 connectionEpoch,
                                          const QString &serverId);

#ifdef Q_OS_ANDROID
    void restoreConnectionRequested(const QString &serverId, int serverIndex,
                                    DockerContainer container, const QJsonObject &vpnConfiguration,
                                    Vpn::ConnectionState state);
#endif

private:
    struct ManagedRouteSyncSnapshot
    {
        bool hasConfirmedAppliedState = false;
        quint64 appliedBaseRevision = 0;
        RouteMode appliedRouteMode = RouteMode::VpnAllSites;
        QStringList appliedManagedIps;
        QString appliedPolicyRevision;
        QString appliedContentHash;
        bool localSplitEnabled = false;
        RouteMode localRouteMode = RouteMode::VpnAllSites;
    };

    struct ManagedRouteDesiredSnapshot
    {
        bool valid = false;
        QString serverId;
        RouteMode routeMode = RouteMode::VpnAllSites;
        QStringList managedIps;
        QString policyRevision;
        QString contentHash;
        QVariantMap localSites;
    };

    ErrorCode defaultContainerForServer(const QString &serverId, DockerContainer &container) const;

    void onVpnConnectionStateChanged(Vpn::ConnectionState state);
    void onVpnConnectionContextChanged(const QString &serverId,
                                       const QString &serverRoutingRulesSyncHost,
                                       quint64 connectionEpoch);
    void onManagedRouteReconciled(quint64 generation,
                                  quint64 connectionEpoch,
                                  const QString &serverId,
                                  bool requestAccepted,
                                  bool updated,
                                  bool reconnectScheduled,
                                  int appliedMode,
                                  const QStringList &appliedRoutes,
                                  quint64 appliedBaseRevision,
                                  const QString &appliedPolicyRevision,
                                  const QString &appliedPolicyContentHash);
    void onManagedRouteBaseReady(quint64 connectionEpoch,
                                 const QString &serverId,
                                 int mode,
                                 const QStringList &managedRoutes,
                                 quint64 baseRevision,
                                 const QString &policyRevision,
                                 const QString &policyContentHash,
                                 bool confirmed);
    ManagedRouteDesiredSnapshot managedRouteDesiredSnapshot(const QString &serverId) const;
    void prepareManagedRouteConnectionSnapshot(const QString &serverId);
    void requestManagedRouteReconciliation(const QString &serverId, const QString &reason);
    void dispatchManagedRouteReconciliation(const ManagedRouteDesiredSnapshot &desired,
                                             const QString &reason);
    void clearPendingManagedRouteReconciliation();
    void preservePendingManagedRouteDesired();
    void preserveLatestManagedRouteDesired(const ManagedRouteDesiredSnapshot &desired);
    void requestManagedRouteFullRebuild();
    void scheduleServerRoutingRulesSync(int intervalMs);
    void scheduleNextServerRoutingRulesSync(bool success);
    void finishServerRoutingRulesSync(bool success);
    void syncServerRoutingRules();
    void syncServerRoutingRulesFromUrls(const QList<QUrl> &syncUrls, int urlIndex, const QString &serverId,
                                        const ManagedRouteSyncSnapshot &routeSnapshot, int syncGeneration);
    bool applyServerRoutingRulesPayload(int serverIndex, const QJsonObject &payload,
                                        const ManagedRoutePolicyMetadata &metadata);
    QStringList managedSplitTunnelIpsForSync(int serverIndex, RouteMode routeMode) const;
    QString effectiveManagedRoutePolicyRevision(int serverIndex) const;
    QString effectiveManagedRouteContentHash(int serverIndex) const;
    bool reconcileManagedRouteState(const QString &serverId,
                                    const ManagedRouteSyncSnapshot &routeSnapshot,
                                    const QString &reason);
    int currentConnectionServerIndex() const;
    QString currentConnectionServerId() const;
    bool isCurrentConnectionServerIndex(int serverIndex) const;
    bool isCurrentConnectionServerId(const QString &serverId) const;

    void scheduleClientManagedSitesResolve(int serverIndex);
    void startClientManagedSitesResolve();
    void resolveNextClientManagedSite();
    void finishClientManagedSitesResolve();
    void cancelClientManagedSitesResolve();
    void scheduleClientManagedSitesResolveRetry(int serverIndex);

    SecureServersRepository* m_serversRepository;
    SecureAppSettingsRepository* m_appSettingsRepository;
    VpnConnection* m_vpnConnection;

    QTimer m_serverRoutingRulesSyncTimer;
    QTimer m_serverRoutingRulesClientResolveTimer;
    bool m_isServerRoutingRulesSyncInProgress = false;
    bool m_serverRoutingRulesSyncPendingRefresh = false;
    int m_serverRoutingRulesSyncFastRetryCount = 0;
    int m_serverRoutingRulesSyncGeneration = 0;
    bool m_hasConfirmedManagedRouteState = false;
    bool m_managedRouteIncrementalBlocked = true;
    bool m_managedRouteReconcileInFlight = false;
    bool m_managedRouteFullRebuildAttempted = false;
    quint64 m_confirmedManagedRouteBaseRevision = 0;
    RouteMode m_confirmedManagedRouteMode = RouteMode::VpnAllSites;
    QStringList m_confirmedManagedSplitTunnelIps;
    QString m_confirmedManagedPolicyRevision;
    QString m_confirmedManagedContentHash;
    Vpn::ConnectionState m_cachedConnectionState = Vpn::ConnectionState::Unknown;
    ErrorCode m_cachedLastConnectionError = ErrorCode::NoError;
    QString m_cachedConnectionServerId;
    QString m_cachedServerRoutingRulesSyncHost;
    quint64 m_cachedConnectionEpoch = 0;
    quint64 m_managedRouteReconcileGeneration = 0;
    quint64 m_pendingManagedRouteReconcileGeneration = 0;
    QString m_pendingManagedRouteReconcileServerId;
    RouteMode m_pendingManagedRouteMode = RouteMode::VpnAllSites;
    QStringList m_pendingManagedRouteIps;
    QString m_pendingManagedRoutePolicyRevision;
    QString m_pendingManagedRouteContentHash;
    QVariantMap m_pendingManagedRouteLocalSites;
    quint64 m_pendingManagedRouteExpectedBaseRevision = 0;
    ManagedRouteDesiredSnapshot m_coalescedManagedRouteDesired;

    bool m_isClientManagedSitesResolveInProgress = false;
    int m_clientManagedSitesResolveGeneration = 0;
    QString m_clientManagedSitesResolveServerId;
    QStringList m_clientManagedSitesResolveQueue;
    QJsonObject m_clientManagedSitesResolvedCache;
    bool m_clientManagedSitesResolveHadFailure = false;
    int m_clientManagedSitesResolveRetryCount = 0;
    bool m_clientManagedSitesResolveOldStateConfirmed = false;
    RouteMode m_clientManagedSitesResolveOldRouteMode = RouteMode::VpnAllSites;
    QStringList m_clientManagedSitesResolveOldManagedSplitTunnelIps;
    QString m_clientManagedSitesResolveOldPolicyRevision;
    QString m_clientManagedSitesResolveOldContentHash;
    bool m_clientManagedSitesResolveOldLocalSplitEnabled = false;
    RouteMode m_clientManagedSitesResolveOldLocalRouteMode = RouteMode::VpnAllSites;
};

#endif
