#ifndef VPNCONNECTION_H
#define VPNCONNECTION_H

#include <QObject>
#include <QElapsedTimer>
#include <QMetaObject>
#include <QString>
#include <QScopedPointer>
#include <QRemoteObjectNode>
#include <QStringList>
#include <QTimer>
#include <QVariantMap>

#include "core/protocols/vpnProtocol.h"
#include "core/utils/errorCodes.h"
#include "core/utils/routeModes.h"
#include "core/utils/commonStructs.h"
#include "core/utils/managedDnsConvergence.h"

#ifdef AMNEZIA_DESKTOP
#include "core/utils/ipcClient.h"
#endif

#ifdef Q_OS_ANDROID
#include "core/protocols/androidVpnProtocol.h"
#endif

using namespace amnezia;

class QThread;

class VpnConnection : public QObject
{
    Q_OBJECT

public:
    // Distinguishes a completed route mutation from the two reconnect paths so
    // callers never acknowledge a deferred policy refresh as already applied.
    enum class ManagedRouteUpdateResult {
        Updated,
        ReconnectRequired,
        ReconnectDeferred,
    };

    struct ManagedRouteRuntimeSnapshot {
        bool confirmed = false;
        bool transitionPending = true;
        RouteMode mode = RouteMode::VpnAllSites;
        QStringList installedRoutes;
        quint64 revision = 0;
        quint64 connectionEpoch = 0;
        QString serverId;
        QString policyRevision;
        QString policyContentHash;
    };

    explicit VpnConnection(QObject* parent = nullptr);
    ~VpnConnection() override;

    static QString bytesPerSecToText(quint64 bytes);

    ErrorCode lastError() const;
    Vpn::ConnectionState connectionState() const;

    QSharedPointer<VpnProtocol> vpnProtocol() const;

    const QString &remoteAddress() const;
    int serverIndex() const;
    QString serverId() const;
    quint64 connectionEpoch() const;
    ManagedRouteRuntimeSnapshot managedRouteRuntimeSnapshot() const;
    DockerContainer container() const;
    amnezia::RouteMode appliedSiteRouteMode() const;
    amnezia::AppsRouteMode appliedAppsRouteMode() const;
    bool applicationUsesVpnDataPath(const QString &applicationId) const;
    QString serverRoutingRulesSyncHost() const;
    void addSitesRoutes(const QString &gw, amnezia::RouteMode mode);
    ManagedRouteUpdateResult updateManagedSplitTunnelRoutes(amnezia::RouteMode mode,
                                                             const QStringList &oldRoutes,
                                                             const QStringList &newRoutes,
                                                             const QVariantMap &localSites);

#ifdef Q_OS_ANDROID
    void restoreConnection(const QString &serverId, int serverIndex,
                           DockerContainer container, const QJsonObject &vpnConfiguration,
                           Vpn::ConnectionState state);
#endif

public slots:
    void connectToVpn(const QString &serverId, int serverIndex,
                      DockerContainer container, const QJsonObject &vpnConfiguration);
    void reconnectToVpn();
    void disconnectFromVpn();
    void prepareManagedRouteConnectionSnapshot(quint64 generation,
                                               const QString &serverId,
                                               int mode,
                                               const QStringList &managedRoutes,
                                               const QString &policyRevision,
                                               const QString &policyContentHash,
                                               const QVariantMap &localSites);
    void reconcileManagedSplitTunnelRoutes(quint64 generation,
                                           quint64 expectedConnectionEpoch,
                                           const QString &expectedServerId,
                                           quint64 expectedBaseRevision,
                                           const QString &expectedPolicyRevision,
                                           const QString &expectedPolicyContentHash,
                                           int mode,
                                           const QStringList &oldRoutes,
                                           const QStringList &newRoutes,
                                           const QString &desiredPolicyRevision,
                                           const QString &desiredPolicyContentHash,
                                           const QVariantMap &localSites);
    void rebuildManagedSplitTunnelRoutes(quint64 expectedConnectionEpoch,
                                         const QString &expectedServerId);
    void shutdownForApplicationExit(bool disconnectVpn, QThread *destructionThread);

    void onKillSwitchModeChanged(bool enabled);
    void disconnectSlots();

    void setConnectionState(Vpn::ConnectionState state);

signals:
    void bytesChanged(quint64 receivedBytes, quint64 sentBytes);
    void connectionStateChanged(Vpn::ConnectionState state);
    void connectionContextChanged(const QString &serverId,
                                  const QString &serverRoutingRulesSyncHost,
                                  quint64 connectionEpoch);
    void managedSplitTunnelRoutesReconciled(quint64 generation,
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
    void managedSplitTunnelRouteBaseReady(quint64 connectionEpoch,
                                          const QString &serverId,
                                          int mode,
                                          const QStringList &managedRoutes,
                                          quint64 baseRevision,
                                          const QString &policyRevision,
                                          const QString &policyContentHash,
                                          bool confirmed);
    void vpnProtocolError(amnezia::ErrorCode error);

    void serviceIsNotReady();

protected slots:
    void onBytesChanged(quint64 receivedBytes, quint64 sentBytes);
    void onConnectionStateChanged(Vpn::ConnectionState state);

protected:
    QSharedPointer<VpnProtocol> m_vpnProtocol;

private:
    QJsonObject m_vpnConfiguration;
    QJsonObject m_routeMode;
    QString m_remoteAddress;
    int m_serverIndex = -1;
    QString m_serverId;
    quint64 m_connectionEpoch = 0;
    quint64 m_latestManagedRouteReconcileGeneration = 0;
    quint64 m_latestPreparedManagedRouteSnapshotGeneration = 0;
    bool m_connectionRestoredWithoutStartup = false;
    bool m_hasAuthoritativeManagedRouteBase = false;
    bool m_managedRouteTransitionPending = true;
    RouteMode m_authoritativeManagedRouteMode = RouteMode::VpnAllSites;
    QStringList m_authoritativeManagedRoutes;
    quint64 m_authoritativeManagedRouteBaseRevision = 0;
    quint64 m_authoritativeManagedRouteConnectionEpoch = 0;
    QString m_authoritativeManagedRouteServerId;
    QString m_authoritativeManagedRoutePolicyRevision;
    QString m_authoritativeManagedRoutePolicyContentHash;
    QString m_preparedManagedRouteServerId;
    RouteMode m_preparedManagedRouteMode = RouteMode::VpnAllSites;
    QStringList m_preparedManagedRoutes;
    QString m_preparedManagedRoutePolicyRevision;
    QString m_preparedManagedRoutePolicyContentHash;
    QVariantMap m_preparedLocalSites;
    bool m_hasPreparedManagedRouteSnapshot = false;
    QString m_startupManagedRouteServerId;
    RouteMode m_startupManagedRouteMode = RouteMode::VpnAllSites;
    QStringList m_startupManagedRoutes;
    QString m_startupManagedRoutePolicyRevision;
    QString m_startupManagedRoutePolicyContentHash;
    QVariantMap m_startupLocalSites;
    bool m_hasStartupManagedRouteSnapshot = false;
    bool m_startupRouteTeardownConfirmed = true;
    DockerContainer m_container = DockerContainer::None;
    // Local and server-managed DNS work have different owners. A managed
    // policy refresh must not discard a user's pending local lookup.
    quint64 m_clientSplitRouteResolveGeneration = 0;
    quint64 m_managedSplitRouteResolveGeneration = 0;
    int m_pendingClientSplitRouteLookups = 0;
    bool m_reconnectAfterClientRouteResolution = false;
#if defined(Q_OS_IOS) || defined(MACOS_NE)
    bool m_reconnectPending = false;
#endif

    // Only for iOS for now, check counters
    QTimer m_checkTimer;
    QTimer m_deferredManagedRouteReconnectTimer;
    QTimer m_managedRouteReconnectCooldownTimer;
    QElapsedTimer m_managedRouteReconnectClock;
    amnezia::managedDnsConvergence::ReconnectGate m_managedRouteReconnectGate;
    bool m_managedRouteReconnectAwaitingBase = false;

#ifdef Q_OS_ANDROID
   AndroidVpnProtocol* androidVpnProtocol = nullptr;

   AndroidVpnProtocol* createDefaultAndroidVpnProtocol();
   void createAndroidConnections();
#endif

   Vpn::ConnectionState m_connectionState = Vpn::ConnectionState::Unknown;

   void createProtocolConnections();
   void invalidateAllSplitRouteResolutions();
   void invalidateAuthoritativeManagedRouteBase();
   void beginManagedRouteReconnectSession(const QString &serverId);
   void clearManagedRouteReconnectSession();
   void recordReconnectFloor();
   void scheduleManagedRouteReconnect(quint64 expectedConnectionEpoch,
                                      const QString &expectedServerId,
                                      const QString &reason);
   void flushManagedRouteReconnect();
   bool latestPreparedManagedRouteSnapshotIsApplied() const;
   bool clearSavedRoutesWithReceipt();
   void publishManagedRouteBase(RouteMode mode,
                                const QStringList &managedRoutes,
                                const QVariantMap &localSites,
                                const QString &policyRevision,
                                const QString &policyContentHash,
                                bool confirmed);
   QStringList normalizedManagedRoutesForRuntime(RouteMode mode,
                                                 const QStringList &managedRoutes,
                                                 const QVariantMap &localSites,
                                                 const QStringList &protectedHosts,
                                                 bool *valid) const;
   QStringList serverRoutingRulesSyncHosts() const;
#if defined(Q_OS_IOS) || defined(MACOS_NE)
   void startIosVpnWithCurrentConfig();
#endif

   void appendSplitTunnelingConfig();
   void appendKillSwitchConfig();
};

#endif // VPNCONNECTION_H
