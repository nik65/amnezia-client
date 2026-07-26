#ifndef ROUTEINSPECTORCONTROLLER_H
#define ROUTEINSPECTORCONTROLLER_H

#include <QObject>
#include <QAbstractSocket>
#include <QHostAddress>
#include <QList>
#include <QString>
#include <QStringList>
#include <QVariantMap>

#include "core/utils/containerEnum.h"
#include "core/utils/routeModes.h"

class SecureAppSettingsRepository;
class SecureServersRepository;
class VpnConnection;

namespace amnezia::routeInspectorBounds
{
inline constexpr int maximumDisplayedAddressesPerFamily = 16;
inline constexpr int maximumProcessedDnsAddresses = 64;

struct BoundedDnsAddresses
{
    QStringList ipv4;
    QStringList ipv6;
    int observedCount = 0;
    int processedCount = 0;
    bool processingTruncated = false;
};

inline BoundedDnsAddresses boundedDnsAddresses(const QList<QHostAddress> &addresses)
{
    BoundedDnsAddresses result;
    result.observedCount = addresses.size();
    const int limit = qMin(addresses.size(), maximumProcessedDnsAddresses);
    for (int index = 0; index < limit; ++index) {
        ++result.processedCount;
        const QHostAddress &address = addresses.at(index);
        if (!address.scopeId().isEmpty()) {
            continue;
        }
        const QString value = address.toString().toLower();
        QStringList *target = address.protocol() == QAbstractSocket::IPv4Protocol
                ? &result.ipv4
                : address.protocol() == QAbstractSocket::IPv6Protocol ? &result.ipv6 : nullptr;
        if (target && !target->contains(value)) {
            target->append(value);
        }
    }
    result.processingTruncated = addresses.size() > maximumProcessedDnsAddresses;
    result.ipv4.sort();
    result.ipv6.sort();
    return result;
}
}

class RouteInspectorController : public QObject
{
    Q_OBJECT

public:
    explicit RouteInspectorController(SecureServersRepository *serversRepository,
                                      SecureAppSettingsRepository *appSettingsRepository,
                                      VpnConnection *vpnConnection = nullptr,
                                      QObject *parent = nullptr);

    void setVpnConnection(VpnConnection *vpnConnection);

    // Returns the immediate inspection state. Hostname lookups return a
    // `resolving` result first and publish the final result through
    // inspectionReady(). Ready results retain the legacy top-level decision
    // fields and add bounded `addressDecisions` plus `aggregateRoute`
    // (`vpn`, `direct`, `mixed`, or `unknown`). Only the most recently
    // requested host is published.
    Q_INVOKABLE QVariantMap inspectHost(const QString &host);

    // Compact JSON counterpart for the future `routes explain` operator CLI.
    // For hostnames, the final JSON is delivered through routesExplainJsonReady().
    Q_INVOKABLE QString routesExplainJson(const QString &host);

    struct VpnConnectionSnapshot
    {
        bool connected = false;
        QString serverId;
        QString remoteAddress;
        QString serverRoutingRulesSyncHost;
        QString vpnGateway;
        amnezia::DockerContainer container = amnezia::DockerContainer::None;
        amnezia::RouteMode appliedSiteRouteMode = amnezia::RouteMode::VpnAllSites;
        bool managedRouteSnapshotConfirmed = false;
        bool managedRouteTransitionPending = true;
        amnezia::RouteMode managedRouteSnapshotMode = amnezia::RouteMode::VpnAllSites;
        QStringList installedManagedRoutes;
        quint64 managedRouteSnapshotRevision = 0;
        QString managedRoutePolicyRevision;
        QString managedRoutePolicyContentHash;
        quint64 connectionEpoch = 0;
    };

signals:
    void inspectionReady(const QVariantMap &result);
    void routesExplainJsonReady(const QString &json);

private:
    int activeServerIndex(const QString &connectedServerId) const;
    void cancelPendingLookup();
    QVariantMap pendingResult(const QString &normalizedHost, quint64 generation) const;
    void requestResultWithSnapshot(const QString &normalizedHost,
                                   const QStringList &ipv4Addresses,
                                   const QStringList &ipv6Addresses,
                                   bool dnsProcessingTruncated,
                                   const QString &state,
                                   const QString &error,
                                   quint64 generation);
    QVariantMap resultFor(const QString &normalizedHost,
                          const QStringList &ipv4Addresses,
                          const QStringList &ipv6Addresses,
                          bool dnsProcessingTruncated,
                          const QString &state,
                          const QString &error,
                          quint64 generation,
                          const VpnConnectionSnapshot &vpnSnapshot,
                          bool snapshotAvailable) const;
    void publishResult(quint64 generation, const QVariantMap &result);
    static QString resultToJson(const QVariantMap &result);

    SecureServersRepository *m_serversRepository = nullptr;
    SecureAppSettingsRepository *m_appSettingsRepository = nullptr;
    VpnConnection *m_vpnConnection = nullptr;
    quint64 m_generation = 0;
    int m_activeLookupId = -1;
    quint64 m_activeLookupGeneration = 0;
};

#endif // ROUTEINSPECTORCONTROLLER_H
