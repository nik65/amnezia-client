#ifndef ROUTEINSPECTORCONTROLLER_H
#define ROUTEINSPECTORCONTROLLER_H

#include <QObject>
#include <QString>
#include <QVariantMap>

class SecureAppSettingsRepository;
class SecureServersRepository;
class VpnConnection;

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

signals:
    void inspectionReady(const QVariantMap &result);
    void routesExplainJsonReady(const QString &json);

private:
    int activeServerIndex(int connectedServerIndex) const;
    void cancelPendingLookup();
    QVariantMap resultFor(const QString &normalizedHost,
                          const QStringList &ipv4Addresses,
                          const QStringList &ipv6Addresses,
                          const QString &state,
                          const QString &error,
                          quint64 generation) const;
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
