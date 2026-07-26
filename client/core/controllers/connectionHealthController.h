#ifndef CONNECTIONHEALTHCONTROLLER_H
#define CONNECTIONHEALTHCONTROLLER_H

#include <QDateTime>
#include <QElapsedTimer>
#include <QJsonObject>
#include <QList>
#include <QMutex>
#include <QObject>
#include <QPointer>
#include <QString>
#include <QTimer>
#include <QUrl>
#include <QVariantList>
#include <QVariantMap>

class QNetworkAccessManager;
class QNetworkReply;

// ConnectionHealthController is the policy, observation and bounded-probe core for
// Amnezia Guardian. The probe uses an integration-supplied, already configured endpoint;
// it never chooses a third-party service, follows redirects or consumes response bodies.
// Recovery remains recommendation-only: this class never changes routes, protocol,
// server or tunnel state.
//
// Flight-recorder entries are bounded and privacy-safe by construction: arbitrary detail
// keys are discarded and non-symbolic strings are replaced with stable one-way identifiers.
class ConnectionHealthController final : public QObject
{
    Q_OBJECT

    Q_PROPERTY(HealthState healthState READ healthState NOTIFY healthSnapshotChanged)
    Q_PROPERTY(QString healthStateName READ healthStateName NOTIFY healthSnapshotChanged)
    Q_PROPERTY(QString lastReason READ lastReason NOTIFY healthSnapshotChanged)
    Q_PROPERTY(QDateTime lastUpdatedAt READ lastUpdatedAt NOTIFY healthSnapshotChanged)
    Q_PROPERTY(QDateTime lastProbeAt READ lastProbeAt NOTIFY healthSnapshotChanged)
    Q_PROPERTY(QDateTime lastStateChangedAt READ lastStateChangedAt NOTIFY healthSnapshotChanged)
    Q_PROPERTY(QDateTime lastHealthyAt READ lastHealthyAt NOTIFY healthSnapshotChanged)
    Q_PROPERTY(QDateTime unhealthySince READ unhealthySince NOTIFY healthSnapshotChanged)
    Q_PROPERTY(bool hasLatency READ hasLatency NOTIFY healthSnapshotChanged)
    Q_PROPERTY(double latencyMs READ latencyMs NOTIFY healthSnapshotChanged)
    Q_PROPERTY(bool hasPacketLoss READ hasPacketLoss NOTIFY healthSnapshotChanged)
    Q_PROPERTY(double packetLossPercent READ packetLossPercent NOTIFY healthSnapshotChanged)
    Q_PROPERTY(bool originAuthenticated READ originAuthenticated NOTIFY healthSnapshotChanged)
    Q_PROPERTY(bool tunnelPathVerified READ tunnelPathVerified NOTIFY healthSnapshotChanged)
    Q_PROPERTY(QVariantMap healthSnapshot READ healthSnapshot NOTIFY healthSnapshotChanged)
    Q_PROPERTY(QVariantList flightRecorder READ flightRecorder NOTIFY flightRecorderChanged)
    Q_PROPERTY(bool probeRunning READ probeRunning NOTIFY probeRunningChanged)
    Q_PROPERTY(bool recoveryPending READ recoveryPending NOTIFY recoveryPolicyChanged)
    Q_PROPERTY(QString pendingRecoveryAction READ pendingRecoveryAction NOTIFY recoveryPolicyChanged)
    Q_PROPERTY(quint64 pendingRecoveryEpoch READ pendingRecoveryEpoch NOTIFY recoveryPolicyChanged)
    Q_PROPERTY(bool recoveryRequestDispatched READ recoveryRequestDispatched NOTIFY recoveryPolicyChanged)
    Q_PROPERTY(int recoveryAttempts READ recoveryAttempts NOTIFY recoveryPolicyChanged)
    Q_PROPERTY(int recoveryBudgetRemaining READ recoveryBudgetRemaining NOTIFY recoveryPolicyChanged)
    Q_PROPERTY(int recoveryCooldownRemainingMs READ recoveryCooldownRemainingMs NOTIFY recoveryPolicyChanged)

public:
    enum class HealthState {
        Unknown,
        Healthy,
        Degraded,
        Unhealthy,
        Recovering
    };
    Q_ENUM(HealthState)

    enum class RecoveryAction {
        None,
        RefreshNetwork,
        RepairDns,
        RepairRoutes,
        ReconnectTunnel,
        SwitchProtocol,
        SwitchServer
    };
    Q_ENUM(RecoveryAction)

    explicit ConnectionHealthController(QObject *parent = nullptr);

    HealthState healthState() const;
    QString healthStateName() const;
    QString lastReason() const;
    QDateTime lastUpdatedAt() const;
    QDateTime lastProbeAt() const;
    QDateTime lastStateChangedAt() const;
    QDateTime lastHealthyAt() const;
    QDateTime unhealthySince() const;
    bool hasLatency() const;
    double latencyMs() const;
    bool hasPacketLoss() const;
    double packetLossPercent() const;
    bool originAuthenticated() const;
    bool tunnelPathVerified() const;
    QVariantMap healthSnapshot() const;
    QVariantList flightRecorder() const;
    bool probeRunning() const;

    bool recoveryPending() const;
    QString pendingRecoveryAction() const;
    quint64 pendingRecoveryEpoch() const;
    bool recoveryRequestDispatched() const;
    int recoveryAttempts() const;
    int recoveryBudgetRemaining() const;
    int recoveryCooldownRemainingMs() const;

    // The status document is intended for UI, CLI and a future local read-only API.
    QJsonObject statusObject() const;
    QJsonObject doctorObject() const;

    Q_INVOKABLE QString statusJson(bool pretty = false) const;
    Q_INVOKABLE QString doctorJson(bool pretty = false) const;

    // Starts one privacy-bounded DNS + HTTP reachability probe. tunnelConnected is a
    // handshake-derived observation from VpnConnection::Connected, not a new protocol
    // handshake. The URL is reduced to its HTTP(S) origin root and no content is trusted.
    // A newer request or cancelConnectivityProbe() invalidates all older callbacks.
    // tunnelPathVerified must only be true when the integration independently
    // proved that this request traverses the VPN data path. A successful HTTPS
    // exchange alone authenticates the origin, not the route used to reach it.
    void startConnectivityProbe(QNetworkAccessManager *networkManager, const QUrl &configuredEndpoint,
                                bool tunnelConnected, int timeoutMs = 5000,
                                bool tunnelPathVerified = false);
    void cancelConnectivityProbe(const QString &reason = QStringLiteral("probe_cancelled"));

public slots:
    // reason must preferably be a symbolic code (for example "dns_probe_failed").
    // Non-symbolic values are replaced with a stable hash before being retained.
    // A requested Healthy state is downgraded unless both independent proofs
    // are supplied; origin authentication alone does not prove the VPN path.
    // State-only observations invalidate freshness and quality metrics from
    // any earlier probe so a new connection/network epoch cannot inherit them.
    void recordHealthState(HealthState state, const QString &reason = QString(),
                           bool originAuthenticated = false, bool tunnelPathVerified = false);
    // originAuthenticated must only be true when the integration observed a
    // successfully encrypted HTTPS exchange with the configured origin.
    // tunnelPathVerified must only be true when the integration independently
    // proved that the probe used the VPN data path.
    void recordProbeResult(bool handshakeOk, bool dnsOk, bool egressOk, double latencyMs = -1.0,
                           double packetLossPercent = -1.0, const QString &reason = QString(),
                           bool originAuthenticated = false, bool tunnelPathVerified = false);
    void recordEvent(const QString &category, const QString &outcome,
                     const QVariantMap &privacySafeDetails = QVariantMap());

    // Returns an accepted/action/reason decision and emits recoverySuggested() when accepted.
    // The controller never performs the suggested action itself.
    QVariantMap evaluateRecovery(const QString &triggerReason = QString());
    Q_INVOKABLE bool requestPendingRecovery();
    void acknowledgeRecoveryResult(bool success, const QString &reason = QString(),
                                   quint64 expectedRecoveryEpoch = 0);
    void resetRecoveryPolicy();
    void configureRecoveryPolicy(int cooldownMs, int maxAttempts, int budgetWindowMs);
    void setFlightRecorderCapacity(int capacity);

signals:
    void healthSnapshotChanged();
    void flightRecorderChanged();
    void probeRunningChanged();
    void recoveryPolicyChanged();
    void recoverySuggested(ConnectionHealthController::RecoveryAction action, const QString &reasonCode, int attempt);
    void recoveryActionRequested(ConnectionHealthController::RecoveryAction action,
                                 const QString &reasonCode, int attempt,
                                 quint64 recoveryEpoch);

private:
    struct HealthSnapshotData
    {
        HealthState state = HealthState::Unknown;
        QString lastReason = QStringLiteral("not_observed");
        QDateTime lastUpdatedAt;
        QDateTime lastProbeAt;
        QDateTime lastStateChangedAt;
        QDateTime lastHealthyAt;
        QDateTime unhealthySince;
        double latencyMs = -1.0;
        double packetLossPercent = -1.0;
        bool originAuthenticated = false;
        bool tunnelPathVerified = false;
        HealthState lastProbeObservedState = HealthState::Unknown;
        QString lastProbeObservedReason = QStringLiteral("not_observed");
        int probeFailureStreak = 0;
        int probeRecoveryStreak = 0;
    };

    struct RecoveryPolicyData
    {
        int cooldownMs = 30000;
        int maxAttempts = 5;
        int budgetWindowMs = 10 * 60 * 1000;
        int nextActionIndex = 0;
        RecoveryAction pendingAction = RecoveryAction::None;
        QString pendingReason;
        int pendingAttempt = 0;
        quint64 pendingEpoch = 0;
        quint64 nextEpoch = 1;
        bool executionRequested = false;
        QDateTime lastDecisionAt;
        QList<QDateTime> attempts;
    };

    static QString stateName(HealthState state);
    static QString actionName(RecoveryAction action);
    static QString safeToken(const QString &value, const QString &fallback);
    static QVariantMap safeDetails(const QVariantMap &details);
    static QJsonObject variantMapToJson(const QVariantMap &map);
    static int boundedDurationMs(qint64 value);
    static QUrl sanitizedProbeUrl(const QUrl &configuredEndpoint);

    void appendEventLocked(const QString &category, const QString &outcome, const QVariantMap &details);
    void completeProbeIfReady(quint64 generation);
    void finishProbe(quint64 generation, bool timedOut);
    void clearActiveProbe(bool abortOperations);
    void pruneRecoveryAttemptsLocked(const QDateTime &now) const;
    int cooldownRemainingMsLocked(const QDateTime &now) const;
    QVariantMap healthSnapshotLocked() const;
    QVariantMap recoverySnapshotLocked(const QDateTime &now) const;
    QJsonObject statusObjectLocked(const QDateTime &now) const;

    mutable QMutex m_mutex;
    HealthSnapshotData m_health;
    mutable RecoveryPolicyData m_recovery;
    QList<QJsonObject> m_flightRecorder;
    int m_flightRecorderCapacity = 128;
    qint64 m_nextEventSequence = 1;

    QTimer m_probeTimeoutTimer;
    QTimer m_probeFreshnessTimer;
    QElapsedTimer m_probeElapsedTimer;
    QPointer<QNetworkReply> m_probeReply;
    quint64 m_probeGeneration = 0;
    int m_probeLookupId = -1;
    bool m_probeActive = false;
    bool m_probeHandshakeOk = false;
    bool m_probeDnsDone = false;
    bool m_probeDnsOk = false;
    bool m_probeEgressDone = false;
    bool m_probeEgressOk = false;
    bool m_probeOriginAuthenticated = false;
    bool m_probeTunnelPathVerified = false;
    bool m_probeTlsErrors = false;
    double m_probeLatencyMs = -1.0;
};

#endif // CONNECTIONHEALTHCONTROLLER_H
