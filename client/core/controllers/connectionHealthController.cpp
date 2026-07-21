#include "connectionHealthController.h"

#include <QCryptographicHash>
#include <QHostAddress>
#include <QHostInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonValue>
#include <QMutexLocker>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QSet>
#include <QtGlobal>

#include <algorithm>
#include <cmath>
#include <limits>

namespace
{
    constexpr int kMinimumRecorderCapacity = 16;
    constexpr int kMaximumRecorderCapacity = 512;
    constexpr int kMinimumCooldownMs = 1000;
    constexpr int kMaximumCooldownMs = 30 * 60 * 1000;
    constexpr int kMinimumBudgetWindowMs = 60 * 1000;
    constexpr int kMaximumBudgetWindowMs = 24 * 60 * 60 * 1000;
    constexpr int kMaximumRecoveryAttempts = 20;
    constexpr qint64 kProbeStaleAfterMs = 2 * 60 * 1000;
    constexpr double kDegradedLatencyMs = 350.0;
    constexpr double kUnhealthyLatencyMs = 1000.0;
    constexpr double kDegradedPacketLossPercent = 5.0;
    constexpr double kUnhealthyPacketLossPercent = 25.0;
    constexpr int kMinimumProbeTimeoutMs = 250;
    constexpr int kMaximumProbeTimeoutMs = 15000;

    const QList<ConnectionHealthController::RecoveryAction> kRecoveryLadder {
        ConnectionHealthController::RecoveryAction::RefreshNetwork,
        ConnectionHealthController::RecoveryAction::RepairDns,
        ConnectionHealthController::RecoveryAction::RepairRoutes,
        ConnectionHealthController::RecoveryAction::ReconnectTunnel,
        ConnectionHealthController::RecoveryAction::SwitchProtocol,
        ConnectionHealthController::RecoveryAction::SwitchServer
    };

    bool isFiniteMetric(double value)
    {
        return std::isfinite(value);
    }

    QString isoUtc(const QDateTime &value)
    {
        return value.isValid() ? value.toUTC().toString(Qt::ISODateWithMs) : QString();
    }
}

ConnectionHealthController::ConnectionHealthController(QObject *parent) : QObject(parent)
{
    const QDateTime now = QDateTime::currentDateTimeUtc();
    m_health.lastUpdatedAt = now;
    m_health.lastStateChangedAt = now;

    QMutexLocker locker(&m_mutex);
    appendEventLocked(QStringLiteral("guardian"), QStringLiteral("initialized"),
                      { { QStringLiteral("state"), stateName(m_health.state) } });

    m_probeTimeoutTimer.setSingleShot(true);
    connect(&m_probeTimeoutTimer, &QTimer::timeout, this, [this]() {
        finishProbe(m_probeGeneration, true);
    });

    m_probeFreshnessTimer.setSingleShot(true);
    m_probeFreshnessTimer.setInterval(static_cast<int>(kProbeStaleAfterMs));
    connect(&m_probeFreshnessTimer, &QTimer::timeout, this, [this]() {
        if (!m_probeActive) {
            recordHealthState(HealthState::Unknown, QStringLiteral("probe_stale"));
        }
    });
}

ConnectionHealthController::HealthState ConnectionHealthController::healthState() const
{
    QMutexLocker locker(&m_mutex);
    return m_health.state;
}

QString ConnectionHealthController::healthStateName() const
{
    QMutexLocker locker(&m_mutex);
    return stateName(m_health.state);
}

QString ConnectionHealthController::lastReason() const
{
    QMutexLocker locker(&m_mutex);
    return m_health.lastReason;
}

QDateTime ConnectionHealthController::lastUpdatedAt() const
{
    QMutexLocker locker(&m_mutex);
    return m_health.lastUpdatedAt;
}

QDateTime ConnectionHealthController::lastProbeAt() const
{
    QMutexLocker locker(&m_mutex);
    return m_health.lastProbeAt;
}

QDateTime ConnectionHealthController::lastStateChangedAt() const
{
    QMutexLocker locker(&m_mutex);
    return m_health.lastStateChangedAt;
}

QDateTime ConnectionHealthController::lastHealthyAt() const
{
    QMutexLocker locker(&m_mutex);
    return m_health.lastHealthyAt;
}

QDateTime ConnectionHealthController::unhealthySince() const
{
    QMutexLocker locker(&m_mutex);
    return m_health.unhealthySince;
}

bool ConnectionHealthController::hasLatency() const
{
    QMutexLocker locker(&m_mutex);
    return m_health.latencyMs >= 0.0;
}

double ConnectionHealthController::latencyMs() const
{
    QMutexLocker locker(&m_mutex);
    return m_health.latencyMs;
}

bool ConnectionHealthController::hasPacketLoss() const
{
    QMutexLocker locker(&m_mutex);
    return m_health.packetLossPercent >= 0.0;
}

double ConnectionHealthController::packetLossPercent() const
{
    QMutexLocker locker(&m_mutex);
    return m_health.packetLossPercent;
}

bool ConnectionHealthController::originAuthenticated() const
{
    QMutexLocker locker(&m_mutex);
    return m_health.originAuthenticated;
}

bool ConnectionHealthController::tunnelPathVerified() const
{
    QMutexLocker locker(&m_mutex);
    return m_health.tunnelPathVerified;
}

QVariantMap ConnectionHealthController::healthSnapshot() const
{
    QMutexLocker locker(&m_mutex);
    return healthSnapshotLocked();
}

QVariantList ConnectionHealthController::flightRecorder() const
{
    QMutexLocker locker(&m_mutex);
    QVariantList result;
    result.reserve(m_flightRecorder.size());
    for (const QJsonObject &event : m_flightRecorder) {
        result.append(event.toVariantMap());
    }
    return result;
}

bool ConnectionHealthController::probeRunning() const
{
    return m_probeActive;
}

void ConnectionHealthController::startConnectivityProbe(QNetworkAccessManager *networkManager,
                                                         const QUrl &configuredEndpoint,
                                                         bool tunnelConnected, int timeoutMs,
                                                         bool tunnelPathVerified)
{
    cancelConnectivityProbe();
    m_probeFreshnessTimer.stop();

    const QUrl probeUrl = sanitizedProbeUrl(configuredEndpoint);
    if (!tunnelConnected) {
        recordProbeResult(false, false, false, -1.0, -1.0,
                          QStringLiteral("handshake_probe_failed"));
        evaluateRecovery(QStringLiteral("handshake_probe_failed"));
        return;
    }
    if (!networkManager || networkManager->thread() != thread()) {
        recordHealthState(HealthState::Unknown, QStringLiteral("service_unavailable"));
        recordEvent(QStringLiteral("probe"), QStringLiteral("probe_unavailable"),
                    { { QStringLiteral("reason_code"), QStringLiteral("service_unavailable") } });
        return;
    }
    if (!probeUrl.isValid() || probeUrl.host().isEmpty()) {
        recordHealthState(HealthState::Unknown, QStringLiteral("probe_endpoint_invalid"));
        recordEvent(QStringLiteral("probe"), QStringLiteral("probe_unavailable"),
                    { { QStringLiteral("reason_code"), QStringLiteral("probe_endpoint_invalid") } });
        return;
    }

    const quint64 generation = ++m_probeGeneration;
    m_probeActive = true;
    m_probeHandshakeOk = true;
    m_probeDnsDone = false;
    m_probeDnsOk = false;
    m_probeEgressDone = false;
    m_probeEgressOk = false;
    m_probeOriginAuthenticated = false;
    m_probeTunnelPathVerified = tunnelPathVerified;
    m_probeTlsErrors = false;
    m_probeLatencyMs = -1.0;
    m_probeElapsedTimer.restart();
    emit probeRunningChanged();

    recordEvent(QStringLiteral("probe"), QStringLiteral("started"),
                { { QStringLiteral("source"), QStringLiteral("connection_controller") },
                  { QStringLiteral("handshake_ok"), true },
                  { QStringLiteral("tunnel_path_verified"), tunnelPathVerified } });

    const int boundedTimeout = std::clamp(timeoutMs, kMinimumProbeTimeoutMs, kMaximumProbeTimeoutMs);
    m_probeTimeoutTimer.start(boundedTimeout);

    QHostAddress literalAddress;
    if (literalAddress.setAddress(probeUrl.host())) {
        m_probeDnsDone = true;
        m_probeDnsOk = !literalAddress.isNull();
    } else {
        m_probeLookupId = QHostInfo::lookupHost(
                probeUrl.host(), this, [this, generation](const QHostInfo &hostInfo) {
                    if (!m_probeActive || generation != m_probeGeneration) {
                        return;
                    }
                    m_probeLookupId = -1;
                    const QList<QHostAddress> addresses = hostInfo.addresses();
                    m_probeDnsDone = true;
                    m_probeDnsOk = hostInfo.error() == QHostInfo::NoError
                            && std::any_of(addresses.cbegin(), addresses.cend(),
                                           [](const QHostAddress &address) { return !address.isNull(); });
                    completeProbeIfReady(generation);
                });
    }

    QNetworkRequest request(probeUrl);
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute,
                         QNetworkRequest::ManualRedirectPolicy);
    request.setAttribute(QNetworkRequest::CacheLoadControlAttribute,
                         QNetworkRequest::AlwaysNetwork);
    request.setAttribute(QNetworkRequest::CacheSaveControlAttribute, false);
    request.setAttribute(QNetworkRequest::CookieLoadControlAttribute,
                         QNetworkRequest::Manual);
    request.setAttribute(QNetworkRequest::CookieSaveControlAttribute,
                         QNetworkRequest::Manual);
    request.setAttribute(QNetworkRequest::AuthenticationReuseAttribute,
                         QNetworkRequest::Manual);
    request.setTransferTimeout(boundedTimeout);
    request.setRawHeader("Cache-Control", "no-store");
    request.setHeader(QNetworkRequest::UserAgentHeader,
                      QStringLiteral("AmneziaVPN-Guardian/1"));

    m_probeReply = networkManager->head(request);
    const bool httpsOrigin = probeUrl.scheme() == QStringLiteral("https");
    const QPointer<QNetworkReply> guardedReply = m_probeReply;
    connect(m_probeReply, &QNetworkReply::sslErrors, this, [this, generation]() {
        if (m_probeActive && generation == m_probeGeneration) {
            m_probeTlsErrors = true;
        }
    });
    connect(m_probeReply, &QNetworkReply::finished, this, [this, generation, guardedReply, httpsOrigin]() {
        if (!guardedReply) {
            return;
        }
        if (!m_probeActive || generation != m_probeGeneration || guardedReply != m_probeReply) {
            guardedReply->deleteLater();
            return;
        }

        const bool replyTimedOut = guardedReply->error() == QNetworkReply::TimeoutError;
        const int httpStatus = guardedReply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        // The body and status meaning are deliberately ignored. Any syntactically valid
        // HTTP response proves that some egress path answered. Only an encrypted response
        // to a configured HTTPS origin is authenticated; redirects are never followed.
        m_probeEgressOk = httpStatus >= 100 && httpStatus <= 599;
        m_probeOriginAuthenticated = m_probeEgressOk && httpsOrigin && !m_probeTlsErrors
                && guardedReply->attribute(QNetworkRequest::ConnectionEncryptedAttribute).toBool();
        m_probeEgressDone = true;
        if (m_probeEgressOk && m_probeElapsedTimer.isValid()) {
            m_probeLatencyMs = static_cast<double>(m_probeElapsedTimer.elapsed());
        }
        m_probeReply = nullptr;
        guardedReply->deleteLater();
        if (replyTimedOut) {
            finishProbe(generation, true);
        } else {
            completeProbeIfReady(generation);
        }
    });

    completeProbeIfReady(generation);
}

void ConnectionHealthController::cancelConnectivityProbe(const QString &reason)
{
    m_probeFreshnessTimer.stop();
    if (!m_probeActive) {
        return;
    }

    ++m_probeGeneration;
    clearActiveProbe(true);
    recordEvent(QStringLiteral("probe"), QStringLiteral("probe_cancelled"),
                { { QStringLiteral("reason_code"), safeToken(reason, QStringLiteral("probe_cancelled")) } });
    emit probeRunningChanged();
}

bool ConnectionHealthController::recoveryPending() const
{
    QMutexLocker locker(&m_mutex);
    return m_recovery.pendingAction != RecoveryAction::None;
}

QString ConnectionHealthController::pendingRecoveryAction() const
{
    QMutexLocker locker(&m_mutex);
    return actionName(m_recovery.pendingAction);
}

int ConnectionHealthController::recoveryAttempts() const
{
    const QDateTime now = QDateTime::currentDateTimeUtc();
    QMutexLocker locker(&m_mutex);
    pruneRecoveryAttemptsLocked(now);
    return m_recovery.attempts.size();
}

int ConnectionHealthController::recoveryBudgetRemaining() const
{
    const QDateTime now = QDateTime::currentDateTimeUtc();
    QMutexLocker locker(&m_mutex);
    pruneRecoveryAttemptsLocked(now);
    return std::max(0, m_recovery.maxAttempts - static_cast<int>(m_recovery.attempts.size()));
}

int ConnectionHealthController::recoveryCooldownRemainingMs() const
{
    const QDateTime now = QDateTime::currentDateTimeUtc();
    QMutexLocker locker(&m_mutex);
    return cooldownRemainingMsLocked(now);
}

QJsonObject ConnectionHealthController::statusObject() const
{
    const QDateTime now = QDateTime::currentDateTimeUtc();
    QMutexLocker locker(&m_mutex);
    pruneRecoveryAttemptsLocked(now);
    return statusObjectLocked(now);
}

QJsonObject ConnectionHealthController::doctorObject() const
{
    const QDateTime now = QDateTime::currentDateTimeUtc();
    QMutexLocker locker(&m_mutex);
    pruneRecoveryAttemptsLocked(now);

    QJsonArray checks;
    QJsonArray recommendations;
    QString overall = QStringLiteral("ok");

    const auto addCheck = [&checks](const QString &id, const QString &status, const QString &reason) {
        checks.append(QJsonObject { { QStringLiteral("id"), id },
                                    { QStringLiteral("status"), status },
                                    { QStringLiteral("reason"), reason } });
    };

    const qint64 ageMs = m_health.lastProbeAt.isValid() ? m_health.lastProbeAt.msecsTo(now) : -1;
    if (ageMs < 0 || ageMs > kProbeStaleAfterMs) {
        addCheck(QStringLiteral("health_freshness"), QStringLiteral("warning"), QStringLiteral("probe_stale"));
        recommendations.append(QStringLiteral("run_connectivity_probe"));
        overall = QStringLiteral("warning");
    } else {
        addCheck(QStringLiteral("health_freshness"), QStringLiteral("ok"), QStringLiteral("probe_current"));
    }

    if (m_health.state == HealthState::Unhealthy) {
        addCheck(QStringLiteral("connection_health"), QStringLiteral("error"), m_health.lastReason);
        recommendations.append(QStringLiteral("evaluate_guardian_recovery"));
        overall = QStringLiteral("error");
    } else if (m_health.state == HealthState::Degraded || m_health.state == HealthState::Recovering) {
        addCheck(QStringLiteral("connection_health"), QStringLiteral("warning"), m_health.lastReason);
        recommendations.append(QStringLiteral("observe_or_recover"));
        if (overall == QStringLiteral("ok")) {
            overall = QStringLiteral("warning");
        }
    } else if (m_health.state == HealthState::Healthy) {
        addCheck(QStringLiteral("connection_health"), QStringLiteral("ok"), m_health.lastReason);
    } else {
        addCheck(QStringLiteral("connection_health"), QStringLiteral("warning"), QStringLiteral("not_observed"));
        recommendations.append(QStringLiteral("run_connectivity_probe"));
        if (overall == QStringLiteral("ok")) {
            overall = QStringLiteral("warning");
        }
    }

    if (m_health.latencyMs < 0.0 && m_health.packetLossPercent < 0.0) {
        addCheck(QStringLiteral("network_quality"), QStringLiteral("unknown"), QStringLiteral("metrics_not_supplied"));
    } else if (m_health.latencyMs >= kUnhealthyLatencyMs || m_health.packetLossPercent >= kUnhealthyPacketLossPercent) {
        addCheck(QStringLiteral("network_quality"), QStringLiteral("error"), QStringLiteral("quality_critical"));
        recommendations.append(QStringLiteral("try_alternative_path"));
        overall = QStringLiteral("error");
    } else if (m_health.latencyMs >= kDegradedLatencyMs || m_health.packetLossPercent >= kDegradedPacketLossPercent) {
        addCheck(QStringLiteral("network_quality"), QStringLiteral("warning"), QStringLiteral("quality_degraded"));
        recommendations.append(QStringLiteral("observe_network_quality"));
        if (overall == QStringLiteral("ok")) {
            overall = QStringLiteral("warning");
        }
    } else {
        addCheck(QStringLiteral("network_quality"), QStringLiteral("ok"), QStringLiteral("within_thresholds"));
    }

    const int budgetRemaining = std::max(0, m_recovery.maxAttempts - static_cast<int>(m_recovery.attempts.size()));
    if (budgetRemaining == 0) {
        addCheck(QStringLiteral("recovery_budget"), QStringLiteral("warning"), QStringLiteral("budget_exhausted"));
        recommendations.append(QStringLiteral("wait_for_budget_window"));
        if (overall == QStringLiteral("ok")) {
            overall = QStringLiteral("warning");
        }
    } else {
        addCheck(QStringLiteral("recovery_budget"), QStringLiteral("ok"), QStringLiteral("budget_available"));
    }

    if (m_recovery.pendingAction != RecoveryAction::None) {
        recommendations.append(QStringLiteral("report_recovery_result"));
    }

    return QJsonObject { { QStringLiteral("schema_version"), 1 },
                         { QStringLiteral("generated_at"), isoUtc(now) },
                         { QStringLiteral("overall"), overall },
                         { QStringLiteral("checks"), checks },
                         { QStringLiteral("recommendations"), recommendations },
                         { QStringLiteral("status"), statusObjectLocked(now) } };
}

QString ConnectionHealthController::statusJson(bool pretty) const
{
    return QString::fromUtf8(
            QJsonDocument(statusObject()).toJson(pretty ? QJsonDocument::Indented : QJsonDocument::Compact));
}

QString ConnectionHealthController::doctorJson(bool pretty) const
{
    return QString::fromUtf8(
            QJsonDocument(doctorObject()).toJson(pretty ? QJsonDocument::Indented : QJsonDocument::Compact));
}

void ConnectionHealthController::recordHealthState(HealthState state, const QString &reason,
                                                   bool originAuthenticated, bool tunnelPathVerified)
{
    HealthState effectiveState = state;
    QString effectiveReason = reason;
    if (effectiveState == HealthState::Healthy && !originAuthenticated) {
        effectiveState = HealthState::Degraded;
        effectiveReason = QStringLiteral("egress_unverified");
    } else if (effectiveState == HealthState::Healthy && !tunnelPathVerified) {
        effectiveState = HealthState::Degraded;
        effectiveReason = QStringLiteral("tunnel_path_unverified");
    }

    // A state-only observation starts a new observation epoch. It must not
    // inherit freshness or quality metrics from a probe performed for an
    // earlier connection/network state. Only recordProbeResult() owns those
    // fields and arms the corresponding freshness timer.
    m_probeFreshnessTimer.stop();
    const QDateTime now = QDateTime::currentDateTimeUtc();
    const QString reasonCode = safeToken(effectiveReason, QStringLiteral("state_observed"));
    bool stateChanged = false;
    bool recoveryExpired = false;

    {
        QMutexLocker locker(&m_mutex);
        const HealthState previousState = m_health.state;
        stateChanged = previousState != effectiveState;
        m_health.state = effectiveState;
        m_health.lastReason = reasonCode;
        m_health.lastUpdatedAt = now;
        m_health.lastProbeAt = QDateTime();
        m_health.latencyMs = -1.0;
        m_health.packetLossPercent = -1.0;
        m_health.originAuthenticated = originAuthenticated;
        m_health.tunnelPathVerified = tunnelPathVerified;

        const RecoveryAction supersededAction = m_recovery.pendingAction;
        recoveryExpired = supersededAction != RecoveryAction::None;
        if (recoveryExpired) {
            m_recovery.pendingAction = RecoveryAction::None;
        }

        if (stateChanged) {
            m_health.lastStateChangedAt = now;
        }
        if (effectiveState == HealthState::Healthy) {
            m_health.lastHealthyAt = now;
            m_health.unhealthySince = QDateTime();
            m_recovery.nextActionIndex = 0;
            m_recovery.pendingAction = RecoveryAction::None;
        } else if (effectiveState == HealthState::Unhealthy && !m_health.unhealthySince.isValid()) {
            m_health.unhealthySince = now;
        } else if (effectiveState != HealthState::Unhealthy) {
            m_health.unhealthySince = QDateTime();
        }

        appendEventLocked(QStringLiteral("health"),
                          stateChanged ? QStringLiteral("state_changed") : QStringLiteral("state_observed"),
                          { { QStringLiteral("previous_state"), stateName(previousState) },
                            { QStringLiteral("state"), stateName(effectiveState) },
                            { QStringLiteral("reason_code"), reasonCode },
                            { QStringLiteral("origin_authenticated"), originAuthenticated },
                            { QStringLiteral("tunnel_path_verified"), tunnelPathVerified } });
        if (recoveryExpired) {
            appendEventLocked(QStringLiteral("recovery"), QStringLiteral("superseded"),
                              { { QStringLiteral("action"), actionName(supersededAction) },
                                { QStringLiteral("reason_code"), QStringLiteral("new_health_observation") } });
        }
    }

    emit healthSnapshotChanged();
    emit flightRecorderChanged();
    if (effectiveState == HealthState::Healthy || recoveryExpired) {
        emit recoveryPolicyChanged();
    }
}

void ConnectionHealthController::recordProbeResult(bool handshakeOk, bool dnsOk, bool egressOk, double latencyMs,
                                                    double packetLossPercent, const QString &reason,
                                                    bool originAuthenticated, bool tunnelPathVerified)
{
    const QDateTime now = QDateTime::currentDateTimeUtc();
    const double safeLatency = isFiniteMetric(latencyMs) && latencyMs >= 0.0 ? latencyMs : -1.0;
    const double safeLoss =
            isFiniteMetric(packetLossPercent) && packetLossPercent >= 0.0 ? std::min(packetLossPercent, 100.0) : -1.0;

    HealthState state = HealthState::Healthy;
    QString inferredReason = QStringLiteral("connectivity_probe_ok");
    if (!handshakeOk) {
        state = HealthState::Unhealthy;
        inferredReason = QStringLiteral("handshake_probe_failed");
    } else if (!egressOk) {
        state = HealthState::Unhealthy;
        inferredReason = QStringLiteral("egress_probe_failed");
    } else if (!originAuthenticated) {
        // Plain HTTP, a captive portal, or a proxy-generated response proves that
        // some egress path answered, not that the configured origin did. Preserve
        // this useful signal without labelling it end-to-end healthy.
        state = HealthState::Degraded;
        inferredReason = QStringLiteral("egress_unverified");
    } else if (!tunnelPathVerified) {
        // Authenticating the configured HTTPS origin proves who answered, but
        // not which interface or route carried the request. Without a separate
        // path guarantee this is useful egress evidence, never tunnel health.
        state = HealthState::Degraded;
        inferredReason = QStringLiteral("tunnel_path_unverified");
    } else if (!dnsOk) {
        // A completed HTTP exchange proves that the configured endpoint was
        // reachable, even when the independent resolver lookup failed (for
        // example because QNetworkAccessManager used a proxy or a warm cache).
        // Preserve the disagreement as degraded instead of claiming total loss.
        state = HealthState::Degraded;
        inferredReason = QStringLiteral("dns_probe_failed");
    } else if (safeLatency >= kUnhealthyLatencyMs || safeLoss >= kUnhealthyPacketLossPercent) {
        state = HealthState::Unhealthy;
        inferredReason = QStringLiteral("network_quality_critical");
    } else if (safeLatency >= kDegradedLatencyMs || safeLoss >= kDegradedPacketLossPercent) {
        state = HealthState::Degraded;
        inferredReason = QStringLiteral("network_quality_degraded");
    }

    const QString reasonCode = safeToken(reason, inferredReason);
    bool recoveryExpired = false;
    {
        QMutexLocker locker(&m_mutex);
        const HealthState previousState = m_health.state;
        m_health.state = state;
        m_health.lastReason = reasonCode;
        m_health.lastUpdatedAt = now;
        m_health.lastProbeAt = now;
        m_health.latencyMs = safeLatency;
        m_health.packetLossPercent = safeLoss;
        m_health.originAuthenticated = originAuthenticated;
        m_health.tunnelPathVerified = tunnelPathVerified;

        const RecoveryAction supersededAction = m_recovery.pendingAction;
        recoveryExpired = supersededAction != RecoveryAction::None;
        if (recoveryExpired) {
            m_recovery.pendingAction = RecoveryAction::None;
        }

        if (previousState != state) {
            m_health.lastStateChangedAt = now;
        }
        if (state == HealthState::Healthy) {
            m_health.lastHealthyAt = now;
            m_health.unhealthySince = QDateTime();
            m_recovery.nextActionIndex = 0;
            m_recovery.pendingAction = RecoveryAction::None;
        } else if (state == HealthState::Unhealthy && !m_health.unhealthySince.isValid()) {
            m_health.unhealthySince = now;
        } else if (state != HealthState::Unhealthy) {
            m_health.unhealthySince = QDateTime();
        }

        QVariantMap details { { QStringLiteral("previous_state"), stateName(previousState) },
                              { QStringLiteral("state"), stateName(state) },
                              { QStringLiteral("reason_code"), reasonCode },
                              { QStringLiteral("handshake_ok"), handshakeOk },
                              { QStringLiteral("dns_ok"), dnsOk },
                              { QStringLiteral("egress_ok"), egressOk },
                              { QStringLiteral("origin_authenticated"), originAuthenticated },
                              { QStringLiteral("tunnel_path_verified"), tunnelPathVerified } };
        if (safeLatency >= 0.0) {
            details.insert(QStringLiteral("latency_ms"), safeLatency);
        }
        if (safeLoss >= 0.0) {
            details.insert(QStringLiteral("packet_loss_percent"), safeLoss);
        }
        appendEventLocked(QStringLiteral("probe"), QStringLiteral("completed"), details);
        if (recoveryExpired) {
            appendEventLocked(QStringLiteral("recovery"), QStringLiteral("superseded"),
                              { { QStringLiteral("action"), actionName(supersededAction) },
                                { QStringLiteral("reason_code"), QStringLiteral("new_probe_observation") } });
        }
    }

    m_probeFreshnessTimer.start();
    emit healthSnapshotChanged();
    emit flightRecorderChanged();
    if (state == HealthState::Healthy || recoveryExpired) {
        emit recoveryPolicyChanged();
    }
}

void ConnectionHealthController::recordEvent(const QString &category, const QString &outcome,
                                             const QVariantMap &privacySafeDetails)
{
    {
        QMutexLocker locker(&m_mutex);
        appendEventLocked(safeToken(category, QStringLiteral("event")), safeToken(outcome, QStringLiteral("observed")),
                          privacySafeDetails);
    }
    emit flightRecorderChanged();
}

QVariantMap ConnectionHealthController::evaluateRecovery(const QString &triggerReason)
{
    const QDateTime now = QDateTime::currentDateTimeUtc();
    RecoveryAction suggestedAction = RecoveryAction::None;
    QString decisionReason;
    int attempt = 0;
    QVariantMap decision;

    {
        QMutexLocker locker(&m_mutex);
        pruneRecoveryAttemptsLocked(now);
        const QString triggerCode = safeToken(triggerReason, m_health.lastReason);

        if (m_health.state == HealthState::Healthy) {
            decisionReason = QStringLiteral("health_is_healthy");
        } else if (m_health.state == HealthState::Unknown) {
            decisionReason = QStringLiteral("health_not_observed");
        } else if (m_recovery.pendingAction != RecoveryAction::None) {
            decisionReason = QStringLiteral("recovery_result_pending");
        } else if (cooldownRemainingMsLocked(now) > 0) {
            decisionReason = QStringLiteral("cooldown_active");
        } else if (m_recovery.attempts.size() >= m_recovery.maxAttempts) {
            decisionReason = QStringLiteral("retry_budget_exhausted");
        } else {
            const int lastActionIndex = static_cast<int>(kRecoveryLadder.size()) - 1;
            const int actionIndex = std::clamp(m_recovery.nextActionIndex, 0, lastActionIndex);
            suggestedAction = kRecoveryLadder.at(actionIndex);
            m_recovery.pendingAction = suggestedAction;
            m_recovery.lastDecisionAt = now;
            m_recovery.attempts.append(now);
            attempt = static_cast<int>(m_recovery.attempts.size());
            decisionReason = triggerCode;
        }

        const int cooldownRemaining = cooldownRemainingMsLocked(now);
        const int budgetRemaining = std::max(0, m_recovery.maxAttempts - static_cast<int>(m_recovery.attempts.size()));
        decision = { { QStringLiteral("accepted"), suggestedAction != RecoveryAction::None },
                     { QStringLiteral("action"), actionName(suggestedAction) },
                     { QStringLiteral("reason"), decisionReason },
                     { QStringLiteral("attempt"), attempt },
                     { QStringLiteral("budget_remaining"), budgetRemaining },
                     { QStringLiteral("cooldown_remaining_ms"), cooldownRemaining } };

        appendEventLocked(QStringLiteral("recovery"),
                          suggestedAction == RecoveryAction::None ? QStringLiteral("deferred")
                                                                  : QStringLiteral("suggested"),
                          { { QStringLiteral("accepted"), suggestedAction != RecoveryAction::None },
                            { QStringLiteral("action"), actionName(suggestedAction) },
                            { QStringLiteral("reason_code"), decisionReason },
                            { QStringLiteral("attempt"), attempt },
                            { QStringLiteral("budget_remaining"), budgetRemaining },
                            { QStringLiteral("cooldown_ms"), cooldownRemaining } });
    }

    emit recoveryPolicyChanged();
    emit flightRecorderChanged();
    if (suggestedAction != RecoveryAction::None) {
        emit recoverySuggested(suggestedAction, decisionReason, attempt);
    }
    return decision;
}

void ConnectionHealthController::acknowledgeRecoveryResult(bool success, const QString &reason)
{
    bool hadPendingAction = false;
    {
        QMutexLocker locker(&m_mutex);
        const RecoveryAction action = m_recovery.pendingAction;
        hadPendingAction = action != RecoveryAction::None;
        const QString reasonCode = safeToken(
                reason,
                hadPendingAction ? (success ? QStringLiteral("recovery_succeeded") : QStringLiteral("recovery_failed"))
                                 : QStringLiteral("no_recovery_pending"));

        if (hadPendingAction) {
            if (success) {
                m_recovery.nextActionIndex = 0;
            } else {
                const int lastActionIndex = static_cast<int>(kRecoveryLadder.size()) - 1;
                m_recovery.nextActionIndex = std::min(m_recovery.nextActionIndex + 1, lastActionIndex);
            }
            m_recovery.pendingAction = RecoveryAction::None;
        }

        appendEventLocked(QStringLiteral("recovery"),
                          hadPendingAction ? (success ? QStringLiteral("succeeded") : QStringLiteral("failed"))
                                           : QStringLiteral("result_ignored"),
                          { { QStringLiteral("action"), actionName(action) },
                            { QStringLiteral("success"), success },
                            { QStringLiteral("reason_code"), reasonCode } });
    }

    emit flightRecorderChanged();
    if (hadPendingAction) {
        emit recoveryPolicyChanged();
    }
}

void ConnectionHealthController::resetRecoveryPolicy()
{
    {
        QMutexLocker locker(&m_mutex);
        m_recovery.nextActionIndex = 0;
        m_recovery.pendingAction = RecoveryAction::None;
        m_recovery.lastDecisionAt = QDateTime();
        m_recovery.attempts.clear();
        appendEventLocked(QStringLiteral("recovery"), QStringLiteral("policy_reset"), QVariantMap());
    }
    emit recoveryPolicyChanged();
    emit flightRecorderChanged();
}

void ConnectionHealthController::configureRecoveryPolicy(int cooldownMs, int maxAttempts, int budgetWindowMs)
{
    const int boundedCooldown = std::clamp(cooldownMs, kMinimumCooldownMs, kMaximumCooldownMs);
    const int boundedAttempts = std::clamp(maxAttempts, 1, kMaximumRecoveryAttempts);
    const int boundedWindow = std::clamp(budgetWindowMs, kMinimumBudgetWindowMs, kMaximumBudgetWindowMs);

    {
        QMutexLocker locker(&m_mutex);
        m_recovery.cooldownMs = boundedCooldown;
        m_recovery.maxAttempts = boundedAttempts;
        m_recovery.budgetWindowMs = boundedWindow;
        pruneRecoveryAttemptsLocked(QDateTime::currentDateTimeUtc());
        appendEventLocked(QStringLiteral("recovery"), QStringLiteral("policy_configured"),
                          { { QStringLiteral("cooldown_ms"), boundedCooldown },
                            { QStringLiteral("max_attempts"), boundedAttempts },
                            { QStringLiteral("window_ms"), boundedWindow } });
    }
    emit recoveryPolicyChanged();
    emit flightRecorderChanged();
}

void ConnectionHealthController::setFlightRecorderCapacity(int capacity)
{
    const int boundedCapacity = std::clamp(capacity, kMinimumRecorderCapacity, kMaximumRecorderCapacity);
    bool changed = false;
    {
        QMutexLocker locker(&m_mutex);
        if (m_flightRecorderCapacity == boundedCapacity) {
            return;
        }
        m_flightRecorderCapacity = boundedCapacity;
        while (m_flightRecorder.size() > m_flightRecorderCapacity) {
            m_flightRecorder.removeFirst();
        }
        changed = true;
        appendEventLocked(QStringLiteral("guardian"), QStringLiteral("recorder_resized"),
                          { { QStringLiteral("count"), boundedCapacity } });
    }
    if (changed) {
        emit flightRecorderChanged();
    }
}

QString ConnectionHealthController::stateName(HealthState state)
{
    switch (state) {
    case HealthState::Unknown: return QStringLiteral("unknown");
    case HealthState::Healthy: return QStringLiteral("healthy");
    case HealthState::Degraded: return QStringLiteral("degraded");
    case HealthState::Unhealthy: return QStringLiteral("unhealthy");
    case HealthState::Recovering: return QStringLiteral("recovering");
    }
    return QStringLiteral("unknown");
}

QString ConnectionHealthController::actionName(RecoveryAction action)
{
    switch (action) {
    case RecoveryAction::None: return QStringLiteral("none");
    case RecoveryAction::RefreshNetwork: return QStringLiteral("refresh_network");
    case RecoveryAction::RepairDns: return QStringLiteral("repair_dns");
    case RecoveryAction::RepairRoutes: return QStringLiteral("repair_routes");
    case RecoveryAction::ReconnectTunnel: return QStringLiteral("reconnect_tunnel");
    case RecoveryAction::SwitchProtocol: return QStringLiteral("switch_protocol");
    case RecoveryAction::SwitchServer: return QStringLiteral("switch_server");
    }
    return QStringLiteral("none");
}

QString ConnectionHealthController::safeToken(const QString &value, const QString &fallback)
{
    const QString normalized = value.trimmed().toLower();
    if (normalized.isEmpty()) {
        return fallback;
    }

    static const QSet<QString> retainedTokens { QStringLiteral("accepted"),
                                                QStringLiteral("awaiting_probe"),
                                                QStringLiteral("awg"),
                                                QStringLiteral("completed"),
                                                QStringLiteral("connection_controller"),
                                                QStringLiteral("connectivity_probe_ok"),
                                                QStringLiteral("cooldown_active"),
                                                QStringLiteral("deferred"),
                                                QStringLiteral("degraded"),
                                                QStringLiteral("dns_probe_failed"),
                                                QStringLiteral("event"),
                                                QStringLiteral("egress_probe_failed"),
                                                QStringLiteral("egress_unverified"),
                                                QStringLiteral("failed"),
                                                QStringLiteral("guardian"),
                                                 QStringLiteral("handshake_probe_failed"),
                                                 QStringLiteral("health"),
                                                 QStringLiteral("health_is_healthy"),
                                                 QStringLiteral("health_not_observed"),
                                                 QStringLiteral("healthy"),
                                                 QStringLiteral("hint_offline"),
                                                 QStringLiteral("ikev2"),
                                                QStringLiteral("initialized"),
                                                QStringLiteral("manual"),
                                                QStringLiteral("network_probe"),
                                                 QStringLiteral("network_quality_critical"),
                                                 QStringLiteral("network_quality_degraded"),
                                                 QStringLiteral("new_health_observation"),
                                                 QStringLiteral("new_probe_observation"),
                                                QStringLiteral("no_recovery_pending"),
                                                QStringLiteral("none"),
                                                QStringLiteral("not_observed"),
                                                QStringLiteral("observed"),
                                                QStringLiteral("openvpn"),
                                                QStringLiteral("policy_configured"),
                                                QStringLiteral("policy_reset"),
                                                QStringLiteral("probe"),
                                                QStringLiteral("probe_cancelled"),
                                                QStringLiteral("probe_endpoint_invalid"),
                                                QStringLiteral("probe_stale"),
                                                 QStringLiteral("probe_timeout"),
                                                 QStringLiteral("probe_unavailable"),
                                                 QStringLiteral("protocol_fallback"),
                                                 QStringLiteral("reachability"),
                                                 QStringLiteral("reachability_hint_offline"),
                                                 QStringLiteral("reachability_offline"),
                                                 QStringLiteral("reachability_online"),
                                                QStringLiteral("reconnect_tunnel"),
                                                QStringLiteral("recorder_resized"),
                                                QStringLiteral("recovering"),
                                                QStringLiteral("recovery"),
                                                QStringLiteral("recovery_failed"),
                                                QStringLiteral("recovery_result_pending"),
                                                QStringLiteral("recovery_succeeded"),
                                                QStringLiteral("refresh_network"),
                                                QStringLiteral("repair_dns"),
                                                QStringLiteral("repair_routes"),
                                                QStringLiteral("result_ignored"),
                                                QStringLiteral("retry_budget_exhausted"),
                                                QStringLiteral("service_unavailable"),
                                                QStringLiteral("state_changed"),
                                                QStringLiteral("state_observed"),
                                                QStringLiteral("started"),
                                                 QStringLiteral("succeeded"),
                                                 QStringLiteral("suggested"),
                                                 QStringLiteral("superseded"),
                                                QStringLiteral("switch_protocol"),
                                                QStringLiteral("switch_server"),
                                                QStringLiteral("system"),
                                                QStringLiteral("tunnel_connected"),
                                                QStringLiteral("tunnel_connecting"),
                                                 QStringLiteral("tunnel_disconnected"),
                                                 QStringLiteral("tunnel_error"),
                                                 QStringLiteral("tunnel_path_unverified"),
                                                 QStringLiteral("unhealthy"),
                                                QStringLiteral("unknown"),
                                                QStringLiteral("wireguard"),
                                                QStringLiteral("xray") };

    bool symbolic =
            normalized.size() <= 64 && normalized.front() >= QLatin1Char('a') && normalized.front() <= QLatin1Char('z');
    for (const QChar ch : normalized) {
        const bool asciiAlpha = ch >= QLatin1Char('a') && ch <= QLatin1Char('z');
        const bool asciiDigit = ch >= QLatin1Char('0') && ch <= QLatin1Char('9');
        if (!(asciiAlpha || asciiDigit || ch == QLatin1Char('_') || ch == QLatin1Char('-'))) {
            symbolic = false;
            break;
        }
    }
    if (symbolic && retainedTokens.contains(normalized)) {
        return normalized;
    }

    const QByteArray digest = QCryptographicHash::hash(normalized.toUtf8(), QCryptographicHash::Sha256).toHex().left(12);
    return QStringLiteral("redacted_%1").arg(QString::fromLatin1(digest));
}

QVariantMap ConnectionHealthController::safeDetails(const QVariantMap &details)
{
    static const QSet<QString> numericKeys { QStringLiteral("attempt"),
                                             QStringLiteral("budget_remaining"),
                                             QStringLiteral("cooldown_ms"),
                                             QStringLiteral("count"),
                                             QStringLiteral("latency_ms"),
                                             QStringLiteral("max_attempts"),
                                             QStringLiteral("packet_loss_percent"),
                                             QStringLiteral("window_ms") };
    static const QSet<QString> booleanKeys { QStringLiteral("accepted"), QStringLiteral("authoritative"),
                                             QStringLiteral("dns_ok"),
                                             QStringLiteral("egress_ok"), QStringLiteral("handshake_ok"),
                                             QStringLiteral("origin_authenticated"), QStringLiteral("success"),
                                             QStringLiteral("tunnel_path_verified") };
    static const QSet<QString> tokenKeys { QStringLiteral("action"),         QStringLiteral("outcome"),
                                           QStringLiteral("previous_state"), QStringLiteral("probe"),
                                           QStringLiteral("protocol"),       QStringLiteral("reason_code"),
                                           QStringLiteral("source"),         QStringLiteral("state") };

    QVariantMap sanitized;
    for (auto it = details.cbegin(); it != details.cend(); ++it) {
        const QString key = it.key().trimmed().toLower();
        if (numericKeys.contains(key)) {
            bool ok = false;
            const double value = it.value().toDouble(&ok);
            if (ok && isFiniteMetric(value)) {
                sanitized.insert(key, value);
            }
        } else if (booleanKeys.contains(key)) {
            sanitized.insert(key, it.value().toBool());
        } else if (tokenKeys.contains(key)) {
            sanitized.insert(key, safeToken(it.value().toString(), QStringLiteral("unknown")));
        }
    }
    return sanitized;
}

QJsonObject ConnectionHealthController::variantMapToJson(const QVariantMap &map)
{
    return QJsonObject::fromVariantMap(map);
}

int ConnectionHealthController::boundedDurationMs(qint64 value)
{
    if (value <= 0) {
        return 0;
    }
    return value > std::numeric_limits<int>::max() ? std::numeric_limits<int>::max() : static_cast<int>(value);
}

QUrl ConnectionHealthController::sanitizedProbeUrl(const QUrl &configuredEndpoint)
{
    if (!configuredEndpoint.isValid()) {
        return {};
    }

    const QString scheme = configuredEndpoint.scheme().trimmed().toLower();
    if (scheme != QStringLiteral("http") && scheme != QStringLiteral("https")) {
        return {};
    }

    const QString host = configuredEndpoint.host();
    if (host.isEmpty()) {
        return {};
    }

    // Probe the origin root only. A custom gateway path, userinfo, query or
    // fragment may contain opaque deployment credentials and is unnecessary:
    // any HTTP response at the same origin is sufficient for reachability.
    QUrl sanitized;
    sanitized.setScheme(scheme);
    sanitized.setHost(host);
    sanitized.setPort(configuredEndpoint.port(-1));
    sanitized.setPath(QStringLiteral("/"));
    return sanitized;
}

void ConnectionHealthController::completeProbeIfReady(quint64 generation)
{
    if (!m_probeActive || generation != m_probeGeneration
        || !m_probeDnsDone || !m_probeEgressDone) {
        return;
    }
    finishProbe(generation, false);
}

void ConnectionHealthController::finishProbe(quint64 generation, bool timedOut)
{
    if (!m_probeActive || generation != m_probeGeneration) {
        return;
    }

    const bool handshakeOk = m_probeHandshakeOk;
    const bool dnsOk = m_probeDnsDone && m_probeDnsOk;
    const bool egressOk = m_probeEgressDone && m_probeEgressOk;
    const bool originAuthenticated = egressOk && m_probeOriginAuthenticated;
    const bool tunnelPathVerified = egressOk && m_probeTunnelPathVerified;
    const double latencyMs = egressOk ? m_probeLatencyMs : -1.0;
    const QString reason = timedOut ? QStringLiteral("probe_timeout") : QString();

    clearActiveProbe(timedOut);
    emit probeRunningChanged();

    // A single bounded request cannot measure packet loss, so leave that metric
    // explicitly unavailable instead of manufacturing a percentage.
    recordProbeResult(handshakeOk, dnsOk, egressOk, latencyMs, -1.0, reason,
                      originAuthenticated, tunnelPathVerified);
    if (healthState() == HealthState::Unhealthy) {
        evaluateRecovery(reason.isEmpty() ? lastReason() : reason);
    }
}

void ConnectionHealthController::clearActiveProbe(bool abortOperations)
{
    m_probeActive = false;
    m_probeTimeoutTimer.stop();

    const int lookupId = m_probeLookupId;
    m_probeLookupId = -1;
    if (abortOperations && lookupId >= 0) {
        QHostInfo::abortHostLookup(lookupId);
    }

    const QPointer<QNetworkReply> reply = m_probeReply;
    m_probeReply = nullptr;
    if (reply) {
        QObject::disconnect(reply, nullptr, this, nullptr);
        if (abortOperations && !reply->isFinished()) {
            reply->abort();
        }
        reply->deleteLater();
    }

    m_probeHandshakeOk = false;
    m_probeDnsDone = false;
    m_probeDnsOk = false;
    m_probeEgressDone = false;
    m_probeEgressOk = false;
    m_probeOriginAuthenticated = false;
    m_probeTunnelPathVerified = false;
    m_probeTlsErrors = false;
    m_probeLatencyMs = -1.0;
    m_probeElapsedTimer.invalidate();
}

void ConnectionHealthController::appendEventLocked(const QString &category, const QString &outcome,
                                                   const QVariantMap &details)
{
    QJsonObject event { { QStringLiteral("sequence"), m_nextEventSequence++ },
                        { QStringLiteral("timestamp"), isoUtc(QDateTime::currentDateTimeUtc()) },
                        { QStringLiteral("category"), safeToken(category, QStringLiteral("event")) },
                        { QStringLiteral("outcome"), safeToken(outcome, QStringLiteral("observed")) } };
    const QVariantMap sanitizedDetails = safeDetails(details);
    if (!sanitizedDetails.isEmpty()) {
        event.insert(QStringLiteral("details"), variantMapToJson(sanitizedDetails));
    }

    m_flightRecorder.append(event);
    while (m_flightRecorder.size() > m_flightRecorderCapacity) {
        m_flightRecorder.removeFirst();
    }
}

void ConnectionHealthController::pruneRecoveryAttemptsLocked(const QDateTime &now) const
{
    while (!m_recovery.attempts.isEmpty() && m_recovery.attempts.first().msecsTo(now) >= m_recovery.budgetWindowMs) {
        m_recovery.attempts.removeFirst();
    }
}

int ConnectionHealthController::cooldownRemainingMsLocked(const QDateTime &now) const
{
    if (!m_recovery.lastDecisionAt.isValid()) {
        return 0;
    }
    return boundedDurationMs(m_recovery.cooldownMs - m_recovery.lastDecisionAt.msecsTo(now));
}

QVariantMap ConnectionHealthController::healthSnapshotLocked() const
{
    QVariantMap snapshot { { QStringLiteral("state"), stateName(m_health.state) },
                           { QStringLiteral("reason"), m_health.lastReason },
                           { QStringLiteral("last_updated_at"), isoUtc(m_health.lastUpdatedAt) },
                           { QStringLiteral("last_probe_at"), isoUtc(m_health.lastProbeAt) },
                           { QStringLiteral("last_state_changed_at"), isoUtc(m_health.lastStateChangedAt) },
                           { QStringLiteral("last_healthy_at"), isoUtc(m_health.lastHealthyAt) },
                           { QStringLiteral("unhealthy_since"), isoUtc(m_health.unhealthySince) },
                           { QStringLiteral("has_latency"), m_health.latencyMs >= 0.0 },
                           { QStringLiteral("has_packet_loss"), m_health.packetLossPercent >= 0.0 },
                           { QStringLiteral("origin_authenticated"), m_health.originAuthenticated },
                           { QStringLiteral("tunnel_path_verified"), m_health.tunnelPathVerified } };
    if (m_health.latencyMs >= 0.0) {
        snapshot.insert(QStringLiteral("latency_ms"), m_health.latencyMs);
    }
    if (m_health.packetLossPercent >= 0.0) {
        snapshot.insert(QStringLiteral("packet_loss_percent"), m_health.packetLossPercent);
    }
    return snapshot;
}

QVariantMap ConnectionHealthController::recoverySnapshotLocked(const QDateTime &now) const
{
    return { { QStringLiteral("mode"), QStringLiteral("recommendation_only") },
             { QStringLiteral("pending"), m_recovery.pendingAction != RecoveryAction::None },
             { QStringLiteral("pending_action"), actionName(m_recovery.pendingAction) },
             { QStringLiteral("attempts"), static_cast<int>(m_recovery.attempts.size()) },
             { QStringLiteral("max_attempts"), m_recovery.maxAttempts },
             { QStringLiteral("budget_remaining"),
               std::max(0, m_recovery.maxAttempts - static_cast<int>(m_recovery.attempts.size())) },
             { QStringLiteral("budget_window_ms"), m_recovery.budgetWindowMs },
             { QStringLiteral("cooldown_ms"), m_recovery.cooldownMs },
             { QStringLiteral("cooldown_remaining_ms"), cooldownRemainingMsLocked(now) } };
}

QJsonObject ConnectionHealthController::statusObjectLocked(const QDateTime &now) const
{
    QJsonArray events;
    for (const QJsonObject &event : m_flightRecorder) {
        events.append(event);
    }
    return { { QStringLiteral("schema_version"), 1 },
             { QStringLiteral("generated_at"), isoUtc(now) },
             { QStringLiteral("health"), variantMapToJson(healthSnapshotLocked()) },
             { QStringLiteral("recovery"), variantMapToJson(recoverySnapshotLocked(now)) },
             { QStringLiteral("flight_recorder"), events } };
}
