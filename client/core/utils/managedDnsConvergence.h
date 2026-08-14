#ifndef MANAGEDDNSCONVERGENCE_H
#define MANAGEDDNSCONVERGENCE_H

#include <QDateTime>
#include <QJsonObject>
#include <QString>
#include <QStringList>
#include <QtGlobal>
#include <limits>

namespace amnezia::managedDnsConvergence
{
inline int initialDelayMs(const QString &retryAfterIso, const QDateTime &nowUtc,
                          int defaultDelayMs)
{
    const QDateTime retryAfter = QDateTime::fromString(retryAfterIso, Qt::ISODate);
    if (!retryAfter.isValid()) {
        return defaultDelayMs;
    }
    const qint64 retryDelayMs = nowUtc.toUTC().msecsTo(retryAfter.toUTC());
    if (retryDelayMs <= 0) {
        return defaultDelayMs;
    }
    return static_cast<int>(qMin<qint64>(retryDelayMs, (std::numeric_limits<int>::max)()));
}

inline QStringList pendingDomainsForCycle(const QStringList &domains,
                                          const QJsonObject &baseline,
                                          const QStringList &persistedPending,
                                          bool refreshAll)
{
    QStringList pending;
    for (const QString &domain : domains) {
        if (pending.contains(domain)) {
            continue;
        }
        if (refreshAll || persistedPending.contains(domain)
            || !baseline.contains(domain)
            || baseline.value(domain).toString().trimmed().isEmpty()) {
            pending.append(domain);
        }
    }
    return pending;
}

inline bool fullSweepDue(const QString &lastFullSweepAtIso,
                         const QDateTime &nowUtc,
                         int refreshIntervalSeconds)
{
    if (refreshIntervalSeconds <= 0) {
        return true;
    }
    const QDateTime lastFullSweepAt =
            QDateTime::fromString(lastFullSweepAtIso, Qt::ISODate);
    if (!lastFullSweepAt.isValid()) {
        return true;
    }
    if (lastFullSweepAt.toUTC() > nowUtc.toUTC().addSecs(10 * 60)) {
        return true;
    }
    return lastFullSweepAt.toUTC().addSecs(refreshIntervalSeconds)
            <= nowUtc.toUTC();
}

inline bool completeCacheRefreshDue(const QString &lastFullSweepAtIso,
                                    const QString &resolvedAtIso,
                                    const QDateTime &nowUtc,
                                    int refreshIntervalSeconds)
{
    const QDateTime lastFullSweepAt =
            QDateTime::fromString(lastFullSweepAtIso, Qt::ISODate);
    return fullSweepDue(
            lastFullSweepAt.isValid() ? lastFullSweepAtIso : resolvedAtIso,
            nowUtc, refreshIntervalSeconds);
}

class ReconnectGate final
{
public:
    struct Request final
    {
        bool accepted = false;
        bool newlyPending = false;
        qint64 delayMs = 0;
    };

    void beginSession(const QString &serverId)
    {
        m_serverId = serverId;
        m_immediateAvailable = !serverId.isEmpty();
        m_pending = false;
        m_lastReconnectMs = -1;
    }

    void clear()
    {
        m_serverId.clear();
        m_immediateAvailable = false;
        m_pending = false;
        m_lastReconnectMs = -1;
    }

    Request request(const QString &serverId, qint64 nowMs, qint64 minimumIntervalMs)
    {
        Request result;
        if (serverId.isEmpty() || serverId != m_serverId || nowMs < 0
            || minimumIntervalMs < 0) {
            return result;
        }

        result.accepted = true;
        if (m_pending) {
            result.delayMs = remainingDelayMs(nowMs, minimumIntervalMs);
            return result;
        }

        m_pending = true;
        result.newlyPending = true;
        result.delayMs = remainingDelayMs(nowMs, minimumIntervalMs);
        return result;
    }

    bool takeDue(const QString &serverId, qint64 nowMs, qint64 minimumIntervalMs)
    {
        if (!m_pending || serverId != m_serverId
            || remainingDelayMs(nowMs, minimumIntervalMs) > 0) {
            return false;
        }
        m_pending = false;
        return true;
    }

    void recordReconnect(const QString &serverId, qint64 nowMs)
    {
        if (serverId != m_serverId || nowMs < 0) {
            return;
        }
        m_immediateAvailable = false;
        m_lastReconnectMs = nowMs;
    }

    void cancelPending() { m_pending = false; }
    bool pending() const { return m_pending; }
    const QString &serverId() const { return m_serverId; }

private:
    qint64 remainingDelayMs(qint64 nowMs, qint64 minimumIntervalMs) const
    {
        if (m_immediateAvailable || m_lastReconnectMs < 0) {
            return 0;
        }
        const qint64 elapsedMs = qMax<qint64>(0, nowMs - m_lastReconnectMs);
        return qMax<qint64>(0, minimumIntervalMs - elapsedMs);
    }

    QString m_serverId;
    bool m_immediateAvailable = false;
    bool m_pending = false;
    qint64 m_lastReconnectMs = -1;
};

class State final
{
public:
    void begin(const QString &serverId, const QString &sourceDigest,
               const QStringList &domains, const QJsonObject &baseline)
    {
        begin(serverId, sourceDigest, domains, baseline, domains);
    }

    void begin(const QString &serverId, const QString &sourceDigest,
               const QStringList &domains, const QJsonObject &baseline,
               const QStringList &pendingDomains)
    {
        m_active = true;
        m_serverId = serverId;
        m_sourceDigest = sourceDigest;
        m_domains = domains;
        m_pending = pendingDomains;
        m_cache = baseline;
        m_completedWaves = 0;
        m_finalized = false;
    }

    void clear()
    {
        m_active = false;
        m_serverId.clear();
        m_sourceDigest.clear();
        m_domains.clear();
        m_pending.clear();
        m_cache = {};
        m_completedWaves = 0;
        m_finalized = false;
    }

    bool matches(const QString &serverId, const QString &sourceDigest) const
    {
        return m_active && m_serverId == serverId && m_sourceDigest == sourceDigest;
    }

    bool active() const { return m_active; }
    bool complete() const { return m_active && m_pending.isEmpty(); }
    const QString &serverId() const { return m_serverId; }
    const QString &sourceDigest() const { return m_sourceDigest; }
    const QJsonObject &cache() const { return m_cache; }
    const QStringList &pending() const { return m_pending; }
    int completedWaves() const { return m_completedWaves; }

    QStringList takePendingWave()
    {
        QStringList wave = m_pending;
        m_pending.clear();
        return wave;
    }

    bool recordSuccess(const QString &domain, const QString &canonicalAddresses)
    {
        if (!m_active || !m_domains.contains(domain) || canonicalAddresses.isEmpty()) {
            return false;
        }
        m_cache.insert(domain, canonicalAddresses);
        return true;
    }

    void recordFailure(const QString &domain)
    {
        if (m_active && m_domains.contains(domain) && !m_pending.contains(domain)) {
            m_pending.append(domain);
        }
    }

    void finishWave()
    {
        if (m_active && !m_finalized) {
            ++m_completedWaves;
        }
    }

    bool shouldRetry(int maximumRetryWaves) const
    {
        return m_active && !m_finalized && !m_pending.isEmpty()
                && m_completedWaves <= maximumRetryWaves;
    }

    bool tryFinalize()
    {
        if (!m_active || m_finalized) {
            return false;
        }
        m_finalized = true;
        return true;
    }

private:
    bool m_active = false;
    QString m_serverId;
    QString m_sourceDigest;
    QStringList m_domains;
    QStringList m_pending;
    QJsonObject m_cache;
    int m_completedWaves = 0;
    bool m_finalized = false;
};
}

#endif
