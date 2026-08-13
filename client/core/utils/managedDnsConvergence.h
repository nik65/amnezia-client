#ifndef MANAGEDDNSCONVERGENCE_H
#define MANAGEDDNSCONVERGENCE_H

#include <QDateTime>
#include <QJsonObject>
#include <QString>
#include <QStringList>
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

class State final
{
public:
    void begin(const QString &serverId, const QString &sourceDigest,
               const QStringList &domains, const QJsonObject &baseline)
    {
        m_active = true;
        m_serverId = serverId;
        m_sourceDigest = sourceDigest;
        m_domains = domains;
        m_pending = domains;
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
