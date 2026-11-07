#pragma once

#include <QObject>
#include <QTimer>
#include <QString>
#include <QJsonObject>
#include <QRegularExpression>
#include <QUuid>
#include <functional>
#include <utility>
#include "errorCodes.h"

// Each administrative binding owns one timer. A changed/deleted profile or
// destroyed receiver can never enqueue a stale authenticated operation.
class AutomaticAwgRetry : public QObject
{
public:
    explicit AutomaticAwgRetry(QObject *parent = nullptr) : QObject(parent), m_timer(this)
    {
        m_timer.setSingleShot(true);
        connect(&m_timer, &QTimer::timeout, this, [this]() {
            m_timer.stop();
            auto guard = std::move(m_guard);
            auto retry = std::move(m_retry);
            if (guard && guard() && retry) retry();
            else cancel();
        });
    }

    static bool transient(amnezia::ErrorCode error, const QString &reason)
    {
        // Authentication, host-key, policy, image integrity and journal failures
        // are permanent even if an unrelated dependency hint accompanies them.
        if (error == amnezia::ErrorCode::SshHostKeyMissingError
                || error == amnezia::ErrorCode::SshHostKeyMalformedError
                || error == amnezia::ErrorCode::SshHostKeyMismatchError
                || error == amnezia::ErrorCode::SshRequestDeniedError
                || error == amnezia::ErrorCode::SshPrivateKeyError
                || error == amnezia::ErrorCode::SshPrivateKeyFormatError) return false;
        if (!reason.isEmpty())
            return reason == "ssh_transport_unavailable" || reason == "image_fetch_unavailable"
                    || reason == "migration_dependency_unavailable" || reason == "migration_busy"
                    || reason == "migration_udp_port_unavailable";
        return error == amnezia::ErrorCode::SshTimeoutError;
    }

    static bool verifiedRetirement(amnezia::ErrorCode error, const QJsonObject &receipt,
                                   const QString &source)
    {
        const auto yes = [&](const char *key) { return receipt.value(QLatin1String(key)).isBool()
            && receipt.value(QLatin1String(key)).toBool(); };
        const auto no = [&](const char *key) { return receipt.value(QLatin1String(key)).isBool()
            && !receipt.value(QLatin1String(key)).toBool(); };
        const auto number = receipt.value(QStringLiteral("generation"));
        const QString operation = receipt.value(QStringLiteral("clientOperationId")).toString();
        const auto hashes = receipt.value(QStringLiteral("controlHashes")).toObject();
        const QRegularExpression digest(QStringLiteral("\\A[a-f0-9]{64}\\z"));
        return error == amnezia::ErrorCode::NoError && yes("ok") && yes("native")
            && yes("reconciled") && yes("retired") && yes("retiredVerified")
            && no("liveVerified") && no("pendingRecovery")
            && (!receipt.contains(QStringLiteral("cleanupRequired")) || no("cleanupRequired"))
            && receipt.value(QStringLiteral("mode")).toString() == QStringLiteral("abort-prepare")
            && receipt.value(QStringLiteral("phase")).toString() == QStringLiteral("aborted")
            && (source == QStringLiteral("amnezia-awg") || source == QStringLiteral("amnezia-awg2"))
            && receipt.value(QStringLiteral("source")).toString() == source
            && number.isDouble() && number.toDouble() >= 1 && number.toDouble() <= 9007199254740991.0
            && number.toDouble() == static_cast<double>(number.toInteger())
            && !QUuid(operation).isNull() && QUuid(operation).toString(QUuid::WithoutBraces) == operation
            && hashes.size() == 1 && digest.match(hashes.value(QStringLiteral("awg-feed")).toString()).hasMatch()
            && digest.match(receipt.value(QStringLiteral("journalSha256")).toString()).hasMatch();
    }

    // A successful retirement is not a prepared endpoint. Retry only after the
    // trusted receipt and unchanged caller binding have both been checked. This
    // separate finite budget is never reset by transport/permanent failures.
    bool scheduleAfterRetirement(amnezia::ErrorCode error, const QJsonObject &receipt,
                                 const QString &source, std::function<bool()> guard,
                                 std::function<void()> retry)
    {
        if (!verifiedRetirement(error, receipt, source)) { cancel(); return false; }
        if (m_timer.isActive()) return true;
        if (m_retirementAttempts >= 3) return false;
        const int delays[] = {1000, 3000, 10000};
        m_guard = std::move(guard);
        m_retry = std::move(retry);
        m_timer.start(delays[m_retirementAttempts++]);
        return true;
    }

    bool schedule(amnezia::ErrorCode error, const QString &reason,
                  std::function<bool()> guard, std::function<void()> retry)
    {
        if (!transient(error, reason)) { cancel(); return false; }
        if (m_timer.isActive()) return true;
        m_failures = qMin(m_failures + 1, 4);
        const int delays[] = {30000, 120000, 300000, 900000};
        m_guard = std::move(guard);
        m_retry = std::move(retry);
        m_timer.start(delays[m_failures - 1]);
        return true;
    }

    int delayMs() const { return m_timer.interval(); }
    void cancel() { m_timer.stop(); m_guard = {}; m_retry = {}; m_failures = 0; }

private:
    QTimer m_timer;
    int m_failures = 0;
    int m_retirementAttempts = 0;
    std::function<bool()> m_guard;
    std::function<void()> m_retry;
};
