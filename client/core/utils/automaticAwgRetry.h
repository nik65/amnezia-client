#pragma once

#include <QObject>
#include <QTimer>
#include <QString>
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
    std::function<bool()> m_guard;
    std::function<void()> m_retry;
};
