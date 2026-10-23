#pragma once
#include <QObject>
#include <QSharedPointer>
#include <QTimer>
#include <QJsonObject>
#include <functional>
#include "nativeSessionRestore.h"

// Retains the native IPC receiver independently of the active protocol slot.
// Receipts identify the retired session, while completion identifies the planned
// disconnect epoch. Ordinary disconnected/error signals never authorize retry.
class MigrationTeardownContext final : public QObject {
public:
    MigrationTeardownContext(QSharedPointer<QObject> owner, QString nonce, quint64 originalEpoch,
            quint64 disconnectEpoch, bool routesConfirmed, std::function<quint64()> currentEpoch,
            std::function<void(bool)> completed, QObject *parent, int deadlineMs = 9000)
        : QObject(parent), m_owner(std::move(owner)), m_nonce(std::move(nonce)),
          m_originalEpoch(originalEpoch), m_disconnectEpoch(disconnectEpoch), m_routesConfirmed(routesConfirmed),
          m_currentEpoch(std::move(currentEpoch)), m_completed(std::move(completed))
    {
        QTimer::singleShot(deadlineMs, this, [this]() { expire(); });
    }
    void observe(const QString &nonce, quint64 originalEpoch, bool nativeConfirmed)
    {
        if (m_requiresRestoredIdentity || m_finished || nonce.isEmpty() || nonce != m_nonce || originalEpoch != m_originalEpoch) return;
        finish(nativeConfirmed && m_routesConfirmed && m_currentEpoch() == m_disconnectEpoch);
    }
    void expire() { if (!m_finished) finish(false); }
    void requireRestoredIdentity(const QJsonObject &identity)
    {
        m_requiresRestoredIdentity = true;
        m_expectedIdentity = NativeSessionRestore::identity(identity) ? identity : QJsonObject{};
    }
    void observeAndroid(const QJsonObject &receipt, quint64 originalEpoch)
    {
        if (!receipt.value("nativeCleanupConfirmed").isBool()) return;
        if (m_requiresRestoredIdentity) {
            if (m_expectedIdentity.isEmpty() || m_finished || originalEpoch!=m_originalEpoch
                || receipt.value("connectionNonce").toString()!=m_nonce
                || NativeSessionRestore::boundIdentity(receipt)!=m_expectedIdentity) return;
            finish(receipt.value("nativeCleanupConfirmed").toBool() && m_routesConfirmed
                && m_currentEpoch()==m_disconnectEpoch);
            return;
        }
        observe(receipt.value("connectionNonce").toString(), originalEpoch,
                receipt.value("nativeCleanupConfirmed").toBool());
    }
private:
    void finish(bool confirmed)
    {
        m_finished = true;
        // Release the old protocol (including its IPC transport) before any
        // completion callback can enqueue a new activation.
        m_owner.clear();
        m_completed(confirmed);
        deleteLater();
    }
    QSharedPointer<QObject> m_owner;
    QString m_nonce;
    quint64 m_originalEpoch, m_disconnectEpoch;
    bool m_routesConfirmed, m_finished = false;
    bool m_requiresRestoredIdentity = false;
    QJsonObject m_expectedIdentity;
    std::function<quint64()> m_currentEpoch;
    std::function<void(bool)> m_completed;
};
