#pragma once
#include <QObject>
#include <QJsonObject>
#include <QTimer>
#include <functional>
#include "core/repositories/secureServersRepository.h"
#include "core/repositories/secureAppSettingsRepository.h"

class AwgMigrationController final : public QObject {
public:
    AwgMigrationController(SecureServersRepository *, SecureAppSettingsRepository *, QObject *parent);
    void beginActivation(const QString &serverId);
    QString activationToken() const { return m_activationToken; }
    QJsonObject prepare(const QString &serverId, const QJsonObject &connection, bool allowTrial = true);
    void observe(const QString &serverId, quint64 epoch, const QJsonObject &observation);
    void cancel();
    void failed();
    QString serverId() const { return m_serverId; }
    void cleanupFailed();
    // Caller must first verify the teardown receipt for the retiring connection.
    bool cleanupCompleted(const QString &serverId, const QString &activationToken, quint64 teardownEpoch);
    std::function<void(const QJsonObject &)> reconnectLegacy;
#ifdef AMNEZIA_AWG_MIGRATION_CONTROLLER_TESTING
    QJsonObject testJournal() const { return m_journal; }
    std::function<void(const QString &, const QJsonObject &,
                       std::function<void(const QJsonObject &)>)> testRequest;
#endif
private:
    void recordFailure(const QString &reason, int httpStatus = 0);
    void clearFailure();
    void clearTrialEvidence();
    bool validChallengeReceipt(const QJsonObject &envelope, bool requireUnexpired = true) const;
    bool committedProfileMatches() const;
    bool targetObservationMatches() const;
    void enrollOrFetch();
    void challenge();
    void acknowledge();
    void request(const QString &path, const QJsonObject &body,
                 std::function<void(const QJsonObject &)> callback);
    bool persist(const QString &state);
    SecureServersRepository *m_servers;
    SecureAppSettingsRepository *m_settings;
    QString m_serverId;
    QString m_activationToken, m_pendingActivationToken, m_pendingActivationServerId;
    QJsonObject m_originalConnection, m_sourceProfile, m_journal, m_observation;
    QTimer m_deadline;
    quint64 m_epoch = 0, m_callbackGeneration = 0;
    qint64 m_startedAt = 0;
    qint64 m_pollAfter = 0;
    double m_initialRx = 0, m_initialTx = 0;
    bool m_trial = false, m_busy = false, m_cancelled = false;
    bool m_committingProfile = false;
    bool m_allowTrial = true;
};
