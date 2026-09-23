#ifndef AMNEZIA_HEADLESS_REMOTE_LOG_UPLOADER_H
#define AMNEZIA_HEADLESS_REMOTE_LOG_UPLOADER_H

#include <QJsonObject>
#include <QByteArray>
#include <QFileInfo>
#include <QNetworkAccessManager>
#include <QObject>
#include <QString>

#include "../client/core/utils/remoteLogSanitizer.h"

namespace amnezia::headless
{

class HeadlessRemoteLogUploader final : public QObject
{
    Q_OBJECT

public:
    enum class State { Disabled, Pending, Healthy, Error };
    Q_ENUM(State)

    explicit HeadlessRemoteLogUploader(QString configPath, QObject *parent = nullptr);
    HeadlessRemoteLogUploader(QString configPath, QNetworkAccessManager *networkManager,
                              QObject *parent = nullptr);

    bool load(QString *error = nullptr);
    bool provisionFromDesktopTarget(const QJsonObject &desktopExport,
                                    const QString &sourcePath,
                                    const QString &installationId,
                                    QString *error = nullptr);
    State state() const { return m_state; }
    QString stateName() const;
    QString lastReason() const { return m_lastReason; }
    QJsonObject status() const;
    QString configPath() const { return m_configPath; }

public slots:
    void poll();

private:
    struct DurableState
    {
        qint64 offset = 0;
        QString fingerprint;
        bool awaitingStable = false;
        bool redactNext = false;
        qint64 highWater = 0;
        QString sourceIdentity;
        QString cursorAnchor;
        QString targetBinding;
        QByteArray sanitizerLookbehind;
        amnezia::remoteLogSanitizer::StreamState sanitizerState;
    };

    bool loadState(QString *error);
    bool saveState(const DurableState &state, QString *error = nullptr) const;
    DurableState currentState() const;
    void applyState(const DurableState &state);
    bool validateConfig(const QJsonObject &config, QString *error) const;
    bool quarantineState(const QString &reason, QString *error = nullptr);
    bool validateSecureFile(const QFileInfo &info, const QString &reason,
                            QString *error = nullptr) const;
    QString targetBinding() const;
    QString sourceIdentity(const QFile &file) const;
    QString sourceFingerprint(const QByteArray &prefix, qint64 size,
                              const QString &identity) const;
    QString cursorAnchor(QFile &file, qint64 offset, bool *ok) const;
    bool sourceStillSafe(const QString &sourcePath, QFile &file,
                         QString *identity, QString *error) const;
    QJsonObject stateToJson(const DurableState &state) const;
    bool stateFromJson(const QJsonObject &object, DurableState *state,
                       QString *error) const;
    QJsonObject sanitizerStateToJson(
            const amnezia::remoteLogSanitizer::StreamState &state) const;
    bool sanitizerStateFromJson(
            const QJsonObject &object,
            amnezia::remoteLogSanitizer::StreamState *state,
            QString *error) const;
    QString batchId(qint64 offset, qint64 nextOffset, const QString &fingerprint) const;
    void setError(const QString &reason);

    QString m_configPath;
    QString m_statePath;
    QJsonObject m_config;
    qint64 m_offset = 0;
    QString m_fingerprint;
    bool m_awaitingStable = false;
    bool m_redactNext = false;
    qint64 m_highWater = 0;
    QString m_sourceIdentity;
    QString m_cursorAnchor;
    QString m_targetBinding;
    QByteArray m_sanitizerLookbehind;
    amnezia::remoteLogSanitizer::StreamState m_sanitizerState;
    State m_state = State::Disabled;
    QString m_lastReason = QStringLiteral("not_configured");
    bool m_pollInProgress = false;
    QNetworkAccessManager m_ownedNetworkManager;
    QNetworkAccessManager *m_networkManager = &m_ownedNetworkManager;
};

} // namespace amnezia::headless

#endif // AMNEZIA_HEADLESS_REMOTE_LOG_UPLOADER_H
