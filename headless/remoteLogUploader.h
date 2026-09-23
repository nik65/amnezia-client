#ifndef AMNEZIA_HEADLESS_REMOTE_LOG_UPLOADER_H
#define AMNEZIA_HEADLESS_REMOTE_LOG_UPLOADER_H

#include <QJsonObject>
#include <QObject>
#include <QString>

namespace amnezia::headless
{

class HeadlessRemoteLogUploader final : public QObject
{
    Q_OBJECT

public:
    enum class State { Disabled, Pending, Healthy, Error };
    Q_ENUM(State)

    explicit HeadlessRemoteLogUploader(QString configPath, QObject *parent = nullptr);

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
    bool loadState(QString *error);
    bool saveState(QString *error = nullptr) const;
    bool validateConfig(const QJsonObject &config, QString *error) const;
    QString sourceFingerprint(const QByteArray &prefix, qint64 size) const;
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
    State m_state = State::Disabled;
    QString m_lastReason = QStringLiteral("not_configured");
    bool m_pollInProgress = false;
};

} // namespace amnezia::headless

#endif // AMNEZIA_HEADLESS_REMOTE_LOG_UPLOADER_H
