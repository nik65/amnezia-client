#ifndef REMOTELOGHEALTHUICONTROLLER_H
#define REMOTELOGHEALTHUICONTROLLER_H

#include <QDateTime>
#include <QObject>
#include <QPointer>

#include "core/controllers/remoteLogUploader.h"

class RemoteLogHealthUiController final : public QObject
{
    Q_OBJECT

    Q_PROPERTY(State state READ state NOTIFY stateChanged)
    Q_PROPERTY(QString stateLabel READ stateLabel NOTIFY stateChanged)
    Q_PROPERTY(QString stateText READ stateLabel NOTIFY statusChanged)
    Q_PROPERTY(QString statusText READ stateLabel NOTIFY statusChanged)
    Q_PROPERTY(bool healthy READ healthy NOTIFY healthChanged)
    Q_PROPERTY(bool isHealthy READ healthy NOTIFY healthChanged)
    Q_PROPERTY(QDateTime lastSuccess READ lastSuccess NOTIFY lastSuccessChanged)
    Q_PROPERTY(QDateTime lastSuccessAt READ lastSuccess NOTIFY lastSuccessAtChanged)
    Q_PROPERTY(qint64 pendingBytes READ pendingBytes NOTIFY pendingBytesChanged)
    Q_PROPERTY(ErrorCategory lastErrorCategory READ lastErrorCategory NOTIFY lastErrorCategoryChanged)
    Q_PROPERTY(QString lastErrorLabel READ lastErrorLabel NOTIFY lastErrorCategoryChanged)
    Q_PROPERTY(QDateTime nextRetryAt READ nextRetryAt NOTIFY nextRetryAtChanged)
    Q_PROPERTY(bool retryAvailable READ retryAvailable NOTIFY stateChanged)

public:
    enum class State {
        WaitingForVpn = static_cast<int>(RemoteLogUploader::State::WaitingForVpn),
        TargetMissing = static_cast<int>(RemoteLogUploader::State::TargetMissing),
        Uploading = static_cast<int>(RemoteLogUploader::State::Uploading),
        Healthy = static_cast<int>(RemoteLogUploader::State::Healthy),
        Stale = static_cast<int>(RemoteLogUploader::State::Stale),
        Error = static_cast<int>(RemoteLogUploader::State::Error),
        Unavailable = 100
    };
    Q_ENUM(State)

    enum class ErrorCategory {
        None = static_cast<int>(RemoteLogUploader::ErrorCategory::None),
        Configuration = static_cast<int>(RemoteLogUploader::ErrorCategory::Configuration),
        Bootstrap = static_cast<int>(RemoteLogUploader::ErrorCategory::Bootstrap),
        Authentication = static_cast<int>(RemoteLogUploader::ErrorCategory::Authentication),
        Network = static_cast<int>(RemoteLogUploader::ErrorCategory::Network),
        Timeout = static_cast<int>(RemoteLogUploader::ErrorCategory::Timeout),
        Server = static_cast<int>(RemoteLogUploader::ErrorCategory::Server),
        Source = static_cast<int>(RemoteLogUploader::ErrorCategory::Source)
    };
    Q_ENUM(ErrorCategory)

    explicit RemoteLogHealthUiController(RemoteLogUploader *uploader, QObject *parent = nullptr);

    State state() const;
    QString stateLabel() const;
    bool healthy() const;
    QDateTime lastSuccess() const;
    qint64 pendingBytes() const;
    ErrorCategory lastErrorCategory() const;
    QString lastErrorLabel() const;
    QDateTime nextRetryAt() const;
    bool retryAvailable() const;

public slots:
    void retryNow();
    void onTranslationsUpdated();

signals:
    void stateChanged();
    void statusChanged();
    void healthChanged();
    void lastSuccessChanged();
    void lastSuccessAtChanged();
    void pendingBytesChanged();
    void lastErrorCategoryChanged();
    void nextRetryAtChanged();

private:
    QPointer<RemoteLogUploader> m_uploader;
};

#endif // REMOTELOGHEALTHUICONTROLLER_H
