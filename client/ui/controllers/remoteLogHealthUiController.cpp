#include "remoteLogHealthUiController.h"
#include <cmath>
#include <QSet>
#ifdef Q_OS_ANDROID
#include "platforms/android/android_controller.h"
#endif

RemoteLogHealthUiController::RemoteLogHealthUiController(RemoteLogUploader *uploader, QObject *parent)
    : QObject(parent), m_uploader(uploader)
{
#ifdef Q_OS_ANDROID
    connect(AndroidController::instance(), &AndroidController::remoteLogHealthObserved,
            this, &RemoteLogHealthUiController::observeServiceHealth);
    connect(AndroidController::instance(), &AndroidController::serviceDisconnected, this, [this]() {
        m_serviceHealth = {};
        emit stateChanged(); emit statusChanged(); emit lastSuccessChanged();
        emit lastSuccessAtChanged(); emit pendingBytesChanged(); emit lastErrorCategoryChanged();
        emit nextRetryAtChanged(); emit healthChanged();
    });
#endif
    if (!m_uploader) {
        return;
    }

    connect(m_uploader, &RemoteLogUploader::stateChanged, this, [this]() {
        emit stateChanged();
        emit statusChanged();
        emit healthChanged();
    });
    connect(m_uploader, &RemoteLogUploader::lastSuccessChanged, this, [this]() {
        emit lastSuccessChanged();
        emit lastSuccessAtChanged();
        emit healthChanged();
    });
    connect(m_uploader, &RemoteLogUploader::pendingBytesChanged, this, [this]() {
        emit pendingBytesChanged();
        emit healthChanged();
    });
    connect(m_uploader, &RemoteLogUploader::lastErrorCategoryChanged, this, [this]() {
        emit lastErrorCategoryChanged();
        emit healthChanged();
    });
    connect(m_uploader, &RemoteLogUploader::nextRetryAtChanged, this, [this]() {
        emit nextRetryAtChanged();
        emit healthChanged();
    });
}

RemoteLogHealthUiController::State RemoteLogHealthUiController::state() const
{
    if (!m_uploader && !m_serviceHealth.isEmpty())
        return static_cast<State>(m_serviceHealth.value("state").toInt());
    return m_uploader ? static_cast<State>(static_cast<int>(m_uploader->state())) : State::Unavailable;
}

QString RemoteLogHealthUiController::stateLabel() const
{
    switch (state()) {
    case State::WaitingForVpn:
        return tr("Waiting for VPN connection");
    case State::TargetMissing:
        return tr("Remote diagnostics collector is not configured");
    case State::Uploading:
        return tr("Uploading diagnostics");
    case State::Healthy:
        return tr("Diagnostics delivery is healthy");
    case State::Stale:
        return tr("Diagnostics delivery is stale");
    case State::Error:
        return tr("Diagnostics delivery failed");
    case State::Unavailable:
        return tr("Diagnostics delivery status is not exposed in this view");
    }
    return {};
}

bool RemoteLogHealthUiController::healthy() const
{
    return state() == State::Healthy;
}

QDateTime RemoteLogHealthUiController::lastSuccess() const
{
    if (!m_uploader && m_serviceHealth.value("lastSuccessMs").toDouble() > 0)
        return QDateTime::fromMSecsSinceEpoch(qint64(m_serviceHealth.value("lastSuccessMs").toDouble()));
    return m_uploader ? m_uploader->lastSuccess() : QDateTime();
}

qint64 RemoteLogHealthUiController::pendingBytes() const
{
    if (!m_uploader) return qint64(m_serviceHealth.value("pendingBytes").toDouble());
    return m_uploader ? m_uploader->pendingBytes() : 0;
}

RemoteLogHealthUiController::ErrorCategory RemoteLogHealthUiController::lastErrorCategory() const
{
    if (!m_uploader) return static_cast<ErrorCategory>(m_serviceHealth.value("errorCategory").toInt());
    return m_uploader
            ? static_cast<ErrorCategory>(static_cast<int>(m_uploader->lastErrorCategory()))
            : ErrorCategory::None;
}

QString RemoteLogHealthUiController::lastErrorLabel() const
{
    switch (lastErrorCategory()) {
    case ErrorCategory::None:
        return {};
    case ErrorCategory::Configuration:
        return tr("Collector configuration is unavailable");
    case ErrorCategory::Bootstrap:
        return tr("Collector enrollment failed");
    case ErrorCategory::Authentication:
        return tr("Collector authentication failed");
    case ErrorCategory::Network:
        return tr("Network request failed");
    case ErrorCategory::Timeout:
        return tr("Collector request timed out");
    case ErrorCategory::Server:
        return tr("Collector rejected the upload");
    case ErrorCategory::Source:
        return tr("Local diagnostics logs are unavailable");
    }
    return {};
}

QDateTime RemoteLogHealthUiController::nextRetryAt() const
{
    if (!m_uploader && m_serviceHealth.value("nextRetryMs").toDouble() > 0)
        return QDateTime::fromMSecsSinceEpoch(qint64(m_serviceHealth.value("nextRetryMs").toDouble()));
    return m_uploader ? m_uploader->nextRetryAt() : QDateTime();
}

int RemoteLogHealthUiController::lastHttpStatus() const
{
    return m_uploader ? 0 : m_serviceHealth.value("httpStatus").toInt();
}

void RemoteLogHealthUiController::observeServiceHealth(const QJsonObject &snapshot)
{
    if (m_uploader) return;
    const QSet<QString> keys{"schema", "state", "lastSuccessMs", "pendingBytes",
                             "errorCategory", "httpStatus", "nextRetryMs"};
    const auto actualKeys = snapshot.keys();
    if (QSet<QString>(actualKeys.begin(), actualKeys.end()) != keys) return;
    const auto validInteger = [&snapshot](const char *key, double maximum) {
        const auto value = snapshot.value(key);
        const double number = value.toDouble(-1);
        return value.isDouble() && std::isfinite(number) && number >= 0
                && number <= maximum && std::floor(number) == number;
    };
    const double deadline = QDateTime::currentMSecsSinceEpoch() + 24.0 * 60 * 60 * 1000;
    if (snapshot.value("schema").toInt() != 1 || !validInteger("schema", 1)
        || !validInteger("state", 5) || !validInteger("errorCategory", 7)
        || !validInteger("httpStatus", 599) || !validInteger("pendingBytes", 1073741824)
        || !validInteger("lastSuccessMs", QDateTime::currentMSecsSinceEpoch() + 300000.0)
        || !validInteger("nextRetryMs", deadline)) return;
    const int http = snapshot.value("httpStatus").toInt();
    if (http != 0 && http < 100) return;
    if (snapshot.value("state").toInt() == 3
        && (snapshot.value("lastSuccessMs").toDouble() <= 0
            || snapshot.value("errorCategory").toInt() != 0)) return;
    m_serviceHealth = snapshot;
    emit stateChanged(); emit statusChanged(); emit lastSuccessChanged();
    emit lastSuccessAtChanged(); emit pendingBytesChanged(); emit lastErrorCategoryChanged();
    emit nextRetryAtChanged(); emit healthChanged();
}

bool RemoteLogHealthUiController::retryAvailable() const
{
    if (!m_uploader) {
        return false;
    }
    const State currentState = state();
    return currentState == State::Error || currentState == State::Stale;
}

void RemoteLogHealthUiController::retryNow()
{
    if (m_uploader) {
        m_uploader->retryNow();
    }
}

void RemoteLogHealthUiController::onTranslationsUpdated()
{
    emit stateChanged();
    emit statusChanged();
    emit lastErrorCategoryChanged();
}
