#include "remoteLogHealthUiController.h"

RemoteLogHealthUiController::RemoteLogHealthUiController(RemoteLogUploader *uploader, QObject *parent)
    : QObject(parent), m_uploader(uploader)
{
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
    return m_uploader ? m_uploader->lastSuccess() : QDateTime();
}

qint64 RemoteLogHealthUiController::pendingBytes() const
{
    return m_uploader ? m_uploader->pendingBytes() : 0;
}

RemoteLogHealthUiController::ErrorCategory RemoteLogHealthUiController::lastErrorCategory() const
{
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
    return m_uploader ? m_uploader->nextRetryAt() : QDateTime();
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
