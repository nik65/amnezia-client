#ifndef WIREGUARDPROTOCOLBINDING_H
#define WIREGUARDPROTOCOLBINDING_H

#include <QMetaType>
#include <QObject>

#include <functional>
#include <utility>

#include "core/utils/errorCodes.h"
#include "mozilla/controllerimpl.h"

namespace amnezia::wireguardProtocolPolicy
{
    inline ErrorCode errorCodeForDaemonFailure(DaemonError error)
    {
        switch (error) {
        case DaemonError::ERROR_SPLIT_TUNNEL_INIT_FAILURE:
            return ErrorCode::SplitTunnelInitializationFailed;
        case DaemonError::ERROR_SPLIT_TUNNEL_START_FAILURE:
            return ErrorCode::SplitTunnelStartFailed;
        case DaemonError::ERROR_SPLIT_TUNNEL_EXCLUDE_FAILURE:
            return ErrorCode::SplitTunnelExclusionFailed;
        case DaemonError::ERROR_SPLIT_TUNNEL_CONFIG_TIMEOUT:
            return ErrorCode::SplitTunnelConfigurationTimeout;
        case DaemonError::ERROR_SPLIT_TUNNEL_CONFIG_WAIT_FAILED:
            return ErrorCode::SplitTunnelConfigurationWaitFailed;
        case DaemonError::ERROR_SPLIT_TUNNEL_CONFIG_CLEANUP_FAILED:
            return ErrorCode::SplitTunnelConfigurationCleanupFailed;
        case DaemonError::ERROR_NONE:
        case DaemonError::ERROR_FATAL:
        case DaemonError::DAEMON_ERROR_MAX:
            return ErrorCode::AmneziaServiceConnectionFailed;
        }
        return ErrorCode::AmneziaServiceConnectionFailed;
    }

    class BackendFailureLatch
    {
    public:
        void beginAttempt() { m_latched = false; }
        void latch() { m_latched = true; }
        bool isLatched() const { return m_latched; }
        bool acceptsConnectionEvent() const { return !m_latched; }

    private:
        bool m_latched = false;
    };

    using ControllerErrorSetter = std::function<void(ErrorCode)>;
    using ControllerStateSetter = std::function<void(bool)>;

    inline void bindControllerSignals(
            ControllerImpl *controller,
            QObject *receiver,
            BackendFailureLatch *failureLatch,
            ControllerErrorSetter setLastError,
            ControllerStateSetter setConnectionState,
            Qt::ConnectionType connectionType = Qt::AutoConnection)
    {
        Q_ASSERT(controller != nullptr);
        Q_ASSERT(receiver != nullptr);
        Q_ASSERT(failureLatch != nullptr);
        Q_ASSERT(setLastError);
        Q_ASSERT(setConnectionState);

        qRegisterMetaType<DaemonError>();
        QObject::connect(
                controller, &ControllerImpl::backendFailure, receiver,
                [failureLatch, setLastError = std::move(setLastError)](DaemonError error) {
                    failureLatch->latch();
                    setLastError(errorCodeForDaemonFailure(error));
                },
                connectionType);
        QObject::connect(
                controller, &ControllerImpl::connected, receiver,
                [failureLatch, setConnectionState](const QString &, const QDateTime &) {
                    if (failureLatch->acceptsConnectionEvent()) {
                        setConnectionState(true);
                    }
                },
                connectionType);
        QObject::connect(
                controller, &ControllerImpl::disconnected, receiver,
                [failureLatch, setConnectionState]() {
                    if (failureLatch->acceptsConnectionEvent()) {
                        setConnectionState(false);
                    }
                },
                connectionType);
    }
}

#endif // WIREGUARDPROTOCOLBINDING_H
