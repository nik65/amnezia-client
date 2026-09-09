#ifndef WIREGUARDPROTOCOL_H
#define WIREGUARDPROTOCOL_H

#include <QObject>
#include <QProcess>
#include <QString>
#include <QTemporaryFile>
#include <QTimer>

#include "vpnProtocol.h"

#include "mozilla/controllerimpl.h"
#include "daemon/daemonerrors.h"

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
}

class WireguardProtocol : public VpnProtocol
{
    Q_OBJECT

public:
    explicit WireguardProtocol(const QJsonObject& configuration, QObject* parent = nullptr);
    virtual ~WireguardProtocol() override;

    ErrorCode start() override;
    void stop() override;

    ErrorCode startMzImpl();
    ErrorCode stopMzImpl();

private:

    QScopedPointer<ControllerImpl> m_impl;
    amnezia::wireguardProtocolPolicy::BackendFailureLatch m_backendFailureLatch;
};

#endif // WIREGUARDPROTOCOL_H
