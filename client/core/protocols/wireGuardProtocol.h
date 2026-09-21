#ifndef WIREGUARDPROTOCOL_H
#define WIREGUARDPROTOCOL_H

#include <QObject>
#include <QProcess>
#include <QString>
#include <QTemporaryFile>
#include <QTimer>

#include <functional>
#include <utility>

#include "vpnProtocol.h"
#include "wireGuardProtocolBinding.h"

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

    void bindControllerSignals();

    QScopedPointer<ControllerImpl> m_impl;
    QScopedPointer<QObject> m_backendFailureConnectionContext;
    amnezia::wireguardProtocolPolicy::BackendFailureLatch m_backendFailureLatch;
};

#endif // WIREGUARDPROTOCOL_H
