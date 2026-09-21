#include <QCoreApplication>
#include <QFileInfo>
#include <QProcess>
#include <QTcpSocket>
#include <QThread>

#include "wireGuardProtocol.h"
#include "core/utils/networkUtilities.h"

#include "mozilla/localsocketcontroller.h"

WireguardProtocol::WireguardProtocol(const QJsonObject &configuration, QObject *parent)
    : VpnProtocol(configuration, parent)
{
    m_impl.reset(new LocalSocketController());
    bindControllerSignals();
    connect(m_impl.get(), &ControllerImpl::statusUpdated, this,
            [this](const QString& serverIpv4Gateway,
                   const QString& deviceIpv4Address, uint64_t txBytes,
                   uint64_t rxBytes) {
                const QString previousGateway = m_vpnGateway;
                const QString previousLocal = m_vpnLocalAddress;

                if (!serverIpv4Gateway.isEmpty()) {
                    m_vpnGateway = serverIpv4Gateway;
                }
                if (!deviceIpv4Address.isEmpty()) {
                    m_vpnLocalAddress = deviceIpv4Address;
                }

                if ((!m_vpnGateway.isEmpty() && m_vpnGateway != previousGateway) ||
                    (!m_vpnLocalAddress.isEmpty() && m_vpnLocalAddress != previousLocal)) {
                    emit tunnelAddressesUpdated(m_vpnGateway, m_vpnLocalAddress);
                }
            });

    m_impl->initialize(nullptr, nullptr);
}

void WireguardProtocol::bindControllerSignals()
{
    m_backendFailureConnectionContext.reset(new QObject());
    amnezia::wireguardProtocolPolicy::bindControllerSignals(
            m_impl.get(), m_backendFailureConnectionContext.get(),
            &m_backendFailureLatch,
            [this](ErrorCode error) { setLastError(error); },
            [this](bool connected) {
                setConnectionState(connected ? Vpn::ConnectionState::Connected
                                             : Vpn::ConnectionState::Disconnected);
            });
}

WireguardProtocol::~WireguardProtocol()
{
    WireguardProtocol::stop();
    QThread::msleep(200);
}

void WireguardProtocol::stop()
{
    stopMzImpl();
    return;
}

ErrorCode WireguardProtocol::startMzImpl()
{
    // A new explicit activation attempt is the only event that clears a
    // latched backend failure. Late connected/disconnected notifications from
    // the previous attempt must not hide the actionable error.
    m_backendFailureConnectionContext.reset();
    m_backendFailureLatch.beginAttempt();
    bindControllerSignals();
    if (lastError() != ErrorCode::NoError) {
        setLastError(ErrorCode::NoError);
    }
    QString protocolName = m_rawConfig.value("protocol").toString();
    QJsonObject vpnConfigData = m_rawConfig.value(protocolName + "_config_data").toObject();
    vpnConfigData[configKey::hostName] = NetworkUtilities::getIPAddress(vpnConfigData.value(configKey::hostName).toString());
    m_rawConfig.insert(protocolName + "_config_data", vpnConfigData);
    m_rawConfig[configKey::hostName] = NetworkUtilities::getIPAddress(m_rawConfig[configKey::hostName].toString());

    m_impl->activate(m_rawConfig);
    return ErrorCode::NoError;
}

ErrorCode WireguardProtocol::stopMzImpl()
{
    m_impl->deactivate();
    return ErrorCode::NoError;
}


ErrorCode WireguardProtocol::start()
{
    return startMzImpl();
}
