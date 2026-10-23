#include "androidVpnProtocol.h"

#include "platforms/android/android_controller.h"


AndroidVpnProtocol::AndroidVpnProtocol(const QJsonObject &configuration, QObject* parent)
    : VpnProtocol(configuration, parent)
{ }

ErrorCode AndroidVpnProtocol::start()
{
    qDebug() << "AndroidVpnProtocol::start()";
    if (!m_startAdmission.valid()) return ErrorCode::ServiceDiscoveryUnconfirmed;
    const auto grant = m_startAdmission;
    m_startAdmission = {};
    return AndroidController::instance()->start(m_rawConfig, grant);
}

void AndroidVpnProtocol::stop()
{
    qDebug() << "AndroidVpnProtocol::stop()";
    setConnectionState(Vpn::ConnectionState::Disconnecting);
    if (m_rawConfig.contains("restoredNativeSession")) {
        AndroidController::instance()->stopBound(m_rawConfig.value("restoredNativeSession").toObject());
        return;
    }
    AndroidController::instance()->stop();
}
