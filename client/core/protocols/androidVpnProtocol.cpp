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

bool AndroidVpnProtocol::adoptObservedDnsSession(const QJsonObject &configuration)
{
    const auto expected = configuration.value("restoredNativeSession").toObject();
    if (!NativeSessionRestore::isDnsConfiguration(configuration) || !NativeSessionRestore::identity(expected)
        || configuration.value("nativeSessionServerId") != m_rawConfig.value("nativeSessionServerId")
        || configuration.value("migrationConnectionNonce") != m_rawConfig.value("migrationConnectionNonce")
        || configuration.value("protocol") != m_rawConfig.value("protocol")
        || configuration.value("dnsProfileDigest").toString()
            != amnezia::dnsFallbackConfig::profileDigest(m_rawConfig.value(amnezia::dnsFallbackConfig::key))
        || (m_rawConfig.contains("restoredNativeSession")
            && m_rawConfig.value("restoredNativeSession").toObject() != expected)) return false;
    m_rawConfig = configuration;
    return true;
}

bool AndroidVpnProtocol::adoptObservedPrimarySession(const QJsonObject &snapshot)
{
    if (!NativeSessionRestore::matchesLivePrimaryOwner(snapshot,
            m_rawConfig.value("nativeSessionServerId").toString(), m_rawConfig,
            m_rawConfig.value("restoredNativeSession").toObject())) return false;
    m_rawConfig["restoredNativeSession"] = NativeSessionRestore::boundIdentity(snapshot);
    return true;
}
