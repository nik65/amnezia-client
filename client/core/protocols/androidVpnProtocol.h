#ifndef ANDROID_VPNPROTOCOL_H
#define ANDROID_VPNPROTOCOL_H

#include "vpnProtocol.h"
#include "core/utils/androidServiceDiscovery.h"

using namespace amnezia;

class AndroidVpnProtocol : public VpnProtocol
{
    Q_OBJECT

public:
    explicit AndroidVpnProtocol(const QJsonObject& configuration, QObject* parent = nullptr);
    ~AndroidVpnProtocol() override = default;

    void setStartAdmission(const AndroidServiceDiscovery::Grant &grant) { m_startAdmission = grant; }
    ErrorCode start() override;
    void stop() override;
    bool adoptObservedPrimarySession(const QJsonObject &snapshot);
    bool adoptObservedDnsSession(const QJsonObject &configuration);

private:
    AndroidServiceDiscovery::Grant m_startAdmission;
};

#endif // ANDROID_VPNPROTOCOL_H
