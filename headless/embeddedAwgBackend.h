#pragma once
#include <QProcess>
#include <QMap>
#include "vpnBackend.h"

namespace amnezia::headless {
class EmbeddedAwgBackend final {
public:
    explicit EmbeddedAwgBackend(std::shared_ptr<CommandRunner> runner);
    static bool available();
    BackendResult start(const Profile &profile, const QString &configPath, const QString &cacheRoot);
    BackendResult stop();
    bool alive() const;
    bool configured() const;
    QString expectedPeer() const { return m_peer; }
    bool handshake(const QString &peer, qint64 startedAt) const;
    bool parametersApplied(const QMap<QString, QString> &parameters) const;
private:
    bool exchange(const QByteArray &request, QByteArray &reply) const;
    bool snapshot(QMap<QString, QString> &device, QMap<QString, qint64> &handshakes) const;
    static QString uapiName(const QString &nativeName);
    std::shared_ptr<CommandRunner> m_runner;
    QProcess m_process;
    QString m_interface;
    QString m_socketPath;
    QString m_peer;
    bool m_dnsOwned = false;
};
}
