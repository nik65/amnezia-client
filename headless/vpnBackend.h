#ifndef AMNEZIA_HEADLESS_VPN_BACKEND_H
#define AMNEZIA_HEADLESS_VPN_BACKEND_H

#include <QJsonObject>
#include <QString>
#include <QStringList>

#include <memory>

#include "profileStore.h"

namespace amnezia::headless
{

struct CommandResult
{
    bool ok = false;
    int exitCode = -1;
    QString message;
    QString output;
};

class CommandRunner
{
public:
    virtual ~CommandRunner() = default;

    virtual bool isAvailable(const QString &program) const = 0;
    virtual QString resolveExecutable(const QStringList &candidates) const = 0;
    virtual CommandResult run(const QString &program, const QStringList &arguments) = 0;
    // Read-only command output is used only for local kernel state probes.
    // Keep the ordinary run() path output-free so backend output never enters
    // the daemon control protocol or logs.
    virtual CommandResult runCaptured(const QString &program,
                                       const QStringList &arguments)
    {
        return run(program, arguments);
    }
    virtual CommandResult startDetached(const QString &program, const QStringList &arguments)
    {
        return run(program, arguments);
    }
    virtual CommandResult start(const QString &id, const QString &program,
                                const QStringList &arguments) = 0;
    virtual CommandResult stop(const QString &id) = 0;
    virtual bool isSessionAlive(const QString &id) const
    {
        Q_UNUSED(id);
        return true;
    }
};

class RealCommandRunner final : public CommandRunner
{
public:
    RealCommandRunner();
    ~RealCommandRunner() override;

    bool isAvailable(const QString &program) const override;
    QString resolveExecutable(const QStringList &candidates) const override;
    CommandResult run(const QString &program, const QStringList &arguments) override;
    CommandResult runCaptured(const QString &program,
                              const QStringList &arguments) override;
    CommandResult startDetached(const QString &program,
                                const QStringList &arguments) override;
    CommandResult start(const QString &id, const QString &program,
                        const QStringList &arguments) override;
    CommandResult stop(const QString &id) override;
    bool isSessionAlive(const QString &id) const override;

private:
    struct RunningProcess;
    std::unique_ptr<RunningProcess> m_processes;
};

struct BackendResult
{
    bool ok = false;
    QString code;
    QString message;
};

class VpnBackend final
{
public:
    explicit VpnBackend(std::shared_ptr<CommandRunner> runner = {},
                        QString configRoot = {},
                        bool requireRootOwnedConfig = false,
                        QString stagingRoot = {});

    BackendResult connect(const Profile &profile);
    BackendResult disconnect();
    QJsonObject doctor() const;

    QString activeProfile() const;
    bool sessionAlive() const;
    BackendResult lastError() const;

private:
    enum class SessionKind
    {
        OneShot,
        LongRunning,
    };

    struct Session
    {
        QString profileId;
        QString protocol;
        QString configPath;
        QString temporaryConfigDirectory;
        QString program;
        SessionKind kind = SessionKind::OneShot;
    };

    BackendResult failure(const QString &code, const QString &message);
    static QString normalizeProtocol(const QString &protocol);
    static bool isSupportedProtocol(const QString &protocol);
    static QStringList candidatesForProtocol(const QString &protocol);
    static bool isLongRunningProtocol(const QString &protocol);
    static QStringList argumentsForProtocol(const QString &protocol,
                                            const QString &configPath);
    bool prepareFullTunnelConfig(const Profile &profile,
                                 const QString &protocol,
                                 QString &configPath,
                                 QString &temporaryDirectory,
                                 QString *error) const;
    bool configIsUsable(const Profile &profile, BackendResult &result) const;

    std::shared_ptr<CommandRunner> m_runner;
    QString m_configRoot;
    bool m_requireRootOwnedConfig = false;
    QString m_stagingRoot;
    std::unique_ptr<Session> m_session;
    BackendResult m_lastError;
};

} // namespace amnezia::headless

#endif // AMNEZIA_HEADLESS_VPN_BACKEND_H
