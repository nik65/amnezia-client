#ifndef AMNEZIA_HEADLESS_VPN_BACKEND_H
#define AMNEZIA_HEADLESS_VPN_BACKEND_H

#include <QJsonObject>
#include <QDateTime>
#include <QList>
#include <QMap>
#include <QString>
#include <QStringList>

#include <memory>

#include "profileStore.h"

namespace amnezia::headless
{
class EmbeddedAwgBackend;

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
    // Mock/injected runners never start a real userspace tunnel implicitly.
    virtual bool supportsEmbeddedProcessOwnership() const { return false; }

    virtual bool isAvailable(const QString &program) const = 0;
    virtual QString resolveExecutable(const QStringList &candidates) const = 0;
    virtual CommandResult run(const QString &program, const QStringList &arguments) = 0;
    // Execute a bounded set of argv-only commands in one privileged helper.
    // The default keeps third-party runners source-compatible; Linux routing
    // overrides this with `ip -batch` so large server allow-lists do not spawn
    // one process per destination.
    virtual CommandResult runBatch(const QString &program,
                                   const QList<QStringList> &commands)
    {
        for (const QStringList &command : commands) {
            const CommandResult result = run(program, command);
            if (!result.ok) return result;
        }
        return { true, 0, {} };
    }
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
    explicit RealCommandRunner(QString stagingRoot = {});
    ~RealCommandRunner() override;
    bool supportsEmbeddedProcessOwnership() const override { return true; }

    bool isAvailable(const QString &program) const override;
    QString resolveExecutable(const QStringList &candidates) const override;
    CommandResult run(const QString &program, const QStringList &arguments) override;
    CommandResult runBatch(const QString &program,
                           const QList<QStringList> &commands) override;
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
    // Trusted runtime/staging root supplied by the installed service.  This
    // is used for ip -batch input because ProtectSystem may make /tmp
    // unavailable even though the unit grants access to /run/amnezia.
    QString m_stagingRoot;
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
    ~VpnBackend();

    BackendResult connect(const Profile &profile);
    BackendResult connectMigrationCandidate(const Profile &original, const QString &candidatePath,
                                            const QString &trustedRoot, const QString &sourceSha256);
    BackendResult disconnect();
    QJsonObject doctor() const;

    QString activeProfile() const;
    QString activeInterface() const;
    QString activeConfigPath() const { return m_session ? m_session->configPath : QString(); }
    bool sessionAlive() const;
    bool interfaceHealthy(const QString &interfaceName) const;
    bool sessionHealthyAfterRouting() const;
    // Migration acceptance is tied to this attempt, never the sticky health
    // observation used for an ordinary idle session.
    bool migrationHandshakeObserved(const QString &expectedPeer, qint64 startedAt) const;
    bool migrationParametersApplied(const QMap<QString, QString> &parameters) const;
    bool configuredInterfacePresent(const Profile &profile) const;
    bool configuredDnsBindingPresent(const Profile &profile) const;
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
        QString interfaceName;
        SessionKind kind = SessionKind::OneShot;
        bool handshakeObserved = false;
    };

    BackendResult failure(const QString &code, const QString &message);
    static QString normalizeProtocol(const QString &protocol);
    static bool isSupportedProtocol(const QString &protocol);
    static QStringList candidatesForProtocol(const QString &protocol);
    static bool isLongRunningProtocol(const QString &protocol);
    static QStringList argumentsForProtocol(const QString &protocol,
                                            const QString &configPath);
    bool prepareManagedNativeConfig(const Profile &profile,
                                 const QString &protocol,
                                 QString &configPath,
                                 QString &temporaryDirectory,
                                 QString *error) const;
    bool configIsUsable(const Profile &profile, BackendResult &result) const;
    bool interfaceHealthy(const QString &interfaceName,
                          bool requireRecentHandshake) const;

    std::shared_ptr<CommandRunner> m_runner;
    QString m_configRoot;
    bool m_requireRootOwnedConfig = false;
    QString m_stagingRoot;
    QString m_validatedMigrationPath;
    std::unique_ptr<Session> m_session;
    std::unique_ptr<EmbeddedAwgBackend> m_embedded;
    BackendResult m_lastError;
};

} // namespace amnezia::headless

#endif // AMNEZIA_HEADLESS_VPN_BACKEND_H
