#pragma once

#include <QByteArray>
#include <QJsonObject>
#include <QString>
#include <QStringList>
#include <memory>
#include <sys/types.h>

namespace amnezia::headless
{

    struct RollbackCoordinatorResult
    {
        bool ok = false;
        QString code;
        QString message;
        QJsonObject evidence;
    };

    // Explicit constructor paths are an owned-test seam, never accepted by CLI.
    struct RollbackCoordinatorPaths
    {
        QString root = QStringLiteral("/var/lib/amnezia/rollback-coordinator");
        QString profiles = QStringLiteral("/var/lib/amnezia/profiles.json");
        QString state = QStringLiteral("/var/lib/amnezia/headless-updates.json");
        QString install = QStringLiteral("/usr/local/bin");
        QString unit = QStringLiteral("/etc/systemd/system/amnezia-rollback-coordinator.service");
        QString socket = QStringLiteral("/run/amnezia/amneziad.sock");
        uid_t owner = 0;
        bool verifySelfExecutable = true; // owned native fixture seam, never CLI-selectable
    };

    class RollbackCoordinatorPlatform
    {
    public:
        virtual ~RollbackCoordinatorPlatform() = default;
        virtual QJsonObject observe(const RollbackCoordinatorPaths &, QString *error) = 0;
        virtual bool stop(QString *error) = 0;
        virtual bool start(QString *error) = 0;
        virtual bool stopped(QString *error) = 0;
        virtual bool installUnit(QString *error) = 0;
        virtual bool startWorker(QString *error) = 0;
        virtual bool acknowledge(const RollbackCoordinatorPaths &, const QString &targetVersion, QString *error) = 0;
        virtual bool retireUnit(QString *error) = 0;
        virtual bool stopObserved(const RollbackCoordinatorPaths &, const QJsonObject &, QString *error);
        virtual bool observedProcessGone(const QJsonObject &, QString *error);
        virtual void waitForObservationRetry();
        virtual qint64 monotonicMilliseconds();
    };

    class RollbackCoordinator
    {
    public:
        explicit RollbackCoordinator(RollbackCoordinatorPaths paths = {},
                                     std::shared_ptr<RollbackCoordinatorPlatform> platform = {});
        // Root CLI preflight: retain the authenticated installed CLI/unit. No pause.
        RollbackCoordinatorResult prepare();
        // Daemon admission: raw JSON all-profile pause/CAS; parent reloads ProfileStore.
        RollbackCoordinatorResult admitRollback();
        // Invoke after actual manager.rollback() persisted its pending state/journal.
        RollbackCoordinatorResult rollbackRequested();
        RollbackCoordinatorResult run();
        RollbackCoordinatorResult resume();
        RollbackCoordinatorResult status(bool requireRetainedExecutable = false);
        static QString profileWriterLockPath(const QString &profiles);
        static int dispatch(const QStringList &arguments);

    private:
        RollbackCoordinatorPaths m_paths;
        std::shared_ptr<RollbackCoordinatorPlatform> m_platform;
        RollbackCoordinatorResult failure(const QString &, const QString &) const;
    };

} // namespace amnezia::headless
