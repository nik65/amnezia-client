#ifndef AMNEZIA_HEADLESS_UPDATE_MANAGER_H
#define AMNEZIA_HEADLESS_UPDATE_MANAGER_H

#include <QJsonObject>
#include <QMap>
#include <QString>
#include <QUrl>

#include <memory>

#include "profileStore.h"
#include "vpnBackend.h"

namespace amnezia::headless
{

struct HeadlessUpdateResult
{
    bool ok = false;
    QString code;
    QString message;
};

class HeadlessUpdateManager final
{
public:
    explicit HeadlessUpdateManager(std::shared_ptr<CommandRunner> runner = {},
                                   QString statePath = {},
                                   QString installDirectory = {},
                                   bool requireRootOwnedFiles = true);

    // A check is deliberately synchronous: the daemon invokes it from its
    // low-frequency timer, while all network and archive bounds are finite.
    HeadlessUpdateResult checkAndApply(const Profile &profile,
                                       const QString &currentVersion);
    HeadlessUpdateResult rollback();
    QJsonObject status() const;

private:
    struct Candidate
    {
        QString version;
        QString platform;
        QUrl url;
        QString sha256;
        qint64 size = -1;
        bool autoInstall = false;
        QString format;
    };

    HeadlessUpdateResult failure(const QString &code, const QString &message);
    HeadlessUpdateResult parseManifest(const QByteArray &manifest,
                                       const QUrl &manifestUrl,
                                       const Profile &profile,
                                       const QString &publicKeyPath,
                                       const QString &currentVersion,
                                       Candidate &candidate) const;
    bool download(const Candidate &candidate, const QString &path,
                  QString *error) const;
    bool extract(const Candidate &candidate, const QString &archivePath,
                 const QString &directory, QString *error) const;
    bool install(const Candidate &candidate, const QString &payloadDirectory,
                 const QString &currentVersion, QString *error);
    bool restartService(QString *error) const;
    bool restoreRollback(QString *error);
    bool loadState();
    bool saveState() const;
    bool writeJournal(const QJsonObject &journal, QString *error) const;
    bool writeRollbackReceipt(QString *error) const;
    bool loadRollbackReceipt();
    bool verifyTrustedKey(const QString &configuredPath, QString *error) const;
    bool verifyInstallFile(const QString &path, QString *error) const;
    bool verifyRollbackFile(const QString &path, const QString &expectedSha256,
                            QString *error) const;
    bool verifyInstalledFile(const QString &path, const QString &expectedSha256,
                             qint64 expectedSize, QString *error) const;
    bool restoreCurrentPair(QString *error);
    static QString trustedUpdatePublicKeyPath();
    static QString sha256ForFile(const QString &path);
    static bool verifyEnvelope(const QJsonObject &envelope,
                               const QString &publicKeyPath,
                               QByteArray &payload);
    static bool decodeStrict(const QByteArray &encoded, bool urlSafe,
                             QByteArray &decoded);
    static bool validVersion(const QString &value);
    static bool validSha256(const QString &value);
    static bool validArtifactUrl(const Profile &profile,
                                 const QUrl &manifestUrl,
                                 const QString &rawUrl,
                                 QUrl &resolved);
    static bool runProcess(const QString &program, const QStringList &arguments,
                           int timeoutMs, QString *output, QString *error);
    static bool atomicReplace(const QString &source, const QString &destination,
                              QString *error);

    std::shared_ptr<CommandRunner> m_runner;
    QString m_statePath;
    QString m_updateRoot;
    QString m_installDirectory;
    QString m_lastCheckedAt;
    QString m_lastAppliedVersion;
    QString m_lastState = QStringLiteral("never_checked");
    QString m_lastError;
    QString m_rollbackDirectory;
    QString m_rollbackVersion;
    QMap<QString, QString> m_rollbackHashes;
    QString m_candidatePlatform;
    QString m_journalPath;
    QString m_rollbackReceiptPath;
    QString m_currentRollbackDirectory;
    bool m_stateValid = true;
    bool m_updateInProgress = false;
    bool m_requireRootOwnedFiles = true;
};

} // namespace amnezia::headless

#endif // AMNEZIA_HEADLESS_UPDATE_MANAGER_H
