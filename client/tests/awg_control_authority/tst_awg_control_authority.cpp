#include <QCoreApplication>
#include <QDebug>
#include <QProcess>
#include <QStandardPaths>
#include <QUuid>
#include "core/utils/awgControlAuthorityStore.h"

using namespace amnezia;
using namespace amnezia::awgControlAuthority;

namespace {
int failures = 0;
void verify(bool value, const char *message)
{
    if (!value) { qCritical() << message; ++failures; }
}
QString storageId(const QJsonObject &scope)
{
    return QStringLiteral("control-authority-v1:") + QString::fromLatin1(QCryptographicHash::hash(
        QJsonDocument(scope).toJson(QJsonDocument::Compact), QCryptographicHash::Sha256).toHex());
}
} // namespace

int main(int argc, char **argv)
{
    QCoreApplication application(argc, argv);
    const bool lockChild = argc == 3 && QString::fromLocal8Bit(argv[1]) == QStringLiteral("--check-lock");
    QCoreApplication::setOrganizationName(lockChild ? QString::fromLocal8Bit(argv[2])
        : QStringLiteral("AmneziaAuthorityTests-") + QUuid::createUuid().toString(QUuid::WithoutBraces));
    QCoreApplication::setApplicationName(QStringLiteral("isolated-fixture"));
    QStandardPaths::setTestModeEnabled(true);
    const QString fixtureRoot = QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation);
    ServerCredentials credentials;
    credentials.hostName = QStringLiteral("vpn.example.test");
    credentials.userName = QStringLiteral("admin");
    credentials.secretData = QStringLiteral("not-persisted-fixture-secret");
    credentials.sshHostKeyFingerprint = QStringLiteral("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    const auto scope = identity(QStringLiteral("fixture-server"), credentials, QStringLiteral("amnezia-awg"));
    if (lockChild) {
        Store competitor(nullptr, scope);
        QString error;
        return !competitor.lock(&error) && error == QStringLiteral("authority_busy") ? 0 : 9;
    }
    verify(!scope.isEmpty(), "valid explicit identity");
    credentials.secretData = QStringLiteral("rotated-secret");
    verify(scope == identity(QStringLiteral("fixture-server"), credentials, QStringLiteral("amnezia-awg")),
        "credential rotation must not reset authority identity");
    verify(!QJsonDocument(scope).toJson().contains("secret"), "scope stores no password");
    const QString oldSha(64, QChar('a')), newSha(64, QChar('b')), journal(64, QChar('c'));
    verify(!digest(oldSha + QLatin1Char('\n')), "digest rejects final newline");
    auto badFingerprint = credentials;
    badFingerprint.sshHostKeyFingerprint += QLatin1Char('\n');
    verify(identity(QStringLiteral("fixture-server"), badFingerprint, QStringLiteral("amnezia-awg")).isEmpty(),
        "fingerprint rejects final newline");
    const auto interruptedScope = identity(QStringLiteral("lost-prepare"), credentials, QStringLiteral("amnezia-awg"));
    {
        Store intent(nullptr, interruptedScope);
        verify(intent.lock() && intent.beginPrepare(oldSha), "prepare intent persisted before lost reply");
    }
    {
        Store restarted(nullptr, interruptedScope);
        verify(restarted.lock(), "prepare restart obtains lock");
        const auto saved = restarted.load();
        verify(saved.ok && !saved.missing && saved.record.value("state") == "pendingPrepare",
               "lost PREPARE reply survives reload as pending");
        verify(!restarted.beginPrepare(oldSha) && !restarted.anchorCurrent(7, oldSha),
               "restart cannot discard uncertain PREPARE or manufacture CURRENT");
    }
    const QString retainedDirectory = QStringLiteral("/tmp/amnezia-migration-maintenance-") + QString(24, QChar('d'));
    {
        Store store(nullptr, scope);
        verify(!store.load().ok, "unlocked reads refused");
        verify(store.lock(), "fresh private store locks after key initialization");
        verify(store.matches(credentials, QStringLiteral("amnezia-awg")), "operation matches immutable SSH scope");
        verify(!store.matches(credentials, QStringLiteral("amnezia-awg2")), "wrong source cannot use locked store");
        verify(store.lock(), "lock is idempotent for same operation");
        Store concurrent(nullptr, scope);
        verify(!concurrent.lock(), "second operation cannot race across pending and commit");
        QProcess competingProcess;
        competingProcess.start(QCoreApplication::applicationFilePath(),
            {QStringLiteral("--check-lock"), QCoreApplication::organizationName()});
        verify(competingProcess.waitForFinished(5000) && competingProcess.exitStatus() == QProcess::NormalExit
            && competingProcess.exitCode() == 0, "independent process cannot race authority operation");
        verify(store.load().ok && store.load().missing, "fresh state distinguished from corruption");
        verify(store.beginPrepare(oldSha), "known bundled SHA starts durable prepare intent");
        verify(!store.anchorCurrent(7, newSha), "explicit pin cannot erase pending prepare");
        verify(!store.commitPrepare(7, newSha), "receipt cannot replace independent prepare SHA");
        verify(!store.commitPrepare(0, oldSha), "invalid generation refused");
        verify(store.commitPrepare(7, oldSha), "successful prepare binds known SHA to generation");
        verify(store.anchorCurrent(7, oldSha), "identical explicit pin is stable");
        verify(!store.anchorCurrent(7, newSha), "conflicting operator pin cannot overwrite CURRENT");
        verify(!store.beginMaintenance(8, oldSha, newSha, journal), "generation mismatch refused");
        verify(!store.beginMaintenance(7, newSha, newSha, journal), "replacement cannot masquerade as CURRENT");
        verify(store.beginMaintenance(7, oldSha, newSha, journal, nullptr, retainedDirectory), "known current permits durable pending replacement");
    }
    {
        Store reloaded(nullptr, scope);
        verify(reloaded.lock(), "restarted operation obtains lock");
        const auto pending = reloaded.load();
        verify(pending.ok && pending.record.value("state") == "pendingMaintenance", "uncertain intent survives reload");
        verify(pending.record.value("retainedDirectory").toString() == retainedDirectory,
               "recovery input location survives transport/process loss");
        verify(!reloaded.beginMaintenance(7, oldSha, newSha, journal), "pending blocks ordinary retry");
        verify(!reloaded.commitMaintenance(7, oldSha, journal), "unknown replacement receipt refused");
        verify(!reloaded.resolvePendingMaintenance(7, journal), "recovery cannot invent a third digest");
        verify(reloaded.resolvePendingMaintenance(7, oldSha), "verified rollback may restore only authorized old digest");
        verify(reloaded.beginMaintenance(7, oldSha, newSha, journal), "new bounded attempt after explicit recovery");
        verify(reloaded.commitMaintenance(7, oldSha, newSha), "verified committed receipt advances CURRENT");
        verify(reloaded.load().record.value("currentSha") == newSha, "new CURRENT persisted");
        verify(reloaded.beginMaintenance(7, newSha, newSha, journal), "same-byte no-op remains supported");
        verify(reloaded.commitMaintenance(7, newSha, newSha), "same-byte receipt commits without inventing replacement");
    }
    {
        Store otherSource(nullptr, identity(QStringLiteral("fixture-server"), credentials, QStringLiteral("amnezia-awg2")));
        verify(otherSource.lock() && otherSource.load().missing, "source scope does not import another authority");
    }
    {
        // Corrupt storage must remain evidence of failure, never fresh state.
        Store corrupt(nullptr, scope);
        verify(corrupt.lock(), "corruption fixture locks");
        const auto original = corrupt.load().record;
        auto unexpectedField = original;
        unexpectedField.insert(QStringLiteral("unexpected"), true);
        auto wrongIdentity = original;
        wrongIdentity.insert(QStringLiteral("identity"), QJsonObject{});
        auto booleanGeneration = original;
        booleanGeneration.insert(QStringLiteral("generation"), true);
        for (const auto &invalid : {unexpectedField, wrongIdentity, booleanGeneration}) {
            verify(awgMigrationSecretStore::write(storageId(scope), QJsonDocument(invalid).toJson(QJsonDocument::Compact)),
                "malformed schema fixture persisted");
            verify(!corrupt.load().ok && !corrupt.load().missing, "malformed schema and identity fail closed");
        }
        verify(awgMigrationSecretStore::write(storageId(scope), QByteArrayLiteral("not-json")), "corruption fixture persisted");
        verify(!corrupt.load().ok && !corrupt.load().missing, "corrupt state cannot re-anchor silently");
        verify(!corrupt.anchorCurrent(7, newSha), "explicit pin cannot overwrite unreadable authority");
    }
    // Only this random test-mode application tree is removed, after all locks.
    verify(fixtureRoot.contains(QStringLiteral("AmneziaAuthorityTests-"))
        && QDir(fixtureRoot).removeRecursively(), "owned fixture cleanup");
    return failures == 0 ? 0 : 1;
}
