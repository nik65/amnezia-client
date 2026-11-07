#include <QCoreApplication>
#include <QDebug>
#include <QElapsedTimer>
#include <QProcess>
#include <QStandardPaths>
#include <QUuid>
#include "core/utils/awgControlAuthorityStore.h"
#include "core/controllers/selfhosted/awgMaintenanceReceipt.h"

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
QString prepareCleanupStorageId(const QJsonObject &scope)
{
    return QStringLiteral("control-prepare-cleanup-v1:") + QString::fromLatin1(QCryptographicHash::hash(
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
        verify(!restarted.resolvePendingPrepare(7, newSha), "prepare recovery cannot accept unrelated digest");
        verify(restarted.resolvePendingPrepare(7, oldSha), "trusted prepare recovery uses original bundled digest");
        verify(restarted.load().record.value("state") == "current", "verified prepare recovery settles pending state");
    }
    const QString retainedDirectory = QStringLiteral("/tmp/amnezia-migration-maintenance-") + QString(24, QChar('d'));
    const QString retainedIdentity = QStringLiteral("0 0 700 123 456");
    const QString retainedUpload = QStringLiteral("/tmp/amnezia-migration-upload-") + QString(24, QChar('e'));
    const QString endpointHost = QStringLiteral("edge.example.test");
    QString prepareOperationId;
    const auto retiredScope = identity(QStringLiteral("retired-prepare"), credentials, QStringLiteral("amnezia-awg"));
    QString retiredOperationId;
    {
        Store interrupted(nullptr, retiredScope);
        verify(interrupted.lock() && interrupted.beginPrepare(oldSha, nullptr, endpointHost),
               "retirement fixture persists independent prepare intent");
        const auto pending = interrupted.load().record;
        retiredOperationId = pending.value("operationId").toString();
        verify(!interrupted.retirePrepare(7, newSha, retiredOperationId, journal), "wrong pin cannot retire prepare");
        verify(!interrupted.retirePrepare(7, oldSha, QUuid::createUuid().toString(QUuid::WithoutBraces), journal),
               "wrong operation cannot retire prepare");
        verify(!interrupted.retirePrepare(0, oldSha, retiredOperationId, journal)
            && !interrupted.retirePrepare(9007199254740992LL, oldSha, retiredOperationId, journal),
               "invalid retirement generation refused");
        verify(!interrupted.retirePrepare(7, oldSha, retiredOperationId, journal + QLatin1Char('\n')),
               "retirement requires exact native journal digest");
        verify(interrupted.load().record == pending, "invalid retirements cannot mutate pending intent");
        const QJsonObject abortReceipt{{"ok", true}, {"mode", "abort-prepare"}, {"source", "amnezia-awg"},
            {"generation", 7}, {"native", true}, {"pendingRecovery", false}, {"phase", "aborted"},
            {"liveVerified", false}, {"retiredVerified", true}, {"clientOperationId", retiredOperationId},
            {"controlHashes", QJsonObject{{"awg-feed", oldSha}}}, {"journalSha256", journal}};
        verify(AwgMaintenance::validNativeOperationReceipt(abortReceipt, "abort-prepare", "amnezia-awg", 7,
            oldSha, retiredOperationId), "actual Qt helper binds abort receipt to original pending intent");
        auto foreignAbort = abortReceipt;
        foreignAbort.insert(QStringLiteral("clientOperationId"), QUuid::createUuid().toString(QUuid::WithoutBraces));
        verify(!AwgMaintenance::validNativeOperationReceipt(foreignAbort, "abort-prepare", "amnezia-awg", 7,
            oldSha, retiredOperationId) && interrupted.load().record == pending,
               "foreign abort receipt cannot authorize Store retirement");
        verify(interrupted.retirePrepare(abortReceipt.value("generation").toInteger(), oldSha, retiredOperationId,
            abortReceipt.value("journalSha256").toString()), "trusted exact abort persists retired tombstone");
    }
    {
        Store retry(nullptr, retiredScope);
        verify(retry.lock(), "retired prepare reload obtains lock");
        const auto tombstone = retry.load();
        verify(tombstone.ok && tombstone.record.value("state") == "retiredPrepare"
            && tombstone.record.value("generation").toInteger() == 7
            && tombstone.record.value("currentSha") == oldSha
            && tombstone.record.value("operationId") == retiredOperationId
            && tombstone.record.value("endpointHost") == endpointHost
            && tombstone.record.value("retiredVerified").toBool(),
               "retirement evidence and generation survive process restart");
        verify(!retry.anchorCurrent(7, oldSha) && !retry.commitPrepare(7, oldSha),
               "retirement cannot masquerade as fresh state or committed prepare");
        auto unverifiedTombstone = tombstone.record;
        unverifiedTombstone.insert(QStringLiteral("retiredVerified"), false);
        verify(awgMigrationSecretStore::write(storageId(retiredScope),
            QJsonDocument(unverifiedTombstone).toJson(QJsonDocument::Compact)), "malformed retirement fixture persisted");
        verify(!retry.load().ok, "unverified retirement record rejected");
        verify(awgMigrationSecretStore::write(storageId(retiredScope),
            QJsonDocument(tombstone.record).toJson(QJsonDocument::Compact)), "verified retirement fixture restored");
        verify(retry.beginPrepare(newSha, nullptr, endpointHost), "new prepare may follow verified retirement");
        const auto pending = retry.load().record;
        const auto operation = pending.value("operationId").toString();
        verify(operation != retiredOperationId && !QUuid(operation).isNull(), "retry receives independent operation nonce");
        verify(pending.value("minimumGeneration").toInteger() == 8, "retry binds next generation floor");
        verify(!retry.commitPrepare(7, newSha) && !retry.commitPrepare(8, oldSha),
               "old generation or old pin cannot commit fresh intent");
        verify(!retry.retirePrepare(7, newSha, operation, journal)
            && !retry.retirePrepare(8, newSha, retiredOperationId, journal),
               "old generation or old nonce cannot retire fresh intent");
        verify(retry.load().record == pending, "replayed old receipt leaves retry pending");
        const QString secondJournal(64, 'd');
        verify(retry.retirePrepare(8, newSha, operation, secondJournal), "second verified abort appends predecessor proof");
        const QJsonArray expectedHistory{
            QJsonObject{{"generation", 7}, {"sha256", oldSha}, {"operationId", retiredOperationId}, {"journalSha256", journal}},
            QJsonObject{{"generation", 8}, {"sha256", newSha}, {"operationId", operation}, {"journalSha256", secondJournal}}};
        verify(retry.load().record.value("retiredPredecessors").toArray() == expectedHistory,
               "second abort preserves both exact independently verified predecessor proofs");
        verify(retry.beginPrepare(newSha, nullptr, endpointHost), "third intent follows complete retirement history");
        const auto newOperation = retry.load().record.value("operationId").toString();
        verify(newOperation != operation && newOperation != retiredOperationId, "third attempt cannot reuse predecessor nonce");
        verify(!retry.commitPrepare(8, newSha) && !retry.retirePrepare(9, newSha, operation, secondJournal),
               "second predecessor generation and nonce cannot settle third attempt");
        verify(retry.commitPrepare(9, newSha), "higher generation known pin commits new intent");
        verify(retry.load().record.value("minimumGeneration").toInteger() == 9
            && retry.load().record.value("prepareOperationId") == newOperation,
               "new CURRENT preserves minimum generation and causal nonce");
        const auto current = retry.load().record;
        verify(current.value("retiredPredecessors").toArray() == expectedHistory, "CURRENT preserves complete predecessor history");
        auto duplicate = expectedHistory;
        duplicate[1] = duplicate[0];
        const QJsonArray unsorted{expectedHistory[1], expectedHistory[0]};
        auto duplicateNonce = expectedHistory;
        auto badNonceProof = duplicateNonce[1].toObject();
        badNonceProof.insert(QStringLiteral("operationId"), retiredOperationId);
        duplicateNonce[1] = badNonceProof;
        auto extra = expectedHistory;
        auto extraProof = extra[0].toObject(); extraProof.insert(QStringLiteral("unexpected"), true); extra[0] = extraProof;
        for (const auto &invalidHistory : {duplicate, unsorted, duplicateNonce, extra}) {
            auto malformed = current;
            malformed.insert(QStringLiteral("retiredPredecessors"), invalidHistory);
            verify(awgMigrationSecretStore::write(storageId(retiredScope), QJsonDocument(malformed).toJson(QJsonDocument::Compact)),
                   "malformed history fixture persisted");
            verify(!retry.load().ok, "duplicate unsorted extra or nonce-replayed history rejected");
        }
        verify(awgMigrationSecretStore::write(storageId(retiredScope), QJsonDocument(current).toJson(QJsonDocument::Compact)),
               "valid exact predecessor history restored");
        verify(retry.anchorCurrent(9, newSha), "identical anchor accepts validated generation floor and history");
        verify(retry.beginMaintenance(9, newSha, oldSha, journal, nullptr, retainedDirectory, retainedIdentity, retainedUpload)
            && retry.commitMaintenance(9, newSha, oldSha), "maintenance after retired retry commits exact replacement");
        verify(retry.load().record.value("minimumGeneration").toInteger() == 9,
               "maintenance settlement preserves retirement generation floor");
        verify(retry.completeCleanup(retainedDirectory, retainedIdentity)
            && retry.load().record.value("minimumGeneration").toInteger() == 9
            && retry.load().record.value("retiredPredecessors").toArray() == expectedHistory,
               "cleanup completion cannot erase retirement generation floor");
    }
    {
        const auto exhaustedScope = identity(QStringLiteral("exhausted-prepare"), credentials, QStringLiteral("amnezia-awg"));
        Store exhausted(nullptr, exhaustedScope);
        verify(exhausted.lock() && exhausted.beginPrepare(oldSha), "generation exhaustion fixture starts actual intent");
        const auto operation = exhausted.load().record.value("operationId").toString();
        verify(exhausted.retirePrepare(9007199254740991LL, oldSha, operation, journal), "maximum retirement generation is durable");
        const auto before = exhausted.load().record;
        QString error;
        verify(!exhausted.beginPrepare(newSha, &error)
            && error == QStringLiteral("authority_generation_exhausted") && exhausted.load().record == before,
               "retired maximum generation cannot overflow or reset authority");
    }
    {
        const auto fullScope = identity(QStringLiteral("full-retired-history"), credentials, QStringLiteral("amnezia-awg"));
        Store full(nullptr, fullScope);
        verify(full.lock(), "maximum history fixture locks actual store");
        for (qint64 number = 1; number <= 32; ++number) {
            verify(full.beginPrepare(oldSha), "bounded retirement sequence starts only while room remains");
            const auto operation = full.load().record.value("operationId").toString();
            verify(full.retirePrepare(number, oldSha, operation, journal), "each abort extends exact predecessor history");
        }
        const auto before = full.load().record;
        verify(before.value("retiredPredecessors").toArray().size() == 32, "all 32 predecessor proofs retained");
        QString error;
        verify(!full.beginPrepare(newSha, &error) && error == QStringLiteral("authority_retired_history_exhausted")
            && full.load().record == before, "full history refuses next mutation instead of dropping tombstones");
    }
    const auto sidecarScope = identity(QStringLiteral("prepare-sidecar"), credentials, QStringLiteral("amnezia-awg"));
    const QJsonObject prepareRoots{{"programDirectory", "/tmp/amnezia-migration-programs-" + QString(24, 'h')},
        {"programIdentity", "0 0 700 123 987"}, {"stagingDirectory", "/tmp/amnezia-migration-" + QString(24, 'i')},
        {"stagingIdentity", "1000 1001 700 123 654"}};
    QJsonObject sidecarRecord;
    {
        Store staged(nullptr, sidecarScope);
        verify(!staged.loadPrepareCleanup().ok, "unlocked PREPARE sidecar reads refused");
        verify(staged.lock() && staged.load().missing && staged.loadPrepareCleanup().missing,
               "missing authority and missing sidecar are independent fresh states");
        for (const auto &change : QList<QPair<QString,QJsonValue>>{
                {"programDirectory", prepareRoots.value("programDirectory").toString() + '\n'},
                {"programIdentity", "1000 0 700 123 987"}, {"programIdentity", "0 0 755 123 987"},
                {"stagingIdentity", "-1 1001 700 123 654"}, {"stagingIdentity", "4294967296 1001 700 123 654"},
                {"stagingIdentity", "1000 1001 700 123 18446744073709551616"}, {"stagingDirectory", true},
                {"extra", "unsafe-leaf"}}) {
            auto invalid = prepareRoots; invalid.insert(change.first,change.second);
            verify(!staged.beginPrepareCleanup(invalid) && staged.loadPrepareCleanup().missing,
                   "invalid ownership paths or extra cleanup fields cannot create sidecar");
        }
        verify(staged.beginPrepareCleanup(prepareRoots), "exact owned roots persist before preflight");
        verify(staged.load().missing, "cleanup intent cannot manufacture pendingPrepare before preflight");
        sidecarRecord = staged.loadPrepareCleanup().record;
        verify(sidecarRecord.size() == 8 && sidecarRecord.value("programFiles").toArray().size() == 2
            && sidecarRecord.value("stagingFiles").toArray().size() == 11, "sidecar records only exact fixed leaf sets");
        verify(!staged.beginPrepareCleanup(prepareRoots), "existing sidecar cannot be replaced implicitly");
    }
    {
        Store staged(nullptr, sidecarScope);
        verify(staged.lock() && staged.loadPrepareCleanup().record == sidecarRecord && staged.load().missing,
               "restart finds staging ownership without manufacturing a remote transaction");
        auto wrong = prepareRoots; wrong.insert(QStringLiteral("stagingIdentity"), "1000 1001 700 123 655");
        verify(!staged.completePrepareCleanup(wrong) && !staged.completePrepareCleanup(sidecarRecord)
            && staged.loadPrepareCleanup().record == sidecarRecord, "only exact four roots can acknowledge sidecar cleanup");
        verify(staged.beginPrepare(oldSha, nullptr, endpointHost), "actual preflight success can still create normal intent");
        const auto operation = staged.load().record.value("operationId").toString();
        verify(staged.retirePrepare(7,oldSha,operation,journal)
            && staged.loadPrepareCleanup().record == sidecarRecord, "retirement never drops independent staging ownership");
        verify(staged.beginPrepare(newSha, nullptr, endpointHost) && staged.commitPrepare(8,newSha)
            && staged.loadPrepareCleanup().record == sidecarRecord, "new prepare and commit preserve sidecar unchanged");
        verify(staged.beginMaintenance(8,newSha,oldSha,journal) && staged.commitMaintenance(8,newSha,oldSha)
            && staged.loadPrepareCleanup().record == sidecarRecord, "maintenance changes cannot erase PREPARE sidecar");
        const auto main = staged.load().record;
        verify(staged.completePrepareCleanup(prepareRoots) && staged.loadPrepareCleanup().missing
            && staged.load().record == main, "exact cleanup removes only independent sidecar");
        verify(!staged.completePrepareCleanup(prepareRoots) && staged.load().record == main,
               "absent sidecar never authorizes resetting main authority");
        if (::geteuid() != 0) {
            const auto directory = awgMigrationSecretStore::directory();
            verify(QFile::setPermissions(directory,QFile::ReadOwner|QFile::ExeOwner), "write-error fixture makes only owned store read-only");
            QString error;
            verify(!staged.beginPrepareCleanup(prepareRoots,&error)
                && error == QStringLiteral("authority_prepare_cleanup_write_failed"), "sidecar write failure is visible");
            verify(QFile::setPermissions(directory,QFile::ReadOwner|QFile::WriteOwner|QFile::ExeOwner), "owned store permissions restored");
            verify(staged.loadPrepareCleanup().ok && staged.loadPrepareCleanup().missing,
                   "failed atomic sidecar write leaves genuine absence intact");
        }
        verify(staged.beginPrepareCleanup(prepareRoots), "sidecar can be recorded after actual backend recovery");
        auto extra = sidecarRecord; extra.insert(QStringLiteral("extra"), true);
        auto foreign = sidecarRecord; foreign.insert(QStringLiteral("identity"), QJsonObject{});
        auto leaves = sidecarRecord; leaves.insert(QStringLiteral("programFiles"), QJsonArray{"native-feed","foreign"});
        QList<QByteArray> corrupt{QJsonDocument(extra).toJson(QJsonDocument::Compact),
            QJsonDocument(foreign).toJson(QJsonDocument::Compact), QJsonDocument(leaves).toJson(QJsonDocument::Compact),
            QByteArray("not-json"), QJsonDocument(sidecarRecord).toJson(QJsonDocument::Compact) + '\n'};
        for (const auto &bytes : corrupt) {
            verify(awgMigrationSecretStore::write(prepareCleanupStorageId(sidecarScope),bytes), "corrupt sidecar fixture persisted");
            const auto observed = staged.loadPrepareCleanup();
            verify(!observed.ok && !observed.missing && !staged.beginPrepareCleanup(prepareRoots)
                && !staged.completePrepareCleanup(prepareRoots), "corrupt sidecar cannot become missing or be silently overwritten");
            verify(staged.load().record == main, "sidecar corruption cannot alter authoritative main state");
        }
        const auto path = awgMigrationSecretStore::journalPath(awgMigrationSecretStore::directory(),prepareCleanupStorageId(sidecarScope));
        verify(QFile::remove(path) && ::mkfifo(QFile::encodeName(path).constData(),0600) == 0,
               "owned sidecar FIFO fixture created");
        QElapsedTimer timer; timer.start();
        verify(!staged.loadPrepareCleanup().ok && timer.elapsed() < 1000, "sidecar FIFO fails promptly without blocking");
        verify(QFile::remove(path) && awgMigrationSecretStore::write(prepareCleanupStorageId(sidecarScope),
            QJsonDocument(sidecarRecord).toJson(QJsonDocument::Compact)), "valid private sidecar restored after read failure");
        verify(staged.completePrepareCleanup(prepareRoots) && staged.load().record == main,
               "verified sidecar completion leaves complete main lifecycle unchanged");
    }
    const auto probeScope = identity(QStringLiteral("probe-cleanup"), credentials, QStringLiteral("amnezia-awg"));
    const QJsonObject probeCleanup{{"directory", retainedDirectory}, {"identity", retainedIdentity},
        {"replacementSha", newSha}, {"upload", retainedUpload}};
    {
        Store probe(nullptr, probeScope);
        verify(probe.lock(), "probe lifecycle fixture locks actual store");
        verify(!probe.beginProbeCleanup(retainedDirectory, retainedIdentity, newSha, retainedUpload),
               "probe overlay cannot manufacture missing authority");
        verify(probe.beginPrepare(oldSha, nullptr, endpointHost)
            && probe.beginProbeCleanup(retainedDirectory, retainedIdentity, newSha, retainedUpload),
               "pending prepare retains helper ownership before execution");
        QString error;
        verify(!probe.beginProbeCleanup(retainedDirectory, retainedIdentity, newSha, retainedUpload, &error)
            && error == QStringLiteral("authority_probe_cleanup_required"), "second probe cannot replace pending cleanup");
    }
    {
        Store probe(nullptr, probeScope);
        verify(probe.lock(), "lost probe transport reload obtains lock");
        const auto pending = probe.load().record;
        verify(pending.value("probeCleanup").toObject() == probeCleanup, "exact probe cleanup survives process restart");
        verify(!probe.completeProbeCleanup(retainedDirectory, QStringLiteral("0 0 700 123 457"))
            && probe.load().record == pending, "wrong inode cannot erase pending probe cleanup");
        verify(probe.retirePrepare(7, oldSha, pending.value("operationId").toString(), journal)
            && probe.load().record.value("probeCleanup").toObject() == probeCleanup,
               "prepare retirement preserves outstanding helper cleanup");
        verify(probe.beginPrepare(oldSha, nullptr, endpointHost)
            && probe.load().record.value("probeCleanup").toObject() == probeCleanup,
               "new prepare cannot lose prior probe cleanup");
        verify(probe.commitPrepare(8, oldSha)
            && probe.load().record.value("probeCleanup").toObject() == probeCleanup,
               "prepare settlement retains outstanding probe cleanup");
        verify(probe.anchorCurrent(8, oldSha)
            && probe.load().record.value("probeCleanup").toObject() == probeCleanup,
               "identical anchor cannot discard exact probe cleanup");
        const auto current = probe.load().record;
        verify(!probe.beginMaintenance(8, oldSha, newSha, journal, nullptr,
            retainedDirectory, QStringLiteral("0 0 700 123 457"), retainedUpload), "wrong inode cannot transfer probe ownership");
        verify(!probe.beginMaintenance(8, oldSha, journal, journal, nullptr,
            retainedDirectory, retainedIdentity, retainedUpload), "different replacement cannot transfer probe ownership");
        verify(!probe.beginMaintenance(8, oldSha, newSha, journal, nullptr,
            retainedDirectory, retainedIdentity), "omitted upload cannot discard tracked input removal");
        verify(probe.load().record == current, "all failed transfers preserve current and overlay");
        verify(probe.beginMaintenance(8, oldSha, newSha, journal, nullptr,
            retainedDirectory, retainedIdentity, retainedUpload), "exact probe atomically becomes transaction recovery inputs");
        verify(!probe.load().record.contains("probeCleanup")
            && probe.load().record.value("retainedDirectory") == retainedDirectory
            && probe.load().record.value("retainedIdentity") == retainedIdentity
            && probe.load().record.value("retainedUpload") == retainedUpload,
               "transferred originals cannot be deleted as disposable probe files");
        verify(!probe.beginProbeCleanup(retainedDirectory, retainedIdentity, newSha, retainedUpload),
               "disposable probe cannot alias pending transaction recovery directory");
        const QString otherDirectory = "/tmp/amnezia-migration-maintenance-" + QString(24, 'f');
        const QString otherIdentity = "0 0 700 123 789";
        const QString otherUpload = "/tmp/amnezia-migration-upload-" + QString(24, 'g');
        const QJsonObject recoveryProbe{{"directory", otherDirectory}, {"identity", otherIdentity},
            {"replacementSha", newSha}, {"upload", otherUpload}};
        verify(probe.beginProbeCleanup(otherDirectory, otherIdentity, newSha, otherUpload)
            && probe.commitMaintenance(8, oldSha, newSha), "maintenance commit preserves independently owned helper");
        verify(probe.load().record.value("probeCleanup").toObject() == recoveryProbe
            && probe.load().record.value("cleanup").toObject() == probeCleanup,
               "committed original and probe cleanup remain distinct");
        const auto settled = probe.load().record;
        auto alias = settled;
        alias.insert(QStringLiteral("probeCleanup"), probeCleanup);
        verify(awgMigrationSecretStore::write(storageId(probeScope), QJsonDocument(alias).toJson(QJsonDocument::Compact)),
               "aliased cleanup fixture persisted");
        verify(!probe.load().ok, "saved probe cannot alias original committed cleanup directory");
        verify(awgMigrationSecretStore::write(storageId(probeScope), QJsonDocument(settled).toJson(QJsonDocument::Compact)),
               "distinct cleanup obligations restored");
        verify(probe.completeCleanup(retainedDirectory, retainedIdentity)
            && probe.load().record.value("probeCleanup").toObject() == recoveryProbe,
               "original cleanup cannot erase unrelated probe ownership");
        verify(probe.completeProbeCleanup(otherDirectory, otherIdentity)
            && !probe.load().record.contains("probeCleanup"), "exact verified probe removal clears only overlay");
        verify(probe.beginProbeCleanup(retainedDirectory, retainedIdentity, oldSha, retainedUpload)
            && probe.beginMaintenance(8, newSha, oldSha, journal, nullptr,
                retainedDirectory, retainedIdentity, retainedUpload)
            && probe.beginProbeCleanup(otherDirectory, otherIdentity, newSha, otherUpload)
            && probe.resolvePendingMaintenance(8, newSha), "trusted rollback preserves both cleanup obligations");
        verify(probe.load().record.value("probeCleanup").toObject() == recoveryProbe
            && probe.load().record.value("cleanup").toObject().value("replacementSha") == oldSha,
               "rollback cleanup addresses staged replacement rather than active digest");
        verify(probe.completeProbeCleanup(otherDirectory, otherIdentity)
            && probe.load().record.contains("cleanup") && probe.completeCleanup(retainedDirectory, retainedIdentity),
               "independent cleanup acknowledgements preserve remaining obligation");
        const auto clean = probe.load().record;
        auto extraProbe = probeCleanup; extraProbe.insert(QStringLiteral("extra"), true);
        auto wrongProbeIdentity = probeCleanup; wrongProbeIdentity.insert(QStringLiteral("identity"), true);
        for (const auto &invalid : {QJsonValue(true), QJsonValue(extraProbe), QJsonValue(wrongProbeIdentity)}) {
            auto malformed = clean; malformed.insert(QStringLiteral("probeCleanup"), invalid);
            verify(awgMigrationSecretStore::write(storageId(probeScope), QJsonDocument(malformed).toJson(QJsonDocument::Compact)),
                   "malformed probe schema fixture persisted");
            verify(!probe.load().ok, "probe metadata is strict even when matching known pin");
        }
        verify(awgMigrationSecretStore::write(storageId(probeScope), QJsonDocument(clean).toJson(QJsonDocument::Compact)),
               "clean probe lifecycle fixture restored");
    }
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
        verify(!store.beginPrepare(oldSha, nullptr, endpointHost + QLatin1Char('\n')),
               "endpoint cannot contain trailing control characters");
        verify(!store.beginPrepare(oldSha, nullptr, QStringLiteral("https://edge.example.test")),
               "endpoint contains only native preparation host syntax");
        verify(store.beginPrepare(oldSha, nullptr, endpointHost), "known bundled SHA starts durable prepare intent");
        prepareOperationId = store.load().record.value("operationId").toString();
        verify(!QUuid(prepareOperationId).isNull(), "prepare creates causal operation identity");
        verify(!store.anchorCurrent(7, newSha), "explicit pin cannot erase pending prepare");
        verify(!store.commitPrepare(7, newSha), "receipt cannot replace independent prepare SHA");
        verify(!store.commitPrepare(0, oldSha), "invalid generation refused");
        verify(store.commitPrepare(7, oldSha), "successful prepare binds known SHA to generation");
        verify(store.load().record.value("prepareOperationId") == prepareOperationId,
               "prepare commit retains independent causal operation identity");
        verify(store.load().record.value("endpointHost") == endpointHost,
               "prepare commit retains selected endpoint context");
        verify(store.anchorCurrent(7, oldSha), "identical explicit pin is stable");
        verify(store.load().record.value("prepareOperationId") == prepareOperationId,
               "explicit same pin cannot remove prepare operation identity");
        verify(!store.anchorCurrent(7, newSha), "conflicting operator pin cannot overwrite CURRENT");
        verify(!store.beginMaintenance(8, oldSha, newSha, journal), "generation mismatch refused");
        verify(!store.beginMaintenance(7, newSha, newSha, journal), "replacement cannot masquerade as CURRENT");
        verify(!store.beginMaintenance(7, oldSha, newSha, journal, nullptr, retainedDirectory),
               "new recovery path cannot be retained without proven identity");
        verify(!store.beginMaintenance(7, oldSha, newSha, journal, nullptr, {}, retainedIdentity),
               "identity without recovery path refused");
        verify(!store.beginMaintenance(7, oldSha, newSha, journal, nullptr, {}, {}, retainedUpload),
               "upload without proven recovery directory refused");
        verify(!store.beginMaintenance(7, oldSha, newSha, journal, nullptr,
            retainedDirectory, retainedIdentity, retainedUpload + QLatin1Char('\n')),
               "noncanonical upload cleanup path refused");
        for (const auto &invalidIdentity : {QStringLiteral("0 0 700 01 456"), QStringLiteral("0 0 700 -1 456"),
                QStringLiteral("0 0 700 18446744073709551616 456"), QStringLiteral("0 0 700 123 456\n"),
                QStringLiteral("1000 0 700 123 456"), QStringLiteral("0 0 755 123 456")}) {
            verify(!store.beginMaintenance(7, oldSha, newSha, journal, nullptr, retainedDirectory, invalidIdentity),
                   "noncanonical or untrusted recovery identity refused");
        }
        verify(store.beginMaintenance(7, oldSha, newSha, journal, nullptr, retainedDirectory, retainedIdentity, retainedUpload),
               "known current permits durable pending replacement with exact ownership");
    }
    {
        Store reloaded(nullptr, scope);
        verify(reloaded.lock(), "restarted operation obtains lock");
        const auto pending = reloaded.load();
        verify(pending.ok && pending.record.value("state") == "pendingMaintenance", "uncertain intent survives reload");
        verify(pending.record.value("retainedDirectory").toString() == retainedDirectory,
               "recovery input location survives transport/process loss");
        verify(pending.record.value("retainedIdentity").toString() == retainedIdentity,
               "recovery input ownership survives transport/process loss");
        verify(pending.record.value("retainedUpload").toString() == retainedUpload,
               "original unprivileged upload location survives process loss");
        verify(pending.record.value("prepareOperationId") == prepareOperationId,
               "reloaded maintenance preserves original prepare identity");
        verify(pending.record.value("endpointHost") == endpointHost,
               "reloaded maintenance preserves captured endpoint context");
        verify(pending.record.value("operationId") != prepareOperationId,
               "maintenance operation uses independent intent identity");
        verify(!reloaded.beginMaintenance(7, oldSha, newSha, journal), "pending blocks ordinary retry");
        verify(!reloaded.commitMaintenance(7, oldSha, journal), "unknown replacement receipt refused");
        verify(!reloaded.resolvePendingMaintenance(7, journal), "recovery cannot invent a third digest");
        verify(reloaded.resolvePendingMaintenance(7, oldSha), "verified rollback may restore only authorized old digest");
        const QJsonObject expectedCleanup{{"directory", retainedDirectory}, {"identity", retainedIdentity},
            {"replacementSha", newSha}, {"upload", retainedUpload}};
        const auto rolledBack = reloaded.load().record;
        verify(rolledBack.value("cleanup").toObject() == expectedCleanup,
               "rollback retains original replacement staging cleanup metadata");
        verify(rolledBack.value("prepareOperationId") == prepareOperationId,
               "rollback preserves original prepare identity");
        verify(rolledBack.value("endpointHost") == endpointHost, "rollback preserves original endpoint context");
        verify(reloaded.anchorCurrent(7, oldSha), "same pin remains current while cleanup is outstanding");
        QString cleanupError;
        verify(!reloaded.beginMaintenance(7, oldSha, newSha, journal, &cleanupError)
            && cleanupError == QStringLiteral("authority_cleanup_required"),
               "another maintenance cannot discard retained cleanup");
        verify(!reloaded.completeCleanup(retainedDirectory, QStringLiteral("0 0 700 123 457")),
               "different inode cannot complete cleanup");
        verify(!reloaded.completeCleanup(retainedDirectory + QLatin1Char('x'), retainedIdentity),
               "different path cannot complete cleanup");
        verify(reloaded.load().record == rolledBack, "mismatched cleanup leaves authority unchanged");
        verify(reloaded.completeCleanup(retainedDirectory, retainedIdentity), "verified exact cleanup clears obligation");
        verify(reloaded.load().record.value("prepareOperationId") == prepareOperationId,
               "cleanup completion cannot erase causal prepare identity");
        verify(reloaded.load().record.value("endpointHost") == endpointHost,
               "cleanup completion cannot erase original endpoint context");
        verify(!reloaded.completeCleanup(retainedDirectory, retainedIdentity), "absent cleanup cannot match stale request");
        verify(reloaded.beginMaintenance(7, oldSha, newSha, journal, nullptr, retainedDirectory, retainedIdentity, retainedUpload),
               "new bounded attempt after explicit recovery and cleanup");
        verify(reloaded.commitMaintenance(7, oldSha, newSha), "verified committed receipt advances CURRENT");
        verify(reloaded.load().record.value("currentSha") == newSha, "new CURRENT persisted");
        verify(reloaded.load().record.value("cleanup").toObject() == expectedCleanup,
               "committed replacement retains exact cleanup metadata");
        verify(reloaded.load().record.value("prepareOperationId") == prepareOperationId,
               "replacement commit preserves original prepare identity");
        verify(reloaded.load().record.value("endpointHost") == endpointHost,
               "replacement commit preserves original endpoint context");
        verify(reloaded.anchorCurrent(7, newSha), "same new pin accepts authenticated cleanup extension");
        verify(reloaded.completeCleanup(retainedDirectory, retainedIdentity), "committed cleanup acknowledged separately");
        verify(reloaded.beginMaintenance(7, newSha, newSha, journal), "same-byte no-op remains supported");
        verify(reloaded.commitMaintenance(7, newSha, newSha), "same-byte receipt commits without inventing replacement");
        verify(reloaded.load().record.value("prepareOperationId") == prepareOperationId,
               "same-byte maintenance preserves original prepare identity");
        verify(reloaded.load().record.value("endpointHost") == endpointHost,
               "same-byte maintenance preserves original endpoint context");
    }
    {
        const auto legacyScope = identity(QStringLiteral("legacy-recovery"), credentials, QStringLiteral("amnezia-awg"));
        Store legacy(nullptr, legacyScope);
        verify(legacy.lock() && legacy.anchorCurrent(7, oldSha)
            && legacy.beginMaintenance(7, oldSha, newSha, journal, nullptr, retainedDirectory, retainedIdentity),
               "legacy pending fixture starts from actual store");
        verify(!legacy.load().record.contains(QStringLiteral("prepareOperationId")),
               "manual anchor never invents historical prepare identity");
        verify(!legacy.load().record.contains(QStringLiteral("endpointHost")),
               "manual anchor never invents historical endpoint context");
        auto historical = legacy.load().record;
        historical.remove(QStringLiteral("retainedIdentity"));
        verify(awgMigrationSecretStore::write(storageId(legacyScope), QJsonDocument(historical).toJson(QJsonDocument::Compact)),
               "historical path-only pending record persisted");
        verify(legacy.load().ok, "historical path-only pending record remains readable");
        QString error;
        verify(!legacy.commitMaintenance(7, oldSha, newSha, &error)
            && error == QStringLiteral("authority_recovery_identity_required"),
               "commit cannot discard historical recovery path or invent inode");
        verify(!legacy.resolvePendingMaintenance(7, oldSha, &error)
            && error == QStringLiteral("authority_recovery_identity_required"),
               "rollback cannot discard historical recovery path or invent inode");
        verify(legacy.load().record == historical, "unproven historical ownership remains pending");
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
        const QJsonObject validCleanup{{"directory", retainedDirectory}, {"identity", retainedIdentity},
            {"replacementSha", newSha}};
        auto extraCleanup = validCleanup;
        extraCleanup.insert(QStringLiteral("extra"), true);
        auto wrongCleanupIdentity = validCleanup;
        wrongCleanupIdentity.insert(QStringLiteral("identity"), QStringLiteral("0 0 700 123 456\n"));
        auto wrongCleanupDigest = validCleanup;
        wrongCleanupDigest.insert(QStringLiteral("replacementSha"), true);
        auto badCleanup = original;
        badCleanup.insert(QStringLiteral("cleanup"), extraCleanup);
        auto badCleanupIdentity = original;
        badCleanupIdentity.insert(QStringLiteral("cleanup"), wrongCleanupIdentity);
        auto badCleanupDigest = original;
        badCleanupDigest.insert(QStringLiteral("cleanup"), wrongCleanupDigest);
        auto wrongPrepareOperation = original;
        wrongPrepareOperation.insert(QStringLiteral("prepareOperationId"), QStringLiteral("not-a-canonical-uuid"));
        auto wrongEndpoint = original;
        wrongEndpoint.insert(QStringLiteral("endpointHost"), endpointHost + QLatin1Char('\n'));
        for (const auto &invalid : {unexpectedField, wrongIdentity, booleanGeneration,
                badCleanup, badCleanupIdentity, badCleanupDigest, wrongPrepareOperation, wrongEndpoint}) {
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
