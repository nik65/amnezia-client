#include <QCoreApplication>
#include "core/controllers/selfhosted/releaseAcceptance.h"
#include <QSemaphore>
#include <QTextStream>
#include <QThreadPool>
#include <QTemporaryDir>
#include <cstdio>

#include <atomic>

#define AMNEZIA_SSH_CLIENT_STATE_ONLY
#include "core/utils/selfhosted/sshClient.h"
#undef AMNEZIA_SSH_CLIENT_STATE_ONLY

#include "core/controllers/selfhosted/selfHostedUpdateBootstrapper.h"

using amnezia::selfhostedUpdates::bundledArtifactRelativePath;
using amnezia::selfhostedUpdates::bundledArtifactRequestPath;
using amnezia::selfhostedUpdates::bundledRollbackArtifactRelativePath;
using amnezia::selfhostedUpdates::accountBoundedRemoteOutput;
using amnezia::selfhostedUpdates::BundledManifestIdentity;
using amnezia::selfhostedUpdates::BundledMutationReconciliation;
using amnezia::selfhostedUpdates::BundledPostCommitDisposition;
using amnezia::selfhostedUpdates::BundledPublishTransitionResult;
using amnezia::selfhostedUpdates::bundledPostCommitDisposition;
using amnezia::selfhostedUpdates::maximumBootstrapPhaseOutputBytes;
using amnezia::selfhostedUpdates::reconcileBundledMutation;
using amnezia::selfhostedUpdates::validateBundledPublishTransition;

namespace
{
    class TestRunner
    {
    public:
        void check(bool condition, const char *expression, int line)
        {
            ++m_assertions;
            if (condition) {
                return;
            }
            ++m_failures;
            QTextStream(stderr) << "FAIL line " << line << ": " << expression << Qt::endl;
        }

        int finish() const
        {
            QTextStream stream(m_failures == 0 ? stdout : stderr);
            stream << (m_failures == 0 ? "PASS" : "FAIL") << ": "
                   << m_assertions << " assertions, " << m_failures << " failures" << Qt::endl;
            return m_failures == 0 ? 0 : 1;
        }

    private:
        int m_assertions = 0;
        int m_failures = 0;
    };

    BundledManifestIdentity manifestIdentity(int schema,
                                             const QString &version,
                                             const QString &generation,
                                             const QByteArray &payload,
                                             const QString &releaseContent)
    {
        BundledManifestIdentity identity;
        identity.schema = schema;
        identity.version = version;
        identity.generation = generation;
        identity.payloadBytes = payload;
        identity.releaseContent.insert(QStringLiteral("content"), releaseContent);
        return identity;
    }
}

#define CHECK(expression) runner.check((expression), #expression, __LINE__)

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    Q_UNUSED(app);
    TestRunner runner;

    const QString digest(64, QLatin1Char('a'));
    const QString contentAddressedPath = QStringLiteral("files/artifacts/%1/AmneziaVPN_4.9.2.1_windows_x64.exe")
            .arg(digest);
    QString relativePath;

    // A Windows-only bundle needs only its own platform artifact, and its
    // content-addressed path must survive parsing exactly.
    CHECK(bundledArtifactRelativePath(contentAddressedPath, digest, relativePath));
    CHECK(relativePath == contentAddressedPath);
    CHECK(bundledArtifactRequestPath(contentAddressedPath) == QStringLiteral("/") + contentAddressedPath);
    const QString encodedNamePath = QStringLiteral("files/artifacts/") + digest
            + QStringLiteral("/AmneziaVPN%20candidate.exe");
    CHECK(bundledArtifactRelativePath(encodedNamePath, digest, relativePath));
    CHECK(relativePath == QStringLiteral("files/artifacts/%1/AmneziaVPN candidate.exe").arg(digest));
    const QString encodedPlusPath = QStringLiteral("files/artifacts/") + digest
            + QStringLiteral("/AmneziaVPN%2Bcandidate.exe");
    CHECK(bundledArtifactRequestPath(encodedPlusPath)
          == QStringLiteral("/files/artifacts/%1/AmneziaVPN%2Bcandidate.exe").arg(digest));
    const QString shellCharactersPath = QStringLiteral("files/artifacts/") + digest
            + QStringLiteral("/Amnezia%24%28id%29%60x%60%22.exe");
    CHECK(bundledArtifactRelativePath(shellCharactersPath, digest, relativePath));
    CHECK(relativePath == QStringLiteral("files/artifacts/%1/Amnezia$(id)`x`\".exe").arg(digest));

    const QStringList unsafeUrls {
        QStringLiteral("https://updates.example.invalid/") + contentAddressedPath,
        QStringLiteral("//updates.example.invalid/") + contentAddressedPath,
        QStringLiteral("/") + contentAddressedPath,
        QStringLiteral("files/artifacts/") + digest + QStringLiteral("/../AmneziaVPN.exe"),
        QStringLiteral("files/artifacts/") + digest + QStringLiteral("/%2E%2E/AmneziaVPN.exe"),
        QStringLiteral("files/artifacts/") + digest + QStringLiteral("/..%2FAmneziaVPN.exe"),
        QStringLiteral("files/artifacts/") + digest + QStringLiteral("/Amnezia%5CVPN.exe"),
        QStringLiteral("files\\artifacts\\") + digest + QStringLiteral("\\AmneziaVPN.exe"),
        QStringLiteral("C:/") + contentAddressedPath,
        QStringLiteral("files/artifacts/") + digest + QStringLiteral("/Amnezia%3AVPN.exe"),
        QStringLiteral("files/artifacts/") + digest + QStringLiteral("/Amnezia%0AVPN.exe"),
        QStringLiteral("files/artifacts/") + digest + QStringLiteral("/AmneziaVPN.exe?cache=1"),
        QStringLiteral("files/artifacts/") + digest + QStringLiteral("/AmneziaVPN.exe#fragment"),
    };
    for (const QString &unsafeUrl : unsafeUrls) {
        CHECK(!bundledArtifactRelativePath(unsafeUrl, digest, relativePath));
    }
    CHECK(!bundledArtifactRelativePath(contentAddressedPath, QString(64, QLatin1Char('b')), relativePath));
    CHECK(!bundledArtifactRelativePath(contentAddressedPath, digest.toUpper(), relativePath));
    CHECK(!bundledArtifactRelativePath(
            QStringLiteral("files/artifacts/%1/AmneziaVPN.exe").arg(digest.toUpper()), digest, relativePath));

    const QString rollbackGeneration = QStringLiteral("42");
    const QString rollbackVersion = QStringLiteral("4.9.0.11");
    const QString rollbackPath = QStringLiteral("files/rollback/") + rollbackGeneration + QStringLiteral("/")
            + rollbackVersion + QStringLiteral("/AmneziaVPN_4.9.0.11_windows_x64.exe");
    CHECK(bundledRollbackArtifactRelativePath(
            rollbackPath, rollbackGeneration, rollbackVersion, relativePath));
    CHECK(relativePath == rollbackPath);
    const QString encodedRollbackPath = QStringLiteral("files/rollback/") + rollbackGeneration + QStringLiteral("/")
            + rollbackVersion + QStringLiteral("/AmneziaVPN%20rollback.exe");
    CHECK(bundledRollbackArtifactRelativePath(
            encodedRollbackPath, rollbackGeneration, rollbackVersion, relativePath));
    CHECK(relativePath == QStringLiteral("files/rollback/%1/%2/AmneziaVPN rollback.exe").arg(
            rollbackGeneration, rollbackVersion));

    const QStringList unsafeRollbackUrls {
        QStringLiteral("https://updates.example.invalid/") + rollbackPath,
        QStringLiteral("/") + rollbackPath,
        QStringLiteral("files/rollback/042/") + rollbackVersion + QStringLiteral("/AmneziaVPN.exe"),
        QStringLiteral("files/rollback/") + rollbackGeneration + QStringLiteral("/4.09.0.11/AmneziaVPN.exe"),
        QStringLiteral("files/rollback/") + rollbackGeneration + QStringLiteral("/") + rollbackVersion
                + QStringLiteral("/..%2FAmneziaVPN.exe"),
        QStringLiteral("files/rollback/") + rollbackGeneration + QStringLiteral("/") + rollbackVersion
                + QStringLiteral("/Amnezia%5CVPN.exe"),
        QStringLiteral("files/rollback/") + rollbackGeneration + QStringLiteral("/") + rollbackVersion
                + QStringLiteral("/AmneziaVPN.exe?cache=1"),
    };
    for (const QString &unsafeUrl : unsafeRollbackUrls) {
        CHECK(!bundledRollbackArtifactRelativePath(
                unsafeUrl, rollbackGeneration, rollbackVersion, relativePath));
    }
    CHECK(!bundledRollbackArtifactRelativePath(rollbackPath, QStringLiteral("042"), rollbackVersion, relativePath));
    CHECK(!bundledRollbackArtifactRelativePath(rollbackPath, rollbackGeneration, QStringLiteral("4.9.0.011"), relativePath));

    const BundledManifestIdentity legacy = manifestIdentity(
            1, QStringLiteral("4.9.1.0"), QString(), QByteArrayLiteral("legacy"), QStringLiteral("release-a"));
    const BundledManifestIdentity legacyLower = manifestIdentity(
            1, QStringLiteral("4.9.0.12"), QString(), QByteArrayLiteral("lower"), QStringLiteral("release-lower"));
    const BundledManifestIdentity schemaTwo = manifestIdentity(
            2, QStringLiteral("4.9.1.1"), QStringLiteral("42"), QByteArrayLiteral("schema-two"), QStringLiteral("release-b"));
    const BundledManifestIdentity staleGeneration = manifestIdentity(
            2, QStringLiteral("4.9.1.2"), QStringLiteral("41"), QByteArrayLiteral("stale"), QStringLiteral("release-c"));
    const BundledManifestIdentity reboundGeneration = manifestIdentity(
            2, QStringLiteral("4.9.1.2"), QStringLiteral("42"), QByteArrayLiteral("rebound"), QStringLiteral("release-c"));
    const BundledManifestIdentity nextGeneration = manifestIdentity(
            2, QStringLiteral("4.9.1.2"), QStringLiteral("43"), QByteArrayLiteral("next"), QStringLiteral("release-c"));
    const BundledManifestIdentity schemaDowngrade = manifestIdentity(
            1, QStringLiteral("4.9.1.2"), QString(), QByteArrayLiteral("downgrade"), QStringLiteral("release-c"));
    const BundledManifestIdentity sameVersionPolicyAdvance = manifestIdentity(
            2, QStringLiteral("4.9.1.1"), QStringLiteral("43"), QByteArrayLiteral("policy-advance"), QStringLiteral("release-b"));
    const BundledManifestIdentity sameVersionRebuild = manifestIdentity(
            2, QStringLiteral("4.9.1.1"), QStringLiteral("43"), QByteArrayLiteral("rebuild"), QStringLiteral("changed-release"));
    const BundledManifestIdentity schemaMigration = manifestIdentity(
            2, QStringLiteral("4.9.1.0"), QStringLiteral("1"), QByteArrayLiteral("migration"), QStringLiteral("release-a"));

    CHECK(validateBundledPublishTransition(nullptr, legacy) == BundledPublishTransitionResult::Allowed);
    CHECK(validateBundledPublishTransition(&legacy, legacy) == BundledPublishTransitionResult::Allowed);
    CHECK(validateBundledPublishTransition(&legacy, legacyLower) == BundledPublishTransitionResult::VersionDowngrade);
    CHECK(validateBundledPublishTransition(&legacy, schemaMigration) == BundledPublishTransitionResult::Allowed);
    CHECK(validateBundledPublishTransition(&schemaTwo, staleGeneration) == BundledPublishTransitionResult::GenerationRollback);
    CHECK(validateBundledPublishTransition(&schemaTwo, reboundGeneration) == BundledPublishTransitionResult::GenerationRebound);
    CHECK(validateBundledPublishTransition(&schemaTwo, nextGeneration) == BundledPublishTransitionResult::Allowed);
    CHECK(validateBundledPublishTransition(&schemaTwo, schemaDowngrade) == BundledPublishTransitionResult::SchemaDowngrade);
    CHECK(validateBundledPublishTransition(&schemaTwo, sameVersionPolicyAdvance) == BundledPublishTransitionResult::Allowed);
    CHECK(validateBundledPublishTransition(&schemaTwo, sameVersionRebuild)
          == BundledPublishTransitionResult::SameVersionContentChanged);

    CHECK(bundledPostCommitDisposition(true, false, false)
          == BundledPostCommitDisposition::FinalizeAndCleanup);
    CHECK(bundledPostCommitDisposition(false, true, false)
          == BundledPostCommitDisposition::FinalizeAndCleanup);
    CHECK(bundledPostCommitDisposition(false, false, true)
          == BundledPostCommitDisposition::RolledBackAndCleanup);
    CHECK(bundledPostCommitDisposition(false, false, false)
          == BundledPostCommitDisposition::PreserveRecoveryEvidence);

    qsizetype acceptedRemoteOutputBytes = 0;
    CHECK(accountBoundedRemoteOutput(
            acceptedRemoteOutputBytes,
            QString(maximumBootstrapPhaseOutputBytes - 1, QLatin1Char('a'))));
    CHECK(acceptedRemoteOutputBytes == maximumBootstrapPhaseOutputBytes - 1);
    CHECK(accountBoundedRemoteOutput(acceptedRemoteOutputBytes, QStringLiteral("b")));
    CHECK(acceptedRemoteOutputBytes == maximumBootstrapPhaseOutputBytes);
    CHECK(!accountBoundedRemoteOutput(acceptedRemoteOutputBytes, QStringLiteral("overflow")));
    CHECK(acceptedRemoteOutputBytes == maximumBootstrapPhaseOutputBytes);

    qsizetype multibyteRemoteOutputBytes = 0;
    const QString euroSign = QString::fromUtf8("\xE2\x82\xAC");
    CHECK(!accountBoundedRemoteOutput(multibyteRemoteOutputBytes, euroSign, 2));
    CHECK(multibyteRemoteOutputBytes == 0);
    CHECK(accountBoundedRemoteOutput(multibyteRemoteOutputBytes, euroSign, 3));
    CHECK(multibyteRemoteOutputBytes == 3);

    const QString priorSha(64, QLatin1Char('1'));
    const QString desiredSha(64, QLatin1Char('2'));
    const QString unrelatedSha(64, QLatin1Char('3'));
    CHECK(reconcileBundledMutation(true, QString(), desiredSha, priorSha)
          == BundledMutationReconciliation::Acknowledged);
    CHECK(reconcileBundledMutation(false, desiredSha, desiredSha, priorSha)
          == BundledMutationReconciliation::AppliedWithoutAcknowledgement);
    CHECK(reconcileBundledMutation(false, priorSha, desiredSha, priorSha)
          == BundledMutationReconciliation::NotApplied);
    CHECK(reconcileBundledMutation(false, unrelatedSha, desiredSha, priorSha)
          == BundledMutationReconciliation::Indeterminate);
    // Rollback uses the same CAS reconciliation with the desired/prior roles
    // reversed. This is the deterministic lost-ACK rollback case.
    CHECK(reconcileBundledMutation(false, priorSha, priorSha, desiredSha)
          == BundledMutationReconciliation::AppliedWithoutAcknowledgement);

    using libssh::detail::BoundaryState;
    using libssh::detail::ExitState;
    using libssh::detail::TeardownMode;
    using libssh::detail::WriteState;

    const QString renderedReceiptCommand =
            (QStringLiteral("upload_target=%1; ")
             + libssh::detail::uploadReceiptPrintCommand()).arg(QStringLiteral("/tmp/target"));
    CHECK(renderedReceiptCommand.contains(QStringLiteral("printf '%s\\n' \"$receipt\"")));
    CHECK(!renderedReceiptCommand.contains(QStringLiteral("%%s")));

    using amnezia::selfhostedUpdates::AutomaticPublishCompletionDisposition;
    using amnezia::selfhostedUpdates::AutomaticPublishRetryState;
    using amnezia::selfhostedUpdates::AutomaticPublishStartDisposition;
    using amnezia::selfhostedUpdates::automaticPublishDelayMs;
    using amnezia::selfhostedUpdates::automaticPublishStartDisposition;
    using amnezia::selfhostedUpdates::beginAutomaticPublishAttempt;
    using amnezia::selfhostedUpdates::completeAutomaticPublishAttempt;
    using amnezia::selfhostedUpdates::rearmAutomaticPublishAfterNotification;

    AutomaticPublishRetryState retryState;
    CHECK(automaticPublishStartDisposition(retryState) == AutomaticPublishStartDisposition::Schedule);
    CHECK(automaticPublishDelayMs(retryState) == 15 * 1000);
    retryState.scheduled = true;
    CHECK(automaticPublishStartDisposition(retryState) == AutomaticPublishStartDisposition::Coalesce);
    beginAutomaticPublishAttempt(retryState);
    CHECK(automaticPublishStartDisposition(retryState) == AutomaticPublishStartDisposition::Coalesce);
    CHECK(completeAutomaticPublishAttempt(retryState, false)
          == AutomaticPublishCompletionDisposition::Retry);
    CHECK(automaticPublishDelayMs(retryState) == 60 * 1000);

    retryState.scheduled = true;
    beginAutomaticPublishAttempt(retryState);
    CHECK(completeAutomaticPublishAttempt(retryState, false)
          == AutomaticPublishCompletionDisposition::Retry);
    CHECK(automaticPublishDelayMs(retryState) == 5 * 60 * 1000);

    retryState.scheduled = true;
    beginAutomaticPublishAttempt(retryState);
    CHECK(completeAutomaticPublishAttempt(retryState, false)
          == AutomaticPublishCompletionDisposition::Exhausted);
    CHECK(retryState.attemptCount == 0);
    CHECK(automaticPublishStartDisposition(retryState) == AutomaticPublishStartDisposition::Disabled);
    rearmAutomaticPublishAfterNotification(retryState);
    CHECK(automaticPublishStartDisposition(retryState) == AutomaticPublishStartDisposition::Schedule);
    CHECK(automaticPublishDelayMs(retryState) == 15 * 1000);

    retryState.scheduled = true;
    beginAutomaticPublishAttempt(retryState);
    CHECK(completeAutomaticPublishAttempt(retryState, true)
          == AutomaticPublishCompletionDisposition::Succeeded);
    CHECK(automaticPublishStartDisposition(retryState) == AutomaticPublishStartDisposition::Disabled);

    CHECK(libssh::detail::boundaryState(99, 100, false) == BoundaryState::Ready);
    CHECK(libssh::detail::boundaryState(100, 100, false) == BoundaryState::TimedOut);
    CHECK(libssh::detail::boundaryState(99, 100, true) == BoundaryState::Cancelled);
    CHECK(libssh::detail::cappedPhaseDeadline(50, 1000, 30) == 80);
    CHECK(libssh::detail::cappedPhaseDeadline(990, 1000, 30) == 1000);
    CHECK(libssh::detail::cappedPhaseDeadline(990, 1000, 0) == 0);

    // Model a DNS callback that never completes. The production resolver uses
    // this same boundary decision on each event-loop wake and therefore exits
    // at the one absolute deadline instead of waiting for the resolver thread.
    std::int64_t simulatedNow = 95;
    while (libssh::detail::boundaryState(simulatedNow, 100, false) == BoundaryState::Ready) {
        ++simulatedNow;
    }
    CHECK(simulatedNow == 100);
    CHECK(libssh::detail::boundaryState(simulatedNow, 100, false) == BoundaryState::TimedOut);

    CHECK(libssh::detail::boundedWriteSize(0, 4096, 2048) == 0);
    CHECK(libssh::detail::boundedWriteSize(512, 4096, 2048) == 512);
    CHECK(libssh::detail::boundedWriteSize(4096, 4096, 2048) == 2048);
    CHECK(libssh::detail::classifyWriteResult(0, -2) == WriteState::Retry);
    CHECK(libssh::detail::classifyWriteResult(-2, -2) == WriteState::Retry);
    CHECK(libssh::detail::classifyWriteResult(42, -2) == WriteState::Progress);
    CHECK(libssh::detail::classifyWriteResult(-1, -2) == WriteState::Failure);

    CHECK(libssh::detail::exitState(false, false, false, false, false, -1) == ExitState::Pending);
    CHECK(libssh::detail::exitState(true, false, false, false, true, 0) == ExitState::Pending);
    CHECK(libssh::detail::exitState(true, false, true, false, true, 0) == ExitState::Pending);
    CHECK(libssh::detail::exitState(true, true, true, true, false, -1) == ExitState::MissingStatus);
    CHECK(libssh::detail::exitState(true, false, true, true, true, 0) == ExitState::Success);
    CHECK(libssh::detail::exitState(false, true, true, true, true, 23) == ExitState::Failure);

    // A terminal notification can arrive while both SSH streams still contain
    // multiple channel-sized chunks. The production pump uses this same gate,
    // so neither exit status nor close can truncate the concurrent tails.
    const QByteArray expectedStdout(12 * 1024 + 17, 'o');
    const QByteArray expectedStderr(12 * 1024 + 31, 'e');
    QByteArray observedStdout;
    QByteArray observedStderr;
    qsizetype stdoutOffset = 0;
    qsizetype stderrOffset = 0;
    while (stdoutOffset < expectedStdout.size() || stderrOffset < expectedStderr.size()) {
        const qsizetype stdoutChunk = qMin<qsizetype>(4096, expectedStdout.size() - stdoutOffset);
        const qsizetype stderrChunk = qMin<qsizetype>(4096, expectedStderr.size() - stderrOffset);
        if (stdoutChunk > 0) {
            observedStdout += expectedStdout.mid(stdoutOffset, stdoutChunk);
            stdoutOffset += stdoutChunk;
        }
        if (stderrChunk > 0) {
            observedStderr += expectedStderr.mid(stderrOffset, stderrChunk);
            stderrOffset += stderrChunk;
        }
        CHECK(libssh::detail::exitState(
                      true,
                      false,
                      stdoutOffset == expectedStdout.size(),
                      stderrOffset == expectedStderr.size(),
                      true,
                      0)
              == ((stdoutOffset == expectedStdout.size() && stderrOffset == expectedStderr.size())
                          ? ExitState::Success : ExitState::Pending));
    }
    CHECK(observedStdout == expectedStdout);
    CHECK(observedStderr == expectedStderr);

    CHECK(libssh::detail::teardownMode(BoundaryState::Ready) == TeardownMode::Graceful);
    CHECK(libssh::detail::teardownMode(BoundaryState::Cancelled) == TeardownMode::AbortTransport);
    CHECK(libssh::detail::teardownMode(BoundaryState::TimedOut) == TeardownMode::AbortTransport);

    // The worker holds a stable dispatch context, while the guarded target is
    // intentionally destroyed before the queued completion is delivered.
    QThreadPool completionPool;
    completionPool.setMaxThreadCount(1);
    QSemaphore workerEntered;
    QSemaphore releaseWorker;
    std::atomic_bool destroyedTargetCalled { false };
    auto deliveryContext = amnezia::selfhostedUpdates::makeQueuedDeliveryContext();
    QObject *destroyedTarget = new QObject;
    const QPointer<QObject> guardedDestroyedTarget(destroyedTarget);
    completionPool.start([deliveryContext,
                          guardedDestroyedTarget,
                          &workerEntered,
                          &releaseWorker,
                          &destroyedTargetCalled]() {
        workerEntered.release();
        releaseWorker.acquire();
        amnezia::selfhostedUpdates::enqueueGuardedCompletion(
                deliveryContext,
                guardedDestroyedTarget,
                [&destroyedTargetCalled](QObject *) {
                    destroyedTargetCalled.store(true, std::memory_order_release);
                });
    });
    workerEntered.acquire();
    delete destroyedTarget;
    releaseWorker.release();
    completionPool.waitForDone();
    QCoreApplication::processEvents();
    CHECK(!destroyedTargetCalled.load(std::memory_order_acquire));

    BundledManifestIdentity invalidGeneration = schemaTwo;
    invalidGeneration.generation = QStringLiteral("042");
    CHECK(validateBundledPublishTransition(&schemaTwo, invalidGeneration)
          == BundledPublishTransitionResult::InvalidCandidate);

    // Exercise actual Ed25519 envelope verification with a fresh in-memory test key.
    using namespace amnezia::selfhostedUpdates;
    const QDateTime acceptanceNow = QDateTime::fromString("2026-10-17T20:00:00Z", Qt::ISODate);
    const QJsonArray acceptanceArtifacts { QJsonObject { { "path", "files/artifacts/a/test" }, { "sha256", digest }, { "size", 10 } } };
    QJsonArray acceptanceReceipts;
    for (const QString &platform : QStringList { "android", "linux", "windows" }) {
        acceptanceReceipts.append(QJsonObject { { "platform", platform }, { "kind", platform == "android" ? "real-device" : "owned-guest" },
            { "runId", "test-run" }, { "profileId", "test-profile" }, { "receiptSha256", digest }, { "cleanupSha256", digest }, { "status", "PASS" } });
    }
    const QJsonObject acceptance { { "schema", 1 }, { "policyId", "amnezia-release-full-v1" }, { "manifestSha256", digest }, { "publisherSha256", digest }, { "version", "5.0.3.11" },
        { "androidVersionCode", 2197 }, { "issuedAt", "2026-10-17T19:59:00Z" }, { "expiresAt", "2026-10-17T21:00:00Z" },
        { "artifacts", acceptanceArtifacts }, { "receipts", acceptanceReceipts } };
    const auto accepts = [&](const QJsonObject &value) { return validateReleaseAcceptance(value, digest, digest, "5.0.3.11", 2197, acceptanceArtifacts, acceptanceNow); };
    CHECK(accepts(acceptance));
    CHECK(!validateReleaseAcceptance(acceptance, digest, digest, "5.0.3.11", 2197, acceptanceArtifacts,
                                    QDateTime::fromString("2026-10-17T21:00:00Z", Qt::ISODate)));
    QTemporaryDir artifactDirectory;
    CHECK(artifactDirectory.isValid());
    const QString sourceArtifact = artifactDirectory.filePath("source");
    QFile artifactFile(sourceArtifact);
    CHECK(artifactFile.open(QIODevice::WriteOnly)); CHECK(artifactFile.write("approved") == 8); artifactFile.close();
    const QByteArray approvedDigest = QCryptographicHash::hash("approved", QCryptographicHash::Sha256).toHex();
    const QString snapshotArtifact = artifactDirectory.filePath("snapshot");
    CHECK(snapshotAcceptanceArtifact(sourceArtifact, snapshotArtifact, 8, approvedDigest));
    CHECK(artifactFile.open(QIODevice::WriteOnly | QIODevice::Truncate)); CHECK(artifactFile.write("replaced") == 8); artifactFile.close();
    CHECK(!snapshotAcceptanceArtifact(sourceArtifact, artifactDirectory.filePath("changed"), 8, approvedDigest));
    CHECK(!snapshotAcceptanceArtifact(sourceArtifact, artifactDirectory.filePath("wrong-size"), 9, approvedDigest));
    CHECK(!snapshotAcceptanceArtifact(sourceArtifact, snapshotArtifact, 8, approvedDigest));
    QFile preservedSnapshot(snapshotArtifact); CHECK(preservedSnapshot.open(QIODevice::ReadOnly)); CHECK(preservedSnapshot.readAll() == "approved");
    for (const auto &field : { "policyId", "manifestSha256", "publisherSha256", "version", "androidVersionCode", "artifacts", "receipts", "issuedAt", "expiresAt" }) {
        QJsonObject missing = acceptance; missing.remove(field); CHECK(!accepts(missing));
    }
    QJsonObject changed = acceptance; changed.insert("manifestSha256", QString(64, u'b')); CHECK(!accepts(changed));
    changed = acceptance; changed.insert("androidVersionCode", 2198); CHECK(!accepts(changed));
    changed = acceptance; changed.insert("unknown", true); CHECK(!accepts(changed));
    changed = acceptance; changed.insert("issuedAt", "2026-10-17T20:00:01Z"); CHECK(!accepts(changed));
    changed = acceptance; changed.insert("expiresAt", "2026-10-17T20:00:00Z"); CHECK(!accepts(changed));
    changed = acceptance; changed.insert("expiresAt", "2026-10-19T20:00:00Z"); CHECK(!accepts(changed));
    changed = acceptance; changed.insert("issuedAt", "2026-10-17T19:59:00+00:00"); CHECK(!accepts(changed));
    for (int i = 0; i < 3; ++i) {
        QJsonArray missing = acceptanceReceipts; missing.removeAt(i); changed = acceptance; changed.insert("receipts", missing); CHECK(!accepts(changed));
        QJsonArray invalid = acceptanceReceipts; QJsonObject receipt = invalid.at(i).toObject(); receipt.insert("status", "PENDING"); invalid[i] = receipt;
        changed = acceptance; changed.insert("receipts", invalid); CHECK(!accepts(changed));
        receipt.insert("status", "PASS"); receipt.insert("kind", "emulator"); invalid[i] = receipt;
        changed.insert("receipts", invalid); CHECK(!accepts(changed));
    }
    EVP_PKEY_CTX *keyContext = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    EVP_PKEY *testKey = nullptr;
    CHECK(keyContext && EVP_PKEY_keygen_init(keyContext) == 1 && EVP_PKEY_keygen(keyContext, &testKey) == 1);
    EVP_PKEY_CTX_free(keyContext);
    BIO *keyBio = BIO_new(BIO_s_mem());
    CHECK(keyBio && testKey && PEM_write_bio_PUBKEY(keyBio, testKey) == 1);
    char *pemData = nullptr; const long pemSize = BIO_get_mem_data(keyBio, &pemData);
    const QByteArray testPublicKey(pemData, int(pemSize)); BIO_free(keyBio);
    const auto signEnvelope = [&](const QByteArray &signedPayload) {
        EVP_MD_CTX *ctx = EVP_MD_CTX_new(); size_t length = 64; QByteArray signature(64, char(0));
        const bool signedOk = ctx && EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, testKey) == 1
            && EVP_DigestSign(ctx, reinterpret_cast<unsigned char *>(signature.data()), &length,
                              reinterpret_cast<const unsigned char *>(signedPayload.constData()), size_t(signedPayload.size())) == 1;
        EVP_MD_CTX_free(ctx); CHECK(signedOk);
        return QJsonDocument(QJsonObject { { "schema", acceptanceSchema }, { "signatureAlgorithm", "Ed25519" },
            { "payload", QString::fromLatin1(signedPayload.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals)) },
            { "signature", QString::fromLatin1(signature.toBase64()) } }).toJson(QJsonDocument::Compact);
    };
    const QByteArray domain = QByteArray(acceptanceSchema) + '\n';
    const QByteArray signedApproval = signEnvelope(domain + QJsonDocument(acceptance).toJson(QJsonDocument::Compact));
    QJsonObject decodedApproval;
    CHECK(decodeReleaseAcceptance(signedApproval, testPublicKey, decodedApproval)); CHECK(accepts(decodedApproval));
    CHECK(!decodeReleaseAcceptance(signedApproval + "\n", testPublicKey, decodedApproval));
    CHECK(!decodeReleaseAcceptance(signedApproval, QByteArray(), decodedApproval));
    CHECK(!decodeReleaseAcceptance(signEnvelope(QJsonDocument(acceptance).toJson(QJsonDocument::Compact)), testPublicKey, decodedApproval));
    CHECK(!decodeReleaseAcceptance(signEnvelope(domain + "{\"schema\":1,\"schema\":1}"), testPublicKey, decodedApproval));
    QByteArray tampered = signedApproval; tampered[tampered.indexOf("payload") + 12] = 'X';
    CHECK(!decodeReleaseAcceptance(tampered, testPublicKey, decodedApproval));
    CHECK(!decodeReleaseAcceptance(QByteArray(maximumAcceptanceBytes + 1, 'x'), testPublicKey, decodedApproval));
    EVP_PKEY_free(testKey);

    // Test-only transport for vectors generated by the actual Python signing
    // primitive. It never overrides the application's compiled authority.
    if (app.arguments().contains(QStringLiteral("--acceptance-vector-stdin"))) {
        QFile input;
        CHECK(input.open(stdin, QIODevice::ReadOnly));
        const QByteArray vectorBytes = input.read(1024 * 1024 + 1);
        CHECK(vectorBytes.size() <= 1024 * 1024);
        const QJsonDocument vectorDocument = QJsonDocument::fromJson(vectorBytes);
        CHECK(vectorDocument.isObject());
        const QJsonObject vector = vectorDocument.object();
        CHECK(acceptanceKeys(vector, { "publicKeyPemBase64", "envelopeBase64", "expectedPayload", "negativeVectors" }));
        QByteArray vectorKey, vectorEnvelope;
        CHECK(acceptanceBase64(vector.value("publicKeyPemBase64").toString(), false, vectorKey));
        CHECK(acceptanceBase64(vector.value("envelopeBase64").toString(), false, vectorEnvelope));
        QJsonObject vectorApproval;
        CHECK(vector.value("expectedPayload").toObject() == acceptance);
        CHECK(decodeReleaseAcceptance(vectorEnvelope, vectorKey, vectorApproval));
        CHECK(vectorApproval == acceptance);
        CHECK(accepts(vectorApproval));
        const QJsonArray negatives = vector.value("negativeVectors").toArray();
        CHECK(negatives.size() >= 3);
        int rejectedDomains = 0, rejectedPolicies = 0;
        for (const QJsonValue &negativeValue : negatives) {
            const QJsonObject negative = negativeValue.toObject();
            CHECK(acceptanceKeys(negative, { "envelopeBase64", "decodeExpected", "policyExpected" }));
            CHECK(negative.value("decodeExpected").isBool());
            CHECK(negative.value("policyExpected") == QJsonValue(false));
            QByteArray negativeEnvelope;
            CHECK(acceptanceBase64(negative.value("envelopeBase64").toString(), false, negativeEnvelope));
            QJsonObject negativeApproval;
            const bool decoded = decodeReleaseAcceptance(negativeEnvelope, vectorKey, negativeApproval);
            CHECK(decoded == negative.value("decodeExpected").toBool());
            CHECK(!(decoded && accepts(negativeApproval)));
            if (decoded) ++rejectedPolicies; else ++rejectedDomains;
        }
        CHECK(rejectedDomains >= 1);
        CHECK(rejectedPolicies >= 2);
    }

    return runner.finish();
}
