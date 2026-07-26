#include <QtTest>

#include "core/utils/remoteLogBatchHealth.h"

class RemoteLogRetryPrivacyTest : public QObject
{
    Q_OBJECT

private slots:
    void rotationWithoutPendingPayloadStillOpensTransition()
    {
        amnezia::RemoteLogSecretTransitionEvidence rotated;
        rotated.lastAcceptedSecretSetMatches = false;
        rotated.sourceSize = 4096;
        rotated.acceptedCursorOffset = 1024;

        const auto result = amnezia::remoteLogAdvanceSecretTransition({}, rotated);
        QVERIFY(result.state.present);
        QVERIFY(!result.state.awaitingStableSource);
        QCOMPARE(result.state.highWaterOffset, qint64 { 4096 });
        QVERIFY(result.updateMarkerSecretSet);
        QVERIFY(result.forceRedacted);
        QVERIFY(!result.clearMarker);
    }

    void appendAfterSnapshotBeforeAckRequiresStableNextScan()
    {
        const amnezia::RemoteLogSecretTransitionState rejected { true, false, 100 };
        const auto armed = amnezia::remoteLogArmStableSourceAfterAck(
                rejected, true, true, true, 100, 100);
        QVERIFY(armed.state.present);
        QVERIFY(armed.state.awaitingStableSource);
        QVERIFY(armed.persistMarker);
        QVERIFY(!armed.clearMarker);

        amnezia::RemoteLogSecretTransitionEvidence appendedAfterSnapshot;
        appendedAfterSnapshot.sourceSize = 140;
        appendedAfterSnapshot.acceptedCursorOffset = 100;
        const auto appended = amnezia::remoteLogAdvanceSecretTransition(
                armed.state, appendedAfterSnapshot);
        QVERIFY(appended.state.present);
        QVERIFY(!appended.state.awaitingStableSource);
        QCOMPARE(appended.state.highWaterOffset, qint64 { 140 });
        QVERIFY(appended.persistMarker);
        QVERIFY(appended.forceRedacted);

        const auto rearmed = amnezia::remoteLogArmStableSourceAfterAck(
                appended.state, true, true, true, 140, 140);
        QVERIFY(rearmed.state.awaitingStableSource);

        auto stableNextScan = appendedAfterSnapshot;
        stableNextScan.acceptedCursorOffset = 140;
        const auto cleared = amnezia::remoteLogAdvanceSecretTransition(
                rearmed.state, stableNextScan);
        QVERIFY(cleared.clearMarker);
        QVERIFY(!cleared.forceRedacted);
        QVERIFY(!cleared.state.present);
    }

    void ackOnlyArmsAndStableScanClosesAtExactHighWater()
    {
        const amnezia::RemoteLogSecretTransitionState open { true, false, 180 };
        const auto ack = amnezia::remoteLogArmStableSourceAfterAck(
                open, true, true, true, 180, 180);
        QVERIFY(ack.state.present);
        QVERIFY(ack.state.awaitingStableSource);
        QVERIFY(!ack.clearMarker);

        QVERIFY(amnezia::remoteLogAcceptedTransitionCanClose(
                true, true, true, true, true, 180, 180, 180));
        QVERIFY(!amnezia::remoteLogAcceptedTransitionCanClose(
                true, true, true, true, true, 181, 180, 180));
        QVERIFY(!amnezia::remoteLogAcceptedTransitionCanClose(
                true, false, true, true, true, 180, 180, 180));
        QVERIFY(!amnezia::remoteLogAcceptedTransitionCanClose(
                true, true, false, true, true, 180, 180, 180));
        QVERIFY(!amnezia::remoteLogAcceptedTransitionCanClose(
                true, true, true, false, true, 180, 180, 180));
        QVERIFY(!amnezia::remoteLogAcceptedTransitionCanClose(
                true, true, true, true, false, 180, 180, 180));
    }

    void growthAndIdentityMismatchPreserveQuarantine()
    {
        const amnezia::RemoteLogSecretTransitionState armed { true, true, 80 };
        amnezia::RemoteLogSecretTransitionEvidence growth;
        growth.sourceSize = 96;
        growth.acceptedCursorOffset = 80;
        const auto extended = amnezia::remoteLogAdvanceSecretTransition(armed, growth);
        QVERIFY(extended.forceRedacted);
        QVERIFY(extended.state.present);
        QVERIFY(!extended.state.awaitingStableSource);
        QCOMPARE(extended.state.highWaterOffset, qint64 { 96 });

        auto secretMismatch = growth;
        secretMismatch.sourceSize = 80;
        secretMismatch.acceptedCursorOffset = 80;
        secretMismatch.markerSecretSetMatches = false;
        secretMismatch.lastAcceptedSecretSetMatches = false;
        const auto rebound = amnezia::remoteLogAdvanceSecretTransition(
                armed, secretMismatch);
        QVERIFY(rebound.forceRedacted);
        QVERIFY(rebound.state.present);
        QVERIFY(!rebound.state.awaitingStableSource);
        QVERIFY(rebound.updateMarkerSecretSet);
        QVERIFY(!rebound.clearMarker);
        QVERIFY(!rebound.globalFailClosed);

        auto mismatch = growth;
        mismatch.sourceSize = 80;
        mismatch.acceptedCursorOffset = 80;
        mismatch.cursorMatchesSource = false;
        const auto failedClosed = amnezia::remoteLogAdvanceSecretTransition(armed, mismatch);
        QVERIFY(failedClosed.forceRedacted);
        QVERIFY(failedClosed.globalFailClosed);
        QVERIFY(!failedClosed.clearMarker);

        auto truncated = growth;
        truncated.sourceSize = 79;
        truncated.acceptedCursorOffset = 79;
        const auto truncatedClosed = amnezia::remoteLogAdvanceSecretTransition(
                armed, truncated);
        QVERIFY(truncatedClosed.forceRedacted);
        QVERIFY(truncatedClosed.globalFailClosed);
    }

    void capturedReadsAndRecordDelimitersAreStrict()
    {
        QVERIFY(amnezia::remoteLogCapturedReadIsExact(0, 0));
        QVERIFY(amnezia::remoteLogCapturedReadIsExact(1024, 1024));
        QVERIFY(!amnezia::remoteLogCapturedReadIsExact(1024, 1023));
        QVERIFY(!amnezia::remoteLogCapturedReadIsExact(-1, -1));
        QVERIFY(amnezia::remoteLogByteIsRecordDelimiter('\n'));
        QVERIFY(amnezia::remoteLogByteIsRecordDelimiter('\r'));
        QVERIFY(!amnezia::remoteLogByteIsRecordDelimiter('x'));
        QVERIFY(!amnezia::remoteLogCapturedTailIsPartial(0, false));
        QVERIFY(!amnezia::remoteLogCapturedTailIsPartial(1, true));
        QVERIFY(amnezia::remoteLogCapturedTailIsPartial(1, false));
    }

    void seventeenthMarkerCreatesStickyGlobalFailClosed()
    {
        using Decision = amnezia::RemoteLogRetryMarkerCapacityDecision;
        using Status = amnezia::RemoteLogPersistenceStatus;
        QCOMPARE(amnezia::remoteLogRetryMarkerCapacityDecision(
                         15, 16, false, false, Status::Healthy),
                 Decision::Store);
        QCOMPARE(amnezia::remoteLogRetryMarkerCapacityDecision(
                         16, 16, true, false, Status::Healthy),
                 Decision::Store);
        QCOMPARE(amnezia::remoteLogRetryMarkerCapacityDecision(
                         16, 16, false, false, Status::Healthy),
                 Decision::GlobalFailClosed);
        QCOMPARE(amnezia::remoteLogRetryMarkerCapacityDecision(
                         0, 16, false, true, Status::Healthy),
                 Decision::GlobalFailClosed);
    }

    void settingsFailuresAndCrashPointsFailClosed()
    {
        using Status = amnezia::RemoteLogPersistenceStatus;
        QVERIFY(!amnezia::remoteLogPersistenceMustFailClosed(Status::Healthy));
        for (const Status failure : { Status::ReadError, Status::FormatError,
                                      Status::WriteError, Status::SyncError }) {
            QVERIFY(amnezia::remoteLogPersistenceMustFailClosed(failure));
            QCOMPARE(amnezia::remoteLogRetryMarkerCapacityDecision(
                             0, 16, false, false, failure),
                     amnezia::RemoteLogRetryMarkerCapacityDecision::GlobalFailClosed);
        }

        amnezia::RemoteLogSecretTransitionState persistedBeforeRequest {
            true, false, 512
        };
        amnezia::RemoteLogSecretTransitionEvidence restartedBeforeAck;
        restartedBeforeAck.lastAcceptedSecretSetMatches = false;
        restartedBeforeAck.sourceSize = 512;
        restartedBeforeAck.acceptedCursorOffset = 0;
        const auto crashBeforeAck = amnezia::remoteLogAdvanceSecretTransition(
                persistedBeforeRequest, restartedBeforeAck);
        QVERIFY(crashBeforeAck.forceRedacted);
        QVERIFY(crashBeforeAck.state.present);

        restartedBeforeAck.markerValid = false;
        const auto partialMarker = amnezia::remoteLogAdvanceSecretTransition(
                persistedBeforeRequest, restartedBeforeAck);
        QVERIFY(partialMarker.forceRedacted);
        QVERIFY(partialMarker.globalFailClosed);

        const auto armedBeforeCursorSave = amnezia::remoteLogArmStableSourceAfterAck(
                persistedBeforeRequest, true, true, true, 512, 512);
        QVERIFY(armedBeforeCursorSave.state.awaitingStableSource);
        amnezia::RemoteLogSecretTransitionEvidence restartedAfterMarkerSave;
        restartedAfterMarkerSave.sourceSize = 512;
        restartedAfterMarkerSave.acceptedCursorOffset = 0;
        restartedAfterMarkerSave.markerCursorMatches = false;
        restartedAfterMarkerSave.markerCursorIsAhead = true;
        const auto safeRetry = amnezia::remoteLogAdvanceSecretTransition(
                armedBeforeCursorSave.state, restartedAfterMarkerSave);
        QVERIFY(!safeRetry.globalFailClosed);
        QVERIFY(safeRetry.forceRedacted);
        QVERIFY(!safeRetry.state.awaitingStableSource);
    }

    void recoveryMarkerFailureRetryIsBounded()
    {
        constexpr int maximumAttempts = 4;
        for (int attempts = 0; attempts < maximumAttempts; ++attempts) {
            QVERIFY(amnezia::remoteLogRecoveryCheckpointCanRetry(
                    attempts, maximumAttempts));
        }
        QVERIFY(!amnezia::remoteLogRecoveryCheckpointCanRetry(
                maximumAttempts, maximumAttempts));
        QVERIFY(!amnezia::remoteLogRecoveryCheckpointCanRetry(
                -1, maximumAttempts));
    }

    void explicitSecretUnionIsBoundedAndFailsClosed()
    {
        QStringList exactLimit;
        for (qsizetype index = 0;
             index < amnezia::MaximumRemoteLogSanitizerExplicitSecrets; ++index) {
            exactLimit.append(QStringLiteral("secret-%1").arg(index));
        }
        const auto bounded = amnezia::remoteLogSanitizerSecretUnion({}, exactLimit);
        QVERIFY(!bounded.forceRedacted);
        QCOMPARE(bounded.values.size(),
                 amnezia::MaximumRemoteLogSanitizerExplicitSecrets);

        const auto overflow = amnezia::remoteLogSanitizerSecretUnion(
                bounded, { QStringLiteral("one-secret-too-many") });
        QVERIFY(overflow.forceRedacted);
        QVERIFY(overflow.values.isEmpty());
    }

    void privacyStatesCannotReportHealthy()
    {
        QVERIFY(amnezia::remoteLogBatchCanBecomeHealthy(
                false, true, false, false, false, false, false));
        QVERIFY(!amnezia::remoteLogBatchCanBecomeHealthy(
                false, true, false, false, true, false, false));
        QVERIFY(!amnezia::remoteLogBatchCanBecomeHealthy(
                false, true, false, false, false, true, false));
        QVERIFY(!amnezia::remoteLogBatchCanBecomeHealthy(
                false, true, false, false, false, false, true));
    }
};

QTEST_MAIN(RemoteLogRetryPrivacyTest)
#include "tst_remote_log_retry_privacy.moc"
