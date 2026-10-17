#include <QtTest>

#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QSharedPointer>
#include <QSettings>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTemporaryDir>
#include <QUrl>

#include "core/utils/remoteLogBatchHealth.h"
#include "core/utils/remoteLogCursor.h"
#include "core/utils/remoteLogReceipt.h"

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

    void staleNonAwaitingEpochRebindsOnlyOpaqueMetadata()
    {
        const amnezia::RemoteLogSecretTransitionState stale { true, false, 811247 };
        amnezia::RemoteLogSecretTransitionEvidence evidence;
        evidence.sourceIdentityMatches = false;
        evidence.cursorMatchesSource = false;
        evidence.sourceEpochRebindSafe = true;
        evidence.sourceSize = 3734;
        evidence.acceptedCursorOffset = 0;

        const auto result = amnezia::remoteLogAdvanceSecretTransition(stale, evidence);
        QVERIFY(result.forceRedacted);
        QVERIFY(result.persistMarker);
        QVERIFY(result.updateMarkerSecretSet);
        QVERIFY(!result.globalFailClosed);
        QVERIFY(result.state.present);
        QVERIFY(!result.state.awaitingStableSource);
        QCOMPARE(result.state.highWaterOffset, qint64 { 3734 });
    }

    void awaitingEpochMismatchCannotRebind()
    {
        const amnezia::RemoteLogSecretTransitionState awaiting { true, true, 811247 };
        amnezia::RemoteLogSecretTransitionEvidence evidence;
        evidence.sourceIdentityMatches = false;
        evidence.cursorMatchesSource = false;
        evidence.sourceEpochRebindSafe = true;
        evidence.sourceSize = 3734;
        evidence.acceptedCursorOffset = 0;

        const auto result = amnezia::remoteLogAdvanceSecretTransition(awaiting, evidence);
        QVERIFY(result.forceRedacted);
        QVERIFY(result.globalFailClosed);
        QVERIFY(!result.persistMarker);
    }

    void epochRebindRejectsOutOfRangeScan()
    {
        const amnezia::RemoteLogSecretTransitionState stale { true, false, 100 };
        amnezia::RemoteLogSecretTransitionEvidence evidence;
        evidence.sourceEpochRebindSafe = true;
        evidence.sourceSize = 32;
        evidence.acceptedCursorOffset = 33;

        const auto result = amnezia::remoteLogAdvanceSecretTransition(stale, evidence);
        QVERIFY(result.forceRedacted);
        QVERIFY(result.globalFailClosed);
        QVERIFY(!result.persistMarker);
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

    void httpReceiptRequiresTheExactBatchId()
    {
        QTcpServer server;
        QVERIFY(server.listen(QHostAddress::LocalHost));
        QNetworkAccessManager manager;

        struct HttpExerciseResult {
            bool transportOk = false;
            bool receiptAccepted = false;
        };

        const auto exercise = [&](const QByteArray &accepted,
                                  const QByteArray &received,
                                  const QByteArray &expected) {
            const QMetaObject::Connection connection = connect(
                    &server, &QTcpServer::newConnection, &server, [&]() {
                        QTcpSocket *socket = server.nextPendingConnection();
                        if (!socket) {
                            return;
                        }
                        const auto responseSent = QSharedPointer<bool>::create(false);
                        const auto sendResponse = [socket, responseSent, accepted, received]() {
                            if (*responseSent || socket->state() == QAbstractSocket::UnconnectedState) {
                                return;
                            }
                            *responseSent = true;
                            const QByteArray response = QByteArrayLiteral(
                                    "HTTP/1.1 204 No Content\r\n"
                                    "Connection: close\r\n"
                                    "Content-Length: 0\r\n"
                                    "X-Amnezia-Batch-Accepted: ")
                                    + accepted
                                    + QByteArrayLiteral("\r\nX-Amnezia-Batch-Id: ")
                                    + received + QByteArrayLiteral("\r\n\r\n");
                            socket->write(response);
                            socket->flush();
                            QObject::connect(socket, &QTcpSocket::bytesWritten, socket,
                                             [socket](qint64) {
                                                 if (socket->bytesToWrite() == 0) {
                                                     socket->disconnectFromHost();
                                                 }
                                             });
                            if (socket->bytesToWrite() == 0) {
                                socket->disconnectFromHost();
                            }
                        };
                        connect(socket, &QTcpSocket::readyRead, socket,
                                [socket, sendResponse]() {
                                    socket->readAll();
                                    sendResponse();
                                });
                        QTimer::singleShot(0, socket, [socket, sendResponse]() {
                            if (socket->bytesAvailable() > 0) {
                                socket->readAll();
                                sendResponse();
                            }
                        });
                        connect(socket, &QTcpSocket::disconnected,
                                socket, &QObject::deleteLater);
                    });
            QNetworkRequest request(QUrl(QStringLiteral(
                    "http://127.0.0.1:%1/logs").arg(server.serverPort())));
            request.setHeader(QNetworkRequest::ContentTypeHeader,
                              QStringLiteral("text/plain"));
            QNetworkReply *reply = manager.post(request, QByteArrayLiteral("log\n"));
            QSignalSpy finished(reply, &QNetworkReply::finished);
            const bool completed = finished.wait(5000);
            const int statusCode = reply->attribute(
                    QNetworkRequest::HttpStatusCodeAttribute).toInt();
            const bool transportOk = completed && reply->error() == QNetworkReply::NoError
                    && statusCode == 204;
            const bool receiptAccepted = amnezia::remoteLogBatchReceiptAccepted(
                    reply->rawHeader("X-Amnezia-Batch-Accepted"),
                    reply->rawHeader("X-Amnezia-Batch-Id"), expected);
            reply->deleteLater();
            disconnect(connection);
            return HttpExerciseResult { transportOk, receiptAccepted };
        };

        const auto matching = exercise(QByteArrayLiteral("1"), QByteArrayLiteral("batch-1"),
                                       QByteArrayLiteral("batch-1"));
        QVERIFY(matching.transportOk);
        QVERIFY(matching.receiptAccepted);

        const auto stale = exercise(QByteArrayLiteral("1"), QByteArrayLiteral("batch-old"),
                                    QByteArrayLiteral("batch-1"));
        QVERIFY(stale.transportOk);
        QVERIFY(!stale.receiptAccepted);

        const auto missingAccepted = exercise(QByteArrayLiteral(""), QByteArrayLiteral("batch-1"),
                                              QByteArrayLiteral("batch-1"));
        QVERIFY(missingAccepted.transportOk);
        QVERIFY(!missingAccepted.receiptAccepted);

        const auto emptyExpected = exercise(QByteArrayLiteral("1"), QByteArrayLiteral("batch-1"),
                                            QByteArray());
        QVERIFY(emptyExpected.transportOk);
        QVERIFY(!emptyExpected.receiptAccepted);
    }

    void malformedPersistedCursorIsDetected()
    {
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        const QString path = directory.filePath(QStringLiteral("settings.ini"));
        const QString prefix = QStringLiteral("Runtime/remoteLogUploader/cursors/test/");
        {
            QSettings settings(path, QSettings::IniFormat);
            settings.setValue(prefix + QStringLiteral("offset"),
                              QStringLiteral("not-a-number"));
            settings.setValue(prefix + QStringLiteral("fingerprintBytes"),
                              QStringLiteral("not-a-number"));
            settings.sync();
            QCOMPARE(settings.status(), QSettings::NoError);
        }
        QSettings reloaded(path, QSettings::IniFormat);
        QVERIFY(amnezia::remoteLogCursorMetadataPresent(reloaded, prefix));
        bool offsetConversionOk = true;
        QCOMPARE(amnezia::remoteLogCursorInt64(
                         reloaded.value(prefix + QStringLiteral("offset")),
                         -1, &offsetConversionOk), qint64(0));
        QVERIFY(!offsetConversionOk);
        bool conversionOk = true;
        QCOMPARE(amnezia::remoteLogCursorInt64(
                         reloaded.value(prefix + QStringLiteral("fingerprintBytes")),
                         0, &conversionOk), qint64(0));
        QVERIFY(!conversionOk);
    }

    void fingerprintBytesOnlyMetadataIsNotTreatedAsFreshCursor()
    {
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        const QString path = directory.filePath(QStringLiteral("settings.ini"));
        const QString prefix = QStringLiteral("Runtime/remoteLogUploader/cursors/test/");
        QSettings settings(path, QSettings::IniFormat);
        settings.setValue(prefix + QStringLiteral("fingerprintBytes"), 64);
        settings.sync();
        QCOMPARE(settings.status(), QSettings::NoError);
        QSettings reloaded(path, QSettings::IniFormat);
        QVERIFY(amnezia::remoteLogCursorMetadataPresent(reloaded, prefix));
    }
};

QTEST_MAIN(RemoteLogRetryPrivacyTest)
#include "tst_remote_log_retry_privacy.moc"
