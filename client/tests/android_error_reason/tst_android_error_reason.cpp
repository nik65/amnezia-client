#include <QtTest>
#include <QPointer>
#include <QTranslator>
#include <limits>
#include "core/protocols/androidProtocolBinding.h"
#include "core/utils/errorStrings.h"

using amnezia::ErrorCode;

class RecordingProtocol final : public QObject
{
    Q_OBJECT
public:
    explicit RecordingProtocol(QStringList &history) : history(history) {}
    void setLastError(ErrorCode error) {
        lastError = error;
        history.append(QStringLiteral("state"));
    }
    QStringList &history;
    ErrorCode lastError = ErrorCode::NoError;
signals:
    void protocolError(amnezia::ErrorCode error);
};

class ServiceEvents final : public QObject
{
    Q_OBJECT
signals:
    void serviceError(amnezia::ErrorCode error);
};

class AndroidErrorReasonTest final : public QObject
{
    Q_OBJECT
private slots:
    void reasonAllowlist_data() {
        QTest::addColumn<int>("reason");
        QTest::addColumn<int>("expected");
        for (int reason : {-1, 0, 100, 104, 106, 200, std::numeric_limits<int>::max()})
            QTest::newRow(qPrintable(QString::number(reason))) << reason << int(ErrorCode::UnknownError);
        QTest::newRow("api28-combined") << 105 << int(ErrorCode::AndroidCombinedRoutingRequiresAndroid10);
    }
    void reasonAllowlist() {
        QFETCH(int, reason);
        QFETCH(int, expected);
        QCOMPARE(int(AndroidProtocolBinding::errorForServiceReason(reason)), expected);
    }
    void actionableProductionErrorString() {
        QCOMPARE(errorString(ErrorCode::AndroidCombinedRoutingRequiresAndroid10),
                 QStringLiteral("ErrorCode: 105. Combining included sites and applications requires Android 10 or newer. On Android 9, use only one included list: sites or applications."));
        QVERIFY(errorString(ErrorCode::AndroidCombinedRoutingRequiresAndroid10)
                    != errorString(ErrorCode::UnknownError));
    }
    void reasonPrecedesErrorState() {
        QStringList history;
        RecordingProtocol protocol(history);
        connect(&protocol, &RecordingProtocol::protocolError, this, [&](ErrorCode error) {
            QCOMPARE(error, ErrorCode::AndroidCombinedRoutingRequiresAndroid10);
            QCOMPARE(protocol.lastError, ErrorCode::NoError);
            history.append(QStringLiteral("reason"));
        });
        QVERIFY(AndroidProtocolBinding::deliverServiceError(QPointer(&protocol), &protocol, 7, 7,
                AndroidProtocolBinding::errorForServiceReason(105), [&] { history.append("generic"); }));
        QCOMPARE(history, QStringList({"reason", "state"}));
        QCOMPARE(protocol.lastError, ErrorCode::AndroidCombinedRoutingRequiresAndroid10);
    }
    void russianProductionTranslation() {
        QTranslator russian;
        QVERIFY(russian.load(QString::fromUtf8(ANDROID_ERROR_REASON_QM)));
        const char *source = "Combining included sites and applications requires Android 10 or newer. On Android 9, use only one included list: sites or applications.";
        const QString translated = russian.translate("QObject", source);
        QVERIFY(!translated.isEmpty());
        QVERIFY(translated != QString::fromUtf8(source));
        QVERIFY(translated.contains(QStringLiteral("Android 10")));
        QVERIFY(translated.contains(QStringLiteral("Android 9")));
        QVERIFY(QCoreApplication::installTranslator(&russian));
        QVERIFY(errorString(ErrorCode::AndroidCombinedRoutingRequiresAndroid10).endsWith(translated));
        QCoreApplication::removeTranslator(&russian);
    }
    void genericErrorKeepsExistingPath() {
        QStringList history;
        RecordingProtocol protocol(history);
        connect(&protocol, &RecordingProtocol::protocolError, this, [&](ErrorCode) { history.append("reason"); });
        QVERIFY(AndroidProtocolBinding::deliverServiceError(QPointer(&protocol), &protocol, 7, 7,
                AndroidProtocolBinding::errorForServiceReason(0), [&] { history.append("generic"); }));
        QCOMPARE(history, QStringList({"generic"}));
        QCOMPARE(protocol.lastError, ErrorCode::NoError);
    }
    void retiredEpochAndProtocolAreIgnored() {
        QStringList history;
        RecordingProtocol oldProtocol(history), currentProtocol(history);
        const auto generic = [&] { history.append("generic"); };
        QVERIFY(!AndroidProtocolBinding::deliverServiceError(QPointer(&oldProtocol), &oldProtocol,
                7, 8, ErrorCode::AndroidCombinedRoutingRequiresAndroid10, generic));
        QVERIFY(!AndroidProtocolBinding::deliverServiceError(QPointer(&oldProtocol), &currentProtocol,
                7, 7, ErrorCode::AndroidCombinedRoutingRequiresAndroid10, generic));
        QVERIFY(!AndroidProtocolBinding::deliverServiceError(QPointer<RecordingProtocol>(), &currentProtocol,
                7, 7, ErrorCode::AndroidCombinedRoutingRequiresAndroid10, generic));
        QVERIFY(history.isEmpty());
    }
    void directReasonObserverMayDestroyProtocol() {
        QStringList history;
        auto *raw = new RecordingProtocol(history);
        QPointer<RecordingProtocol> protocol(raw);
        connect(raw, &RecordingProtocol::protocolError, this, [&](ErrorCode) {
            history.append("reason");
            delete raw;
        });
        QVERIFY(AndroidProtocolBinding::deliverServiceError(protocol, raw, 7, 7,
                ErrorCode::AndroidCombinedRoutingRequiresAndroid10, [&] { history.append("generic"); }));
        QVERIFY(protocol.isNull());
        QCOMPARE(history, QStringList({"reason"}));
    }
    void queuedOldEpochIsIgnoredAtDelivery() {
        QStringList history;
        RecordingProtocol protocol(history);
        ServiceEvents service;
        quint64 epoch = 7;
        connect(&service, &ServiceEvents::serviceError, &protocol,
                [&, guarded = QPointer(&protocol), eventEpoch = epoch](ErrorCode error) {
            AndroidProtocolBinding::deliverServiceError(guarded, &protocol, eventEpoch, epoch,
                error, [&] { history.append("generic"); });
        }, Qt::QueuedConnection);
        emit service.serviceError(ErrorCode::AndroidCombinedRoutingRequiresAndroid10);
        ++epoch;
        QCoreApplication::sendPostedEvents(nullptr, QEvent::MetaCall);
        QVERIFY(history.isEmpty());
    }
    void queuedEventDoesNotOutliveReceiver() {
        QStringList history;
        ServiceEvents service;
        auto *protocol = new RecordingProtocol(history);
        connect(&service, &ServiceEvents::serviceError, protocol,
                [&, guarded = QPointer(protocol)](ErrorCode error) {
            AndroidProtocolBinding::deliverServiceError(guarded, protocol, 7, 7,
                error, [&] { history.append("generic"); });
        }, Qt::QueuedConnection);
        emit service.serviceError(ErrorCode::AndroidCombinedRoutingRequiresAndroid10);
        delete protocol;
        QCoreApplication::sendPostedEvents(nullptr, QEvent::MetaCall);
        QVERIFY(history.isEmpty());
    }
};

QTEST_GUILESS_MAIN(AndroidErrorReasonTest)
#include "tst_android_error_reason.moc"
