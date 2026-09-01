#include <QtTest>

#include "headlessProtocol.h"

using namespace amnezia::headless;

class HeadlessProtocolTest : public QObject
{
    Q_OBJECT

private slots:
    void statusRequestRoundTrips()
    {
        const Request original { Command::Status, QStringLiteral("request-1"), {} };
        const QByteArray frame = encodeRequest(original);

        Request parsed;
        QString error;
        QVERIFY(parseRequest(frame, parsed, &error));
        QVERIFY2(error.isEmpty(), qPrintable(error));
        QCOMPARE(parsed.command, Command::Status);
        QCOMPARE(parsed.requestId, QStringLiteral("request-1"));
        QVERIFY(parsed.parameters.isEmpty());
    }

    void commandsWithParametersRoundTrip()
    {
        const Request original {
            Command::Connect,
            QStringLiteral("request-2"),
            QJsonObject { { QStringLiteral("profile"), QStringLiteral("work") } }
        };

        Request parsed;
        QVERIFY(parseRequest(encodeRequest(original), parsed));
        QCOMPARE(parsed.command, Command::Connect);
        QCOMPARE(parsed.parameters.value(QStringLiteral("profile")).toString(),
                 QStringLiteral("work"));
    }

    void unknownCommandIsRejected()
    {
        Request parsed;
        QString error;
        QVERIFY(!parseRequest(
            QByteArrayLiteral("{\"protocol\":1,\"id\":\"x\",\"command\":\"reboot\",\"params\":{}}\n"),
            parsed, &error));
        QVERIFY(error.contains(QStringLiteral("command")));
    }

    void malformedAndOversizedFramesAreRejected()
    {
        Request parsed;
        QString error;
        QVERIFY(!parseRequest(QByteArrayLiteral("not-json\n"), parsed, &error));
        QVERIFY(!error.isEmpty());

        QByteArray oversized(MaximumFrameSize + 1, 'x');
        oversized.append('\n');
        QVERIFY(!parseRequest(oversized, parsed, &error));
        QVERIFY(error.contains(QStringLiteral("large")));
    }

    void responseIsSingleLineAndVersioned()
    {
        const QByteArray frame = encodeResponse(
            QStringLiteral("request-3"), QJsonObject { { QStringLiteral("connected"), false } });
        QVERIFY(frame.endsWith('\n'));
        QCOMPARE(frame.count('\n'), 1);

        const QJsonDocument document = QJsonDocument::fromJson(frame.trimmed());
        QVERIFY(document.isObject());
        QCOMPARE(document.object().value(QStringLiteral("protocol")).toInt(),
                 WireProtocolVersion);
        QCOMPARE(document.object().value(QStringLiteral("ok")).toBool(), true);
        QCOMPARE(document.object().value(QStringLiteral("id")).toString(),
                 QStringLiteral("request-3"));
    }
};

QTEST_MAIN(HeadlessProtocolTest)
#include "tst_headless_protocol.moc"
