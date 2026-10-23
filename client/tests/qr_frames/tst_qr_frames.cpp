#include <QDataStream>
#include <QIODevice>
#include <QTest>
#include "qrCodeUtils.h"

class QrFramesTest final : public QObject
{
    Q_OBJECT
    static QByteArray frame(quint8 count, quint8 id, const QByteArray &payload)
    {
        QByteArray data;
        QDataStream stream(&data, QIODevice::WriteOnly);
        stream << qrCodeUtils::qrMagicCode << count << id << payload;
        return data;
    }
private slots:
    void boundaryRoundTrip()
    {
        for (const qsizetype size : {qsizetype(1), qsizetype(849), qsizetype(850), qsizetype(851),
                                    qrCodeUtils::maximumQrPayloadBytes}) {
            QByteArray input(size, 'x');
            input[0] = '\0';
            const auto encoded = qrCodeUtils::encodeQrCodeChunks(input);
            QCOMPARE(encoded.size(), (size + 849) / 850);
            QByteArray joined;
            for (qsizetype i = 0; i < encoded.size(); ++i) {
                qrCodeUtils::QrCodeChunk chunk;
                QVERIFY(qrCodeUtils::decodeQrCodeChunk(encoded[i], chunk));
                QCOMPARE(chunk.chunksCount, quint8(encoded.size()));
                QCOMPARE(chunk.chunkId, quint8(i));
                joined += chunk.payload;
            }
            QCOMPARE(joined, input);
        }
    }
    void overflowRefusesBeforeRendering()
    {
        QVERIFY(qrCodeUtils::encodeQrCodeChunks({}).isEmpty());
        const QByteArray oversized(qrCodeUtils::maximumQrPayloadBytes + 1, 'x');
        QVERIFY(qrCodeUtils::encodeQrCodeChunks(oversized).isEmpty());
        QVERIFY(qrCodeUtils::generateQrCodeImageSeries(oversized).isEmpty());
        QVERIFY(qrCodeUtils::generateQrCodeImageSeries({}).isEmpty());
    }
    void rejectsInvalidFramesWithoutChangingOutput()
    {
        auto nullLength = frame(2, 0, "x");
        for (qsizetype i = 4; i < 8; ++i) nullLength[i] = char(0xff);
        for (const auto &invalid : {QByteArray(), frame(0, 0, "x"), frame(2, 2, "x"),
                frame(2, 255, "x"), frame(2, 0, {}), frame(2, 0, "x").left(4),
                frame(2, 0, "x").left(8), frame(2, 0, "x") + "trailing", nullLength,
                frame(2, 0, QByteArray(851, 'x'))}) {
            qrCodeUtils::QrCodeChunk output{7, 3, "unchanged"};
            QVERIFY(!qrCodeUtils::decodeQrCodeChunk(invalid, output));
            QCOMPARE(output.chunksCount, quint8(7));
            QCOMPARE(output.chunkId, quint8(3));
            QCOMPARE(output.payload, QByteArray("unchanged"));
        }
    }
    void legacyWireBytesAreUnchanged()
    {
        const QByteArray payload("owned\0bytes", 11);
        const auto encoded = qrCodeUtils::encodeQrCodeChunks(payload);
        QCOMPARE(encoded.size(), 1);
        QCOMPARE(encoded.front(), frame(1, 0, payload));
        qrCodeUtils::QrCodeChunk decoded;
        QVERIFY(qrCodeUtils::decodeQrCodeChunk(frame(255, 254, "last"), decoded));
        QCOMPARE(decoded.chunkId, quint8(254));
        QCOMPARE(decoded.chunksCount, quint8(255));
    }
    void ordinaryImageSeriesStillWorks()
    {
        const auto images = qrCodeUtils::generateQrCodeImageSeries("owned non-sensitive data");
        QCOMPARE(images.size(), 1);
        QVERIFY(images.front().startsWith("data:image/svg;base64,"));
    }
};
QTEST_GUILESS_MAIN(QrFramesTest)
#include "tst_qr_frames.moc"
