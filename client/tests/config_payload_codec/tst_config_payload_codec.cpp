#include <QTest>
#include <QList>
#include <QtEndian>
#include <limits>

#include "core/utils/configPayloadCodec.h"

using namespace amnezia::configPayloadCodec;

class TestConfigPayloadCodec : public QObject
{
    Q_OBJECT

private slots:
    void rawData_data()
    {
        QTest::addColumn<QByteArray>("input");
        QTest::newRow("json") << QByteArray("{\"containers\":[],\"description\":\"fixture\"}");
        QTest::newRow("wireguard") << QByteArray("[Interface]\nAddress=10.0.0.1/24\n[Peer]\nAllowedIPs=10.0.0.2/32\n");
        QTest::newRow("empty") << QByteArray();
        QTest::newRow("short") << QByteArray("abc");
        QTest::newRow("json-zlib-header-collision") << QByteArray(R"({"xxx^":1,"containers":[]})");
        QTest::newRow("json-leading-whitespace") << QByteArray(" \t\r\n[1,2,3]");
        QTest::newRow("json-leading-bom") << QByteArray("\xef\xbb\xbf") + QByteArray(R"({"containers":[]})");
        QTest::newRow("wireguard-comment-zlib-collision")
            << QByteArray("#AAAx^ comment\n[Interface]\nAddress=10.0.0.1/24\n[Peer]\nAllowedIPs=10.0.0.2/32\n");
        QTest::newRow("openvpn-comment-zlib-collision")
            << QByteArray(";AAAx^ comment\nclient\ndev tun\nremote vpn.example 1194\n");
        QTest::newRow("generic-text-zlib-collision") << QByteArray("AAAAx^ plaintext");
        QTest::newRow("whitespace-text-prefix") << QByteArray("\t\n\f\vtext");
        QTest::newRow("text-prefix-bom") << QByteArray("\xef\xbb\xbf") + QByteArray("#AAAx^ comment\nclient\ndev tun\n");
        QTest::newRow("unicode-wireguard-comment-zlib-collision")
            << QString::fromUtf8("#АAx^ comment\n[Interface]\nAddress=10.0.0.1/24\n[Peer]\nAllowedIPs=10.0.0.2/32\n").toUtf8();
        QTest::newRow("unicode-openvpn-comment-zlib-collision")
            << QString::fromUtf8(";АAx^ comment\nclient\ndev tun\nremote vpn.example 1194\n").toUtf8();
        QTest::newRow("comment-prefix-bom-whitespace")
            << QByteArray("\xef\xbb\xbf \t\f\v") + QString::fromUtf8("#АAx^ comment\nclient\ndev tun\n").toUtf8();
    }

    void rawData()
    {
        QFETCH(QByteArray, input);
        if (QByteArray(QTest::currentDataTag()).startsWith("unicode-")) {
            QCOMPARE(input.at(4), 'x');
            QCOMPARE(input.at(5), '^');
        }
        const auto result = decode(input);
        QCOMPARE(result.status, Status::NotCompressed);
        QVERIFY(result.accepted());
        QCOMPARE(result.data, input);
    }

    void roundTrip_data()
    {
        QTest::addColumn<QByteArray>("input");
        QTest::newRow("text") << QByteArray("owned configuration fixture");
        QTest::newRow("unicode") << QString::fromUtf8("Конфигурация 🙂 世界").toUtf8();
        QTest::newRow("nul") << QByteArray("one\0two\0three", 13);
        QTest::newRow("empty") << QByteArray();
    }

    void roundTrip()
    {
        QFETCH(QByteArray, input);
        const auto result = decode(qCompress(input, 9));
        QCOMPARE(result.status, Status::Decoded);
        QVERIFY(result.accepted());
        QCOMPARE(result.data, input);
    }

    void sizeHintsDoNotControlAllocationOrActualLimit()
    {
        const QByteArray input(100000, 'a');
        auto compressed = qCompress(input, 9);
        for (const quint32 hint : { quint32(0), quint32(1), quint32(100000), std::numeric_limits<quint32>::max() }) {
            qToBigEndian(hint, reinterpret_cast<uchar *>(compressed.data()));
            const auto result = decode(compressed);
            QCOMPARE(result.status, Status::Decoded);
            QCOMPARE(result.data, input);
        }
        QByteArray large(17 * 1024 * 1024, 'a');
        compressed = qCompress(large, 9);
        qToBigEndian(quint32(1), reinterpret_cast<uchar *>(compressed.data()));
        const auto rejected = decode(compressed);
        QCOMPARE(rejected.status, Status::TooLarge);
        QVERIFY(rejected.data.isEmpty());
        QVERIFY(!rejected.accepted());
    }

    void decodedBoundaryAndOverflow()
    {
        const auto exact = decode(qCompress(QByteArray(maximumDecodedBytes, 'x'), 9));
        QCOMPARE(exact.status, Status::Decoded);
        QCOMPARE(exact.data.size(), maximumDecodedBytes);
        const auto over = decode(qCompress(QByteArray(maximumDecodedBytes + 1, 'x'), 9));
        QCOMPARE(over.status, Status::TooLarge);
        QVERIFY(over.data.isEmpty());
    }

    void incompressibleBoundaryIncludesWrapperOverhead()
    {
        QByteArray input(maximumDecodedBytes, '\0');
        quint32 state = 0x12345678;
        for (auto &byte : input) {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            byte = static_cast<char>(state);
        }
        for (const int level : { 0, 6 }) {
            const auto compressed = qCompress(input, level);
            QVERIFY(compressed.size() > maximumDecodedBytes);
            QVERIFY(compressed.size() <= maximumCompressedBytes);
            const auto result = decode(compressed);
            QCOMPARE(result.status, Status::Decoded);
            QCOMPARE(result.data, input);
            QVERIFY(6 + compressed.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals).size()
                    <= maximumEncodedTextBytes);
        }
    }

    void checksumTruncationAndTrailingBytesRejectWithoutPartialOutput()
    {
        const auto compressed = qCompress(QByteArray(100000, 'a'), 9);
        QList<QByteArray> invalid;
        for (const auto cut : { qsizetype(6), compressed.size() / 2, compressed.size() - 1 })
            invalid.append(compressed.first(cut));
        auto checksum = compressed;
        checksum[checksum.size() - 1] ^= 1;
        invalid << checksum << compressed + 'x' << compressed + compressed;
        for (const auto &bytes : invalid) {
            const auto result = decode(bytes);
            QCOMPARE(result.status, Status::Invalid);
            QVERIFY(!result.accepted());
            QVERIFY(result.data.isEmpty());
        }
    }

    void independentInputAndRawBounds()
    {
        QCOMPARE(decode(QByteArray(maximumDecodedBytes, 'r')).status, Status::NotCompressed);
        auto tooLarge = decode(QByteArray(maximumDecodedBytes + 1, 'r'));
        QCOMPARE(tooLarge.status, Status::TooLarge);
        QVERIFY(tooLarge.data.isEmpty());
        QCOMPARE(decode(QByteArray(maximumCompressedBytes + 1, 'r')).status, Status::TooLarge);
        auto textOverflow = QByteArray("AAAAx^") + QByteArray(maximumDecodedBytes - 5, 'r');
        QCOMPARE(textOverflow.size(), maximumDecodedBytes + 1);
        const auto rejectedText = decode(textOverflow);
        QCOMPARE(rejectedText.status, Status::TooLarge);
        QVERIFY(rejectedText.data.isEmpty());
        QCOMPARE(decode(QByteArray("abc"), 2).status, Status::TooLarge);
        QCOMPARE(decode(QByteArray(), -1).status, Status::Invalid);
        QCOMPARE(decode(QByteArray(), maximumDecodedBytes + 1).status, Status::Invalid);
        QCOMPARE(decode(qCompress(QByteArray()), 0).status, Status::Decoded);
        QCOMPARE(decode(qCompress(QByteArray("a")), 0).status, Status::TooLarge);
    }

    void noProgressOrDictionaryStreamIsRejected()
    {
        // Valid zlib header with dictionary request; qCompress does not emit dictionaries.
        QByteArray dictionary = QByteArray::fromHex("0000000178bb00000000");
        const auto result = decode(dictionary);
        QCOMPARE(result.status, Status::Invalid);
        QVERIFY(result.data.isEmpty());
    }
};

QTEST_GUILESS_MAIN(TestConfigPayloadCodec)
#include "tst_config_payload_codec.moc"
