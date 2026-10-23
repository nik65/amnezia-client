#ifndef QRCODEUTILS_H
#define QRCODEUTILS_H

#include <QByteArray>
#include <QList>
#include <QString>

#include "qrcodegen.hpp"

namespace qrCodeUtils
{
    constexpr const qint16 qrMagicCode = 1984;
    constexpr qsizetype qrChunkPayloadBytes = 850;
    constexpr int maximumQrChunks = 255;
    constexpr qsizetype maximumQrPayloadBytes = qrChunkPayloadBytes * maximumQrChunks;

    struct QrCodeChunk {
        quint8 chunksCount = 0;
        quint8 chunkId = 0;
        QByteArray payload;
    };

    // Existing wire format: big-endian magic/count/id/QByteArray length/data.
    // Decode validates the claimed length before copying any payload bytes.
    bool decodeQrCodeChunk(const QByteArray &frame, QrCodeChunk &chunk);
    QList<QByteArray> encodeQrCodeChunks(const QByteArray &data);

    QList<QString> generateQrCodeImageSeries(const QByteArray &data);
    QString generatePlainQrCodeImage(const QByteArray &data);
    qrcodegen::QrCode generateQrCode(const QByteArray &data);
    QString svgToBase64(const QString &image);
};

#endif // QRCODEUTILS_H
