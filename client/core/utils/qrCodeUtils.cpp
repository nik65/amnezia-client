#include "qrCodeUtils.h"

#include <QDataStream>
#include <QIODevice>
#include <QList>

bool qrCodeUtils::decodeQrCodeChunk(const QByteArray &frame, QrCodeChunk &chunk)
{
    constexpr qsizetype headerBytes = 8;
    if (frame.size() < headerBytes || frame.size() > headerBytes + qrChunkPayloadBytes) {
        return false;
    }
    QDataStream stream(frame);
    qint16 magic = 0;
    quint8 count = 0, id = 0;
    quint32 length = 0;
    stream >> magic >> count >> id >> length;
    if (stream.status() != QDataStream::Ok || magic != qrMagicCode || count == 0
        || id >= count || length == 0 || length > qrChunkPayloadBytes
        || frame.size() != headerBytes + length) {
        return false;
    }
    chunk = QrCodeChunk{count, id, frame.mid(headerBytes, length)};
    return true;
}

QList<QByteArray> qrCodeUtils::encodeQrCodeChunks(const QByteArray &data)
{
    if (data.isEmpty() || data.size() > maximumQrPayloadBytes) {
        return {};
    }
    const quint8 count = static_cast<quint8>((data.size() + qrChunkPayloadBytes - 1) / qrChunkPayloadBytes);
    QList<QByteArray> frames;
    for (qsizetype offset = 0; offset < data.size(); offset += qrChunkPayloadBytes) {
        QByteArray frame;
        QDataStream stream(&frame, QIODevice::WriteOnly);
        stream << qrMagicCode << count << static_cast<quint8>(offset / qrChunkPayloadBytes)
               << data.mid(offset, qrChunkPayloadBytes);
        if (stream.status() != QDataStream::Ok) {
            return {};
        }
        frames.append(frame);
    }
    return frames;
}

QList<QString> qrCodeUtils::generateQrCodeImageSeries(const QByteArray &data)
{
    QList<QString> chunks;
    for (const QByteArray &frame : encodeQrCodeChunks(data)) {
        const QByteArray base64 = frame.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
        qrcodegen::QrCode qr = qrcodegen::QrCode::encodeText(base64.constData(), qrcodegen::QrCode::Ecc::LOW);
        const QString svg = QString::fromStdString(toSvgString(qr, 1));
        chunks.append(svgToBase64(svg));
    }
    return chunks;
}

QString qrCodeUtils::generatePlainQrCodeImage(const QByteArray &data)
{
    try {
        qrcodegen::QrCode qr = qrcodegen::QrCode::encodeText(data.constData(), qrcodegen::QrCode::Ecc::LOW);
        QString svg = QString::fromStdString(toSvgString(qr, 1));
        return svgToBase64(svg);
    } catch (const qrcodegen::data_too_long &) {
        return {};
    }
}

QString qrCodeUtils::svgToBase64(const QString &image)
{
    return "data:image/svg;base64," + QString::fromLatin1(image.toUtf8().toBase64().data());
}

qrcodegen::QrCode qrCodeUtils::generateQrCode(const QByteArray &data)
{
    return qrcodegen::QrCode::encodeText(data.constData(), qrcodegen::QrCode::Ecc::LOW);
}
