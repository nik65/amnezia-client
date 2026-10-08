#pragma once
#include <QByteArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>

namespace amnezia::awgMigration {
inline bool passiveMigrationRequestAllowed(const QString &state)
{
    return state.isEmpty() || state == QStringLiteral("enrolling")
            || state == QStringLiteral("enrolled") || state == QStringLiteral("expired")
            || state == QStringLiteral("rolled_back");
}

struct ControlReply {
    enum State { Pending, Complete, Failed } state = Pending;
    QString reason;
    int httpStatus = 0;
    QJsonObject payload;
};
inline ControlReply parseControlReply(const QByteArray &bytes, int maximumDocumentBytes = 32768)
{
    ControlReply result;
    auto fail = [&](const char *reason) {
        result.state = ControlReply::Failed;
        result.reason = QString::fromLatin1(reason);
        return result;
    };
    if (bytes.size() > maximumDocumentBytes + 8192) return fail("control_response_too_large");
    const auto boundary = bytes.indexOf("\r\n\r\n");
    if (boundary < 0) return result;
    if (boundary > 8192) return fail("control_response_headers_too_large");
    const auto headers = bytes.left(boundary).split('\n');
    const auto status = headers.first().trimmed().split(' ');
    if (status.size() < 3 || (status[0] != "HTTP/1.0" && status[0] != "HTTP/1.1")
        || status[1].size() != 3) return fail("control_response_invalid_status");
    bool valid = false;
    result.httpStatus = status[1].toInt(&valid);
    if (!valid || result.httpStatus < 100 || result.httpStatus > 599)
        return fail("control_response_invalid_status");
    if (result.httpStatus != 200) return fail("control_http_rejected");
    qint64 length = -1;
    for (const auto &header : headers.mid(1)) {
        const auto lower = header.toLower();
        if (lower.startsWith("transfer-encoding:")) return fail("control_response_transfer_encoding");
        if (lower.startsWith("content-length:")) {
            const auto parsed = header.mid(15).trimmed().toLongLong(&valid);
            if (!valid || length >= 0 || parsed <= 0 || parsed > maximumDocumentBytes)
                return fail("control_response_invalid_length");
            length = parsed;
        }
    }
    if (length < 0) return fail("control_response_missing_length");
    if (bytes.size() < boundary + 4 + length) return result;
    if (bytes.size() != boundary + 4 + length) return fail("control_response_extra_bytes");
    QJsonParseError error;
    const auto document = QJsonDocument::fromJson(bytes.mid(boundary + 4), &error);
    if (error.error != QJsonParseError::NoError || !document.isObject())
        return fail("control_response_invalid_json");
    result.state = ControlReply::Complete;
    result.payload = document.object();
    return result;
}
}
