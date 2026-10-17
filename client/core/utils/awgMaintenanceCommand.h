#pragma once
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>

namespace amnezia::operatorMode {
inline QJsonObject parseAwgMaintenanceArgument(const QString &input)
{
    // A deliberately flat JSON grammar. Decode each string with Qt's JSON
    // parser, but detect repeated decoded keys before an object can erase them.
    if (input.isEmpty() || input.size() > 4096) return {};
    qsizetype offset = 0;
    const auto space = [&]() {
        while (offset < input.size() && (input[offset] == ' ' || input[offset] == '\t'
               || input[offset] == '\r' || input[offset] == '\n')) ++offset;
    };
    const auto string = [&](QString &decoded) {
        if (offset >= input.size() || input[offset] != '"') return false;
        const qsizetype begin = offset++;
        bool escaped = false;
        while (offset < input.size()) {
            const QChar ch = input[offset++];
            if (!escaped && ch == '"') {
                const QByteArray token = input.mid(begin, offset - begin).toUtf8();
                const auto parsed = QJsonDocument::fromJson('[' + token + ']');
                if (!parsed.isArray() || parsed.array().size() != 1 || !parsed.array()[0].isString()) return false;
                decoded = parsed.array()[0].toString();
                return true;
            }
            if (!escaped && ch == '\\') escaped = true;
            else escaped = false;
        }
        return false;
    };
    space();
    if (offset >= input.size() || input[offset++] != '{') return {};
    QJsonObject result;
    for (;;) {
        space();
        QString key;
        if (!string(key) || result.contains(key)) return {};
        if (key != "serverId" && key != "source" && key != "generation" && key != "expectedJournalSha256") return {};
        space();
        if (offset >= input.size() || input[offset++] != ':') return {};
        space();
        if (key == "generation") {
            const qsizetype begin = offset;
            while (offset < input.size() && input[offset] >= '0' && input[offset] <= '9') ++offset;
            const QString token = input.mid(begin, offset - begin);
            bool ok = false;
            const qint64 generation = token.toLongLong(&ok);
            if (!ok || generation < 1 || generation > 9007199254740991LL || QString::number(generation) != token) return {};
            result.insert(key, generation);
        } else {
            QString value;
            if (!string(value)) return {};
            result.insert(key, value);
        }
        space();
        if (offset >= input.size()) return {};
        const QChar separator = input[offset++];
        if (separator == '}') break;
        if (separator != ',') return {};
    }
    space();
    if (offset != input.size() || result.size() != 4) return {};
    const QString serverId = result.value("serverId").toString();
    if (serverId.isEmpty() || serverId.size() > 256) return {};
    for (const QChar ch : serverId) if (ch.unicode() < 32) return {};
    const QString source = result.value("source").toString();
    if (source != "amnezia-awg" && source != "amnezia-awg2") return {};
    if (!QRegularExpression(QStringLiteral("^[a-f0-9]{64}$")).match(result.value("expectedJournalSha256").toString()).hasMatch()) return {};
    return result;
}
}
