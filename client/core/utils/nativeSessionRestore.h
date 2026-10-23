#pragma once
#include <QByteArray>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>
#include <QSet>
#include <QStringDecoder>
#include <limits>
#include <atomic>
#include <mutex>

// Process-local authority only; never a managed-route or kernel-address receipt.
namespace NativeSessionRestore {
// Linearizes observed-native ingress against the final Java fresh-start call.
inline std::recursive_mutex admissionMutex;
// A local ordering ticket, never native-session or cleanup authority. A JNI
// observation is remembered synchronously before its queued Qt delivery, so
// worker start cannot overtake an already received unbound-native observation.
class Ingress {
public:
    quint64 observe() {
        const auto ticket=m_version.load();
        auto previous=m_observation.load();
        while (previous<ticket && !m_observation.compare_exchange_weak(previous,ticket)) {}
        return ticket;
    }
    quint64 version() const { return m_version.load(); }
    bool observed(quint64 ticket) const {
        return ticket!=0 && ticket==m_observation.load() && ticket==m_version.load();
    }
    bool observed() const { return observed(version()); }
    void invalidate() { m_version.fetch_add(1); }
private:
    std::atomic<quint64> m_version{1},m_observation{0};
};
inline Ingress ingress;
inline bool uuid(const QString &s) {
    static const QRegularExpression pattern(QStringLiteral("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"));
    return s.size() == 36 && pattern.match(s).hasMatch();
}
inline bool decimal(const QString &s) {
    if (s.isEmpty() || s.size() > 19 || s.front() < '1' || s.front() > '9') return false;
    for (QChar c : s) if (c < '0' || c > '9') return false;
    bool okay = false; const auto n = s.toULongLong(&okay);
    return okay && n > 0 && n <= quint64(std::numeric_limits<qint64>::max());
}
inline bool ipv4(const QString &s) {
    const auto parts = s.split('.'); if (parts.size() != 4) return false;
    for (const auto &part : parts) {
        bool okay = false; const auto n = part.toUInt(&okay);
        if (!okay || n > 255 || QString::number(n) != part) return false;
    }
    return true;
}
inline bool peer(const QString &s) {
    const auto b = QByteArray::fromBase64(s.toLatin1(), QByteArray::AbortOnBase64DecodingErrors);
    return b.size() == 32 && QString::fromLatin1(b.toBase64()) == s;
}
inline bool identity(const QJsonObject &o) {
    return o.size() == 3 && uuid(o.value("serviceInstanceId").toString())
        && uuid(o.value("serviceActivationId").toString()) && uuid(o.value("connectionNonce").toString());
}
inline bool serverId(const QString &s) {
    if (s.isEmpty() || s.toUtf8().size()>256) return false;
    for (QChar c:s) if (c.unicode()<32) return false;
    return true;
}
inline QJsonObject boundIdentity(const QJsonObject &o) {
    QJsonObject result;
    for (const char *key : {"serviceInstanceId", "serviceActivationId", "connectionNonce"}) result[key] = o.value(key);
    return identity(result) ? result : QJsonObject{};
}
// This wire object contains only a numeric schema and strings. Parse its
// grammar before QJsonDocument so duplicate/escaped aliases cannot be lost.
inline QJsonObject decode(const QByteArray &bytes) {
    if (bytes.isEmpty() || bytes.size() > 8192) return {};
    QStringDecoder utf8(QStringDecoder::Utf8); const QString text = utf8(bytes);
    if (utf8.hasError() || text.contains(QChar::Null)) return {};
    qsizetype at = 0;
    auto ws = [&]() { while (at < bytes.size() && (bytes[at]==' ' || bytes[at]=='\t' || bytes[at]=='\r' || bytes[at]=='\n')) ++at; };
    auto string = [&]() -> QString {
        if (at >= bytes.size() || bytes[at] != '"') return {};
        const auto start = at++; bool escaped = false;
        while (at < bytes.size()) {
            const char c = bytes[at++];
            if (!escaped && c == '"') {
                const auto array = QJsonDocument::fromJson("[" + bytes.mid(start, at-start) + "]");
                if (!array.isArray() || array.array().size()!=1 || !array.array()[0].isString()) return {};
                const auto value=array.array()[0].toString();
                if (value.contains(QChar::Null)) return {};
                for (qsizetype i=0;i<value.size();++i) {
                    if (value[i].isHighSurrogate()) {
                        if (++i>=value.size() || !value[i].isLowSurrogate()) return {};
                    } else if (value[i].isLowSurrogate()) return {};
                }
                return value;
            }
            if (!escaped && c == '\\') escaped = true; else escaped = false;
        }
        return {};
    };
    ws(); if (at >= bytes.size() || bytes[at++]!='{') return {};
    QSet<QString> keys; QJsonObject result;
    for (;;) {
        ws(); const auto key = string(); if (key.isEmpty() || keys.contains(key)) return {}; keys.insert(key);
        ws(); if (at >= bytes.size() || bytes[at++]!=':') return {}; ws();
        if (key == "schema") { if (at >= bytes.size() || bytes[at++]!='1') return {}; result[key]=1; }
        else { const auto value = string(); if (value.isNull()) return {}; result[key]=value; }
        ws(); if (at >= bytes.size()) return {};
        const char separator = bytes[at++]; if (separator=='}') break; if(separator!=',') return {};
    }
    ws(); if (at != bytes.size()) return {};
    const QSet<QString> expected = {"schema","requestId","bindingGeneration","state","serverId","protocol","serviceInstanceId","serviceActivationId","connectionNonce","peerPublicKey","deviceIpv4Address","nativeGeneration"};
    if (keys != expected || result.value("schema").toInt()!=1 || result.value("state")!="CONNECTED"
        || !uuid(result.value("requestId").toString()) || !decimal(result.value("bindingGeneration").toString())
        || !decimal(result.value("nativeGeneration").toString()) || boundIdentity(result).isEmpty()
        || !serverId(result.value("serverId").toString())
        || (result.value("protocol")!="AWG" && result.value("protocol")!="WIREGUARD")
        || !peer(result.value("peerPublicKey").toString()) || !ipv4(result.value("deviceIpv4Address").toString())) return {};
    return result;
}
inline bool matchesConfiguration(const QJsonObject &snapshot, const QString &serverId, const QJsonObject &config) {
    const auto kind = config.value("protocol").toString().toUpper();
    const auto protocolConfig = config.value(config.value("protocol").toString()+"_config_data").toObject();
    QString configuredIpv4;
    for (const auto &address : protocolConfig.value("client_ip").toString().split(',')) {
        const auto network = address.trimmed().split('/');
        if (network.size()>2 || !ipv4(network.front())) continue;
        if (network.size()==2) {
            bool okay=false; const auto prefix=network.back().toUInt(&okay);
            if (!okay || prefix>32 || QString::number(prefix)!=network.back()) return false;
        }
        configuredIpv4=network.front(); break;
    }
    return !snapshot.isEmpty() && snapshot.value("serverId")==serverId && snapshot.value("protocol")==kind
        && (kind=="AWG" || kind=="WIREGUARD") && peer(protocolConfig.value("server_pub_key").toString())
        && snapshot.value("peerPublicKey")==protocolConfig.value("server_pub_key")
        && !configuredIpv4.isEmpty() && snapshot.value("deviceIpv4Address")==configuredIpv4;
}
struct Pending {
    QString requestId, generation; quint64 epoch = 0;
    void invalidate() { requestId.clear(); generation.clear(); epoch=0; }
    bool registerRequest(const QString &id, const QString &binding, quint64 currentEpoch) {
        invalidate(); if (!uuid(id) || !decimal(binding)) return false;
        requestId=id; generation=binding; epoch=currentEpoch; return true;
    }
    bool matches(const QJsonObject &snapshot, quint64 currentEpoch) const {
        return !requestId.isEmpty() && epoch==currentEpoch && snapshot.value("requestId")==requestId && snapshot.value("bindingGeneration")==generation;
    }
    bool consume(const QJsonObject &snapshot, quint64 currentEpoch) {
        if (!matches(snapshot,currentEpoch)) return false;
        invalidate(); return true;
    }
};
}
