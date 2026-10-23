#pragma once
#include "nativeSessionRestore.h"
#include <QMutex>
#include <QMutexLocker>

// Process-local Activity discovery admission; never native identity or cleanup proof.
namespace AndroidServiceDiscovery {
inline constexpr qsizetype maximumWireBytes = 2048;
inline QJsonObject flatObject(const QByteArray &bytes, const QSet<QString> &expected) {
    if (bytes.isEmpty() || bytes.size()>maximumWireBytes) return {};
    QStringDecoder decoder(QStringDecoder::Utf8); const QString text=decoder(bytes);
    if (decoder.hasError() || text.contains(QChar::Null)) return {};
    qsizetype at=0;
    auto ws=[&] { while(at<bytes.size() && (bytes[at]==' ' || bytes[at]=='\t' || bytes[at]=='\r' || bytes[at]=='\n')) ++at; };
    auto string=[&](QString &value) {
        if(at>=bytes.size() || bytes[at]!='"') return false;
        const auto begin=at++; bool escape=false;
        while(at<bytes.size()) {
            const char c=bytes[at++];
            if(!escape && c=='"') {
                const auto doc=QJsonDocument::fromJson("["+bytes.mid(begin,at-begin)+"]");
                if(!doc.isArray() || doc.array().size()!=1 || !doc.array()[0].isString()) return false;
                value=doc.array()[0].toString();
                if(value.contains(QChar::Null)) return false;
                for(qsizetype i=0;i<value.size();++i) {
                    if(value[i].isHighSurrogate()) { if(++i>=value.size() || !value[i].isLowSurrogate()) return false; }
                    else if(value[i].isLowSurrogate()) return false;
                }
                return true;
            }
            if(!escape && c=='\\') escape=true; else escape=false;
        }
        return false;
    };
    ws(); if(at>=bytes.size() || bytes[at++]!='{') return {};
    QJsonObject result; QSet<QString> keys;
    for(;;) {
        ws(); QString key;
        if(!string(key) || !expected.contains(key) || keys.contains(key)) return {};
        keys.insert(key); ws(); if(at>=bytes.size() || bytes[at++]!=':') return {}; ws();
        if(key=="schema") { if(at>=bytes.size() || bytes[at++]!='1') return {}; result[key]=1; }
        else { QString value; if(!string(value)) return {}; result[key]=value; }
        ws(); if(at>=bytes.size()) return {};
        const auto separator=bytes[at++]; if(separator=='}') break; if(separator!=',') return {};
    }
    ws(); return at==bytes.size() && keys==expected ? result : QJsonObject{};
}
inline QJsonObject decodeDiscovery(const QByteArray &bytes) {
    auto o=flatObject(bytes,{"schema","requestId","generation","phase","component","reason"});
    if(o.isEmpty() || !NativeSessionRestore::decimal(o.value("generation").toString())) return {};
    const auto id=o.value("requestId").toString(), p=o.value("phase").toString(), c=o.value("component").toString(), r=o.value("reason").toString();
    if(!NativeSessionRestore::uuid(id) && !(id.isEmpty() && p=="PENDING")) return {};
    if(!QSet<QString>{"NONE","AWG","OPENVPN","XRAY"}.contains(c)
        || !QSet<QString>{"NONE","INVENTORY_ERROR","MULTIPLE","BIND_FAILED","BIND_TIMEOUT","DIED","STATUS_UNPROVEN","CANCELLED"}.contains(r)) return {};
    if(p=="PENDING") { if(c!="NONE" || r!="NONE") return {}; }
    else if(p=="EMPTY") { if(c!="NONE" || r!="NONE") return {}; }
    else if(p=="BOUND_NATIVE" || p=="IDLE_NATIVE") { if(c!="AWG" || r!="NONE") return {}; }
    else if(p=="BOUND_LEGACY") { if((c!="OPENVPN" && c!="XRAY") || r!="NONE") return {}; }
    else if(p=="UNCERTAIN") { if(c!="NONE" || r=="NONE") return {}; }
    else return {};
    return o;
}
inline QJsonObject decodeAdmission(const QByteArray &bytes) {
    auto o=flatObject(bytes,{"schema","generation","requestId","outcome","reason"});
    if(o.isEmpty() || !NativeSessionRestore::decimal(o.value("generation").toString()) || !NativeSessionRestore::uuid(o.value("requestId").toString())) return {};
    const auto outcome=o.value("outcome").toString(), reason=o.value("reason").toString();
    if(outcome=="DISPATCHED") { if(reason!="NONE") return {}; }
    else if(outcome=="DISPATCH_UNCERTAIN") { if(reason!="START_EXCEPTION") return {}; }
    else if(outcome=="REJECTED") { if(!QSet<QString>{"DISCOVERY_UNCONFIRMED","STALE","START_EXCEPTION"}.contains(reason)) return {}; }
    else if(outcome=="CANCELLED") { if(!QSet<QString>{"PERMISSION_DENIED","LIFECYCLE_CANCELLED"}.contains(reason)) return {}; }
    else return {};
    return o;
}
struct Grant {
    QString requestId, generation, component;
    quint64 revision=0;
    bool valid() const { return revision && NativeSessionRestore::uuid(requestId) && NativeSessionRestore::decimal(generation); }
};
class Coordinator {
public:
    bool registerRefresh(const QString &id) {
        QMutexLocker lock(&mutex);
        if(!NativeSessionRestore::uuid(id)) return false;
        ++revision; pending=id; baseline=latest; assigned=0; acknowledged=false; terminal=false; available=false; dispatchAuthority=false; current={}; activeGrant={};
        return true;
    }
    bool acknowledge(const QString &id) {
        QMutexLocker lock(&mutex); if(id!=pending || pending.isEmpty() || terminal) return false; acknowledged=true; return true;
    }
    bool registeredRequest(const QString &id) const { QMutexLocker lock(&mutex); return !id.isEmpty() && id==pending && !terminal; }
    bool currentRequest(const QString &id) const { QMutexLocker lock(&mutex); return !id.isEmpty() && id==pending && acknowledged && !terminal; }
    bool ingest(const QJsonObject &input) {
        const auto o=decodeDiscovery(QJsonDocument(input).toJson(QJsonDocument::Compact));
        if(o.isEmpty()) return false;
        QMutexLocker lock(&mutex);
        const auto g=o.value("generation").toString().toULongLong();
        const auto id=o.value("requestId").toString(), phase=o.value("phase").toString();
        if(id.isEmpty()) {
            // Only strictly newer lifecycle invalidation can close an existing grant.
            if(g<=latest) return false;
            latest=g; floor=g; ++revision; pending.clear(); assigned=0; acknowledged=false; terminal=false; available=false; dispatchAuthority=false; activeGrant={}; current=o;
            return true;
        }
        if(!acknowledged || terminal || id!=pending || g<=baseline || g<floor || g<latest || (assigned && assigned!=g)) return false;
        assigned=g; latest=g; current=o;
        if(phase!="PENDING") { terminal=true; available=(phase=="EMPTY" || phase=="IDLE_NATIVE" || phase=="BOUND_LEGACY"); }
        return true;
    }
    QJsonObject snapshot() const { QMutexLocker lock(&mutex); return current; }
    bool resolved() const { QMutexLocker lock(&mutex); return terminal; }
    bool allowsFresh() const { QMutexLocker lock(&mutex); return terminal && available; }
    bool canReconnect(const QString &component) const {
        if(!QSet<QString>{"AWG","OPENVPN","XRAY"}.contains(component)) return false;
        QMutexLocker lock(&mutex);
        const auto phase=current.value("phase").toString();
        return terminal && ((phase=="BOUND_NATIVE" && component=="AWG")
            || (phase=="BOUND_LEGACY" && current.value("component")==component)
            || ((phase=="EMPTY" || phase=="IDLE_NATIVE") && available
                && (phase=="EMPTY" || component=="AWG")));
    }
    bool ackCurrent(const QString &id) const { return currentRequest(id); }
    Grant takeGrant(const QString &startId, const QString &component) {
        QMutexLocker lock(&mutex);
        const auto phase=current.value("phase").toString();
        if(!terminal || !available || !NativeSessionRestore::uuid(startId)
            || !QSet<QString>{"AWG","OPENVPN","XRAY"}.contains(component)
            || (phase=="IDLE_NATIVE" && component!="AWG")
            || (phase=="BOUND_LEGACY" && current.value("component")!=component)) return {};
        available=false; activeGrant={startId,current.value("generation").toString(),component,revision}; dispatchAuthority=true; return activeGrant;
    }
    bool authorizes(const Grant &grant) const {
        QMutexLocker lock(&mutex); return grant.valid() && grant.revision==revision && grant.requestId==activeGrant.requestId && grant.generation==activeGrant.generation && grant.component==activeGrant.component;
    }
    bool validatesGrant(const Grant &grant) const { return authorizes(grant); }
    bool acceptsGrant(const Grant &grant) const { return authorizes(grant); }
    bool authorizeStart(const Grant &grant) {
        QMutexLocker lock(&mutex);
        if(!dispatchAuthority || !grant.valid() || grant.revision!=revision
            || grant.requestId!=activeGrant.requestId || grant.generation!=activeGrant.generation
            || grant.component!=activeGrant.component) return false;
        dispatchAuthority=false; return true;
    }
    void invalidate() {
        QMutexLocker lock(&mutex); ++revision; pending.clear(); acknowledged=false; terminal=false; available=false; dispatchAuthority=false; activeGrant={}; current={}; assigned=0;
    }
private:
    mutable QMutex mutex;
    quint64 latest=0, floor=0, baseline=0, assigned=0, revision=1;
    QString pending; bool acknowledged=false, terminal=false, available=false, dispatchAuthority=false;
    QJsonObject current; Grant activeGrant;
};
inline Coordinator coordinator;
enum class Outcome { Ignored, Dispatched, Uncertain, Rejected, Cancelled };
class Ledger {
public:
    bool registerStart(const Grant &grant, quint64 workerEpoch, quintptr wrapperIdentity) {
        if(!grant.valid() || !workerEpoch || !wrapperIdentity) return false;
        admission=grant; epoch=workerEpoch; wrapper=wrapperIdentity; state=State::Unstarted; return true;
    }
    bool matches(const QString &id, const QString &generation, quint64 workerEpoch, quintptr wrapperIdentity) const {
        return state!=State::Empty && admission.requestId==id && admission.generation==generation && epoch==workerEpoch && wrapper==wrapperIdentity;
    }
    Outcome apply(const QJsonObject &input, quint64 workerEpoch, quintptr wrapperIdentity) {
        const auto o=decodeAdmission(QJsonDocument(input).toJson(QJsonDocument::Compact));
        if(o.isEmpty() || !matches(o.value("requestId").toString(),o.value("generation").toString(),workerEpoch,wrapperIdentity)) return Outcome::Ignored;
        const auto outcome=o.value("outcome").toString();
        if(state==State::Dispatched || state==State::Uncertain || state==State::Rejected || state==State::Cancelled) return Outcome::Ignored;
        if(outcome=="DISPATCHED") { state=State::Dispatched; return Outcome::Dispatched; }
        if(outcome=="DISPATCH_UNCERTAIN") { state=State::Uncertain; return Outcome::Uncertain; }
        // A timeout retains the exact still-undispatched ledger; only Java's
        // authoritative no-dispatch outcome may subsequently permit rollback.
        if(outcome=="REJECTED") { state=State::Rejected; return Outcome::Rejected; }
        state=State::Cancelled; return Outcome::Cancelled;
    }
    Outcome timeout(const QString &id, const QString &generation, quint64 workerEpoch, quintptr wrapperIdentity) {
        if(!matches(id,generation,workerEpoch,wrapperIdentity) || state!=State::Unstarted) return Outcome::Ignored;
        state=State::TimedOut; return Outcome::Uncertain;
    }
    void clear() { admission={}; epoch=0; wrapper=0; state=State::Empty; }
    Grant grant() const { return admission; }
    quint64 workerEpoch() const { return epoch; }
    quintptr wrapperIdentity() const { return wrapper; }
private:
    enum class State { Empty, Unstarted, Dispatched, Uncertain, TimedOut, Rejected, Cancelled };
    Grant admission; quint64 epoch=0; quintptr wrapper=0; State state=State::Empty;
};
}
