#include "androidServiceDiscovery.h"
#include <QCoreApplication>
#include <QDebug>
#include <QFile>
#include <QCryptographicHash>
#include <cstdlib>
#include <thread>
#include "actual_classifier.inc"
using namespace AndroidServiceDiscovery;
static int checks=0;
static void check(bool b,const char *message) { ++checks; if(!b) { qCritical()<<message; std::exit(1); } }
static const QString id="11111111-1111-1111-1111-111111111111", start="22222222-2222-2222-2222-222222222222";
static QJsonObject discovery(QString generation,QString phase="EMPTY",QString component="NONE",QString request=id,QString reason="NONE") {
    return {{"schema",1},{"requestId",request},{"generation",generation},{"phase",phase},{"component",component},{"reason",reason}};
}
static QJsonObject admission(QString outcome,QString reason="NONE") {
    return {{"schema",1},{"requestId",start},{"generation","2"},{"outcome",outcome},{"reason",reason}};
}
static QByteArray bytes(QJsonObject o) { return QJsonDocument(o).toJson(QJsonDocument::Compact); }
int main(int argc,char **argv) {
    QCoreApplication app(argc,argv);
    if(app.arguments().size()!=1) {
        check(app.arguments().size()==4 && app.arguments()[1]=="--corpus","usage: --corpus discovery.jsonl admission.jsonl");
        for(int kind=0;kind<2;++kind) {
            QFile file(app.arguments()[kind+2]); check(file.open(QIODevice::ReadOnly),"corpusopen");
            QCryptographicHash hash(QCryptographicHash::Sha256); int rows=0;
            while(!file.atEnd()) {
                const auto line=file.readLine(maximumWireBytes+2); hash.addData(line);
                auto payload=line; if(payload.endsWith('\n')) payload.chop(1); if(payload.endsWith('\r')) payload.chop(1);
                check(!payload.isEmpty() && payload.size()<=maximumWireBytes,"corpusrowbound");
                const auto parsed=kind==0 ? decodeDiscovery(payload) : decodeAdmission(payload);
                check(!parsed.isEmpty() && parsed.size()==(kind==0 ? 6 : 5),"actualKotlinserializerinterop");
                ++rows;
            }
            check(rows==(kind==0 ? 8 : 6),"corpusrowcount");
            qInfo().noquote()<< (kind==0 ? "discovery" : "admission")<<"rows"<<rows<<"sha256"<<hash.result().toHex();
        }
        qInfo()<<"PASS"<<checks<<"actual Kotlin serializer corpus checks"; return 0;
    }
    check(!decodeDiscovery(bytes(discovery("1"))).isEmpty(),"discovery valid");
    check(!decodeAdmission(bytes(admission("DISPATCHED"))).isEmpty(),"admission valid");
    auto raw=bytes(discovery("1")); raw.insert(1,"\"schema\":1,");
    check(decodeDiscovery(raw).isEmpty(),"duplicate schema");
    raw=bytes(discovery("1")); raw.insert(1,"\"\\u0073chema\":1,");
    check(decodeDiscovery(raw).isEmpty(),"escaped duplicate alias");
    auto o=discovery("1"); o["unknown"]="x"; check(decodeDiscovery(bytes(o)).isEmpty(),"unknown key");
    for(const auto &g: {QString("0"),QString("01"),QString("-1"),QString("9223372036854775808")})
        check(decodeDiscovery(bytes(discovery(g))).isEmpty(),"invalid generation");
    o=discovery("1"); o["generation"]=1; check(decodeDiscovery(bytes(o)).isEmpty(),"generation numeric");
    check(decodeDiscovery(bytes(discovery("1","EMPTY","AWG"))).isEmpty(),"phase/component mismatch");
    check(decodeDiscovery(bytes(discovery("1","UNCERTAIN","AWG",id,"DIED"))).isEmpty(),"uncertaincomponent");
    check(decodeDiscovery(bytes(discovery("1","PENDING","NONE",{},"DIED"))).isEmpty(),"pendingreason");
    check(decodeDiscovery(bytes(discovery("1","EMPTY","NONE",{}))).isEmpty(),"unsolicited terminal");
    check(!decodeDiscovery(bytes(discovery("1","PENDING","NONE",{}))).isEmpty(),"unsolicited pending");
    raw=bytes(discovery("1")); raw.append(QByteArray(2048-raw.size(),' '));
    check(!decodeDiscovery(raw).isEmpty(),"exactwireboundary");
    raw.append(' '); check(decodeDiscovery(raw).isEmpty(),"wireboundaryplusone");
    check(decodeDiscovery(QByteArray(2049,' ')).isEmpty(),"bound");
    check(decodeDiscovery(QByteArray("{\"schema\":1,\"requestId\":\"\xff\"}")).isEmpty(),"badutf8");
    raw=bytes(discovery("1")); raw.replace("EMPTY","\\ud800"); check(decodeDiscovery(raw).isEmpty(),"unpairedsurrogate");
    check(decodeAdmission(bytes(admission("DISPATCHED","START_EXCEPTION"))).isEmpty(),"dispatchedreason");
    check(decodeAdmission(bytes(admission("REJECTED","PERMISSION_DENIED"))).isEmpty(),"rejectedreason");
    for(const auto &entry: {qMakePair(QString("awg"),QString("AWG")),
        qMakePair(QString("wireguard"),QString("AWG")),qMakePair(QString("openvpn"),QString("OPENVPN")),
        qMakePair(QString("xray"),QString("XRAY")),qMakePair(QString("ssxray"),QString("XRAY"))}) {
        check(androidDiscoveryComponent({{"protocol",entry.first}})==entry.second,"actualclassifierlowercase");
        check(androidDiscoveryComponent({{"protocol",entry.first.toUpper()}})==entry.second,"actualclassifieruppercase");
    }
    check(androidDiscoveryComponent({{"protocol","unknown"}}).isEmpty(),"actualclassifierunknown");
    check(androidDiscoveryComponent({}).isEmpty(),"actualclassifiermissing");
    check(androidDiscoveryComponent({{"protocol",1}}).isEmpty(),"actualclassifierwrongtype");
    Coordinator c;
    check(!c.allowsFresh(),"defaultfloor");
    check(!c.takeGrant(start,"AWG").valid(),"defaultnogrant");
    check(c.registerRefresh(id),"register");
    check(!c.ingest(discovery("1")),"beforeack");
    check(c.acknowledge(id),"ack");
    check(c.ingest(discovery("2","PENDING")),"solicitedpending");
    check(c.ingest(discovery("2")),"samegenerationterminal");
    check(!c.ingest(discovery("2","PENDING","NONE",{})),"duplicatelifecycleidempotent");
    check(!c.canReconnect("")&&!c.canReconnect("UNKNOWN"),"unknownreconnectmustnotteardown");
    auto grant=c.takeGrant(start,"AWG"); check(grant.valid(),"emptygrant");
    check(!c.takeGrant(start,"AWG").valid(),"oneshotgrant");
    check(c.authorizeStart(grant),"finaladmission"); check(!c.authorizeStart(grant),"onedispatch");
    check(!c.ingest(discovery("2")),"duplicateterminal");
    check(c.ingest(discovery("3","PENDING","NONE",{})),"newlifecycle");
    check(!c.validatesGrant(grant),"lifecycleinvalidatesreserved");
    check(!c.ingest(discovery("4")),"oldrequestinvalidated");
    check(c.registerRefresh(id) && c.acknowledge(id),"refresh");
    check(!c.ingest(discovery("3")),"strictbaseline");
    check(c.ingest(discovery("4","IDLE_NATIVE","AWG")),"idle");
    check(!c.takeGrant(start,"OPENVPN").valid(),"idlesameservice");
    check(c.takeGrant(start,"AWG").valid(),"idlefresh");
    check(c.registerRefresh(id)&&c.acknowledge(id)&&c.ingest(discovery("5","BOUND_NATIVE","AWG")),"boundnative");
    check(c.canReconnect("AWG")&&!c.canReconnect("OPENVPN"),"reconnectmatching");
    check(!c.takeGrant(start,"AWG").valid(),"boundnativeneverfresh");
    check(c.registerRefresh(id)&&c.acknowledge(id)&&c.ingest(discovery("6","BOUND_LEGACY","XRAY")),"legacy");
    check(!c.takeGrant(start,"OPENVPN").valid()&&c.takeGrant(start,"XRAY").valid(),"legacysamecomponent");
    Ledger l; grant={start,"2","AWG",1};
    check(l.registerStart(grant,7,99),"ledgerregister");
    check(l.apply(admission("REJECTED","STALE"),8,99)==Outcome::Ignored,"oldworker");
    check(l.apply(admission("REJECTED","STALE"),7,100)==Outcome::Ignored,"replacementwrapper");
    check(l.timeout(start,"2",7,99)==Outcome::Uncertain,"timeoutuncertain");
    check(l.apply(admission("REJECTED","STALE"),7,99)==Outcome::Rejected,"lateauthoritativerejection");
    check(l.apply(admission("REJECTED","STALE"),7,99)==Outcome::Ignored,"duplicates");
    check(l.registerStart(grant,8,100),"newstart");
    check(l.apply(admission("DISPATCHED"),8,100)==Outcome::Dispatched,"dispatch");
    check(l.apply(admission("REJECTED","STALE"),8,100)==Outcome::Ignored,"dispatchcannotrollback");
    check(l.registerStart(grant,9,101),"newuncertainstart");
    check(l.apply(admission("DISPATCH_UNCERTAIN","START_EXCEPTION"),9,101)==Outcome::Uncertain,"explicituncertain");
    check(l.apply(admission("REJECTED","STALE"),9,101)==Outcome::Ignored,"explicituncertaincannotrollback");
    for(int n=10;n<12;++n) {
        check(c.registerRefresh(id)&&c.acknowledge(id)&&c.ingest(discovery(QString::number(n))),"repeatrefresh");
        const auto next=c.takeGrant(start,"AWG"); check(next.valid()&&c.authorizeStart(next),"repeatadmission");
        c.invalidate(); check(!c.allowsFresh(),"disconnectclosesfloor");
    }
    check(c.registerRefresh(id)&&c.acknowledge(id)&&c.ingest(discovery("20")),"concurrentprepare");
    grant=c.takeGrant(start,"AWG");
    std::thread invalidator([&] { c.ingest(discovery("21","PENDING","NONE",{})); });
    invalidator.join();
    check(!c.authorizeStart(grant),"ingressfloorbeforeworkerdispatch");
    check(!c.registeredRequest(id) && !c.currentRequest(id),"lifecycleinvalidatesack");
    check(c.registerRefresh(id)&&c.registeredRequest(id)&&!c.currentRequest(id),"preackregistration");
    c.invalidate(); check(!c.acknowledge(id),"lateackrejected");
    check(l.registerStart({start,"2","AWG",1},22,222),"cancelprepare");
    check(l.apply(admission("CANCELLED","PERMISSION_DENIED"),22,222)==Outcome::Cancelled,"permissioncancel");
    check(l.timeout(start,"2",22,222)==Outcome::Ignored,"cancelnottimeout");
    check(l.registerStart({start,"2","AWG",1},23,223),"uncertainlateprepare");
    check(l.timeout(start,"2",23,223)==Outcome::Uncertain,"latetimeout");
    check(l.apply(admission("DISPATCHED"),23,223)==Outcome::Dispatched,"lateauthoritativedispatch");
    check(l.apply(admission("CANCELLED","LIFECYCLE_CANCELLED"),23,223)==Outcome::Ignored,"latecancelcannotretiredispatched");
    qInfo()<<"PASS"<<checks<<"discovery/admission checks";
}
