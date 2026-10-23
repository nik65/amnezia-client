#include "worker_fixture.h"
#include "core/utils/migrationTeardownContext.h"
#include <QCoreApplication>
#include <QDebug>
#include <QFile>
#include <QEventLoop>

static int failures=0, checks=0;
static void check(bool value,const char *label) { ++checks; if(!value){++failures;qCritical()<<label;} }
static const QString id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
static QJsonObject snapshot() {
    return {{"schema",1},{"requestId",id},{"bindingGeneration","7"},{"state","CONNECTED"},
        {"serverId","stable-server"},{"protocol","AWG"},{"serviceInstanceId",id},
        {"serviceActivationId","bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"},
        {"connectionNonce","cccccccc-cccc-cccc-cccc-cccccccccccc"},
        {"peerPublicKey",QString::fromLatin1(QByteArray(32,'x').toBase64())},
        {"deviceIpv4Address","10.8.0.2"},{"nativeGeneration","19"}};
}
static QByteArray wire(const QJsonObject &o) { return QJsonDocument(o).toJson(QJsonDocument::Compact); }
static QJsonObject config() {
    return {{"protocol","awg"},{"awg_config_data",QJsonObject{{"server_pub_key",snapshot().value("peerPublicKey")},{"client_ip","10.8.0.2/32, fd00::1/128"}}}};
}
static void decoder() {
    const auto good=snapshot(); check(NativeSessionRestore::decode(wire(good))==good,"strict valid snapshot");
    for (const auto &key:good.keys()) {
        auto bad=good;bad.remove(key);check(NativeSessionRestore::decode(wire(bad)).isEmpty(),"missing key rejected");
        bad=good;bad[key]=QJsonArray{};check(NativeSessionRestore::decode(wire(bad)).isEmpty(),"wrong type rejected");
    }
    auto bad=good;bad["extra"]=1;check(NativeSessionRestore::decode(wire(bad)).isEmpty(),"unknown key");
    bad=good;bad["serverId"]=QString(QChar::Null);check(NativeSessionRestore::decode(wire(bad)).isEmpty(),"escaped NUL string");
    bad=good;bad["serverId"]=QString(QChar(0xd800));check(NativeSessionRestore::decode(wire(bad)).isEmpty(),"unpaired surrogate");
    bad=good;bad["serverId"]=QString(128,QChar(0x044f));check(!NativeSessionRestore::decode(wire(bad)).isEmpty(),"256byte Unicode stable ID");
    bad["serverId"]=QString(129,QChar(0x044f));check(NativeSessionRestore::decode(wire(bad)).isEmpty(),"stable ID limit is UTF8bytes");
    bad=good;bad["serverId"]="id\ncontrol";check(NativeSessionRestore::decode(wire(bad)).isEmpty(),"stable ID controls rejected");
    const auto valid=wire(good);
    check(NativeSessionRestore::decode("{\"schema\":1,"+valid.mid(1)).isEmpty(),"duplicate schema");
    check(NativeSessionRestore::decode("{\"sch\\u0065ma\":1,"+valid.mid(1)).isEmpty(),"escaped duplicate key");
    check(NativeSessionRestore::decode(valid+"garbage").isEmpty(),"trailing bytes");
    check(NativeSessionRestore::decode(valid+QByteArray(8192,' ')).isEmpty(),"byte limit");
    auto invalidUtf=valid; invalidUtf[5]=char(0xff);check(NativeSessionRestore::decode(invalidUtf).isEmpty(),"invalid UTF8");
    for (const auto &key:QStringList{"bindingGeneration","nativeGeneration"})
        for (const auto &value:QStringList{"0","01","-1","9223372036854775808"," 1"}) {
            bad=good;bad[key]=value;check(NativeSessionRestore::decode(wire(bad)).isEmpty(),"noncanonical generation");
        }
    for (const auto &value:QStringList{"10.08.0.2","256.0.0.1","10.8.0.2/32","127.1"}) {
        bad=good;bad["deviceIpv4Address"]=value;check(NativeSessionRestore::decode(wire(bad)).isEmpty(),"invalid snapshot address");
    }
    check(NativeSessionRestore::matchesConfiguration(good,"stable-server",config()),"prepared identity matches");
    check(!NativeSessionRestore::matchesConfiguration(good,"changed-id",config()),"exact stable ID");
    auto changed=config();auto nested=changed["awg_config_data"].toObject();nested["client_ip"]="10.8.0.3";changed["awg_config_data"]=nested;
    check(!NativeSessionRestore::matchesConfiguration(good,"stable-server",changed),"changed prepared config");
}
static void worker() {
    VpnConnection w;const auto s=snapshot();
    w.adoptNativeRestore(s,"stable-server",0,DockerContainer::Awg,config());check(w.adopted.isEmpty(),"request before ACK has no authority");
    w.registerNativeRestore(id,"7");check(w.events==QStringList{"ack"},"registration ACK first");
    auto wrong=s;wrong["bindingGeneration"]="8";w.adoptNativeRestore(wrong,"stable-server",0,DockerContainer::Awg,config());check(w.adopted.isEmpty(),"wrong binding");
    ++w.m_connectionEpoch;w.adoptNativeRestore(s,"stable-server",0,DockerContainer::Awg,config());check(w.adopted.isEmpty(),"changed worker epoch");
    w.registerNativeRestore(id,"7");w.observeUnboundNativeSession(NativeSessionRestore::ingress.observe());
    w.adoptNativeRestore(s,"stable-server",0,DockerContainer::Awg,config());
    check(w.events.mid(w.events.size()-3)==QStringList{"wrapper","accepted","UI"},"UI seam follows worker accepted callback");
    check(w.adopted["restoredNativeSession"].toObject()==NativeSessionRestore::boundIdentity(s),"bound stop identity carried");
    check(w.adopted["migrationConnectionNonce"]==s["connectionNonce"],"actual native nonce adopted");
    const auto size=w.events.size();w.adoptNativeRestore(s,"stable-server",0,DockerContainer::Awg,config());check(w.events.size()==size,"one-shot consumption");
    w.registerNativeRestore(id,"7");w.invalidateNativeRestore();w.adopted={};w.adoptNativeRestore(s,"stable-server",0,DockerContainer::Awg,config());check(w.adopted.isEmpty(),"close/shutdown invalidation seam");
    VpnConnection emptyService,legacyNative;
    emptyService.observeEmptyNativeServiceState(Vpn::ConnectionState::Disconnected);
    check(emptyService.events==QStringList{"UI"} && emptyService.adopted.isEmpty(),"empty initial service can display disconnected without adoption");
    emptyService.registerNativeRestore(id,"7");legacyNative.registerNativeRestore(id,"7");legacyNative.observeUnboundNativeSession(NativeSessionRestore::ingress.observe());
    const auto before=legacyNative.events.size();legacyNative.observeEmptyNativeServiceState(Vpn::ConnectionState::Disconnected);
    check(legacyNative.events.size()==before && legacyNative.m_unboundNativeSessionObserved,"generic disconnected never clears native gate");
    QEventLoop loop;QTimer::singleShot(5600,Qt::PreciseTimer,&loop,&QEventLoop::quit);loop.exec();
    check(emptyService.m_nativeRestoreProbe.isEmpty() && emptyService.m_pendingNativeRestore.requestId.isEmpty(),"empty service challenge resolves boundedly");
    check(!emptyService.m_unboundNativeSessionObserved && !emptyService.events.contains("704"),"blank service never latches legacy native gate");
    check(legacyNative.m_unboundNativeSessionObserved && legacyNative.events.contains("704"),"unbound connected native remains fail closed after timeout");
}
static void ingress() {
    NativeSessionRestore::Ingress local;
    check(!local.observed(),"no invented initial observation");
    const auto early=local.observe();check(local.observed(early),"observation cached before core ready");
    local.invalidate();check(!local.observed(early),"stale queued observation rejected after lifecycle");
    const auto current=local.observe();check(local.observed(current)&&current!=early,"fresh observation survives fresh lifecycle");
    VpnConnection w;
    const auto old=NativeSessionRestore::ingress.observe();NativeSessionRestore::ingress.invalidate();
    w.observeUnboundNativeSession(old);check(!w.m_unboundNativeSessionObserved,"actual worker rejects old observation ticket");
    const auto ticket=NativeSessionRestore::ingress.observe();w.observeUnboundNativeSession(ticket);
    check(w.m_unboundNativeSessionObserved,"actual worker gates current native observation without index");
    VpnConnection active;active.m_vpnProtocol=QSharedPointer<QObject>::create();
    active.observeUnboundNativeSession(ticket);check(!active.m_unboundNativeSessionObserved,"late generic observation cannot override accepted wrapper");
    NativeSessionRestore::ingress.invalidate();
    VpnConnection receivedButQueued;
    NativeSessionRestore::ingress.observe();
    check(receivedButQueued.rejectNativeRestoreConnect() && receivedButQueued.m_unboundNativeSessionObserved,"actual fresh guard sees JNI observation before queued worker delivery");
    NativeSessionRestore::ingress.invalidate();
    VpnConnection neverObserved;
    check(!neverObserved.rejectNativeRestoreConnect(),"blank first service without observation remains connectable");
    auto controller=AndroidController::instance();
    controller->restoreEvents.clear();controller->m_restoreServiceGeneration="7";
    NativeSessionRestore::ingress.observe(); // JNI arrived before core routes.
    controller->flushRestoreServiceReady();controller->flushRestoreServiceReady();
    check(controller->restoreEvents.isEmpty(),"actual cache flush dispatch is queued until routes installed");
    QCoreApplication::processEvents();
    check(controller->restoreEvents==QStringList{"observation","ready"},"actual duplicate flush gates before READY exactly once");
    controller->restoreEvents.clear();controller->m_restoreServiceGeneration="8";
    controller->flushRestoreServiceReady();NativeSessionRestore::ingress.invalidate();
    QCoreApplication::processEvents();check(controller->restoreEvents.isEmpty(),"actual queued flush cannot cross fresh lifecycle");
    NativeSessionRestore::ingress.observe();controller->flushRestoreServiceReady();QCoreApplication::processEvents();
    check(controller->restoreEvents==QStringList{"observation","ready"},"current observation not lost after stale flush discarded");
    NativeSessionRestore::ingress.invalidate();
}
static void refusalUi() {
    for (const auto retained:{Vpn::ConnectionState::Connected,Vpn::ConnectionState::Disconnecting,Vpn::ConnectionState::Unknown}) {
        NativeSessionRestore::ingress.invalidate();
        VpnConnection worker;ConnectionController controller;ConnectionUiController ui;
        worker.m_connectionState=retained;
        if(retained==Vpn::ConnectionState::Connected){worker.m_vpnProtocol=QSharedPointer<QObject>::create();worker.m_restoredNativeIdentity=NativeSessionRestore::boundIdentity(snapshot());}
        else worker.m_nativeRestoreProbe=id;
        const auto owner=worker.m_vpnProtocol;const auto epoch=worker.m_connectionEpoch;
        ui.onConnectionStateChanged(Vpn::ConnectionState::Preparing);
        check(ui.m_isConnectionInProgress,"actual UI enters Preparing before refused open");
        controller.uiSink=[&](Vpn::ConnectionState state){ui.lastError=controller.m_cachedLastConnectionError;ui.onConnectionStateChanged(state);};
        worker.refusalSink=[&](Vpn::ConnectionState state){QMetaObject::invokeMethod(&controller,[&,state](){controller.handleNativeRestoreConnectRefused(state);},Qt::QueuedConnection);};
        check(worker.rejectNativeRestoreConnect(),"actual guarded connect refused");
        QCoreApplication::processEvents();
        check(controller.m_cachedLastConnectionError==ErrorCode::NativeTunnelCleanupUnconfirmed,"actual cache retains704");
        check(ui.m_state==retained && ui.m_state!=Vpn::ConnectionState::Preparing,"actual cache/UI reverts to retained owner state");
        check(ui.m_isConnectionInProgress==(retained==Vpn::ConnectionState::Disconnecting),"no stuck preparing; real Disconnecting remains pending");
        check(worker.m_vpnProtocol==owner && worker.m_connectionEpoch==epoch && !worker.events.contains("UI"),"refusal does not transition worker/native or route cleanup");
    }
    NativeSessionRestore::ingress.invalidate();
}
static void teardown() {
    const auto expected=NativeSessionRestore::boundIdentity(snapshot());
    bool completed=false,confirmed=false; quint64 epoch=14;
    auto *context=new MigrationTeardownContext(QSharedPointer<QObject>::create(),expected["connectionNonce"].toString(),12,14,true,
        [&](){return epoch;},[&](bool okay){completed=true;confirmed=okay;},nullptr);
    context->requireRestoredIdentity(expected);
    context->observe(expected["connectionNonce"].toString(),12,true);check(!completed,"strict rejects generic receipt");
    auto receipt=expected;receipt["nativeCleanupConfirmed"]=true;receipt["serviceActivationId"]=id;
    context->observeAndroid(receipt,12);check(!completed,"replaced activation cannot retire owner");
    receipt=expected;receipt["nativeCleanupConfirmed"]=true;context->observeAndroid(receipt,12);check(completed&&confirmed,"exact identity+nonce+epoch+routes receipt");
    bool invalidCompleted=false,invalidConfirmed=true;
    auto *invalid=new MigrationTeardownContext(QSharedPointer<QObject>::create(),"nonce",12,14,true,[&](){return epoch;},[&](bool okay){invalidCompleted=true;invalidConfirmed=okay;},nullptr);
    invalid->requireRestoredIdentity({});invalid->observe("nonce",12,true);check(!invalidCompleted,"invalid strict expected identity never downgrades");invalid->expire();check(invalidCompleted&&!invalidConfirmed,"invalid bound session expires unconfirmed");
    bool freshConfirmed=false;
    auto *fresh=new MigrationTeardownContext(QSharedPointer<QObject>::create(),"fresh",12,14,true,[&](){return epoch;},[&](bool okay){freshConfirmed=okay;},nullptr);
    fresh->observe("fresh",12,true);check(freshConfirmed,"fresh desktop/generic receipt mode preserved");
    bool missingRoutesConfirmed=true;
    auto *routes=new MigrationTeardownContext(QSharedPointer<QObject>::create(),expected["connectionNonce"].toString(),12,14,false,[&](){return epoch;},[&](bool okay){missingRoutesConfirmed=okay;},nullptr);
    routes->requireRestoredIdentity(expected);routes->observeAndroid(receipt,12);check(!missingRoutesConfirmed,"native binding never substitutes for route receipt");
    QCoreApplication::sendPostedEvents(nullptr,QEvent::DeferredDelete);
}
static void boundStop() {
    AndroidVpnProtocol protocol;
    auto controller=AndroidController::instance();
    protocol.m_rawConfig["restoredNativeSession"]=NativeSessionRestore::boundIdentity(snapshot());
    protocol.stop();check(controller->genericStops==0 && controller->boundStops==1,"actual protocol restored stop selects conditional API");
    check(controller->lastIdentity==NativeSessionRestore::boundIdentity(snapshot()),"actual stop carries exact expected identity");
    protocol.m_rawConfig["restoredNativeSession"]=QJsonObject{};
    protocol.stop();check(controller->genericStops==0 && controller->boundStops==2,"malformed bound identity never downgrades to generic stop");
    protocol.m_rawConfig.remove("restoredNativeSession");protocol.stop();
    check(controller->genericStops==1,"fresh generic stop behavior preserved");
}
int main(int argc,char **argv) {
    QCoreApplication app(argc,argv);decoder();worker();teardown();boundStop();ingress();refusalUi();
    if(argc==2) { QFile file(QString::fromLocal8Bit(argv[1]));check(file.open(QIODevice::ReadOnly),"shared Kotlin corpus readable");
        int rows=0;
        while (!file.atEnd()) {
            const auto line=file.readLine().trimmed(); if (line.isEmpty()) continue;
            ++rows;check(!NativeSessionRestore::decode(line).isEmpty(),"actual Kotlin serialized corpus decoded");
        }
        check(rows>=2,"ordinary and escaped Unicode Kotlin vectors consumed"); }
    qInfo()<<checks<<"checks; failures"<<failures;return failures?1:0;
}
