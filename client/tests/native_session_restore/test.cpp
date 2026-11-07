#include "worker_fixture.h"
#include "core/utils/migrationTeardownContext.h"
#include <QCoreApplication>
#include <QDebug>
#include <QFile>
#include <QEventLoop>
#include <cstdio>

static int failures=0, checks=0;
static void check(bool value,const char *label) { ++checks; if(!value){++failures;fprintf(stderr,"FAIL: %s\n",label);} }
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
static QJsonObject dnsEnrollment() {
    return {{"enabled",true},{"domain","d27.example.com"},{"publicKey",QString(64,QLatin1Char('a'))},
        {"vlessId","12345678-1234-4321-abcd-123456789abc"}};
}
static QJsonObject dnsConfig() {
    auto value=config();value["dnsFallback"]=dnsEnrollment();
    value["migrationActivationToken"]="old-primary-trial";value["migrationTrial"]=true;
    return value;
}
static QJsonObject dnsSnapshot() {
    auto value=snapshot();value["schema"]=2;value.remove("peerPublicKey");value.remove("deviceIpv4Address");
    value["effectiveTransport"]="dns";
    value["dnsProfileDigest"]="4b2c5fbf6587d94ad85f8ab4ab71092854d1f7dcfa2526a2cff415e95254e24b";
    return value;
}
static void dnsDecoder() {
    const auto good=dnsSnapshot();
    check(amnezia::dnsFallbackConfig::profileDigest(dnsEnrollment())==good.value("dnsProfileDigest"),"cross-language canonical enrollment digest");
    check(NativeSessionRestore::decode(wire(good))==good,"exact DNS schema2 accepted");
    auto reconnecting=good;reconnecting["state"]="RECONNECTING";
    check(NativeSessionRestore::decode(wire(reconnecting))==reconnecting,"owned unhealthy DNS can restore truthful reconnecting control");
    auto legacyReconnect=snapshot();legacyReconnect["state"]="RECONNECTING";
    check(NativeSessionRestore::decode(wire(legacyReconnect)).isEmpty(),"legacy AWG schema never inherits DNS reconnect authority");
    for(const auto &key:good.keys()) {
        auto bad=good;bad.remove(key);check(NativeSessionRestore::decode(wire(bad)).isEmpty(),"DNS missing field rejected");
        bad=good;bad[key]=QJsonArray{};check(NativeSessionRestore::decode(wire(bad)).isEmpty(),"DNS wrong scalar type rejected");
    }
    auto bad=good;bad["schema"]=1;check(NativeSessionRestore::decode(wire(bad)).isEmpty(),"DNS cannot pose as AWG schema1");
    bad=good;bad["schema"]=3;check(NativeSessionRestore::decode(wire(bad)).isEmpty(),"unknown schema rejected");
    bad=good;bad["peerPublicKey"]=snapshot().value("peerPublicKey");check(NativeSessionRestore::decode(wire(bad)).isEmpty(),"DNS peer identity forbidden");
    bad=good;bad["deviceIpv4Address"]="10.8.0.2";check(NativeSessionRestore::decode(wire(bad)).isEmpty(),"DNS AWG address identity forbidden");
    bad=good;bad["effectiveTransport"]="awg";check(NativeSessionRestore::decode(wire(bad)).isEmpty(),"DNS transport cannot be coerced");
    bad=good;bad["dnsProfileDigest"]=QString(64,QLatin1Char('G'));check(NativeSessionRestore::decode(wire(bad)).isEmpty(),"DNS invalid digest alphabet");
    bad=good;bad["dnsProfileDigest"]=QString(63,QLatin1Char('a'));check(NativeSessionRestore::decode(wire(bad)).isEmpty(),"DNS invalid digest length");
    const auto valid=wire(good);
    check(NativeSessionRestore::decode("{\"schema\":2,"+valid.mid(1)).isEmpty(),"DNS duplicate schema");
    check(NativeSessionRestore::decode("{\"effectiveTransport\":\"dns\","+valid.mid(1)).isEmpty(),"DNS duplicate transport");
    check(NativeSessionRestore::decode(valid+"garbage").isEmpty(),"DNS trailing bytes");
    check(NativeSessionRestore::matchesConfiguration(good,"stable-server",dnsConfig()),"DNS owner matches enrolled transport");
    check(!NativeSessionRestore::matchesConfiguration(good,"other-server",dnsConfig()),"DNS exact logical server required");
    check(!NativeSessionRestore::matchesConfiguration(good,"stable-server",config()),"DNS missing enrollment rejected");
    for(const auto &key:QStringList{"domain","publicKey","vlessId","enabled"}) {
        auto changed=dnsConfig();auto enrolled=changed.value("dnsFallback").toObject();
        if(key=="enabled")enrolled[key]=false;
        else if(key=="domain")enrolled[key]="another.example.com";
        else if(key=="publicKey")enrolled[key]=QString(64,QLatin1Char('b'));
        else enrolled[key]="abcdef12-1234-4321-abcd-123456789abc";
        changed["dnsFallback"]=enrolled;
        check(!NativeSessionRestore::matchesConfiguration(good,"stable-server",changed),"DNS changed enrollment rejected");
    }
    auto changed=dnsConfig();auto protocol=changed.value("awg_config_data").toObject();
    protocol["server_pub_key"]="not-a-native-DNS-identity";protocol["client_ip"]="not-a-native-DNS-address";changed["awg_config_data"]=protocol;
    check(NativeSessionRestore::matchesConfiguration(good,"stable-server",changed),"DNS restore never guesses a cached AWG peer/address");
    auto adopted=NativeSessionRestore::configurationForAdoption(good,dnsConfig());
    check(NativeSessionRestore::isDnsConfiguration(adopted)&&adopted.value("dnsProfileDigest")==good.value("dnsProfileDigest"),"DNS effective context marked");
    check(!adopted.contains("migrationActivationToken")&&!adopted.contains("migrationTrial"),"DNS context cannot activate AWG migration trial");
    check(adopted.value("protocol")=="awg"&&adopted.value("dnsFallback")==dnsConfig().value("dnsFallback"),"logical owner and enrollment preserved");
    adopted=NativeSessionRestore::configurationForAdoption(snapshot(),adopted);
    check(!adopted.contains("effectiveTransport")&&!adopted.contains("dnsProfileDigest"),"AWG adoption clears stale DNS effective markers");
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
    auto invalidUtf=valid; invalidUtf[5]=QByteArray::fromHex("ff").front();check(NativeSessionRestore::decode(invalidUtf).isEmpty(),"invalid UTF8");
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
static void dnsWorker() {
    NativeSessionRestore::ingress.invalidate();
    VpnConnection worker;const auto dns=dnsSnapshot();
    worker.registerNativeRestore(id,"7");
    worker.adoptNativeRestore(dns,"stable-server",0,DockerContainer::Awg,config());
    check(worker.adopted.isEmpty()&&!worker.m_pendingNativeRestore.requestId.isEmpty(),"DNS failed enrollment does not consume challenge");
    worker.adoptNativeRestore(dns,"stable-server",0,DockerContainer::Awg,dnsConfig());
    check(worker.events.mid(worker.events.size()-3)==QStringList{"dns","accepted","UI"}&&worker.events.contains("wrapper"),"DNS exact worker adoption precedes UI");
    check(worker.adopted.value("restoredNativeSession").toObject()==NativeSessionRestore::boundIdentity(dns),"DNS stop uses exact common native identity");
    check(worker.adopted.value("effectiveTransport")=="dns"&&!worker.adopted.contains("migrationActivationToken"),"actual worker stages DNS context without AWG trial");
    check(NativeSessionRestore::ingress.observed(),"DNS owner keeps stale migration callbacks fenced until stop");
    const auto before=worker.events.size();worker.adoptNativeRestore(dns,"stable-server",0,DockerContainer::Awg,dnsConfig());
    check(worker.events.size()==before,"DNS challenge is one-shot");
    VpnConnection stale;stale.registerNativeRestore(id,"7");++stale.m_connectionEpoch;
    stale.adoptNativeRestore(dns,"stable-server",0,DockerContainer::Awg,dnsConfig());
    check(stale.adopted.isEmpty(),"DNS stale worker epoch rejected");
    VpnConnection unhealthy;unhealthy.registerNativeRestore(id,"7");auto reconnecting=dns;reconnecting["state"]="RECONNECTING";
    unhealthy.adoptNativeRestore(reconnecting,"stable-server",0,DockerContainer::Awg,dnsConfig());
    check(unhealthy.m_connectionState==Vpn::ConnectionState::Reconnecting&&!unhealthy.adopted.isEmpty(),"fresh DNS adoption never calls unhealthy tunnel connected");
    NativeSessionRestore::ingress.invalidate();
}
static void setupLiveDns(VpnConnection &worker, const QSharedPointer<AndroidVpnProtocol> &protocol) {
    worker.m_vpnProtocol=protocol;worker.androidVpnProtocol=protocol.data();
    worker.m_serverId="stable-server";worker.m_container=DockerContainer::Awg;
    worker.m_connectionState=Vpn::ConnectionState::Connected;
    worker.m_vpnConfiguration=dnsConfig();
    worker.m_vpnConfiguration["nativeSessionServerId"]="stable-server";
    worker.m_vpnConfiguration["migrationConnectionNonce"]=dnsSnapshot().value("connectionNonce");
    worker.m_restoredNativeIdentity=NativeSessionRestore::boundIdentity(dnsSnapshot());
    worker.m_vpnConfiguration["restoredNativeSession"]=worker.m_restoredNativeIdentity;
    protocol->m_rawConfig=worker.m_vpnConfiguration;
}




static void orphanObservationRecovery() {
    static quint64 generation=5000;
    for(const auto &fault:QStringList{"none","epoch","server","new-observation","new-version","late-latch","consumed","active-owner","cleanup","uncertain"}) {
        AndroidServiceDiscovery::coordinator.invalidate();NativeSessionRestore::ingress.invalidate();
        VpnConnection worker;worker.m_serverId="stable-server";worker.m_connectionState=Vpn::ConnectionState::Disconnected;
        NativeSessionRestore::ingress.observe();worker.observeUnboundNativeSession(NativeSessionRestore::ingress.version());
        NativeSessionRestore::ingress.invalidate();
        if(fault=="late-latch")worker.m_unboundNativeSessionObserved=false;
        AndroidServiceDiscovery::coordinator.registerRefresh(id);worker.registerServiceDiscovery(id);
        QJsonObject proof{{"schema",1},{"requestId",id},{"generation",QString::number(++generation)},
            {"phase",fault=="uncertain"?"UNCERTAIN":"EMPTY"},{"component","NONE"},{"reason",fault=="uncertain"?"STATUS_UNPROVEN":"NONE"}};
        check(AndroidServiceDiscovery::coordinator.ingest(proof),"fresh orphan absence challenge");
        if(fault=="epoch")++worker.m_connectionEpoch;
        if(fault=="server")worker.m_serverId="different";
        if(fault=="new-observation")NativeSessionRestore::ingress.observe();
        if(fault=="new-version")NativeSessionRestore::ingress.invalidate();
        if(fault=="late-latch")worker.m_unboundNativeSessionObserved=true;
        if(fault=="consumed")AndroidServiceDiscovery::coordinator.takeGrant(id,"AWG");
        if(fault=="active-owner")worker.m_vpnProtocol=QSharedPointer<AndroidVpnProtocol>::create();
        if(fault=="cleanup")worker.m_migrationTeardownContext=&worker;
        const bool retired=worker.retireAbsentNativeReceiver(proof);
        check(retired==(fault=="none"),"only exact captured orphan plus fresh strong EMPTY can retire observation gate");
        if(retired)check(!worker.m_unboundNativeSessionObserved&&!worker.rejectNativeRestoreConnect(),"fresh orphan reconciliation permits next guarded manual start");
        else check(worker.m_unboundNativeSessionObserved,"wrong/new/live owner retains conservative orphan gate");
    }
    for(const auto &fault:QStringList{"none","epoch","server","live-owner","active-context","recovery"}) {
        VpnConnection worker;worker.m_serverId="stable-server";worker.m_unboundNativeSessionObserved=true;
        worker.m_nativeRestoreProbe=id;worker.m_restoredNativeIdentity=NativeSessionRestore::boundIdentity(snapshot());
        const auto epoch=worker.m_connectionEpoch;
        if(fault=="epoch")++worker.m_connectionEpoch;
        if(fault=="server")worker.m_serverId="different";
        if(fault=="live-owner")worker.m_vpnProtocol=QSharedPointer<AndroidVpnProtocol>::create();
        if(fault=="active-context")worker.m_migrationTeardownContext=&worker;
        if(fault=="recovery")worker.m_migrationTeardownRecoveryRequired=true;
        const bool cleared=worker.retireConfirmedNativeObservation("stable-server",epoch);
        check(cleared==(fault=="none"),"confirmed teardown clears only its exact current epoch without live owner");
        check(worker.m_unboundNativeSessionObserved!=(fault=="none"),"stale confirmed receipt cannot clear new observation gate");
    }
    AndroidServiceDiscovery::coordinator.invalidate();NativeSessionRestore::ingress.invalidate();
}

static void rapidIdleRestoreChallenge() {
    static quint64 generation=3000;
    for(const auto &fault:QStringList{"none","empty","epoch","receiver","server","consumed","unproven","native-observed","cleanup-held","active-owner","unsettled"}) {
        NativeSessionRestore::ingress.invalidate();AndroidServiceDiscovery::coordinator.invalidate();
        VpnConnection worker;worker.m_serverId="stable-server";worker.m_connectionState=Vpn::ConnectionState::Disconnected;
        AndroidServiceDiscovery::coordinator.registerRefresh(id);worker.registerServiceDiscovery(id);
        QJsonObject proof{{"schema",1},{"requestId",id},{"generation",QString::number(++generation)},
            {"phase",fault=="empty"?"EMPTY":"IDLE_NATIVE"},{"component",fault=="empty"?"NONE":"AWG"},{"reason","NONE"}};
        check(AndroidServiceDiscovery::coordinator.ingest(proof),"fresh idle observation before rapid reconnect");
        worker.registerNativeRestore(id,"7");
        check(!worker.m_nativeRestoreProbe.isEmpty(),"idle service observation-only restore challenge pending");
        if(fault=="epoch")++worker.m_connectionEpoch;
        if(fault=="receiver")worker.m_discoveryObservationReceiver=99;
        if(fault=="server")worker.m_serverId="changed";
        if(fault=="consumed")AndroidServiceDiscovery::coordinator.takeGrant(id,"AWG");
        if(fault=="unproven")AndroidServiceDiscovery::coordinator.invalidate();
        if(fault=="native-observed")NativeSessionRestore::ingress.observe();
        if(fault=="cleanup-held")worker.m_migrationTeardownRecoveryRequired=true;
        if(fault=="active-owner")worker.m_vpnProtocol=QSharedPointer<AndroidVpnProtocol>::create();
        if(fault=="unsettled"){auto grant=AndroidServiceDiscovery::coordinator.takeGrant(id,"AWG");worker.m_startAdmissionLedger.registerStart(grant,worker.m_connectionEpoch,99);}
        const bool refused=worker.rejectNativeRestoreConnect();
        check(refused!=(fault=="none"||fault=="empty"),"fresh exact idle proof supersedes stale restore challenge; foreign/live proof stays blocked");
        if(!refused)check(worker.m_nativeRestoreProbe.isEmpty()&&AndroidServiceDiscovery::coordinator.allowsFresh(),"idle guard does not consume final start grant or synthesize native state");
    }
    NativeSessionRestore::ingress.invalidate();AndroidServiceDiscovery::coordinator.invalidate();
}

static void absentNativeOwner() {
    static quint64 generation=1000;
    for(const auto &fault:QStringList{"none","terminal-recovery","recovery-server","recovery-epoch","recovery-pending","active-cleanup","expired-grace","epoch","receiver","consumed","different-request","held-cleanup","disconnecting","recent-dispatch","clock-rollback","unsettled-admission","stale-snapshot"}) {
        NativeSessionRestore::ingress.invalidate();AndroidServiceDiscovery::coordinator.invalidate();
        VpnConnection worker;auto protocol=QSharedPointer<AndroidVpnProtocol>::create();setupLiveDns(worker,protocol);
        worker.m_connectionState=Vpn::ConnectionState::Connecting;
        if(fault=="terminal-recovery"||fault=="recovery-server"||fault=="recovery-epoch"||fault=="recovery-pending"||fault=="active-cleanup"){worker.m_vpnProtocol.clear();worker.androidVpnProtocol=nullptr;worker.m_migrationTeardownRecoveryRequired=true;}
        if(fault=="active-cleanup")worker.m_migrationTeardownContext=&worker;
        check(AndroidServiceDiscovery::coordinator.registerRefresh(id),"register absence challenge");
        worker.registerServiceDiscovery(id);
        QJsonObject proof{{"schema",1},{"requestId",id},{"generation",QString::number(++generation)},{"phase","EMPTY"},{"component","NONE"},{"reason","NONE"}};
        check(AndroidServiceDiscovery::coordinator.ingest(proof),"ingest fresh native absence");
        if(fault=="epoch"||fault=="recovery-epoch")++worker.m_connectionEpoch;
        if(fault=="recovery-server")worker.m_serverId="changed-server";
        if(fault=="receiver"){auto replacement=QSharedPointer<AndroidVpnProtocol>::create();worker.m_vpnProtocol=replacement;worker.androidVpnProtocol=replacement.data();}
        if(fault=="consumed")AndroidServiceDiscovery::coordinator.takeGrant(id,"AWG");
        if(fault=="different-request")worker.m_discoveryRegisteredId="dddddddd-dddd-dddd-dddd-dddddddddddd";
        if(fault=="held-cleanup")worker.m_migrationTeardownRecoveryRequired=true;
        if(fault=="disconnecting")worker.m_connectionState=Vpn::ConnectionState::Disconnecting;
        if(fault=="recent-dispatch"){worker.m_nativeStartAdmissionAge.valid=true;worker.m_nativeStartAdmissionAge.age=9999;}
        if(fault=="clock-rollback"){worker.m_nativeStartAdmissionAge.valid=true;worker.m_nativeStartAdmissionAge.age=-1;}
        if(fault=="expired-grace"){worker.m_nativeStartAdmissionAge.valid=true;worker.m_nativeStartAdmissionAge.age=10000;}
        if(fault=="unsettled-admission"||fault=="recovery-pending"){auto grant=AndroidServiceDiscovery::coordinator.takeGrant(id,"AWG");worker.m_startAdmissionLedger.registerStart(grant,worker.m_connectionEpoch,quintptr(worker.m_vpnProtocol.data()));}
        if(fault=="stale-snapshot")AndroidServiceDiscovery::coordinator.invalidate();
        const auto epoch=worker.m_connectionEpoch;const auto owner=worker.m_vpnProtocol;
        NativeSessionRestore::ingress.observe();
        const auto stopped=AndroidController::instance()->genericStops+AndroidController::instance()->boundStops;
        const bool accepted=worker.retireAbsentNativeReceiver(proof);
        if(fault=="recent-dispatch") {
            QEventLoop wait;QTimer::singleShot(100,Qt::PreciseTimer,&wait,&QEventLoop::quit);wait.exec();
            check(worker.events.contains("discovery-refresh")&&worker.m_vpnProtocol==owner,"grace expiry requests new proof instead of reusing early absence");
        }
        if(fault=="none"||fault=="expired-grace"||fault=="terminal-recovery") {
            check(accepted&&worker.m_connectionState==Vpn::ConnectionState::Disconnected&&!worker.m_vpnProtocol&&worker.androidVpnProtocol==nullptr,"fresh native absence retires stale Connecting receiver");
            check(worker.m_connectionEpoch==epoch+1&&!NativeSessionRestore::ingress.observed()&&worker.m_restoredNativeIdentity.isEmpty(),"absence fences stale callbacks and clears dead restore owner");
            check(!worker.events.contains("dns")&&!worker.events.contains("wrapper")&&AndroidController::instance()->genericStops+AndroidController::instance()->boundStops==stopped,"absence never stops native service or fabricates owner receipt");
            check(!worker.retireAbsentNativeReceiver(proof),"absence retirement one shot");
        } else check(!accepted&&worker.m_vpnProtocol==owner&&worker.m_connectionEpoch==epoch&&NativeSessionRestore::ingress.observed(),"stale/unsettled absence cannot retire current owner");
    }
    NativeSessionRestore::ingress.invalidate();AndroidServiceDiscovery::coordinator.invalidate();
}

static void livePrimaryWorker() {
    for (const auto &fault : QStringList{"none","first-binding","nonce","activation","instance","peer","address","epoch","request","server","container","protocol","receiver-peer","disconnecting","dns-owner"}) {
        NativeSessionRestore::ingress.invalidate();
        VpnConnection worker; auto receiver=QSharedPointer<AndroidVpnProtocol>::create();
        worker.m_vpnProtocol=receiver;worker.androidVpnProtocol=receiver.data();
        worker.m_serverId="stable-server";worker.m_container=DockerContainer::Awg;
        worker.m_connectionState=Vpn::ConnectionState::Connecting;
        worker.m_vpnConfiguration=config();worker.m_vpnConfiguration["nativeSessionServerId"]="stable-server";
        worker.m_vpnConfiguration["migrationConnectionNonce"]=snapshot().value("connectionNonce");
        worker.m_restoredNativeIdentity=NativeSessionRestore::boundIdentity(snapshot());
        worker.m_vpnConfiguration["restoredNativeSession"]=worker.m_restoredNativeIdentity;
        if(fault=="first-binding"){worker.m_restoredNativeIdentity={};worker.m_vpnConfiguration.remove("restoredNativeSession");}
        receiver->m_rawConfig=worker.m_vpnConfiguration;
        worker.registerNativeRestore(id,"7"); auto proof=snapshot();
        if(fault=="nonce")proof["connectionNonce"]="dddddddd-dddd-dddd-dddd-dddddddddddd";
        if(fault=="activation")proof["serviceActivationId"]="dddddddd-dddd-dddd-dddd-dddddddddddd";
        if(fault=="instance")proof["serviceInstanceId"]="dddddddd-dddd-dddd-dddd-dddddddddddd";
        if(fault=="protocol")worker.m_vpnConfiguration["protocol"]="wireguard";
        if(fault=="receiver-peer"){auto nested=receiver->m_rawConfig["awg_config_data"].toObject();nested["server_pub_key"]=QString::fromLatin1(QByteArray(32,'y').toBase64());receiver->m_rawConfig["awg_config_data"]=nested;}
        if(fault=="peer")proof["peerPublicKey"]=QString::fromLatin1(QByteArray(32,'y').toBase64());
        if(fault=="address")proof["deviceIpv4Address"]="10.8.0.3";
        if(fault=="epoch"||fault=="recovery-epoch")++worker.m_connectionEpoch;
        if(fault=="recovery-server")worker.m_serverId="changed-server";
        if(fault=="request")proof["requestId"]="dddddddd-dddd-dddd-dddd-dddddddddddd";
        if(fault=="server")worker.m_serverId="different-server";
        if(fault=="container")worker.m_container=DockerContainer::WireGuard;
        if(fault=="disconnecting")worker.m_connectionState=Vpn::ConnectionState::Disconnecting;
        if(fault=="dns-owner"){worker.m_vpnConfiguration["effectiveTransport"]="dns";worker.m_vpnConfiguration["dnsProfileDigest"]=dnsSnapshot().value("dnsProfileDigest");}
        const auto raw=receiver->m_rawConfig;const auto epoch=worker.m_connectionEpoch;
        worker.adoptNativeRestore(proof,"stable-server",0,DockerContainer::Awg,config());
        if(fault=="none"||fault=="first-binding") {
            check(worker.m_connectionState==Vpn::ConnectionState::Connected,"live primary same owner repairs missed CONNECTED event");
            check(worker.m_vpnProtocol==receiver&&worker.m_connectionEpoch==epoch&&!worker.events.contains("wrapper")&&!worker.events.contains("dns"),"primary refresh creates no TUN epoch or DNS migration event");
            check(!NativeSessionRestore::ingress.observed(),"primary refresh never fabricates ingress observation");
            const auto count=worker.events.size();worker.adoptNativeRestore(proof,"stable-server",0,DockerContainer::Awg,config());
            check(worker.events.size()==count,"primary proof consumed once");
        } else check(worker.m_connectionState!=Vpn::ConnectionState::Connected&&receiver->m_rawConfig==raw,"foreign primary proof cannot refresh state or rewrite receiver");
    }
}

static void liveDnsWorker() {
    for(const auto &fault:QStringList{"nonce","activation","server","epoch","disconnecting","profile"}) {
        NativeSessionRestore::ingress.invalidate();
        VpnConnection worker;ConnectionController controller;
        auto protocol=QSharedPointer<AndroidVpnProtocol>::create();setupLiveDns(worker,protocol);
        controller.migration.deadline.start();const auto beforeGeneration=controller.m_awgMigrationReconnectGeneration;
        worker.dnsAdoptedSink=[&](const QString &server){controller.handleNativeDnsTransportAdopted(server);};
        worker.registerNativeRestore(id,"7");auto changed=dnsSnapshot();auto prepared=dnsConfig();
        if(fault=="nonce")changed["connectionNonce"]="dddddddd-dddd-dddd-dddd-dddddddddddd";
        if(fault=="activation")changed["serviceActivationId"]="dddddddd-dddd-dddd-dddd-dddddddddddd";
        if(fault=="server")worker.m_serverId="another-current-server";
        if(fault=="epoch"||fault=="recovery-epoch")++worker.m_connectionEpoch;
        if(fault=="recovery-server")worker.m_serverId="changed-server";
        if(fault=="disconnecting")worker.m_connectionState=Vpn::ConnectionState::Disconnecting;
        if(fault=="profile"){auto enrolled=prepared["dnsFallback"].toObject();enrolled["domain"]="another.example.com";prepared["dnsFallback"]=enrolled;}
        const auto raw=protocol->m_rawConfig;
        worker.adoptNativeRestore(changed,"stable-server",0,DockerContainer::Awg,prepared);
        check(!worker.events.contains("dns")&&controller.migration.cancellations==0&&controller.migration.deadline.isActive(),"wrong owner/epoch proof cannot cancel real trial intent");
        check(controller.m_awgMigrationReconnectGeneration==beforeGeneration&&protocol->m_rawConfig==raw,"rejected live DNS proof cannot rewrite owner state");
    }
    NativeSessionRestore::ingress.invalidate();
    VpnConnection worker;ConnectionController controller;auto protocol=QSharedPointer<AndroidVpnProtocol>::create();setupLiveDns(worker,protocol);
    controller.migration.deadline.start();worker.dnsAdoptedSink=[&](const QString &server){controller.handleNativeDnsTransportAdopted(server);};
    worker.registerNativeRestore(id,"7");const auto epoch=worker.m_connectionEpoch;const auto receiver=worker.m_vpnProtocol;
    auto reconnecting=dnsSnapshot();reconnecting["state"]="RECONNECTING";
    worker.adoptNativeRestore(reconnecting,"stable-server",0,DockerContainer::Awg,dnsConfig());
    check(worker.m_vpnProtocol==receiver&&worker.m_connectionEpoch==epoch&&!worker.events.contains("wrapper"),"live DNS binding creates no wrapper TUN or new epoch");
    check(worker.m_connectionState==Vpn::ConnectionState::Reconnecting&&NativeSessionRestore::isDnsConfiguration(worker.m_vpnConfiguration),"live unhealthy DNS preserves truthful state");
    check(controller.migration.cancellations==1&&!controller.migration.deadline.isActive()&&controller.m_awgMigrationReconnectGeneration==1,"only accepted matching DNS owner cancels stale migration deadline");
    check(NativeSessionRestore::ingress.observed(),"live bound DNS retains ingress fence");
    check(protocol->m_rawConfig.value("restoredNativeSession").toObject()==worker.m_restoredNativeIdentity,"live protocol stop becomes exact conditional owner stop");
    worker.registerNativeRestore(id,"8");auto healthy=dnsSnapshot();healthy["bindingGeneration"]="8";
    worker.adoptNativeRestore(healthy,"stable-server",0,DockerContainer::Awg,dnsConfig());
    check(worker.m_connectionState==Vpn::ConnectionState::Connected&&worker.m_vpnProtocol==receiver,"fresh exact healthy proof updates state without restart");
    const auto accepted=worker.events.size();worker.adoptNativeRestore(healthy,"stable-server",0,DockerContainer::Awg,dnsConfig());
    check(worker.events.size()==accepted,"live DNS proof is one-shot");
    ConnectionController foreign;foreign.migration.owner="another-server";foreign.migration.deadline.start();
    foreign.handleNativeDnsTransportAdopted("stable-server");
    check(foreign.migration.cancellations==0&&foreign.migration.deadline.isActive(),"accepted DNS owner cannot cancel another server trial");
    NativeSessionRestore::ingress.invalidate();
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

static void unknownUiErrorNotification() {
    ConnectionUiController ui;
    ui.lastError=ErrorCode::NoError;
    ui.onConnectionStateChanged(Vpn::ConnectionState::Unknown);
    check(ui.errorNotifications.isEmpty(),"unknown state without an error must not display ErrorCode0 modal");
    check(!ui.m_isConnected&&!ui.m_isConnectionInProgress&&ui.m_state==Vpn::ConnectionState::Unknown,"no-error UNKNOWN remains truthful disconnected from known healthy state");
    ui.lastError=ErrorCode::NativeTunnelCleanupUnconfirmed;
    ui.onConnectionStateChanged(Vpn::ConnectionState::Unknown);
    check(ui.errorNotifications.size()==1&&ui.errorNotifications.last()==ErrorCode::NativeTunnelCleanupUnconfirmed,"real UNKNOWN cleanup failure still notifies");
    ui.onConnectionStateChanged(Vpn::ConnectionState::Error);
    check(ui.errorNotifications.size()==2&&ui.errorNotifications.last()==ErrorCode::NativeTunnelCleanupUnconfirmed,"normal real Error notification preserved");
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
    QCoreApplication app(argc,argv);decoder();dnsDecoder();worker();dnsWorker();liveDnsWorker();livePrimaryWorker();absentNativeOwner();rapidIdleRestoreChallenge();orphanObservationRecovery();teardown();boundStop();ingress();refusalUi();unknownUiErrorNotification();
    if(argc==2) { QFile file(QString::fromLocal8Bit(argv[1]));check(file.open(QIODevice::ReadOnly),"shared Kotlin corpus readable");
        int rows=0;
        while (!file.atEnd()) {
            const auto line=file.readLine().trimmed(); if (line.isEmpty()) continue;
            ++rows;check(!NativeSessionRestore::decode(line).isEmpty(),"actual Kotlin serialized corpus decoded");
        }
        check(rows>=2,"ordinary and escaped Unicode Kotlin vectors consumed"); }
    std::fprintf(stderr,"%d checks, %d failures\n",checks,failures);return failures?1:0;
}
