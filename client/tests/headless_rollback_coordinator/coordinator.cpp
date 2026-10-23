#include "rollbackCoordinator.h"
#include "headlessUpdateManager.h"
#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QLockFile>
#include <QTemporaryDir>
#include <cassert>
#include <iostream>
#include <sys/stat.h>
#include <unistd.h>

using namespace amnezia::headless;
namespace {
int checks=0, groups=0;
void verify(bool v, const char *label) { ++checks; if(!v)std::cerr<<"check="<<checks<<" "<<label<<'\n'; assert(v); }
QString sha(const QByteArray &b) { return QString::fromLatin1(QCryptographicHash::hash(b,QCryptographicHash::Sha256).toHex()); }
QByteArray read(const QString &p) { QFile f(p); assert(f.open(QIODevice::ReadOnly)); return f.readAll(); }
QJsonObject object(const QString &p) { return QJsonDocument::fromJson(read(p)).object(); }
void write(const QString &p, const QByteArray &b, mode_t mode=0600) { QFile f(p); assert(f.open(QIODevice::WriteOnly)); assert(f.write(b)==b.size()); f.close(); assert(::chmod(p.toUtf8().constData(),mode)==0); }
void json(const QString &p,const QJsonObject &o) { write(p,QJsonDocument(o).toJson(QJsonDocument::Compact)); }
QJsonObject pair(const QString &dir) { QJsonObject o; for(const auto &n:{"amneziad","amnezia-cli"}) {auto b=read(dir+"/"+n);o.insert(n,QJsonObject{{"sha256",sha(b)},{"size",b.size()}});} return o; }

struct Platform final:RollbackCoordinatorPlatform {
    QStringList calls; bool running=true,failStop=false,failAck=false,failStart=false,failWorker=false;
    qint64 clock=0;int oldObservations=0;bool wrongVersion=false,wrongPair=false,wrongDoctor=false; qint64 pid=1301,ticks=900;
    QJsonObject observe(const RollbackCoordinatorPaths &p,QString *) override {
        calls<<"observe";if(!running)return {};if(oldObservations>0){--oldObservations;return {{"version","5.0.3.14"}};}
        auto state=object(p.state);auto installed=pair(p.install);if(wrongPair)installed.insert("amnezia-cli",QJsonObject{{"sha256",QString(64,'f')},{"size",3}});
        QJsonObject updates{{"recoveryRequired",wrongDoctor},{"lastError",wrongDoctor?"fixture-error":""},
            {"lastAppliedVersion",state.value("lastAppliedVersion")},{"state",state.value("state")}};
        QJsonObject doctor{{"ok",true},{"result",QJsonObject{{"ready",true},{"updates",updates}}}};
        return {{"daemon_pid",pid},{"start_ticks",QString::number(ticks)},{"pair",installed},
            {"version",wrongVersion?"0.0.0.0":state.value("lastAppliedVersion").toString()},{"doctor",doctor}};
    }
    qint64 monotonicMilliseconds() override {return clock;}
    void waitForObservationRetry() override {calls<<"wait";clock+=250;}
    bool stop(QString *) override {calls<<"stop";if(failStop)return false;running=false;return true;}
    bool start(QString *) override {calls<<"start";if(failStart)return false;running=true;++pid;++ticks;return true;}
    bool stopped(QString *) override {calls<<"stopped";return !running;}
    bool installUnit(QString *) override {calls<<"install-unit";return true;}
    bool startWorker(QString *) override {calls<<"start-worker";return !failWorker;}
    bool retireUnit(QString *) override {calls<<"retire-unit";return true;}
    bool acknowledge(const RollbackCoordinatorPaths &p,const QString &v,QString *error) override {
        calls<<"ack";verify(!running,"stop precedes actual manager construction/ACK");
        if(failAck)return false;
        const auto r=HeadlessUpdateManager::acknowledgeStoppedRollback(p.state,p.install,v,{},true);if(!r.ok){std::cerr<<"actual ACK code="<<r.code.toStdString()<<" message="<<r.message.toStdString()<<"\n";if(error)*error=r.message;}
        return r.ok&&r.code=="disabled";
    }
};
struct Fixture {
    QTemporaryDir temp; RollbackCoordinatorPaths paths; std::shared_ptr<Platform> platform=std::make_shared<Platform>();
    QString updates,backup,previous,transaction; QByteArray original;
    Fixture() {
        assert(temp.isValid());paths.root=temp.path()+"/coordinator";paths.profiles=temp.path()+"/profiles.json";
        assert(QDir().mkpath(temp.path()+"/state"));paths.state=temp.path()+"/state/headless-updates.json";paths.install=temp.path()+"/bin";paths.unit=temp.path()+"/coordinator.service";
        paths.socket=temp.path()+"/owned.sock";paths.owner=geteuid();paths.verifySelfExecutable=false;
        updates=temp.path()+"/state/updates";backup=updates+"/rollback-owned";previous=updates+"/rollback-current-owned";transaction=updates+"/transaction-owned";
        for(const auto &d:{paths.install,backup,previous,transaction})assert(QDir().mkpath(d));
        for(const auto &n:{"amneziad","amnezia-cli"}) {write(paths.install+"/"+n,"new14",0700);write(backup+"/"+n,"old13",0700);write(previous+"/"+n,"new14",0700);}
        original="{\n \"unknownRoot\":{\"keep\":[1,2]},\"version\":1, \"profiles\":[{\"id\":\"first\",\"autoUpdate\":true,\"unknown\":{\"autoUpdate\":true},\"updateManifestUrl\":\"http://10.8.1.1:17865/manifest.json\"},{\"id\":\"second\",\"autoUpdate\":true},{\"id\":\"false\",\"autoUpdate\":false},{\"id\":\"absent\"}]}\n";
        write(paths.profiles,original);
        QJsonObject hashes;for(const auto &n:{"amneziad","amnezia-cli"})hashes.insert(n,sha("old13"));
        json(paths.state,{{"version",2},{"lastCheckedAt",""},{"state","updated"},{"lastAppliedVersion","5.0.3.14"},{"lastError",""},
            {"rollbackVersion","5.0.3.13"},{"rollbackDirectory",backup},{"rollbackHashes",hashes},{"installDirectory",paths.install},{"updateRoot",updates}});
        json(updates+"/rollback-receipt.json",{{"version",1},{"rollbackVersion","5.0.3.13"},{"rollbackDirectory",backup},{"rollbackHashes",hashes},{"installDirectory",paths.install},{"updateRoot",updates}});
    }
    RollbackCoordinator core() {return RollbackCoordinator(paths,platform);}
    QString recordPath()const{return paths.root+"/coordinator.json";}
    QJsonObject record()const{return object(recordPath());}
    void prepare() {const auto r=core().prepare();if(!r.ok)std::cerr<<r.message.toStdString()<<'\n';verify(r.ok,"prepare");}
    void pause() {prepare();const auto r=core().admitRollback();if(!r.ok)std::cerr<<r.message.toStdString()<<'\n';verify(r.ok,"pause");}
    void replaceWithTarget() {
        for(const auto &n:{"amneziad","amnezia-cli"})write(paths.install+"/"+n,"old13",0700);
        auto s=object(paths.state);s.insert("state","rollback_restart_pending");s.insert("lastAppliedVersion","5.0.3.13");json(paths.state,s);
        QJsonObject oldHashes,newHashes,sizes;for(const auto &n:{"amneziad","amnezia-cli"}){oldHashes.insert(n,sha("old13"));newHashes.insert(n,sha("new14"));sizes.insert(n,5);}
        json(updates+"/transaction.json",{{"version",1},{"operation","rollback"},{"phase","rollback_restart_pending"},
            {"candidateVersion","5.0.3.13"},{"currentVersion","5.0.3.13"},{"installDirectory",paths.install},{"transactionDirectory",transaction},
            {"rollbackDirectory",backup},{"rollbackHashes",oldHashes},{"candidateHashes",oldHashes},{"candidateSizes",sizes},
            {"previousDirectory",previous},{"previousHashes",newHashes},{"previousSizes",sizes}});
    }
    void requested(){pause();replaceWithTarget();const auto r=core().rollbackRequested();if(!r.ok)std::cerr<<r.message.toStdString()<<'\n';verify(r.ok,"real pending request");}
    void held(){requested();const auto r=core().run();if(!r.ok)std::cerr<<r.message.toStdString()<<'\n';verify(r.ok&&r.code=="held","hold");}
};
}
int main(int argc,char **argv) {
    QCoreApplication app(argc,argv);
    { ++groups; Fixture f;f.pause();auto expected=f.original;expected.replace("\"autoUpdate\":true,\"unknown\"","\"autoUpdate\":false,\"unknown\"");expected.replace("\"id\":\"second\",\"autoUpdate\":true","\"id\":\"second\",\"autoUpdate\":false");verify(read(f.paths.profiles)==expected,"raw all-profile exact preservation");verify(f.record().value("pausedProfileCount").toInt()==2,"both enabled profiles paused");verify(f.record().value("authority")=="retained14Coordinator","named authority"); }
    { ++groups;Fixture f;f.pause();const auto changed=read(f.paths.profiles)+" ";write(f.paths.profiles,changed);f.replaceWithTarget();verify(!f.core().rollbackRequested().ok,"changed policy rejects request");verify(read(f.paths.profiles)==changed,"conflicting policy not overwritten"); }
    { ++groups;Fixture f;f.prepare();write(f.paths.root+"/amnezia-cli","tamper",0500);verify(!f.core().admitRollback().ok,"changed retained binary rejects");verify(read(f.paths.profiles)==f.original,"tamper no pause"); }
    { ++groups;Fixture f;f.pause();verify(!f.core().rollbackRequested().ok,"no real pending journal rejects");verify(!f.platform->calls.contains("ack"),"no journal no ACK"); }
    { ++groups;Fixture f;f.held();verify(f.record().value("acknowledgementAuthority")=="retained14Coordinator","not daemon13 ACK");verify(!QFile::exists(f.updates+"/transaction.json"),"actual updater journal retired");verify(object(f.paths.state).value("state")=="disabled","actual legacy-compatible disabled");verify(f.platform->calls.indexOf("stop")<f.platform->calls.indexOf("ack"),"stop before constructor/ACK");verify(f.platform->calls.indexOf("ack")<f.platform->calls.indexOf("start"),"reload after ACK"); }
    { ++groups;for(const auto &bad:{"version","pair","doctor"}){Fixture f;f.requested();f.platform->wrongVersion=QString(bad)=="version";f.platform->wrongPair=QString(bad)=="pair";f.platform->wrongDoctor=QString(bad)=="doctor";verify(!f.core().run().ok,"wrong actual runtime rejects");verify(!f.platform->calls.contains("ack"),"bad runtime never ACKs");} }
    { ++groups;Fixture f;f.requested();f.platform->failAck=true;verify(!f.core().run().ok,"injected ACK failure");verify(f.record().value("phase")=="coordinator_commit_pending","durable precommit phase");f.platform->failAck=false;f.platform->running=true;verify(f.core().run().ok,"new entry recovers pending ACK"); }
    { ++groups;Fixture f;f.held();const auto calls=f.platform->calls;verify(f.core().run().ok,"held reboot reentry verifies");verify(f.platform->calls.count("ack")==calls.count("ack"),"held never repeats ACK");write(f.paths.profiles,read(f.paths.profiles)+" ");verify(!f.core().status().ok,"later profile import/edit invalidates hold"); }
    { ++groups;Fixture f;f.held();const auto r=f.core().resume();if(!r.ok)std::cerr<<r.message.toStdString()<<'\n';verify(r.ok,"explicit resume");verify(read(f.paths.profiles)==f.original,"resume exact original unknown fields");verify(f.record().value("phase")=="resumed","durable resumed");verify(f.platform->calls.contains("retire-unit"),"only successful resume retires recovery unit"); }
    { ++groups;Fixture f;auto doc=QJsonDocument::fromJson(f.original).object();doc.insert("largeUnknown",QString(96*1024,'x'));f.original=QJsonDocument(doc).toJson(QJsonDocument::Compact);write(f.paths.profiles,f.original);f.prepare();const auto result=f.core().admitRollback();verify(result.ok,"large raw profile pause");verify(QJsonDocument(result.evidence).toJson(QJsonDocument::Compact).size()<65536,"bounded public evidence");verify(QByteArray::fromBase64(f.record().value("originalProfilesBase64").toString().toLatin1())==f.original,"private full raw retained");}
    { ++groups;Fixture f;f.pause();auto paused=read(f.paths.profiles);auto r=f.record();r.insert("phase","pause_prepared");json(f.recordPath(),r);write(f.paths.profiles,f.original);verify(f.core().run().ok,"restart before pause CAS");verify(read(f.paths.profiles)==paused,"restart finishes same raw pause");verify(!f.platform->calls.contains("ack"),"pause-only no fabricated ACK");}
    { ++groups;Fixture f;f.pause();auto r=f.record();r.insert("phase","pause_prepared");json(f.recordPath(),r);verify(f.core().run().ok,"restart after pause CAS");verify(f.record().value("phase")=="profiles_paused","pause phase completed");}
    { ++groups;Fixture f;f.requested();auto j=object(f.updates+"/transaction.json");auto sizes=j.value("candidateSizes").toObject();sizes.insert("amnezia-cli",6);j.insert("candidateSizes",sizes);json(f.updates+"/transaction.json",j);verify(!f.core().run().ok,"wrong pending pair size rejects before ACK");verify(!f.platform->calls.contains("ack"),"conflicting size no ACK");}
    { ++groups;Fixture f;f.requested();f.platform->failStop=true;verify(!f.core().run().ok,"stop failure rejects");verify(!f.platform->calls.contains("ack"),"failed stop no ACK");f.platform->failStop=false;verify(f.core().run().ok,"stop retry recovers");}
    { ++groups;Fixture f;f.requested();f.platform->failStart=true;verify(!f.core().run().ok,"post ACK restart failure");verify(!QFile::exists(f.updates+"/transaction.json"),"ACK committed before failed restart");f.platform->failStart=false;verify(f.core().run().ok,"post ACK crash restart resumes");}
    { ++groups;Fixture f;f.held();f.platform->failStart=true;verify(!f.core().resume().ok,"resume restart failure");verify(read(f.paths.profiles)==f.original,"original restored before failed restart");verify(f.record().value("phase")=="resume_requested","resume intent durable");f.platform->failStart=false;verify(f.core().run().ok,"run recovers resume after original restored");verify(f.record().value("phase")=="resumed","resumed finalized");}
    { ++groups;Fixture f;f.prepare();auto r=f.record();const auto unit=f.paths.unit;write(unit,read(unit)+"#changed\n",0644);verify(!f.core().admitRollback().ok,"changed unit rejects");verify(read(f.paths.profiles)==f.original,"unit tamper no policy mutation");verify(!r.value("operationId").toString().isEmpty(),"operation nonce exists");}
    { ++groups;Fixture f;auto doc=QJsonDocument::fromJson(f.original).object();doc.insert("padding","");auto base=QJsonDocument(doc).toJson(QJsonDocument::Compact);doc.insert("padding",QString(16*1024*1024-base.size(),'x'));f.original=QJsonDocument(doc).toJson(QJsonDocument::Compact);verify(f.original.size()==16*1024*1024,"exact raw input bound");write(f.paths.profiles,f.original);f.prepare();verify(!f.core().admitRollback().ok,"pause growth exceeds bound");verify(read(f.paths.profiles)==f.original,"overflow leaves raw store unchanged");}
    { ++groups;Fixture f;f.requested();f.platform->oldObservations=8;verify(f.core().run().ok,"old14 observation eventually genuine13");verify(f.platform->calls.count("wait")==8,"bounded observation retries");verify(f.platform->calls.count("ack")==1,"transient observation one ACK");}
    { ++groups;Fixture f;f.requested();auto previousObserves=f.platform->calls.count("observe");f.platform->oldObservations=100;verify(!f.core().run().ok,"never genuine13 rejects");verify(f.platform->calls.count("observe")-previousObserves==60,"15-second observation maximum");verify(!f.platform->calls.contains("stop")&&!f.platform->calls.contains("ack"),"old14 never stopped or ACKed");}
    { ++groups;Fixture f;f.pause();const auto paused=read(f.paths.profiles);const auto orphan=f.paths.root+"/.coordinator-owned-conflict";write(orphan,"displaced-private-original");verify(!f.core().admitRollback().ok,"orphan blocks pause replay");verify(!f.core().run().ok,"orphan blocks worker replay");verify(!f.core().status().ok,"orphan blocks status authority");verify(!f.core().resume().ok,"orphan blocks resume");verify(read(orphan)=="displaced-private-original"&&read(f.paths.profiles)==paused,"orphan preserved without policy overwrite");}
    { ++groups;Fixture f;f.pause();f.replaceWithTarget();f.platform->failWorker=true;const auto result=f.core().rollbackRequested();verify(!result.ok,"worker scheduling failure never accepted");verify(f.record().value("phase")=="rollback_requested","pending request durable after worker failure");verify(!f.platform->calls.contains("ack"),"worker failure no fabricated ACK");}
    { ++groups;Fixture f;f.requested();const auto originalPendingState=read(f.paths.state);const auto originalPendingJournal=read(f.updates+"/transaction.json");verify(f.core().run().ok,"capture raw private pending proof");const auto record=f.record();const auto stop=record.value("stopEvidence").toObject();verify(stop.value("verifiedStopped").toBool()&&stop.value("observedProcessGone").toBool(),"private stopped identity proof");const auto pending=record.value("pendingEvidence").toObject();const auto stateBytes=QByteArray::fromBase64(pending.value("stateBytesBase64").toString().toLatin1());const auto journalBytes=QByteArray::fromBase64(pending.value("journalBytesBase64").toString().toLatin1());verify(stateBytes==originalPendingState&&sha(stateBytes)==pending.value("stateSha256").toString(),"private exact raw pending state plus reproducible hash");verify(journalBytes==originalPendingJournal&&sha(journalBytes)==pending.value("journalSha256").toString(),"private exact raw pending journal plus reproducible hash");const auto ack=record.value("coordinatorAcknowledgement").toObject();verify(ack.value("authority")=="retained14Coordinator"&&ack.value("returnedSuccessfully").toBool(),"successful own ACK exact authority");verify(ack.value("result")=="disabled"&&!ack.value("completedAt").toString().isEmpty(),"own ACK result and timestamp");verify(ack.value("postStateSha256")==sha(read(f.paths.state)),"actual ACK poststate hash");}
    { ++groups;Fixture f;f.requested();f.platform->failStart=true;verify(!f.core().run().ok,"commit before restart crash");auto r=f.record();r.remove("coordinatorAcknowledgement");json(f.recordPath(),r);f.platform->failStart=false;verify(f.core().run().ok,"recover actual disabled poststate");auto ack=f.record().value("coordinatorAcknowledgement").toObject();verify(ack.value("result")=="recovered_disabled_poststate"&&!ack.value("returnedSuccessfully").toBool(),"recovery does not invent returned ACK");}
    std::cout<<"actual coordinator fixture groups="<<groups<<" checks="<<checks<<" live services=0\n";
}
