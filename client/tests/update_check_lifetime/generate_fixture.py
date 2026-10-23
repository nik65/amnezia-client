"""Owned Qt fixture: actual updater methods/completion, inert effects only.

Gateway future, network transport, manifest signature/business interpretation and
publication work are explicit seams. No real network, installer, publication,
application/GUI, VPN or service operation is invoked by the generated executable.
"""
from pathlib import Path
import argparse
import hashlib

parser = argparse.ArgumentParser()
parser.add_argument('client_root', type=Path)
parser.add_argument('output', type=Path)
parser.add_argument('--update-source', type=Path)
parser.add_argument('--bootstrap-source', type=Path)
args = parser.parse_args()
update_path = args.update_source or args.client_root / 'core/controllers/updateController.cpp'
bootstrap_path = args.bootstrap_source or args.client_root / 'core/controllers/selfhosted/selfHostedUpdateBootstrapper.cpp'
header_path = args.client_root / 'core/controllers/selfhosted/selfHostedUpdateBootstrapper.h'
update = update_path.read_text(encoding='utf8')
bootstrap = bootstrap_path.read_text(encoding='utf8')
header = header_path.read_text(encoding='utf8')

def section(text, first, last):
    start = text.index(first)
    return text[start:text.index(last, start)]

manifest = section(update, 'void UpdateController::fetchSelfHostedManifestFromUrls(', '\nvoid UpdateController::doGetAsync(')
metadata = section(update, 'void UpdateController::doGetAsync(', '\nvoid UpdateController::fetchGatewayUrl(')
gateway = section(update, 'void UpdateController::fetchGatewayUrl(', '\nvoid UpdateController::fetchVersionInfo(')
pinned = section(update, '    bool samePinnedUrl(', '\n#if defined(Q_OS_WINDOWS)')
completion = section(bootstrap, '                    [success](SelfHostedUpdateBootstrapper *bootstrapper) {', '\n                    });').strip() + '\n}'
retry = section(header, '    constexpr int maximumAutomaticPublishAttempts', '\n    inline bool accountBoundedRemoteOutput(')
prefix = r'''
#include <QByteArray>
#include <QCoreApplication>
#include <QElapsedTimer>
#include <QEvent>
#include <QFuture>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QPointer>
#include <QPromise>
#include <QSet>
#include <QSharedPointer>
#include <QThread>
#include <QTimer>
#include <QUrl>
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <memory>
#include <vector>
#include "core/utils/boundedNetworkReply.h"
#define APP_VERSION "5.0.3.13"
enum class ErrorCode { NoError, OwnedFailure };
struct NoLog { template<class T> NoLog &operator<<(const T &) { return *this; } };
struct TestLogger { NoLog info()const{return{};} NoLog error()const{return{};} } logger;
constexpr qsizetype kManifestMaxPayloadBytes=1024*1024;
constexpr qsizetype kUpdateMetadataMaxPayloadBytes=1024*1024;
constexpr int kManifestTransferTimeoutMs=7000;
enum class ManifestProcessResult { Invalid, NoUpdate, Found };
bool shouldTryNextManifest(ManifestProcessResult result){return result==ManifestProcessResult::Invalid;}
static int checks=0;
void check(bool condition,const char *description){
 ++checks;if(!condition){std::fprintf(stderr,"update-check fixture failure%d: %s\n",checks,description);std::exit(1);}
}
void events(int milliseconds=20){
 QElapsedTimer clock;clock.start();
 do { QCoreApplication::processEvents(); QThread::msleep(1); }while(clock.elapsed()<milliseconds);
}
class FakeReply:public QNetworkReply {
public:
 QByteArray payload;qint64 offset=0,readBytes=0,maximumReadRequest=0;int aborts=0;
 explicit FakeReply(const QNetworkRequest &request,QObject *parent):QNetworkReply(parent){
  setRequest(request);setUrl(request.url());setOpenMode(QIODevice::ReadOnly);
  setAttribute(QNetworkRequest::HttpStatusCodeAttribute,200);
 }
 void abort()override{
  ++aborts;setError(QNetworkReply::OperationCanceledError,"owned fake cancellation");
  if(!isFinished()){setFinished(true);emit finished();}
 }
 qint64 bytesAvailable()const override{return payload.size()-offset+QNetworkReply::bytesAvailable();}
 void body(const QByteArray &bytes,bool ready=true){payload=bytes;offset=0;if(ready)emit readyRead();}
 void complete(){if(!isFinished()){setFinished(true);emit finished();}}
 void declared(qint64 size){setHeader(QNetworkRequest::ContentLengthHeader,size);emit metaDataChanged();}
protected:
 qint64 readData(char *buffer,qint64 maximum)override{
  maximumReadRequest=qMax(maximumReadRequest,maximum);
  const qint64 count=qMin<qint64>(maximum,payload.size()-offset);
  if(count<=0)return -1;
  std::memcpy(buffer,payload.constData()+offset,static_cast<std::size_t>(count));offset+=count;readBytes+=count;return count;
 }
};
class FakeManager:public QNetworkAccessManager {
public:
 std::vector<QPointer<FakeReply>> replies;
protected:
 QNetworkReply *createRequest(Operation,const QNetworkRequest &request,QIODevice *)override{
  auto *reply=new FakeReply(request,this);replies.push_back(reply);return reply;
 }
};
struct FakeApplication {FakeManager manager;FakeManager *networkManager(){return &manager;}};
FakeApplication *amnApp=nullptr;
struct Settings {
 QString getGatewayEndpoint()const{return "https://gateway.invalid";}
 bool isDevGatewayEnv()const{return false;}
 bool isStrictKillSwitchEnabled()const{return false;}
};
namespace apiDefs::key { inline const QString cliVersion="cli_version"; }
struct GatewayPayloadBuilder {
 explicit GatewayPayloadBuilder(Settings*){}
 GatewayPayloadBuilder &addField(const QString&,const QString&){return *this;}
 QJsonObject build()const{return{};}
};
using GatewayResult=QPair<ErrorCode,QByteArray>;
struct PendingGateway {std::shared_ptr<QPromise<GatewayResult>> promise;bool completed=false;};
std::vector<PendingGateway> pendingGateway;
class GatewayController:public QObject {
public:
 GatewayController(const QString&,bool,int,bool,Settings*){}
 QFuture<GatewayResult> postAsync(const QString&,const QJsonObject&){
  auto promise=std::make_shared<QPromise<GatewayResult>>();promise->start();
  pendingGateway.push_back({promise,false});return promise->future();
 }
};
void completeGateway(std::size_t index,bool success,const QString &url={}){
 auto &pending=pendingGateway.at(index);check(!pending.completed,"owned future completed once");
 pending.completed=true;
 pending.promise->addResult(GatewayResult{success?ErrorCode::NoError:ErrorCode::OwnedFailure,
   success?QJsonDocument(QJsonObject{{"url",url}}).toJson(QJsonDocument::Compact):QByteArray()});
 pending.promise->finish();events();
}
void finishOwnedGateways(){
 for(std::size_t i=0;i<pendingGateway.size();++i)if(!pendingGateway[i].completed)completeGateway(i,false);
 pendingGateway.clear();events();
}
class UpdateController:public QObject {
public:
 Settings settings;Settings *m_appSettingsRepository=&settings;
 bool m_updateCheckRunning=true,m_updateFoundDuringCheck=false;
 quint64 m_updateCheckGeneration=1;
 QSet<QNetworkReply*>m_updateCheckReplies;
 QString m_baseUrl;
 int versionCalls=0,finishCalls=0,updateSignals=0,installSchedules=0,manifestCalls=0,networkErrors=0;
 QString finishError;QByteArray processedManifest;
 ManifestProcessResult expectedManifest=ManifestProcessResult::NoUpdate;
 void fetchSelfHostedManifestFromUrls(const QList<QUrl>&,int);
 void doGetAsync(const QString&,std::function<void(bool,QByteArray)>);
 void fetchGatewayUrl();
 void finishUpdateCheck(const QString &error={}){++finishCalls;finishError=error;m_updateCheckRunning=false;}
 ManifestProcessResult processSelfHostedManifest(const QUrl&,const QByteArray&data){++manifestCalls;processedManifest=data;return expectedManifest;}
 void updateFound(){++updateSignals;}
 void scheduleSelfHostedAutoInstall(){++installSchedules;}
 void setupNetworkErrorHandling(QNetworkReply*,const QString&){}
 void handleNetworkError(QNetworkReply*,const QString&){++networkErrors;}
 void fetchVersionInfo(){++versionCalls;}
};
'''
bootstrap_prefix = '\nnamespace amnezia::selfhostedUpdates {\n' + retry + '\n}\n'
bootstrap_prefix += r'''
static int bootstrapStarts=0;
class SelfHostedUpdateBootstrapper:public QObject {
 Q_OBJECT
public:
 amnezia::selfhostedUpdates::AutomaticPublishRetryState m_publishRetryState;
 bool start(){++bootstrapStarts;m_publishRetryState.scheduled=true;return true;}
signals:
 void publishFinished(bool success);
};
'''
tests = r'''
FakeReply *lastReply(FakeApplication &application){
 check(!application.manager.replies.empty(),"owned fake request created");
 auto *reply=application.manager.replies.back().data();check(reply!=nullptr,"owned fake reply alive");return reply;
}
void gatewayCase(const QString &name){
 auto controller=std::make_unique<UpdateController>();
 controller->fetchGatewayUrl();
 if(name=="gateway-delayed-invalidated"){
  ++controller->m_updateCheckGeneration;controller->m_updateCheckRunning=false;events(1150);
  check(pendingGateway.empty(),"timed-out delayed start must not issue gateway request");
 }else{
  events(1150);check(pendingGateway.size()==1,"current delayed gateway starts");
  if(name=="gateway-current"){
   completeGateway(0,true,"https://current.invalid/");
   check(controller->m_baseUrl=="https://current.invalid"&&controller->versionCalls==1,"current gateway response progresses once");
  }else{
   ++controller->m_updateCheckGeneration;controller->m_updateCheckRunning=false;
   ++controller->m_updateCheckGeneration;controller->m_updateCheckRunning=true;
   controller->fetchGatewayUrl();events(1150);check(pendingGateway.size()==2,"new generation gateway starts");
   completeGateway(0,name=="gateway-stale-success","https://stale.invalid/");
   check(controller->m_baseUrl.isEmpty()&&controller->versionCalls==0,"old gateway success cannot mutate newer generation");
   check(controller->m_updateCheckRunning&&controller->finishCalls==0,"old gateway error cannot finish newer generation");
   completeGateway(1,true,"https://current.invalid/");
   check(controller->m_baseUrl=="https://current.invalid"&&controller->versionCalls==1,"new generation remains usable");
  }
 }
 controller.reset();finishOwnedGateways();
}
void manifestCase(const QString &name,FakeApplication &application){
 auto controller=std::make_unique<UpdateController>();
 controller->fetchSelfHostedManifestFromUrls({QUrl("https://updates.invalid/manifest.json")},0);
 auto *reply=lastReply(application);
 if(name=="manifest-exact"){
  QByteArray data(kManifestMaxPayloadBytes,'x');reply->body(data);reply->complete();
  check(controller->manifestCalls==1&&controller->processedManifest==data,"exact manifest limit preserved");
  check(controller->finishCalls==1&&controller->finishError.isEmpty(),"exact manifest finishes normally");
 }else if(name=="manifest-overflow"){
  reply->body(QByteArray(8*kManifestMaxPayloadBytes,'x'));
  check(reply->readBytes<=kManifestMaxPayloadBytes+1,"manifest read bounded before allocation/append");
  check(reply->aborts==1&&controller->manifestCalls==0,"manifest overflow rejected before processing");
 }else if(name=="manifest-declared"){
  reply->declared(kManifestMaxPayloadBytes+1);
  check(reply->aborts==1&&reply->readBytes==0&&controller->manifestCalls==0,"declared manifest overflow rejected before read");
 }else if(name=="manifest-final-only"){
  const QByteArray data="owned-final-manifest";reply->body(data,false);reply->complete();
  check(controller->processedManifest==data,"finished-only remaining manifest data drained");
 }else if(name=="manifest-destroy-reply"){
  delete reply;
  check(controller->m_updateCheckReplies.isEmpty(),"destroyed manifest reply removed from pending set");
 }else{
  reply->body(QByteArray(1024,'x'));
  QPointer<FakeReply> observed(reply);controller.reset();
  if(name=="manifest-destroy-owner")check(observed.isNull(),"manifest reply owned by controller");
  if(observed)delete observed.data();
  // In manifest-leak ASAN/LSAN observes actual old raw state allocations after
  // both owner/reply are destroyed without finished. No test allocator seam.
 }
 events();
}
void metadataCase(const QString &name,FakeApplication &application){
 auto controller=std::make_unique<UpdateController>();controller->m_baseUrl="https://updates.invalid";
 int calls=0;bool success=false;QByteArray result;
 controller->doGetAsync("/CHANGELOG",[&](bool ok,QByteArray data){++calls;success=ok;result=data;});
 auto *reply=lastReply(application);
 if(name=="metadata-exact"){
  const QByteArray data(kUpdateMetadataMaxPayloadBytes,'x');reply->body(data);reply->complete();
  check(calls==1&&success&&result==data,"metadata exact limit preserved");
 }else if(name=="metadata-overflow"){
  reply->body(QByteArray(8*kUpdateMetadataMaxPayloadBytes,'x'));reply->complete();
  check(reply->readBytes<=kUpdateMetadataMaxPayloadBytes+1,"metadata read bounded before allocation");
  check(calls==1&&!success&&result.isEmpty(),"metadata overflow cannot succeed or return partial data");
 }else if(name=="metadata-declared"){
  reply->declared(kUpdateMetadataMaxPayloadBytes+1);reply->complete();
  check(reply->aborts==1&&reply->readBytes==0,"declared metadata overflow rejected before read");
  check(calls==1&&!success&&result.isEmpty(),"declared metadata overflow fails callback");
 }else if(name=="metadata-stale"){
  ++controller->m_updateCheckGeneration;reply->body("stale");reply->complete();
  check(calls==0,"old metadata reply inert after generation changes");
 }else if(name=="metadata-destroy-reply"){
  delete reply;
  check(controller->m_updateCheckReplies.isEmpty(),"destroyed metadata reply removed from pending set");
 }else{
  reply->body("pending");QPointer<FakeReply> observed(reply);controller.reset();
  check(observed.isNull(),"metadata reply owned by controller");
 }
 events();
}
'''
main = r'''
int main(int argc,char **argv){
 QCoreApplication application(argc,argv);check(argc==2,"one owned scenario argument");
 FakeApplication fake;amnApp=&fake;
 const QString name=QString::fromLocal8Bit(argv[1]);
 if(name.startsWith("gateway-"))gatewayCase(name);
 else if(name.startsWith("manifest-"))manifestCase(name,fake);
 else if(name.startsWith("metadata-"))metadataCase(name,fake);
 else if(name.startsWith("bootstrap-"))bootstrapCase(name);
 else check(false,"known owned scenario");
 QCoreApplication::sendPostedEvents(nullptr,QEvent::DeferredDelete);
 std::printf("update-check actual-source scenario %s checks:%d PASS\n",argv[1],checks);
}
#include "update_check_fixture.moc"
'''
bootstrap_test = r'''
void bootstrapCase(const QString &name){
 const bool success=name=="bootstrap-success-delete";
 auto *object=new SelfHostedUpdateBootstrapper;
 object->m_publishRetryState.inProgress=true;
 object->m_publishRetryState.attemptCount=name.contains("exhausted")?3:1;
 QPointer<SelfHostedUpdateBootstrapper> observed(object);
 int notifications=0;bool exhaustedDuringSignal=false;
 QObject receiver;
 QObject::connect(object,&SelfHostedUpdateBootstrapper::publishFinished,&receiver,[&](bool){
  ++notifications;exhaustedDuringSignal=object->m_publishRetryState.exhausted;
  if(name.endsWith("-delete"))delete object;
 },Qt::DirectConnection);
 auto completion=ACTUAL_COMPLETION;
 completion(object);
 check(notifications==1,"one publication-completion notification");
 if(name.endsWith("-delete")){
  check(observed.isNull(),"direct receiver deleted emitter");
  check(bootstrapStarts==0,"no retry after synchronous emitter deletion");
 }else if(name=="bootstrap-normal-retry"){
  check(bootstrapStarts==1&&object->m_publishRetryState.scheduled,"normal retry remains scheduled");
 }else{
  check(exhaustedDuringSignal&&!object->m_publishRetryState.exhausted&&bootstrapStarts==0,"exhausted latch stays during notification and rearms after");
 }
 if(observed)delete observed.data();
}
'''.replace('ACTUAL_COMPLETION', completion)
provenance = ''
for path in (update_path, bootstrap_path, header_path):
    provenance += '// Actual source SHA256 ' + str(path) + ': ' + hashlib.sha256(path.read_bytes()).hexdigest() + '\n'
args.output.write_text(provenance + prefix + pinned + '\n' + manifest + metadata + gateway
                       + bootstrap_prefix + tests + bootstrap_test + main, encoding='utf8')
