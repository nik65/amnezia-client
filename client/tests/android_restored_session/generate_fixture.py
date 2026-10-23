"""Actual-source fixture extraction; no app, device, transport, or installer."""
from pathlib import Path
import argparse,hashlib,json
p=argparse.ArgumentParser();p.add_argument('repository',type=Path);p.add_argument('output',type=Path);p.add_argument('--vpn-source',type=Path);a=p.parse_args()
root=a.repository
worker=(a.vpn_source or root/'client/vpnConnection.cpp').read_text(encoding='utf-8')
controller=(root/'client/core/controllers/connectionController.cpp').read_text(encoding='utf-8')
ui=(root/'client/ui/controllers/connectionUiController.cpp').read_text(encoding='utf-8')
def section(s,start,end):
 i=s.index(start);return s[i:s.index(end,i)]
completion=section(worker,'                [this, serverId, retiringEpoch, disconnectEpoch, requestToken](bool confirmed) {','\n                }, this);').strip()+'\n}'
activation=section(worker,'    if (m_migrationTeardownContext || m_migrationTeardownRecoveryRequired) {','\n    qDebug() << QString("Trying to connect to VPN,')
cache=section(controller,'            [this](ErrorCode error) { m_cachedLastConnectionError = error; },','\n            Qt::QueuedConnection);').strip().removesuffix(',')
ui_error=section(ui,'    case Vpn::ConnectionState::Error: {','\n    case Vpn::ConnectionState::Unknown: {')
reconnect=section(worker, '                [this, startUpdatedProtocol](bool confirmed) {', '\n                }, this);').strip()+'\n}'
disconnect=worker[worker.index('void VpnConnection::disconnectFromVpn()'):]
missing=section(disconnect, '    if (m_vpnProtocol.isNull()) {', '\n    setConnectionState(Vpn::ConnectionState::Disconnecting);').replace('#if defined(Q_OS_ANDROID) || defined(AMNEZIA_DESKTOP)', '#if 1')
cpp=r"""
#include <QCoreApplication>
#include <QEvent>
#include <QPointer>
#include <QSharedPointer>
#include <QJsonObject>
#include <QString>
#include <QStringList>
#include "core/utils/errorStrings.h"
#include <cstdio>
#include <cstring>
#include "core/utils/migrationTeardownContext.h"
namespace Vpn { enum class ConnectionState {Disconnected,Disconnecting,Error,Preparing,Connecting}; }
using amnezia::ErrorCode;
namespace ContainerUtils {bool isAwgContainer(int container){return container==1;}}
class Worker: public QObject {
 Q_OBJECT
public:
 MigrationTeardownContext *m_migrationTeardownContext=nullptr;
 bool m_migrationTeardownRecoveryRequired=false;
 quint64 m_connectionEpoch=11;
 QString m_serverId="owned-server";
 int activations=0,m_container=1;
 QSharedPointer<QObject> m_vpnProtocol;QPointer<QObject> observedOwner;
 Vpn::ConnectionState state=Vpn::ConnectionState::Disconnecting;
 void setConnectionState(Vpn::ConnectionState next){state=next;emit connectionStateChanged(next);}
 void beginRestoredDisconnect(const QString &nonce={},bool routesConfirmed=true){
  const QString serverId=m_serverId;const quint64 retiringEpoch=10,disconnectEpoch=11,requestToken=0;
  auto completion=ACTUAL_COMPLETION;
  // Explicit seam: restored repository config has no live service nonce.
  // Actual context validates the known nonempty native receipt against it.
  QSharedPointer<QObject> owner(new QObject);observedOwner=owner.data();
  m_migrationTeardownContext=new MigrationTeardownContext(owner,
      nonce,retiringEpoch,disconnectEpoch,routesConfirmed,[this]{return m_connectionEpoch;},completion,this);
 }
 void missingOwner(){
  const quint64 requestToken=0,retiringEpoch=10;
ACTUAL_MISSING
 }
 void reconnectCompletion(bool confirmed){
  auto startUpdatedProtocol=[this]{++activations;};
  auto completion=ACTUAL_RECONNECT;completion(confirmed);
 }
 void activate(){
ACTUAL_ACTIVATION
  ++activations;setConnectionState(Vpn::ConnectionState::Connecting);
 }
signals:
 void vpnProtocolError(ErrorCode);
 void connectionStateChanged(Vpn::ConnectionState);
 void migrationTeardownObserved(const QString&,quint64,bool);
 void migrationTeardownReceipt(const QString&,quint64,quint64,quint64,bool);
};
class Controller: public QObject {
 Q_OBJECT
public:
 ErrorCode m_cachedLastConnectionError=ErrorCode::NoError;
 Vpn::ConnectionState state=Vpn::ConnectionState::Disconnecting;
 QStringList history;
 int errorSignals=0,observedSignals=0;ErrorCode notified=ErrorCode::UnknownError;
 bool m_isConnectionInProgress=true;QString m_connectionStateText;
 ErrorCode getLastConnectionError()const{return m_cachedLastConnectionError;}
 void attach(Worker &worker){
  connect(&worker,&Worker::vpnProtocolError,this,[this](ErrorCode error){history.append("reason");auto cache=ACTUAL_CACHE;cache(error);},Qt::QueuedConnection);
  connect(&worker,&Worker::connectionStateChanged,this,[this](Vpn::ConnectionState next){
   history.append("state");state=next;switch(next){
ACTUAL_UI_ERROR
    default:break;
   }
  },Qt::QueuedConnection);
  connect(this,&Controller::connectionErrorOccurred,this,[this](ErrorCode code){
   ++errorSignals;notified=code;
   // Actual CoreSignalHandlers error receiver marks controller/UI Disconnected;
   // this seam has no native cleanup effect, just the documented UI state.
   state=Vpn::ConnectionState::Disconnected;
  });
  connect(&worker,&Worker::migrationTeardownObserved,this,[this](const QString&,quint64,bool){++observedSignals;},Qt::QueuedConnection);
 }
signals:
 void connectionErrorOccurred(ErrorCode);
};
void events(){QCoreApplication::processEvents();QCoreApplication::processEvents();}
void require(bool ok,const char *message){if(!ok){std::fprintf(stderr,"FAIL: %s\n",message);std::exit(1);}}
int main(int argc,char **argv){
 QCoreApplication app(argc,argv);if(argc!=2)return 2;const QString name=QString::fromUtf8(argv[1]);
 Worker worker;Controller controller;controller.attach(worker);
 require(int(ErrorCode::NativeTunnelCleanupUnconfirmed)==704,"stable unique typed cleanup reason");
 require(errorString(ErrorCode::NativeTunnelCleanupUnconfirmed).contains("Native VPN tunnel cleanup could not be confirmed"),"real production error string actionable");
 bool shouldError=true;
 if(name=="missing-owner")worker.missingOwner();
 else if(name=="reconnect-unconfirmed")worker.reconnectCompletion(false);
 else if(name=="reconnect-confirmed"){worker.reconnectCompletion(true);shouldError=false;require(worker.activations==1,"confirmed reconnect can proceed");}
 else if(name=="refused-pending"||name=="pending-confirmed"){
  worker.beginRestoredDisconnect("session");auto *context=worker.m_migrationTeardownContext;
  auto *const owner=worker.observedOwner.data();
  controller.state=Vpn::ConnectionState::Preparing;worker.activate();
  events();
  require(worker.m_migrationTeardownContext==context&&!worker.m_migrationTeardownRecoveryRequired,"pending context preserved on refusal");
  require(worker.m_connectionEpoch==11&&worker.activations==0&&owner&&worker.observedOwner.data()==owner,"pending refusal preserves epoch/owner and starts no protocol");
  require(controller.errorSignals==0&&worker.state==Vpn::ConnectionState::Disconnecting&&controller.state==Vpn::ConnectionState::Disconnecting,"pending refusal stays Disconnecting without Error cleanup side effects");
  controller.history.clear();
  if(name=="pending-confirmed"){
   context->observeAndroid(QJsonObject{{"connectionNonce","session"},{"nativeCleanupConfirmed",true}},10);
   shouldError=false;
  }else context->expire();
 }else{
  const bool restored=name=="restored-timeout"||name=="refused-recovery";
  worker.beginRestoredDisconnect(restored?QString():QString("session"),name!="failed-routes");
  auto *context=worker.m_migrationTeardownContext;
  const QString nonce=name=="wrong-nonce"?"old-session":(restored?"native-session":"session");
  const quint64 originalEpoch=name=="wrong-epoch"?9:10;
  context->observeAndroid(QJsonObject{{"connectionNonce",nonce},{"nativeCleanupConfirmed",true}},originalEpoch);
  if(name=="confirmed")shouldError=false;
  else if(name=="failed-routes")require(worker.m_migrationTeardownRecoveryRequired,"failed route receipt cannot authorize cleanup");
  else{
   require(worker.m_migrationTeardownContext==context,"unbound or stale receipt rejected");
   context->expire();
  }
  events();
  if(name=="refused-recovery"){
   require(worker.m_migrationTeardownRecoveryRequired,"failure safety latch set");
   controller.history.clear();controller.errorSignals=0;controller.m_cachedLastConnectionError=ErrorCode::NoError;
   controller.state=Vpn::ConnectionState::Preparing;worker.activate();
   require(worker.m_migrationTeardownRecoveryRequired&&!worker.m_migrationTeardownContext,"refused activation does not clear latch or recreate context");
  }
 }
 events();
 if(shouldError){
  require(controller.errorSignals>0&&controller.notified==ErrorCode::NativeTunnelCleanupUnconfirmed,"typed nonzero reason reaches UI");
  require(controller.history.indexOf("reason")>=0&&controller.history.indexOf("reason")<controller.history.indexOf("state"),"reason delivered before Error state");
  require(controller.state!=Vpn::ConnectionState::Preparing&&worker.state==Vpn::ConnectionState::Error,"refusal/error reaches terminal state");
  require(worker.activations==0,"unconfirmed cleanup never activates protocol");
 }else{require(controller.errorSignals==0,"confirmed cleanup does not notify error");require(!worker.m_migrationTeardownRecoveryRequired&&!worker.m_migrationTeardownContext,"confirmed cleanup has no recovery latch or pending context");}
 QCoreApplication::sendPostedEvents(nullptr,QEvent::DeferredDelete);
 std::printf("actual restored-session callback scenario %s PASS\n",argv[1]);
}

#include "restored_fixture.moc"
"""
for marker,actual in [('ACTUAL_COMPLETION',completion),('ACTUAL_ACTIVATION',activation),('ACTUAL_CACHE',cache),('ACTUAL_UI_ERROR',ui_error),('ACTUAL_RECONNECT',reconnect),('ACTUAL_MISSING',missing)]:
 assert cpp.count(marker)==1;cpp=cpp.replace(marker,actual)
a.output.write_text(cpp,encoding='utf8')
