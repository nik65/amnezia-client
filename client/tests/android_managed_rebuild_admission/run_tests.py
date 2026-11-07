"""Compile actual managed-rebuild and Qt admission wiring, no app/device actions."""
from pathlib import Path
import argparse,subprocess,os,json,hashlib
p=argparse.ArgumentParser();p.add_argument('--source-root',type=Path,required=True);p.add_argument('--repo',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=True)
root=a.source_root.resolve();repo=a.repo.resolve()
def method(text,signature):
 i=text.index(signature);b=text.index('{',i);e=b+1;depth=1
 while depth:depth+=(text[e]=='{')-(text[e]=='}');e+=1
 return text[i:e]
v=(root/'client/vpnConnection.cpp').read_text();ui=(root/'client/ui/controllers/connectionUiController.cpp').read_text();core=(root/'client/core/controllers/coreSignalHandlers.cpp').read_text()
flush=method(v,'void VpnConnection::flushManagedRouteReconnect()');classifier=method(v,'static QString androidDiscoveryComponent(')
# A forward declaration can precede the definition; select the actual definition.
if ';' in classifier.split('{',1)[0]:classifier=method(v[v.index('static QString androidDiscoveryComponent(',v.index('static QString androidDiscoveryComponent(')+1):],'static QString androidDiscoveryComponent(')
ui_start=ui.index('    connect(m_connectionController, &ConnectionController::serviceDiscoveryBlocked');ui_end=ui.index(';',ui_start)+1;ui_wire=ui[ui_start:ui_end]
core_start=core.index('void CoreSignalHandlers::initErrorMessagesHandler()');core_start=core.index('{',core_start)+1;core_end=core.index('    connect(m_coreController->m_subscriptionUiController',core_start);core_wire=core[core_start:core_end]
wake_start=v.index('void VpnConnection::serviceDiscoveryChanged(');wake_end=v.index('    if (!m_discoveryReconnectStart) return;',wake_start);wake=v[wake_start:wake_end];i=wake.find('    if (m_managedRouteReconnectGate.pending()');wake=wake[i:] if i>=0 else ''
marker='    // Rebind discovery only after exact accepted native restoration'
rebind=v[v.index(marker):v.index('    if (NativeSessionRestore::isDnsSnapshot(checked))',v.index(marker))] if marker in v else ''
fixture=r"""
#include <QCoreApplication>
#include <QObject>
#include <QDebug>
#include <QStringList>
#include <limits>
#include <cstdio>
#define Q_OS_ANDROID 1
#include "core/utils/androidServiceDiscovery.h"
#include "core/utils/managedDnsConvergence.h"
#include "core/utils/errorCodes.h"
using namespace amnezia;
using ErrorCode=amnezia::ErrorCode;
namespace Vpn {enum class ConnectionState{Connected,Disconnected};}
class ConnectionController:public QObject {Q_OBJECT
public:int forced=0;Vpn::ConnectionState state=Vpn::ConnectionState::Connected;
 void setConnectionState(Vpn::ConnectionState s){forced++;state=s;}
signals:void serviceDiscoveryBlocked(ErrorCode);
};
class ConnectionUiController:public QObject {Q_OBJECT
public:void wire(ConnectionController *m_connectionController){UI_WIRE}
 void notifyConnectionBlocked(ErrorCode);
signals:void connectionErrorOccurred(ErrorCode);void connectionAdmissionBlocked(ErrorCode);void unsupportedConnectDrawerRequested();void noInstalledContainers();
};
struct PageController{int errors=0;ErrorCode last=ErrorCode::NoError;void showErrorMessage(ErrorCode e){errors++;last=e;}};
struct Core{ConnectionUiController*m_connectionUiController;ConnectionController*m_connectionController;PageController*m_pageController;};
class CoreSignalHandlers:public QObject{public:Core*m_coreController;void wire(){CORE_WIRE}};
NOTIFY
CLASSIFIER
struct Clock{qint64 now=0;qint64 elapsed()const{return now;}};
struct Timer{int last=-1;void start(int n){last=n;}void stop(){last=-1;}};
struct LogicalReceiver{bool present=true;operator bool()const{return present;}void operator=(bool value){present=value;}QObject*data()const{return present?reinterpret_cast<QObject*>(1):nullptr;}};
class VpnConnection {
public:
 managedDnsConvergence::ReconnectGate m_managedRouteReconnectGate;
 Clock m_managedRouteReconnectClock;Timer m_managedRouteReconnectCooldownTimer;
 Vpn::ConnectionState m_connectionState=Vpn::ConnectionState::Connected;
 QString m_serverId="synthetic-server";bool m_managedRouteReconnectAwaitingBase=false,m_hasAuthoritativeManagedRouteBase=true;
 bool m_migrationTeardownContext=false,m_migrationTeardownRecoveryRequired=false,m_unboundNativeSessionObserved=false;LogicalReceiver m_vpnProtocol;
 QJsonObject m_vpnConfiguration{{"protocol","awg"}};
 int m_preparedManagedRouteMode=0;QStringList m_preparedManagedRoutes,m_preparedLocalSites;QString m_preparedManagedRoutePolicyRevision,m_preparedManagedRoutePolicyContentHash;
 int floors=0,nativeCalls=0,refusals=0;bool applied=false,revokeAtNativeBoundary=false;quint64 m_connectionEpoch=1,m_discoveryObservationEpoch=1;quintptr m_discoveryObservationReceiver=1;QString m_discoveryObservationServerId="synthetic-server",m_discoveryRegisteredId="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
 static constexpr qint64 managedRouteReconnectMinimumIntervalMs=7200000;
 VpnConnection(){m_managedRouteReconnectGate.beginSession(m_serverId);m_managedRouteReconnectGate.request(m_serverId,0,managedRouteReconnectMinimumIntervalMs);}
 bool latestPreparedManagedRouteSnapshotIsApplied(){return applied;}
 template<class...T>void publishManagedRouteBase(T...){}
 void recordReconnectFloor(){floors++;m_managedRouteReconnectGate.recordReconnect(m_serverId,m_managedRouteReconnectClock.elapsed());}
 void reconnectToVpn(){if(revokeAtNativeBoundary)AndroidServiceDiscovery::coordinator.invalidate();if(AndroidServiceDiscovery::coordinator.canReconnect("AWG")){nativeCalls++;recordReconnectFloor();++m_connectionEpoch;}else refusals++;}
 void flushManagedRouteReconnect();
 void captureNativeDiscoveryOwner(){m_discoveryObservationEpoch=m_connectionEpoch;m_discoveryObservationReceiver=quintptr(m_vpnProtocol.data());m_discoveryObservationServerId=m_serverId;}
 void acceptExactNativeRestore(){const auto priorRestoreEpoch=m_connectionEpoch;const auto serverId=m_serverId;++m_connectionEpoch;m_vpnProtocol=true;REBIND}

 void freshDiscovery(const QJsonObject&snapshot){if(snapshot!=AndroidServiceDiscovery::coordinator.snapshot())return;WAKE}
};
FLUSH
int checks=0,failures=0;
void expect(bool ok,const char*label){checks++;if(!ok){failures++;fprintf(stderr,"FAIL %s\n",label);}}
QJsonObject activeProof(){static quint64 gen=10000;const QString id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";AndroidServiceDiscovery::coordinator.registerRefresh(id);AndroidServiceDiscovery::coordinator.acknowledge(id);QJsonObject proof{{"schema",1},{"requestId",id},{"generation",QString::number(++gen)},{"phase","BOUND_NATIVE"},{"component","AWG"},{"reason","NONE"}};expect(AndroidServiceDiscovery::coordinator.ingest(proof),"fresh active owner proof");return proof;}
int main(int argc,char**argv){QCoreApplication app(argc,argv);
 ConnectionController controller;ConnectionUiController ui;PageController page;Core core{&ui,&controller,&page};CoreSignalHandlers hooks;hooks.m_coreController=&core;ui.wire(&controller);hooks.wire();
 emit controller.serviceDiscoveryBlocked(ErrorCode::ServiceDiscoveryUnconfirmed);
 expect(page.errors==1&&page.last==ErrorCode::ServiceDiscoveryUnconfirmed,"real admission705 remains visible");
 expect(controller.state==Vpn::ConnectionState::Connected&&controller.forced==0,"admission refusal must not fabricate native Disconnected");
 emit ui.connectionErrorOccurred(ErrorCode::InternalError);
 expect(page.errors==2&&controller.state==Vpn::ConnectionState::Disconnected&&controller.forced==1,"real generic failure handling preserved");
 AndroidServiceDiscovery::coordinator.invalidate();NativeSessionRestore::ingress.invalidate();VpnConnection w;
 w.flushManagedRouteReconnect();expect(w.m_managedRouteReconnectGate.pending()&&w.floors==0&&w.nativeCalls==0&&w.refusals==0,"background rebuild retains desired state and untouched cooldown without refusal");
 auto snapshot=activeProof();w.freshDiscovery(snapshot);expect(w.nativeCalls==1&&w.floors==1&&!w.m_managedRouteReconnectGate.pending(),"fresh active discovery resumes exactly one pending rebuild");
 w.freshDiscovery(snapshot);expect(w.nativeCalls==1&&w.floors==1,"same discovery cannot duplicate rebuild");
 w.m_managedRouteReconnectClock.now=1;w.m_managedRouteReconnectGate.request(w.m_serverId,1,w.managedRouteReconnectMinimumIntervalMs);w.freshDiscovery(snapshot);
 expect(w.nativeCalls==1&&w.m_managedRouteReconnectGate.pending()&&w.m_managedRouteReconnectCooldownTimer.last==7199999,"existing two hour cooldown remains authoritative");
 w.m_managedRouteReconnectClock.now=7200000;auto dueProof=activeProof();w.captureNativeDiscoveryOwner();w.freshDiscovery(dueProof);expect(w.nativeCalls==2&&w.floors==2,"due fresh-authority rebuild runs after cooldown");
 for(int fault=0;fault<4;fault++){activeProof();VpnConnection h;if(fault==0)h.m_migrationTeardownContext=true;if(fault==1)h.m_migrationTeardownRecoveryRequired=true;if(fault==2)h.m_unboundNativeSessionObserved=true;if(fault==3)h.m_vpnProtocol=false;h.flushManagedRouteReconnect();expect(h.floors==0&&h.nativeCalls==0&&h.m_managedRouteReconnectGate.pending(),"held native cleanup or observed owner never consumes rebuild");}
 auto ownerProof=activeProof();VpnConnection observer;observer.m_vpnProtocol=false;observer.captureNativeDiscoveryOwner();observer.freshDiscovery(ownerProof);expect(observer.nativeCalls==0&&observer.m_managedRouteReconnectGate.pending(),"read-only observed active owner cannot rebuild before exact worker restoration");observer.acceptExactNativeRestore();observer.freshDiscovery(ownerProof);expect(observer.nativeCalls==1&&!observer.m_managedRouteReconnectGate.pending(),"restored actual worker resumes pending desired routes under current proof");
 auto epochProof=activeProof();VpnConnection oldEpoch;++oldEpoch.m_connectionEpoch;oldEpoch.freshDiscovery(epochProof);expect(oldEpoch.nativeCalls==0&&oldEpoch.floors==0&&oldEpoch.m_managedRouteReconnectGate.pending(),"current snapshot from stale worker epoch cannot wake rebuild");
 oldEpoch.captureNativeDiscoveryOwner();oldEpoch.freshDiscovery(epochProof);expect(oldEpoch.nativeCalls==1&&!oldEpoch.m_managedRouteReconnectGate.pending(),"new correlated worker observation can wake retained desired routes");
 activeProof();VpnConnection raced;raced.revokeAtNativeBoundary=true;raced.flushManagedRouteReconnect();expect(raced.floors==0&&raced.nativeCalls==0&&raced.refusals==1&&raced.m_managedRouteReconnectGate.pending(),"revoked authority at final native boundary preserves pending rebuild and cooldown");
 auto renewed=activeProof();raced.revokeAtNativeBoundary=false;raced.freshDiscovery(renewed);expect(raced.nativeCalls==1&&raced.floors==1&&!raced.m_managedRouteReconnectGate.pending(),"correlated renewed discovery retries previously revoked authority exactly once");
 AndroidServiceDiscovery::coordinator.invalidate();VpnConnection stale;stale.freshDiscovery(snapshot);expect(stale.nativeCalls==0&&stale.m_managedRouteReconnectGate.pending(),"stale discovery cannot resume rebuild");
 fprintf(stderr,"actual managed admission checks=%d failures=%d\n",checks,failures);return failures?1:0;}
#include "test.moc"
""".replace('UI_WIRE',ui_wire).replace('CORE_WIRE',core_wire).replace('NOTIFY',method(ui,'void ConnectionUiController::notifyConnectionBlocked(')).replace('CLASSIFIER',classifier).replace('WAKE',wake).replace('FLUSH',flush).replace('REBIND',rebind)
(a.output/'test.cpp').write_text(fixture)
(a.output/'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.25)\nproject(ActualAdmission LANGUAGES CXX)\nset(CMAKE_AUTOMOC ON)\nfind_package(Qt6 REQUIRED COMPONENTS Core)\nadd_executable(actual test.cpp \"'+(repo/'client/core/utils/errorCodes.h').as_posix()+'\")\ntarget_include_directories(actual PRIVATE "'+(repo/'client').as_posix()+'")\ntarget_compile_features(actual PRIVATE cxx_std_17)\ntarget_link_libraries(actual PRIVATE Qt6::Core)\nenable_testing()\nadd_test(NAME actual_admission COMMAND actual)\n')
(a.output/'source_receipt.json').write_text(json.dumps({'root':str(root),'actual_code_extracted':True,'sources':{f:hashlib.sha256((root/f).read_bytes()).hexdigest() for f in ['client/vpnConnection.cpp','client/ui/controllers/connectionUiController.cpp','client/core/controllers/coreSignalHandlers.cpp']}},indent=2)+'\n')
print('Actual native admission + Qt wiring fixture generated')
