#include <QCoreApplication>
#include <QDebug>
#include <QTimer>
#include <QObject>
#include <QPointer>
#include <QVector>
#include <cstdlib>
#include "core/utils/errorCodes.h"
using namespace amnezia;
namespace Vpn { enum ConnectionState { Error }; }
QString errorString(ErrorCode) { return {}; }
class VpnProtocol : public QObject {
 Q_OBJECT
public:
 ErrorCode m_lastError=ErrorCode::NoError;
 void setLastError(ErrorCode);
 void setConnectionState(Vpn::ConnectionState s){emit connectionStateChanged(s);}
signals:
 void protocolError(amnezia::ErrorCode);
 void connectionStateChanged(Vpn::ConnectionState);
};
#include "actual_setter.inc"
class Worker : public QObject {
 Q_OBJECT
signals:
 void vpnProtocolError(amnezia::ErrorCode);
 void connectionStateChanged(Vpn::ConnectionState);
};
static void require(bool b){if(!b)std::abort();}
int main(int argc,char**argv){
 QCoreApplication app(argc,argv);
 qRegisterMetaType<amnezia::ErrorCode>();
 qRegisterMetaType<Vpn::ConnectionState>();
 VpnProtocol protocol;Worker worker;QObject controller;
 ErrorCode cached=ErrorCode::NoError;QVector<ErrorCode> shown;QVector<int> order;
 // Production forwarding and queued-controller topology: cache error before UI Error.
 QObject::connect(&protocol,&VpnProtocol::protocolError,&worker,[&](ErrorCode e){emit worker.vpnProtocolError(e);});
 QObject::connect(&protocol,&VpnProtocol::connectionStateChanged,&worker,[&](Vpn::ConnectionState s){emit worker.connectionStateChanged(s);});
 QObject::connect(&worker,&Worker::vpnProtocolError,&controller,[&](ErrorCode e){cached=e;order.append(1);},Qt::QueuedConnection);
 QObject::connect(&worker,&Worker::connectionStateChanged,&controller,[&](Vpn::ConnectionState){shown.append(cached);order.append(2);},Qt::QueuedConnection);
 const auto drain=[&](){QCoreApplication::sendPostedEvents(nullptr,QEvent::MetaCall);};
 protocol.setLastError(ErrorCode::AmneziaServiceConnectionFailed);
 require(shown.isEmpty());drain();
 require(shown==QVector<ErrorCode>{ErrorCode::AmneziaServiceConnectionFailed});require(order==QVector<int>{1,2});
 protocol.setLastError(ErrorCode::NoError);drain();require(shown.size()==1);require(protocol.m_lastError==ErrorCode::NoError);
 cached=ErrorCode::NoError;order.clear();
 protocol.setLastError(ErrorCode::InternalError);drain();
 require(shown.size()==2&&shown.last()==ErrorCode::InternalError);require(order==QVector<int>{1,2});
 QPointer<VpnProtocol> dying=new VpnProtocol;int dyingStates=0;
 QObject::connect(dying.data(),&VpnProtocol::connectionStateChanged,&controller,[&](Vpn::ConnectionState){++dyingStates;});
 QObject::connect(dying.data(),&VpnProtocol::protocolError,&controller,[&](ErrorCode){delete dying.data();});
 dying.data()->setLastError(ErrorCode::InternalError);
 require(!dying&&dyingStates==0);
 QPointer<VpnProtocol> stateDying=new VpnProtocol;
 QObject::connect(stateDying.data(),&VpnProtocol::connectionStateChanged,&controller,[&](Vpn::ConnectionState){delete stateDying.data();});
 stateDying.data()->setLastError(ErrorCode::InternalError);
 require(!stateDying);
 qInfo()<<"PASS: actual setter, typed real Qt queued forwarding, nonzero cache before Error, reset does not notify, second code preserved";
}
#include "test.moc"
