"""Generate an isolated Qt harness from production gateway context methods.
No application, daemon, installer or network operations. CMake compiles/runs it.
"""
from pathlib import Path
import argparse
parser=argparse.ArgumentParser()
parser.add_argument('--source-root',type=Path,default=Path(__file__).resolve().parents[3])
parser.add_argument('--output',type=Path,required=True)
parser.add_argument('--baseline',action='store_true',help='Reproduce pre-fix mismatch; source-root must point to old source')
args=parser.parse_args()
ROOT=args.source_root.resolve()
out=args.output.resolve()
out.mkdir(parents=True,exist_ok=True)
fixed=not args.baseline
src=(ROOT/'client/vpnConnection.cpp').read_text(encoding='utf8')
def extract(sig):
    i=src.index(sig); b=src.index('{',i); depth=0
    for j in range(b,len(src)):
        if src[j]=='{': depth+=1
        if src[j]=='}':
            depth-=1
            if depth==0:return src[i:j+1]
funcs='\n'.join(extract(x) for x in ['QString VpnConnection::serverRoutingRulesSyncHost() const','QStringList VpnConnection::serverRoutingRulesSyncHosts() const'])
helper=extract('void VpnConnection::prepareNativeWireGuardGateway()') if fixed else 'void VpnConnection::prepareNativeWireGuardGateway() {}'
pre=r'''
#include <QCoreApplication>
#include <QJsonObject>
#include <QSharedPointer>
#include <QStringList>
#include <QDebug>
#include <cassert>
#include <cstdio>
namespace configKey {const auto dns1="dns1"; const auto dns2="dns2";const auto vpnProto="protocol";const auto hostName="hostName";const auto serverRoutingRulesSyncHost="sync";const auto clientLogs="clientLogs";}
enum class Proto{Awg,WireGuard,Other};
namespace ProtocolUtils {QString protoToString(Proto p){return p==Proto::Awg?"awg":p==Proto::WireGuard?"wg":"other";}}
namespace NetworkUtilities {int calls=0; QString getIPAddress(QString x){if(x=="fixture.example"){++calls;return "198.51.100.42";}if(x=="new.example"){++calls;return "198.51.100.43";}if(x=="bad.example"){++calls;return "";}return x;}}
namespace protocols {namespace serverRoutingRules {const auto syncHost="192.0.2.10";}namespace selfHostedUpdates{const auto syncHost="192.0.2.11";}namespace clientLogs{const auto syncHost="192.0.2.12";}}
QString serverRoutingRulesSyncHostFromConfig(const QJsonObject &c){return c.value("sync").toString().trimmed();}
struct Protocol {QString gateway;QString vpnGateway()const{return gateway;}};
struct VpnConnection {
 QJsonObject m_vpnConfiguration;QSharedPointer<Protocol> m_vpnProtocol;bool m_usesPreparedNativeGateway=false;QString m_preparedNativeGateway;
 void prepareNativeWireGuardGateway();QString serverRoutingRulesSyncHost() const;QStringList serverRoutingRulesSyncHosts() const;
};
'''
main=r'''
int main(int argc,char **argv){QCoreApplication app(argc,argv);const bool fixed=FIXED;
 VpnConnection v;v.m_vpnConfiguration={{"protocol","awg"},{"awg_config_data",QJsonObject{{"hostName","fixture.example"}}}};
 QStringList masks;int previousCalls=0;
 for(int epoch=1;epoch<=3;++epoch){
  v.prepareNativeWireGuardGateway();
  const auto construction=v.serverRoutingRulesSyncHosts();
  // New wrapper receives Connected before asynchronous nonempty native status.
  v.m_vpnProtocol=QSharedPointer<Protocol>::create();
  const auto published=v.serverRoutingRulesSyncHosts();
  auto nested=v.m_vpnConfiguration.value("awg_config_data").toObject();
  // Production startMzImpl resolves same nested value; activate sends it as native gateway.
  const auto nativeGateway=NetworkUtilities::getIPAddress(nested.value("hostName").toString());
  v.m_vpnProtocol->gateway=nativeGateway;
  const auto current=v.serverRoutingRulesSyncHosts();
  const auto mask=published==current?0:64;masks<<QString::number(mask);
  assert(mask==(fixed?0:64));
  if(fixed){assert(construction==published);assert(published==current);assert(current.contains(nativeGateway));assert(v.serverRoutingRulesSyncHost()==nativeGateway);}
 }
 if(fixed)assert(NetworkUtilities::calls==1);
 // New activation/config endpoint must change the protected context before wrapper status.
 v.m_vpnConfiguration["awg_config_data"]=QJsonObject{{"hostName","new.example"}};v.prepareNativeWireGuardGateway();
 if(fixed){assert(v.serverRoutingRulesSyncHosts().contains("198.51.100.43"));assert(!v.serverRoutingRulesSyncHosts().contains("198.51.100.42"));}
 v.m_vpnConfiguration["sync"]="192.0.2.33";v.prepareNativeWireGuardGateway();
 assert(v.serverRoutingRulesSyncHost()=="192.0.2.33");assert(v.serverRoutingRulesSyncHosts().contains("192.0.2.33"));
 v.m_vpnConfiguration.remove("sync");v.m_vpnConfiguration["awg_config_data"]=QJsonObject{{"hostName","bad.example"}};v.prepareNativeWireGuardGateway();
 if(fixed){assert(!v.serverRoutingRulesSyncHosts().contains("198.51.100.42"));assert(v.m_preparedNativeGateway.isEmpty());}
 v.m_vpnConfiguration["protocol"]="other";v.prepareNativeWireGuardGateway();
 assert(v.serverRoutingRulesSyncHosts().contains(v.m_vpnProtocol->gateway));
 printf("EXTRACTED_QT_HARNESS %s masks=%s PASS\n",fixed?"PATCHED":"BASELINE",masks.join(',').toUtf8().constData());
}
'''.replace('FIXED','true' if fixed else 'false')
(out/'test_gateway_context.cpp').write_text(pre+helper+'\n'+funcs+'\n'+main,encoding='utf8')
print('generated', 'patched.cpp' if fixed else 'baseline.cpp')

if fixed:
    connect=extract('void VpnConnection::connectToVpn(')
    assert connect.index('m_vpnConfiguration = vpnConfiguration') < connect.index('prepareNativeWireGuardGateway()') < connect.index('setConnectionState(Vpn::ConnectionState::Connecting)')
    failure=connect.index('m_usesPreparedNativeGateway && m_preparedNativeGateway.isEmpty()')
    factory=connect.index('VpnProtocol::factory(')
    assert failure<factory
    assert 'return;' in connect[failure:factory]
    append=extract('void VpnConnection::appendSplitTunnelingConfig()')
    assert '!m_usesPreparedNativeGateway || !m_preparedNativeGateway.isEmpty()' in append
    print('SOURCE_ORDER_AND_FAIL_CLOSED_GUARDS PASS')
