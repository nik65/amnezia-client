from pathlib import Path
import sys
root=Path(sys.argv[1]);out=Path(sys.argv[2]);src=Path(sys.argv[3] if len(sys.argv)>3 else root/'client/vpnConnection.cpp').read_text(encoding='utf-8')
def method(needle):
 start=src.index(needle);begin=src.index('{',start);depth=0
 for end in range(begin,len(src)):
  if src[end]=='{':depth+=1
  elif src[end]=='}':
   depth-=1
   if depth==0:return src[start:end+1]
 raise ValueError(needle)
classifier=method('static QString androidDiscoveryComponent(')
entry=method('void VpnConnection::connectToVpn(')
marker='    beginManagedRouteReconnectSession(serverId);'
assert entry.count(marker)==1
entry=entry[:entry.index(marker)]+marker+'\n    fixtureStartedIndex=serverIndex;\n    fixtureStartedConfiguration=vpnConfiguration;\n    (void)startAdmission;\n}\n'
t=(Path(__file__).with_name('entry.cpp.in')).read_text(encoding='utf-8')
extra = '\n'.join(method('void VpnConnection::'+name+'(') for name in
    ('registerServiceDiscovery','serviceDiscoveryTimedOut','serviceDiscoveryChanged','awaitReconnectDiscovery','refreshReconnectDiscovery'))
disconnect = method('void VpnConnection::disconnectFromVpn(')
disconnect = disconnect[:disconnect.index('    const quint64 requestToken')] + '}\n'
out.write_text(t.replace('@CLASSIFIER@',classifier).replace('@ENTRY@',entry).replace('@REJECT@',method('bool VpnConnection::rejectNativeRestoreConnect(')).replace('@OBSERVATION@',extra+'\n'+disconnect),encoding='utf-8')
