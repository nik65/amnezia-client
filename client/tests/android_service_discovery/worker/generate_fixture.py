from pathlib import Path
import sys
root=Path(sys.argv[1]); target=Path(sys.argv[2])
source=Path(sys.argv[3]).read_text(encoding='utf-8') if len(sys.argv)>3 else (root/'client/vpnConnection.cpp').read_text(encoding='utf-8')
names=['registerServiceDiscovery','serviceDiscoveryTimedOut','refuseServiceDiscovery','serviceDiscoveryChanged','awaitReconnectDiscovery','armStartAdmission','handleStartAdmission']
if 'void VpnConnection::refreshReconnectDiscovery(' in source:
 names += ['refreshReconnectDiscovery']
def extract(name, text=source, owner='VpnConnection'):
 source=text
 start=source.index('void '+owner+'::'+name+'('); begin=source.index('{',start); depth=0
 for end in range(begin,len(source)):
  if source[end]=='{': depth+=1
  elif source[end]=='}':
   depth-=1
   if not depth:return source[start:end+1]
 raise RuntimeError(name)
extra='\n\n'.join([extract('handleServiceDiscoveryConnectRefused',(root/'client/core/controllers/connectionController.cpp').read_text(encoding='utf-8'),'ConnectionController'),extract('notifyConnectionBlocked',(root/'client/ui/controllers/connectionUiController.cpp').read_text(encoding='utf-8'),'ConnectionUiController'),extract('onConnectionStateChanged',(root/'client/ui/controllers/connectionUiController.cpp').read_text(encoding='utf-8'),'ConnectionUiController')])
text=(Path(__file__).with_name('fixture.cpp.in')).read_text(encoding='utf-8')
assert text.count('@METHODS@')==1
target.write_text(text.replace('@METHODS@','\n\n'.join(extract(n) for n in names)+'\n\n'+extra),encoding='utf-8')
