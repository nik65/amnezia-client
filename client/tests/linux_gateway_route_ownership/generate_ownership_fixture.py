from pathlib import Path
ROOT=Path(__file__).resolve().parent
REPOSITORY=ROOT.parents[1]
SOURCE=REPOSITORY/'platforms/linux/daemon/linuxroutemonitor.cpp'
def body(source,signature):
 start=source.index(signature);opening=source.index('{',start);depth=0
 for i in range(opening,len(source)):
  if source[i]=='{':depth+=1
  elif source[i]=='}':
   depth-=1
   if depth==0:return source[start:i+1]
 raise RuntimeError('unclosed production function')
s=SOURCE.read_text();names=['bool LinuxRouteMonitor::addExclusionRoute','LinuxRouteMonitor::EndpointRouteResult\nLinuxRouteMonitor::createEndpointRoute','LinuxRouteMonitor::EndpointRouteResult\nLinuxRouteMonitor::acquireGatewayRoute','LinuxRouteMonitor::EndpointRouteResult\nLinuxRouteMonitor::removeOwnedEndpointRoute','LinuxRouteMonitor::EndpointRouteResult\nLinuxRouteMonitor::releaseGatewayRoute','bool LinuxRouteMonitor::deleteExclusionRoute']
parts='\n\n'.join(body(s,n) for n in names)
parts+='\n'+body((SOURCE.parent/'wireguardutilslinux.cpp').read_text(),'bool WireguardUtilsLinux::cleanupEndpointRoute')
ack=body(s,'LinuxRouteMonitor::EndpointRouteResult LinuxRouteMonitor::rtmSendRoute')
start=ack.index('if (error->error == 0)')
end=ack.index('return EndpointRouteResult::Failed;',start)+len('return EndpointRouteResult::Failed;')
parts+='\nLinuxRouteMonitor::EndpointRouteResult productionAckClassification(int code, int action=RTM_DELROUTE) { struct Error {int error;} value{code}; const auto* error=&value; using EndpointRouteResult=LinuxRouteMonitor::EndpointRouteResult;\n'+ack[start:end]+'\n}\n'

header=SOURCE.with_suffix('.h').read_text()
prefix=(ROOT/'harness_prefix.cpp').read_text()
for signature in ('enum class EndpointRouteResult','enum class GatewayRouteOwner','struct EndpointRouteReceipt','struct GatewayRouteState'):
 prefix=prefix.replace(body(prefix,signature)+';',body(header,signature)+';',1)
wireguard_header=(SOURCE.parent/'wireguardutilslinux.h')
prefix=prefix.replace(body(prefix,'struct EndpointRouteState')+';',body(wireguard_header.read_text(),'struct EndpointRouteState')+';',1)
(Path(__import__('sys').argv[1]) if len(__import__('sys').argv)>1 else ROOT/'generated_regression.cpp').write_text(prefix+'\n'+parts+'\n'+(ROOT/'harness_tests.cpp').read_text())
print('Extracted seven exact production bodies and actual production state declarations; no product or test compilation performed')
