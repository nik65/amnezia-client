"""Extract actual allocation/ownership fragments without app or JNI."""
from pathlib import Path
import sys

source, template, output = map(Path, sys.argv[1:4])
text=source.read_text(encoding='utf-8')
start=text.index('#elif defined Q_OS_ANDROID',text.index('void VpnConnection::connectToVpn('))
end=text.index('#elif defined Q_OS_IOS',start)
fresh=text[start:end].split('\n',1)[1]
start=text.index('void VpnConnection::createAndroidConnections()')
brace=text.index('{',start)
end=text.index('\n\n',brace)
connections_prefix=text[start:end]+'\n}'
start=text.index('AndroidVpnProtocol *VpnConnection::createDefaultAndroidVpnProtocol()')
brace=text.index('{',start)
end,depth=brace+1,1
while depth:
    depth += (text[end]=='{')-(text[end]=='}')
    end += 1
factory=text[start:end]
assert 'm_vpnProtocol.reset(androidVpnProtocol);' in fresh
assert 'androidVpnProtocol = createDefaultAndroidVpnProtocol();' in connections_prefix
assert 'return new AndroidVpnProtocol(m_vpnConfiguration);' in factory
rendered=template.read_text(encoding='utf-8')
for key,value in [('ACTUAL_FRESH',fresh),('ACTUAL_CONNECTIONS_PREFIX',connections_prefix),('ACTUAL_FACTORY',factory)]:
    assert rendered.count(key)==1
    rendered=rendered.replace(key,value)
output.write_text(rendered,encoding='utf-8')
