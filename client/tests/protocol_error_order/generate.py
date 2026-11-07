import pathlib,sys,re
root=pathlib.Path(sys.argv[1]);text=(root/'core/protocols/vpnProtocol.cpp').read_text()
setter=text.split('void VpnProtocol::setLastError(ErrorCode lastError)\n',1)[1].split('\nErrorCode VpnProtocol::lastError()',1)[0]
worker=(root/'vpnConnection.cpp').read_text()
assert not re.search(r'setConnectionState\(Vpn::ConnectionState::Error\);\s*emit vpnProtocolError',worker),'state must not overtake its actionable error'
assert 'if (!m_vpnProtocol) {\n        emit vpnProtocolError(ErrorCode::InternalError);' in worker
pathlib.Path(sys.argv[2]).write_text('void VpnProtocol::setLastError(ErrorCode lastError)\n'+setter)

assert 'invalid server id" << serverId;\n        emit vpnProtocolError(ErrorCode::InternalError);\n        setConnectionState(Vpn::ConnectionState::Error);' in worker
for match in re.finditer(r'if \(!m_vpnProtocol\) \{\n( +)setConnectionState\(Vpn::ConnectionState::Error\);',worker):
 raise AssertionError('factory-null must publish InternalError before Error')
assert 'if (isCurrentDisconnect()) {\n            emit vpnProtocolError(ErrorCode::NativeTunnelCleanupUnconfirmed);\n            setConnectionState(Vpn::ConnectionState::Error);' in worker
