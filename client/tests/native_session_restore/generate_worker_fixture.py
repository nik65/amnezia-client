"""Compile actual worker register/consume methods with explicit inert seams."""
from pathlib import Path
import sys
root, output = map(Path, sys.argv[1:3])
text = (root / 'vpnConnection.cpp').read_text()
parts = ['#include "worker_fixture.h"\n']
for name in ('registerNativeRestore', 'invalidateNativeRestore',
             'observeUnboundNativeSession', 'observeEmptyNativeServiceState', 'adoptNativeRestore'):
    start = text.index('void VpnConnection::' + name + '(')
    brace = text.index('{', start)
    end, depth = brace + 1, 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    parts.append(text[start:end] + '\n')
text=(root/'core/protocols/androidVpnProtocol.cpp').read_text()
start=text.index('void AndroidVpnProtocol::stop()')
brace=text.index('{',start)
end,depth=brace+1,1
while depth:
    depth += (text[end]=='{')-(text[end]=='}')
    end += 1
parts.append(text[start:end]+'\n')
for filename, signature in (
        ('platforms/android/android_controller.cpp','void AndroidController::flushRestoreServiceReady()'),
        ('vpnConnection.cpp','bool VpnConnection::rejectNativeRestoreConnect()'),
        ('core/controllers/connectionController.cpp','void ConnectionController::handleNativeRestoreConnectRefused('),
        ('ui/controllers/connectionUiController.cpp','void ConnectionUiController::onConnectionStateChanged(')):
    text=(root/filename).read_text()
    start=text.index(signature)
    brace=text.index('{',start)
    end,depth=brace+1,1
    while depth:
        depth += (text[end]=='{')-(text[end]=='}')
        end += 1
    parts.append(text[start:end]+'\n')
output.write_text(''.join(parts))
