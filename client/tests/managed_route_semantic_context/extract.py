"""Generate a production-backed no-mutation worker fixture, never copy logic.

Actual current routing helpers, network validation and reconciliation bodies are
compiled. Native mutation is a fatal tripwire: these tests prove only no-op
ownership/context decisions and never pretend that a native operation succeeded.
"""
from pathlib import Path
import sys


def function(text, signature):
    start = text.index(signature)
    brace = text.index('{', start)
    depth = 0
    for index in range(brace, len(text)):
        depth += (text[index] == '{') - (text[index] == '}')
        if depth == 0:
            return text[start:index + 1]
    raise ValueError(signature)


repo, output = map(Path, sys.argv[1:])
production = (repo / 'client/vpnConnection.cpp').read_text(encoding='utf-8')
network = (repo / 'client/core/utils/networkUtilities.cpp').read_text(encoding='utf-8')
fixture = (repo / 'client/tests/vpn_log_recovery/test_worker.cpp').read_text(encoding='utf-8').split('#include "production_methods.inc"')[0]
normalizer_start = fixture.index('    // Production normalization')
normalizer_end = fixture.index('    struct ManagedRouteRuntimeSnapshot', normalizer_start)
fixture = fixture[:normalizer_start] + '''
    QStringList normalizedManagedRoutesForRuntime(RouteMode, const QStringList&,
        const QVariantMap&, const QStringList&, bool*) const;
    ManagedRouteUpdateResult updateManagedSplitTunnelRoutes(RouteMode, const QStringList&,
        const QStringList&, const QVariantMap&) {
        qFatal("native mutation reached in semantic no-op reproducer");
        return ManagedRouteUpdateResult::RuntimeUncertain;
    }
''' + fixture[normalizer_end:]
from production_helpers import routing_helpers
helpers = routing_helpers(production, network)
methods = ('QStringList VpnConnection::normalizedManagedRoutesForRuntime(',
           'void VpnConnection::invalidateAuthoritativeManagedRouteBase()',
           'void VpnConnection::publishManagedRouteBase(',
           'void VpnConnection::prepareManagedRouteConnectionSnapshot(',
           'void VpnConnection::scheduleManagedRouteReconnect(',
           'void VpnConnection::flushManagedRouteReconnect()',
           'bool VpnConnection::latestPreparedManagedRouteSnapshotIsApplied() const',
           'void VpnConnection::reconcileManagedSplitTunnelRoutes(')
# Actual production helpers need Qt/policy includes from the fixture preamble.
position = fixture.index('// Inert dependencies')
output.write_text(fixture[:position] + helpers + '\n' + fixture[position:]
                  + '\n' + '\n'.join(function(production, signature) for signature in methods), encoding='utf-8')
