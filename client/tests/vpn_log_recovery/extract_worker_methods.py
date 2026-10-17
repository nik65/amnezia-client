"""Compile the current production worker methods with inert dependencies.

No Python behavior model: tests execute the bodies from vpnConnection.cpp.
Routing normalization and network validation are actual production helpers.
IPC mutation and protocol restart remain named test doubles.
"""
import pathlib
import sys

signatures = (
    "QStringList VpnConnection::normalizedManagedRoutesForRuntime(",
    "void VpnConnection::invalidateAuthoritativeManagedRouteBase()",
    "void VpnConnection::publishManagedRouteBase(",
    "void VpnConnection::prepareManagedRouteConnectionSnapshot(",
    "void VpnConnection::scheduleManagedRouteReconnect(",
    "void VpnConnection::flushManagedRouteReconnect()",
    "bool VpnConnection::latestPreparedManagedRouteSnapshotIsApplied() const",
    "void VpnConnection::reconcileManagedSplitTunnelRoutes(",
)
source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "managed_route_semantic_context"))
from production_helpers import routing_helpers
network = (pathlib.Path(sys.argv[1]).parent / "core/utils/networkUtilities.cpp").read_text(encoding="utf-8")
functions = [routing_helpers(source, network)]
for signature in signatures:
    start = source.index(signature)
    brace = source.index("{", start)
    depth = 0
    for index in range(brace, len(source)):
        depth += (source[index] == "{") - (source[index] == "}")
        if depth == 0:
            functions.append(source[start:index + 1])
            break
    else:
        raise ValueError(f"Unterminated method: {signature}")
pathlib.Path(sys.argv[2]).write_text("\n\n".join(functions), encoding="utf-8")
