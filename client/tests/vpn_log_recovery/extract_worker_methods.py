"""Compile the current production worker methods with inert dependencies.

No Python behavior model: tests execute the bodies from vpnConnection.cpp.
IPC, normalization and protocol restart are replaced with named test doubles.
"""
import pathlib
import sys

signatures = (
    "void VpnConnection::invalidateAuthoritativeManagedRouteBase()",
    "void VpnConnection::publishManagedRouteBase(",
    "void VpnConnection::prepareManagedRouteConnectionSnapshot(",
    "void VpnConnection::scheduleManagedRouteReconnect(",
    "void VpnConnection::flushManagedRouteReconnect()",
    "bool VpnConnection::latestPreparedManagedRouteSnapshotIsApplied() const",
    "void VpnConnection::reconcileManagedSplitTunnelRoutes(",
)
source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
functions = []
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
