from pathlib import Path
s = (Path(__file__).resolve().parents[2] / "vpnConnection.cpp").read_text()
block = s.split("if (!baseMatches) {", 1)[1].split("} else if (normalizedExpectedOld == normalizedDesiredNew)", 1)[0]
assert block.count("managedRouteMismatchDiagnostic::describe(") == 1
assert block.count("managed-route base mismatch diagnostic schema=1") == 1
log = block.split('qWarning() << "VpnConnection: managed-route base mismatch diagnostic schema=1"', 1)[1]
assert all(x not in log for x in ["localSites", "protectedHosts", "expectedServerId", "normalizedExpectedOld", "PolicyContentHash", "m_vpnConfiguration"])
assert all(x in log for x in ["mismatchMask", "mismatchNames", "counts[0]", "counts[1]", "counts[2]", "desiredEqualsApplied"])
assert "desiredNewValid && m_hasAuthoritativeManagedRouteBase" in block
assert "expectedConnectionEpoch == m_authoritativeManagedRouteConnectionEpoch" in block
assert "expectedServerId == m_authoritativeManagedRouteServerId" in block
assert "requestedMode == m_authoritativeManagedRouteMode" in block
print("rejection-only producer privacy and unknown-binding guards PASS")
