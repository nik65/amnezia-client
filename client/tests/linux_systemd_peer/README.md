# Linux privileged-server identity

Standalone tests compile the real sd-bus transport, property policy and Linux
service-manager collector with QtCore/Network and official libsystemd headers.
They exercise typed negative policy facts and owned Unix socketpairs, never an
Amnezia process, real system bus, VM, installer or VPN.

The production direct executable check remains primary. Only native readlink
EACCES/EPERM on a root connected peer permits the alternative system-manager
path. It connects to fixed /run/dbus/system_bus_socket under protected root
directories, verifies the real system manager unique owner UID0/PID1, exact
packaged AmneziaVPN.service, current MainPID/ExecStart/invocation/no-job state,
protected binary/unit and unchanged final readback. No environment-selected bus,
shell command or caller-supplied manager facts authorize a peer.

All connect/auth/Hello and method operations share one 1.5-second monotonic
deadline using nonblocking Unix sockets, asynchronous sd-bus requests and poll.
Scheduling and millisecond poll rounding can add small overrun; this is not a
hard real-time guarantee. Cleanup cancels callback slots and closes without
blocking flush. The transport never uses synchronous sd_bus_call.

This is root-administrator/service-manager attribution, analogous to Windows
SCM, rather than proof of a readable current /proc executable. It does not
defend against a malicious root administrator replacing the trusted service.
Custom units, overrides and alternate install paths fail closed.

Build dependency: pkg-config libsystemd >=246, Linux desktop only; Android,
Windows and macOS retain their previous dependencies and authorization paths.
The fallback requires connected-peer SO_PEERPIDFD (Linux >=6.5). Older kernels
retain direct executable authentication but reject this alternative with an
explicit unsupported reason. No universal older-kernel compatibility is claimed.

Configure this directory with CMAKE_PREFIX_PATH pointing at the existing Qt
development prefix, build its focused target, then run ctest. If using extracted
official development packages, point PKG_CONFIG_LIBDIR/SYSROOT at that extraction.
No application or release package is built by this test project.
