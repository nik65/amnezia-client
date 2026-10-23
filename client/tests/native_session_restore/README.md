# Android native-session restore source contract

This standalone QtCore target compiles the actual strict decoder, one-shot pending
token and MigrationTeardownContext header. A generated fixture extracts the actual
worker registration/invalidation/adoption/refusal methods from vpnConnection.cpp,
actual AndroidVpnProtocol::stop, AndroidController cache flush, and the actual
controller refusal-cache and UI-state callbacks. Explicit inert seams replace
repository/container definitions, JNI stop transport, final Android wrapper
creation and the UI network-manager cache API. It neither compiles the application
nor invokes JNI, sockets or a VPN.

Configure with Qt6 Core. `RESTORE_SANITIZERS=ON` enables ASAN/UBSAN for this target.
CTest covers malformed/duplicate/escaped JSON keys, byte and scalar bounds,
canonical identity, exact prepared config, challenge/epoch/one-shot worker
adoption, strict conditional-cleanup receipts and legacy receipt rejection.
It also checks observation-before-READY ordering, duplicate flush, stale local
lifecycle tickets and refusal through the actual guard/cache/UI functions without
changing the retained native owner or entering the worker Error cleanup path.
An optional executable argument names JSONL emitted by the actual Kotlin serializer
to test ordinary and escaped Unicode snapshot interoperability.

The fixture proves actual extracted component logic, not Android linkage or
runtime acceptance. The AndroidController JNI routes, ConnectionController
repository preparation, CoreSignalHandlers ordering and full VpnConnection
lifecycle still require source review; no smartphone or app build is authorized.
