# Restored-session error and refusal regression

Standalone QtCore harness extracts actual VpnConnection disconnect completion, missing-owner branch, activation refusal and reconnect completion; actual ConnectionController queued reason-cache callback and ConnectionUiController Error switch branch. It includes actual MigrationTeardownContext, real errorCodes enum/MOC and real errorStrings implementation. It never starts the app, connects a device/network, changes a native tunnel or launches an installer.

Eleven cases cover reason before Error, terminal refusal with no protocolstart, preserved pending context/recovery latch, confirmed cleanup without error, stale/wrong nonce/epoch, failed routesreceipt, missing protocolowner, and confirmed/unconfirmed reconnectcompletion. Frozen diagnostic RED is retained separately under dist/diagnostics/android-restored-session-20261021. Maintained baseline comparison may override AUDIT_VPN_SOURCE with a reviewed exact source snapshot; enum and error strings remain current.

Configure this directory as its own CMakeproject with Qt6 Core/CoreTools. Set RESTORED_SESSION_SANITIZERS=ON for ASAN+UBSAN (GCC/Clang). Run CTest. Linux Qt6.10.1 reference check: configure/build0,11/11GREEN; baseline VPNsource9/11RED,2confirmedcasesPASS; ASAN/UBSAN/LSAN no diagnostics. Fixture generation tracks source dependencies so cmake--build refreshes actual extracted callbacks.

Explicit seams: fake protocolowner, native receipt data, initial missing sessionnonce, manual context.expire instead of9secondwait, inert terminal UIstateassignment and protocolstartcounter. No actualAndroid/JNI worker/sessionbinding acceptance is claimed. The new704message is currently English until translated normally.

This patch fixes erroneous NoError notification and permanent Preparing on a refused activation. It deliberately does not restore missing native sessionnonce, authorize a secondtunnel, clear safety latches, or change native attestation.


Independent review correction: a refused activation during an already active cleanup returns to Disconnecting without emitting an error. Actual VpnConnection::onConnectionStateChanged(Error) repeats route/DNS cleanup; avoiding that Error branch prevents introducing those effects while cleanup is pending. The harness does not execute real route/DNS side effects. Both pending cases verify unchanged context, epoch and retained owner, no activation and no error before the receipt. Expiration then delivers typed reason before terminal Error; a matching confirmed receipt finishes Disconnected without error. Recovery latch refusal after a completed failedcleanup still produces typed terminal Error. Generator source reads explicitly use UTF-8 for Windows portability.
