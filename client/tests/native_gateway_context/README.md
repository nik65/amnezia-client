# Native gateway context regression

Standalone Qt Core test, executing production method bodies extracted at CMake configure time. Protocol wrapper and resolver are deterministic test doubles: the test cannot control the host VPN, contact a network, or launch the product.

Configure this directory with Qt6 Core on CMAKE_PREFIX_PATH; build and run ctest. Assertions remain enabled in Release. Covers Connected before nonempty status, repeated replacement wrappers, config/native gateway identity, one DNS lookup, fresh endpoint, explicit syncHost, failed resolution, nonAWG fallback and source ordering/fail-closed activation guards.

To reproduce old behavior, point NATIVE_GATEWAY_SOURCE_ROOT to a pre-fix source tree and set NATIVE_GATEWAY_REPRODUCE_BASELINE=ON. Baseline success means observed mismatches64/64/64; default patched mode requires0/0/0. Baseline source tree is external evidence, not included as a duplicated production snapshot.

This is selected-method lifecycle integration, not full worker/service or guest acceptance. Source-order guards cover the adjacent activation boundary; they do not execute protocol factory/start.
