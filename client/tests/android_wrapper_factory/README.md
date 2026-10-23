# Android wrapper ownership regression

This standalone C++ test extracts the actual fresh Android connection branch,
actual factory method and actual allocation prefix of createAndroidConnections.
An inert wrapper counts construction/destruction; std::unique_ptr models the
owning reset slot. Qt subscriptions, the real protocol class, application, JNI,
native backend and VPN are not built or executed.

Exactly one wrapper must be constructed and destroyed. Set
`WRAPPER_FACTORY_SANITIZERS=ON` for ASAN/UBSAN/LSAN. `AUDIT_VPN_SOURCE` can point
to a preserved original source to reproduce the double-allocation leak.

Discovery integration adds an inert armStartAdmission(int) seam and local grant
placeholder to compile the unchanged extracted allocation fragment. No admission
behavior is claimed by this lifetime-only target.
