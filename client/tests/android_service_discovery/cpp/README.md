# Pure C++ discovery/admission contract

This target compiles the maintained header directly against QtCore 6.10.1. It
performs 92 checks of the strict bounded six-key discovery/five-key admission
wire, generation/UUID correlation, ACK ordering, synchronous lifecycle floor,
one-shot reservation/final dispatch, component matching, two repeated-use
cycles, exact wrapper/epoch ledger, missing outcomes and authoritative late
callbacks. Its one joined thread tests a received lifecycle floor before final
worker admission; it is not a stress or whole-application race proof.

Configure from WSL:

```
cmake -S /mnt/c/Users/ivano/PycharmProjects/amnezia-client/client/tests/android_service_discovery/cpp -B /mnt/c/Users/ivano/PycharmProjects/amnezia-client/dist/diagnostics/android-service-discovery-20261021/cpp/helper/build -DCMAKE_PREFIX_PATH=/home/ivano/Qt/6.10.1/gcc_64
cmake --build /mnt/c/Users/ivano/PycharmProjects/amnezia-client/dist/diagnostics/android-service-discovery-20261021/cpp/helper/build
ctest --test-dir /mnt/c/Users/ivano/PycharmProjects/amnezia-client/dist/diagnostics/android-service-discovery-20261021/cpp/helper/build --output-on-failure
```

No JNI, Android framework, service, device, native VPN backend or application is
built or invoked. The coordinator never clears the separate native-session or
cleanup704 authority; integration must check those existing gates first.
Process-only Grant is deliberately not deserialized from configuration.

The additional classifier fixture extracts androidDiscoveryComponent directly
from current vpnConnection.cpp at CMake configure time; its generated receipt
pins source and fragment hashes. It tests AWG/WireGuard/OpenVPN/Xray/SSXray in
both cases and unknown/missing/wrong-type input. Extraction Python is test-only,
not a working application dependency. The helper additionally rejects unknown
reconnect components before any caller teardown decision.

Limits: authorizeStart closes the C++ one-shot grant immediately before JNI, but
the helper mutex cannot serialize the subsequent external Java invocation with
an independent Activity lifecycle event. Java must perform its specified final
generation/service-admission check. This fixture proves no framework lifecycle,
route side effect, native absence or device-wide exclusivity. Worker/controller
actual-source integration and exact rejection/UI behavior need separate tests.

Actual Kotlin serializer interoperability:

```
android_service_discovery_contract --corpus DISCOVERY_JSONL ADMISSION_JSONL
```

Alternatively configure `-DDISCOVERY_CORPUS=/absolute/discovery-snapshots.jsonl`
and `-DADMISSION_CORPUS=/absolute/admission-snapshots.jsonl`; CTest then adds the
interop test. This mode bounds each row, runs the production decoders, requires
exact 6/5 keys and 8/6 current fixture rows, and prints input SHA-256. It reads the
producer's corpus directly without copying it. Current actual producer corpus
passed 33 assertions; ordinary helper/classifier mode retains 92 assertions.
