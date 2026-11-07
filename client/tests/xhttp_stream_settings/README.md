# XHTTP stream settings regression

Standalone Qt Core test, without application/installer builds or network effects.
The fixture extracts the actual production `buildStreamSettings` and its helpers;
it uses the production config structs and constants. No copy of the selection
logic is maintained in the test. Covers explicit/default modes, packet-up
header/cookie placement, TLS SNI, host/path, and raw transport isolation.

Configure this directory with CMake and a Qt6 Core prefix, build only
`xhttp_stream_settings_tests`, then run CTest. The original forced stream-one
implementation must fail the mode and packet placement checks.
