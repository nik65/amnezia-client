# DNS fallback profile boundary

Standalone Qt Core C++ test; no application, installer, APK, network or VPN.
Compiles the real descriptor validator and actual `toJson`/`fromJson` bodies of
the self-hosted admin/user and native profiles. Only unrelated container parsing
and the format-version constant are inert seams; no fallback logic is copied.

Covers canonical enrollment, bounded fields, malformed/disabled credentials,
unsafe URL/endpoint forms, unknown launch parameters, per-profile isolation and
all three model roundtrips. CMake automatically regenerates model fixtures when
their actual declarations/implementations change.

The owner app is included for DNS health probes only in the existing explicit
application-allowlist mode. An application-exclusion list that names the owner
remains unchanged and disables the runtime fallback with
`owner_excluded_by_app_split`; no-enrollment, disabled, all-apps and unrelated
exclusion modes keep their application lists.

The live connection hook is Android-only. Non-enrolled profiles never get a
default server/key/UUID. A newly generated client share intentionally omits the
exporter's DNS identity until a distinct client is enrolled server-side; full
access and same-profile serialization preserve an explicit enrollment.
