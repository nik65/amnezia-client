# AWG control core: standalone staging

`control_service.{h,cpp}` provides all five service.py routes through a synchronous typed API. The caller supplies the actual transport peer, lowercase duplicate-free headers, body, authenticated client callback and optional clock. A non-migration path returns handled=false. Invalid migration requests return handled=true/status403 with no diagnostic secrets. The transport owner must add Content-Type application/json, Cache-Control no-store, exact Content-Length and reject duplicate HTTP framing headers. No HTTP server, Docker action, app integration or production switch is included.

RapidJSON SAX Reader owns grammar/UTF-8/escape validation. Its callbacks reject duplicate keys before inserting into json-c. RapidJSON ASCII Writer owns escaping, including UTF-16 pairs; only escape hex letter case is normalized to Python. Canonical objects use sorted UTF-8 keys, matching Unicode scalar order. Strict supported subset: signed int64, arrays, objects, booleans, null and Unicode strings; floats, lone UTF-16 surrogates, NUL object keys and excessive depth are rejected. These are deliberate fail-closed differences from Python, not universal JSON byte parity claims.

The private state directory must be owned by effective uid and mode0700; signer and SQLite DB must be private regular files. Signer is opened O_NOFOLLOW and checked Ed25519 against ready.json at bootstrap; PEM password prompts are disabled. The SQLite DB is created0600 without changing process-global umask. BEGIN IMMEDIATE serializes bootstrap and nonce/grant mutations; exceptions roll back before returning403. Commit plus directory fsync precedes200. Renewal nonces remain unique; failed authentication/grant-limit checks do not consume a nonce. Signatures remain real OpenSSL Ed25519, no test signer injected.

Dependencies: C++17, json-c, OpenSSL Crypto, SQLite3 and RapidJSON headers. The official Ubuntu rapidjson-dev1.1.0+dfsg2-7.2 package is extracted without installation at /home/ivano/amnezia-owned-builds/awg-control-deps; APT metadata and actual package SHA256 agree:5384b30b878b085e847fb50ca0af5a1fa740bb845c3e17b68e311098e87b366e. Root owns shared CMake integration; include its extracted/usr/include as SYSTEM.

Run diagnostics/python-native-deep-audit-20261020/control/run.sh (under dist/) for exact standalone build and both suites. Tests use private temporary files and ephemeral keys only, never release keys, Docker or network. Coverage includes actual Python/native canonical and HMAC bytes, actual Ed25519 signatures, all five routes, bootstrap retries across eight processes, concurrent renewal anti-replay, expired-state/expired-grant exceptions, stale handshakes, auth and grant-limit rollback, exact fields/types and malformed/duplicate/Unicode/numeric JSON. Historical Python remains unchanged. Independent review and runtime delivery are separate pending steps.


## Native control business logic adapter (2026-10-21)

New native-selected prepare now routes all five migration-control operations to
C++ ControlService through private --control-json. Python still owns HTTP/PID1
and the original authentication callback; absent native bundle retains legacy.
The production state root is fixed /migration; no caller directory/clock/seed is
accepted. Request256KiB/5s, body16KiB, JSON output16MiB are bounded separately.

Authentication is deferred at the core callback via an exception, forcing SQLite
rollback. Parent authenticates once and repeats the same request with verified
client ID; None preserves an already-sent HTTP error. At most two passes occur;
no token/PEM enters the frame and no Python business-logic fallback runs. The same
grants.sqlite3 is shared; no parallel journal or state store was introduced.

Startup captures the exact validated static ELF into sealed memfd. Both control
containers receive the same read-only helper and expected SHA; pure capability
checks reject an old helper before preparation/listener setup. Pre-ready checks
bind actual Python PID1/start time, source pair and retained sealed FD bytes/hash.
Existing native-generation maintenance now explicitly HOLDs before recipe/runner
operations; blocked transaction-journal/FLOCK and collector bootstrap are untouched.

Confirmed control state size defect fixed:6000 valid peers have source522911B,
native quick553255B, ready1245098B. Native formerly403 where Python200; only ready
read/parse grows to8MiB, with exactcap/+1/no-new-grant regression. Request/canonical,
signer and handshake limits remain. Windows legacy import/tests are preserved by
loading fcntl only for explicit Linux native capture.

Final standalone CTest47/47; control runtime unit53 checks, private business bridge8,
wiring10, CLI26, Windows legacy22, separate maintenance24 pass. Actual Ed25519/SQLite
tests use ephemeral owned data; prepare/Docker/proc metadata are inert. The static
capture fixture does not execute, and the dynamic business fixture is manually
sealed/test-only. Real container PID1/listener/loaded-FD acceptance is still pending.
No app/version/release/static-delivery build, install, publication, production or
host VPN/app/service/network operations occurred. Evidence:
dist/diagnostics/python-native-control-20261021/.
