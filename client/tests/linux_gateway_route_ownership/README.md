# Linux gateway-route ownership regression

Standalone build: cmake -S client/tests/linux_gateway_route_ownership -B <owned-test-output> -DCMAKE_BUILD_TYPE=Release, then cmake --build <owned-test-output> -j1 and ctest --test-dir <owned-test-output> --output-on-failure.

The ownership executable compiles seven exact production method bodies, actual production state declarations, and the production netlink ACK classification block against inert Qt/OS adapters. It exercises role sharing, both cleanup orders, rollback, multiple peers, failed and uncertain acknowledgements, foreign routes, legacy metric0 rejection, interface changes, and 1,253-route linear cleanup. The adapters issue no sockets or routing operations. Python is used only to generate the C++ test translation unit at build time; application/runtime code remains C++.

The second executable tests the actual allocation-free netlink decoder against complete and incomplete dumps, sender/sequence/port checks, malformed messages/attributes, duplicate FIB keys, distinct metrics, interruption/filtering/truncation, and a 65,228-byte dump containing 1,253 unrelated routes. Release tests force -UNDEBUG and fail compilation if NDEBUG remains defined.

Kernel-semantic fixture: Linux v6.8 fib_nh_match compares priority only if fc_priority is nonzero. A DEL0 can therefore select a foreign metric5 route after owned0 disappears. The test reproduces that unsafe predicate, then exercises actual production receipts/cleanup using nonzero gateway priority1. Tunnel priority2 preserves own exclusion preference for identical prefixes; longest-prefix routing still makes the two /1 VPN routes beat a physical /0 default. Source: https://github.com/torvalds/linux/blob/v6.8/net/ipv4/fib_semantics.c#L824-L833 and https://github.com/torvalds/linux/blob/v6.8/net/ipv4/fib_trie.c#L1616-L1666.

These inert tests do not prove full Qt integration or live kernel DELETE behavior. The separately retained read-only dump probe checks actual kernel wire compatibility only. Owned disposable guest connection/cleanup tests remain required for final artifact acceptance.
