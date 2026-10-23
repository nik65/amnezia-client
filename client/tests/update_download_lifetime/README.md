# Inert updater download fixture

Standalone Linux test target requiring Qt 6 Core/Network, Python 3 and a C++17 compiler.
The generator extracts the current production download method and legacy callback;
fake replies and handoff stubs never start an app, network request or installer.
Five lifetime and six payload/error cases verify teardown, exact committed bytes,
rejected transfers and staging descriptor cleanup. This is not installer acceptance.

```sh
cmake -S client/tests/update_download_lifetime -B /tmp/update-download-fixture \
  -DCMAKE_PREFIX_PATH=/path/to/Qt/gcc_64 -DUPDATE_DOWNLOAD_FIXTURE_ASAN=ON
cmake --build /tmp/update-download-fixture --parallel 2
ctest --test-dir /tmp/update-download-fixture --no-tests=error --output-on-failure
```

ASAN is optional and defaults off. With it enabled, leak detection is disabled for
Qt runtime allocations; invalid accesses and explicit staging descriptor checks
remain enabled. Changing the production source or generator regenerates the fixture.
`run_fixture.py SOURCE OUTPUT --generate-only` only generates C++; direct compilation
requires an explicit `--qt-prefix` and accepts optional `--asan`.
