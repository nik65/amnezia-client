`run_source_checkout_regression.py --conan <conan-2-executable> --output <new-directory>`
executes the actual AWG recipe through `conan source` with an isolated Conan home.
It downloads the immutable upstream Git commit and submodules, verifies their
metadata after relocation, checks the exported and installed union overlay bytes,
and proves a pre-existing source collision fails without overwriting files.

The optional `--recipe <preserved-recipe-directory>` supports a failing regression
run. Logs, commands, native exits, input hashes and timestamps remain in the output
directory. This test needs Git/network access; it builds no native code or APK and
performs no Android device operations.
