# Legacy headless updater compatibility preflight

Run before preparing automatic publication for an existing 5.0.3.18 fleet:

```sh
python3 deploy/headless/check_legacy_updater_compatibility.py \
  --baseline-updater-source /verified/baseline/headlessUpdateManager.cpp \
  --baseline-manifest /verified/baseline/manifest.json \
  --candidate-manifest /verified/candidate/manifest.json \
  --public-key /existing/trust/update-public-key.pem \
  --expected-public-key-sha256 <independently-pinned-existing-key-sha256>
```

This optional, read-only preflight reuses `make_manifest.decode_manifest_envelope`
and `verify_provisioning_bundle.verify_signature`. Both envelopes must authenticate
under the independently pinned existing key. It does not generate keys, sign,
install, contact a server, publish, or modify the normal release gate. It is not
a complete publication validator and must not replace existing validation.

Only the preserved 5.0.3.18 updater source digest
`496b581a7754d8ec38a0162a9a1aef7fb5e187f9a8dcac6afc6c878f15cd6d55`
is recognized. A version string alone cannot identify a local fork. Unknown
source is rejected rather than guessed compatible. The recognized old updater
requires its exact ordered eight-file provisioning contract. A candidate with
the ninth `amnezia-verify-provisioning-native` file is incompatible even if its
signature is valid. Re-signing alone does not repair this mismatch.

A positive result proves only this file-list compatibility and signature check.
Version progression, full package/hash validation, runtime dependencies/ABI,
actual download/apply/restart and normal release acceptance remain mandatory.
The regression suite mocks the signature boundary to test control flow; mocks
are not cryptographic or runtime evidence.

## Operator migration

Do not remove a declared mandatory native verifier, alter signed packageFiles,
or change the installed trust key to force old clients to accept a new package.
The native verifier and the CLI filesystem-helper role are separate contracts.
For an incompatible existing client, use the documented operator-run complete
provisioning upgrade in `headless/README.md`, after ordinary authorization and
verification against the existing trusted key. Preserve the full mandatory
verifier, package manifest, checksums and receipt bindings. Automatic bridging
requires an explicitly backward-compatible signed package/metadata transition
and real old-client validation. This preflight does not change the already
installed automatic updater, provide rollback, or authorize publication.

Tests: `python3 -m unittest discover -s deploy/headless -p test_legacy_updater_compatibility.py`.
