"""Publication-only acceptance boundary; ordinary builds do not call this gate.

The current lab archives are controller-acquired, hash-bound JSON, not signed
acquisition attestations. There is no implemented trusted real-phone/Linux
acquisition authority. Never turn cached PASS fields into release approval.

Future authority uses the single existing release key, not another key layer:
the trusted signer/controller process must validate live owned acquisition,
original byte capture and cleanup before signing. Optional offline acquisition
must be a domain-separated export previously signed by that same authority.
This assumes the keyholder and controller host are trusted; filesystem PASS
flags are not a substitute. Neither trusted acquisition mode exists here yet.
"""

from pathlib import Path


class AcceptanceUnavailable(RuntimeError):
    """No authenticated complete acquisition is available for approval issuance."""


def validate_publication_acceptance(
    *, run_id: str, state_root: Path, manifest_path: Path,
    outer_artifact: Path, public_key_path: Path,
    source_authentication_path: Path | None = None,
) -> list[dict[str, object]]:
    """Fail closed until a reviewed acquisition authority is implemented.

    File presence, ownership flags, signed update manifests and unsigned lab
    summaries do not authenticate a complete postvalidation acceptance matrix.
    The current interface intentionally accepts no caller-supplied PASS records,
    lane override, environment bypass or alternate trust key.
    """
    if not run_id:
        raise AcceptanceUnavailable("AUTHENTICATION_UNAVAILABLE: an owned run identity is required")
    if source_authentication_path is None:
        raise AcceptanceUnavailable(
            "AUTHENTICATION_UNAVAILABLE: no authenticated acquisition authority/export; "
            "Linux GUI/headless and real Android acceptance cannot be inferred from cached JSON"
        )
    # Even an existing file cannot bootstrap its own authority. Do not read or
    # bless arbitrary unsigned/signed JSON with an unimplemented verifier.
    raise AcceptanceUnavailable(
        "AUTHENTICATION_UNAVAILABLE: acquisition-export authentication and full matrix "
        "validation are not implemented; no publication approval was issued"
    )
