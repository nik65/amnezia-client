"""Local approval issuance/verification and a user-run, copy-only handoff.

No command in this tool launches an application/installer or controls a VPN.
The copy operation is reserved for the user's manual handoff script.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import tempfile

from .android_real_device_acquisition import file_record
from .trusted_acquisition_export import (AcquisitionContext, MAX_EXPORT_BYTES, TrustedAcquisitionError,
    canonical, issue_full_acceptance, verify_full_acceptance)


def read_json(path, limit):
    record = file_record(Path(path).absolute())
    if record["size"] > limit:
        raise TrustedAcquisitionError("JSON input exceeds bound")
    from deploy.selfhosted_updates.make_manifest import strict_json_object
    try:
        return json.loads(Path(record["path"]).read_bytes(), object_pairs_hook=strict_json_object)
    except (ValueError, SystemExit) as error:
        raise TrustedAcquisitionError("invalid/duplicate handoff JSON") from error


def write_new(path, data):
    path = Path(path).absolute()
    if path.exists() or path.is_symlink():
        raise TrustedAcquisitionError("refusing to overwrite an existing approval/handoff")
    path.parent.mkdir(parents=True, exist_ok=True)
    for parent in (path.parent, *path.parent.parents):
        info = parent.lstat()
        if parent.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400:
            raise TrustedAcquisitionError("handoff path follows link/reparse point")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as out:
        out.write(data)
        out.flush()
        os.fsync(out.fileno())


def verify_installed(context, *, installed_root, expected_client_sha256, copy_approval=False):
    if os.name != "nt":
        raise TrustedAcquisitionError("manual installed handoff is Windows-only")
    root = Path(installed_root).absolute()
    if str(root).lower() != "c:\\program files\\amneziavpn":
        raise TrustedAcquisitionError("installed handoff requires the fixed product directory")
    client = file_record(root / "AmneziaVPN.exe")
    if client["sha256"] != expected_client_sha256:
        raise TrustedAcquisitionError("installed GUI bytes differ from tested package")
    installed_bundle = root / "selfhosted_updates"
    manifest = file_record(installed_bundle / "manifest.json")
    if (manifest["sha256"], manifest["size"]) != (context.manifest["sha256"], context.manifest["size"]):
        raise TrustedAcquisitionError("installed manifest differs from accepted release")
    from deploy.selfhosted_updates.make_manifest import acceptance_upload_closure
    if acceptance_upload_closure(installed_bundle) != context.artifacts:
        raise TrustedAcquisitionError("installed publication payload differs from accepted release")
    approval_path = context.bundle / "release-acceptance.json"
    approval_record = file_record(approval_path)
    approval = read_json(approval_path, 128 * 1024)
    verify_full_acceptance(approval, context=context)
    destination = installed_bundle / "release-acceptance.json"
    if copy_approval:
        if destination.exists():
            if file_record(destination)["sha256"] != approval_record["sha256"]:
                raise TrustedAcquisitionError("a different installed approval exists; refusing overwrite")
        else:
            data = approval_path.read_bytes()
            if hashlib.sha256(data).hexdigest() != approval_record["sha256"]:
                raise TrustedAcquisitionError("approval changed before copy")
            # Exactly this new public signed receipt is created. No application,
            # service, route, DNS, firewall or installer operation is performed.
            write_new(destination, data)
        if file_record(destination)["sha256"] != approval_record["sha256"]:
            raise TrustedAcquisitionError("installed approval readback differs")
    return {"installedGuiVerified": True, "manifestVerified": True, "artifactsVerified": len(context.artifacts),
            "approvalVerified": True, "approvalCopied": copy_approval, "hostVpnTouched": False,
            "applicationLaunched": False, "installerLaunched": False}


def prepare_copy_script(context, *, expected_client_sha256, destination, python_path):
    from .trusted_acquisition_export import SHA
    if not isinstance(expected_client_sha256, str) or not SHA.fullmatch(expected_client_sha256):
        raise TrustedAcquisitionError("exact tested Windows GUI SHA required")
    approval = read_json(context.bundle / "release-acceptance.json", 128 * 1024)
    verify_full_acceptance(approval, context=context)
    script = Path(__file__).absolute()
    repo = script.parents[2]
    protected = [script, script.with_name("trusted_acquisition_export.py"),
                 script.with_name("android_real_device_acquisition.py"),
                 repo / "deploy/selfhosted_updates/make_manifest.py", context.public_key]
    quote = lambda value: "'" + str(value).replace("'", "''") + "'"
    lines = ["#Requires -Version 5.1", "#Requires -RunAsAdministrator", "$ErrorActionPreference = 'Stop'",
             "# Run manually AFTER installing the exact self-hosted EXE. This script only verifies and copies approval.",
             "# It never launches or closes Amnezia, runs an installer, or changes the VPN."]
    for path in protected:
        record = file_record(path)
        lines.append("if ((Get-FileHash -LiteralPath " + quote(path) + " -Algorithm SHA256).Hash.ToLowerInvariant() -ne "
                     + quote(record["sha256"]) + ") { throw 'Handoff verifier/key changed; stop and request a refreshed handoff' }")
    args = [str(python_path), "-m", "deploy.release_lab.trusted_acceptance_handoff", "verify-installed",
            "--bundle", str(context.bundle), "--outer", context.outer["path"], "--publisher", context.publisher["path"],
            "--public-key", str(context.public_key), "--installed-root", "C:\\Program Files\\AmneziaVPN",
            "--expected-client-sha256", expected_client_sha256, "--copy-approval"]
    lines.extend(["Push-Location -LiteralPath " + quote(repo), "try {",
                  "    & " + " ".join(quote(arg) for arg in args),
                  "    if ($LASTEXITCODE -ne 0) { throw 'Approval handoff verification failed' }", "} finally { Pop-Location }",
                  "Write-Host 'Signed approval copied and verified. Use the normal Connect action manually in Amnezia when ready.'"])
    write_new(destination, ("\r\n".join(lines) + "\r\n").encode("utf-8-sig"))
    return file_record(Path(destination).absolute())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("issue", "verify", "prepare-handoff", "verify-installed"))
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--outer", required=True, type=Path)
    parser.add_argument("--publisher", required=True, type=Path)
    parser.add_argument("--public-key", required=True, type=Path)
    parser.add_argument("--export", action="append", type=Path, default=[])
    parser.add_argument("--private-key", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--expected-client-sha256")
    parser.add_argument("--python", type=Path, default=Path("C:/Python313/python.exe"))
    parser.add_argument("--installed-root", type=Path)
    parser.add_argument("--copy-approval", action="store_true")
    parser.add_argument("--android-original-bundle", type=Path)
    parser.add_argument("--android-original-outer", type=Path)
    parser.add_argument("--android-original-export", type=Path)
    parser.add_argument("--android-equivalence-proof-out", type=Path)
    args = parser.parse_args()
    equivalence_options = (args.android_original_bundle, args.android_original_outer,
                           args.android_original_export, args.android_equivalence_proof_out)
    if any(value is not None for value in equivalence_options) and (
            args.action != "issue" or any(value is None for value in equivalence_options)):
        parser.error("historical Android equivalence requires issue and all four explicit --android-* options")
    context = AcquisitionContext.load(bundle=args.bundle, outer=args.outer, publisher=args.publisher, public_key=args.public_key)
    if args.action == "issue":
        if args.private_key is None or args.output is not None:
            parser.error("issue requires existing --private-key and writes only bundle/release-acceptance.json")
        exports = [read_json(path, MAX_EXPORT_BYTES) for path in args.export]
        if args.android_original_bundle is not None:
            from .android_dependency_equivalence import issue_equivalent_acceptance
            original_context = AcquisitionContext.load(bundle=args.android_original_bundle,
                outer=args.android_original_outer, publisher=Path(context.publisher["path"]), public_key=context.public_key)
            original_envelope = read_json(args.android_original_export, MAX_EXPORT_BYTES)
            original_bytes = args.android_original_export.read_bytes()
            if original_bytes != canonical(original_envelope):
                parser.error("original Android envelope must retain exact canonical source bytes")
            approval, proof = issue_equivalent_acceptance(exports, original_context=original_context,
                context=context, original_android_bytes=original_bytes, private_key=args.private_key)
            write_new(args.android_equivalence_proof_out, canonical(proof))
        else:
            approval = issue_full_acceptance(context=context, exports=exports, private_key=args.private_key)
        write_new(context.bundle / "release-acceptance.json", canonical(approval))
        result = {"approvalIssued": True, "version": context.version, "published": False}
    elif args.action == "prepare-handoff":
        if args.output is None: parser.error("prepare-handoff requires --output")
        result = prepare_copy_script(context, expected_client_sha256=args.expected_client_sha256,
                                     destination=args.output, python_path=args.python)
    elif args.action == "verify-installed":
        result = verify_installed(context, installed_root=args.installed_root,
                                  expected_client_sha256=args.expected_client_sha256, copy_approval=args.copy_approval)
    else:
        verify_full_acceptance(read_json(context.bundle / "release-acceptance.json", 128 * 1024), context=context)
        result = {"approvalVerified": True, "version": context.version, "published": False}
    print(json.dumps(result))


if __name__ == "__main__": main()
