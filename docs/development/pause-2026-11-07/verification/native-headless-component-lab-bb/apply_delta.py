#!/usr/bin/python3
"""Apply the minimal headless-verifier component delta to the copied lab.py."""
from pathlib import Path

path = Path(__file__).resolve().parent / "source/deploy/release_lab/lab.py"
text = path.read_text(encoding="utf-8")

HEADLESS = r'''
# --- explicit headless provisioning-verifier component admission (data only) ---
HEADLESS_COMPONENT_KIND = "headless-verifier"
_HEADLESS_ROLE = "provisioning-verifier"
_HEADLESS_DATA = {
    "component": "amnezia-verify-provisioning-native",
    "manifest": "manifest.json",
    "public_key": "owned-TEST-public.pem",
    "archive": "AmneziaHeadless_1.0.0.42_linux_x64_provisioning.tar.gz",
}
_HEADLESS_REQUIRED_SOURCES = {
    "deploy/release_lab/lab.py",
    "deploy/release_lab/guest_helpers/native_headless_verifier_probe.py",
    "deploy/headless/verify_provisioning_bundle.py",
    "deploy/headless/native/provisioning_verifier/CMakeLists.txt",
    "deploy/headless/native/provisioning_verifier/bootstrap_n.cpp",
    "deploy/headless/native/provisioning_verifier/preauth_modes.cpp",
    "deploy/headless/native/provisioning_verifier/host_runtime.inc",
    "deploy/headless/native/provisioning_verifier/verify_provisioning.cpp",
}
_HEADLESS_CASES = {"default_verify", "stage_inputs", "validate_package", "package_identity", "owned_root_cleanup"}
_HEADLESS_NOT_RUN = ["headlessInstaller", "rootOSMutation", "hostProbes", "recovery", "applicationAcceptance"]


def _headless_elf(raw: bytes, role: str) -> None:
    """Validate an inert x86_64 ELF data record without executing it."""
    le = lambda at, length: int.from_bytes(raw[at:at + length], "little")
    if (len(raw) < 64 or raw[:7] != b"\x7fELF\x02\x01\x01" or raw[7] not in (0, 3) or raw[8] != 0
            or le(16, 2) != 2 or le(18, 2) != 62 or le(20, 4) != 1 or le(52, 2) != 64 or le(54, 2) != 56):
        raise LabError(f"headless component {role} is not an x86_64 ELF data record")
    table, count = le(32, 8), le(56, 2)
    if not 0 < count <= 128 or table < 64 or table + count * 56 > len(raw):
        raise LabError("headless component program-header table refused")
    for index in range(count):
        at = table + index * 56
        kind = le(at, 4)
        offset, file_size = le(at + 8, 8), le(at + 32, 8)
        if kind in (2, 3) or offset > len(raw) or file_size > len(raw) - offset:
            raise LabError("headless component loader/dynamic segment refused")


def native_headless_bundle(files: Mapping[str, Any], expected: Mapping[str, Any]) -> dict[str, Any]:
    """Admit the separately built verifier plus signed DATA, never a collector alias."""
    if not isinstance(files, Mapping) or set(files) != set(_HEADLESS_DATA) or not isinstance(expected, Mapping):
        raise LabError("headless component input roles are incomplete")
    limits = {"component": 64 * 1024 * 1024, "manifest": 64 * 1024, "public_key": 4 * 1024,
              "archive": 32 * 1024 * 1024}
    records = {}
    for role, name in _HEADLESS_DATA.items():
        value = Path(os.path.abspath(str(files[role])))
        if value.name != name or value.is_symlink():
            raise LabError(f"headless component {role} does not use the exact flat input name")
        raw = _native_component_bytes(value, limits[role], private=True)
        digest = hashlib.sha256(raw).hexdigest()
        pin = expected.get(role + "_sha256")
        if not isinstance(pin, str) or not re.fullmatch(r"[0-9a-f]{64}", pin) or digest != pin:
            raise LabError(f"headless component {role} hash pin refused")
        records[role] = {"role": _HEADLESS_ROLE if role == "component" else role,
                         "path": str(value), "sha256": digest, "size": len(raw),
                         "mode": 0o600, "uid": os.geteuid()}
    _headless_elf(_native_component_bytes(Path(records["component"]["path"]), limits["component"], private=True),
                  _HEADLESS_ROLE)
    raw_manifest = _native_component_bytes(Path(records["manifest"]["path"]), limits["manifest"], private=True)
    raw_key = _native_component_bytes(Path(records["public_key"]["path"]), limits["public_key"], private=True)
    raw_archive = _native_component_bytes(Path(records["archive"]["path"]), limits["archive"], private=True)
    if (not raw_key.startswith(b"-----BEGIN PUBLIC KEY-----") or b"-----END PUBLIC KEY-----" not in raw_key
            or raw_key.count(b"BEGIN PUBLIC KEY") != 1 or raw_key.count(b"END PUBLIC KEY") != 1):
        raise LabError("headless public key is not a single PEM public key")
    try:
        sys.path.insert(0, str(repo_root() / "deploy" / "selfhosted_updates"))
        import make_manifest  # type: ignore
        payload, payload_bytes, signature_b64 = make_manifest.decode_manifest_envelope(raw_manifest)
    except (SystemExit, ValueError, OSError, json.JSONDecodeError) as exc:
        raise LabError(f"headless signed manifest envelope refused: {type(exc).__name__}") from exc
    finally:
        try:
            sys.path.remove(str(repo_root() / "deploy" / "selfhosted_updates"))
        except ValueError:
            pass
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except (ValueError, TypeError) as exc:
        raise LabError("headless manifest signature is not valid base64") from exc
    provisioning = payload.get("headlessProvisioning") if isinstance(payload, dict) else None
    platform_item = payload.get("platforms", {}).get("linux-headless-x64") if isinstance(payload.get("platforms"), dict) else None
    if (len(signature) != 64 or not isinstance(provisioning, dict) or not isinstance(platform_item, dict)
            or not isinstance(payload.get("autoInstall"), bool) or not isinstance(payload.get("version"), str)
            or not re.fullmatch(r"[0-9]+(?:\.[0-9]+){3}", payload["version"])
            or provisioning.get("sha256") != records["archive"]["sha256"]
            or provisioning.get("size") != records["archive"]["size"]
            or not re.fullmatch(r"[0-9a-f]{64}", str(provisioning.get("packageManifestSha256", "")))
            or not re.fullmatch(r"[0-9a-f]{64}", str(provisioning.get("checksumsSha256", "")))
            or not isinstance(platform_item.get("autoInstall"), bool)):
        raise LabError("headless signed manifest does not bind the admitted archive bytes")
    return {"schema": 1, "kind": HEADLESS_COMPONENT_KIND, "data_dir": None,
            "files": records, "expected": dict(expected), "payload": {
                "version": payload["version"], "signature_bytes": len(signature),
                "packageManifestSha256": provisioning["packageManifestSha256"],
                "checksumsSha256": provisioning["checksumsSha256"],
                "manifestPayloadSha256": hashlib.sha256(payload_bytes).hexdigest()}}


def verify_native_headless_sources(manifest_path: Path) -> dict[str, Any]:
    """Bind the verifier/helper implementation that the guest will actually run."""
    raw = _native_component_bytes(manifest_path, 2 * 1024 * 1024)
    record = {"path": os.path.abspath(str(manifest_path)), "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}
    rows = json.loads(raw)
    if not isinstance(rows, list) or not rows:
        raise LabError("headless component source manifest must enumerate physical inputs")
    seen = set()
    for row in rows:
        if (not isinstance(row, dict) or set(row) != {"path", "sha256", "size"}
                or not isinstance(row["path"], str) or not row["path"] or row["path"] in seen
                or not Path(row["path"]).parts or Path(row["path"]).as_posix() != row["path"]
                or "\\" in row["path"] or "\0" in row["path"] or Path(row["path"]).is_absolute()
                or ".." in Path(row["path"]).parts or Path(row["path"]).parts[0] in {".git", ".env"}
                or type(row["size"]) is not int or row["size"] < 0
                or not isinstance(row["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", row["sha256"])):
            raise LabError("headless component source row is invalid or duplicated")
        path = ensure_owned_child(repo_root(), repo_root() / row["path"], "headless physical source")
        digest, size = sha256_file(path)
        if digest != row["sha256"] or size != row["size"]:
            raise LabError("headless physical source drift: " + row["path"])
        seen.add(row["path"])
    if not _HEADLESS_REQUIRED_SOURCES <= seen or _native_component_bytes(manifest_path, 2 * 1024 * 1024) != raw:
        raise LabError("headless source closure is missing verifier/helper roles or changed")
    return {"manifest": record, "verified_files": len(seen)}


def validate_native_headless_receipt(receipt: Any, guest_plan: Mapping[str, Any]) -> None:
    keys = {"schema", "kind", "run_id", "profile", "nonce", "artifacts", "expected", "mode_exits",
            "root_identity", "package", "work_passed", "cleanup_passed", "capture_complete",
            "cases", "streams", "errors", "not_run"}
    if (not isinstance(receipt, dict) or set(receipt) != keys or type(receipt.get("schema")) is not int
            or receipt.get("schema") != 1 or receipt.get("kind") != HEADLESS_COMPONENT_KIND
            or any(receipt.get(key) != guest_plan[key] for key in ("run_id", "profile", "nonce", "artifacts", "expected"))
            or receipt.get("mode_exits") != {"default_verify": 0, "stage_inputs": 0, "validate_package": 0}
            or any(receipt.get(key) is not True for key in ("work_passed", "cleanup_passed", "capture_complete"))
            or receipt.get("errors") != {"primary": None, "cleanup": None}
            or receipt.get("not_run") != _HEADLESS_NOT_RUN):
        raise LabError("headless guest receipt identity, modes, scope, or outcome refused")
    identity = receipt.get("root_identity")
    if (not isinstance(identity, dict) or set(identity) != {"before", "after"} or identity["after"] is not None
            or not isinstance(identity["before"], list) or len(identity["before"]) != 2
            or any(type(part) is not int or part < 0 for part in identity["before"])):
        raise LabError("headless guest root incarnation/cleanup evidence refused")
    package = receipt.get("package")
    if (not isinstance(package, dict)
            or set(package) != {"files", "structural_validated", "host_probes_executed", "release_accepted", "native_verifier_sha256"}
            or package.get("structural_validated") is not True or package.get("host_probes_executed") is not False
            or package.get("release_accepted") is not False
            or not isinstance(package.get("files"), list) or not 1 <= len(package["files"]) <= 64
            or len(set(package["files"])) != len(package["files"])
            or any(not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", name) for name in package["files"])
            or not {"package-manifest.json", "SHA256SUMS", "amnezia-verify-provisioning-native"} <= set(package["files"])
            or not re.fullmatch(r"[0-9a-f]{64}", str(package.get("native_verifier_sha256", "")))):
        raise LabError("headless guest package structural evidence refused")
    cases = receipt.get("cases")
    if not isinstance(cases, list) or len(cases) != len(_HEADLESS_CASES):
        raise LabError("headless guest receipt omitted required cases")
    names = set()
    for row in cases:
        if (not isinstance(row, dict) or set(row) != {"name", "status"} or row.get("status") != "PASS"
                or row.get("name") not in _HEADLESS_CASES or row["name"] in names):
            raise LabError("headless guest case is missing, duplicated, or failed")
        names.add(row["name"])
    streams = receipt.get("streams")
    if not isinstance(streams, dict) or len(streams) != 6:
        raise LabError("headless guest did not retain all three child stream pairs")
    pairs = {}
    for key, row in streams.items():
        if not isinstance(key, str) or not re.fullmatch(r"[1-9][0-9]*:(stdout|stderr)", key) or not isinstance(row, dict):
            raise LabError("headless guest stream identity refused")
        pid, channel = key.split(":")
        pairs.setdefault(pid, set()).add(channel)
        if (set(row) != {"size", "sha256", "eof", "truncated", "head_b64", "tail_b64"}
                or type(row["size"]) is not int or not 0 <= row["size"] <= 1048576
                or row["eof"] is not True or row["truncated"] is not False
                or not isinstance(row["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", row["sha256"])):
            raise LabError("headless guest capture incomplete or exceeds retained full window")
        try:
            head = base64.b64decode(row["head_b64"], validate=True)
            tail = base64.b64decode(row["tail_b64"], validate=True)
        except (ValueError, TypeError) as exc:
            raise LabError("headless guest capture encoding refused") from exc
        if len(head) != min(row["size"], 2048) or len(tail) != min(row["size"], 2048):
            raise LabError("headless guest capture window length refused")
        complete = head if row["size"] <= 2048 else head + tail[-(row["size"] - 2048):]
        if hashlib.sha256(complete).hexdigest() != row["sha256"] or (row["size"] <= 2048 and head != tail):
            raise LabError("headless guest capture bytes do not match digest")
    if len(pairs) != 3 or any(channels != {"stdout", "stderr"} for channels in pairs.values()):
        raise LabError("headless guest capture pairs refused")


'''

if text.count("_NATIVE_COMPONENT_CASES = {") != 1:
    raise SystemExit("insertion marker missing")
text = text.replace("_NATIVE_COMPONENT_CASES = {", HEADLESS + "_NATIVE_COMPONENT_CASES = {", 1)

old = '''    if '/' in target or target not in ('collector', 'collector-route', 'manifest.json', 'probe.py', 'plan.json'):
        raise SystemExit('component staging target refused')'''
new = '''    allowed = tuple(cfg.get('allowed') or ('collector', 'collector-route', 'manifest.json', 'probe.py', 'plan.json'))
    if '/' in target or target not in allowed:
        raise SystemExit('component staging target refused')'''
assert old in text
text = text.replace(old, new, 1)
old = '''        if '/' in name or name not in ('collector', 'collector-route', 'manifest.json', 'probe.py', 'plan.json'):
            raise SystemExit('component staged member name refused')'''
new = '''        allowed = tuple(cfg.get('allowed') or ('collector', 'collector-route', 'manifest.json', 'probe.py', 'plan.json'))
        if '/' in name or name not in allowed:
            raise SystemExit('component staged member name refused')'''
assert old in text
text = text.replace(old, new, 1)

old = "    def create_component(self, bundle_dir: Path, source_manifest: Path, run_id: str | None = None) -> dict[str, Any]:"
new = ("    def create_component(self, bundle_dir: Path | None, source_manifest: Path, run_id: str | None = None,\n"
       "                        *, component_kind: str = \"native-component\", headless_files: Mapping[str, Any] | None = None,\n"
       "                        headless_expected: Mapping[str, Any] | None = None) -> dict[str, Any]:")
assert old in text
text = text.replace(old, new, 1)
old = '''        if self.dry_run:
            raise LabError("component admission cannot run in dry-run")
        run_id = run_id or "native-" + uuid.uuid4().hex'''
new = '''        if self.dry_run:
            raise LabError("component admission cannot run in dry-run")
        if component_kind == HEADLESS_COMPONENT_KIND:
            return self._create_headless_component(source_manifest, run_id, headless_files, headless_expected)
        if component_kind != "native-component" or headless_files is not None or headless_expected is not None:
            raise LabError("component kind/role admission refused")
        if bundle_dir is None:
            raise LabError("native component bundle directory is required")
        run_id = run_id or "native-" + uuid.uuid4().hex'''
assert old in text
text = text.replace(old, new, 1)

old = '''        if native_component_bundle(Path(plan["bundle"]["bundle_dir"])) != plan["bundle"]:
            raise LabError("component artifact bytes changed after admission")'''
new = '''        if plan.get("component_kind") == HEADLESS_COMPONENT_KIND:
            admitted = plan.get("headless")
            files = admitted.get("files") if isinstance(admitted, dict) else None
            expected = admitted.get("expected") if isinstance(admitted, dict) else None
            if (not isinstance(files, dict) or not isinstance(expected, dict)
                    or native_headless_bundle({key: Path(value["path"]) for key, value in files.items()}, expected) != admitted):
                raise LabError("headless artifact bytes changed after admission")
            if verify_native_headless_sources(Path(plan["source_context"]["manifest"]["path"])) != plan["source_context"]:
                raise LabError("headless source context changed after admission")
            if artifact_record(profiles_root() / "linux-headless-x64.json") != plan["profile_record"]:
                raise LabError("headless profile changed after admission")
            return plan
        if native_component_bundle(Path(plan["bundle"]["bundle_dir"])) != plan["bundle"]:
            raise LabError("component artifact bytes changed after admission")'''
assert old in text
text = text.replace(old, new, 1)

old = '''        plan = self._native_component_plan(run_id)
        run = self.get_run(run_id)
        runtime = run.get("component_runtime")'''
new = '''        plan = self._native_component_plan(run_id)
        run = self.get_run(run_id)
        if plan.get("component_kind") == HEADLESS_COMPONENT_KIND:
            return self._gate_headless_component(run_id, plan, run)
        runtime = run.get("component_runtime")'''
assert old in text
text = text.replace(old, new, 1)

old = '''        if run.get("component_runtime") is not None:
            raise LabError("component acquisition is already spent")
        profile = "linux-headless-x64"'''
new = '''        if run.get("component_runtime") is not None:
            raise LabError("component acquisition is already spent")
        if plan.get("component_kind") == HEADLESS_COMPONENT_KIND:
            return self._run_headless_component(run_id, plan, run)
        profile = "linux-headless-x64"'''
assert old in text
text = text.replace(old, new, 1)

METHODS = r'''
    def _create_headless_component(self, source_manifest: Path, run_id: str | None,
                                   files: Mapping[str, Any] | None, expected: Mapping[str, Any] | None) -> dict[str, Any]:
        if files is None or expected is None:
            raise LabError("headless component requires the four admitted DATA inputs")
        run_id = run_id or "native-" + uuid.uuid4().hex
        if not isinstance(run_id, str) or not re.fullmatch(r"native-[0-9a-f]{32}", run_id):
            raise LabError("component run identity must be native- plus 32 lowercase hex characters")
        with self.mutation_session("create_component"):
            headless = native_headless_bundle(files, expected)
            source_context = verify_native_headless_sources(source_manifest)
            profile_id = "linux-headless-x64"
            profile = load_profiles()[profile_id]
            if profile.get("backend") != "qemu-linux" or profile.get("nic") != "none":
                raise LabError("headless profile must remain the existing isolated Linux QEMU profile")
            state = self.load_state()
            run_dir = ensure_owned_child(self.root, self.root / "runs" / run_id, "headless run directory")
            if run_id in state.get("runs", {}) or run_dir.exists():
                raise LabError("headless run already exists")
            run_dir.parent.mkdir(parents=True, exist_ok=True)
            run_dir.mkdir(mode=0o700)
            profile_dir = run_dir / profile_id
            profile_dir.mkdir(mode=0o700)
            overlay = ensure_owned_child(self.root, profile_dir / "overlay.qcow2", "headless overlay")
            json_dump(profile_dir / ".owned-overlay.json", {"run_id": run_id, "profile": profile_id, "overlay": str(overlay)})
            plan = {"schema": 1, "run_id": run_id, "kind": "native-component",
                    "component_kind": HEADLESS_COMPONENT_KIND, "profile": profile_id,
                    "nonce": uuid.uuid4().hex + uuid.uuid4().hex, "created_at": utc_now(),
                    "expires_epoch": time.time() + 480, "headless": headless,
                    "source_context": source_context,
                    "profile_record": artifact_record(profiles_root() / f"{profile_id}.json")}
            plan_path = run_dir / "native-component-plan.json"
            json_dump(plan_path, plan)
            plan_path.chmod(0o600)
            run = {"run_id": run_id, "kind": "native-component", "lane": "component", "release_eligible": False,
                   "dry_run": False, "test_mode": self.test_mode, "created_at": plan["created_at"],
                   "component_kind": HEADLESS_COMPONENT_KIND,
                   "component_plan": artifact_record(plan_path), "windows_backend": "qemu",
                   "expected_profiles": [profile_id], "artifacts": {},
                   "profiles": {profile_id: {"status": "created", "vm": None, "evidence": None}}}
            state["lab_id"] = state.get("lab_id") or "lab-" + uuid.uuid4().hex
            state.setdefault("runs", {})[run_id] = run
            self.save_state(state)
            return run

    def _gate_headless_component(self, run_id: str, plan: Mapping[str, Any], run: Mapping[str, Any]) -> dict[str, Any]:
        runtime = run.get("component_runtime")
        if runtime is None:
            return {"run_id": run_id, "component_passed": False, "runtime_acceptance": "NOT_RUN",
                    "release_passed": False, "reason": "no controller-acquired guest execution evidence"}
        if not isinstance(runtime, dict) or runtime.get("status") != "captured":
            raise LabError("headless runtime is not captured and finalized")
        path = ensure_owned_child(self.root, Path(runtime["archive"]["path"]), "headless runtime archive")
        raw = _native_component_bytes(path, 1024 * 1024, private=True)
        if artifact_record(path) != runtime["archive"]:
            raise LabError("headless runtime archive changed")
        record = json.loads(raw)
        if (record.get("run_id") != run_id or record.get("nonce") != plan["nonce"]
                or record.get("plan_binding") != run["component_plan"] or record.get("status") != "captured"
                or record.get("reset", {}).get("reset_profiles") != [plan["profile"]]
                or record.get("reset", {}).get("run_id") != run_id
                or run["profiles"][plan["profile"]].get("vm") is not None
                or run["profiles"][plan["profile"]].get("status") != "reset"
                or record.get("component_kind") != HEADLESS_COMPONENT_KIND):
            raise LabError("headless runtime plan, kind, or canonical reset binding refused")
        source_rows = json.loads(_native_component_bytes(Path(plan["source_context"]["manifest"]["path"]), 2 * 1024 * 1024))
        helper_rows = [row for row in source_rows if row["path"] == "deploy/release_lab/guest_helpers/native_headless_verifier_probe.py"]
        if len(helper_rows) != 1 or record.get("helper") != helper_rows[0]:
            raise LabError("headless runtime helper binding refused")
        validate_native_headless_receipt(record["receipt"], record["guest_plan"])
        expected = [{"path": guest_path, "role": role, "sha256": plan["headless"]["files"][key]["sha256"],
                     "size": plan["headless"]["files"][key]["size"]}
                    for guest_path, role, key in record["guest_plan"].get("artifact_binding", [])]
        if record["guest_plan"].get("artifacts") != expected:
            raise LabError("headless runtime artifact binding refused")
        return {"run_id": run_id, "runtime_acceptance": "PASS_SCOPED_HEADLESS_VERIFIER_DATA_ONLY",
                "component_passed": False, "release_passed": False, "not_run": list(_HEADLESS_NOT_RUN),
                "runtime_archive": dict(runtime["archive"]),
                "scope": "default verify/stage/validate package data only; root runtime acceptance remains parent-owned"}

    def _run_headless_component(self, run_id: str, plan: Mapping[str, Any], run: Mapping[str, Any]) -> dict[str, Any]:
        profile = "linux-headless-x64"
        vm = self.owned_vm(run_id, profile)  # first actual external boundary; no guest IO yet
        source_rows = json.loads(_native_component_bytes(Path(plan["source_context"]["manifest"]["path"]), 2 * 1024 * 1024))
        relative = "deploy/release_lab/guest_helpers/native_headless_verifier_probe.py"
        helpers = [row for row in source_rows if row["path"] == relative]
        helper_path = repo_root() / relative
        helper_raw = _native_component_bytes(helper_path, 128 * 1024)
        helper = {"path": relative, "sha256": hashlib.sha256(helper_raw).hexdigest(), "size": len(helper_raw)}
        if helpers != [helper]:
            raise LabError("headless acquisition lacks the exact admitted guest helper")
        nonce = plan["nonce"]
        root = "/var/tmp/amnezia-native-" + nonce
        files = plan["headless"]["files"]
        names = _HEADLESS_DATA
        guest_paths = {"component": root + "/" + names["component"], "manifest": root + "/" + names["manifest"],
                       "public_key": root + "/" + names["public_key"], "archive": root + "/" + names["archive"]}
        roles = {"component": _HEADLESS_ROLE, "manifest": "signed-manifest-data",
                 "public_key": "public-key-data", "archive": "provisioning-archive-data"}
        binding = [[guest_paths[key], roles[key], key] for key in ("component", "manifest", "public_key", "archive")]
        artifacts = [{"path": path, "role": role, "sha256": files[key]["sha256"], "size": files[key]["size"]}
                     for path, role, key in binding]
        expected = {key: value for key, value in plan["headless"]["expected"].items()}
        guest_plan = {"schema": 1, "kind": HEADLESS_COMPONENT_KIND, "run_id": run_id, "profile": profile,
                      "nonce": nonce, "root": root, "marker_path": "/tmp/amnezia-release-lab-marker",
                      "marker_content": f"amnezia-release-lab:{run_id}:{profile}",
                      "artifacts": artifacts, "artifact_binding": binding, "expected": expected,
                      "inputs": {"component": guest_paths["component"], "manifest": guest_paths["manifest"],
                                 "public_key": guest_paths["public_key"], "archive": guest_paths["archive"],
                                 "private_root": root + "/private", "verified_receipt": root + "/verified-receipt.json",
                                 "staged_receipt": root + "/staged-receipt.json",
                                 "metadata_receipt": root + "/metadata.json"},
                      "helper": helper,
                      "manifest_sha256": files["manifest"]["sha256"], "archive_sha256": files["archive"]["sha256"],
                      "package_manifest_sha256": plan["headless"]["payload"]["packageManifestSha256"],
                      "checksums_sha256": plan["headless"]["payload"]["checksumsSha256"],
                      "version": plan["headless"]["payload"]["version"]}
        parent = ensure_owned_child(self.root, self.root / "exports" / run_id / "native-component-host", "headless host archive")
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        directory = parent / uuid.uuid4().hex
        directory.mkdir(mode=0o700)
        identity = directory.lstat()
        sequence = 0
        capture_safe = True

        def retain(label: str, data: bytes) -> dict[str, Any]:
            nonlocal sequence
            now = directory.lstat()
            if ((now.st_dev, now.st_ino, now.st_uid, stat.S_IMODE(now.st_mode))
                    != (identity.st_dev, identity.st_ino, os.geteuid(), 0o700)
                    or not isinstance(data, bytes) or len(data) > 1024 * 1024 or sequence >= 4096):
                raise LabError("headless host private capture boundary refused")
            path = directory / f"{sequence:04d}-{label}.json"
            sequence += 1
            immutable_bytes_dump(path, data)
            if _native_component_bytes(path, 1024 * 1024, private=True) != data:
                raise LabError("headless host private capture readback refused")
            return artifact_record(path)

        plan_bytes = (json.dumps(guest_plan, sort_keys=True, separators=(",", ":")) + "\n").encode()
        plan_record = retain("guest-plan", plan_bytes)
        state = self.load_state()
        state["runs"][run_id]["component_runtime"] = {"status": "acquiring", "nonce": nonce, "guest_plan": plan_record}
        self.save_state(state)
        primary, receipt, reset_result, cleanup_error = None, None, None, None
        cfg = {"run_id": run_id, "nonce": nonce, "root": root,
               "allowed": tuple(names.values()) + ("probe.py", "plan.json")}

        def execute(args: list[str], timeout: float) -> bytes:
            nonlocal capture_safe
            if time.time() >= plan["expires_epoch"]:
                raise LabError("headless acquisition plan expired")
            capture_safe = False
            try:
                result = self._native_component_exec(run_id, vm, "/usr/bin/python3", ["-I", "-B", *args], timeout=timeout)
            except BaseException as error:
                if isinstance(getattr(error, "component_capture_archive", None), dict):
                    capture_safe = True
                raise
            capture_safe = True
            retain("stdout", result["stdout"])
            if result["stderr"]:
                raise LabError("headless helper produced unexpected stderr; retained in private QGA capture")
            return result["stdout"]

        def stage(operation: str, extra: Mapping[str, Any] | None = None, timeout: float = 10) -> dict[str, Any]:
            value = json.loads(execute(["-c", _NATIVE_COMPONENT_STAGE, operation, json.dumps({**cfg, **(extra or {})})], timeout))
            expected_marker = hashlib.sha256(f"amnezia-release-lab:{run_id}:{profile}".encode()).hexdigest()
            incarnation = value.get("incarnation") if isinstance(value, dict) else None
            if (not isinstance(value, dict) or type(value.get("schema")) is not int or value["schema"] != 1
                    or value.get("root") != root or value.get("marker_sha256") != expected_marker
                    or not isinstance(incarnation, list) or len(incarnation) != 2
                    or any(type(part) is not int or part < 0 for part in incarnation)
                    or (operation != "create" and incarnation != cfg["incarnation"])):
                raise LabError("headless guest staging identity refused")
            return value

        try:
            cfg["incarnation"] = stage("create")["incarnation"]
            stage_files = [(names[key], Path(files[key]["path"]), files[key]) for key in ("component", "manifest", "public_key", "archive")]
            stage_files.extend((("probe.py", helper_path, helper), ("plan.json", Path(plan_record["path"]), plan_record)))
            qga = QgaClient(Path(vm["qga_socket"]), timeout=5)
            original_request = qga._request_on_connection

            def recorded_request(connection, command, arguments=None):
                nonlocal capture_safe
                capture_safe = False
                response = original_request(connection, command, arguments)
                retain("file-qga", (json.dumps(response, sort_keys=True, separators=(",", ":")) + "\n").encode())
                capture_safe = True
                return response

            qga._request_on_connection = recorded_request
            for name, source, record in stage_files:
                deadline = time.monotonic() + 20
                stage("check", {"target": name}, timeout=min(10, deadline - time.monotonic()))
                self._native_component_fence(run_id, vm, deadline)
                capture_safe = False
                try:
                    qga.write_file_from_path(root + "/" + name, source, record["sha256"], record["size"],
                                             deadline=deadline, max_size=64 * 1024 * 1024)
                    capture_safe = True
                except BaseException as error:
                    try:
                        self._native_component_fence(run_id, vm, deadline)
                    except Exception as secondary:
                        error.add_note("headless post-write ownership fence failed: " + type(secondary).__name__)
                    raise
                self._native_component_fence(run_id, vm, deadline)
            stage("seal", {"files": [{"name": name, "sha256": record["sha256"], "size": record["size"]}
                                      for name, source, record in stage_files]})
            output = execute([root + "/probe.py", "--plan", root + "/plan.json"], timeout=20)
            try:
                receipt = json.loads(output)
            except (ValueError, UnicodeDecodeError) as error:
                raise LabError("headless guest receipt JSON refused") from error
            validate_native_headless_receipt(receipt, guest_plan)
            self._native_component_plan(run_id)
        except BaseException as error:
            primary = error
        finally:
            if capture_safe:
                try:
                    reset_result = self.reset(run_id, profile)
                    if reset_result.get("run_id") != run_id or reset_result.get("reset_profiles") != [profile]:
                        raise LabError("headless canonical reset result refused")
                except BaseException as error:
                    cleanup_error = type(error).__name__
                    if primary is None:
                        primary = error
                    else:
                        primary.add_note("headless canonical reset also failed: " + type(error).__name__)
            elif primary is not None:
                primary.add_note("headless owned VM preserved: incomplete or uncertain private capture")
            record = {"schema": 1, "run_id": run_id, "nonce": nonce, "profile": profile,
                      "component_kind": HEADLESS_COMPONENT_KIND,
                      "status": "captured" if primary is None else "failed", "plan_binding": run["component_plan"],
                      "helper": helper, "guest_plan": guest_plan, "receipt": receipt,
                      "vm_identity": {key: vm.get(key) for key in ("pid", "proc_start_time", "uid", "uuid", "qmp_socket", "qga_socket", "argv")},
                      "reset": reset_result, "capture_safe": capture_safe,
                      "primary_error": type(primary).__name__ if primary else None, "cleanup_error": cleanup_error}
            try:
                archive = retain("runtime-record", (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode())
                state = self.load_state()
                state["runs"][run_id]["component_runtime"] = {"status": record["status"], "archive": archive}
                self.save_state(state)
            except BaseException as error:
                if primary is None:
                    primary = error
                else:
                    primary.add_note("headless final record also failed: " + type(error).__name__)
        if primary is not None:
            raise primary
        return self.gate_component(run_id)

'''
marker = "    def gate_component(self, run_id: str) -> dict[str, Any]:"
assert text.count(marker) == 1
text = text.replace(marker, METHODS + marker, 1)

old = '''    component_create = sub.add_parser("create-component")
    component_create.add_argument("--bundle-dir", required=True)
    component_create.add_argument("--source-manifest", required=True)
    component_create.add_argument("--run-id")'''
new = '''    component_create = sub.add_parser("create-component")
    component_create.add_argument("--bundle-dir")
    component_create.add_argument("--source-manifest", required=True)
    component_create.add_argument("--run-id")
    component_create.add_argument("--component-kind", choices=("native-component", "headless-verifier"), default="native-component")
    component_create.add_argument("--headless-component", type=Path)
    component_create.add_argument("--headless-manifest", type=Path)
    component_create.add_argument("--headless-public-key", type=Path)
    component_create.add_argument("--headless-archive", type=Path)
    component_create.add_argument("--expected-component-sha256")
    component_create.add_argument("--expected-manifest-sha256")
    component_create.add_argument("--expected-public-key-sha256")
    component_create.add_argument("--expected-archive-sha256")'''
assert old in text
text = text.replace(old, new, 1)

old = '''        elif args.command == "create-component":
            result = controller.create_component(Path(args.bundle_dir), Path(args.source_manifest), args.run_id)'''
new = '''        elif args.command == "create-component":
            files = expected = None
            if args.component_kind == HEADLESS_COMPONENT_KIND:
                if any(value is None for value in (args.headless_component, args.headless_manifest,
                                                   args.headless_public_key, args.headless_archive)):
                    raise LabError("headless component admission requires all four DATA inputs")
                files = {"component": args.headless_component, "manifest": args.headless_manifest,
                         "public_key": args.headless_public_key, "archive": args.headless_archive}
                expected = {"component_sha256": args.expected_component_sha256,
                            "manifest_sha256": args.expected_manifest_sha256,
                            "public_key_sha256": args.expected_public_key_sha256,
                            "archive_sha256": args.expected_archive_sha256}
            result = controller.create_component(
                Path(args.bundle_dir) if args.bundle_dir else None, Path(args.source_manifest), args.run_id,
                component_kind=args.component_kind, headless_files=files, headless_expected=expected)'''
assert old in text
text = text.replace(old, new, 1)

path.write_text(text, encoding="utf-8")
print("applied", path)
