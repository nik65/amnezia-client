"""Plans and validates real guest-only headless native-update acceptance.

The module performs no I/O.  A release-lab controller must execute the plan
inside its already proven owned QEMU guest over QGA.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import re
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Mapping, Sequence
from urllib.parse import unquote, urlparse


SHA_RE = re.compile(r"[0-9a-f]{64}")
ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}")
VERSION_RE = re.compile(r"\d+\.\d+\.\d+\.\d+")
FIXED_KEY = "/etc/amnezia/update-public-key.pem"
FIXED_SOCKET = "/run/amnezia/amneziad.sock"
FIXED_STORE = "/var/lib/amnezia/profiles.json"
UPDATE_STATE = "/var/lib/amnezia/headless-updates.json"
UPDATE_JOURNAL = "/var/lib/amnezia/updates/transaction.json"
ROLLBACK_RECEIPT = "/var/lib/amnezia/updates/rollback-receipt.json"
OWNED_ROOT = "/var/lib/amnezia-release-lab/"


class HeadlessAcceptanceError(RuntimeError):
    pass


def _integer(value: object, label: str, *, positive: bool = True) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or (positive and value <= 0):
        raise HeadlessAcceptanceError(f"{label} must be a real integer")
    return value


def _timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise HeadlessAcceptanceError(f"{label} must be UTC")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise HeadlessAcceptanceError(f"{label} is invalid") from exc


@dataclass(frozen=True)
class OuterBinding:
    pid: int
    start_ticks: int
    uuid: str
    qmp_socket: str
    qga_socket: str

    def validate(self) -> None:
        _integer(self.pid, "outer PID"); _integer(self.start_ticks, "outer start ticks")
        try: uuid.UUID(self.uuid)
        except (ValueError, AttributeError) as exc: raise HeadlessAcceptanceError("outer UUID is invalid") from exc
        if not self.qmp_socket.startswith(OWNED_ROOT) or not self.qga_socket.startswith(OWNED_ROOT):
            raise HeadlessAcceptanceError("outer sockets must be under the owned release-lab root")


@dataclass(frozen=True)
class ReleaseBytes:
    version: str
    manifest_sha256: str
    manifest_size: int
    tar_sha256: str
    tar_size: int
    amneziad_sha256: str
    amneziad_size: int
    cli_sha256: str
    cli_size: int
    key_sha256: str

    def validate(self) -> None:
        if not VERSION_RE.fullmatch(self.version): raise HeadlessAcceptanceError("release version is invalid")
        for label in ("manifest_sha256", "tar_sha256", "amneziad_sha256", "cli_sha256", "key_sha256"):
            if not SHA_RE.fullmatch(getattr(self, label)): raise HeadlessAcceptanceError(f"{label} is invalid")
        for label in ("manifest_size", "tar_size", "amneziad_size", "cli_size"):
            _integer(getattr(self, label), label)


@dataclass(frozen=True)
class Fixture:
    endpoint: str
    forward_routes: tuple[str, ...]
    nonce: str
    manifest_path: str
    artifact_path: str

    def validate(self) -> None:
        if not ID_RE.fullmatch(self.nonce) or len(self.nonce) < 16: raise HeadlessAcceptanceError("fixture nonce is invalid")
        parsed = urlparse(self.endpoint)
        if parsed.scheme != "http" or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ("", "/"):
            raise HeadlessAcceptanceError("fixture must be a plain private-IPv4 HTTP origin")
        try: address = ipaddress.ip_address(parsed.hostname or "")
        except ValueError as exc: raise HeadlessAcceptanceError("fixture host must be a literal IPv4 address") from exc
        try: endpoint_port = parsed.port
        except ValueError as exc: raise HeadlessAcceptanceError("fixture port is invalid") from exc
        if (address.version != 4 or not address.is_private or address.is_loopback
                or address.is_link_local or address.is_unspecified or address.is_multicast
                or address.is_reserved or endpoint_port is None):
            raise HeadlessAcceptanceError("fixture endpoint is not an allowed private IPv4 address/port")
        networks = []
        for value in self.forward_routes:
            try:
                network = ipaddress.ip_network(value, strict=False)
            except ValueError as exc: raise HeadlessAcceptanceError("fixture forward route is invalid") from exc
            if network.version != 4 or not network.is_private or network.prefixlen == 0:
                raise HeadlessAcceptanceError("fixture forward route must be a private IPv4 CIDR")
            networks.append(network)
        if not networks or not any(address in network for network in networks):
            raise HeadlessAcceptanceError("fixture IPv4 address is not covered by forwardRoutes")
        for path in (self.manifest_path, self.artifact_path):
            decoded = unquote(path)
            if not path.startswith("/") or "?" in path or "#" in path or ".." in decoded.split("/") or "//" in path:
                raise HeadlessAcceptanceError("fixture GET path is unsafe")
        if self.manifest_path == self.artifact_path:
            raise HeadlessAcceptanceError("manifest and artifact paths must differ")


@dataclass(frozen=True)
class NativeUpdatePlan:
    run_id: str
    case_id: str
    attempt_nonce: str
    created_at: str
    outer_binding: OuterBinding
    baseline: ReleaseBytes
    candidate: ReleaseBytes
    fixture: Fixture

    def validate(self) -> None:
        for label, value in (("run id", self.run_id), ("case id", self.case_id), ("attempt nonce", self.attempt_nonce)):
            if not ID_RE.fullmatch(value): raise HeadlessAcceptanceError(f"{label} is invalid")
        _timestamp(self.created_at, "plan creation time")
        self.outer_binding.validate(); self.baseline.validate(); self.candidate.validate(); self.fixture.validate()
        if self.attempt_nonce != self.fixture.nonce: raise HeadlessAcceptanceError("fixture and plan attempt nonce differ")
        if self.baseline.version == self.candidate.version: raise HeadlessAcceptanceError("native update requires distinct N-1 and N versions")
        if self.baseline.key_sha256 != self.candidate.key_sha256: raise HeadlessAcceptanceError("native update cannot rotate the fixed trust anchor")
        if self.baseline.tar_sha256 == self.candidate.tar_sha256: raise HeadlessAcceptanceError("native update candidate bytes equal the baseline")


def build_acceptance_plan(plan: NativeUpdatePlan) -> dict:
    plan.validate()
    profile = {
        "id": f"release-lab-{plan.attempt_nonce}", "name": "release-lab native updater",
        "protocol": "wireguard", "configPath": "/etc/amnezia/profiles/release-lab.conf",
        "forwardRoutes": list(plan.fixture.forward_routes), "autoUpdate": True,
        "updateManifestUrl": plan.fixture.endpoint.rstrip("/") + plan.fixture.manifest_path,
        "updatePublicKeyPath": FIXED_KEY,
    }
    return {
        "schema": 1, "operation": "headless-native-update-acceptance", "plan": asdict(plan),
        "profile": profile,
        "profile_store": {"path": FIXED_STORE, "uid": 0, "gid": 0, "mode": "0600",
                          "readback_argv": ["/usr/local/bin/amnezia-cli", "--socket", FIXED_SOCKET, "--json", "list-profiles"]},
        "required_product_sources": {"state": UPDATE_STATE, "journal": UPDATE_JOURNAL,
            "rollback_receipt": ROLLBACK_RECEIPT, "doctor": "cli:doctor",
            "rollback_cli": "cli:update-rollback"},
        "cli_rollback_argv": ["/usr/local/bin/amnezia-cli", "--socket", FIXED_SOCKET, "--json", "update-rollback"],
        "startup_update_trigger_seconds": 10, "transport": "qga", "host_network_mutation": False,
    }


def _common(plan: NativeUpdatePlan, receipt: Mapping, operation: str, *, origin: str = "guest") -> None:
    plan.validate()
    if receipt.get("schema") != 1 or receipt.get("operation") != operation:
        raise HeadlessAcceptanceError("receipt schema/operation mismatch")
    expected = {"run_id": plan.run_id, "case_id": plan.case_id, "attempt_nonce": plan.attempt_nonce,
                "origin": origin, "transport": "qga", "injected": False, "outer_binding": asdict(plan.outer_binding)}
    if any(receipt.get(key) != value for key, value in expected.items()):
        raise HeadlessAcceptanceError("receipt identity/origin/outer binding mismatch")
    created = _timestamp(plan.created_at, "plan creation time")
    observed = _timestamp(receipt.get("observed_at"), "receipt observation time")
    if observed < created:
        raise HeadlessAcceptanceError("receipt predates this plan")


def validate_http_receipt(plan: NativeUpdatePlan, receipt: Mapping) -> dict:
    _common(plan, receipt, "headless-native-http", origin="server-fixture")
    fixture = receipt.get("fixture")
    marker = f"amnezia-release-lab:{plan.run_id}:{plan.case_id}:{plan.attempt_nonce}"
    if (not isinstance(fixture, Mapping) or fixture.get("marker") != marker or fixture.get("listener") != plan.fixture.endpoint
            or fixture.get("run_id") != plan.run_id or fixture.get("case_id") != plan.case_id
            or fixture.get("attempt_nonce") != plan.attempt_nonce):
        raise HeadlessAcceptanceError("HTTP log is not bound to the owned fixture")
    _integer(fixture.get("pid"), "fixture PID"); _integer(fixture.get("start_ticks"), "fixture start ticks")
    transcript = receipt.get("requests")
    if not isinstance(transcript, list) or len(transcript) < 2:
        raise HeadlessAcceptanceError("fixture transcript is incomplete")
    expected = (
        (plan.fixture.manifest_path, plan.candidate.manifest_sha256, plan.candidate.manifest_size),
        (plan.fixture.artifact_path, plan.candidate.tar_sha256, plan.candidate.tar_size),
    )
    prior = _timestamp(plan.created_at, "plan creation time")
    artifact_seen = False
    peer = None
    for item in transcript:
        if not isinstance(item, Mapping) or item.get("method") != "GET":
            raise HeadlessAcceptanceError("fixture request is malformed")
        path = item.get("path")
        if path == plan.fixture.artifact_path:
            if artifact_seen: raise HeadlessAcceptanceError("fixture served the candidate artifact more than once")
            artifact_seen = True; digest = plan.candidate.tar_sha256; size = plan.candidate.tar_size
        elif path == plan.fixture.manifest_path:
            if artifact_seen: raise HeadlessAcceptanceError("manifest GET occurred outside the update phase")
            digest = plan.candidate.manifest_sha256; size = plan.candidate.manifest_size
        else:
            raise HeadlessAcceptanceError("fixture request path differs from the plan")
        if item.get("status") != 200 or item.get("sha256") != digest or item.get("bytes") != size or item.get("content_length") != size or item.get("eof") is not True:
            raise HeadlessAcceptanceError("fixture request bytes/EOF differ from the plan")
        try: item_peer = ipaddress.ip_address(item.get("peer"))
        except ValueError as exc: raise HeadlessAcceptanceError("fixture request peer is invalid") from exc
        if item_peer.version != 4 or not item_peer.is_private or item_peer.is_loopback or item_peer.is_unspecified:
            raise HeadlessAcceptanceError("fixture request peer is outside the private guest fixture")
        if peer is None: peer = item_peer
        elif item_peer != peer: raise HeadlessAcceptanceError("fixture transcript mixes request peers")
        timestamp = _timestamp(item.get("observed_at"), "fixture request time")
        if timestamp < prior: raise HeadlessAcceptanceError("fixture transcript timestamps are stale or unordered")
        prior = timestamp
    if not artifact_seen or transcript[0].get("path") != plan.fixture.manifest_path:
        raise HeadlessAcceptanceError("fixture transcript lacks ordered manifest-to-artifact evidence")
    return dict(receipt)


def _raw_json(value: object, label: str, *, path: str) -> object:
    if not isinstance(value, Mapping) or value.get("origin") != "guest" or value.get("transport") != "qga" or value.get("path") != path:
        raise HeadlessAcceptanceError(f"{label} raw source binding is invalid")
    try: raw = base64.b64decode(value.get("bytes_b64"), validate=True)
    except (TypeError, ValueError) as exc: raise HeadlessAcceptanceError(f"{label} raw source encoding is invalid") from exc
    if (not isinstance(value.get("size"), int) or isinstance(value.get("size"), bool) or value.get("size") != len(raw)
            or value.get("sha256") != hashlib.sha256(raw).hexdigest()):
        raise HeadlessAcceptanceError(f"{label} raw source hash/size is invalid")
    try: parsed = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc: raise HeadlessAcceptanceError(f"{label} raw JSON is invalid") from exc
    return parsed


def receipt_sha256(receipt: Mapping) -> str:
    return hashlib.sha256(json.dumps(dict(receipt), sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _identity(value: object, release: ReleaseBytes, label: str) -> tuple[int, int]:
    if not isinstance(value, Mapping) or value.get("version") != release.version:
        raise HeadlessAcceptanceError(f"{label} version mismatch")
    if value.get("amneziad_sha256") != release.amneziad_sha256 or value.get("amneziad_size") != release.amneziad_size or value.get("cli_sha256") != release.cli_sha256 or value.get("cli_size") != release.cli_size:
        raise HeadlessAcceptanceError(f"{label} managed binary identity mismatch")
    pid = _integer(value.get("daemon_pid"), f"{label} daemon PID")
    ticks = _integer(value.get("daemon_start_ticks"), f"{label} daemon start ticks")
    return pid, ticks


def _state_sequence(plan: NativeUpdatePlan, value: object, expected: Sequence[tuple[str, str]]) -> None:
    if not isinstance(value, list) or len(value) != len(expected):
        raise HeadlessAcceptanceError("persisted update state sequence is incomplete")
    prior = _timestamp(plan.created_at, "plan creation time")
    for item, (state, phase) in zip(value, expected):
        if not isinstance(item, Mapping) or item.get("state") != state or item.get("journal_phase") != phase or item.get("attempt_nonce") != plan.attempt_nonce:
            raise HeadlessAcceptanceError("persisted update state transition mismatch")
        observed = _timestamp(item.get("observed_at"), "state transition time")
        if observed < prior: raise HeadlessAcceptanceError("state transition timestamps are stale or unordered")
        prior = observed


def validate_update_receipt(plan: NativeUpdatePlan, receipt: Mapping, http_receipt: Mapping) -> dict:
    _common(plan, receipt, "headless-native-update")
    validate_http_receipt(plan, http_receipt)
    before = _identity(receipt.get("before"), plan.baseline, "before update")
    after = _identity(receipt.get("after"), plan.candidate, "after update")
    if before == after: raise HeadlessAcceptanceError("daemon did not restart onto candidate bytes")
    try: boot_before, boot_after = uuid.UUID(str(receipt.get("boot_id_before"))), uuid.UUID(str(receipt.get("boot_id_after")))
    except ValueError as exc: raise HeadlessAcceptanceError("update boot identity is invalid") from exc
    if boot_before != boot_after: raise HeadlessAcceptanceError("daemon update unexpectedly crossed a guest reboot")
    raw = receipt.get("raw_sources")
    if not isinstance(raw, Mapping): raise HeadlessAcceptanceError("native update raw sources are missing")
    before_doctor = _raw_json(raw.get("before_doctor"), "baseline doctor", path="cli:doctor")
    after_doctor = _raw_json(raw.get("after_doctor"), "candidate doctor", path="cli:doctor")
    if not isinstance(before_doctor, Mapping) or not isinstance(after_doctor, Mapping) or before_doctor.get("ok") is not True or after_doctor.get("ok") is not True or (((after_doctor.get("result") or {}).get("updates") or {}).get("state") != "updated"):
        raise HeadlessAcceptanceError("raw doctor responses do not prove stable candidate health")
    profile_store = _raw_json(raw.get("profile_store"), "profile store", path=FIXED_STORE)
    profile_source = raw.get("profile_store")
    if not isinstance(profile_source, Mapping) or profile_source.get("uid") != 0 or profile_source.get("gid") != 0 or profile_source.get("mode") != "0600":
        raise HeadlessAcceptanceError("ProfileStore ownership/mode readback is invalid")
    profiles = profile_store.get("profiles") if isinstance(profile_store, Mapping) and isinstance(profile_store.get("profiles"), list) else profile_store
    if not isinstance(profiles, list) or not any(isinstance(x, Mapping) and x.get("id") == f"release-lab-{plan.attempt_nonce}" and x.get("updateManifestUrl") == plan.fixture.endpoint.rstrip("/") + plan.fixture.manifest_path and x.get("updatePublicKeyPath") == FIXED_KEY and x.get("autoUpdate") is True for x in profiles):
        raise HeadlessAcceptanceError("installed ProfileStore readback lacks the exact update profile")
    pending = _raw_json(raw.get("pending_state"), "pending update state", path=UPDATE_STATE)
    stable = _raw_json(raw.get("stable_state"), "stable update state", path=UPDATE_STATE)
    rollback = _raw_json(raw.get("rollback_receipt"), "rollback receipt", path=ROLLBACK_RECEIPT)
    journal = _raw_json(raw.get("pending_journal"), "pending update journal", path=UPDATE_JOURNAL)
    absence = _raw_json(raw.get("retired_journal"), "retired update journal", path=UPDATE_JOURNAL + ".absence")
    if not isinstance(pending, Mapping) or not isinstance(stable, Mapping) or not isinstance(rollback, Mapping) or not isinstance(journal, Mapping) or pending.get("version") != 2 or pending.get("state") != "restart_pending" or journal.get("phase") != "restart_pending":
        raise HeadlessAcceptanceError("product did not persist restart_pending update state/journal")
    if stable.get("version") != 2 or stable.get("state") != "updated" or stable.get("lastAppliedVersion") != plan.candidate.version:
        raise HeadlessAcceptanceError("product stable update state is invalid")
    rollback_hashes = rollback.get("rollbackHashes") if isinstance(rollback, Mapping) else None
    if (rollback.get("version") != 1 or rollback.get("rollbackVersion") != plan.baseline.version
            or not isinstance(rollback_hashes, Mapping) or rollback_hashes.get("amneziad") != plan.baseline.amneziad_sha256
            or rollback_hashes.get("amnezia-cli") != plan.baseline.cli_sha256 or absence != {"exists": False}):
        raise HeadlessAcceptanceError("rollback receipt or acknowledged journal retirement is invalid")
    if receipt.get("http_receipt_sha256") != receipt_sha256(http_receipt): raise HeadlessAcceptanceError("update is not bound to HTTP receipt")
    if (receipt.get("fixed_key_path") != FIXED_KEY or receipt.get("fixed_key_sha256") != plan.candidate.key_sha256
            or receipt.get("verified_manifest_sha256") != plan.candidate.manifest_sha256
            or receipt.get("verified_manifest_size") != plan.candidate.manifest_size
            or receipt.get("passed") is not True):
        raise HeadlessAcceptanceError("native update trust/final result mismatch")
    return dict(receipt)


def validate_rollback_receipt(plan: NativeUpdatePlan, receipt: Mapping, update_receipt: Mapping) -> dict:
    _common(plan, receipt, "headless-native-rollback")
    before = _identity(receipt.get("before"), plan.candidate, "before rollback")
    after = _identity(receipt.get("after"), plan.baseline, "after rollback")
    if before == after: raise HeadlessAcceptanceError("rollback did not restart onto N-1 bytes")
    if receipt.get("boot_id_before") != update_receipt.get("boot_id_after") or receipt.get("boot_id_after") != receipt.get("boot_id_before"):
        raise HeadlessAcceptanceError("rollback boot-id chain is discontinuous")
    try: uuid.UUID(str(receipt.get("boot_id_before")))
    except ValueError as exc: raise HeadlessAcceptanceError("rollback boot identity is invalid") from exc
    if _timestamp(receipt.get("observed_at"), "rollback time") <= _timestamp(update_receipt.get("observed_at"), "update time"):
        raise HeadlessAcceptanceError("rollback does not follow update")
    process = receipt.get("cli_process")
    expected_argv = ["/usr/local/bin/amnezia-cli", "--socket", FIXED_SOCKET, "--json", "update-rollback"]
    if not isinstance(process, Mapping) or process.get("argv") != expected_argv:
        raise HeadlessAcceptanceError("rollback did not use the official CLI entrypoint")
    _integer(process.get("pid"), "rollback CLI PID"); _integer(process.get("start_ticks"), "rollback CLI start ticks")
    if isinstance(process.get("exit_code"), bool) or process.get("exit_code") != 0:
        raise HeadlessAcceptanceError("rollback CLI did not return real integer zero")
    if receipt.get("update_receipt_sha256") != receipt_sha256(update_receipt): raise HeadlessAcceptanceError("rollback is not bound to update receipt")
    raw = receipt.get("raw_sources")
    if not isinstance(raw, Mapping): raise HeadlessAcceptanceError("rollback raw sources are missing")
    cli = _raw_json(raw.get("cli_response"), "rollback CLI response", path="cli:update-rollback")
    pending = _raw_json(raw.get("pending_state"), "pending rollback state", path=UPDATE_STATE)
    journal = _raw_json(raw.get("pending_journal"), "pending rollback journal", path=UPDATE_JOURNAL)
    stable = _raw_json(raw.get("stable_state"), "stable rollback state", path=UPDATE_STATE)
    doctor = _raw_json(raw.get("after_doctor"), "rollback doctor", path="cli:doctor")
    absence = _raw_json(raw.get("retired_journal"), "retired rollback journal", path=UPDATE_JOURNAL + ".absence")
    if not all(isinstance(x, Mapping) for x in (cli, pending, journal, stable, doctor)):
        raise HeadlessAcceptanceError("rollback raw JSON values are not objects")
    updates = ((cli.get("result") or {}).get("updates") or {}) if isinstance(cli.get("result"), Mapping) else {}
    if cli.get("ok") is not True or updates.get("state") != "rollback_restart_pending": raise HeadlessAcceptanceError("official CLI did not report pending rollback")
    if pending.get("state") != "rollback_restart_pending" or journal.get("phase") != "rollback_restart_pending" or stable.get("state") != "rolled_back" or stable.get("lastAppliedVersion") != plan.baseline.version or absence != {"exists": False} or doctor.get("ok") is not True or (((doctor.get("result") or {}).get("updates") or {}).get("state") != "rolled_back"):
        raise HeadlessAcceptanceError("product rollback state/journal lifecycle is invalid")
    if receipt.get("passed") is not True:
        raise HeadlessAcceptanceError("rollback evidence is incomplete")
    return dict(receipt)


def validate_reboot_receipt(plan: NativeUpdatePlan, receipt: Mapping, expected_release: ReleaseBytes, prior_receipt: Mapping) -> dict:
    _common(plan, receipt, "headless-native-reboot")
    before_id, after_id = receipt.get("boot_id_before"), receipt.get("boot_id_after")
    try: before_uuid, after_uuid = uuid.UUID(str(before_id)), uuid.UUID(str(after_id))
    except ValueError as exc: raise HeadlessAcceptanceError("reboot boot-id evidence is invalid") from exc
    if before_uuid == after_uuid: raise HeadlessAcceptanceError("guest boot-id did not change")
    if receipt.get("prior_receipt_sha256") != receipt_sha256(prior_receipt): raise HeadlessAcceptanceError("reboot is not bound to the prior stage")
    if prior_receipt.get("boot_id_after") != receipt.get("boot_id_before"): raise HeadlessAcceptanceError("reboot boot-id chain is discontinuous")
    _identity(receipt.get("after"), expected_release, "after reboot")
    raw = receipt.get("raw_sources")
    if not isinstance(raw, Mapping): raise HeadlessAcceptanceError("reboot raw sources are missing")
    marker = _raw_json(raw.get("persistent_marker"), "persistent marker", path=f"/var/lib/amnezia/release-lab-native-{plan.attempt_nonce}.json")
    service = _raw_json(raw.get("service"), "service state", path="systemctl:amneziad.service")
    state = _raw_json(raw.get("stable_state"), "post-reboot update state", path=UPDATE_STATE)
    doctor = _raw_json(raw.get("doctor"), "post-reboot doctor", path="cli:doctor")
    if marker != {"attempt_nonce": plan.attempt_nonce}:
        raise HeadlessAcceptanceError("run-bound persistent marker did not survive reboot")
    if not isinstance(service, Mapping) or service.get("enabled") != "enabled" or service.get("active") != "active":
        raise HeadlessAcceptanceError("headless service did not persist across reboot")
    if not isinstance(state, Mapping) or state.get("state") not in {"updated", "rolled_back"} or state.get("lastAppliedVersion") != expected_release.version or not isinstance(doctor, Mapping) or doctor.get("ok") is not True or receipt.get("passed") is not True:
        raise HeadlessAcceptanceError("reboot persistence evidence is incomplete")
    return dict(receipt)
