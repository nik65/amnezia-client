"""Pure, distinct retained-coordinator evidence contract; performs no I/O.

Synthetic tests prove rejection rules only. A controller must collect genuine
owned-guest raw evidence before this contract can support runtime acceptance.
Legacy native rollback/reboot validators are deliberately unchanged.
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
import posixpath
import re
from urllib.parse import urlparse
import uuid
from copy import deepcopy
from typing import Mapping

from .headless_native_acceptance import (
    FIXED_SOCKET, FIXED_STORE, UPDATE_JOURNAL, UPDATE_STATE,
    HeadlessAcceptanceError, NativeUpdatePlan, _common, _integer, _timestamp,
    receipt_sha256, validate_update_receipt, _identity, _raw_json,
)

ROOT = "/var/lib/amnezia/rollback-coordinator"
RETAINED = ROOT + "/amnezia-cli"
RECORD = ROOT + "/coordinator.json"
UNIT = "/etc/systemd/system/amnezia-rollback-coordinator.service"
AUTHORITY = "retained14Coordinator"


def require(condition, message):
    if not condition:
        raise HeadlessAcceptanceError("coordinated rollback: " + message)


def exact(left, right):
    """JSON semantic equality that never equates booleans with numbers."""
    return json.dumps(left, sort_keys=True, separators=(",", ":"), allow_nan=False) == json.dumps(right, sort_keys=True, separators=(",", ":"), allow_nan=False)


def bound(path):
    return (48*1024*1024 if path == RECORD else 16*1024*1024 if path == FIXED_STORE
            else 4*1024*1024 if path in (UPDATE_STATE, UPDATE_JOURNAL) else 16384 if path == UNIT else 4*1024*1024)


def raw(value, path, mode="0600", *, maximum=None):
    if maximum is None: maximum = bound(path)
    require(isinstance(value, Mapping), "raw source missing")
    require(value.get("origin") == "guest" and value.get("transport") == "qga"
            and value.get("path") == path, "raw source binding")
    require(value.get("uid") == 0 and type(value.get("uid")) is int
            and type(value.get("gid")) is int and value["gid"] >= 0
            and value.get("mode") == mode, "raw source ownership/mode")
    require(value.get("nofollow") is True and value.get("regular") is True
            and value.get("nlink") == 1 and type(value.get("nlink")) is int
            and value.get("stable_identity") is True, "raw descriptor proof")
    try:
        data = base64.b64decode(value.get("bytes_b64"), validate=True)
    except (ValueError, TypeError) as exc:
        raise HeadlessAcceptanceError("coordinated rollback: raw encoding") from exc
    require(type(value.get("size")) is int and value["size"] == len(data)
            and 0 < len(data) <= maximum
            and value.get("sha256") == hashlib.sha256(data).hexdigest(), "raw hash/size")
    return data


def obj(value, path, mode="0600"):
    try:
        def unique(pairs):
            result = {}
            for key, item in pairs:
                require(key not in result, "duplicate JSON key")
                result[key] = item
            return result
        result = json.loads(raw(value, path, mode), object_pairs_hook=unique)
    except (ValueError, UnicodeError) as exc:
        raise HeadlessAcceptanceError("coordinated rollback: raw JSON") from exc
    require(isinstance(result, dict), "raw JSON object")
    return result


def pair(release):
    return {"amneziad": {"sha256": release.amneziad_sha256, "size": release.amneziad_size},
            "amnezia-cli": {"sha256": release.cli_sha256, "size": release.cli_size}}


def observation(value, release, state):
    require(isinstance(value, Mapping) and exact(value.get("pair"), pair(release))
            and value.get("version") == release.version, "observed binary pair/version")
    pid = _integer(value.get("daemon_pid"), "coordinator daemon PID")
    ticks = value.get("start_ticks")
    require(isinstance(ticks, str) and ticks.isdecimal() and int(ticks) > 0,
            "observed process start ticks")
    doctor = value.get("doctor", {})
    result = doctor.get("result", {}) if isinstance(doctor, Mapping) else {}
    updates = result.get("updates", {}) if isinstance(result, Mapping) else {}
    require(doctor.get("ok") is True and result.get("ready") is True
            and updates.get("state") == state
            and updates.get("lastAppliedVersion") == release.version
            and updates.get("lastError") == "" and updates.get("recoveryRequired") is False,
            "observed doctor state")
    return pid, ticks


def process(value, executable, digest, argv):
    require(isinstance(value, Mapping) and value.get("exe") == executable
            and value.get("exe_sha256") == digest and value.get("argv") == argv
            and type(value.get("exit_code")) is int and value["exit_code"] == 0,
            "official process identity/argv/exit")
    _integer(value.get("pid"), "coordinator CLI PID")
    _integer(value.get("start_ticks"), "coordinator CLI start ticks")


def record(raw_record, plan, phase, operation=None):
    value = obj(raw_record, RECORD)
    require(type(value.get("schema")) is int and value["schema"] == 1
            and value.get("authority") == AUTHORITY and value.get("phase") == phase,
            "coordinator record schema/authority/phase")
    try:
        uuid.UUID(value.get("operationId"))
    except (ValueError, TypeError, AttributeError) as exc:
        raise HeadlessAcceptanceError("coordinated rollback: operation identity") from exc
    require(operation is None or value["operationId"] == operation, "operation changed")
    require(value.get("targetVersion") == plan.baseline.version
            and value.get("originalVersion") == plan.candidate.version
            and exact(value.get("targetPair"), pair(plan.baseline))
            and exact(value.get("originalPair"), pair(plan.candidate))
            and value.get("retainedSha256") == plan.candidate.cli_sha256,
            "coordinator release authority")
    return value


def executable_metadata(value, plan):
    require(isinstance(value, Mapping) and value.get("kind") == "guest-descriptor-metadata"
            and value.get("origin") == "guest" and value.get("transport") == "qga"
            and value.get("path") == RETAINED and type(value.get("uid")) is int and value["uid"] == 0
            and type(value.get("gid")) is int and value["gid"] >= 0
            and value.get("mode") == "0500" and value.get("nofollow") is True
            and value.get("regular") is True and type(value.get("nlink")) is int and value["nlink"] == 1
            and value.get("stable_identity") is True and type(value.get("size")) is int
            and value["size"] == plan.candidate.cli_size and value.get("sha256") == plan.candidate.cli_sha256,
            "retained14 executable descriptor/known-archive hash")


def raw_outcome(value, path):
    """Decode genuine guest command/lstat output, without invented file stat."""
    require(isinstance(value, Mapping) and value.get("kind") in
            {"guest-lstat-outcome", "guest-exec-outcome"}, "guest outcome kind")
    return _raw_json(value, "coordinated guest outcome", path=path)


def absence(value, inspected_path, label):
    require(isinstance(value, Mapping) and value.get("kind") == "guest-lstat-outcome"
            and value.get("inspected_path") == inspected_path, label + " source")
    decoded = raw_outcome(value, inspected_path + ".absence")
    require(isinstance(decoded, Mapping) and set(decoded) == {"exists"}
            and decoded["exists"] is False, label)


def validate_coordinated_candidate_reboot(plan, value, prior):
    _common(plan, value, "headless-coordinated-candidate-reboot")
    require(value.get("prior_receipt_sha256") == receipt_sha256(prior)
            and value.get("boot_id_before") == prior.get("boot_id_after"), "candidate reboot prior binding")
    try:
        before, after = uuid.UUID(value.get("boot_id_before")), uuid.UUID(value.get("boot_id_after"))
    except (ValueError, TypeError, AttributeError) as exc:
        raise HeadlessAcceptanceError("coordinated rollback: candidate reboot IDs") from exc
    require(before != after, "candidate did not reboot")
    after = _raw_json(value.get("after_raw"), "candidate reboot identity", path="identity:post-reboot")
    _identity(after, plan.candidate, "coordinated candidate reboot")
    if "after" in value: require(exact(value["after"], after), "candidate reboot derived identity differs")
    sources = value.get("raw_sources", {})
    marker = _raw_json(sources.get("persistent_marker"), "candidate reboot marker", path=f"/var/lib/amnezia/release-lab-native-{plan.attempt_nonce}.json")
    require(exact(marker, {"attempt_nonce":plan.attempt_nonce}), "candidate reboot marker")
    service = _raw_json(sources.get("service"), "candidate reboot service", path="systemctl:amneziad.service")
    require(service.get("enabled") == "enabled" and service.get("active") == "active", "candidate reboot service")
    state = _raw_json(sources.get("stable_state"), "candidate reboot state", path=UPDATE_STATE)
    doctor = _raw_json(sources.get("doctor"), "candidate reboot doctor", path="cli:doctor")
    updates = doctor.get("result", {}).get("updates", {})
    require(state.get("state") in {"updated", "no_update"}
            and state.get("lastAppliedVersion") == plan.candidate.version
            and state.get("lastError") == "" and doctor.get("ok") is True
            and doctor.get("result", {}).get("ready") is True
            and updates.get("state") in {"updated", "no_update"}
            and updates.get("lastAppliedVersion") == plan.candidate.version
            and updates.get("lastError") == "" and updates.get("recoveryRequired") is False,
            "candidate reboot healthy updater")
    absence(sources.get("retired_journal"), UPDATE_JOURNAL, "candidate reboot retired journal")


def _held(plan, receipt, candidate_reboot):
    _common(plan, receipt, "headless-coordinated-rollback-with-pause")
    require(type(receipt.get("schema")) is int, "typed receipt schema")
    require(receipt.get("candidate_reboot_sha256") == receipt_sha256(candidate_reboot),
            "candidate reboot receipt binding")
    raw_sources = receipt.get("raw_sources")
    require(isinstance(raw_sources, Mapping), "raw sources missing")
    held = record(raw_sources.get("held_record"), plan, "held")
    operation = held["operationId"]
    require(held.get("acknowledgementAuthority") == AUTHORITY, "ACK authority")
    process(receipt.get("rollback_process"), "/usr/local/bin/amnezia-cli",
            plan.candidate.cli_sha256,
            ["/usr/local/bin/amnezia-cli", "--socket", FIXED_SOCKET, "--json", "update-rollback"])
    cli = raw_outcome(raw_sources.get("rollback_stdout"), "cli:update-rollback")
    result = cli.get("result", {})
    pending_result = isinstance(result, Mapping) and result.get("updates", {}).get("state") == "rollback_restart_pending"
    accepted = (isinstance(result, Mapping) and result.get("state") == "rollback_coordinator_accepted_pending"
                and result.get("pending") is True and result.get("authority") == "retained14CoordinatorRequest"
                and result.get("coordinator", {}).get("authority") == AUTHORITY
                and result.get("coordinator", {}).get("phase") == "rollback_requested")
    require(cli.get("ok") is True and (pending_result or accepted), "real official rollback pending result")

    original_bytes = raw(raw_sources.get("original_profiles"), FIXED_STORE)
    paused_bytes = raw(raw_sources.get("paused_profiles"), FIXED_STORE)
    original = obj(raw_sources["original_profiles"], FIXED_STORE)
    paused = obj(raw_sources["paused_profiles"], FIXED_STORE)
    require(original.get("version") == 1 and isinstance(original.get("profiles"), list)
            and original["profiles"] and type(original.get("version")) is int, "original profile store")
    expected = deepcopy(original)
    enabled = []
    ids = []
    for profile in expected["profiles"]:
        require(isinstance(profile, dict) and isinstance(profile.get("id"), str)
                and profile["id"] and type(profile.get("autoUpdate", False)) is bool, "typed profile")
        ids.append(profile["id"])
        if profile.get("autoUpdate", False):
            enabled.append(profile["id"])
            profile["autoUpdate"] = False
    require(len(ids) == len(set(ids)) and enabled and exact(paused, expected),
            "all-profile pause/nonpolicy preservation")
    require(held.get("originalProfilesSha256") == hashlib.sha256(original_bytes).hexdigest()
            and held.get("pausedProfilesSha256") == hashlib.sha256(paused_bytes).hexdigest()
            and type(held.get("pausedProfileCount")) is int
            and held["pausedProfileCount"] == len(enabled), "pause hash/count/IDs")

    require(held.get("originalProfilesBase64") == base64.b64encode(original_bytes).decode(),
            "saved original profile bytes")
    executable_metadata(raw_sources.get("retained_executable"), plan)
    unit = raw(raw_sources.get("retained_unit"), UNIT, "0644")
    expected_unit = ("[Unit]\nDescription=Amnezia rollback-with-pause recovery\nAfter=amneziad.service\n\n"
                     "[Service]\nType=oneshot\nUser=root\nUMask=0077\nExecStart=" + RETAINED +
                     " --rollback-coordinator run\nTimeoutStartSec=120\nNoNewPrivileges=true\nPrivateTmp=true\n"
                     "ProtectSystem=strict\nReadWritePaths=/var/lib/amnezia /usr/local/bin\n\n"
                     "[Install]\nWantedBy=multi-user.target\n").encode()
    require(unit == expected_unit, "exact retained recovery unit")
    before = observation(held.get("observed13"), plan.baseline, "rollback_restart_pending")
    final = observation(held.get("final13"), plan.baseline, "disabled")
    require(before != final, "13 reload after ACK")
    stop = held.get("stopEvidence", {})
    require(stop.get("verifiedStopped") is True and stop.get("observedProcessGone") is True
            and exact(stop.get("observedIdentity"), held["observed13"]), "verified stopped13 evidence")
    pending = held.get("pendingEvidence", {})
    pending_bytes = {}
    for name in ("state", "journal"):
        try:
            encoded = pending[name + "BytesBase64"]
            data = base64.b64decode(encoded, validate=True)
            require(base64.b64encode(data).decode() == encoded and 0 < len(data) <= 4*1024*1024,
                    "durable pending canonical base64/size")
            require(hashlib.sha256(data).hexdigest() == pending[name + "Sha256"], "durable pending bytes hash")
            pending_bytes[name] = json.loads(data)
            require(isinstance(pending_bytes[name], dict), "durable pending JSON object")
        except (KeyError, TypeError, ValueError, UnicodeError) as exc:
            raise HeadlessAcceptanceError("coordinated rollback: durable pending source") from exc
    state, journal = pending_bytes["state"], pending_bytes["journal"]
    require(state.get("state") == "rollback_restart_pending"
            and state.get("lastAppliedVersion") == plan.baseline.version
            and journal.get("phase") == "rollback_restart_pending"
            and journal.get("operation") == "rollback"
            and journal.get("candidateVersion") == plan.baseline.version
            and journal.get("currentVersion") == plan.baseline.version
            and journal.get("installDirectory") == "/usr/local/bin"
            and exact(journal.get("candidateHashes"), {n:v["sha256"] for n,v in pair(plan.baseline).items()})
            and exact(journal.get("candidateSizes"), {n:v["size"] for n,v in pair(plan.baseline).items()}),
            "real pending updater journal target")
    stable = obj(raw_sources.get("held_state"), UPDATE_STATE)
    ack = held.get("coordinatorAcknowledgement", {})
    require(ack.get("authority") == AUTHORITY and ack.get("result") == "disabled"
            and ack.get("returnedSuccessfully") is True
            and ack.get("postStateSha256") == raw_sources["held_state"]["sha256"], "genuine coordinator ACK")
    require(stable.get("state") == "disabled" and stable.get("lastAppliedVersion") == plan.baseline.version
            and stable.get("lastError") == "",
            "held updater stable state")
    absence(raw_sources.get("held_journal_absence"), UPDATE_JOURNAL, "journal retirement")
    times = [_timestamp(x, "coordinator timeline") for x in
             (held.get("createdAt"), stop.get("observedAt"), pending.get("capturedAt"),
              ack.get("completedAt"), held.get("updatedAt"))]
    require(times == sorted(times), "stop/pending/ACK/held chronology")

    return raw_sources, held, original_bytes, paused_bytes, unit, final, times, operation


def validate_coordinated_held(plan, receipt, candidate_reboot, update, http):
    """Validate actual held snapshot before requesting reboot or resume."""
    validate_update_receipt(plan, update, http)
    validate_coordinated_candidate_reboot(plan, candidate_reboot, update)
    _held(plan, receipt, candidate_reboot)
    return {"authority":AUTHORITY, "held_snapshot_validated":True, "legacy_native_rollback_pass":False}


def validate_coordinated_held_reboot(plan, receipt, candidate_reboot):
    """Validate held reboot evidence before permitting explicit resume."""
    raw_sources, held, original_bytes, paused_bytes, unit, final, times, operation = _held(plan, receipt, candidate_reboot)
    reboot = receipt.get("held_reboot", {})
    require(reboot.get("prior_held_record_sha256") == raw_sources["held_record"]["sha256"], "held reboot binding")
    require(reboot.get("boot_id_before") == candidate_reboot.get("boot_id_after"), "rollback boot chain")
    try:
        old_boot = uuid.UUID(reboot.get("boot_id_before")); new_boot = uuid.UUID(reboot.get("boot_id_after"))
    except (ValueError, TypeError, AttributeError) as exc:
        raise HeadlessAcceptanceError("coordinated rollback: held reboot UUID") from exc
    require(old_boot != new_boot, "real held reboot")
    after_record = record(raw_sources.get("held_reboot_record"), plan, "held", operation)
    require(exact(after_record, held), "held record changed across reboot")
    require(observation(reboot.get("after"), plan.baseline, "disabled") != final, "held reboot process reload")
    require(raw(raw_sources.get("held_reboot_profiles"), FIXED_STORE) == paused_bytes,
            "held policy survived reboot")
    absence(raw_sources.get("held_reboot_journal_absence"), UPDATE_JOURNAL, "held reboot journal absence")

    native = reboot.get("native_observation", {})
    require(native.get("boot_id_before") == reboot["boot_id_before"]
            and native.get("boot_id_after") == reboot["boot_id_after"], "held reboot native boot binding")
    actual_identity = _raw_json(native.get("after_raw"), "held reboot identity", path="identity:post-reboot")
    actual_pid, actual_ticks = _identity(actual_identity, plan.baseline, "held reboot native identity")
    require((actual_pid, str(actual_ticks)) == observation(reboot["after"], plan.baseline, "disabled"),
            "held reboot identity observations differ")
    native_raw = native.get("raw_sources", {})
    marker = _raw_json(native_raw.get("persistent_marker"), "held reboot marker", path=f"/var/lib/amnezia/release-lab-native-{plan.attempt_nonce}.json")
    require(exact(marker, {"attempt_nonce":plan.attempt_nonce}), "held reboot marker")
    service = _raw_json(native_raw.get("service"), "held reboot service", path="systemctl:amneziad.service")
    require(service.get("enabled") == "enabled" and service.get("active") == "active", "held reboot service")
    reboot_state = _raw_json(native_raw.get("stable_state"), "held reboot state", path=UPDATE_STATE)
    require(reboot_state.get("state") == "disabled" and reboot_state.get("lastAppliedVersion") == plan.baseline.version
            and reboot_state.get("lastError") == "", "held reboot actual updater state")
    reboot_doctor = _raw_json(native_raw.get("doctor"), "held reboot doctor", path="cli:doctor")
    doctor_observation = dict(reboot["after"], doctor=reboot_doctor)
    observation(doctor_observation, plan.baseline, "disabled")
    return {"authority":AUTHORITY, "held_reboot_validated":True, "legacy_native_rollback_pass":False}


def _bytes64(value, digest, label, limit=4*1024*1024):
    try:
        data = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise HeadlessAcceptanceError("coordinated rollback: " + label) from exc
    require(len(data) <= limit and hashlib.sha256(data).hexdigest() == digest, label + " bytes/hash")
    return data


def _number(value, label):
    require(type(value) in (int, float) and math.isfinite(value) and value >= 0, label)
    return value


def validate_coordinated_http_ledger(plan, ledger, required_boots, *, held_at, resume_at, expected_sources, expected_daemons):
    """Validate per-boot real readiness/daemon ordering and retained request logs.

    Expected source hashes come from the controller's reviewed source capsule,
    never from the ledger's own claims. This function performs no network I/O.
    """
    require(isinstance(expected_sources, Mapping) and set(expected_sources) ==
            {"server_sha256", "wrapper_sha256", "unit_sha256"}, "external HTTP source pins required")
    require(all(isinstance(v, str) and len(v) == 64 and all(c in "0123456789abcdef" for c in v)
                for v in expected_sources.values()), "HTTP source pin format")
    require(isinstance(ledger, Mapping) and ledger.get("schema") == "amnezia-coordinated-http-ledger-v1"
            and ledger.get("run_id") == plan.run_id and ledger.get("case_id") == plan.case_id
            and ledger.get("attempt_nonce") == plan.attempt_nonce
            and ledger.get("endpoint") == plan.fixture.endpoint
            and ledger.get("diagnosticOnly") is True and ledger.get("releasePass") is False,
            "HTTP epoch ledger binding")
    encoded = _bytes64(ledger.get("raw_ledger_bytes_base64"), ledger.get("raw_ledger_sha256"), "HTTP epoch ledger", 1024*1024)
    try: metadata = [json.loads(line) for line in encoded.splitlines()]
    except (ValueError, UnicodeError) as exc: raise HeadlessAcceptanceError("coordinated rollback: epoch JSONL") from exc
    epochs = ledger.get("epochs")
    require(isinstance(epochs, list) and len(epochs) == len(metadata) == len(required_boots)
            and len(set(required_boots)) == len(required_boots), "complete HTTP boot epochs")
    require(isinstance(expected_daemons, (list, tuple)) and len(expected_daemons) == len(required_boots), "HTTP daemon chain associations")
    prior_reset = 0.0
    for epoch, original, boot, expected_daemon in zip(epochs, metadata, required_boots, expected_daemons):
        metadata_keys = {"boot_id", "pid", "start_ticks", "ready_monotonic_us", "epoch", "request_log", "cursor",
                         "reset_receipt", "server_sha256", "wrapper_sha256", "unit_sha256", "enablement", "address",
                         "run_id", "attempt_nonce"}
        require(isinstance(epoch, Mapping) and isinstance(original, Mapping) and set(original) == metadata_keys
                and all(key in epoch and exact(epoch[key], val) for key,val in original.items()), "immutable epoch metadata")
        try: uuid.UUID(boot)
        except (ValueError, TypeError, AttributeError) as exc: raise HeadlessAcceptanceError("coordinated rollback: epoch boot ID") from exc
        pid = _integer(epoch.get("pid"), "HTTP epoch PID")
        ticks = _integer(epoch.get("start_ticks"), "HTTP epoch ticks")
        ready = _integer(epoch.get("ready_monotonic_us"), "HTTP ready monotonic time")
        identity = boot + "-" + str(pid) + "-" + str(ticks)
        root = "/var/lib/amnezia-release-lab/coordinated-http/" + plan.attempt_nonce + "/epochs/" + identity
        require(epoch.get("boot_id") == boot and epoch.get("epoch") == identity
                and epoch.get("request_log") == root + "/requests.jsonl" and epoch.get("cursor") == root + "/cursor.json"
                and epoch.get("run_id") == plan.run_id and epoch.get("attempt_nonce") == plan.attempt_nonce
                and epoch.get("address") == urlparse(plan.fixture.endpoint).hostname
                and all(epoch.get(k) == v for k,v in expected_sources.items()), "HTTP epoch source/identity")
        enablement = epoch.get("enablement", {})
        unit_name = "amnezia-lab-http-" + plan.attempt_nonce + ".service"
        link = "/etc/systemd/system/multi-user.target.wants/" + unit_name
        target = enablement.get("target")
        require(isinstance(enablement, Mapping) and enablement.get("path") == link
                and type(enablement.get("uid")) is int and enablement["uid"] == 0
                and enablement.get("unit_sha256") == expected_sources["unit_sha256"]
                and isinstance(target, str) and posixpath.normpath(target if target.startswith("/")
                    else posixpath.join(posixpath.dirname(link), target)) == "/etc/systemd/system/" + unit_name,
                "persistent HTTP unit enablement")
        reset = epoch.get("reset_receipt", {})
        require(isinstance(reset, Mapping) and reset.get("ok") is True
                and reset.get("run_id") == plan.run_id and reset.get("attempt_nonce") == plan.attempt_nonce
                and reset.get("reset_token") == plan.attempt_nonce
                and type(reset.get("offset")) is int and reset["offset"] == 0
                and reset.get("empty_sha256") == hashlib.sha256(b"").hexdigest(), "epoch reset proof")
        reset_at = _number(reset.get("reset_at"), "epoch reset timestamp")
        require(reset_at > prior_reset, "epoch reset chronological order")
        prior_reset = reset_at
        health = reset.get("cleared_health_request", {})
        require(isinstance(health, Mapping) and health.get("method") == "GET" and health.get("path") == "/healthz"
                and type(health.get("status")) is int and health["status"] == 200 and health.get("eof") is True
                and health.get("run_id") == plan.run_id and health.get("attempt_nonce") == plan.attempt_nonce,
                "epoch pre-reset health")
        transcript = epoch.get("transcript")
        transcript_bytes = _bytes64(epoch.get("transcript_bytes_base64"), epoch.get("transcript_sha256"), "epoch transcript")
        try: decoded = json.loads(transcript_bytes)
        except (ValueError, UnicodeError) as exc: raise HeadlessAcceptanceError("coordinated rollback: transcript JSON") from exc
        require(exact(decoded, transcript) and isinstance(transcript, Mapping)
                and transcript.get("reset_token") == reset.get("reset_token")
                and type(reset.get("log_inode")) is int and reset["log_inode"] > 0
                and type(transcript.get("log_inode")) is int and transcript["log_inode"] == reset["log_inode"]
                and type(transcript.get("start_offset")) is int and transcript["start_offset"] == 0,
                "transcript reset/inode binding")
        require(_number(transcript.get("finished_at"), "transcript end") >= resume_at, "held HTTP end coverage")
        require(type(transcript.get("log_size")) is int and 0 <= transcript["log_size"] <= 1024*1024
                and isinstance(transcript.get("log_sha256"), str) and len(transcript["log_sha256"]) == 64,
                "bounded retained HTTP log")
        requests = transcript.get("rows")
        require(isinstance(requests, list) and len(requests) <= 4096, "HTTP request ledger rows")
        prior = reset_at
        for request in requests:
            require(isinstance(request, Mapping) and isinstance(request.get("method"), str)
                    and isinstance(request.get("path"), str) and type(request.get("status")) is int,
                    "HTTP row types")
            stamp = _number(request.get("observed_at"), "HTTP row time")
            require(prior <= stamp <= transcript["finished_at"], "HTTP row chronology")
            prior = stamp
            require(not (held_at <= stamp < resume_at and request["method"] == "GET"
                         and request["path"] == plan.fixture.artifact_path), "artifact GET while held")
        observations = epoch.get("daemon_observations")
        require(isinstance(observations, list) and 0 < len(observations) <= 32,
                "bounded immutable daemon observation checkpoints")
        selected, identities = [], set()
        for captured in observations:
            require(isinstance(captured, Mapping), "daemon checkpoint entry")
            observation_bytes = _bytes64(captured.get("daemon_observation_bytes_base64"), captured.get("daemon_observation_sha256"), "daemon boot observation")
            try: actual = json.loads(observation_bytes)
            except (ValueError, UnicodeError) as exc: raise HeadlessAcceptanceError("coordinated rollback: daemon observation JSON") from exc
            require(exact(actual, captured.get("daemon_observation")) and isinstance(actual, Mapping)
                    and actual.get("boot_id") == boot, "daemon observation boot binding")
            daemon_pid = _integer(actual.get("pid"), "epoch daemon PID")
            daemon_ticks = _integer(actual.get("start_ticks"), "epoch daemon ticks")
            identity_key = (daemon_pid, daemon_ticks)
            require(identity_key not in identities, "duplicate daemon checkpoint identity")
            identities.add(identity_key)
            if identity_key == tuple(expected_daemon): selected.append(actual)
        require(len(selected) == 1, "HTTP ready proof belongs to unrelated daemon")
        actual = selected[0]
        daemon_pid = actual["pid"]
        observed = _integer(actual.get("observed_monotonic_us"), "daemon observed monotonic time")
        props_bytes = _bytes64(actual.get("systemctl_bytes_base64"), actual.get("systemctl_sha256"), "systemctl properties")
        try: props = dict(line.split("=",1) for line in props_bytes.decode().splitlines() if line)
        except (ValueError, UnicodeError) as exc: raise HeadlessAcceptanceError("coordinated rollback: systemctl properties format") from exc
        require(exact(props, actual.get("properties")) and props.get("MainPID") == str(daemon_pid)
                and props.get("ActiveState") == "active" and props.get("SubState") == "running"
                and props.get("FragmentPath") == "/etc/systemd/system/amneziad.service" and props.get("DropInPaths") == "",
                "genuine unmodified daemon unit properties")
        started = props.get("ExecMainStartTimestampMonotonic", "")
        active = props.get("ActiveEnterTimestampMonotonic", "")
        require(isinstance(started, str) and started.isdecimal() and isinstance(active, str) and active.isdecimal()
                and ready <= int(started) <= int(active) <= observed, "HTTP was not ready before actual daemon")
    require(_number(epochs[1]["reset_receipt"]["reset_at"], "candidate boot reset") <= held_at,
            "held HTTP start coverage")
    return {"boot_epochs_validated":len(epochs), "artifact_get_while_held":False}


def validate_coordinated_rollback_chain(plan: NativeUpdatePlan, receipt: Mapping,
                                      update: Mapping, candidate_reboot: Mapping,
                                      http: Mapping, *, expected_http_sources: Mapping) -> dict:
    """Validate update/reboot, held rollback/reboot and explicit resume chain.

    ``raw_sources`` and phase observations are mandatory; no PASS flag or
    signed host receipt substitutes for these guest/controller source records.
    """
    validate_update_receipt(plan, update, http)
    validate_coordinated_candidate_reboot(plan, candidate_reboot, update)
    raw_sources, held, original_bytes, paused_bytes, unit, final, times, operation = _held(plan, receipt, candidate_reboot)
    validate_coordinated_held_reboot(plan, receipt, candidate_reboot)
    reboot = receipt["held_reboot"]
    resumed = record(raw_sources.get("resumed_record"), plan, "resumed", operation)
    process(receipt.get("resume_process"), RETAINED, plan.candidate.cli_sha256,
            [RETAINED, "--rollback-coordinator", "resume"])
    require(raw(raw_sources.get("resumed_profiles"), FIXED_STORE) == original_bytes,
            "exact policy restored on explicit resume")
    require(resumed.get("originalProfilesSha256") == held["originalProfilesSha256"]
            and resumed.get("pausedProfilesSha256") == held["pausedProfilesSha256"], "resume policy authority")
    for key in ("originalProfilesBase64", "originalProfilesSha256", "pausedProfilesSha256",
                "acknowledgementAuthority", "coordinatorAcknowledgement", "pendingEvidence", "stopEvidence"):
        require(exact(resumed.get(key), held.get(key)), "resume changed held authority")
    stopped_resume = observation(resumed.get("resumeStoppedService"), plan.baseline, "disabled")
    require(stopped_resume == observation(reboot.get("after"), plan.baseline, "disabled"),
            "resume did not stop held reboot service")
    final_resume = resumed.get("resumeObservedService", {})
    resume_state = final_resume.get("doctor", {}).get("result", {}).get("updates", {}).get("state")
    require(resume_state in {"disabled", "no_update", "updated", "checking", "restart_pending"}, "resumed doctor phase")
    require(observation(final_resume, plan.baseline, resume_state) != stopped_resume, "resume service did not reload")
    reply = raw_outcome(raw_sources.get("resume_stdout"), "cli:coordinator-resume")
    require(reply.get("ok") is True and reply.get("code") == "resumed"
            and reply.get("coordinator", {}).get("operationId") == operation, "successful explicit resume")
    require(raw(raw_sources.get("retired_unit"), UNIT, "0644") == unit, "retired unit bytes changed")
    retired = raw_outcome(raw_sources.get("retired_unit_state"), "systemctl:amnezia-rollback-coordinator.service")
    require(retired.get("enabled") == "disabled", "coordinator recovery unit not disabled")
    require(receipt.get("retained_resumed_record") is True, "terminal resumed record must stay retained")
    # A complete, run-bound server-fixture observation window is necessary to
    # prove absence of downloads; an empty host list alone is not evidence.
    process_times = receipt["resume_process"]
    for name in ("invoked_at", "observed_at"):
        require(isinstance(process_times.get(name), str)
                and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z", process_times[name]),
                "precise guest resume " + name)
    resume_started = _timestamp(process_times["invoked_at"], "explicit resume invocation time")
    resume_observed = _timestamp(process_times["observed_at"], "explicit resume process observation")
    require(times[-1] < resume_started <= resume_observed
            and resume_started <= _timestamp(resumed.get("updatedAt"), "resume time")
            and resume_observed <= _timestamp(receipt.get("observed_at"), "final collection time"),
            "resume chronology")
    validate_coordinated_http_ledger(plan, receipt.get("held_http"),
        [candidate_reboot["boot_id_before"], candidate_reboot["boot_id_after"], reboot["boot_id_after"]],
        held_at=times[-1].timestamp(), resume_at=resume_started.timestamp(), expected_sources=expected_http_sources,
        expected_daemons=[_identity(update.get("after"), plan.candidate, "initial updated daemon"),
            _identity(_raw_json(candidate_reboot.get("after_raw"), "candidate boot identity", path="identity:post-reboot"), plan.candidate, "candidate boot daemon"),
            (reboot["after"]["daemon_pid"], int(reboot["after"]["start_ticks"]))])

    return {"operation":"headless-coordinated-rollback-with-pause", "authority":AUTHORITY,
            "operation_id":operation, "held_version":plan.baseline.version,
            "runtime_evidence_validated":True, "legacy_native_rollback_pass":False,
            "automatic_publication_approved":False}
