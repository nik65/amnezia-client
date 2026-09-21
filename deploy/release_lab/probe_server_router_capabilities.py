#!/usr/bin/env python3
"""Probe one disposable server-router overlay through the release-lab guards.

The sealed golden is supplied by an owned state root and is only opened as the
read-only backing image for a fresh overlay. The probe records guest capability
readback through QGA and destroys only the disposable overlay/process through
LabController.reset(). It never changes the active profile or golden path.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from lab import (
    LabController,
    LabError,
    QgaClient,
    QmpClient,
    load_profiles,
    sha256_file,
)


PROFILE = "server-router"
BUSYBOX = "docker.io/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662"


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_marker(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    return values


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", args.run_id):
        raise SystemExit("run id is unsafe")
    root = args.state_root.resolve()
    output = args.output.resolve()
    if output.parent != root:
        raise SystemExit("probe output must be directly under the owned state root")
    profile = load_profiles()[PROFILE]
    base = (root / profile["base_image"]).resolve()
    readiness = (root / profile["golden_readiness"]).resolve()
    expected_run_dir = root / "runs" / args.run_id / PROFILE
    if len(str(expected_run_dir / "qmp.sock")) >= 100 or len(str(expected_run_dir / "qga.sock")) >= 100:
        raise SystemExit("probe state root is too deep for QEMU Unix socket limits")
    before_sha, before_size = sha256_file(base)
    readiness_doc = json.loads(readiness.read_text(encoding="utf-8"))
    if readiness_doc.get("base_sha256") != before_sha or readiness_doc.get("sealed") is not True:
        raise SystemExit("probe backing golden does not match its sealed readiness receipt")

    controller = LabController(root)
    run = {
        "schema": 1,
        "run_id": args.run_id,
        "dry_run": False,
        "windows_backend": "qemu",
        "profiles": {PROFILE: {"status": "created", "vm": None}},
    }
    state = controller.load_state()
    if args.run_id in state.get("runs", {}):
        raise SystemExit("probe run already exists")
    state.setdefault("runs", {})[args.run_id] = run
    controller.save_state(state)
    run_dir = root / "runs" / args.run_id / PROFILE
    run_dir.mkdir(parents=True, mode=0o700)
    overlay = run_dir / "overlay.qcow2"
    (run_dir / ".owned-overlay.json").write_text(
        json.dumps({"run_id": args.run_id, "profile": PROFILE, "overlay": str(overlay)}, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    receipt: dict[str, object] = {
        "schema": 1,
        "run_id": args.run_id,
        "profile": PROFILE,
        "transport": "qga",
        "origin": "guest",
        "injected": False,
        "started_at": now(),
        "base_sha256_before": before_sha,
        "base_size": before_size,
        "sealed_readiness": readiness_doc,
    }
    failure: str | None = None
    cleanup: dict[str, object] | None = None
    try:
        controller.start(args.run_id, PROFILE)
        vm = controller.get_run(args.run_id)["profiles"][PROFILE]["vm"]
        deadline = time.monotonic() + 30
        qmp_path = Path(vm["qmp_socket"])
        qga_path = Path(vm["qga_socket"])
        while (not qmp_path.exists() or not qga_path.exists()) and time.monotonic() < deadline:
            proc_path = Path(f"/proc/{int(vm['pid'])}")
            if not proc_path.exists():
                raise LabError(f"owned QEMU exited before QMP/QGA sockets appeared; see {root / 'runs' / args.run_id / PROFILE / 'qemu.log'}")
            time.sleep(0.2)
        if not qmp_path.exists() or not qga_path.exists():
            raise LabError("owned QEMU did not publish QMP and QGA sockets within 30s")
        qmp = QmpClient(Path(vm["qmp_socket"]))
        qga = QgaClient(Path(vm["qga_socket"]))
        controller.guest_probe(args.run_id, PROFILE)
        owned = controller.owned_vm(args.run_id, PROFILE)
        qmp_status = qmp.request("query-status")
        if "return" not in qmp_status:
            raise LabError(f"owned QMP status failed: {qmp_status}")
        if not qga.sync():
            raise LabError("owned QGA sync failed")
        probe_marker = f"amnezia-release-lab:{args.run_id}:{PROFILE}\n"
        qga.write_file("/var/lib/amnezia-lab/probe-marker", probe_marker.encode("utf-8"))
        if qga.read_file("/var/lib/amnezia-lab/probe-marker").decode("utf-8", "strict") != probe_marker:
            raise LabError("guest run/profile probe marker did not round-trip through QGA")
        marker_text = qga.read_file("/var/lib/amnezia-lab/READY").decode("utf-8", "strict")
        marker = parse_marker(marker_text)
        expected_marker = {
            "profile": PROFILE,
            "phase": "ready",
            "candidate_credentials": "absent",
            "docker_service": "running",
            "qga_service": "running",
            "passwordless_sudo": "verified",
            "busybox_image": BUSYBOX,
            "router_mode": "guest-only",
            "os_ready": "true",
            "wan_after_seal": "disabled",
        }
        if any(marker.get(key) != value for key, value in expected_marker.items()):
            raise LabError(f"guest READY marker capability mismatch: {marker}")
        command = (
            "check() { name=$1; shift; if \"$@\" >/dev/null 2>&1; then printf '%s=true\\n' \"$name\"; else printf '%s=false\\n' \"$name\"; fi; }; "
            "i=0; while ! systemctl is-active --quiet docker.service; do i=$((i+1)); [ $i -lt 60 ] || exit 3; sleep 1; done; printf 'docker_active=true\\n'; "
            "check qga_active systemctl is-active --quiet qemu-guest-agent.service; "
            f"check busybox_digest docker image inspect {BUSYBOX}; "
            "check passwordless_sudo runuser -u lab -- sudo -n true; "
            "exit 0"
        )
        guest = qga.guest_exec_wait("/bin/sh", ["-c", command], timeout=60)
        capability_output = parse_marker(guest["stdout"])
        if capability_output.get("docker_active") != "true" or capability_output.get("qga_active") != "true" or capability_output.get("passwordless_sudo") != "true" or capability_output.get("busybox_digest") != "true":
            diagnostics = qga.guest_exec_wait(
                "/bin/sh",
                ["-c", "systemctl --no-pager --full status docker.service || true; journalctl --no-pager -u docker.service -n 80 || true"],
                timeout=30,
            )
            receipt["capability_diagnostics"] = diagnostics["stdout"]
            raise LabError(f"guest capability command reported failure: {capability_output}")
        receipt.update({
            "device_identity": {
                "pid": int(owned["pid"]),
                "uuid": owned["uuid"],
                "qmp_socket": owned["qmp_socket"],
                "qga_socket": owned["qga_socket"],
                "process_start_time": owned["proc_start_time"],
                "argv": owned["argv"],
            },
            "qmp_status": qmp_status["return"],
            "qga_sync": True,
            "guest_marker": marker,
            "guest_marker_raw": marker_text,
            "guest_probe_marker": probe_marker.strip(),
            "capability_command": guest["stdout"],
            "capabilities": {
                "docker_active": True,
                "qga_active": True,
                "passwordless_sudo": True,
                "busybox_digest": BUSYBOX,
            },
            "status": "capabilities-verified",
        })
    except (LabError, OSError, ValueError, json.JSONDecodeError) as exc:
        failure = str(exc)
        receipt.update({"status": "failed", "failure": failure})
    finally:
        try:
            cleanup = controller.reset(args.run_id, PROFILE)
        except (LabError, OSError, ValueError) as exc:
            cleanup = {"status": "cleanup-failed", "error": str(exc)}
            failure = failure or f"cleanup failed: {exc}"
    after_sha, after_size = sha256_file(base)
    receipt["base_sha256_after"] = after_sha
    receipt["base_size_after"] = after_size
    receipt["base_unchanged"] = after_sha == before_sha and after_size == before_size
    receipt["cleanup"] = cleanup
    receipt["finished_at"] = now()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if failure or receipt.get("base_unchanged") is not True:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
