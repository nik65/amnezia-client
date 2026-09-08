#!/usr/bin/env python3
"""Build and optionally boot one disposable golden guest.

The command is plan-only unless --execute is supplied. It owns only the
provided external output directory, uses user-mode NAT during provisioning,
waits for a guest READY marker through QGA, disables the lab NIC through QMP,
then powers off and records the sealed disk hash. It never touches host VPN,
routes, DNS, firewall, WSL state, or an Amnezia installer.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pwd
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"bootstrap-guest: ERROR: {message}")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_tree(path: Path) -> str:
    digest = hashlib.sha256()
    for child in sorted(p for p in path.rglob("*") if p.is_file()):
        digest.update(str(child.relative_to(path)).encode("utf-8"))
        digest.update(b"\0")
        digest.update(sha256(child).encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def read_lock(path: Path, key: str) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        item = data["images"][key]
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        fail(f"invalid image lock/key {path}:{key}: {exc}")
    if not isinstance(item, dict) or not isinstance(item.get("filename"), str):
        fail(f"lock entry is incomplete: {key}")
    return item


def verify_locked_image(path: Path, item: dict, receipt: Path | None) -> str:
    if path.name != item["filename"]:
        fail(f"image basename differs from lock (expected {item['filename']}, got {path.name})")
    expected = item.get("sha256")
    actual = sha256(path)
    if isinstance(expected, str) and expected:
        if actual.lower() != expected.lower():
            fail(f"locked image SHA-256 mismatch (expected {expected}, got {actual})")
        return actual
    if receipt is None or not receipt.is_file():
        fail("dynamic signed image requires an external verification receipt")
    try:
        data = json.loads(receipt.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"invalid verification receipt: {exc}")
    if data.get("verified_by") != "WSL gpgv + sha256sum" or data.get("sha256", "").lower() != actual.lower() or data.get("source") != item.get("url"):
        fail("verification receipt does not match the locked source/image")
    return actual


def verify_seed(seed: Path, profile: str, base_image: Path) -> dict:
    candidates = [seed.parent / "provisioning-manifest.json", seed.parent.parent / "provisioning-manifest.json"]
    manifest_path = next((item for item in candidates if item.is_file() and not item.is_symlink()), None)
    if manifest_path is None:
        fail("seed must have an adjacent provisioning-manifest.json")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"invalid seed provisioning manifest: {exc}")
    aliases = {"windows11": "windows-x64", "linux-headless": "linux-headless-x64", "linux-gui": "linux-x64-gui"}
    if aliases.get(manifest.get("profile"), manifest.get("profile")) != profile or manifest.get("qemu_started") is not False:
        fail("seed manifest profile or pre-boot state is invalid")
    if manifest.get("candidate_credentials") not in ("absent", False):
        fail("seed manifest contains candidate credentials")
    expected_seed = manifest.get("seed_sha256") or manifest.get("answer_iso_sha256")
    actual_seed = sha256(seed)
    if not isinstance(expected_seed, str) or actual_seed.lower() != expected_seed.lower():
        fail("seed SHA-256 differs from its provisioning manifest")
    declared = manifest.get("seed") or manifest.get("answer_iso")
    if not isinstance(declared, str) or Path(declared).name != seed.name:
        fail("seed path does not match provisioning manifest")
    declared_base = manifest.get("base_image") or manifest.get("source_iso")
    if isinstance(declared_base, str) and Path(declared_base).name != base_image.name:
        fail("seed was provisioned for a different base image")
    template_rel = manifest.get("template")
    if not isinstance(template_rel, str) or ".." in Path(template_rel).parts:
        fail("seed template binding is missing or unsafe")
    template_path = Path(__file__).parent / template_rel
    if not template_path.is_file() or template_path.is_symlink():
        fail("seed template is not an approved repository template")
    if manifest.get("template_sha256") != sha256(template_path):
        fail("seed template changed after provisioning")
    template_text = template_path.read_text(encoding="utf-8")
    template_safe = ("__LAB_ADMIN_PASSWORD__" in template_text and "__SEED_NONCE__" in template_text) if profile == "windows-x64" else "candidate_credentials=absent" in template_text
    if not template_safe or "PRIVATE KEY" in template_text:
        fail("seed template failed credential safety checks")
    return {"manifest": str(manifest_path), "seed_sha256": actual_seed, "template_sha256": manifest["template_sha256"]}


def qga_request(sock: socket.socket, execute: str, arguments: dict | None = None) -> dict:
    payload = {"execute": execute}
    if arguments:
        payload["arguments"] = arguments
    sock.sendall((json.dumps(payload) + "\r\n").encode())
    data = b""
    while b"\n" not in data:
        block = sock.recv(65536)
        if not block:
            fail("QGA closed before returning a response")
        data += block
        if len(data) > 1024 * 1024:
            fail("QGA response exceeded safety limit")
    line = data.split(b"\n", 1)[0].strip(b"\xff")
    return json.loads(line.decode())


def qga_ready(path: Path, profile: str) -> bool:
    marker = r"C:\ProgramData\AmneziaLab\READY" if profile == "windows-x64" else "/var/lib/amnezia-lab/READY"
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(3)
            sock.connect(str(path))
            # Windows and Linux QGA both accept guest-sync-delimited.
            qga_request(sock, "guest-sync-delimited", {"id": int(time.time()) & 0xFFFFFFFF})
            opened = qga_request(sock, "guest-file-open", {"path": marker, "mode": "r"})
            handle = opened.get("return")
            if not isinstance(handle, int):
                return False
            try:
                read = qga_request(sock, "guest-file-read", {"handle": handle, "count": 4096})
                encoded = read.get("return", {}).get("buf-b64", "")
                import base64
                text = base64.b64decode(encoded).decode("utf-8", "replace")
                common = f"profile={profile}" in text and "phase=ready" in text and "candidate_credentials=absent" in text
                if profile == "windows-x64":
                    return common and "qga_service=running" in text
                if profile == "linux-x64-gui":
                    return common and "qga_service=running" in text and "display_manager=running" in text
                return common and "qga_service=running" in text
            finally:
                qga_request(sock, "guest-file-close", {"handle": handle})
    except (OSError, ValueError, KeyError, json.JSONDecodeError):
        return False


def qmp(path: Path, execute: str, arguments: dict | None = None) -> dict:
    pending = bytearray()
    def read_line(sock: socket.socket) -> dict:
        while b"\n" not in pending:
            block = sock.recv(65536)
            if not block:
                fail("QMP closed before returning a response")
            pending.extend(block)
        line, _, rest = pending.partition(b"\n")
        pending.clear()
        pending.extend(rest)
        return json.loads(line.decode())

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(5)
        sock.connect(str(path))
        read_line(sock)  # greeting
        sock.sendall(b'{"execute":"qmp_capabilities"}\r\n')
        while True:
            if "return" in read_line(sock):
                break
        payload = {"execute": execute}
        if arguments:
            payload["arguments"] = arguments
        sock.sendall((json.dumps(payload) + "\r\n").encode())
        while True:
            response = read_line(sock)
            if "return" in response or "error" in response:
                return response


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", required=True, choices=("windows-x64", "linux-x64-gui", "linux-headless-x64", "server-router"))
    parser.add_argument("--base-image", required=True, type=Path)
    parser.add_argument("--base-sha256", required=True)
    parser.add_argument("--base-receipt", type=Path)
    parser.add_argument("--lock", type=Path, default=Path(__file__).parent / "images" / "lock.json")
    parser.add_argument("--seed", required=True, type=Path)
    parser.add_argument("--support-iso", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--execute", action="store_true", help="actually boot and provision the guest")
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--accelerator", choices=("kvm", "tcg"), default="kvm")
    parser.add_argument("--boot-key-delay", type=int, default=4)
    args = parser.parse_args()
    if args.base_image.is_symlink() or args.seed.is_symlink() or not args.base_image.is_file() or not args.seed.is_file():
        fail("base image and seed must be existing regular files")
    if len(args.base_sha256) != 64 or any(c not in "0123456789abcdefABCDEF" for c in args.base_sha256):
        fail("--base-sha256 must be a verified 64-character hex digest")
    base_key = "windows11-25h2-evaluation-amd64" if args.profile == "windows-x64" else "ubuntu24-cloud-amd64"
    base_item = read_lock(args.lock, base_key)
    actual = verify_locked_image(args.base_image, base_item, args.base_receipt)
    if actual.lower() != args.base_sha256.lower():
        fail(f"base image SHA-256 differs from supplied digest (expected {args.base_sha256}, got {actual})")
    seed_info = verify_seed(args.seed, args.profile, args.base_image)
    support_hash = None
    if args.profile == "windows-x64" and (args.support_iso is None or args.support_iso.is_symlink() or not args.support_iso.is_file()):
        fail("Windows requires the separately verified virtio-win support ISO")
    if args.profile == "windows-x64":
        support_item = read_lock(args.lock, "windows-virtio-win-stable")
        support_hash = verify_locked_image(args.support_iso, support_item, None)
    if args.profile != "windows-x64" and args.accelerator != "kvm":
        fail("Linux and server profiles require KVM; TCG is permitted only for the Windows software lane")
    if args.output.exists():
        fail("output exists; use a new run directory; recursive overwrite is refused")
    if args.output.is_symlink():
        fail("output must not be a symlink")
    lab_root = Path("/var/lib/amnezia-release-lab").resolve()
    cursor = args.output.parent
    while cursor != cursor.parent and str(cursor) != str(lab_root):
        if cursor.is_symlink():
            fail(f"output parent is a symlink: {cursor}")
        cursor = cursor.parent
    output_parent = args.output.parent.resolve()
    try:
        output_parent.relative_to(lab_root / "guests")
    except ValueError:
        fail("output must be contained below /var/lib/amnezia-release-lab/guests")
    if args.execute:
        try:
            effective = pwd.getpwuid(os.geteuid())
        except (AttributeError, KeyError, OSError):
            fail("--execute requires a POSIX WSL user identity")
        if effective.pw_name != "amnezia-lab" or os.geteuid() != effective.pw_uid:
            fail("--execute must run as the unprivileged amnezia-lab user")
    disk = args.output / "golden-disk.qcow2"
    qmp_path = args.output / "qmp.sock"
    qga_path = args.output / "qga.sock"
    cpu_model = "max" if args.accelerator == "tcg" else "host"
    manifest = {"schema": 1, "profile": args.profile, "base_image": str(args.base_image), "base_image_sha256": actual, "qemu_started": False, "sealed": False, "accelerator": "tcg-software" if args.accelerator == "tcg" else "kvm", "cpu_model": cpu_model, "network": "user-mode NAT before seal; NIC detached before seal", "support_iso_sha256": support_hash, "seed": seed_info}
    if not args.execute:
        print(json.dumps(manifest, indent=2))
        return 0
    args.output.mkdir(parents=True, mode=0o700)
    (args.output / "bootstrap-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    qemu = "/usr/bin/qemu-system-x86_64"
    qimg = "/usr/bin/qemu-img"
    if not Path(qemu).is_file() or not Path(qimg).is_file():
        fail("qemu-system-x86_64 and qemu-img are required in WSL")
    if args.profile == "windows-x64":
        subprocess.run([qimg, "create", "-f", "qcow2", str(disk), "128G"], check=True)
    else:
        subprocess.run([qimg, "create", "-f", "qcow2", "-F", "qcow2", "-b", str(args.base_image), str(disk)], check=True)
        guest_size = "64G" if args.profile == "linux-x64-gui" else "32G"
        subprocess.run([qimg, "resize", str(disk), guest_size], check=True)
    accel_arg = "kvm" if args.accelerator == "kvm" else "tcg,thread=multi"
    argv = [qemu, "-machine", "q35", "-cpu", cpu_model, "-accel", accel_arg, "-m", "8192" if args.profile == "windows-x64" else "4096", "-smp", "4", "-drive", f"file={disk},if=ide,format=qcow2"]
    if args.profile != "windows-x64":
        argv += ["-drive", f"file={args.seed},media=cdrom,readonly=on"]
    display_args = ["-vnc", f"unix:{args.output / 'vnc.sock'}"] if args.profile == "linux-x64-gui" else ["-nographic"]
    argv += ["-netdev", "user,id=labnet", "-device", "e1000,netdev=labnet,id=labnet-device", "-qmp", f"unix:{qmp_path},server=on,wait=off", "-chardev", f"socket,id=qga0,path={qga_path},server=on,wait=off", "-device", "virtio-serial-pci", "-device", "virtserialport,chardev=qga0,name=org.qemu.guest_agent.0", "-serial", f"file:{args.output / 'serial.log'}", *display_args]
    if args.profile == "linux-x64-gui":
        # The default QEMU video device is not guaranteed to expose a KMS
        # framebuffer on the Noble cloud image.  An explicit virtio GPU lets
        # Xorg/modesetting create a real desktop session over the VNC display.
        argv += ["-vga", "virtio"]
    tpm_proc = None
    if args.profile == "windows-x64":
        ovmf_code = Path("/usr/share/OVMF/OVMF_CODE_4M.ms.fd")
        ovmf_template = Path("/usr/share/OVMF/OVMF_VARS_4M.ms.fd")
        swtpm = "/usr/bin/swtpm"
        if not ovmf_code.is_file() or not ovmf_template.is_file() or not Path(swtpm).is_file():
            fail("Windows bootstrap requires Microsoft-keyed OVMF vars/code and swtpm")
        ovmf_vars = args.output / "OVMF_VARS_4M.ms.fd"
        shutil.copy2(ovmf_template, ovmf_vars)
        tpm_state = args.output / "tpm-state"
        tpm_state.mkdir()
        tpm_ctrl = args.output / "swtpm.sock"
        tpm_proc = subprocess.Popen([swtpm, "socket", "--tpm2", "--tpmstate", f"dir={tpm_state}", "--ctrl", f"type=unixio,path={tpm_ctrl}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        tpm_deadline = time.monotonic() + 10
        while not tpm_ctrl.exists() and time.monotonic() < tpm_deadline:
            if tpm_proc.poll() is not None:
                fail("swtpm exited before creating its owned control socket")
            time.sleep(0.1)
        if not tpm_ctrl.exists():
            fail("swtpm control socket did not become ready")
        argv += ["-drive", f"if=pflash,format=raw,readonly=on,file={ovmf_code}", "-drive", f"if=pflash,format=raw,file={ovmf_vars}", "-chardev", f"socket,id=chrtpm,path={tpm_ctrl}", "-tpmdev", "emulator,id=tpm0,chardev=chrtpm", "-device", "tpm-tis,tpmdev=tpm0"]
        argv += ["-drive", f"file={args.base_image},media=cdrom,readonly=on", "-drive", f"file={args.seed},media=cdrom,readonly=on", "-drive", f"file={args.support_iso},media=cdrom,readonly=on", "-boot", "once=d,menu=off"]
    proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=(args.output / "qemu.log").open("w"))
    manifest["qemu_started"] = True
    try:
        if args.profile == "windows-x64":
            key_deadline = time.monotonic() + 15
            while not qmp_path.exists() and time.monotonic() < key_deadline:
                if proc.poll() is not None:
                    fail(f"QEMU exited before Windows boot-key handoff (exit {proc.returncode})")
                time.sleep(0.1)
            if not qmp_path.exists():
                fail("Windows QMP socket did not become ready for the single boot-key handoff")
            # The firmware needs time to enumerate the attached Windows ISO;
            # delay the one permitted key event until a screenshot can confirm
            # the CD prompt on slow TCG hosts.
            time.sleep(max(0, min(args.boot_key_delay, 12)))
            qmp(qmp_path, "send-key", {"keys": [{"type": "qcode", "data": "spc"}]})
            manifest["boot_key_event"] = "single-qmp-space-after-bounded-window"
            (args.output / "bootstrap-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        deadline = time.monotonic() + args.timeout
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                fail(f"QEMU exited before guest readiness (exit {proc.returncode})")
            if qga_path.exists() and qga_ready(qga_path, args.profile):
                break
            time.sleep(2)
        else:
            fail("guest READY marker was not observed through QGA")
        disabled = qmp(qmp_path, "set_link", {"name": "labnet-device", "up": False})
        if "error" in disabled:
            fail(f"could not detach provisioning NIC: {disabled}")
        qmp(qmp_path, "system_powerdown")
        proc.wait(timeout=120)
        if proc.returncode != 0:
            fail(f"QEMU exited unsuccessfully during golden shutdown: {proc.returncode}")
        if tpm_proc is not None:
            tpm_proc.terminate()
            tpm_proc.wait(timeout=10)
        if args.profile != "windows-x64":
            flattened = args.output / "golden-disk.flattened.qcow2"
            subprocess.run([qimg, "convert", "-p", "-O", "qcow2", "-o", "compression_type=zstd", str(disk), str(flattened)], check=True)
            subprocess.run([qimg, "check", str(flattened)], check=True, stdout=subprocess.DEVNULL)
            os.replace(flattened, disk)
        if args.profile == "windows-x64":
            ovmf_sha = sha256(ovmf_vars)
            tpm_sha = sha256_tree(tpm_state)
            manifest.update({"ovmf_vars_sha256": ovmf_sha, "tpm_state_sha256": tpm_sha})
        subprocess.run([qimg, "check", str(disk)], check=True, stdout=subprocess.DEVNULL)
        golden_sha = sha256(disk)
        disk.chmod(0o440)
        if args.profile == "windows-x64":
            ovmf_vars.chmod(0o440)
            for state_file in tpm_state.rglob("*"):
                if state_file.is_file():
                    state_file.chmod(0o440)
        readiness = {"schema": 1, "profile": args.profile, "sealed": True, "network_sealed": True, "immutable": True, "candidate_credentials": False, "guest_agent": "qga", "base_sha256": golden_sha, "ready_via": "qga", "observed_nic_down": True, "support_iso_sha256": support_hash, "accelerator": manifest["accelerator"], "cpu_model": manifest["cpu_model"]}
        if args.profile == "windows-x64":
            readiness.update({"ovmf_vars_sha256": manifest["ovmf_vars_sha256"], "tpm_state_sha256": manifest["tpm_state_sha256"]})
        (args.output / "golden-readiness.json").write_text(json.dumps(readiness, indent=2) + "\n", encoding="utf-8")
        manifest.update({"sealed": True, "golden_sha256": golden_sha, "ready_via": "qga", "post_seal_wan": "disabled", "readiness": "golden-readiness.json"})
        (args.output / "bootstrap-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(manifest, indent=2))
        return 0
    finally:
        if proc.poll() is None:
            proc.terminate()
            proc.wait(timeout=30)
        if tpm_proc is not None and tpm_proc.poll() is None:
            tpm_proc.terminate()
            tpm_proc.wait(timeout=10)


if __name__ == "__main__":
    main()
