#!/usr/bin/python3
"""Guest-only native component runtime for collector + route refusal checks.

Invoked by the controller as:
  /usr/bin/python3 -I -B component_runtime_guest.py --plan <guest-plan.json>

The script refuses unless euid==0 and an independently read lab marker matches
the plan run_id/profile.  It verifies the two pinned ELF artifacts, stages an
isolated collector data root, spawns the real collector on explicit loopback,
performs real HTTP probes, invokes the route CLI only on its no-argument /
invalid-scope refusal path, drains both child streams, reaps, and prints one
bounded canonical receipt JSON line.

No repository, host, Docker, service, DNS, route or firewall operation is
performed here.  Everything is confined to the guest root from the plan.
"""
from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
import re
import select
import selectors
import signal
import socket
import stat
import subprocess
import sys
import time

PROFILE = "linux-headless-x64"
MARKER_PATH = "/tmp/amnezia-release-lab-marker"
RUN_ID_RE = re.compile(r"native-[0-9a-f]{32}")
NONCE_RE = re.compile(r"^[0-9a-f]{64}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")

# Exact hashes from the real, separately verified bundle manifest. Byte counts
# and hash tokens are separate fields; no prefix stripping or case repair.
ARTIFACT_PINS = {
    "collector": "7a938dbbf464e68674d5514c0a32936411ea9a800ea4988971fa9e4ca1f01620",
    "collector-route": "c416d41341867e5f1ba339f8eb213a2c4a7e6f3e40cff25717a88dc87331e656",
}
MANIFEST_PIN = "e461cdda368419956f7419a5b22f70aaae43940a09ca098d0ad096d32000347d"
ARTIFACT_ROLES = ("collector", "collector-route")
UPLOAD_PATH = "/logs"
BOOTSTRAP_PATH = "/bootstrap"
WORK_LIMIT = 15.0
CLEANUP_RESERVE = 3.0
HTTP_TIMEOUT = 2.0
HEALTH_TIMEOUT = 5.0
CAPTURE_LIMIT = 1 << 20
STREAM_HEAD_TAIL = 2048
RECEIPT_LIMIT = 65536
MAX_ARTIFACT_BYTES = 64 << 20
ROUTE_REFUSAL = b"collector route reconciliation refused"
NOT_RUN = [
    "fullDocker",
    "reconcile",
    "96MiB",
    "cgroup",
    "nativeCTest",
    "rootmutation",
]


class Refusal(ValueError):
    """A fail-closed preflight/work check.  Never carries secrets."""


class CaptureError(RuntimeError):
    """Capture failed while the child remains registered for reaping."""


def _pin_digest(pin):
    if not isinstance(pin, str) or not HEX64_RE.fullmatch(pin):
        raise Refusal("invalid controller pin")
    return pin


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _within(path, root):
    if not isinstance(path, str) or not path.startswith("/") or "\x00" in path:
        return False
    if not isinstance(root, str) or not root.startswith("/"):
        return False
    norm = path.rstrip("/")
    root_norm = root.rstrip("/")
    if norm == root_norm:
        return False
    if ".." in norm.split("/"):
        return False
    return norm.startswith(root_norm + "/")


class Capture:
    def __init__(self, limit=CAPTURE_LIMIT):
        self.limit = limit
        self.size = 0
        self.hash = hashlib.sha256()
        self.head = bytearray()
        self.tail = bytearray()
        self.truncated = False

    def add(self, chunk):
        self.size += len(chunk)
        self.hash.update(chunk)
        self.head.extend(chunk[:STREAM_HEAD_TAIL - len(self.head)] if len(self.head) < STREAM_HEAD_TAIL else b"")
        self.tail.extend(chunk[-STREAM_HEAD_TAIL:] if len(chunk) > STREAM_HEAD_TAIL else chunk)
        if len(self.tail) > STREAM_HEAD_TAIL:
            del self.tail[:-STREAM_HEAD_TAIL]
        if self.size > self.limit:
            self.truncated = True

    def record(self, eof):
        return {
            "size": self.size,
            "sha256": self.hash.hexdigest(),
            "eof": bool(eof),
            "truncated": self.truncated,
            "head_b64": __import__("base64").b64encode(bytes(self.head)).decode("ascii"),
            "tail_b64": __import__("base64").b64encode(bytes(self.tail)).decode("ascii"),
        }


_REGISTRY = {}


class RealChild:
    def __init__(self, process):
        self.process = process
        self.pid = process.pid
        self.selector = None
        self.streams = {}
        self.eof = {"stdout": False, "stderr": False}
        self.code = None
        self.capture_error = False
        self.expect_zero = True
        # Popen succeeded: acquire cleanup ownership BEFORE selector/fd setup.
        _REGISTRY[self.pid] = self
        try:
            self.selector = selectors.DefaultSelector()
            for name, pipe in (("stdout", process.stdout), ("stderr", process.stderr)):
                fd = pipe.fileno()
                os.set_blocking(fd, False)
                self.selector.register(fd, selectors.EVENT_READ, name)
                self.streams[name] = (fd, Capture())
        except BaseException:
            self.capture_error = True
            raise

    def pump(self, deadline):
        if self.selector is None:
            time.sleep(max(0, min(0.01, deadline - time.monotonic())))
            return
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            events = self.selector.select(min(remaining, 0.02))
            if not events:
                if self.code is not None and all(self.eof.values()):
                    return
                continue
            for key, _ in events:
                name = key.data
                try:
                    chunk = os.read(key.fd, 4096)
                except BlockingIOError:
                    continue
                except OSError:
                    self.capture_error = True
                    try:
                        self.selector.unregister(key.fd)
                    except Exception:
                        pass
                    continue
                if not chunk:
                    self.eof[name] = True
                    try:
                        self.selector.unregister(key.fd)
                    except Exception:
                        pass
                    continue
                self.streams[name][1].add(chunk)

    def poll(self):
        if self.code is None:
            code = self.process.poll()
            if code is not None:
                self.code = code
        return self.code

    def wait(self, deadline):
        while time.monotonic() < deadline:
            self.pump(min(deadline, time.monotonic() + 0.05))
            if self.poll() is not None:
                self.pump(min(deadline, time.monotonic() + 0.05))
                return self.code
        return None

    def close(self):
        # The Popen pipe objects own their fds; do not close a recycled fd twice.
        if self.selector is not None:
            for fd, _ in self.streams.values():
                try:
                    self.selector.unregister(fd)
                except Exception:
                    pass
            self.selector.close()
        for pipe in (self.process.stdout, self.process.stderr):
            try:
                pipe.close()
            except Exception:
                pass


class RealRuntime:
    def geteuid(self):
        return os.geteuid()

    def clock(self):
        return time.monotonic()

    def lstat(self, path):
        st = os.lstat(path)
        return (st.st_mode, st.st_uid, st.st_ino, st.st_dev, st.st_size)

    def read_bytes(self, path, limit, deadline):
        before = os.lstat(path)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1
                or not 0 <= before.st_size <= limit or before.st_mode & 0o022):
            raise Refusal("bounded regular owned input required before open")
        identity = lambda row: (row.st_dev, row.st_ino, row.st_mode, row.st_uid, row.st_nlink,
                                row.st_size, row.st_mtime_ns, row.st_ctime_ns)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            st = os.fstat(fd)
            if identity(st) != identity(before):
                raise Refusal("input changed while opening")
            body = bytearray()
            while len(body) <= limit:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise Refusal("read deadline")
                ready, _, _ = select.select([fd], [], [], min(remaining, 0.5))
                if not ready:
                    continue
                chunk = os.read(fd, min(65536, limit + 1 - len(body)))
                if not chunk:
                    if (len(body) != before.st_size or identity(os.fstat(fd)) != identity(before)
                            or identity(os.lstat(path)) != identity(before)):
                        raise Refusal("input changed while reading")
                    return bytes(body)
                body.extend(chunk)
            raise Refusal("file too large")
        finally:
            os.close(fd)

    def write_exclusive(self, path, data, mode):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
        try:
            remaining = memoryview(data)
            while remaining:
                written = os.write(fd, remaining)
                if written <= 0:
                    raise Refusal("short exclusive write")
                remaining = remaining[written:]
            st = os.fstat(fd)
            os.fsync(fd)
            return (st.st_ino, st.st_dev)
        finally:
            os.close(fd)

    def mkdir_exclusive(self, path, mode):
        os.mkdir(path, mode)
        st = os.lstat(path)
        os.chmod(path, mode)
        return (st.st_ino, st.st_dev)

    def chmod_owned(self, path, mode, ino, dev):
        st = os.lstat(path)
        if (st.st_ino, st.st_dev) != (ino, dev) or not stat.S_ISREG(st.st_mode):
            raise Refusal("artifact incarnation changed")
        os.chmod(path, mode)

    def listdir(self, path):
        return sorted(os.listdir(path))

    def connect(self, host, port, timeout):
        return socket.create_connection((host, port), timeout=timeout)

    def choose_port(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind(("127.0.0.1", 0))
            return sock.getsockname()[1]
        finally:
            sock.close()

    def spawn(self, argv, env, cwd):
        process = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            cwd=cwd,
            close_fds=True,
            bufsize=0,
            start_new_session=True,
        )
        return RealChild(process)

    def signal_group(self, pid, sig):
        child = _REGISTRY.get(pid)
        if not isinstance(child, RealChild) or child.pid != pid:
            raise Refusal("unregistered process signal refused")
        if child.poll() is None:
            child.process.send_signal(sig)

    def remove_tree(self, path):
        # Only regular files and directories created by this run under the
        # verified guest root; symlinks are refused, never followed.
        for name in self.listdir(path):
            child = os.path.join(path, name)
            st = os.lstat(child)
            if stat.S_ISDIR(st.st_mode):
                self.remove_tree(child)
            elif stat.S_ISREG(st.st_mode):
                os.unlink(child)
            else:
                raise Refusal("unexpected cleanup entry")
        os.rmdir(path)


class HttpConn:
    def __init__(self, sock, deadline, clock=time.monotonic):
        self.sock = sock
        self.deadline = deadline
        self.clock = clock

    def _timeout(self):
        remaining = self.deadline - self.clock()
        if remaining <= 0:
            raise CaptureError("http deadline")
        self.sock.settimeout(min(HTTP_TIMEOUT, remaining))

    def send(self, data):
        self._timeout()
        self.sock.sendall(data)

    def recv(self):
        self._timeout()
        return self.sock.recv(65536)

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def http_request(rt, host, port, method, target, headers, body, deadline):
    if deadline - rt.clock() <= 0:
        raise CaptureError("http deadline")
    remaining = deadline - rt.clock()
    if remaining <= 0:
        raise CaptureError("http deadline")
    conn = HttpConn(rt.connect(host, port, min(HTTP_TIMEOUT, remaining)), deadline, rt.clock)
    try:
        if any(key.lower() == 'content-length' for key in headers):
            raise CaptureError("caller-supplied content length refused")
        lines = [f"{method} {target} HTTP/1.1", f"Host: {host}:{port}", "Connection: close", f"Content-Length: {len(body)}"]
        lines += [f"{k}: {v}" for k, v in headers.items()]
        raw = ("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + body
        conn.send(raw)
        data = bytearray()
        while b"\r\n\r\n" not in data:
            if len(data) > 65536:
                raise CaptureError("response header too large")
            chunk = conn.recv()
            if not chunk:
                raise CaptureError("response truncated")
            data.extend(chunk)
        head, rest = bytes(data).split(b"\r\n\r\n", 1)
        head_lines = head.split(b"\r\n")
        status_parts = head_lines[0].split(b" ", 2)
        if len(status_parts) < 2 or not status_parts[1].isdigit():
            raise CaptureError("response status")
        status = int(status_parts[1])
        length = None
        for line in head_lines[1:]:
            if b":" not in line:
                raise CaptureError("response header")
            key, value = line.split(b":", 1)
            if key.strip().lower() == b"content-length":
                if length is not None or not value.strip().isdigit():
                    raise CaptureError("duplicate or invalid content length")
                length = int(value.strip())
            if key.strip().lower() == b"transfer-encoding":
                raise CaptureError("unexpected transfer encoding")
        if length is None or length > (1 << 20):
            raise CaptureError("response body too large")
        body_out = bytearray(rest)
        while len(body_out) < length:
            chunk = conn.recv()
            if not chunk:
                raise CaptureError("response body truncated")
            body_out.extend(chunk)
        if len(body_out) != length:
            raise CaptureError("response length mismatch")
        return status, bytes(body_out)
    finally:
        conn.close()


def _expect(status, want):
    if status != want:
        raise Refusal(f"http status {status} != {want}")


def _case(cases, name, ok, **extra):
    row = {"name": name, "status": "PASS" if ok else "FAIL"}
    row.update(extra)
    cases.append(row)
    return ok


def validate_plan(plan, pins=None):
    pins = pins or ARTIFACT_PINS
    manifest_pin = pins.get("manifest", MANIFEST_PIN)
    artifact_pins = {role: pins.get(role, ARTIFACT_PINS[role]) for role in ARTIFACT_ROLES}
    if not isinstance(plan, dict) or type(plan.get("schema")) is not int or plan["schema"] != 1:
        raise Refusal("plan schema")
    run_id = plan.get("run_id")
    nonce = plan.get("nonce")
    if not isinstance(run_id, str) or not RUN_ID_RE.fullmatch(run_id):
        raise Refusal("plan run_id")
    if not isinstance(nonce, str) or not NONCE_RE.fullmatch(nonce):
        raise Refusal("plan nonce")
    if plan.get("profile") != PROFILE:
        raise Refusal("plan profile")
    root = plan.get("root") if "root" in plan else plan.get("guest_root")
    if root != f"/var/tmp/amnezia-native-{nonce}":
        raise Refusal("plan root")
    if plan.get("marker_path") != MARKER_PATH:
        raise Refusal("plan marker path")
    expected_marker = f"amnezia-release-lab:{run_id}:{PROFILE}".encode("ascii")
    if plan.get("marker_content") not in (expected_marker.decode("ascii"), None):
        raise Refusal("plan marker content")
    artifacts = plan.get("artifacts")
    if not isinstance(artifacts, list) or len(artifacts) != 2:
        raise Refusal("plan artifacts")
    seen = {}
    for item in artifacts:
        if not isinstance(item, dict) or item.get("role") not in ARTIFACT_ROLES:
            raise Refusal("artifact role")
        role = item["role"]
        if role in seen:
            raise Refusal("duplicate artifact role")
        path, size, digest = item.get("path"), item.get("size"), item.get("sha256")
        if not _within(path, root):
            raise Refusal("artifact path outside guest root")
        if not isinstance(size, int) or isinstance(size, bool) or not (0 < size <= MAX_ARTIFACT_BYTES):
            raise Refusal("artifact size")
        if _pin_digest(digest) != _pin_digest(artifact_pins[role]):
            raise Refusal("artifact pin")
        seen[role] = {"path": path, "role": role, "sha256": digest, "size": size}
    manifest = plan.get("manifest")
    if not isinstance(manifest, dict):
        raise Refusal("manifest record")
    if not _within(manifest.get("path"), root):
        raise Refusal("manifest path outside guest root")
    if _pin_digest(manifest.get("sha256")) != _pin_digest(manifest_pin):
        raise Refusal("manifest digest")
    if not isinstance(manifest.get("size"), int) or isinstance(manifest.get("size"), bool) or manifest["size"] <= 0:
        raise Refusal("manifest size")
    port = plan.get("port")
    if port is not None and (not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535):
        raise Refusal("plan port")
    return {
        "run_id": run_id,
        "nonce": nonce,
        "root": root,
        "expected_marker": expected_marker,
        "artifacts": [seen[r] for r in ARTIFACT_ROLES],
        "manifest": manifest,
        "manifest_pin": manifest_pin,
        "port": port,
    }


def verify_root(rt, root, deadline):
    if not isinstance(root, str) or not root.startswith("/"):
        raise Refusal("root path")
    parts = [p for p in root.split("/") if p]
    ancestors = ["/" ]
    for index in range(1, len(parts) + 1):
        ancestors.append("/" + "/".join(parts[:index]))
    for path in ancestors:
        mode, uid, ino, dev, _ = rt.lstat(path)
        if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
            raise Refusal("root ancestor not a directory")
        if path == root:
            if stat.S_IMODE(mode) != 0o700 or uid != 0:
                raise Refusal("root mode/owner")
    return rt.lstat(root)


def verify_artifact(rt, record, root, deadline, executable):
    mode, uid, ino, dev, size = rt.lstat(record["path"])
    if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
        raise Refusal("artifact not regular")
    if uid != 0 or stat.S_IMODE(mode) != 0o600:
        raise Refusal("artifact mode/owner")
    if size != record["size"]:
        raise Refusal("artifact size drift")
    data = rt.read_bytes(record["path"], MAX_ARTIFACT_BYTES, deadline)
    if len(data) != record["size"] or _sha256(data) != _pin_digest(record["sha256"]):
        raise Refusal("artifact bytes")
    after = rt.lstat(record["path"])
    if after[2] != ino or after[3] != dev or stat.S_IMODE(after[0]) != 0o600:
        raise Refusal("artifact incarnation drift")
    if executable:
        rt.chmod_owned(record["path"], 0o700, ino, dev)
        mode2 = rt.lstat(record["path"])
        if stat.S_IMODE(mode2[0]) != 0o700:
            raise Refusal("artifact chmod")
    return (ino, dev)


def verify_marker(rt, expected, deadline):
    data = rt.read_bytes(MARKER_PATH, 256, deadline)
    if data != expected:
        raise Refusal("lab marker mismatch")
    return True


def build_token_fixture(nonce):
    client = _sha256(("client:" + nonce).encode())
    token = _sha256(("token:" + nonce).encode())
    batch = _sha256(("batch:" + nonce).encode())
    return client, token, batch


def _spawn_child(rt, argv, env, cwd, expect_zero=True):
    child = rt.spawn(argv, env, cwd)
    child.expect_zero = expect_zero
    _REGISTRY[child.pid] = child
    return child


def _pump_both(rt, children, streams, deadline):
    for child in children:
        child.pump(deadline)
    for child in children:
        for name, cap in child.streams.items() if hasattr(child, "streams") else ():
            streams.setdefault(f"{child.pid}:{name}", cap)


def _stop_child(rt, child, deadline, streams, require_zero):
    pid = child.pid
    status = child.poll()
    forced = False
    if status is None:
        try:
            rt.signal_group(pid, signal.SIGTERM)
        except OSError:
            pass
        status = child.wait(min(deadline, rt.clock() + 2.0))
    if status is None:
        try:
            rt.signal_group(pid, getattr(signal, "SIGKILL", 9))
        except OSError:
            pass
        forced = True
        status = child.wait(min(deadline, rt.clock() + 2.0))
    child.pump(min(deadline, rt.clock() + 0.1))
    for name in ("stdout", "stderr"):
        if hasattr(child, "streams"):
            streams[f"{pid}:{name}"] = child.streams[name][1]
        if hasattr(child, "eof") and not child.eof.get(name, False):
            # A terminated process must show EOF for a complete capture.
            pass
    if status is not None:
        _REGISTRY.pop(pid, None)
        try:
            child.close()
        except Exception:
            pass
    try:
        child.capture_ok = not getattr(child, 'capture_error', False) and set(child.streams) == {'stdout', 'stderr'} and all(child.eof.values()) and not any(
            cap.truncated for _, cap in child.streams.values()
        )
        for name, (_, cap) in child.streams.items():
            cap.eof_seen = bool(child.eof.get(name, False))
    except Exception:
        child.capture_ok = False
    ok = status is not None and not forced and (not require_zero or status == 0)
    return ok, status, forced


def run_work(rt, checked, plan, receipt, cases, overall_deadline=None):
    start = rt.clock()
    total_deadline = overall_deadline if overall_deadline is not None else start + WORK_LIMIT
    deadline = total_deadline - CLEANUP_RESERVE
    root = checked["root"]
    runtime = os.path.join(root, "runtime")
    artifacts = checked["artifacts"]
    collector_path = artifacts[0]["path"]
    route_path = artifacts[1]["path"]
    streams = {}
    children = []
    primary = None
    cleanup_error = None
    work_ok = False
    incarnation = None
    runtime_lease = None
    route_capture_ok = True

    try:
        verify_marker(rt, checked["expected_marker"], deadline)
        incarnation = verify_root(rt, root, deadline)
        _case(cases, "marker_uid0_gate", True)
        _case(cases, "root_private_incarnation", True)

        inodes = {}
        for record in artifacts:
            inodes[record["role"]] = verify_artifact(rt, record, root, deadline, executable=True)
        manifest = dict(checked["manifest"])
        manifest["role"] = "manifest"
        manifest["sha256"] = _pin_digest(checked["manifest_pin"])
        verify_artifact(rt, manifest, root, deadline, executable=False)
        _case(cases, "two_elf_pins_and_manifest", True)

        port = checked["port"]
        if port is None:
            port = rt.choose_port()
            if not isinstance(port, int) or not 1 <= port <= 65535:
                raise Refusal("ephemeral port")
        _case(cases, "explicit_loopback_port", port != 17866 or checked["port"] == 17866, actual={"bind": "127.0.0.1", "port": port})

        runtime_lease = rt.mkdir_exclusive(runtime, 0o700)
        client, token, batch = build_token_fixture(checked["nonce"])
        rt.write_exclusive(os.path.join(runtime, "tokens.tsv"), f"{client}\t{token}\n".encode(), 0o600)

        env = {
            "PATH": "/usr/bin:/bin",
            "LANG": "C",
            "TZ": "UTC",
        }
        argv = [
            collector_path,
            "--root", runtime,
            "--bind", "127.0.0.1",
            "--port", str(port),
            "--upload-path", UPLOAD_PATH,
            "--bootstrap-path", BOOTSTRAP_PATH,
        ]
        _case(cases, "collector_argv_source_derived", True, argv=[collector_path.rsplit("/", 1)[-1], "--root", "<runtime>", "--bind", "127.0.0.1", "--port", "<port>", "--upload-path", "/logs", "--bootstrap-path", "/bootstrap"])
        child = _spawn_child(rt, argv, env, runtime)
        children.append(child)
        _case(cases, "process_registry_before_setup", child.pid in _REGISTRY, pid=child.pid)

        health_deadline = min(deadline, rt.clock() + HEALTH_TIMEOUT)
        healthy = False
        while rt.clock() < health_deadline:
            child.pump(min(health_deadline, rt.clock() + 0.05))
            if child.poll() is not None:
                break
            try:
                status, body = http_request(rt, "127.0.0.1", port, "GET", "/healthz", {}, b"", min(deadline, rt.clock() + HTTP_TIMEOUT))
            except (OSError, CaptureError):
                continue
            if status == 200 and body == b'{"status":"ok","collectorVersion":3}':
                healthy = True
                break
        if not healthy:
            code = child.poll()
            raise Refusal("collector did not become healthy" + (f" (exit {code})" if code is not None else ""))
        _case(cases, "health_ok", True, actual_http=200)

        status, _ = http_request(rt, "127.0.0.1", port, "GET", "/missing", {}, b"", min(deadline, rt.clock() + HTTP_TIMEOUT))
        _case(cases, "unknown_route_404", status == 404, actual_http=status)

        bad = {"x-amnezia-client-id": client, "x-amnezia-log-token": "wrong", "x-amnezia-batch-id": batch, "x-amnezia-log-kind": "client"}
        status, _ = http_request(rt, "127.0.0.1", port, "POST", UPLOAD_PATH, bad, b"synthetic-body", min(deadline, rt.clock() + HTTP_TIMEOUT))
        _case(cases, "auth_wrong_token_403", status == 403, actual_http=status)

        body = b"synthetic-guest-artifact-data\n"
        good = {"x-amnezia-client-id": client, "x-amnezia-log-token": token, "x-amnezia-batch-id": batch, "x-amnezia-log-kind": "client", "x-amnezia-installation-id": "guest-b"}
        status1, _ = http_request(rt, "127.0.0.1", port, "POST", UPLOAD_PATH, good, body, min(deadline, rt.clock() + HTTP_TIMEOUT))
        _case(cases, "upload_first_204", status1 == 204, actual_http=status1)
        status2, _ = http_request(rt, "127.0.0.1", port, "POST", UPLOAD_PATH, good, body, min(deadline, rt.clock() + HTTP_TIMEOUT))
        _case(cases, "upload_idempotent_204", status2 == 204, actual_http=status2)
        status3, _ = http_request(rt, "127.0.0.1", port, "POST", UPLOAD_PATH, good, body + b"x", min(deadline, rt.clock() + HTTP_TIMEOUT))
        _case(cases, "upload_conflict_409", status3 == 409, actual_http=status3)

        logdir = os.path.join(runtime, "logs", client)
        files = [n for n in rt.listdir(logdir) if n.endswith("-" + batch + ".log")] if _exists(rt, logdir) else []
        stored_ok = False
        evidence = {}
        if len(files) == 1:
            stored = rt.read_bytes(os.path.join(logdir, files[0]), MAX_ARTIFACT_BYTES, min(deadline, rt.clock() + HTTP_TIMEOUT))
            stored_ok = stored == body
            evidence = {"files": 1, "sha256": _sha256(stored), "size": len(stored)}
        _case(cases, "stored_file_bytes_hash", stored_ok, evidence=evidence)

        route_checks = []
        for label, route_args in (("route_noarg_refusal", []), ("route_invalid_scope_refusal", ["bogus-scope"])):
            rchild = _spawn_child(rt, [route_path] + route_args, {"PATH": "/usr/bin:/bin", "LANG": "C"}, runtime, expect_zero=False)
            children.append(rchild)
            code = rchild.wait(min(deadline, rt.clock() + 2.0))
            rchild.pump(min(deadline, rt.clock() + 0.1))
            for name in ("stdout", "stderr"):
                streams[f"{rchild.pid}:{name}"] = rchild.streams[name][1]
            stderr = bytes(rchild.streams["stderr"][1].head + rchild.streams["stderr"][1].tail)
            errcap = rchild.streams['stderr'][1]
            outcap = rchild.streams['stdout'][1]
            exact_refusal = ROUTE_REFUSAL + b'\n'
            refused = (type(code) is int and code == 1 and errcap.size == len(exact_refusal)
                       and bytes(errcap.head) == exact_refusal and outcap.size == 0)
            route_capture_ok = route_capture_ok and not getattr(rchild, 'capture_error', False) and all(rchild.eof.values()) and not any(
                cap.truncated for _, cap in rchild.streams.values()
            )
            for stream_name, (_, cap) in rchild.streams.items():
                cap.eof_seen = bool(rchild.eof.get(stream_name, False))
            route_checks.append(refused)
            _case(cases, label, refused, native_exit=code, expected="refusal", actual_http=None)
            if code is not None:
                _REGISTRY.pop(rchild.pid, None)
                rchild.close()
                children.remove(rchild)
            else:
                raise Refusal('route child did not exit within its deadline')
        _case(cases, "route_refusal_negative_control", all(route_checks))

        work_ok = all(row["status"] == "PASS" for row in cases if row["name"] not in ("cleanup",))

    except Refusal as exc:
        primary = str(exc)
    except Exception as exc:  # bounded, class only; no paths/secrets
        primary = "runtime " + type(exc).__name__
    finally:
        cleanup_deadline = total_deadline
        cleanup_ok = True
        capture_ok = route_capture_ok
        # A successful spawn may have failed during selector/stream setup.
        children.extend(child for child in list(_REGISTRY.values()) if child not in children)
        for child in reversed(children):
            try:
                good, code, forced = _stop_child(
                    rt, child, cleanup_deadline, streams, getattr(child, "expect_zero", True)
                )
            except Exception:
                good, code, forced = False, None, False
            if not good:
                cleanup_ok = False
                if child.pid in _REGISTRY:
                    cleanup_error = cleanup_error or "unreaped child"
            if forced or not getattr(child, "capture_ok", False):
                capture_ok = False
        try:
            if runtime_lease is not None:
                current_root = rt.lstat(root)
                current_runtime = rt.lstat(runtime)
                if (_REGISTRY or incarnation is None
                        or current_root[1:4] != incarnation[1:4]
                        or stat.S_IMODE(current_root[0]) != 0o700
                        or current_runtime[1] != 0 or stat.S_IMODE(current_runtime[0]) != 0o700
                        or (current_runtime[2], current_runtime[3]) != runtime_lease):
                    raise Refusal('runtime cleanup deferred: ownership or child lease incomplete')
                rt.remove_tree(runtime)
        except Exception as exc:
            cleanup_ok = False
            cleanup_error = cleanup_error or ("cleanup " + type(exc).__name__)
        current = None
        if incarnation is not None:
            try:
                current = rt.lstat(root)
            except Exception:
                cleanup_ok = False
                cleanup_error = cleanup_error or "root disappeared"
            if current is not None and (current[2] != incarnation[2] or current[3] != incarnation[3] or stat.S_IMODE(current[0]) != 0o700):
                cleanup_ok = False
                cleanup_error = cleanup_error or "root incarnation drift"
        receipt["cleanup_passed"] = cleanup_ok
        receipt["capture_complete"] = capture_ok
        if cleanup_error:
            receipt["errors"]["cleanup"] = cleanup_error
        _case(cases, "cleanup", cleanup_ok)

    if not work_ok and primary is None:
        primary = "case failed"
    receipt["work_passed"] = bool(work_ok)
    receipt["errors"]["primary"] = primary
    receipt["streams"] = {
        key: cap.record(getattr(cap, "eof_seen", False))
        for key, cap in sorted(streams.items())
    }


def _exists(rt, path):
    try:
        rt.lstat(path)
        return True
    except OSError:
        return False


def emit(receipt):
    text = json.dumps(receipt, sort_keys=True, separators=(",", ":"))
    if len(text.encode()) > RECEIPT_LIMIT:
        raise Refusal("receipt too large")
    sys.stdout.write(text + "\n")
    sys.stdout.flush()


def sanitize_error(value, root):
    if value is None:
        return None
    text = str(value)
    for secret in (root, MARKER_PATH):
        if secret:
            text = text.replace(secret, "<private>")
    return text[:512]


def main(argv=None, rt=None, fixture_pins=None):
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--plan", required=True)
    args = parser.parse_args(argv)
    rt = rt or RealRuntime()
    receipt = {
        "schema": 1,
        "run_id": None,
        "profile": PROFILE,
        "nonce": None,
        "origin": "guest",
        "injected": False,
        "artifacts": [],
        "work_passed": False,
        "cleanup_passed": False,
        "capture_complete": False,
        "cases": [],
        "streams": {},
        "errors": {"primary": None, "cleanup": None},
        "not_run": NOT_RUN,
    }
    exit_code = 1
    cases = receipt["cases"]
    root = ""
    main_deadline = rt.clock() + WORK_LIMIT
    try:
        if rt.geteuid() != 0:
            raise Refusal("guest uid0 required")
        plan = json.loads(rt.read_bytes(args.plan, 65536, min(main_deadline, rt.clock() + 5.0)))
        checked = validate_plan(plan, pins=fixture_pins)
        receipt["run_id"] = checked["run_id"]
        receipt["nonce"] = checked["nonce"]
        receipt["artifacts"] = checked["artifacts"]
        root = checked["root"]
        run_work(rt, checked, plan, receipt, cases, main_deadline)
        exit_code = 0 if (receipt["work_passed"] and receipt["cleanup_passed"] and receipt["capture_complete"]) else 1
    except Refusal as exc:
        receipt["errors"]["primary"] = sanitize_error(exc, root)
    except Exception as exc:
        receipt["errors"]["primary"] = "runtime " + type(exc).__name__
    finally:
        if root and receipt["errors"]["primary"]:
            receipt["errors"]["primary"] = sanitize_error(receipt["errors"]["primary"], root)
        try:
            emit(receipt)
        except Exception:
            sys.stderr.write("receipt emission failed\n")
            exit_code = 1
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
