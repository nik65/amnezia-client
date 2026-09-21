#!/usr/bin/env python3
"""One-shot driver for the disposable Amnezia release lab (fast path).

Runs the canonical guest sequence in the only correct order:

    create -> start -> guest-probe (retry until the guest agent answers)
           -> run -> gate --lane <lane>

Why this exists: `lab.py` is fail-closed and single-command.  Driving it by
hand repeatedly hit two live defects (see the 2026-09-15 release report):

  * the `start` -> `run` race: `run_steps` writes the first QGA file within
    1-5 s of QEMU start, the guest agent is not up yet and the run dies on
    `socket.timeout`.  This wrapper therefore polls `guest-probe` in a loop
    until the agent answers instead of sleeping a fixed amount of time.
  * the manifest contract (`lab.py:927`) needs `autoInstall=true`; the gate
    call must carry the lane, otherwise a candidate run is validated as a
    release run.  Here the lane is always forwarded, including to `gate`.

On failure the wrapper decodes the base64 `out-data`/`err-data` payloads that
`lab.py` embeds in its error strings (and any base64 fields recorded in the
run state) into readable guest output, so a failed step is diagnosable
without opening the QEMU guest by hand.

Examples:

    python3 Testing/lab_fast.py --run-id rel39x --profile linux-headless-x64 \
        --lane candidate --plan Testing/rel39x-frozen-plan.json

    python3 Testing/lab_fast.py --run-id rel39x --profile linux-headless-x64 \
        --lane candidate --baseline-version 5.0.1.37 --candidate-version 5.0.1.39 \
        --artifact linux-headless-x64=dist/.../AmneziaHeadless_5.0.1.39_linux_x64.tar.gz \
        --baseline-artifact linux-headless-x64=dist/.../AmneziaHeadless_5.0.1.37_linux_x64.tar.gz \
        --manifest dist/.../updates/manifest.json \
        --manifest-public-key /c/keys/selfhosted-update-public.pem \
        --baseline-manifest dist/.../signed/manifest.json

Exit codes: 0 = all requested steps passed; 1 = a lab step failed;
2 = guest agent was not ready within --wait-timeout; 3 = gate rejected the
run; 4 = usage error (missing create inputs).

This wrapper never starts an Amnezia build and never invokes anything except
the lab's own CLI subcommands.
"""

from __future__ import annotations

import argparse
import ast
import base64
import binascii
import json
import os
import re
import subprocess
import sys
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LAB_PY = os.path.join(REPO_ROOT, "deploy", "release_lab", "lab.py")

KNOWN_PROFILES = (
    "windows-x64",
    "android-arm64-v8a",
    "linux-x64-gui",
    "linux-headless-x64",
    "server-router",
)
KNOWN_LANES = ("candidate", "release", "publisher-diagnostic")
DEFAULT_STATE_ROOT = "/var/lib/amnezia-release-lab"

# guest-probe errors that mean "not ready yet, keep waiting"
TRANSIENT_PROBE_MARKERS = (
    "socket",
    "timed out",
    "timeout",
    "qga",
    "not running",
    "has not been started",
    "connection refused",
    "connection reset",
    "broken pipe",
    "probe",  # hyper-v probe not ready
    "lab busy",  # another controller call holds the mutation lock
)
# guest-probe errors that can never fix themselves by retrying
FATAL_PROBE_MARKERS = (
    "unknown lab run",
    "unknown lab run:",  # explicit duplicate for clarity
    "android sandbox disabled",
    "state root",
    "identity",
    "requires",
    "must be",
    "not owned",
    "not a regular file",
    "symlink",
)

B64_KEY_RE = re.compile(
    r"(out[-_]?data|err[-_]?data|stdout[-_]?b64|stderr[-_]?b64|buf[-_]?b64|bytes[-_]?b64|excerpt[-_]?b64|payload[-_]?b64|log[-_]?b64|data[-_]?b64|b64)",
    re.IGNORECASE,
)
B64_VALUE_RE = re.compile(r"[A-Za-z0-9+/=_-]{16,}")


def decode_b64_text(value):
    """Decode a base64 string to text; return None when it is not base64 text."""
    if not isinstance(value, str) or len(value) < 16:
        return None
    candidate = value.strip()
    if not B64_VALUE_RE.fullmatch(candidate):
        return None
    padded = candidate + "=" * (-len(candidate) % 4)
    for variant in ("standard", "urlsafe"):
        try:
            raw = (
                base64.b64decode(padded, validate=True)
                if variant == "standard"
                else base64.urlsafe_b64decode(candidate + "=" * (-len(candidate) % 4))
            )
        except (binascii.Error, ValueError):
            continue
        if not raw:
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            try:
                text = raw.decode("latin-1")
            except Exception:  # pragma: no cover - defensive
                continue
            printable = sum(1 for c in text if c.isprintable() or c in "\n\r\t")
            if printable / max(len(text), 1) < 0.85:
                continue
        if text.strip():
            return text
    return None


def walk_decodable(obj, path="", results=None, depth=0):
    """Recursively collect readable text decoded from base64-ish fields."""
    if results is None:
        results = []
    if depth > 8:
        return results
    if isinstance(obj, dict):
        for key, value in obj.items():
            child = "%s.%s" % (path, key) if path else str(key)
            if isinstance(value, str) and B64_KEY_RE.search(str(key)):
                decoded = decode_b64_text(value)
                if decoded:
                    results.append((child, decoded))
                    continue
            walk_decodable(value, child, results, depth + 1)
    elif isinstance(obj, (list, tuple)):
        for index, value in enumerate(obj):
            walk_decodable(value, "%s[%d]" % (path, index), results, depth + 1)
    return results


def find_dict_literals(text):
    """Yield Python dict literals embedded in a lab error message."""
    for match in re.finditer(r"\{", text):
        start = match.start()
        depth = 0
        quote = None
        escaped = False
        for index in range(start, len(text)):
            char = text[index]
            if quote:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = None
                continue
            if char in ("'", '"'):
                quote = char
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    chunk = text[start : index + 1]
                    try:
                        value = ast.literal_eval(chunk)
                    except (ValueError, SyntaxError):
                        break
                    if isinstance(value, dict):
                        yield value
                    break


def decode_lab_error(error_text):
    """Extract human-readable guest output from a lab.py error string."""
    decoded = []
    seen = set()
    for literal in find_dict_literals(error_text or ""):
        for label, text in walk_decodable(literal, "error"):
            if (label, text) not in seen:
                seen.add((label, text))
                decoded.append((label, text))
    # Fallback: quoted base64 values directly after out-data/err-data keys.
    for match in re.finditer(
        r"['\"]?(out[-_]?data|err[-_]?data)['\"]?\s*[:=]\s*['\"]([A-Za-z0-9+/=_-]{16,})['\"]",
        error_text or "",
    ):
        text = decode_b64_text(match.group(2))
        label = "error.%s" % match.group(1)
        if text and (label, text) not in seen:
            seen.add((label, text))
            decoded.append((label, text))
    return decoded


def translate_path(path):
    """Best-effort translation of WSL <-> Windows paths for local tooling."""
    if not path:
        return path
    if os.path.exists(path):
        return path
    if os.name == "nt":
        match = re.match(r"^/mnt/([a-zA-Z])/(.*)$", path)
        if match:
            drive = match.group(1).upper()
            return "%s:/%s" % (drive, match.group(2))
        match = re.match(r"^/([a-zA-Z])/(.*)$", path)
        if match:
            return "%s:/%s" % (match.group(1).upper(), match.group(2))
        return path
    match = re.match(r"^([A-Za-z]):[\\/](.*)$", path)
    if match:
        candidate = "/mnt/%s/%s" % (match.group(1).lower(), match.group(2).replace("\\", "/"))
        if os.path.exists(candidate) or os.path.exists("/mnt/%s" % match.group(1).lower()):
            return candidate
    return path


def resolve_state_root(explicit):
    raw = explicit or os.environ.get("AMNEZIA_RELEASE_LAB_STATE_ROOT") or DEFAULT_STATE_ROOT
    return raw


def parse_lab_output(stdout):
    """Parse the JSON object lab.py prints; tolerate leading/trailing noise."""
    text = (stdout or "").strip()
    if not text:
        return None
    try:
        value = json.loads(text)
        return value if isinstance(value, dict) else None
    except ValueError:
        pass
    start = text.find("{")
    end = text.rfind("}")
    if 0 <= start < end:
        try:
            value = json.loads(text[start : end + 1])
            return value if isinstance(value, dict) else None
        except ValueError:
            return None
    return None


class LabStep(object):
    def __init__(self, name, argv):
        self.name = name
        self.argv = argv
        self.rc = None
        self.seconds = 0.0
        self.stdout = ""
        self.stderr = ""
        self.result = None
        self.error = None
        self.note = None


class LabFast(object):
    def __init__(self, args):
        self.args = args
        self.python = args.python or sys.executable or "python3"
        self.base = []
        if args.state_root:
            self.base += ["--state-root", args.state_root]
        if args.windows_backend:
            self.base += ["--windows-backend", args.windows_backend]
        if args.android_backend:
            self.base += ["--android-backend", args.android_backend]
        if args.dry_run:
            self.base.append("--dry-run")
        for extra in args.lab_arg or []:
            self.base.append(extra)
        self.steps = []
        self.child_env = dict(os.environ)
        self.child_env.setdefault("PYTHONIOENCODING", "utf-8")
        self.child_env.setdefault("PYTHONUTF8", "1")

    # -- process plumbing -------------------------------------------------
    def run_lab(self, name, tail_args, timeout=None):
        argv = [self.python, LAB_PY] + self.base + list(tail_args)
        step = LabStep(name, argv)
        if timeout is None:
            timeout = self.args.timeout
        started = time.time()
        try:
            proc = subprocess.run(
                argv,
                cwd=REPO_ROOT,
                env=self.child_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout if timeout and timeout > 0 else None,
            )
            step.rc = proc.returncode
            step.stdout = proc.stdout.decode("utf-8", errors="replace")
            step.stderr = proc.stderr.decode("utf-8", errors="replace")
        except subprocess.TimeoutExpired as exc:
            step.rc = 124
            step.stdout = (exc.stdout or b"").decode("utf-8", errors="replace")
            step.stderr = (exc.stderr or b"").decode("utf-8", errors="replace")
            step.error = "timed out after %ss" % timeout
        except OSError as exc:
            step.rc = 127
            step.error = "cannot execute %s: %s" % (self.python, exc)
        step.seconds = time.time() - started
        step.result = parse_lab_output(step.stdout)
        if step.rc != 0 and not step.error:
            if isinstance(step.result, dict) and step.result.get("error"):
                step.error = str(step.result.get("error"))
            else:
                step.error = (step.stderr or step.stdout or "exit %s" % step.rc).strip()
        self.steps.append(step)
        if self.args.verbose or self.args.json:
            self.dump_step(step)
        return step

    def dump_step(self, step):
        print("--- %s: %s" % (step.name, " ".join(step.argv[2:])))
        if step.stdout.strip():
            print(step.stdout.rstrip())
        if step.stderr.strip():
            print("[stderr] " + step.stderr.rstrip())

    # -- flow -------------------------------------------------------------
    def create_args(self):
        args = ["create", "--run-id", self.args.run_id, "--lane", self.args.lane]
        if self.args.baseline_version:
            args += ["--baseline-version", self.args.baseline_version]
        if self.args.candidate_version:
            args += ["--candidate-version", self.args.candidate_version]
        for value in self.args.artifact or []:
            args += ["--artifact", value]
        for value in self.args.baseline_artifact or []:
            args += ["--baseline-artifact", value]
        for flag, value in (
            ("--manifest", self.args.manifest),
            ("--manifest-public-key", self.args.manifest_public_key),
            ("--baseline-manifest", self.args.baseline_manifest),
            ("--headless-baseline-receipt", self.args.headless_baseline_receipt),
            ("--headless-candidate-receipt", self.args.headless_candidate_receipt),
            ("--outer-artifact", self.args.outer_artifact),
            ("--baseline-outer-artifact", self.args.baseline_outer_artifact),
        ):
            if value:
                args += [flag, translate_path(value)]
        return args

    def validate_create_inputs(self):
        missing = []
        if not self.args.baseline_version:
            missing.append("--baseline-version")
        if not self.args.candidate_version:
            missing.append("--candidate-version")
        if not (self.args.artifact or []):
            missing.append("--artifact")
        if not self.args.manifest:
            missing.append("--manifest")
        if not self.args.manifest_public_key:
            missing.append("--manifest-public-key")
        return missing

    def wait_for_agent(self):
        deadline = time.time() + self.args.wait_timeout
        attempt = 0
        last_error = "no attempt made"
        while True:
            attempt += 1
            step = self.run_lab(
                "probe",
                ["guest-probe", "--run-id", self.args.run_id, "--profile", self.args.profile],
            )
            if step.rc == 0:
                step.note = "%d attempt(s)" % attempt
                return step
            last_error = step.error or (step.stderr or step.stdout).strip()
            lowered = (last_error or "").lower()
            if any(marker in lowered for marker in FATAL_PROBE_MARKERS):
                step.note = "fatal probe error, not retrying"
                return step
            if not any(marker in lowered for marker in TRANSIENT_PROBE_MARKERS):
                step.note = "unrecognized probe error, not retrying"
                return step
            if time.time() + self.args.probe_interval >= deadline:
                step.error = "guest agent not ready within %ss (last: %s)" % (
                    self.args.wait_timeout,
                    last_error,
                )
                step.note = "%d attempt(s), timeout" % attempt
                return step
            remaining = max(deadline - time.time(), 0)
            print(
                "      probe attempt %d not ready (%.0fs left): %s"
                % (attempt, remaining, (last_error or "").splitlines()[0][:160])
            )
            time.sleep(self.args.probe_interval)

    def gate_args(self):
        args = ["gate", "--run-id", self.args.run_id, "--lane", self.args.lane]
        if self.args.gate_artifact_dir:
            args += ["--artifact-dir", translate_path(self.args.gate_artifact_dir)]
        if self.args.gate_outer_artifact:
            args += ["--outer-artifact", translate_path(self.args.gate_outer_artifact)]
        return args

    def run_flow(self):
        plan_ok = True
        stages = []
        if not self.args.no_create:
            if self.args.resume and self.run_exists():
                print("      create skipped: run %s already exists (--resume)" % self.args.run_id)
            else:
                missing = self.validate_create_inputs()
                if missing:
                    print(
                        "ERROR: create needs %s (or pass --plan / --no-create / --resume)"
                        % ", ".join(missing),
                        file=sys.stderr,
                    )
                    return 4
                stages.append(("create", self.create_args()))
        if not self.args.no_start:
            stages.append(
                ("start", ["start", "--run-id", self.args.run_id, "--profile", self.args.profile])
            )
        if not self.args.no_probe:
            stages.append(("probe", None))  # handled by wait_for_agent
        if not self.args.no_run:
            run_args = ["run", "--run-id", self.args.run_id, "--profile", self.args.profile]
            for step_id in self.args.step or []:
                run_args += ["--step", step_id]
            if self.args.preserve_failed_guest:
                run_args.append("--preserve-failed-guest")
            stages.append(("run", run_args))
        if not self.args.no_gate:
            stages.append(("gate", self.gate_args()))

        failed = None
        for name, argv in stages:
            if name == "probe":
                print("[probe] waiting for guest agent (timeout %ss) ..." % self.args.wait_timeout)
                step = self.wait_for_agent()
            else:
                print("[%s] running ..." % name)
                step = self.run_lab(name, argv)
            status = "OK" if step.rc == 0 else "FAIL(%s)" % step.rc
            print(
                "  -> %-6s %-9s %.1fs%s"
                % (name, status, step.seconds, " [%s]" % step.note if step.note else "")
            )
            if step.rc != 0:
                failed = step
                break

        self.print_failure(failed)
        self.print_summary(stages, failed)
        if failed is None:
            if not self.args.no_gate:
                gate = self.steps[-1]
                verdict = gate.result or {}
                passed = verdict.get("release_passed") or verdict.get("candidate_passed")
                if gate.rc != 0 or not passed:
                    print("RESULT: GATE_REJECTED (lane=%s)" % self.args.lane)
                    return 3
            print("RESULT: PASS")
            return 0
        if failed.name == "gate":
            print("RESULT: GATE_REJECTED (lane=%s)" % self.args.lane)
            return 3
        if failed.name == "probe" and (failed.error or "").startswith("guest agent not ready"):
            print("RESULT: AGENT_NOT_READY")
            return 2
        print("RESULT: FAIL step=%s exit=%s" % (failed.name, failed.rc))
        return 1

    def run_exists(self):
        step = self.run_lab("status", ["status"])
        if step.rc != 0 or not isinstance(step.result, dict):
            return False
        return self.args.run_id in (step.result.get("runs") or {})

    # -- reporting --------------------------------------------------------
    def collect_failure_texts(self, failed):
        """All base64-decoded guest payloads relevant to a failure."""
        blobs = []
        seen = set()

        def add(label, text):
            key = (label, text)
            if key in seen or not text:
                return
            seen.add(key)
            blobs.append((label, text))

        if failed is not None and failed.error:
            for label, text in decode_lab_error(failed.error):
                add(label, text)
            for label, text in decode_lab_error(failed.stdout):
                add(label, text)
        state_path = os.path.join(resolve_state_root(self.args.state_root), "state.json")
        if os.path.isfile(state_path):
            try:
                with open(state_path, "r", encoding="utf-8", errors="replace") as handle:
                    state = json.load(handle)
                run = (state.get("runs") or {}).get(self.args.run_id)
                profile_state = ((run or {}).get("profiles") or {}).get(self.args.profile)
                if isinstance(profile_state, dict):
                    for label, text in walk_decodable(
                        profile_state, "state.profiles.%s" % self.args.profile
                    ):
                        add(label, text)
            except (OSError, ValueError):
                pass
        return blobs

    def print_failure(self, failed):
        if failed is None:
            return
        print("")
        print("FAILURE: step=%s rc=%s" % (failed.name, failed.rc))
        if failed.error:
            print("  error: %s" % self.one_line(failed.error, 1200))
        elif failed.stderr.strip():
            print("  stderr: %s" % self.one_line(failed.stderr, 1200))
        for label, text in self.collect_failure_texts(failed):
            print("  decoded %s:" % label)
            for line in self.truncate(text, self.args.decode_limit).splitlines():
                print("    | %s" % line)

    @staticmethod
    def one_line(text, limit):
        collapsed = " ".join(str(text).split())
        if len(collapsed) > limit:
            collapsed = collapsed[: limit - 3] + "..."
        return collapsed

    @staticmethod
    def truncate(text, limit):
        if limit and len(text) > limit:
            return text[:limit] + "\n... [%d more chars]" % (len(text) - limit)
        return text

    def print_summary(self, stages, failed):
        print("")
        print("=== lab_fast summary ===")
        print("run_id  : %s" % self.args.run_id)
        print("profile : %s" % self.args.profile)
        print("lane    : %s" % self.args.lane)
        print("state   : %s" % resolve_state_root(self.args.state_root))
        order = [name for name, _ in stages]
        by_name = {}
        for step in self.steps:
            by_name[step.name] = step  # last attempt wins (probe retries)
        for name in order:
            step = by_name.get(name)
            if step is None:
                print("  %-7s : skipped" % name)
                continue
            verdict = ""
            if name == "gate" and isinstance(step.result, dict):
                verdict = " release_passed=%s candidate_passed=%s" % (
                    step.result.get("release_passed"),
                    step.result.get("candidate_passed"),
                )
            print(
                "  %-7s : %-4s %6.1fs%s%s"
                % (
                    name,
                    "ok" if step.rc == 0 else "fail",
                    step.seconds,
                    verdict,
                    " [%s]" % step.note if step.note else "",
                )
            )
        if failed is not None:
            print("  stop_at : %s" % failed.name)


def load_plan(path):
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        plan = json.load(handle)
    if not isinstance(plan, dict):
        raise SystemExit("plan is not a JSON object: %s" % path)
    return plan


def apply_plan(args, plan):
    def record_path(value):
        if isinstance(value, dict):
            return value.get("path")
        if isinstance(value, str):
            return value
        return None

    if not args.run_id and plan.get("run_id"):
        args.run_id = str(plan["run_id"])
    if args.lane is None and plan.get("lane") in KNOWN_LANES:
        args.lane = plan["lane"]
    if not args.baseline_version and plan.get("baseline_version"):
        args.baseline_version = str(plan["baseline_version"])
    if not args.candidate_version and plan.get("candidate_version"):
        args.candidate_version = str(plan["candidate_version"])
    if not (args.artifact or []):
        for platform, item in sorted((plan.get("artifacts") or {}).items()):
            path = record_path(item)
            if path:
                args.artifact = (args.artifact or []) + ["%s=%s" % (platform, path)]
    if not (args.baseline_artifact or []):
        for platform, item in sorted((plan.get("baseline_artifacts") or {}).items()):
            path = record_path(item)
            if path:
                args.baseline_artifact = (args.baseline_artifact or []) + [
                    "%s=%s" % (platform, path)
                ]
    for attribute, key in (
        ("manifest", "manifest"),
        ("manifest_public_key", "manifest_public_key"),
        ("baseline_manifest", "baseline_manifest"),
        ("headless_baseline_receipt", "headless_baseline_receipt"),
        ("headless_candidate_receipt", "headless_candidate_receipt"),
        ("outer_artifact", "outer_artifact"),
        ("baseline_outer_artifact", "baseline_outer_artifact"),
    ):
        if not getattr(args, attribute):
            path = record_path(plan.get(key))
            if path:
                setattr(args, attribute, path)
    if not args.windows_backend and plan.get("windows_backend") in ("qemu", "hyperv"):
        args.windows_backend = plan["windows_backend"]
    if not args.android_backend and plan.get("android_backend") in ("linux", "windows"):
        args.android_backend = plan["android_backend"]
    return args


def build_parser():
    parser = argparse.ArgumentParser(
        description="One-shot create/start/wait/run/gate driver for the Amnezia release lab"
    )
    parser.add_argument("--run-id", help="lab run id (required unless --plan provides it)")
    parser.add_argument("--profile", required=True, choices=KNOWN_PROFILES)
    parser.add_argument(
        "--lane",
        choices=("candidate", "release", "publisher-diagnostic"),
        default=None,
        help="lane forwarded to create and gate (default: candidate)",
    )
    parser.add_argument("--plan", help="frozen plan JSON with artifacts/versions/manifest inputs")
    parser.add_argument("--baseline-version")
    parser.add_argument("--candidate-version")
    parser.add_argument("--artifact", action="append", default=[], metavar="PLATFORM=PATH")
    parser.add_argument(
        "--baseline-artifact", action="append", default=[], metavar="PLATFORM=PATH"
    )
    parser.add_argument("--manifest")
    parser.add_argument("--manifest-public-key")
    parser.add_argument("--baseline-manifest")
    parser.add_argument("--headless-baseline-receipt")
    parser.add_argument("--headless-candidate-receipt")
    parser.add_argument("--outer-artifact")
    parser.add_argument("--baseline-outer-artifact")
    parser.add_argument("--gate-artifact-dir")
    parser.add_argument("--gate-outer-artifact")
    parser.add_argument("--step", action="append", default=[], help="forwarded to run (repeatable)")
    parser.add_argument("--preserve-failed-guest", action="store_true")
    parser.add_argument(
        "--wait-timeout",
        type=int,
        default=900,
        help="seconds to wait for the guest agent via repeated guest-probe (default: 900)",
    )
    parser.add_argument(
        "--probe-interval", type=int, default=5, help="seconds between guest-probe attempts"
    )
    parser.add_argument(
        "--timeout", type=int, default=0, help="per-lab-command timeout in seconds (0 = none)"
    )
    parser.add_argument("--state-root", help="lab state root (default: lab.py's own default)")
    parser.add_argument("--windows-backend", choices=("qemu", "hyperv"))
    parser.add_argument("--android-backend", choices=("linux", "windows"))
    parser.add_argument("--dry-run", action="store_true", help="forwarded to lab.py")
    parser.add_argument("--python", help="interpreter used to run lab.py (default: current)")
    parser.add_argument(
        "--lab-arg",
        action="append",
        default=[],
        help="extra global lab.py argument inserted before every subcommand (repeatable)",
    )
    parser.add_argument("--resume", action="store_true", help="skip create when the run exists")
    parser.add_argument("--no-create", action="store_true")
    parser.add_argument("--no-start", action="store_true")
    parser.add_argument("--no-probe", action="store_true")
    parser.add_argument("--no-run", action="store_true")
    parser.add_argument("--no-gate", action="store_true")
    parser.add_argument("--json", action="store_true", help="print each raw lab JSON result")
    parser.add_argument("--verbose", action="store_true", help="print full lab output per step")
    parser.add_argument(
        "--decode-limit",
        type=int,
        default=4000,
        help="max characters printed per decoded base64 payload (default: 4000)",
    )
    return parser


def main(argv=None):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # pragma: no cover - very old interpreters
        pass
    args = build_parser().parse_args(argv)
    if not os.path.isfile(LAB_PY):
        print("ERROR: lab.py not found at %s" % LAB_PY, file=sys.stderr)
        return 4
    if args.plan:
        args = apply_plan(args, load_plan(translate_path(args.plan)))
    if args.lane is None:
        args.lane = "candidate"
    if not args.run_id:
        print("ERROR: --run-id is required (or provide --plan with run_id)", file=sys.stderr)
        return 4
    print("=== lab_fast ===")
    print(
        "run_id=%s profile=%s lane=%s python=%s"
        % (args.run_id, args.profile, args.lane, args.python or sys.executable)
    )
    return LabFast(args).run_flow()


if __name__ == "__main__":
    sys.exit(main())
