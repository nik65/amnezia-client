#!/usr/bin/env python3
from __future__ import annotations

import ast
import base64
import contextlib
import hashlib
import io
import json
import os
import plistlib
import re
import shutil
import shlex
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import time
import types
import unittest
import warnings
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlparse
from unittest import mock

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parents[1]
sys.path.insert(0, str(SCRIPT_DIR))

import release_freeze  # noqa: E402
import make_manifest  # noqa: E402


def find_openssl() -> str | None:
    candidates = [
        shutil.which("openssl"),
        r"C:\Program Files\Git\usr\bin\openssl.exe",
        r"C:\Program Files\Git\mingw64\bin\openssl.exe",
    ]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return str(candidate)
    return None


def find_sh() -> str | None:
    candidates = [
        shutil.which("sh"),
        r"C:\Program Files\Git\bin\sh.exe",
        r"C:\Program Files\Git\usr\bin\sh.exe",
    ]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return str(candidate)
    return None


def find_bash() -> str | None:
    candidates = [
        r"C:\Program Files\Git\bin\bash.exe",
        r"C:\Program Files\Git\usr\bin\bash.exe",
        shutil.which("bash"),
    ]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return str(candidate)
    return None


def find_powershell() -> str | None:
    candidates = [
        shutil.which("pwsh"),
        shutil.which("powershell"),
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    ]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return str(candidate)
    return None


def find_windows_powershell() -> str | None:
    if os.name != "nt":
        return None
    candidate = (
        Path(os.environ.get("SystemRoot", r"C:\Windows"))
        / "System32"
        / "WindowsPowerShell"
        / "v1.0"
        / "powershell.exe"
    )
    return str(candidate) if candidate.is_file() else None


def find_wsl() -> str | None:
    return shutil.which("wsl.exe") or shutil.which("wsl")


def to_wsl_path(path: Path) -> str:
    wsl = find_wsl()
    if not wsl:
        raise unittest.SkipTest("WSL is required")
    result = subprocess.run([wsl, "wslpath", "-a", str(path).replace("\\", "/")], text=True, capture_output=True)
    if result.returncode != 0:
        raise AssertionError(result.stderr + result.stdout)
    return result.stdout.strip()


def find_git() -> str | None:
    return shutil.which("git")


def extract_client_logs_collector_script() -> str:
    export_controller = (REPO_ROOT / "client/core/controllers/selfhosted/exportController.cpp").read_text(encoding="utf-8")
    function_start = export_controller.find("QByteArray clientLogsCollectorScript()")
    function_end = export_controller.find("QString clientLogsLegacyMapRefreshScript()", function_start)
    if function_start < 0 or function_end < 0:
        raise AssertionError("client log collector script raw string was not found")
    function_body = export_controller[function_start:function_end]
    chunks = re.findall(
        r'(?:QString script =|script \+=)\s*QStringLiteral\(R"(PY\d*)\(\n(.*?)\n\)\1"\);',
        function_body,
        re.S,
    )
    if not chunks:
        raise AssertionError("client log collector script raw string was not found")
    script = "\n".join(body for _, body in chunks)
    script = (
        script.replace("__MAX_UPLOAD_BYTES__", str(15 * 1024 * 1024))
        .replace("__MAX_CLIENT_BYTES__", str(30 * 1024 * 1024))
        .replace("__PORT__", "17866")
        .replace("__UPLOAD_PATH__", "/logs")
        .replace("__BOOTSTRAP_PATH__", "/bootstrap")
    )
    if re.search(r"__[A-Z0-9_]+__", script):
        raise AssertionError("client log collector script contains unresolved placeholders")
    return script


def exec_client_logs_collector_script(namespace: dict[str, object]) -> None:
    fake_fcntl = types.ModuleType("fcntl")
    fake_fcntl.LOCK_EX = 1  # type: ignore[attr-defined]
    fake_fcntl.LOCK_UN = 2  # type: ignore[attr-defined]
    fake_fcntl.flock = lambda *_args: None  # type: ignore[attr-defined]
    with mock.patch.dict(sys.modules, {"fcntl": fake_fcntl}):
        exec(extract_client_logs_collector_script(), namespace)


def extract_client_logs_legacy_map_refresh_script() -> str:
    export_controller = (REPO_ROOT / "client/core/controllers/selfhosted/exportController.cpp").read_text(encoding="utf-8")
    match = re.search(r'QString script = QStringLiteral\(R"LMAP\(\n(.*?)\n\)LMAP"\);', export_controller, re.S)
    if not match:
        raise AssertionError("client log legacy map refresh script raw string was not found")
    return match.group(1)


def extract_server_routing_rules_resolver_script() -> str:
    install_controller = (
        REPO_ROOT / "client/core/controllers/selfhosted/installController.cpp"
    ).read_text(encoding="utf-8")
    match = re.search(
        r'QString script = QStringLiteral\(R"SERVER_RULES_SH\((.*?)\)SERVER_RULES_SH"\);',
        install_controller,
        re.S,
    )
    if not match:
        raise AssertionError("server routing rules resolver script was not found")
    script = match.group(1)
    replacements = {
        "__RULES_FILE__": "rules.json",
        "__SOURCE_FILE__": "rules-source.txt",
        "__READY_FILE__": "rules-ready",
        "__POLICY_JSON__": "''",
        "__SERVER_EXCEPT_KEY__": "server.except",
        "__MANAGED_EXCEPT_KEY__": "managedSplitTunnelExceptSites",
        "__SOURCE_EXCEPT_KEY__": "managedSplitTunnelExceptSourceSites",
        "__FORCE_KEY__": "managedSplitTunnelForceEnabled",
        "__FORCE_ENABLED__": "0",
        "__SYNC_PORT__": "17864",
        "__RESOLVE_INTERVAL_SECONDS__": "86400",
        "__RESOLVE_JITTER_SECONDS__": "3600",
        "__INITIAL_RESOLVE_TIMEOUT_SECONDS__": "90",
        "__INITIAL_RESOLVE_RETRY_SECONDS__": "5",
        "__RESOLVE_QUERY_TIMEOUT_SECONDS__": "3",
        "__RECOVERY_QUERY_TIMEOUT_SECONDS__": "1",
        "__VALIDATE_RESOLVE_BUDGET_SECONDS__": "15",
        "__RECOVERY_INITIAL_DELAY_SECONDS__": "15",
        "__RECOVERY_MAXIMUM_DELAY_SECONDS__": "300",
        "__RECOVERY_MAXIMUM_ATTEMPTS__": "6",
        "__RECOVERY_ATTEMPT_BUDGET_SECONDS__": "30",
    }
    for placeholder, value in replacements.items():
        script = script.replace(placeholder, value)
    if re.search(r"__[A-Z0-9_]+__", script):
        raise AssertionError("server routing rules resolver script contains unresolved placeholders")
    return script


def run_git(cwd: Path, *args: str, stdout: object | None = None) -> subprocess.CompletedProcess[str]:
    command = [find_git() or "git", *args]
    return subprocess.run(command, cwd=cwd, check=True, text=True, stdout=stdout, stderr=subprocess.PIPE)


def manifest_payload(manifest_path: Path) -> dict[str, object]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    payload_bytes = base64.urlsafe_b64decode(manifest["payload"] + "=" * (-len(manifest["payload"]) % 4))
    return json.loads(payload_bytes.decode("utf-8"))


def sha256_hex_for_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def planned_action(args: object) -> str:
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        release_freeze.plan(args)
    return json.loads(output.getvalue())["action"]


def assert_no_duplicate_yaml_keys(test_case: unittest.TestCase, path: Path) -> None:
    stack: list[tuple[int, set[str]]] = []
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        if raw_line.lstrip() != raw_line:
            indent = len(raw_line) - len(raw_line.lstrip(" "))
        else:
            indent = 0
        if raw_line[indent:].startswith("- "):
            continue
        stripped = raw_line.strip()
        if ":" not in stripped or stripped.startswith(("|", ">")):
            continue
        key = stripped.split(":", 1)[0].strip().strip("'\"")
        if not key or " " in key:
            continue
        while stack and stack[-1][0] >= indent:
            stack.pop()
        if not stack or stack[-1][0] != indent:
            stack.append((indent, set()))
        keys = stack[-1][1]
        test_case.assertNotIn(key, keys, f"Duplicate YAML key {key!r} in {path}:{line_number}")
        keys.add(key)


def read_workflow_if_enabled(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8")


def shell_absolute_path(path: Path) -> str:
    resolved = path.resolve()
    if os.name != "nt":
        return str(resolved)
    drive = resolved.drive.rstrip(":").lower()
    tail = resolved.as_posix().split(":", 1)[1].lstrip("/")
    return f"/{drive}/{tail}"


def sh_quote(value: str) -> str:
    """Quote a value for the POSIX shell snippets exercised by these tests."""

    return "'" + value.replace("'", "'\"'\"'") + "'"


def bundled_publisher_harness_source(channel_root: Path) -> tuple[str, Path]:
    """Adapt only compile-time publisher constants in a private POSIX test copy."""

    source = (SCRIPT_DIR / "publish_bundled_release.sh").read_text(encoding="utf-8")
    anchor = channel_root.parent
    upload_prefix = anchor / "upload."
    replacements = {
        "PINNED_ROOT='/opt/amnezia/client-updates'": (
            "PINNED_ROOT=" + sh_quote(str(channel_root))
        ),
        "PINNED_PARENT='/opt/amnezia'": "PINNED_PARENT=" + sh_quote(str(anchor)),
        "TRUST_ANCHOR='/opt'": "TRUST_ANCHOR=" + sh_quote(str(anchor)),
        "UPLOAD_PREFIX='/tmp/amnezia-client-updates.'": (
            "UPLOAD_PREFIX=" + sh_quote(str(upload_prefix))
        ),
        "TRUSTED_UID=0": "TRUSTED_UID=$(id -u)",
        "TRUSTED_GID=0": "TRUSTED_GID=$(id -g)",
        'as_root() {\n    sudo -n -- "$@"\n}': 'as_root() {\n    "$@"\n}',
    }
    for original, replacement in replacements.items():
        if source.count(original) != 1:
            raise AssertionError(f"publisher harness replacement is not unique: {original!r}")
        source = source.replace(original, replacement, 1)
    return source, upload_prefix


def bundled_publisher_receipt(
    kind: str,
    run_id: str,
    expected: str,
    candidate: str,
    metadata_sha: str,
    file_count: int,
    result: str,
    phase: str,
) -> str:
    return (
        f"{kind}\t{run_id}\t{expected}\t{candidate}\t{metadata_sha}\t"
        f"{file_count}\t{result}\t{phase}\n"
    )


def extract_ssh_upload_shell_command(variable_name: str) -> str:
    source = (REPO_ROOT / "client/core/utils/selfhosted/sshClient.cpp").read_text(encoding="utf-8")
    command_start = source.index(f"const QString {variable_name} = (QStringLiteral(")
    command_end = source.index(".arg(shellQuote(remotePath)", command_start)
    command_source = source[command_start:command_end]
    literal_parts = re.findall(r'"((?:\\.|[^"\\])*)"', command_source)
    return (
        "".join(ast.literal_eval(f'"{part}"') for part in literal_parts)
        + "printf '%s\\n' \"$receipt\""
    )


def extract_ssh_upload_durable_sync_function() -> str:
    command = extract_ssh_upload_shell_command("command")
    function_start = command.index("durable_sync() {")
    function_end = command.index("cleanup_upload()", function_start)
    return command[function_start:function_end]


PINNED_UPDATE_HOST_IMAGE = (
    "docker.io/library/busybox@"
    "sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662"
)


def update_host_installer_harness_source(trust_anchor: Path) -> str:
    """Move only trusted filesystem constants into a private POSIX test root."""

    source = (SCRIPT_DIR / "install_server_update_host.sh").read_text(encoding="utf-8")
    lock_parent = trust_anchor / "amnezia"
    replacements = {
        "TRUST_ANCHOR='/opt'": "TRUST_ANCHOR=" + sh_quote(str(trust_anchor)),
        "LOCK_PARENT='/opt/amnezia'": "LOCK_PARENT=" + sh_quote(str(lock_parent)),
        "TRUSTED_UID=0": "TRUSTED_UID=$(id -u)",
        "TRUSTED_GID=0": "TRUSTED_GID=$(id -g)",
        'as_root() {\n    sudo -n -- "$@"\n}': 'as_root() {\n    "$@"\n}',
    }
    for original, replacement in replacements.items():
        if source.count(original) != 1:
            raise AssertionError(f"installer harness replacement is not unique: {original!r}")
        source = source.replace(original, replacement, 1)
    return source


def transactional_fake_docker_source() -> str:
    return textwrap.dedent(
        f'''\
        #!/usr/bin/env python3
        import json
        import os
        import sys
        import time
        from pathlib import Path

        PINNED_IMAGE = {PINNED_UPDATE_HOST_IMAGE!r}
        POISONED_TAG = "docker.io/library/busybox:1.36.1"
        args = sys.argv[1:]
        state_path = Path(os.environ["FAKE_DOCKER_STATE"])
        log_path = Path(os.environ["FAKE_DOCKER_LOG"])
        state = json.loads(state_path.read_text(encoding="utf-8"))

        def save() -> None:
            state_path.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")

        def resolve(reference: str):
            if reference in containers:
                return reference, containers[reference]
            for container_name, container in containers.items():
                if container.get("id") == reference:
                    return container_name, container
            return None, None

        def inject_aba(phase: str) -> None:
            if os.environ.get("FAKE_DOCKER_ABA_PHASE") != phase:
                return
            marker = Path(os.environ.get("FAKE_DOCKER_ABA_MARKER", str(state_path) + ".aba"))
            if marker.exists():
                return
            marker.touch()
            canonical = os.environ.get("FAKE_MAIN_NAME", "amnezia-client-updates")
            if canonical in containers:
                displaced = canonical + ".aba-displaced"
                if displaced in containers:
                    raise SystemExit(79)
                containers[displaced] = containers.pop(canonical)
            containers[canonical] = {{
                "id": "foreign-container-id",
                "role": "foreign",
                "running": True,
                "network": "foreign-network",
                "ip": "",
                "labels": {{}},
                "image": "foreign/image:latest",
                "mount_source": "",
                "mount_rw": True,
            }}
            save()

        def complete(phase: str, code: int = 0) -> None:
            invocation = os.environ.get("FAKE_DOCKER_INVOCATION", "single")
            with log_path.open("a", encoding="utf-8") as handle:
                handle.write(f"{{invocation}}|{{phase}}|{{' '.join(args)}}\\n")
            if os.environ.get("FAKE_DOCKER_HOLD_PHASE") == phase:
                entered = Path(os.environ["FAKE_DOCKER_HOLD_ENTERED"])
                release = Path(os.environ["FAKE_DOCKER_HOLD_RELEASE"])
                entered.touch()
                deadline = time.monotonic() + 20
                while not release.exists() and time.monotonic() < deadline:
                    time.sleep(0.02)
                if not release.exists():
                    raise SystemExit(78)
            inject_aba(phase)
            fail_phase = os.environ.get("FAKE_DOCKER_FAIL_PHASE")
            fail_marker = Path(os.environ.get("FAKE_DOCKER_FAIL_MARKER", str(state_path) + ".failed"))
            if fail_phase == phase and not fail_marker.exists():
                fail_marker.touch()
                raise SystemExit(73)
            raise SystemExit(code)

        def fail_before(phase: str) -> None:
            if os.environ.get("FAKE_DOCKER_FAIL_BEFORE_PHASE") == phase:
                complete("before-" + phase, 74)

        def option(name: str) -> str | None:
            try:
                return args[args.index(name) + 1]
            except (ValueError, IndexError):
                return None

        containers = state.setdefault("containers", {{}})
        networks = state.setdefault("networks", {{}})

        def resolve_network(reference: str):
            if reference in networks:
                return reference, networks[reference]
            for network_name, network in networks.items():
                if network.get("id") == reference:
                    return network_name, network
            return None, None

        def render_container(name: str, container: dict, template: str) -> None:
            if ".Id" in template:
                print(container["id"])
            elif ".Name" in template:
                print("/" + name)
            elif ".State.Running" in template:
                print("true" if container["running"] else "false")
            elif ".NetworkSettings.Networks" in template:
                print(container.get("ip", ""))
            elif ".Config.Image" in template:
                print(container.get("image", PINNED_IMAGE))
            elif ".HostConfig.NetworkMode" in template:
                print(container.get("network", ""))
            elif ".Config.Labels" in template:
                for label_key, label_value in container.get("labels", {{}}).items():
                    if label_key in template:
                        print(label_value)
                        break
                else:
                    print("")
            elif ".Mounts" in template:
                print(f"{{container.get('mount_source', '')}}|{{str(container.get('mount_rw', False)).lower()}}")

        if args[:2] == ["image", "inspect"]:
            reference = args[2] if len(args) > 2 else ""
            present = bool(state.get("image_present")) if reference == PINNED_IMAGE else (
                bool(state.get("poisoned_tag_present")) if reference == POISONED_TAG else False
            )
            if not present:
                print(f"Error: No such image: {{reference}}", file=sys.stderr)
            complete("image-inspect", 0 if present else 1)

        if args and args[0] == "pull":
            if len(args) < 2 or args[1] != PINNED_IMAGE:
                complete("pull-unpinned", 68)
            if os.environ.get("FAKE_DOCKER_ALLOW_PULL", "0") != "1":
                complete("pull-pinned", 69)
            state["image_present"] = True
            save()
            complete("pull-pinned")

        if args[:2] == ["container", "inspect"]:
            name, container = resolve(args[-1])
            if container is None:
                print(f"Error: No such object: {{args[-1]}}", file=sys.stderr)
                complete("container-inspect", 1)
            render_container(name, container, option("-f") or "")
            complete("container-inspect")

        if args and args[0] == "inspect":
            name, container = resolve(args[-1])
            if container is None:
                print(f"Error: No such object: {{args[-1]}}", file=sys.stderr)
                complete("inspect-container", 1)
            template = option("-f") or ""
            render_container(name, container, template)
            complete("inspect-container")

        if args and args[0] == "ps":
            include_stopped = any(value.startswith("-") and "a" in value for value in args)
            quiet = any(value.startswith("-") and "q" in value for value in args)
            filters = [args[index + 1] for index, value in enumerate(args[:-1]) if value == "--filter"]
            for name, container in containers.items():
                if not (include_stopped or container["running"]):
                    continue
                matched = True
                for filter_value in filters:
                    if filter_value.startswith("label="):
                        label_expression = filter_value[len("label="):]
                        label_key, _, label_value = label_expression.partition("=")
                        if container.get("labels", {{}}).get(label_key) != label_value:
                            matched = False
                if matched:
                    print(container["id"] if quiet else name)
            complete("ps")

        if args[:2] == ["network", "inspect"]:
            network_name, network = resolve_network(args[-1])
            if network is None:
                print(f"Error: No such network: {{args[-1]}}", file=sys.stderr)
                complete("network-inspect", 1)
            template = option("-f") or ""
            if ".Id" in template:
                print(network["id"])
            elif ".Name" in template:
                print(network_name)
            elif ".IPAM.Config" in template:
                print(network.get("subnet", ""))
            elif ".Labels" in template:
                for label_key, label_value in network.get("labels", {{}}).items():
                    if label_key in template:
                        print(label_value)
                        break
                else:
                    print("")
            complete("network-inspect")

        if args[:2] == ["network", "ls"]:
            filters = [args[index + 1] for index, value in enumerate(args[:-1]) if value == "--filter"]
            for network in networks.values():
                matched = True
                for filter_value in filters:
                    if filter_value.startswith("label="):
                        label_key, _, label_value = filter_value[len("label="):].partition("=")
                        if network.get("labels", {{}}).get(label_key) != label_value:
                            matched = False
                if matched:
                    print(network["id"])
            complete("network-ls")

        if args[:2] == ["network", "create"]:
            network_name = args[-1]
            subnet = next((value.split("=", 1)[1] for value in args if value.startswith("--subnet=")), "")
            labels = {{}}
            for index, value in enumerate(args[:-1]):
                if value == "--label":
                    label_key, _, label_value = args[index + 1].partition("=")
                    labels[label_key] = label_value
            next_network_id = int(state.get("next_network_id", 2000))
            state["next_network_id"] = next_network_id + 1
            networks[network_name] = {{
                "id": f"network-id-{{next_network_id}}",
                "subnet": subnet,
                "labels": labels,
            }}
            save()
            complete("network-create")

        if args[:2] == ["network", "rm"]:
            network_name, network = resolve_network(args[-1])
            if network is None:
                print(f"Error: No such network: {{args[-1]}}", file=sys.stderr)
                complete("network-rm", 1)
            del networks[network_name]
            save()
            complete("network-rm")

        if args[:2] == ["network", "disconnect"]:
            network_name, reference = args[-2:]
            name, container = resolve(reference)
            if container is None or container.get("network") != network_name:
                complete("disconnect-main", 1)
            container["network"] = ""
            container["ip"] = ""
            save()
            complete("disconnect-main")

        if args[:2] == ["network", "connect"]:
            reference = args[-1]
            network_name = args[-2]
            name, container = resolve(reference)
            if container is None:
                complete("rollback-connect", 1)
            container["network"] = network_name
            container["ip"] = option("--ip") or ""
            save()
            complete("rollback-connect")

        if args and args[0] == "rename":
            reference, new_name = args[1:3]
            old_name, container = resolve(reference)
            if container is None or new_name in containers:
                complete("rename-invalid", 1)
            container = containers.pop(old_name)
            containers[new_name] = container
            save()
            complete("rename-" + container["role"])

        if args and args[0] == "stop":
            name, container = resolve(args[-1])
            if container is None:
                complete("stop-invalid", 1)
            container["running"] = False
            save()
            complete("stop-" + container["role"])

        if args and args[0] == "start":
            name, container = resolve(args[-1])
            if container is None:
                complete("rollback-start", 1)
            container["running"] = True
            save()
            complete("rollback-start")

        if args and args[0] == "run":
            if PINNED_IMAGE not in args:
                complete("run-unpinned", 68)
            name = option("--name")
            command_text = " ".join(args)
            if name is None:
                if "busybox --list" in command_text:
                    complete("candidate-preflight")
                expected_address = os.environ.get("FAKE_EXPECT_HOST_PROBE_ADDRESS")
                if expected_address and f"http://{{expected_address}}:" not in command_text:
                    complete("health-host-wrong-bind", 24)
                status = int(os.environ.get("FAKE_HTTP_STATUS", "200"))
                if status < 200 or status >= 300:
                    complete("health-host-http-status", 22)
                if os.environ.get("FAKE_SENTINEL_MATCH", "1") != "1":
                    complete("health-host-sentinel", 23)
                complete("health-host")
            if name in containers:
                complete("run-name-collision", 1)
            labels = {{}}
            for index, value in enumerate(args[:-1]):
                if value == "--label":
                    label_key, _, label_value = args[index + 1].partition("=")
                    labels[label_key] = label_value
            main_name = os.environ.get("FAKE_MAIN_NAME", "amnezia-client-updates")
            host_name = os.environ.get("FAKE_HOST_NAME", main_name + "-host")
            if name == main_name:
                role = "new-main"
                phase = "run-main"
            elif name == host_name:
                role = "new-host"
                phase = "run-host"
            else:
                role = "new-sidecar"
                phase = "run-sidecar"
            next_id = int(state.get("next_id", 1000))
            state["next_id"] = next_id + 1
            container_id = f"container-id-{{next_id}}"
            volume = option("-v") or ""
            mount_source = volume.rsplit(":/www:ro", 1)[0] if volume.endswith(":/www:ro") else ""
            containers[name] = {{
                "id": container_id,
                "role": role,
                "running": True,
                "network": option("--network") or "",
                "ip": option("--ip") or "",
                "labels": labels,
                "image": PINNED_IMAGE,
                "mount_source": mount_source,
                "mount_rw": False,
            }}
            cidfile = option("--cidfile")
            if cidfile:
                Path(cidfile).write_text(container_id + "\\n", encoding="utf-8")
            save()
            if os.environ.get("FAKE_DOCKER_FAIL_ROLE") == labels.get(
                    "org.amnezia.client-update-host.role"
            ):
                complete("run-sidecar-target", 73)
            complete(phase)

        if args and args[0] == "exec":
            name, container = resolve(args[1])
            if container is None or not container["running"]:
                complete("health-missing", 1)
            role = container["role"]
            if role in ("main", "new-main"):
                phase = "health-main"
            elif role in ("host", "new-host"):
                phase = "health-host"
            else:
                phase = "health-sidecar"
            if role.startswith("new-"):
                expected_address = os.environ.get("FAKE_EXPECT_HOST_PROBE_ADDRESS")
                if phase == "health-host" and expected_address \
                        and f"http://{{expected_address}}:" not in " ".join(args):
                    complete("health-host-wrong-bind", 24)
                status = int(os.environ.get("FAKE_HTTP_STATUS", "200"))
                if status < 200 or status >= 300:
                    complete(phase + "-http-status", 22)
                if os.environ.get("FAKE_SENTINEL_MATCH", "1") != "1":
                    complete(phase + "-sentinel", 23)
            complete(phase)

        if args and args[0] == "rm":
            references = [value for value in args[1:] if not value.startswith("-")]
            phase = "rm"
            resolved = []
            for reference in references:
                name, container = resolve(reference)
                if container is not None:
                    role = container["role"]
                    if ".amnezia-backup." in name:
                        phase = "cleanup-backup-" + role
                    elif role.startswith("new-"):
                        phase = "rollback-remove-" + role
                    resolved.append(name)
            fail_before(phase)
            for name in resolved:
                del containers[name]
            save()
            complete(phase)

        complete("unhandled")
        '''
    )


def transactional_fake_firewall_source() -> str:
    return textwrap.dedent(
        '''\
        #!/usr/bin/env python3
        import json
        import os
        import sys
        from pathlib import Path

        backend = Path(sys.argv[0]).name
        args = sys.argv[1:]
        state_path = Path(os.environ["FAKE_FIREWALL_STATE"])
        log_path = Path(os.environ["FAKE_FIREWALL_LOG"])
        state = json.loads(state_path.read_text(encoding="utf-8"))

        def save() -> None:
            state_path.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")

        def finish(phase: str, code: int = 0) -> None:
            fail_phase = os.environ.get("FAKE_FIREWALL_FAIL_AFTER")
            with log_path.open("a", encoding="utf-8") as handle:
                handle.write(f"{phase}|fail={fail_phase or ''}|{' '.join(args)}\\n")
            marker = Path(os.environ.get("FAKE_FIREWALL_FAIL_MARKER", str(state_path) + ".failed"))
            if fail_phase == phase and not marker.exists():
                marker.touch()
                raise SystemExit(75)
            raise SystemExit(code)

        def value_after(name: str) -> str:
            try:
                return args[args.index(name) + 1]
            except (ValueError, IndexError):
                return ""

        if backend == "ufw":
            rules = state.setdefault("ufw", [])
            if args[:2] == ["show", "added"]:
                for rule in rules:
                    print(rule)
                finish("ufw-query")
            comment = value_after("comment")
            if "delete" in args:
                if comment in rules:
                    rules.remove(comment)
                save()
                finish("ufw-remove")
            if args and args[0] == "allow":
                if comment not in rules:
                    rules.append(comment)
                save()
                finish("ufw-add")
            finish("ufw-unhandled", 2)

        if backend == "firewall-cmd":
            if args == ["--state"]:
                if os.environ.get("FAKE_FIREWALLD_RUNNING", "1") == "1":
                    print("running")
                    finish("firewalld-state")
                print("not running")
                finish("firewalld-state", 1)
            permanent = "--permanent" in args
            key = "firewalld_permanent" if permanent else "firewalld_runtime"
            rules = state.setdefault(key, [])
            rich_arg = next((value for value in args if "rich-rule=" in value), "")
            rule = rich_arg.split("=", 1)[1] if "=" in rich_arg else ""
            if any(value.startswith("--query-rich-rule=") for value in args):
                finish(key + "-query", 0 if rule in rules else 1)
            if any(value.startswith("--add-rich-rule=") for value in args):
                if rule not in rules:
                    rules.append(rule)
                save()
                finish(key + "-add")
            if any(value.startswith("--remove-rich-rule=") for value in args):
                if rule in rules:
                    rules.remove(rule)
                save()
                finish(key + "-remove")
            finish(key + "-unhandled", 2)

        if backend == "iptables":
            rules = state.setdefault("iptables", [])
            comment = value_after("--comment")
            if "-C" in args:
                finish("iptables-query", 0 if comment in rules else 1)
            if "-I" in args:
                if comment not in rules:
                    rules.append(comment)
                save()
                finish("iptables-add")
            if "-D" in args:
                if comment in rules:
                    rules.remove(comment)
                save()
                finish("iptables-remove")
            finish("iptables-unhandled", 2)

        finish("unknown-firewall-backend", 2)
        '''
    )


def initial_transactional_docker_state(*, image_present: bool = True) -> dict[str, object]:
    return {
        "image_present": image_present,
        "poisoned_tag_present": True,
        "networks": {
            "amnezia-dns-net": {
                "id": "network-dns-id",
                "subnet": "172.29.172.0/24",
                "labels": {},
            }
        },
        "containers": {
            "amnezia-client-updates": {
                "id": "old-main-id",
                "role": "main",
                "running": True,
                "network": "amnezia-dns-net",
                "ip": "172.29.172.252",
            },
            "amnezia-client-updates-host": {
                "id": "old-host-id",
                "role": "host",
                "running": True,
                "network": "host",
                "ip": "",
            },
            "amnezia-client-updates-vpn-amnezia-awg": {
                "id": "old-awg-sidecar-id",
                "role": "sidecar-running",
                "running": True,
                "network": "container:amnezia-awg",
                "ip": "",
            },
            "amnezia-client-updates-vpn-retired": {
                "id": "retired-sidecar-id",
                "role": "sidecar-stopped",
                "running": False,
                "network": "container:retired-vpn",
                "ip": "",
            },
            "amnezia-awg": {
                "id": "vpn-awg-id",
                "role": "vpn",
                "running": True,
                "network": "bridge",
                "ip": "172.17.0.2",
            },
        },
    }


def prepare_transactional_installer_harness(root: Path, state: dict[str, object]) -> tuple[Path, Path, Path, dict[str, str]]:
    trust_anchor = root / "trust-anchor"
    trust_anchor.mkdir(mode=0o755)
    trust_anchor.chmod(0o755)
    host_dir = root / "updates"
    bin_dir = root / "bin"
    bin_dir.mkdir()
    installer = root / "install_server_update_host.sh"
    installer.write_text(update_host_installer_harness_source(trust_anchor), encoding="utf-8")
    installer.chmod(0o700)
    fake_docker = bin_dir / "docker"
    fake_docker.write_text(transactional_fake_docker_source(), encoding="utf-8")
    fake_docker.chmod(0o700)
    for firewall_binary in ("ufw", "firewall-cmd", "iptables"):
        fake_firewall = bin_dir / firewall_binary
        fake_firewall.write_text(transactional_fake_firewall_source(), encoding="utf-8")
        fake_firewall.chmod(0o700)
    state_path = root / "docker-state.json"
    state_path.write_text(json.dumps(state, sort_keys=True), encoding="utf-8")
    log_path = root / "docker.log"
    firewall_state_path = root / "firewall-state.json"
    firewall_state_path.write_text(
        json.dumps(
            {
                "ufw": [],
                "firewalld_runtime": [],
                "firewalld_permanent": [],
                "iptables": [],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    firewall_log_path = root / "firewall.log"
    env = os.environ.copy()
    env.update(
        {
            "PATH": str(bin_dir) + os.pathsep + env.get("PATH", ""),
            "FAKE_DOCKER_STATE": str(state_path),
            "FAKE_DOCKER_LOG": str(log_path),
            "FAKE_FIREWALL_STATE": str(firewall_state_path),
            "FAKE_FIREWALL_LOG": str(firewall_log_path),
            "AMNEZIA_UPDATE_VPN_CONTAINER": "amnezia-awg",
        }
    )
    return installer, host_dir, state_path, env


def write_bundled_publisher_stage(
    upload_prefix: Path,
    run_id: str,
    manifest_data: bytes,
    version: str,
    schema: int,
    generation: int,
    records: list[tuple[str, str, bytes]],
) -> tuple[Path, str, str]:
    stage = Path(str(upload_prefix) + run_id)
    stage.mkdir(mode=0o700)
    os.chmod(stage, 0o700)
    (stage / "manifest.json").write_bytes(manifest_data)
    candidate_sha = hashlib.sha256(manifest_data).hexdigest()
    lines = [
        "\t".join((
            "amnezia-bundled-publish-v1",
            candidate_sha,
            version,
            str(schema),
            str(generation),
            str(len(records)),
        ))
    ]
    for kind, relative_path, contents in records:
        path = stage.joinpath(*PurePosixPath(relative_path).parts)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(contents)
        lines.append("\t".join((kind, relative_path, hashlib.sha256(contents).hexdigest(), str(len(contents)))))
    metadata = ("\n".join(lines) + "\n").encode("utf-8")
    (stage / "publish.meta").write_bytes(metadata)
    return stage, candidate_sha, hashlib.sha256(metadata).hexdigest()


class ReleaseFreezeTests(unittest.TestCase):
    def test_plan_wait_freeze_and_advance_after_frozen(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "state.json"
            base_args = {
                "state_file": state_path,
                "upstream_repo": "amnezia-vpn/amnezia-client",
                "target_branch": "dev",
                "baseline_tag": "4.8.16.0",
            }

            self.assertFalse(release_freeze.is_newer("4.8.16.0", "4.8.16.0"))
            self.assertTrue(release_freeze.is_newer("4.8.17.0", "4.8.16.0"))

            wait_args = type("Args", (), {**base_args, "latest_tag": "4.8.16.0", "force_freeze_tag": ""})()
            freeze_args = type("Args", (), {**base_args, "latest_tag": "4.8.17.0", "force_freeze_tag": ""})()

            wait_state = release_freeze.read_state(state_path)
            self.assertFalse(wait_state["frozen"])
            self.assertEqual(planned_action(wait_args), "wait")
            self.assertEqual(planned_action(freeze_args), "freeze")

            record_args = type(
                "Args",
                (),
                {
                    **base_args,
                    "latest_tag": "4.8.17.0",
                    "action": "freeze",
                    "release_tag": "4.8.17.0",
                    "release_sha": "deadbeef",
                    "upstream_dev_sha": "cafebabe",
                },
            )()
            self.assertEqual(release_freeze.record(record_args), 0)
            frozen_state = release_freeze.read_state(state_path)
            self.assertTrue(frozen_state["frozen"])
            self.assertEqual(frozen_state["frozenTag"], "4.8.17.0")
            self.assertEqual(frozen_state["baselineTag"], "4.8.17.0")
            frozen_args = type("Args", (), {**base_args, "latest_tag": "4.8.17.0", "force_freeze_tag": ""})()
            next_release_args = type("Args", (), {**base_args, "latest_tag": "4.8.18.0", "force_freeze_tag": ""})()
            self.assertEqual(planned_action(frozen_args), "already-frozen")
            self.assertEqual(planned_action(next_release_args), "freeze")

    def test_plan_rejects_invalid_release_tags(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "state.json"
            base_args = {
                "state_file": state_path,
                "upstream_repo": "amnezia-vpn/amnezia-client",
                "target_branch": "dev",
                "baseline_tag": "4.8.16.0",
            }

            with self.assertRaises(SystemExit):
                planned_action(type("Args", (), {**base_args, "latest_tag": "dev", "force_freeze_tag": ""})())

            with self.assertRaises(SystemExit):
                planned_action(type("Args", (), {**base_args, "latest_tag": "4.8.16.0", "force_freeze_tag": "release"})())

    def test_plan_rejects_baseline_newer_than_latest_release(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "state.json"
            base_args = {
                "state_file": state_path,
                "upstream_repo": "amnezia-vpn/amnezia-client",
                "target_branch": "dev",
                "baseline_tag": "4.8.16.0",
                "latest_tag": "4.8.15.4",
            }
            args = type(
                "Args",
                (),
                {
                    **base_args,
                    "force_freeze_tag": "",
                },
            )()

            with self.assertRaises(SystemExit) as context:
                planned_action(args)
            self.assertIn("is newer than --latest-tag", str(context.exception))

            forced_args = type("Args", (), {**base_args, "force_freeze_tag": "4.8.16.0"})()
            self.assertEqual(planned_action(forced_args), "freeze")

    @unittest.skipUnless(find_git(), "git is required to exercise release freeze patch semantics")
    def test_patch_based_freeze_does_not_keep_post_release_upstream_commits(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            run_git(repo, "init", "-q")
            run_git(repo, "config", "user.name", "test")
            run_git(repo, "config", "user.email", "test@example.invalid")

            (repo / "app.txt").write_text("release-base\n", encoding="utf-8")
            run_git(repo, "add", ".")
            run_git(repo, "commit", "-q", "-m", "release base")
            run_git(repo, "tag", "4.8.17.0")

            run_git(repo, "checkout", "-q", "-b", "upstream/dev")
            (repo / "app.txt").write_text("post-release-upstream\n", encoding="utf-8")
            (repo / "post-release-only.txt").write_text("must not be retained\n", encoding="utf-8")
            run_git(repo, "add", ".")
            run_git(repo, "commit", "-q", "-m", "post release upstream dev")

            run_git(repo, "checkout", "-q", "-b", "dev")
            (repo / "fork-feature.txt").write_text("self-hosted updater\n", encoding="utf-8")
            run_git(repo, "add", ".")
            run_git(repo, "commit", "-q", "-m", "fork feature")

            patch_path = repo / "fork.patch"
            with patch_path.open("w", encoding="utf-8") as stream:
                run_git(repo, "diff", "--binary", "upstream/dev...HEAD", stdout=stream)

            run_git(repo, "checkout", "-q", "-B", "dev", "refs/tags/4.8.17.0")
            run_git(repo, "apply", "--index", "--3way", str(patch_path))
            run_git(repo, "commit", "-q", "-m", "apply fork patch to release")

            self.assertEqual((repo / "app.txt").read_text(encoding="utf-8"), "release-base\n")
            self.assertEqual((repo / "fork-feature.txt").read_text(encoding="utf-8"), "self-hosted updater\n")
            self.assertFalse((repo / "post-release-only.txt").exists())


class SourceContractTests(unittest.TestCase):
    @staticmethod
    def function_body(signature: str, source: str) -> str:
        start = source.find(signature)
        if start < 0:
            raise AssertionError(f"missing C++ function: {signature}")
        opening_brace = source.find("{", start)
        if opening_brace < 0:
            raise AssertionError(f"missing C++ function body: {signature}")
        depth = 0
        for offset in range(opening_brace, len(source)):
            character = source[offset]
            if character == "{":
                depth += 1
            elif character == "}":
                depth -= 1
                if depth == 0:
                    return source[opening_brace : offset + 1]
        raise AssertionError(f"unterminated C++ function: {signature}")

    def test_headless_base_url_is_private_http_or_https_with_port(self) -> None:
        self.assertEqual(
            make_manifest.validate_headless_base_url("http://172.29.172.252:17865/"),
            "http://172.29.172.252:17865",
        )
        self.assertEqual(
            make_manifest.validate_headless_base_url("https://172.29.172.252:443/"),
            "https://172.29.172.252:443",
        )
        for invalid_base_url in (
            "http://8.8.8.8:17865",
            "http://updates.example.invalid:17865",
            "https://updates.example.invalid:443",
            "https://updates.example.invalid",
            "https://updates.example.invalid:65536",
        ):
            with self.subTest(base_url=invalid_base_url):
                with self.assertRaises(SystemExit):
                    make_manifest.validate_headless_base_url(invalid_base_url)

    def test_manifest_url_validation_rejects_cidr_routes(self) -> None:
        self.assertEqual(make_manifest.validate_release_version("4.8.16.0"), "4.8.16.0")
        self.assertEqual(make_manifest.validate_release_version("4.8.16.0"), "4.8.16.0")
        for invalid_version in (
            " 4.8.16.0 ",
            "4.8.16",
            "4.8.16.0-beta",
            "release",
            "4.8.16.0\nnext",
        ):
            with self.assertRaises(SystemExit):
                make_manifest.validate_release_version(invalid_version)
            with self.assertRaises(SystemExit):
                make_manifest.validate_release_version(invalid_version)

        self.assertEqual(
            make_manifest.validate_base_url("http://172.29.172.252:17865/"),
            "http://172.29.172.252:17865",
        )
        self.assertEqual(
            make_manifest.validate_base_url("https://updates.example.invalid/1"),
            "https://updates.example.invalid/1",
        )
        for invalid_base_url in (
            "https://user:pass@updates.example.invalid",
            "https://updates.example.invalid/update?token=secret",
            "https://updates.example.invalid/update#manifest",
            "https://updates.example.invalid:65536",
            "https://bad_host.example.invalid",
        ):
            with self.assertRaises(SystemExit):
                make_manifest.validate_base_url(invalid_base_url)
        with self.assertRaises(SystemExit) as no_scheme:
            make_manifest.validate_base_url("10.8.1.0/1")
        self.assertIn("http(s) endpoint URL", str(no_scheme.exception))

        with self.assertRaises(SystemExit) as cidr_path:
            make_manifest.validate_base_url("http://10.8.1.0/1")
        self.assertIn("not a CIDR route", str(cidr_path.exception))

        with self.assertRaises(SystemExit) as relative_external:
            make_manifest.validate_external_url("ios", "/files/app.plist")
        self.assertIn("must be absolute", str(relative_external.exception))

        with self.assertRaises(SystemExit) as ios_http_external:
            make_manifest.validate_external_url(
                "ios",
                "itms-services://?action=download-manifest&url=http%3A%2F%2F172.29.172.252%3A17865%2Ffiles%2Fapp.plist",
            )
        self.assertIn("must use HTTPS", str(ios_http_external.exception))

        self.assertEqual(
            make_manifest.validate_external_url(
                "ios",
                "itms-services://?action=download-manifest&url=https%3A%2F%2Fupdates.example.invalid%2Ffiles%2Fapp.plist",
            ),
            "itms-services://?action=download-manifest&url=https%3A%2F%2Fupdates.example.invalid%2Ffiles%2Fapp.plist",
        )
        self.assertEqual(
            make_manifest.validate_external_url("ios", "itms-apps://apps.apple.com/app/id123456789"),
            "itms-apps://apps.apple.com/app/id123456789",
        )
        with self.assertRaises(SystemExit) as ios_itms_apps_without_host:
            make_manifest.validate_external_url("ios", "itms-apps:///app/id123456789")
        self.assertIn("must include a host", str(ios_itms_apps_without_host.exception))

        with self.assertRaises(SystemExit) as ios_itms_services_without_manifest_host:
            make_manifest.validate_external_url(
                "ios",
                "itms-services://?action=download-manifest&url=https%3A%2F%2F%2Ffiles%2Fapp.plist",
            )
        self.assertIn("must use HTTPS with a host", str(ios_itms_services_without_manifest_host.exception))

        with self.assertRaises(SystemExit) as ios_http_base:
            make_manifest.require_https_base_url_for_ios_ota("http://172.29.172.252:17865")
        self.assertIn("--ios-ipa requires --base-url to use HTTPS", str(ios_http_base.exception))

        with self.assertRaises(SystemExit) as android_file_external:
            make_manifest.validate_external_url("android", "file:///tmp/AmneziaVPN.apk")
        self.assertIn("must use HTTP or HTTPS", str(android_file_external.exception))
        self.assertEqual(
            make_manifest.validate_external_url("android", "https://updates.example.invalid/files/AmneziaVPN.apk"),
            "https://updates.example.invalid/files/AmneziaVPN.apk",
        )

    def test_manifest_rejects_external_headless_platform_alias(self) -> None:
        for alias in ("headless-x64", "linux-headless"):
            with self.subTest(alias=alias):
                with self.assertRaises(SystemExit):
                    make_manifest.validate_platform_vocabulary(alias, "--external")

    def test_headless_verifier_pins_key_uses_rawin_and_extracts_one_private_copy(self) -> None:
        verifier = (REPO_ROOT / "deploy/headless/verify_provisioning_bundle.py").read_text(encoding="utf-8")
        self.assertIn("validate_release_version", verifier)
        self.assertNotIn("is_canonical_release_version", verifier)
        self.assertIn('parser.add_argument("--expected-public-key-sha256", required=True)', verifier)
        self.assertIn('"-rawin"', verifier)
        self.assertIn("_copy_archive_to_private_temp", verifier)
        self.assertIn("_copy_regular_file_to_private_temp", verifier)
        self.assertIn('"manifest.json"', verifier)
        self.assertIn('"update-public-key.pem"', verifier)
        self.assertIn("exact_copy", verifier)
        self.assertIn("sha256(exact_copy)", verifier)
        self.assertIn("hashlib.sha256(manifest_data).hexdigest()", verifier)
        self.assertIn("private provisioning archive changed after verification", verifier)

    def test_headless_manifest_requires_provisioning_binding(self) -> None:
        helper = (REPO_ROOT / "deploy/headless/make_headless_manifest.py").read_text(encoding="utf-8")
        self.assertIn('parser.add_argument("--provisioning", type=Path, required=True', helper)
        self.assertIn('payload["headlessProvisioning"]', helper)
        self.assertIn("inspect_headless_provisioning", helper)

    def test_signed_headless_provisioning_metadata_is_shape_checked(self) -> None:
        metadata = {
            "url": "files/artifacts/" + "a" * 64 + "/bundle.tar.gz",
            "sha256": "b" * 64,
            "size": 123,
            "format": make_manifest.HEADLESS_PROVISIONING_FORMAT,
            "version": "9.9.9.9",
            "packageManifestSha256": "c" * 64,
            "checksumsSha256": "d" * 64,
            "packageVersion": "9.9.9.9",
            "packageFiles": list(make_manifest.HEADLESS_PROVISIONING_FILES),
        }
        self.assertEqual(metadata["format"], "amnezia-headless-provisioning-tar-v1")
        self.assertEqual(metadata["packageVersion"], metadata["version"])
        self.assertEqual(metadata["packageFiles"], list(make_manifest.HEADLESS_PROVISIONING_FILES))

    def test_headless_manifest_inner_receipt_is_signed_and_exact(self) -> None:
        manifest_tool = (REPO_ROOT / "deploy/selfhosted_updates/make_manifest.py").read_text(encoding="utf-8")
        bootstrapper = (REPO_ROOT / "client/core/controllers/selfhosted/selfHostedUpdateBootstrapper.cpp").read_text(encoding="utf-8")
        self.assertIn("inspect_headless_provisioning", manifest_tool)
        self.assertIn('"packageManifestSha256"', manifest_tool)
        self.assertIn('"checksumsSha256"', manifest_tool)
        self.assertIn('"packageFiles"', manifest_tool)
        self.assertIn("hasHeadlessPlatform != !provisioningValue.isUndefined()", bootstrapper)
        self.assertIn("provisioning.size() != 9", bootstrapper)
        self.assertIn("non-canonical Linux headless platform", bootstrapper)
        self.assertIn('QStringLiteral("amnezia-headless-tar-v1")', bootstrapper)

    def test_provisioning_verifier_is_verify_only_by_default(self) -> None:
        verifier = (REPO_ROOT / "deploy/headless/verify_provisioning_bundle.py").read_text(encoding="utf-8")
        self.assertIn('"--run-installer", action="store_true"', verifier)
        self.assertIn("if not args.run_installer:", verifier)
        self.assertIn("inspect_headless_provisioning", verifier)
        self.assertIn("extract_verified_bundle", verifier)
        self.assertNotIn("tar.extractall", verifier)
        self.assertIn("Python 3.10 safe", verifier)

    def test_provisioning_installer_requires_authenticated_regular_package(self) -> None:
        installer = (REPO_ROOT / "deploy/headless/install_headless.sh").read_text(encoding="utf-8")
        builder = (REPO_ROOT / "deploy/headless/build_headless_release.sh").read_text(encoding="utf-8")
        self.assertIn("VERIFIED_RECEIPT", installer)
        self.assertIn("receipt is not trusted", installer)
        self.assertIn("readelf -h", installer)
        self.assertIn("--version", installer)
        self.assertIn("GROUP_CREATED", installer)
        self.assertIn('"backendModes"', builder)
        self.assertIn('"groupdel"', builder)
        self.assertNotIn("id command;", installer)
        self.assertNotIn('"command"', builder)

    def test_provisioning_receipt_is_bound_to_signed_manifest_and_fresh_state_is_ambiguous(self) -> None:
        installer = (REPO_ROOT / "deploy/headless/install_headless.sh").read_text(encoding="utf-8")
        self.assertIn("EXPECTED_SIGNED_MANIFEST_SHA256", installer)
        self.assertIn('receipt["manifestSha256"] != expected_signed_manifest.lower()', installer)
        self.assertIn("/var/lib/amnezia /run/amnezia /etc/amnezia /etc/amnezia/profiles", installer)
        self.assertIn("preexisting-state installation already exists", installer)
        self.assertIn("systemctl disable amneziad.service", installer)
        self.assertIn('rmdir -- "$state_dir"', installer)
        self.assertIn('groupdel --system amnezia', installer)

    def test_headless_standalone_manifest_writes_through_private_staging(self) -> None:
        helper = (REPO_ROOT / "deploy/headless/make_headless_manifest.py").read_text(encoding="utf-8")
        self.assertIn("atomic_copy_file", helper)
        self.assertIn("atomic_write_bytes", helper)
        self.assertIn("replace_output_tree(out_dir, requested_out_dir)", helper)
        self.assertIn("fsync_directory", helper)
        self.assertIn("replace_output_tree(out_dir, requested_out_dir)", helper)

    def test_manifest_tool_rejects_duplicate_platforms(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = root / "first.exe"
            second = root / "second.exe"
            first.write_bytes(b"first")
            second.write_bytes(b"second")

            with self.assertRaises(SystemExit) as duplicate_artifact:
                make_manifest.parse_artifact([
                    f"windows-x64={first}",
                    f"windows-x64={second}",
                ])
            self.assertIn("duplicate artifact platform: windows-x64", str(duplicate_artifact.exception))

    def test_manifest_tool_rejects_duplicate_output_filenames(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first_dir = root / "first"
            second_dir = root / "second"
            first_dir.mkdir()
            second_dir.mkdir()
            first = first_dir / "AmneziaVPN.bin"
            second = second_dir / "AmneziaVPN.bin"
            first.write_bytes(b"first")
            second.write_bytes(b"second")

            old_argv = sys.argv
            sys.argv = [
                "make_manifest.py",
                "--version",
                "9.9.9.9",
                "--base-url",
                "https://updates.example.invalid",
                "--private-key",
                str(root / "missing.pem"),
                "--artifact",
                f"windows-x64={first}",
                "--artifact",
                f"linux-x64={second}",
                "--out-dir",
                str(root / "out"),
            ]
            try:
                with self.assertRaises(SystemExit) as duplicate_output:
                    make_manifest.main()
            finally:
                sys.argv = old_argv
            self.assertIn("duplicate artifact output filename", str(duplicate_output.exception))

    def test_android_apk_install_handoff_controls_auto_install_marker(self) -> None:
        activity = (REPO_ROOT / "client/android/src/org/amnezia/vpn/AmneziaActivity.kt").read_text(encoding="utf-8")
        android_controller_cpp = (REPO_ROOT / "client/platforms/android/android_controller.cpp").read_text(encoding="utf-8")
        android_controller_h = (REPO_ROOT / "client/platforms/android/android_controller.h").read_text(encoding="utf-8")
        update_controller = (REPO_ROOT / "client/core/controllers/updateController.cpp").read_text(encoding="utf-8")
        update_controller_h = (REPO_ROOT / "client/core/controllers/updateController.h").read_text(encoding="utf-8")
        update_policy = (REPO_ROOT / "client/core/utils/selfhostedUpdatePolicy.h").read_text(encoding="utf-8")
        signal_handlers = (REPO_ROOT / "client/core/controllers/coreSignalHandlers.cpp").read_text(encoding="utf-8")
        client_cmake = (REPO_ROOT / "client/CMakeLists.txt").read_text(encoding="utf-8")
        client_3rdparty_cmake = (REPO_ROOT / "client/cmake/3rdparty.cmake").read_text(encoding="utf-8")
        openssl_recipe = (REPO_ROOT / "recipes/openssl/conanfile.py").read_text(encoding="utf-8")

        qt_android_controller = (REPO_ROOT / "client/android/src/org/amnezia/vpn/qt/QtAndroidController.kt").read_text(encoding="utf-8")

        self.assertIn("private const val APK_INSTALL_FAILED = 0", activity)
        self.assertIn("private const val APK_INSTALL_STARTED = 1", activity)
        self.assertIn("private const val APK_INSTALL_PERMISSION_SETTINGS_OPENED = 2", activity)
        self.assertIn("fun installApk(fileName: String): Int", activity)
        self.assertIn("private fun startApkInstaller(fileName: String, openSettingsIfBlocked: Boolean): Int", activity)
        self.assertIn("pendingInstallApkPath?.let { outState.putString(KEY_PENDING_INSTALL_APK_PATH, it) }", activity)
        self.assertIn("pendingInstallApkPath == null || installApkDeliveryScheduled || !isActivityResumed", activity)
        self.assertIn("Prefs.load<String>(KEY_PENDING_INSTALL_APK_PATH)", activity)
        self.assertIn("persistPendingInstallApkPath(fileName)", activity)
        self.assertIn("if (!editor.commit())", activity)
        self.assertIn("apk_pending_state_persist_failed", activity)
        self.assertIn("startActivity(intent)", activity)
        self.assertIn("persistPendingInstallApkPath(null)", activity)
        self.assertIn("installApkDeliveryScheduled = false", activity)
        self.assertIn("schedulePendingApkInstallDelivery()", activity)
        self.assertIn("qtInitialized.await()", activity)
        self.assertIn('startApkInstaller(apkPath, openSettingsIfBlocked = false)', activity)
        self.assertIn('failApkInstaller(fileName, "apk_install_permission_missing")', activity)
        self.assertIn("Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES", activity)
        self.assertIn("return APK_INSTALL_PERMISSION_SETTINGS_OPENED", activity)
        self.assertIn("QtAndroidController.onApkInstallerStarted(fileName)", activity)
        self.assertIn("external fun onApkInstallerStarted(fileName: String)", qt_android_controller)
        self.assertIn("external fun authorizeApkInstallerLaunch(", qt_android_controller)
        self.assertIn("packageName: String", qt_android_controller)
        self.assertIn("versionName: String", qt_android_controller)
        self.assertIn("versionCode: Long", qt_android_controller)
        self.assertIn("int installApk(const QString &fileName);", android_controller_h)
        self.assertIn("void apkInstallerStarted(QString fileName);", android_controller_h)
        self.assertIn('callActivityMethod<jint>("installApk", "(Ljava/lang/String;)I"', android_controller_cpp)
        self.assertIn('(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;J)Z', android_controller_cpp)
        self.assertIn('{"onApkInstallerStarted", "(Ljava/lang/String;)V"', android_controller_cpp)
        self.assertIn("emit AndroidController::instance()->apkInstallerStarted", android_controller_cpp)
        self.assertIn("InstallerHandoffResult", update_controller_h)
        self.assertIn("apk_pending_state_persist_failed", update_controller)
        self.assertIn("m_androidApkInstallPermissionPending || !m_appSettingsRepository", update_controller)
        self.assertIn("kAndroidApkInstallPermissionWaitMs", update_controller)
        self.assertIn("kAndroidApkInstallPermissionSettingsOpened", update_controller)
        self.assertIn("InstallerHandoffResult::PendingPermission", update_controller)
        self.assertIn("void UpdateController::onAndroidApkInstallerStarted", update_controller)
        self.assertIn("inline bool isCanonicalSha256(const QString &value)", update_policy)
        self.assertIn("if (value.size() != 64)", update_policy)
        self.assertIn("if (!decimal && !lowerHex)", update_policy)
        self.assertIn("artifact.sha256 = normalizeSha256(", update_controller)
        self.assertIn("!isCanonicalSha256(artifact.sha256)", update_controller)
        self.assertIn("actualSha256 != normalizeSha256(m_selectedArtifact.sha256)", update_controller)
        self.assertIn("Self-hosted update artifact is missing or has invalid sha256", update_controller)
        self.assertIn("bool isHttpOrHttpsUrl(const QUrl &url)", update_controller)
        self.assertIn("Self-hosted update artifact URL must use http(s)", update_controller)
        self.assertIn("Self-hosted update artifact is missing or has invalid size", update_controller)
        self.assertIn("!artifact.openExternally && artifact.size <= 0", update_controller)
        self.assertIn("bool isAllowedExternalUpdateUrl(const QUrl &url)", update_controller)
        self.assertIn("#if defined(Q_OS_IOS)\n        if (scheme == QStringLiteral(\"http\")) {\n            return false;\n        }\n#endif", update_controller)
        self.assertIn("#include <QUrlQuery>", update_controller)
        self.assertIn("const QUrlQuery query(url);", update_controller)
        self.assertIn('query.queryItemValue(QStringLiteral("url"))', update_controller)
        self.assertIn('manifestUrl.scheme().toLower() == QStringLiteral("https")', update_controller)
        self.assertIn('if (scheme == QStringLiteral("itms-apps")) {\n            return !url.host().isEmpty();\n        }', update_controller)
        self.assertIn("#else\n        return false;\n#endif", update_controller)
        self.assertIn("bool decodeStrictBase64", update_controller)
        self.assertIn("Self-hosted external update URL has unsupported scheme", update_controller)
        self.assertIn("Update URL has unsupported external scheme", update_controller)
        self.assertIn("constexpr int kInstallerTransferTimeoutMs = 2 * 60 * 1000;", update_controller)
        self.assertIn("constexpr int kInstallerTotalDeadlineMs = 25 * 60 * 1000;", update_controller)
        self.assertIn(
            "constexpr int kRollbackIntentLeaseSeconds = kInstallerTotalDeadlineMs / 1000 + 60;",
            update_controller,
        )
        self.assertIn("totalDeadlineTimer->setInterval(kInstallerTotalDeadlineMs);", update_controller)
        self.assertIn("auto *file = new QSaveFile(installerPath);", update_controller)
        self.assertIn("file->setDirectWriteFallback(false);", update_controller)
        self.assertIn("&QIODevice::readyRead", update_controller)
        self.assertIn("hash->addData(chunk);", update_controller)
        self.assertIn("const int statusCode = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();", update_controller)
        self.assertIn("reply->error() != QNetworkReply::NoError || statusCode < 200 || statusCode >= 300", update_controller)
        self.assertIn("Self-hosted installer size differs from manifest", update_controller)
        self.assertIn("if (m_selectedArtifact.size >= 0 && *bytesWritten != m_selectedArtifact.size) {\n            logger.error()", update_controller)
        self.assertIn("if (!file->commit()) {", update_controller)
        self.assertNotIn("expectedSha256Matches", update_controller + update_controller_h)
        self.assertIn("startBackgroundUpdateChecks();", update_controller)
        self.assertIn("QTimer::singleShot(kInitialBackgroundUpdateCheckMs, this, &UpdateController::checkForUpdates);", update_controller)
        self.assertIn("m_backgroundUpdateTimer->setInterval(kBackgroundUpdateCheckIntervalMs);", update_controller)
        self.assertIn("QTimer* m_backgroundUpdateTimer", update_controller_h)
        self.assertIn("bool m_selfHostedInstallInProgress = false;", update_controller_h)
        self.assertIn("bool m_androidApkInstallPermissionPending = false;", update_controller_h)
        self.assertIn("void finishSelfHostedInstallerAttempt(InstallerHandoffResult result);", update_controller_h)
        self.assertIn("#include <QDate>", update_controller)
        self.assertIn("QString selfHostedAutoInstallAttemptMarker() const;", update_controller_h)
        self.assertIn("QString UpdateController::selfHostedAutoInstallAttemptMarker() const", update_controller)
        self.assertIn("QDate::currentDate().toString(Qt::ISODate)", update_controller)
        self.assertIn("const QString attemptMarker = selfHostedAutoInstallAttemptMarker();", update_controller)
        self.assertIn("selfHostedUpdateLastAutoInstallAttempt() != attemptMarker", update_controller)
        self.assertIn("m_pendingAutoInstallAttemptId = selfHostedAutoInstallAttemptMarker();", update_controller)
        self.assertIn("m_updateCheckRunning || m_selfHostedInstallInProgress || m_androidApkInstallPermissionPending || !m_appSettingsRepository", update_controller)
        self.assertIn("Self-hosted update installer handoff is already in progress", update_controller)
        self.assertIn("m_selfHostedInstallInProgress = true;", update_controller)
        self.assertIn("void UpdateController::finishSelfHostedInstallerAttempt(InstallerHandoffResult result)", update_controller)
        self.assertIn("m_selfHostedInstallInProgress = false;", update_controller)
        self.assertIn("isSelfHostedUpdateChannelConfigured()", update_controller)
        self.assertIn("if (isSelfHostedUpdateChannelConfigured())", update_controller)
        self.assertIn('add_definitions(-DSELFHOSTED_UPDATE_PUBLIC_KEY_PEM_BASE64="$ENV{SELFHOSTED_UPDATE_PUBLIC_KEY_PEM_BASE64}")', client_cmake)
        self.assertIn("SELFHOSTED_UPDATE_PUBLIC_KEY_PEM_BASE64", update_controller)
        self.assertIn("bool decodeStrictBase64(const QByteArray &encoded, QByteArray::Base64Options options, QByteArray &decoded)", update_controller)
        self.assertIn("QByteArray::fromBase64Encoding(\n                encoded, options | QByteArray::AbortOnBase64DecodingErrors)", update_controller)
        self.assertIn("signature.size() != 64", update_controller)
        self.assertIn("Self-hosted update manifest payload is too large", update_controller)
        self.assertIn("decodeStrictBase64(QByteArray(SELFHOSTED_UPDATE_PUBLIC_KEY_PEM_BASE64)", update_controller)
        self.assertNotIn("QByteArray::fromBase64(QByteArray(SELFHOSTED_UPDATE_PUBLIC_KEY_PEM_BASE64))", update_controller)
        self.assertIn("find_package(OpenSSL REQUIRED)", client_3rdparty_cmake)
        self.assertIn("OpenSSL::Crypto", client_3rdparty_cmake)
        self.assertIn('self.options.shared and self.settings.os == "Android"', openssl_recipe)
        self.assertIn('self.cpp_info.components["ssl"].libs = ["ssl_3"]', openssl_recipe)
        self.assertIn('self.cpp_info.components["crypto"].libs = ["crypto_3"]', openssl_recipe)
        self.assertIn("target_link_libraries(${PROJECT} PRIVATE ${LIBS})", client_cmake)
        self.assertIn('endpoint.contains(QStringLiteral("://"))', update_controller)
        self.assertIn('#include "core/utils/constants/configKeys.h"', update_controller)
        self.assertIn("serverJson.value(configKey::serverRoutingRulesSyncHost).toString()", update_controller)
        self.assertIn("QStringList serverCredentialHosts;", update_controller)
        self.assertLess(
            update_controller.index("serverCredentialHosts.append(credentials.hostName);"),
            update_controller.index("addHost(QString::fromLatin1(amnezia::protocols::selfHostedUpdates::syncHost));"),
        )
        self.assertLess(
            update_controller.index("addHost(QString::fromLatin1(amnezia::protocols::selfHostedUpdates::syncHost));"),
            update_controller.index("for (const QString &host : serverCredentialHosts)"),
        )
        vpn_connection = (REPO_ROOT / "client/vpnConnection.cpp").read_text(encoding="utf-8")
        self.assertIn("addHost(QString::fromLatin1(protocols::clientLogs::syncHost));", vpn_connection)
        self.assertIn("appsRouteMode == amnezia::AppsRouteMode::VpnOnlyForwardApps", vpn_connection)
        self.assertIn('appsJsonArray.append(QStringLiteral("org.amnezia.vpn"));', vpn_connection)
        self.assertIn("normalizedSelfHostedManifestUrl", update_controller)
        self.assertIn("url.setPath(path + manifestPath)", update_controller)
        self.assertIn("url.setPort(amnezia::protocols::selfHostedUpdates::syncPort);", update_controller)
        self.assertIn("url.setPath(normalizedPath);", update_controller)
        self.assertNotIn('return QStringLiteral("http://%1:%2%3")', update_controller)
        self.assertNotIn("if (manifestUrls.isEmpty()) {\n        fetchGatewayUrl();", update_controller)
        self.assertIn("if (manifestUrls.isEmpty()) {\n        finishUpdateCheck();", update_controller)
        self.assertIn("if (urlIndex < 0 || urlIndex >= manifestUrls.size()) {\n        finishUpdateCheck(QStringLiteral(\"self_hosted_update_endpoint_unreachable\"));", update_controller)
        self.assertIn("m_updateCheckTimeoutTimer->setInterval(30000);", update_controller)
        network_security_config = (REPO_ROOT / "client/android/res/xml/network_security_config.xml").read_text(encoding="utf-8")
        self.assertIn("@_amnezia_selfhosted_update_sync_host@", network_security_config)
        self.assertIn("@_amnezia_legacy_update_domains@", network_security_config)
        self.assertIn("scheduleDesktopQuitAfterInstallerStart();", update_controller)
        self.assertIn("amnApp->forceQuit();", update_controller)
        self.assertIn("kDesktopQuitAfterInstallerStartMs", update_controller)
        self.assertIn("runWindowsInstaller(installerPath, installerSha256, installerSize)", update_controller)
        self.assertIn("runMacInstaller(installerPath, installerSha256, installerSize)", update_controller)
        self.assertIn("runLinuxInstaller(installerPath, installerSha256, installerSize)", update_controller)
        self.assertIn("FILE_SHARE_READ", update_controller)
        self.assertIn("FILE_FLAG_OPEN_REPARSE_POINT", update_controller)
        self.assertIn("QStandardPaths::AppLocalDataLocation", update_controller)
        self.assertIn("D:P(A;OICI;FA;;;", update_controller)
        self.assertIn("windowsInstallerDirectoryIsPrivate(directoryHandle)", update_controller)
        self.assertIn("windowsDirectoryContainsOnlyInstaller(", update_controller)
        self.assertIn("finalWindowsPathForHandle(installerHandle)", update_controller)
        self.assertIn("finalWindowsPathForHandle(directoryHandle)", update_controller)
        self.assertIn("STARTUPINFOW startupInfo {}", update_controller)
        self.assertIn("startupInfo.cb = sizeof(startupInfo);", update_controller)
        self.assertIn("FILE_SHARE_READ,", update_controller)
        self.assertNotIn("FILE_SHARE_READ | FILE_SHARE_DELETE,", update_controller)
        self.assertIn("nullptr, nullptr, FALSE,", update_controller)
        self.assertIn("resolvedInstallerPath.utf16()", update_controller)
        update_controller = (
            REPO_ROOT / "client/core/controllers/updateController.cpp"
        ).read_text(encoding="utf-8")
        launch_body = self.function_body(
            "int UpdateController::runWindowsInstaller(", update_controller
        )
        self.assertIn(
            "GENERIC_READ,\n            FILE_SHARE_READ,\n            nullptr,\n            OPEN_EXISTING",
            launch_body,
        )
        self.assertIn(
            "FILE_LIST_DIRECTORY | READ_CONTROL,\n            FILE_SHARE_READ,\n            nullptr,\n            OPEN_EXISTING",
            launch_body,
        )
        self.assertLess(
            launch_body.rfind("reverifyWindowsInstallerHandle("),
            launch_body.find("CreateProcessW("),
        )
        self.assertGreater(
            launch_body.rfind("CloseHandle(installerHandle)"),
            launch_body.find("CreateProcessW("),
        )
        self.assertIn("SetHandleInformation(directoryHandle, HANDLE_FLAG_INHERIT, 0)", launch_body)
        self.assertLess(
            launch_body.find("SetHandleInformation(directoryHandle, HANDLE_FLAG_INHERIT, 0)"),
            launch_body.find("CreateProcessW("),
        )
        self.assertGreater(
            launch_body.rfind("CloseHandle(directoryHandle)"),
            launch_body.find("CreateProcessW("),
        )
        self.assertGreater(
            launch_body.find("finalWindowsPathForHandle(directoryHandle)"),
            launch_body.find("CreateFileW("),
        )
        self.assertLess(
            launch_body.find("finalWindowsPathForHandle(directoryHandle)"),
            launch_body.find("windowsDirectoryContainsOnlyInstaller("),
        )
        self.assertNotIn("PROC_THREAD_ATTRIBUTE_HANDLE_LIST", update_controller)
        self.assertNotIn("startupInfo.lpAttributeList", update_controller)
        self.assertNotIn("EXTENDED_STARTUPINFO_PRESENT", update_controller)
        self.assertIn("::fexecve(installerFd, arguments, environ);", update_controller)
        self.assertIn("SYS_memfd_create", update_controller)
        self.assertIn("MFD_ALLOW_SEALING", update_controller)
        self.assertIn("F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL", update_controller)
        self.assertIn("::fcntl(installerFd, F_GET_SEALS) != requiredSeals", update_controller)
        self.assertLess(
            update_controller.index("::fcntl(installerFd, F_GET_SEALS) != requiredSeals"),
            update_controller.index("QCryptographicHash hash(QCryptographicHash::Sha256);", update_controller.index("SYS_memfd_create")),
        )
        self.assertLess(
            update_controller.index("QCryptographicHash hash(QCryptographicHash::Sha256);", update_controller.index("SYS_memfd_create")),
            update_controller.index("::fexecve(installerFd, arguments, environ);"),
        )
        self.assertIn("ClientScriptType::mac_installer", update_controller)
        self.assertIn("QProcessEnvironment cleanEnvironment;", update_controller)
        self.assertIn("process.setProcessEnvironment(cleanEnvironment);", update_controller)
        self.assertIn('QStringLiteral("--noprofile")', update_controller)
        self.assertIn('QStringLiteral("--norc")', update_controller)
        self.assertNotIn("QProcessEnvironment::systemEnvironment()", update_controller)
        mac_installer = (REPO_ROOT / "client/client_scripts/mac_installer.sh").read_text(encoding="utf-8")
        self.assertIn('/usr/bin/install -o root -g wheel -m 0600 "$source_path" "$root_pkg"', mac_installer)
        self.assertIn('/usr/sbin/pkgutil --check-signature "$root_pkg"', mac_installer)
        self.assertIn('/usr/sbin/spctl --assess --type install "$root_pkg"', mac_installer)
        self.assertIn('/usr/sbin/installer -pkg "$root_pkg" -target /', mac_installer)
        self.assertNotIn("|| true", mac_installer)
        confirmation_start = update_controller.index(
            'if (rollbackState == QStringLiteral("confirmation_pending")) {'
        )
        confirmation_end = update_controller.index(
            'if (rollbackState == QStringLiteral("leased")) {', confirmation_start
        )
        confirmation_branch = update_controller[confirmation_start:confirmation_end]
        self.assertIn(
            'if (!rollbackVersion.isEmpty() && runningVersion == rollbackVersion)',
            confirmation_branch,
        )
        self.assertIn('QStringLiteral("rollback_readiness_timeout")', confirmation_branch)
        self.assertIn('QStringLiteral("rollback_version_not_observed")', confirmation_branch)
        self.assertIn('QStringLiteral("rollbackConfirmationFailureCount")', confirmation_branch)
        self.assertIn('QStringLiteral("automaticRollbackTerminalAt")', confirmation_branch)
        self.assertIn(
            'receipt.take(QStringLiteral("rollbackSourceInstallerStartedAt"))',
            confirmation_branch,
        )
        self.assertIn(
            "setSelfHostedUpdatePendingHealthReceipt(receipt)", confirmation_branch
        )
        self.assertIn(
            'restoredReceipt.value(QStringLiteral("rollbackSha256"))', confirmation_branch
        )
        self.assertIn("struct RollbackAttemptContext", update_controller_h)
        self.assertIn("QString receiptId;", update_controller_h)
        self.assertIn("QString leaseId;", update_controller_h)
        self.assertIn(
            "recordRollbackHandoffFailure(const RollbackAttemptContext &expectedAttempt,",
            update_controller_h,
        )
        self.assertIn('QStringLiteral("rollbackHandoffLeaseId")', update_controller)
        self.assertIn('!= expectedAttempt.receiptId', update_controller)
        self.assertIn('!= expectedAttempt.intentId', update_controller)
        self.assertIn('!= expectedAttempt.leaseId', update_controller)
        self.assertIn("Ignoring stale rollback failure callback for a superseded lease", update_controller)
        android_validator_start = update_controller.index(
            "bool UpdateController::isAndroidApkInstallerAuthorizationValid("
        )
        android_validator_end = update_controller.index(
            "bool UpdateController::verifiedAndroidApkMatchesAuthorization(",
            android_validator_start,
        )
        android_validator = update_controller[android_validator_start:android_validator_end]
        self.assertIn("isCanonicalAndroidInstallerStagingPath(", android_validator)
        self.assertNotIn("localInstallerPath()", android_validator)
        self.assertIn("normalizedPrivateInstallerStagingPath(", update_controller)
        self.assertIn("bool requireLivePath = false", update_controller)
        self.assertIn("m_localInstallerPath = persistedLocalPath;", update_controller)
        self.assertIn("verifiedAndroidApkMatchesAuthorization(persistedLocalPath, authorization)", update_controller)
        self.assertIn("ConnectionController::connectionStateChanged", signal_handlers)
        self.assertIn("state != Vpn::ConnectionState::Connected", signal_handlers)
        self.assertIn("QTimer::singleShot(5000, m_coreController->m_updateController, &UpdateController::checkForUpdates);", signal_handlers)

    def test_automatic_rollback_pre_handoff_failures_retry_with_backoff(self) -> None:
        update_controller = (
            REPO_ROOT / "client/core/controllers/updateController.cpp"
        ).read_text(encoding="utf-8")

        self.assertIn(
            "constexpr int kMaximumAutomaticRollbackPreHandoffFailures = 3;",
            update_controller,
        )
        self.assertIn(
            "constexpr int kAutomaticRollbackInitialRetrySeconds = 15;",
            update_controller,
        )
        self.assertIn(
            'QStringLiteral("automaticRollbackPreHandoffFailureCount")',
            update_controller,
        )
        self.assertIn(
            'QStringLiteral("automaticRollbackNextAttemptAt")', update_controller
        )

        failure_start = update_controller.index(
            "void UpdateController::recordRollbackHandoffFailure("
        )
        failure_end = update_controller.index(
            "bool UpdateController::prepareSelfHostedInstallerHandoff()",
            failure_start,
        )
        failure_body = update_controller[failure_start:failure_end]
        self.assertIn(
            'const bool automaticPreHandoff = origin == QStringLiteral("automatic");',
            failure_body,
        )
        self.assertIn("previousPreHandoffFailures + 1", failure_body)
        self.assertIn(
            "preHandoffFailures < kMaximumAutomaticRollbackPreHandoffFailures",
            failure_body,
        )
        self.assertIn("!permanentValidationFailure", failure_body)
        self.assertIn("automaticRollbackRetryDelaySeconds(preHandoffFailures)", failure_body)
        self.assertIn("scheduleAutomaticRollbackRetry(persistedReceipt)", failure_body)
        self.assertLess(
            failure_body.index("Ignoring stale rollback failure callback"),
            failure_body.index("previousPreHandoffFailures + 1"),
        )
        self.assertIn(
            'receipt.value(QStringLiteral("receiptId")).toString()\n                != expectedAttempt.receiptId',
            failure_body,
        )
        self.assertIn(
            'receipt.value(QStringLiteral("rollbackIntentId")).toString()\n                != expectedAttempt.intentId',
            failure_body,
        )
        self.assertIn("activeLeaseId != expectedAttempt.leaseId", failure_body)

        retry_start = update_controller.index(
            "bool UpdateController::scheduleAutomaticRollbackRetry("
        )
        retry_end = update_controller.index(
            "bool UpdateController::scheduleAutomaticRollbackIfEligible()",
            retry_start,
        )
        retry_body = update_controller[retry_start:retry_end]
        self.assertIn(
            "[this, receiptId, failureCount, expectedRetryAt]()", retry_body
        )
        self.assertIn(
            'current.value(QStringLiteral("receiptId")).toString() != receiptId',
            retry_body,
        )
        self.assertIn(
            '!current.value(QStringLiteral("rollbackState")).toString().isEmpty()',
            retry_body,
        )
        self.assertIn("scheduleAutomaticRollbackIfEligible();", retry_body)

        download_start = update_controller.index(
            "bool UpdateController::startArtifactDownload()"
        )
        download_end = update_controller.index(
            "UpdateController::InstallerHandoffResult "
            "UpdateController::launchDownloadedArtifact",
            download_start,
        )
        download_body = update_controller[download_start:download_end]
        for marker in (
            "Self-hosted installer download failed:",
            "Self-hosted installer sha256 verification failed",
            "Failed to atomically commit verified self-hosted installer:",
        ):
            marker_index = download_body.index(marker)
            self.assertIn(
                "finishSelfHostedInstallerAttempt(InstallerHandoffResult::Failed);",
                download_body[marker_index : marker_index + 800],
                marker,
            )

        run_start = update_controller.index(
            "bool UpdateController::runPendingRollbackWithIntent("
        )
        run_end = update_controller.index(
            "bool UpdateController::checkForUpdates()", run_start
        )
        run_body = update_controller[run_start:run_end]
        self.assertIn("const bool exactLeaseOwned", run_body)
        self.assertIn('QStringLiteral("rollbackLeaseExpiresAt")', run_body)
        self.assertIn("refreshPendingUpdateHealth();", run_body)
        self.assertIn(
            "recordRollbackHandoffFailure(expectedAttempt, true);", run_body
        )
        self.assertLess(
            run_body.index('QStringLiteral("rollbackLeaseExpiresAt")'),
            run_body.index("m_selectedArtifact = rollbackArtifact;"),
        )

    @unittest.skipUnless(find_bash(), "bash is required for the hostile updater environment probe")
    def test_macos_updater_helper_does_not_inherit_bash_env(self) -> None:
        bash = find_bash()
        assert bash is not None
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            marker = root / "sourced.txt"
            bash_env = root / "hostile-env.sh"
            bash_env.write_text(
                'printf compromised > "$AMNEZIA_ENV_MARKER"\n', encoding="utf-8"
            )
            if os.name == "nt":
                def shell_path(path: Path) -> str:
                    converted = subprocess.run(
                        [bash, "--noprofile", "--norc", "-c", 'cygpath -u "$1"',
                         "amnezia-path", str(path)],
                        check=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                    return converted.stdout.strip()
            else:
                def shell_path(path: Path) -> str:
                    return str(path)

            hostile_environment = os.environ.copy()
            hostile_environment["BASH_ENV"] = shell_path(bash_env)
            hostile_environment["AMNEZIA_ENV_MARKER"] = shell_path(marker)
            subprocess.run(
                [bash, "-c", "true"],
                check=True,
                env=hostile_environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertTrue(marker.is_file(), "probe must demonstrate inherited BASH_ENV")
            marker.unlink()

            clean_environment = {
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                "LANG": "C",
            }
            subprocess.run(
                [bash, "--noprofile", "--norc", "-c", "true"],
                check=True,
                env=clean_environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertFalse(marker.exists())

    @unittest.skipUnless(
        sys.platform.startswith("linux") or find_wsl(),
        "Linux or WSL is required for the sealed memfd mutation probe",
    )
    def test_linux_sealed_memfd_rejects_post_verification_mutation(self) -> None:
        probe = textwrap.dedent(
            """
            import errno
            import fcntl
            import os

            required = 1 | 2 | 4 | 8
            fd = os.memfd_create("amnezia-seal-test", os.MFD_ALLOW_SEALING)
            os.write(fd, b"verified-installer")
            fcntl.fcntl(fd, 1033, required)
            assert fcntl.fcntl(fd, 1034) == required
            try:
                os.pwrite(fd, b"X", 0)
            except OSError as error:
                assert error.errno in (errno.EPERM, errno.EACCES)
            else:
                raise AssertionError("sealed memfd accepted a write")
            try:
                os.ftruncate(fd, 0)
            except OSError as error:
                assert error.errno in (errno.EPERM, errno.EACCES)
            else:
                raise AssertionError("sealed memfd accepted truncate")
            print("sealed-memfd-ok")
            """
        )
        command = (
            [find_wsl(), "python3", "-c", probe]
            if os.name == "nt"
            else [sys.executable, "-c", probe]
        )
        result = subprocess.run(
            command,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertIn("sealed-memfd-ok", result.stdout)

    def test_guardian_uses_a_dedicated_fail_closed_no_proxy_manager(self) -> None:
        core_header = (
            REPO_ROOT / "client/core/controllers/coreController.h"
        ).read_text(encoding="utf-8")
        core_controller = (
            REPO_ROOT / "client/core/controllers/coreController.cpp"
        ).read_text(encoding="utf-8")

        schedule_start = core_controller.index(
            "void CoreController::scheduleGuardianConnectivityProbe("
        )
        schedule_end = core_controller.index(
            "void CoreController::handleGuardianRecoveryRequest(", schedule_start
        )
        schedule_probe = core_controller[schedule_start:schedule_end]

        self.assertIn(
            "QNetworkAccessManager* m_guardianNetworkManager = nullptr;",
            core_header,
        )
        self.assertEqual(
            core_controller.count(
                "m_guardianNetworkManager = new QNetworkAccessManager(this);"
            ),
            1,
        )
        self.assertEqual(
            core_controller.count(
                "m_guardianNetworkManager->setProxy(QNetworkProxy::NoProxy);"
            ),
            1,
        )
        self.assertNotIn(
            "m_guardianNetworkManager->setProxyFactory", core_controller
        )
        self.assertNotIn("amnApp->networkManager()", schedule_probe)
        self.assertNotIn("guardianNetworkPathHasNoProxy", core_controller)

        factory_gate = schedule_probe.index(
            "m_guardianNetworkManager->proxyFactory() != nullptr"
        )
        no_proxy_gate = schedule_probe.index(
            "m_guardianNetworkManager->proxy().type()"
        )
        request = schedule_probe.index(
            "m_connectionHealthController->startConnectivityProbe("
        )
        self.assertLess(factory_gate, request)
        self.assertLess(no_proxy_gate, request)
        self.assertIn(
            "startConnectivityProbe(\n"
            "                            m_guardianNetworkManager,",
            schedule_probe,
        )

    def test_always_on_remote_logs_contract(self) -> None:
        remote_log_uploader = (REPO_ROOT / "client/core/controllers/remoteLogUploader.cpp").read_text(encoding="utf-8")
        android_service = (REPO_ROOT / "client/android/src/org/amnezia/vpn/AmneziaVpnService.kt").read_text(encoding="utf-8")
        android_log = (REPO_ROOT / "client/android/utils/src/main/kotlin/Log.kt").read_text(encoding="utf-8")
        android_prefs = (REPO_ROOT / "client/android/utils/src/main/kotlin/Prefs.kt").read_text(encoding="utf-8")
        android_activity = (REPO_ROOT / "client/android/src/org/amnezia/vpn/AmneziaActivity.kt").read_text(encoding="utf-8")
        ios_packet_tunnel = (REPO_ROOT / "client/platforms/ios/PacketTunnelProvider.swift").read_text(encoding="utf-8")
        ios_openvpn = (REPO_ROOT / "client/platforms/ios/PacketTunnelProvider+OpenVPN.swift").read_text(encoding="utf-8")
        ios_controller = (REPO_ROOT / "client/platforms/ios/ios_controller.mm").read_text(encoding="utf-8")
        import_controller = (REPO_ROOT / "client/core/controllers/selfhosted/importController.cpp").read_text(encoding="utf-8")
        export_controller = (REPO_ROOT / "client/core/controllers/selfhosted/exportController.cpp").read_text(encoding="utf-8")
        export_ui_controller = (REPO_ROOT / "client/ui/controllers/selfhosted/exportUiController.cpp").read_text(encoding="utf-8")
        export_ui_controller_h = (REPO_ROOT / "client/ui/controllers/selfhosted/exportUiController.h").read_text(encoding="utf-8")
        page_share = (REPO_ROOT / "client/ui/qml/Pages2/PageShare.qml").read_text(encoding="utf-8")
        users_controller = (REPO_ROOT / "client/core/controllers/selfhosted/usersController.cpp").read_text(encoding="utf-8")
        logger_cpp = (REPO_ROOT / "common/logger/logger.cpp").read_text(encoding="utf-8")
        core_controller = (REPO_ROOT / "client/core/controllers/coreController.cpp").read_text(encoding="utf-8")
        connection_controller = (REPO_ROOT / "client/core/controllers/connectionController.cpp").read_text(encoding="utf-8")
        client_logs_utils = (REPO_ROOT / "client/core/utils/selfhosted/clientLogsUtils.cpp").read_text(encoding="utf-8")
        protocol = (REPO_ROOT / "client/core/utils/constants/protocolConstants.h").read_text(encoding="utf-8")
        system_service = (REPO_ROOT / "service/server/systemservice.cpp").read_text(encoding="utf-8")
        ipc_server = (REPO_ROOT / "ipc/ipcserver.cpp").read_text(encoding="utf-8")
        secure_qsettings = (REPO_ROOT / "client/secureQSettings.cpp").read_text(encoding="utf-8")

        self.assertIn("m_appSettingsRepository->setSaveLogs(true);", core_controller)
        self.assertIn("Logger::setServiceLogsEnabled(true);", core_controller)
        self.assertIn("#ifdef Q_OS_ANDROID\n    return;\n#endif\n\n    m_remoteLogUploader", core_controller)
        self.assertIn("Logger::init(true);", system_service)
        self.assertIn("#if defined(Q_OS_IOS) || defined(MACOS_NE)\n    #include <AmneziaVPN-Swift.h>\n#endif", core_controller)
        self.assertIn("#if defined(Q_OS_IOS) || defined(MACOS_NE)\n    AmneziaVPN::toggleLogging(true);\n#endif", core_controller)
        self.assertIn("#if defined(Q_OS_IOS) || defined(MACOS_NE)", logger_cpp)

        self.assertIn("url.host() == QString::fromLatin1(amnezia::protocols::clientLogs::syncHost)", remote_log_uploader)
        self.assertIn("url.port() == amnezia::protocols::clientLogs::syncPort", remote_log_uploader)
        self.assertIn("url.path() == QString::fromLatin1(amnezia::protocols::clientLogs::uploadPath)", remote_log_uploader)
        self.assertIn("requestBoundedQueuedSnapshot(", remote_log_uploader)
        self.assertIn("m_vpnConnection, this, vpnSnapshotTimeoutMs", remote_log_uploader)
        self.assertIn("[](VpnConnection *vpnConnection)", remote_log_uploader)
        self.assertIn("snapshot.state = vpnConnection->connectionState();", remote_log_uploader)
        self.assertIn("snapshot.serverId = vpnConnection->serverId();", remote_log_uploader)
        self.assertIn("snapshot.container = vpnConnection->container();", remote_log_uploader)
        self.assertNotIn("QMetaObject::invokeMethod(m_vpnConnection", remote_log_uploader)
        self.assertNotIn("Qt::BlockingQueuedConnection", remote_log_uploader)
        self.assertNotIn("m_vpnConnection->connectionState()", remote_log_uploader)
        self.assertNotIn("vpnConnection->serverIndex()", remote_log_uploader)
        self.assertNotIn("m_vpnConnection->container()", remote_log_uploader)
        self.assertIn("snapshot.state != Vpn::ConnectionState::Connected", remote_log_uploader)
        self.assertIn("m_serversRepository->indexOfServerId(serverId)", remote_log_uploader)
        self.assertNotIn("m_serversRepository->defaultServerId()", remote_log_uploader)
        self.assertIn("serverJson.value(amnezia::configKey::clientLogs).toObject()", remote_log_uploader)
        self.assertIn("clientLogsUtils::legacyBootstrapTarget", remote_log_uploader)
        self.assertIn("bootstrapCurrentTarget()", remote_log_uploader)
        self.assertIn("setRemoteLogToken(target.tokenCacheKey, token)", remote_log_uploader)
        self.assertIn("clearRemoteLogToken(m_currentTarget.tokenCacheKey)", remote_log_uploader)
        self.assertIn("request.setTransferTimeout(uploadTimeoutMs);", remote_log_uploader)
        arm_transition = remote_log_uploader.index(
            "armRetrySanitizerStableSource(\n                        payload, nextCursor)"
        )
        persist_cursor = remote_log_uploader.index(
            "persistCursor(payload.offsetKey, nextCursor)", arm_transition
        )
        publish_cursor = remote_log_uploader.index(
            "m_logCursors.insert(payload.offsetKey, nextCursor)", persist_cursor
        )
        self.assertLess(arm_transition, persist_cursor)
        self.assertLess(persist_cursor, publish_cursor)
        self.assertIn("fileFingerprint(file, fingerprintBytes)", remote_log_uploader)
        self.assertIn("cursor.fingerprintBytes", remote_log_uploader)
        self.assertIn("QString fileFingerprint(QFile &file, qint64 sampleBytes)", remote_log_uploader)
        self.assertIn("fileAnchor(file, offset) == cursor.anchor", remote_log_uploader)
        self.assertIn('request.setRawHeader("X-Amnezia-Batch-Id", batchIdForPayload(payload).toLatin1());', remote_log_uploader)
        self.assertIn("maxBootstrapResponseBytes = 4096", remote_log_uploader)
        self.assertIn("m_nextTokenRefreshAt = QDateTime::currentDateTimeUtc().addMSecs(uploadIntervalMs);", remote_log_uploader)
        self.assertIn("Logger::userLogsFilePath(), &clientSourceReadable", remote_log_uploader)
        self.assertIn("Logger::serviceLogsFilePath(), &serviceSourceReadable", remote_log_uploader)
        self.assertIn("sameTarget(findUploadTarget(m_currentConnectionSnapshot), m_currentTarget)", remote_log_uploader)
        self.assertIn("targetIdentity(m_currentTarget).left(12)", remote_log_uploader)
        self.assertIn("errorCategoryName(category)", remote_log_uploader)
        self.assertNotIn("reply->errorString()", remote_log_uploader)
        self.assertNotIn("<< m_currentTarget.serverId", remote_log_uploader)
        self.assertNotIn("<< m_currentTarget.endpoint", remote_log_uploader)
        self.assertNotIn("m_lastPayloadHashes", remote_log_uploader)
        self.assertIn("vpnConfiguration[configKey::clientLogs] = clientLogs;", connection_controller)
        self.assertIn("clientLogsUtils::legacyBootstrapTarget(container, containerConfig)", connection_controller)

        self.assertIn('private const val CLIENT_LOGS_TRUSTED_ENDPOINT = "http://172.29.172.251:17866/logs"', android_service)
        self.assertIn('private const val CLIENT_LOGS_BOOTSTRAP_ENDPOINT = "http://172.29.172.251:17866/bootstrap"', android_service)
        self.assertIn(
            "if (endpoint != CLIENT_LOGS_TRUSTED_ENDPOINT || !SHA256_HEX_PATTERN.matches(clientId) ||\n"
            "            (!bootstrap && !isValidRemoteLogToken(token))",
            android_service,
        )
        self.assertIn("bootstrapRemoteLogTarget(attempt)", android_service)
        self.assertIn("val tokenCacheKey = remoteLogTokenPrefsKey(config?.optString(\"hostName\").orEmpty(), clientId)", android_service)
        self.assertIn("Prefs.loadSecureString(tokenCacheKey)", android_service)
        self.assertIn("Prefs.saveSecureString(target.tokenCacheKey, token)", android_service)
        self.assertIn("Prefs.saveSecureString(target.tokenCacheKey, \"\")", android_service)
        self.assertIn(
            "DISCONNECTED -> {\n"
            "                        if (this@AmneziaVpnService.protocolState.value != DISCONNECTED) return@collect\n"
            "                        networkState.unbindNetworkListener()\n"
            "                        stopRemoteLogUploader()",
            android_service,
        )
        self.assertIn(
            "CONNECTED -> {\n"
            "                        if (this@AmneziaVpnService.protocolState.value != CONNECTED) return@collect\n"
            "                        networkState.bindNetworkListener()\n"
            "                        configureRemoteLogUploader(activeVpnConfig)",
            android_service,
        )
        self.assertIn("configureRemoteLogUploader(activeVpnConfig)", android_service)
        self.assertIn("private fun stopRemoteLogUploader()", android_service)
        self.assertIn(
            "if (remoteLogPausedGeneration == generation || protocolState.value != CONNECTED)",
            android_service,
        )
        self.assertIn("Log.getAppLogs(CLIENT_LOGS_MAX_PAYLOAD_BYTES)", android_service)
        self.assertIn("private data class RemoteLogCursor(", android_service)
        self.assertIn("if (!saveRemoteLogCursorForAttempt(attempt, payload.cursorBeforeUpload))", android_service)
        self.assertIn("if (!saveRemoteLogCursorForAttempt(attempt, payload.cursorAfterUpload))", android_service)
        self.assertIn("logBytes.copyOfRange(offset, batchEndOffset)", android_service)
        self.assertNotIn("lastRemoteLogUploadHash", android_service)
        self.assertIn("val initialAttempt = currentRemoteLogAttempt()", android_service)
        self.assertIn("var attempt = initialAttempt", android_service)
        self.assertIn(
            "private fun uploadRemoteLogsOnce(\n"
            "        allowTokenRefreshRetry: Boolean = true,",
            android_service,
        )
        self.assertIn("allowTokenRefreshRetry = false", android_service)
        self.assertIn("requiredInitialAttempt = retryAttempt", android_service)
        self.assertIn("CLIENT_LOGS_MAX_BOOTSTRAP_RESPONSE_BYTES = 4096", android_service)
        self.assertIn("private fun readLimitedUtf8(stream: InputStream, maxBytes: Int): String?", android_service)
        self.assertIn('setRequestProperty("X-Amnezia-Installation-Id", remoteLogInstallationId())', android_service)
        self.assertIn('setRequestProperty("X-Amnezia-Log-Kind", CLIENT_LOGS_KIND_ANDROID)', android_service)
        self.assertIn('setRequestProperty("X-Amnezia-Batch-Id", payload.batchId)', android_service)
        self.assertIn("val initialized: Boolean = false", android_service)
        self.assertIn("freshRemoteLogRecoveryCursor", android_service)
        self.assertIn("if (storedCursor.initialized)", android_service)
        self.assertIn("retryingPendingPayload && !pendingSecretSetChanged", android_service)
        self.assertIn("val payloadSecrets = remoteLogSanitizerSecretsForAttempt(", android_service)
        self.assertIn("inheritedSecrets = sanitizerExplicitSecrets", android_service)
        self.assertIn("explicitSecrets = payloadSecrets", android_service)
        self.assertIn(
            "inheritedSecrets?.values.orEmpty() + listOf(currentToken, installationId, originNonce)",
            android_service,
        )
        self.assertIn("remoteLogExplicitSecretsSha256(mergedRetrySecrets)", android_service)
        self.assertIn("retryAuthorization = target.bootstrap", android_service)
        self.assertIn("retryAuthorization = true", android_service)
        self.assertIn("isRemoteLogRetryableHttpStatus(401, retryAuthorization = true)", android_service)
        self.assertNotIn("clientId=${target.clientId}", android_service)
        self.assertNotIn("endpoint=$CLIENT_LOGS_BOOTSTRAP_ENDPOINT", android_service)
        self.assertIn("private fun remoteLogBatchId(", android_service)
        self.assertIn("fun getAppLogs(maxBytes: Int = DEFAULT_EXPORT_MAX_BYTES): String", android_log)
        self.assertIn("withLock {\n            if (logFile.length() > LOG_MAX_FILE_SIZE)", android_log)
        self.assertIn("fun saveSecureString(key: String, value: String?): Boolean", android_prefs)
        self.assertIn("fun loadSecureString(key: String): String", android_prefs)
        self.assertNotIn("BIND_ABOVE_CLIENT and BIND_AUTO_CREATE", android_activity)
        self.assertIn("BIND_ABOVE_CLIENT or BIND_AUTO_CREATE", android_activity)
        self.assertIn("logcat\", \"-d\", \"-t\", LOGCAT_MAX_LINES.toString()", android_log)
        self.assertNotIn("qDebug().noquote() << QJsonDocument(config).toJson()", import_controller)
        self.assertNotIn("ovpnPreview", ios_packet_tunnel)
        self.assertIn("ovpnBytes=\\(ovpnData.count)", ios_packet_tunnel)
        self.assertNotIn('ovpnLog(.info, title: "config: ", message: openVPNConfig.str)', ios_openvpn)
        self.assertNotIn("amnezia_ovpn_adapter_config.conf", ios_openvpn)
        self.assertNotIn("ConfigDump", ios_openvpn)
        self.assertNotIn("config raw", ios_openvpn)
        self.assertNotIn("preview=", ios_openvpn)
        self.assertNotIn("ConfigHead", ios_openvpn)
        self.assertNotIn("ConfigTail", ios_openvpn)
        self.assertNotIn("ConfigTailSanitized", ios_openvpn)
        self.assertNotIn("info=\\(nsError.userInfo\\)", ios_openvpn)
        self.assertNotIn("payloadPreview", ios_controller)
        self.assertNotIn("decodedPayload", ios_controller)
        self.assertIn("Logger::init(true);", ipc_server)
        self.assertNotIn("Logger::deInit();", ipc_server)
        self.assertNotIn("Logger::cleanUp();", ipc_server)
        self.assertNotIn("Logger::clearLogs(true);", ipc_server)
        self.assertIn("withoutRemoteLogTokens", secure_qsettings)
        self.assertIn('clientLogs.remove(QStringLiteral("token"));', secure_qsettings)
        self.assertIn('clientLogs.insert(QStringLiteral("bootstrap"), true);', secure_qsettings)
        self.assertIn("sanitizedBackupValue(key, value(storedKey), &sanitized)", secure_qsettings)
        self.assertIn("QVariantMap sanitizedValues;", secure_qsettings)
        self.assertIn("sanitizedValues.insert(key, sanitizedValue);", secure_qsettings)
        self.assertIn("setValue(it.key(), it.value());", secure_qsettings)

        self.assertIn("SAFE_CLIENT_ID = re.compile", export_controller)
        self.assertIn("SAFE_INSTALLATION_ID = re.compile", export_controller)
        self.assertIn("class LogServer(ThreadingHTTPServer):", export_controller)
        self.assertIn("daemon_threads = True", export_controller)
        self.assertIn("def authenticate_client(self):", export_controller)
        self.assertIn('BOOTSTRAP_PATH = "__BOOTSTRAP_PATH__"', export_controller)
        self.assertIn("ALLOW_BOOTSTRAP = os.environ.get", export_controller)
        self.assertIn("def resolve_legacy_client_id(source_ip):", export_controller)
        self.assertIn("def ensure_legacy_token(client_id):", export_controller)
        self.assertIn("def is_legacy_token(client_id, token):", export_controller)
        self.assertIn("def bootstrap_client(self):", export_controller)
        self.assertIn("if legacy_scopes:", export_controller)
        self.assertIn("if not ALLOW_BOOTSTRAP or CONTAINER_SCOPE not in legacy_scopes:", export_controller)
        self.assertIn("MAX_BOOTSTRAP_BYTES = 1024", export_controller)
        self.assertIn("content_length > MAX_BOOTSTRAP_BYTES", export_controller)
        self.assertIn('HEALTH_PATH = "/healthz"', export_controller)
        self.assertIn("def do_GET(self):", export_controller)
        self.assertIn("if self.path != HEALTH_PATH:", export_controller)
        self.assertIn('"collectorVersion": 3', export_controller)
        self.assertIn('SAFE_BATCH_ID = re.compile(r"^[a-f0-9]{64}$")', export_controller)
        self.assertIn("if not SAFE_BATCH_ID.fullmatch(batch_id):", export_controller)
        self.assertIn("batch_receipt_exists(client_id, batch_id)", export_controller)
        self.assertIn("self.send_no_content(batch_id=batch_id, replayed=True)", export_controller)
        self.assertIn("QByteArray adminClientLogsDownloadScript", export_controller)
        self.assertIn("ExportController::DownloadClientLogsResult ExportController::downloadClientLogs", export_controller)
        self.assertIn("adminClientLogsDownloadScript(clientLogsStorageId(container, clientId))", export_controller)
        self.assertIn("remoteClientExists(credentials, container, clientId, result.errorCode)", export_controller)
        self.assertIn("QByteArray::fromBase64Encoding(downloadOutput.mid(statusEnd + 1).trimmed().toLatin1()", export_controller)
        self.assertIn("QByteArray::AbortOnBase64DecodingErrors", export_controller)
        self.assertIn("prune_client_dir(client_dir)", export_controller)
        self.assertIn("content_length > MAX_UPLOAD_BYTES", export_controller)
        self.assertIn("total <= MAX_CLIENT_BYTES", export_controller)
        self.assertIn("printf '0\\n'", export_controller)
        self.assertIn("printf '1\\n'", export_controller)
        self.assertIn("find \"$CLIENT_DIR\" -maxdepth 1 -type f -name '*.log'", export_controller)
        self.assertIn("downloadOutput.indexOf(QLatin1Char('\\n'))", export_controller)
        self.assertIn("UPLOAD_SEMAPHORE = threading.BoundedSemaphore(4)", export_controller)
        self.assertIn("CLIENT_LOCKS = {}", export_controller)
        self.assertIn("with client_lock(client_id):", export_controller)
        self.assertIn('name.endswith(".log")', export_controller)
        self.assertIn("os.umask(0o077)", export_controller)
        self.assertIn("os.makedirs(client_dir, mode=0o700, exist_ok=True)", export_controller)
        self.assertIn("-d __BRIDGE_HOST__/32 -p tcp --dport __SYNC_PORT__ -j REDIRECT --to-ports __SYNC_PORT__", export_controller)
        self.assertIn("--memory=96m --cpus=0.5 --pids-limit=64", export_controller)
        self.assertIn("AMNEZIA_CLIENT_LOGS_BOOTSTRAP=0", export_controller)
        self.assertIn("AMNEZIA_CLIENT_LOGS_BOOTSTRAP=__ALLOW_LEGACY_BOOTSTRAP__", export_controller)
        self.assertIn("read -r iface peer allowed_ips", export_controller)
        self.assertIn("__WG_SHOW_BIN__ show all allowed-ips", export_controller)
        self.assertIn("__HOST_DIRECTORY__/legacy/__CONTAINER_SCOPE__.tsv", export_controller)
        self.assertIn("legacy_attempt=$((legacy_attempt + 1))", export_controller)
        self.assertIn("legacy_expected_peers", export_controller)
        self.assertIn("legacy_unique_ips", export_controller)
        self.assertIn("legacy_map_empty", export_controller)
        self.assertIn("sudo mv -f \"$legacy_stage\" \"$legacy_dest\"", export_controller)
        self.assertIn("tokens.lock", export_controller)
        self.assertIn("cleanupTmpFiles();", export_controller)
        self.assertIn("echo __ERROR_MARKER__:network_subnet", export_controller)
        self.assertNotIn("docker network rm amnezia-dns-net", export_controller)
        self.assertLess(export_controller.index("emit appendClientRequested(serverId, clientId, clientName, container);"),
                        export_controller.index("publishClientLogCollector(credentials, container, clientLogId, clientLogToken)"))
        self.assertIn("maxBytesPerUpload = 15 * 1024 * 1024", protocol)
        self.assertIn('constexpr char bootstrapPath[] = "/bootstrap";', protocol)
        self.assertIn("clientLogs.insert(configKey::clientLogsBootstrap, true);", client_logs_utils)
        self.assertIn("configKey::clientPubKey", client_logs_utils)
        self.assertIn("removeClientLogAccess(credentials, container, clientId);", users_controller)
        self.assertIn("tokens.lock", users_controller)
        self.assertIn("tokens.tsv.__CLIENT_LOG_ID__.tmp", users_controller)
        self.assertIn("legacy_tokens.tsv.__CLIENT_LOG_ID__.tmp", users_controller)
        self.assertNotIn("logs/__CLIENT_LOG_ID__", users_controller)
        self.assertIn("ErrorCode removeClientLogAccess", users_controller)
        self.assertIn("__AMNEZIA_CLIENT_LOGS_CLEANUP_ERROR__", users_controller)
        self.assertIn("return ErrorCode::ServerCheckFailed;", users_controller)
        self.assertIn("isAlphaNumericId(clientId)", users_controller)
        self.assertIn("set -e ;\\\\", users_controller)
        self.assertIn("export EASYRSA_BATCH=1 ;\\\\", users_controller)
        self.assertIn("sectionHasExactPublicKey(section, clientId)", users_controller)
        self.assertIn("removedSections != 1", users_controller)
        self.assertIn("bool downloadClientLogs(const QString &serverId, int containerIndex, const QString &clientId, const QString &fileName);", export_ui_controller_h)
        self.assertIn("void clientLogsDownloadFinished(bool saved, bool logsFound);", export_ui_controller_h)
        self.assertIn("QtConcurrent::run", export_ui_controller)
        self.assertIn("static_cast<DockerContainer>(containerIndex)", export_ui_controller)
        self.assertIn("return exportController->downloadClientLogs(serverId, static_cast<DockerContainer>(containerIndex), clientId);", export_ui_controller)
        self.assertIn("if (!result.logsFound)", export_ui_controller)
        self.assertIn("SystemController::saveFile(fileName, result.data)", export_ui_controller)
        self.assertIn('text: qsTr("Download logs")', page_share)
        self.assertIn("ExportController.downloadClientLogs(ServersUiController.processedServerId,", page_share)
        self.assertIn("ServersUiController.processedContainerIndex,", page_share)
        self.assertIn('qsTr("No remote logs found")', page_share)
        self.assertIn('qsTr("Logs save dialog opened")', page_share)
        self.assertIn("Existing server-side logs will remain until the storage limit cleanup removes old log files.", page_share)

    def test_client_log_collector_prunes_oldest_files(self) -> None:
        namespace: dict[str, object] = {"__name__": "collector_test"}
        exec_client_logs_collector_script(namespace)
        with tempfile.TemporaryDirectory() as tmp:
            client_dir = Path(tmp) / "client"
            client_dir.mkdir()
            old_file = client_dir / "old.log"
            middle_file = client_dir / "middle.log"
            new_file = client_dir / "new.log"
            ignored_file = client_dir / "keep.txt"
            old_file.write_bytes(b"old")
            middle_file.write_bytes(b"mid!")
            new_file.write_bytes(b"newer")
            ignored_file.write_bytes(b"not a log")
            os.utime(old_file, (1, 1))
            os.utime(middle_file, (2, 2))
            os.utime(new_file, (3, 3))

            namespace["MAX_CLIENT_BYTES"] = middle_file.stat().st_size + new_file.stat().st_size
            namespace["MAX_FILES_PER_CLIENT"] = 512
            namespace["prune_client_dir"](str(client_dir))  # type: ignore[index]

            self.assertFalse(old_file.exists())
            self.assertTrue(middle_file.exists())
            self.assertTrue(new_file.exists())
            self.assertTrue(ignored_file.exists())

            namespace["MAX_CLIENT_BYTES"] = 1024 * 1024
            namespace["MAX_FILES_PER_CLIENT"] = 1
            namespace["prune_client_dir"](str(client_dir))  # type: ignore[index]

            self.assertFalse(middle_file.exists())
            self.assertTrue(new_file.exists())
            self.assertEqual(new_file.read_bytes(), b"newer")
            self.assertEqual(ignored_file.read_bytes(), b"not a log")

    def test_client_log_collector_legacy_bootstrap_uses_source_ip_map(self) -> None:
        namespace: dict[str, object] = {"__name__": "collector_test"}
        exec_client_logs_collector_script(namespace)
        client_id = "a" * 64
        other_client_id = "b" * 64
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            legacy_root = root / "legacy"
            legacy_root.mkdir()
            (legacy_root / "amnezia-awg2.tsv").write_text(
                f"10.8.1.14\tunsafe/client-id\tbad-peer\n10.8.1.14\t{client_id}\tpeer-public-key\n",
                encoding="utf-8",
            )
            (legacy_root / "amnezia-wg.tsv").write_text(
                f"10.8.1.14\t{other_client_id}\tother-peer-public-key\n",
                encoding="utf-8",
            )

            namespace["ROOT"] = str(root)
            namespace["TOKEN_FILE"] = str(root / "tokens.tsv")
            namespace["TOKEN_LOCK_DIR"] = str(root / "tokens.lock")
            namespace["LEGACY_TOKEN_FILE"] = str(root / "legacy_tokens.tsv")
            namespace["LEGACY_ROOT"] = str(legacy_root)
            namespace["ALLOW_BOOTSTRAP"] = False
            namespace["CONTAINER_SCOPE"] = "amnezia-awg2"

            self.assertEqual(namespace["resolve_legacy_client_id"]("10.8.1.14"), "")

            namespace["ALLOW_BOOTSTRAP"] = True
            self.assertEqual(namespace["resolve_legacy_client_id"]("10.8.1.14"), client_id)
            self.assertEqual(namespace["resolve_legacy_client_id"]("10.8.1.99"), "")

            namespace["CONTAINER_SCOPE"] = "amnezia-wg"
            self.assertEqual(namespace["resolve_legacy_client_id"]("10.8.1.14"), other_client_id)
            namespace["CONTAINER_SCOPE"] = "amnezia-awg2"

            token = namespace["ensure_legacy_token"](client_id)
            self.assertTrue(token)
            self.assertEqual(namespace["ensure_legacy_token"](client_id), token)
            self.assertEqual(namespace["load_tokens"]()[client_id], token)
            self.assertIn((client_id, token, "amnezia-awg2"), namespace["load_legacy_tokens"]())
            self.assertEqual(namespace["is_legacy_token"](client_id, token), ["amnezia-awg2"])

            namespace["CONTAINER_SCOPE"] = "amnezia-wg"
            self.assertNotIn("amnezia-wg", namespace["is_legacy_token"](client_id, token))
            namespace["CONTAINER_SCOPE"] = ""
            self.assertEqual(namespace["resolve_legacy_client_id"]("10.8.1.14"), "")
            self.assertEqual(namespace["is_legacy_token"](client_id, token), ["amnezia-awg2"])

    @unittest.skipUnless(find_sh(), "sh is required to exercise the legacy client map refresh")
    def test_client_log_legacy_map_refresh_preserves_last_good_map_on_empty_reads(self) -> None:
        sh = find_sh()
        assert sh
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            legacy_dir = root / "client-logs" / "legacy"
            legacy_dir.mkdir(parents=True)
            target = legacy_dir / "amnezia-awg2.tsv"
            target.write_text("last-good-map\n", encoding="utf-8")
            attempts = root / "docker-attempts"

            refresh_script = (
                extract_client_logs_legacy_map_refresh_script()
                .replace("__HOST_DIRECTORY__", shell_absolute_path(root / "client-logs"))
                .replace("__CONTAINER_SCOPE__", "amnezia-awg2")
                .replace("__VPN_CONTAINER__", "amnezia-awg2")
                .replace("__WG_SHOW_BIN__", "awg")
                .replace("__WG_CONFIG_PATH__", "/opt/amnezia/awg/awg0.conf")
                .replace("__ERROR_MARKER__", "TEST_ERROR")
                .replace("\n", " ")
            )
            harness = textwrap.dedent(
                f"""\
                sudo() {{ "$@"; }}
                sleep() {{ :; }}
                docker() {{
                    case "$*" in *"grep -c"*) printf '2\n'; return 0 ;; esac
                    attempt=0
                    [ ! -f {shell_absolute_path(attempts)!r} ] || attempt="$(cat {shell_absolute_path(attempts)!r})"
                    attempt=$((attempt + 1))
                    printf '%s\n' "$attempt" > {shell_absolute_path(attempts)!r}
                    return 0
                }}
                """
            ) + "if [ '1' = '1' ]; then " + refresh_script + " fi\n"

            result = subprocess.run([sh, "-s"], input=harness, text=True, capture_output=True)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("TEST_ERROR:legacy_map_empty", result.stdout)
            self.assertEqual(attempts.read_text(encoding="utf-8").strip(), "6")
            self.assertEqual(target.read_text(encoding="utf-8"), "last-good-map\n")
            self.assertEqual(list(legacy_dir.glob("*.tmp")), [])

    @unittest.skipUnless(find_sh(), "sh is required to exercise the legacy client map refresh")
    def test_client_log_legacy_map_refresh_retries_then_installs_complete_map_atomically(self) -> None:
        sh = find_sh()
        assert sh
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            legacy_dir = root / "client-logs" / "legacy"
            legacy_dir.mkdir(parents=True)
            target = legacy_dir / "amnezia-awg2.tsv"
            target.write_text("last-good-map\n", encoding="utf-8")
            attempts = root / "docker-attempts"

            refresh_script = (
                extract_client_logs_legacy_map_refresh_script()
                .replace("__HOST_DIRECTORY__", shell_absolute_path(root / "client-logs"))
                .replace("__CONTAINER_SCOPE__", "amnezia-awg2")
                .replace("__VPN_CONTAINER__", "amnezia-awg2")
                .replace("__WG_SHOW_BIN__", "awg")
                .replace("__WG_CONFIG_PATH__", "/opt/amnezia/awg/awg0.conf")
                .replace("__ERROR_MARKER__", "TEST_ERROR")
                .replace("\n", " ")
            )
            harness = textwrap.dedent(
                f"""\
                sudo() {{ "$@"; }}
                sleep() {{ :; }}
                docker() {{
                    case "$*" in *"grep -c"*) printf '2\n'; return 0 ;; esac
                    attempt=0
                    [ ! -f {shell_absolute_path(attempts)!r} ] || attempt="$(cat {shell_absolute_path(attempts)!r})"
                    attempt=$((attempt + 1))
                    printf '%s\n' "$attempt" > {shell_absolute_path(attempts)!r}
                    printf 'awg0\tpeer-a\t10.8.1.14/32\n'
                    if [ "$attempt" -ge 2 ]; then
                        printf 'awg0\tpeer-b\t10.8.1.16/32\n'
                    fi
                    return 0
                }}
                """
            ) + "if [ '1' = '1' ]; then " + refresh_script + " fi\n"

            result = subprocess.run([sh, "-s"], input=harness, text=True, capture_output=True)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("TEST_ERROR", result.stdout)
            self.assertEqual(attempts.read_text(encoding="utf-8").strip(), "2")
            expected = (
                f"10.8.1.14\t{sha256_hex_for_text('amnezia-awg2' + chr(9) + 'peer-a')}\tpeer-a\n"
                f"10.8.1.16\t{sha256_hex_for_text('amnezia-awg2' + chr(9) + 'peer-b')}\tpeer-b\n"
            )
            self.assertEqual(target.read_text(encoding="utf-8"), expected)
            self.assertEqual(list(legacy_dir.glob("*.tmp")), [])

    def test_selfhosted_publish_defaults_to_local_non_apple_platforms(self) -> None:
        workflow_paths = (
            REPO_ROOT / ".github/workflows/deploy.yml",
            REPO_ROOT / ".github/workflows/upstream-release-freeze.yml",
            REPO_ROOT / ".github/workflows/tag-deploy.yml",
        )
        for workflow_path in workflow_paths:
            if workflow_path.exists():
                assert_no_duplicate_yaml_keys(self, workflow_path)

        deploy_workflow = read_workflow_if_enabled(REPO_ROOT / ".github/workflows/deploy.yml")
        freeze_workflow = read_workflow_if_enabled(REPO_ROOT / ".github/workflows/upstream-release-freeze.yml")
        tag_deploy_workflow = read_workflow_if_enabled(REPO_ROOT / ".github/workflows/tag-deploy.yml")
        readme = (REPO_ROOT / "deploy/selfhosted_updates/README.md").read_text(encoding="utf-8")
        gitignore = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")

        if deploy_workflow:
            self.assertNotIn("SELFHOSTED_", deploy_workflow)
            self.assertNotIn("Publish-Selfhosted-Updates", deploy_workflow)
            self.assertNotIn("Validate-Selfhosted-Inputs", deploy_workflow)
            self.assertNotIn("default: 'windows-x64 linux-x64 macos-x64 ios", deploy_workflow)
        if tag_deploy_workflow:
            self.assertNotIn("SELFHOSTED_", tag_deploy_workflow)
        self.assertFalse((REPO_ROOT / ".github/workflows/selfhosted-update-publish.yml").exists())
        local_release = (REPO_ROOT / "deploy/selfhosted_updates/local_release.ps1").read_text(encoding="utf-8")
        setup_release = (REPO_ROOT / "deploy/selfhosted_updates/setup_release_workstation.ps1").read_text(encoding="utf-8")
        build_bat = (REPO_ROOT / "deploy/build.bat").read_text(encoding="utf-8")
        build_sh = (REPO_ROOT / "deploy/build.sh").read_text(encoding="utf-8")
        platform_settings = (REPO_ROOT / "cmake/platform_settings.cmake").read_text(encoding="utf-8")
        android_cmake = (REPO_ROOT / "client/cmake/android.cmake").read_text(encoding="utf-8")
        android_gradle = (REPO_ROOT / "client/android/build.gradle.kts").read_text(encoding="utf-8")
        client_cmake = (REPO_ROOT / "client/CMakeLists.txt").read_text(encoding="utf-8")
        protocol_constants = (REPO_ROOT / "client/core/utils/constants/protocolConstants.h").read_text(encoding="utf-8")
        update_controller = (REPO_ROOT / "client/core/controllers/updateController.cpp").read_text(encoding="utf-8")
        update_controller_h = (REPO_ROOT / "client/core/controllers/updateController.h").read_text(encoding="utf-8")
        update_ui_controller = (REPO_ROOT / "client/ui/controllers/updateUiController.cpp").read_text(encoding="utf-8")
        update_ui_controller_h = (REPO_ROOT / "client/ui/controllers/updateUiController.h").read_text(encoding="utf-8")
        connection_ui_controller = (REPO_ROOT / "client/ui/controllers/connectionUiController.cpp").read_text(encoding="utf-8")
        about_page = (REPO_ROOT / "client/ui/qml/Pages2/PageSettingsAbout.qml").read_text(encoding="utf-8")
        qif_component_script = (REPO_ROOT / "deploy/installer/qif/componentscript.js").read_text(encoding="utf-8")
        bootstrapper = (REPO_ROOT / "client/core/controllers/selfhosted/selfHostedUpdateBootstrapper.cpp").read_text(encoding="utf-8")
        bootstrapper_h = (REPO_ROOT / "client/core/controllers/selfhosted/selfHostedUpdateBootstrapper.h").read_text(encoding="utf-8")
        core_controller = (REPO_ROOT / "client/core/controllers/coreController.cpp").read_text(encoding="utf-8")
        core_signal_handlers = (REPO_ROOT / "client/core/controllers/coreSignalHandlers.cpp").read_text(encoding="utf-8")
        app_cpp = (REPO_ROOT / "client/amneziaApplication.cpp").read_text(encoding="utf-8")
        app_h = (REPO_ROOT / "client/amneziaApplication.h").read_text(encoding="utf-8")
        main_cpp = (REPO_ROOT / "client/main.cpp").read_text(encoding="utf-8")
        ssh_session_h = (REPO_ROOT / "client/core/utils/selfhosted/sshSession.h").read_text(encoding="utf-8")
        ssh_session_cpp = (REPO_ROOT / "client/core/utils/selfhosted/sshSession.cpp").read_text(encoding="utf-8")
        server_scripts_qrc = (REPO_ROOT / "client/server_scripts/serverScripts.qrc").read_text(encoding="utf-8")
        self.assertIn("local_release.ps1", readme)
        self.assertIn("setup_release_workstation.ps1", readme)
        self.assertIn("dist/selfhosted-release-env.ps1", gitignore)
        self.assertIn("dist/selfhosted-local-artifacts/", gitignore)
        self.assertIn("dist/selfhosted-updates/", gitignore)
        self.assertIn("dist/selfhosted-windows-client/", gitignore)
        self.assertIn("aqtinstall.log", gitignore)
        self.assertIn("*.jks", gitignore)
        self.assertIn("*.keystore", gitignore)
        self.assertIn("android-release-keystore.env.ps1", gitignore)
        self.assertIn("selfhosted-update-private.pem", gitignore)
        self.assertIn("get_android_toolchain_dir", build_sh)
        self.assertIn('$QT_ROOT_PATH/android/lib/cmake/Qt6/qt.toolchain.cmake', build_sh)
        self.assertIn('"-o=openssl/*:no_asm=True"', platform_settings)
        self.assertIn('WIN32 AND (CONAN_NO_REMOTE', platform_settings)
        self.assertIn("AMNEZIA_BUILD_JOBS_STRIPPED", platform_settings)
        self.assertIn('MATCHES "^[1-9][0-9]*$"', platform_settings)
        self.assertIn('set "AMNEZIA_BUILD_JOBS=%BUILD_JOBS%"', build_bat)
        self.assertIn('export AMNEZIA_BUILD_JOBS="$BUILD_JOBS"', build_sh)
        self.assertIn("CL_MPCount=%BUILD_JOBS%", build_bat)
        self.assertIn("qt_internal_android_armeabi-v7a_configure", build_sh)
        self.assertIn("qt_internal_android_x86_configure", build_sh)
        self.assertIn("qt_internal_android_x86_64_configure", build_sh)
        self.assertIn("libxray-aar-copy.lock", android_cmake)
        self.assertIn("configure_file(${AMNEZIA_LIBXRAY_PATH}", android_cmake)
        self.assertIn("SELFHOSTED_UPDATE_SYNC_HOST", client_cmake)
        self.assertIn("SELFHOSTED_UPDATE_BUNDLE_DIR", client_cmake)
        self.assertIn('DESTINATION "selfhosted_updates"', client_cmake)
        self.assertIn("QT_ANDROID_SHADERTOOLS_LIB", android_cmake)
        self.assertIn("QT_ANDROID_EXTRA_LIBS", android_cmake)
        self.assertIn("Resolve-AndroidShaderToolsLib", local_release)
        self.assertIn("#define SELFHOSTED_UPDATE_SYNC_HOST", protocol_constants)
        self.assertNotIn('QStringLiteral("macos-', update_controller)
        self.assertNotIn('QStringLiteral("ios-', update_controller)
        self.assertIn("SELFHOSTED_UPDATE_SYNC_HOST", readme)
        self.assertNotIn('Qt.openUrlExternally("https://github.com/amnezia-vpn/desktop-client/releases/latest")', about_page)
        self.assertIn("UpdateController.checkForUpdates()", about_page)
        self.assertIn("manualUpdateCheckNoUpdates", update_ui_controller_h)
        self.assertIn("isUpdateCheckRunning()", update_controller_h)
        self.assertIn("bool checkForUpdates()", update_controller_h)
        self.assertIn("updateCheckFinished(updateAvailable)", update_controller)
        self.assertIn("wasUpdateCheckRunning", update_ui_controller)
        self.assertIn("onUpdateCheckFinished(false)", update_ui_controller)
        self.assertIn('QCoreApplication::translate("ConnectionController", "Connected")', connection_ui_controller)
        self.assertNotIn('m_connectionStateText = tr("Connected")', connection_ui_controller)
        self.assertNotIn('"--publish-bundled-updates-once"', qif_component_script)
        self.assertNotIn("Published bundled self-hosted updates", qif_component_script)
        self.assertIn('QStringLiteral("/tmp/amnezia-client-updates.%1").arg(runId)', bootstrapper)
        self.assertIn('QStringLiteral("sh %1 %2 %3 %4 %5 %6 %7 %8")', bootstrapper)
        self.assertIn('runPublisher(QStringLiteral("prepare"))', bootstrapper)
        self.assertIn('runPublisher(QStringLiteral("commit"))', bootstrapper)
        self.assertIn("metadataSha256", bootstrapper)
        self.assertIn("fileCount", bootstrapper)
        self.assertNotIn("remote_tmp=$(mktemp", bootstrapper)
        self.assertIn("[ValidateSet(\"windows\", \"linux\", \"android\", \"headless\")]", local_release)
        self.assertIn('"windows-x64"', local_release)
        self.assertIn(
            "Bundled Windows update publisher requires the windows-x64 manifest artifact",
            local_release,
        )
        self.assertIn('"linux-x64"', local_release)
        self.assertIn('"android-arm64-v8a"', local_release)
        self.assertNotIn('"android-armeabi-v7a"', local_release)
        self.assertNotIn('"android-x86"', local_release)
        self.assertNotIn('"android-x86_64"', local_release)
        self.assertNotIn('"ios"', local_release)
        self.assertNotIn('"macos"', local_release)
        self.assertIn("androidManifestAttribute(\"versionCode\")", android_gradle)
        self.assertIn("androidManifestAttribute(\"versionName\")", android_gradle)
        self.assertIn("deploy\\build.bat", local_release)
        self.assertIn("--installer ifw -arch x64", local_release)
        self.assertNotIn("--installer all -arch x64", local_release)
        self.assertIn("run_repo_build_sh --source", local_release)
        self.assertIn("[int] $BuildJobs = 0", local_release)
        self.assertIn('[string] $SyncHost = $(if ($env:SELFHOSTED_UPDATE_SYNC_HOST)', local_release)
        self.assertIn("Resolve-BuildJobs", local_release)
        self.assertIn("Assert-ReleaseInputs", local_release)
        self.assertIn("export AMNEZIA_BUILD_JOBS=", local_release)
        self.assertIn("export CMAKE_BUILD_PARALLEL_LEVEL=", local_release)
        self.assertIn("export MAKEFLAGS=", local_release)
        self.assertIn("export SELFHOSTED_UPDATE_SYNC_HOST=$(Quote-Sh $SyncHost)", local_release)
        self.assertIn("Get-RequiredAndroidBuildToolsRevision", local_release)
        self.assertIn("export GRADLE_OPTS=", local_release)
        self.assertIn("--jobs $buildJobs", local_release)
        self.assertIn("run_repo_build_sh --target android --sign --abi arm64-v8a", local_release)
        self.assertIn("build_headless_release.sh", local_release)
        self.assertIn("AmneziaHeadless_${Version}_linux_x64.tar.gz", local_release)
        self.assertIn("HeadlessOpenSslIncludeDir", local_release)
        self.assertIn("HeadlessOpenSslCryptoLibrary", local_release)
        self.assertIn("--build `\"`$build_dir`\" --jobs $buildJobs", local_release)
        self.assertNotIn("run_repo_build_sh --target android --sign --aab", local_release)
        self.assertNotIn("build-android-universal", local_release)
        self.assertIn('Join-Path $RepoRoot "deploy\\build-android-arm64-v8a"', local_release)
        self.assertIn('$env:CONAN_NO_REMOTE = "1"', local_release)
        self.assertIn('export AWG_ANDROID_GRADLE_USER_HOME="$HOME/.cache/amnezia/awg-android-gradle"', local_release)
        self.assertIn('find "$HOME/.conan2/p/t" -mindepth 1 -maxdepth 1 -exec rm -rf {} +', local_release)
        self.assertIn("rename_artifact()", local_release)
        self.assertIn("Missing fresh Android artifact", local_release)
        self.assertIn("AmneziaVPN_*_android9+_arm64-v8a.apk", local_release)
        self.assertIn("Remove-UnsupportedAndroidArtifacts", local_release)
        self.assertIn("tr -d '\\r' < \"$source_script\"", local_release)
        self.assertIn("Android local auto-update builds require", local_release)
        self.assertIn("[switch] $Preflight", local_release)
        self.assertIn("[switch] $NoBundleUpdatesInWindowsClient", local_release)
        self.assertIn("Build-WindowsInstaller $OutDir", local_release)
        self.assertIn("dist\\selfhosted-windows-client\\$Version", local_release)
        self.assertIn("windows_x64_selfhosted.exe", local_release)
        self.assertIn("SELFHOSTED_UPDATE_BUNDLE_DIR", local_release)
        self.assertIn("Assert-LocalReleasePrerequisites", local_release)
        self.assertIn("Assert-WslReady", local_release)
        self.assertIn("GetTempFileName", local_release)
        self.assertIn('Invoke-External "wsl.exe" @("bash", $tempScriptWsl)', local_release)
        self.assertIn("[System.Text.UTF8Encoding]::new($false)", local_release)
        self.assertIn('export PATH="$HOME/.local/jdk-17/bin:$HOME/.local/bin:$PATH"', local_release)
        self.assertIn('Assert-WslCommand "conan"', local_release)
        self.assertIn("[string] $WslAndroidHome", local_release)
        self.assertIn("Resolve-WslAndroidHome", local_release)
        self.assertIn("Assert-WslAndroidSdkReady", local_release)
        self.assertIn("Assert-WslQifReady", local_release)
        self.assertIn("WSL_QIF_ROOT_PATH", local_release)
        self.assertIn("linux-x86_64/bin/clang", local_release)
        self.assertIn("Qt6RemoteObjects", local_release)
        self.assertIn("Qt6RemoteObjectsTools", local_release)
        self.assertIn("Qt6Core5Compat", local_release)
        self.assertIn("qtremoteobjects", local_release)
        self.assertIn("Assert-JavaForWsl", local_release)
        self.assertIn("Assert-AndroidQtKit", local_release)
        self.assertIn('Test-QtTargetKit $QtRootPath "android"', local_release)
        self.assertIn("Install either '$QtRootPath\\android' or '$QtRootPath\\android_arm64_v8a'", local_release)
        self.assertIn("Test-WindowsJavaHome", local_release)
        self.assertIn("java_shim_dir", local_release)
        self.assertIn("windows_java_home", local_release)
        self.assertIn("$androidExportScript = $androidExports -join", local_release)
        self.assertIn("Ensure-WslJava", setup_release)
        self.assertIn('Assert-ExistingFile $env:QT_ANDROID_KEYSTORE_PATH "QT_ANDROID_KEYSTORE_PATH"', local_release)
        self.assertIn('Assert-QtTargetKit $qtRootPath "gcc_64"', local_release)
        self.assertIn('"android_arm64_v8a"', local_release)
        self.assertIn("export QT_ROOT_PATH=", local_release)
        self.assertIn("export QIF_ROOT_PATH=", local_release)
        self.assertIn("[switch] $InstallMissing", setup_release)
        self.assertIn("[switch] $GenerateUpdateKeys", setup_release)
        self.assertIn("[switch] $GenerateAndroidKeystore", setup_release)
        self.assertIn("$QtMirrorBase", setup_release)
        self.assertIn("QT_MIRROR_BASE", setup_release)
        self.assertIn("-b $(Quote-Sh $QtMirrorBase)", setup_release)
        self.assertIn("python3 -m aqt install-qt", setup_release)
        self.assertIn("--timeout 30", setup_release)
        self.assertIn("Test-AqtQtVersionAvailable $QtHost $Target", setup_release)
        self.assertIn("Test-AqtQtArchAvailable $QtHost $Target $aqtArch", setup_release)
        self.assertIn("Ensure-Conan", setup_release)
        self.assertIn("python3 -m pip install --user conan", setup_release)
        self.assertIn("Ensure-WslInstallerFramework", setup_release)
        self.assertIn("qt.tools.ifw.47", setup_release)
        self.assertIn("WSL_QIF_ROOT_PATH", setup_release)
        self.assertIn("[string] $WslAndroidHome", setup_release)
        self.assertIn("commandlinetools-linux-14742923_latest.zip", setup_release)
        self.assertIn("Ensure-WslAndroidSdk", setup_release)
        self.assertIn('"android-36"', setup_release)
        self.assertIn('"36.0.0"', setup_release)
        self.assertIn("[string] $BaseUrl", setup_release)
        self.assertIn("SELFHOSTED_UPDATE_BASE_URL", setup_release)
        self.assertIn("WSL_ANDROID_HOME", setup_release)
        self.assertIn("$QtAndroidModules", setup_release)
        self.assertIn("qtremoteobjects", setup_release)
        self.assertIn("qt5compat", setup_release)
        self.assertIn("Qt6RemoteObjectsTools", setup_release)
        self.assertIn("Qt6Core5Compat", setup_release)
        self.assertIn('if ($KitName -eq "gcc_64")', setup_release)
        self.assertIn('return "linux_gcc_64"', setup_release)
        self.assertIn("Ensure-AndroidQtKits", setup_release)
        self.assertIn('Ensure-QtKit "all_os" "android" "android_arm64_v8a"', setup_release)
        self.assertIn("Test-AndroidQtKit", setup_release)
        self.assertIn("aqtinstall cannot install Qt", setup_release)
        self.assertIn('Ensure-QtKit "linux" "desktop" "gcc_64"', setup_release)
        self.assertNotIn('"android_arm64_v8a", "android_armv7", "android_x86", "android_x86_64"', setup_release)
        self.assertIn("WslJdkUrl", setup_release)
        self.assertIn("~/.local/jdk-17", setup_release)
        self.assertIn("genpkey -algorithm Ed25519", setup_release)
        self.assertIn("GenerateAndroidKeystore", readme)
        self.assertIn("MaintenanceTool", readme)
        self.assertIn("all_os android", readme)
        self.assertIn("QT_MIRROR_BASE", readme)
        self.assertIn("keytool -genkeypair", setup_release)
        self.assertIn("android-release-keystore.env.ps1", setup_release)
        self.assertNotIn("macos", setup_release.lower())
        self.assertNotIn("ios", setup_release.lower())
        self.assertIn("make_manifest.py", local_release)
        self.assertNotIn("[switch] $Publish", local_release)
        self.assertNotIn("[switch] $NoPublish", local_release)
        self.assertNotIn("[switch] $NoInstallHost", local_release)
        self.assertIn("--auto-install", local_release)
        self.assertIn("--public-key-base64", local_release)
        self.assertIn("--require-platform", local_release)
        self.assertIn("SELFHOSTED_UPDATE_PUBLIC_KEY_PEM_BASE64", local_release)
        self.assertIn("SELFHOSTED_UPDATE_BASE_URL", local_release)
        self.assertNotIn("SELFHOSTED_UPDATE_SERVER", local_release)
        self.assertNotIn("SELFHOSTED_UPDATE_SSH_PRIVATE_KEY_PATH", local_release)
        self.assertIn("selfhosted-windows-client", readme)
        self.assertIn("selfhosted_updates", readme)
        self.assertIn("recursive package", readme)
        self.assertIn("SelfHostedUpdateBootstrapper", core_controller)
        self.assertNotIn("m_selfHostedUpdateBootstrapper->start();", core_controller)
        self.assertIn("state != Vpn::ConnectionState::Connected", core_signal_handlers)
        self.assertIn("m_coreController->m_selfHostedUpdateBootstrapper->start()", core_signal_handlers)
        self.assertIn("SelfHostedUpdateBootstrapper::publishFinished", core_signal_handlers)
        self.assertIn("scheduleUpdateCheck();", core_signal_handlers)
        self.assertIn("return;\n        }\n#endif\n\n        QTimer::singleShot(5000, m_coreController->m_updateController", core_signal_handlers)
        self.assertIn("bool start()", bootstrapper_h)
        self.assertIn("AutomaticPublishRetryState m_publishRetryState", bootstrapper_h)
        self.assertIn("maximumAutomaticPublishAttempts = 3", bootstrapper_h)
        self.assertIn("firstAutomaticPublishRetryDelayMs", bootstrapper_h)
        self.assertIn("secondAutomaticPublishRetryDelayMs", bootstrapper_h)
        self.assertIn("beginAutomaticPublishAttempt(m_publishRetryState)", bootstrapper)
        self.assertIn("bootstrapper->start();", bootstrapper)
        self.assertIn("publishFinished(success)", bootstrapper)
        self.assertIn("bool publishNow()", bootstrapper_h)
        self.assertIn("return publishPayload(payload, credentials);", bootstrapper)
        self.assertIn("installOrRefreshUpdateHost", bootstrapper)
        self.assertIn('installScript.replace("\\r\\n", "\\n")', bootstrapper)
        self.assertIn("installScript.replace('\\r', '\\n')", bootstrapper)
        self.assertIn("verifyRemoteUpdateHost", bootstrapper)
        self.assertIn("Remote self-hosted update host verified", bootstrapper)
        self.assertIn("verifyManifestSignature", bootstrapper)
        self.assertIn("PayloadFile", bootstrapper_h)
        self.assertIn("relativePath", bootstrapper_h)
        self.assertIn('QStringLiteral("/tmp/amnezia-client-updates.%1").arg(runId)', bootstrapper)
        self.assertIn("QRandomGenerator::system()->generate()", bootstrapper)
        self.assertNotIn("mktemp -d /tmp/amnezia-client-updates.XXXXXX", bootstrapper)
        self.assertIn("bridge_id=$(inspect_value '{{.Id}}' amnezia-client-updates)", bootstrapper)
        verify_host = bootstrapper[
            bootstrapper.index("const auto verifyRemoteUpdateHost"):
            bootstrapper.index("QByteArray publishMetadata")
        ]
        self.assertIn('"set -eu\\n"', verify_host)
        self.assertIn('docker exec \\"$bridge_id\\"', bootstrapper)
        self.assertIn("runScriptInSingleShell", verify_host)
        self.assertIn('docker ps -aq --no-trunc --filter \\"label=$tx_label=$transaction_id\\"', verify_host)
        self.assertIn("tunnel-*", verify_host)
        self.assertIn(".HostConfig.NetworkMode", verify_host)
        self.assertIn("org.amnezia.client-update-host.transaction", bootstrapper)
        self.assertIn("org.amnezia.client-update-host.role", bootstrapper)
        self.assertIn("org.amnezia.client-update-host.bind", bootstrapper)
        self.assertIn("org.amnezia.client-update-host.probe", bootstrapper)
        self.assertIn("org.amnezia.client-update-host.port", bootstrapper)
        self.assertIn("{{.Config.Image}}", bootstrapper)
        self.assertIn("{{range .Mounts}}", bootstrapper)
        self.assertIn("|false", bootstrapper)
        self.assertIn("{{.State.Running}}", bootstrapper)
        self.assertIn("bridge_container_id", bootstrapper)
        self.assertIn("--network host", bootstrapper)
        self.assertIn("host_container_id", bootstrapper)
        self.assertIn(
            "docker.io/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662",
            bootstrapper,
        )
        self.assertNotIn("docker.io/library/busybox:latest", bootstrapper)
        self.assertNotIn("Bundled self-hosted update payload is already published", bootstrapper)
        self.assertNotIn("remoteManifestHash", bootstrapper)
        self.assertNotIn("readRemoteHash", bootstrapper)
        self.assertLess(
            bootstrapper.index("uploadLocalFileToHost(credentials, file.localPath, remotePath)"),
            bootstrapper.index("Bundled self-hosted update payload published"),
        )
        self.assertIn("publish-bundled-updates-once", app_cpp)
        self.assertIn("m_optPublishBundledUpdatesOnce", app_h)
        self.assertIn("isPublishBundledUpdatesOnceCommand", main_cpp)
        self.assertIn("!publishBundledUpdatesOnce", main_cpp)
        self.assertIn("uploadLocalFileToHost", ssh_session_h)
        self.assertIn("overwriteMode, localPath, remotePath", ssh_session_cpp)
        ssh_client_cpp = (REPO_ROOT / "client/core/utils/selfhosted/sshClient.cpp").read_text(encoding="utf-8")
        self.assertIn("QTemporaryFile snapshot", ssh_client_cpp)
        self.assertIn("QFileInfo(source).isFile()", ssh_client_cpp)
        self.assertIn('actual_size=$(wc -c < \\"$upload_tmp\\")', ssh_client_cpp)
        self.assertIn("command.toUtf8(), {}, snapshotPath, true", ssh_client_cpp)
        self.assertNotIn("ssh_scp_", ssh_client_cpp)
        self.assertNotIn("ssh_channel_get_exit_status", ssh_client_cpp)
        self.assertIn("channel_exit_status_function", ssh_client_cpp)
        self.assertIn("ErrorCode::ServerCheckFailed", ssh_client_cpp)
        self.assertIn("update_host/install_server_update_host.sh", server_scripts_qrc)
        self.assertIn("bundledArtifactRelativePath", bootstrapper)
        self.assertIn("bundledRollbackArtifactRelativePath", bootstrapper)
        self.assertIn("unsafe artifact URL", bootstrapper)
        self.assertIn('remoteTmp + QStringLiteral("/") + file.relativePath', bootstrapper)
        self.assertIn("mkdir -p -- %1", bootstrapper)
        self.assertIn("hasSymlinkOrReparsePoint", bootstrapper)
        self.assertIn("relativeUrlPath", bootstrapper_h)
        self.assertIn("bundledArtifactRequestPath", bootstrapper_h)
        self.assertIn("bundledArtifactRequestPath(urlText)", bootstrapper)
        self.assertIn("headlessProvisioning", bootstrapper)
        self.assertIn("packageManifestSha256", bootstrapper)
        self.assertIn("checksumsSha256", bootstrapper)
        self.assertIn("packageFiles", bootstrapper)
        self.assertIn("amnezia-headless-provisioning-tar-v1", bootstrapper)
        self.assertIn("linux-headless-provisioning", bootstrapper)
        self.assertIn("uploadLocalFileToHost(credentials, file.localPath, remotePath)", bootstrapper)
        self.assertIn('if (!path.startsWith(u\'/\'))', bootstrapper_h)
        self.assertIn("kWindowsPlatform", bootstrapper)
        self.assertIn("platforms.value(QString::fromLatin1(kWindowsPlatform))", bootstrapper)
        self.assertIn("for (auto iterator = platforms.constBegin()", bootstrapper)
        self.assertIn("rollbackPlatforms.constBegin()", bootstrapper)
        self.assertIn("releasePolicy.contains(QStringLiteral(\"rollback\"))", bootstrapper)
        self.assertIn("canonicalPolicyGeneration", bootstrapper)
        self.assertIn("rollbackGeneration", bootstrapper)
        self.assertIn("rollbackVersion", bootstrapper)
        self.assertIn("platformObject.value(QStringLiteral(\"openExternal\")).toBool()", bootstrapper)
        self.assertIn("expectedSize <= 0", bootstrapper)
        self.assertIn('busybox wget -q -O - "', bootstrapper)
        self.assertIn("file.relativePath.left(file.relativePath.lastIndexOf(u'/'))", bootstrapper)
        self.assertIn("publish_bundled_release.sh", bootstrapper)
        self.assertNotIn("sudo cp -a %3 %2/", bootstrapper)
        self.assertNotIn("for f in %3/*", bootstrapper)
        self.assertIn("SELFHOSTED_BUNDLED_UPDATE_PAYLOAD_DIR", bootstrapper)
        self.assertIn("QCoreApplication::applicationDirPath()", bootstrapper)
        self.assertIn("selfhosted_updates", bootstrapper)
        self.assertIn("QUrl::FullyDecoded", bootstrapper_h)
        self.assertIn("Bundled update artifact size mismatch", bootstrapper)
        self.assertIn("Bundled update artifact sha256 mismatch", bootstrapper)
        self.assertIn("isCanonicalSha256", bootstrapper_h)
        self.assertIn("uploadLocalFileToHost(credentials, file.localPath, remotePath)", bootstrapper)
        self.assertNotIn("manifest.json.tmp", bootstrapper)
        self.assertIn('runPublisher(QStringLiteral("commit"))', bootstrapper)
        self.assertIn("exactMachineReceipt", bootstrapper)
        self.assertIn("sha256sum", bootstrapper)
        self.assertIn("hostDirectory", bootstrapper)
        self.assertIn("install_server_update_host.sh", bootstrapper)
        self.assertIn("update_host/publish_bundled_release.sh", server_scripts_qrc)
        if deploy_workflow:
            self.assertNotIn("needs.Build-iOS.result == 'success'", deploy_workflow)
            self.assertNotIn("needs.Build-MacOS.result == 'success'", deploy_workflow)
            self.assertNotIn("args+=(--require-platform ios)", deploy_workflow)
            for job in ("Linux", "Windows", "Android"):
                bake_job = f"Bake-Prebuilts-{job}"
                self.assertIn(
                    f"(needs.{bake_job}.result == 'success' || needs.{bake_job}.result == 'skipped')",
                    deploy_workflow,
                )
        if freeze_workflow:
            self.assertNotIn("PUBLISH_SELFHOSTED_UPDATES", freeze_workflow)
            self.assertNotIn("RUN_BUILD_AFTER_FREEZE", freeze_workflow)
            self.assertIn('gh api "repos/${UPSTREAM_REPO}/releases/latest"', freeze_workflow)
            self.assertNotIn("git ls-remote --tags --refs upstream", freeze_workflow)
            self.assertNotIn("git tag -l | grep", freeze_workflow)
            self.assertIn("action == 'wait'", freeze_workflow)
            self.assertIn("Ordinary upstream/dev commits are intentionally not merged between releases", freeze_workflow)
            self.assertNotIn("git merge --no-edit upstream/dev", freeze_workflow)
            self.assertNotIn("--action sync", freeze_workflow)
            self.assertIn("git diff --binary upstream/dev...HEAD", freeze_workflow)
            self.assertIn('git checkout -B "$TARGET_BRANCH" "refs/tags/${release_tag}"', freeze_workflow)
            self.assertIn('git apply --index --3way "$fork_patch"', freeze_workflow)
            self.assertIn("apply server-managed fork changes to upstream release", freeze_workflow)
            self.assertIn('git push --force-with-lease origin HEAD:"$TARGET_BRANCH"', freeze_workflow)
            self.assertIn('git rev-parse "refs/tags/${release_tag}^{commit}"', freeze_workflow)
            self.assertNotIn("gh workflow run deploy.yml", freeze_workflow)
            self.assertIn("local_release.ps1 -Version", freeze_workflow)
        self.assertIn("latest published upstream GitHub Release", readme)
        self.assertIn("an upstream tag alone is not enough", readme)
        self.assertIn("post-release `upstream/dev` commits are not retained", readme)

    def test_windows_split_tunnel_does_not_route_empty_peer_endpoints(self) -> None:
        wg_windows = (REPO_ROOT / "client/platforms/windows/daemon/wireguardutilswindows.cpp").read_text(encoding="utf-8")
        route_monitor = (REPO_ROOT / "client/platforms/windows/daemon/windowsroutemonitor.cpp").read_text(encoding="utf-8")
        route_monitor_h = (REPO_ROOT / "client/platforms/windows/daemon/windowsroutemonitor.h").read_text(encoding="utf-8")
        split_tunnel = (REPO_ROOT / "client/platforms/windows/daemon/windowssplittunnel.cpp").read_text(encoding="utf-8")
        windows_daemon = (REPO_ROOT / "client/platforms/windows/daemon/windowsdaemon.cpp").read_text(encoding="utf-8")
        router_win = (REPO_ROOT / "service/server/router_win.cpp").read_text(encoding="utf-8")
        vpn_connection = (REPO_ROOT / "client/vpnConnection.cpp").read_text(encoding="utf-8")

        self.assertIn("if (!config.m_serverIpv4AddrIn.isEmpty())", wg_windows)
        self.assertIn("if (!config.m_serverIpv6AddrIn.isEmpty())", wg_windows)
        self.assertNotIn("addExclusionRoute(IPAddress(config.m_serverIpv6AddrIn));\n  }", wg_windows)
        self.assertIn("addr.protocol() == QAbstractSocket::UnknownNetworkLayerProtocol", route_monitor)
        self.assertIn("prefix.address().protocol() == QAbstractSocket::UnknownNetworkLayerProtocol", route_monitor)
        self.assertIn("if (error == NO_ERROR) {\n    updateCapturedRoutes(family, table);", route_monitor)
        self.assertIn("isOnLinkRoute(row)", route_monitor)
        self.assertIn("ERROR_OBJECT_ALREADY_EXISTS", route_monitor)
        self.assertIn("MIB_IPPROTO_LOCAL", route_monitor)
        self.assertIn("Adopting existing captured route", route_monitor)
        self.assertIn("NotifyRouteChange2(AF_UNSPEC", route_monitor)
        self.assertIn("m_routeChangeTimer.setInterval(300)", route_monitor)
        self.assertIn("std::atomic_bool m_routeChangeQueued", route_monitor_h)
        self.assertIn("std::atomic_int m_pendingRouteChanges", route_monitor_h)
        self.assertIn("notifyRouteChanged", route_monitor)
        self.assertIn("m_routeChangeQueued.compare_exchange_strong", route_monitor)
        self.assertIn("if (!m_routeChangeTimer.isActive())", route_monitor)
        self.assertIn("m_pendingRouteChanges.exchange(0", route_monitor)
        self.assertIn("m_exclusionRoutes[prefix] = data", route_monitor)
        self.assertIn("coalesced notifications", route_monitor)
        self.assertIn("QDir::fromNativeSeparators", split_tunnel)
        self.assertIn("if (dosPaths.isEmpty())", split_tunnel)
        self.assertIn("sizeof(CONFIGURATION_ENTRY) * dosPaths.size()", split_tunnel)
        self.assertIn("header->NumEntries = dosPaths.size()", split_tunnel)
        self.assertIn("if (config.empty())", split_tunnel)
        self.assertIn("std::numeric_limits<USHORT>::max()", split_tunnel)
        self.assertIn("GetLastError() == ERROR_INSUFFICIENT_BUFFER", split_tunnel)
        self.assertIn("m_splitTunnelManager->stop();\n      return true;", windows_daemon.replace("\r\n", "\n"))
        self.assertIn("isRouteAddCandidate", router_win)
        self.assertIn("address.isMulticast()", router_win)
        self.assertIn("minPublicBypassPrefixLength = 16", router_win)
        self.assertIn("minLocalBypassPrefixLength = 24", router_win)
        self.assertIn("MIB_IPFORWARDROW ipfrow = {}", router_win)
        self.assertIn("routeCandidates.size() > 500", router_win)
        self.assertIn("trackManagedRoute", router_win)
        self.assertIn("m_ipForwardRows.insert(routeKey, row)", router_win)
        self.assertIn("DeleteIpForwardEntry(&existing)", router_win)
        self.assertIn("routableSplitTunnelRoutes", vpn_connection)
        self.assertIn("hostAddress.isMulticast()", vpn_connection)
        self.assertIn("minPublicBypassPrefixLength = 16", vpn_connection)
        self.assertIn("minLocalBypassPrefixLength = 24", vpn_connection)
        self.assertIn("splitRoutesKeepingHostsInVpn(ips, protectedHosts)", vpn_connection)
        self.assertIn("if (!reply.waitForFinished(1000) || !reply.returnValue())", vpn_connection)
        self.assertIn("constexpr int incrementalManagedRouteIpcTimeoutMs = 5000", vpn_connection)
        self.assertIn("auto addReply = iface->routeAddTrustedList(gateway, addedRoutes);", vpn_connection)
        self.assertIn("!addReply.waitForFinished(incrementalManagedRouteIpcTimeoutMs)", vpn_connection)
        self.assertIn("addReply.returnValue() != addedRoutes.size()", vpn_connection)

    def test_windows_dns_prefers_vpn_interface_metric(self) -> None:
        dns_utils = (REPO_ROOT / "client/platforms/windows/daemon/dnsutilswindows.cpp").read_text(encoding="utf-8")
        dns_utils_h = (REPO_ROOT / "client/platforms/windows/daemon/dnsutilswindows.h").read_text(encoding="utf-8")

        self.assertIn("VPN_DNS_INTERFACE_METRIC = 1", dns_utils)
        self.assertIn("preferInterfaceMetric(AF_INET, m_ipv4Metric)", dns_utils)
        self.assertIn("preferInterfaceMetric(AF_INET6, m_ipv6Metric)", dns_utils)
        self.assertIn("row.UseAutomaticMetric = false", dns_utils)
        self.assertIn("SetIpInterfaceEntry(&row)", dns_utils)
        self.assertIn("restoreInterfaceMetric(AF_INET, m_ipv4Metric)", dns_utils)
        self.assertIn("restoreInterfaceMetric(AF_INET6, m_ipv6Metric)", dns_utils)
        self.assertIn("InterfaceMetricState", dns_utils_h)

    def test_wireguard_ipv6_routes_require_server_ipv6_availability(self) -> None:
        config_keys = (REPO_ROOT / "client/core/utils/constants/configKeys.h").read_text(encoding="utf-8")
        vpn_connection = (REPO_ROOT / "client/vpnConnection.cpp").read_text(encoding="utf-8")
        protocol = (REPO_ROOT / "client/android/protocolApi/src/main/kotlin/Protocol.kt").read_text(encoding="utf-8")
        protocol_config = (REPO_ROOT / "client/android/protocolApi/src/main/kotlin/ProtocolConfig.kt").read_text(encoding="utf-8")
        local_socket = (REPO_ROOT / "client/mozilla/localsocketcontroller.cpp").read_text(encoding="utf-8")
        ios_controller = (REPO_ROOT / "client/platforms/ios/ios_controller.mm").read_text(encoding="utf-8")

        self.assertIn('serverIpv6Available("serverIpv6Available")', config_keys)
        self.assertIn("wireGuardServerHasUsableIpv6Egress", vpn_connection)
        self.assertIn("isUsableIpv6TunnelAddress", vpn_connection)
        self.assertIn("wireGuardStringListFromJsonValue", vpn_connection)
        self.assertIn("isUniqueLocalIpv6Address", vpn_connection)
        self.assertIn("(rawAddress[0] & 0xfe) == 0xfc", vpn_connection)
        self.assertIn("!isUniqueLocalIpv6Address(address)", vpn_connection)
        self.assertIn("wireGuardNativeConfigValue", vpn_connection)
        self.assertIn('QRegularExpression::escape(key)', vpn_connection)
        self.assertIn("allowedIpsWithoutUnavailableIpv6Routes", vpn_connection)
        self.assertIn("splitWireGuardList(allowedIpValue.toString())", vpn_connection)
        self.assertIn("defaultWireGuardAllowedIps", vpn_connection)
        self.assertIn('allowedIps.append(QStringLiteral("::/0"))', vpn_connection)
        self.assertIn("Skipping IPv6 allowed IP because server IPv6 egress is unavailable", vpn_connection)
        self.assertIn("m_vpnConfiguration.insert(configKey::serverIpv6Available, serverIpv6Available)", vpn_connection)
        self.assertIn("configData.insert(configKey::serverIpv6Available, serverIpv6Available)", vpn_connection)
        self.assertIn("configData.insert(configKey::allowedIps, allowedIpsJsonArray)", vpn_connection)

        self.assertIn('setAllowIpv6Routes(config.optBoolean("serverIpv6Available", true))', protocol)
        self.assertIn("internal var allowIpv6Routes: Boolean = true", protocol_config)
        self.assertIn("fun setAllowIpv6Routes(allowIpv6Routes: Boolean)", protocol_config)
        self.assertIn('if (allowIpv6Routes) addRoute(InetNetwork("2000::", 3))', protocol_config)
        self.assertIn("routes.removeIf { it.inetNetwork.isIpv6 }", protocol_config)

        self.assertIn("rawConfig.contains(amnezia::configKey::serverIpv6Available)", local_socket)
        self.assertIn("bool canUseIpFamily", local_socket)
        self.assertIn("canUseIpFamily(rawConfig.value(amnezia::configKey::dns1).toString(), serverIpv6Available)", local_socket)
        self.assertIn("canUseIpFamily(rawConfig.value(amnezia::configKey::dns2).toString(), serverIpv6Available)", local_socket)
        self.assertIn("const bool allowedIpsMissing = !wgConfig.contains(amnezia::configKey::allowedIps)", local_socket)
        self.assertIn("serverIpv6Available && allowedIpsMissing", local_socket)
        self.assertIn("serverIpv6Available && allowedIp == QStringLiteral(\"::/0\")", local_socket)
        self.assertIn("appSplitTunnelAllowsGlobalBlock", local_socket)
        self.assertIn("appSplitTunnelType == amnezia::AppsRouteMode::VpnAllApps", local_socket)
        self.assertIn('json.insert("blockIpv6Traffic"', local_socket)
        self.assertIn("range.insert(\"isIpv6\", isIpv6)", local_socket)
        self.assertIn("filteredAllowedDns", local_socket)

        interface_config = (REPO_ROOT / "client/daemon/interfaceconfig.h").read_text(encoding="utf-8")
        daemon = (REPO_ROOT / "client/daemon/daemon.cpp").read_text(encoding="utf-8")
        firewall_h = (REPO_ROOT / "client/platforms/windows/daemon/windowsfirewall.h").read_text(encoding="utf-8")
        firewall = (REPO_ROOT / "client/platforms/windows/daemon/windowsfirewall.cpp").read_text(encoding="utf-8")
        wg_windows = (REPO_ROOT / "client/platforms/windows/daemon/wireguardutilswindows.cpp").read_text(encoding="utf-8")
        import_controller = (REPO_ROOT / "client/core/controllers/selfhosted/importController.cpp").read_text(encoding="utf-8")
        self.assertIn("bool m_blockIpv6Traffic = false", interface_config)
        self.assertIn('obj.value("blockIpv6Traffic").toBool(false)', daemon)
        self.assertIn("current.m_blockIpv6Traffic == config.m_blockIpv6Traffic", daemon)
        self.assertIn('logger.error() << JSON_ALLOWEDIPADDRESSRANGES << "must not be empty"', daemon)
        self.assertIn("auto peer_cleanup_guard = qScopeGuard", daemon)
        self.assertIn("peer_cleanup_guard.dismiss()", daemon)
        self.assertIn("QMultiMap<QString, quint64> m_ipv6BlockRules", firewall_h)
        self.assertIn("blockIpv6TrafficForPeer", firewall_h)
        self.assertIn("m_ipv6BlockRules.contains(peer)", firewall)
        self.assertIn("m_ipv6BlockRules.insert(peer, filterId)", firewall)
        self.assertIn("m_ipv6BlockRules.remove(pubkey)", firewall)
        self.assertIn('blockTrafficTo(IPAddress("::/0"), LOW_WEIGHT', firewall)
        self.assertIn("m_firewall->blockIpv6TrafficForPeer(config.m_serverPublicKey)", wg_windows)
        self.assertIn("Failed to block unavailable IPv6 traffic", wg_windows)
        self.assertIn("const int separatorIndex = trimmedLine.indexOf('=')", import_controller)
        self.assertIn('split(QRegularExpression("\\\\s*,\\\\s*"), Qt::SkipEmptyParts)', import_controller)

        self.assertIn("processAddressFamilies", protocol_config)
        self.assertIn("addresses.removeIf { it.isIpv6 }", protocol_config)
        self.assertIn("dnsServers.removeIf { it is Inet6Address }", protocol_config)
        self.assertIn("config.contains(configKey::allowedIps) && config[configKey::allowedIps].isArray()", ios_controller)
        self.assertIn("m_rawConfig.contains(configKey::serverIpv6Available)", ios_controller)
        self.assertIn('allowed_ips.append("::/0")', ios_controller)

    def test_site_split_rejects_broad_and_special_bypass_routes(self) -> None:
        router_win = (REPO_ROOT / "service/server/router_win.cpp").read_text(encoding="utf-8")
        vpn_connection = (REPO_ROOT / "client/vpnConnection.cpp").read_text(encoding="utf-8")
        connection_controller = (
            REPO_ROOT / "client/core/controllers/connectionController.cpp"
        ).read_text(encoding="utf-8")

        for source in (router_win, vpn_connection):
            self.assertIn("minPublicBypassPrefixLength = 16", source)
            self.assertIn("minLocalBypassPrefixLength = 24", source)
            self.assertIn("routeOverlapsIpv4Range", source)
            self.assertIn("routeOverlapsRange", source)
            self.assertIn("localOrServiceRoute", source)
            self.assertIn("? minLocalBypassPrefixLength", source)
            self.assertIn(": minPublicBypassPrefixLength", source)
            self.assertIn("prefixLength >= minPrefixLength", source)
            self.assertIn("inRange(0x0a000000u, 8)", source)
            self.assertIn("inRange(0xac100000u, 12)", source)
            self.assertIn("inRange(0xc0a80000u, 16)", source)
            self.assertIn("inRange(0x64400000u, 10)", source)
            self.assertIn("routeOverlapsRange(0xc01f0000u, 24)", source)
            self.assertIn("routeOverlapsRange(0xc01fc400u, 24)", source)
            self.assertIn("routeOverlapsRange(0xc034c100u, 24)", source)
            self.assertIn("routeOverlapsRange(0xc0586300u, 24)", source)
            self.assertIn("routeOverlapsRange(0xc0af3000u, 24)", source)
            self.assertIn("routeOverlapsRange(0xc6336400u, 24)", source)
            self.assertIn("routeOverlapsRange(0xcb007100u, 24)", source)
            self.assertIn("routeOverlapsRange(0xe0000000u, 4)", source)
            self.assertIn("routeOverlapsRange(0xf0000000u, 4)", source)

        self.assertIn("enum class SplitTunnelRouteSource", vpn_connection)
        self.assertIn("SplitTunnelRouteSource::Client && !isRoutableSplitTunnelRoute(route)", vpn_connection)
        self.assertIn("SplitTunnelRouteSource::ServerManaged", vpn_connection)
        self.assertIn("auto activeClientRoutes = QSharedPointer<QSet<QString>>::create()", vpn_connection)
        self.assertEqual(
            len(
                re.findall(
                    r"if\s*\(\s*!activeClientRoutes->contains\(route\)\s*&&\s*"
                    r"!activeManagedRoutes->contains\(route\)\s*\)",
                    vpn_connection,
                )
            ),
            1,
        )
        normalized_runtime = ManagedRoutesSourceContractTests.function_body(
            vpn_connection,
            "QStringList VpnConnection::normalizedManagedRoutesForRuntime(",
        )
        self.assertIn("const QSet<QString> localSet", normalized_runtime)
        self.assertIn(
            "!localSet.contains(route) && !result.contains(route)",
            normalized_runtime,
        )
        self.assertGreaterEqual(
            vpn_connection.count("normalizedManagedRoutesForRuntime("), 5
        )
        self.assertIn("addTrustedRoutesWithReceipt(gw, managedOnlyRoutes)", vpn_connection)
        self.assertGreaterEqual(vpn_connection.count("iface->routeAddTrustedList("), 2)
        self.assertIn("iface->routeAddList(gw, newClientRoutes)", vpn_connection)
        self.assertNotIn("iface->routeAddTrustedList(gw, managedIps)", vpn_connection)
        self.assertNotIn("managedVpnSitesForRouting(", vpn_connection)
        self.assertIn(
            "managedVpnSitesForRouting(serverIndex, routeMode)",
            connection_controller,
        )
        self.assertGreaterEqual(
            connection_controller.count(
                "managedSplitTunnelIpsForSync(serverIndex, RouteMode::VpnAllExceptSites)"
            ),
            3,
        )

        ipc_interface = (REPO_ROOT / "ipc/ipc_interface.rep").read_text(encoding="utf-8")
        ipc_server = (REPO_ROOT / "ipc/ipcserver.cpp").read_text(encoding="utf-8")
        router = (REPO_ROOT / "service/server/router.cpp").read_text(encoding="utf-8")
        self.assertIn("routeAddTrustedList", ipc_interface)
        self.assertIn("Router::routeAddTrustedList", ipc_server)
        self.assertIn("RouterWin::Instance().routeAddTrustedList(gw, managedRoutes)", router)
        self.assertIn("validateRoutes && !isRouteAddCandidate(ipWithMask)", router_win)
        self.assertIn("skipping invalid trusted split route", router_win)

    def test_selfhosted_release_documents_own_monotonic_versioning(self) -> None:
        cmake = (REPO_ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
        headless_cmake = (REPO_ROOT / "headless/CMakeLists.txt").read_text(encoding="utf-8")
        readme = (REPO_ROOT / "deploy/selfhosted_updates/README.md").read_text(encoding="utf-8")
        client_rc = (REPO_ROOT / "client/platforms/windows/amneziavpn.rc.in").read_text(encoding="utf-8")
        service_rc = (REPO_ROOT / "service/server/amneziavpn-service.rc.in").read_text(encoding="utf-8")

        self.assertIn("set(AMNEZIAVPN_VERSION 5.0.1.37)", cmake)
        self.assertIn("set(APP_ANDROID_VERSION_CODE 2185)", cmake)
        self.assertIn('set(HEADLESS_BUILD_VERSION "5.0.1.37")', headless_cmake)
        self.assertIn("current self-hosted release line is `5.0.1.37`", readme)
        self.assertIn("`versionCode` `2185`", readme)
        self.assertIn("routing_degraded", readme)
        self.assertIn("`10.8.1.0/24` remains", readme)
        self.assertIn("own monotonically increasing app version", readme)
        self.assertIn("never update backward to an older fork release", readme)
        product_version = (
            "PRODUCTVERSION  @CMAKE_PROJECT_VERSION_MAJOR@,@CMAKE_PROJECT_VERSION_MINOR@,"
            "@CMAKE_PROJECT_VERSION_PATCH@,@CMAKE_PROJECT_VERSION_TWEAK@"
        )
        self.assertIn(product_version, client_rc)
        self.assertIn(product_version, service_rc)
        self.assertIn("5.0.1.16", readme)
        self.assertIn("historical", readme.lower())

    def test_headless_update_restart_is_non_blocking(self) -> None:
        update_manager = (
            REPO_ROOT / "headless/headlessUpdateManager.cpp"
        ).read_text(encoding="utf-8")
        self.assertIn(
            'QStringLiteral("systemd-run")',
            update_manager,
        )

        self.assertIn('startDetached', update_manager)
        self.assertIn('QStringLiteral("--collect")', update_manager)
        self.assertIn('QStringLiteral("--no-block")', update_manager)
        self.assertIn('QStringLiteral("restart_pending")', update_manager)
        self.assertIn('headless restart receipt cannot be persisted', update_manager)
        self.assertIn('headless update source is not a regular file', update_manager)
        self.assertNotIn(
            '{ QStringLiteral("restart"), QString::fromLatin1(UpdateServiceName) }',
            update_manager,
        )

    def test_headless_batch_staging_uses_validated_runtime_root(self) -> None:
        runner = (REPO_ROOT / "headless/vpnBackend.cpp").read_text(encoding="utf-8")
        runner_header = (REPO_ROOT / "headless/vpnBackend.h").read_text(encoding="utf-8")
        daemon = (REPO_ROOT / "headless/daemon.cpp").read_text(encoding="utf-8")
        service = (REPO_ROOT / "headless/amneziad.service.in").read_text(encoding="utf-8")
        self.assertIn('QStringLiteral("/run/amnezia")', runner)
        self.assertIn("isSecureWritableDirectory", runner)
        self.assertIn("isSymLink", runner)
        self.assertIn("geteuid", runner)
        self.assertIn("WriteGroup", runner)
        self.assertIn("WriteOther", runner)
        self.assertIn("setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner)", runner)
        self.assertIn('QStringLiteral("temporary")', runner)
        self.assertIn("MaxCapturedProbeStdout = 1024 * 1024", runner)
        self.assertIn("MaxCapturedProbeStderr = 4096", runner)
        self.assertIn('QStringLiteral("probe output exceeded safe limit")', runner)
        self.assertNotIn("readAllStandardOutput().left(8192)", runner)
        self.assertIn("RealCommandRunner(QString stagingRoot", runner_header)
        self.assertIn("std::make_shared<RealCommandRunner>(stagingRoot)", daemon)
        self.assertIn("--staging-root /run/amnezia", service)
        self.assertIn("ReadWritePaths=/run/amnezia", service)

    def test_headless_update_archive_has_two_managed_files_and_provisioning_is_separate(self) -> None:
        update_manager = (REPO_ROOT / "headless/headlessUpdateManager.cpp").read_text(encoding="utf-8")
        build_script = (REPO_ROOT / "deploy/headless/build_headless_release.sh").read_text(encoding="utf-8")
        managed_files_start = update_manager.index("const QStringList &managedPayloadFiles()")
        managed_files_end = update_manager.index("QString utcNow()", managed_files_start)
        managed_files = update_manager[managed_files_start:managed_files_end]
        self.assertIn('QStringLiteral("amneziad"), QStringLiteral("amnezia-cli")', managed_files)
        self.assertNotIn('QStringLiteral("amneziad.service")', managed_files)
        self.assertIn("amneziad amnezia-cli", build_script)
        archive_start = build_script.index('tar --create --gzip --file "$ARCHIVE_TMP"')
        archive_end = build_script.index('sha256sum "$ARCHIVE"', archive_start)
        self.assertNotIn("amneziad.service", build_script[archive_start:archive_end])
        self.assertIn('sha256sum install_headless.sh', build_script)
        self.assertIn("headless-package", build_script)
        self.assertIn("amneziad.service", build_script)
        self.assertIn('"schema":2', build_script)
        self.assertIn('"codenames":["jammy"]', build_script)
        self.assertIn('"codenames":["noble"]', build_script)
        self.assertIn('"backendModes"', build_script)
        local_release = (REPO_ROOT / "deploy/selfhosted_updates/local_release.ps1").read_text(encoding="utf-8")
        self.assertIn('@("windows", "linux", "android", "headless")', local_release)
        self.assertIn('PSBoundParameters.ContainsKey("BuildPlatform")', local_release)
        self.assertIn('$headlessArtifactPresent', local_release)
        self.assertIn('"linux-headless-x64"', local_release)
        self.assertIn('$BuildPlatform.Count -eq 1 -and $BuildPlatform[0] -eq "headless"', local_release)
        self.assertIn('$RequirePlatform = @("linux-headless-x64")', local_release)

    def test_headless_installer_requires_strict_identity_and_transactional_restore(self) -> None:
        installer = (REPO_ROOT / "deploy/headless/install_headless.sh").read_text(encoding="utf-8")
        for marker in (
            'SERVICE_PATH=""',
            'service exists in both /etc and /lib',
            'upgrade requires exactly one complete installation identity',
            'ELF64',
            'runtime dependency alternatives are not satisfied',
            'readelf -h',
            'receipt is not trusted',
            'systemd enabled/active state was not preserved',
            'headless-recovery-required',
        ):
            self.assertIn(marker, installer)

    def test_headless_route_cleanup_is_transactional_and_probes_orphans(self) -> None:
        reconciler = (REPO_ROOT / "headless/linuxRouteReconciler.cpp").read_text(encoding="utf-8")
        self.assertIn("QStringList removedRoutes", reconciler)
        self.assertIn("restoreRoutes(previousInterface, removedRoutes)", reconciler)
        self.assertIn('QStringLiteral(".recovery-required")', reconciler)
        self.assertIn("readRuleSnapshot()", reconciler)
        self.assertIn("Retire stale allow-list rules before reusing priority 1000", reconciler)
        self.assertIn("restoreRemovedPreviousBypassRoutes", reconciler)
        self.assertNotIn("priorityWasFreedForReplacement", reconciler)
        self.assertIn("runBatch", reconciler)
        self.assertIn("FullTunnelRuleBatchSize", reconciler)
        self.assertIn("FullTunnelBypassPreferredPriority", reconciler)
        self.assertIn("only-forward receipt", reconciler)
        self.assertIn("selectedRulesValid", reconciler)
        self.assertIn("postcondition snapshot", reconciler)
        self.assertIn("from\\\\s+all", reconciler)
        controller = (REPO_ROOT / "headless/headlessRoutingController.cpp").read_text(encoding="utf-8")
        self.assertIn("fallbackToOnlyForward", controller)
        self.assertIn('QStringLiteral("routing_degraded")', controller)
        self.assertIn("routingDegraded", controller)
        self.assertIn("stale full-tunnel allow-list rule removal failed", reconciler)
        headless_readme = (REPO_ROOT / "headless/README.md").read_text(encoding="utf-8")
        self.assertIn("безопасный `only-forward` fallback", headless_readme)
        self.assertIn("`10.8.1.0/24`", headless_readme)
        self.assertIn("обычный интернет", headless_readme)
        self.assertIn("`routing_degraded`", headless_readme)
        self.assertIn("`proto 2`", headless_readme)
        self.assertIn("`scope 253`", headless_readme)
        self.assertIn("`docker0`, `br-*`", headless_readme)
        self.assertIn("`187` или `isis`", headless_readme)
        self.assertIn("`186`, который может отображаться как `186` или `bgp`", headless_readme)
        self.assertIn("rejected-protocol diagnostics", headless_readme)
        self.assertIn("CAP_NET_ADMIN", headless_readme)

    def test_managed_routing_transaction_runs_in_one_remote_shell(self) -> None:
        install_controller = (
            REPO_ROOT / "client/core/controllers/selfhosted/installController.cpp"
        ).read_text(encoding="utf-8")

        runner = install_controller[
            install_controller.index("auto runPublishingScript ="):
            install_controller.index("auto cleanupCandidate =")
        ]
        self.assertIn("sshSession.runScriptInSingleShell", runner)
        self.assertNotIn("sshSession.runScript(credentials, script", runner)
        self.assertIn("output.append(data);", runner)
        self.assertNotIn('data + QStringLiteral("\\n")', runner)

        # libssh callbacks are arbitrary transport chunks, not complete lines.
        # A candidate larger than the 4096-byte read buffer must therefore be
        # reconstructed without injecting separators at chunk boundaries.
        large_candidate = json.dumps(
            {"policy": {"sites": ["x" * 5000]}}, separators=(",", ":")
        )
        chunks = [large_candidate[:4096], large_candidate[4096:]]
        self.assertEqual(json.loads("".join(chunks))["policy"]["sites"][0], "x" * 5000)
        with self.assertRaises(json.JSONDecodeError):
            json.loads("\n".join(chunks))

        stage_index = install_controller.index("errorCode = runPublishingScript(stageScript")
        commit_index = install_controller.index("errorCode = runPublishingScript(commitScript")
        self.assertLess(stage_index, commit_index)
        self.assertIn("if ! sudo mkdir", install_controller)
        self.assertIn("<<'AMNEZIA_ROUTING_STAGE'", install_controller)
        self.assertIn("<<'AMNEZIA_ROUTING_COMMIT'", install_controller)

    def test_managed_routing_queue_reports_rejected_jobs_and_clears_ui(self) -> None:
        sites_controller = (
            REPO_ROOT / "client/ui/controllers/sitesController.cpp"
        ).read_text(encoding="utf-8")
        qml = (
            REPO_ROOT / "client/ui/qml/Pages2/PageSettingsServerManagedSplitTunneling.qml"
        ).read_text(encoding="utf-8")

        rejection = sites_controller[
            sites_controller.index("if (serverIndex < 0 || job.credentials.userName.isEmpty()"):
            sites_controller.index("m_isManagedSplitTunnelingPublishInProgress = true", sites_controller.index("if (serverIndex < 0 || job.credentials.userName.isEmpty()"))
        ]
        self.assertIn("emit managedSplitTunnelingRulesPublishFailed", rejection)
        self.assertIn("emit errorOccurred(reason)", rejection)
        self.assertIn("restoreManagedSplitTunnelingLocalState", rejection)
        self.assertIn("onManagedSplitTunnelingRulesPublishIdle", qml)
        self.assertIn("root.managedPublishPending = false", qml)

    def test_selfhosted_release_has_one_command_rebuild_wrapper(self) -> None:
        readme = (REPO_ROOT / "deploy/selfhosted_updates/README.md").read_text(encoding="utf-8")
        rebuild = (REPO_ROOT / "deploy/selfhosted_updates/rebuild_clients.ps1").read_text(encoding="utf-8")

        self.assertIn("rebuild_clients.ps1 -BuildJobs 24", readme)
        self.assertIn("dist\\selfhosted-release-env.ps1", rebuild)
        self.assertIn("selfhosted_preflight_", rebuild)
        self.assertIn("selfhosted_rebuild_", rebuild)
        self.assertIn("local_release.ps1", rebuild)

    def test_upstream_5_0_0_5_port_keeps_runtime_regressions_fixed(self) -> None:
        page_home = (REPO_ROOT / "client/ui/qml/Pages2/PageHome.qml").read_text(encoding="utf-8")
        tap_controller = (REPO_ROOT / "service/server/tapcontroller_win.cpp").read_text(encoding="utf-8")
        wireguard_windows = (
            REPO_ROOT / "client/platforms/windows/daemon/wireguardutilswindows.cpp"
        ).read_text(encoding="utf-8")
        client_cmake = (REPO_ROOT / "client/CMakeLists.txt").read_text(encoding="utf-8")
        marketplace_updates = (
            REPO_ROOT / "client/ui/controllers/marketplaceUpdateController.cpp"
        ).read_text(encoding="utf-8")
        tun2socks_recipe = (REPO_ROOT / "recipes/tun2socks/conanfile.py").read_text(encoding="utf-8")
        libxray_recipe = (REPO_ROOT / "recipes/amnezia-libxray/conanfile.py").read_text(encoding="utf-8")
        libxray_conandata = (REPO_ROOT / "recipes/amnezia-libxray/conandata.yml").read_text(encoding="utf-8")
        config_keys = (REPO_ROOT / "client/core/utils/constants/configKeys.h").read_text(encoding="utf-8")

        self.assertEqual(page_home.count("property var apiAvailableProtocols:"), 1)
        self.assertEqual(page_home.count("property string apiCurrentProtocol:"), 1)
        self.assertEqual(page_home.count("isApiProtocolSelectionVisible:"), 1)
        self.assertEqual(page_home.count("function protocolDisplayName(protocol)"), 1)
        self.assertIn("function updateApiProtocolState()", page_home)
        self.assertIn("SubscriptionUiController.availableProtocols", page_home)

        self.assertIn('output.contains("No matching devices found")', tap_controller)
        self.assertNotIn('output.contains("No matched devices found")', tap_controller)

        self.assertIn(
            "const QString persistentKeepalive = config.m_persistentKeepalive.isEmpty()",
            wireguard_windows,
        )
        self.assertIn('? QStringLiteral("60")', wireguard_windows)
        self.assertNotIn("WG_KEEPALIVE_PERIOD", wireguard_windows)
        self.assertIn(
            'out << "persistent_keepalive_interval=" << persistentKeepalive << "\\n";',
            wireguard_windows,
        )

        self.assertIn("add_compile_definitions(AMNEZIA_SELFHOSTED_BUILD)", client_cmake)
        self.assertIn(
            "#if defined(AMNEZIA_SELFHOSTED_BUILD)\n"
            "    // A self-hosted release has its own signed update channel",
            marketplace_updates,
        )
        self.assertIn("    return;\n#endif\n\n#if defined(Q_OS_IOS) || defined(Q_OS_ANDROID)", marketplace_updates)

        self.assertIn('go_tmp_dir = os.path.join(self.build_folder, "gotmp")', tun2socks_recipe)
        self.assertIn("os.makedirs(go_tmp_dir, exist_ok=True)", tun2socks_recipe)
        self.assertIn('env.define("GOTMPDIR", go_tmp_dir)', tun2socks_recipe)
        self.assertIn('env.define("TMP", go_tmp_dir)', tun2socks_recipe)
        self.assertIn('env.define("TEMP", go_tmp_dir)', tun2socks_recipe)
        self.assertIn("GO111MODULE=on", tun2socks_recipe)
        self.assertIn("CGO_ENABLED=0", tun2socks_recipe)
        self.assertIn("go build -v", tun2socks_recipe)
        self.assertIn('env="conanbuild"', tun2socks_recipe)

        self.assertIn('version = "1.0.2"', libxray_recipe)
        self.assertIn('"1.0.2":', libxray_conandata)

        for key in (
            "sendPayload",
            "sendPayloadEndpoint",
            "sendPayloadProtocol",
            "sendPayloadTimeoutMs",
            "sendPayloadData",
            "sendPayloadExpectedResponse",
        ):
            self.assertEqual(config_keys.count(f"constexpr QLatin1String {key}("), 1)

    def test_windows_split_tunnel_uses_race_fixed_driver_and_bounded_helper(self) -> None:
        firewall = (REPO_ROOT / "client/platforms/windows/daemon/windowsfirewall.cpp").read_text(encoding="utf-8")
        firewall_header = (REPO_ROOT / "client/platforms/windows/daemon/windowsfirewall.h").read_text(encoding="utf-8")
        split_tunnel = (REPO_ROOT / "client/platforms/windows/daemon/windowssplittunnel.cpp").read_text(encoding="utf-8")
        split_tunnel_header = (REPO_ROOT / "client/platforms/windows/daemon/windowssplittunnel.h").read_text(encoding="utf-8")
        service_main = (REPO_ROOT / "service/server/main.cpp").read_text(encoding="utf-8")
        root_conan = (REPO_ROOT / "conanfile.py").read_text(encoding="utf-8")
        recipe = (REPO_ROOT / "recipes/win-split-tunnel/conanfile.py").read_text(encoding="utf-8")

        self.assertIn("win-split-tunnel v1.3.0.0 at initialization", firewall)
        self.assertIn("0x60090787, 0xcca1, 0x4937", firewall)
        self.assertIn("Amnezia-SplitTunnel-DNS-Sublayer", firewall)
        self.assertIn("Persistent DNS filters shared with the split-tunnel driver", firewall)
        self.assertIn("FwpmEngineClose0(engineHandle)", firewall)
        self.assertIn("blockTrafficOnPort(53, MED_WEIGHT, \"Block all DNS\",\n                          ST_DRIVER_DNS_SUBLAYER_KEY", firewall)
        self.assertIn("FWP_E_SUBLAYER_NOT_FOUND", firewall)
        self.assertIn("baselineExists && dnsExists", firewall)
        self.assertIn("splitTunnelBaselineSublayerKey", firewall_header)
        self.assertIn("splitTunnelDnsSublayerKey", firewall_header)
        self.assertIn("IOCTL_INITIALIZE CTL_CODE(0x8000, 1, METHOD_BUFFERED", split_tunnel)
        self.assertIn("initDriver(driverFile, sublayerGuids)", split_tunnel)
        self.assertIn("sendInitializeIoctl(driverIO, sublayerGuids)", split_tunnel)
        self.assertIn("sendInitializeIoctl(m_driver, m_sublayerGuids)", split_tunnel)
        self.assertNotIn("IOCTL_INITIALIZE, nullptr, 0", split_tunnel)
        self.assertIn("sizeof(SUBLAYER_GUIDS) == 2 * sizeof(GUID)", split_tunnel_header)

        self.assertIn('version = "1.3.0.0"', recipe)
        self.assertIn('self.requires("win-split-tunnel/1.3.0.0")', root_conan)
        self.assertNotIn('self.requires("win-split-tunnel/1.2.5.0")', root_conan)
        self.assertIn("5b6f46cde692acb77ee74b37b9fd3f1678c45a52", recipe)
        self.assertIn("10cf25bbcfe51fd663a1fec88a98e9b858f3a579589bb2ec496b66e4fdd1b201", recipe)
        self.assertIn("6af8b3bfe5aa095d5276187558c7c7d3a3e0c174b34406cd6c4b3f8e6ffa6534", recipe)

        self.assertIn("CONFIGURATION_HELPER_TIMEOUT_MS = 5000", split_tunnel)
        self.assertIn("CreateJobObjectW", split_tunnel)
        self.assertIn("JOB_OBJECT_LIMIT_ACTIVE_PROCESS", split_tunnel)
        self.assertIn("CREATE_SUSPENDED", split_tunnel)
        self.assertIn("CreateFileMappingW", split_tunnel)
        self.assertIn("SetEvent(configuredEvent)", split_tunnel)
        self.assertIn("SetEvent(commitEvent)", split_tunnel)
        self.assertIn("controlEvents = {abortEvent, parentProcess", split_tunnel)
        self.assertIn("stopSignals = {abortEvent, parentProcess}", split_tunnel)
        self.assertEqual(split_tunnel.count("parentStoppedOrAborted()"), 2)
        pre_ioctl_guard = split_tunnel.rfind(
            "parentStoppedOrAborted()",
            0,
            split_tunnel.find("DeviceIoControl(driver, IOCTL_SET_CONFIGURATION"),
        )
        self.assertGreaterEqual(pre_ioctl_guard, 0)
        self.assertGreater(
            pre_ioctl_guard,
            split_tunnel.find("HANDLE driver = openSplitTunnelDriver()"),
        )
        self.assertIn("OpenProcess(SYNCHRONIZE, TRUE, GetCurrentProcessId())", split_tunnel)
        self.assertIn("reapQuarantinedConfigurationHelper", split_tunnel)
        self.assertNotIn("WriteFile(", split_tunnel)
        self.assertIn("quarantineConfigurationHelper", split_tunnel)
        self.assertIn("state is indeterminate until late cleanup completes", split_tunnel)
        self.assertIn("IOCTL_CLEAR_CONFIGURATION", split_tunnel)
        self.assertNotIn("DeviceIoControl(m_driver, IOCTL_SET_CONFIGURATION", split_tunnel)
        self.assertIn("split-tunnel-config-helper", service_main)

    def test_deploy_upload_artifacts_have_stable_names(self) -> None:
        deploy_workflow = read_workflow_if_enabled(REPO_ROOT / ".github/workflows/deploy.yml")
        tag_deploy_workflow = read_workflow_if_enabled(REPO_ROOT / ".github/workflows/tag-deploy.yml")
        if not deploy_workflow and not tag_deploy_workflow:
            return
        required_names = {
            "AmneziaVPN_linux_x64_run",
            "AmneziaVPN_windows_x64_msi",
            "AmneziaVPN_windows_x64_exe",
            "AmneziaVPN_android_universal_apk",
            "AmneziaVPN_android_aab",
            "AmneziaVPN_android_arm64-v8a_apk",
            "AmneziaVPN_android_armeabi-v7a_apk",
            "AmneziaVPN_android_x86_apk",
            "AmneziaVPN_android_x86_64_apk",
        }
        for name in required_names:
            self.assertIn(f"name: {name}", deploy_workflow)
        self.assertIn("uses: actions/upload-artifact@v7", tag_deploy_workflow)
        self.assertIn("name: AmneziaVPN_android_release_apk", tag_deploy_workflow)
        self.assertIn("archive: false", tag_deploy_workflow)
        self.assertNotIn("uses: actions/upload-artifact@v3", deploy_workflow + tag_deploy_workflow)
        self.assertNotIn("uses: actions/checkout@v3", tag_deploy_workflow)
        self.assertNotIn("uses: actions/setup-java@v3", tag_deploy_workflow)

        lines = deploy_workflow.splitlines()
        for index, line in enumerate(lines):
            if "uses: actions/upload-artifact@v7" not in line:
                continue
            block = "\n".join(lines[index:index + 8])
            self.assertIn("name:", block, f"upload-artifact@v7 step at line {index + 1} must set a unique name")
        for name in required_names:
            index = next(index for index, line in enumerate(lines) if f"name: {name}" in line)
            block = "\n".join(lines[index:index + 8])
            self.assertIn("if-no-files-found: error", block, f"{name} upload must fail when the expected artifact is missing")

        tag_lines = tag_deploy_workflow.splitlines()
        tag_index = next(index for index, line in enumerate(tag_lines) if "name: AmneziaVPN_android_release_apk" in line)
        tag_block = "\n".join(tag_lines[tag_index:tag_index + 8])
        self.assertIn("if-no-files-found: error", tag_block)

    def test_bundled_publisher_has_pinned_atomic_protocol(self) -> None:
        bootstrapper = (
            REPO_ROOT / "client/core/controllers/selfhosted/selfHostedUpdateBootstrapper.cpp"
        ).read_text(encoding="utf-8")
        bootstrapper_header = (
            REPO_ROOT / "client/core/controllers/selfhosted/selfHostedUpdateBootstrapper.h"
        ).read_text(encoding="utf-8")
        publisher = (SCRIPT_DIR / "publish_bundled_release.sh").read_text(encoding="utf-8")
        resources = (REPO_ROOT / "client/server_scripts/serverScripts.qrc").read_text(encoding="utf-8")

        self.assertIn("PINNED_ROOT='/opt/amnezia/client-updates'", publisher)
        self.assertIn("PINNED_PARENT='/opt/amnezia'", publisher)
        self.assertIn("TRUST_ANCHOR='/opt'", publisher)
        self.assertIn("UPLOAD_PREFIX='/tmp/amnezia-client-updates.'", publisher)
        self.assertIn("flock -x -w 60 9", publisher)
        self.assertIn("MARKER_SHA256='e7f84faa235a87b73f4876438a67069e5e460f405879138e5bb81527dd951bbb'", publisher)
        self.assertIn("require_channel_marker", publisher)
        self.assertIn('as_root mv -T -n -- "$source_tree" "$target_tree"', publisher)
        self.assertIn('as_root diff -qr -- "$source_tree" "$target_tree"', publisher)
        self.assertIn('manifest_tmp_candidate="$PINNED_ROOT/.manifest.$RUN_ID"', publisher)
        self.assertIn("MANIFEST_TMP=$manifest_tmp_candidate", publisher)
        self.assertIn('as_root mv -fT -- "$MANIFEST_TMP" "$PINNED_ROOT/manifest.json"', publisher)
        self.assertIn('as_root sync -f -- "$MANIFEST_TMP"', publisher)
        self.assertIn('as_root sync -f -- "$PINNED_ROOT"', publisher)
        self.assertNotIn("cp -a", publisher)
        self.assertNotIn("manifest.json.tmp", publisher)
        self.assertNotIn('rm -rf -- "$PINNED_ROOT"', publisher)
        self.assertIn("finalize_mode()", publisher)
        self.assertIn("finalize_abort_mode()", publisher)
        self.assertIn("reconcile_mode()", publisher)
        self.assertIn("rollback_mode()", publisher)
        self.assertIn("reconcile_rollback_mode()", publisher)
        self.assertIn("finalize_rollback_mode()", publisher)
        self.assertIn("STATE_MAGIC='amnezia-bundled-publish-state-v1'", publisher)
        self.assertIn("write_publication_state prepared", publisher)
        self.assertIn("write_publication_state committing", publisher)
        self.assertIn("write_publication_state committed", publisher)
        self.assertIn("AMNEZIA_PUBLISH_PREPARE_V1 READY prepared", publisher)
        self.assertIn("AMNEZIA_PUBLISH_COMMIT_V1 APPLIED committed", publisher)
        self.assertIn("AMNEZIA_PUBLISH_RECONCILE_V1", publisher)
        self.assertIn("AMNEZIA_PUBLISH_RECONCILE_ROLLBACK_V1", publisher)
        self.assertIn('as_root sync -f -- "$STATE_TMP"', publisher)
        self.assertIn('as_root mv -fT -- "$STATE_TMP" "$STATE_PATH"', publisher)
        self.assertNotIn("published_manifest_sha256=", publisher)
        self.assertNotIn("rolled_back_manifest_sha256=", publisher)
        self.assertIn('manifest CAS conflict during rollback', publisher)
        self.assertIn('previous-manifest.json', publisher)
        rollback_body = publisher[
            publisher.index("rollback_mode() {") : publisher.index("reconcile_rollback_mode() {")
        ]
        self.assertNotIn('rm -rf -- "$UPLOAD_STAGE"', rollback_body)
        finalize_rollback_body = publisher[
            publisher.index("finalize_rollback_mode() {") : publisher.index("require_tools\n", publisher.index("finalize_rollback_mode() {"))
        ]
        self.assertIn('manifest CAS conflict during rollback finalize', finalize_rollback_body)
        self.assertIn("cleanup_transaction_staging_durably", finalize_rollback_body)

        commit = publisher[
            publisher.index("commit_mode() {") : publisher.index("reconcile_mode() {")
        ]
        self.assertEqual(commit.count('check_cas "$expected" "$candidate"'), 2)
        lock_index = commit.index("create_lock_and_acquire")
        state_read_index = commit.index("read_publication_state", lock_index)
        committing_index = commit.index("write_publication_state committing", state_read_index)
        snapshot_index = commit.index("unable to snapshot candidate manifest", committing_index)
        verified_index = commit.index("manifest staging hash mismatch")
        publish_tree_index = commit.index("publish_immutable_tree", verified_index)
        final_cas_index = commit.index('check_cas "$expected" "$candidate"', publish_tree_index)
        manifest_switch_index = commit.index('mv -fT -- "$MANIFEST_TMP"', final_cas_index)
        committed_index = commit.index("write_publication_state committed", manifest_switch_index)
        self.assertLess(lock_index, state_read_index)
        self.assertLess(state_read_index, committing_index)
        self.assertLess(committing_index, snapshot_index)
        self.assertLess(snapshot_index, verified_index)
        self.assertLess(verified_index, publish_tree_index)
        self.assertLess(publish_tree_index, final_cas_index)
        self.assertLess(final_cas_index, manifest_switch_index)
        self.assertLess(manifest_switch_index, committed_index)

        self.assertIn("QRandomGenerator::system()->generate()", bootstrapper)
        self.assertIn("result.reserve(48)", bootstrapper)
        self.assertIn("decoded.toBase64(options) != encoded", bootstrapper)
        self.assertIn('QStringLiteral("/tmp/amnezia-client-updates.%1").arg(runId)', bootstrapper)
        self.assertIn("parseVerifiedManifest(currentManifestData", bootstrapper)
        self.assertIn("validateBundledPublishTransition", bootstrapper)
        self.assertIn("exactMachineReceipt", bootstrapper)
        self.assertIn('runPublisher(QStringLiteral("reconcile"))', bootstrapper)
        self.assertIn('runPublisher(QStringLiteral("reconcile-rollback"))', bootstrapper)
        self.assertNotIn("probePublishedManifestSha256", bootstrapper)
        self.assertNotIn("remoteStageIsAbsent", bootstrapper)
        self.assertIn("AppliedWithoutAcknowledgement", bootstrapper)
        self.assertIn("Indeterminate", bootstrapper)
        self.assertNotIn("capturePublisherOutput,\n                    capturePublisherOutput", bootstrapper)
        self.assertIn("VersionDowngrade", bootstrapper_header)
        self.assertIn("GenerationRebound", bootstrapper_header)
        self.assertIn("BundledMutationReconciliation", bootstrapper_header)
        self.assertNotIn("remote_tmp=$(mktemp", bootstrapper)
        prepare_index = bootstrapper.index('runPublisher(QStringLiteral("prepare"))')
        installer_index = bootstrapper.index("if (!installOrRefreshUpdateHost())", prepare_index)
        commit_index = bootstrapper.index('runPublisher(QStringLiteral("commit"))', installer_index)
        verify_index = bootstrapper.index("if (!verifyRemoteUpdateHost())", commit_index)
        rollback_index = bootstrapper.index('runPublisher(QStringLiteral("rollback"))', verify_index)
        finalize_rollback_index = bootstrapper.index(
            'QStringLiteral("finalize-rollback")', rollback_index
        )
        finalize_index = bootstrapper.index('QStringLiteral("finalize")', verify_index)
        self.assertLess(prepare_index, installer_index)
        self.assertLess(installer_index, commit_index)
        self.assertLess(commit_index, verify_index)
        self.assertIn("previous-manifest.json", bootstrapper)
        self.assertGreater(rollback_index, verify_index)
        self.assertGreater(finalize_rollback_index, rollback_index)
        self.assertGreater(finalize_index, verify_index)
        recovery_required_index = bootstrapper.index(
            "RECOVERY_REQUIRED: bundled candidate verification", rollback_index
        )
        recovery_branch = bootstrapper[rollback_index:bootstrapper.index("return false;", recovery_required_index) + 13]
        self.assertIn('<< "run_id=" << runId', recovery_branch)
        self.assertIn('<< "remote_stage=" << remoteTmp', recovery_branch)
        self.assertIn("preserving durable state and the remote recovery stage", recovery_branch)
        self.assertNotIn("cleanupRemoteTmp();", recovery_branch)
        self.assertIn(
            '<file alias="update_host/publish_bundled_release.sh">../../deploy/selfhosted_updates/publish_bundled_release.sh</file>',
            resources,
        )

    def test_bootstrapper_verifies_uploaded_installer_before_execution(self) -> None:
        bootstrapper = (
            REPO_ROOT / "client/core/controllers/selfhosted/selfHostedUpdateBootstrapper.cpp"
        ).read_text(encoding="utf-8")
        runner = (SCRIPT_DIR / "run_verified_update_host_installer.sh").read_text(encoding="utf-8")
        publisher = (SCRIPT_DIR / "publish_bundled_release.sh").read_text(encoding="utf-8")
        resources = (REPO_ROOT / "client/server_scripts/serverScripts.qrc").read_text(encoding="utf-8")

        self.assertIn("kVerifiedInstallHostRunner", bootstrapper)
        self.assertIn("installScriptSha256", bootstrapper)
        self.assertIn("verifiedRunnerSha256", bootstrapper)
        self.assertIn("verifiedRunner.toBase64()", bootstrapper)
        self.assertIn("/opt/amnezia/.install-server-update-host.%1", bootstrapper)
        self.assertIn("amnezia-verified-installer", bootstrapper)
        self.assertIn(
            "docker.io/library/busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662",
            bootstrapper,
        )
        self.assertNotIn(
            'QStringLiteral("sh %1 %2").arg(shellQuote(remoteInstallScript), shellQuote(serverDir))',
            bootstrapper,
        )
        upload_index = bootstrapper.index(
            "uploadFileToHost(credentials, installScript, remoteInstallScript)"
        )
        verification_index = bootstrapper.index("verifiedInstallCommand", upload_index)
        execution_index = bootstrapper.index('sh -c \\"$verifier\\" amnezia-verified-installer', verification_index)
        self.assertLess(upload_index, verification_index)
        self.assertLess(verification_index, execution_index)

        uploaded_hash_index = runner.index('sha256sum -- "$UPLOADED_INSTALLER"')
        seal_index = runner.index('as_root install -o 0 -g 0 -m 0444', uploaded_hash_index)
        sealed_hash_index = runner.index('as_root sha256sum -- "$SEALED_INSTALLER"', seal_index)
        sealed_execution_index = runner.index('timeout --signal=TERM --kill-after=60s', sealed_hash_index)
        self.assertLess(uploaded_hash_index, seal_index)
        self.assertLess(seal_index, sealed_hash_index)
        self.assertLess(sealed_hash_index, sealed_execution_index)
        self.assertIn('sudo -n -- "$@"', runner)
        self.assertIn('sudo -n -- "$@"', publisher)
        self.assertNotIn('sudo "$@"', runner)
        self.assertNotIn('sudo "$@"', publisher)
        self.assertIn('INSTALL_TIMEOUT_SECONDS=900', runner)
        self.assertIn("kInstallerOuterSshTimeoutMs = 20 * 60 * 1000", bootstrapper)
        self.assertIn("kInstallerOuterSshTimeoutMs);", bootstrapper)
        self.assertIn(
            '<file alias="update_host/run_verified_update_host_installer.sh">../../deploy/selfhosted_updates/run_verified_update_host_installer.sh</file>',
            resources,
        )

    def test_ssh_transport_runs_verifier_in_one_bounded_deadlock_safe_shell(self) -> None:
        ssh_client_h = (REPO_ROOT / "client/core/utils/selfhosted/sshClient.h").read_text(encoding="utf-8")
        ssh_client = (REPO_ROOT / "client/core/utils/selfhosted/sshClient.cpp").read_text(encoding="utf-8")
        ssh_session = (REPO_ROOT / "client/core/utils/selfhosted/sshSession.cpp").read_text(encoding="utf-8")
        focused_state_test = (
            REPO_ROOT
            / "client/tests/selfhosted_update_bootstrapper_path/tst_selfhosted_update_bootstrapper_path.cpp"
        ).read_text(encoding="utf-8")
        bootstrapper = (
            REPO_ROOT / "client/core/controllers/selfhosted/selfHostedUpdateBootstrapper.cpp"
        ).read_text(encoding="utf-8")

        self.assertIn("DefaultConnectTimeoutMs = 30 * 1000", ssh_client_h)
        self.assertIn("DefaultChannelOpenTimeoutMs = 30 * 1000", ssh_client_h)
        self.assertIn("DefaultCommandTimeoutMs = 15 * 60 * 1000", ssh_client_h)
        self.assertIn("DefaultScpTimeoutMs = 15 * 60 * 1000", ssh_client_h)
        self.assertIn("std::atomic_bool m_cancelRequested", ssh_client_h)
        self.assertIn("std::atomic<qint64> m_operationDeadlineMs", ssh_client_h)
        self.assertIn("ErrorCode beginOperation(int timeoutMs)", ssh_client_h)
        self.assertIn("detail::boundaryState", ssh_client)
        self.assertIn("detail::cappedPhaseDeadline", ssh_client)
        self.assertEqual(ssh_client.count("m_operationDeadlineMs.store(deadlineMs"), 1)
        self.assertNotIn("QtConcurrent", ssh_client)
        self.assertNotIn("QFutureWatcher", ssh_client)
        self.assertIn("QHostInfo::lookupHost", ssh_client)
        self.assertIn("QHostInfo::abortHostLookup", ssh_client)
        self.assertIn("numericHost", ssh_client)
        self.assertNotIn('credentials.userName + "@"', ssh_client)
        self.assertIn('QByteArrayLiteral("sh -s --")', ssh_client)
        self.assertIn("ssh_channel_read_nonblocking", ssh_client)
        self.assertIn("standardError ? 1 : 0", ssh_client)
        self.assertIn("ssh_set_blocking(m_session, 0)", ssh_client)
        self.assertIn("m_cancelRequested.load", ssh_client)
        execute_channel = ssh_client[
            ssh_client.index("ErrorCode Client::executeChannel"):
            ssh_client.index("ErrorCode Client::writeResponse")
        ]
        self.assertNotIn("drainStream", execute_channel)
        self.assertIn("stderrFirst = !stderrFirst", execute_channel)
        self.assertIn("callbacks.channel_exit_status_function = channelExitStatusCallback", execute_channel)
        self.assertNotIn("ssh_channel_get_exit_status", ssh_client)
        self.assertIn("openResult != SSH_AGAIN", execute_channel)
        self.assertIn("requestResult != SSH_AGAIN", execute_channel)
        self.assertIn("boundaryError(openDeadlineMs)", execute_channel)
        self.assertIn("boundaryError(commandDeadlineMs)", execute_channel)
        self.assertIn("detail::classifyWriteResult(bytesWritten, SSH_AGAIN)", execute_channel)
        self.assertIn("eofResult != SSH_AGAIN", execute_channel)
        self.assertIn("terminalObserved = remoteEof || remoteClosed", execute_channel)
        self.assertIn("stdoutDrained", execute_channel)
        self.assertIn("stderrDrained", execute_channel)
        window_query = execute_channel.index("ssh_channel_window_size")
        bounded_write = execute_channel.index("detail::boundedWriteSize", window_query)
        write_call = execute_channel.index("ssh_channel_write", bounded_write)
        self.assertLess(window_query, bounded_write)
        self.assertLess(bounded_write, write_call)
        self.assertIn("if (attemptSize > 0)", execute_channel[bounded_write:write_call])
        write_response = ssh_client[
            ssh_client.index("ErrorCode Client::writeResponse"):
            ssh_client.index("ErrorCode Client::closeChannel")
        ]
        self.assertIn("m_pendingResponse.append(response)", write_response)
        self.assertNotIn("ssh_channel_write", write_response)
        upload = ssh_client[
            ssh_client.index("ErrorCode Client::scpFileCopy"):
            ssh_client.index("ErrorCode Client::fromLibsshErrorCode")
        ]
        self.assertNotIn("ssh_scp_", ssh_client)
        self.assertIn("QTemporaryFile snapshot", upload)
        self.assertIn("QCryptographicHash snapshotHash", upload)
        self.assertIn("_commit(snapshot.handle())", upload)
        self.assertIn("::fsync(snapshot.handle())", upload)
        self.assertIn("executeChannel(\n                command.toUtf8(), {}, snapshotPath, true", upload)
        self.assertIn('actual_size=$(wc -c < \\"$upload_tmp\\")', upload)
        self.assertIn('upload_parent=${upload_target%/*}', upload)
        self.assertIn('sync -f -- \\"$sync_path\\"', upload)
        self.assertIn('fsync \\"$sync_path\\" || exit 74', upload)
        self.assertIn('"exit 69; }; "', upload)
        self.assertIn('mv -fT -- \\"$upload_tmp\\" \\"$upload_target\\"', upload)
        self.assertIn('AMNEZIA_UPLOAD_V1\\t', upload)
        self.assertIn("trap cleanup_upload EXIT HUP INT TERM", upload)
        self.assertIn("Reconnect under the same absolute deadline", upload)
        self.assertIn("reconcileCommand", upload)
        reconcile = upload[upload.index("const QString reconcileCommand"):]
        self.assertIn('test -d \\"$upload_parent\\" && ! test -L \\"$upload_parent\\"', reconcile)
        self.assertIn('sync -f -- \\"$sync_path\\"', reconcile)
        self.assertIn('fsync \\"$sync_path\\" || exit 74', reconcile)
        self.assertIn('durable_sync \\"$upload_parent\\"', reconcile)
        self.assertIn("detail::uploadReceiptPrintCommand()", upload)
        self.assertNotIn("printf '%%s", upload)
        self.assertNotIn("printf '%%s", bootstrapper)
        self.assertIn("overwriteMode != ScpOverwriteExisting", upload)
        self.assertIn("ErrorCode::NotImplementedError", upload)
        close_channel = ssh_client[
            ssh_client.index("ErrorCode Client::closeChannel"):
            ssh_client.index("ErrorCode Client::scpFileCopy")
        ]
        self.assertIn("detail::teardownMode", close_channel)
        self.assertIn("abortSession()", close_channel)
        self.assertIn("ssh_silent_disconnect(m_session)", ssh_client)

        # This executable test includes the production state decisions instead
        # of duplicating them in a Python-only fake.
        self.assertIn("AMNEZIA_SSH_CLIENT_STATE_ONLY", focused_state_test)
        self.assertIn("boundedWriteSize(0, 4096, 2048) == 0", focused_state_test)
        self.assertIn("ExitState::MissingStatus", focused_state_test)
        self.assertIn("BoundaryState::Cancelled", focused_state_test)
        single_shell = ssh_session[
            ssh_session.index("ErrorCode SshSession::runScriptInSingleShell"):
            ssh_session.index("ErrorCode SshSession::runContainerScript")
        ]
        self.assertIn("m_sshClient.executeScript(script", single_shell)
        self.assertNotIn('script.split("\\n"', single_shell)
        self.assertLess(single_shell.index("beginOperation(timeoutMs)"), single_shell.index("connectToHost(credentials)"))
        self.assertLess(single_shell.index("connectToHost(credentials)"), single_shell.index("executeScript(script"))
        self.assertLess(single_shell.index("executeScript(script"), single_shell.index("finishOperation(error)"))
        verifier = bootstrapper[
            bootstrapper.index("const auto verifyRemoteUpdateHost"):
            bootstrapper.index("QByteArray publishMetadata")
        ]
        self.assertIn("sshSession.runScriptInSingleShell", verifier)

    def test_bootstrapper_install_and_verification_output_is_bounded_and_not_logged(self) -> None:
        bootstrapper = (
            REPO_ROOT / "client/core/controllers/selfhosted/selfHostedUpdateBootstrapper.cpp"
        ).read_text(encoding="utf-8")
        bootstrapper_header = (
            REPO_ROOT / "client/core/controllers/selfhosted/selfHostedUpdateBootstrapper.h"
        ).read_text(encoding="utf-8")
        focused_state_test = (
            REPO_ROOT
            / "client/tests/selfhosted_update_bootstrapper_path/tst_selfhosted_update_bootstrapper_path.cpp"
        ).read_text(encoding="utf-8")

        installer = bootstrapper[
            bootstrapper.index("const auto installOrRefreshUpdateHost"):
            bootstrapper.index("const auto verifyRemoteUpdateHost")
        ]
        verifier = bootstrapper[
            bootstrapper.index("const auto verifyRemoteUpdateHost"):
            bootstrapper.index("QByteArray publishMetadata")
        ]

        self.assertIn("maximumBootstrapPhaseOutputBytes = 64 * 1024", bootstrapper_header)
        self.assertIn("accountBoundedRemoteOutput", bootstrapper_header)
        self.assertIn("chunkBytes > maximumBytes - acceptedBytes", bootstrapper_header)
        for phase in (installer, verifier):
            self.assertIn("accountBoundedRemoteOutput", phase)
            self.assertIn("ErrorCode::ReadError", phase)
            self.assertIn('<< "phase"', phase)
            self.assertIn('<< "errorCode"', phase)
        self.assertNotIn("installOutput +=", installer)
        self.assertNotIn("verifyOutput +=", verifier)
        self.assertNotIn("installOutput.trimmed()", installer)
        self.assertNotIn("verifyOutput.trimmed()", verifier)
        self.assertIn("acceptedRemoteOutputBytes == maximumBootstrapPhaseOutputBytes", focused_state_test)
        self.assertIn("!accountBoundedRemoteOutput", focused_state_test)
        self.assertIn("multibyteRemoteOutputBytes == 3", focused_state_test)

    def test_ssh_host_key_pinning_is_fail_closed_before_auth_and_reaches_all_builds(self) -> None:
        ssh_client = (REPO_ROOT / "client/core/utils/selfhosted/sshClient.cpp").read_text(encoding="utf-8")
        pin_policy = (REPO_ROOT / "client/core/utils/selfhosted/sshHostKeyPin.cpp").read_text(encoding="utf-8")
        common_structs = (REPO_ROOT / "client/core/utils/commonStructs.h").read_text(encoding="utf-8")
        admin_config = (
            REPO_ROOT / "client/core/models/selfhosted/selfHostedAdminServerConfig.cpp"
        ).read_text(encoding="utf-8")
        client_cmake = (REPO_ROOT / "client/CMakeLists.txt").read_text(encoding="utf-8")
        local_release = (SCRIPT_DIR / "local_release.ps1").read_text(encoding="utf-8")
        setup_release = (SCRIPT_DIR / "setup_release_workstation.ps1").read_text(encoding="utf-8")
        setup_qml = (REPO_ROOT / "client/ui/qml/Pages2/PageSetupWizardCredentials.qml").read_text(
            encoding="utf-8"
        )
        install_ui = (REPO_ROOT / "client/ui/controllers/selfhosted/installUiController.cpp").read_text(
            encoding="utf-8"
        )
        install_controller = (
            REPO_ROOT / "client/core/controllers/selfhosted/installController.cpp"
        ).read_text(encoding="utf-8")

        connect = ssh_client[
            ssh_client.index("ErrorCode Client::connectToHost"):
            ssh_client.index("void Client::abortSession")
        ]
        pin_resolution = connect.index("sshHostKeyPin::resolve")
        dns_resolution = connect.index("resolveHostName")
        network_connect = connect.index("ssh_connect")
        key_verification = connect.index("verifyServerHostKey", network_connect)
        private_key_import = connect.index("ssh_pki_import_privkey_base64")
        password_auth = connect.index("ssh_userauth_password")
        self.assertLess(pin_resolution, dns_resolution)
        self.assertLess(dns_resolution, network_connect)
        self.assertLess(network_connect, key_verification)
        self.assertLess(key_verification, private_key_import)
        self.assertLess(key_verification, password_auth)
        self.assertIn("SshHostKeyMissingError", ssh_client)
        self.assertIn("SshHostKeyMalformedError", ssh_client)
        self.assertIn("SshHostKeyMismatchError", ssh_client)
        self.assertIn("m_credentials.sshHostKeyFingerprint == effectiveCredentials.sshHostKeyFingerprint", connect)
        self.assertIn("ssh_get_server_publickey", ssh_client)
        self.assertIn("SSH_PUBLICKEY_HASH_SHA256", ssh_client)
        self.assertIn("matchesFingerprint", ssh_client)
        self.assertNotIn("ssh_session_update_known_hosts", ssh_client)
        self.assertNotIn("ssh_session_is_known_server", ssh_client)
        self.assertIn("AbortOnBase64DecodingErrors", pin_policy)
        self.assertIn("difference |=", pin_policy)

        self.assertIn("QString sshHostKeyFingerprint", common_structs)
        self.assertIn("creds.sshHostKeyFingerprint = sshHostKeyFingerprint", admin_config)
        self.assertIn("configKey::sshHostKeyFingerprint", admin_config)
        self.assertIn("SELFHOSTED_SSH_TRUSTED_HOST and SELFHOSTED_SSH_TRUSTED_HOST_KEY_SHA256 must be supplied together", client_cmake)
        self.assertIn("add_compile_definitions(", client_cmake)
        for script in (local_release, setup_release):
            self.assertIn("Assert-SshHostKeyPinPair", script)
            self.assertIn("SELFHOSTED_SSH_TRUSTED_HOST_KEY_SHA256", script)
        self.assertIn("export SELFHOSTED_SSH_TRUSTED_HOST=$(Quote-Sh $SshTrustedHost)", local_release)
        self.assertIn("export SELFHOSTED_SSH_TRUSTED_HOST_KEY_SHA256=$(Quote-Sh $SshTrustedHostKeySha256)", local_release)
        self.assertIn("Remove-Item Env:\\SELFHOSTED_SSH_TRUSTED_HOST", local_release)
        self.assertIn("Remove-Item Env:\\SELFHOSTED_SSH_TRUSTED_HOST_KEY_SHA256", local_release)
        self.assertIn("SSH server host key fingerprint", setup_qml)
        self.assertIn("independent trusted channel", setup_qml)
        self.assertIn("m_processedServerCredentials.sshHostKeyFingerprint = sshHostKeyFingerprint", install_ui)
        self.assertEqual(
            install_controller.count(
                "serverConfig.sshHostKeyFingerprint = credentials.sshHostKeyFingerprint"
            ),
            2,
        )
        self.assertIn("StrictHostKeyChecking=yes", install_controller)
        self.assertNotIn("StrictHostKeyChecking=no", install_controller)
        self.assertNotIn("UserKnownHostsFile=/dev/null", install_controller)

    @unittest.skipUnless(os.name == "posix" and find_sh(), "POSIX sh is required for durability injection")
    def test_ssh_upload_refuses_rename_without_durable_sync_primitive(self) -> None:
        sh = find_sh()
        real_mv = shutil.which("mv")
        assert sh is not None
        if not real_mv:
            self.skipTest("mv is required")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fake_path = root / "fake-path"
            fake_path.mkdir()
            source = root / "source"
            target = root / "target"
            source.write_bytes(b"must remain staged\n")
            durable_sync = extract_ssh_upload_durable_sync_function()
            attempted = subprocess.run(
                [
                    sh,
                    "-c",
                    "set -eu\n"
                    + durable_sync
                    + '\ndurable_sync "$1"\n'
                    + sh_quote(real_mv)
                    + ' -f -- "$1" "$2"\n',
                    "durability-test",
                    str(source),
                    str(target),
                ],
                env={**os.environ, "PATH": str(fake_path)},
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(attempted.returncode, 69, attempted.stderr)
            self.assertTrue(source.exists())
            self.assertFalse(target.exists())

    @unittest.skipUnless(os.name == "posix" and find_sh(), "POSIX sh is required for durability injection")
    def test_ssh_upload_reconcile_requires_durable_parent_sync_before_receipt(self) -> None:
        sh = find_sh()
        assert sh is not None

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            parent = root / "upload-parent"
            parent.mkdir()
            target = parent / "payload.bin"
            payload = b"rename-completed-before-ack\n"
            target.write_bytes(payload)
            expected_sha = hashlib.sha256(payload).hexdigest()
            expected_receipt = f"AMNEZIA_UPLOAD_V1\t{len(payload)}\t{expected_sha}"
            reconcile_template = extract_ssh_upload_shell_command("reconcileCommand")

            def render_reconcile(target_path: Path) -> str:
                rendered = reconcile_template
                replacements = (
                    sh_quote(str(target_path)),
                    str(len(payload)),
                    expected_sha,
                    sh_quote(expected_receipt),
                )
                for index, replacement in reversed(tuple(enumerate(replacements, start=1))):
                    rendered = rendered.replace(f"%{index}", replacement)
                return rendered

            fake_bin = root / "fake-bin"
            fake_bin.mkdir()
            allow_sync = root / "allow-sync"
            fake_sync = fake_bin / "sync"
            fake_sync.write_text(
                "#!/bin/sh\n"
                "if [ \"${1-}\" = --help ]; then\n"
                "    printf '%s\\n' 'usage: sync -f FILE'\n"
                "    exit 0\n"
                "fi\n"
                "test -f \"$AMNEZIA_TEST_ALLOW_SYNC\"\n",
                encoding="utf-8",
            )
            fake_sync.chmod(0o700)
            env = {
                **os.environ,
                "PATH": str(fake_bin) + os.pathsep + os.environ.get("PATH", ""),
                "AMNEZIA_TEST_ALLOW_SYNC": str(allow_sync),
            }

            failed = subprocess.run(
                [sh, "-c", render_reconcile(target)],
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(failed.returncode, 74, failed.stderr)
            self.assertEqual(failed.stdout, "")
            self.assertEqual(target.read_bytes(), payload)

            allow_sync.touch()
            reconciled = subprocess.run(
                [sh, "-c", render_reconcile(target)],
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(reconciled.returncode, 0, reconciled.stderr)
            self.assertEqual(reconciled.stdout, expected_receipt + "\n")

            linked_parent = root / "linked-parent"
            linked_parent.symlink_to(parent, target_is_directory=True)
            unsafe_parent = subprocess.run(
                [sh, "-c", render_reconcile(linked_parent / target.name)],
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(unsafe_parent.returncode, 65, unsafe_parent.stderr)
            self.assertEqual(unsafe_parent.stdout, "")

    @unittest.skipUnless(find_sh(), "sh is required to exercise the verified installer runner")
    def test_verified_installer_runner_rejects_tampered_remote_upload(self) -> None:
        sh = find_sh()
        assert sh
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            bin_dir = tmp_path / "bin"
            bin_dir.mkdir()
            (bin_dir / "sudo").write_text(
                '#!/bin/sh\n[ "$1" = -n ] && shift\n[ "$1" = -- ] && shift\nexec "$@"\n',
                encoding="utf-8",
            )
            os.chmod(bin_dir / "sudo", 0o755)

            host_dir = tmp_path / "updates"
            host_dir.mkdir()
            uploaded = tmp_path / "install_server_update_host.sh"
            sealed = tmp_path / "sealed-installer.sh"
            expected_installer = b'#!/bin/sh\nprintf \'safe\\n\' > "$1/executed"\n'
            tampered_installer = b'#!/bin/sh\nprintf \'evil\\n\' > "$1/executed"\n'
            self.assertEqual(len(expected_installer), len(tampered_installer))
            expected_sha256 = hashlib.sha256(expected_installer).hexdigest()
            uploaded.write_bytes(expected_installer)
            uploaded.write_bytes(tampered_installer)

            env = os.environ.copy()
            env["PATH"] = str(bin_dir) + os.pathsep + env.get("PATH", "")
            rejected = subprocess.run(
                [
                    sh,
                    str(SCRIPT_DIR / "run_verified_update_host_installer.sh"),
                    shell_absolute_path(uploaded),
                    shell_absolute_path(sealed),
                    expected_sha256,
                    str(len(expected_installer)),
                    shell_absolute_path(host_dir),
                ],
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("Uploaded installer sha256 mismatch", rejected.stderr)
            self.assertFalse((host_dir / "executed").exists())
            self.assertFalse(sealed.exists())

    @unittest.skipUnless(os.name == "posix" and find_sh(), "POSIX sh is required for timeout injection")
    def test_verified_installer_runner_propagates_timeout_and_removes_sealed_copy(self) -> None:
        sh = find_sh()
        assert sh
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            bin_dir = tmp_path / "bin"
            bin_dir.mkdir()
            (bin_dir / "sudo").write_text(
                textwrap.dedent(
                    '''\
                    #!/bin/sh
                    [ "$1" = -n ] && shift
                    [ "$1" = -- ] && shift
                    if [ "$1" = install ]; then
                        shift 8
                        cp "$1" "$2" && chmod 0444 "$2"
                        exit $?
                    fi
                    if [ "$1" = stat ] && [ "$3" = %u:%g:%a ]; then
                        printf '0:0:444\\n'
                        exit 0
                    fi
                    exec "$@"
                    '''
                ),
                encoding="utf-8",
            )
            (bin_dir / "timeout").write_text(
                '#!/bin/sh\nprintf \'%s\\n\' "$@" > "$FAKE_TIMEOUT_LOG"\nexit 124\n',
                encoding="utf-8",
            )
            os.chmod(bin_dir / "sudo", 0o755)
            os.chmod(bin_dir / "timeout", 0o755)

            host_dir = tmp_path / "updates"
            host_dir.mkdir()
            uploaded = tmp_path / "install_server_update_host.sh"
            sealed = tmp_path / "sealed-installer.sh"
            installer_data = b'#!/bin/sh\nprintf \'unexpected\\n\' > "$1/executed"\n'
            uploaded.write_bytes(installer_data)
            timeout_log = tmp_path / "timeout-args.txt"
            env = os.environ.copy()
            env["PATH"] = str(bin_dir) + os.pathsep + env.get("PATH", "")
            env["FAKE_TIMEOUT_LOG"] = str(timeout_log)
            timed_out = subprocess.run(
                [
                    sh,
                    str(SCRIPT_DIR / "run_verified_update_host_installer.sh"),
                    shell_absolute_path(uploaded),
                    shell_absolute_path(sealed),
                    hashlib.sha256(installer_data).hexdigest(),
                    str(len(installer_data)),
                    shell_absolute_path(host_dir),
                ],
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(timed_out.returncode, 124, timed_out.stderr)
            timeout_arguments = timeout_log.read_text(encoding="utf-8").splitlines()
            self.assertEqual(
                timeout_arguments[:3],
                ["--signal=TERM", "--kill-after=60s", "900s"],
            )
            self.assertFalse((host_dir / "executed").exists())
            self.assertFalse(sealed.exists())

    @unittest.skipUnless(os.name == "posix" and find_sh(), "POSIX sh is required for bundled publisher behavior")
    def test_bundled_publisher_initial_and_idempotent_publish(self) -> None:
        sh = find_sh()
        assert sh is not None
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            root.chmod(0o755)
            channel = root / "channel"
            publisher_source, upload_prefix = bundled_publisher_harness_source(channel)
            publisher_path = root / "publish_bundled_release.sh"
            publisher_path.write_text(publisher_source, encoding="utf-8")
            publisher_path.chmod(0o700)

            def invoke(*arguments: object) -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    [sh, str(publisher_path), *(str(argument) for argument in arguments)],
                    cwd=root,
                    text=True,
                    capture_output=True,
                    check=False,
                )

            probe = invoke("probe", channel)
            if probe.returncode == 69:
                self.skipTest(probe.stderr.strip())
            self.assertEqual(probe.returncode, 0, probe.stderr)
            self.assertEqual(probe.stdout, "ABSENT\n")

            artifact_data = b"signed bundled artifact\n"
            artifact_digest = hashlib.sha256(artifact_data).hexdigest()
            artifact_name = "artifact-$(touch SHOULD_NOT_EXIST)-'quoted'.bin"
            artifact_path = f"files/artifacts/{artifact_digest}/{artifact_name}"
            manifest_data = b'{"candidate":"initial"}\n'
            run_id = "1" * 48
            stage, candidate_sha, metadata_sha = write_bundled_publisher_stage(
                upload_prefix,
                run_id,
                manifest_data,
                "4.9.1.0",
                1,
                0,
                [("A", artifact_path, artifact_data)],
            )
            prepared = invoke("prepare", channel, run_id, "absent", candidate_sha, metadata_sha, 1)
            self.assertEqual(prepared.returncode, 0, prepared.stderr)
            self.assertEqual(
                prepared.stdout,
                bundled_publisher_receipt(
                    "AMNEZIA_PUBLISH_PREPARE_V1",
                    run_id,
                    "absent",
                    candidate_sha,
                    metadata_sha,
                    1,
                    "READY",
                    "prepared",
                ),
            )
            committed = invoke("commit", channel, run_id, "absent", candidate_sha, metadata_sha, 1)
            self.assertEqual(committed.returncode, 0, committed.stderr)
            self.assertEqual(
                committed.stdout,
                bundled_publisher_receipt(
                    "AMNEZIA_PUBLISH_COMMIT_V1",
                    run_id,
                    "absent",
                    candidate_sha,
                    metadata_sha,
                    1,
                    "APPLIED",
                    "committed",
                ),
            )
            self.assertEqual((channel / "manifest.json").read_bytes(), manifest_data)
            self.assertEqual(channel.joinpath(*PurePosixPath(artifact_path).parts).read_bytes(), artifact_data)
            self.assertEqual(
                (channel / ".amnezia-update-channel-v1").read_text(encoding="utf-8"),
                "amnezia-selfhosted-update-channel-v1\n",
            )
            self.assertTrue(stage.exists(), "commit must retain rollback state until endpoint verification")
            finalized = invoke(
                "finalize", channel, run_id, "absent", candidate_sha, metadata_sha, 1
            )
            self.assertEqual(finalized.returncode, 0, finalized.stderr)
            self.assertEqual(
                finalized.stdout,
                bundled_publisher_receipt(
                    "AMNEZIA_PUBLISH_FINALIZE_V1",
                    run_id,
                    "absent",
                    candidate_sha,
                    metadata_sha,
                    1,
                    "APPLIED",
                    "finalized",
                ),
            )
            self.assertFalse(stage.exists())
            self.assertIn(
                "\tfinalized\n",
                (channel / f".publish-state.{run_id}").read_text(encoding="utf-8"),
            )
            self.assertFalse((root / "SHOULD_NOT_EXIST").exists())

            outside = root / "outside.txt"
            outside.write_text("must not be exposed\n", encoding="utf-8")
            unsafe_link = channel / "files/leak"
            unsafe_link.symlink_to(outside)
            rejected_probe = invoke("probe", channel)
            self.assertEqual(rejected_probe.returncode, 64, rejected_probe.stderr)
            self.assertIn("contains a link or special file", rejected_probe.stderr)
            self.assertEqual((channel / "manifest.json").read_bytes(), manifest_data)
            unsafe_link.unlink()

            replay_run_id = "2" * 48
            replay_stage, replay_candidate_sha, replay_metadata_sha = write_bundled_publisher_stage(
                upload_prefix,
                replay_run_id,
                manifest_data,
                "4.9.1.0",
                1,
                0,
                [("A", artifact_path, artifact_data)],
            )
            self.assertEqual(replay_candidate_sha, candidate_sha)
            prepared = invoke(
                "prepare",
                channel,
                replay_run_id,
                candidate_sha,
                candidate_sha,
                replay_metadata_sha,
                1,
            )
            self.assertEqual(prepared.returncode, 0, prepared.stderr)
            committed = invoke(
                "commit", channel, replay_run_id, candidate_sha, candidate_sha, replay_metadata_sha, 1
            )
            self.assertEqual(committed.returncode, 0, committed.stderr)
            self.assertEqual(
                committed.stdout,
                bundled_publisher_receipt(
                    "AMNEZIA_PUBLISH_COMMIT_V1",
                    replay_run_id,
                    candidate_sha,
                    candidate_sha,
                    replay_metadata_sha,
                    1,
                    "APPLIED",
                    "committed",
                ),
            )
            self.assertEqual((channel / "manifest.json").read_bytes(), manifest_data)
            self.assertTrue(replay_stage.exists())
            finalized = invoke(
                "finalize",
                channel,
                replay_run_id,
                candidate_sha,
                replay_candidate_sha,
                replay_metadata_sha,
                1,
            )
            self.assertEqual(finalized.returncode, 0, finalized.stderr)
            self.assertEqual(
                finalized.stdout,
                bundled_publisher_receipt(
                    "AMNEZIA_PUBLISH_FINALIZE_V1",
                    replay_run_id,
                    candidate_sha,
                    replay_candidate_sha,
                    replay_metadata_sha,
                    1,
                    "APPLIED",
                    "finalized",
                ),
            )
            self.assertFalse(replay_stage.exists())

    @unittest.skipUnless(os.name == "posix" and find_sh(), "POSIX sh is required for bundled publisher behavior")
    def test_bundled_publisher_rejects_rollback_rebinding_and_stale_cas(self) -> None:
        sh = find_sh()
        assert sh is not None
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            root.chmod(0o755)
            channel = root / "channel"
            publisher_source, upload_prefix = bundled_publisher_harness_source(channel)
            publisher_path = root / "publish_bundled_release.sh"
            publisher_path.write_text(publisher_source, encoding="utf-8")
            publisher_path.chmod(0o700)

            def invoke(*arguments: object) -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    [sh, str(publisher_path), *(str(argument) for argument in arguments)],
                    cwd=root,
                    text=True,
                    capture_output=True,
                    check=False,
                )

            probe = invoke("probe", channel)
            if probe.returncode == 69:
                self.skipTest(probe.stderr.strip())
            self.assertEqual(probe.returncode, 0, probe.stderr)

            baseline_artifact = b"baseline artifact\n"
            baseline_digest = hashlib.sha256(baseline_artifact).hexdigest()
            baseline_path = f"files/artifacts/{baseline_digest}/baseline.bin"
            baseline_manifest = b'{"candidate":"baseline"}\n'
            baseline_run_id = "3" * 48
            baseline_stage, baseline_sha, baseline_metadata_sha = write_bundled_publisher_stage(
                upload_prefix,
                baseline_run_id,
                baseline_manifest,
                "4.9.1.0",
                1,
                0,
                [("A", baseline_path, baseline_artifact)],
            )
            self.assertEqual(
                invoke(
                    "prepare",
                    channel,
                    baseline_run_id,
                    "absent",
                    baseline_sha,
                    baseline_metadata_sha,
                    1,
                ).returncode,
                0,
            )
            baseline_commit = invoke(
                "commit", channel, baseline_run_id, "absent", baseline_sha, baseline_metadata_sha, 1
            )
            self.assertEqual(baseline_commit.returncode, 0, baseline_commit.stderr)
            self.assertTrue(baseline_stage.exists())
            self.assertEqual(
                invoke(
                    "finalize",
                    channel,
                    baseline_run_id,
                    "absent",
                    baseline_sha,
                    baseline_metadata_sha,
                    1,
                ).returncode,
                0,
            )

            failed_verify_run_id = "7" * 48
            failed_verify_artifact = b"candidate awaiting endpoint verification\n"
            failed_verify_digest = hashlib.sha256(failed_verify_artifact).hexdigest()
            failed_verify_path = f"files/artifacts/{failed_verify_digest}/candidate.bin"
            failed_verify_manifest = b'{"candidate":"failed-endpoint-verification"}\n'
            failed_verify_stage, failed_verify_sha, failed_verify_metadata_sha = (
                write_bundled_publisher_stage(
                    upload_prefix,
                    failed_verify_run_id,
                    failed_verify_manifest,
                    "4.9.1.1",
                    2,
                    40,
                    [("A", failed_verify_path, failed_verify_artifact)],
                )
            )
            (failed_verify_stage / "previous-manifest.json").write_bytes(baseline_manifest)
            self.assertEqual(
                invoke(
                    "prepare",
                    channel,
                    failed_verify_run_id,
                    baseline_sha,
                    failed_verify_sha,
                    failed_verify_metadata_sha,
                    1,
                ).returncode,
                0,
            )
            failed_verify_commit = invoke(
                "commit",
                channel,
                failed_verify_run_id,
                baseline_sha,
                failed_verify_sha,
                failed_verify_metadata_sha,
                1,
            )
            self.assertEqual(failed_verify_commit.returncode, 0, failed_verify_commit.stderr)
            self.assertEqual((channel / "manifest.json").read_bytes(), failed_verify_manifest)
            rolled_back = invoke(
                "rollback",
                channel,
                failed_verify_run_id,
                baseline_sha,
                failed_verify_sha,
                failed_verify_metadata_sha,
                1,
            )
            self.assertEqual(rolled_back.returncode, 0, rolled_back.stderr)
            self.assertEqual(
                rolled_back.stdout,
                bundled_publisher_receipt(
                    "AMNEZIA_PUBLISH_ROLLBACK_V1",
                    failed_verify_run_id,
                    baseline_sha,
                    failed_verify_sha,
                    failed_verify_metadata_sha,
                    1,
                    "APPLIED",
                    "rolled_back",
                ),
            )
            self.assertEqual((channel / "manifest.json").read_bytes(), baseline_manifest)
            self.assertTrue(
                failed_verify_stage.exists(),
                "rollback must retain evidence until its receipt is acknowledged",
            )
            # Simulate a lost rollback stdout ACK. Reconciliation is bound to
            # the full durable identity under the publisher lock.
            rollback_ack_loss_probe = invoke(
                "reconcile-rollback",
                channel,
                failed_verify_run_id,
                baseline_sha,
                failed_verify_sha,
                failed_verify_metadata_sha,
                1,
            )
            self.assertEqual(rollback_ack_loss_probe.returncode, 0, rollback_ack_loss_probe.stderr)
            self.assertEqual(
                rollback_ack_loss_probe.stdout,
                bundled_publisher_receipt(
                    "AMNEZIA_PUBLISH_RECONCILE_ROLLBACK_V1",
                    failed_verify_run_id,
                    baseline_sha,
                    failed_verify_sha,
                    failed_verify_metadata_sha,
                    1,
                    "APPLIED",
                    "rolled_back",
                ),
            )
            rollback_finalized = invoke(
                "finalize-rollback",
                channel,
                failed_verify_run_id,
                baseline_sha,
                failed_verify_sha,
                failed_verify_metadata_sha,
                1,
            )
            self.assertEqual(rollback_finalized.returncode, 0, rollback_finalized.stderr)
            self.assertEqual(
                rollback_finalized.stdout,
                bundled_publisher_receipt(
                    "AMNEZIA_PUBLISH_FINALIZE_ROLLBACK_V1",
                    failed_verify_run_id,
                    baseline_sha,
                    failed_verify_sha,
                    failed_verify_metadata_sha,
                    1,
                    "APPLIED",
                    "rollback_finalized",
                ),
            )
            self.assertFalse(failed_verify_stage.exists())

            rollback_cas_run_id = "8" * 48
            rollback_cas_manifest = b'{"candidate":"rollback-cas-guard"}\n'
            rollback_cas_artifact = b"rollback cas artifact\n"
            rollback_cas_digest = hashlib.sha256(rollback_cas_artifact).hexdigest()
            rollback_cas_stage, rollback_cas_sha, rollback_cas_metadata_sha = (
                write_bundled_publisher_stage(
                    upload_prefix,
                    rollback_cas_run_id,
                    rollback_cas_manifest,
                    "4.9.1.1",
                    2,
                    41,
                    [("A", f"files/artifacts/{rollback_cas_digest}/cas.bin", rollback_cas_artifact)],
                )
            )
            (rollback_cas_stage / "previous-manifest.json").write_bytes(baseline_manifest)
            self.assertEqual(
                invoke(
                    "prepare",
                    channel,
                    rollback_cas_run_id,
                    baseline_sha,
                    rollback_cas_sha,
                    rollback_cas_metadata_sha,
                    1,
                ).returncode,
                0,
            )
            self.assertEqual(
                invoke(
                    "commit",
                    channel,
                    rollback_cas_run_id,
                    baseline_sha,
                    rollback_cas_sha,
                    rollback_cas_metadata_sha,
                    1,
                ).returncode,
                0,
            )
            post_commit_concurrent_manifest = b'{"candidate":"post-commit-concurrent"}\n'
            published_manifest = channel / "manifest.json"
            published_manifest.chmod(0o644)
            published_manifest.write_bytes(post_commit_concurrent_manifest)
            published_manifest.chmod(0o444)
            rollback_conflict = invoke(
                "rollback",
                channel,
                rollback_cas_run_id,
                baseline_sha,
                rollback_cas_sha,
                rollback_cas_metadata_sha,
                1,
            )
            self.assertEqual(rollback_conflict.returncode, 75, rollback_conflict.stderr)
            self.assertIn("manifest CAS conflict during rollback", rollback_conflict.stderr)
            self.assertEqual(published_manifest.read_bytes(), post_commit_concurrent_manifest)
            self.assertTrue(rollback_cas_stage.exists(), "failed rollback must retain retry evidence")

            published_manifest.chmod(0o644)
            published_manifest.write_bytes(baseline_manifest)
            published_manifest.chmod(0o444)

            marker_run_id = "6" * 48
            marker_artifact = b"marker guard candidate\n"
            marker_digest = hashlib.sha256(marker_artifact).hexdigest()
            marker_path = f"files/artifacts/{marker_digest}/marker.bin"
            marker_manifest = b'{"candidate":"marker-removed"}\n'
            marker_stage, marker_sha, marker_metadata_sha = write_bundled_publisher_stage(
                upload_prefix,
                marker_run_id,
                marker_manifest,
                "4.9.1.1",
                2,
                41,
                [("A", marker_path, marker_artifact)],
            )
            prepared = invoke(
                "prepare",
                channel,
                marker_run_id,
                baseline_sha,
                marker_sha,
                marker_metadata_sha,
                1,
            )
            self.assertEqual(prepared.returncode, 0, prepared.stderr)
            (channel / ".amnezia-update-channel-v1").unlink()
            rejected = invoke(
                "commit", channel, marker_run_id, baseline_sha, marker_sha, marker_metadata_sha, 1
            )
            self.assertEqual(rejected.returncode, 64, rejected.stderr)
            self.assertIn("update channel marker is not a regular file", rejected.stderr)
            self.assertEqual((channel / "manifest.json").read_bytes(), baseline_manifest)
            self.assertTrue(marker_stage.exists(), "failed commit must retain durable recovery evidence")

            rollback_target = channel / "files/rollback/42/4.9.0.0/old.bin"
            rollback_target.parent.mkdir(parents=True)
            rollback_target.write_bytes(b"permanently bound rollback\n")
            rollback_target.chmod(0o444)
            rollback_target.parent.chmod(0o755)
            rollback_target.parent.parent.chmod(0o755)

            rollback_run_id = "4" * 48
            rebound_data = b"different rollback bytes\n"
            rebound_path = "files/rollback/42/4.9.0.0/old.bin"
            rebound_manifest = b'{"candidate":"rollback-rebind"}\n'
            rebound_stage, rebound_sha, rebound_metadata_sha = write_bundled_publisher_stage(
                upload_prefix,
                rollback_run_id,
                rebound_manifest,
                "4.9.1.1",
                2,
                42,
                [("R", rebound_path, rebound_data)],
            )
            prepared = invoke(
                "prepare",
                channel,
                rollback_run_id,
                baseline_sha,
                rebound_sha,
                rebound_metadata_sha,
                1,
            )
            self.assertEqual(prepared.returncode, 0, prepared.stderr)
            rejected = invoke(
                "commit", channel, rollback_run_id, baseline_sha, rebound_sha, rebound_metadata_sha, 1
            )
            self.assertEqual(rejected.returncode, 65, rejected.stderr)
            self.assertIn("already exists with different content", rejected.stderr)
            self.assertEqual((channel / "manifest.json").read_bytes(), baseline_manifest)
            self.assertEqual(rollback_target.read_bytes(), b"permanently bound rollback\n")
            self.assertTrue(rebound_stage.exists(), "failed commit must retain durable recovery evidence")

            cas_run_id = "5" * 48
            cas_artifact = b"cas candidate artifact\n"
            cas_digest = hashlib.sha256(cas_artifact).hexdigest()
            cas_path = f"files/artifacts/{cas_digest}/cas.bin"
            cas_manifest = b'{"candidate":"stale-cas"}\n'
            cas_stage, cas_sha, cas_metadata_sha = write_bundled_publisher_stage(
                upload_prefix,
                cas_run_id,
                cas_manifest,
                "4.9.1.2",
                2,
                43,
                [("A", cas_path, cas_artifact)],
            )
            prepared = invoke(
                "prepare",
                channel,
                cas_run_id,
                baseline_sha,
                cas_sha,
                cas_metadata_sha,
                1,
            )
            self.assertEqual(prepared.returncode, 0, prepared.stderr)
            concurrent_manifest = b'{"candidate":"concurrent"}\n'
            published_manifest = channel / "manifest.json"
            published_manifest.chmod(0o644)
            published_manifest.write_bytes(concurrent_manifest)
            published_manifest.chmod(0o444)
            rejected = invoke("commit", channel, cas_run_id, baseline_sha, cas_sha, cas_metadata_sha, 1)
            self.assertEqual(rejected.returncode, 75, rejected.stderr)
            self.assertIn("manifest CAS conflict", rejected.stderr)
            self.assertEqual(published_manifest.read_bytes(), concurrent_manifest)
            self.assertTrue(cas_stage.exists(), "indeterminate CAS conflict must preserve evidence")

    @unittest.skipUnless(os.name == "posix" and find_sh(), "POSIX flock is required for lock fencing")
    def test_bundled_publisher_lock_fences_identity_and_rejects_late_commit(self) -> None:
        import fcntl

        sh = find_sh()
        assert sh is not None
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            root.chmod(0o755)
            channel = root / "channel"
            publisher_source, upload_prefix = bundled_publisher_harness_source(channel)
            publisher_path = root / "publish_bundled_release.sh"
            publisher_path.write_text(publisher_source, encoding="utf-8")
            publisher_path.chmod(0o700)

            def invoke(*arguments: object) -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    [sh, str(publisher_path), *(str(argument) for argument in arguments)],
                    cwd=root,
                    text=True,
                    capture_output=True,
                    check=False,
                )

            self.assertEqual(invoke("probe", channel).returncode, 0)
            run_id = "9" * 48
            artifact = b"lock-fenced artifact\n"
            digest = hashlib.sha256(artifact).hexdigest()
            stage, candidate_sha, metadata_sha = write_bundled_publisher_stage(
                upload_prefix,
                run_id,
                b'{"candidate":"lock-fenced"}\n',
                "4.9.2.0",
                1,
                0,
                [("A", f"files/artifacts/{digest}/lock.bin", artifact)],
            )
            identity = (channel, run_id, "absent", candidate_sha, metadata_sha, 1)
            prepared = invoke("prepare", *identity)
            self.assertEqual(prepared.returncode, 0, prepared.stderr)

            wrong_metadata = "f" * 64
            mismatched = invoke(
                "reconcile",
                channel,
                run_id,
                "absent",
                candidate_sha,
                wrong_metadata,
                1,
            )
            self.assertEqual(mismatched.returncode, 0, mismatched.stderr)
            self.assertEqual(
                mismatched.stdout,
                bundled_publisher_receipt(
                    "AMNEZIA_PUBLISH_RECONCILE_V1",
                    run_id,
                    "absent",
                    candidate_sha,
                    wrong_metadata,
                    1,
                    "INDETERMINATE",
                    "identity_mismatch",
                ),
            )
            self.assertIn(
                "\tprepared\n",
                (channel / f".publish-state.{run_id}").read_text(encoding="utf-8"),
            )

            lock_path = channel / ".manifest-publish.lock"
            with lock_path.open("rb") as lock_handle:
                fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
                delayed_commit = subprocess.Popen(
                    [sh, str(publisher_path), "commit", *(str(value) for value in identity)],
                    cwd=root,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                time.sleep(0.2)
                self.assertIsNone(delayed_commit.poll(), "commit bypassed the global publisher lock")
                (stage / "manifest.json").write_bytes(b'{"candidate":"tampered-while-waiting"}\n')
                fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
                delayed_stdout, delayed_stderr = delayed_commit.communicate(timeout=10)

            self.assertEqual(delayed_stdout, "")
            self.assertEqual(delayed_commit.returncode, 65, delayed_stderr)
            self.assertIn("candidate manifest hash mismatch", delayed_stderr)
            self.assertIn(
                "\tcommitting\n",
                (channel / f".publish-state.{run_id}").read_text(encoding="utf-8"),
            )
            reconciled = invoke("reconcile", *identity)
            self.assertEqual(reconciled.returncode, 0, reconciled.stderr)
            self.assertEqual(
                reconciled.stdout,
                bundled_publisher_receipt(
                    "AMNEZIA_PUBLISH_RECONCILE_V1",
                    run_id,
                    "absent",
                    candidate_sha,
                    metadata_sha,
                    1,
                    "NOT_APPLIED",
                    "aborted",
                ),
            )
            late_commit = invoke("commit", *identity)
            self.assertEqual(late_commit.returncode, 75, late_commit.stderr)
            self.assertIn("rejects commit from phase aborted", late_commit.stderr)
            finalized = invoke("finalize-abort", *identity)
            self.assertEqual(finalized.returncode, 0, finalized.stderr)
            self.assertFalse(stage.exists())
            self.assertFalse((channel / "manifest.json").exists())

    @unittest.skipUnless(os.name == "posix" and find_sh(), "POSIX signals are required for crash recovery")
    def test_bundled_publisher_reconciles_sigkill_after_manifest_switch(self) -> None:
        sh = find_sh()
        real_sync = shutil.which("sync")
        real_sha256sum = shutil.which("sha256sum")
        real_grep = shutil.which("grep")
        assert sh is not None
        if not real_sync or not real_sha256sum or not real_grep:
            self.skipTest("sync, sha256sum, and grep are required")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            root.chmod(0o755)
            channel = root / "channel"
            publisher_source, upload_prefix = bundled_publisher_harness_source(channel)
            publisher_path = root / "publish_bundled_release.sh"
            publisher_path.write_text(publisher_source, encoding="utf-8")
            publisher_path.chmod(0o700)

            def invoke(
                *arguments: object,
                env: dict[str, str] | None = None,
            ) -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    [sh, str(publisher_path), *(str(argument) for argument in arguments)],
                    cwd=root,
                    env=env,
                    text=True,
                    capture_output=True,
                    check=False,
                )

            self.assertEqual(invoke("probe", channel).returncode, 0)
            run_id = "a" * 48
            artifact = b"crash-reconciled artifact\n"
            digest = hashlib.sha256(artifact).hexdigest()
            manifest_data = b'{"candidate":"crash-reconciled"}\n'
            stage, candidate_sha, metadata_sha = write_bundled_publisher_stage(
                upload_prefix,
                run_id,
                manifest_data,
                "4.9.2.1",
                1,
                0,
                [("A", f"files/artifacts/{digest}/crash.bin", artifact)],
            )
            identity = (channel, run_id, "absent", candidate_sha, metadata_sha, 1)
            self.assertEqual(invoke("prepare", *identity).returncode, 0)

            fake_bin = root / "fake-bin"
            fake_bin.mkdir()
            kill_marker = root / "sync-kill-triggered"
            sync_wrapper = fake_bin / "sync"
            sync_wrapper.write_text(
                textwrap.dedent(
                    f"""\
                    #!/bin/sh
                    {sh_quote(real_sync)} "$@" || exit $?
                    last=
                    for argument do last=$argument; done
                    if [ "$last" = "$KILL_SYNC_ROOT" ] \\
                        && [ -f "$KILL_SYNC_ROOT/manifest.json" ] \\
                        && [ "$({sh_quote(real_sha256sum)} "$KILL_SYNC_ROOT/manifest.json")" != "" ]; then
                        digest=$({sh_quote(real_sha256sum)} "$KILL_SYNC_ROOT/manifest.json")
                        digest=${{digest%% *}}
                        if [ "$digest" = "$KILL_SYNC_SHA256" ] \\
                            && {sh_quote(real_grep)} -Eq "$(printf '\\t')committing$" "$KILL_SYNC_STATE"; then
                            : > "$KILL_SYNC_MARKER"
                            kill -KILL "$PPID"
                            exit 137
                        fi
                    fi
                    """
                ),
                encoding="utf-8",
            )
            sync_wrapper.chmod(0o700)
            crash_env = os.environ.copy()
            crash_env.update(
                {
                    "PATH": str(fake_bin) + os.pathsep + crash_env.get("PATH", ""),
                    "KILL_SYNC_ROOT": str(channel),
                    "KILL_SYNC_SHA256": candidate_sha,
                    "KILL_SYNC_STATE": str(channel / f".publish-state.{run_id}"),
                    "KILL_SYNC_MARKER": str(kill_marker),
                }
            )
            crashed = invoke("commit", *identity, env=crash_env)
            self.assertNotEqual(crashed.returncode, 0)
            self.assertTrue(kill_marker.exists(), crashed.stderr)
            self.assertEqual((channel / "manifest.json").read_bytes(), manifest_data)
            self.assertIn(
                "\tcommitting\n",
                (channel / f".publish-state.{run_id}").read_text(encoding="utf-8"),
            )
            self.assertTrue(stage.exists())

            reconciled = invoke("reconcile", *identity)
            self.assertEqual(reconciled.returncode, 0, reconciled.stderr)
            self.assertEqual(
                reconciled.stdout,
                bundled_publisher_receipt(
                    "AMNEZIA_PUBLISH_RECONCILE_V1",
                    run_id,
                    "absent",
                    candidate_sha,
                    metadata_sha,
                    1,
                    "APPLIED",
                    "committed",
                ),
            )
            finalized = invoke("finalize", *identity)
            self.assertEqual(finalized.returncode, 0, finalized.stderr)
            self.assertFalse(stage.exists())
            self.assertFalse((channel / "files" / f".publish.{run_id}").exists())

    def test_update_host_setup_rejects_route_values_for_bridge_host(self) -> None:
        script = (REPO_ROOT / "deploy/selfhosted_updates/install_server_update_host.sh").read_text(encoding="utf-8")
        self.assertIn('HOST_DIRECTORY must be an absolute path', script)
        self.assertIn('AMNEZIA_UPDATE_BRIDGE_HOST must be a single IPv4 address, not a CIDR route', script)
        self.assertIn('AMNEZIA_UPDATE_HOST_BIND must be a single IPv4 address', script)
        self.assertIn('AMNEZIA_UPDATE_HOST_CONTAINER_NAME is invalid', script)
        self.assertIn('is_ipv4_address "$BRIDGE_HOST"', script)
        self.assertIn('is_ipv4_address "$HOST_BIND"', script)
        self.assertIn('case "$candidate" in', script)
        self.assertIn('""|*/*)', script)
        self.assertIn('is_port "$SYNC_PORT"', script)
        self.assertIn('AMNEZIA_UPDATE_PUBLISH_HOST_PORT must be 0 or 1', script)
        self.assertIn('EXPECTED_SUBNET="172.29.172.0/24"', script)
        self.assertIn('NETWORK_NAME="${CONTAINER_NAME}-net"', script)
        self.assertIn('AUTO_VPN_CONTAINERS="amnezia-awg2 amnezia-awg amnezia-wireguard amnezia-openvpn"', script)
        self.assertIn('AMNEZIA_UPDATE_VPN_CONTAINER must name a running VPN container', script)
        self.assertIn('--network "container:$vpn_id"', script)
        self.assertIn('--cidfile "$main_cidfile"', script)
        self.assertIn('--label "${TRANSACTION_LABEL_KEY}=${TRANSACTION_ID}"', script)
        self.assertIn('--label "${ROLE_LABEL_KEY}=bridge"', script)
        self.assertIn("assert_name_maps_to_id()", script)
        self.assertIn("assert_transaction_container_identity()", script)
        self.assertIn("wait_http_ready()", script)
        self.assertIn("wait_host_http_ready()", script)
        self.assertIn("reconcile_firewall_rules()", script)
        self.assertIn("rollback_firewall()", script)
        self.assertIn("ufw allow proto tcp", script)
        self.assertIn("firewall-cmd --add-rich-rule", script)
        self.assertIn("firewall-cmd --permanent --add-rich-rule", script)
        self.assertNotIn("runtime-to-permanent", script)
        self.assertIn("iptables -C INPUT -p tcp -d", script)
        self.assertIn("iptables -I INPUT 1 -p tcp -d", script)
        self.assertIn("--network host", script)
        self.assertIn("busybox wget -q -O -", script)
        self.assertIn("HEALTH_SENTINEL_CONTENT", script)
        self.assertNotIn("grep -q 'HTTP/'", script)
        self.assertIn("Bridge update endpoint did not serve the exact health sentinel", script)
        self.assertIn("Tunnel update endpoint did not serve the exact health sentinel", script)
        self.assertIn("Host update endpoint did not serve the exact health sentinel", script)
        self.assertIn('IMAGE_REPOSITORY="docker.io/library/busybox"', script)
        self.assertIn(
            'IMAGE_DIGEST="sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662"',
            script,
        )
        self.assertIn('IMAGE="${IMAGE_REPOSITORY}@${IMAGE_DIGEST}"', script)
        self.assertIn('docker image inspect "$1"', script)
        self.assertIn('Docker failed while querying pinned image identity', script)
        self.assertIn('Docker failed while querying $query_description', script)
        self.assertIn('Docker failed while querying $network_description', script)
        self.assertIn('docker pull "$IMAGE"', script)
        self.assertIn("Pinned update image identity verification failed", script)
        self.assertIn("registry-1.docker.io/v2/library/busybox/manifests/1.36.1", script)
        self.assertIn("Content-Type: application/vnd.oci.image.index.v1+json", script)
        self.assertIn("Docker-Content-Digest: sha256:73aaf090", script)
        self.assertNotIn("AMNEZIA_UPDATE_IMAGE", script)
        self.assertNotIn("docker.io/library/busybox:1.36.1", script)
        self.assertNotIn("busybox:latest", script)
        self.assertIn("LOCK_PATH=", script)
        self.assertIn('flock -x -w "$LOCK_WAIT_SECONDS" 9', script)
        self.assertIn("backup_container()", script)
        self.assertIn("rollback_transaction()", script)
        self.assertIn('docker rename "$original_id" "$backup_name"', script)
        self.assertIn('docker network disconnect "$disconnect_network" "$original_id"', script)
        self.assertIn('docker network connect --ip "$prior_ip" "$prior_network" "$original_id"', script)
        self.assertIn('restore_running_state "$original_id" "$original_name"', script)
        self.assertIn("TRANSACTION_COMMITTED=1", script)
        self.assertIn("cleanup_backups", script)
        self.assertNotIn('docker rm -f "$HOST_CONTAINER_NAME"', script)
        self.assertIn('sudo -n -- "$@"', script)
        self.assertIn('JOURNAL_PATH=', script)
        self.assertIn('persist_transaction_journal active', script)
        self.assertIn('persist_transaction_journal committed_pending_cleanup', script)
        self.assertIn('recover_incomplete_transaction', script)

        lock_index = script.index('flock -x -w "$LOCK_WAIT_SECONDS" 9')
        image_mutation_index = script.index('docker pull "$IMAGE"', lock_index)
        network_mutation_index = script.index("docker network create", lock_index)
        backup_record_index = script.index("append_backup_record", script.index("backup_container()"))
        rename_index = script.index('docker rename "$original_id" "$backup_name"', backup_record_index)
        health_index = script.index('wait_host_http_ready || die "Host update endpoint did not serve the exact health sentinel"')
        durable_commit_index = script.index("persist_transaction_journal committed_pending_cleanup", health_index)
        commit_index = script.index("TRANSACTION_COMMITTED=1", health_index)
        cleanup_index = script.index("cleanup_backups || die", commit_index)
        self.assertLess(lock_index, image_mutation_index)
        self.assertLess(lock_index, network_mutation_index)
        self.assertLess(backup_record_index, rename_index)
        self.assertLess(health_index, commit_index)
        self.assertLess(durable_commit_index, commit_index)
        self.assertLess(commit_index, cleanup_index)

    @unittest.skipUnless(find_sh(), "sh is required to exercise update-host input validation")
    def test_update_host_setup_validates_inputs_before_any_mutation(self) -> None:
        sh = find_sh()
        assert sh
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            bin_dir = tmp_path / "bin"
            bin_dir.mkdir()
            log_path = tmp_path / "docker.log"
            host_dir = tmp_path / "updates"
            host_dir_arg = shell_absolute_path(host_dir)
            (bin_dir / "docker").write_text(
                f"#!/bin/sh\nprintf '%s\\n' \"$*\" >> {log_path.as_posix()!r}\nexit 99\n",
                encoding="utf-8",
            )
            os.chmod(bin_dir / "docker", 0o755)

            env = os.environ.copy()
            env["PATH"] = str(bin_dir) + os.pathsep + env.get("PATH", "")
            script = str(SCRIPT_DIR / "install_server_update_host.sh")

            relative_host_dir = subprocess.run(
                [sh, script, "relative-updates"],
                env=env,
                text=True,
                capture_output=True,
            )
            self.assertNotEqual(relative_host_dir.returncode, 0)
            self.assertIn("HOST_DIRECTORY must be an absolute path", relative_host_dir.stderr)
            self.assertFalse(log_path.exists(), "relative host directory must fail before any docker command is called")

            env["AMNEZIA_UPDATE_BRIDGE_HOST"] = "10.8.1.0/1"
            invalid = subprocess.run(
                [sh, script, host_dir_arg],
                env=env,
                text=True,
                capture_output=True,
            )
            self.assertNotEqual(invalid.returncode, 0)
            self.assertIn("must be a single IPv4 address", invalid.stderr)
            self.assertFalse(log_path.exists(), "CIDR bridge host must fail before any docker command is called")

            env["AMNEZIA_UPDATE_BRIDGE_HOST"] = "172.29.172.252"
            env["AMNEZIA_UPDATE_HOST_BIND"] = "0.0.0.0 --privileged"
            invalid_bind = subprocess.run(
                [sh, script, host_dir_arg],
                env=env,
                text=True,
                capture_output=True,
            )
            self.assertNotEqual(invalid_bind.returncode, 0)
            self.assertIn("AMNEZIA_UPDATE_HOST_BIND must be a single IPv4 address", invalid_bind.stderr)
            self.assertFalse(log_path.exists(), "invalid host bind must fail before any docker command is called")

            env["AMNEZIA_UPDATE_HOST_BIND"] = "0.0.0.0"
            env["AMNEZIA_UPDATE_CONTAINER_NAME"] = "invalid name"
            invalid_name = subprocess.run(
                [sh, script, host_dir_arg],
                env=env,
                text=True,
                capture_output=True,
            )
            self.assertNotEqual(invalid_name.returncode, 0)
            self.assertIn("AMNEZIA_UPDATE_CONTAINER_NAME is invalid", invalid_name.stderr)
            self.assertFalse(log_path.exists(), "invalid container name must fail before any docker command is called")

    @unittest.skipUnless(os.name == "posix" and find_sh(), "POSIX sh and flock are required")
    def test_update_host_setup_does_not_trust_poisoned_preexisting_tag(self) -> None:
        sh = find_sh()
        assert sh
        poisoned_tag = "docker.io/library/busybox:1.36.1"
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            state = initial_transactional_docker_state(image_present=False)
            installer, host_dir, state_path, env = prepare_transactional_installer_harness(tmp_path, state)
            env["AMNEZIA_UPDATE_IMAGE"] = poisoned_tag

            rejected = subprocess.run(
                [sh, str(installer), str(host_dir)],
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(rejected.returncode, 0)
            rejected_log = (tmp_path / "docker.log").read_text(encoding="utf-8")
            self.assertIn(f"image inspect {PINNED_UPDATE_HOST_IMAGE}", rejected_log)
            self.assertIn(f"pull {PINNED_UPDATE_HOST_IMAGE}", rejected_log)
            self.assertNotIn(poisoned_tag, rejected_log)
            self.assertFalse(any("|run-" in line for line in rejected_log.splitlines()))
            self.assertEqual(json.loads(state_path.read_text(encoding="utf-8"))["containers"], state["containers"])

            (tmp_path / "docker.log").unlink()
            env["FAKE_DOCKER_ALLOW_PULL"] = "1"
            accepted = subprocess.run(
                [sh, str(installer), str(host_dir)],
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            accepted_log = (tmp_path / "docker.log").read_text(encoding="utf-8")
            self.assertIn(f"pull {PINNED_UPDATE_HOST_IMAGE}", accepted_log)
            run_lines = [
                line
                for line in accepted_log.splitlines()
                if "|run-" in line or "|candidate-preflight|" in line
            ]
            self.assertTrue(run_lines)
            self.assertTrue(all(PINNED_UPDATE_HOST_IMAGE in line for line in run_lines))
            self.assertNotIn(poisoned_tag, accepted_log)

            final_state = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertTrue(final_state["containers"]["amnezia-client-updates"]["running"])
            self.assertEqual(final_state["containers"]["amnezia-client-updates"]["ip"], "172.29.172.252")
            self.assertEqual(final_state["containers"]["amnezia-client-updates-host"]["network"], "host")
            self.assertEqual(
                final_state["containers"]["amnezia-client-updates-vpn-amnezia-awg"]["network"],
                "container:vpn-awg-id",
            )
            self.assertFalse(any(".amnezia-backup." in name for name in final_state["containers"]))
            health_positions = [index for index, line in enumerate(accepted_log.splitlines()) if "|health-" in line]
            cleanup_positions = [index for index, line in enumerate(accepted_log.splitlines()) if "|cleanup-backup-" in line]
            self.assertTrue(health_positions and cleanup_positions)
            self.assertLess(max(health_positions), min(cleanup_positions))

    @unittest.skipUnless(os.name == "posix" and find_sh(), "POSIX sh and flock are required")
    def test_update_host_query_errors_never_mean_absent(self) -> None:
        sh = find_sh()
        assert sh
        cases = (
            ("image-inspect", "Docker failed while querying pinned image identity", False),
            ("container-inspect", "Docker failed while querying container", False),
            ("network-inspect", "Docker failed while querying network ID", False),
            ("network-ls", "Docker failed while resolving the transaction network", True),
        )
        for phase, expected_error, remove_default_network in cases:
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as tmp:
                tmp_path = Path(tmp)
                initial = initial_transactional_docker_state()
                if remove_default_network:
                    initial["networks"] = {}
                expected_containers = json.loads(json.dumps(initial["containers"]))
                expected_networks = json.loads(json.dumps(initial["networks"]))
                installer, host_dir, state_path, env = prepare_transactional_installer_harness(
                    tmp_path, initial
                )
                env["FAKE_DOCKER_FAIL_PHASE"] = phase
                env["FAKE_DOCKER_FAIL_MARKER"] = str(tmp_path / "query-failure-injected")
                rejected = subprocess.run(
                    [sh, str(installer), str(host_dir)],
                    env=env,
                    text=True,
                    capture_output=True,
                    check=False,
                    timeout=45,
                )
                self.assertNotEqual(rejected.returncode, 0)
                self.assertIn(expected_error, rejected.stderr)
                final_state = json.loads(state_path.read_text(encoding="utf-8"))
                self.assertEqual(final_state["containers"], expected_containers)
                self.assertEqual(final_state["networks"], expected_networks)
                self.assertFalse(
                    (tmp_path / "trust-anchor/amnezia/.client-update-host-transaction").exists()
                )

    @unittest.skipUnless(os.name == "posix" and find_sh(), "POSIX sh and flock are required")
    def test_update_host_journal_sync_and_remove_failures_are_explicit(self) -> None:
        sh = find_sh()
        assert sh
        real_sync = shutil.which("sync")
        real_rm = shutil.which("rm")
        assert real_sync and real_rm

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            initial = initial_transactional_docker_state()
            expected_containers = json.loads(json.dumps(initial["containers"]))
            installer, host_dir, state_path, env = prepare_transactional_installer_harness(
                tmp_path, initial
            )
            fake_sync = tmp_path / "bin/sync"
            fake_sync.write_text(
                "#!/bin/sh\n"
                "case \"$*\" in *client-update-host-transaction*) exit 76 ;; esac\n"
                f"exec {sh_quote(real_sync)} \"$@\"\n",
                encoding="utf-8",
            )
            fake_sync.chmod(0o700)
            rejected = subprocess.run(
                [sh, str(installer), str(host_dir)],
                env=env,
                text=True,
                capture_output=True,
                check=False,
                timeout=45,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("Unable to persist update-host transaction journal", rejected.stderr)
            self.assertEqual(
                json.loads(state_path.read_text(encoding="utf-8"))["containers"],
                expected_containers,
            )

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            installer, host_dir, _state_path, env = prepare_transactional_installer_harness(
                tmp_path, initial_transactional_docker_state()
            )
            journal_path = tmp_path / "trust-anchor/amnezia/.client-update-host-transaction"
            fake_rm = tmp_path / "bin/rm"
            fake_rm.write_text(
                "#!/bin/sh\n"
                f"blocked={sh_quote(str(journal_path))}\n"
                "for candidate do test \"$candidate\" = \"$blocked\" && exit 76; done\n"
                f"exec {sh_quote(real_rm)} \"$@\"\n",
                encoding="utf-8",
            )
            fake_rm.chmod(0o700)
            rejected = subprocess.run(
                [sh, str(installer), str(host_dir)],
                env=env,
                text=True,
                capture_output=True,
                check=False,
                timeout=45,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("durable transaction journal cleanup failed", rejected.stderr)
            self.assertTrue(journal_path.is_file())
            self.assertIn("phase=committed_pending_cleanup", journal_path.read_text(encoding="utf-8"))

    @unittest.skipUnless(os.name == "posix" and find_sh(), "POSIX sh and flock are required")
    def test_update_host_transaction_rolls_back_after_each_destructive_phase(self) -> None:
        sh = find_sh()
        assert sh
        failure_phases = (
            "rename-main",
            "stop-main",
            "disconnect-main",
            "rename-host",
            "stop-host",
            "rename-sidecar-running",
            "stop-sidecar-running",
            "run-main",
            "run-sidecar",
            "run-host",
            "health-main",
            "health-sidecar",
            "health-host",
        )
        for failure_phase in failure_phases:
            with self.subTest(failure_phase=failure_phase), tempfile.TemporaryDirectory() as tmp:
                tmp_path = Path(tmp)
                initial_state = initial_transactional_docker_state()
                expected_containers = json.loads(json.dumps(initial_state["containers"]))
                installer, host_dir, state_path, env = prepare_transactional_installer_harness(
                    tmp_path, initial_state
                )
                env["FAKE_DOCKER_FAIL_PHASE"] = failure_phase
                env["FAKE_DOCKER_FAIL_MARKER"] = str(tmp_path / "failure-injected")
                result = subprocess.run(
                    [sh, str(installer), str(host_dir)],
                    env=env,
                    text=True,
                    capture_output=True,
                    check=False,
                    timeout=30,
                )
                self.assertNotEqual(result.returncode, 0, failure_phase)
                self.assertIn("Previous update host containers restored", result.stderr, failure_phase)
                final_state = json.loads(state_path.read_text(encoding="utf-8"))
                self.assertEqual(final_state["containers"], expected_containers, failure_phase)
                self.assertFalse(
                    any(".amnezia-backup." in name for name in final_state["containers"]),
                    failure_phase,
                )
                log = (tmp_path / "docker.log").read_text(encoding="utf-8")
                self.assertIn(f"|{failure_phase}|", log, failure_phase)

    @unittest.skipUnless(os.name == "posix" and find_sh(), "POSIX sh and flock are required")
    def test_update_host_transaction_confirms_backup_cleanup_postconditions(self) -> None:
        sh = find_sh()
        assert sh
        cleanup_phases = (
            "cleanup-backup-main",
            "cleanup-backup-host",
            "cleanup-backup-sidecar-running",
        )
        for cleanup_phase in cleanup_phases:
            with self.subTest(cleanup_phase=cleanup_phase), tempfile.TemporaryDirectory() as tmp:
                tmp_path = Path(tmp)
                installer, host_dir, state_path, env = prepare_transactional_installer_harness(
                    tmp_path, initial_transactional_docker_state()
                )
                env["FAKE_DOCKER_FAIL_PHASE"] = cleanup_phase
                env["FAKE_DOCKER_FAIL_MARKER"] = str(tmp_path / "failure-injected")
                result = subprocess.run(
                    [sh, str(installer), str(host_dir)],
                    env=env,
                    text=True,
                    capture_output=True,
                    check=False,
                    timeout=30,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                final_state = json.loads(state_path.read_text(encoding="utf-8"))
                self.assertFalse(
                    any(".amnezia-backup." in name for name in final_state["containers"]),
                    cleanup_phase,
                )
                self.assertTrue(final_state["containers"]["amnezia-client-updates"]["running"])
                log = (tmp_path / "docker.log").read_text(encoding="utf-8")
                self.assertIn(f"|{cleanup_phase}|", log, cleanup_phase)

    @unittest.skipUnless(os.name == "posix" and find_sh(), "POSIX sh and flock are required")
    def test_update_host_readiness_uses_custom_bind_2xx_and_exact_sentinel(self) -> None:
        sh = find_sh()
        assert sh
        custom_bind = "192.0.2.44"

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            installer, host_dir, state_path, env = prepare_transactional_installer_harness(
                tmp_path, initial_transactional_docker_state()
            )
            env["AMNEZIA_UPDATE_HOST_BIND"] = custom_bind
            env["FAKE_EXPECT_HOST_PROBE_ADDRESS"] = custom_bind
            accepted = subprocess.run(
                [sh, str(installer), str(host_dir)],
                env=env,
                text=True,
                capture_output=True,
                check=False,
                timeout=45,
            )
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            log = (tmp_path / "docker.log").read_text(encoding="utf-8")
            self.assertIn(f"-p {custom_bind}:17865", log)
            self.assertIn(f"http://{custom_bind}:17865/amnezia-update-health-", log)
            self.assertIn("amnezia-update-health-v1:", log)
            self.assertFalse(list(host_dir.glob("amnezia-update-health-*")))

        for failure_env in (
            {"FAKE_HTTP_STATUS": "404"},
            {"FAKE_HTTP_STATUS": "500"},
            {"FAKE_SENTINEL_MATCH": "0"},
            {"FAKE_EXPECT_HOST_PROBE_ADDRESS": "198.51.100.9"},
        ):
            with self.subTest(failure_env=failure_env), tempfile.TemporaryDirectory() as tmp:
                tmp_path = Path(tmp)
                initial = initial_transactional_docker_state()
                expected_containers = json.loads(json.dumps(initial["containers"]))
                installer, host_dir, state_path, env = prepare_transactional_installer_harness(
                    tmp_path, initial
                )
                env["AMNEZIA_UPDATE_HOST_BIND"] = custom_bind
                env.update(failure_env)
                rejected = subprocess.run(
                    [sh, str(installer), str(host_dir)],
                    env=env,
                    text=True,
                    capture_output=True,
                    check=False,
                    timeout=45,
                )
                self.assertNotEqual(rejected.returncode, 0)
                final = json.loads(state_path.read_text(encoding="utf-8"))
                self.assertEqual(final["containers"], expected_containers)
                self.assertFalse(list(host_dir.glob("amnezia-update-health-*")))
                self.assertFalse(
                    (tmp_path / "trust-anchor/amnezia/.client-update-host-transaction").exists()
                )

    @unittest.skipUnless(os.name == "posix" and find_sh(), "POSIX sh and flock are required")
    def test_update_host_aba_never_deletes_or_restores_foreign_container(self) -> None:
        sh = find_sh()
        assert sh
        for aba_phase in ("rename-main", "run-main"):
            with self.subTest(aba_phase=aba_phase), tempfile.TemporaryDirectory() as tmp:
                tmp_path = Path(tmp)
                installer, host_dir, state_path, env = prepare_transactional_installer_harness(
                    tmp_path, initial_transactional_docker_state()
                )
                env["FAKE_DOCKER_ABA_PHASE"] = aba_phase
                result = subprocess.run(
                    [sh, str(installer), str(host_dir)],
                    env=env,
                    text=True,
                    capture_output=True,
                    check=False,
                    timeout=45,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("CRITICAL: update host container rollback was incomplete", result.stderr)
                containers = json.loads(state_path.read_text(encoding="utf-8"))["containers"]
                self.assertEqual(containers["amnezia-client-updates"]["id"], "foreign-container-id")
                self.assertEqual(containers["amnezia-client-updates"]["role"], "foreign")
                self.assertTrue(
                    any(
                        name.startswith("amnezia-client-updates.amnezia-backup.")
                        and container["id"] == "old-main-id"
                        for name, container in containers.items()
                    )
                )
                self.assertFalse(
                    any(
                        container.get("labels", {}).get(
                            "org.amnezia.client-update-host.transaction"
                        )
                        for container in containers.values()
                    )
                )

    @unittest.skipUnless(os.name == "posix" and find_sh(), "POSIX sh and flock are required")
    def test_update_host_auto_mode_preserves_and_serves_all_running_vpns(self) -> None:
        sh = find_sh()
        assert sh

        def multi_vpn_state() -> dict[str, object]:
            state = initial_transactional_docker_state()
            containers = state["containers"]
            assert isinstance(containers, dict)
            containers["amnezia-wireguard"] = {
                "id": "vpn-wireguard-id",
                "role": "vpn-wireguard",
                "running": True,
                "network": "bridge",
                "ip": "172.17.0.3",
            }
            containers["amnezia-client-updates-vpn-amnezia-wireguard"] = {
                "id": "old-wireguard-sidecar-id",
                "role": "sidecar-wireguard-running",
                "running": True,
                "network": "container:amnezia-wireguard",
                "ip": "",
            }
            return state

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            installer, host_dir, state_path, env = prepare_transactional_installer_harness(
                tmp_path, multi_vpn_state()
            )
            env.pop("AMNEZIA_UPDATE_VPN_CONTAINER")
            result = subprocess.run(
                [sh, str(installer), str(host_dir)],
                env=env,
                text=True,
                capture_output=True,
                check=False,
                timeout=45,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            containers = json.loads(state_path.read_text(encoding="utf-8"))["containers"]
            self.assertEqual(
                containers["amnezia-client-updates-vpn-amnezia-awg"]["network"],
                "container:vpn-awg-id",
            )
            self.assertEqual(
                containers["amnezia-client-updates-vpn-amnezia-wireguard"]["network"],
                "container:vpn-wireguard-id",
            )
            self.assertEqual(
                containers["amnezia-client-updates-vpn-amnezia-wireguard"]["labels"][
                    "org.amnezia.client-update-host.role"
                ],
                "tunnel-amnezia-wireguard",
            )
            self.assertEqual(containers["amnezia-client-updates-vpn-retired"]["id"], "retired-sidecar-id")
            self.assertEqual(
                (tmp_path / "docker.log").read_text(encoding="utf-8").count("|run-sidecar|"),
                2,
            )

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            initial = multi_vpn_state()
            expected_containers = json.loads(json.dumps(initial["containers"]))
            installer, host_dir, state_path, env = prepare_transactional_installer_harness(tmp_path, initial)
            env.pop("AMNEZIA_UPDATE_VPN_CONTAINER")
            env["FAKE_DOCKER_FAIL_ROLE"] = "tunnel-amnezia-wireguard"
            result = subprocess.run(
                [sh, str(installer), str(host_dir)],
                env=env,
                text=True,
                capture_output=True,
                check=False,
                timeout=45,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(
                json.loads(state_path.read_text(encoding="utf-8"))["containers"],
                expected_containers,
            )

    @unittest.skipUnless(os.name == "posix" and find_sh(), "POSIX sh and flock are required")
    def test_update_host_firewall_rolls_back_exact_rules_and_reconciles_disabled_publish(self) -> None:
        sh = find_sh()
        assert sh
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            initial = initial_transactional_docker_state()
            expected_containers = json.loads(json.dumps(initial["containers"]))
            installer, host_dir, state_path, env = prepare_transactional_installer_harness(tmp_path, initial)
            env["FAKE_FIREWALL_FAIL_AFTER"] = "iptables-add"
            env["FAKE_FIREWALL_FAIL_MARKER"] = str(tmp_path / "firewall-failure-injected")
            rejected = subprocess.run(
                [sh, str(installer), str(host_dir)],
                env=env,
                text=True,
                capture_output=True,
                check=False,
                timeout=45,
            )
            firewall_debug = (
                (tmp_path / "firewall.log").read_text(encoding="utf-8")
                if (tmp_path / "firewall.log").exists()
                else "<no firewall log>"
            )
            self.assertNotEqual(rejected.returncode, 0, rejected.stderr + "\n" + firewall_debug)
            self.assertEqual(
                json.loads(state_path.read_text(encoding="utf-8"))["containers"],
                expected_containers,
            )
            firewall_state = json.loads((tmp_path / "firewall-state.json").read_text(encoding="utf-8"))
            self.assertTrue(all(not rules for rules in firewall_state.values()))
            firewall_log = (tmp_path / "firewall.log").read_text(encoding="utf-8")
            self.assertIn("iptables-add|", firewall_log)
            self.assertIn("iptables-remove|", firewall_log)
            self.assertIn("firewalld_permanent-remove|", firewall_log)
            self.assertIn("ufw-remove|", firewall_log)
            self.assertNotIn("runtime-to-permanent", firewall_log)

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            installer, host_dir, state_path, env = prepare_transactional_installer_harness(
                tmp_path, initial_transactional_docker_state()
            )
            enabled = subprocess.run(
                [sh, str(installer), str(host_dir)],
                env=env,
                text=True,
                capture_output=True,
                check=False,
                timeout=45,
            )
            self.assertEqual(enabled.returncode, 0, enabled.stderr)
            enabled_state = json.loads((tmp_path / "firewall-state.json").read_text(encoding="utf-8"))
            self.assertTrue(all(len(rules) == 1 for rules in enabled_state.values()))
            env["AMNEZIA_UPDATE_PUBLISH_HOST_PORT"] = "0"
            disabled = subprocess.run(
                [sh, str(installer), str(host_dir)],
                env=env,
                text=True,
                capture_output=True,
                check=False,
                timeout=45,
            )
            self.assertEqual(disabled.returncode, 0, disabled.stderr)
            disabled_state = json.loads((tmp_path / "firewall-state.json").read_text(encoding="utf-8"))
            self.assertTrue(all(not rules for rules in disabled_state.values()))
            containers = json.loads(state_path.read_text(encoding="utf-8"))["containers"]
            self.assertNotIn("amnezia-client-updates-host", containers)
            self.assertFalse(
                (tmp_path / "trust-anchor/amnezia/.client-update-host-firewall-state").exists()
            )

    @unittest.skipUnless(os.name == "posix" and find_sh(), "POSIX sh and flock are required")
    def test_update_host_persistent_cleanup_failure_recovers_from_durable_journal(self) -> None:
        sh = find_sh()
        assert sh
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            installer, host_dir, state_path, env = prepare_transactional_installer_harness(
                tmp_path, initial_transactional_docker_state()
            )
            env["FAKE_DOCKER_FAIL_BEFORE_PHASE"] = "cleanup-backup-main"
            first = subprocess.run(
                [sh, str(installer), str(host_dir)],
                env=env,
                text=True,
                capture_output=True,
                check=False,
                timeout=45,
            )
            self.assertNotEqual(first.returncode, 0)
            self.assertIn("transactional backup cleanup failed", first.stderr)
            journal = tmp_path / "trust-anchor/amnezia/.client-update-host-transaction"
            self.assertTrue(journal.is_file())
            self.assertIn("phase=committed_pending_cleanup", journal.read_text(encoding="utf-8"))
            first_log = (tmp_path / "docker.log").read_text(encoding="utf-8")
            self.assertEqual(first_log.count("|run-main|"), 1)

            env.pop("FAKE_DOCKER_FAIL_BEFORE_PHASE")
            recovered = subprocess.run(
                [sh, str(installer), str(host_dir)],
                env=env,
                text=True,
                capture_output=True,
                check=False,
                timeout=45,
            )
            self.assertEqual(recovered.returncode, 0, recovered.stderr)
            self.assertIn("Recovered committed update-host transaction", recovered.stdout)
            self.assertFalse(journal.exists())
            containers = json.loads(state_path.read_text(encoding="utf-8"))["containers"]
            self.assertFalse(any(".amnezia-backup." in name for name in containers))
            self.assertEqual(
                (tmp_path / "docker.log").read_text(encoding="utf-8").count("|run-main|"),
                1,
            )

    @unittest.skipUnless(os.name == "posix" and find_sh(), "POSIX sh and flock are required")
    def test_update_host_sigkill_recovery_rolls_back_by_durable_ids(self) -> None:
        sh = find_sh()
        assert sh
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            initial = initial_transactional_docker_state()
            expected_containers = json.loads(json.dumps(initial["containers"]))
            installer, host_dir, state_path, env = prepare_transactional_installer_harness(tmp_path, initial)
            entered = tmp_path / "entered-run-main"
            release = tmp_path / "release-run-main"
            env.update(
                {
                    "FAKE_DOCKER_HOLD_PHASE": "run-main",
                    "FAKE_DOCKER_HOLD_ENTERED": str(entered),
                    "FAKE_DOCKER_HOLD_RELEASE": str(release),
                }
            )
            process = subprocess.Popen(
                [sh, str(installer), str(host_dir)],
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                deadline = time.monotonic() + 20
                while not entered.exists() and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertTrue(entered.exists(), "installer did not reach the journaled run-main phase")
                process.kill()
                release.touch()
                process.communicate(timeout=10)
                time.sleep(0.2)
            finally:
                release.touch(exist_ok=True)
                if process.poll() is None:
                    process.kill()
                    process.communicate()

            journal = tmp_path / "trust-anchor/amnezia/.client-update-host-transaction"
            self.assertTrue(journal.is_file())
            recovery_env = env.copy()
            for key in ("FAKE_DOCKER_HOLD_PHASE", "FAKE_DOCKER_HOLD_ENTERED", "FAKE_DOCKER_HOLD_RELEASE"):
                recovery_env.pop(key, None)
            recovered = subprocess.run(
                [sh, str(installer), str(host_dir)],
                env=recovery_env,
                text=True,
                capture_output=True,
                check=False,
                timeout=45,
            )
            self.assertEqual(recovered.returncode, 0, recovered.stderr)
            self.assertIn("Recovered and rolled back incomplete update-host transaction", recovered.stderr)
            self.assertEqual(
                json.loads(state_path.read_text(encoding="utf-8"))["containers"],
                expected_containers,
            )
            self.assertFalse(journal.exists())

    @unittest.skipUnless(os.name == "posix" and find_sh(), "POSIX sh and flock are required")
    def test_update_host_installer_serializes_concurrent_runs(self) -> None:
        sh = find_sh()
        assert sh
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            installer, host_dir, state_path, base_env = prepare_transactional_installer_harness(
                tmp_path, initial_transactional_docker_state()
            )
            entered = tmp_path / "first-entered-docker"
            release = tmp_path / "release-first"
            first_env = base_env.copy()
            first_env.update(
                {
                    "FAKE_DOCKER_INVOCATION": "first",
                    "FAKE_DOCKER_HOLD_PHASE": "candidate-preflight",
                    "FAKE_DOCKER_HOLD_ENTERED": str(entered),
                    "FAKE_DOCKER_HOLD_RELEASE": str(release),
                }
            )
            second_env = base_env.copy()
            second_env["FAKE_DOCKER_INVOCATION"] = "second"

            first = subprocess.Popen(
                [sh, str(installer), str(host_dir)],
                env=first_env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            second: subprocess.Popen[str] | None = None
            try:
                deadline = time.monotonic() + 10
                while not entered.exists() and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertTrue(entered.exists(), "first installer did not reach the locked preflight")
                second = subprocess.Popen(
                    [sh, str(installer), str(host_dir)],
                    env=second_env,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                time.sleep(0.4)
                locked_log = (tmp_path / "docker.log").read_text(encoding="utf-8")
                self.assertNotIn("second|", locked_log)
                self.assertIsNone(second.poll(), "second installer bypassed the host-level lock")
                release.touch()
                first_stdout, first_stderr = first.communicate(timeout=30)
                second_stdout, second_stderr = second.communicate(timeout=30)
                self.assertEqual(first.returncode, 0, first_stderr + first_stdout)
                self.assertEqual(second.returncode, 0, second_stderr + second_stdout)
            finally:
                release.touch(exist_ok=True)
                if first.poll() is None:
                    first.kill()
                    first.communicate()
                if second is not None and second.poll() is None:
                    second.kill()
                    second.communicate()

            final_log = (tmp_path / "docker.log").read_text(encoding="utf-8")
            first_last = max(index for index, line in enumerate(final_log.splitlines()) if line.startswith("first|"))
            second_first = min(index for index, line in enumerate(final_log.splitlines()) if line.startswith("second|"))
            self.assertLess(first_last, second_first)
            final_state = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertTrue(final_state["containers"]["amnezia-client-updates"]["running"])
            self.assertFalse(any(".amnezia-backup." in name for name in final_state["containers"]))


class ManifestReleasePolicyTests(unittest.TestCase):
    def policy(self) -> dict[str, object]:
        generated_at = datetime.now(timezone.utc).replace(microsecond=0)
        expires_at = generated_at + timedelta(days=7)
        return {
            "schema": 2,
            "generation": 42,
            "generatedAt": generated_at.isoformat().replace("+00:00", "Z"),
            "expiresAt": expires_at.isoformat().replace("+00:00", "Z"),
            "channel": "canary",
            "rollout": {
                "percentage": 10,
                "cohortSaltId": "fleet-v1",
            },
            "eligibility": {
                "minimumVersion": "4.9.0.1",
                "maximumVersion": "4.9.0.10",
            },
            "healthDeadlineSeconds": 600,
        }

    def test_cohort_bucket_has_stable_cross_client_vectors(self) -> None:
        self.assertEqual(
            make_manifest.cohort_bucket("00000000-0000-0000-0000-000000000000", "fleet-v1"),
            8765,
        )
        self.assertEqual(
            make_manifest.cohort_bucket("123e4567-e89b-12d3-a456-426614174000", "fleet-v1"),
            4110,
        )
        self.assertEqual(
            make_manifest.cohort_bucket("FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF", "fleet-v1"),
            5782,
        )
        self.assertEqual(
            make_manifest.cohort_bucket(" 123E4567-E89B-12D3-A456-426614174000 ", "fleet-v1"),
            4110,
        )
        self.assertFalse(
            make_manifest.client_is_in_rollout("123e4567-e89b-12d3-a456-426614174000", "fleet-v1", 0)
        )
        self.assertTrue(
            make_manifest.client_is_in_rollout("123e4567-e89b-12d3-a456-426614174000", "fleet-v1", 100)
        )

        for invalid_percentage in (-1, 101, True, 10.5, "10"):
            with self.subTest(invalid_percentage=invalid_percentage), self.assertRaises(SystemExit):
                make_manifest.validate_rollout_percentage(invalid_percentage)
        for invalid_salt in ("", "contains space", "secret/value", "x" * 65):
            with self.subTest(invalid_salt=invalid_salt), self.assertRaises(SystemExit):
                make_manifest.validate_cohort_salt_id(invalid_salt)

    def test_release_policy_validation_is_strict(self) -> None:
        make_manifest.validate_release_policy(self.policy())

        invalid_policies: list[tuple[str, object, str]] = []
        policy = self.policy()
        policy["unknown"] = True
        invalid_policies.append(("unknown field", policy, "invalid fields"))
        policy = self.policy()
        policy["schema"] = True
        invalid_policies.append(("boolean schema", policy, "schema must be integer 2"))
        policy = self.policy()
        policy["schema"] = 2.0
        invalid_policies.append(("float schema", policy, "schema must be integer 2"))
        policy = self.policy()
        policy["generation"] = 0
        invalid_policies.append(("zero generation", policy, "generation must be an integer"))
        policy = self.policy()
        policy["generation"] = 9007199254740992
        invalid_policies.append(("generation outside JSON-safe integer range", policy, "9007199254740991"))
        policy = self.policy()
        policy["channel"] = "preview"
        invalid_policies.append(("unknown channel", policy, "stable, canary, or emergency"))
        policy = self.policy()
        policy["rollout"] = {"percentage": True, "cohortSaltId": "fleet-v1"}
        invalid_policies.append(("boolean percentage", policy, "rollout percentage"))
        policy = self.policy()
        policy["rollout"] = {"percentage": 10, "cohortSaltId": "fleet-v1", "extra": 1}
        invalid_policies.append(("rollout extra field", policy, "must contain exactly"))
        policy = self.policy()
        policy["eligibility"] = {"minimumVersion": "4.9.0.10", "maximumVersion": "4.9.0.1"}
        invalid_policies.append(("inverted versions", policy, "must not be newer"))
        policy = self.policy()
        policy["eligibility"] = {"minimumVersion": None}
        invalid_policies.append(("null minimum version", policy, "must be a release version"))
        policy = self.policy()
        policy["eligibility"] = {"minimumVersion": " 4.9.0.1 "}
        invalid_policies.append(("whitespace minimum version", policy, "without leading-zero components"))
        policy = self.policy()
        policy["eligibility"] = {"maximumVersion": None}
        invalid_policies.append(("null maximum version", policy, "must be a release version"))
        policy = self.policy()
        policy["healthDeadlineSeconds"] = False
        invalid_policies.append(("boolean deadline", policy, "healthDeadlineSeconds"))
        policy = self.policy()
        policy["healthDeadlineSeconds"] = 59
        invalid_policies.append(("deadline before readiness margin", policy, "integer from 60"))
        policy = self.policy()
        policy["generatedAt"] = "2026-07-20T10:00:00"
        invalid_policies.append(("missing timezone", policy, "canonical UTC"))
        policy = self.policy()
        policy["expiresAt"] = policy["generatedAt"]
        invalid_policies.append(("non-increasing expiry", policy, "must be later"))
        policy = self.policy()
        policy["previousVersion"] = None
        invalid_policies.append(("null previous version", policy, "must be a release version"))
        policy = self.policy()
        policy["rollback"] = None
        invalid_policies.append(("null rollback", policy, "requires previousVersion"))

        for name, invalid_policy, expected_error in invalid_policies:
            with self.subTest(name=name), self.assertRaises(SystemExit) as error:
                make_manifest.validate_release_policy(invalid_policy)
            self.assertIn(expected_error, str(error.exception))

    def test_release_policy_validates_rollback_artifact_schema(self) -> None:
        policy = self.policy()
        policy["previousVersion"] = "4.9.0.9"
        policy["rollback"] = {
            "version": "4.9.0.9",
            "platforms": {
                "windows-x64": {
                    "url": "files/rollback/42/4.9.0.9/AmneziaVPN.exe",
                    "sha256": "a" * 64,
                    "size": 123,
                    "autoInstall": True,
                }
            },
        }
        make_manifest.validate_release_policy(policy)

        invalid_policy = json.loads(json.dumps(policy))
        invalid_policy["rollback"]["platforms"]["windows-x64"]["url"] = "https://example.invalid/AmneziaVPN.exe"
        with self.assertRaises(SystemExit) as external_url:
            make_manifest.validate_release_policy(invalid_policy)
        self.assertIn("relative and stay under files/", str(external_url.exception))

        invalid_policy = json.loads(json.dumps(policy))
        invalid_policy["rollback"]["platforms"]["windows-x64"]["url"] = "files/%2e%2e/AmneziaVPN.exe"
        with self.assertRaises(SystemExit) as encoded_traversal:
            make_manifest.validate_release_policy(invalid_policy)
        self.assertIn("relative and stay under files/", str(encoded_traversal.exception))

        invalid_policy = json.loads(json.dumps(policy))
        invalid_policy["rollback"]["platforms"]["windows-x64"]["size"] = True
        with self.assertRaises(SystemExit) as boolean_size:
            make_manifest.validate_release_policy(invalid_policy)
        self.assertIn("positive integer size", str(boolean_size.exception))

        invalid_policy = json.loads(json.dumps(policy))
        invalid_policy["rollback"]["version"] = "4.9.0.8"
        with self.assertRaises(SystemExit) as wrong_version:
            make_manifest.validate_release_policy(invalid_policy)
        self.assertIn("must equal previousVersion", str(wrong_version.exception))

    def test_release_wrappers_expose_safe_fleet_policy_controls(self) -> None:
        expected_options = (
            "PayloadSchema",
            "Channel",
            "RolloutPercentage",
            "CohortSaltId",
            "MinimumEligibleVersion",
            "MaximumEligibleVersion",
            "HealthDeadlineSeconds",
            "PolicyGeneration",
            "GeneratedAt",
            "ExpiresAt",
            "PolicyValidForHours",
            "PreviousVersion",
            "RollbackArtifact",
        )
        for script_name in (
            "local_release.ps1",
            "rebuild_clients.ps1",
            "setup_release_workstation.ps1",
        ):
            script = (SCRIPT_DIR / script_name).read_text(encoding="utf-8")
            with self.subTest(script=script_name):
                for option in expected_options:
                    self.assertIn(f"${option}", script)
                self.assertIn("ValidateRange(60, 86400)", script)
                self.assertIn("ValidateRange(0, 9007199254740991)", script)
                if script_name == "rebuild_clients.ps1":
                    self.assertIn('ContainsKey("PayloadSchema")', script)
                else:
                    self.assertIn("PayloadSchema -eq 1", script)


@unittest.skipUnless(find_openssl(), "openssl is required for signed manifest tests")
class ManifestPublisherTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.openssl = find_openssl()
        assert self.openssl
        self.private_key = self.root / "selfhosted-update-private.pem"
        subprocess.run([self.openssl, "genpkey", "-algorithm", "Ed25519", "-out", str(self.private_key)], check=True)
        self.public_key = self.root / "selfhosted-update-public.pem"
        subprocess.run([self.openssl, "pkey", "-in", str(self.private_key), "-pubout", "-out", str(self.public_key)], check=True)
        self.public_key_base64 = base64.b64encode(self.public_key.read_bytes()).decode("ascii")
        self.previous_path = os.environ.get("PATH", "")
        os.environ["PATH"] = str(Path(self.openssl).parent) + os.pathsep + self.previous_path
        self.env = os.environ.copy()
        self.env["SELFHOSTED_SSH_TRUSTED_HOST"] = "85.208.87.69"
        self.env[
            "SELFHOSTED_SSH_TRUSTED_HOST_KEY_SHA256"
        ] = "SHA256:2UtHIoVd4Lft+s4E/LZlA8+reysEexYyhkt03rg8Rdg"

    def tearDown(self) -> None:
        os.environ["PATH"] = self.previous_path
        self.tmp.cleanup()

    def write_artifact(self, name: str, contents: bytes = b"dummy artifact") -> Path:
        artifact_dir = self.root / "artifacts"
        artifact_dir.mkdir(exist_ok=True)
        artifact = artifact_dir / name
        artifact.write_bytes(contents)
        return artifact

    def build_test_manifest(
        self,
        name: str,
        version: str,
        *,
        schema: int = 1,
        generation: int | None = None,
        artifact_seed: str | None = None,
        policy_valid_for_hours: int | None = None,
    ) -> bytes:
        artifact_seed = artifact_seed or name
        artifact = self.write_artifact(
            f"{artifact_seed}-{version}.exe",
            artifact_seed.encode("utf-8"),
        )
        out_dir = self.root / name
        command = [
            sys.executable,
            str(SCRIPT_DIR / "make_manifest.py"),
            "--version",
            version,
            "--base-url",
            "https://updates.example.invalid",
            "--private-key",
            str(self.private_key),
            "--out-dir",
            str(out_dir),
            "--artifact",
            f"windows-x64={artifact}",
            "--payload-schema",
            str(schema),
        ]
        if generation is not None:
            command += ["--policy-generation", str(generation)]
        if policy_valid_for_hours is not None:
            command += ["--policy-valid-for-hours", str(policy_valid_for_hours)]
        subprocess.run(command, check=True, capture_output=True, text=True, env=self.env)
        return (out_dir / "manifest.json").read_bytes()

    def test_manifest_tools_reject_noncanonical_leading_zero_versions(self) -> None:
        for value in (
            "04.9.0.11",
            "4.09.0.11",
            "4.9.00.11",
            "4.9.0.011",
            " 4.9.0.11 ",
            "2147483648.9.0.11",
        ):
            with self.subTest(value=value):
                with self.assertRaises(SystemExit):
                    make_manifest.validate_release_version(value)
                with self.assertRaises(SystemExit):
                    make_manifest.validate_release_version(value)

        self.assertEqual(make_manifest.validate_release_version("4.9.0.11"), "4.9.0.11")
        self.assertEqual(make_manifest.validate_release_version("4.9.0.11"), "4.9.0.11")

    def test_manifest_tools_reject_non_ed25519_keys(self) -> None:
        rsa_private_key = self.root / "rsa-private.pem"
        rsa_public_key = self.root / "rsa-public.pem"
        subprocess.run(
            [self.openssl, "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(rsa_private_key)],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [self.openssl, "pkey", "-in", str(rsa_private_key), "-pubout", "-out", str(rsa_public_key)],
            check=True,
            capture_output=True,
        )
        with self.assertRaises(SystemExit) as private_key_error:
            make_manifest.require_ed25519_private_key(rsa_private_key)
        self.assertIn("must contain an Ed25519 key", str(private_key_error.exception))
        with self.assertRaises(SystemExit) as key_pair_error:
            make_manifest.verify_public_key_matches_private(
                base64.b64encode(rsa_public_key.read_bytes()).decode("ascii"),
                rsa_private_key,
            )
        self.assertIn("must contain an Ed25519", str(key_pair_error.exception))

    def test_local_artifact_urls_are_content_addressed(self) -> None:
        version = "9.9.9.9"
        artifact = self.write_artifact(f"AmneziaVPN_{version}_windows_x64.exe", b"first build")
        first_out = self.root / "content-addressed-first"
        second_out = self.root / "content-addressed-second"

        base_command = [
            sys.executable,
            str(SCRIPT_DIR / "make_manifest.py"),
            "--version",
            version,
            "--base-url",
            "https://updates.example.invalid",
            "--private-key",
            str(self.private_key),
            "--artifact",
            f"windows-x64={artifact}",
        ]
        subprocess.run([*base_command, "--out-dir", str(first_out)], check=True, env=self.env)
        first_platform = manifest_payload(first_out / "manifest.json")["platforms"]["windows-x64"]

        artifact.write_bytes(b"second build")
        subprocess.run([*base_command, "--out-dir", str(second_out)], check=True, env=self.env)
        second_platform = manifest_payload(second_out / "manifest.json")["platforms"]["windows-x64"]

        self.assertNotEqual(first_platform["sha256"], second_platform["sha256"])
        self.assertNotEqual(first_platform["url"], second_platform["url"])
        for out_dir, platform in ((first_out, first_platform), (second_out, second_platform)):
            self.assertRegex(platform["url"], rf"^files/artifacts/{platform['sha256']}/")
            self.assertTrue((out_dir / unquote(platform["url"])).is_file())

    def test_headless_manifest_declares_required_artifact_format(self) -> None:
        version = "9.9.9.9"
        artifact = self.write_artifact(
            f"AmneziaHeadless_{version}_linux_x64.tar.gz",
            b"headless release archive",
        )
        provisioning = self.root / f"AmneziaHeadless_{version}_linux_x64_provisioning.tar.gz"
        package_files = {
            name: f"fixture-{name}\n".encode("utf-8")
            for name in make_manifest.HEADLESS_PROVISIONING_FILES
            if name not in {"package-manifest.json", "SHA256SUMS"}
        }
        package_files["package-manifest.json"] = json.dumps(
            {
                "schema": 2,
                "version": version,
                "platform": "linux-headless-x64",
                "installModes": ["fresh", "upgrade"],
                "artifacts": ["amneziad", "amnezia-cli", "amneziad.service"],
                "service": "amneziad.service",
                "servicePaths": [
                    "/etc/systemd/system/amneziad.service",
                    "/run/systemd/system/amneziad.service",
                    "/usr/local/lib/systemd/system/amneziad.service",
                    "/usr/lib/systemd/system/amneziad.service",
                    "/lib/systemd/system/amneziad.service",
                ],
                "trustAnchor": "external-ed25519-sha256-receipt",
                "runtimeManifest": "runtime-dependencies.json",
                "checksums": "SHA256SUMS",
                "runtimeText": "runtime-dependencies.txt",
            },
            separators=(",", ":"),
        ).encode("utf-8")
        package_files["SHA256SUMS"] = (
            "".join(
                f"{hashlib.sha256(package_files[name]).hexdigest()}  {name}\n"
                for name in make_manifest.HEADLESS_PROVISIONING_FILES
                if name != "SHA256SUMS"
            )
        ).encode("utf-8")
        with tarfile.open(provisioning, mode="w:gz") as archive:
            root_member = tarfile.TarInfo("headless-package/")
            root_member.type = tarfile.DIRTYPE
            root_member.mode = 0o755
            archive.addfile(root_member)
            for name in make_manifest.HEADLESS_PROVISIONING_FILES:
                payload = package_files[name]
                member = tarfile.TarInfo(f"headless-package/{name}")
                member.size = len(payload)
                member.mode = 0o644
                archive.addfile(member, io.BytesIO(payload))
        out_dir = self.root / "headless-format"
        subprocess.run(
            [
                sys.executable,
                str(SCRIPT_DIR / "make_manifest.py"),
                "--version",
                version,
                "--base-url",
                "https://192.0.2.10:17865",
                "--private-key",
                str(self.private_key),
                "--out-dir",
                str(out_dir),
                "--headless-provisioning",
                str(provisioning),
                "--artifact",
                f"linux-headless-x64={artifact}",
            ],
            check=True,
            capture_output=True,
            text=True,
            env=self.env,
        )
        platform = manifest_payload(out_dir / "manifest.json")["platforms"]["linux-headless-x64"]
        self.assertEqual(platform["format"], make_manifest.HEADLESS_ARTIFACT_FORMAT)
        manifest = manifest_payload(out_dir / "manifest.json")
        self.assertEqual(
            manifest["headlessProvisioning"]["format"],
            make_manifest.HEADLESS_PROVISIONING_FORMAT,
        )
        self.assertEqual(
            manifest["headlessProvisioning"]["packageFiles"],
            list(make_manifest.HEADLESS_PROVISIONING_FILES),
        )
        make_manifest.validate_local_artifact_metadata(
            "linux-headless-x64",
            platform,
            context="test manifest",
        )

        without_format = dict(platform)
        without_format.pop("format")
        with self.assertRaises(SystemExit):
            make_manifest.validate_local_artifact_metadata(
                "linux-headless-x64",
                without_format,
                context="test manifest",
            )

    def test_targeted_non_headless_manifest_does_not_require_provisioning(self) -> None:
        out_dir = self.root / "targeted-non-headless"
        self.build_test_manifest("targeted-non-headless", "9.9.9.9")
        manifest = manifest_payload(out_dir / "manifest.json")
        self.assertEqual(set(manifest["platforms"]), {"windows-x64"})
        self.assertNotIn("headlessProvisioning", manifest)

    def test_headless_manifest_requires_provisioning_bundle(self) -> None:
        artifact = self.write_artifact(
            "AmneziaHeadless_9.9.9.9_linux_x64.tar.gz",
            b"headless release archive",
        )
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT_DIR / "make_manifest.py"),
                "--version",
                "9.9.9.9",
                "--base-url",
                "https://192.0.2.10:17865",
                "--private-key",
                str(self.private_key),
                "--out-dir",
                str(self.root / "missing-provisioning"),
                "--artifact",
                f"linux-headless-x64={artifact}",
            ],
            capture_output=True,
            text=True,
            env=self.env,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "Linux headless artifacts require --headless-provisioning",
            result.stderr + result.stdout,
        )

    def test_manifest_rejects_case_insensitive_artifact_basename_collisions(self) -> None:
        first_dir = self.root / "case-first"
        second_dir = self.root / "case-second"
        first_dir.mkdir()
        second_dir.mkdir()
        first = first_dir / "Client.bin"
        second = second_dir / "client.BIN"
        first.write_bytes(b"first")
        second.write_bytes(b"second")
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT_DIR / "make_manifest.py"),
                "--version",
                "9.9.9.9",
                "--base-url",
                "https://updates.example.invalid",
                "--private-key",
                str(self.private_key),
                "--out-dir",
                str(self.root / "case-collision-out"),
                "--artifact",
                f"windows-x64={first}",
                "--artifact",
                f"linux-x64={second}",
            ],
            text=True,
            capture_output=True,
            env=self.env,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate artifact output filename", result.stderr + result.stdout)

    def test_manifest_rejects_case_insensitive_rollback_basename_collisions(self) -> None:
        version = "9.9.9.9"
        previous_version = "9.9.9.8"
        current_windows = self.write_artifact(f"AmneziaVPN_{version}_windows_x64.exe", b"current-windows")
        current_linux = self.write_artifact(f"AmneziaVPN_{version}_linux_x64.run", b"current-linux")
        first_dir = self.root / "rollback-case-first"
        second_dir = self.root / "rollback-case-second"
        first_dir.mkdir()
        second_dir.mkdir()
        first = first_dir / "Rollback.bin"
        second = second_dir / "rollback.BIN"
        first.write_bytes(b"first")
        second.write_bytes(b"second")
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT_DIR / "make_manifest.py"),
                "--version",
                version,
                "--payload-schema",
                "2",
                "--policy-generation",
                "42",
                "--previous-version",
                previous_version,
                "--base-url",
                "https://updates.example.invalid",
                "--private-key",
                str(self.private_key),
                "--out-dir",
                str(self.root / "rollback-case-collision-out"),
                "--artifact",
                f"windows-x64={current_windows}",
                "--artifact",
                f"linux-x64={current_linux}",
                "--rollback-artifact",
                f"windows-x64={first}",
                "--rollback-artifact",
                f"linux-x64={second}",
            ],
            text=True,
            capture_output=True,
            env=self.env,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate rollback artifact output filename", result.stderr + result.stdout)

    def test_manifest_generator_rejects_response_larger_than_client_cap(self) -> None:
        version = "9.9.9.9"
        artifact = self.write_artifact(f"AmneziaVPN_{version}_windows_x64.exe", b"windows")
        changelog = self.root / "oversized-changelog.txt"
        changelog.write_text("x" * (800 * 1024), encoding="utf-8")
        out_dir = self.root / "oversized-manifest"
        (out_dir / "files").mkdir(parents=True)
        previous_manifest = b"previous signed channel placeholder"
        previous_artifact = b"previous artifact"
        (out_dir / "manifest.json").write_bytes(previous_manifest)
        (out_dir / "files" / artifact.name).write_bytes(previous_artifact)
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT_DIR / "make_manifest.py"),
                "--version",
                version,
                "--base-url",
                "https://updates.example.invalid",
                "--private-key",
                str(self.private_key),
                "--out-dir",
                str(out_dir),
                "--artifact",
                f"windows-x64={artifact}",
                "--changelog-file",
                str(changelog),
            ],
            text=True,
            capture_output=True,
            env=self.env,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("client-compatible 1 MiB response limit", result.stderr + result.stdout)
        self.assertEqual((out_dir / "manifest.json").read_bytes(), previous_manifest)
        self.assertEqual((out_dir / "files" / artifact.name).read_bytes(), previous_artifact)

    def test_manifest_output_switch_reports_success_after_backup_cleanup_edge_cases(self) -> None:
        file_out = self.root / "output-was-file"
        file_out.write_bytes(b"old file")
        staged_file_replacement = self.root / "staged-file-replacement"
        staged_file_replacement.mkdir()
        (staged_file_replacement / "manifest.json").write_bytes(b"new tree")

        make_manifest.replace_output_tree(staged_file_replacement, file_out)

        self.assertEqual((file_out / "manifest.json").read_bytes(), b"new tree")
        self.assertEqual(list(self.root.glob(".output-was-file.previous-*")), [])

        directory_out = self.root / "output-with-readonly-file"
        directory_out.mkdir()
        readonly = directory_out / "readonly.bin"
        readonly.write_bytes(b"old tree")
        os.chmod(readonly, 0o444)
        staged_directory_replacement = self.root / "staged-directory-replacement"
        staged_directory_replacement.mkdir()
        (staged_directory_replacement / "manifest.json").write_bytes(b"newer tree")

        make_manifest.replace_output_tree(staged_directory_replacement, directory_out)

        self.assertEqual((directory_out / "manifest.json").read_bytes(), b"newer tree")
        self.assertEqual(list(self.root.glob(".output-with-readonly-file.previous-*")), [])

    def signature_verifies(self, payload_bytes: bytes, signature_base64: str) -> bool:
        with tempfile.TemporaryDirectory(dir=self.root) as tmp:
            tmp_path = Path(tmp)
            payload_path = tmp_path / "payload.json"
            signature_path = tmp_path / "payload.sig"
            payload_path.write_bytes(payload_bytes)
            signature_path.write_bytes(base64.b64decode(signature_base64))
            result = subprocess.run(
                [
                    self.openssl,
                    "pkeyutl",
                    "-verify",
                    "-rawin",
                    "-pubin",
                    "-inkey",
                    str(self.public_key),
                    "-in",
                    str(payload_path),
                    "-sigfile",
                    str(signature_path),
                ],
                text=True,
                capture_output=True,
            )
            return result.returncode == 0

    def test_manifest_schema_one_stays_compatible_and_rejects_restrictive_policy(self) -> None:
        version = "9.9.9.9"
        artifact = self.write_artifact(f"AmneziaVPN_{version}_windows_x64.exe", b"windows-v1")
        out_dir = self.root / "schema-one"
        base_command = [
            sys.executable,
            str(SCRIPT_DIR / "make_manifest.py"),
            "--version",
            version,
            "--base-url",
            "http://172.29.172.252:17865",
            "--private-key",
            str(self.private_key),
            "--artifact",
            f"windows-x64={artifact}",
        ]
        result = subprocess.run(
            [*base_command, "--out-dir", str(out_dir)],
            env=self.env,
            text=True,
            capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        payload = manifest_payload(out_dir / "manifest.json")
        self.assertEqual(payload["schema"], 1)
        self.assertNotIn("releasePolicy", payload)

        restrictive_cases = {
            "channel": ["--channel", "canary"],
            "percentage": ["--rollout-percentage", "99"],
            "salt": ["--cohort-salt-id", "canary-v1"],
            "minimum": ["--minimum-eligible-version", "4.9.0.1"],
            "maximum": ["--maximum-eligible-version", "9.9.9.8"],
            "health": ["--health-deadline-seconds", "601"],
            "generation": ["--policy-generation", "42"],
            "generated-at": ["--generated-at", "2026-07-20T10:00:00Z"],
            "expires-at": ["--expires-at", "2026-07-27T10:00:00Z"],
            "validity": ["--policy-valid-for-hours", "169"],
            "previous": ["--previous-version", "9.9.9.8"],
            "rollback-artifact": ["--rollback-artifact", f"windows-x64={artifact}"],
        }
        for name, flags in restrictive_cases.items():
            with self.subTest(name=name):
                restrictive_out_dir = self.root / f"schema-one-restrictive-{name}"
                restrictive = subprocess.run(
                    [*base_command, "--out-dir", str(restrictive_out_dir), *flags],
                    env=self.env,
                    text=True,
                    capture_output=True,
                )
                self.assertNotEqual(restrictive.returncode, 0)
                self.assertIn("requires --payload-schema 2", restrictive.stderr + restrictive.stdout)
                self.assertFalse((restrictive_out_dir / "manifest.json").exists())

        missing_generation_out_dir = self.root / "schema-two-missing-generation"
        missing_generation = subprocess.run(
            [
                *base_command,
                "--out-dir",
                str(missing_generation_out_dir),
                "--payload-schema",
                "2",
            ],
            env=self.env,
            text=True,
            capture_output=True,
        )
        self.assertNotEqual(missing_generation.returncode, 0)
        self.assertIn("--policy-generation is required", missing_generation.stderr + missing_generation.stdout)
        self.assertFalse((missing_generation_out_dir / "manifest.json").exists())

        short_deadline_out_dir = self.root / "schema-two-short-health-deadline"
        short_deadline = subprocess.run(
            [
                *base_command,
                "--out-dir",
                str(short_deadline_out_dir),
                "--payload-schema",
                "2",
                "--policy-generation",
                "1",
                "--health-deadline-seconds",
                "59",
            ],
            env=self.env,
            text=True,
            capture_output=True,
        )
        self.assertNotEqual(short_deadline.returncode, 0)
        self.assertIn("integer from 60", short_deadline.stderr + short_deadline.stdout)
        self.assertFalse((short_deadline_out_dir / "manifest.json").exists())

        unsafe_generation_out_dir = self.root / "schema-two-unsafe-generation"
        unsafe_generation = subprocess.run(
            [
                *base_command,
                "--out-dir",
                str(unsafe_generation_out_dir),
                "--payload-schema",
                "2",
                "--policy-generation",
                "9007199254740992",
            ],
            env=self.env,
            text=True,
            capture_output=True,
        )
        self.assertNotEqual(unsafe_generation.returncode, 0)
        self.assertIn("9007199254740991", unsafe_generation.stderr + unsafe_generation.stdout)
        self.assertFalse((unsafe_generation_out_dir / "manifest.json").exists())

    def test_manifest_schema_two_signs_canary_eligibility_expiry_and_rollback(self) -> None:
        version = "9.9.9.9"
        previous_version = "9.9.9.8"
        generated_at = datetime.now(timezone.utc).replace(microsecond=0)
        expires_at = generated_at + timedelta(days=7)
        generated_at_z = generated_at.isoformat().replace("+00:00", "Z")
        expires_at_z = expires_at.isoformat().replace("+00:00", "Z")
        generated_at_plus_three = generated_at.astimezone(timezone(timedelta(hours=3))).isoformat()
        artifact = self.write_artifact(f"AmneziaVPN_{version}_windows_x64.exe", b"windows-current")
        rollback_artifact = self.write_artifact(
            f"AmneziaVPN_{previous_version}_windows_x64.exe",
            b"windows-rollback",
        )
        out_dir = self.root / "schema-two"
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT_DIR / "make_manifest.py"),
                "--version",
                version,
                "--payload-schema",
                "2",
                "--channel",
                "canary",
                "--rollout-percentage",
                "10",
                "--cohort-salt-id",
                "canary-2026q3",
                "--minimum-eligible-version",
                "4.9.0.1",
                "--maximum-eligible-version",
                "9.9.9.8",
                "--health-deadline-seconds",
                "900",
                "--policy-generation",
                "42",
                "--generated-at",
                generated_at_plus_three,
                "--expires-at",
                expires_at_z,
                "--previous-version",
                previous_version,
                "--rollback-artifact",
                f"windows-x64={rollback_artifact}",
                "--base-url",
                "http://172.29.172.252:17865",
                "--private-key",
                str(self.private_key),
                "--public-key-base64",
                self.public_key_base64,
                "--out-dir",
                str(out_dir),
                "--artifact",
                f"windows-x64={artifact}",
                "--auto-install",
            ],
            env=self.env,
            text=True,
            capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn("Verified schema-2 manifest signature", result.stdout)

        manifest = json.loads((out_dir / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["schema"], "amnezia-selfhosted-update-v1")
        payload_bytes = base64.urlsafe_b64decode(manifest["payload"] + "=" * (-len(manifest["payload"]) % 4))
        self.assertTrue(self.signature_verifies(payload_bytes, manifest["signature"]))
        payload = json.loads(payload_bytes.decode("utf-8"))
        self.assertEqual(payload["schema"], 2)
        policy = payload["releasePolicy"]
        self.assertEqual(policy["schema"], 2)
        self.assertEqual(policy["generation"], 42)
        self.assertEqual(policy["generatedAt"], generated_at_z)
        self.assertEqual(policy["expiresAt"], expires_at_z)
        self.assertEqual(policy["channel"], "canary")
        self.assertEqual(policy["rollout"], {"percentage": 10, "cohortSaltId": "canary-2026q3"})
        self.assertEqual(
            policy["eligibility"],
            {"minimumVersion": "4.9.0.1", "maximumVersion": "9.9.9.8"},
        )
        self.assertEqual(policy["healthDeadlineSeconds"], 900)
        self.assertEqual(policy["previousVersion"], previous_version)
        rollback_metadata = policy["rollback"]["platforms"]["windows-x64"]
        self.assertEqual(
            rollback_metadata["url"],
            f"files/rollback/42/{previous_version}/{rollback_artifact.name}",
        )
        self.assertEqual(rollback_metadata["sha256"], hashlib.sha256(b"windows-rollback").hexdigest())
        self.assertEqual(rollback_metadata["size"], len(b"windows-rollback"))
        self.assertTrue(rollback_metadata["autoInstall"])
        self.assertEqual(
            (out_dir / rollback_metadata["url"]).read_bytes(),
            b"windows-rollback",
        )
        make_manifest.validate_release_policy(policy)

        payload["releasePolicy"]["rollout"]["percentage"] = 11
        tampered_payload_bytes = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        self.assertFalse(self.signature_verifies(tampered_payload_bytes, manifest["signature"]))

    def test_manifest_schema_two_rejects_expired_future_and_overlong_time_policy(self) -> None:
        version = "9.9.9.9"
        artifact = self.write_artifact(f"AmneziaVPN_{version}_windows_x64.exe", b"windows-current")
        now = datetime.now(timezone.utc).replace(microsecond=0)

        def utc(value: datetime) -> str:
            return value.isoformat().replace("+00:00", "Z")

        base_command = [
            sys.executable,
            str(SCRIPT_DIR / "make_manifest.py"),
            "--version",
            version,
            "--payload-schema",
            "2",
            "--policy-generation",
            "42",
            "--base-url",
            "https://updates.example.invalid",
            "--private-key",
            str(self.private_key),
            "--artifact",
            f"windows-x64={artifact}",
        ]
        cases = {
            "expired": (
                utc(now - timedelta(hours=2)),
                utc(now - timedelta(hours=1)),
                "expired",
            ),
            "future": (
                utc(now + timedelta(days=1)),
                utc(now + timedelta(days=2)),
                "future",
            ),
            "overlong": (
                utc(now),
                utc(now + timedelta(hours=make_manifest.MAX_POLICY_VALIDITY_HOURS + 1)),
                "validity",
            ),
        }
        for name, (generated_at, expires_at, expected_error) in cases.items():
            with self.subTest(name=name):
                result = subprocess.run(
                    [
                        *base_command,
                        "--out-dir",
                        str(self.root / f"invalid-time-{name}"),
                        "--generated-at",
                        generated_at,
                        "--expires-at",
                        expires_at,
                    ],
                    text=True,
                    capture_output=True,
                    env=self.env,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected_error, (result.stderr + result.stdout).lower())

    def test_manifest_revalidates_expiry_after_artifact_staging(self) -> None:
        version = "9.9.9.9"
        artifact = self.write_artifact(f"AmneziaVPN_{version}_windows_x64.exe", b"windows-current")
        start = datetime(2030, 1, 1, tzinfo=timezone.utc)

        class AdvancingDateTime(datetime):
            calls = 0

            @classmethod
            def now(cls, tz=None):
                cls.calls += 1
                value = start if cls.calls <= 2 else start + timedelta(seconds=2)
                return value if tz is not None else value.replace(tzinfo=None)

        old_argv = sys.argv
        try:
            sys.argv = [
                str(SCRIPT_DIR / "make_manifest.py"),
                "--version",
                version,
                "--payload-schema",
                "2",
                "--policy-generation",
                "42",
                "--generated-at",
                start.isoformat().replace("+00:00", "Z"),
                "--expires-at",
                (start + timedelta(seconds=1)).isoformat().replace("+00:00", "Z"),
                "--base-url",
                "https://updates.example.invalid",
                "--private-key",
                str(self.private_key),
                "--out-dir",
                str(self.root / "expires-during-staging"),
                "--artifact",
                f"windows-x64={artifact}",
            ]
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", ResourceWarning)
                with mock.patch.object(make_manifest, "datetime", AdvancingDateTime):
                    with self.assertRaises(SystemExit) as expired:
                        make_manifest.main()
        finally:
            sys.argv = old_argv

        self.assertIn("already expired", str(expired.exception))
        self.assertFalse((self.root / "expires-during-staging" / "manifest.json").exists())

    def test_manifest_refuses_macos_rollback_until_all_macos_clients_can_apply_it(self) -> None:
        version = "9.9.9.9"
        previous_version = "9.9.9.8"
        artifact = self.write_artifact(f"AmneziaVPN_{version}_macos_x64.pkg", b"macos-current")
        rollback_artifact = self.write_artifact(
            f"AmneziaVPN_{previous_version}_macos_x64.pkg",
            b"macos-rollback",
        )
        for platform in ("macos-x64", "macos-arm64", "macos"):
            with self.subTest(platform=platform):
                result = subprocess.run(
                    [
                        sys.executable,
                        str(SCRIPT_DIR / "make_manifest.py"),
                        "--version",
                        version,
                        "--payload-schema",
                        "2",
                        "--policy-generation",
                        "42",
                        "--previous-version",
                        previous_version,
                        "--rollback-artifact",
                        f"{platform}={rollback_artifact}",
                        "--base-url",
                        "https://updates.example.invalid",
                        "--private-key",
                        str(self.private_key),
                        "--out-dir",
                        str(self.root / f"macos-rollback-incompatible-{platform}"),
                        "--artifact",
                        f"{platform}={artifact}",
                    ],
                    text=True,
                    capture_output=True,
                    env=self.env,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("macos", (result.stderr + result.stdout).lower())
                self.assertIn("rollback", (result.stderr + result.stdout).lower())

    def test_publish_rejects_mismatched_public_key(self) -> None:
        version = "9.9.9.9"
        self.write_artifact(f"AmneziaVPN_{version}_windows_x64.exe", b"windows")
        other_private_key = self.root / "other-private.pem"
        other_public_key = self.root / "other-public.pem"
        subprocess.run([self.openssl, "genpkey", "-algorithm", "Ed25519", "-out", str(other_private_key)], check=True)
        subprocess.run([self.openssl, "pkey", "-in", str(other_private_key), "-pubout", "-out", str(other_public_key)], check=True)

        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT_DIR / "make_manifest.py"),
                "--version",
                version,
                "--private-key",
                str(self.private_key),
                "--public-key-base64",
                base64.b64encode(other_public_key.read_bytes()).decode("ascii"),
                "--artifact",
                f"windows-x64={self.root / 'artifacts' / f'AmneziaVPN_{version}_windows_x64.exe'}",
                "--out-dir",
                str(self.root / "out-mismatched-key"),
                "--base-url",
                "http://172.29.172.252:17865",
                "--require-platform",
                "windows-x64",
            ],
            env=self.env,
            text=True,
            capture_output=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match SELFHOSTED_UPDATE_PRIVATE_KEY", result.stderr + result.stdout)

    @unittest.skipUnless(find_powershell(), "PowerShell is required for the local release wrapper smoke test")
    def test_local_release_wrapper_verifies_local_non_apple_artifacts(self) -> None:
        powershell = find_powershell()
        assert powershell
        version = "9.9.9.9"
        for name in (
            f"AmneziaVPN_{version}_windows_x64.exe",
            f"AmneziaVPN_{version}_linux_x64.run",
            f"AmneziaVPN_{version}_android9+_arm64-v8a.apk",
            f"AmneziaVPN_{version}_android9+_universal.apk",
            f"AmneziaVPN_{version}_android9+_armeabi-v7a.apk",
            f"AmneziaVPN_{version}_android9+_x86.apk",
            f"AmneziaVPN_{version}_android9+_x86_64.apk",
        ):
            self.write_artifact(name, f"artifact-{name}".encode("utf-8"))

        out_dir = self.root / "local-release-out"
        result = subprocess.run(
            [
                powershell,
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(SCRIPT_DIR / "local_release.ps1"),
                "-Version",
                version,
                "-SkipBuild",
                "-BuildPlatform",
                "windows,linux,android",
                "-RequirePlatform",
                "windows-x64,linux-x64,android-arm64-v8a",
                "-NoBundleUpdatesInWindowsClient",
                "-ArtifactDir",
                str(self.root / "artifacts"),
                "-OutDir",
                str(out_dir),
                "-BaseUrl",
                "http://172.29.172.252:17865",
                "-SshTrustedHost",
                self.env["SELFHOSTED_SSH_TRUSTED_HOST"],
                "-SshTrustedHostKeySha256",
                self.env["SELFHOSTED_SSH_TRUSTED_HOST_KEY_SHA256"],
                "-PrivateKey",
                str(self.private_key),
                "-PublicKeyBase64",
                self.public_key_base64,
            ],
            env=self.env,
            text=True,
            capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn("Verified self-hosted update manifest signature and required platforms", result.stdout)
        payload = manifest_payload(out_dir / "manifest.json")
        self.assertEqual(
            set(payload["platforms"]),
            {
                "windows-x64",
                "linux-x64",
                "android-arm64-v8a",
            },
        )
        self.assertNotIn("ios", payload["platforms"])
        self.assertNotIn("macos-x64", payload["platforms"])
        self.assertNotIn("android", payload["platforms"])
        self.assertNotIn("android-armeabi-v7a", payload["platforms"])
        self.assertNotIn("android-x86", payload["platforms"])
        self.assertNotIn("android-x86_64", payload["platforms"])
        for platform, artifact in payload["platforms"].items():
            self.assertTrue(artifact["url"].startswith("files/"), platform)
            self.assertNotIn("172.29.172.252", artifact["url"])
        for stale_name in (
            f"AmneziaVPN_{version}_android9+_universal.apk",
            f"AmneziaVPN_{version}_android9+_armeabi-v7a.apk",
            f"AmneziaVPN_{version}_android9+_x86.apk",
            f"AmneziaVPN_{version}_android9+_x86_64.apk",
        ):
            self.assertFalse((self.root / "artifacts" / stale_name).exists())

    @unittest.skipUnless(find_powershell(), "PowerShell is required for the schema-2 local release smoke test")
    def test_local_release_wrapper_forwards_schema_two_policy(self) -> None:
        powershell = find_powershell()
        assert powershell
        version = "9.9.9.9"
        previous_version = "9.9.9.8"
        artifact = self.write_artifact(f"AmneziaVPN_{version}_windows_x64.exe", b"local-current")
        rollback_artifact = self.write_artifact(
            f"AmneziaVPN_{previous_version}_windows_x64.exe",
            b"local-rollback",
        )
        out_dir = self.root / "local-schema-two"
        result = subprocess.run(
            [
                powershell,
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(SCRIPT_DIR / "local_release.ps1"),
                "-Version",
                version,
                "-SkipBuild",
                "-NoBundleUpdatesInWindowsClient",
                "-BuildPlatform",
                "windows",
                "-RequirePlatform",
                "windows-x64",
                "-ArtifactDir",
                str(artifact.parent),
                "-OutDir",
                str(out_dir),
                "-BaseUrl",
                "http://172.29.172.252:17865",
                "-PrivateKey",
                str(self.private_key),
                "-PublicKeyBase64",
                self.public_key_base64,
                "-PayloadSchema",
                "2",
                "-Channel",
                "canary",
                "-RolloutPercentage",
                "50",
                "-PolicyGeneration",
                "44",
                "-PreviousVersion",
                previous_version,
                "-RollbackArtifact",
                f"windows-x64={rollback_artifact}",
            ],
            env=self.env,
            text=True,
            capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        payload = manifest_payload(out_dir / "manifest.json")
        self.assertEqual(payload["schema"], 2)
        self.assertEqual(payload["releasePolicy"]["generation"], 44)
        self.assertEqual(payload["releasePolicy"]["rollout"]["percentage"], 50)

    @unittest.skipUnless(find_powershell(), "PowerShell is required for the local release wrapper smoke test")
    def test_local_release_preflight_rejects_missing_unpaired_and_malformed_ssh_pins(self) -> None:
        powershell = find_powershell()
        assert powershell

        command = [
            powershell,
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(SCRIPT_DIR / "local_release.ps1"),
            "-Version",
            "9.9.9.9",
            "-Preflight",
            "-BuildPlatform",
            "windows",
            "-BaseUrl",
            "http://172.29.172.252:17865",
            "-PrivateKey",
            str(self.private_key),
            "-PublicKeyBase64",
            self.public_key_base64,
        ]
        cases = []

        missing = self.env.copy()
        missing.pop("SELFHOSTED_SSH_TRUSTED_HOST", None)
        missing.pop("SELFHOSTED_SSH_TRUSTED_HOST_KEY_SHA256", None)
        cases.append(("missing", missing, "are both required"))

        unpaired = self.env.copy()
        unpaired.pop("SELFHOSTED_SSH_TRUSTED_HOST_KEY_SHA256", None)
        cases.append(("unpaired", unpaired, "are both required"))

        malformed = self.env.copy()
        malformed["SELFHOSTED_SSH_TRUSTED_HOST_KEY_SHA256"] += "="
        cases.append(("malformed", malformed, "canonical SHA256"))

        for name, environment, expected_error in cases:
            with self.subTest(case=name):
                result = subprocess.run(command, env=environment, text=True, capture_output=True)
                self.assertNotEqual(result.returncode, 0, result.stderr + result.stdout)
                self.assertIn(expected_error, result.stderr + result.stdout)

    @unittest.skipUnless(find_powershell(), "PowerShell is required for the local release wrapper smoke test")
    def test_local_release_preflight_validates_local_inputs_without_building(self) -> None:
        powershell = find_powershell()
        assert powershell

        out_dir = self.root / "preflight-out"
        result = subprocess.run(
            [
                powershell,
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(SCRIPT_DIR / "local_release.ps1"),
                "-Version",
                "9.9.9.9",
                "-Preflight",
                "-BuildPlatform",
                "windows",
                "-OutDir",
                str(out_dir),
                "-BaseUrl",
                "http://172.29.172.252:17865",
                "-PrivateKey",
                str(self.private_key),
                "-PublicKeyBase64",
                self.public_key_base64,
            ],
            env=self.env,
            text=True,
            capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn("Preflight OK", result.stdout)
        self.assertFalse((out_dir / "manifest.json").exists())

    @unittest.skipUnless(find_powershell() and find_wsl(), "PowerShell and WSL are required for the Linux local preflight smoke test")
    def test_local_release_linux_preflight_converts_windows_paths_for_wsl(self) -> None:
        powershell = find_powershell()
        assert powershell

        qt_root = self.root / "Qt" / "6.99.0"
        qt_toolchain = qt_root / "gcc_64" / "lib" / "cmake" / "Qt6" / "qt.toolchain.cmake"
        qt_toolchain.parent.mkdir(parents=True)
        qt_toolchain.write_text("# fake qt toolchain\n", encoding="utf-8")
        for module in ("Qt6RemoteObjects", "Qt6Core5Compat"):
            module_config = qt_root / "gcc_64" / "lib" / "cmake" / module / f"{module}Config.cmake"
            module_config.parent.mkdir(parents=True)
            module_config.write_text("# fake module\n", encoding="utf-8")
        qif_root = self.root / "Qt" / "Tools" / "QtInstallerFramework" / "9.9"
        (qif_root / "bin").mkdir(parents=True)
        (qif_root / "bin" / "binarycreator").write_text("#!/bin/sh\n", encoding="utf-8")
        wsl_qif_root = to_wsl_path(qif_root)

        result = subprocess.run(
            [
                powershell,
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(SCRIPT_DIR / "local_release.ps1"),
                "-Version",
                "9.9.9.9",
                "-Preflight",
                "-BuildPlatform",
                "linux",
                "-BaseUrl",
                "http://172.29.172.252:17865",
                "-PrivateKey",
                str(self.private_key),
                "-PublicKeyBase64",
                self.public_key_base64,
            ],
            env={
                **self.env,
                "QT_ROOT_PATH": str(qt_root / "gcc_64"),
                "QIF_ROOT_PATH": str(qif_root),
                "WSL_QIF_ROOT_PATH": wsl_qif_root,
            },
            text=True,
            capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn("Preflight OK", result.stdout)
        self.assertNotIn("Failed to convert path to WSL path", result.stderr + result.stdout)

    @unittest.skipUnless(find_powershell() and find_wsl(), "PowerShell and WSL are required for the Android local preflight smoke test")
    def test_local_release_android_preflight_accepts_single_qt6_android_kit(self) -> None:
        powershell = find_powershell()
        assert powershell

        qt_root = self.root / "Qt" / "6.99.0"
        for kit in ("gcc_64", "android"):
            toolchain = qt_root / kit / "lib" / "cmake" / "Qt6" / "qt.toolchain.cmake"
            toolchain.parent.mkdir(parents=True)
            toolchain.write_text("# fake qt toolchain\n", encoding="utf-8")
        host_tools = qt_root / "gcc_64" / "lib" / "cmake" / "Qt6RemoteObjectsTools" / "Qt6RemoteObjectsToolsConfig.cmake"
        host_tools.parent.mkdir(parents=True)
        host_tools.write_text("# fake remote objects tools\n", encoding="utf-8")
        host_core5 = qt_root / "gcc_64" / "lib" / "cmake" / "Qt6Core5Compat" / "Qt6Core5CompatConfig.cmake"
        host_core5.parent.mkdir(parents=True)
        host_core5.write_text("# fake core5 compat\n", encoding="utf-8")
        for module in ("Qt6RemoteObjects", "Qt6Core5Compat"):
            module_config = qt_root / "android" / "lib" / "cmake" / module / f"{module}Config.cmake"
            module_config.parent.mkdir(parents=True)
            module_config.write_text("# fake module\n", encoding="utf-8")
        android_home = self.root / "Android" / "Sdk"
        (android_home / "ndk" / "26.1.10909125").mkdir(parents=True)
        build_tools = android_home / "build-tools" / "36.0.0"
        build_tools.mkdir(parents=True)
        (build_tools / "apksigner").write_text("# fake apksigner\n", encoding="utf-8")
        linux_toolchain = android_home / "ndk" / "26.1.10909125" / "toolchains" / "llvm" / "prebuilt" / "linux-x86_64" / "bin"
        linux_toolchain.mkdir(parents=True)
        for compiler in ("clang", "clang++"):
            compiler_path = linux_toolchain / compiler
            compiler_path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            subprocess.run([find_wsl() or "wsl.exe", "chmod", "+x", to_wsl_path(compiler_path)], check=True)
        keystore = self.root / "android-release.keystore"
        keystore.write_bytes(b"fake keystore")

        result = subprocess.run(
            [
                powershell,
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(SCRIPT_DIR / "local_release.ps1"),
                "-Version",
                "9.9.9.9",
                "-Preflight",
                "-BuildPlatform",
                "android",
                "-BaseUrl",
                "http://172.29.172.252:17865",
                "-PrivateKey",
                str(self.private_key),
                "-PublicKeyBase64",
                self.public_key_base64,
                "-WslAndroidHome",
                to_wsl_path(android_home),
            ],
            env={
                **self.env,
                "QT_ROOT_PATH": str(qt_root),
                "ANDROID_HOME": str(android_home),
                "QT_ANDROID_KEYSTORE_PATH": str(keystore),
                "QT_ANDROID_KEYSTORE_ALIAS": "release",
                "QT_ANDROID_KEYSTORE_STORE_PASS": "password",
                "JAVA_HOME": os.environ.get("JAVA_HOME", ""),
            },
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn("Preflight OK", result.stdout)

    @unittest.skipUnless(find_powershell() and find_wsl(), "PowerShell and WSL are required for the setup smoke test")
    def test_setup_release_workstation_generates_update_keys_and_env_file(self) -> None:
        powershell = find_powershell()
        assert powershell

        qt_install_dir = self.root / "Qt"
        qt_version = "6.99.0"
        for kit in ("gcc_64", "android_arm64_v8a", "android_armv7", "android_x86", "android_x86_64"):
            toolchain = qt_install_dir / qt_version / kit / "lib" / "cmake" / "Qt6" / "qt.toolchain.cmake"
            toolchain.parent.mkdir(parents=True)
            toolchain.write_text("# fake qt toolchain\n", encoding="utf-8")
        android_home = self.root / "Android" / "Sdk"
        (android_home / "ndk" / "26.1.10909125").mkdir(parents=True)
        build_tools = android_home / "build-tools" / "36.0.0"
        build_tools.mkdir(parents=True)
        (build_tools / "apksigner").write_text("# fake apksigner\n", encoding="utf-8")
        key_dir = self.root / "keys"
        env_file = self.root / "release-env.ps1"

        result = subprocess.run(
            [
                powershell,
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(SCRIPT_DIR / "setup_release_workstation.ps1"),
                "-QtInstallDir",
                str(qt_install_dir),
                "-QtVersion",
                qt_version,
                "-AndroidHome",
                str(android_home),
                "-KeyDir",
                str(key_dir),
                "-EnvFile",
                str(env_file),
                "-GenerateUpdateKeys",
            ],
            env=self.env,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertTrue((key_dir / "selfhosted-update-private.pem").is_file())
        self.assertTrue((key_dir / "selfhosted-update-public.pem").is_file())
        env_text = env_file.read_text(encoding="utf-8-sig")
        self.assertIn("SELFHOSTED_UPDATE_PRIVATE_KEY_PATH", env_text)
        self.assertIn("SELFHOSTED_UPDATE_PUBLIC_KEY_PEM_BASE64", env_text)
        self.assertIn("SELFHOSTED_UPDATE_SYNC_HOST = '10.8.1.0'", env_text)
        self.assertIn("SELFHOSTED_SSH_TRUSTED_HOST = '85.208.87.69'", env_text)
        self.assertIn(
            "SELFHOSTED_SSH_TRUSTED_HOST_KEY_SHA256 = 'SHA256:2UtHIoVd4Lft+s4E/LZlA8+reysEexYyhkt03rg8Rdg'",
            env_text,
        )
        self.assertIn("SELFHOSTED_UPDATE_PAYLOAD_SCHEMA = '1'", env_text)
        self.assertIn("SELFHOSTED_UPDATE_CHANNEL = 'stable'", env_text)
        self.assertIn("SELFHOSTED_UPDATE_ROLLOUT_PERCENTAGE = '100'", env_text)
        self.assertIn("SELFHOSTED_UPDATE_HEALTH_DEADLINE_SECONDS = '600'", env_text)
        self.assertIn("SELFHOSTED_UPDATE_POLICY_GENERATION = '0'", env_text)
        self.assertIn("SELFHOSTED_UPDATE_ROLLBACK_ARTIFACTS = ''", env_text)
        self.assertIn("QT_ANDROID_KEYSTORE_PATH", env_text)
        self.assertNotIn("keytool -genkeypair", result.stdout + result.stderr + env_text)

    def test_ios_bundle_version_validation(self) -> None:
        self.assertEqual(make_manifest.ios_bundle_version("4.8.16.0"), "4.8.16")
        self.assertEqual(make_manifest.ios_bundle_version("04.08.016"), "4.8.16")
        with self.assertRaises(SystemExit) as explicit_four_part:
            make_manifest.ios_bundle_version("4.8.16.0", explicit=True)
        self.assertIn("one to three numeric components", str(explicit_four_part.exception))
        with self.assertRaises(SystemExit) as non_numeric:
            make_manifest.ios_bundle_version("4.8.beta", explicit=True)
        self.assertIn("only digits and periods", str(non_numeric.exception))


class ManagedRoutesSourceContractTests(unittest.TestCase):
    """Guard the trust, resource, identity, and privacy boundaries of Living Routes."""

    @staticmethod
    def function_body(source: str, signature: str) -> str:
        start = source.find(signature)
        if start < 0:
            raise AssertionError(f"missing C++ function: {signature}")
        opening_brace = source.find("{", start)
        if opening_brace < 0:
            raise AssertionError(f"missing C++ function body: {signature}")

        depth = 0
        for offset in range(opening_brace, len(source)):
            character = source[offset]
            if character == "{":
                depth += 1
            elif character == "}":
                depth -= 1
                if depth == 0:
                    return source[opening_brace : offset + 1]
        raise AssertionError(f"unterminated C++ function: {signature}")

    def test_effective_managed_policy_requires_matching_declared_content_and_caps_sites(self) -> None:
        managed_policy = (
            REPO_ROOT / "client/core/utils/managedRoutePolicy.h"
        ).read_text(encoding="utf-8")
        connection_controller = (
            REPO_ROOT / "client/core/controllers/connectionController.cpp"
        ).read_text(encoding="utf-8")
        is_effective = self.function_body(managed_policy, "inline bool isEffective(")

        self.assertIn("metadataForEffectiveContent", is_effective)
        self.assertIn("contentMatchesDeclaration", is_effective)
        self.assertIn("isExpired(now)", is_effective)

        site_cap = re.search(r"maximumSiteCount\s*=\s*(\d+)", managed_policy)
        self.assertIsNotNone(site_cap, "managed route policy must expose a shared site-count cap")
        assert site_cap
        self.assertGreater(int(site_cap.group(1)), 0)
        self.assertLessEqual(int(site_cap.group(1)), 2048)
        self.assertIn("managedRoutePolicy::canonicalSourceSites(value, &valid)", connection_controller)

    def test_managed_policy_http_sync_streams_into_a_bounded_buffer_with_deadline(self) -> None:
        connection_controller = (
            REPO_ROOT / "client/core/controllers/connectionController.cpp"
        ).read_text(encoding="utf-8")
        sync_body = self.function_body(
            connection_controller,
            "void ConnectionController::syncServerRoutingRulesFromUrls(",
        )

        self.assertRegex(sync_body, r"&Q(?:IODevice|NetworkReply)::readyRead")
        self.assertIn("setReadBufferSize(", sync_body)
        self.assertIn("QTimer", sync_body)
        self.assertIn("->abort()", sync_body)
        self.assertNotIn("readAll()", sync_body)
        self.assertRegex(
            connection_controller,
            r"constexpr\s+int\s+serverRoutingRules\w*(?:Deadline|Timeout)\w*Ms\s*=\s*[1-9]\d*",
        )

    def test_admin_publish_uses_raw_draft_managed_policy_getters(self) -> None:
        repository_h = (
            REPO_ROOT / "client/core/repositories/secureServersRepository.h"
        ).read_text(encoding="utf-8")
        repository_cpp = (
            REPO_ROOT / "client/core/repositories/secureServersRepository.cpp"
        ).read_text(encoding="utf-8")
        sites_controller = (
            REPO_ROOT / "client/ui/controllers/sitesController.cpp"
        ).read_text(encoding="utf-8")

        self.assertIn("rawManagedVpnSites", repository_h)
        self.assertIn("rawManagedSplitTunnelingForceEnabled", repository_h)
        self.assertIn("SecureServersRepository::rawManagedVpnSites", repository_cpp)
        self.assertIn("SecureServersRepository::rawManagedSplitTunnelingForceEnabled", repository_cpp)
        self.assertGreaterEqual(sites_controller.count("rawManagedVpnSites("), 2)
        self.assertIn("rawManagedSplitTunnelingForceEnabled(", sites_controller)

    def test_vpn_connection_tracks_stable_server_identity(self) -> None:
        vpn_connection_h = (REPO_ROOT / "client/vpnConnection.h").read_text(encoding="utf-8")
        vpn_connection = (REPO_ROOT / "client/vpnConnection.cpp").read_text(encoding="utf-8")
        connection_controller = (
            REPO_ROOT / "client/core/controllers/connectionController.cpp"
        ).read_text(encoding="utf-8")
        server_index = self.function_body(vpn_connection, "int VpnConnection::serverIndex() const")
        connect_to_vpn = self.function_body(vpn_connection, "void VpnConnection::connectToVpn(")

        self.assertRegex(vpn_connection_h, r"\bQString\s+serverId\(\)\s+const;")
        self.assertIn("QString m_serverId", vpn_connection_h)
        self.assertIn("return m_serverIndex", server_index)
        self.assertIn("m_serverId = serverId", connect_to_vpn)
        self.assertIn("m_serverIndex = serverIndex", connect_to_vpn)
        self.assertIn("currentConnectionServerId", connection_controller)
        self.assertIn("isCurrentConnectionServerId(serverId)", connection_controller)
        current_index = self.function_body(
            connection_controller,
            "int ConnectionController::currentConnectionServerIndex() const",
        )
        self.assertIn("indexOfServerId(serverId)", current_index)
        self.assertNotIn("m_serversRepository", server_index)

    def test_managed_dns_resolution_has_a_small_concurrency_cap(self) -> None:
        connection_controller = (
            REPO_ROOT / "client/core/controllers/connectionController.cpp"
        ).read_text(encoding="utf-8")
        connection_controller_h = (
            REPO_ROOT / "client/core/controllers/connectionController.h"
        ).read_text(encoding="utf-8")
        resolve_next = self.function_body(
            connection_controller,
            "void ConnectionController::resolveNextClientManagedSite()",
        )

        # The queue now dispatches exactly one lookup. Every terminal callback
        # either cancels or advances the queue, which is a stricter concurrency
        # bound than the former small parallel pool.
        self.assertIn("QStringList m_clientManagedSitesResolveQueue", connection_controller_h)
        self.assertIn("m_clientManagedSitesResolveQueue.takeFirst()", resolve_next)
        self.assertEqual(resolve_next.count("QHostInfo::lookupHost"), 1)
        self.assertGreaterEqual(resolve_next.count("resolveNextClientManagedSite()"), 3)
        self.assertNotIn("while (", resolve_next)
        self.assertIn("m_clientManagedSitesLookupTimeoutTimer.start", resolve_next)
        self.assertIn("QHostInfo::abortHostLookup", connection_controller)

    def test_managed_dns_retries_only_failures_and_reconciles_once_after_bounded_convergence(self) -> None:
        connection_controller = (
            REPO_ROOT / "client/core/controllers/connectionController.cpp"
        ).read_text(encoding="utf-8")
        connection_controller_h = (
            REPO_ROOT / "client/core/controllers/connectionController.h"
        ).read_text(encoding="utf-8")
        convergence_test = (
            REPO_ROOT / "client/tests/managed_dns_convergence/tst_managed_dns_convergence.cpp"
        ).read_text(encoding="utf-8")
        vpn_connection = (REPO_ROOT / "client/vpnConnection.cpp").read_text(encoding="utf-8")
        start_resolve = self.function_body(
            connection_controller,
            "void ConnectionController::startClientManagedSitesResolve()",
        )
        schedule_resolve = self.function_body(
            connection_controller,
            "void ConnectionController::scheduleClientManagedSitesResolve(",
        )
        finish_resolve = self.function_body(
            connection_controller,
            "void ConnectionController::finishClientManagedSitesResolve()",
        )
        request_reconcile = self.function_body(
            connection_controller,
            "void ConnectionController::requestManagedRouteReconciliation(",
        )
        dispatch_reconcile = self.function_body(
            connection_controller,
            "void ConnectionController::dispatchManagedRouteReconciliation(",
        )
        worker_reconcile = self.function_body(
            vpn_connection,
            "void VpnConnection::reconcileManagedSplitTunnelRoutes(",
        )

        failure_gate = finish_resolve.index("if (!m_clientManagedSitesConvergence.complete()")
        retry = finish_resolve.index(
            "scheduleClientManagedSitesResolveRetry(serverIndex)", failure_gate
        )
        early_return = finish_resolve.index("return;", retry)
        cache_write = finish_resolve.index(
            "configKey::managedSplitTunnelClientResolvedExceptSites"
        )
        freshness_write = finish_resolve.index(
            "configKey::managedSplitTunnelClientResolvedAt"
        )
        persist = finish_resolve.index("m_serversRepository->editServerJson")
        publish = finish_resolve.index("emit serverRoutingRulesChanged")
        request = finish_resolve.index("requestManagedRouteReconciliation")
        failure_block = finish_resolve[failure_gate : early_return + len("return;")]

        self.assertIn("managedDnsConvergence::State", connection_controller_h)
        self.assertIn("m_clientManagedSitesConvergence.takePendingWave()", start_resolve)
        self.assertNotIn("managedResolveDomains(sourceSites)", start_resolve)
        self.assertIn("shouldRetry(serverRoutingRulesClientResolveMaxRetryWaves)", failure_block)
        self.assertIn("m_clientManagedSitesResolveDeadline.hasExpired()", failure_block)
        self.assertLess(early_return, cache_write)
        self.assertLess(early_return, freshness_write)
        self.assertLess(failure_gate, persist)
        self.assertLess(early_return, persist)
        self.assertLess(early_return, publish)
        self.assertLess(early_return, request)
        self.assertEqual(failure_block.count("scheduleClientManagedSitesResolveRetry(serverIndex)"), 1)
        self.assertEqual(failure_block.count("return;"), 1)
        self.assertIn("only unresolved domains will be retried", failure_block)
        self.assertNotIn("editServerJson", failure_block)
        self.assertNotIn("requestManagedRouteReconciliation", failure_block)
        self.assertNotIn("reconnectToVpn", failure_block)
        self.assertIn("if (!stagedCache.contains(domain))", finish_resolve)
        self.assertIn("stagedCache.insert(domain, QString())", finish_resolve)
        self.assertIn("if (unresolvedCount == 0)", finish_resolve)
        self.assertIn("configKey::managedSplitTunnelClientResolveRetryAfter", finish_resolve)
        self.assertIn("configKey::managedSplitTunnelClientResolvePendingSites", finish_resolve)
        self.assertIn("configKey::managedSplitTunnelClientResolvePendingSourceDigest", finish_resolve)
        self.assertIn("configKey::managedSplitTunnelClientResolveLastFullSweepAt", finish_resolve)
        self.assertIn("now.addSecs(serverRoutingRulesClientResolveRetryMaxMs / 1000)", finish_resolve)
        self.assertIn("serverConfig.value(configKey::managedSplitTunnelClientResolveRetryAfter)", connection_controller)
        self.assertIn("managedDnsConvergence::initialDelayMs", connection_controller)
        self.assertIn("managedDnsConvergence::pendingDomainsForCycle", connection_controller)
        self.assertIn("managedDnsConvergence::fullSweepDue", schedule_resolve)
        self.assertIn("managedDnsConvergence::completeCacheRefreshDue", connection_controller)
        self.assertIn("resumePartialCycle", schedule_resolve)
        self.assertIn(": QString()", schedule_resolve)
        apply_payload = self.function_body(
            connection_controller,
            "bool ConnectionController::applyServerRoutingRulesPayload(",
        )
        source_change = apply_payload[apply_payload.index("if (managedSourceChanged)") :]
        self.assertIn("managedSplitTunnelClientResolveRetryAfter", source_change)
        self.assertIn("managedSplitTunnelClientResolvePendingSites", source_change)
        self.assertIn("managedSplitTunnelClientResolvePendingSourceDigest", source_change)
        self.assertIn("managedSplitTunnelClientResolveLastFullSweepAt", source_change)
        self.assertEqual(finish_resolve.count("m_serversRepository->editServerJson"), 1)
        self.assertLess(persist, publish)
        self.assertIn("retriesOnlyFailuresAndKeepsSuccessfulResults", convergence_test)
        self.assertIn("keepsLastKnownGoodUntilFailedDomainSucceeds", convergence_test)
        self.assertIn("supersedingSourceCannotAcceptOldDomains", convergence_test)
        self.assertIn("boundedWavesFinalizeAtMostOnce", convergence_test)
        self.assertIn("retryAfterDelaysButDoesNotSuppressNextCycle", convergence_test)
        self.assertIn("partialCycleRetriesOnlyPersistedFailures", convergence_test)
        self.assertIn("scheduledRefreshChecksEveryDomain", convergence_test)
        self.assertIn("firstReconnectIsImmediateThenTwoHourFloorApplies", convergence_test)
        self.assertIn("reconnectRequestsCoalesceWithoutSlidingTheDeadline", convergence_test)
        self.assertIn("externalReconnectPreservesPendingAtTheSameDeadline", convergence_test)
        self.assertIn("partialCyclesStillRunADailyFullSweep", convergence_test)
        self.assertIn("QVERIFY(!state.tryFinalize())", convergence_test)
        self.assertIn("deferring managed route reconciliation until DNS convergence", connection_controller)
        self.assertIn("deferring managed route-mode transition until DNS convergence", connection_controller)

        self.assertIn("dispatchManagedRouteReconciliation(desired, reason)", request_reconcile)
        self.assertNotIn("emit managedRouteReconcileRequested", request_reconcile)
        self.assertIn("emit managedRouteReconcileRequested", dispatch_reconcile)
        self.assertRegex(
            connection_controller,
            r"(?s)connect\s*\(\s*this\s*,\s*&ConnectionController::managedRouteReconcileRequested"
            r".*?&VpnConnection::reconcileManagedSplitTunnelRoutes\s*,\s*Qt::QueuedConnection\s*\)",
        )
        thread_guard = worker_reconcile.index("QThread::currentThread() != thread()")
        binding_gate = worker_reconcile.index("const bool bindingMatches")
        runtime_update = worker_reconcile.index("updateManagedSplitTunnelRoutes")
        reconnect = worker_reconcile.index("scheduleManagedRouteReconnect(")
        self.assertLess(thread_guard, binding_gate)
        self.assertLess(binding_gate, runtime_update)
        self.assertLess(runtime_update, reconnect)
        self.assertIn("expectedConnectionEpoch == m_connectionEpoch", worker_reconcile)
        self.assertIn("expectedServerId == m_serverId", worker_reconcile)

    def test_managed_route_reconnects_are_rate_limited_without_throttling_dns(self) -> None:
        vpn_connection_h = (REPO_ROOT / "client/vpnConnection.h").read_text(encoding="utf-8")
        vpn_connection = (REPO_ROOT / "client/vpnConnection.cpp").read_text(encoding="utf-8")
        convergence = (
            REPO_ROOT / "client/core/utils/managedDnsConvergence.h"
        ).read_text(encoding="utf-8")

        constructor = self.function_body(vpn_connection, "VpnConnection::VpnConnection(")
        schedule = self.function_body(
            vpn_connection, "void VpnConnection::scheduleManagedRouteReconnect("
        )
        flush = self.function_body(
            vpn_connection, "void VpnConnection::flushManagedRouteReconnect()"
        )
        connect_to_vpn = self.function_body(vpn_connection, "void VpnConnection::connectToVpn(")
        reconnect_to_vpn = self.function_body(vpn_connection, "void VpnConnection::reconnectToVpn()")
        restore_connection = self.function_body(
            vpn_connection, "void VpnConnection::restoreConnection("
        )
        disconnect_from_vpn = self.function_body(
            vpn_connection, "void VpnConnection::disconnectFromVpn()"
        )
        rebuild = self.function_body(
            vpn_connection, "void VpnConnection::rebuildManagedSplitTunnelRoutes("
        )

        self.assertIn("2LL * 60 * 60 * 1000", vpn_connection)
        self.assertIn("ReconnectGate m_managedRouteReconnectGate", vpn_connection_h)
        self.assertIn("QTimer m_managedRouteReconnectCooldownTimer", vpn_connection_h)
        self.assertIn("m_managedRouteReconnectCooldownTimer.setSingleShot(true)", constructor)
        self.assertIn("m_managedRouteReconnectGate.request", schedule)
        self.assertIn("if (!request.newlyPending)", schedule)
        self.assertIn("m_managedRouteReconnectGate.takeDue", flush)
        self.assertIn("recordReconnectFloor()", flush)
        self.assertIn("reconnectToVpn()", flush)
        self.assertIn("m_managedRouteReconnectAwaitingBase", flush)
        self.assertIn("latestPreparedManagedRouteSnapshotIsApplied", flush)
        self.assertNotIn("start(1000)", flush)
        applied = self.function_body(
            vpn_connection,
            "bool VpnConnection::latestPreparedManagedRouteSnapshotIsApplied() const",
        )
        self.assertIn("normalizedManagedRoutesForRuntime", applied)
        self.assertIn("m_preparedLocalSites", applied)
        self.assertIn("beginManagedRouteReconnectSession(serverId)", connect_to_vpn)
        self.assertNotIn("recordReconnectFloor()", connect_to_vpn)
        self.assertNotIn("beginManagedRouteReconnectSession", reconnect_to_vpn)
        self.assertGreaterEqual(reconnect_to_vpn.count("recordReconnectFloor()"), 1)
        self.assertIn("beginManagedRouteReconnectSession(serverId)", restore_connection)
        self.assertIn("recordReconnectFloor()", restore_connection)
        self.assertIn("clearManagedRouteReconnectSession()", disconnect_from_vpn)
        self.assertIn("scheduleManagedRouteReconnect", rebuild)
        self.assertNotIn("reconnectToVpn", rebuild)
        self.assertIn("class ReconnectGate final", convergence)
        self.assertIn("m_pending", convergence)
        self.assertIn("m_lastReconnectMs", convergence)

    @unittest.skipUnless(find_sh(), "sh is required to validate the managed routing resolver")
    def test_server_managed_dns_recovery_is_bounded_atomic_and_preserves_lkg(self) -> None:
        sh = find_sh()
        self.assertIsNotNone(sh)
        resolver_script = extract_server_routing_rules_resolver_script()
        install_controller = (
            REPO_ROOT / "client/core/controllers/selfhosted/installController.cpp"
        ).read_text(encoding="utf-8")

        syntax = subprocess.run(
            [sh, "-n"], input=resolver_script, text=True, capture_output=True, check=False
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr + syntax.stdout)
        retry_function = resolver_script[
            resolver_script.index("retry_unresolved_burst() {") :
            resolver_script.index("validate_source_file || exit 20")
        ]
        background = resolver_script[
            resolver_script.index("(\n    retry_unresolved_burst") :
            resolver_script.index("busybox httpd -f")
        ]
        self.assertIn('"$retry_attempt" -lt "$RECOVERY_MAXIMUM_ATTEMPTS"', retry_function)
        self.assertIn('build_rules 1 "$RECOVERY_QUERY_TIMEOUT_SECONDS"', retry_function)
        self.assertIn("RECOVERY_ATTEMPT_BUDGET_SECONDS", retry_function)
        self.assertIn("resolve_deadline_seconds=0", retry_function)
        self.assertIn('retry_delay="$RECOVERY_MAXIMUM_DELAY_SECONDS"', retry_function)
        self.assertNotIn("docker", retry_function)
        self.assertLess(background.index("retry_unresolved_burst"), background.index("while :; do"))
        self.assertIn('mv "$tmp_file" "$RULES_FILE"', resolver_script)
        self.assertIn("candidate_lkg_seed", install_controller)
        self.assertIn(
            "rm -f '__HOST_DIRECTORY__/__READY_FILE__' || fail_commit old_ready_remove",
            install_controller,
        )
        self.assertNotIn(
            "rm -f '__HOST_DIRECTORY__/__READY_FILE__' '__HOST_DIRECTORY__/__RULES_FILE__'",
            install_controller,
        )
        self.assertIn('if [ "${VALIDATE_ONLY:-0}" = "1" ]; then', resolver_script)
        self.assertIn("VALIDATE_RESOLVE_BUDGET_SECONDS", resolver_script)
        self.assertIn('build_rules 1 "$RECOVERY_QUERY_TIMEOUT_SECONDS"', resolver_script)
        self.assertIn('skip_dns="${3:-0}"', resolver_script)
        self.assertIn('build_rules 1 "$RECOVERY_QUERY_TIMEOUT_SECONDS" 1', resolver_script)
        initial_runtime = resolver_script[
            resolver_script.index("# Readiness is an atomic publication invariant") :
            resolver_script.index("resolve_deadline_seconds=0", resolver_script.index("# Readiness is an atomic publication invariant"))
        ]
        self.assertNotIn('build_rules 0 "$RESOLVE_QUERY_TIMEOUT_SECONDS"', initial_runtime)
        self.assertIn("Candidate resolver output dropped the requested IP or subnet route", install_controller)
        self.assertIn("candidateServerExcept.contains(it.key())", install_controller)
        self.assertIn("candidateServerExcept.value(it.key()).toString().isEmpty()", install_controller)
        self.assertIn('ready_tmp_file="${READY_FILE}.tmp.$$"', resolver_script)
        main_qml = (REPO_ROOT / "client/ui/qml/main2.qml").read_text(encoding="utf-8")
        page_qml = (
            REPO_ROOT / "client/ui/qml/Pages2/PageSettingsServerManagedSplitTunneling.qml"
        ).read_text(encoding="utf-8")
        self.assertIn("target: SitesController", main_qml)
        self.assertIn("onManagedSplitTunnelingRulesPublishIdle", main_qml)
        self.assertIn("onManagedSplitTunnelingRulesPublishIdle", page_qml)
        self.assertIn('candidate_log_file="/tmp/amnezia-routing-candidate-$$.log"', install_controller)
        self.assertIn('>"$candidate_log_file" 2>&1', install_controller)
        self.assertIn('candidate_resolver_run_${candidate_rc}', install_controller)

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            fake_nslookup = fake_bin / "nslookup"
            fake_nslookup.write_text(
                "#!/bin/sh\n"
                "if [ \"${FAKE_DNS_MODE:-fail}\" = success ]; then\n"
                "  printf 'Server: 172.29.172.254\\nAddress 1: 172.29.172.254\\nName: recover.test\\nAddress 1: 203.0.113.55\\n'\n"
                "fi\n",
                encoding="utf-8",
                newline="\n",
            )
            fake_nslookup.chmod(0o755)
            source_file = root / "rules-source.txt"
            rules_file = root / "rules.json"
            ready_file = root / "rules-ready"
            source_file.write_text("D|recover.test|\n", encoding="utf-8", newline="\n")
            rules_file.write_text(
                '{"version":1,"server.except":{"recover.test":"198.51.100.10"}}',
                encoding="utf-8",
            )

            functions = resolver_script[: resolver_script.index("validate_source_file || exit 20")]
            functions = functions.replace(
                'RULES_FILE="/www/rules.json"',
                "RULES_FILE=" + sh_quote(shell_absolute_path(rules_file)),
            ).replace(
                'SOURCE_FILE="/www/rules-source.txt"',
                "SOURCE_FILE=" + sh_quote(shell_absolute_path(source_file)),
            ).replace(
                'READY_FILE="/www/rules-ready"',
                "READY_FILE=" + sh_quote(shell_absolute_path(ready_file)),
            )
            harness = functions + textwrap.dedent(
                """\
                validate_source_file || exit 31
                FAKE_DNS_MODE=fail
                export FAKE_DNS_MODE
                build_rules 1 1 || exit 32
                grep -Fq '"recover.test":"198.51.100.10"' "$RULES_FILE" || exit 33
                FAKE_DNS_MODE=success
                export FAKE_DNS_MODE
                last_unresolved_count=1
                RECOVERY_INITIAL_DELAY_SECONDS=0
                RECOVERY_MAXIMUM_ATTEMPTS=1
                retry_unresolved_burst
                grep -Fq '"recover.test":"203.0.113.55"' "$RULES_FILE" || exit 34
                """
            )
            environment = os.environ.copy()
            environment["PATH"] = str(fake_bin) + os.pathsep + environment.get("PATH", "")
            probe = subprocess.run(
                [sh],
                input=harness,
                text=True,
                capture_output=True,
                check=False,
                env=environment,
            )
            self.assertEqual(probe.returncode, 0, probe.stderr + probe.stdout)
            parsed_rules = json.loads(rules_file.read_text(encoding="utf-8"))
            self.assertEqual(
                parsed_rules["server.except"]["recover.test"], "203.0.113.55"
            )

            source_file.write_text(
                "I|172.16.31.0/24|\nD|recover.test|\n",
                encoding="utf-8",
                newline="\n",
            )
            rules_file.write_text(
                '{"version":1,"server.except":{"recover.test":"198.51.100.10"}}',
                encoding="utf-8",
            )
            ready_file.unlink(missing_ok=True)
            startup_harness = functions + textwrap.dedent(
                """\
                validate_source_file || exit 41
                FAKE_DNS_MODE=fail
                export FAKE_DNS_MODE
                build_rules 1 1 1 || exit 42
                test -s "$READY_FILE" || exit 43
                grep -Fq '"172.16.31.0/24":""' "$RULES_FILE" || exit 44
                grep -Fq '"recover.test":"198.51.100.10"' "$RULES_FILE" || exit 45
                """
            )
            startup_probe = subprocess.run(
                [sh],
                input=startup_harness,
                text=True,
                capture_output=True,
                check=False,
                env=environment,
            )
            self.assertEqual(startup_probe.returncode, 0, startup_probe.stderr + startup_probe.stdout)

    def test_route_dns_logs_do_not_disclose_site_hostnames(self) -> None:
        connection_controller = (
            REPO_ROOT / "client/core/controllers/connectionController.cpp"
        ).read_text(encoding="utf-8")
        dns_route_logs = [
            statement
            for statement in re.findall(
                r"q(?:Debug|Info|Warning|Critical)\(\)\s*<<.*?;",
                connection_controller,
                re.S,
            )
            if "managed site resolve" in statement or "managed DNS" in statement
        ]

        self.assertTrue(dns_route_logs, "expected at least one route-DNS diagnostic")
        for statement in dns_route_logs:
            self.assertNotRegex(statement, r"<<\s*(?:site|domain)\b")
            self.assertNotIn("hostInfo.hostName()", statement)
            self.assertNotIn("hostInfo.errorString()", statement)
        self.assertIn(
            '<< "errorCode" << static_cast<int>(hostInfo.error())',
            connection_controller,
        )

    def test_service_readiness_probes_ipc_reachability_not_process_name(self) -> None:
        connection_controller = (
            REPO_ROOT / "client/core/controllers/connectionController.cpp"
        ).read_text(encoding="utf-8")
        is_service_ready = self.function_body(
            connection_controller,
            "bool ConnectionController::isServiceReady() const",
        )

        self.assertIn("IpcClient::withInterface", is_service_ready)
        self.assertNotIn("Utils::processIsRunning", is_service_ready)

    def test_vpn_connection_exposes_applied_site_route_mode(self) -> None:
        vpn_connection_h = (REPO_ROOT / "client/vpnConnection.h").read_text(encoding="utf-8")
        vpn_connection = (REPO_ROOT / "client/vpnConnection.cpp").read_text(encoding="utf-8")
        applied_mode = self.function_body(
            vpn_connection,
            "RouteMode VpnConnection::appliedSiteRouteMode() const",
        )

        self.assertRegex(vpn_connection_h, r"(?:amnezia::)?RouteMode\s+appliedSiteRouteMode\(\)\s+const;")
        self.assertIn("configKey::splitTunnelType", applied_mode)
        self.assertIn("RouteMode::VpnAllSites", applied_mode)

    def test_managed_routes_are_bounded_and_guarded_on_both_sides_of_ipc(self) -> None:
        managed_policy = (
            REPO_ROOT / "client/core/utils/managedRoutePolicy.h"
        ).read_text(encoding="utf-8")
        vpn_connection = (REPO_ROOT / "client/vpnConnection.cpp").read_text(
            encoding="utf-8"
        )
        repository = (
            REPO_ROOT / "client/core/repositories/secureServersRepository.cpp"
        ).read_text(encoding="utf-8")
        connection_controller = (
            REPO_ROOT / "client/core/controllers/connectionController.cpp"
        ).read_text(encoding="utf-8")
        ipc_server = (REPO_ROOT / "ipc/ipcserver.cpp").read_text(encoding="utf-8")
        router = (REPO_ROOT / "service/server/router.cpp").read_text(encoding="utf-8")
        router_win = (REPO_ROOT / "service/server/router_win.cpp").read_text(
            encoding="utf-8"
        )

        self.assertIn("maximumRoutesPerSite = 64", managed_policy)
        self.assertIn("maximumTotalRouteCount = 4096", managed_policy)
        self.assertIn("maximumStoredRouteValueLength = 4096", managed_policy)
        self.assertIn("canonicalManagedIpv4Route", managed_policy)
        self.assertIn("!directRoute.isEmpty() && !routes.isEmpty()", managed_policy)
        self.assertIn("isAllowedManagedIpv4Route", managed_policy)
        self.assertIn("prefixLength == 0", managed_policy)
        self.assertIn("0x64400000u, 10", managed_policy)
        self.assertIn("0xa9fe0000u, 16", managed_policy)
        self.assertIn("ipv4RouteIsWithinRange(address, prefixLength, 0x0a000000u, 8)", managed_policy)
        self.assertIn("validatedManagedRoutes(managedIps", vpn_connection)
        normalized_runtime = self.function_body(
            vpn_connection,
            "QStringList VpnConnection::normalizedManagedRoutesForRuntime(",
        )
        self.assertGreaterEqual(
            normalized_runtime.count("managedRoutePolicy::validatedManagedRoutes"),
            2,
        )
        self.assertIn("const QSet<QString> localSet", normalized_runtime)
        self.assertIn("mobile managed route snapshot failed its safety boundary", vpn_connection)
        self.assertIn("managed DNS cache reached its safety boundary", connection_controller)
        self.assertIn("canonicalMergedSites", repository)
        self.assertIn("validatedManagedRoutes(ips", ipc_server)
        self.assertIn("m_trustedManagedRoutes", ipc_server)
        self.assertIn("validatedManagedRoutes(ips", router)
        self.assertIn("validatedManagedRoutes(ips", router_win)

    def test_versioned_lkg_requires_canonical_hash_and_lifecycle(self) -> None:
        managed_policy = (
            REPO_ROOT / "client/core/utils/managedRoutePolicy.h"
        ).read_text(encoding="utf-8")
        metadata_from_json = self.function_body(
            managed_policy, "inline std::optional<ManagedRoutePolicyMetadata> metadataFromJson("
        )
        is_effective = self.function_body(managed_policy, "inline bool isEffective(")

        self.assertIn("metadata.contentHash.isEmpty()", metadata_from_json)
        self.assertIn("metadata.declaredContentHash.isEmpty()", metadata_from_json)
        self.assertIn('policyType == QStringLiteral("legacy") && numericRevision', metadata_from_json)
        self.assertIn("contentMatchesDeclaration", metadata_from_json)
        self.assertIn("!metadata.issuedAt.isValid()", metadata_from_json)
        self.assertIn("!metadata.expiresAt.isValid()", metadata_from_json)
        self.assertIn("metadata.expiresAt <= metadata.issuedAt", metadata_from_json)
        self.assertIn("stateValue.isUndefined()", is_effective)
        self.assertIn("!retainedValue.isObject()", is_effective)

    def test_route_inspector_reports_policy_trust_and_ineffective_reason(self) -> None:
        inspector = (
            REPO_ROOT / "client/core/controllers/routeInspectorController.cpp"
        ).read_text(encoding="utf-8")
        qml = (
            REPO_ROOT / "client/ui/qml/Pages2/PageRouteInspector.qml"
        ).read_text(encoding="utf-8")

        self.assertIn('QStringLiteral("trustState")', inspector)
        self.assertIn('QStringLiteral("contentMatchesDeclaration")', inspector)
        self.assertIn('QStringLiteral("policyIneffectiveReason")', inspector)
        self.assertIn('QStringLiteral("managed_policy_unsigned")', inspector)
        self.assertIn("Managed policy trust: unsigned", qml)
        self.assertIn("lifecycle metadata is invalid", qml)
        self.assertIn("failed current safety limits", qml)


class WindowsFirewallSourceContractTests(unittest.TestCase):
    """Guard the Windows kill-switch fail-closed and transaction boundaries."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.source = (
            REPO_ROOT / "client/platforms/windows/daemon/windowsfirewall.cpp"
        ).read_text(encoding="utf-8")
        cls.killswitch = (REPO_ROOT / "service/server/killswitch.cpp").read_text(
            encoding="utf-8"
        )
        cls.wireguard = (
            REPO_ROOT
            / "client/platforms/windows/daemon/wireguardutilswindows.cpp"
        ).read_text(encoding="utf-8")
        cls.openvpn = (
            REPO_ROOT / "client/core/protocols/openVpnProtocol.cpp"
        ).read_text(encoding="utf-8")
        cls.localserver = (
            REPO_ROOT / "service/server/localserver.cpp"
        ).read_text(encoding="utf-8")
        cls.windowsdaemon = (
            REPO_ROOT / "client/platforms/windows/daemon/windowsdaemon.cpp"
        ).read_text(encoding="utf-8")
        cls.split_tunnel = (
            REPO_ROOT / "client/platforms/windows/daemon/windowssplittunnel.cpp"
        ).read_text(encoding="utf-8")
        cls.service_manager = (
            REPO_ROOT / "client/platforms/windows/windowsservicemanager.cpp"
        ).read_text(encoding="utf-8")
        cls.service_main = (REPO_ROOT / "service/server/main.cpp").read_text(
            encoding="utf-8"
        )
        cls.system_service = (
            REPO_ROOT / "service/server/systemservice.cpp"
        ).read_text(encoding="utf-8")
        cls.post_uninstall = (
            REPO_ROOT / "deploy/data/windows/post_uninstall.cmd"
        ).read_text(encoding="utf-8")
        cls.batch_runner = (
            REPO_ROOT / "deploy/data/windows/run_batch_file.ps1"
        ).read_text(encoding="utf-8")
        cls.cpack = (REPO_ROOT / "cmake/CPack.cmake").read_text(encoding="utf-8")
        cls.qif_component_script = (
            REPO_ROOT / "deploy/installer/qif/componentscript.js"
        ).read_text(encoding="utf-8")
        cls.qif_control_script = (
            REPO_ROOT / "deploy/installer/qif/controlscript.js"
        ).read_text(encoding="utf-8")
        cls.update_controller = (
            REPO_ROOT / "client/core/controllers/updateController.cpp"
        ).read_text(encoding="utf-8")
        cls.wix_service_patch = (
            REPO_ROOT / "deploy/installer/wix/service_install_patch.xml"
        ).read_text(encoding="utf-8")
        cls.wix_close_patch = (
            REPO_ROOT / "deploy/installer/wix/close_client_patch.xml"
        ).read_text(encoding="utf-8")

    def function_body(self, signature: str, source: str | None = None) -> str:
        source = self.source if source is None else source
        start = source.find(signature)
        self.assertNotEqual(start, -1, f"missing WindowsFirewall function: {signature}")
        opening_brace = source.find("{", start)
        self.assertNotEqual(opening_brace, -1, f"missing function body: {signature}")

        depth = 0
        for offset in range(opening_brace, len(source)):
            character = source[offset]
            if character == "{":
                depth += 1
            elif character == "}":
                depth -= 1
                if depth == 0:
                    return source[opening_brace : offset + 1]
        self.fail(f"unterminated function body: {signature}")

    def assert_separate_udp_tcp_filters(self, body: str, condition_count: int) -> None:
        # WFP ANDs all conditions in a filter. A single protocol condition is
        # mutated before each enableFilter call, producing distinct UDP/TCP
        # filters instead of an impossible "UDP AND TCP" filter.
        self.assertEqual(body.count("FWPM_CONDITION_IP_PROTOCOL"), 1)
        self.assertIn(f"filter.numFilterConditions = {condition_count};", body)
        self.assertIn("const auto enableProtocolFilters =", body)
        self.assertEqual(body.count("enableProtocolFilters(IPPROTO_UDP"), 1)
        self.assertEqual(body.count("enableProtocolFilters(IPPROTO_TCP"), 1)
        self.assertIn("conds[0].conditionValue.uint8 = protocol;", body)

    def test_dns_permit_is_outbound_only_and_bound_to_vpn_luid(self) -> None:
        body = self.function_body(
            "bool WindowsFirewall::allowDnsTrafficTo(const QHostAddress& targetIP"
        )

        self.assert_separate_udp_tcp_filters(body, condition_count=4)
        self.assertIn("filter.layerKey = layerOut;", body)
        self.assertIn("FWPM_CONDITION_IP_LOCAL_INTERFACE", body)
        self.assertIn("conditionValue.type = FWP_UINT64", body)
        self.assertIn("ST_DRIVER_DNS_SUBLAYER_KEY", body)
        self.assertNotIn("FWPM_LAYER_ALE_AUTH_RECV_ACCEPT", body)
        self.assertNotIn("FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT", body)

    def test_block_traffic_on_port_uses_distinct_udp_and_tcp_filters(self) -> None:
        body = self.function_body(
            "bool WindowsFirewall::blockTrafficOnPort(uint port, uint8_t weight"
        )

        self.assert_separate_udp_tcp_filters(body, condition_count=2)
        for layer in (
            "FWPM_LAYER_ALE_AUTH_CONNECT_V4",
            "FWPM_LAYER_ALE_AUTH_CONNECT_V6",
            "FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4",
            "FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6",
        ):
            self.assertEqual(body.count(layer), 1)

    def test_filters_are_persistent_provider_owned_and_reconciled_on_startup(self) -> None:
        create = self.function_body("WindowsFirewall* WindowsFirewall::create(")
        init_sublayer = self.function_body("bool WindowsFirewall::initSublayer()")
        enable_filter = self.function_body("bool WindowsFirewall::enableFilter(")
        load_filters = self.function_body("bool WindowsFirewall::loadProviderFilters()")
        enumerate_filters = self.function_body(
            "bool WindowsFirewall::enumerateProviderFilters("
        )
        enable_interface = self.function_body("bool WindowsFirewall::enableInterface(")

        self.assertNotIn("FWPM_SESSION_FLAG_DYNAMIC", create)
        self.assertIn("loadProviderFilters()", create)
        self.assertIn("FWPM_PROVIDER_FLAG_PERSISTENT", init_sublayer)
        self.assertIn("provider.serviceName", init_sublayer)
        self.assertIn('L"AmneziaVPN-service"', self.source)
        self.assertIn("FWPM_SUBLAYER_FLAG_PERSISTENT", init_sublayer)
        self.assertIn("filter->providerKey", enable_filter)
        self.assertIn("FWPM_FILTER_FLAG_PERSISTENT", enable_filter)
        self.assertIn("target.append(filterID)", enable_filter)
        self.assertIn("enumerateProviderFilters(m_orphanedRules)", load_filters)
        self.assertIn("FwpmFilterEnum0", enumerate_filters)
        self.assertIn("FWP_FILTER_ENUM_FULLY_CONTAINED", enumerate_filters)
        self.assertIn("FWP_FILTER_ENUM_FLAG_INCLUDE_BOOTTIME", enumerate_filters)
        self.assertIn("FWP_FILTER_ENUM_FLAG_INCLUDE_DISABLED", enumerate_filters)
        self.assertIn("enumTemplate.actionMask = 0xFFFFFFFFu", enumerate_filters)
        self.assertIn("enumerateProviderFilters(liveProviderRules)", enable_interface)
        self.assertIn("deleteFilters(liveProviderRules)", enable_interface)
        self.assertNotIn("0xe2c114ee", self.source)
        self.assertIn("ST_DRIVER_BASELINE_SUBLAYER_KEY", init_sublayer)
        self.assertNotIn("ST_FW_WINFW_BASELINE_SUBLAYER_KEY", self.source)
        self.assertIn("subLayer.providerKey = nullptr", init_sublayer)

        reset_call = self.windowsdaemon.find(
            "WindowsSplitTunnel::resetForFirewallMigration()"
        )
        conflict_check = self.windowsdaemon.find(
            "WindowsSplitTunnel::detectConflict()"
        )
        firewall_create = self.windowsdaemon.find("WindowsFirewall::create(this)")
        self.assertGreaterEqual(conflict_check, 0)
        self.assertGreater(reset_call, conflict_check)
        self.assertGreaterEqual(reset_call, 0)
        self.assertGreater(firewall_create, reset_call)

        init = self.function_body("bool KillSwitch::init()", self.killswitch)
        startup = self.function_body("LocalServer::LocalServer(", self.localserver)
        self.assertIn("return disableKillSwitch();", init)
        self.assertIn("if (!KillSwitch::instance()->init())", startup)
        self.assertIn("failStartup", startup)

    def test_uninstall_removes_persistent_policy_before_binary_removal(self) -> None:
        cleanup = self.function_body(
            "bool WindowsFirewall::removePersistentPolicy()"
        )

        self.assertIn("loadProviderFilters()", cleanup)
        self.assertIn("enumerateProviderFilters(liveProviderRules)", cleanup)
        self.assertIn("deleteFilters(liveProviderRules)", cleanup)
        self.assertNotIn("allowAllTraffic()", cleanup)
        self.assertNotIn("FwpmSubLayerDeleteByKey0", cleanup)
        self.assertIn("FwpmProviderDeleteByKey0", cleanup)
        self.assertIn('QStringLiteral("cleanup-firewall")', self.service_main)
        self.assertIn("WindowsSplitTunnel::removeForUninstall()", self.service_main)
        self.assertIn("CleanupServiceState cleanupServiceState()", self.service_main)
        self.assertIn("QueryServiceStatusEx", self.service_main)
        self.assertIn("status.dwCurrentState != SERVICE_STOPPED", self.service_main)
        self.assertIn("ERROR_SERVICE_DOES_NOT_EXIST", self.service_main)
        self.assertIn("CleanupServiceActiveExitCode", self.service_main)
        remove_driver = self.function_body(
            "bool WindowsSplitTunnel::removeForUninstall()", self.split_tunnel
        )
        self.assertIn("resetDriver(driverFile)", remove_driver)
        self.assertIn("driverManager->stopService()", remove_driver)
        self.assertIn("uninstallDriver()", remove_driver)
        stop_service = self.function_body(
            "bool WindowsServiceManager::stopService()", self.service_manager
        )
        self.assertIn("SERVICE_STATUS status = {};", stop_service)
        self.assertIn(
            "ControlService(m_service, SERVICE_CONTROL_STOP, &status)",
            stop_service,
        )
        self.assertNotIn(
            "ControlService(m_service, SERVICE_CONTROL_STOP, NULL)",
            stop_service,
        )
        self.assertIn("cleanup-firewall", self.post_uninstall)
        self.assertIn("setlocal EnableExtensions DisableDelayedExpansion", self.post_uninstall)
        self.assertIn('set "AmneziaPath=%~dp0"', self.post_uninstall)
        self.assertIn('set "MaxCleanupAttempts=6"', self.post_uninstall)
        self.assertIn('set "MaxDeleteAttempts=6"', self.post_uninstall)
        self.assertIn('set "MaxDriverDeleteAttempts=6"', self.post_uninstall)
        self.assertIn(
            'set "FAILURE_RECEIPT=%RECOVERY_ROOT%\\uninstall-cleanup-failed.txt"',
            self.post_uninstall,
        )
        self.assertIn(
            'set "RECOVERY_ROOT=%ProgramFiles%\\AmneziaVPN-Recovery"',
            self.post_uninstall,
        )
        self.assertIn(
            'set "RECOVERY_DIR=%RECOVERY_ROOT%\\uninstall-recovery"',
            self.post_uninstall,
        )
        self.assertNotIn('set "RECOVERY_DIR=%SYS_APP_DIR%', self.post_uninstall)
        self.assertIn(
            'set "EMERGENCY_MARKER=%RECOVERY_ROOT%\\uninstall-recovery-required.txt"',
            self.post_uninstall,
        )
        self.assertNotIn('set "FAILURE_RECEIPT=%SYS_APP_DIR%', self.post_uninstall)
        self.assertNotIn('set "EMERGENCY_MARKER=%SYS_APP_DIR%', self.post_uninstall)
        self.assertNotIn("EMERGENCY_FALLBACK_MARKER", self.post_uninstall)
        self.assertNotIn("echo script=%~f0", self.post_uninstall)
        self.assertNotIn("echo %AmneziaPath%", self.post_uninstall)
        self.assertIn(":cleanup_firewall", self.post_uninstall)
        self.assertIn("goto cleanup_firewall", self.post_uninstall)
        self.assertIn(":cleanup_failed", self.post_uninstall)
        self.assertIn(":cleanup_failure_cleanup", self.post_uninstall)
        self.assertIn(":create_recovery_bundle", self.post_uninstall)
        self.assertIn(":copy_recovery_tree", self.post_uninstall)
        self.assertIn(":mirror_recovery_tree", self.post_uninstall)
        self.assertIn(":prepare_recovery_root", self.post_uninstall)
        self.assertIn(":verify_recovery_acl", self.post_uninstall)
        self.assertIn(":reject_reparse_point", self.post_uninstall)
        self.assertIn("reparsepoint query", self.post_uninstall)
        self.assertIn("/inheritance:r", self.post_uninstall)
        self.assertIn('"*S-1-5-18:(OI)(CI)F"', self.post_uninstall)
        self.assertIn('"*S-1-5-32-544:(OI)(CI)F"', self.post_uninstall)
        self.assertIn("AreAccessRulesProtected", self.post_uninstall)
        self.assertIn("recovery_acl_status=%RecoveryAclStatus%", self.post_uninstall)
        self.assertIn(":write_emergency_marker", self.post_uninstall)
        self.assertIn(":write_failure_receipt", self.post_uninstall)
        self.assertIn(":write_failure_event", self.post_uninstall)
        self.assertIn('call :reject_reparse_point "%RECOVERY_ROOT%"', self.post_uninstall)
        self.assertIn('call :reject_reparse_point "%FAILURE_RECEIPT%"', self.post_uninstall)
        self.assertIn('call :reject_reparse_point "%EMERGENCY_MARKER%"', self.post_uninstall)
        self.assertIn("FailureReceiptStatus=protected-recovery-root", self.post_uninstall)
        self.assertIn("/E /COPY:DAT /DCOPY:DAT /R:1 /W:1", self.post_uninstall)
        self.assertIn("/MIR /COPY:DAT /DCOPY:DAT /R:1 /W:1", self.post_uninstall)
        self.assertIn(
            'if not exist "%RECOVERY_DIR%\\AmneziaVPN-service.exe"',
            self.post_uninstall,
        )
        self.assertIn(
            'if not exist "%RECOVERY_DIR%\\post_uninstall.cmd"',
            self.post_uninstall,
        )
        self.assertIn("recovery_validated=%RecoveryValidated%", self.post_uninstall)
        self.assertIn("recovery_status=%RecoveryStatus%", self.post_uninstall)
        self.assertIn("reinstall a fixed AmneziaVPN package", self.post_uninstall)
        self.assertIn("call :write_failure_receipt", self.post_uninstall)
        self.assertIn(":verify_split_tunnel_driver_deleted", self.post_uninstall)
        self.assertIn("sc stop AmneziaVPNSplitTunnel", self.post_uninstall)
        self.assertIn("sc delete AmneziaVPNSplitTunnel", self.post_uninstall)
        self.assertIn("sc delete AmneziaVPN-service", self.post_uninstall)
        self.assertIn("sc delete AmneziaWGTunnel$AmneziaVPN", self.post_uninstall)
        self.assertIn("sc config AmneziaVPN-service start= disabled", self.post_uninstall)
        self.assertNotIn("sc config AmneziaVPN-service start= auto", self.post_uninstall)
        self.assertNotIn("sc start AmneziaVPN-service", self.post_uninstall)
        self.assertIn(":wait_before_retry", self.post_uninstall)
        self.assertIn(":wait_for_service_stop", self.post_uninstall)
        self.assertIn('"%SystemRoot%\\System32\\ping.exe" -n 6 127.0.0.1',
                      self.post_uninstall)
        self.assertNotIn("timeout /t", self.post_uninstall)
        self.assertIn("exit /b 1", self.post_uninstall)
        self.assertIn('"UNDOEXECUTE", windowsPowerShell, "-NoLogo", "-NoProfile"',
                      self.qif_component_script)
        self.assertIn('let batchRunner = pu_path + "run_batch_file.ps1"',
                      self.qif_component_script)
        self.assertIn('let postUninstallScript = pu_path + "post_uninstall.cmd"',
                      self.qif_component_script)
        self.assertNotIn('"UNDOEXECUTE", "cmd"', self.qif_component_script)
        self.assertIn("& $resolvedBatchPath", self.batch_runner)
        self.assertIn("[Environment+SpecialFolder]::ProgramFiles", self.batch_runner)
        self.assertIn("[Environment+SpecialFolder]::CommonApplicationData", self.batch_runner)
        self.assertIn("[IO.FileAttributes]::ReparsePoint", self.batch_runner)
        self.assertIn("Install directory owner is not trusted", self.batch_runner)
        self.assertIn("Install directory is writable by an untrusted principal", self.batch_runner)
        self.assertIn("deploy/data/windows/run_batch_file.ps1", self.cpack)
        self.assertNotIn('installer.value("ApplicationsDirX64")', self.qif_component_script)
        self.assertNotIn('installer.value("RootDir")', self.qif_component_script)
        self.assertIn('let protectedTargetDir = "C:\\\\Program Files\\\\AmneziaVPN"', self.qif_component_script)
        self.assertIn('let systemSc = "C:\\\\Windows\\\\System32\\\\sc.exe"', self.qif_component_script)
        self.assertNotIn('installer.environmentVariable("SystemRoot")', self.qif_component_script)
        self.assertIn('installer.setValue("TargetDir", "C:\\\\Program Files\\\\AmneziaVPN")', self.qif_control_script)
        self.assertNotIn('installer.value("ApplicationsDirX64")', self.qif_control_script)
        self.assertNotIn('installer.value("RootDir")', self.qif_control_script)
        self.assertIn('appInstalledUninstallerPath = "C:/Program Files/AmneziaVPN/maintenancetool.exe"', self.qif_control_script)
        self.assertIn('$env:ComSpec = [IO.Path]::Combine($windowsDirectory, "System32", "cmd.exe")', self.batch_runner)
        self.assertIn('$env:Path = [IO.Path]::Combine($windowsDirectory, "System32")', self.batch_runner)
        self.assertIn('Push-Location -LiteralPath $trustedWorkingDirectory', self.batch_runner)
        self.assertIn("bounded retry budget", self.qif_component_script)
        self.assertIn(
            'installer.setMessageBoxAutomaticAnswer("installationErrorWithIgnore", QMessageBox.Ignore)',
            self.qif_control_script,
        )
        self.assertNotIn(
            'installer.setMessageBoxAutomaticAnswer("installationErrorWithRetry"',
            self.qif_control_script,
        )
        shortcut_operation = self.qif_component_script.find(
            'component.addOperation("CreateShortcut"'
        )
        cleanup_undo = self.qif_component_script.find(
            '"UNDOEXECUTE", windowsPowerShell'
        )
        self.assertGreaterEqual(shortcut_operation, 0)
        self.assertGreaterEqual(cleanup_undo, 0)
        # IFW undoes operations in reverse order, so bounded service cleanup
        # runs before ordinary shortcut removal while its helper is available.
        self.assertLess(shortcut_operation, cleanup_undo)
        self.assertNotIn("CleanupAmneziaPersistentFirewall", self.wix_service_patch)
        self.assertIn("CleanupAmneziaPersistentFirewall", self.wix_close_patch)
        self.assertIn('FileRef="CM_FP_AmneziaVPN.AmneziaVPN_service.exe"', self.wix_close_patch)
        self.assertIn('Return="check"', self.wix_close_patch)
        self.assertIn('After="StopServices"', self.wix_close_patch)
        self.assertIn('Condition="REMOVE=&quot;ALL&quot;"', self.wix_close_patch)
        self.assertLess(
            self.post_uninstall.find("cleanup-firewall"),
            self.post_uninstall.find("sc delete AmneziaVPN-service"),
        )
        disable = self.post_uninstall.find(
            "sc config AmneziaVPN-service start= disabled"
        )
        stop = self.post_uninstall.find("sc stop AmneziaVPN-service")
        force_stop = self.post_uninstall.find(
            'taskkill /IM "AmneziaVPN-service.exe" /F'
        )
        cleanup_call = self.post_uninstall.find(
            '"%AmneziaPath%AmneziaVPN-service.exe" cleanup-firewall'
        )
        self.assertGreaterEqual(disable, 0)
        self.assertGreater(stop, disable)
        self.assertGreater(force_stop, stop)
        self.assertGreater(cleanup_call, force_stop)
        failure_path = self.post_uninstall.find(":cleanup_failure_cleanup")
        recovery_bundle = self.post_uninstall.find("call :create_recovery_bundle", failure_path)
        receipt = self.post_uninstall.find("call :write_failure_receipt", failure_path)
        deregister = self.post_uninstall.find("sc delete AmneziaVPN-service", failure_path)
        self.assertGreater(recovery_bundle, failure_path)
        self.assertGreater(receipt, recovery_bundle)
        self.assertGreater(deregister, receipt)
        recovery_root = self.post_uninstall.find("call :prepare_recovery_root")
        first_copy = self.post_uninstall.find("call :copy_recovery_tree")
        self.assertGreaterEqual(recovery_root, 0)
        self.assertGreater(first_copy, recovery_root)
        prepare_definition = self.post_uninstall.find("\n:prepare_recovery_root\n")
        acl_verify = self.post_uninstall.find(
            "call :verify_recovery_acl", prepare_definition
        )
        prepare_return = self.post_uninstall.find("exit /b 0", acl_verify)
        self.assertGreater(prepare_definition, first_copy)
        self.assertGreater(acl_verify, prepare_definition)
        self.assertGreater(prepare_return, acl_verify)
        self.assertNotIn("/COPYALL", self.post_uninstall)
        self.assertNotIn(" /SEC", self.post_uninstall)

    def test_qif_uninstall_disarms_recovery_and_proves_service_deletion(self) -> None:
        self.assertIn('set "MaxServiceStopAttempts=15"', self.post_uninstall)
        self.assertIn('set "MaxRegistrationChecks=30"', self.post_uninstall)
        self.assertIn('set "RecoveryActionsDisarmed=0"', self.post_uninstall)
        self.assertIn(
            'call :clear_service_failure_actions AmneziaVPN-service',
            self.post_uninstall,
        )
        self.assertIn(
            '"%SystemRoot%\\System32\\sc.exe" failure "%~1" reset= 0 actions= ""',
            self.post_uninstall,
        )

        clear_recovery = self.post_uninstall.find(
            "call :clear_service_failure_actions AmneziaVPN-service"
        )
        disable_start = self.post_uninstall.find(
            "sc config AmneziaVPN-service start= disabled"
        )
        stop_service = self.post_uninstall.find("sc stop AmneziaVPN-service")
        wait_for_stop = self.post_uninstall.find("call :wait_for_service_stop", stop_service)
        forced_fallback = self.post_uninstall.find(
            'taskkill /IM "AmneziaVPN-service.exe" /F', wait_for_stop
        )
        second_wait = self.post_uninstall.find(
            "call :wait_for_service_stop", forced_fallback
        )
        self.assertGreaterEqual(clear_recovery, 0)
        self.assertGreater(disable_start, clear_recovery)
        self.assertGreater(stop_service, disable_start)
        self.assertGreater(wait_for_stop, stop_service)
        self.assertGreater(forced_fallback, wait_for_stop)
        self.assertGreater(second_wait, forced_fallback)

        failure_cleanup = self.post_uninstall[
            self.post_uninstall.index("\n:cleanup_failure_cleanup\n") :
            self.post_uninstall.index("\n:create_recovery_bundle\n")
        ]
        disarm_gate = failure_cleanup.find('if "%RecoveryActionsDisarmed%"=="1"')
        forced_failure_kill = failure_cleanup.find(
            'taskkill /IM "AmneziaVPN-service.exe" /F'
        )
        forced_failure_delete = failure_cleanup.find(
            "sc delete AmneziaVPN-service"
        )
        failure_stop = failure_cleanup.find("sc stop AmneziaVPN-service")
        self.assertGreaterEqual(disarm_gate, 0)
        self.assertGreater(failure_stop, disarm_gate)
        self.assertGreater(forced_failure_kill, disarm_gate)
        self.assertGreater(forced_failure_delete, disarm_gate)
        self.assertIn(
            "leaving its process and registration intact",
            failure_cleanup,
        )

        clear_helper = self.post_uninstall[
            self.post_uninstall.index("\n:clear_service_failure_actions\n") :
            self.post_uninstall.index("\n:wait_for_service_absent\n")
        ]
        self.assertGreaterEqual(clear_helper.count('set "RecoveryActionsDisarmed=1"'), 2)

        for service_name, failure_stage, failure_code in (
            (
                "AmneziaVPNSplitTunnel",
                "split-tunnel-driver-delete",
                "driver-registration-still-present",
            ),
            (
                "AmneziaVPN-service",
                "main-service-delete",
                "main-service-registration-still-present",
            ),
            (
                "AmneziaWGTunnel$AmneziaVPN",
                "wireguard-tunnel-service-delete",
                "wireguard-tunnel-registration-still-present",
            ),
        ):
            self.assertIn(
                f"call :wait_for_service_absent {service_name} "
                f"{failure_stage} {failure_code}",
                self.post_uninstall,
            )

        absent_helper = self.post_uninstall[
            self.post_uninstall.index("\n:wait_for_service_absent\n") :
            self.post_uninstall.index("\n:wait_before_retry\n")
        ]
        self.assertIn('if "%ServiceQueryExitCode%"=="1060" exit /b 0', absent_helper)
        self.assertIn('if not "%ServiceQueryExitCode%"=="0"', absent_helper)
        self.assertIn('if not "%ServiceQueryExitCode%"=="1072"', absent_helper)
        self.assertIn("call :wait_for_short_poll", absent_helper)
        self.assertIn("set \"CleanupFailureStage=%WaitFailureStage%\"", absent_helper)
        self.assertIn("set \"CleanupExitCode=%WaitFailureCode%\"", absent_helper)

        install_recovery = self.qif_component_script.find(
            'component.addElevatedOperation("Execute", systemSc, "failure", serviceName()'
        )
        install_start = self.qif_component_script.find(
            'component.addElevatedOperation("Execute", ["{0,1056}", systemSc, "start", serviceName()])'
        )
        self.assertGreaterEqual(install_recovery, 0)
        self.assertGreater(install_start, install_recovery)

        prepare_legacy = self.function_body(
            "function prepareWindowsMainServiceForUpgrade", self.qif_control_script
        )
        ensure_admin = self.function_body(
            "function ensureWindowsUpgradeAdminRights", self.qif_control_script
        )
        release_admin = self.function_body(
            "function releaseWindowsUpgradeAdminRights", self.qif_control_script
        )
        prepare_failure_message = self.function_body(
            "function windowsUpgradePrepareFailureMessage", self.qif_control_script
        )
        self.assertIn("installer.hasAdminRights()", ensure_admin)
        self.assertIn("installer.gainAdminRights()", ensure_admin)
        self.assertIn("windowsUpgradeAdminRightsAcquired = true", ensure_admin)
        self.assertIn("installer.dropAdminRights()", release_admin)
        self.assertIn("windowsUpgradeAdminRightsAcquired = false", release_admin)
        self.assertIn('=== "administrator-approval-required"', prepare_failure_message)
        self.assertIn('=== "service-deletion-pending"', prepare_failure_message)
        self.assertIn("Approve the Windows UAC prompt", prepare_failure_message)
        self.assertIn("still pending deletion", prepare_failure_message)
        acquire_admin = prepare_legacy.find("ensureWindowsUpgradeAdminRights()")
        disarm_recovery = prepare_legacy.find(
            '["failure", serviceName, "reset=", "0", "actions=", ""]'
        )
        self.assertGreaterEqual(acquire_admin, 0)
        self.assertGreater(disarm_recovery, acquire_admin)
        self.assertGreaterEqual(prepare_legacy.count("queryExitCode === 1072"), 2)
        self.assertGreaterEqual(
            prepare_legacy.count("windowsServiceIsAbsent(serviceName)"), 2
        )
        self.assertIn(
            '["failure", serviceName, "reset=", "0", "actions=", ""]',
            prepare_legacy,
        )
        snapshot = prepare_legacy.find(
            "windowsMainServiceConfigSnapshot = queryWindowsMainServiceConfig(serviceName)"
        )
        self.assertGreaterEqual(snapshot, 0)
        self.assertGreater(prepare_legacy.find("windowsMainServiceConfigSnapshot === null"), snapshot)
        self.assertLess(snapshot, disarm_recovery)
        self.assertIn('["query", serviceName]', prepare_legacy)
        self.assertIn("queryExitCode === 1060", prepare_legacy)
        self.assertIn("queryExitCode !== 0", prepare_legacy)
        self.assertIn(
            '["config", serviceName, "start=", "disabled"]',
            prepare_legacy,
        )
        self.assertIn("failureExitCode !== 0", prepare_legacy)
        self.assertIn("disableExitCode !== 0", prepare_legacy)
        self.assertNotIn("failureExitCode !== 1060", prepare_legacy)
        self.assertNotIn("disableExitCode !== 1060", prepare_legacy)
        self.assertIn("windowsMainServicePrepared = true", prepare_legacy)
        self.assertIn("restoreWindowsMainServiceAfterAbortedUpgrade()", prepare_legacy)

        restore_legacy = self.function_body(
            "function restoreWindowsMainServiceAfterAbortedUpgrade",
            self.qif_control_script,
        )
        controller = self.function_body(
            "function recoverWindowsServiceUpgradeJournalIfPresent",
            self.qif_control_script,
        )
        query_service = self.function_body(
            "function queryWindowsMainServiceConfig",
            self.qif_control_script,
        )
        self.assertIn("parseScOutputFields", query_service)
        self.assertIn('replace(/\\s+/g, " ")', query_service)
        self.assertIn('startType = "delayed-auto"', query_service)
        self.assertIn('start: startType', query_service)
        self.assertIn("AUTO_START\\s+\\(DELAYED\\)", query_service)
        self.assertIn('failureFields["FAILURE_ACTIONS"]', query_service)
        self.assertIn('failureFields["RESET_PERIOD (IN SECONDS)"]', query_service)
        self.assertIn('failureFields["REBOOT_MESSAGE"]', query_service)
        self.assertIn('failureFields["COMMAND_LINE"]', query_service)
        self.assertIn('failureFlagFields["FAILURE_ACTIONS_ON_NONCRASH_FAILURES"]', query_service)
        self.assertIn("normalizeWindowsFailureActionsFlag", query_service)
        self.assertIn('failureActionsFlag === ""', query_service)
        self.assertIn("windowsServiceIdentityMatches", query_service)
        self.assertIn('installer.execute(systemSc, ["qfailureflag", serviceName])', query_service)
        self.assertIn("queryWindowsMainServiceIdentity", query_service)
        self.assertIn("serviceType", self.qif_control_script)
        self.assertIn("LocalSystem", self.qif_control_script)
        self.assertIn('"identity-image-path"', self.qif_control_script)
        self.assertIn('"identity-dependencies"', self.qif_control_script)
        self.assertIn("AmneziaVPN-Recovery/upgrade-service-journal.json", self.qif_control_script)
        self.assertIn("[IO.File]::Move($Temp,$Path)", self.qif_control_script)
        self.assertIn("$BackupPath=$Path+'.bak-'+[Guid]::NewGuid().ToString('N')", self.qif_control_script)
        self.assertIn("[IO.File]::Replace($Temp,$Path,$BackupPath,$true)", self.qif_control_script)
        self.assertIn("$Stream.Flush($true)", self.qif_control_script)
        self.assertIn("$CleanupOk", self.qif_control_script)
        self.assertIn("AreAccessRulesProtected", self.qif_control_script)
        self.assertIn("S-1-5-32-544", self.qif_control_script)
        self.assertIn("Program Files (x86)/AmneziaVPN/AmneziaVPN-service.exe", self.qif_control_script)
        self.assertIn("Program Files (x86)/AmneziaVPN/mullvad-split-tunnel.sys", self.qif_control_script)
        self.assertIn("persistWindowsServiceUpgradeJournal", prepare_legacy)
        self.assertIn(
            "recoverWindowsServiceUpgradeJournalIfPresent",
            self.qif_control_script,
        )
        self.assertIn("deleted service from stale installer state", self.qif_control_script)
        self.assertIn(
            '["failure", serviceName, "reset=", "100", "actions=",',
            restore_legacy,
        )
        self.assertIn(
            'windowsMainServiceConfigSnapshot.failureActions]',
            restore_legacy,
        )
        self.assertIn(
            '["config", serviceName, "start=", windowsMainServiceConfigSnapshot.start]',
            restore_legacy,
        )
        self.assertIn("queryWindowsMainServiceConfig(serviceName)", restore_legacy)
        self.assertIn("windowsMainServiceConfigMatches", restore_legacy)
        self.assertIn("failureExitCode !== 0", restore_legacy)
        self.assertIn("failureFlagExitCode !== 0", restore_legacy)
        self.assertIn("startExitCode !== 0", restore_legacy)
        self.assertIn("queryExitCode === 1060", restore_legacy)
        self.assertNotIn("PowerShell", restore_legacy)
        self.assertIn("windowsMainServicePrepared = false", restore_legacy)

        controller = self.function_body(
            "function Controller ()", self.qif_control_script
        )
        close_client = controller.find("isDesktopAppProcessRunningMessageLoop()")
        prepare_service = controller.find("prepareWindowsMainServiceForUpgrade()")
        launch_uninstaller = controller.find("installer.execute(uninstallerPath)")
        self.assertGreaterEqual(close_client, 0)
        self.assertGreater(prepare_service, close_client)
        self.assertGreater(launch_uninstaller, prepare_service)
        prepare_failure = controller[
            prepare_service : controller.find("var installedUninstallers", prepare_service)
        ]
        self.assertIn("installer.setCancelled()", prepare_failure)
        self.assertIn("return;", prepare_failure)
        wait_for_uninstall = controller.find(
            "var uninstallerOutcome = waitForWindowsLegacyUninstaller();",
            launch_uninstaller,
        )
        uninstaller_launch = controller[launch_uninstaller:wait_for_uninstall]
        postcondition = controller[
            wait_for_uninstall : controller.find(
                "windowsUpgradeCleanupIsComplete()", wait_for_uninstall
            )
        ]
        confirm_still_installed = postcondition.find("appInstalled()")
        restore_service = postcondition.find(
            "restoreWindowsMainServiceAfterAbortedUpgrade()"
        )
        cancel_install = postcondition.find("installer.setCancelled()")
        self.assertIn("uninstallerExitCode", uninstaller_launch)
        self.assertIn('writeWindowsInstallerLog("legacy-uninstaller-exit"', uninstaller_launch)
        self.assertNotIn("uninstallerExitCode !== 0", controller)
        self.assertNotIn("uninstallerExitCode === 0", controller)
        self.assertNotIn("installer.setCancelled()", uninstaller_launch)
        self.assertNotIn("return;", uninstaller_launch)
        self.assertIn("availableUninstallers.length > 1", controller)
        self.assertIn("availableUninstallers.length === 1", controller)
        self.assertEqual(controller.count("installer.execute(uninstallerPath)"), 1)
        self.assertIn('uninstallerPostcondition !== "removed"', postcondition)
        self.assertGreaterEqual(confirm_still_installed, 0)
        self.assertGreater(restore_service, confirm_still_installed)
        self.assertGreater(cancel_install, restore_service)
        self.assertIn('uninstallerPostcondition === "present-stopped"', postcondition)
        self.assertIn("freshOldInstallationPresent = appInstalled()", postcondition)
        self.assertIn(
            "freshUninstallerProcessState = windowsLegacyMaintenanceToolProcessState()",
            postcondition,
        )
        self.assertIn("&& freshUninstallerProcessState === 0", postcondition)
        self.assertIn("&& freshOldInstallationPresent", postcondition)
        self.assertIn("windowsMainServicePrepared && safeToRestoreOldService", postcondition)
        self.assertIn('"windows.upgrade.uninstaller.still.running"', postcondition)
        self.assertIn('? "present-stopped" : "timeout-active"', postcondition)
        self.assertIn('"legacy-uninstaller-postcondition", "removed"', postcondition)
        self.assertIn("releaseWindowsUpgradeAdminRights()", prepare_failure)
        self.assertIn("releaseWindowsUpgradeAdminRights()", postcondition)
        cleanup_failure = controller[
            controller.find("windowsUpgradeCleanupIsComplete()") :
            controller.find("} else if (installer.isUninstaller())")
        ]
        self.assertGreaterEqual(
            cleanup_failure.count("releaseWindowsUpgradeAdminRights()"), 2
        )

        wait_helper = self.function_body(
            "function waitForWindowsLegacyUninstaller",
            self.qif_control_script,
        )
        self.assertIn("for (var i = 0; i < 1200; i++)", wait_helper)
        self.assertIn("sleep(500)", wait_helper)
        self.assertIn("removedQuiescentChecks++", wait_helper)
        self.assertIn("presentQuiescentChecks++", wait_helper)
        self.assertIn("removedQuiescentChecks = 0", wait_helper)
        self.assertIn("presentQuiescentChecks = 0", wait_helper)
        self.assertIn("removedQuiescentChecks >= 4", wait_helper)
        self.assertIn("presentQuiescentChecks >= 20", wait_helper)

        process_probe = self.function_body(
            "function windowsLegacyMaintenanceToolProcessState",
            self.qif_control_script,
        )
        self.assertIn("C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe", process_probe)
        self.assertIn("Get-Process -Name 'maintenancetool'", process_probe)
        self.assertIn("appInstalledUninstallerPath", process_probe)
        self.assertIn("appInstalledUninstallerPath_x86", process_probe)
        self.assertIn("[StringComparison]::OrdinalIgnoreCase", process_probe)
        self.assertIn(
            "if ([string]::IsNullOrWhiteSpace($ExecutablePath)) { exit 97 }",
            process_probe,
        )
        self.assertNotIn("tasklist.exe", process_probe)
        self.assertNotIn("@", process_probe)
        self.assertIn("return -1", process_probe)
        self.assertIn("exitCode === 10", process_probe)

        introduction = self.function_body(
            "Controller.prototype.IntroductionPageCallback", self.qif_control_script
        )
        ready = self.function_body(
            "Controller.prototype.ReadyForInstallationPageCallback",
            self.qif_control_script,
        )
        consent = controller.find("windowsUpgradeReplacementRequested = true")
        launch_uninstaller = controller.find("installer.execute(uninstallerPath)")
        cleanup_succeeded = controller.find("windowsUpgradeContinuationRequested = true")
        direct_continuation = controller.find(
            'continueWindowsUpgradeInstallation("cleanup-success")'
        )
        self.assertGreaterEqual(consent, 0)
        self.assertLess(consent, launch_uninstaller)
        self.assertGreater(cleanup_succeeded, launch_uninstaller)
        self.assertGreater(
            cleanup_succeeded, controller.find("!windowsUpgradeCleanupIsComplete()")
        )
        self.assertEqual(direct_continuation, -1)
        self.assertIn('continueWindowsUpgradeInstallation("introduction-callback")', introduction)
        self.assertIn('commitWindowsUpgradeInstallation("ready-callback")', ready)

        continuation = self.function_body(
            "function continueWindowsUpgradeInstallation", self.qif_control_script
        )
        commit = self.function_body(
            "function commitWindowsUpgradeInstallation", self.qif_control_script
        )
        self.assertIn("windowsUpgradeNextRequested", continuation)
        self.assertIn("windowsUpgradeNextRequested = true", continuation)
        self.assertIn("gui.isButtonEnabled(buttons.NextButton)", continuation)
        self.assertEqual(continuation.count("gui.clickButton(buttons.NextButton, 250)"), 1)
        self.assertIn("windowsUpgradeCommitRequested", commit)
        self.assertIn("windowsUpgradeCommitRequested = true", commit)
        self.assertIn("gui.isButtonEnabled(buttons.CommitButton)", commit)
        self.assertEqual(commit.count("gui.clickButton(buttons.CommitButton, 250)"), 1)

    @unittest.skipUnless(shutil.which("node"), "Node.js is required")
    def test_qif_windows_service_config_parser_accepts_standard_fields_in_any_order(self) -> None:
        parser = "function parseScOutputFields(output)\n" + self.function_body(
            "function parseScOutputFields", self.qif_control_script
        )
        field_guard = "function scFieldsHaveOnly(fields, allowedFields)\n" + self.function_body(
            "function scFieldsHaveOnly", self.qif_control_script
        )
        query = self.function_body("function queryWindowsMainServiceConfig", self.qif_control_script)
        identity = self.function_body("function queryWindowsMainServiceIdentity", self.qif_control_script)
        normalize_flag = self.function_body(
            "function normalizeWindowsFailureActionsFlag", self.qif_control_script
        )
        normalize_image = self.function_body(
            "function normalizeWindowsServiceImagePath", self.qif_control_script
        )
        identity_matches = self.function_body(
            "function windowsServiceIdentityMatches", self.qif_control_script
        )
        identity_reason = self.function_body(
            "function windowsServiceIdentityFailureReason", self.qif_control_script
        )
        standard_failure = """[SC] QueryServiceConfig2 SUCCESS

SERVICE_NAME : AmneziaVPN-service
FAILURE_ACTIONS :
  RESTART -- Delay = 2000 milliseconds.
  RESTART -- Delay = 2000 milliseconds.
  RESTART -- Delay = 2000 milliseconds.
COMMAND_LINE :
RESET_PERIOD (in seconds) : 100
REBOOT_MESSAGE :
"""
        nonstandard_failure = standard_failure.replace("2000", "5000", 1)
        harness = f"""
{parser}
{field_guard}
function normalizeWindowsFailureActionsFlag(value)
{normalize_flag}
function normalizeWindowsServiceImagePath(value)
{normalize_image}
function windowsServiceIdentityMatches(identity, expectedStart, allowDisabled)
{identity_matches}
function windowsServiceIdentityFailureReason(identity, expectedStart, allowDisabled)
{identity_reason}
function queryWindowsMainServiceIdentity(serviceName)
{identity}
function queryWindowsMainServiceConfig(serviceName)
{query}
function runningOnWindows() {{ return true; }}
var outputs = {{}};
var installer = {{
    execute: function(_path, args) {{
        if (args.indexOf("-Command") >= 0) {{
            return [outputs.identity || "", outputs.identityExit === undefined ? 0 : outputs.identityExit];
        }}
        return [outputs[args[0]] || "", 0];
    }}
}};
function evaluate(startOutput, failureOutput, failureFlagOutput) {{
    outputs = {{
        query: "SERVICE_NAME : AmneziaVPN-service",
        qc: startOutput,
        qfailure: failureOutput,
        qfailureflag: failureFlagOutput,
        identity: JSON.stringify({{
            name: "AmneziaVPN-service", serviceType: 16, errorControl: 1, start: 2,
            delayedAutoStart: startOutput.indexOf("(DELAYED)") >= 0 ? 1 : 0,
            startName: "LocalSystem",
            imagePath: "C:/Program Files/AmneziaVPN/AmneziaVPN-service.exe",
            dependencies: "BFE,nsi"
        }})
    }};
    return queryWindowsMainServiceConfig("AmneziaVPN-service");
}}
process.stdout.write(JSON.stringify({{
    standard: evaluate("START_TYPE : 2 AUTO_START", {json.dumps(standard_failure)}, "FAILURE_ACTIONS_ON_NONCRASH_FAILURES : FALSE"),
    delayed: evaluate("START_TYPE : 2 AUTO_START (DELAYED)", {json.dumps(standard_failure)}, "FAILURE_ACTIONS_ON_NONCRASH_FAILURES : TRUE"),
    unsupported: evaluate("START_TYPE : 3 DEMAND_START", {json.dumps(standard_failure)}, "FAILURE_ACTIONS_ON_NONCRASH_FAILURES : FALSE"),
    nonstandard: evaluate("START_TYPE : 2 AUTO_START", {json.dumps(nonstandard_failure)}, "FAILURE_ACTIONS_ON_NONCRASH_FAILURES : FALSE"),
    localized: evaluate("START_TYPE : 2 AUTO_START", {json.dumps(standard_failure)}, "FAILURE_ACTIONS_ON_NONCRASH_FAILURES : НЕИЗВЕСТНО")
}}));
"""
        completed = subprocess.run(
            [shutil.which("node"), "-e", harness],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        result = json.loads(completed.stdout)
        self.assertEqual(
            result["standard"],
            {
                "start": "auto",
                "failureActions": "restart/2000/restart/2000/restart/2000",
                "failureActionsFlag": "0",
                "failureActionsFlagRaw": "FALSE",
            },
        )
        self.assertEqual(result["delayed"]["start"], "delayed-auto")
        self.assertEqual(result["delayed"]["failureActionsFlag"], "1")
        self.assertIsNone(result["unsupported"])
        self.assertIsNone(result["nonstandard"])
        self.assertIsNone(result["localized"])

    @unittest.skipUnless(shutil.which("node"), "Node.js is required")
    def test_qif_windows_legacy_wait_requires_consecutive_combined_states(self) -> None:
        helper = self.function_body(
            "function waitForWindowsLegacyUninstaller",
            self.qif_control_script,
        )
        harness = f"""
function waitForWindowsLegacyUninstaller()
{{
{helper}
}}
var presentStates = JSON.parse(process.argv[1]);
var processStates = JSON.parse(process.argv[2]);
var pathSample = 0;
var processSample = 0;
var waitLogs = [];
function sleep(milliseconds) {{}}
function appInstalled() {{
    var state = presentStates[Math.min(pathSample, presentStates.length - 1)];
    pathSample++;
    return state;
}}
function windowsLegacyMaintenanceToolProcessState() {{
    var state = processStates[Math.min(processSample, processStates.length - 1)];
    processSample++;
    return state;
}}
function writeWindowsInstallerLog(phase, detail) {{ waitLogs.push(phase + ":" + detail); }}
var outcome = waitForWindowsLegacyUninstaller();
outcome.pathSamples = pathSample;
outcome.processSamples = processSample;
outcome.waitLogs = waitLogs;
process.stdout.write(JSON.stringify(outcome));
"""

        def run_wait(present: list[bool], processes: list[int]) -> dict[str, object]:
            completed = subprocess.run(
                [
                    shutil.which("node"),
                    "-e",
                    harness,
                    json.dumps(present),
                    json.dumps(processes),
                ],
                check=True,
                capture_output=True,
                text=True,
                timeout=30,
            )
            return json.loads(completed.stdout)

        removed = run_wait([True] * 3 + [False] * 4, [-1])
        self.assertEqual(removed["status"], "removed")
        self.assertEqual(removed["pathSamples"], 7)
        self.assertEqual(removed["processSamples"], 3)
        self.assertFalse(removed["oldInstallationPresent"])
        self.assertIn("legacy-uninstaller-wait:path-absent", removed["waitLogs"])

        cancelled = run_wait([True] * 20, [0])
        self.assertEqual(cancelled["status"], "present-stopped")
        self.assertEqual(cancelled["pathSamples"], 20)
        self.assertEqual(cancelled["processSamples"], 20)
        self.assertTrue(cancelled["oldInstallationPresent"])

        ambiguous = run_wait([True], [1])
        self.assertEqual(ambiguous["status"], "timeout-ambiguous")
        self.assertEqual(ambiguous["pathSamples"], 1200)
        self.assertEqual(ambiguous["processSamples"], 1200)

        inaccessible = run_wait([True], [-1])
        self.assertEqual(inaccessible["status"], "timeout-ambiguous")
        self.assertEqual(inaccessible["pathSamples"], 1200)

        flapped = run_wait([False] * 3 + [True] + [False] * 4, [1])
        self.assertEqual(flapped["status"], "removed")
        self.assertEqual(flapped["pathSamples"], 8)
        self.assertEqual(flapped["processSamples"], 1)

    @unittest.skipUnless(find_windows_powershell(), "Windows PowerShell 5.1 is required")
    def test_qif_windows_legacy_process_probe_matches_exact_executable_path(self) -> None:
        process_probe = self.function_body(
            "function windowsLegacyMaintenanceToolProcessState",
            self.qif_control_script,
        )
        script_assignment = re.search(
            r'var script = (?P<expression>.*?);\s*var result = installer\.execute',
            process_probe,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(script_assignment)
        literals = re.findall(
            r'"(?:\\.|[^"\\])*"', script_assignment.group("expression")
        )
        powershell_script = "".join(json.loads(value) for value in literals)
        self.assertNotIn("@", powershell_script)

        with tempfile.TemporaryDirectory() as temp_dir:
            process_path = Path(temp_dir) / "maintenancetool.exe"
            shutil.copy2(Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/ping.exe", process_path)
            process = subprocess.Popen(
                [str(process_path), "-n", "30", "127.0.0.1"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            try:
                time.sleep(0.2)
                base_command = [
                    find_windows_powershell(),
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-WindowStyle",
                    "Hidden",
                    "-Command",
                    powershell_script,
                ]
                exact = subprocess.run(
                    [*base_command, str(process_path), str(process_path)],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                unrelated = subprocess.run(
                    [
                        *base_command,
                        str(Path(temp_dir) / "other-maintenance.exe"),
                        str(Path(temp_dir) / "other-maintenance-x86.exe"),
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                self.assertEqual(exact.returncode, 10, exact.stderr)
                self.assertEqual(unrelated.returncode, 0, unrelated.stderr)
            finally:
                process.terminate()
                process.wait(timeout=10)

    def test_qif_windows_upgrade_log_is_private_bounded_and_survives_old_uninstall(self) -> None:
        log_writer = self.function_body(
            "function writeWindowsInstallerLog", self.qif_control_script
        )
        post_uninstall = (
            REPO_ROOT / "deploy/data/windows/post_uninstall.cmd"
        ).read_text(encoding="utf-8")

        self.assertIn("$env:LOCALAPPDATA", log_writer)
        self.assertIn("AmneziaVPN-InstallerLogs", log_writer)
        self.assertIn("[IO.FileAttributes]::ReparsePoint", log_writer)
        self.assertIn("$PathItem.PSIsContainer", log_writer)
        self.assertIn("installer-*.jsonl", log_writer)
        self.assertIn("256KB", log_writer)
        self.assertIn("5MB", log_writer)
        self.assertIn("AddDays(-14)", log_writer)
        self.assertIn("Select-Object -Skip 20", log_writer)
        self.assertIn("ConvertTo-Json -Compress", log_writer)
        self.assertIn("[IO.File]::AppendAllText", log_writer)
        self.assertIn("Text.UTF8Encoding($false)", log_writer)
        self.assertIn("catch { exit 97 }", log_writer)
        self.assertNotIn("@", log_writer)
        self.assertIn("[^A-Za-z0-9._:-]", log_writer)
        self.assertNotIn("resultArray[0]", self.qif_control_script)
        self.assertNotIn("AmneziaVPN-InstallerLogs", post_uninstall)
        controller = self.function_body(
            "function Controller ()", self.qif_control_script
        )
        self.assertIn("installer.installationStarted.connect", controller)
        self.assertIn("installer.installationFinished.connect", controller)
        self.assertIn("installer.installationInterrupted.connect", controller)

    @unittest.skipUnless(find_windows_powershell(), "Windows PowerShell 5.1 is required")
    def test_qif_windows_upgrade_log_survives_ifw_argument_replacement(self) -> None:
        log_writer = self.function_body(
            "function writeWindowsInstallerLog", self.qif_control_script
        )
        script_assignment = re.search(
            r'var script = (?P<expression>.*?);\s*var result = installer\.execute',
            log_writer,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(script_assignment)
        literals = re.findall(
            r'"(?:\\.|[^"\\])*"', script_assignment.group("expression")
        )
        powershell_script = "".join(json.loads(value) for value in literals)

        # Qt IFW 4.7 treats every at-sign pair in execute arguments as a
        # variable placeholder. The logging payload must therefore be stable
        # under that preprocessing, not merely valid PowerShell source.
        self.assertNotIn("@", powershell_script)
        ifw_processed = re.sub(r"@[^@]*@", "", powershell_script)
        self.assertEqual(ifw_processed, powershell_script)

        with tempfile.TemporaryDirectory() as local_app_data:
            env = {**os.environ, "LOCALAPPDATA": local_app_data}
            log_root = Path(local_app_data) / "AmneziaVPN-InstallerLogs"
            log_root.mkdir()
            old_time = time.time() - (15 * 24 * 60 * 60)
            for index in range(24):
                retained = log_root / f"installer-retention-{index:02d}.jsonl"
                retained.write_bytes(b"x" * (300 * 1024))
                if index == 0:
                    os.utime(retained, (old_time, old_time))
            command = [
                find_windows_powershell(),
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-WindowStyle",
                "Hidden",
                "-Command",
                powershell_script,
                "installer-smoke-session",
            ]
            for phase, detail in (("installer-start", "installer"), ("cleanup-verdict", "complete")):
                completed = subprocess.run(
                    [*command, phase, detail],
                    check=False,
                    capture_output=True,
                    text=True,
                    env=env,
                    timeout=30,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)

            log_path = log_root / "installer-smoke-session.jsonl"
            raw = log_path.read_bytes()
            self.assertFalse(raw.startswith(b"\xef\xbb\xbf"))
            records = [json.loads(line) for line in raw.decode("utf-8").splitlines()]
            self.assertEqual([record["phase"] for record in records], [
                "installer-start",
                "cleanup-verdict",
            ])
            self.assertEqual([record["detail"] for record in records], [
                "installer",
                "complete",
            ])
            retained_files = list(log_root.glob("installer-*.jsonl"))
            self.assertLessEqual(len(retained_files), 20)
            self.assertLessEqual(sum(path.stat().st_size for path in retained_files), 5 * 1024 * 1024)
            self.assertFalse((log_root / "installer-retention-00.jsonl").exists())

    def test_wireguard_tunneldaemon_exits_without_starting_privileged_daemon(self) -> None:
        run_application = self.function_body(
            "int runApplication(int argc, char** argv)", self.service_main
        )
        tunnel_dispatch = run_application.find(
            'if (!tokens.empty() && tokens[0] == "tunneldaemon")'
        )
        tunnel_return = run_application.find("return daemon.run(tokens);", tunnel_dispatch)
        privileged_server = run_application.find("LocalServer localServer;")

        self.assertGreaterEqual(tunnel_dispatch, 0)
        self.assertGreater(tunnel_return, tunnel_dispatch)
        self.assertGreater(privileged_server, tunnel_return)
        self.assertIn("WindowsDaemonTunnel daemon;", run_application)
        self.assertNotIn("new WindowsDaemonTunnel", run_application)
        self.assertNotIn("tunneldaemon", self.system_service)

    def test_qif_closes_windows_client_and_waits_for_async_service_delete(self) -> None:
        close_client = self.function_body(
            "function requestWindowsDesktopAppExit", self.qif_control_script
        )
        process_gate = self.function_body(
            "isDesktopAppProcessRunningMessageLoop = function",
            self.qif_control_script,
        )
        controller = self.function_body(
            "function Controller ()", self.qif_control_script
        )
        service_check = self.function_body(
            "function windowsServiceIsAbsent", self.qif_control_script
        )

        self.assertIn('var systemTaskkill = "C:/Windows/System32/taskkill.exe"', close_client)
        self.assertIn(
            '"C:/Program Files/AmneziaVPN/AmneziaVPN.exe"', close_client
        )
        self.assertIn(
            '"C:/Program Files (x86)/AmneziaVPN/AmneziaVPN.exe"', close_client
        )
        disconnect = close_client.find(
            'installer.execute(clientPath, ["--disconnect", "--json"])'
        )
        receipt_parse = close_client.find("JSON.parse(disconnectResult[0])")
        receipt_schema = close_client.find(
            'disconnectReceipt.schema === "amnezia.operator.disconnect.v1"'
        )
        receipt_ok = close_client.find("disconnectReceipt.ok === true")
        receipt_completed = close_client.find("disconnectReceipt.completed === true")
        receipt_state = close_client.find(
            'disconnectReceipt.state === "disconnected"'
        )
        disconnect_confirmed = close_client.find("disconnectConfirmed = true")
        disconnect_gate = close_client.find("if (!disconnectConfirmed)")
        graceful = close_client.find(
            'installer.execute(systemTaskkill, ["/IM", "AmneziaVPN.exe"])'
        )
        exact_path_fallback = close_client.find(
            "installer.killProcess(installedClientPaths[killIndex])"
        )
        self.assertGreaterEqual(disconnect, 0)
        self.assertGreater(receipt_parse, disconnect)
        self.assertGreater(receipt_schema, receipt_parse)
        self.assertGreater(receipt_ok, receipt_schema)
        self.assertGreater(receipt_completed, receipt_ok)
        self.assertGreater(receipt_state, receipt_completed)
        self.assertGreater(disconnect_confirmed, receipt_state)
        self.assertGreater(disconnect_gate, disconnect)
        self.assertGreater(graceful, disconnect_gate)
        self.assertGreater(exact_path_fallback, graceful)
        self.assertIn("gracefulAttempt < 100", close_client)
        self.assertIn("forcedAttempt < 50", close_client)
        self.assertIn("sleep(100)", close_client)
        self.assertNotIn("installer.environmentVariable", close_client)
        self.assertNotIn('["/F", "/IM", "AmneziaVPN.exe"]', close_client)

        automatic_close = process_gate.find("requestWindowsDesktopAppExit()")
        manual_fallback = process_gate.find("could not be closed automatically")
        self.assertGreaterEqual(automatic_close, 0)
        self.assertGreater(manual_fallback, automatic_close)

        installer_dispatch = controller.find("if (installer.isInstaller())")
        replace_consent = controller.find("var automaticReplacement = isSelfHostedAutomaticUpdate();")
        close_after_consent = controller.find(
            "isDesktopAppProcessRunningMessageLoop()", replace_consent
        )
        self.assertGreaterEqual(installer_dispatch, 0)
        self.assertGreater(replace_consent, installer_dispatch)
        self.assertGreater(close_after_consent, replace_consent)
        self.assertNotIn(
            "isDesktopAppProcessRunningMessageLoop()",
            controller[installer_dispatch:replace_consent],
        )

        self.assertIn("attempt < 150", service_check)
        self.assertIn("exitCode === 1060", service_check)
        self.assertIn("exitCode !== 0 && exitCode !== 1072", service_check)
        self.assertIn("sleep(100)", service_check)

    def test_qif_cli_install_starts_service_before_reporting_success(self) -> None:
        create_body = self.function_body(
            "Component.prototype.createOperations",
            self.qif_component_script,
        )
        finish_body = self.function_body(
            "Component.prototype.installationFinished",
            self.qif_component_script,
        )

        post_install = create_body.find(
            'component.addElevatedOperation("Execute", windowsPowerShell, '
            '"-NoLogo", "-NoProfile"'
        )
        service_create = create_body.find('[systemSc, "create", serviceName()')
        service_delete_undo = create_body.find(
            '"UNDOEXECUTE", ["{0,1060}", systemSc, "delete", serviceName()]'
        )
        cleanup_undo = create_body.find(
            '"UNDOEXECUTE", windowsPowerShell, "-NoLogo", "-NoProfile"'
        )
        configure_recovery = create_body.find(
            'component.addElevatedOperation("Execute", systemSc, "failure", '
            "serviceName()"
        )
        start_service = create_body.find(
            'component.addElevatedOperation("Execute", ["{0,1056}", systemSc, '
            '"start", serviceName()])'
        )

        self.assertGreaterEqual(service_create, 0)
        self.assertGreater(service_delete_undo, service_create)
        self.assertGreater(cleanup_undo, service_delete_undo)
        self.assertGreaterEqual(post_install, 0)
        self.assertLess(service_create, post_install)
        self.assertGreater(configure_recovery, post_install)
        self.assertGreater(start_service, configure_recovery)
        self.assertIn(
            '"reset=", "100", "actions=",\n'
            '                                       "restart/2000/restart/2000/restart/2000"',
            create_body,
        )
        self.assertNotIn("UNDOEXECUTE", create_body[post_install:start_service])
        self.assertNotIn('installer.execute("net", ["start"', finish_body)
        self.assertNotIn('installer.execute("sc", ["failure"', finish_body)

    def test_qif_windows_driver_upgrade_is_uninstall_first_and_fail_closed(self) -> None:
        controller = self.function_body(
            "function Controller ()", self.qif_control_script
        )
        service_check = self.function_body(
            "function windowsServiceIsAbsent", self.qif_control_script
        )
        cleanup_check = self.function_body(
            "function windowsUpgradeCleanupIsComplete", self.qif_control_script
        )
        component_ops = self.function_body(
            "Component.prototype.createOperations", self.qif_component_script
        )

        updater_guard = controller.find(
            "if (runningOnWindows() && installer.isUpdater())"
        )
        installer_dispatch = controller.find("if (installer.isInstaller())")
        self.assertGreaterEqual(updater_guard, 0)
        self.assertLess(updater_guard, installer_dispatch)
        self.assertIn("full offline AmneziaVPN installer", controller)
        self.assertIn("installer.setCancelled()", controller[updater_guard:installer_dispatch])

        component_updater_guard = component_ops.find("if (runningOnWindows()")
        default_extract_creation = component_ops.find("component.createOperations()")
        self.assertGreaterEqual(component_updater_guard, 0)
        self.assertLess(component_updater_guard, default_extract_creation)
        self.assertIn(
            "installer.isUpdater() || component.updateRequested()",
            component_ops[:default_extract_creation],
        )
        self.assertIn("throw new Error", component_ops[:default_extract_creation])

        self.assertIn('var systemSc = "C:/Windows/System32/sc.exe"', service_check)
        self.assertIn("exitCode === 1060", service_check)
        self.assertIn("return false", service_check)
        for service_name in (
            "AmneziaVPN-service",
            "AmneziaVPNSplitTunnel",
            "AmneziaWGTunnel$AmneziaVPN",
        ):
            self.assertIn(service_name, cleanup_check)
        for residue in (
            "C:/Program Files/AmneziaVPN",
            "maintenancetool.exe",
            "AmneziaVPN-service.exe",
            "mullvad-split-tunnel.sys",
            "uninstall-cleanup-failed.txt",
            "uninstall-recovery-required.txt",
        ):
            self.assertIn(residue, cleanup_check)
        self.assertIn(
            "for (var residueAttempt = 0; residueAttempt < 150; ++residueAttempt)",
            cleanup_check,
        )
        self.assertIn("if (residueAttempt < 149)", cleanup_check)
        self.assertIn("sleep(100)", cleanup_check)
        self.assertIn('if (blockingResidue === "")', cleanup_check)
        self.assertIn(
            'console.log("Previous Windows cleanup residue blocks installation: "',
            cleanup_check,
        )

        uninstall_launch = controller.find(
            "var resultArray = installer.execute(uninstallerPath);"
        )
        cleanup_postcondition = controller.find(
            "!windowsUpgradeCleanupIsComplete()"
        )
        uninstaller_dispatch = controller.find(
            "} else if (installer.isUninstaller())"
        )
        self.assertGreaterEqual(uninstall_launch, 0)
        self.assertGreater(cleanup_postcondition, uninstall_launch)
        self.assertLess(cleanup_postcondition, uninstaller_dispatch)

        launch = self.function_body(
            "int UpdateController::runWindowsInstaller(", self.update_controller
        )
        self.assertIn("CreateProcessW(", launch)
        self.assertIn("resolvedInstallerPath.utf16()", launch)
        self.assertIn('const QString commandLine = QStringLiteral("\\\"")', launch)
        self.assertIn("--accept-messages", launch)
        self.assertNotIn("--silent", launch)
        self.assertIn("--accept-licenses", launch)
        self.assertIn("--confirm-command", launch)
        self.assertIn(
            'QStringLiteral("\\\" --accept-messages --accept-licenses --confirm-command install AmneziaSelfHostedUpdate=true")',
            launch,
        )
        self.assertIn('char selfHostedUpdate[] = "AmneziaSelfHostedUpdate=true";', self.update_controller)
        self.assertNotIn("maintenancetool", launch.lower())

        self.assertIn("function isSelfHostedAutomaticUpdate()", self.qif_control_script)
        self.assertIn('installer.value("AmneziaSelfHostedUpdate")', self.qif_control_script)
        self.assertIn("var automaticReplacement = isSelfHostedAutomaticUpdate();", self.qif_control_script)
        self.assertIn("automaticReplacement\n                    || QMessageBox.Ok", self.qif_control_script)
        self.assertIn("cancelling without user interaction", self.qif_control_script)

    @unittest.skipUnless(os.name == "nt", "Windows PowerShell runner test")
    def test_qif_batch_runner_rejects_untrusted_install_directory(self) -> None:
        source_runner = REPO_ROOT / "deploy/data/windows/run_batch_file.ps1"
        powershell = (
            Path(os.environ.get("SystemRoot", r"C:\Windows"))
            / "System32/WindowsPowerShell/v1.0/powershell.exe"
        )
        self.assertTrue(powershell.is_file())

        with tempfile.TemporaryDirectory(prefix="Amnezia & (safe) ") as tmp:
            install_dir = Path(tmp) / "custom & (target)"
            install_dir.mkdir()
            runner = install_dir / "run_batch_file.ps1"
            batch = install_dir / "post install & (probe).cmd"
            marker = install_dir / "probe-result.txt"
            shutil.copy2(source_runner, runner)
            batch.write_text(
                '@echo off\r\n> "%~dp0probe-result.txt" echo safe\r\n',
                encoding="utf-8",
            )

            result = subprocess.run(
                [
                    str(powershell),
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(runner),
                    str(batch),
                ],
                text=True,
                capture_output=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Install directory owner is not trusted", result.stderr)
            self.assertFalse(marker.exists())

            outside_batch = Path(tmp) / "outside.cmd"
            outside_batch.write_text("@exit /b 0\r\n", encoding="utf-8")
            rejected = subprocess.run(
                [
                    str(powershell),
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(runner),
                    str(outside_batch),
                ],
                text=True,
                capture_output=True,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("must be located beside the trusted runner", rejected.stderr)

            rejected_install_dir = Path(tmp) / "custom %PATH%"
            rejected_install_dir.mkdir()
            rejected_runner = rejected_install_dir / "run_batch_file.ps1"
            rejected_batch = rejected_install_dir / "post_install.cmd"
            shutil.copy2(source_runner, rejected_runner)
            rejected_batch.write_text("@exit /b 0\r\n", encoding="utf-8")
            expansion_path = subprocess.run(
                [
                    str(powershell),
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(rejected_runner),
                    str(rejected_batch),
                ],
                text=True,
                capture_output=True,
            )
            self.assertNotEqual(expansion_path.returncode, 0)
            self.assertIn("must not contain shell expansion characters", expansion_path.stderr)

    def test_qif_quotes_windows_service_image_path(self) -> None:
        create_body = self.function_body(
            "Component.prototype.createOperations",
            self.qif_component_script,
        )

        self.assertIn(
            'let serviceImagePath = "\\\"" + pu_path + serviceName() + ".exe\\\""',
            create_body,
        )
        self.assertIn(
            '[systemSc, "create", serviceName(), "binpath=", serviceImagePath,',
            create_body,
        )
        self.assertNotIn(
            '"binpath=", pu_path + serviceName() + ".exe"',
            create_body,
        )

    def test_strict_transition_removes_all_bypass_buckets_atomically(self) -> None:
        body = self.function_body("bool WindowsFirewall::enableInterface(")

        self.assertIn("enumerateProviderFilters(liveProviderRules)", body)
        self.assertIn("deleteFilters(liveProviderRules)", body)
        self.assertIn('IPAddress("0.0.0.0/0")', body)
        self.assertIn('IPAddress("::/0")', body)
        self.assertIn("m_vpnInterfaceLuid = 0", body)
        self.assertLess(
            body.find("FwpmTransactionCommit0"),
            body.find("m_orphanedRules.clear()"),
        )
        self.assertNotIn("disableKillSwitch()", body)
        self.assertIn("pendingActivationFenceRules", body)

        peer = self.function_body("bool WindowsFirewall::enablePeerTraffic(")
        self.assertIn("deleteFilters(m_activationFenceRules)", peer)
        self.assertLess(
            peer.find("FwpmTransactionCommit0"),
            peer.find("m_activationFenceRules.clear()"),
        )

    def test_filter_bookkeeping_changes_only_after_successful_commit(self) -> None:
        delete_filters = self.function_body("bool WindowsFirewall::deleteFilters(")
        allow_all = self.function_body("bool WindowsFirewall::allowAllTraffic()")
        peer = self.function_body("bool WindowsFirewall::enablePeerTraffic(")

        self.assertIn("FwpmFilterDeleteById0", delete_filters)
        self.assertIn("FWP_E_FILTER_NOT_FOUND", delete_filters)
        self.assertIn("return false", delete_filters)
        self.assertLess(
            allow_all.find("FwpmTransactionCommit0"),
            allow_all.find("m_baseRules.clear()"),
        )
        self.assertLess(
            peer.find("FwpmTransactionCommit0"),
            peer.find("m_peerRules.remove(config.m_serverPublicKey)"),
        )
        self.assertNotIn("disableKillSwitch()", peer)

    def test_wfp_engine_and_callers_propagate_failures(self) -> None:
        destructor = self.function_body("WindowsFirewall::~WindowsFirewall()")
        enable_kill_switch = self.function_body(
            "bool KillSwitch::enableKillSwitch(", self.killswitch
        )
        reset_ranges = self.function_body(
            "bool KillSwitch::resetAllowedRange(", self.killswitch
        )
        add_interface = self.function_body(
            "bool WireguardUtilsWindows::addInterface(", self.wireguard
        )
        update_peer = self.function_body(
            "bool WireguardUtilsWindows::updatePeer(", self.wireguard
        )
        update_gateway = self.function_body(
            "void OpenVpnProtocol::updateVpnGateway(", self.openvpn
        )

        self.assertIn("FwpmEngineClose0", destructor)
        self.assertNotIn("CloseHandle", destructor)
        self.assertNotIn("allowAllTraffic()", enable_kill_switch)
        self.assertIn("!firewall->enableInterface", enable_kill_switch)
        self.assertNotIn("enableInterface(-1)", reset_ranges)
        self.assertIn("!firewall->allowTrafficRange", reset_ranges)
        self.assertNotIn("allowAllTraffic()", add_interface)
        self.assertIn("!m_firewall->enableInterface", add_interface)
        self.assertIn("!m_firewall->enablePeerTraffic", update_peer)
        delete_peer = self.function_body(
            "bool WireguardUtilsWindows::deletePeer(", self.wireguard
        )
        self.assertIn("deferFirewallRemoval", delete_peer)
        self.assertIn("m_configuredPeers.size() <= 1", delete_peer)
        self.assertIn("enableKillSwitch.waitForFinished(1000)", update_gateway)
        self.assertIn("enablePeerTraffic.waitForFinished(1000)", update_gateway)
        self.assertIn("emit protocolError", update_gateway)
        self.assertIn("stop();", update_gateway)


if __name__ == "__main__":
    unittest.main()
