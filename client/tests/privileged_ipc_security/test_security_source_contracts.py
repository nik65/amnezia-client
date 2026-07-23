"""Source-level regression contracts for privileged IPC hardening.

These tests deliberately use only the Python standard library so that the
security invariants can be checked even when a full Qt toolchain is not
available.  Runtime C++ tests remain the stronger companion signal; this file
guards platform-specific branches and packaging inputs that a single host
cannot execute.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]


def read_source(relative_path: str) -> str:
    path = REPO_ROOT / relative_path
    if not path.is_file():
        raise AssertionError(f"required security source is missing: {relative_path}")
    return path.read_text(encoding="utf-8")


def compact(source: str) -> str:
    return re.sub(r"\s+", " ", source).strip()


def strip_cpp_comments(source: str) -> str:
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.DOTALL)
    return re.sub(r"//[^\r\n]*", "", source)


def braced_block(source: str, declaration_pattern: str) -> str:
    """Return the balanced C/C++ block following a declaration regex."""

    match = re.search(declaration_pattern, source, flags=re.MULTILINE)
    if not match:
        raise AssertionError(f"declaration not found: {declaration_pattern}")
    opening = source.find("{", match.end())
    if opening < 0:
        raise AssertionError(f"opening brace not found: {declaration_pattern}")

    depth = 0
    state = "code"
    escaped = False
    index = opening
    while index < len(source):
        char = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""

        if state == "line_comment":
            if char in "\r\n":
                state = "code"
        elif state == "block_comment":
            if char == "*" and following == "/":
                state = "code"
                index += 1
        elif state in {"string", "character"}:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif (state == "string" and char == '"') or (
                state == "character" and char == "'"
            ):
                state = "code"
        elif char == "/" and following == "/":
            state = "line_comment"
            index += 1
        elif char == "/" and following == "*":
            state = "block_comment"
            index += 1
        elif char == '"':
            state = "string"
        elif char == "'":
            state = "character"
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[opening : index + 1]
        index += 1

    raise AssertionError(f"unterminated block: {declaration_pattern}")


def patch_hunk_source(patch: str) -> str:
    """Return added/context source lines from unified-diff hunks."""

    lines: list[str] = []
    in_hunk = False
    for line in patch.splitlines():
        if line.startswith("@@"):
            in_hunk = True
            continue
        if in_hunk and (line.startswith("diff --git ") or line == "-- "):
            in_hunk = False
        if in_hunk and line.startswith(("+", " ")):
            lines.append(line[1:])
    return "\n".join(lines)


def constexpr_int(source: str, name: str) -> int:
    match = re.search(
        rf"\bconstexpr\s+(?:int|qint\d+|qsizetype)\s+{re.escape(name)}\s*=\s*(\d+)\s*;",
        source,
    )
    if not match:
        raise AssertionError(f"bounded constant not found: {name}")
    return int(match.group(1))


def world_access_is_non_windows_only(source: str) -> bool:
    """Check every WorldAccessOption occurrence is inside a non-Windows branch."""

    branch_stack: list[str] = []
    found = False
    directive = re.compile(r"^\s*#\s*(ifdef|ifndef|if|else|elif|endif)\b(.*)$")
    for line in source.splitlines():
        match = directive.match(line)
        if match:
            kind, expression = match.group(1), match.group(2).strip()
            if kind in {"ifdef", "ifndef", "if"}:
                if "Q_OS_WIN" not in expression:
                    branch_stack.append("other")
                elif kind == "ifndef" or re.search(
                    r"!\s*defined\s*\(\s*Q_OS_WIN\s*\)", expression
                ):
                    branch_stack.append("non_windows")
                else:
                    branch_stack.append("windows")
            elif kind in {"else", "elif"} and branch_stack:
                if kind == "elif":
                    if "Q_OS_WIN" not in expression:
                        branch_stack[-1] = "other"
                    elif re.search(
                        r"!\s*defined\s*\(\s*Q_OS_WIN\s*\)", expression
                    ):
                        branch_stack[-1] = "non_windows"
                    else:
                        branch_stack[-1] = "windows"
                elif branch_stack[-1] == "windows":
                    branch_stack[-1] = "non_windows"
                elif branch_stack[-1] == "non_windows":
                    branch_stack[-1] = "windows"
            elif kind == "endif" and branch_stack:
                branch_stack.pop()

        if "WorldAccessOption" in line:
            found = True
            if "non_windows" not in branch_stack:
                return False
    return found


class PrivilegedIpcSecuritySourceContracts(unittest.TestCase):
    maxDiff = None

    def test_concurrent_desktop_singleton_race_loser_cannot_reach_core_init(self) -> None:
        header = read_source("client/amneziaApplication.h")
        application = read_source("client/amneziaApplication.cpp")
        main = read_source("client/main.cpp")
        operator_protocol = read_source("client/core/utils/operatorCommand.h")
        runtime_test = read_source(
            "client/tests/privileged_ipc_security/tst_privileged_ipc_security.cpp"
        )

        self.assertRegex(header, r"\bbool\s+startLocalServer\s*\(\s*\)\s*;")
        self.assertRegex(
            compact(header),
            r"AmneziaApplication\s*\(.*?CommandParseResult\s*&\s*"
            r"startupOperatorArguments\s*,\s*bool\s+publishBundledUpdatesOnceCommand",
        )
        self.assertRegex(
            header,
            r"amnezia::ipc::PrivilegedLocalServer\s*\*\s*m_localServer",
        )

        lock_name = compact(
            strip_cpp_comments(
                braced_block(application, r"QString\s+coreOwnershipLockName\s*\(\s*\)")
            )
        )
        self.assertIn("sharedSettingsOwnershipIdentity", lock_name)
        self.assertIn("QCryptographicHash::Sha256", lock_name)
        self.assertNotIn("currentProcessUserIdentifier", lock_name)
        self.assertNotIn("applicationFilePath", lock_name)

        lock_directory = compact(
            strip_cpp_comments(
                braced_block(application, r"QString\s+coreOwnershipDirectoryPath\s*\(\s*\)")
            )
        )
        self.assertIn("QStandardPaths::AppConfigLocation", lock_directory)
        self.assertIn("QDir::isAbsolutePath(appConfigPath)", lock_directory)
        self.assertIn('QStringLiteral(".instance")', lock_directory)
        self.assertIn("QDir().mkpath(ownershipDirectory)", lock_directory)
        self.assertIn("QFile::setPermissions(ownershipDirectory, ownerOnlyPermissions)", lock_directory)
        # Processes sharing QSettings must not split ownership merely because
        # XDG_RUNTIME_DIR, TMPDIR, or Windows TEMP differs.
        self.assertNotIn("RuntimeLocation", lock_directory)
        self.assertNotIn("TempLocation", lock_directory)

        endpoint_name = compact(
            strip_cpp_comments(
                braced_block(
                    application,
                    r"QString\s+AmneziaApplication::localServerName\s*\(\s*\)",
                )
            )
        )
        self.assertIn("applicationFilePath()", endpoint_name)

        acquisition = compact(
            strip_cpp_comments(
                braced_block(
                    application,
                    r"bool\s+AmneziaApplication::acquireCoreOwnership\s*\(\s*\)",
                )
            )
        )
        self.assertIn("coreOwnershipDirectoryPath()", acquisition)
        self.assertIn("m_localServerLock->setStaleLockTime(0)", acquisition)
        self.assertEqual(acquisition.count("m_localServerLock->tryLock(0)"), 1)
        self.assertNotIn("removeStaleLockFile", acquisition)
        self.assertNotIn("RuntimeLocation", acquisition)
        self.assertNotIn("TempLocation", acquisition)
        self.assertRegex(
            acquisition,
            r"if\s*\(\s*m_localServerLock->tryLock\s*\(\s*0\s*\)\s*\)\s*"
            r"\{\s*return\s+true\s*;\s*\}\s*m_localServerLock\.reset\s*\(\s*\)\s*;"
            r"\s*return\s+false\s*;",
        )

        constructor_start = application.index("AmneziaApplication::AmneziaApplication(")
        destructor_start = application.index("AmneziaApplication::~AmneziaApplication()")
        constructor = compact(
            strip_cpp_comments(application[constructor_start:destructor_start])
        )
        app_name_index = constructor.find("setApplicationName")
        organization_name_index = constructor.find("setOrganizationName")
        lock_index = constructor.find("acquireCoreOwnership()")
        qsettings_index = constructor.find("QSettings s(")
        secure_settings_index = constructor.find("new SecureQSettings")
        self.assertTrue(
            0 <= app_name_index < lock_index < qsettings_index < secure_settings_index,
            constructor,
        )
        self.assertTrue(0 <= organization_name_index < lock_index, constructor)
        self.assertRegex(
            constructor,
            r"if\s*\(\s*!m_operatorCommandLineDetected\s*&&\s*!acquireCoreOwnership\s*\(\s*\)\s*\)"
            r"\s*\{\s*return\s*;\s*\}",
        )

        start = braced_block(
            application,
            r"bool\s+AmneziaApplication::startLocalServer\s*\(\s*\)",
        )
        start_code = compact(strip_cpp_comments(start))
        self.assertIn("new amnezia::ipc::PrivilegedLocalServer(this)", start_code)
        self.assertRegex(
            start_code,
            r"if\s*\(\s*!m_localServerLock\s*\|\|\s*!m_localServerLock->isLocked\s*\(\s*\)\s*\)"
            r"\s*\{.*?return\s+false\s*;\s*\}",
        )
        self.assertIn("PrivilegedLocalServer::newConnection", start_code)
        self.assertIn("socket->bytesAvailable() > 0", start_code)
        self.assertIn("QTimer::singleShot(0, socket, consumeRequest)", start_code)
        self.assertNotIn("m_localServerLock.reset", start_code)
        ownership_prefix = start_code.split("const auto activeConnections", 1)[0]
        self.assertNotRegex(ownership_prefix, r"\breturn\s*;")
        self.assertRegex(start_code, r"return\s+true\s*;\s*\}$")

        trust = compact(
            strip_cpp_comments(
                braced_block(application, r"bool\s+operatorPeerIsTrusted\s*\(")
            )
        )
        marker_index = trust.find("isWindowsPrivilegedPipeSocket")
        identity_index = trust.find("queryLocalServerIdentity")
        self.assertTrue(0 <= marker_index < identity_index, trust)

        connector = compact(
            strip_cpp_comments(
                braced_block(application, r"bool\s+connectOperatorSocket\s*\(")
            )
        )
        self.assertIn("connectWindowsPrivilegedPipe", connector)
        trusted_probe = compact(
            strip_cpp_comments(
                braced_block(
                    application,
                    r"bool\s+AmneziaApplication::isTrustedPrimaryRunning\s*\(",
                )
            )
        )
        forward = compact(
            strip_cpp_comments(
                braced_block(
                    application,
                    r"bool\s+AmneziaApplication::tryForwardOperatorCommand\s*\(",
                )
            )
        )
        self.assertIn("connectOperatorSocket", trusted_probe)
        self.assertIn("connectOperatorSocket", forward)
        self.assertIn("requestPrimaryWindowRaise", trusted_probe)

        raise_request = compact(
            strip_cpp_comments(
                braced_block(application, r"bool\s+requestPrimaryWindowRaise\s*\(")
            )
        )
        self.assertIn("CommandType::Raise", raise_request)
        self.assertIn("socket->write(payload)", raise_request)
        self.assertIn("socket->waitForReadyRead", raise_request)
        self.assertIn("CommandResponse::fromJson", raise_request)
        self.assertIn('QStringLiteral("amnezia.operator.raise.v1")', raise_request)
        self.assertIn("CommandType::Raise", operator_protocol)
        self.assertRegex(
            operator_protocol,
            r"case\s+CommandType::Raise\s*:\s*return\s+QStringLiteral\s*\(\s*\"raise\"\s*\)",
        )

        execute = compact(
            strip_cpp_comments(
                braced_block(
                    application,
                    r"AmneziaApplication::executeOperatorCommand\s*\(",
                )
            )
        )
        raise_index = execute.find("CommandType::Raise")
        settings_readiness_index = execute.find("if (!m_settings)")
        self.assertTrue(0 <= raise_index < settings_readiness_index, execute)
        self.assertIn("raiseMainWindow", execute)
        self.assertIn('QStringLiteral("amnezia.operator.raise.v1")', execute)
        self.assertIn("waitForPendingConnection(shortClientServer, 1000)", runtime_test)
        self.assertIn("decodedRaiseRequest.type", runtime_test)
        self.assertIn("decodedAcknowledgement.result", runtime_test)

        watch_poll = compact(
            strip_cpp_comments(braced_block(application, r"void\s+poll\s*\(\s*\)"))
        )
        self.assertIn("connectWindowsPrivilegedPipe", watch_poll)
        self.assertIn("sendRequest()", watch_poll)

        parse_commands = compact(
            strip_cpp_comments(
                braced_block(
                    application,
                    r"bool\s+AmneziaApplication::parseCommands\s*\(\s*\)",
                )
            )
        )
        self.assertIn("m_startupOperatorArguments.hasOperatorArguments", parse_commands)
        self.assertIn("m_operatorCommand = m_startupOperatorArguments.request", parse_commands)
        self.assertNotIn("parseArguments(argc, argv)", parse_commands)

        destructor = compact(
            strip_cpp_comments(
                braced_block(application, r"AmneziaApplication::~AmneziaApplication\s*\(\s*\)")
            )
        )
        teardown_steps = (
            "m_coreController.reset()",
            "m_vpnConnection.reset()",
            "delete m_settings",
            "delete m_localServer",
            "m_localServerLock.reset()",
        )
        teardown_positions = [destructor.find(step) for step in teardown_steps]
        self.assertTrue(all(position >= 0 for position in teardown_positions), teardown_positions)
        self.assertEqual(teardown_positions, sorted(teardown_positions), teardown_positions)

        main_body = braced_block(main, r"int\s+main\s*\(")
        main_code = compact(strip_cpp_comments(main_body))
        publisher_detector = compact(
            strip_cpp_comments(
                braced_block(main, r"bool\s+isPublishBundledUpdatesOnceCommand\s*\(")
            )
        )
        self.assertIn("argc == 2", publisher_detector)
        self.assertIn("argv[1]", publisher_detector)
        self.assertNotRegex(publisher_detector, r"\bfor\s*\(")
        parse_index = main_code.find("parseArguments(argc, argv)")
        app_index = main_code.find("AmneziaApplication app(")
        forward_index = main_code.find("tryForwardOperatorCommand(operatorArguments")
        self.assertTrue(0 <= parse_index < app_index < forward_index, main_code)
        self.assertIn(
            "AmneziaApplication app(argc, argv, operatorArguments, publishBundledUpdatesOnce)",
            main_code,
        )
        self.assertRegex(
            main_code,
            r"publishBundledUpdatesOnce\s*&&\s*!app\.hasCoreOwnership\s*\(\s*\)",
        )
        self.assertIn("#ifdef MACOS_NE", main)
        self.assertRegex(
            main_code,
            r"!operatorInvocation\s*&&\s*!publishBundledUpdatesOnce\s*&&\s*"
            r"!app\.hasCoreOwnership\s*\(\s*\)",
        )
        self.assertIn(
            "#if !defined(Q_OS_ANDROID) && !defined(Q_OS_IOS)\n"
            "    // Acquire the settings-global Core lock",
            application,
        )
        ownership = braced_block(
            main_body,
            r"if\s*\(\s*!operatorInvocation\s*&&\s*!publishBundledUpdatesOnce\s*\)\s*"
            r"(?=\{\s*if\s*\(\s*!app\.startLocalServer)",
        )
        ownership_code = compact(strip_cpp_comments(ownership))
        self.assertRegex(
            ownership_code,
            r"if\s*\(\s*!app\.startLocalServer\s*\(\s*\)\s*\)\s*\{"
            r".*?if\s*\(\s*isAnotherInstanceRunning\s*\(\s*\)\s*\)\s*\{"
            r".*?return\s+app\.exec\s*\(\s*\)\s*;\s*\}"
            r".*?return\s+1\s*;\s*\}",
        )

        acquisition_index = main_body.find("app.startLocalServer()")
        self.assertGreaterEqual(acquisition_index, 0)
        self.assertLess(acquisition_index, main_body.find("Migrations migrationsManager"))
        self.assertLess(acquisition_index, main_body.find("app.registerTypes()"))
        self.assertLess(acquisition_index, main_body.find("app.init()"))

    def test_windows_privileged_pipe_rearm_acl_and_registry_are_regression_covered(self) -> None:
        pipe = read_source("ipc/windowsprivilegedpipe.cpp")
        runtime = read_source(
            "client/tests/windows_privileged_pipe_reuse/tst_windows_privileged_pipe_reuse.cpp"
        )
        cmake = read_source(
            "client/tests/windows_privileged_pipe_reuse/CMakeLists.txt"
        )

        security = compact(
            strip_cpp_comments(
                braced_block(pipe, r"bool\s+buildPipeSecurity\s*\(")
            )
        )
        self.assertRegex(
            security,
            r"entries\[3\]\.grfAccessPermissions\s*=\s*"
            r"FILE_GENERIC_READ\s*\|\s*FILE_GENERIC_WRITE\s*;",
        )
        self.assertRegex(
            security,
            r"BuildTrusteeWithSidW\s*\(\s*&entries\[3\]\.Trustee\s*,\s*"
            r"ownerRightsSid\.data\s*\(\s*\)\s*\)",
        )
        self.assertRegex(
            security,
            r"entries\[4\]\.grfAccessPermissions\s*=\s*clientPipeAccess\s*;",
        )

        connector = compact(
            strip_cpp_comments(
                braced_block(pipe, r"bool\s+connectWindowsPrivilegedPipe\s*\(")
            )
        )
        self.assertIn("CreateFileW", connector)
        self.assertIn("clientPipeAccess", connector)
        self.assertNotIn("FILE_GENERIC_WRITE", connector)
        self.assertIn("QHash<const QLocalSocket *, qintptr> privilegedSockets", pipe)
        self.assertIn("privilegedSockets.constFind(socket)", pipe)

        self.assertIn("simultaneousClientOne", runtime)
        self.assertIn("simultaneousClientTwo", runtime)
        self.assertIn("sequentialClientOne", runtime)
        self.assertIn("sequentialClientTwo", runtime)
        self.assertIn("sequentialClientThree", runtime)
        self.assertIn("reserveHandleValue", runtime)
        self.assertIn("AuthzAccessCheck", runtime)
        self.assertIn("Advapi32", cmake)
        self.assertIn("Authz", cmake)

    def test_openvpn_recipe_has_semantic_pull_mode_setenv_rejection(self) -> None:
        conandata = read_source("recipes/openvpn/conandata.yml")
        self.assertRegex(
            conandata,
            r"patch_file\s*:\s*[\"']patches/0003-reject-pushed-unsafe-setenv\.patch[\"']",
        )

        patch = read_source("recipes/openvpn/patches/0003-reject-pushed-unsafe-setenv.patch")
        self.assertIn("src/openvpn/options.c", patch)
        hunk = compact(patch_hunk_source(patch))
        self.assertRegex(
            hunk,
            r"else\s+if\s*\(\s*streq\s*\(\s*p\[0\]\s*,\s*\"setenv\"\s*\)"
            r".*?VERIFY_PERMISSION\s*\(\s*OPT_P_GENERAL\s*\)\s*;"
            r".*?if\s*\(\s*pull_mode\s*\)\s*\{.*?goto\s+err\s*;",
        )
        self.assertIn("setenv-safe", hunk)

    def test_openvpn_config_and_resolver_scripts_are_hardened(self) -> None:
        ipc = read_source("ipc/ipc.h")
        policy = braced_block(
            ipc, r"inline\s+QByteArray\s+openVpnConfigSecurityPolicyPrefix\s*\("
        )
        expected_filters = (
            r'pull-filter reject \"setenv \"',
            r'pull-filter accept \"setenv-safe\"',
            r'pull-filter reject \"setenv\"',
        )
        positions = [policy.find(item) for item in expected_filters]
        self.assertTrue(all(position >= 0 for position in positions), positions)
        self.assertEqual(positions, sorted(positions), "setenv-safe must be accepted before catch-all")

        hardener = compact(
            braced_block(ipc, r"inline\s+QByteArray\s+hardenOpenVpnConfigContent\s*\(")
        )
        self.assertRegex(hardener, r"content\.startsWith\s*\(\s*policy\s*\)")
        self.assertLess(hardener.find("hardened.append(policy)"), hardener.find("hardened.append(content)"))

        forbidden = re.search(
            r"forbiddenDirectives\s*\{(?P<body>.*?)\}\s*;\s*"
            r"static\s+const\s+QSet<QString>\s+externalFileDirectives",
            ipc,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(forbidden)
        self.assertRegex(forbidden.group("body"), r"QStringLiteral\s*\(\s*\"setenv\"\s*\)")
        for directive in (
            "mode",
            "server",
            "server-ipv6",
            "server-bridge",
            "tls-server",
            "ifconfig-pool",
            "ifconfig-ipv6-pool",
            "ifconfig-pool-persist",
            "client-config-dir",
            "port-share",
            "genkey",
            "capath",
            "http-proxy",
            "dns-updown",
            "cryptoapicert",
        ):
            with self.subTest(directive=directive):
                self.assertRegex(
                    forbidden.group("body"),
                    rf"QStringLiteral\s*\(\s*\"{re.escape(directive)}\"\s*\)",
                )

        validator = braced_block(
            ipc,
            r"inline\s+bool\s+validateOpenVpnConfigContent\s*\("
            r"[\s\S]*?QString\s*\*errorMessage\s*=\s*nullptr\s*\)",
        )
        self.assertIn("hasClientSemantics", validator)
        self.assertRegex(
            compact(validator),
            r'directive\s*==\s*QStringLiteral\s*\(\s*"client"\s*\).*?'
            r'directive\s*==\s*QStringLiteral\s*\(\s*"tls-client"\s*\).*?'
            r'value\.isEmpty\s*\(\s*\)',
        )
        self.assertRegex(
            compact(validator),
            r'if\s*\(\s*!hasClientSemantics\s*\).*?return\s+false\s*;',
        )

        configurator = read_source("client/core/configurators/openVpnConfigurator.cpp")
        process_source = read_source("ipc/ipcserverprocess.cpp")
        self.assertIn("hardenOpenVpnConfigContent", configurator)
        staging = braced_block(process_source, r"bool\s+IpcServerProcess::stageInputFile\s*\(")
        validator_position = staging.find("validateOpenVpnConfigContent")
        hardener_position = staging.find("hardenOpenVpnConfigContent")
        self.assertGreaterEqual(validator_position, 0)
        self.assertGreaterEqual(hardener_position, 0)
        self.assertLess(validator_position, hardener_position)

        scripts = {
            "linux": read_source("deploy/data/linux/update-resolv-conf.sh"),
            "macos": read_source("deploy/data/macos/update-resolv-conf.sh"),
        }
        for platform, script in scripts.items():
            with self.subTest(platform=platform):
                self.assertEqual(script.splitlines()[0], "#!/bin/bash")
                self.assertIn("TRUSTED_PATH='/usr/sbin:/usr/bin:/sbin:/bin'", script)
                self.assertIn('PATH="$TRUSTED_PATH"', script)
                self.assertRegex(script, r"builtin\s+unset\b[^\n]*BASH_ENV\s+ENV")
                self.assertIn("LD_PRELOAD", script)
                self.assertIn("DYLD_INSERT_LIBRARIES", script)
                self.assertRegex(script, r"case\s+\"\$script_type\"\s+in\s*\n\s*up\|down\)")
                self.assertRegex(script, r"\[\[\s+\"\$dev\"\s+=~\s+\^\[A-Za-z0-9_")
                self.assertIn("/usr/bin/env -i", script)
                self.assertNotRegex(script, r"\beval\b")

        self.assertRegex(
            scripts["linux"],
            r"for\s+candidate\s+in\s+/usr/sbin/resolvconf\s+/sbin/resolvconf\s+"
            r"/usr/bin/resolvconf\s+/bin/resolvconf",
        )
        self.assertIn('"$RESOLVCONF"', scripts["linux"])
        self.assertIn("/usr/sbin/networksetup", scripts["macos"])

    def test_process_staging_uses_one_validated_handle(self) -> None:
        source = read_source("ipc/ipcserverprocess.cpp")
        reader = braced_block(source, r"bool\s+readValidatedRegularFile\s*\(")

        windows_open = re.search(
            r"HANDLE\s+(?P<handle>[A-Za-z_]\w*)\s*=\s*CreateFileW\s*\((?P<args>.*?)\)\s*;",
            reader,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(windows_open)
        handle = windows_open.group("handle")
        windows_args = compact(windows_open.group("args"))
        self.assertIn("GENERIC_READ", windows_args)
        self.assertIn("FILE_FLAG_OPEN_REPARSE_POINT", windows_args)
        self.assertRegex(reader, rf"GetFileType\s*\(\s*{re.escape(handle)}\s*\)")
        self.assertRegex(
            reader, rf"GetFileInformationByHandleEx\s*\(\s*{re.escape(handle)}\s*,"
        )
        self.assertRegex(reader, rf"GetFileSizeEx\s*\(\s*{re.escape(handle)}\s*,")
        self.assertRegex(reader, rf"ReadFile\s*\(\s*{re.escape(handle)}\s*,")
        self.assertIn("FILE_ATTRIBUTE_REPARSE_POINT", reader)

        unix_open = re.search(
            r"const\s+int\s+(?P<fd>[A-Za-z_]\w*)\s*=\s*::open\s*\((?P<args>.*?)\)\s*;",
            reader,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(unix_open)
        descriptor = unix_open.group("fd")
        unix_args = compact(unix_open.group("args"))
        self.assertIn("O_NOFOLLOW", unix_args)
        self.assertIn("O_NONBLOCK", unix_args)
        self.assertIn("O_CLOEXEC", unix_args)
        self.assertRegex(reader, rf"::fstat\s*\(\s*{re.escape(descriptor)}\s*,")
        self.assertRegex(reader, rf"::read\s*\(\s*{re.escape(descriptor)}\s*,")
        self.assertIn("S_ISREG", reader)

    def test_process_wait_output_and_environment_are_bounded(self) -> None:
        source = read_source("ipc/ipcserverprocess.cpp")
        ipc = read_source("ipc/ipc.h")

        environment = braced_block(source, r"QProcessEnvironment\s+trustedProcessEnvironment\s*\(")
        environment_code = strip_cpp_comments(environment)
        self.assertIn("QProcessEnvironment environment;", compact(environment_code))
        self.assertNotIn("systemEnvironment", environment_code)
        self.assertNotIn("qEnvironmentVariable", environment_code)
        self.assertRegex(environment_code, r"environment\.insert\s*\(\s*QStringLiteral\s*\(\s*\"PATH\"")
        self.assertIn('QStringLiteral("SystemRoot")', environment_code)
        self.assertIn('QStringLiteral("LC_ALL")', environment_code)
        self.assertIn("setProcessEnvironment(trustedProcessEnvironment())", compact(source))

        clamps = re.findall(
            r"std::clamp\s*\(\s*msecs\s*,\s*0\s*,\s*MaximumRemoteProcessWaitMs\s*\)",
            source,
        )
        self.assertGreaterEqual(len(clamps), 2)
        self.assertLessEqual(constexpr_int(source, "MaximumRemoteProcessWaitMs"), 5000)

        start = compact(braced_block(source, r"void\s+IpcServerProcess::start\s*\(") )
        self.assertIn("m_process->start()", start)
        self.assertNotIn("waitForStarted", start)

        self.assertRegex(
            compact(source),
            r"readyReadStandardOutput.*?drainProcessChannel\s*\(\s*QProcess::StandardOutput\s*\)",
        )
        self.assertRegex(
            compact(source),
            r"readyReadStandardError.*?drainProcessChannel\s*\(\s*QProcess::StandardError\s*\)",
        )
        bounded_append = braced_block(source, r"void\s+appendBounded\s*\(")
        self.assertIn("MaximumBufferedProcessOutput", bounded_append)
        self.assertIn("buffer.remove", bounded_append)
        self.assertIn("buffer.append", bounded_append)
        self.assertRegex(
            source,
            r"MaximumBufferedProcessOutput\s*=\s*[1-9]\d*\s*\*\s*1024\s*\*\s*1024",
        )
        self.assertIn("MaximumProcessOutputChunk", source)
        self.assertRegex(
            ipc,
            r"MaximumProcessOutputChunk\s*=\s*(?:[1-9]\d*\s*\*\s*)?1024\s*\*\s*1024",
        )

    def test_daemon_times_out_silent_first_frame_immediately(self) -> None:
        source = read_source("client/daemon/daemonlocalserverconnection.cpp")
        constructor = compact(
            braced_block(
                source,
                r"DaemonLocalServerConnection::DaemonLocalServerConnection\s*\(",
            )
        )
        self.assertIn("m_incompleteFrameTimer.setSingleShot(true)", constructor)
        self.assertRegex(constructor, r"m_incompleteFrameTimer\.setInterval\s*\(\s*[1-9]\d{2,4}\s*\)")
        self.assertRegex(
            constructor,
            r"QTimer::timeout.*?m_socket->abort\s*\(\s*\)",
        )
        timer_start = constructor.find("m_incompleteFrameTimer.start()")
        ready_read = constructor.find("QLocalSocket::readyRead")
        self.assertGreaterEqual(timer_start, 0)
        self.assertGreater(ready_read, timer_start)

        read_data = compact(braced_block(source, r"void\s+DaemonLocalServerConnection::readData\s*\(") )
        self.assertIn("m_receivedValidFrame = true", read_data)
        self.assertRegex(
            read_data,
            r"if\s*\(\s*m_buffer\.isEmpty\s*\(\s*\)\s*&&\s*m_receivedValidFrame\s*\)\s*"
            r"\{\s*m_incompleteFrameTimer\.stop",
        )

    def test_windows_pipe_is_local_first_instance_with_minimal_client_rights(self) -> None:
        source = read_source("ipc/windowsprivilegedpipe.cpp")
        code = strip_cpp_comments(source)
        self.assertIn("CreateNamedPipeW", code)
        self.assertIn("FILE_FLAG_FIRST_PIPE_INSTANCE", code)
        self.assertIn("PIPE_REJECT_REMOTE_CLIENTS", code)
        self.assertIn("Remote named-pipe paths are forbidden", source)

        security = compact(braced_block(code, r"bool\s+buildPipeSecurity\s*\("))
        self.assertIn("WinNetworkSid", security)
        self.assertIn("SetEntriesInAclW", security)
        self.assertIn("SetSecurityDescriptorDacl", security)
        network_trustee = re.search(
            r"BuildTrusteeWithSidW\s*\(\s*&entries\[(\d+)\]\.Trustee\s*,\s*"
            r"networkSid\.data\s*\(\s*\)\s*\)",
            security,
        )
        self.assertIsNotNone(network_trustee)
        network_index = network_trustee.group(1)
        self.assertRegex(
            security,
            rf"entries\[{network_index}\]\.grfAccessPermissions\s*=\s*FILE_ALL_ACCESS\s*;",
        )
        self.assertRegex(
            security,
            rf"entries\[{network_index}\]\.grfAccessMode\s*=\s*DENY_ACCESS\s*;",
        )

        access = re.search(
            r"constexpr\s+(?:DWORD|auto)\s+(?P<name>[A-Za-z_]\w*)\s*=\s*"
            r"(?P<rights>[^;]*\bFILE_READ_DATA\b[^;]*)\s*;",
            code,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(access)
        access_name = access.group("name")
        rights = set(
            re.findall(
                r"\b(?:FILE_[A-Z0-9_]+|GENERIC_[A-Z0-9_]+|SYNCHRONIZE)\b",
                access.group("rights"),
            )
        )
        self.assertEqual(
            rights,
            {"FILE_READ_DATA", "FILE_WRITE_DATA", "FILE_READ_ATTRIBUTES", "SYNCHRONIZE"},
        )

        connector = compact(braced_block(code, r"bool\s+connectWindowsPrivilegedPipe\s*\("))
        self.assertIn("CreateFileW", connector)
        self.assertRegex(connector, rf"CreateFileW\s*\(.*?\b{re.escape(access_name)}\b")
        for forbidden_right in ("GENERIC_WRITE", "FILE_APPEND_DATA", "FILE_CREATE_PIPE_INSTANCE"):
            self.assertNotIn(forbidden_right, connector)

        interactive_trustee = re.search(
            r"BuildTrusteeWithSidW\s*\(\s*&entries\[(\d+)\]\.Trustee\s*,\s*"
            r"interactiveSid\.data\s*\(\s*\)\s*\)",
            security,
        )
        self.assertIsNotNone(interactive_trustee)
        interactive_index = interactive_trustee.group(1)
        self.assertRegex(
            security,
            rf"entries\[{interactive_index}\]\.grfAccessPermissions\s*=\s*"
            rf"{re.escape(access_name)}\s*;",
        )

    def test_windows_client_identity_comes_from_impersonated_pipe_token(self) -> None:
        source = read_source("ipc/localpeerauthentication.cpp")
        sid_lookup = compact(braced_block(source, r"QString\s+sidForToken\s*\("))
        self.assertIn("TokenUser", sid_lookup)
        token_identity = compact(
            braced_block(source, r"bool\s+queryWindowsTokenIdentity\s*\(")
        )
        self.assertIn("sidForToken", token_identity)
        for token_class in ("TokenSessionId", "TokenStatistics"):
            self.assertIn(token_class, token_identity)
        self.assertIn("WinInteractiveSid", token_identity)
        self.assertIn("WinNetworkSid", token_identity)

        peer = compact(braced_block(source, r"bool\s+queryLocalPeerIdentity\s*\("))
        ordered_controls = (
            "isWindowsPrivilegedPipeSocket",
            "ImpersonateNamedPipeClient",
            "OpenThreadToken",
            "queryWindowsTokenIdentity",
            "GetNamedPipeClientSessionId",
            "GetNamedPipeClientProcessId",
            "queryProcessIdentity",
        )
        positions = [peer.find(control) for control in ordered_controls]
        self.assertTrue(all(position >= 0 for position in positions), positions)
        self.assertEqual(positions, sorted(positions))
        self.assertRegex(
            peer,
            r"queryWindowsTokenIdentity.*?CloseHandle\s*\(\s*pipeToken\s*\)\s*;.*?"
            r"const\s+bool\s+reverted\s*=\s*RevertToSelf\s*\(\s*\)",
        )
        self.assertRegex(
            peer,
            r"if\s*\(\s*!OpenThreadToken.*?if\s*\(\s*!RevertToSelf\s*\(\s*\)\s*\)"
            r"\s*\{\s*qFatal",
        )
        self.assertRegex(
            peer,
            r"pipeIdentity\.network\s*\|\|\s*!pipeIdentity\.interactive\s*\|\|\s*"
            r"pipeIdentity\.sessionId\s*==\s*0",
        )
        self.assertIn("processIdentity.userIdentifier.compare(pipeIdentity.userIdentifier", peer)
        self.assertIn("processIdentity.logonIdentifier != pipeIdentity.logonIdentifier", peer)
        self.assertIn("processIdentity.sessionId != pipeIdentity.sessionId", peer)
        self.assertRegex(peer, r"if\s*\(\s*!reverted\s*\)\s*\{\s*qFatal")

        authorization = compact(
            braced_block(source, r"bool\s+authorizePrivilegedClient\s*\(")
        )
        self.assertIn("isWindowsPrivilegedPipeSocket", authorization)
        self.assertIn("queryLocalPeerIdentity", authorization)
        self.assertIn("executablePathsMatch", authorization)
        self.assertIn("installProtectedFromWindowsPeer", authorization)

    def test_windows_privileged_server_is_authenticated_by_kernel_pid_and_scm(self) -> None:
        source = read_source("ipc/localpeerauthentication.cpp")
        authorization = compact(
            braced_block(source, r"bool\s+authorizePrivilegedServer\s*\(")
        )
        self.assertIn("namedPipeServerProcessId", authorization)
        self.assertIn("windowsServiceMatchesExpectedServer", authorization)
        # A normal desktop user cannot inspect the LocalSystem service process.
        windows_runtime = authorization.split("qint64 serverProcessId", 1)[1].split(
            "#elif defined(Q_OS_LINUX)", 1
        )[0]
        self.assertNotIn("queryLocalServerIdentity", windows_runtime)
        self.assertIn("installProtectedFromWindowsPeer", authorization)

        # The Windows-only replacement must not remove the existing peer
        # identity and executable checks used on Unix-domain sockets.
        self.assertRegex(
            authorization,
            r"#ifndef Q_OS_WIN.*?queryLocalServerIdentity.*?"
            r"executablePathsMatch\(resolved\.executablePath, expected\).*?#endif.*?"
            r"#ifdef Q_OS_WIN.*?qint64 serverProcessId",
        )

        kernel_pid = compact(
            braced_block(source, r"bool\s+namedPipeServerProcessId\s*\(")
        )
        self.assertIn("GetNamedPipeServerProcessId", kernel_pid)

        scm_identity = compact(
            braced_block(source, r"bool\s+windowsServiceMatchesExpectedServer\s*\(")
        )
        self.assertIn("SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG", scm_identity)
        self.assertIn("QueryServiceStatusEx", scm_identity)
        self.assertIn("QueryServiceConfigW", scm_identity)
        self.assertIn("config->dwServiceType == SERVICE_WIN32_OWN_PROCESS", scm_identity)
        self.assertIn('QStringLiteral("LocalSystem")', scm_identity)
        self.assertIn("serviceExecutablePathFromCommandLine", scm_identity)
        self.assertIn("executablePathsMatch", scm_identity)
        self.assertIn("statusBefore", scm_identity)
        self.assertIn("statusAfter", scm_identity)
        self.assertIn(
            "statusBefore.dwServiceType != SERVICE_WIN32_OWN_PROCESS", scm_identity
        )
        self.assertIn(
            "statusAfter.dwServiceType != SERVICE_WIN32_OWN_PROCESS", scm_identity
        )
        self.assertIn("statusBefore.dwProcessId != statusAfter.dwProcessId", scm_identity)

        command_line = compact(
            braced_block(source, r"bool\s+serviceExecutablePathFromCommandLine\s*\(")
        )
        # A quoted path must consume the whole service command line, and an
        # old unquoted registration is accepted only when the full string
        # matches the expected executable.  Splitting at whitespace would
        # turn a service argument into an invisible authentication bypass.
        self.assertIn("closingQuote != trimmed.size() - 1", command_line)
        self.assertIn("path = trimmed", command_line)
        self.assertNotIn("firstWhitespace", command_line)
        self.assertIn("!executablePathsMatch(path, expectedPath)", command_line)

    def test_all_privileged_endpoints_use_native_windows_wiring(self) -> None:
        server_pairs = {
            "service": ("service/server/localserver.h", "service/server/localserver.cpp"),
            "process": ("ipc/ipcserver.h", "ipc/ipcserver.cpp"),
            "daemon": (
                "client/daemon/daemonlocalserver.h",
                "client/daemon/daemonlocalserver.cpp",
            ),
        }
        for endpoint, paths in server_pairs.items():
            with self.subTest(endpoint=endpoint):
                combined = "\n".join(read_source(path) for path in paths)
                self.assertIn("PrivilegedLocalServer", combined)
                source = read_source(paths[1])
                if "WorldAccessOption" in source:
                    self.assertTrue(world_access_is_non_windows_only(source))

        ipc_client = read_source("client/core/utils/ipcClient.cpp")
        daemon_client = read_source("client/mozilla/localsocketcontroller.cpp")
        self.assertGreaterEqual(ipc_client.count("connectWindowsPrivilegedPipe"), 2)
        self.assertGreaterEqual(daemon_client.count("connectWindowsPrivilegedPipe"), 1)
        self.assertRegex(
            compact(ipc_client),
            r"#\s*ifdef\s+Q_OS_WIN.*?connectWindowsPrivilegedPipe",
        )
        self.assertRegex(
            compact(daemon_client),
            r"#\s*ifdef\s+Q_OS_WIN.*?connectWindowsPrivilegedPipe",
        )

    def test_capability_lifecycle_is_bounded_and_cleans_up(self) -> None:
        source = read_source("ipc/ipcserver.cpp")
        header = read_source("ipc/ipcserver.h")
        create = compact(braced_block(source, r"QString\s+IpcServer::createPrivilegedProcess\s*\("))

        global_limit = constexpr_int(source, "maximumGlobalProcessCapabilities")
        user_limit = constexpr_int(source, "maximumProcessCapabilitiesPerUser")
        unclaimed_limit = constexpr_int(source, "maximumUnclaimedProcessCapabilities")
        reject_limit = constexpr_int(source, "maximumRejectedCapabilityPeers")
        claim_timeout = constexpr_int(source, "capabilityClaimTimeoutMilliseconds")
        self.assertGreater(global_limit, 0)
        self.assertGreater(user_limit, 0)
        self.assertLessEqual(user_limit, global_limit)
        self.assertGreater(unclaimed_limit, 0)
        self.assertLessEqual(unclaimed_limit, global_limit)
        self.assertGreater(reject_limit, 1, "one rejected peer must not consume a capability")
        self.assertGreaterEqual(claim_timeout, 1000)
        self.assertLessEqual(claim_timeout, 60_000)

        self.assertRegex(
            create,
            r"m_processes\.size\s*\(\s*\)\s*>=\s*maximumGlobalProcessCapabilities",
        )
        self.assertRegex(create, r"unclaimed\s*>=\s*maximumUnclaimedProcessCapabilities")
        self.assertIn("setMaxPendingConnections(1)", create)
        self.assertIn("setListenBacklogSize(1)", create)
        self.assertIn("lifecycleTimer.setSingleShot(true)", create)
        self.assertIn("lifecycleTimer.start(capabilityClaimTimeoutMilliseconds)", create)

        quota = compact(braced_block(source, r"bool\s+IpcServer::processQuotaAvailable\s*\("))
        self.assertRegex(quota, r"forUser\s*<\s*maximumProcessCapabilitiesPerUser")
        self.assertRegex(quota, r"forProcess\s*<\s*maximumProcessCapabilitiesPerPid")

        connection = compact(braced_block(source, r"void\s+IpcServer::handleProcessConnection\s*\("))
        self.assertLess(connection.find("authorizePrivilegedClient"), connection.find("processQuotaAvailable"))
        self.assertRegex(
            connection,
            r"(?:\+\+\s*pd->rejectedPeers|pd->rejectedPeers\s*\+\+)\s*;.*?"
            r"if\s*\(\s*pd->rejectedPeers\s*>=\s*maximumRejectedCapabilityPeers\s*\)\s*"
            r"\{.*?finalizeProcessCapability",
        )
        self.assertIn("resumeAccepting", connection)

        self.assertIn("&QLocalSocket::disconnected", connection)
        self.assertIn("&QObject::destroyed", connection)
        self.assertGreaterEqual(connection.count("handleProcessSocketGone"), 2)
        socket_gone = compact(braced_block(source, r"void\s+IpcServer::handleProcessSocketGone\s*\("))
        self.assertIn("beginProcessTermination", socket_gone)
        self.assertIn("finalizeProcessCapability", socket_gone)

        timeout = compact(braced_block(source, r"void\s+IpcServer::handleProcessTimeout\s*\("))
        self.assertRegex(
            timeout,
            r"case\s+ProcessPhase::AwaitingClaim\s*:.*?finalizeProcessCapability",
        )
        self.assertRegex(
            timeout,
            r"case\s+ProcessPhase::Finished\s*:.*?finalizeProcessCapability",
        )

        self.assertRegex(
            compact(source),
            r"&IpcServerProcess::finished.*?ProcessPhase::Finished.*?"
            r"lifecycleTimer\.start\s*\(\s*processFinishedGraceMilliseconds\s*\)",
        )
        finalize = compact(braced_block(source, r"void\s+IpcServer::finalizeProcessCapability\s*\("))
        self.assertIn("m_processes.take(capability)", finalize)
        self.assertIn("lifecycleTimer.stop()", finalize)
        self.assertIn("localServer.close()", finalize)
        self.assertIn("disableRemoting", finalize)
        self.assertIn("ProcessPhase::AwaitingClaim", header)
        self.assertIn("QTimer lifecycleTimer", header)


if __name__ == "__main__":
    unittest.main(verbosity=2)
