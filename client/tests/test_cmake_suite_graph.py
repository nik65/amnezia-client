"""Configure the real test directory under each root/client routing combination.

Only desktop application/dependency-provider setup is replaced by a tiny host;
all test subdirectories, Qt targets, generated resources and target names come
from the repository. Root/client routing blocks are executed verbatim, so double
registration and missing app-scope variables cause real CMake failures.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]


def bracket(value):
    assert "]==]" not in value
    return "[==[" + value + "]==]"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cmake", required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--qt-dir", required=True)
    parser.add_argument("--prefix", default="")
    args = parser.parse_args()
    args.work_dir.mkdir(parents=True, exist_ok=True)
    root_source = (ROOT / "CMakeLists.txt").read_text()
    client_source = (ROOT / "client/CMakeLists.txt").read_text()
    options = root_source.split("# Test options must be visible", 1)[1].split("\n", 1)[1].split("# trigger conan", 1)[0]
    focused_route = root_source.split("# Register focused-only tests here.", 1)[1].split("\n", 1)[1].split("if(AMNEZIAVPN_BUILD_HEADLESS)", 1)[0]
    client_route = client_source[client_source.rindex("if(AMNEZIA_BUILD_TESTS)"):]
    assert "add_subdirectory(tests)" in client_route
    for app, focused in [(False, False), (False, True), (True, False), (True, True)]:
        case = args.work_dir / ("app-" + str(int(app)) + "-focused-" + str(int(focused)))
        source, build = case / "source", case / "build"
        (source / "client").mkdir(parents=True, exist_ok=True)
        (source / "client/dummy.cpp").write_text("int graph_fixture_source() { return 1; }\n")
        (source / "client/dummy.h").write_text("#pragma once\n")
        (source / "client/CMakeLists.txt").write_text(
            'set(SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/dummy.cpp")\n'
            'set(HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/dummy.h")\n'
            'set(LIBS Qt6::Core Qt6::Network Qt6::RemoteObjects)\n'
            'add_compile_definitions(AMNEZIA_DESKTOP)\n' + client_route + '\n'
            'if(AMNEZIA_BUILD_TESTS)\n'
            '  if(NOT TARGET test_common)\n    message(FATAL_ERROR "legacy graph missing")\n  endif()\n'
            '  get_target_property(inherited test_common SOURCES)\n'
            '  if(NOT "${CMAKE_CURRENT_SOURCE_DIR}/dummy.cpp" IN_LIST inherited)\n'
            '    message(FATAL_ERROR "legacy app sources lost their client scope")\n  endif()\nendif()\n')
        (source / "CMakeLists.txt").write_text(
            'cmake_minimum_required(VERSION 3.25)\nproject(TestSuiteGraph LANGUAGES CXX)\n'
            'set(PROJECT AmneziaVPN)\n'
            'find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets Network Test Core5Compat RemoteObjects)\n'
            'find_package(OpenSSL REQUIRED)\n'
            'set(ACTUAL_REPO ' + bracket(str(ROOT)) + ')\n'
            'function(add_subdirectory path)\n'
            '  if(path STREQUAL "client/tests" OR path STREQUAL "tests")\n'
            '    _add_subdirectory("${ACTUAL_REPO}/client/tests" "${CMAKE_CURRENT_BINARY_DIR}/registered-tests")\n'
            '  else()\n    _add_subdirectory(${ARGV})\n  endif()\nendfunction()\n'
            + options + '\nadd_subdirectory(client)\n' + focused_route + '\n'
            'if(AMNEZIA_BUILD_TESTS OR AMNEZIAVPN_BUILD_FOCUSED_TESTS)\n'
            '  if(NOT TARGET awg_control_maintenance_tests)\n    message(FATAL_ERROR "focused graph missing")\n  endif()\n'
            '  if(NOT AMNEZIA_BUILD_TESTS AND TARGET test_common)\n'
            '    message(FATAL_ERROR "focused-only graph contains legacy app tests")\n  endif()\nendif()\n')
        command = [args.cmake, "-S", str(source), "-B", str(build), "-G", "Ninja",
                   "-DAMNEZIA_BUILD_TESTS=" + ("ON" if app else "OFF"),
                   "-DAMNEZIAVPN_BUILD_FOCUSED_TESTS=" + ("ON" if focused else "OFF"),
                   "-DQt6_DIR=" + args.qt_dir, "-DCMAKE_PREFIX_PATH=" + args.prefix,
                   "-DPython3_EXECUTABLE=" + sys.executable]
        with (case / "configure.log").open("w") as log:
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
        if result.returncode:
            raise RuntimeError(str(case / "configure.log") + "\n" + (case / "configure.log").read_text()[-6000:])
        # Parse the actual Ninja graph too: configure can succeed even when two
        # unnormalized CMAKE_CONFIGURE_DEPENDS paths generate the same output.
        with (case / "target-help.log").open("w") as log:
            result = subprocess.run([args.cmake, "--build", str(build), "--target", "help"],
                                    stdout=log, stderr=subprocess.STDOUT)
        if result.returncode:
            raise RuntimeError(str(case / "target-help.log") + "\n" + (case / "target-help.log").read_text()[-6000:])
        if app or focused:
            # Isolated daemon/logger fixtures must retain the service-side
            # logger even when registered below the full desktop application.
            cache = (build / "CMakeCache.txt").read_text()
            ninja = next(line.split("=", 1)[1] for line in cache.splitlines()
                         if line.startswith("CMAKE_MAKE_PROGRAM:FILEPATH="))
            daemon_commands = subprocess.check_output(
                [ninja, "-C", str(build), "-t", "commands", "daemon_exclusion_tests"], text=True)
            assert "-DAMNEZIA_DESKTOP" not in daemon_commands, "daemon fixture inherited client IPC"
            if app:
                legacy_commands = subprocess.check_output(
                    [ninja, "-C", str(build), "-t", "commands", "test_common"], text=True)
                assert "-DAMNEZIA_DESKTOP" in legacy_commands, "legacy app lost desktop compile context"
        # Enumerate real CTest registration without executing unrelated suites.
        ctest = str(Path(args.cmake).with_name("ctest"))
        result = subprocess.run([ctest, "--test-dir", str(build), "--show-only=json-v1"],
                                capture_output=True, text=True, check=True)
        (case / "tests.json").write_text(result.stdout)
        names = [test["name"] for test in json.loads(result.stdout)["tests"]]
        assert names.count("awg_control_maintenance") == int(app or focused), names
        assert names.count("MultipleImportsTest") == int(app), names
        assert len(names) == len(set(names)), "duplicate tests: " + str(case)
        if app and focused:
            # Exercise learned MOC include dependencies as well as the initial
            # graph: a generated include must not depend on its own autogen.
            target = "vpn_route_recovery_tests"
            for attempt in range(3):
                if attempt == 1:
                    timestamps = list(build.glob("**/vpn_route_recovery_tests_autogen/timestamp"))
                    assert len(timestamps) == 1, timestamps
                    timestamps[0].unlink()
                with (case / f"route-incremental-{attempt}.log").open("w") as log:
                    result = subprocess.run(
                        [args.cmake, "--build", str(build), "--target", target, "--parallel", "1"],
                        stdout=log, stderr=subprocess.STDOUT)
                if result.returncode:
                    raise RuntimeError(str(case / f"route-incremental-{attempt}.log"))
        print(case.name, "configured", len(names), "unique tests", flush=True)


if __name__ == "__main__":
    main()
