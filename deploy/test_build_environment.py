"""Exercise build.sh cache overrides without building or installing the application."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


@unittest.skipUnless(os.name == "posix" and shutil.which("cmake"), "requires POSIX and CMake")
class BuildEnvironmentTest(unittest.TestCase):
    def test_offline_wrapper_is_opt_in_and_preserves_arguments(self):
        with tempfile.TemporaryDirectory(prefix="amnezia gradle forwarding ") as tmp:
            root = Path(tmp)
            java = root / "jdk/bin/java"
            java.parent.mkdir(parents=True)
            java.write_text('#!/bin/sh\nprintf "%s\\n" "$@"\n')
            java.chmod(0o700)
            wrapper = root / "gradlew"
            wrapper.write_text((Path(__file__).resolve().parents[1] / "client/android/gradlew").read_text())
            for offline in ("", "1"):
                env = dict(os.environ, JAVA_HOME=str(root / "jdk"), AMNEZIA_GRADLE_OFFLINE=offline,
                           JAVA_OPTS="", GRADLE_OPTS="")
                run = subprocess.run(["sh", str(wrapper), "assembleRelease", "-Pvalue=with spaces"],
                                     env=env, capture_output=True, text=True, timeout=10)
                self.assertEqual(run.returncode, 0, run.stderr)
                args = run.stdout.splitlines()
                actual = args[args.index("org.gradle.wrapper.GradleWrapperMain") + 1:]
                expected = (["--offline"] if offline else []) + ["assembleRelease", "-Pvalue=with spaces"]
                self.assertEqual(actual, expected)

    def test_explicit_release_identity_replaces_cached_values(self):
        with tempfile.TemporaryDirectory(prefix="amnezia build forwarding ") as tmp:
            root = Path(tmp)
            source = root / "source"
            source.mkdir()
            (source / "CMakeLists.txt").write_text(r'''cmake_minimum_required(VERSION 3.20)
project(ForwardingProbe NONE)
set(AMNEZIAVPN_VERSION "old" CACHE STRING "Version")
set(AMNEZIA_DNSTT_ANDROID_CLIENT "old" CACHE FILEPATH "Native component")
file(WRITE "${CMAKE_BINARY_DIR}/observed.json"
    "{\"version\":\"${AMNEZIAVPN_VERSION}\",\"component\":\"${AMNEZIA_DNSTT_ANDROID_CLIENT}\"}")
''')
            # The repository may use CRLF on Windows; execute the same shell source as LF.
            script = root / "build.sh"
            script.write_text(Path(__file__).with_name("build.sh").read_text())
            env = os.environ.copy()
            for key in ("FORCE", "BUILD_PATH", "SOURCE_PATH", "INSTALLERS", "CMAKE_TOOLCHAIN_FILE",
                        "BUILD_AAB", "BUILD_APK", "AMNEZIA_BUILD_TESTS", "DEPLOY"):
                env.pop(key, None)
            env.update(QT_ROOT_PATH=str(root / "unused Qt"), HOST="linux", CMAKE_GENERATOR="Unix Makefiles")
            for version, name in (("5.0.3.15", "old component"), ("5.0.3.16", "new component")):
                component = str(root / name / "libdnstt.so")
                env.update(AMNEZIAVPN_VERSION=version, AMNEZIA_DNSTT_ANDROID_CLIENT=component)
                run = subprocess.run(["bash", str(script), "--source", str(source), "--build",
                                      str(root / "build"), "--target", "linux", "--jobs", "1"],
                                     env=env, text=True, capture_output=True, timeout=30)
                self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
                self.assertEqual(json.loads((root / "build/observed.json").read_text()),
                                 {"version": version, "component": component})


if __name__ == "__main__":
    unittest.main()
