"""Exercise actual CMake installation under a private builder umask."""
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
NORMALIZER = ROOT / "cmake/normalize_linux_runtime_permissions.cmake"
CMAKE = shutil.which("cmake")


@unittest.skipUnless(sys.platform.startswith("linux") and CMAKE, "Linux CMake consumer test")
class LinuxRuntimePermissionsTests(unittest.TestCase):
    def run_cmake(self, *arguments, success=True):
        result = subprocess.run([CMAKE, *map(str, arguments)], capture_output=True,
                                timeout=30, umask=0o077)
        self.assertEqual(result.returncode == 0, success,
                         result.stdout.decode(errors="replace") + result.stderr.decode(errors="replace"))
        return result

    def test_actual_install_normalizes_only_public_runtime_permissions(self):
        with tempfile.TemporaryDirectory(prefix="amnezia-runtime-modes-") as temporary:
            base = Path(temporary)
            source = base / "source"
            source.mkdir(mode=0o700)
            (source / "fixture.txt").write_text("public runtime fixture\n")
            (source / "tool.sh").write_text("#!/bin/sh\nexit 0\n")
            (source / "CMakeLists.txt").write_text('''cmake_minimum_required(VERSION 3.25)
project(RuntimePermissionFixture LANGUAGES NONE)
install(FILES "${CMAKE_CURRENT_LIST_DIR}/fixture.txt" DESTINATION lib)
install(PROGRAMS "${CMAKE_CURRENT_LIST_DIR}/tool.sh" DESTINATION bin)
install(CODE [[file(CHMOD "${CMAKE_INSTALL_PREFIX}/bin/tool.sh" PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE)]])
install(CODE [[file(MAKE_DIRECTORY "${CMAKE_INSTALL_PREFIX}/translations")]])
install(CODE [[file(WRITE "${CMAKE_INSTALL_PREFIX}/translations/qt_fixture.qm" "generated translation")]])
install(CODE [[file(WRITE "${CMAKE_INSTALL_PREFIX}/bin/qt.conf" "[Paths]\\nPrefix=..\\n")]])
''')
            private = base / "private"
            private.mkdir(mode=0o700)
            private_file = private / "private.txt"
            private_file.write_text("private payload")
            private_file.chmod(0o600)
            stage = base / "stage"
            runtime = stage / "packages/AmneziaVPN/data"
            self.run_cmake("-S", source, "-B", base / "build")
            self.run_cmake("--install", base / "build", "--prefix", runtime)
            self.assertEqual(stat.S_IMODE((runtime / "lib").stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((runtime / "translations").stat().st_mode), 0o700)
            (runtime / "private-link").symlink_to(private, target_is_directory=True)
            (runtime / "private-file-link").symlink_to(private_file)
            payload = runtime / "lib/fixture.txt"
            original = payload.read_bytes(), stat.S_IMODE(payload.stat().st_mode)
            generated = (runtime / "translations/qt_fixture.qm", runtime / "bin/qt.conf")
            for path in generated:
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE((runtime / "bin/tool.sh").stat().st_mode), 0o700)
            writable = runtime / "shared.txt"
            writable.write_text("public data with unsafe initial mode")
            writable.chmod(0o666)
            contents = {path: path.read_bytes() for path in (*generated, writable, runtime / "bin/tool.sh")}
            self.run_cmake(f"-DCPACK_TEMPORARY_DIRECTORY={stage}", "-P", NORMALIZER)
            for directory in (runtime, runtime / "lib", runtime / "bin", runtime / "translations"):
                self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o755)
            self.assertEqual((payload.read_bytes(), stat.S_IMODE(payload.stat().st_mode)), original)
            for path in generated:
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)
            self.assertEqual(stat.S_IMODE(writable.stat().st_mode), 0o644)
            self.assertEqual(stat.S_IMODE((runtime / "bin/tool.sh").stat().st_mode), 0o755)
            self.assertEqual({path: path.read_bytes() for path in contents}, contents)
            self.assertEqual(stat.S_IMODE(private.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(private_file.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(source.stat().st_mode), 0o700)
            self.assertTrue((runtime / "private-link").is_symlink())
            self.assertTrue((runtime / "private-file-link").is_symlink())

    def test_missing_or_linked_runtime_root_is_rejected_before_chmod(self):
        with tempfile.TemporaryDirectory(prefix="amnezia-runtime-mode-guard-") as temporary:
            base = Path(temporary)
            stage = base / "stage"
            self.run_cmake(f"-DCPACK_TEMPORARY_DIRECTORY={stage}", "-P", NORMALIZER, success=False)
            private = base / "private"
            private.mkdir(mode=0o700)
            (stage / "packages/AmneziaVPN").mkdir(parents=True)
            (stage / "packages/AmneziaVPN/data").symlink_to(private, target_is_directory=True)
            self.run_cmake(f"-DCPACK_TEMPORARY_DIRECTORY={stage}", "-P", NORMALIZER, success=False)
            self.assertEqual(stat.S_IMODE(private.stat().st_mode), 0o700)


if __name__ == "__main__":
    unittest.main()
