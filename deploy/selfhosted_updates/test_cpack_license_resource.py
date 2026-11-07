"""Check the actual CPack license configuration with a Windows-style checkout."""
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
CMAKE = shutil.which("cmake")


@unittest.skipUnless(CMAKE, "CMake consumer test")
class CPackLicenseResourceTests(unittest.TestCase):
    def test_regular_build_copy_uses_full_license_instead_of_checkout_link_text(self):
        cpack = (ROOT / "cmake/CPack.cmake").read_text()
        match = re.search(
            r'^configure_file\("\$\{CMAKE_SOURCE_DIR\}/LICENSE"[^\n]+COPYONLY\)\n'
            r'set\(CPACK_RESOURCE_FILE_LICENSE[^\n]+\)', cpack, re.MULTILINE)
        self.assertIsNotNone(match, "missing canonical license copy configuration")
        expected = (ROOT / "LICENSE").read_bytes()
        with tempfile.TemporaryDirectory(prefix="amnezia-cpack-license-") as temporary:
            base = Path(temporary)
            source = base / "source"
            (source / "deploy/data").mkdir(parents=True)
            # Git without symlink support materializes this literal 13-byte file.
            placeholder = source / "deploy/data/LICENSE.txt"
            placeholder.write_bytes(b"../../LICENSE")
            (source / "LICENSE").write_bytes(expected)
            (source / "CMakeLists.txt").write_text(
                'cmake_minimum_required(VERSION 3.25)\nproject(LicenseFixture LANGUAGES NONE)\n'
                + match.group(0)
                + '\nfile(WRITE "${CMAKE_BINARY_DIR}/license-path.txt" "${CPACK_RESOURCE_FILE_LICENSE}")\n')
            result = subprocess.run([CMAKE, "-S", str(source), "-B", str(base / "build")],
                                    capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
            copied = Path((base / "build/license-path.txt").read_text())
            self.assertEqual(copied.name, "LICENSE.txt")
            self.assertTrue(copied.is_file())
            self.assertFalse(copied.is_symlink())
            self.assertEqual(copied.read_bytes(), expected)
            self.assertEqual(placeholder.read_bytes(), b"../../LICENSE")


if __name__ == "__main__":
    unittest.main()
