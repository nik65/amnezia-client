"""Check the actual CPack license configuration with a Windows-style checkout."""
from pathlib import Path
import os
import re
import shutil
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[2]
CMAKE = shutil.which("cmake")
CPACK = shutil.which("cpack")
IFW_BINARYCREATOR = (os.environ.get("AMNEZIA_TEST_IFW_BINARYCREATOR")
                     or shutil.which("binarycreator"))


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

    @unittest.skipUnless(CPACK and IFW_BINARYCREATOR, "actual CPack IFW consumer tools")
    def test_ifw_package_metadata_contains_referenced_full_license(self):
        cpack = (ROOT / "cmake/CPack.cmake").read_text()
        copy = re.search(
            r'^configure_file\("\$\{CMAKE_SOURCE_DIR\}/LICENSE"[^\n]+COPYONLY\)\n'
            r'set\(CPACK_RESOURCE_FILE_LICENSE[^\n]+\)', cpack, re.MULTILINE)
        component = re.search(
            r'^cpack_ifw_configure_component\(AmneziaVPN\n.*?^\)',
            cpack, re.MULTILINE | re.DOTALL)
        self.assertIsNotNone(copy)
        self.assertIsNotNone(component)
        expected = (ROOT / "LICENSE").read_bytes()
        with tempfile.TemporaryDirectory(prefix="amnezia-cpack-ifw-license-") as temporary:
            base = Path(temporary)
            source = base / "source"
            (source / "deploy/data").mkdir(parents=True)
            (source / "deploy/installer/qif").mkdir(parents=True)
            placeholder = source / "deploy/data/LICENSE.txt"
            placeholder.write_bytes(b"../../LICENSE")
            (source / "LICENSE").write_bytes(expected)
            (source / "payload.txt").write_text("license consumer fixture\n")
            (source / "deploy/installer/qif/componentscript.js").write_text(
                "function Component() {}\n")
            binarycreator = Path(IFW_BINARYCREATOR).resolve().as_posix()
            (source / "CMakeLists.txt").write_text(
                'cmake_minimum_required(VERSION 3.25)\nproject(LicenseFixture LANGUAGES NONE)\n'
                'set(AMNEZIAVPN_VERSION 1.0.0)\nset(RELEASE_DATE 2026-11-07)\n'
                'set(CPACK_PACKAGE_NAME AmneziaVPN)\nset(CPACK_PACKAGE_VERSION 1.0.0)\n'
                'set(CPACK_COMPONENTS_ALL AmneziaVPN)\nset(CPACK_GENERATOR IFW)\n'
                'set(CPACK_IFW_PACKAGE_NAME AmneziaVPN)\n'
                'set(CPACK_IFW_PACKAGE_TITLE "AmneziaVPN license fixture")\n'
                f'set(CPACK_IFW_BINARYCREATOR_EXECUTABLE "{binarycreator}")\n'
                + copy.group(0) + '\ninclude(CPackIFW)\n' + component.group(0)
                + '\ninstall(FILES "${CMAKE_SOURCE_DIR}/payload.txt" DESTINATION . COMPONENT AmneziaVPN)\n'
                'include(CPack)\n')
            build = base / "build"
            for command in ([CMAKE, "-S", str(source), "-B", str(build)],
                            [CPACK, "--config", str(build / "CPackConfig.cmake"),
                             "-G", "IFW", "-B", str(base / "packages")]):
                result = subprocess.run(command, capture_output=True, timeout=90)
                self.assertEqual(result.returncode, 0,
                                 (result.stdout + result.stderr).decode(errors="replace"))
            metadata = list((base / "packages/_CPack_Packages").glob(
                "*/IFW/*/packages/AmneziaVPN/meta/package.xml"))
            self.assertEqual(len(metadata), 1)
            licenses = ET.parse(metadata[0]).findall("./Licenses/License")
            self.assertEqual(len(licenses), 1)
            self.assertEqual(licenses[0].get("name"), "GNU GPL v3")
            filename = licenses[0].get("file")
            self.assertEqual(filename, "LICENSE.txt")
            self.assertEqual((metadata[0].parent / filename).read_bytes(), expected)
            self.assertEqual(placeholder.read_bytes(), b"../../LICENSE")


if __name__ == "__main__":
    unittest.main()
