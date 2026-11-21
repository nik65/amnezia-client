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
            r'^set\(_amnezia_ifw_component_script .+?\n'
            r'.*?^cpack_ifw_configure_component\(AmneziaVPN\n.*?^\)',
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
            component_script = "function Component() {}\n"
            (source / "deploy/installer/qif/componentscript.js").write_text(component_script)
            binarycreator = Path(IFW_BINARYCREATOR).resolve().as_posix()
            (source / "CMakeLists.txt").write_text(
                'cmake_minimum_required(VERSION 3.25)\nproject(LicenseFixture LANGUAGES NONE)\n'
                'set(AMNEZIAVPN_VERSION 1.0.0)\nset(RELEASE_DATE 2026-11-07)\n'
                'set(CPACK_PACKAGE_NAME AmneziaVPN)\nset(CPACK_PACKAGE_VERSION 1.0.0)\n'
                'set(CPACK_COMPONENTS_ALL AmneziaVPN)\nset(CPACK_GENERATOR IFW)\n'
                'set(CPACK_IFW_PACKAGE_NAME AmneziaVPN)\n'
                'set(CPACK_IFW_PACKAGE_TITLE "AmneziaVPN license fixture")\n'
                f'set(CPACK_IFW_BINARYCREATOR_EXECUTABLE "{binarycreator}")\n'
                + copy.group(0) + '\n' + component.group(0)
                + '\ninstall(FILES "${CMAKE_SOURCE_DIR}/payload.txt" DESTINATION . COMPONENT AmneziaVPN)\n'
                'include(CPack)\n')
            cases = ["thin", "legacy-bundle", "publish-on-install"] if os.name == "nt" else ["thin"]
            for case in cases:
                with self.subTest(case=case):
                    env = os.environ.copy()
                    env.pop("SELFHOSTED_UPDATE_BUNDLE_DIR", None)
                    env.pop("AMNEZIA_LAUNCH_PUBLISHER_FROM_CLI", None)
                    if case != "thin":
                        env["SELFHOSTED_UPDATE_BUNDLE_DIR"] = str(source)
                    if case == "publish-on-install":
                        env["AMNEZIA_LAUNCH_PUBLISHER_FROM_CLI"] = "1"
                    build = base / case / "build"
                    package = base / case / "package"
                    for command in ([CMAKE, "-S", str(source), "-B", str(build)],
                                    [CPACK, "--config", str(build / "CPackConfig.cmake"),
                                     "-G", "IFW", "-B", str(package)]):
                        result = subprocess.run(command, capture_output=True, timeout=90, env=env)
                        self.assertEqual(result.returncode, 0,
                                         (result.stdout + result.stderr).decode(errors="replace"))
                    metadata = list((package / "_CPack_Packages").glob(
                        "*/IFW/*/packages/AmneziaVPN/meta/package.xml"))
                    self.assertEqual(len(metadata), 1)
                    root = ET.parse(metadata[0])
                    licenses = root.findall("./Licenses/License")
                    self.assertEqual(len(licenses), 1)
                    self.assertEqual(licenses[0].get("name"), "GNU GPL v3")
                    filename = licenses[0].get("file")
                    self.assertEqual(filename, "LICENSE.txt")
                    self.assertEqual((metadata[0].parent / filename).read_bytes(), expected)
                    self.assertEqual(placeholder.read_bytes(), b"../../LICENSE")
                    script_name = "componentscript.js"
                    script_contents = component_script
                    if case == "publish-on-install":
                        script_name = "selfhosted-componentscript.js"
                        script_contents = "var bundledWindowsPublisherInstaller = true;\n" + component_script
                    self.assertEqual(root.findtext("./Script"), script_name)
                    self.assertEqual((metadata[0].parent / script_name).read_text(), script_contents)
                    if case == "publish-on-install":
                        devtool = Path(binarycreator).with_name("devtool.exe")
                        self.assertTrue(devtool.is_file(), "Qt IFW devtool is required for EXE readback")
                        installers = list(package.glob("*.exe"))
                        self.assertEqual(len(installers), 1)
                        unpacked = package / "unpacked"
                        result = subprocess.run(
                            [str(devtool), "dump", str(installers[0]), str(unpacked)],
                            capture_output=True, timeout=30,
                        )
                        self.assertEqual(result.returncode, 0,
                                         (result.stdout + result.stderr).decode(errors="replace"))
                        embedded = unpacked / "metadata/AmneziaVPN" / script_name
                        self.assertEqual(embedded.read_text(), script_contents)


if __name__ == "__main__":
    unittest.main()
