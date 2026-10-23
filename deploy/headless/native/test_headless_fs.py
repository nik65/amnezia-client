"""Standalone helper tests. Only owned temporary files; no host provisioning."""
import os
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest

HELPER = str(Path(sys.argv.pop(1)).resolve())


class NativeFsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.file = self.root / "regular"
        self.file.write_bytes(b"durable")

    def tearDown(self):
        self.tmp.cleanup()

    def run_check(self, command, path, success):
        result = subprocess.run([HELPER, command, str(path)], capture_output=True, timeout=5)
        self.assertEqual(result.returncode == 0, success, result.stderr)

    def test_fsync_types_missing_symlink_fifo(self):
        self.run_check("fsync-directory", self.root, True)
        self.run_check("fsync-file", self.file, True)
        self.run_check("fsync-file", self.root, False)
        self.run_check("fsync-directory", self.file, False)
        self.run_check("fsync-file", self.root / "missing", False)
        link = self.root / "link"
        link.symlink_to(self.file)
        self.run_check("fsync-file", link, False)
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        self.run_check("fsync-file", fifo, False)
        directory_link = self.root / "directory-link"
        directory_link.symlink_to(self.root, target_is_directory=True)
        self.run_check("fsync-directory", directory_link, False)
        # This regular procfs file opens successfully but rejects fsync.
        self.run_check("fsync-file", "/proc/version", False)

    def test_elf_both_endians_and_rejections(self):
        for endian in (1, 2):
            data = bytearray(20)
            data[:6] = b"\x7fELF\x02" + bytes([endian])
            data[18:20] = (62).to_bytes(2, "little" if endian == 1 else "big")
            self.file.write_bytes(data)
            self.run_check("verify-elf64-x86-64", self.file, True)
            data[18:20] = b"\x00\x00"
            self.file.write_bytes(data)
            self.run_check("verify-elf64-x86-64", self.file, False)
        for data in (b"", b"\x7fELF", bytes(20)):
            self.file.write_bytes(data)
            self.run_check("verify-elf64-x86-64", self.file, False)
        link = self.root / "elf-link"
        link.symlink_to(self.file)
        self.run_check("verify-elf64-x86-64", link, False)

    @unittest.skipUnless(os.geteuid() == 0, "positive root ownership requires root test runner")
    def test_private_tree_types_modes_nested_exception(self):
        self.run_check("verify-root-private-tree", self.root, True)
        self.file.chmod(0o666)
        self.run_check("verify-root-private-tree", self.root, False)
        self.file.chmod(0o600)
        nested = self.root / "nested"
        nested.mkdir(mode=0o700)
        link = nested / "link"
        link.symlink_to(self.file)
        self.run_check("verify-root-private-tree", self.root, False)
        link.unlink()
        sock = socket.socket(socket.AF_UNIX)
        try:
            sock.bind(str(nested / "amneziad.sock"))
            self.run_check("verify-root-private-tree", self.root, False)
        finally:
            sock.close()

    def test_cli_fail_closed(self):
        self.run_check("unknown", self.file, False)
        self.run_check("journal-write", self.file, False)
        self.run_check("journal-unknown", self.file, False)
        for args in ([], ["fsync-file"], ["fsync-file", str(self.file), "extra"]):
            self.assertNotEqual(subprocess.run([HELPER, *args], capture_output=True).returncode, 0)

    def test_installer_authentication_precedes_native_activation(self):
        source = (Path(__file__).parents[1] / "install_headless.sh").read_text()
        activation = source.index('NATIVE_HELPER="$PACKAGE_ROOT/amnezia-headless-fs"')
        self.assertGreater(activation, source.index('native helper does not match authenticated checksums'))
        self.assertGreater(activation, source.index('supplied trust anchor fingerprint does not match'))
        tree_call = source.index('verify_root_private_tree "$candidate" || exit 4')
        self.assertGreater(tree_call, activation)
        # Native error returns directly; no fallthrough to the Python reference.
        for command in ("fsync-directory", "fsync-file", "verify-root-private-tree"):
            self.assertIn(f'run_native_helper {command} "$1"\n        return $?', source)
        build = (Path(__file__).parents[1] / "build_headless_release.sh").read_text()
        self.assertIn('--target amneziad amnezia-cli --parallel', build)
        self.assertIn('"nativeHelper":"amnezia-cli"', build)
        self.assertIn('runtime-dependencies.txt > SHA256SUMS', build)

    def test_actual_installer_receipt_block_rejects_unbound_helper(self):
        source = (Path(__file__).parents[1] / "install_headless.sh").read_text()
        marker = 'if ! python3 - "$VERIFIED_RECEIPT" "$PACKAGE_ROOT"'
        block = source.split(marker, 1)[1].split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
        package = self.root / "package"
        package.mkdir()
        names = ["install_headless.sh", "amneziad", "amnezia-cli", "amneziad.service",
                 "package-manifest.json", "runtime-dependencies.json",
                 "runtime-dependencies.txt", "SHA256SUMS", "amnezia-headless-fs"]
        for name in names:
            (package / name).write_bytes(b"fixture")
        manifest = {"version": "5.0.3.13", "artifacts": ["amneziad", "amnezia-cli", "amneziad.service"],
                    "nativeHelper": "amnezia-headless-fs"}
        (package / "package-manifest.json").write_text(json.dumps(manifest))
        digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
        helper_hash = digest(package / "amnezia-headless-fs")
        checksums = package / "SHA256SUMS"
        checksums.write_text(helper_hash + "  amnezia-headless-fs\n")
        public = self.root / "public"
        public.write_bytes(b"fixture public key; crypto verification is outside this block")
        receipt = {"schema": 1, "tool": "amnezia-verify-provisioning-v1", "verified": True,
                   "manifestSha256": "a" * 64, "publicKeySha256": digest(public),
                   "archiveSha256": "b" * 64, "archiveSize": 1, "version": "5.0.3.13",
                   "packageVersion": "5.0.3.13", "packageFiles": names,
                   "packageManifestSha256": digest(package / "package-manifest.json"),
                   "checksumsSha256": digest(checksums)}
        receipt_path = self.root / "receipt.json"

        def check(success, refresh_checksums=False):
            if refresh_checksums:
                receipt["checksumsSha256"] = digest(checksums)
            receipt_path.write_text(json.dumps(receipt))
            result = subprocess.run([sys.executable, "-c", block, str(receipt_path), str(package),
                                     str(public), receipt["publicKeySha256"], receipt["packageManifestSha256"],
                                     receipt["checksumsSha256"], receipt["manifestSha256"]],
                                    capture_output=True)
            self.assertEqual(result.returncode == 0, success, result.stderr)

        check(True)
        (package / "amnezia-headless-fs").write_bytes(b"tampered")
        check(False)
        (package / "amnezia-headless-fs").write_bytes(b"fixture")
        checksums.write_text("")
        check(False, True)
        checksums.write_text((helper_hash + "  amnezia-headless-fs\n") * 2)
        check(False, True)
        checksums.write_text(helper_hash + "  amnezia-headless-fs\n")
        receipt["packageFiles"] = names[:-1]
        check(False, True)


unittest.main()
