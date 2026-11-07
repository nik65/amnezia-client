"""Exercise the canonical GNU tar commands without building or installing."""
from pathlib import Path
import os
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
PRODUCER = ROOT / "deploy/headless/build_headless_release.sh"
TAR = shutil.which("tar")


def archive_command(kind, bindings):
    start = 'GZIP=-n tar --create --gzip --file "$' + ("ARCHIVE_TMP" if kind == "update" else "PACKAGE_ARCHIVE_TMP") + '"'
    lines = PRODUCER.read_text().splitlines()
    index = next(i for i, line in enumerate(lines) if line.startswith(start))
    command = lines[index]
    while command.endswith("\\"):
        index += 1
        command = command[:-1] + lines[index].strip()
    tokens = shlex.split(command)
    if tokens[:2] != ["GZIP=-n", "tar"]:
        raise AssertionError("unexpected archive producer command")
    resolved = []
    for token in tokens[2:]:
        for name, value in bindings.items():
            token = token.replace("${" + name + "}", str(value)).replace("$" + name, str(value))
        if "$" in token:
            raise AssertionError("unknown archive command binding")
        resolved.append(token)
    return [TAR, *resolved]


@unittest.skipUnless(sys.platform.startswith("linux") and TAR, "GNU tar consumer test")
class HeadlessPackagePermissionsTests(unittest.TestCase):
    def test_canonical_commands_normalize_public_headers_without_changing_files(self):
        self.assertIn("GNU tar", subprocess.check_output([TAR, "--version"], text=True))
        for builder_mode in (0o077, 0o000):
            with self.subTest(builder_umask=oct(builder_mode)), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                update = base / "update"
                package = base / "headless-package"
                update.mkdir(mode=0o700)
                package.mkdir(mode=0o700)
                package.chmod(0o777 if builder_mode == 0 else 0o700)
                for directory in (update, package):
                    for name in ("amneziad", "amnezia-cli"):
                        (directory / name).write_bytes(b"inert executable fixture\n")
                        (directory / name).chmod(0o755)
                metadata = package / "package-manifest.json"
                metadata.write_text('{"fixture":true}\n')
                metadata.chmod(0o666 if builder_mode == 0 else 0o600)
                before = {p: (p.read_bytes(), stat.S_IMODE(p.stat().st_mode))
                          for p in base.rglob("*") if p.is_file()}
                original_package_mode = stat.S_IMODE(package.stat().st_mode)
                bindings = {"ARCHIVE_TMP": base / "update.tar.gz", "UPDATE_DIR": update,
                            "PACKAGE_ARCHIVE_TMP": base / "package.tar.gz", "STAGE_DIR": base,
                            "ARCHIVE_MTIME": 1234567890}
                for kind, output in (("update", bindings["ARCHIVE_TMP"]),
                                     ("package", bindings["PACKAGE_ARCHIVE_TMP"])):
                    result = subprocess.run(archive_command(kind, bindings),
                                            env=dict(os.environ, GZIP="-n"),
                                            capture_output=True, timeout=20, umask=builder_mode)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    with tarfile.open(output) as archive:
                        for member in archive.getmembers():
                            self.assertEqual(member.mode, 0o755 if member.isdir() or member.name.endswith(("amneziad", "amnezia-cli")) else 0o644)
                            if member.isfile():
                                self.assertEqual(archive.extractfile(member).read(), (update if kind == "update" else base).joinpath(member.name).read_bytes())
                for path, value in before.items():
                    self.assertEqual((path.read_bytes(), stat.S_IMODE(path.stat().st_mode)), value)
                self.assertEqual(stat.S_IMODE(package.stat().st_mode), original_package_mode)
                self.assertEqual(stat.S_IMODE(base.stat().st_mode), 0o700)


if __name__ == "__main__":
    unittest.main()
