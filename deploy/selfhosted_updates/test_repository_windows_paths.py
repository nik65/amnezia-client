"""Require repository paths that a normal Windows Git checkout can represent."""
import argparse
from collections import defaultdict
from pathlib import Path
import subprocess
import sys
import unittest


REPO = Path(__file__).resolve().parents[2]
GIT_TREE = None
RESERVED = {"CON", "PRN", "AUX", "NUL"}
RESERVED.update(prefix + number for prefix in ("COM", "LPT") for number in "123456789¹²³")


def windows_path_errors(paths):
    errors = []
    folded = defaultdict(list)
    for path in paths:
        folded[path.casefold()].append(path)
        for part in path.split("/"):
            if (not part or part in (".", "..")
                    or any(ord(char) < 32 or char in '<>:"\\|?*' for char in part)
                    or part.endswith((" ", "."))
                    or part.split(".", 1)[0].rstrip(" .").upper() in RESERVED):
                errors.append(f"invalid Windows component: {path!r}")
                break
    for collision in folded.values():
        if len(collision) > 1:
            errors.append(f"case-insensitive collision: {collision!r}")
    return errors


def repository_paths():
    if GIT_TREE is not None:
        command = ["git", "ls-tree", "-rz", "--name-only", GIT_TREE]
    else:
        command = ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"]
    data = subprocess.check_output(command, cwd=REPO)
    return [name.decode("utf-8") for name in data.split(b"\0") if name]


class RepositoryWindowsPathsTests(unittest.TestCase):
    def test_windows_constraints(self):
        self.assertEqual(windows_path_errors([
            "CMakeLists.txt", "deploy/data/windows/config.xml", "src/COM10.txt",
        ]), [])
        for invalid in [
                "\\/conffiles", "dir/stream:payload", "dir/CON.txt",
                "dir/LPT1", "dir/NUL", "dir/name.", "dir/name ",
                "dir/question?.txt", "dir/name\x01", "dir/../file"]:
            with self.subTest(path=invalid):
                self.assertTrue(windows_path_errors([invalid]))
        self.assertTrue(windows_path_errors(["src/File.cpp", "src/file.cpp"]))

    def test_repository_checkout_paths(self):
        paths = repository_paths()
        self.assertTrue(paths, "empty path list cannot prove checkout portability")
        self.assertEqual(windows_path_errors(paths), [])


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=REPO)
    parser.add_argument("--git-tree", help="Check a committed tree instead of the prospective index/new files")
    options, remaining = parser.parse_known_args()
    REPO = options.repo.resolve()
    GIT_TREE = options.git_tree
    unittest.main(argv=[sys.argv[0], *remaining])
