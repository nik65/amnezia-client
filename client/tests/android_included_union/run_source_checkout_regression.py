"""Exercise fresh AWG source acquisition through the real Conan CLI.

Downloads the pinned upstream checkout and submodules; builds no native code.
An optional --recipe selects a preserved recipe for a failing regression run.
"""

import argparse
import ast
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess


parser = argparse.ArgumentParser()
parser.add_argument("--conan", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
parser.add_argument("--recipe", type=Path, default=Path(__file__).resolve().parents[3] / "recipes/awg-android")
args = parser.parse_args()
out = args.output.resolve()
if out.exists():
    raise SystemExit("Use a new output directory to preserve prior evidence")
out.mkdir(parents=True)
recipe = args.recipe.resolve()
env = os.environ.copy()
env["CONAN_HOME"] = str(out / "conan-home")
for name in ("AWG_ANDROID_SOURCE_DIR", "AWG_ANDROID_SOURCE_CONTRACT", "AWG_ANDROID_SOURCE_CONTRACT_SHA256"):
    env.pop(name, None)
commands = []


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def overlay_hashes(root):
    files = [root / "patch_union.py"] + sorted((root / "union").rglob("*"))
    return {p.relative_to(root).as_posix(): sha(p) for p in files if p.is_file()}


def fixture(name):
    target = out / name
    target.mkdir()
    for file in ("conanfile.py", "patch_union.py"):
        shutil.copy2(recipe / file, target / file)
    shutil.copytree(recipe / "union", target / "union")
    return target


def source(target, label):
    command = [str(args.conan.resolve()), "source", str(target), "--lockfile="]
    with (out / (label + ".log")).open("w", encoding="utf-8") as log:
        result = subprocess.run(command, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=300)
    commands.append({"argv": command, "exitCode": result.returncode})
    return result.returncode


def git(target, *arguments):
    return subprocess.check_output(["git", "-C", str(target), *arguments], text=True).strip()


receipt = {"startedUtc": datetime.now(timezone.utc).isoformat(), "commands": commands,
           "harnessSha256": sha(Path(__file__)), "recipeSha256": sha(recipe / "conanfile.py"),
           "exportedOverlaySha256": overlay_hashes(recipe), "nativeBuildOrDeviceAcceptance": False}
try:
    constants = {}
    for node in ast.parse((recipe / "conanfile.py").read_text()).body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in {"UPSTREAM_COMMIT", "UPSTREAM_SUBMODULES"}:
                    constants[target.id] = ast.literal_eval(node.value)
    fresh = fixture("fresh")
    assert source(fresh, "fresh") == 0, "Fresh real Conan source() must succeed alongside exported overlay"
    assert Path(git(fresh, "rev-parse", "--show-toplevel")).resolve() == fresh.resolve()
    assert git(fresh, "rev-parse", "HEAD") == constants["UPSTREAM_COMMIT"]
    for path, commit in constants["UPSTREAM_SUBMODULES"].items():
        assert Path(git(fresh / path, "rev-parse", "--show-toplevel")).resolve() == (fresh / path).resolve()
        assert git(fresh / path, "rev-parse", "HEAD") == commit, "Relocated submodule metadata/pin changed"
    assert overlay_hashes(fresh) == receipt["exportedOverlaySha256"], "Exported overlay was overwritten"
    installed = fresh / "tunnel/tools/libwg-go"
    for path, digest in receipt["exportedOverlaySha256"].items():
        if path.startswith("union/"):
            assert sha(installed / path.removeprefix("union/")) == digest, "Installed overlay differs"
    assert "func turnOn(" in (installed / "api-android.go").read_text(), "Actual union patch was not applied"
    # Select an actual top-level upstream file so the negative case cannot pass
    # because a guessed collision filename disappeared from a future checkout.
    tree_files = [line.split("\t", 1)[1] for line in git(fresh, "ls-tree", "HEAD").splitlines()
                  if line.startswith("100") and "\t" in line]
    collision_name = next(name for name in tree_files if not (recipe / name).exists())
    collision = fixture("collision")
    sentinel = b"pre-existing source must never be overwritten\n"
    (collision / collision_name).write_bytes(sentinel)
    assert source(collision, "collision") != 0, "Conan source() must reject an existing source collision"
    assert (collision / collision_name).read_bytes() == sentinel, "Collision replaced pre-existing source"
    assert "collides with existing source or overlay" in (out / "collision.log").read_text()
    assert not (collision / ".git").exists(), "Collision must be rejected before moving checkout entries"
    assert overlay_hashes(collision) == receipt["exportedOverlaySha256"]
    assert not list(collision.glob(".awg-upstream-*")), "Temporary checkout must be cleaned on refusal"
    receipt.update(passed=True, upstreamCommit=constants["UPSTREAM_COMMIT"],
                   submodules=constants["UPSTREAM_SUBMODULES"], collisionPath=collision_name)
except Exception as error:
    receipt.update(passed=False, error=str(error))
    raise
finally:
    receipt["finishedUtc"] = datetime.now(timezone.utc).isoformat()
    (out / "result.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")

print("Actual Conan source: fresh pinned checkout + relocated submodules + preserved overlay + collision refusal PASS")
