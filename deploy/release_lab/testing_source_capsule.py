"""Physical temporary inputs for controller unit tests, never release evidence.

The controller records all dependency files when admitting a run. These tests
exercise that byte/path closure without needing downloaded VM dependencies.
Real source helpers are copied; dependency archives are explicitly inert bytes.
No archive is installed, executed or claimed to have passed a static ABI probe.
"""
from contextlib import contextmanager
from pathlib import Path
import shutil
import tempfile
from unittest.mock import patch

try:
    from . import lab
except ImportError:
    import lab


@contextmanager
def isolated_controller_sources():
    actual = Path(__file__).resolve().parents[2]
    with tempfile.TemporaryDirectory(prefix="amnezia-controller-source-fixture-") as directory:
        root = Path(directory)
        shutil.copytree(actual / "deploy/release_lab", root / "deploy/release_lab",
                        ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"))
        relatives = set(lab.SEMANTIC_HELPER_RELATIVES)
        for name in ("ANDROID_VULKAN_RELATIVES", "ANDROID_HOST_DEPENDENCY_RELATIVES",
                     "ANDROID_WAYLAND_RELATIVES"):
            relatives.update(getattr(lab, name).values())
        for relative in relatives:
            if not relative.startswith("dist/"):
                continue
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(("INERT UNIT-TEST DEPENDENCY: " + relative + "\n").encode())
        with patch.object(lab, "repo_root", return_value=root):
            yield root
