"""Execute build.bat's real VS-selection block without compiling or installing.

The fake vswhere models a newer SSMS instance and an installed C++ toolchain.
Only that selector block runs; vcvarsall, builds and product installers do not.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


BUILD_SCRIPT = Path(__file__).resolve().parents[2] / "deploy" / "build.bat"
OUTPUT_DIR = None
CPP_REQUIREMENT = "-requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64"


@unittest.skipUnless(os.name == "nt", "Windows cmd.exe consumer test")
class WindowsToolchainSelectionTests(unittest.TestCase):
    def test_cpp_instance_and_explicit_override(self):
        source = BUILD_SCRIPT.read_text(encoding="utf-8-sig")
        first = source.index(":: use vswhere to find path to vcvarsall.bat")
        last = source.index(":: setup MSVC toolchain using vsvarsall.bat", first)
        selector = source[first:last]
        temporary = tempfile.TemporaryDirectory(prefix="amnezia-vs-selector-") if OUTPUT_DIR is None else None
        work = Path(temporary.name) if temporary else OUTPUT_DIR
        if not temporary:
            work.mkdir(parents=True, exist_ok=False)
        results = []

        def run_case(name, block, version=None, override=False):
            folder = work / name
            folder.mkdir()
            cpp = folder / "fake instances" / "Visual Studio Cpp"
            ssms = folder / "fake instances" / "SSMS Newer"
            explicit = folder / "explicit" / "vcvarsall.bat"
            vcvars = cpp / "VC" / "Auxiliary" / "Build" / "vcvarsall.bat"
            vcvars.parent.mkdir(parents=True)
            ssms.mkdir(parents=True)
            explicit.parent.mkdir()
            # These files are existence markers only and must never execute.
            vcvars.write_text("@exit /b 91\n", encoding="ascii")
            explicit.write_text("@exit /b 92\n", encoding="ascii")
            log = folder / "vswhere-args.txt"
            fake = folder / "vswhere.cmd"
            fake.write_text(
                "@echo off\nsetlocal EnableDelayedExpansion\n"
                f'echo %* > "{log}"\n'
                'set "require_flag="\nset "cpp_component="\n'
                ':parse\nif "%~1"=="" goto result\n'
                'if /i "%~1"=="-requires" set "require_flag=yes"\n'
                'if /i "%~1"=="Microsoft.VisualStudio.Component.VC.Tools.x86.x64" set "cpp_component=yes"\n'
                'shift\ngoto parse\n:result\n'
                f'if defined require_flag if defined cpp_component (echo {cpp}&exit /b 0)\n'
                f'echo {ssms}\nexit /b 0\n', encoding="ascii")
            batch = folder / "selector.cmd"
            batch.write_text(
                "@echo off\nsetlocal EnableExtensions EnableDelayedExpansion\n" + block
                + '\necho SELECTED=!VCVARS_PATH!\nexit /b 0\n', encoding="ascii")
            env = dict(os.environ)
            for key in ("VCINSTALLDIR", "VS_INSTALLATION_VERSION", "VCVARS_PATH"):
                env.pop(key, None)
            env["VS_INSTALLER_PATH"] = str(fake)
            if version:
                env["VS_INSTALLATION_VERSION"] = version
            if override:
                env["VCVARS_PATH"] = str(explicit)
            process = subprocess.run(
                [os.environ.get("COMSPEC", "cmd.exe"), "/d", "/c", str(batch)],
                cwd=folder, env=env, capture_output=True, timeout=15)
            (folder / "stdout.bin").write_bytes(process.stdout)
            (folder / "stderr.bin").write_bytes(process.stderr)
            text = process.stdout.decode("utf-8", errors="replace")
            selected = [line[len("SELECTED="):] for line in text.splitlines() if line.startswith("SELECTED=")]
            self.assertEqual(process.returncode, 0, text)
            self.assertEqual(len(selected), 1, text)
            args = log.read_text(encoding="ascii") if log.exists() else ""
            entry = {"case": name, "exitCode": process.returncode, "selected": selected[0],
                     "arguments": args, "selectorSha256": hashlib.sha256(block.encode()).hexdigest()}
            results.append(entry)
            return selected[0], args, vcvars, explicit

        try:
            selected, args, vcvars, _ = run_case("default", selector)
            self.assertEqual(selected, str(vcvars))
            self.assertTrue(Path(selected).is_file())
            self.assertIn(CPP_REQUIREMENT, args)
            self.assertIn("-latest", args)
            selected, args, vcvars, _ = run_case("explicit-version", selector, version="17.14")
            self.assertEqual(selected, str(vcvars))
            self.assertIn("-version [17.14]", args)
            self.assertIn(CPP_REQUIREMENT, args)
            selected, _, _, explicit = run_case("explicit-vcvars", selector, override=True)
            self.assertEqual(selected, str(explicit))
            # Negative control: the original selector chooses SSMS, which has no VC tools.
            self.assertIn(CPP_REQUIREMENT, selector)
            old = selector.replace(CPP_REQUIREMENT, "")
            selected, _, vcvars, _ = run_case("old-selector-negative-control", old)
            self.assertNotEqual(selected, str(vcvars))
            self.assertFalse(Path(selected).exists())
        finally:
            (work / "results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
            if temporary:
                temporary.cleanup()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-script", type=Path, default=BUILD_SCRIPT)
    parser.add_argument("--output-dir", type=Path)
    options, remaining = parser.parse_known_args()
    BUILD_SCRIPT = options.build_script.resolve()
    OUTPUT_DIR = options.output_dir.resolve() if options.output_dir else None
    unittest.main(argv=[sys.argv[0], *remaining])
