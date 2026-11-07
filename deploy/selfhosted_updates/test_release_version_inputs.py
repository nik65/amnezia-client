"""Run the actual release version readers without invoking full release scripts."""
from pathlib import Path
import json
import os
import re
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell consumer test")
@pytest.mark.parametrize("wrapper", ["local_release.ps1", "rebuild_clients.ps1"])
def test_default_release_version_reads_shared_cmake_without_running_wrapper(tmp_path, wrapper):
    fixture = tmp_path / "fixture"
    (fixture / "cmake").mkdir(parents=True)
    shared = (ROOT / "cmake/version.cmake").read_text(encoding="utf-8")
    expected = re.search(r"set\(AMNEZIAVPN_VERSION\s+([0-9.]+)", shared).group(1)
    (fixture / "cmake/version.cmake").write_text(shared, encoding="utf-8")
    (fixture / "CMakeLists.txt").write_text(
        'include("${CMAKE_CURRENT_LIST_DIR}/cmake/version.cmake")\n', encoding="utf-8")
    harness = tmp_path / "version-reader.ps1"
    harness.write_text(r'''
param([string]$Source,[string]$Fixture,[string]$Expected)
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Wrapper syntax rejected'}
$nodes=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-ProjectVersion'},$true))
if($nodes.Count -ne 1){throw 'Expected one version reader'}
$definition=$nodes[0].Extent.Text
$RepoRoot=$Fixture
. ([scriptblock]::Create($definition))
if((Get-ProjectVersion) -ne $Expected){throw 'Shared version not read'}
$old=$definition.Replace('"cmake\version.cmake"','"CMakeLists.txt"')
if($old -eq $definition){throw 'Negative control did not change the reader'}
. ([scriptblock]::Create($old))
$rejected=$false
try{$null=Get-ProjectVersion}catch{$rejected=$true}
if(-not $rejected){throw 'Legacy location negative control unexpectedly succeeded'}
[ordered]@{passed=$true;version=$Expected;legacyLocationRejected=$true;fullWrapperRuns=0}|ConvertTo-Json -Compress
''', encoding="utf-8")
    powershell = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    result = subprocess.run([
        str(powershell), "-NoLogo", "-NoProfile", "-NonInteractive",
        "-ExecutionPolicy", "Bypass", "-File", str(harness),
        "-Source", str(ROOT / "deploy/selfhosted_updates" / wrapper),
        "-Fixture", str(fixture), "-Expected", expected,
    ], capture_output=True, timeout=30)
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    receipt = json.loads(result.stdout)
    assert receipt == {"passed": True, "version": expected,
                       "legacyLocationRejected": True, "fullWrapperRuns": 0}
