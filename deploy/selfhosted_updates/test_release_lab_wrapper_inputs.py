"""N-1 outer input must reach real lab admission; no guest/installer runs."""
from pathlib import Path
import re
from unittest.mock import patch

import pytest

from deploy.release_lab import lab


ROOT = Path(__file__).resolve().parents[2]


def section(text, start, end):
    return text.split(start, 1)[1].split(end, 1)[0]


def test_actual_release_admission_requires_separate_baseline_outer_before_any_backend(tmp_path):
    candidate, baseline = tmp_path / "candidate.exe", tmp_path / "baseline-outer.exe"
    candidate.write_bytes(b"inert candidate")
    baseline.write_bytes(b"inert baseline outer")
    controller = lab.LabController(tmp_path / "state", test_mode=True, windows_backend="hyperv")
    artifacts = {name: candidate for name in lab.RELEASE_PLATFORM_IDS}
    old = {name: baseline for name in lab.RELEASE_PLATFORM_IDS}
    inputs = dict(manifest=candidate, manifest_public_key=candidate,
                  baseline_manifest=baseline, headless_baseline_receipt=baseline,
                  headless_candidate_receipt=candidate, baseline_artifacts=old,
                  baseline_version="5.0.3.17", candidate_version="5.0.3.18")
    class NextIndependentGate(Exception):
        pass
    with patch.object(lab, "validate_signed_manifest", side_effect=NextIndependentGate) as signature, \
            patch.object(controller, "start", side_effect=AssertionError("no guest")), \
            patch.object(controller, "hyperv_call", side_effect=AssertionError("no backend")):
        with pytest.raises(lab.LabError, match="explicit N-1 baseline outer artifact"):
            controller.create("release", artifacts, candidate, **inputs)
        signature.assert_not_called()
        with pytest.raises(NextIndependentGate):
            controller.create("release", artifacts, candidate, baseline_outer_artifact=baseline, **inputs)
        signature.assert_called_once()
    assert not (controller.root / "runs").exists()


def test_both_wrappers_expose_and_forward_the_explicit_baseline_outer_path():
    local = (ROOT / "deploy/selfhosted_updates/local_release.ps1").read_text()
    rebuild = (ROOT / "deploy/selfhosted_updates/rebuild_clients.ps1").read_text()
    for source in (local, rebuild):
        parameters = source.split("\n)", 1)[0]
        assert re.search(r"\[string\]\s*\$LabBaselineOuterArtifact\s*=.*AMNEZIA_RELEASE_LAB_BASELINE_OUTER_ARTIFACT", parameters)
    forwarding = section(rebuild, "function New-LocalReleaseCommand(", "function Invoke-LoggedPowerShell(")
    assert '$parts += @("-LabBaselineOuterArtifact", (Quote-PowerShellString $LabBaselineOuterArtifact))' in forwarding
    suite = section(local, '$suiteArgs = @("--run-id", $LabRunId)', 'Invoke-ReleaseLab "run-suite" $suiteArgs')
    assert '$suiteArgs += @("--baseline-outer-artifact", (Convert-ToWslPath $LabBaselineOuterArtifact))' in suite
    assert 'Convert-ToWslPath $ThinWindowsArtifactPath' not in suite


def test_baseline_outer_preflight_keeps_build_only_independent_and_requires_real_file():
    local = (ROOT / "deploy/selfhosted_updates/local_release.ps1").read_text()
    preflight = section(local, "function Assert-ReleaseLabPrerequisites {", "if ([string]::IsNullOrWhiteSpace($Version))")
    assert preflight.index('if ($LabLane -eq "off") { return }') < preflight.index("$LabBaselineOuterArtifact")
    assert 'if ($LabLane -eq "release" -or $LabWindowsBackend -eq "hyperv")' in preflight
    assert 'Assert-ExistingFile $LabBaselineOuterArtifact "Release-lab N-1 outer self-hosted artifact"' in preflight
