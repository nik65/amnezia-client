import hashlib
import json
import tarfile
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
ORIGINAL = REPO / "dist/selfhosted-updates/5.0.1.37"
ORIGINAL_ARCHIVE = ORIGINAL / "files/artifacts/491fdb8d42eff3a7e4ad5a71d4ad9c940ce9a9e82990fd4968d29ae5274175bd/AmneziaHeadless_5.0.1.37_linux_x64_provisioning.tar.gz"
FIXTURE = REPO / "dist/release-lab-fixtures/headless-5.0.1.37-corrected-installer-20260914"
FIXTURE_ARCHIVE = FIXTURE / "provisioning/AmneziaHeadless_5.0.1.37_linux_x64_provisioning-reconstructed-test-fixture.tar.gz"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def members(path: Path) -> dict[str, bytes]:
    with tarfile.open(path, "r:gz") as archive:
        return {
            member.name: archive.extractfile(member).read()
            for member in archive.getmembers()
            if member.isfile()
        }


def test_reconstructed_fixture_preserves_original_payload_and_uses_fixed_installer():
    original = members(ORIGINAL_ARCHIVE)
    fixture = members(FIXTURE_ARCHIVE)
    payload = (
        "amneziad",
        "amnezia-cli",
        "amneziad.service",
        "package-manifest.json",
        "runtime-dependencies.json",
        "runtime-dependencies.txt",
    )
    for name in payload:
        member = f"headless-package/{name}"
        assert digest(fixture[member]) == digest(original[member])

    current_installer = (REPO / "deploy/headless/install_headless.sh").read_bytes()
    fixture_installer = fixture["headless-package/install_headless.sh"]
    assert fixture_installer == current_installer
    text = fixture_installer.decode("utf-8")
    assert "TRANSACTION_ROOT_PREEXISTING" in text
    assert 'if [[ "$TRANSACTION_ROOT_PREEXISTING" -eq 0 && "$STATE_DIR_COUNT" -gt 0 ]]' in text
    assert "STATE_DIR_COUNT=$((STATE_DIR_COUNT - 1))" in text

    sums = fixture["headless-package/SHA256SUMS"].decode("utf-8")
    for line in sums.splitlines():
        expected, name = line.split(None, 1)
        assert digest(fixture[f"headless-package/{name}"]) == expected


def test_fixture_is_separate_signed_and_officially_verified():
    receipt = json.loads((FIXTURE / "signed/official-verifier-receipt.json").read_text())
    assert receipt["verified"] is True
    assert receipt["version"] == "5.0.1.37"
    assert receipt["publicKeySha256"] == "aeced4b158793068e6f1df13a052ecdcfd49e3aafb4906bea965c04828cc2d59"
    assert receipt["archiveSha256"] == digest(FIXTURE_ARCHIVE.read_bytes())
    assert digest((ORIGINAL / "manifest.json").read_bytes()) == "591eb85171d851eb473ab36f196cd42f3749dac80c63a0d6ade9e020a42a156b"
    assert digest(ORIGINAL_ARCHIVE.read_bytes()) == "491fdb8d42eff3a7e4ad5a71d4ad9c940ce9a9e82990fd4968d29ae5274175bd"
