import json
import unittest
from pathlib import Path
from xml.etree import ElementTree


ROOT = Path(__file__).parent


class GuestAssetContractTests(unittest.TestCase):
    def test_lock_has_official_sources_and_fails_closed_support_media(self):
        lock = json.loads((ROOT / "images" / "lock.json").read_text(encoding="utf-8"))
        ubuntu = lock["images"]["ubuntu24-cloud-amd64"]
        self.assertTrue(ubuntu["url"].startswith("https://cloud-images.ubuntu.com/"))
        self.assertTrue(ubuntu["signature_required"])
        windows = lock["images"]["windows11-25h2-evaluation-amd64"]
        self.assertRegex(windows["sha256"], r"^[0-9a-f]{64}$")
        support = lock["images"]["windows-virtio-win-stable"]
        self.assertFalse(support["verification_blocked"])
        self.assertRegex(support["sha256"], r"^[0-9a-f]{64}$")

    def test_templates_contain_no_runtime_secret_values(self):
        for path in (ROOT / "guest_templates").rglob("*"):
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8")
            self.assertNotRegex(text, r"(?i)(BEGIN (RSA|OPENSSH|EC) PRIVATE KEY|sk-[a-z]+-[A-Za-z0-9]{20,})")
        xml = ElementTree.parse(ROOT / "guest_templates" / "windows11" / "autounattend.xml.template")
        self.assertIn("__LAB_ADMIN_PASSWORD__", "".join(xml.getroot().itertext()))

    def test_provisioners_are_prepare_only(self):
        linux = (ROOT / "provision_linux_guest.sh").read_text(encoding="utf-8")
        windows = (ROOT / "provision_windows_guest.ps1").read_text(encoding="utf-8")
        self.assertIn("qemu-img create", linux)
        self.assertIn("QEMU not started", linux)
        self.assertIn("QEMU not started", windows)
        self.assertNotIn("qemu-system", windows.lower())
        self.assertNotIn("Start-Process", windows)

    def test_shell_assets_parse_and_downloader_has_no_eval(self):
        downloader = (ROOT / "images" / "download_official_images.sh").read_text(encoding="utf-8")
        self.assertNotRegex(downloader, r"\beval\s*\$")
        self.assertIn("FILENAME" , downloader)

    def test_linux_bootstrap_captures_serial_and_gui_uses_private_vnc(self):
        bootstrap = (ROOT / "bootstrap_guest.py").read_text(encoding="utf-8")
        self.assertIn('"-serial", f"file:{args.output / \'serial.log\'}"', bootstrap)
        self.assertIn('"-vnc", f"unix:{args.output / \'vnc.sock\'}"', bootstrap)
        headless = (ROOT / "guest_templates" / "linux-headless" / "user-data").read_text(encoding="utf-8")
        self.assertIn("binutils", headless)
        self.assertIn("readelf", headless)
        gui = (ROOT / "guest_templates" / "linux-gui" / "user-data").read_text(encoding="utf-8")
        self.assertIn('APT::Install-Recommends "false";', gui)
        self.assertIn("AutomaticLogin=lab", gui)


if __name__ == "__main__":
    unittest.main()
