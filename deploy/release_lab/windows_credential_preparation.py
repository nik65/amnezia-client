"""Reviewed, owned-guest pre-probe preparation; canonical matrix checks stay intact.

Only the ordinary Windows expired-password UI is automated. Unknown screens
stop before credential input. Credentials use private stdin and owned 0600 files.
No host VPN, application, installer, network or sealed parent action is exposed.
"""
from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import os
import re
import secrets
import stat
import struct
import subprocess
import time
from pathlib import Path
from typing import Any

from . import lab

pwd = lab.pwd

BASE_CONTROLLER = lab.LabController
HELPER = Path(__file__).parent / "windows_host" / "credential_preparation.ps1"
OCR = Path("/mnt/c/Program Files/Tesseract-OCR/tesseract.exe")
OCR_LANGUAGE = OCR.parent / "tessdata" / "eng.traineddata"
WIDTH, HEIGHT = 1024, 768
MAX_PREPARATION_SECONDS = 240
OCR_CROP = (300, 315, 720, 590)


def capsule() -> dict[str, Any]:
    return {name: lab.artifact_record(path) for name, path in {
        "controller": Path(lab.__file__), "preparation": Path(__file__),
        "helper": HELPER, "ocr": OCR, "ocr_language": OCR_LANGUAGE,
        "adapter": lab.hyperv_adapter_source(), "profile": lab.hyperv_profile_source(),
        "windows_acquisition": Path(__file__).parent / "trusted_windows_acquisition.py",
        "acquisition_export": Path(__file__).parent / "trusted_acquisition_export.py",
    }.items()}


def read_credential(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise lab.LabError("child credential must be a regular private file")
    metadata = path.stat()
    if (metadata.st_uid != os.getuid() or metadata.st_gid != pwd.getpwnam("amnezia-lab").pw_gid
            or stat.S_IMODE(metadata.st_mode) != 0o600):
        raise lab.LabError("child credential ownership/mode mismatch")
    value = path.read_text(encoding="utf-8").rstrip("\r\n")
    if not 12 <= len(value) <= 512 or not value.isascii():
        raise lab.LabError("child credential has unsupported encoding/length")
    return value


def classify(words: list[dict[str, Any]]) -> str:
    text = " ".join(str(word["text"]).lower() for word in words)
    text = re.sub(r"[^a-z0-9 ]", "", text)
    if "labadmin" not in text:
        return "unknown"
    if "your password has expired and must be changed" in text:
        return "expired"
    if "your password has been changed" in text:
        return "changed"
    if "new password" in text and "confirm password" in text:
        return "change"
    if "password" in text and not any(s in text for s in ("incorrect", "reset", "expired", "new password")):
        return "login"
    return "unknown"


def field_geometry(words: list[dict[str, Any]], change: bool) -> dict[str, int]:
    def unique(label: str) -> dict[str, Any]:
        matches = [word for word in words if str(word["text"]).lower() == label]
        if len(matches) != 1:
            raise lab.LabError("credential UI field label is ambiguous")
        return matches[0]
    if change:
        new, confirm = unique("new"), unique("confirm")
        new_y = int(new["top"]) + int(new["height"]) // 2
        confirm_y = int(confirm["top"]) + int(confirm["height"]) // 2
        gap = confirm_y - new_y
        result = {"x": int(new["left"]) + 120, "old_y": new_y - gap,
                  "new_y": new_y, "confirm_y": confirm_y}
        if not 35 <= gap <= 70 or abs(int(new["left"]) - int(confirm["left"])) > 20:
            raise lab.LabError("credential form geometry is not reviewed")
    else:
        label = unique("password")
        result = {"x": int(label["left"]) + 120,
                  "y": int(label["top"]) + int(label["height"]) // 2}
    if not 350 <= result["x"] <= 650 or any(not 350 <= value <= 540 for key, value in result.items() if key != "x"):
        raise lab.LabError("credential form is outside reviewed geometry")
    return result


def rgb565_bmp(raw: bytes, *, focused: bool = False) -> bytes:
    length = WIDTH * HEIGHT * 2
    if len(raw) not in (length, length + 4):
        raise lab.LabError("unexpected VM thumbnail byte count")
    raw = raw[-length:]
    left, top, right, bottom = OCR_CROP if focused else (0, 0, WIDTH, HEIGHT)
    width, height = right - left, bottom - top
    rows = bytearray()
    for y in range(bottom - 1, top - 1, -1):
        for x in range(left, right):
            offset = (y * WIDTH + x) * 2
            pixel = raw[offset] | raw[offset + 1] << 8
            # Hyper-V RGB565: blue in low five bits, red in high five bits.
            blue = (pixel & 31) * 255 // 31
            green = ((pixel >> 5) & 63) * 255 // 63
            red = ((pixel >> 11) & 31) * 255 // 31
            if focused:
                # The standard blue Windows wallpaper defeats whole-screen
                # PSM6. Focused luminance removes wallpaper color noise while
                # preserving anti-aliased small labels on black/blue screens.
                # A binary threshold damages "Confirm password" in practice.
                value = (red * 299 + green * 587 + blue * 114) // 1000
                rows.extend((value, value, value))
            else:
                rows.extend((blue, green, red))
    size = 54 + len(rows)
    header = b"BM" + struct.pack("<IHHI", size, 0, 0, 54)
    header += struct.pack("<IiiHHIIiiII", 40, width, height, 1, 24, 0, len(rows), 0, 0, 0, 0)
    return header + rows


class GuestPreparation:
    def __init__(self, controller: BASE_CONTROLLER, run_id: str, case_id: str, child: dict[str, Any]):
        self.controller, self.run_id, self.case_id = controller, run_id, case_id
        self.vm_id, self.parent_sha = child["vm_id"], child["parent_sha256"]
        self.directory = lab.ensure_owned_child(controller.root,
            controller.root / "exports" / run_id / "windows-x64" / case_id / "credential-preparation",
            "credential preparation evidence")
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.screens: list[dict[str, str]] = []
        self.deadline = time.monotonic() + MAX_PREPARATION_SECONDS

    def remaining(self, maximum: float) -> float:
        value = min(maximum, self.deadline - time.monotonic())
        if value <= 0:
            raise lab.LabError("owned guest credential preparation exceeded its bounded deadline")
        return value

    def call(self, action: str, **private: Any) -> dict[str, Any]:
        self.remaining(45)
        self.controller.assert_mutation_context()
        self.controller.verify_preparation_capsule(self.run_id)
        argv = [lab.HYPERV_POWERSHELL_WSL, "-NoProfile", "-NonInteractive", "-File",
                lab.windows_path_for_wsl(HELPER), "-RunId", self.run_id, "-CaseId", self.case_id,
                "-VmId", self.vm_id, "-ParentSha256", self.parent_sha]
        payload = json.dumps({"action": action, **private}).encode()
        try:
            result = subprocess.run(argv, input=payload, capture_output=True, timeout=self.remaining(45))
        except subprocess.SubprocessError as exc:
            raise lab.LabError("owned guest credential helper timed out/failed") from None
        if result.returncode:
            # PowerShell errors can include source lines: never echo either stream.
            raise lab.LabError("owned guest credential helper failed (details suppressed)")
        try:
            answer = json.loads(result.stdout.decode("utf-8-sig"))
        except (ValueError, UnicodeError):
            raise lab.LabError("owned guest credential helper returned invalid response") from None
        expected = {"vm_id": self.vm_id, "run_id": self.run_id, "case_id": self.case_id,
                    "parent_sha256": self.parent_sha, "action": action, "installer_started": False}
        if any(answer.get(key) != value for key, value in expected.items()):
            raise lab.LabError("owned guest credential response binding differs")
        return answer

    def capture(self, phase: str) -> tuple[str, list[dict[str, Any]]]:
        reply = self.call("capture")
        try:
            raw = base64.b64decode(reply["rgb565"], validate=True)
        except (ValueError, KeyError):
            raise lab.LabError("VM thumbnail encoding is invalid") from None
        image = self.directory / f"{len(self.screens):02d}-{phase}.bmp"
        image.write_bytes(rgb565_bmp(raw))
        # OCR runs only on login/dialog/form snapshots before typing, never on
        # a password entry in progress. Only the classification is retained.
        result = subprocess.run([str(OCR), "stdin", "stdout",
                                 "--tessdata-dir", lab.windows_path_for_wsl(OCR_LANGUAGE.parent),
                                 "-l", "eng", "--psm", "6", "tsv"],
                                input=rgb565_bmp(raw, focused=True), capture_output=True, timeout=self.remaining(20))
        if result.returncode:
            raise lab.LabError("local credential screen OCR failed")
        rows = list(csv.DictReader(io.StringIO(result.stdout.decode("utf-8")), delimiter="\t"))
        words = [{"text": row["text"], **{key: int(row[key]) for key in ("left", "top", "width", "height")}}
                 for row in rows if row.get("text", "").strip()]
        for word in words:
            word["left"] += OCR_CROP[0]
            word["top"] += OCR_CROP[1]
        state = classify(words)
        self.screens.append({"phase": phase, "state": state,
                             "sha256": hashlib.sha256(image.read_bytes()).hexdigest()})
        return state, words

    def expect(self, expected: str, phase: str, timeout: int = 25) -> list[dict[str, Any]]:
        deadline = min(self.deadline, time.monotonic() + timeout)
        while True:
            state, words = self.capture(phase)
            if state == expected:
                return words
            if time.monotonic() >= deadline:
                raise lab.LabError("credential UI did not show the required state; no further input")
            time.sleep(2)

    def prepare(self, original: str) -> tuple[Path | None, dict[str, Any]]:
        auth = None
        for _ in range(12):
            auth = self.call("authenticate", credential=original)
            if auth.get("authenticated") is True:
                return None, {"credential_prepared": True, "changed": False, "authentication": auth,
                              "vm_id": self.vm_id, "release_passed": False}
            if auth.get("invalid_credential") is True:
                break
            time.sleep(2)
        if not auth or auth.get("invalid_credential") is not True:
            raise lab.LabError("guest authentication failed without recognized credential error")
        if any(not 32 <= ord(character) <= 126 for character in original):
            raise lab.LabError("VM console credential requires printable ASCII without control keys")
        state, words = self.capture("initial")
        if state != "login":
            self.call("attention")
            words = self.expect("login", "login")
        geometry = field_geometry(words, False)
        self.call("login", credential=original, **geometry)
        self.expect("expired", "expired")
        self.call("enter")
        words = self.expect("change", "change-form")
        geometry = field_geometry(words, True)
        directory = lab.ensure_owned_child(self.controller.root,
            self.controller.root / "credentials", "child credentials")
        directory.mkdir(mode=0o700, exist_ok=True)
        name = hashlib.sha256(f"{self.run_id}\t{self.case_id}\t{self.vm_id}".encode()).hexdigest()
        path = directory / f"child-{name}.secret"
        new = "Aa7!" + secrets.token_hex(16)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="ascii") as stream:
                stream.write(new)
                stream.flush()
                os.fsync(stream.fileno())
            read_credential(path)
            self.call("change", old=original, new=new, **geometry)
            self.expect("changed", "changed")
            self.call("enter")
            for _ in range(15):
                auth = self.call("authenticate", credential=new)
                if auth.get("authenticated") is True:
                    receipt = {"credential_prepared": True, "changed": True, "authentication": auth,
                               "vm_id": self.vm_id, "screens": self.screens, "release_passed": False,
                               "method": "normal old-password-authenticated Windows UI"}
                    (self.directory / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
                    return path, receipt
                time.sleep(2)
            raise lab.LabError("new child credential could not be authenticated")
        finally:
            # Preserve the private file on uncertain change outcome for recovery.
            new = ""


class PreparedWindowsController(BASE_CONTROLLER):
    """Exact reviewed controller; delegates real matrix execution to lab.py."""
    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self._active_credential_path: Path | None = None
        self._prepared_credentials: dict[tuple[str, str], Path] = {}
        self._trusted_acquisition_session = None

    def verify_preparation_capsule(self, run_id: str) -> None:
        expected = self.get_run(run_id).get("credential_preparation_capsule")
        if expected != capsule():
            raise lab.LabError("credential preparation source/OCR changed after planning")

    def verify_acquisition_provenance(self, run_id: str) -> None:
        self.verify_preparation_capsule(run_id)

    @lab.mutation_operation
    def create(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        value = super().create(*args, **kwargs)
        if self.dry_run or self.test_mode:
            return value
        run_id = value["run_id"]
        state = self.load_state()
        state["runs"][run_id]["credential_preparation_capsule"] = capsule()
        self.save_state(state)
        return self.get_run(run_id)

    def hyperv_credential(self) -> str:
        return read_credential(self._active_credential_path) if self._active_credential_path else super().hyperv_credential()

    def hyperv_call(self, action: str, *, run_id: str | None = None,
                    credential: bool = False, **kwargs: Any) -> dict[str, Any]:
        case_id = str(kwargs.get("CaseId", "control"))
        previous = self._active_credential_path
        self._active_credential_path = self._prepared_credentials.get((str(run_id), case_id))
        try:
            captured = False
            capture_error = None
            if action == "reset" and run_id and self._trusted_acquisition_session is not None:
                run = self.get_run(run_id)
                profile = run.get("profiles", {}).get("windows-x64", {})
                receipts = profile.get("case_receipts", [])
                passed = any(receipt.get("case_id") == case_id for receipt in receipts)
                if case_id == "outer-interactive":
                    passed = isinstance(profile.get("interactive_receipt"), dict)
                if passed:
                    try:
                        self._trusted_acquisition_session.capture_windows_case(case_id)
                        captured = True
                    except Exception:
                        # Acquisition failure must not prevent canonical owned
                        # guest cleanup. No proof is issued for this case.
                        capture_error = True
            result = super().hyperv_call(action, run_id=run_id, credential=credential, **kwargs)
            if action == "start" and run_id and not self.dry_run and not self.test_mode:
                self.assert_mutation_context()
                self.verify_preparation_capsule(run_id)
                child = result.get("child") or {}
                original = super().hyperv_credential()
                path, receipt = GuestPreparation(self, run_id, case_id, child).prepare(original)
                if path:
                    self._prepared_credentials[(run_id, case_id)] = path
                state = self.load_state()
                state["runs"][run_id].setdefault("credential_preparations", {})[case_id] = receipt
                self.save_state(state)
            if action == "reset" and run_id:
                if captured:
                    self._trusted_acquisition_session.record_windows_cleanup(case_id, result)
                self._prepared_credentials.pop((run_id, case_id), None)
                if capture_error:
                    raise lab.LabError("live Windows capture failed; canonical owned child reset completed")
            return result
        finally:
            self._active_credential_path = previous
