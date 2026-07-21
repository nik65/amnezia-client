#!/usr/bin/env python3
"""Build and optionally upload a self-hosted Amnezia update channel release."""

from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
import hashlib
import json
import os
import re
import secrets
import shutil
import shlex
import stat
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from urllib.error import ContentTooShortError, HTTPError, URLError
from urllib.parse import parse_qs, unquote, urlparse
from urllib.request import Request, urlopen
from urllib.request import urlretrieve


SCRIPT_DIR = Path(__file__).resolve().parent
MAKE_MANIFEST = SCRIPT_DIR / "make_manifest.py"
INSTALL_HOST = SCRIPT_DIR / "install_server_update_host.sh"

KNOWN_PATTERNS = {
    "windows-x64": "AmneziaVPN_{version}_windows_x64.exe",
    "linux-x64": "AmneziaVPN_{version}_linux_x64.run",
    "macos-x64": "AmneziaVPN_{version}_macos_x64.pkg",
    "android": "AmneziaVPN_{version}_android9+_universal.apk",
    "android-arm64-v8a": "AmneziaVPN_{version}_android9+_arm64-v8a.apk",
    "android-armeabi-v7a": "AmneziaVPN_{version}_android9+_armeabi-v7a.apk",
    "android-x86": "AmneziaVPN_{version}_android9+_x86.apk",
    "android-x86_64": "AmneziaVPN_{version}_android9+_x86_64.apk",
}
KNOWN_PATTERN_ALIASES = {
    "windows-x64": ["AmneziaVPN_{version}_x64.exe"],
    "macos-x64": ["AmneziaVPN_{version}_macos.pkg"],
}
IOS_IPA_PATTERN = "AmneziaVPN_{version}_ios.ipa"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
VERSION_RE = re.compile(r"^(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){3}$")
WINDOWS_SHORT_NAME_RE = re.compile(r"^[^\\/.]{1,6}~[1-9][0-9]*(?:\.[^\\/.]{0,3})?$", re.IGNORECASE)
DEFAULT_COHORT_SALT_ID = "fleet-v1"
DEFAULT_HEALTH_DEADLINE_SECONDS = 10 * 60
MIN_HEALTH_DEADLINE_SECONDS = 60
DEFAULT_POLICY_VALIDITY_HOURS = 7 * 24
MAX_POLICY_GENERATION = (1 << 53) - 1
MAX_VERSION_COMPONENT = (1 << 31) - 1
MAX_ANDROID_VERSION_CODE = 2_100_000_000
MAX_MANIFEST_RESPONSE_BYTES = 1024 * 1024
ED25519_PUBLIC_KEY_DER_PREFIX = bytes.fromhex("302a300506032b6570032100")
ED25519_PUBLIC_KEY_DER_BYTES = len(ED25519_PUBLIC_KEY_DER_PREFIX) + 32
REMOTE_MANIFEST_ABSENT_EXIT_CODE = 3
CHANNEL_MARKER_NAME = ".amnezia-update-channel-v1"
CHANNEL_MARKER_TEXT = "amnezia-selfhosted-update-channel-v1"
CHANNEL_MARKER_SHA256 = hashlib.sha256((CHANNEL_MARKER_TEXT + "\n").encode("utf-8")).hexdigest()
CHANNEL_MARKER_PREFIX_SHA256 = tuple(
    hashlib.sha256((CHANNEL_MARKER_TEXT + "\n").encode("utf-8")[:length]).hexdigest()
    for length in range(len((CHANNEL_MARKER_TEXT + "\n").encode("utf-8")) + 1)
)


def openssl_command() -> str:
    candidates = [
        os.environ.get("OPENSSL"),
        shutil.which("openssl"),
        r"C:\Program Files\Git\usr\bin\openssl.exe",
        r"C:\Program Files\Git\mingw64\bin\openssl.exe",
    ]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return str(candidate)
    return "openssl"


def sh_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def validate_release_version(value: str) -> str:
    if not isinstance(value, str) or not VERSION_RE.fullmatch(value):
        raise SystemExit(
            "--version must be a canonical release version in x.y.z.w numeric format "
            "without leading-zero components"
        )
    if any(int(component) > MAX_VERSION_COMPONENT for component in value.split(".")):
        raise SystemExit(
            f"--version components must be from 0 to {MAX_VERSION_COMPONENT} for client compatibility"
        )
    return value


def is_android_platform(platform: object) -> bool:
    return isinstance(platform, str) and (
        platform == "android" or platform.startswith("android-")
    )


def validate_android_version_code(value: object) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= MAX_ANDROID_VERSION_CODE
    ):
        raise SystemExit(
            f"--android-version-code must be an integer from 1 to {MAX_ANDROID_VERSION_CODE}"
        )
    return value


def release_version_key(value: object, label: str) -> tuple[int, int, int, int]:
    """Return the client-compatible ordering key for a canonical four-part version."""

    if not isinstance(value, str) or not VERSION_RE.fullmatch(value):
        raise SystemExit(
            f"{label} manifest has a non-canonical release version: {value!r}; "
            "expected x.y.z.w with no leading-zero components"
        )
    raw_components = value.split(".")
    components = (
        int(raw_components[0]),
        int(raw_components[1]),
        int(raw_components[2]),
        int(raw_components[3]),
    )
    if any(component > MAX_VERSION_COMPONENT for component in components):
        raise SystemExit(
            f"{label} manifest release version components must be from 0 to "
            f"{MAX_VERSION_COMPONENT}: {value!r}"
        )
    return components


def validate_server_dir(value: str) -> str:
    """Require a dedicated, canonical absolute POSIX publication directory."""

    if not isinstance(value, str) or not value.startswith("/") or value.startswith("//"):
        raise SystemExit("--server-dir must be a canonical absolute POSIX path")
    if "\\" in value or any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise SystemExit("--server-dir contains unsafe non-POSIX path characters")
    components = value.split("/")[1:]
    if len(components) < 2:
        raise SystemExit("--server-dir must name a dedicated directory below a top-level directory")
    if any(component in {"", ".", ".."} for component in components):
        raise SystemExit(
            "--server-dir must be normalized and must not contain empty, dot, or dot-dot components"
        )
    normalized = "/" + "/".join(components)
    if normalized != value or normalized in {"/", "/."}:
        raise SystemExit("--server-dir must be a normalized dedicated absolute POSIX path")
    return normalized


def lexical_absolute_path(path: Path) -> Path:
    """Make a path absolute without resolving symlinks or Windows junctions."""

    absolute = Path(os.path.abspath(os.fspath(path.expanduser())))
    if os.name != "nt":
        return absolute

    missing_parts: list[str] = []
    existing = absolute
    while not existing.exists() and not is_link_or_junction(existing):
        if existing.parent == existing:
            break
        missing_parts.append(existing.name)
        existing = existing.parent
    reject_absent_windows_short_name_components(missing_parts)
    try:
        import ctypes

        required = ctypes.windll.kernel32.GetLongPathNameW(str(existing), None, 0)
        if required == 0:
            raise OSError(ctypes.get_last_error(), "GetLongPathNameW failed")
        buffer = ctypes.create_unicode_buffer(required)
        written = ctypes.windll.kernel32.GetLongPathNameW(str(existing), buffer, required)
        if written == 0 or written >= required:
            raise OSError(ctypes.get_last_error(), "GetLongPathNameW failed")
        normalized = Path(buffer.value)
    except (AttributeError, OSError) as error:
        raise SystemExit(f"Unable to canonicalize Windows publication path: {absolute}") from error
    for part in reversed(missing_parts):
        normalized /= part
    return normalized


def reject_absent_windows_short_name_components(parts: list[str]) -> None:
    """Keep first-create publications from acquiring distinct long/8.3 alias locks."""

    short_shaped = next((part for part in parts if WINDOWS_SHORT_NAME_RE.fullmatch(part)), None)
    if short_shaped is not None:
        raise SystemExit(
            "Refusing an absent Windows publication path component shaped like an 8.3 alias: "
            + short_shaped
        )


def is_link_or_junction(path: Path) -> bool:
    is_junction = getattr(path, "is_junction", None)
    if path.is_symlink() or bool(is_junction and is_junction()):
        return True
    if os.name == "nt":
        try:
            attributes = getattr(os.lstat(path), "st_file_attributes", 0)
        except FileNotFoundError:
            return False
        except OSError as error:
            raise SystemExit(f"Unable to inspect Windows path for a reparse point: {path}") from error
        return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return False


def reject_link_like_components(path: Path, label: str) -> None:
    """Reject link-like output components before staging or destructive renames."""

    current = path
    while True:
        if is_link_or_junction(current):
            raise SystemExit(f"Refusing {label} through symlink or junction component: {current}")
        parent = current.parent
        if parent == current:
            break
        current = parent


def parse_platform_values(values: list[str], label: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for value in values:
        if "=" not in value:
            raise SystemExit(f"{label} must be platform=value, got {value!r}")
        platform, item = value.split("=", 1)
        platform = platform.strip()
        item = item.strip()
        if not platform or not item:
            raise SystemExit(f"{label} must contain non-empty platform and value: {value!r}")
        if platform in result:
            raise SystemExit(f"{label} contains duplicate platform: {platform}")
        result[platform] = item
    return result


def release_policy_arguments(args: argparse.Namespace) -> list[str]:
    """Build the make_manifest policy arguments without weakening schema 1.

    Restrictive policy is deliberately never allowed to opt itself into schema
    2. The release operator must select schema 2 explicitly, after the schema-1
    bootstrap client has reached the intended fleet.
    """

    restrictive_policy_requested = any((
        args.channel != "stable",
        args.rollout_percentage != 100,
        args.cohort_salt_id != DEFAULT_COHORT_SALT_ID,
        bool(args.minimum_eligible_version),
        bool(args.maximum_eligible_version),
        args.health_deadline_seconds != DEFAULT_HEALTH_DEADLINE_SECONDS,
        args.policy_generation is not None,
        bool(args.generated_at),
        bool(args.expires_at),
        args.policy_valid_for_hours != DEFAULT_POLICY_VALIDITY_HOURS,
        bool(args.previous_version),
        bool(args.rollback_artifact),
    ))
    if args.payload_schema == 1 and restrictive_policy_requested:
        raise SystemExit(
            "rollout, eligibility, expiry, health, and rollback policy requires explicit "
            "--payload-schema 2; schema 1 is allowed only for an unrestricted stable 100% release"
        )
    if args.payload_schema == 2 and (
        args.policy_generation is None
        or not 1 <= args.policy_generation <= MAX_POLICY_GENERATION
    ):
        raise SystemExit(
            "--policy-generation must be a positive monotonic JSON-safe integer "
            f"up to {MAX_POLICY_GENERATION} with --payload-schema 2"
        )
    rollback_artifacts = parse_platform_values(args.rollback_artifact, "--rollback-artifact")
    unsupported_android_rollbacks = sorted(
        platform for platform in rollback_artifacts if is_android_platform(platform)
    )
    if unsupported_android_rollbacks:
        raise SystemExit(
            "Android rollback artifacts are unsupported: "
            + ", ".join(unsupported_android_rollbacks)
            + ". Android's package installer rejects ordinary lower-versionCode APKs."
        )
    if bool(args.previous_version) != bool(rollback_artifacts):
        raise SystemExit("--previous-version and at least one --rollback-artifact must be supplied together")

    command = [
        "--payload-schema",
        str(args.payload_schema),
        "--channel",
        args.channel,
        "--rollout-percentage",
        str(args.rollout_percentage),
        "--cohort-salt-id",
        args.cohort_salt_id,
        "--health-deadline-seconds",
        str(args.health_deadline_seconds),
    ]
    if args.policy_generation is not None:
        command += ["--policy-generation", str(args.policy_generation)]
    if args.minimum_eligible_version:
        command += ["--minimum-eligible-version", args.minimum_eligible_version]
    if args.maximum_eligible_version:
        command += ["--maximum-eligible-version", args.maximum_eligible_version]
    if args.generated_at:
        command += ["--generated-at", args.generated_at]
    if args.expires_at:
        command += ["--expires-at", args.expires_at]
    else:
        command += ["--policy-valid-for-hours", str(args.policy_valid_for_hours)]
    if args.previous_version:
        command += ["--previous-version", args.previous_version]
    for platform, path in sorted(rollback_artifacts.items()):
        command += ["--rollback-artifact", f"{platform}={Path(path).expanduser().resolve()}"]
    return command


def artifact_filenames(platform: str, version: str) -> list[str]:
    patterns = [KNOWN_PATTERNS[platform], *KNOWN_PATTERN_ALIASES.get(platform, [])]
    return [pattern.format(version=version) for pattern in patterns]


def discover_artifacts(artifact_dir: Path, version: str) -> dict[str, Path]:
    artifacts: dict[str, Path] = {}
    for platform in KNOWN_PATTERNS:
        for filename in artifact_filenames(platform, version):
            direct_candidate = artifact_dir / filename
            if direct_candidate.is_file():
                artifacts[platform] = direct_candidate.resolve()
                break
            matches = sorted(path for path in artifact_dir.rglob(filename) if path.is_file())
            if matches:
                artifacts[platform] = matches[0].resolve()
                break
    return artifacts


def discover_ios_ipa(artifact_dir: Path, version: str) -> Path | None:
    filename = IOS_IPA_PATTERN.format(version=version)
    direct_candidate = artifact_dir / filename
    if direct_candidate.is_file():
        return direct_candidate.resolve()
    matches = sorted(path for path in artifact_dir.rglob(filename) if path.is_file())
    return matches[0].resolve() if matches else None


def download_known_release_assets(repo: str, version: str, artifact_dir: Path, required_platforms: set[str]) -> None:
    artifact_dir.mkdir(parents=True, exist_ok=True)
    download_filenames = {platform: artifact_filenames(platform, version) for platform in KNOWN_PATTERNS}
    download_filenames["ios"] = [IOS_IPA_PATTERN.format(version=version)]
    for platform, filenames in download_filenames.items():
        existing = next((artifact_dir / filename for filename in filenames if (artifact_dir / filename).exists()), None)
        if existing and existing.stat().st_size > 0 and platform not in required_platforms:
            continue
        if existing:
            existing.unlink(missing_ok=True)
        last_error: Exception | None = None
        for filename in filenames:
            target = artifact_dir / filename
            tmp_target = target.with_name(target.name + ".tmp")
            url = f"https://github.com/{repo}/releases/download/{version}/{filename}"
            print(f"Downloading {url}", flush=True)
            try:
                tmp_target.unlink(missing_ok=True)
                urlretrieve(url, tmp_target)
                if tmp_target.stat().st_size <= 0:
                    raise RuntimeError(f"downloaded empty asset: {url}")
                tmp_target.replace(target)
                last_error = None
                break
            except (ContentTooShortError, HTTPError, URLError, RuntimeError) as error:
                last_error = error
                tmp_target.unlink(missing_ok=True)
                target.unlink(missing_ok=True)
        if last_error:
            if platform in required_platforms:
                raise last_error
            print(f"Skipping missing optional release asset: {' or '.join(filenames)}", flush=True)


def required_release_asset_platforms(
    required_platforms: list[str],
    external_platforms: set[str],
    explicit_artifact_platforms: set[str],
) -> set[str]:
    return set(required_platforms) - external_platforms - explicit_artifact_platforms


def missing_platform_messages(missing_platforms: list[str], artifact_dir: Path, version: str) -> list[str]:
    messages: list[str] = []
    linux_archive = f"AmneziaVPN_{version}_linux_x64.tar"
    has_linux_archive = (artifact_dir / linux_archive).is_file() or any(
        path.is_file() for path in artifact_dir.rglob(linux_archive)
    )
    for platform in missing_platforms:
        if platform == "linux-x64" and has_linux_archive:
            messages.append(
                f"{platform} (found {linux_archive}, but Linux auto-install requires the fork CI .run artifact)"
            )
        else:
            messages.append(platform)
    return messages


def run(
    command: list[str],
    *,
    stdin_path: Path | None = None,
    stdin_data: bytes | None = None,
) -> None:
    if stdin_path is not None and stdin_data is not None:
        raise ValueError("stdin_path and stdin_data are mutually exclusive")
    if stdin_path:
        with stdin_path.open("rb") as stdin:
            subprocess.run(command, stdin=stdin, check=True)
    elif stdin_data is not None:
        subprocess.run(command, input=stdin_data, check=True)
    else:
        subprocess.run(command, check=True)


def run_remote_script(ssh: list[str], server: str, script: str) -> None:
    """Stream generated shell to avoid the Windows CreateProcess command-line ceiling."""

    run(ssh + [server, "sh -s"], stdin_data=(script + "\n").encode("utf-8"))


def run_capture(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=True, text=True, capture_output=True)


def b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def command_parts(command: str) -> list[str]:
    parts = shlex.split(command)
    if not parts:
        raise SystemExit("empty command")
    return parts


def fetch_github_release_metadata(repo: str, version: str, token: str | None) -> tuple[str, str]:
    request = Request(
        f"https://api.github.com/repos/{repo}/releases/tags/{version}",
        headers={"Accept": "application/vnd.github+json"},
    )
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    with urlopen(request) as response:
        payload = json.loads(response.read().decode("utf-8"))
    return payload.get("published_at", ""), payload.get("body", "") or ""


def is_sha256_hex(value: object) -> bool:
    return isinstance(value, str) and bool(SHA256_RE.fullmatch(value.lower()))


def is_allowed_external_update_url(platform: str, url: str) -> bool:
    parsed = urlparse(url)
    if not parsed.scheme:
        return False
    if platform == "ios":
        if parsed.scheme == "https":
            return bool(parsed.netloc)
        if parsed.scheme == "itms-apps":
            return bool(parsed.netloc)
        if parsed.scheme == "itms-services":
            manifest_urls = parse_qs(parsed.query).get("url", [])
            if not manifest_urls:
                return False
            manifest_url = urlparse(manifest_urls[0])
            return manifest_url.scheme == "https" and bool(manifest_url.netloc)
        return False
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def require_ed25519_private_key(private_key: Path) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        public_key_path = Path(tmp) / "public.der"
        try:
            run_capture([
                openssl_command(),
                "pkey",
                "-in",
                str(private_key),
                "-pubout",
                "-outform",
                "DER",
                "-out",
                str(public_key_path),
            ])
        except subprocess.CalledProcessError as exc:
            raise SystemExit("SELFHOSTED_UPDATE_PRIVATE_KEY must be a valid Ed25519 PEM private key") from exc
        public_key = public_key_path.read_bytes()
        if (
            len(public_key) != ED25519_PUBLIC_KEY_DER_BYTES
            or not public_key.startswith(ED25519_PUBLIC_KEY_DER_PREFIX)
        ):
            raise SystemExit("SELFHOSTED_UPDATE_PRIVATE_KEY must contain an Ed25519 private key")


def verify_public_key_matches_private(public_key_base64: str, private_key: Path) -> None:
    if any(ch.isspace() for ch in public_key_base64):
        raise SystemExit("SELFHOSTED_UPDATE_PUBLIC_KEY_PEM_BASE64 must not contain whitespace or line breaks")
    try:
        public_key_pem = base64.b64decode(public_key_base64, validate=True)
    except Exception as exc:
        raise SystemExit("SELFHOSTED_UPDATE_PUBLIC_KEY_PEM_BASE64 must be a single-line base64-encoded PEM public key") from exc
    if b"BEGIN PUBLIC KEY" not in public_key_pem:
        raise SystemExit("SELFHOSTED_UPDATE_PUBLIC_KEY_PEM_BASE64 must decode to a PEM public key")

    with tempfile.TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)
        public_key_path = tmp_dir / "public.pem"
        normalized_public_key_path = tmp_dir / "normalized-public.der"
        derived_public_key_path = tmp_dir / "derived-public.der"
        public_key_path.write_bytes(public_key_pem)
        try:
            run_capture([
                openssl_command(),
                "pkey",
                "-pubin",
                "-in",
                str(public_key_path),
                "-pubout",
                "-outform",
                "DER",
                "-out",
                str(normalized_public_key_path),
            ])
        except subprocess.CalledProcessError as exc:
            raise SystemExit("SELFHOSTED_UPDATE_PUBLIC_KEY_PEM_BASE64 must decode to a valid PEM public key") from exc
        try:
            run_capture([
                openssl_command(),
                "pkey",
                "-in",
                str(private_key),
                "-pubout",
                "-outform",
                "DER",
                "-out",
                str(derived_public_key_path),
            ])
        except subprocess.CalledProcessError as exc:
            raise SystemExit("SELFHOSTED_UPDATE_PRIVATE_KEY must be a valid Ed25519 PEM private key") from exc
        normalized_public_key = normalized_public_key_path.read_bytes()
        derived_public_key = derived_public_key_path.read_bytes()
        if (
            len(normalized_public_key) != ED25519_PUBLIC_KEY_DER_BYTES
            or not normalized_public_key.startswith(ED25519_PUBLIC_KEY_DER_PREFIX)
        ):
            raise SystemExit("SELFHOSTED_UPDATE_PUBLIC_KEY_PEM_BASE64 must contain an Ed25519 public key")
        if (
            len(derived_public_key) != ED25519_PUBLIC_KEY_DER_BYTES
            or not derived_public_key.startswith(ED25519_PUBLIC_KEY_DER_PREFIX)
        ):
            raise SystemExit("SELFHOSTED_UPDATE_PRIVATE_KEY must contain an Ed25519 private key")
        if normalized_public_key != derived_public_key:
            raise SystemExit("SELFHOSTED_UPDATE_PUBLIC_KEY_PEM_BASE64 does not match SELFHOSTED_UPDATE_PRIVATE_KEY")


def read_manifest_bytes(path: Path) -> bytes:
    size = path.stat().st_size
    if size > MAX_MANIFEST_RESPONSE_BYTES:
        raise SystemExit(
            f"Update manifest exceeds the client-compatible 1 MiB response limit: {path} ({size} bytes)"
        )
    manifest_data = path.read_bytes()
    if len(manifest_data) > MAX_MANIFEST_RESPONSE_BYTES:
        raise SystemExit(
            f"Update manifest grew beyond the client-compatible 1 MiB response limit while being read: {path}"
        )
    return manifest_data


def decode_manifest_envelope(manifest_data: bytes) -> tuple[dict[str, object], bytes, bytes]:
    if len(manifest_data) > MAX_MANIFEST_RESPONSE_BYTES:
        raise SystemExit("Update manifest exceeds the client-compatible 1 MiB response limit")
    try:
        manifest = json.loads(manifest_data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SystemExit("Update manifest is not valid UTF-8 JSON") from error
    if not isinstance(manifest, dict):
        raise SystemExit("Update manifest envelope must be an object")
    if manifest.get("schema") != "amnezia-selfhosted-update-v1":
        raise SystemExit(f"Unexpected manifest schema: {manifest.get('schema')!r}")
    if manifest.get("signatureAlgorithm") != "Ed25519":
        raise SystemExit(f"Unexpected manifest signature algorithm: {manifest.get('signatureAlgorithm')!r}")

    encoded_payload = manifest.get("payload")
    encoded_signature = manifest.get("signature")
    if not isinstance(encoded_payload, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", encoded_payload):
        raise SystemExit("Update manifest payload is not strict unpadded base64url")
    if not isinstance(encoded_signature, str):
        raise SystemExit("Update manifest signature is missing")
    try:
        payload_bytes = base64.b64decode(
            encoded_payload + "=" * (-len(encoded_payload) % 4),
            altchars=b"-_",
            validate=True,
        )
        signature = base64.b64decode(encoded_signature, validate=True)
    except (ValueError, TypeError) as error:
        raise SystemExit("Update manifest payload or signature is not valid base64") from error
    if not payload_bytes:
        raise SystemExit("Update manifest payload is empty")
    if len(signature) != 64:
        raise SystemExit("Update manifest signature is not a 64-byte Ed25519 signature")
    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SystemExit("Update manifest payload is not valid UTF-8 JSON") from error
    if not isinstance(payload, dict):
        raise SystemExit("Update manifest payload must be an object")
    return payload, payload_bytes, signature


def verify_manifest_signature(private_key: Path, payload_bytes: bytes, signature: bytes) -> None:
    require_ed25519_private_key(private_key)
    with tempfile.TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)
        payload_path = tmp_dir / "payload.json"
        signature_path = tmp_dir / "payload.sig"
        public_key_path = tmp_dir / "public.pem"
        payload_path.write_bytes(payload_bytes)
        signature_path.write_bytes(signature)
        run([openssl_command(), "pkey", "-in", str(private_key), "-pubout", "-out", str(public_key_path)])
        run([
            openssl_command(),
            "pkeyutl",
            "-verify",
            "-rawin",
            "-pubin",
            "-inkey",
            str(public_key_path),
            "-in",
            str(payload_path),
            "-sigfile",
            str(signature_path),
        ])


def verified_manifest_payload(manifest_data: bytes, private_key: Path) -> tuple[dict[str, object], bytes]:
    payload, payload_bytes, signature = decode_manifest_envelope(manifest_data)
    verify_manifest_signature(private_key, payload_bytes, signature)
    return payload, payload_bytes


def release_content_projection(payload: dict[str, object]) -> dict[str, object]:
    """Return signed release content that a policy-only generation may not change."""

    return {
        key: value
        for key, value in payload.items()
        if key not in {"schema", "releasePolicy"}
    }


def validate_publish_transition(
    existing_manifest_data: bytes | None,
    candidate_manifest_data: bytes,
    private_key: Path,
) -> str | None:
    """Validate client anti-replay rules and return the current envelope SHA for remote CAS."""

    candidate_payload, candidate_payload_bytes = verified_manifest_payload(candidate_manifest_data, private_key)
    candidate_schema = candidate_payload.get("schema")
    if isinstance(candidate_schema, bool) or candidate_schema not in {1, 2}:
        raise SystemExit(f"Candidate manifest has unsupported payload schema: {candidate_schema!r}")
    candidate_version = candidate_payload.get("version")
    candidate_version_key = release_version_key(candidate_version, "Candidate")
    candidate_generation: int | None = None
    if candidate_schema == 2:
        candidate_policy = candidate_payload.get("releasePolicy")
        if not isinstance(candidate_policy, dict) or candidate_policy.get("schema") != 2:
            raise SystemExit("Candidate payload schema 2 requires releasePolicy schema 2")
        candidate_generation_value = candidate_policy.get("generation")
        if (
            isinstance(candidate_generation_value, bool)
            or not isinstance(candidate_generation_value, int)
            or not 1 <= candidate_generation_value <= MAX_POLICY_GENERATION
        ):
            raise SystemExit(f"Candidate manifest has invalid policy generation: {candidate_generation_value!r}")
        candidate_generation = candidate_generation_value
    if existing_manifest_data is None:
        return None

    existing_payload, existing_payload_bytes = verified_manifest_payload(existing_manifest_data, private_key)
    existing_schema = existing_payload.get("schema")
    if isinstance(existing_schema, bool) or existing_schema not in {1, 2}:
        raise SystemExit(f"Published manifest has unsupported payload schema: {existing_schema!r}")
    existing_version = existing_payload.get("version")
    existing_version_key = release_version_key(existing_version, "Published")
    if candidate_version_key < existing_version_key:
        raise SystemExit(
            f"Refusing candidate release version {candidate_version!r}; "
            f"published release version is newer: {existing_version!r}"
        )

    existing_generation: int | None = None
    if existing_schema == 2:
        if candidate_schema != 2:
            raise SystemExit("Refusing to downgrade an existing payload-schema-2 update channel to schema 1")
        existing_policy = existing_payload.get("releasePolicy")
        if not isinstance(existing_policy, dict) or existing_policy.get("schema") != 2:
            raise SystemExit("Published payload schema 2 requires releasePolicy schema 2")
        existing_generation_value = existing_policy.get("generation")
        if (
            isinstance(existing_generation_value, bool)
            or not isinstance(existing_generation_value, int)
            or not 1 <= existing_generation_value <= MAX_POLICY_GENERATION
        ):
            raise SystemExit(f"Published manifest has invalid policy generation: {existing_generation_value!r}")
        existing_generation = existing_generation_value
        assert candidate_generation is not None
        if candidate_generation < existing_generation:
            raise SystemExit(
                f"Refusing stale policy generation {candidate_generation}; published generation is {existing_generation}"
            )
        if candidate_generation == existing_generation and candidate_payload_bytes != existing_payload_bytes:
            raise SystemExit(
                f"Refusing policy generation {candidate_generation} with a different payload; "
                "a generation is permanently bound to one payload hash"
            )
    if candidate_version_key == existing_version_key and candidate_payload_bytes != existing_payload_bytes:
        same_version_policy_advance = (
            candidate_schema == 2
            and release_content_projection(candidate_payload) == release_content_projection(existing_payload)
            and (
                existing_schema == 1
                or (
                    existing_generation is not None
                    and candidate_generation is not None
                    and candidate_generation > existing_generation
                )
            )
        )
        if not same_version_policy_advance:
            raise SystemExit(
                f"Refusing to change release content for version {candidate_version!r}; "
                "only an exact republish or a policy-only monotonic schema-2 generation advance is allowed"
            )
    return hashlib.sha256(existing_manifest_data).hexdigest()


def remote_server_dir_validation_command(server_dir: str) -> str:
    """Build a read-only remote canonicalization check for the publication path."""

    server_dir = validate_server_dir(server_dir)
    parent_dir = server_dir.rsplit("/", 1)[0] or "/"
    commands = [
        f"target={sh_quote(server_dir)}",
        f"parent={sh_quote(parent_dir)}",
        "root_identity=$(sudo stat -Lc '%d:%i' -- /)",
        "resolved=$(sudo readlink -m -- \"$target\")",
        "resolved_parent=$(sudo readlink -m -- \"$parent\")",
        (
            "[ \"$resolved\" = \"$target\" ] && [ \"$resolved\" != / ] || "
            "{ echo 'server directory resolves through a symlink or to filesystem root' >&2; exit 64; }"
        ),
        (
            "[ \"$resolved_parent\" = \"$parent\" ] || "
            "{ echo 'server directory parent resolves through a symlink' >&2; exit 64; }"
        ),
        (
            "check_trusted_directory() { checked=$1; description=$2; "
            "sudo test -d \"$checked\" && ! sudo test -L \"$checked\" || { "
            "echo \"$description is not a real directory\" >&2; return 64; }; "
            "identity=$(sudo stat -Lc '%d:%i' -- \"$checked\") || return 64; "
            "[ \"$identity\" != \"$root_identity\" ] || { "
            "echo \"$description is a bind-mounted alias of filesystem root\" >&2; return 64; }; "
            "trusted=$(sudo find \"$checked\" -maxdepth 0 -uid 0 ! -perm /0022 -print -quit) || return 64; "
            "[ -n \"$trusted\" ] || { "
            "echo \"$description must be root-owned and not group/other-writable\" >&2; return 64; }; "
            "}"
        ),
        (
            "validate_channel_layout() { "
            "unexpected=$(sudo find \"$target\" -mindepth 1 -maxdepth 1 "
            f"! -name {sh_quote(CHANNEL_MARKER_NAME)} ! -name manifest.json "
            "! -name files ! -name .manifest-publish.lock "
            "! -name '.channel-marker.*' ! -name '.manifest.*' -print -quit) || return 64; "
            "[ -z \"$unexpected\" ] || { "
            "echo 'server directory is nonempty and is not a dedicated update channel' >&2; return 64; }; "
            "for leaf in manifest.json .manifest-publish.lock files; do "
            "entry=\"$target/$leaf\"; "
            "if sudo test -e \"$entry\" || sudo test -L \"$entry\"; then "
            "case \"$leaf\" in files) "
            "sudo test -d \"$entry\" && ! sudo test -L \"$entry\" || { "
            "echo \"update channel entry is not a real directory: $leaf\" >&2; return 64; };; "
            "*) sudo test -f \"$entry\" && ! sudo test -L \"$entry\" || { "
            "echo \"update channel entry is not a regular file: $leaf\" >&2; return 64; };; esac; "
            "entry_safe=$(sudo find \"$entry\" -maxdepth 0 -uid 0 -gid 0 ! -perm /0022 -print -quit) "
            "|| return 64; [ -n \"$entry_safe\" ] || { "
            "echo \"update channel entry must be root-owned and not group/other-writable: $leaf\" >&2; "
            "return 64; }; fi; done; "
            f"marker=\"$target/{CHANNEL_MARKER_NAME}\"; "
            "marker_valid=0; "
            "if sudo test -e \"$marker\" || sudo test -L \"$marker\"; then "
            "sudo test -f \"$marker\" && ! sudo test -L \"$marker\" || { "
            "echo 'update channel marker is not a regular file' >&2; return 64; }; "
            "marker_safe=$(sudo find \"$marker\" -maxdepth 0 -uid 0 -gid 0 ! -perm /0022 -print -quit) "
            "|| return 64; [ -n \"$marker_safe\" ] || { "
            "echo 'update channel marker must be root-owned and not group/other-writable' >&2; return 64; }; "
            "marker_sha=$(sudo sha256sum -- \"$marker\" | awk '{print $1}') || return 64; "
            f"[ \"$marker_sha\" = {sh_quote(CHANNEL_MARKER_SHA256)} ] || {{ "
            "echo 'update channel marker has unexpected content' >&2; return 64; }; marker_valid=1; fi; "
            "for orphan in \"$target\"/.channel-marker.* \"$target\"/.manifest.*; do "
            "if sudo test -e \"$orphan\" || sudo test -L \"$orphan\"; then "
            "orphan_name=${orphan##*/}; "
            "case \"$orphan_name\" in "
            ".channel-marker.*) printf '%s\\n' \"$orphan_name\" | "
            "grep -Eq '^\\.channel-marker\\.[0-9a-f]{48}$' || { "
            "echo 'update channel marker orphan has an invalid name' >&2; return 64; };; "
            ".manifest.*) printf '%s\\n' \"$orphan_name\" | "
            "grep -Eq '^\\.manifest\\.[0-9a-f]{48}$' || { "
            "echo 'update manifest orphan has an invalid name' >&2; return 64; }; "
            "[ \"$marker_valid\" = 1 ] || { "
            "echo 'unmarked directory must not contain manifest staging files' >&2; return 64; };; "
            "*) echo 'unexpected update channel temporary entry' >&2; return 64;; esac; "
            "sudo test -f \"$orphan\" && ! sudo test -L \"$orphan\" || { "
            "echo 'update channel temporary orphan is not a regular file' >&2; return 64; }; "
            "orphan_safe=$(sudo find \"$orphan\" -maxdepth 0 -uid 0 -gid 0 ! -perm /0022 -print -quit) "
            "|| return 64; [ -n \"$orphan_safe\" ] || { "
            "echo 'update channel temporary orphan has unsafe ownership or mode' >&2; return 64; }; "
            f"orphan_size=$(sudo stat -c %s -- \"$orphan\") || return 64; "
            f"[ \"$orphan_size\" -le {MAX_MANIFEST_RESPONSE_BYTES} ] || {{ "
            "echo 'update channel temporary orphan is oversized' >&2; return 64; }; "
            "case \"$orphan_name\" in .channel-marker.*) "
            f"[ \"$orphan_size\" -le {len((CHANNEL_MARKER_TEXT + chr(10)).encode('utf-8'))} ] || {{ "
            "echo 'update channel marker orphan is too large to be a valid partial marker' >&2; return 64; }; "
            "orphan_sha=$(sudo sha256sum -- \"$orphan\" | awk '{print $1}') || return 64; "
            "case \"$orphan_sha\" in "
            + "|".join(sh_quote(digest) for digest in CHANNEL_MARKER_PREFIX_SHA256)
            + ") :;; *) echo 'update channel marker orphan has unexpected partial content' >&2; "
            "return 64;; esac;; esac; "
            "fi; done; "
            "}"
        ),
        (
            "if sudo test -e \"$target\" || sudo test -L \"$target\"; then "
            "check_trusted_directory \"$target\" 'server directory' || exit $?; "
            "validate_channel_layout || exit $?; fi"
        ),
        (
            "ancestor=$parent; while [ \"$ancestor\" != / ]; do "
            "if sudo test -e \"$ancestor\" || sudo test -L \"$ancestor\"; then "
            "check_trusted_directory \"$ancestor\" 'server directory ancestor' || exit $?; fi; "
            "next=${ancestor%/*}; [ -n \"$next\" ] || next=/; "
            "[ \"$next\" != \"$ancestor\" ] || { echo 'unable to traverse server directory ancestors' >&2; exit 64; }; "
            "ancestor=$next; done"
        ),
    ]
    return " && ".join(commands)


def validate_remote_server_dir(args: argparse.Namespace) -> None:
    """Resolve the remote target without mutating it before any publication write."""

    ssh = command_parts(args.ssh)
    run(ssh + [args.server, remote_server_dir_validation_command(args.server_dir)])


def remote_orphan_cleanup_command(server_dir: str, *, kind: str) -> str:
    server_dir = validate_server_dir(server_dir)
    if kind == "marker":
        glob = ".channel-marker.*"
        pattern = r"^\.channel-marker\.[0-9a-f]{48}$"
    elif kind == "manifest":
        glob = ".manifest.*"
        pattern = r"^\.manifest\.[0-9a-f]{48}$"
    else:
        raise ValueError("remote orphan cleanup kind must be marker or manifest")
    return (
        f"if sudo test -d {sh_quote(server_dir)} && ! sudo test -L {sh_quote(server_dir)}; then "
        f"for orphan in {sh_quote(server_dir)}/{glob}; do "
        "if sudo test -e \"$orphan\" || sudo test -L \"$orphan\"; then "
        "orphan_name=${orphan##*/}; printf '%s\\n' \"$orphan_name\" | "
        f"grep -Eq {sh_quote(pattern)} || exit 64; "
        "sudo test -f \"$orphan\" && ! sudo test -L \"$orphan\" || exit 64; "
        "sudo rm -f -- \"$orphan\" || exit 1; fi; done; fi"
    )


def fetch_remote_manifest(args: argparse.Namespace) -> bytes | None:
    ssh = command_parts(args.ssh)
    manifest_path = validate_server_dir(args.server_dir) + "/manifest.json"
    command = (
        f"if sudo test -L {sh_quote(manifest_path)}; then "
        "echo 'published update manifest must not be a symlink' >&2; exit 64; "
        f"elif sudo test -f {sh_quote(manifest_path)}; then "
        f"sudo head -c {MAX_MANIFEST_RESPONSE_BYTES + 1} {sh_quote(manifest_path)}; "
        f"else exit {REMOTE_MANIFEST_ABSENT_EXIT_CODE}; fi"
    )
    result = subprocess.run(ssh + [args.server, command], capture_output=True)
    if result.returncode == REMOTE_MANIFEST_ABSENT_EXIT_CODE:
        return None
    if result.returncode != 0:
        error = result.stderr.decode("utf-8", errors="replace").strip()[:500]
        raise SystemExit(f"Unable to read the currently published update manifest: {error or result.returncode}")
    if len(result.stdout) > MAX_MANIFEST_RESPONSE_BYTES:
        raise SystemExit("Published update manifest exceeds the client-compatible 1 MiB response limit")
    return result.stdout


def publish_files_remote_command(
    server_dir: str,
    remote_tmp: str,
    expected_current_manifest_sha256: str | None = None,
    candidate_file_expectations: dict[str, tuple[str, int]] | None = None,
) -> str:
    server_dir = validate_server_dir(server_dir)
    if expected_current_manifest_sha256 is not None and not SHA256_RE.fullmatch(
        expected_current_manifest_sha256
    ):
        raise ValueError("expected current manifest sha256 must be lowercase hexadecimal")
    candidate_file_expectations = candidate_file_expectations or {}
    rollback_expectations = {
        path: metadata
        for path, metadata in candidate_file_expectations.items()
        if path.startswith("files/rollback/")
    }
    artifact_expectations = {
        path: metadata
        for path, metadata in candidate_file_expectations.items()
        if path.startswith("files/artifacts/")
    }
    artifact_expectations_by_digest: dict[str, dict[str, tuple[str, int]]] = {}
    for path, (digest, size) in artifact_expectations.items():
        parts = PurePosixPath(path).parts
        if (
            len(parts) != 4
            or parts[:2] != ("files", "artifacts")
            or not SHA256_RE.fullmatch(parts[2])
            or parts[2] != digest
            or not isinstance(size, int)
            or size <= 0
        ):
            raise ValueError(f"invalid signed content-addressed artifact expectation for {path}")
        artifact_expectations_by_digest.setdefault(parts[2], {})[parts[3]] = (digest, size)
    rollback_expectations_by_generation: dict[str, dict[str, tuple[str, int]]] = {}
    for path, (digest, size) in rollback_expectations.items():
        if not SHA256_RE.fullmatch(digest) or not isinstance(size, int) or size <= 0:
            raise ValueError(f"invalid signed rollback expectation for {path}")
        parts = PurePosixPath(path).parts
        if (
            len(parts) < 4
            or parts[:2] != ("files", "rollback")
            or not re.fullmatch(r"[1-9][0-9]*", parts[2])
        ):
            raise ValueError(f"invalid signed rollback path for {path}")
        relative_in_generation = PurePosixPath(*parts[3:]).as_posix()
        rollback_expectations_by_generation.setdefault(parts[2], {})[
            relative_in_generation
        ] = (digest, size)
    files_dir = server_dir + "/files"
    artifacts_dir = files_dir + "/artifacts"
    rollback_dir = files_dir + "/rollback"
    verify_digest_function = (
        "verify_digest_tree() { tree=$1; expected=$2; [ -n \"$expected\" ] || return 0; "
        "sudo sh -c 'tree=$1; expected=$2; found=0; "
        "for item in \"$tree\"/* \"$tree\"/.[!.]* \"$tree\"/..?*; do "
        "[ -e \"$item\" ] || [ -L \"$item\" ] || continue; found=1; "
        "[ -f \"$item\" ] && [ ! -L \"$item\" ] || exit 65; "
        "actual=$(sha256sum -- \"$item\") || exit 65; actual=${actual%% *}; "
        "[ \"$actual\" = \"$expected\" ] || exit 65; done; [ \"$found\" = 1 ]' "
        "sh \"$tree\" \"$expected\"; "
        "}"
    )
    verify_readable_function = (
        "verify_readable_tree() { tree=$1; "
        "unsafe=$(sudo find \"$tree\" ! -type d ! -type f -print -quit) || return 65; "
        "[ -z \"$unsafe\" ] || return 65; "
        "mutable=$(sudo find \"$tree\" \\( ! -uid 0 -o ! -gid 0 -o -perm /0022 \\) -print -quit) || return 65; "
        "[ -z \"$mutable\" ] || return 65; "
        "unreadable_dir=$(sudo find \"$tree\" -type d ! -perm -0005 -print -quit) || return 65; "
        "[ -z \"$unreadable_dir\" ] || return 65; "
        "unreadable_file=$(sudo find \"$tree\" -type f ! -perm -0004 -print -quit) || return 65; "
        "[ -z \"$unreadable_file\" ]; "
        "}"
    )
    rollback_generation_cases: list[str] = []
    for generation, expectations in sorted(
        rollback_expectations_by_generation.items(), key=lambda item: int(item[0])
    ):
        checks = [
            f"actual_count=$(sudo find \"$tree\" -type f -printf . | wc -c) || return 65; "
            f"[ \"$actual_count\" -eq {len(expectations)} ] || return 65; "
        ]
        for relative_path, (digest, size) in sorted(expectations.items()):
            suffix = "/" + relative_path
            checks.extend([
                f"item=\"$tree\"{sh_quote(suffix)}; ",
                "sudo test -f \"$item\" && ! sudo test -L \"$item\" || return 65; ",
                f"[ \"$(sudo stat -c %s -- \"$item\")\" -eq {size} ] || return 65; ",
                "actual=$(sudo sha256sum -- \"$item\" | awk '{print $1}') || return 65; ",
                f"[ \"$actual\" = {sh_quote(digest)} ] || return 65; ",
            ])
        rollback_generation_cases.append(
            f"{sh_quote(generation)}) " + "".join(checks) + ";; "
        )
    verify_signed_rollback_function = (
        "verify_signed_rollback_tree() { tree=$1; generation=$2; "
        "case \"$generation\" in "
        + "".join(rollback_generation_cases)
        + "*) return 65;; esac; }"
    )
    artifact_digest_cases: list[str] = []
    for digest, expectations in sorted(artifact_expectations_by_digest.items()):
        checks = [
            f"actual_count=$(sudo find \"$tree\" -type f -printf . | wc -c) || return 65; "
            f"[ \"$actual_count\" -eq {len(expectations)} ] || return 65; "
        ]
        for relative_path, (expected_digest, size) in sorted(expectations.items()):
            suffix = "/" + relative_path
            checks.extend([
                f"item=\"$tree\"{sh_quote(suffix)}; ",
                "sudo test -f \"$item\" && ! sudo test -L \"$item\" || return 65; ",
                *(
                    [f"[ \"$(sudo stat -c %s -- \"$item\")\" -eq {size} ] || return 65; "]
                    if size > 0
                    else []
                ),
                "actual=$(sudo sha256sum -- \"$item\" | awk '{print $1}') || return 65; ",
                f"[ \"$actual\" = {sh_quote(expected_digest)} ] || return 65; ",
            ])
        artifact_digest_cases.append(f"{sh_quote(digest)}) " + "".join(checks) + ";; ")
    verify_signed_artifact_function = (
        "verify_signed_artifact_tree() { tree=$1; digest=$2; case \"$digest\" in "
        + "".join(artifact_digest_cases)
        + "*) return 65;; esac; }"
    )
    artifact_seal_cases: list[str] = []
    for digest, expectations in sorted(artifact_expectations_by_digest.items()):
        commands: list[str] = []
        for relative_path, (_expected_digest, size) in sorted(expectations.items()):
            parent = PurePosixPath(relative_path).parent.as_posix()
            source_suffix = "/" + relative_path
            target_suffix = "/" + relative_path
            if parent != ".":
                commands.append(
                    f"sudo install -d -o 0 -g 0 -m 0700 -- \"$destination\"{sh_quote('/' + parent)} || return 1; "
                )
            commands.append(
                "sudo sh -c 'head -c \"$3\" -- \"$1\" > \"$2\"' sh "
                f"\"$source\"{sh_quote(source_suffix)} \"$destination\"{sh_quote(target_suffix)} {size} "
                "|| return 1; "
            )
        artifact_seal_cases.append(f"{sh_quote(digest)}) " + "".join(commands) + ";; ")
    rollback_seal_cases: list[str] = []
    for generation, expectations in sorted(
        rollback_expectations_by_generation.items(), key=lambda item: int(item[0])
    ):
        commands = []
        for relative_path, (_expected_digest, size) in sorted(expectations.items()):
            parent = PurePosixPath(relative_path).parent.as_posix()
            source_suffix = "/" + relative_path
            target_suffix = "/" + relative_path
            if parent != ".":
                commands.append(
                    f"sudo install -d -o 0 -g 0 -m 0700 -- \"$destination\"{sh_quote('/' + parent)} || return 1; "
                )
            commands.append(
                "sudo sh -c 'head -c \"$3\" -- \"$1\" > \"$2\"' sh "
                f"\"$source\"{sh_quote(source_suffix)} \"$destination\"{sh_quote(target_suffix)} {size} "
                "|| return 1; "
            )
        rollback_seal_cases.append(f"{sh_quote(generation)}) " + "".join(commands) + ";; ")
    seal_signed_tree_function = (
        "seal_signed_tree() { source=$1; destination=$2; artifact_digest=$3; rollback_generation=$4; "
        "if [ -n \"$artifact_digest\" ]; then case \"$artifact_digest\" in "
        + "".join(artifact_seal_cases)
        + "*) return 65;; esac; elif [ -n \"$rollback_generation\" ]; then "
        "case \"$rollback_generation\" in "
        + "".join(rollback_seal_cases)
        + "*) return 65;; esac; else return 65; fi; }"
    )
    cleanup_stage_function = (
        "cleanup_publish_stage() { if [ -n \"${stage_cleanup:-}\" ]; then "
        "sudo rm -rf -- \"$stage_cleanup\" >/dev/null 2>&1 || true; stage_cleanup=; fi; }"
    )
    cleanup_state_function = (
        "cleanup_publish_state() { cleanup_publish_stage; "
        "if [ -n \"${source_snapshot_cleanup:-}\" ]; then "
        "rm -rf -- \"$source_snapshot_cleanup\" >/dev/null 2>&1 || "
        "sudo rm -rf -- \"$source_snapshot_cleanup\" >/dev/null 2>&1 || true; "
        "source_snapshot_cleanup=; fi; "
        "if [ -n \"${marker_cleanup:-}\" ]; then "
        "sudo rm -f -- \"$marker_cleanup\" >/dev/null 2>&1 || true; marker_cleanup=; fi; }"
    )
    marker_path = server_dir + "/" + CHANNEL_MARKER_NAME
    marker_temp_path = server_dir + "/.channel-marker." + secrets.token_hex(24)
    install_marker_function = (
        "install_channel_marker() { "
        f"marker={sh_quote(marker_path)}; "
        "if sudo test -e \"$marker\" || sudo test -L \"$marker\"; then return 0; fi; "
        "existing_entry=$(sudo find \"$target\" -mindepth 1 -maxdepth 1 "
        "! -name .manifest-publish.lock -print -quit) || return 64; "
        "if [ -n \"$existing_entry\" ]; then "
        f"legacy_expected={sh_quote(expected_current_manifest_sha256 or '')}; "
        "[ -n \"$legacy_expected\" ] || { "
        "echo 'refusing to adopt a nonempty unmarked update directory without a verified manifest' >&2; "
        "return 64; }; "
        "legacy_manifest=\"$target/manifest.json\"; "
        "sudo test -f \"$legacy_manifest\" && ! sudo test -L \"$legacy_manifest\" || { "
        "echo 'unmarked legacy update directory requires a regular manifest' >&2; return 64; }; "
        "legacy_actual=$(sudo sha256sum -- \"$legacy_manifest\" | awk '{print $1}') || return 64; "
        "[ \"$legacy_actual\" = \"$legacy_expected\" ] || { "
        "echo 'unmarked legacy update manifest changed after local signature verification' >&2; return 75; }; fi; "
        f"marker_tmp={sh_quote(marker_temp_path)}; marker_cleanup=$marker_tmp; "
        "if sudo test -e \"$marker_tmp\" || sudo test -L \"$marker_tmp\"; then "
        "echo 'random channel marker staging path already exists' >&2; return 75; fi; "
        "sudo install -o 0 -g 0 -m 0600 /dev/null \"$marker_tmp\" || { "
        "cleanup_publish_state; return 1; }; "
        f"printf '%s\\n' {sh_quote(CHANNEL_MARKER_TEXT)} | sudo tee -- \"$marker_tmp\" >/dev/null "
        "|| { cleanup_publish_state; return 1; }; "
        "sudo chown 0:0 -- \"$marker_tmp\" && sudo chmod 0444 -- \"$marker_tmp\" "
        "|| { cleanup_publish_state; return 1; }; "
        "sudo mv -T -n -- \"$marker_tmp\" \"$marker\" || { cleanup_publish_state; return 1; }; "
        "if sudo test -e \"$marker_tmp\" || sudo test -L \"$marker_tmp\"; then "
        "sudo rm -f -- \"$marker_tmp\" || { cleanup_publish_state; return 1; }; fi; "
        "marker_cleanup=; "
        "}"
    )
    publish_tree_function = (
        "publish_immutable_tree() { "
        "source=$1; target=$2; label=$3; expected_digest=$4; "
        "expected_artifact_digest=$5; expected_rollback_generation=$6; parent=${target%/*}; "
        "sudo test -d \"$parent\" && ! sudo test -L \"$parent\" || { "
        "echo \"immutable release parent is not a real directory: $label\" >&2; return 65; }; "
        "parent_identity=$(sudo stat -Lc '%d:%i' -- \"$parent\") || return 65; "
        "[ \"$parent_identity\" != \"$root_identity\" ] || { "
        "echo \"immutable release parent aliases filesystem root: $label\" >&2; return 65; }; "
        "parent_safe=$(sudo find \"$parent\" -maxdepth 0 -uid 0 -gid 0 ! -perm /0022 -perm -0005 -print -quit) || return 65; "
        "[ -n \"$parent_safe\" ] || { echo \"unsafe immutable release parent: $label\" >&2; return 65; }; "
        f"snapshot=$(mktemp -d {sh_quote(remote_tmp + '/.publish-source-')}\"$label\".XXXXXXXXXX) || return 1; "
        "source_snapshot_cleanup=$snapshot; "
        "if ! cp -a -- \"$source\"/. \"$snapshot\"/; then cleanup_publish_state; return 1; fi; "
        "snapshot_unsafe=$(find \"$snapshot\" ! -type d ! -type f -print -quit) || { "
        "cleanup_publish_state; return 65; }; "
        "[ -z \"$snapshot_unsafe\" ] || { cleanup_publish_state; "
        "echo \"uploaded source snapshot contains an unsafe entry: $label\" >&2; return 65; }; "
        "if [ -n \"$expected_artifact_digest\" ] && "
        "! verify_signed_artifact_tree \"$snapshot\" \"$expected_artifact_digest\"; then "
        "cleanup_publish_state; echo \"artifact source snapshot differs from signed metadata: $label\" >&2; "
        "return 65; fi; "
        "if [ -n \"$expected_rollback_generation\" ] && "
        "! verify_signed_rollback_tree \"$snapshot\" \"$expected_rollback_generation\"; then "
        "cleanup_publish_state; echo \"rollback source snapshot differs from signed metadata: $label\" >&2; "
        "return 65; fi; "
        "if sudo test -e \"$target\" || sudo test -L \"$target\"; then "
        "if sudo test -d \"$target\" && ! sudo test -L \"$target\"; then "
        "verify_readable_tree \"$target\" || { "
        "echo \"immutable release tree is not safely HTTP-readable: $label\" >&2; return 65; }; "
        "verify_digest_tree \"$target\" \"$expected_digest\" || { "
        "echo \"immutable release tree has invalid content digest: $label\" >&2; return 65; }; "
        "if [ -n \"$expected_artifact_digest\" ] && "
        "! verify_signed_artifact_tree \"$target\" \"$expected_artifact_digest\"; then "
        "echo \"immutable artifact tree differs from signed metadata: $label\" >&2; return 65; fi; "
        "if [ -n \"$expected_rollback_generation\" ] && "
        "! verify_signed_rollback_tree \"$target\" \"$expected_rollback_generation\"; then "
        "echo \"immutable rollback tree differs from signed metadata: $label\" >&2; return 65; fi; "
        "sudo diff -qr -- \"$snapshot\" \"$target\" >/dev/null || { "
        "echo \"immutable release tree already exists with different content: $label\" >&2; return 65; }; "
        "cleanup_publish_state; return 0; fi; "
        "echo \"immutable release target is not a real directory: $label\" >&2; return 65; fi; "
        "stage_root=$(sudo mktemp -d \"$parent/.publish-$label.XXXXXXXXXX\") || return 1; "
        "stage_cleanup=$stage_root; quarantine=$stage_root/source; stage=$stage_root/tree; "
        "sudo mv -T -- \"$snapshot\" \"$quarantine\" || { cleanup_publish_state; return 1; }; "
        "source_snapshot_cleanup=; "
        "sudo test -d \"$quarantine\" && ! sudo test -L \"$quarantine\" || { "
        "cleanup_publish_stage; echo \"uploaded snapshot changed type during root handoff: $label\" >&2; "
        "return 65; }; "
        "sudo chown 0:0 -- \"$quarantine\" && sudo chmod 0700 -- \"$quarantine\" && "
        "sudo find \"$quarantine\" -type d -exec chown 0:0 {} + && "
        "sudo find \"$quarantine\" -type d -exec chmod 0700 {} + "
        "|| { cleanup_publish_stage; return 1; }; "
        "quarantine_unsafe=$(sudo find \"$quarantine\" ! -type d ! -type f -print -quit) || { "
        "cleanup_publish_stage; return 65; }; "
        "[ -z \"$quarantine_unsafe\" ] || { cleanup_publish_stage; "
        "echo \"root quarantine contains an unsafe entry: $label\" >&2; return 65; }; "
        "sudo install -d -o 0 -g 0 -m 0700 -- \"$stage\" || { cleanup_publish_stage; return 1; }; "
        "seal_signed_tree \"$quarantine\" \"$stage\" \"$expected_artifact_digest\" "
        "\"$expected_rollback_generation\" || { seal_status=$?; cleanup_publish_stage; return \"$seal_status\"; }; "
        "sudo rm -rf -- \"$quarantine\" || { cleanup_publish_stage; return 1; }; "
        "stage_unsafe=$(sudo find \"$stage\" ! -type d ! -type f -print -quit) || { "
        "cleanup_publish_stage; return 65; }; "
        "if [ -n \"$stage_unsafe\" ]; then "
        "cleanup_publish_stage; echo \"staged release tree contains an unsafe entry: $label\" >&2; return 65; fi; "
        "if ! verify_digest_tree \"$stage\" \"$expected_digest\"; then "
        "cleanup_publish_stage; echo \"staged release tree has invalid content digest: $label\" >&2; return 65; fi; "
        "if [ -n \"$expected_artifact_digest\" ] && "
        "! verify_signed_artifact_tree \"$stage\" \"$expected_artifact_digest\"; then "
        "cleanup_publish_stage; echo \"staged artifact tree differs from signed metadata: $label\" >&2; "
        "return 65; fi; "
        "if [ -n \"$expected_rollback_generation\" ] && "
        "! verify_signed_rollback_tree \"$stage\" \"$expected_rollback_generation\"; then "
        "cleanup_publish_stage; echo \"staged rollback tree differs from signed metadata: $label\" >&2; "
        "return 65; fi; "
        "sudo find \"$stage\" -type d -exec chmod 0755 {} + && "
        "sudo find \"$stage\" -type f -exec chmod 0644 {} + || { cleanup_publish_stage; return 1; }; "
        "if ! verify_readable_tree \"$stage\"; then "
        "cleanup_publish_stage; echo \"staged release tree is not safely immutable and HTTP-readable: $label\" >&2; return 65; fi; "
        "if sudo mv -T -n -- \"$stage\" \"$target\" 2>/dev/null && ! sudo test -e \"$stage\"; then "
        "cleanup_publish_stage; return 0; fi; "
        "if sudo test -d \"$target\" && ! sudo test -L \"$target\" && "
        "verify_readable_tree \"$target\" && verify_digest_tree \"$target\" \"$expected_digest\" && "
        "{ [ -z \"$expected_artifact_digest\" ] || "
        "verify_signed_artifact_tree \"$target\" \"$expected_artifact_digest\"; } && "
        "{ [ -z \"$expected_rollback_generation\" ] || "
        "verify_signed_rollback_tree \"$target\" \"$expected_rollback_generation\"; } && "
        "sudo diff -qr -- \"$stage\" \"$target\" >/dev/null; then "
        "cleanup_publish_stage; return 0; fi; "
        "cleanup_publish_stage; "
        "echo \"failed to publish immutable release tree without overwriting: $label\" >&2; return 65; "
        "}"
    )
    ensure_directory_function = (
        "ensure_real_directory() { directory=$1; "
        "if sudo test -e \"$directory\" || sudo test -L \"$directory\"; then :; "
        "else sudo install -d -o 0 -g 0 -m 0755 -- \"$directory\" || return 1; fi; "
        "sudo test -d \"$directory\" && ! sudo test -L \"$directory\" || { "
        "echo \"publication path component is not a real directory: $directory\" >&2; return 64; }; "
        "identity=$(sudo stat -Lc '%d:%i' -- \"$directory\") || return 64; "
        "[ \"$identity\" != \"$root_identity\" ] || { "
        "echo \"publication path component aliases filesystem root: $directory\" >&2; return 64; }; "
        "safe=$(sudo find \"$directory\" -maxdepth 0 -uid 0 -gid 0 ! -perm /0022 -perm -0005 -print -quit) || return 64; "
        "[ -n \"$safe\" ] || { echo \"publication path component must be root-owned, non-writable, and traversable: $directory\" >&2; return 64; }; "
        "}"
    )
    source_files = remote_tmp + "/files"
    rollback_source_dir = source_files + "/rollback"
    rollback_validation_parts = [
        (
            f"if test -d {sh_quote(rollback_source_dir)} && ! test -L {sh_quote(rollback_source_dir)}; "
            f"then rollback_file_count=$(find {sh_quote(rollback_source_dir)} -type f -print | wc -l); "
            "else rollback_file_count=0; fi"
        ),
        f"[ \"$rollback_file_count\" -eq {len(rollback_expectations)} ] || "
        "{ echo 'uploaded rollback tree contains files not bound by the signed manifest' >&2; exit 65; }",
    ]
    for relative_path, (digest, size) in sorted(rollback_expectations.items()):
        remote_path = remote_tmp + "/" + relative_path
        rollback_validation_parts.extend([
            f"test -f {sh_quote(remote_path)} && ! test -L {sh_quote(remote_path)} || "
            "{ echo 'signed rollback artifact is missing after upload' >&2; exit 65; }",
            f"[ \"$(stat -c %s -- {sh_quote(remote_path)})\" -eq {size} ] || "
            "{ echo 'uploaded rollback artifact size differs from signed metadata' >&2; exit 65; }",
            f"[ \"$(sha256sum -- {sh_quote(remote_path)} | awk '{{print $1}}')\" = {sh_quote(digest)} ] || "
            "{ echo 'uploaded rollback artifact digest differs from signed metadata' >&2; exit 65; }",
        ])
    commands = [
        remote_server_dir_validation_command(server_dir),
        f"sudo install -d -o 0 -g 0 -m 0755 -- {sh_quote(server_dir)}",
        f"sudo flock -x -w 60 {sh_quote(server_dir + '/.manifest-publish.lock')} true",
        remote_server_dir_validation_command(server_dir),
        f"exec 9< {sh_quote(server_dir + '/.manifest-publish.lock')}",
        "flock -x -w 60 9",
        remote_server_dir_validation_command(server_dir),
        remote_orphan_cleanup_command(server_dir, kind="marker"),
        remote_server_dir_validation_command(server_dir),
        cleanup_stage_function,
        cleanup_state_function,
        install_marker_function,
        "{ stage_cleanup=; source_snapshot_cleanup=; marker_cleanup=; trap 'cleanup_publish_state' EXIT; "
        "trap 'cleanup_publish_state; exit 74' HUP INT TERM; }",
        "install_channel_marker",
        remote_server_dir_validation_command(server_dir),
        ensure_directory_function,
        f"ensure_real_directory {sh_quote(server_dir)}",
        f"ensure_real_directory {sh_quote(files_dir)}",
        f"ensure_real_directory {sh_quote(artifacts_dir)}",
        f"ensure_real_directory {sh_quote(rollback_dir)}",
        verify_digest_function,
        verify_readable_function,
        verify_signed_artifact_function,
        verify_signed_rollback_function,
        seal_signed_tree_function,
        publish_tree_function,
        " && ".join(rollback_validation_parts),
        (
            f"for f in {sh_quote(source_files)}/* {sh_quote(source_files)}/.[!.]* {sh_quote(source_files)}/..?*; do "
            "[ -e \"$f\" ] || [ -L \"$f\" ] || continue; "
            "name=${f##*/}; "
            "[ -d \"$f\" ] && [ ! -L \"$f\" ] || "
            "{ echo \"unexpected non-directory release entry: $name\" >&2; exit 64; }; "
            "case \"$name\" in "
            "artifacts) has_digest=0; "
            "for digest_dir in \"$f\"/* \"$f\"/.[!.]* \"$f\"/..?*; do "
            "[ -e \"$digest_dir\" ] || [ -L \"$digest_dir\" ] || continue; has_digest=1; "
            "digest=${digest_dir##*/}; "
            "printf '%s\\n' \"$digest\" | grep -Eq '^[0-9a-f]{64}$' || "
            "{ echo \"invalid artifact digest directory: $digest\" >&2; exit 64; }; "
            "[ -d \"$digest_dir\" ] && [ ! -L \"$digest_dir\" ] || "
            "{ echo \"artifact digest entry is not a real directory: $digest\" >&2; exit 64; }; "
            "has_artifact=0; "
            "for artifact in \"$digest_dir\"/* \"$digest_dir\"/.[!.]* \"$digest_dir\"/..?*; do "
            "[ -e \"$artifact\" ] || [ -L \"$artifact\" ] || continue; has_artifact=1; "
            "[ -f \"$artifact\" ] && [ ! -L \"$artifact\" ] || "
            "{ echo \"artifact digest tree contains a non-regular file: $digest\" >&2; exit 64; }; "
            "actual_digest=$(sha256sum -- \"$artifact\" | awk '{print $1}') && "
            "[ \"$actual_digest\" = \"$digest\" ] || "
            "{ echo \"artifact bytes do not match digest directory: $digest\" >&2; exit 65; }; "
            "done; "
            "[ \"$has_artifact\" = 1 ] || { echo \"empty artifact digest directory: $digest\" >&2; exit 64; }; "
            f"publish_immutable_tree \"$digest_dir\" {sh_quote(artifacts_dir)}/\"$digest\" \"artifact-$digest\" \"$digest\" \"$digest\" '' || exit $?; "
            "done; "
            "[ \"$has_digest\" = 1 ] || { echo 'empty artifacts release directory' >&2; exit 64; };; "
            "rollback) has_generation=0; "
            "for generation_dir in \"$f\"/* \"$f\"/.[!.]* \"$f\"/..?*; do "
            "[ -e \"$generation_dir\" ] || [ -L \"$generation_dir\" ] || continue; has_generation=1; "
            "generation=${generation_dir##*/}; "
            "printf '%s\\n' \"$generation\" | grep -Eq '^[1-9][0-9]*$' || "
            "{ echo \"invalid rollback generation: $generation\" >&2; exit 64; }; "
            "[ -d \"$generation_dir\" ] && [ ! -L \"$generation_dir\" ] || "
            "{ echo \"rollback generation is not a real directory: $generation\" >&2; exit 64; }; "
            "rollback_unsafe=$(find \"$generation_dir\" ! -type d ! -type f -print -quit) || exit 64; "
            "[ -z \"$rollback_unsafe\" ] || "
            "{ echo \"rollback generation contains a symlink or special file: $generation\" >&2; exit 64; }; "
            "rollback_file=$(find \"$generation_dir\" -type f -print -quit) || exit 64; "
            "[ -n \"$rollback_file\" ] || { echo \"empty rollback generation: $generation\" >&2; exit 64; }; "
            f"publish_immutable_tree \"$generation_dir\" {sh_quote(rollback_dir)}/\"$generation\" \"rollback-$generation\" '' '' \"$generation\" || exit $?; "
            "done; "
            "[ \"$has_generation\" = 1 ] || { echo 'empty rollback release directory' >&2; exit 64; };; "
            "*) echo \"unexpected release directory: $name\" >&2; exit 64;; "
            "esac; "
            "done"
        ),
        "{ cleanup_publish_state; trap - EXIT HUP INT TERM; flock -u 9; exec 9<&-; }",
    ]
    return " && ".join(commands)


def publish_manifest_remote_command(
    server_dir: str,
    remote_tmp: str,
    expected_current_sha256: str | None,
    expected_candidate_sha256: str,
) -> str:
    server_dir = validate_server_dir(server_dir)
    if not SHA256_RE.fullmatch(expected_candidate_sha256):
        raise ValueError("expected candidate manifest sha256 must be lowercase hexadecimal")
    manifest_path = server_dir + "/manifest.json"
    lock_path = server_dir + "/.manifest-publish.lock"
    candidate_path = remote_tmp + "/manifest.json"
    candidate_snapshot_path = remote_tmp + "/.manifest-source." + secrets.token_hex(24)
    manifest_temp_path = server_dir + "/.manifest." + secrets.token_hex(24)
    if expected_current_sha256 is None:
        compare_command = (
            f"if test -e {sh_quote(manifest_path)} || test -L {sh_quote(manifest_path)}; then "
            "echo 'update manifest appeared during publication; refusing an unchecked overwrite' >&2; exit 75; fi"
        )
    else:
        if not SHA256_RE.fullmatch(expected_current_sha256):
            raise ValueError("expected current manifest sha256 must be lowercase hexadecimal")
        compare_command = (
            f"test -f {sh_quote(manifest_path)} && ! test -L {sh_quote(manifest_path)} && "
            f"current_manifest_sha=$(sha256sum {sh_quote(manifest_path)} | awk '{{print $1}}') && "
            f"[ \"$current_manifest_sha\" = {sh_quote(expected_current_sha256)} ] || "
            "{ echo 'update manifest changed during publication; refusing a stale overwrite' >&2; exit 75; }"
        )
    locked_command = " && ".join([
        remote_server_dir_validation_command(server_dir),
        remote_orphan_cleanup_command(server_dir, kind="manifest"),
        remote_server_dir_validation_command(server_dir),
        (
            "cleanup_manifest_tmp() { "
            "[ -z \"${manifest_quarantine_root:-}\" ] || rm -rf -- \"$manifest_quarantine_root\"; "
            "manifest_quarantine_root=; manifest_quarantine=; "
            "[ -z \"${manifest_tmp:-}\" ] || rm -f -- \"$manifest_tmp\"; "
            "manifest_tmp=; }"
        ),
        (
            "{ manifest_quarantine_root=; manifest_quarantine=; "
            f"manifest_tmp={sh_quote(manifest_temp_path)}; trap 'cleanup_manifest_tmp' EXIT; "
            "trap 'cleanup_manifest_tmp; exit 74' HUP INT TERM; }"
        ),
        (
            "if test -e \"$manifest_tmp\" || test -L \"$manifest_tmp\"; then "
            "echo 'random manifest sealing path already exists' >&2; exit 75; fi"
        ),
        "manifest_quarantine_root=$(mktemp -d /tmp/amnezia-manifest-seal.XXXXXXXXXX)",
        "manifest_quarantine=$manifest_quarantine_root/source",
        f"mv -T -- {sh_quote(candidate_snapshot_path)} \"$manifest_quarantine\"",
        (
            "test -f \"$manifest_quarantine\" && ! test -L \"$manifest_quarantine\" || "
            "{ echo 'candidate manifest snapshot changed type during root handoff' >&2; exit 65; }"
        ),
        "candidate_size=$(stat -c %s -- \"$manifest_quarantine\")",
        (
            f"[ \"$candidate_size\" -gt 0 ] && [ \"$candidate_size\" -le {MAX_MANIFEST_RESPONSE_BYTES} ] || "
            "{ echo 'uploaded candidate manifest exceeds the client-compatible 1 MiB limit' >&2; exit 65; }"
        ),
        "candidate_sha=$(sha256sum -- \"$manifest_quarantine\" | awk '{print $1}')",
        (
            f"[ \"$candidate_sha\" = {sh_quote(expected_candidate_sha256)} ] || "
            "{ echo 'uploaded candidate manifest sha256 does not match the locally verified envelope' >&2; exit 65; }"
        ),
        "install -o 0 -g 0 -m 0400 /dev/null \"$manifest_tmp\"",
        (
            "sh -c 'head -c \"$3\" -- \"$1\" > \"$2\"' sh "
            "\"$manifest_quarantine\" \"$manifest_tmp\" \"$candidate_size\""
        ),
        f"installed_size=$(stat -c %s -- \"$manifest_tmp\") && [ \"$installed_size\" = \"$candidate_size\" ]",
        f"installed_sha=$(sha256sum -- \"$manifest_tmp\" | awk '{{print $1}}') && [ \"$installed_sha\" = {sh_quote(expected_candidate_sha256)} ]",
        "rm -rf -- \"$manifest_quarantine_root\"",
        "manifest_quarantine_root=; manifest_quarantine=",
        compare_command,
        "chmod 0644 -- \"$manifest_tmp\"",
        f"mv -fT -- \"$manifest_tmp\" {sh_quote(manifest_path)}",
        "manifest_tmp=",
        "{ cleanup_manifest_tmp; trap - EXIT HUP INT TERM; }",
    ])
    return " && ".join([
        remote_server_dir_validation_command(server_dir),
        (
            "cleanup_candidate_snapshot() { rm -f -- "
            f"{sh_quote(candidate_snapshot_path)} >/dev/null 2>&1 || true; }}"
        ),
        "{ trap 'cleanup_candidate_snapshot' EXIT; trap 'cleanup_candidate_snapshot; exit 74' HUP INT TERM; }",
        (
            f"test -f {sh_quote(candidate_path)} && ! test -L {sh_quote(candidate_path)} || "
            "{ echo 'uploaded candidate manifest is not a regular file' >&2; exit 65; }"
        ),
        (
            f"if test -e {sh_quote(candidate_snapshot_path)} || test -L {sh_quote(candidate_snapshot_path)}; then "
            "echo 'random candidate manifest snapshot path already exists' >&2; exit 75; fi"
        ),
        f"install -m 0600 -- {sh_quote(candidate_path)} {sh_quote(candidate_snapshot_path)}",
        f"snapshot_size=$(stat -c %s -- {sh_quote(candidate_snapshot_path)})",
        (
            f"[ \"$snapshot_size\" -gt 0 ] && [ \"$snapshot_size\" -le {MAX_MANIFEST_RESPONSE_BYTES} ] || "
            "{ echo 'uploaded candidate manifest exceeds the client-compatible 1 MiB limit' >&2; exit 65; }"
        ),
        f"snapshot_sha=$(sha256sum -- {sh_quote(candidate_snapshot_path)} | awk '{{print $1}}')",
        (
            f"[ \"$snapshot_sha\" = {sh_quote(expected_candidate_sha256)} ] || "
            "{ echo 'uploaded candidate manifest sha256 does not match the locally verified envelope' >&2; exit 65; }"
        ),
        f"sudo flock -x -w 60 {sh_quote(lock_path)} sh -c {sh_quote(locked_command)}",
        "{ cleanup_candidate_snapshot; trap - EXIT HUP INT TERM; }",
        f"rm -rf -- {sh_quote(remote_tmp)} >/dev/null 2>&1 || true",
    ])


def verify_manifest(
    manifest_path: Path,
    private_key: Path,
    expected_version: str,
    required_platforms: set[str],
    auto_install: bool,
    expected_payload_schema: int = 1,
    expected_policy_generation: int | None = None,
    expected_android_version_code: int | None = None,
) -> None:
    payload, payload_bytes, signature = decode_manifest_envelope(read_manifest_bytes(manifest_path))
    if payload.get("schema") != expected_payload_schema:
        raise SystemExit(f"Unexpected manifest payload schema: {payload.get('schema')!r}")
    if expected_payload_schema == 1:
        if "releasePolicy" in payload:
            raise SystemExit("Payload schema 1 must not contain releasePolicy")
    elif expected_payload_schema == 2:
        policy = payload.get("releasePolicy")
        if not isinstance(policy, dict) or policy.get("schema") != 2:
            raise SystemExit("Payload schema 2 must contain releasePolicy schema 2")
        generation = policy.get("generation")
        if isinstance(generation, bool) or not isinstance(generation, int) or generation <= 0:
            raise SystemExit("Payload schema 2 releasePolicy has invalid generation")
        if expected_policy_generation is not None and generation != expected_policy_generation:
            raise SystemExit(
                f"Generated policy generation {generation!r} does not match requested generation "
                f"{expected_policy_generation!r}"
            )
    else:
        raise SystemExit(f"Unsupported expected payload schema: {expected_payload_schema!r}")
    if payload.get("version") != expected_version:
        raise SystemExit(
            f"Generated manifest version {payload.get('version')!r} does not match requested version {expected_version!r}"
        )
    platforms = payload.get("platforms", {})
    missing = sorted(required_platforms - set(platforms))
    if missing:
        raise SystemExit("Generated manifest is missing required platforms: " + ", ".join(missing))
    for platform, artifact in platforms.items():
        if not isinstance(artifact, dict):
            raise SystemExit(f"Generated manifest platform {platform} must be an object")
        url = artifact.get("url")
        parsed_url = urlparse(url) if isinstance(url, str) else None
        if not isinstance(url, str) or not parsed_url:
            raise SystemExit(f"Generated manifest platform {platform} is missing a URL")
        sha256 = artifact.get("sha256")
        size = artifact.get("size")
        local_android_artifact = is_android_platform(platform) and not artifact.get("openExternal")
        if "versionCode" in artifact:
            if not is_android_platform(platform):
                raise SystemExit(
                    f"Generated manifest platform {platform} must not contain Android versionCode"
                )
            validate_android_version_code(artifact.get("versionCode"))
        if expected_payload_schema == 2 and local_android_artifact and "versionCode" not in artifact:
            raise SystemExit(
                f"Generated manifest platform {platform} is missing signed Android versionCode"
            )
        if (
            expected_android_version_code is not None
            and local_android_artifact
            and artifact.get("versionCode") != expected_android_version_code
        ):
            raise SystemExit(
                f"Generated manifest platform {platform} versionCode does not match the requested Android versionCode"
            )
        if artifact.get("openExternal"):
            if not parsed_url.scheme:
                raise SystemExit(f"Generated manifest platform {platform} external URL must be absolute")
            if not is_allowed_external_update_url(platform, url):
                raise SystemExit(f"Generated manifest platform {platform} external URL has unsupported scheme")
            if sha256 is not None and not is_sha256_hex(sha256):
                raise SystemExit(f"Generated manifest platform {platform} has invalid sha256")
            if size is not None and (not isinstance(size, int) or size <= 0):
                raise SystemExit(f"Generated manifest platform {platform} has invalid size")
        else:
            if parsed_url.scheme:
                if parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
                    raise SystemExit(f"Generated manifest platform {platform} URL must use http(s)")
            elif not url.startswith("files/") or ".." in Path(url).parts:
                raise SystemExit(f"Generated manifest platform {platform} relative URL must stay under files/")
            if not is_sha256_hex(sha256):
                raise SystemExit(f"Generated manifest platform {platform} is missing or has invalid sha256")
            if not isinstance(size, int) or size <= 0:
                raise SystemExit(f"Generated manifest platform {platform} is missing a positive size")
    if auto_install:
        if payload.get("autoInstall") is not True:
            raise SystemExit("Generated manifest is missing top-level autoInstall=true")
        for platform, artifact in platforms.items():
            if artifact.get("autoInstall") is not True:
                raise SystemExit(f"Generated manifest is missing autoInstall=true for {platform}")

    verify_manifest_signature(private_key, payload_bytes, signature)


def local_files_path_from_url(url: object) -> str | None:
    if not isinstance(url, str):
        return None
    parsed = urlparse(url)
    if parsed.scheme == "itms-services":
        manifest_urls = parse_qs(parsed.query).get("url", [])
        return local_files_path_from_url(manifest_urls[0]) if manifest_urls else None
    path_text = unquote(parsed.path if parsed.scheme else url)
    if path_text.startswith("files/"):
        relative = path_text
    else:
        marker = "/files/"
        marker_index = path_text.rfind(marker)
        if marker_index < 0:
            return None
        relative = path_text[marker_index + 1:]
    parts = PurePosixPath(relative).parts
    if not parts or parts[0] != "files" or any(part in {"", ".", ".."} for part in parts):
        return None
    return "/".join(parts)


def signed_local_file_expectations(manifest_data: bytes) -> dict[str, tuple[str, int]]:
    payload, _payload_bytes, _signature = decode_manifest_envelope(manifest_data)
    expectations: dict[str, tuple[str, int]] = {}

    def add_expected(relative_path: str | None, digest: object, size: object, label: str) -> None:
        if (
            relative_path is None
            or not is_sha256_hex(digest)
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
        ):
            raise SystemExit(f"Signed {label} has invalid local file metadata")
        expected = (str(digest).lower(), size)
        if relative_path in expectations and expectations[relative_path] != expected:
            raise SystemExit(f"Signed manifest binds {relative_path} to conflicting metadata")
        expectations[relative_path] = expected

    def add_artifact(artifact: object, label: str) -> None:
        if not isinstance(artifact, dict):
            return
        if artifact.get("openExternal") is True:
            ipa_url = artifact.get("ipaUrl")
            plist_url = artifact.get("plistUrl")
            if ipa_url is None and plist_url is None:
                return
            add_expected(
                local_files_path_from_url(ipa_url),
                artifact.get("sha256"),
                artifact.get("size"),
                label + " IPA",
            )
            plist_path = local_files_path_from_url(plist_url)
            plist_parts = PurePosixPath(plist_path).parts if plist_path else ()
            plist_digest = plist_parts[2] if len(plist_parts) >= 4 and plist_parts[:2] == ("files", "artifacts") else None
            add_expected(plist_path, plist_digest, 0, label + " plist")
            return
        relative_path = local_files_path_from_url(artifact.get("url"))
        digest = artifact.get("sha256")
        size = artifact.get("size")
        if (
            relative_path is None
            or not is_sha256_hex(digest)
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size <= 0
        ):
            raise SystemExit(f"Signed {label} has invalid local file metadata")
        add_expected(relative_path, digest, size, label)

    platforms = payload.get("platforms")
    if isinstance(platforms, dict):
        for platform, artifact in platforms.items():
            add_artifact(artifact, f"platform {platform}")
    policy = payload.get("releasePolicy")
    rollback = policy.get("rollback") if isinstance(policy, dict) else None
    rollback_platforms = rollback.get("platforms") if isinstance(rollback, dict) else None
    if isinstance(rollback_platforms, dict):
        for platform, artifact in rollback_platforms.items():
            add_artifact(artifact, f"rollback platform {platform}")
    return expectations


def verify_staged_release_files(
    out_dir: Path,
    manifest_data: bytes,
    *,
    allow_unreferenced_rollback: bool = False,
    candidate_only: bool = False,
) -> None:
    """Bind every signed local/rollback file and every content-addressed artifact to staged bytes."""

    expectations = signed_local_file_expectations(manifest_data)
    files_dir = out_dir / "files"
    require_real_local_directory(files_dir, "Staged signed files tree")
    top_entries = {entry.name for entry in files_dir.iterdir()}
    unexpected_top = top_entries - {"artifacts", "rollback"}
    if unexpected_top:
        raise SystemExit(
            "Staged signed files tree contains unexpected entries: " + ", ".join(sorted(unexpected_top))
        )

    seen: set[str] = set()
    artifacts_dir = files_dir / "artifacts"
    if not candidate_only and (artifacts_dir.exists() or is_link_or_junction(artifacts_dir)):
        require_real_local_directory(artifacts_dir, "Staged content-addressed artifacts")
        for digest_dir in artifacts_dir.iterdir():
            require_real_local_directory(digest_dir, "Staged artifact digest directory")
            if not SHA256_RE.fullmatch(digest_dir.name):
                raise SystemExit(f"Invalid staged artifact digest directory: {digest_dir.name}")
            artifact_files = list(digest_dir.iterdir())
            if not artifact_files:
                raise SystemExit(f"Empty staged artifact digest directory: {digest_dir.name}")
            for artifact_file in artifact_files:
                if is_link_or_junction(artifact_file) or not artifact_file.is_file():
                    raise SystemExit(f"Staged artifact is not a regular file: {artifact_file}")
                if file_sha256(artifact_file) != digest_dir.name:
                    raise SystemExit(f"Staged artifact bytes do not match digest path: {artifact_file}")
                seen.add(artifact_file.relative_to(out_dir).as_posix())

    rollback_dir = files_dir / "rollback"
    if not candidate_only and (rollback_dir.exists() or is_link_or_junction(rollback_dir)):
        require_real_local_directory(rollback_dir, "Staged rollback tree")
        for path in rollback_dir.rglob("*"):
            if is_link_or_junction(path):
                raise SystemExit(f"Staged rollback tree contains a link: {path}")
            if path.is_dir():
                continue
            if not path.is_file():
                raise SystemExit(f"Staged rollback tree contains a special file: {path}")
            relative_path = path.relative_to(out_dir).as_posix()
            expected = expectations.get(relative_path)
            if expected is None:
                if allow_unreferenced_rollback:
                    continue
                raise SystemExit(f"Staged rollback file is not signed by the candidate manifest: {relative_path}")
            digest, size = expected
            if path.stat().st_size != size or file_sha256(path) != digest:
                raise SystemExit(f"Staged rollback file does not match signed size/sha256: {relative_path}")
            seen.add(relative_path)

    for relative_path, (digest, size) in expectations.items():
        path = out_dir.joinpath(*PurePosixPath(relative_path).parts)
        reject_link_like_components(path, "signed staged file verification")
        if is_link_or_junction(path) or not path.is_file():
            raise SystemExit(f"Signed staged file is missing or not regular: {relative_path}")
        if (size > 0 and path.stat().st_size != size) or file_sha256(path) != digest:
            raise SystemExit(f"Signed staged file does not match signed size/sha256: {relative_path}")
        seen.add(relative_path)


def upload_release(
    args: argparse.Namespace,
    out_dir: Path,
    expected_current_manifest_sha256: str | None,
    expected_candidate_manifest_sha256: str | None = None,
) -> None:
    remote_tmp = f"/tmp/amnezia-client-updates-{secrets.token_hex(24)}"
    server_dir = validate_server_dir(args.server_dir)
    ssh = command_parts(args.ssh)
    scp = command_parts(args.scp)
    candidate_manifest_data = read_manifest_bytes(out_dir / "manifest.json")
    observed_candidate_manifest_sha256 = hashlib.sha256(candidate_manifest_data).hexdigest()
    if expected_candidate_manifest_sha256 is None:
        expected_candidate_manifest_sha256 = observed_candidate_manifest_sha256
    elif not SHA256_RE.fullmatch(expected_candidate_manifest_sha256):
        raise ValueError("expected candidate manifest sha256 must be lowercase hexadecimal")
    if observed_candidate_manifest_sha256 != expected_candidate_manifest_sha256:
        raise SystemExit("Staged candidate manifest changed after signature and transition verification")
    verify_staged_release_files(out_dir, candidate_manifest_data)
    candidate_file_expectations = signed_local_file_expectations(candidate_manifest_data)
    for relative_path, (digest, size) in list(candidate_file_expectations.items()):
        if size == 0:
            local_path = out_dir.joinpath(*PurePosixPath(relative_path).parts)
            if is_link_or_junction(local_path) or not local_path.is_file():
                raise SystemExit(f"Signed staged file is missing before upload: {relative_path}")
            measured_size = local_path.stat().st_size
            if measured_size <= 0:
                raise SystemExit(f"Signed staged file must be nonempty before upload: {relative_path}")
            candidate_file_expectations[relative_path] = (digest, measured_size)

    validate_remote_server_dir(args)
    cleanup_remote_staging = True
    try:
        run(ssh + [
            args.server,
            f"umask 077 && mkdir -m 0700 -- {sh_quote(remote_tmp)}",
        ])
        run(scp + [str(out_dir / "manifest.json"), args.server + ":" + remote_tmp + "/manifest.json"])
        run(scp + ["-r", str(out_dir / "files"), args.server + ":" + remote_tmp + "/files"])
        run_remote_script(
            ssh,
            args.server,
            publish_files_remote_command(
                server_dir,
                remote_tmp,
                expected_current_manifest_sha256,
                candidate_file_expectations,
            ),
        )

        if not args.no_install_host:
            run(ssh + [args.server, f"sh -s -- {sh_quote(server_dir)}"], stdin_path=INSTALL_HOST)

        run_remote_script(
            ssh,
            args.server,
            publish_manifest_remote_command(
                server_dir,
                remote_tmp,
                expected_current_manifest_sha256,
                expected_candidate_manifest_sha256,
            ),
        )
        cleanup_remote_staging = False
    finally:
        if cleanup_remote_staging:
            subprocess.run(
                ssh + [args.server, f"rm -rf -- {sh_quote(remote_tmp)}"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )


def securely_open_local_lock_file(lock_path: Path):
    """Open a regular, unlinked lock file without following a predictable symlink."""

    reject_link_like_components(lock_path.parent, "local publication lock parent")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    reject_link_like_components(lock_path, "local publication lock")
    if os.name != "nt":
        parent_status = os.stat(lock_path.parent, follow_symlinks=False)
        if (
            parent_status.st_uid != os.geteuid()
            or parent_status.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise SystemExit(
                "Local publication lock parent must be publisher-owned and not group/other-writable: "
                f"{lock_path.parent}"
            )
    base_flags = os.O_RDWR | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(lock_path, base_flags | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        if is_link_or_junction(lock_path):
            raise SystemExit(f"Refusing linked local publication lock: {lock_path}")
        try:
            path_before = os.stat(lock_path, follow_symlinks=False)
        except OSError as error:
            raise SystemExit(f"Unable to inspect local publication lock: {lock_path}") from error
        if not stat.S_ISREG(path_before.st_mode) or path_before.st_nlink != 1:
            raise SystemExit(f"Local publication lock must be one regular, unlinked file: {lock_path}")
        try:
            descriptor = os.open(lock_path, base_flags | getattr(os, "O_NOFOLLOW", 0))
        except OSError as error:
            raise SystemExit(f"Unable to securely open local publication lock: {lock_path}") from error

    try:
        opened = os.fstat(descriptor)
        path_after = os.stat(lock_path, follow_symlinks=False)
        if (
            not stat.S_ISREG(opened.st_mode)
            or not stat.S_ISREG(path_after.st_mode)
            or opened.st_nlink != 1
            or path_after.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (path_after.st_dev, path_after.st_ino)
        ):
            raise SystemExit(f"Local publication lock changed while it was opened: {lock_path}")
        if os.name != "nt" and (
            opened.st_uid != os.geteuid()
            or opened.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise SystemExit(
                "Local publication lock must be publisher-owned and not group/other-writable: "
                f"{lock_path}"
            )
        return os.fdopen(descriptor, "r+b")
    except BaseException:
        os.close(descriptor)
        raise


@contextmanager
def local_publish_lock(lock_path: Path, timeout_seconds: float = 60.0):
    """Hold a standard-library advisory lock shared by Windows and POSIX publishers."""

    handle = securely_open_local_lock_file(lock_path)
    handle.seek(0, os.SEEK_END)
    if handle.tell() == 0:
        handle.write(b"\0")
        handle.flush()

    acquired = False
    deadline = time.monotonic() + timeout_seconds
    try:
        if os.name == "nt":
            import msvcrt

            while not acquired:
                try:
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                    acquired = True
                except OSError:
                    if time.monotonic() >= deadline:
                        raise SystemExit(f"Timed out waiting for local publication lock: {lock_path}")
                    time.sleep(0.1)
        else:
            import fcntl

            while not acquired:
                try:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    acquired = True
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise SystemExit(f"Timed out waiting for local publication lock: {lock_path}")
                    time.sleep(0.1)
        locked_handle_status = os.fstat(handle.fileno())
        locked_path_status = os.stat(lock_path, follow_symlinks=False)
        if (
            not stat.S_ISREG(locked_path_status.st_mode)
            or locked_path_status.st_nlink != 1
            or (locked_handle_status.st_dev, locked_handle_status.st_ino)
            != (locked_path_status.st_dev, locked_path_status.st_ino)
        ):
            raise SystemExit(f"Local publication lock pathname changed after acquisition: {lock_path}")
        yield
    finally:
        if acquired:
            handle.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        handle.close()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fsync_directory_best_effort(path: Path) -> None:
    """Persist directory entries where the host supports directory fsync."""

    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        os.close(descriptor)


def require_real_local_directory(path: Path, label: str) -> None:
    if is_link_or_junction(path) or not path.is_dir():
        raise SystemExit(f"{label} must be a real directory: {path}")


def copy_immutable_local_file(
    source: Path,
    target: Path,
    expected: tuple[str, int | None] | None = None,
) -> None:
    """Install one immutable file without overwriting an existing path."""

    if is_link_or_junction(source) or not source.is_file():
        raise SystemExit(f"Staged local release contains a non-regular file: {source}")
    expected_digest, expected_size = expected or (None, None)
    if expected_digest is not None and not SHA256_RE.fullmatch(expected_digest):
        raise ValueError(f"Invalid immutable local file digest binding: {expected_digest!r}")

    def verify_fixed_binding(path: Path) -> bool:
        return (
            (expected_size is None or path.stat().st_size == expected_size)
            and (expected_digest is None or file_sha256(path) == expected_digest)
        )

    if target.exists() or target.is_symlink():
        if is_link_or_junction(target) or not target.is_file():
            raise SystemExit(f"Immutable local release target is not a regular file: {target}")
        if expected is not None:
            matches = verify_fixed_binding(target)
        else:
            matches = source.stat().st_size == target.stat().st_size and file_sha256(source) == file_sha256(target)
        if not matches:
            raise SystemExit(f"Immutable local release target already has different content: {target}")
        return

    temporary_handle = tempfile.NamedTemporaryFile(
        prefix=f".{target.name}.publish-",
        dir=target.parent,
        delete=False,
    )
    temporary_path = Path(temporary_handle.name)
    try:
        with temporary_handle, source.open("rb") as source_handle:
            shutil.copyfileobj(source_handle, temporary_handle, length=1024 * 1024)
            temporary_handle.flush()
            os.fsync(temporary_handle.fileno())
        if expected is not None:
            copied_correctly = verify_fixed_binding(temporary_path)
        else:
            copied_correctly = (
                source.stat().st_size == temporary_path.stat().st_size
                and file_sha256(source) == file_sha256(temporary_path)
            )
        if not copied_correctly:
            raise SystemExit(f"Local immutable staging copy failed verification: {source}")
        try:
            temporary_path.chmod(0o644)
        except OSError:
            pass
        try:
            os.link(temporary_path, target)
        except FileExistsError:
            if is_link_or_junction(target) or not target.is_file():
                raise SystemExit(f"Immutable local release target raced with a non-file: {target}")
            if expected is not None:
                raced_correctly = verify_fixed_binding(target)
            else:
                raced_correctly = (
                    source.stat().st_size == target.stat().st_size
                    and file_sha256(source) == file_sha256(target)
                )
            if not raced_correctly:
                raise SystemExit(f"Immutable local release target raced with different content: {target}")
        fsync_directory_best_effort(target.parent)
    finally:
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass


def merge_immutable_local_tree(
    source: Path,
    target: Path,
    expectations: dict[str, tuple[str, int]] | None = None,
    *,
    source_root: Path | None = None,
) -> None:
    """Merge a staged immutable tree, rejecting links, special files, and rebinding."""

    if source_root is None:
        source_root = source
    require_real_local_directory(source, "Staged local release tree")
    if target.exists() or target.is_symlink():
        require_real_local_directory(target, "Local release tree")
    else:
        target.mkdir(mode=0o755)
        fsync_directory_best_effort(target.parent)

    for entry in sorted(source.iterdir(), key=lambda path: path.name):
        destination = target / entry.name
        if is_link_or_junction(entry):
            raise SystemExit(f"Staged local release contains a symlink or junction: {entry}")
        if entry.is_dir():
            merge_immutable_local_tree(
                entry,
                destination,
                expectations,
                source_root=source_root,
            )
        elif entry.is_file():
            expected: tuple[str, int | None] | None = None
            if expectations is not None:
                relative_parts = entry.relative_to(source_root).parts
                relative_path = PurePosixPath("files", *relative_parts).as_posix()
                signed_expected = expectations.get(relative_path)
                if signed_expected is not None:
                    digest, size = signed_expected
                    expected = (digest, size if size > 0 else None)
                else:
                    raise SystemExit(
                        f"Staged immutable file has no signed or content-addressed binding: {relative_path}"
                    )
            copy_immutable_local_file(entry, destination, expected)
        else:
            raise SystemExit(f"Staged local release contains a special file: {entry}")


def current_local_manifest_sha256(out_dir: Path) -> str | None:
    current_manifest_path = out_dir / "manifest.json"
    if is_link_or_junction(current_manifest_path):
        raise SystemExit("Refusing to replace a local channel whose manifest is a symlink or junction")
    if current_manifest_path.exists() and not current_manifest_path.is_file():
        raise SystemExit("Refusing to replace a local channel whose manifest path is not a regular file")
    if not current_manifest_path.is_file():
        return None
    return hashlib.sha256(read_manifest_bytes(current_manifest_path)).hexdigest()


def retry_intent_projection(
    manifest_data: bytes,
    private_key: Path,
    *,
    ignore_generated_clock: bool = False,
) -> dict[str, object]:
    """Ignore only generator-clock fields when recognizing a resumed publication."""

    payload, _payload_bytes = verified_manifest_payload(manifest_data, private_key)
    projection = dict(payload)
    policy = projection.get("releasePolicy")
    if isinstance(policy, dict) and ignore_generated_clock:
        projected_policy = dict(policy)
        generated_at = projected_policy.get("generatedAt")
        expires_at = projected_policy.get("expiresAt")
        if not (
            isinstance(generated_at, str)
            and isinstance(expires_at, str)
            and generated_at.endswith("Z")
            and expires_at.endswith("Z")
        ):
            raise SystemExit("Signed release policy has invalid generatedAt/expiresAt values")
        try:
            generated = datetime.fromisoformat(generated_at[:-1] + "+00:00")
            expires = datetime.fromisoformat(expires_at[:-1] + "+00:00")
        except ValueError as error:
            raise SystemExit("Signed release policy has invalid generatedAt/expiresAt values") from error
        validity_microseconds = int((expires - generated).total_seconds() * 1_000_000)
        if validity_microseconds <= 0:
            raise SystemExit("Signed release policy has a non-positive validity duration")
        projected_policy.pop("generatedAt", None)
        projected_policy.pop("expiresAt", None)
        projected_policy["__retryValidityMicroseconds"] = validity_microseconds
        projection["releasePolicy"] = projected_policy
    return projection


def manifest_policy_is_fresh(manifest_data: bytes, private_key: Path) -> bool:
    payload, _payload_bytes = verified_manifest_payload(manifest_data, private_key)
    policy = payload.get("releasePolicy")
    if not isinstance(policy, dict):
        return True
    expires_at = policy.get("expiresAt")
    if not isinstance(expires_at, str) or not expires_at.endswith("Z"):
        return False
    try:
        expiry = datetime.fromisoformat(expires_at[:-1] + "+00:00")
    except ValueError:
        return False
    return expiry > datetime.now(timezone.utc)


def prepared_manifest_paths(out_dir: Path) -> list[Path]:
    if not out_dir.is_dir() or is_link_or_junction(out_dir):
        return []
    return sorted(out_dir.glob(".manifest.publish-*"), key=lambda path: path.name)


def cleanup_stale_prepared_manifests(out_dir: Path, keep_data: bytes | None = None) -> None:
    for candidate in prepared_manifest_paths(out_dir):
        if is_link_or_junction(candidate) or not candidate.is_file():
            continue
        try:
            candidate_data = read_manifest_bytes(candidate)
        except SystemExit:
            candidate_data = None
        if keep_data is not None and candidate_data == keep_data:
            continue
        try:
            candidate.unlink()
        except OSError:
            pass


def reconcile_prepared_remote_manifest(
    out_dir: Path,
    current_local_manifest_data: bytes | None,
    remote_manifest_data: bytes | None,
    private_key: Path,
) -> bool:
    """Finish a local commit when a prior process already committed the exact remote envelope."""

    if remote_manifest_data is None:
        cleanup_stale_prepared_manifests(out_dir)
        return False
    if current_local_manifest_data == remote_manifest_data:
        cleanup_stale_prepared_manifests(out_dir)
        return False

    matching_path: Path | None = None
    for candidate in prepared_manifest_paths(out_dir):
        if is_link_or_junction(candidate) or not candidate.is_file():
            continue
        try:
            if read_manifest_bytes(candidate) == remote_manifest_data:
                matching_path = candidate
                break
        except SystemExit:
            continue
    if matching_path is None:
        cleanup_stale_prepared_manifests(out_dir)
        return False

    expected_current_sha256 = validate_publish_transition(
        current_local_manifest_data,
        remote_manifest_data,
        private_key,
    )
    remote_sha256 = hashlib.sha256(remote_manifest_data).hexdigest()
    commit_release_output_locked(
        matching_path,
        out_dir,
        expected_current_sha256,
        remote_sha256,
    )
    cleanup_stale_prepared_manifests(out_dir)
    return True


def prepare_local_manifest(source_manifest: Path, out_dir: Path) -> Path:
    """Write and verify the candidate manifest without making it live."""

    if is_link_or_junction(source_manifest) or not source_manifest.is_file():
        raise SystemExit("Staged local channel manifest must be a regular file")
    manifest_data = read_manifest_bytes(source_manifest)
    temporary_handle = tempfile.NamedTemporaryFile(
        prefix=".manifest.publish-",
        dir=out_dir,
        delete=False,
    )
    temporary_path = Path(temporary_handle.name)
    try:
        with temporary_handle:
            temporary_handle.write(manifest_data)
            temporary_handle.flush()
            os.fsync(temporary_handle.fileno())
        if read_manifest_bytes(temporary_path) != manifest_data:
            raise SystemExit("Local candidate manifest failed post-copy verification")
        try:
            temporary_path.chmod(0o644)
        except OSError:
            pass
        fsync_directory_best_effort(out_dir)
        return temporary_path
    except BaseException:
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass
        raise


def commit_prepared_local_manifest(
    prepared_manifest: Path,
    out_dir: Path,
    expected_candidate_manifest_sha256: str,
) -> None:
    """Atomically make an already durable candidate manifest live."""

    if not SHA256_RE.fullmatch(expected_candidate_manifest_sha256):
        raise ValueError("expected candidate manifest sha256 must be lowercase hexadecimal")
    if is_link_or_junction(prepared_manifest) or not prepared_manifest.is_file():
        raise SystemExit("Prepared local channel manifest must be a regular file")
    prepared_manifest_data = read_manifest_bytes(prepared_manifest)
    if hashlib.sha256(prepared_manifest_data).hexdigest() != expected_candidate_manifest_sha256:
        raise SystemExit("Prepared local channel manifest changed after verification")
    verify_staged_release_files(
        out_dir,
        prepared_manifest_data,
        allow_unreferenced_rollback=True,
        candidate_only=True,
    )
    current_manifest_path = out_dir / "manifest.json"
    if current_manifest_path.is_file() and not is_link_or_junction(current_manifest_path):
        try:
            current_mode = current_manifest_path.stat(follow_symlinks=False).st_mode
            if os.name == "nt":
                os.chmod(current_manifest_path, current_mode | stat.S_IWRITE)
            else:
                os.chmod(
                    current_manifest_path,
                    current_mode | stat.S_IWUSR,
                    follow_symlinks=False,
                )
        except (NotImplementedError, OSError):
            pass
    os.replace(prepared_manifest, current_manifest_path)
    fsync_directory_best_effort(out_dir)


def prepare_release_output_locked(
    staged_out_dir: Path,
    out_dir: Path,
    expected_current_manifest_sha256: str | None,
    expected_candidate_manifest_sha256: str,
) -> Path:
    """Prepare immutable files and a durable manifest while the old manifest stays live."""

    if expected_current_manifest_sha256 is not None and not SHA256_RE.fullmatch(
        expected_current_manifest_sha256
    ):
        raise ValueError("expected local manifest sha256 must be lowercase hexadecimal")
    if not SHA256_RE.fullmatch(expected_candidate_manifest_sha256):
        raise ValueError("expected candidate manifest sha256 must be lowercase hexadecimal")
    reject_link_like_components(out_dir, "local channel output preparation")
    require_real_local_directory(staged_out_dir, "Staged local channel output")
    staged_manifest_data = read_manifest_bytes(staged_out_dir / "manifest.json")
    if hashlib.sha256(staged_manifest_data).hexdigest() != expected_candidate_manifest_sha256:
        raise SystemExit("Staged candidate manifest changed before local output preparation")
    verify_staged_release_files(staged_out_dir, staged_manifest_data)
    if current_local_manifest_sha256(out_dir) != expected_current_manifest_sha256:
        raise SystemExit(
            "Local update channel changed during publication; refusing stale output preparation"
        )
    staged_entries = {entry.name for entry in staged_out_dir.iterdir()}
    unexpected_entries = staged_entries - {"manifest.json", "files"}
    if unexpected_entries:
        raise SystemExit(
            "Staged local release contains unexpected top-level entries: "
            + ", ".join(sorted(unexpected_entries))
        )
    if out_dir.exists() or is_link_or_junction(out_dir):
        require_real_local_directory(out_dir, "Local channel output")
    else:
        out_dir.mkdir(mode=0o755)
        fsync_directory_best_effort(out_dir.parent)
    staged_files = staged_out_dir / "files"
    if staged_files.exists() or is_link_or_junction(staged_files):
        merge_immutable_local_tree(
            staged_files,
            out_dir / "files",
            signed_local_file_expectations(staged_manifest_data),
        )
    verify_staged_release_files(
        out_dir,
        staged_manifest_data,
        allow_unreferenced_rollback=True,
    )
    if current_local_manifest_sha256(out_dir) != expected_current_manifest_sha256:
        raise SystemExit(
            "Local update channel changed while immutable files were copied; "
            "refusing a stale manifest preparation"
        )
    return prepare_local_manifest(staged_out_dir / "manifest.json", out_dir)


def commit_release_output_locked(
    prepared_manifest: Path,
    out_dir: Path,
    expected_current_manifest_sha256: str | None,
    expected_candidate_manifest_sha256: str,
) -> None:
    """CAS-commit a prepared manifest while the caller holds the publish lock."""

    reject_link_like_components(out_dir, "local channel manifest commit")
    if current_local_manifest_sha256(out_dir) != expected_current_manifest_sha256:
        raise SystemExit(
            "Local update channel changed after preparation; refusing a stale manifest switch"
        )
    commit_prepared_local_manifest(
        prepared_manifest,
        out_dir,
        expected_candidate_manifest_sha256,
    )


def replace_release_output_locked(
    staged_out_dir: Path,
    out_dir: Path,
    expected_current_manifest_sha256: str | None,
    expected_candidate_manifest_sha256: str | None = None,
) -> None:
    """CAS-replace a local channel output while the caller holds its publish lock."""

    if expected_current_manifest_sha256 is not None and not SHA256_RE.fullmatch(
        expected_current_manifest_sha256
    ):
        raise ValueError("expected local manifest sha256 must be lowercase hexadecimal")
    reject_link_like_components(out_dir, "local channel output replacement")
    if current_local_manifest_sha256(out_dir) != expected_current_manifest_sha256:
        raise SystemExit(
            "Local update channel changed during publication; refusing a stale output replacement"
        )

    observed_candidate_manifest_sha256 = hashlib.sha256(
        read_manifest_bytes(staged_out_dir / "manifest.json")
    ).hexdigest()
    if expected_candidate_manifest_sha256 is None:
        expected_candidate_manifest_sha256 = observed_candidate_manifest_sha256
    elif observed_candidate_manifest_sha256 != expected_candidate_manifest_sha256:
        raise SystemExit("Staged candidate manifest changed after transition verification")
    if out_dir.is_dir() or not out_dir.exists():
        prepared_manifest = prepare_release_output_locked(
            staged_out_dir,
            out_dir,
            expected_current_manifest_sha256,
            expected_candidate_manifest_sha256,
        )
        try:
            commit_release_output_locked(
                prepared_manifest,
                out_dir,
                expected_current_manifest_sha256,
                expected_candidate_manifest_sha256,
            )
        finally:
            try:
                prepared_manifest.unlink()
            except FileNotFoundError:
                pass
        return

    backup_path: Path | None = None
    if out_dir.exists():
        backup_path = Path(tempfile.mkdtemp(prefix=f".{out_dir.name}.previous-", dir=out_dir.parent))
        backup_path.rmdir()
        os.replace(out_dir, backup_path)
    try:
        os.replace(staged_out_dir, out_dir)
    except Exception:
        if backup_path is not None and backup_path.exists() and not out_dir.exists():
            os.replace(backup_path, out_dir)
        raise
    if backup_path is not None:
        cleanup_replaced_output_backup(backup_path)


def replace_release_output(
    staged_out_dir: Path,
    out_dir: Path,
    expected_current_manifest_sha256: str | None,
) -> None:
    """CAS-replace a local channel output under an inter-process lock."""

    out_dir = lexical_absolute_path(out_dir)
    reject_link_like_components(out_dir, "local channel output publication")
    lock_path = out_dir.parent / f".{out_dir.name}.publish.lock"
    with local_publish_lock(lock_path):
        replace_release_output_locked(
            staged_out_dir,
            out_dir,
            expected_current_manifest_sha256,
        )


def cleanup_replaced_output_backup(backup_path: Path) -> None:
    """Best-effort cleanup that cannot turn a successful atomic switch into failure."""

    def make_writable_and_retry(function, path: str, _error_info) -> None:
        current_mode = os.stat(path, follow_symlinks=False).st_mode
        os.chmod(
            path,
            current_mode | stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR,
            follow_symlinks=False,
        )
        function(path)

    try:
        if backup_path.is_dir() and not backup_path.is_symlink():
            shutil.rmtree(backup_path, onerror=make_writable_and_retry)
        elif backup_path.exists() or backup_path.is_symlink():
            try:
                backup_path.chmod(backup_path.stat(follow_symlinks=False).st_mode | stat.S_IWUSR)
            except (NotImplementedError, OSError):
                pass
            backup_path.unlink()
    except Exception as error:
        print(
            f"Warning: published the new local update channel but could not remove old backup "
            f"{backup_path}: {error}",
            file=sys.stderr,
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--release-date", default="")
    parser.add_argument("--changelog-file", type=Path)
    parser.add_argument("--base-url", default="http://172.29.172.252:17865")
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--public-key-base64", default=os.environ.get("SELFHOSTED_UPDATE_PUBLIC_KEY_PEM_BASE64", ""))
    parser.add_argument("--artifact-dir", type=Path, default=Path("deploy/build"))
    parser.add_argument("--out-dir", type=Path)
    parser.add_argument("--artifact", action="append", default=[], help="Explicit platform=path, overrides autodiscovery")
    parser.add_argument(
        "--android-version-code",
        type=int,
        help=(
            "Signed Android package versionCode for every local Android artifact; "
            "required for Android in payload schema 2"
        ),
    )
    parser.add_argument("--external", action="append", default=[], help="platform=url, for TestFlight/App Store/MDM/etc.")
    parser.add_argument("--include-platform", action="append", default=[], help="Only include these platforms in the generated manifest")
    parser.add_argument("--ios-ipa", type=Path)
    parser.add_argument("--ios-bundle-id", default="org.amnezia.AmneziaVPN")
    parser.add_argument("--ios-bundle-version")
    parser.add_argument("--ios-title", default="AmneziaVPN")
    parser.add_argument("--require-platform", action="append", default=[])
    parser.add_argument("--download-github-release", action="store_true")
    parser.add_argument("--github-release-metadata", action="store_true")
    parser.add_argument("--github-repo", default="amnezia-vpn/amnezia-client")
    parser.add_argument("--github-token", default=os.environ.get("GITHUB_TOKEN"))
    parser.add_argument("--auto-install", action="store_true")
    parser.add_argument("--payload-schema", type=int, choices=(1, 2), default=1)
    parser.add_argument("--channel", choices=("stable", "canary", "emergency"), default="stable")
    parser.add_argument("--rollout-percentage", type=int, choices=range(0, 101), default=100)
    parser.add_argument("--cohort-salt-id", default=DEFAULT_COHORT_SALT_ID)
    parser.add_argument("--minimum-eligible-version", default="")
    parser.add_argument("--maximum-eligible-version", default="")
    parser.add_argument(
        "--health-deadline-seconds",
        type=int,
        choices=range(MIN_HEALTH_DEADLINE_SECONDS, 24 * 60 * 60 + 1),
        default=DEFAULT_HEALTH_DEADLINE_SECONDS,
    )
    parser.add_argument("--policy-generation", type=int)
    parser.add_argument("--generated-at", default="")
    expiry_group = parser.add_mutually_exclusive_group()
    expiry_group.add_argument("--expires-at", default="")
    expiry_group.add_argument(
        "--policy-valid-for-hours",
        type=int,
        choices=range(1, 365 * 24 + 1),
        default=DEFAULT_POLICY_VALIDITY_HOURS,
    )
    parser.add_argument("--previous-version", default="")
    parser.add_argument(
        "--rollback-artifact",
        action="append",
        default=[],
        help="platform=path for a previous-version rollback artifact; repeat per platform",
    )
    parser.add_argument("--server", help="SSH target, for example root@203.0.113.10")
    parser.add_argument("--server-dir", default="/opt/amnezia/client-updates")
    parser.add_argument("--ssh", default="ssh")
    parser.add_argument("--scp", default="scp")
    parser.add_argument("--no-install-host", action="store_true")
    args = parser.parse_args()
    args.version = validate_release_version(args.version)
    if args.android_version_code is not None:
        args.android_version_code = validate_android_version_code(args.android_version_code)
    if args.server:
        args.server_dir = validate_server_dir(args.server_dir)
    policy_command = release_policy_arguments(args)

    private_key = args.private_key.expanduser().resolve()
    if not private_key.is_file():
        raise SystemExit(f"Private key file does not exist: {private_key}")
    if args.server and not args.public_key_base64:
        raise SystemExit("--public-key-base64 or SELFHOSTED_UPDATE_PUBLIC_KEY_PEM_BASE64 is required when publishing to a server")
    if args.public_key_base64:
        verify_public_key_matches_private(args.public_key_base64, private_key)

    artifact_dir = args.artifact_dir.expanduser().resolve()
    explicit_artifacts = {
        platform: Path(path).expanduser().resolve()
        for platform, path in parse_platform_values(args.artifact, "--artifact").items()
    }
    missing_explicit = [f"{platform}={path}" for platform, path in explicit_artifacts.items() if not path.is_file()]
    if missing_explicit:
        raise SystemExit("Explicit update artifact does not exist: " + ", ".join(missing_explicit))
    rollback_artifacts = {
        platform: Path(path).expanduser().resolve()
        for platform, path in parse_platform_values(args.rollback_artifact, "--rollback-artifact").items()
    }
    missing_rollback = [f"{platform}={path}" for platform, path in rollback_artifacts.items() if not path.is_file()]
    if missing_rollback:
        raise SystemExit("Rollback update artifact does not exist: " + ", ".join(missing_rollback))
    externals = parse_platform_values(args.external, "--external")
    if args.download_github_release:
        download_known_release_assets(
            args.github_repo,
            args.version,
            artifact_dir,
            required_release_asset_platforms(args.require_platform, set(externals), set(explicit_artifacts)),
        )

    artifacts = discover_artifacts(artifact_dir, args.version)
    artifacts.update(explicit_artifacts)
    ios_ipa = args.ios_ipa.expanduser().resolve() if args.ios_ipa else discover_ios_ipa(artifact_dir, args.version)
    if "ios" in externals:
        ios_ipa = None
    if args.include_platform:
        included_platforms = set(args.include_platform)
        artifacts = {
            platform: path
            for platform, path in artifacts.items()
            if platform in included_platforms
        }
        externals = {
            platform: url
            for platform, url in externals.items()
            if platform in included_platforms
        }
        if "ios" not in included_platforms:
            ios_ipa = None

    local_android_platforms = sorted(
        platform for platform in artifacts if is_android_platform(platform)
    )
    if args.android_version_code is not None and not local_android_platforms:
        raise SystemExit("--android-version-code requires at least one local Android artifact")
    if args.payload_schema == 2 and local_android_platforms and args.android_version_code is None:
        raise SystemExit(
            "--android-version-code is required with --payload-schema 2 when a local Android artifact is included"
        )

    available_platforms = set(artifacts) | set(externals)
    if ios_ipa:
        available_platforms.add("ios")

    missing = [platform for platform in args.require_platform if platform not in available_platforms]
    if ios_ipa and not args.ios_bundle_id:
        missing.append("ios-bundle-id")
    if missing:
        raise SystemExit(
            "Missing required update artifacts/settings: "
            + ", ".join(missing_platform_messages(missing, artifact_dir, args.version))
        )
    if ios_ipa and not ios_ipa.is_file():
        raise SystemExit(f"iOS IPA file does not exist: {ios_ipa}")

    out_dir = lexical_absolute_path(args.out_dir or Path("dist") / "selfhosted-updates" / args.version)
    reject_link_like_components(out_dir, "local channel output publication")
    out_dir.parent.mkdir(parents=True, exist_ok=True)
    staging_directory = tempfile.TemporaryDirectory(prefix=f".{out_dir.name}.publish-", dir=out_dir.parent)
    staged_out_dir = Path(staging_directory.name) / "release"
    staged_out_dir.mkdir(parents=True)

    generated_changelog: Path | None = None
    release_date = args.release_date
    if args.github_release_metadata:
        metadata_release_date, metadata_changelog = fetch_github_release_metadata(
            args.github_repo, args.version, args.github_token
        )
        if not release_date:
            release_date = metadata_release_date
        if not args.changelog_file and metadata_changelog:
            generated_changelog = staged_out_dir / ".github-release-changelog.txt"
            generated_changelog.write_text(metadata_changelog.replace("\r", ""), encoding="utf-8")

    command = [
        sys.executable,
        str(MAKE_MANIFEST),
        "--version",
        args.version,
        "--release-date",
        release_date,
        "--base-url",
        args.base_url,
        "--private-key",
        str(private_key),
        "--out-dir",
        str(staged_out_dir),
    ]
    command += policy_command
    if args.android_version_code is not None:
        command += ["--android-version-code", str(args.android_version_code)]
    changelog_file = args.changelog_file or generated_changelog
    if changelog_file:
        command += ["--changelog-file", str(changelog_file.expanduser().resolve())]
    if args.auto_install:
        command.append("--auto-install")
    for platform, path in sorted(artifacts.items()):
        command += ["--artifact", f"{platform}={path}"]
    for platform, url in externals.items():
        command += ["--external", f"{platform}={url}"]
    if ios_ipa:
        command += [
            "--ios-ipa",
            str(ios_ipa),
            "--ios-bundle-id",
            args.ios_bundle_id,
            "--ios-title",
            args.ios_title,
        ]
        if args.ios_bundle_version:
            command += ["--ios-bundle-version", args.ios_bundle_version]

    run(command)
    verify_manifest(
        staged_out_dir / "manifest.json",
        private_key,
        args.version,
        set(args.require_platform),
        args.auto_install,
        args.payload_schema,
        args.policy_generation,
        args.android_version_code,
    )
    candidate_manifest_data = read_manifest_bytes(staged_out_dir / "manifest.json")
    verify_staged_release_files(staged_out_dir, candidate_manifest_data)
    candidate_manifest_sha256 = hashlib.sha256(candidate_manifest_data).hexdigest()
    lock_path = out_dir.parent / f".{out_dir.name}.publish.lock"
    with local_publish_lock(lock_path):
        reject_link_like_components(out_dir, "local channel output publication")
        current_local_manifest_path = out_dir / "manifest.json"
        if is_link_or_junction(current_local_manifest_path):
            raise SystemExit("Refusing to publish through a linked local channel manifest")
        if current_local_manifest_path.exists() and not current_local_manifest_path.is_file():
            raise SystemExit("Refusing to publish over a non-regular local channel manifest")
        existing_local_manifest_data = (
            read_manifest_bytes(current_local_manifest_path)
            if current_local_manifest_path.is_file()
            else None
        )
        expected_local_manifest_sha256 = validate_publish_transition(
            existing_local_manifest_data,
            candidate_manifest_data,
            private_key,
        )

        if args.server:
            published_manifest_data = fetch_remote_manifest(args)
            recovered_remote_commit = reconcile_prepared_remote_manifest(
                out_dir,
                existing_local_manifest_data,
                published_manifest_data,
                private_key,
            )
            if recovered_remote_commit:
                assert published_manifest_data is not None
                existing_local_manifest_data = published_manifest_data
                expected_local_manifest_sha256 = hashlib.sha256(
                    published_manifest_data
                ).hexdigest()
                ignore_generated_clock = not args.generated_at and not args.expires_at
                if (
                    manifest_policy_is_fresh(published_manifest_data, private_key)
                    and retry_intent_projection(
                        published_manifest_data,
                        private_key,
                        ignore_generated_clock=ignore_generated_clock,
                    )
                    == retry_intent_projection(
                        candidate_manifest_data,
                        private_key,
                        ignore_generated_clock=ignore_generated_clock,
                    )
                ):
                    staging_directory.cleanup()
                    print(
                        "Recovered the exact remote manifest from an interrupted prior local commit",
                        flush=True,
                    )
                    print(f"Output: {out_dir}", flush=True)
                    return 0
            expected_current_manifest_sha256 = validate_publish_transition(
                published_manifest_data,
                candidate_manifest_data,
                private_key,
            )
            prepared_manifest = prepare_release_output_locked(
                staged_out_dir,
                out_dir,
                expected_local_manifest_sha256,
                candidate_manifest_sha256,
            )
            preserve_prepared_manifest = True
            try:
                try:
                    upload_release(
                        args,
                        staged_out_dir,
                        expected_current_manifest_sha256,
                        candidate_manifest_sha256,
                    )
                except Exception as upload_error:
                    try:
                        observed_after_error = fetch_remote_manifest(args)
                    except Exception:
                        raise upload_error
                    if observed_after_error != candidate_manifest_data:
                        preserve_prepared_manifest = False
                        raise upload_error
                commit_release_output_locked(
                    prepared_manifest,
                    out_dir,
                    expected_local_manifest_sha256,
                    candidate_manifest_sha256,
                )
                preserve_prepared_manifest = False
            finally:
                if not preserve_prepared_manifest:
                    try:
                        prepared_manifest.unlink()
                    except FileNotFoundError:
                        pass
            print(f"Uploaded to {args.server}:{args.server_dir}", flush=True)
        else:
            replace_release_output_locked(
                staged_out_dir,
                out_dir,
                expected_local_manifest_sha256,
                candidate_manifest_sha256,
            )
    staging_directory.cleanup()
    print("Published manifest platforms:", ", ".join(sorted(available_platforms)), flush=True)
    print("Verified self-hosted update manifest signature and required platforms", flush=True)
    print(f"Output: {out_dir}", flush=True)

    return 0


if __name__ == "__main__":
    sys.exit(main())
