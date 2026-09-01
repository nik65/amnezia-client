#!/usr/bin/env python3
"""Build a signed self-hosted Amnezia update manifest.

The client verifies an Ed25519 signature over the exact payload bytes stored
inside the base64url manifest envelope. This avoids brittle JSON
canonicalization differences between Python and Qt.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import os
import plistlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from urllib.parse import parse_qs, quote, unquote, urlparse

VERSION_COMPONENT_PATTERN = r"(?:0|[1-9][0-9]*)"
VERSION_RE = re.compile(rf"^{VERSION_COMPONENT_PATTERN}(?:\.{VERSION_COMPONENT_PATTERN}){{3}}$")
COHORT_SALT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
PLATFORM_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
CANONICAL_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
RELEASE_CHANNELS = {"stable", "canary", "emergency"}
DEFAULT_POLICY_VALIDITY_HOURS = 7 * 24
DEFAULT_HEALTH_DEADLINE_SECONDS = 10 * 60
MIN_HEALTH_DEADLINE_SECONDS = 60
MAX_HEALTH_DEADLINE_SECONDS = 24 * 60 * 60
MAX_POLICY_VALIDITY_HOURS = 365 * 24
# Five minutes is enough for ordinary NTP/build-host skew without allowing a
# publisher to predate a policy far into the future. Capture ``now`` once and
# pass it through policy validation so the boundary is deterministic.
MAX_GENERATED_AT_FUTURE_SKEW = timedelta(minutes=5)
MAX_MANIFEST_RESPONSE_BYTES = 1024 * 1024
ED25519_PUBLIC_KEY_DER_PREFIX = bytes.fromhex("302a300506032b6570032100")
ED25519_PUBLIC_KEY_DER_BYTES = len(ED25519_PUBLIC_KEY_DER_PREFIX) + 32
# QJson stores numbers as IEEE-754 doubles. Keep the signed policy counter in
# the lossless JSON integer range shared by Python and every Qt client.
MAX_POLICY_GENERATION = (1 << 53) - 1
MAX_VERSION_COMPONENT = (1 << 31) - 1
MAX_ANDROID_VERSION_CODE = 2_100_000_000
HEADLESS_ARTIFACT_FORMAT = "amnezia-headless-tar-v1"


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


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_content_address(target: Path, expected_digest: str) -> None:
    if not SHA256_RE.fullmatch(expected_digest) or target.parent.name != expected_digest:
        raise SystemExit(f"invalid content-addressed artifact path: {target}")
    actual_digest = sha256(target)
    if actual_digest != expected_digest:
        raise SystemExit(
            f"artifact changed while it was copied to {target}: "
            f"expected sha256 {expected_digest}, copied sha256 {actual_digest}"
        )


def copy_content_addressed_artifact(source: Path, files_dir: Path) -> tuple[Path, str]:
    digest = sha256(source)
    target = files_dir / "artifacts" / digest / source.name
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)
    verify_content_address(target, digest)
    return target, digest


def write_content_addressed_artifact(
    files_dir: Path,
    filename: str,
    contents: bytes,
) -> tuple[Path, str]:
    digest = hashlib.sha256(contents).hexdigest()
    target = files_dir / "artifacts" / digest / filename
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(contents)
    verify_content_address(target, digest)
    return target, digest


def file_url(base_url: str, filename: str) -> str:
    return f"{base_url.rstrip('/')}/files/{quote(filename)}"


def relative_file_url(filename: str) -> str:
    return f"files/{quote(filename)}"


def relative_artifact_file_url(digest: str, filename: str) -> str:
    return f"files/artifacts/{digest}/{quote(filename, safe='')}"


def artifact_file_url(base_url: str, digest: str, filename: str) -> str:
    return f"{base_url.rstrip('/')}/{relative_artifact_file_url(digest, filename)}"


def relative_rollback_file_url(generation: int, version: str, filename: str) -> str:
    return f"files/rollback/{generation}/{quote(version, safe='')}/{quote(filename, safe='')}"


def itms_services_url(plist_url: str) -> str:
    return f"itms-services://?action=download-manifest&url={quote(plist_url, safe='')}"


def validate_base_url(value: str) -> str:
    normalized = value.strip().rstrip("/")
    parsed = urlparse(normalized)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or not parsed.hostname:
        raise SystemExit("--base-url must be an http(s) endpoint URL with a host, for example http://172.29.172.252:17865")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise SystemExit("--base-url must not contain userinfo, query, or fragment parts")
    if "/" in parsed.hostname:
        raise SystemExit("--base-url host must be a single host or IP address, not a CIDR route")
    try:
        ipaddress.ip_address(parsed.hostname)
        host_is_ip = True
    except ValueError:
        host_is_ip = False
    if host_is_ip and parsed.path.count("/") == 1 and parsed.path[1:].isdigit():
        raise SystemExit("--base-url must point to an update endpoint, not a CIDR route such as 10.8.1.0/1")
    return normalized


def validate_release_version(value: str) -> str:
    return validate_named_release_version(value, "--version")


def validate_named_release_version(value: str, option_name: str) -> str:
    normalized = value if isinstance(value, str) else ""
    if not VERSION_RE.fullmatch(normalized):
        raise SystemExit(
            f"{option_name} must be a release version in canonical x.y.z.w numeric format "
            "without leading-zero components"
        )
    if any(int(part) > MAX_VERSION_COMPONENT for part in normalized.split(".")):
        raise SystemExit(
            f"{option_name} components must be from 0 to {MAX_VERSION_COMPONENT} "
            "to match the client version parser"
        )
    return normalized


def release_version_tuple(value: str) -> tuple[int, int, int, int]:
    return tuple(int(part) for part in value.split("."))  # type: ignore[return-value]


def is_android_platform(platform: object) -> bool:
    return isinstance(platform, str) and (
        platform == "android" or platform.startswith("android-")
    )


def is_headless_platform(platform: object) -> bool:
    return isinstance(platform, str) and (
        platform == "linux-headless" or platform.startswith("linux-headless-")
    )


def validate_android_version_code(value: object, option_name: str = "--android-version-code") -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= MAX_ANDROID_VERSION_CODE
    ):
        raise SystemExit(
            f"{option_name} must be an integer from 1 to {MAX_ANDROID_VERSION_CODE}"
        )
    return value


def canonical_utc_timestamp(value: str, option_name: str) -> str:
    normalized = value.strip() if isinstance(value, str) else ""
    if not normalized:
        raise SystemExit(f"{option_name} must be a timezone-aware ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(normalized[:-1] + "+00:00" if normalized.endswith("Z") else normalized)
    except ValueError as error:
        raise SystemExit(f"{option_name} must be a timezone-aware ISO-8601 timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise SystemExit(f"{option_name} must include a timezone offset or Z")
    return parsed.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_canonical_utc_timestamp(value: object, field_name: str) -> datetime:
    if not isinstance(value, str) or not CANONICAL_UTC_RE.fullmatch(value):
        raise SystemExit(f"releasePolicy.{field_name} must use canonical UTC format YYYY-MM-DDTHH:MM:SSZ")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise SystemExit(f"releasePolicy.{field_name} is not a valid UTC timestamp") from error


def validate_cohort_salt_id(value: object) -> str:
    if not isinstance(value, str) or not COHORT_SALT_ID_RE.fullmatch(value):
        raise SystemExit(
            "cohort salt identifier must be 1-64 ASCII letters, digits, dots, underscores, or hyphens; "
            "store only a public identifier, never a secret"
        )
    return value


def validate_rollout_percentage(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 100:
        raise SystemExit("rollout percentage must be an integer from 0 to 100")
    return value


def cohort_bucket(client_id: str, cohort_salt_id: str) -> int:
    """Return a stable 0..9999 rollout bucket shared by all releases using a salt id.

    ``cohort_salt_id`` is deliberately an identifier rather than key material.
    The hash prevents recognizable client identifiers from leaking into the
    manifest while keeping the assignment deterministic and easy to reproduce
    in other client implementations.
    """

    if not isinstance(client_id, str) or len(client_id) > 512:
        raise SystemExit("client id for rollout cohort must contain 1-512 characters")
    normalized_client_id = client_id.strip().lower()
    if not normalized_client_id:
        raise SystemExit("client id for rollout cohort must contain 1-512 characters")
    salt_id = validate_cohort_salt_id(cohort_salt_id)
    digest = hashlib.sha256(
        f"amnezia-update-cohort-v1\0{salt_id}\0{normalized_client_id}".encode("utf-8")
    ).digest()
    return int.from_bytes(digest[:8], "big") % 10_000


def client_is_in_rollout(client_id: str, cohort_salt_id: str, percentage: int) -> bool:
    percentage = validate_rollout_percentage(percentage)
    return cohort_bucket(client_id, cohort_salt_id) < percentage * 100


def validate_local_artifact_metadata(
    platform: object,
    artifact: object,
    *,
    context: str,
    require_android_version_code: bool = False,
) -> None:
    if not isinstance(platform, str) or not PLATFORM_RE.fullmatch(platform):
        raise SystemExit(f"{context} platform must match {PLATFORM_RE.pattern}")
    if not isinstance(artifact, dict):
        raise SystemExit(f"{context} platform {platform} must be an object")
    required_keys = {"url", "sha256", "size", "autoInstall"}
    optional_keys = set()
    if is_android_platform(platform):
        optional_keys.add("versionCode")
    if is_headless_platform(platform):
        optional_keys.add("format")
    if set(artifact) - optional_keys != required_keys:
        missing = sorted(required_keys - set(artifact))
        unknown = sorted(set(artifact) - required_keys - optional_keys)
        details = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if unknown:
            details.append("unknown " + ", ".join(unknown))
        raise SystemExit(f"{context} platform {platform} has invalid artifact fields: {'; '.join(details)}")
    url = artifact["url"]
    parsed_url = urlparse(url) if isinstance(url, str) else None
    decoded_url = unquote(url) if isinstance(url, str) else ""
    if (
        not isinstance(url, str)
        or not parsed_url
        or parsed_url.scheme
        or parsed_url.netloc
        or parsed_url.query
        or parsed_url.fragment
        or not decoded_url.startswith("files/")
        or ".." in PurePosixPath(decoded_url).parts
    ):
        raise SystemExit(f"{context} platform {platform} URL must be relative and stay under files/")
    digest = artifact["sha256"]
    if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
        raise SystemExit(f"{context} platform {platform} must have a lowercase sha256")
    size = artifact["size"]
    if isinstance(size, bool) or not isinstance(size, int) or size <= 0:
        raise SystemExit(f"{context} platform {platform} must have a positive integer size")
    if not isinstance(artifact["autoInstall"], bool):
        raise SystemExit(f"{context} platform {platform} autoInstall must be a boolean")
    if is_headless_platform(platform) and artifact.get("format") != HEADLESS_ARTIFACT_FORMAT:
        raise SystemExit(
            f"{context} platform {platform} format must be {HEADLESS_ARTIFACT_FORMAT!r}"
        )
    if is_android_platform(platform):
        if require_android_version_code and "versionCode" not in artifact:
            raise SystemExit(f"{context} platform {platform} must have versionCode")
        if "versionCode" in artifact:
            validate_android_version_code(
                artifact["versionCode"],
                f"{context} platform {platform} versionCode",
            )


def reject_unsupported_rollback_platforms(platforms: set[str]) -> None:
    unsupported_android_platforms = sorted(
        platform for platform in platforms if is_android_platform(platform)
    )
    if unsupported_android_platforms:
        raise SystemExit(
            "Rollback policy cannot cover " + ", ".join(unsupported_android_platforms) +
            ": Android's package installer rejects ordinary lower-versionCode APKs. "
            "Publish the Android update without rollback until a separately versioned recovery "
            "artifact contract is supported."
        )
    unsupported_macos_platforms = sorted(platforms & {"macos", "macos-x64", "macos-arm64"})
    if unsupported_macos_platforms:
        raise SystemExit(
            "Rollback policy cannot cover " + ", ".join(unsupported_macos_platforms) +
            ": MACOS_NE clients can select these macOS aliases but cannot launch a verified "
            "local rollback installer. Publish this release without rollback, or exclude macOS "
            "platform aliases from the release channel that uses rollback."
        )


def validate_rollback_platform_coverage(
    platforms: dict[str, dict[str, object]],
    rollback_platforms: dict[str, dict[str, object]],
) -> None:
    local_platforms = {
        platform
        for platform, artifact in platforms.items()
        if not artifact.get("openExternal", False)
    }
    for platform in sorted(local_platforms):
        validate_local_artifact_metadata(
            platform,
            platforms[platform],
            context="release payload",
            require_android_version_code=True,
        )
    if rollback_platforms:
        reject_unsupported_rollback_platforms(set(rollback_platforms))
    rollback_required_platforms = {
        platform for platform in local_platforms if not is_android_platform(platform)
    }
    if rollback_platforms and set(rollback_platforms) != rollback_required_platforms:
        missing_rollback = sorted(rollback_required_platforms - set(rollback_platforms))
        unexpected_rollback = sorted(set(rollback_platforms) - rollback_required_platforms)
        details = []
        if missing_rollback:
            details.append("missing " + ", ".join(missing_rollback))
        if unexpected_rollback:
            details.append("unexpected " + ", ".join(unexpected_rollback))
        raise SystemExit(
            "Rollback artifacts must cover every supported local rollback platform exactly: "
            + "; ".join(details)
        )


def validate_release_policy(policy: object, *, now: datetime | None = None) -> None:
    if not isinstance(policy, dict):
        raise SystemExit("releasePolicy must be an object")
    required_keys = {
        "schema",
        "generation",
        "generatedAt",
        "expiresAt",
        "channel",
        "rollout",
        "eligibility",
        "healthDeadlineSeconds",
    }
    optional_keys = {"previousVersion", "rollback"}
    missing = sorted(required_keys - set(policy))
    unknown = sorted(set(policy) - required_keys - optional_keys)
    if missing or unknown:
        details = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if unknown:
            details.append("unknown " + ", ".join(unknown))
        raise SystemExit("releasePolicy has invalid fields: " + "; ".join(details))

    if isinstance(policy["schema"], bool) or not isinstance(policy["schema"], int) or policy["schema"] != 2:
        raise SystemExit("releasePolicy.schema must be integer 2")
    generation = policy["generation"]
    if isinstance(generation, bool) or not isinstance(generation, int) or not 1 <= generation <= MAX_POLICY_GENERATION:
        raise SystemExit(f"releasePolicy.generation must be an integer from 1 to {MAX_POLICY_GENERATION}")
    generated_at = parse_canonical_utc_timestamp(policy["generatedAt"], "generatedAt")
    expires_at = parse_canonical_utc_timestamp(policy["expiresAt"], "expiresAt")
    if expires_at <= generated_at:
        raise SystemExit("releasePolicy.expiresAt must be later than generatedAt")
    policy_now = now or datetime.now(timezone.utc)
    if policy_now.tzinfo is None or policy_now.utcoffset() is None:
        raise SystemExit("policy validation time must include a timezone")
    policy_now = policy_now.astimezone(timezone.utc)
    if generated_at > policy_now + MAX_GENERATED_AT_FUTURE_SKEW:
        raise SystemExit(
            "releasePolicy.generatedAt must not be more than 5 minutes in the future"
        )
    if expires_at <= policy_now:
        raise SystemExit("releasePolicy.expiresAt is already expired")
    if expires_at - generated_at > timedelta(hours=MAX_POLICY_VALIDITY_HOURS):
        raise SystemExit(
            "releasePolicy validity must not exceed "
            f"{MAX_POLICY_VALIDITY_HOURS} hours"
        )

    channel = policy["channel"]
    if channel not in RELEASE_CHANNELS:
        raise SystemExit("releasePolicy.channel must be stable, canary, or emergency")
    rollout = policy["rollout"]
    if not isinstance(rollout, dict) or set(rollout) != {"percentage", "cohortSaltId"}:
        raise SystemExit("releasePolicy.rollout must contain exactly percentage and cohortSaltId")
    validate_rollout_percentage(rollout["percentage"])
    validate_cohort_salt_id(rollout["cohortSaltId"])

    eligibility = policy["eligibility"]
    if not isinstance(eligibility, dict) or not set(eligibility) <= {"minimumVersion", "maximumVersion"}:
        raise SystemExit("releasePolicy.eligibility may contain only minimumVersion and maximumVersion")
    minimum_version = eligibility.get("minimumVersion")
    maximum_version = eligibility.get("maximumVersion")
    if "minimumVersion" in eligibility:
        minimum_version = validate_named_release_version(minimum_version, "releasePolicy.eligibility.minimumVersion")
    if "maximumVersion" in eligibility:
        maximum_version = validate_named_release_version(maximum_version, "releasePolicy.eligibility.maximumVersion")
    if minimum_version and maximum_version and release_version_tuple(minimum_version) > release_version_tuple(maximum_version):
        raise SystemExit("releasePolicy minimumVersion must not be newer than maximumVersion")

    health_deadline = policy["healthDeadlineSeconds"]
    if (
        isinstance(health_deadline, bool)
        or not isinstance(health_deadline, int)
        or not MIN_HEALTH_DEADLINE_SECONDS <= health_deadline <= MAX_HEALTH_DEADLINE_SECONDS
    ):
        raise SystemExit(
            "releasePolicy.healthDeadlineSeconds must be an integer from "
            f"{MIN_HEALTH_DEADLINE_SECONDS} to {MAX_HEALTH_DEADLINE_SECONDS}"
        )

    previous_version = policy.get("previousVersion")
    if "previousVersion" in policy:
        previous_version = validate_named_release_version(previous_version, "releasePolicy.previousVersion")
    rollback = policy.get("rollback")
    if "rollback" in policy:
        if not previous_version:
            raise SystemExit("releasePolicy.rollback requires previousVersion")
        if not isinstance(rollback, dict) or set(rollback) != {"version", "platforms"}:
            raise SystemExit("releasePolicy.rollback must contain exactly version and platforms")
        rollback_version = validate_named_release_version(rollback["version"], "releasePolicy.rollback.version")
        if rollback_version != previous_version:
            raise SystemExit("releasePolicy.rollback.version must equal previousVersion")
        rollback_platforms = rollback["platforms"]
        if not isinstance(rollback_platforms, dict) or not rollback_platforms:
            raise SystemExit("releasePolicy.rollback.platforms must be a non-empty object")
        reject_unsupported_rollback_platforms(set(rollback_platforms))
        for platform, artifact in rollback_platforms.items():
            validate_local_artifact_metadata(platform, artifact, context="releasePolicy.rollback")


def build_release_policy(
    *,
    version: str,
    channel: str,
    rollout_percentage: int,
    cohort_salt_id: str,
    minimum_version: str,
    maximum_version: str,
    health_deadline_seconds: int,
    generated_at: str,
    expires_at: str,
    generation: int,
    previous_version: str,
    rollback_platforms: dict[str, dict[str, object]],
    now: datetime | None = None,
) -> dict[str, object]:
    version = validate_named_release_version(version, "--version")
    if channel not in RELEASE_CHANNELS:
        raise SystemExit("--channel must be stable, canary, or emergency")
    rollout_percentage = validate_rollout_percentage(rollout_percentage)
    cohort_salt_id = validate_cohort_salt_id(cohort_salt_id)
    generated_at = canonical_utc_timestamp(generated_at, "--generated-at")
    expires_at = canonical_utc_timestamp(expires_at, "--expires-at")

    eligibility: dict[str, str] = {}
    if minimum_version:
        eligibility["minimumVersion"] = validate_named_release_version(minimum_version, "--minimum-eligible-version")
    if maximum_version:
        eligibility["maximumVersion"] = validate_named_release_version(maximum_version, "--maximum-eligible-version")
    previous_version = (
        validate_named_release_version(previous_version, "--previous-version") if previous_version else ""
    )
    if previous_version and release_version_tuple(previous_version) >= release_version_tuple(version):
        raise SystemExit("--previous-version must be older than --version")

    policy: dict[str, object] = {
        "schema": 2,
        "generation": generation,
        "generatedAt": generated_at,
        "expiresAt": expires_at,
        "channel": channel,
        "rollout": {
            "percentage": rollout_percentage,
            "cohortSaltId": cohort_salt_id,
        },
        "eligibility": eligibility,
        "healthDeadlineSeconds": health_deadline_seconds,
    }
    if previous_version:
        policy["previousVersion"] = previous_version
    if rollback_platforms:
        if not previous_version:
            raise SystemExit("--rollback-artifact requires --previous-version")
        policy["rollback"] = {
            "version": previous_version,
            "platforms": rollback_platforms,
        }
    validate_release_policy(policy, now=now)
    return policy


def validate_external_url(platform: str, value: str) -> str:
    normalized = value.strip()
    parsed = urlparse(normalized)
    normalized_platform = platform.strip()
    if not normalized_platform:
        raise SystemExit("external platform must not be empty")
    if not parsed.scheme:
        raise SystemExit(f"external URL for {platform} must be absolute")
    if normalized_platform == "ios":
        validate_ios_external_url(normalized)
    elif parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise SystemExit(f"external URL for {platform} must use HTTP or HTTPS")
    return normalized


def validate_ios_external_url(value: str) -> None:
    parsed = urlparse(value)
    if parsed.scheme == "itms-services":
        manifest_urls = parse_qs(parsed.query).get("url", [])
        if not manifest_urls:
            raise SystemExit("iOS itms-services URL must include a manifest url query parameter")
        manifest = urlparse(manifest_urls[0])
        if manifest.scheme != "https" or not manifest.netloc:
            raise SystemExit("iOS itms-services manifest URL must use HTTPS with a host")
        return
    if parsed.scheme == "https":
        if not parsed.netloc:
            raise SystemExit("iOS HTTPS external URL must include a host")
        return
    if parsed.scheme == "itms-apps":
        if not parsed.netloc:
            raise SystemExit("iOS itms-apps external URL must include a host")
        return
    raise SystemExit("iOS external URL must use HTTPS, itms-apps, or itms-services with an HTTPS manifest")


def require_https_base_url_for_ios_ota(base_url: str) -> None:
    if urlparse(base_url).scheme != "https":
        raise SystemExit("--ios-ipa requires --base-url to use HTTPS so iOS can install the OTA manifest and IPA")


def ios_bundle_version(value: str, *, explicit: bool = False) -> str:
    parts = value.strip().split(".")
    if not parts or any(not part.isdigit() for part in parts):
        raise SystemExit("iOS bundle version must contain only digits and periods")
    if explicit and len(parts) > 3:
        raise SystemExit("--ios-bundle-version must contain one to three numeric components")
    normalized = parts[:3]
    if not normalized:
        raise SystemExit("iOS bundle version must not be empty")
    return ".".join(str(int(part)) for part in normalized)


def require_ed25519_private_key(private_key: Path) -> None:
    """Fail closed unless ``private_key`` derives an Ed25519 public key."""

    with tempfile.TemporaryDirectory() as tmp:
        public_key_der_path = Path(tmp) / "public.der"
        try:
            subprocess.run(
                [
                    openssl_command(),
                    "pkey",
                    "-in",
                    str(private_key),
                    "-pubout",
                    "-outform",
                    "DER",
                    "-out",
                    str(public_key_der_path),
                ],
                check=True,
                capture_output=True,
            )
        except subprocess.CalledProcessError as error:
            raise SystemExit("--private-key must be a valid Ed25519 PEM private key") from error

        public_key_der = public_key_der_path.read_bytes()
        if (
            len(public_key_der) != ED25519_PUBLIC_KEY_DER_BYTES
            or not public_key_der.startswith(ED25519_PUBLIC_KEY_DER_PREFIX)
        ):
            raise SystemExit("--private-key must contain an Ed25519 key")


def sign_payload(private_key: Path, payload: bytes) -> str:
    require_ed25519_private_key(private_key)
    with tempfile.TemporaryDirectory() as tmp:
        payload_path = Path(tmp) / "payload.json"
        sig_path = Path(tmp) / "payload.sig"
        payload_path.write_bytes(payload)
        subprocess.run(
            [
                openssl_command(),
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                str(private_key),
                "-in",
                str(payload_path),
                "-out",
                str(sig_path),
            ],
            check=True,
        )
        signature = sig_path.read_bytes()
        if len(signature) != 64:
            raise SystemExit("generated manifest signature is not a 64-byte Ed25519 signature")
        return base64.b64encode(signature).decode("ascii")


def verify_payload_signature(private_key: Path, payload: bytes, signature_base64: str) -> None:
    require_ed25519_private_key(private_key)
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        payload_path = tmp_path / "payload.json"
        signature_path = tmp_path / "payload.sig"
        public_key_path = tmp_path / "public.pem"
        payload_path.write_bytes(payload)
        try:
            signature = base64.b64decode(signature_base64, validate=True)
        except (ValueError, TypeError) as error:
            raise SystemExit("generated manifest signature is not valid base64") from error
        if len(signature) != 64:
            raise SystemExit("generated manifest signature is not a 64-byte Ed25519 signature")
        signature_path.write_bytes(signature)
        subprocess.run(
            [
                openssl_command(),
                "pkey",
                "-in",
                str(private_key),
                "-pubout",
                "-out",
                str(public_key_path),
            ],
            check=True,
        )
        subprocess.run(
            [
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
            ],
            check=True,
        )


def verify_public_key_matches_private(public_key_base64: str, private_key: Path) -> None:
    """Verify the public key embedded in clients belongs to the signing key."""

    if any(character.isspace() for character in public_key_base64):
        raise SystemExit("SELFHOSTED_UPDATE_PUBLIC_KEY_PEM_BASE64 must not contain whitespace or line breaks")
    try:
        public_key_pem = base64.b64decode(public_key_base64, validate=True)
    except Exception as error:
        raise SystemExit(
            "SELFHOSTED_UPDATE_PUBLIC_KEY_PEM_BASE64 must be a single-line base64-encoded PEM public key"
        ) from error
    if b"BEGIN PUBLIC KEY" not in public_key_pem:
        raise SystemExit("SELFHOSTED_UPDATE_PUBLIC_KEY_PEM_BASE64 must decode to a PEM public key")

    with tempfile.TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)
        public_key_path = tmp_dir / "public.pem"
        normalized_public_key_path = tmp_dir / "normalized-public.der"
        derived_public_key_path = tmp_dir / "derived-public.der"
        public_key_path.write_bytes(public_key_pem)
        try:
            subprocess.run(
                [
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
                ],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                [
                    openssl_command(),
                    "pkey",
                    "-in",
                    str(private_key),
                    "-pubout",
                    "-outform",
                    "DER",
                    "-out",
                    str(derived_public_key_path),
                ],
                check=True,
                capture_output=True,
            )
        except subprocess.CalledProcessError as error:
            raise SystemExit("SELFHOSTED_UPDATE_PUBLIC_KEY_PEM_BASE64 must decode to a valid Ed25519 public key") from error
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


def decode_manifest_envelope(manifest_data: bytes) -> tuple[dict[str, object], bytes, str]:
    """Decode the signed envelope without contacting or publishing to a server."""

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
    return payload, payload_bytes, encoded_signature


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
    """Verify a locally generated payload before the self-hosted client receives it."""

    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise SystemExit("Generated manifest must be a regular file")
    if manifest_path.stat().st_size > MAX_MANIFEST_RESPONSE_BYTES:
        raise SystemExit("Update manifest exceeds the client-compatible 1 MiB response limit")
    payload, payload_bytes, signature = decode_manifest_envelope(manifest_path.read_bytes())
    if payload.get("schema") != expected_payload_schema:
        raise SystemExit(f"Unexpected manifest payload schema: {payload.get('schema')!r}")
    if expected_payload_schema == 1 and "releasePolicy" in payload:
        raise SystemExit("Payload schema 1 must not contain releasePolicy")
    if expected_payload_schema == 2:
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
    elif expected_payload_schema != 1:
        raise SystemExit(f"Unsupported expected payload schema: {expected_payload_schema!r}")
    if payload.get("version") != expected_version:
        raise SystemExit(
            f"Generated manifest version {payload.get('version')!r} does not match requested version "
            f"{expected_version!r}"
        )
    platforms = payload.get("platforms")
    if not isinstance(platforms, dict):
        raise SystemExit("Generated manifest platforms must be an object")
    missing = sorted(required_platforms - set(platforms))
    if missing:
        raise SystemExit("Generated manifest is missing required platforms: " + ", ".join(missing))
    for platform, artifact in platforms.items():
        if not isinstance(platform, str) or not isinstance(artifact, dict):
            raise SystemExit(f"Generated manifest platform {platform!r} must be an object")
        if artifact.get("openExternal"):
            url = artifact.get("url")
            if not isinstance(url, str):
                raise SystemExit(f"Generated manifest platform {platform} is missing an external URL")
            validate_external_url(platform, url)
        else:
            validate_local_artifact_metadata(
                platform,
                artifact,
                context="Generated manifest",
                require_android_version_code=expected_payload_schema == 2,
            )
            if expected_android_version_code is not None and is_android_platform(platform):
                if artifact.get("versionCode") != expected_android_version_code:
                    raise SystemExit(
                        f"Generated manifest platform {platform} versionCode does not match the requested Android versionCode"
                    )
    if auto_install:
        if payload.get("autoInstall") is not True:
            raise SystemExit("Generated manifest is missing top-level autoInstall=true")
        if any(artifact.get("autoInstall") is not True for artifact in platforms.values()):
            raise SystemExit("Generated manifest is missing autoInstall=true for a platform")
    verify_payload_signature(private_key, payload_bytes, signature)


def parse_artifact(values: list[str]) -> dict[str, Path]:
    artifacts: dict[str, Path] = {}
    for value in values:
        if "=" not in value:
            raise SystemExit(f"artifact must be platform=path, got {value!r}")
        platform, path = value.split("=", 1)
        platform = platform.strip()
        artifact_path = Path(path).expanduser().resolve()
        if not platform:
            raise SystemExit("artifact platform must not be empty")
        if not artifact_path.is_file():
            raise SystemExit(f"artifact file does not exist: {artifact_path}")
        if platform in artifacts:
            raise SystemExit(f"duplicate artifact platform: {platform}")
        artifacts[platform] = artifact_path
    return artifacts


def remove_replaced_output_backup(backup_path: Path) -> None:
    """Best-effort cleanup that cannot turn a committed switch into a reported failure."""

    try:
        if backup_path.is_symlink() or not backup_path.is_dir():
            backup_path.unlink(missing_ok=True)
            return

        def make_writable_and_retry(function, path: str, _error_info) -> None:
            try:
                os.chmod(path, stat.S_IREAD | stat.S_IWRITE)
                function(path)
            except OSError:
                pass

        shutil.rmtree(backup_path, onerror=make_writable_and_retry)
        if backup_path.exists() or backup_path.is_symlink():
            print(
                f"Warning: published output was switched, but old backup remains at {backup_path}",
                file=sys.stderr,
            )
    except OSError as error:
        print(
            f"Warning: published output was switched, but old backup cleanup failed for {backup_path}: {error}",
            file=sys.stderr,
        )


def replace_output_tree(staged_out_dir: Path, out_dir: Path) -> None:
    backup_dir: Path | None = None
    if out_dir.exists():
        backup_dir = Path(tempfile.mkdtemp(prefix=f".{out_dir.name}.previous-", dir=out_dir.parent))
        backup_dir.rmdir()
        os.replace(out_dir, backup_dir)
    try:
        os.replace(staged_out_dir, out_dir)
    except Exception:
        if backup_dir is not None and backup_dir.exists() and not out_dir.exists():
            os.replace(backup_dir, out_dir)
        raise
    if backup_dir is not None:
        remove_replaced_output_backup(backup_dir)


def ios_plist_bytes(ipa_url: str, bundle_id: str, bundle_version: str, title: str) -> bytes:
    payload = {
        "items": [
            {
                "assets": [
                    {
                        "kind": "software-package",
                        "url": ipa_url,
                    }
                ],
                "metadata": {
                    "bundle-identifier": bundle_id,
                    "bundle-version": bundle_version,
                    "kind": "software",
                    "title": title,
                },
            }
        ]
    }
    return plistlib.dumps(payload, sort_keys=True)


def write_ios_plist(path: Path, ipa_url: str, bundle_id: str, bundle_version: str, title: str) -> None:
    path.write_bytes(ios_plist_bytes(ipa_url, bundle_id, bundle_version, title))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--release-date", default="")
    parser.add_argument("--changelog-file", type=Path)
    parser.add_argument("--base-url", required=True, help="Example: http://172.29.172.252:17865")
    parser.add_argument("--private-key", type=Path, required=True, help="Ed25519 private key PEM")
    parser.add_argument("--public-key-base64", default=os.environ.get("SELFHOSTED_UPDATE_PUBLIC_KEY_PEM_BASE64", ""))
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument(
        "--artifact",
        action="append",
        default=[],
        help="platform=path; examples: windows-x64=AmneziaVPN.exe android-arm64-v8a=app.apk",
    )
    parser.add_argument(
        "--android-version-code",
        type=int,
        help=(
            "Signed Android package versionCode for every local Android artifact; "
            "required for Android in payload schema 2"
        ),
    )
    parser.add_argument("--require-platform", action="append", default=[])
    parser.add_argument(
        "--external",
        action="append",
        default=[],
        help="platform=url for platforms where the client should open an external installer URL, such as ios=itms-services://...",
    )
    parser.add_argument("--ios-ipa", type=Path, help="Optional iOS enterprise/MDM IPA to copy into files/")
    parser.add_argument("--ios-bundle-id", help="Required with --ios-ipa, for example org.amnezia.AmneziaVPN")
    parser.add_argument("--ios-bundle-version", help="Defaults to --version when --ios-ipa is used")
    parser.add_argument("--ios-title", default="AmneziaVPN")
    parser.add_argument("--auto-install", action="store_true", help="Ask clients to start the OS installer automatically")
    parser.add_argument(
        "--payload-schema",
        type=int,
        choices=(1, 2),
        default=1,
        help="Signed payload schema; use 2 only after schema-2-capable bootstrap clients are deployed",
    )
    parser.add_argument(
        "--channel",
        choices=sorted(RELEASE_CHANNELS),
        default="stable",
        help="Signed release channel policy (default: stable)",
    )
    parser.add_argument(
        "--rollout-percentage",
        type=int,
        default=100,
        help="Deterministic eligible cohort percentage from 0 to 100 (default: 100)",
    )
    parser.add_argument(
        "--cohort-salt-id",
        default="fleet-v1",
        help="Public stable cohort salt identifier; this is not a secret",
    )
    parser.add_argument("--minimum-eligible-version", default="")
    parser.add_argument("--maximum-eligible-version", default="")
    parser.add_argument(
        "--health-deadline-seconds",
        type=int,
        default=DEFAULT_HEALTH_DEADLINE_SECONDS,
        help="Seconds after install for a client health receipt, from 60 to 86400 (default: 600)",
    )
    parser.add_argument(
        "--policy-generation",
        type=int,
        help=(
            "Required monotonic policy generation for payload schema 2; "
            f"must be a JSON-safe integer up to {MAX_POLICY_GENERATION}"
        ),
    )
    parser.add_argument(
        "--generated-at",
        default="",
        help="Timezone-aware ISO-8601 policy generation time; defaults to current UTC",
    )
    expiry_group = parser.add_mutually_exclusive_group()
    expiry_group.add_argument(
        "--expires-at",
        default="",
        help="Timezone-aware ISO-8601 policy expiry; must be later than generatedAt",
    )
    expiry_group.add_argument(
        "--policy-valid-for-hours",
        type=int,
        default=DEFAULT_POLICY_VALIDITY_HOURS,
        help="Policy lifetime when --expires-at is omitted (default: 168)",
    )
    parser.add_argument(
        "--previous-version",
        default="",
        help="Older release version to restore when post-update health misses its deadline",
    )
    parser.add_argument(
        "--rollback-artifact",
        action="append",
        default=[],
        help="platform=path for a previous-version rollback artifact; repeat per platform",
    )
    args = parser.parse_args()
    version = validate_release_version(args.version)
    base_url = validate_base_url(args.base_url)
    android_version_code = (
        validate_android_version_code(args.android_version_code)
        if args.android_version_code is not None
        else None
    )

    restrictive_policy_requested = any((
        args.channel != "stable",
        args.rollout_percentage != 100,
        args.cohort_salt_id != "fleet-v1",
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
            "rollout, eligibility, expiry, health, and rollback policy requires --payload-schema 2; "
            "schema 1 is allowed only for an unrestricted stable 100% release so old clients cannot bypass policy"
        )

    generated_at = ""
    expires_at = ""
    generation = 0
    previous_version = ""
    policy_now: datetime | None = None
    if args.payload_schema == 2:
        if args.policy_generation is None:
            raise SystemExit("--policy-generation is required with --payload-schema 2")
        policy_now = datetime.now(timezone.utc).replace(microsecond=0)
        generated_at = canonical_utc_timestamp(
            args.generated_at or policy_now.isoformat().replace("+00:00", "Z"),
            "--generated-at",
        )
        generated_at_datetime = parse_canonical_utc_timestamp(generated_at, "generatedAt")
        if args.expires_at:
            expires_at = canonical_utc_timestamp(args.expires_at, "--expires-at")
        else:
            if not 1 <= args.policy_valid_for_hours <= MAX_POLICY_VALIDITY_HOURS:
                raise SystemExit(f"--policy-valid-for-hours must be from 1 to {MAX_POLICY_VALIDITY_HOURS}")
            expires_at = (
                generated_at_datetime + timedelta(hours=args.policy_valid_for_hours)
            ).isoformat().replace("+00:00", "Z")
        generation = args.policy_generation
        previous_version = (
            validate_named_release_version(args.previous_version, "--previous-version") if args.previous_version else ""
        )
        if previous_version and release_version_tuple(previous_version) >= release_version_tuple(version):
            raise SystemExit("--previous-version must be older than --version")
        if bool(previous_version) != bool(args.rollback_artifact):
            raise SystemExit(
                "--previous-version and at least one --rollback-artifact must be supplied together"
            )

    requested_out_dir = args.out_dir.resolve()
    requested_out_dir.parent.mkdir(parents=True, exist_ok=True)
    staging_directory = tempfile.TemporaryDirectory(
        prefix=f".{requested_out_dir.name}.manifest-",
        dir=requested_out_dir.parent,
    )
    out_dir = Path(staging_directory.name) / "release"
    files_dir = out_dir / "files"
    files_dir.mkdir(parents=True, exist_ok=True)

    platforms: dict[str, dict[str, object]] = {}
    reserved_file_names: dict[str, tuple[str, str]] = {}
    def add_platform(platform: str, artifact: dict[str, object]) -> None:
        if platform in platforms:
            raise SystemExit(f"duplicate manifest platform: {platform}")
        platforms[platform] = artifact

    def reserve_file_name(platform: str, file_name: str) -> None:
        reservation_key = file_name.casefold()
        existing = reserved_file_names.get(reservation_key)
        if existing is not None:
            existing_name, owner = existing
            raise SystemExit(
                f"duplicate artifact output filename under case-insensitive matching: "
                f"{existing_name!r} for {owner} and {file_name!r} for {platform}"
            )
        reserved_file_names[reservation_key] = (file_name, platform)

    for platform, artifact_path in parse_artifact(args.artifact).items():
        reserve_file_name(platform, artifact_path.name)
        target, digest = copy_content_addressed_artifact(artifact_path, files_dir)
        artifact_metadata: dict[str, object] = {
            "url": relative_artifact_file_url(digest, target.name),
            "sha256": digest,
            "size": target.stat().st_size,
            "autoInstall": args.auto_install,
        }
        if is_headless_platform(platform):
            artifact_metadata["format"] = HEADLESS_ARTIFACT_FORMAT
        if is_android_platform(platform) and android_version_code is not None:
            artifact_metadata["versionCode"] = android_version_code
        add_platform(platform, artifact_metadata)

    rollback_platforms: dict[str, dict[str, object]] = {}
    rollback_file_names: dict[str, tuple[str, str]] = {}
    if args.rollback_artifact:
        rollback_dir = files_dir / "rollback" / str(generation) / previous_version
        rollback_dir.mkdir(parents=True, exist_ok=True)
        for platform, artifact_path in parse_artifact(args.rollback_artifact).items():
            reservation_key = artifact_path.name.casefold()
            existing = rollback_file_names.get(reservation_key)
            if existing is not None:
                existing_name, owner = existing
                raise SystemExit(
                    f"duplicate rollback artifact output filename under case-insensitive matching: "
                    f"{existing_name!r} for {owner} and {artifact_path.name!r} for {platform}"
                )
            rollback_file_names[reservation_key] = (artifact_path.name, platform)
            target = rollback_dir / artifact_path.name
            shutil.copy2(artifact_path, target)
            rollback_digest = sha256(artifact_path)
            if sha256(target) != rollback_digest:
                raise SystemExit(
                    f"rollback artifact changed while it was copied: {artifact_path}"
                )
            rollback_platforms[platform] = {
                "url": relative_rollback_file_url(generation, previous_version, target.name),
                "sha256": rollback_digest,
                "size": target.stat().st_size,
                "autoInstall": args.auto_install,
            }
            if is_headless_platform(platform):
                rollback_platforms[platform]["format"] = HEADLESS_ARTIFACT_FORMAT

    if args.ios_ipa:
        require_https_base_url_for_ios_ota(base_url)
        if not args.ios_bundle_id:
            raise SystemExit("--ios-bundle-id is required when --ios-ipa is used")
        ipa_path = args.ios_ipa.expanduser().resolve()
        if not ipa_path.is_file():
            raise SystemExit(f"iOS IPA file does not exist: {ipa_path}")
        reserve_file_name("ios", ipa_path.name)
        plist_name = f"{ipa_path.stem}.plist"
        reserve_file_name("ios", plist_name)
        ipa_target, ipa_digest = copy_content_addressed_artifact(ipa_path, files_dir)
        ipa_url = artifact_file_url(base_url, ipa_digest, ipa_target.name)
        plist_contents = ios_plist_bytes(
            ipa_url,
            args.ios_bundle_id,
            ios_bundle_version(args.ios_bundle_version, explicit=True) if args.ios_bundle_version else ios_bundle_version(version),
            args.ios_title,
        )
        plist_target, plist_digest = write_content_addressed_artifact(
            files_dir,
            plist_name,
            plist_contents,
        )
        plist_url = artifact_file_url(base_url, plist_digest, plist_target.name)
        add_platform("ios", {
            "url": itms_services_url(plist_url),
            "openExternal": True,
            "autoInstall": args.auto_install,
            "ipaUrl": ipa_url,
            "plistUrl": plist_url,
            "sha256": ipa_digest,
            "size": ipa_target.stat().st_size,
        })

    for value in args.external:
        if "=" not in value:
            raise SystemExit(f"external must be platform=url, got {value!r}")
        platform, url = value.split("=", 1)
        platform = platform.strip()
        add_platform(platform, {
            "url": validate_external_url(platform, url),
            "openExternal": True,
            "autoInstall": args.auto_install,
        })

    if not platforms:
        raise SystemExit("at least one --artifact or --external entry is required")
    local_android_platforms = sorted(
        platform
        for platform, artifact in platforms.items()
        if is_android_platform(platform) and not artifact.get("openExternal", False)
    )
    if android_version_code is not None and not local_android_platforms:
        raise SystemExit("--android-version-code requires at least one local Android --artifact")
    if args.payload_schema == 2 and local_android_platforms and android_version_code is None:
        raise SystemExit(
            "--android-version-code is required with --payload-schema 2 when a local Android artifact is included"
        )
    missing_platforms = sorted(set(args.require_platform) - set(platforms))
    if missing_platforms:
        raise SystemExit("Missing required update artifacts/settings: " + ", ".join(missing_platforms))
    if args.payload_schema == 2:
        validate_rollback_platform_coverage(platforms, rollback_platforms)

    changelog = ""
    if args.changelog_file:
        changelog = args.changelog_file.read_text(encoding="utf-8")

    payload: dict[str, object] = {
        "schema": args.payload_schema,
        "version": version,
        "releaseDate": args.release_date,
        "changelog": changelog,
        "autoInstall": args.auto_install,
        "platforms": platforms,
    }
    if args.payload_schema == 2:
        payload["releasePolicy"] = build_release_policy(
            version=version,
            channel=args.channel,
            rollout_percentage=args.rollout_percentage,
            cohort_salt_id=args.cohort_salt_id,
            minimum_version=args.minimum_eligible_version,
            maximum_version=args.maximum_eligible_version,
            health_deadline_seconds=args.health_deadline_seconds,
            generated_at=generated_at,
            expires_at=expires_at,
            generation=generation,
            previous_version=previous_version,
            rollback_platforms=rollback_platforms,
            now=datetime.now(timezone.utc),
        )
    private_key = args.private_key.expanduser().resolve()
    payload_bytes = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature = sign_payload(private_key, payload_bytes)
    if args.payload_schema == 2:
        verify_payload_signature(private_key, payload_bytes, signature)
    manifest = {
        "schema": "amnezia-selfhosted-update-v1",
        "signatureAlgorithm": "Ed25519",
        "payload": b64url(payload_bytes),
        "signature": signature,
    }
    manifest_bytes = (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    if len(manifest_bytes) > MAX_MANIFEST_RESPONSE_BYTES:
        raise SystemExit(
            "generated manifest exceeds the client-compatible 1 MiB response limit "
            f"({len(manifest_bytes)} bytes > {MAX_MANIFEST_RESPONSE_BYTES})"
        )
    manifest_path = out_dir / "manifest.json"
    manifest_path.write_bytes(manifest_bytes)
    if (args.public_key_base64 or args.require_platform) and args.payload_schema == 1:
        if args.public_key_base64:
            verify_public_key_matches_private(args.public_key_base64, private_key)
        verify_manifest(manifest_path, private_key, version, set(args.require_platform), args.auto_install)
        print("Verified self-hosted update manifest signature and required platforms", flush=True)
    elif args.payload_schema == 2:
        if args.public_key_base64:
            verify_public_key_matches_private(args.public_key_base64, private_key)
        print("Verified schema-2 manifest signature, signing key, and required platforms", flush=True)
    if args.payload_schema == 2:
        validate_release_policy(payload["releasePolicy"], now=datetime.now(timezone.utc))
    replace_output_tree(out_dir, requested_out_dir)
    staging_directory.cleanup()
    return 0


if __name__ == "__main__":
    sys.exit(main())
