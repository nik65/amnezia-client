"""Canonical signed file map for the embedded self-hosted publisher."""
from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any, Mapping


class PublisherFileMapError(ValueError):
    pass


def _metadata(label: str, value: object) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise PublisherFileMapError(f"signed metadata is missing for {label}")
    path, digest, size = value.get("url"), value.get("sha256"), value.get("size")
    if not isinstance(path, str) or not path.startswith("files/artifacts/"):
        raise PublisherFileMapError(f"signed artifact path is invalid for {label}")
    pure = PurePosixPath(path)
    if pure.is_absolute() or str(pure) != path or ".." in pure.parts:
        raise PublisherFileMapError(f"signed artifact path escapes the endpoint for {label}")
    if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise PublisherFileMapError(f"signed artifact hash is invalid for {label}")
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        raise PublisherFileMapError(f"signed artifact size is invalid for {label}")
    return {"path": path, "sha256": digest, "size": size}


def canonical_publisher_file_map(run: Mapping[str, Any], payload: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    """Return every local file the signed payload instructs the client to publish."""
    planned, baselines, platforms = run.get("artifacts"), run.get("baseline_artifacts"), payload.get("platforms")
    if not isinstance(planned, Mapping) or not isinstance(baselines, Mapping) or not isinstance(platforms, Mapping):
        raise PublisherFileMapError("publication plan or signed platform map is missing")
    result: dict[str, dict[str, Any]] = {}
    paths: set[str] = set()

    def add(label: str, signed: object, plan: object | None) -> None:
        item = _metadata(label, signed)
        if label in result or item["path"] in paths:
            raise PublisherFileMapError(f"duplicate publication label or path: {label}")
        if plan is not None and (not isinstance(plan, Mapping) or plan.get("sha256") != item["sha256"] or plan.get("size") != item["size"]):
            raise PublisherFileMapError(f"signed bytes differ from the frozen plan for {label}")
        paths.add(item["path"]); result[label] = item

    if set(platforms) != set(planned):
        raise PublisherFileMapError("signed platform set differs from the frozen plan")
    for platform, plan in planned.items():
        signed = platforms.get(platform)
        if not isinstance(signed, Mapping) or signed.get("openExternal") is True:
            raise PublisherFileMapError(f"publication platform is not an embedded local artifact: {platform}")
        add(f"platform:{platform}", signed, plan)
    if payload.get("headlessProvisioning") is not None:
        add("headlessProvisioning", payload["headlessProvisioning"], None)
    rollback = ((payload.get("releasePolicy") or {}).get("rollback") or {}).get("platforms")
    if rollback is not None:
        if not isinstance(rollback, Mapping):
            raise PublisherFileMapError("signed rollback platform map is invalid")
        for platform, signed in rollback.items():
            if platform not in baselines:
                raise PublisherFileMapError(f"signed rollback lacks a frozen baseline: {platform}")
            add(f"rollback:{platform}", signed, baselines[platform])
    return result


def validate_observed_file_map(expected: Mapping[str, Mapping[str, Any]], observed: object) -> None:
    if not isinstance(observed, Mapping) or set(observed) != set(expected):
        raise PublisherFileMapError("publication HTTP artifact readback set is incomplete")
    for label, planned in expected.items():
        value = observed.get(label)
        if not isinstance(value, Mapping) or any(value.get(key) != planned.get(key) for key in ("path", "sha256", "size")):
            raise PublisherFileMapError(f"publication HTTP bytes/path differ for {label}")
