#!/usr/bin/env python3
"""Offline-only consumer fixture HTTP server for the sealed server-router guest.

The controller uploads the signed manifest and APK through QGA. This process
serves those exact bytes and refuses to start when either digest is wrong.
It is a test fixture, never a release publisher.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import threading
import time
from urllib.parse import parse_qs, urlsplit
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Final


GUEST_PORT: Final = 17865
MAX_REQUEST_LOG_BYTES: Final = 1024 * 1024
MAX_REQUEST_RECORDS: Final = 4096


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_manifest(path: Path) -> dict:
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document.get("payload"), str) or not document.get("signature"):
        raise SystemExit("fixture requires a signed self-hosted manifest")
    return document


def artifact_path_from_manifest(document: dict, expected_sha256: str) -> str:
    payload = document["payload"] + "=" * (-len(document["payload"]) % 4)
    decoded = json.loads(base64.b64decode(payload).decode("utf-8"))
    artifact = decoded.get("platforms", {}).get("android-arm64-v8a", {})
    raw_url = artifact.get("url")
    parsed = urlsplit(raw_url) if isinstance(raw_url, str) else None
    path = "/" + parsed.path.lstrip("/") if parsed is not None else ""
    prefix = f"/files/artifacts/{expected_sha256.lower()}/"
    if parsed is None or parsed.query or parsed.fragment or not path.startswith(prefix) or path == prefix:
        raise SystemExit("fixture manifest Android ARM64 URL is not bound to the planned APK digest")
    return path


class FixtureHandler(BaseHTTPRequestHandler):
    server_version = "AmneziaConsumerFixture/1"
    protocol_version = "HTTP/1.1"

    def do_HEAD(self) -> None:  # noqa: N802
        self._serve(False)

    def do_GET(self) -> None:  # noqa: N802
        self._serve(True)

    def log_message(self, *_args: object) -> None:
        return

    def _serve(self, body: bool) -> None:
        fixture = self.server.fixture  # type: ignore[attr-defined]
        parsed = urlsplit(self.path)
        if parsed.path in ("/__lab__/attempt/reset", "/__lab__/request-log", "/__lab__/health"):
            query = parse_qs(parsed.query)
            nonce = query.get("nonce", [""])[0]
            run_id = query.get("run_id", [""])[0]
            if nonce != fixture["attempt_nonce"] or run_id != fixture["run_id"]:
                self.send_error(403)
                return
            if parsed.path.endswith("/health"):
                data = json.dumps({"status": "ok", "run_id": fixture["run_id"], "role": "consumer-fixture"}).encode()
            elif parsed.path.endswith("/reset"):
                with fixture["request_lock"]:
                    if fixture["reset_used"]:
                        self.send_error(409, "attempt reset already consumed")
                        return
                    try:
                        raw = fixture["request_log"].read_bytes()
                        rows = [json.loads(line) for line in raw.splitlines()]
                    except (OSError, json.JSONDecodeError):
                        self.send_error(409, "invalid pre-reset request log")
                        return
                    if (len(raw) > MAX_REQUEST_LOG_BYTES or len(rows) != 1
                            or rows[0].get("run_id") != fixture["run_id"]
                            or rows[0].get("attempt_nonce") != fixture["attempt_nonce"]
                            or rows[0].get("method") != "GET" or rows[0].get("path") != "/healthz"
                            or rows[0].get("status") != 200
                            or rows[0].get("bytes") != rows[0].get("content_length")):
                        self.send_error(409, "unexpected pre-reset request log")
                        return
                    fixture["request_log"].write_text("", encoding="utf-8")
                    fixture["request_count"] = 0
                    fixture["request_log_limited"] = False
                    fixture["reset_used"] = True
                data = json.dumps({"status": "reset", "run_id": fixture["run_id"]}).encode()
            else:
                if not fixture["reset_used"]:
                    self.send_error(409, "attempt reset is required")
                    return
                data = fixture["request_log"].read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "application/jsonl")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-Amnezia-Run-Id", fixture["run_id"])
            self.end_headers()
            if body:
                self.wfile.write(data)
            return
        if self.path.split("?", 1)[0] == "/healthz":
            data = json.dumps({"status": "ok", "run_id": fixture["run_id"], "role": "consumer-fixture"}).encode()
            source_sha = hashlib.sha256(data).hexdigest()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-Amnezia-Run-Id", fixture["run_id"])
            self.send_header("X-Amnezia-Sha256", source_sha)
            self.end_headers()
            if body:
                self.wfile.write(data)
            self._log_request(fixture, 200, len(data) if body else 0, len(data), source_sha)
            return
        path = self.path.split("?", 1)[0]
        if path == "/manifest.json":
            source, content_type = fixture["manifest"], "application/json"
        elif path == fixture["artifact_path"]:
            source, content_type = fixture["apk"], "application/vnd.android.package-archive"
        else:
            self.send_error(404)
            self._log_request(fixture, 404, 0, 0, "")
            return
        size = source.stat().st_size
        source_sha = sha256(source)
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(size))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Amnezia-Run-Id", fixture["run_id"])
        self.send_header("X-Amnezia-Sha256", source_sha)
        self.end_headers()
        if body:
            with source.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    self.wfile.write(chunk)
        self._log_request(fixture, 200, size if body else 0, size, source_sha)

    def _log_request(self, fixture: dict, status: int, body_bytes: int, content_length: int, sha256_value: str) -> None:
        with fixture["request_lock"]:
            if fixture["request_log_limited"]:
                return
            if fixture["request_count"] >= MAX_REQUEST_RECORDS - 1 or fixture["request_log"].stat().st_size >= MAX_REQUEST_LOG_BYTES:
                record = {
                    "attempt_nonce": fixture["attempt_nonce"],
                    "error": "request-log-limit",
                    "method": "LIMIT",
                    "path": self.path,
                    "run_id": fixture["run_id"],
                    "status": 599,
                    "timestamp": time.time(),
                }
                with fixture["request_log"].open("a", encoding="utf-8") as log:
                    log.write(json.dumps(record, sort_keys=True) + "\n")
                fixture["request_count"] += 1
                fixture["request_log_limited"] = True
                return
            record = {
                "attempt_nonce": fixture["attempt_nonce"],
                "bytes": body_bytes,
                "client": self.client_address[0],
                "content_length": content_length,
                "method": self.command,
                "path": self.path,
                "run_id": fixture["run_id"],
                "sha256": sha256_value,
                "status": status,
                "timestamp": time.time(),
            }
            encoded = json.dumps(record, sort_keys=True) + "\n"
            if fixture["request_log"].stat().st_size + len(encoded.encode("utf-8")) > MAX_REQUEST_LOG_BYTES:
                fixture["request_log_limited"] = True
                return
            with fixture["request_log"].open("a", encoding="utf-8") as log:
                log.write(encoded)
            fixture["request_count"] += 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--apk", type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--apk-sha256", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--attempt-nonce", required=True)
    parser.add_argument("--port", type=int, default=GUEST_PORT)
    parser.add_argument("--request-log", type=Path, default=Path("/tmp/amnezia-consumer-fixture-requests.jsonl"))
    args = parser.parse_args()
    if args.port != GUEST_PORT:
        raise SystemExit(f"fixture guest port is fixed at {GUEST_PORT}")
    if sha256(args.manifest) != args.manifest_sha256.lower():
        raise SystemExit("fixture manifest digest mismatch")
    manifest = load_manifest(args.manifest)
    if sha256(args.apk) != args.apk_sha256.lower():
        raise SystemExit("fixture APK digest mismatch")
    server = ThreadingHTTPServer(("0.0.0.0", args.port), FixtureHandler)
    server.fixture = {  # type: ignore[attr-defined]
        "run_id": args.run_id,
        "attempt_nonce": args.attempt_nonce,
        "manifest": args.manifest,
        "apk": args.apk,
        "artifact_path": artifact_path_from_manifest(manifest, args.apk_sha256),
        "document": manifest,
        "request_log": args.request_log,
        "request_lock": threading.Lock(),
        "request_count": 0,
        "request_log_limited": False,
        "reset_used": False,
    }
    server.serve_forever(poll_interval=0.2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
