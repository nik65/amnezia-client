#!/usr/bin/env python3
"""Offline-only consumer fixture HTTP server for the sealed server-router guest.

The controller uploads the signed manifest and APK through QGA. This process
serves those exact bytes and refuses to start when either digest is wrong.
It is a test fixture, never a release publisher.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Final


GUEST_PORT: Final = 17865


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


class FixtureHandler(BaseHTTPRequestHandler):
    server_version = "AmneziaConsumerFixture/1"

    def do_HEAD(self) -> None:  # noqa: N802
        self._serve(False)

    def do_GET(self) -> None:  # noqa: N802
        self._serve(True)

    def log_message(self, *_args: object) -> None:
        return

    def _serve(self, body: bool) -> None:
        fixture = self.server.fixture  # type: ignore[attr-defined]
        with fixture["request_log"].open("a", encoding="utf-8") as log:
            log.write(json.dumps({"method": self.command, "path": self.path, "client": self.client_address[0]}) + "\n")
        if self.path.split("?", 1)[0] == "/healthz":
            data = json.dumps({"status": "ok", "run_id": fixture["run_id"], "role": "consumer-fixture"}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            if body:
                self.wfile.write(data)
            return
        path = self.path.split("?", 1)[0]
        if path == "/manifest.json":
            source, content_type = fixture["manifest"], "application/json"
        elif path == "/artifact.apk" or path.startswith("/files/artifacts/"):
            source, content_type = fixture["apk"], "application/vnd.android.package-archive"
        else:
            self.send_error(404)
            return
        size = source.stat().st_size
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(size))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if body:
            with source.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    self.wfile.write(chunk)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--apk", type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--apk-sha256", required=True)
    parser.add_argument("--run-id", required=True)
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
    server.fixture = {"run_id": args.run_id, "manifest": args.manifest, "apk": args.apk, "document": manifest, "request_log": args.request_log}  # type: ignore[attr-defined]
    server.serve_forever(poll_interval=0.2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
