import http.client
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import socket
import sqlite3
import sys
import tempfile
import threading
import time
import types
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest import mock


SOURCE_PATH = Path(__file__).with_name("exportController.cpp")


def load_collector(root: Path):
    source = SOURCE_PATH.read_text(encoding="utf-8")
    segments = re.findall(r'R"PY\d*\((.*?)\)PY\d*"', source, re.DOTALL)
    if not segments:
        raise AssertionError("embedded client log collector script was not found")

    script = "".join(segments)
    script = script.replace('ROOT = "/data"', f"ROOT = {str(root)!r}")
    script = script.replace("__MAX_UPLOAD_BYTES__", str(15 * 1024 * 1024))
    script = script.replace("__MAX_CLIENT_BYTES__", str(30 * 1024 * 1024))
    script = script.replace("__PORT__", "17866")
    script = script.replace("__UPLOAD_PATH__", "/logs")
    script = script.replace("__BOOTSTRAP_PATH__", "/bootstrap")

    module_overrides = {}
    try:
        importlib.import_module("fcntl")
    except ModuleNotFoundError:
        fake_fcntl = types.ModuleType("fcntl")
        fake_fcntl.LOCK_EX = 1
        fake_fcntl.LOCK_UN = 2
        fake_fcntl.flock = lambda *_args: None
        module_overrides["fcntl"] = fake_fcntl
    module = types.ModuleType("amnezia_client_logs_collector_test")
    with mock.patch.dict(sys.modules, module_overrides):
        exec(compile(script, str(SOURCE_PATH), "exec"), module.__dict__)
    return module


def cross_process_lock_worker(root, start_event, active_count, peak_count):
    collector = load_collector(Path(root))
    start_event.wait(timeout=5)
    with collector.client_lock("c" * 64):
        with active_count.get_lock():
            active_count.value += 1
            active = active_count.value
        with peak_count.get_lock():
            peak_count.value = max(peak_count.value, active)
        time.sleep(0.15)
        with active_count.get_lock():
            active_count.value -= 1


def cross_process_global_storage_lock_worker(
        root, start_event, active_count, peak_count):
    collector = load_collector(Path(root))
    start_event.wait(timeout=5)
    with collector.global_storage_lock():
        with active_count.get_lock():
            active_count.value += 1
            active = active_count.value
        with peak_count.get_lock():
            peak_count.value = max(peak_count.value, active)
        time.sleep(0.15)
        with active_count.get_lock():
            active_count.value -= 1


class ClientLogsCollectorTest(unittest.TestCase):
    CLIENT_ID = "a" * 64
    TOKEN = "test-token"
    BATCH_ID = "b" * 64

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.collector = load_collector(self.root)
        self.real_fsync_directory = self.collector.fsync_directory
        if os.name == "nt":
            self.collector.fsync_directory = lambda _path: None
        self.collector.MAX_HANDLER_THREADS = 4
        self.collector.PRE_HEADER_TIMEOUT_SECONDS = 0.5
        self.root.mkdir(mode=0o700, exist_ok=True)
        (self.root / "logs").mkdir(mode=0o700, exist_ok=True)
        (self.root / "tokens.tsv").write_text(
            f"{self.CLIENT_ID}\t{self.TOKEN}\n", encoding="utf-8")

        self.server = self.collector.LogServer(("127.0.0.1", 0), self.collector.Handler)
        self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.server_thread.start()
        self.port = self.server.server_address[1]

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.server_thread.join(timeout=5)
        self.temp_dir.cleanup()

    def request(self, method, path, body=b"", extra_headers=None):
        headers = dict(extra_headers or {})
        if method == "POST":
            headers.setdefault("Content-Length", str(len(body)))
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        response_body = response.read()
        result = response.status, dict(response.getheaders()), response_body
        connection.close()
        return result

    def upload_headers(self, batch_id=None):
        headers = {
            "X-Amnezia-Client-Id": self.CLIENT_ID,
            "X-Amnezia-Log-Token": self.TOKEN,
            "X-Amnezia-Log-Kind": "client",
            "X-Amnezia-Installation-Id": "test-installation",
        }
        if batch_id is not None:
            headers["X-Amnezia-Batch-Id"] = batch_id
        return headers

    def stored_logs(self):
        client_dir = self.root / "logs" / self.CLIENT_ID
        return sorted(client_dir.glob("*.log")) if client_dir.exists() else []

    def assert_no_batch_receipt_headers(self, headers):
        self.assertNotIn("X-Amnezia-Batch-Accepted", headers)
        self.assertNotIn("X-Amnezia-Batch-Id", headers)
        self.assertNotIn("X-Amnezia-Batch-Replayed", headers)

    def test_batch_retry_is_replayed_without_duplicate_file(self):
        payload = b"first payload"
        status, headers, _ = self.request(
            "POST", "/logs", payload, self.upload_headers(self.BATCH_ID))
        self.assertEqual(204, status)
        self.assertEqual("1", headers.get("X-Amnezia-Batch-Accepted"))
        self.assertEqual(self.BATCH_ID, headers.get("X-Amnezia-Batch-Id"))
        self.assertNotIn("X-Amnezia-Batch-Replayed", headers)

        status, headers, _ = self.request(
            "POST", "/logs", payload, self.upload_headers(self.BATCH_ID))
        self.assertEqual(204, status)
        self.assertEqual("1", headers.get("X-Amnezia-Batch-Accepted"))
        self.assertEqual(self.BATCH_ID, headers.get("X-Amnezia-Batch-Id"))
        self.assertEqual("1", headers.get("X-Amnezia-Batch-Replayed"))

        stored = self.stored_logs()
        self.assertEqual(1, len(stored))
        self.assertEqual(payload, stored[0].read_bytes())

    def test_batch_retry_with_different_body_is_rejected(self):
        status, _, _ = self.request(
            "POST", "/logs", b"first payload", self.upload_headers(self.BATCH_ID))
        self.assertEqual(204, status)

        status, headers, _ = self.request(
            "POST", "/logs", b"different retry body", self.upload_headers(self.BATCH_ID))

        self.assertEqual(409, status)
        self.assert_no_batch_receipt_headers(headers)
        stored = self.stored_logs()
        self.assertEqual(1, len(stored))
        self.assertEqual(b"first payload", stored[0].read_bytes())

    def test_receipt_replays_after_log_retention(self):
        status, _, _ = self.request(
            "POST", "/logs", b"original", self.upload_headers(self.BATCH_ID))
        self.assertEqual(204, status)
        self.stored_logs()[0].unlink()

        status, headers, _ = self.request(
            "POST", "/logs", b"original", self.upload_headers(self.BATCH_ID))

        self.assertEqual(204, status)
        self.assertEqual("1", headers.get("X-Amnezia-Batch-Accepted"))
        self.assertEqual(self.BATCH_ID, headers.get("X-Amnezia-Batch-Id"))
        self.assertEqual("1", headers.get("X-Amnezia-Batch-Replayed"))
        self.assertEqual([], self.stored_logs())

    def test_directory_fsync_failure_never_records_receipt_or_success(self):
        def fail_fsync(_path):
            raise OSError("simulated directory fsync failure")

        self.collector.fsync_directory = fail_fsync
        status, headers, _ = self.request(
            "POST", "/logs", b"payload", self.upload_headers(self.BATCH_ID))
        self.assertEqual(500, status)
        self.assert_no_batch_receipt_headers(headers)
        self.assertFalse(self.collector.batch_receipt_exists(self.CLIENT_ID, self.BATCH_ID))

        status, _, _ = self.request(
            "POST", "/logs", b"payload", self.upload_headers(self.BATCH_ID))
        self.assertEqual(500, status)
        self.assertFalse(self.collector.batch_receipt_exists(self.CLIENT_ID, self.BATCH_ID))

        self.collector.fsync_directory = (
            self.real_fsync_directory if os.name != "nt" else (lambda _path: None))
        status, headers, _ = self.request(
            "POST", "/logs", b"payload", self.upload_headers(self.BATCH_ID))
        self.assertEqual(204, status)
        self.assertEqual("1", headers.get("X-Amnezia-Batch-Accepted"))
        self.assertEqual(self.BATCH_ID, headers.get("X-Amnezia-Batch-Id"))
        self.assertEqual("1", headers.get("X-Amnezia-Batch-Replayed"))
        self.assertTrue(self.collector.batch_receipt_exists(self.CLIENT_ID, self.BATCH_ID))

    def test_concurrent_batch_retries_store_one_file(self):
        def upload():
            return self.request(
                "POST", "/logs", b"same payload", self.upload_headers(self.BATCH_ID))

        with ThreadPoolExecutor(max_workers=4) as executor:
            responses = list(executor.map(lambda _: upload(), range(4)))

        self.assertTrue(all(status == 204 for status, _, _ in responses))
        self.assertTrue(all(
            headers.get("X-Amnezia-Batch-Accepted") == "1"
            and headers.get("X-Amnezia-Batch-Id") == self.BATCH_ID
            for _, headers, _ in responses))
        self.assertEqual(1, len(self.stored_logs()))
        replay_count = sum(
            headers.get("X-Amnezia-Batch-Replayed") == "1"
            for _, headers, _ in responses)
        self.assertEqual(3, replay_count)

    def test_concurrent_distinct_clients_serialize_global_commit_and_keep_hard_cap(self):
        clients = [character * 64 for character in ("a", "c", "d", "e")]
        tokens = [f"token-{index}" for index in range(len(clients))]
        (self.root / "tokens.tsv").write_text(
            "".join(f"{client_id}\t{token}\n" for client_id, token in zip(clients, tokens)),
            encoding="utf-8")
        self.collector.invalidate_token_caches()
        self.collector.MAX_TOTAL_BYTES = 12
        self.collector.MAX_TOTAL_FILES = 2

        real_replace = self.collector.os.replace
        commit_guard = threading.Lock()
        active_commits = 0
        peak_commits = 0
        observed_summaries = []

        def observing_replace(source, destination):
            nonlocal active_commits, peak_commits
            if not os.fspath(destination).endswith(".log"):
                return real_replace(source, destination)
            with commit_guard:
                active_commits += 1
                peak_commits = max(peak_commits, active_commits)
            try:
                time.sleep(0.03)
                result = real_replace(source, destination)
                observed_summaries.append(self.collector.storage_summary())
                return result
            finally:
                with commit_guard:
                    active_commits -= 1

        start_event = threading.Event()

        def upload(index):
            start_event.wait(timeout=5)
            batch_id = format(index + 1, "x") * 64
            headers = self.upload_headers(batch_id)
            headers["X-Amnezia-Client-Id"] = clients[index]
            headers["X-Amnezia-Log-Token"] = tokens[index]
            return batch_id, self.request("POST", "/logs", b"data-0", headers)

        with mock.patch.object(self.collector.os, "replace", side_effect=observing_replace):
            with ThreadPoolExecutor(max_workers=len(clients)) as executor:
                futures = [executor.submit(upload, index) for index in range(len(clients))]
                start_event.set()
                results = [future.result() for future in futures]

        self.assertTrue(all(response[0] == 204 for _, response in results))
        self.assertEqual(1, peak_commits)
        self.assertEqual(len(clients), len(observed_summaries))
        self.assertTrue(all(
            summary["bytes"] <= self.collector.MAX_TOTAL_BYTES
            and summary["files"] <= self.collector.MAX_TOTAL_FILES
            for summary in observed_summaries))
        summary = self.collector.storage_summary()
        self.assertLessEqual(summary["bytes"], self.collector.MAX_TOTAL_BYTES)
        self.assertLessEqual(summary["files"], self.collector.MAX_TOTAL_FILES)
        for index, (batch_id, _) in enumerate(results):
            self.assertTrue(self.collector.batch_receipt_exists(clients[index], batch_id))

    def test_upload_larger_than_global_quota_is_rejected_without_receipt(self):
        self.collector.MAX_TOTAL_BYTES = 3

        status, headers, _ = self.request(
            "POST", "/logs", b"four", self.upload_headers(self.BATCH_ID))

        self.assertEqual(507, status)
        self.assert_no_batch_receipt_headers(headers)
        self.assertEqual([], self.stored_logs())
        self.assertFalse(self.collector.batch_receipt_exists(self.CLIENT_ID, self.BATCH_ID))
        self.assertEqual([], list((self.root / "logs").rglob("*.tmp-*")))

    def test_missing_batch_id_is_rejected_without_storing_raw_legacy_payload(self):
        status, headers, _ = self.request(
            "POST", "/logs", b"legacy secret payload", self.upload_headers())

        self.assertEqual(428, status)
        self.assert_no_batch_receipt_headers(headers)
        self.assertEqual([], self.stored_logs())

    def test_invalid_batch_id_is_rejected(self):
        status, headers, _ = self.request(
            "POST", "/logs", b"payload", self.upload_headers("B" * 64))
        self.assertEqual(400, status)
        self.assert_no_batch_receipt_headers(headers)
        self.assertEqual([], self.stored_logs())

    def test_non_ascii_token_is_rejected_without_dropping_connection(self):
        headers = self.upload_headers(self.BATCH_ID)
        headers["X-Amnezia-Log-Token"] = "t\u00e9st-token"
        status, response_headers, _ = self.request("POST", "/logs", b"payload", headers)
        self.assertEqual(403, status)
        self.assert_no_batch_receipt_headers(response_headers)

    def test_token_file_content_is_cached_until_signature_changes(self):
        original_open = open
        token_reads = 0

        def counting_open(path, mode="r", *args, **kwargs):
            nonlocal token_reads
            if os.fspath(path) == str(self.root / "tokens.tsv") and mode == "r":
                token_reads += 1
            return original_open(path, mode, *args, **kwargs)

        with mock.patch("builtins.open", side_effect=counting_open):
            for batch_id in ("d" * 64, "e" * 64):
                status, _, _ = self.request(
                    "POST", "/logs", b"payload", self.upload_headers(batch_id))
                self.assertEqual(204, status)
        self.assertEqual(1, token_reads)

        token_path = self.root / "tokens.tsv"
        previous_stat = token_path.stat()
        replacement = self.root / "tokens.tsv.replacement"
        replacement.write_text(
            f"{self.CLIENT_ID}\tnext-token\n", encoding="utf-8")
        os.utime(
            replacement,
            ns=(previous_stat.st_atime_ns, previous_stat.st_mtime_ns))
        os.replace(replacement, token_path)
        self.assertEqual("next-token", self.collector.load_tokens()[self.CLIENT_ID])

    def test_legacy_token_and_address_maps_invalidate_on_atomic_replace(self):
        self.collector.ALLOW_BOOTSTRAP = True
        self.collector.CONTAINER_SCOPE = "awg"
        legacy_token_path = self.root / "legacy_tokens.tsv"
        legacy_root = self.root / "legacy"
        legacy_root.mkdir(exist_ok=True)
        legacy_map_path = legacy_root / "awg.tsv"
        legacy_token_path.write_text(
            f"{self.CLIENT_ID}\told-token\tawg\n", encoding="utf-8")
        legacy_map_path.write_text(
            f"10.0.0.2\t{self.CLIENT_ID}\n", encoding="utf-8")
        self.assertIn(
            (self.CLIENT_ID, "old-token", "awg"),
            self.collector.load_legacy_tokens())
        self.assertEqual(
            self.CLIENT_ID,
            self.collector.resolve_legacy_client_id("10.0.0.2"))

        for path, content in (
                (legacy_token_path, f"{self.CLIENT_ID}\tnew-token\tawg\n"),
                (legacy_map_path, f"10.0.0.3\t{self.CLIENT_ID}\n")):
            previous_stat = path.stat()
            replacement = path.with_suffix(path.suffix + ".replacement")
            replacement.write_text(content, encoding="utf-8")
            os.utime(
                replacement,
                ns=(previous_stat.st_atime_ns, previous_stat.st_mtime_ns))
            os.replace(replacement, path)

        self.assertIn(
            (self.CLIENT_ID, "new-token", "awg"),
            self.collector.load_legacy_tokens())
        self.assertNotIn(
            (self.CLIENT_ID, "old-token", "awg"),
            self.collector.load_legacy_tokens())
        self.assertEqual("", self.collector.resolve_legacy_client_id("10.0.0.2"))
        self.assertEqual(
            self.CLIENT_ID,
            self.collector.resolve_legacy_client_id("10.0.0.3"))

    def test_bootstrap_response_has_no_batch_receipt_headers(self):
        self.collector.ALLOW_BOOTSTRAP = True
        self.collector.CONTAINER_SCOPE = "awg"
        legacy_root = self.root / "legacy"
        legacy_root.mkdir(exist_ok=True)
        (legacy_root / "awg.tsv").write_text(
            f"127.0.0.1\t{self.CLIENT_ID}\n", encoding="utf-8")

        status, headers, body = self.request(
            "POST",
            "/bootstrap",
            b"",
            {"X-Amnezia-Client-Id": self.CLIENT_ID})

        self.assertEqual(200, status)
        self.assert_no_batch_receipt_headers(headers)
        response = json.loads(body)
        self.assertEqual(self.CLIENT_ID, response["clientId"])
        self.assertEqual(self.TOKEN, response["token"])

    def test_health_is_readiness_only_and_contains_no_activity_or_credentials(self):
        status, _, _ = self.request(
            "POST", "/logs", b"payload", self.upload_headers(self.BATCH_ID))
        self.assertEqual(204, status)

        status, headers, body = self.request("GET", "/healthz")
        self.assertEqual(200, status)
        self.assertEqual("no-store", headers.get("Cache-Control"))
        self.assert_no_batch_receipt_headers(headers)
        health = json.loads(body)
        self.assertEqual({"status": "ok", "collectorVersion": 3}, health)
        rendered = body.decode("utf-8")
        self.assertNotIn(self.CLIENT_ID, rendered)
        self.assertNotIn(self.TOKEN, rendered)
        self.assertNotIn("storage", health)
        self.assertNotIn("processUploads", health)
        self.assertNotIn("lastSuccessAgeSeconds", health)

    def test_health_degrades_when_a_required_store_is_not_ready(self):
        self.collector.receipt_store_ready = lambda: False
        self.collector.invalidate_health_cache()

        status, headers, body = self.request("GET", "/healthz")

        self.assertEqual(503, status)
        self.assert_no_batch_receipt_headers(headers)
        self.assertEqual(
            {"status": "degraded", "collectorVersion": 3},
            json.loads(body))

    def test_health_degrades_when_token_store_is_missing(self):
        (self.root / "tokens.tsv").unlink()
        self.collector.invalidate_health_cache()

        status, headers, body = self.request("GET", "/healthz")

        self.assertEqual(503, status)
        self.assert_no_batch_receipt_headers(headers)
        self.assertEqual("degraded", json.loads(body)["status"])

    def test_health_degrades_when_global_log_quota_is_already_exceeded(self):
        client_dir = self.root / "logs" / self.CLIENT_ID
        client_dir.mkdir(mode=0o700, exist_ok=True)
        (client_dir / "external.log").write_bytes(b"over")
        self.collector.MAX_TOTAL_BYTES = 3
        self.collector.invalidate_health_cache()

        status, headers, body = self.request("GET", "/healthz")

        self.assertEqual(503, status)
        self.assert_no_batch_receipt_headers(headers)
        self.assertEqual("degraded", json.loads(body)["status"])

    def test_global_prune_enforces_age_and_total_size(self):
        client_dir = self.root / "logs" / self.CLIENT_ID
        client_dir.mkdir(mode=0o700, exist_ok=True)
        expired = client_dir / "expired.log"
        older = client_dir / "older.log"
        newest = client_dir / "newest.log"
        expired.write_bytes(b"xxxxx")
        older.write_bytes(b"yyyyy")
        newest.write_bytes(b"zzzzz")
        now = time.time()
        os.utime(expired, (now - 100, now - 100))
        os.utime(older, (now - 2, now - 2))
        os.utime(newest, (now - 1, now - 1))
        self.collector.MAX_LOG_AGE_SECONDS = 10
        self.collector.MAX_TOTAL_BYTES = 8

        self.collector.prune_all_logs()

        self.assertFalse(expired.exists())
        self.assertFalse(older.exists())
        self.assertTrue(newest.exists())
        self.assertLessEqual(self.collector.storage_summary()["bytes"], 8)

    def test_prune_enforces_file_count(self):
        client_dir = self.root / "logs" / self.CLIENT_ID
        client_dir.mkdir(mode=0o700, exist_ok=True)
        files = [client_dir / f"{index}.log" for index in range(3)]
        now = time.time()
        for index, path in enumerate(files):
            path.write_bytes(b"x")
            os.utime(path, (now + index, now + index))
        self.collector.MAX_CLIENT_BYTES = 1024
        self.collector.MAX_FILES_PER_CLIENT = 2

        self.collector.prune_client_dir(str(client_dir))

        self.assertFalse(files[0].exists())
        self.assertTrue(files[1].exists())
        self.assertTrue(files[2].exists())

    def test_periodic_retention_removes_expired_logs_without_upload(self):
        client_dir = self.root / "logs" / self.CLIENT_ID
        client_dir.mkdir(mode=0o700, exist_ok=True)
        expired = client_dir / "expired.log"
        expired.write_bytes(b"expired")
        old = time.time() - 60
        os.utime(expired, (old, old))
        self.collector.MAX_LOG_AGE_SECONDS = 1
        stop_event = threading.Event()
        worker = threading.Thread(
            target=self.collector.retention_worker,
            args=(stop_event, 0.02),
            daemon=True)
        worker.start()
        deadline = time.time() + 2
        while expired.exists() and time.time() < deadline:
            time.sleep(0.02)
        stop_event.set()
        worker.join(timeout=2)
        self.assertFalse(expired.exists())

    def test_stale_token_lock_is_recovered(self):
        lock_dir = self.root / "tokens.lock"
        lock_dir.mkdir()
        old = time.time() - self.collector.TOKEN_LOCK_STALE_SECONDS - 1
        os.utime(lock_dir, (old, old))
        called = []

        self.collector.with_token_file_lock(lambda: called.append(True))

        self.assertEqual([True], called)
        self.assertFalse(lock_dir.exists())

    def test_receipt_ledger_is_bounded_per_client_and_globally(self):
        self.collector.MAX_RECEIPTS_PER_CLIENT = 2
        self.collector.MAX_TOTAL_RECEIPTS = 2
        batches = [character * 64 for character in ("d", "e", "f")]
        for batch_id in batches:
            self.collector.record_batch_receipt(
                self.CLIENT_ID, batch_id, hashlib.sha256(batch_id.encode()).hexdigest(), 1)
        self.assertFalse(self.collector.batch_receipt_exists(self.CLIENT_ID, batches[0]))
        self.assertTrue(self.collector.batch_receipt_exists(self.CLIENT_ID, batches[-1]))

        self.collector.record_batch_receipt(
            "c" * 64, "9" * 64, hashlib.sha256(b"other").hexdigest(), 1)
        self.collector.prune_batch_receipts()
        connection = self.collector.open_receipt_db()
        try:
            receipt_count = connection.execute(
                "SELECT COUNT(*) FROM batch_receipts").fetchone()[0]
        finally:
            connection.close()
        self.assertLessEqual(receipt_count, 2)

    def test_old_receipt_schema_is_migrated_and_bound_on_first_replay(self):
        receipt_path = self.root / "batch-receipts.sqlite3"
        connection = sqlite3.connect(receipt_path)
        try:
            connection.execute(
                "CREATE TABLE batch_receipts ("
                "client_id TEXT NOT NULL, batch_id TEXT NOT NULL, accepted_at INTEGER NOT NULL, "
                "PRIMARY KEY (client_id, batch_id))")
            connection.execute(
                "INSERT INTO batch_receipts (client_id, batch_id, accepted_at) VALUES (?, ?, ?)",
                (self.CLIENT_ID, self.BATCH_ID, int(time.time())))
            connection.commit()
        finally:
            connection.close()

        status, headers, _ = self.request(
            "POST", "/logs", b"migration payload", self.upload_headers(self.BATCH_ID))

        self.assertEqual(204, status)
        self.assertEqual("1", headers.get("X-Amnezia-Batch-Accepted"))
        self.assertEqual(self.BATCH_ID, headers.get("X-Amnezia-Batch-Id"))
        self.assertEqual("1", headers.get("X-Amnezia-Batch-Replayed"))
        self.assertEqual(
            (hashlib.sha256(b"migration payload").hexdigest(), len(b"migration payload")),
            self.collector.batch_receipt_metadata(self.CLIENT_ID, self.BATCH_ID))
        self.assertEqual([], self.stored_logs())

    def test_global_retention_scan_is_throttled_and_persisted(self):
        original_prune = self.collector.prune_all_logs_unlocked
        with mock.patch.object(
                self.collector, "prune_all_logs_unlocked", wraps=original_prune) as prune:
            for batch_id in ("d" * 64, "e" * 64):
                status, _, _ = self.request(
                    "POST", "/logs", b"payload", self.upload_headers(batch_id))
                self.assertEqual(204, status)
            self.assertEqual(1, prune.call_count)

        self.assertTrue((self.root / "retention.last").is_file())
        reloaded = load_collector(self.root)
        if os.name == "nt":
            reloaded.fsync_directory = lambda _path: None
        with mock.patch.object(
                reloaded,
                "prune_all_logs_unlocked",
                wraps=reloaded.prune_all_logs_unlocked) as reloaded_prune:
            self.assertFalse(reloaded.run_retention_pass())
            self.assertEqual(0, reloaded_prune.call_count)

    def test_pre_header_connections_are_timed_out_and_thread_count_is_bounded(self):
        self.collector.PRE_HEADER_TIMEOUT_SECONDS = 1
        partial_connections = []
        try:
            for _ in range(self.collector.MAX_HANDLER_THREADS):
                connection = socket.create_connection(("127.0.0.1", self.port), timeout=2)
                connection.sendall(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n")
                partial_connections.append(connection)

            deadline = time.time() + 2
            while (self.server.active_handler_count() < self.collector.MAX_HANDLER_THREADS
                   and time.time() < deadline):
                time.sleep(0.01)
            self.assertEqual(
                self.collector.MAX_HANDLER_THREADS,
                self.server.active_handler_count())

            overflow = socket.create_connection(("127.0.0.1", self.port), timeout=2)
            try:
                overflow.sendall(
                    b"GET /healthz HTTP/1.0\r\nHost: localhost\r\n\r\n")
                try:
                    response = overflow.recv(256)
                except (ConnectionAbortedError, ConnectionResetError):
                    response = b""
            finally:
                overflow.close()
            self.assertTrue(
                not response
                or response.startswith(b"HTTP/1.0 503 Service Unavailable"))
            self.assertLessEqual(
                self.server.active_handler_count(),
                self.collector.MAX_HANDLER_THREADS)

            deadline = time.time() + 2
            while self.server.active_handler_count() and time.time() < deadline:
                time.sleep(0.01)
            self.assertEqual(0, self.server.active_handler_count())
        finally:
            for connection in partial_connections:
                connection.close()

    def test_incomplete_headers_are_closed_after_pre_header_timeout(self):
        self.collector.PRE_HEADER_TIMEOUT_SECONDS = 0.1
        connection = socket.create_connection(("127.0.0.1", self.port), timeout=2)
        try:
            connection.sendall(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n")
            connection.settimeout(2)
            self.assertEqual(b"", connection.recv(1))
        finally:
            connection.close()

        deadline = time.time() + 2
        while self.server.active_handler_count() and time.time() < deadline:
            time.sleep(0.01)
        self.assertEqual(0, self.server.active_handler_count())

    def test_collector_container_is_digest_pinned_and_hardened(self):
        source = SOURCE_PATH.read_text(encoding="utf-8")
        self.assertRegex(
            source,
            r'python:3\.12-alpine@sha256:[a-f0-9]{64}')
        run_lines = [line for line in source.splitlines() if "sudo docker run -d" in line]
        self.assertEqual(2, len(run_lines))
        for run_line in run_lines:
            self.assertIn("--cap-drop ALL", run_line)
            self.assertIn("--security-opt no-new-privileges:true", run_line)
            self.assertIn("--read-only", run_line)
            self.assertIn("--tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777", run_line)
            self.assertIn("PYTHONDONTWRITEBYTECODE=1", run_line)

    @unittest.skipUnless(os.name == "posix", "requires real POSIX flock")
    def test_client_lock_serializes_independent_processes(self):
        import multiprocessing

        context = multiprocessing.get_context("fork")
        start_event = context.Event()
        active_count = context.Value("i", 0)
        peak_count = context.Value("i", 0)
        processes = [
            context.Process(
                target=cross_process_lock_worker,
                args=(str(self.root), start_event, active_count, peak_count))
            for _ in range(2)
        ]
        for process in processes:
            process.start()
        start_event.set()
        for process in processes:
            process.join(timeout=5)
            self.assertEqual(0, process.exitcode)
        self.assertEqual(1, peak_count.value)

    @unittest.skipUnless(os.name == "posix", "requires real POSIX flock")
    def test_global_storage_lock_serializes_independent_processes(self):
        import multiprocessing

        context = multiprocessing.get_context("fork")
        start_event = context.Event()
        active_count = context.Value("i", 0)
        peak_count = context.Value("i", 0)
        processes = [
            context.Process(
                target=cross_process_global_storage_lock_worker,
                args=(str(self.root), start_event, active_count, peak_count))
            for _ in range(2)
        ]
        for process in processes:
            process.start()
        start_event.set()
        for process in processes:
            process.join(timeout=5)
            self.assertEqual(0, process.exitcode)
        self.assertEqual(1, peak_count.value)


if __name__ == "__main__":
    unittest.main()
