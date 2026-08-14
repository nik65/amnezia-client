#include "exportController.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QDebug>
#include <QByteArray>
#include <QStringList>

#include "core/configurators/configuratorBase.h"
#include "core/utils/selfhosted/sshSession.h"
#include "core/utils/qrCodeUtils.h"
#include "core/utils/serialization/serialization.h"
#include "core/utils/protocolEnum.h"
#include "core/protocols/protocolUtils.h"
#include "core/utils/constants/configKeys.h"
#include "core/utils/constants/protocolConstants.h"
#include "core/utils/selfhosted/clientLogsUtils.h"
#include "core/models/selfhosted/selfHostedAdminServerConfig.h"
#include "core/models/containerConfig.h"
#include "core/models/protocolConfig.h"
#include "core/utils/containers/containerUtils.h"
#include "core/utils/utilities.h"

using namespace amnezia;

namespace
{
void removeClientResolvedServerRoutingRules(QJsonObject &serverConfig)
{
    serverConfig.remove(configKey::managedSplitTunnelClientResolvedExceptSites);
    serverConfig.remove(configKey::managedSplitTunnelClientResolvedAt);
    serverConfig.remove(configKey::managedSplitTunnelClientResolveRetryAfter);
    serverConfig.remove(configKey::managedSplitTunnelClientResolvePendingSites);
    serverConfig.remove(configKey::managedSplitTunnelClientResolvePendingSourceDigest);
    serverConfig.remove(configKey::managedSplitTunnelClientResolveLastFullSweepAt);
}

constexpr char clientLogsPublishErrorMarker[] = "__AMNEZIA_CLIENT_LOGS_PUBLISH_ERROR__";
constexpr char clientLogsCollectorImage[] =
        "python:3.12-alpine@sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df";

QString clientLogsTunnelInterface(DockerContainer container)
{
    if (container == DockerContainer::Awg2) {
        return QStringLiteral("awg0");
    }
    if (container == DockerContainer::Awg || container == DockerContainer::WireGuard) {
        return QStringLiteral("wg0");
    }
    if (container == DockerContainer::OpenVpn) {
        return QStringLiteral("tun0");
    }
    return {};
}

QString clientLogsEndpoint()
{
    return clientLogsUtils::endpoint();
}

QString clientLogsStorageId(DockerContainer container, const QString &clientId)
{
    return clientLogsUtils::storageId(container, clientId);
}

QString clientsTablePath(DockerContainer container)
{
    if (container == DockerContainer::OpenVpn) {
        return QStringLiteral("/opt/amnezia/%1/clientsTable")
                .arg(ContainerUtils::containerTypeToString(DockerContainer::OpenVpn));
    }
    return QStringLiteral("/opt/amnezia/%1/clientsTable").arg(ContainerUtils::containerTypeToString(container));
}

bool remoteClientExists(const ServerCredentials &credentials, DockerContainer container, const QString &clientId, ErrorCode &errorCode)
{
    if (clientId.isEmpty()) {
        errorCode = ErrorCode::InternalError;
        return false;
    }

    SshSession sshSession;
    const QByteArray clientsTableData = sshSession.getTextFileFromContainer(container, credentials, clientsTablePath(container), errorCode);
    if (errorCode != ErrorCode::NoError) {
        return false;
    }

    const QJsonDocument document = QJsonDocument::fromJson(clientsTableData);
    if (document.isArray()) {
        const QJsonArray clients = document.array();
        for (const QJsonValue &value : clients) {
            if (value.toObject().value(configKey::clientId).toString() == clientId) {
                return true;
            }
        }
        return false;
    }

    if (document.isObject()) {
        return document.object().contains(clientId);
    }

    return false;
}

QByteArray clientLogsCollectorScript()
{
    QString script = QStringLiteral(R"PY1(
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import contextlib
import fcntl
import hashlib
import json
import os
import re
import secrets
import sqlite3
import threading
import time

ROOT = "/data"
TOKEN_FILE = os.path.join(ROOT, "tokens.tsv")
TOKEN_LOCK_DIR = os.path.join(ROOT, "tokens.lock")
LEGACY_TOKEN_FILE = os.path.join(ROOT, "legacy_tokens.tsv")
LEGACY_ROOT = os.path.join(ROOT, "legacy")
LOG_ROOT = os.path.join(ROOT, "logs")
LOCK_ROOT = os.path.join(ROOT, "locks")
RETENTION_LOCK_FILE = os.path.join(ROOT, "retention.lock")
RETENTION_STATE_FILE = os.path.join(ROOT, "retention.last")
RECEIPT_DB = os.path.join(ROOT, "batch-receipts.sqlite3")
MAX_UPLOAD_BYTES = __MAX_UPLOAD_BYTES__
MAX_BOOTSTRAP_BYTES = 1024
MAX_CLIENT_BYTES = __MAX_CLIENT_BYTES__
MAX_FILES_PER_CLIENT = 512
MAX_TOTAL_BYTES = 512 * 1024 * 1024
MAX_TOTAL_FILES = 8192
MAX_LOG_AGE_SECONDS = 30 * 24 * 60 * 60
MAX_TMP_AGE_SECONDS = 60 * 60
RECEIPT_TTL_SECONDS = 35 * 24 * 60 * 60
MAX_RECEIPTS_PER_CLIENT = 131072
MAX_TOTAL_RECEIPTS = 1048576
RETENTION_INTERVAL_SECONDS = 60 * 60
RETENTION_CHECK_INTERVAL_SECONDS = 60
TOKEN_LOCK_STALE_SECONDS = 2 * 60
HEALTH_CACHE_SECONDS = 15
PRE_HEADER_TIMEOUT_SECONDS = 10
MAX_HANDLER_THREADS = 16
PORT = __PORT__
UPLOAD_PATH = "__UPLOAD_PATH__"
BOOTSTRAP_PATH = "__BOOTSTRAP_PATH__"
HEALTH_PATH = "/healthz"
ALLOW_BOOTSTRAP = os.environ.get("AMNEZIA_CLIENT_LOGS_BOOTSTRAP", "0") == "1"
CONTAINER_SCOPE = os.environ.get("AMNEZIA_CLIENT_LOGS_SCOPE", "")
SAFE_CLIENT_ID = re.compile(r"^[a-f0-9]{64}$")
SAFE_KIND = re.compile(r"^(android|client|service)$")
SAFE_INSTALLATION_ID = re.compile(r"^[A-Za-z0-9_.-]{1,80}$")
SAFE_BATCH_ID = re.compile(r"^[a-f0-9]{64}$")
UPLOAD_SEMAPHORE = threading.BoundedSemaphore(4)
CLIENT_LOCKS = {}
CLIENT_LOCKS_GUARD = threading.Lock()
METRICS_LOCK = threading.Lock()
HEALTH_CACHE_LOCK = threading.Lock()
HEALTH_SEMAPHORE = threading.BoundedSemaphore(8)
RECEIPT_MAINTENANCE_LOCK = threading.Lock()
RECEIPT_SCHEMA_LOCK = threading.Lock()
RETENTION_RUNTIME_LOCK = threading.Lock()
GLOBAL_STORAGE_THREAD_LOCK = threading.Lock()
TOKEN_CACHE_LOCK = threading.Lock()
STARTED_AT = time.monotonic()
HEALTH_CACHE = {"expiresAt": 0.0, "ready": None}
RECEIPT_INSERTS_SINCE_MAINTENANCE = 0
RECEIPT_SCHEMA_READY = False
NEXT_RETENTION_CHECK_AT = 0.0
TOKEN_CACHE_UNSET = object()
TOKEN_CACHE = {"signature": TOKEN_CACHE_UNSET, "value": {}}
LEGACY_TOKEN_CACHE = {"signature": TOKEN_CACHE_UNSET, "value": frozenset()}
LEGACY_MAP_CACHE = {"signature": TOKEN_CACHE_UNSET, "value": {}}
METRICS = {
    "accepted": 0,
    "replayed": 0,
    "legacyAccepted": 0,
    "errors": 0,
    "lastSuccessAt": 0.0,
}


class StorageQuotaExceeded(Exception):
    pass


def increment_metric(name):
    with METRICS_LOCK:
        METRICS[name] += 1
        if name in ("accepted", "legacyAccepted", "replayed"):
            METRICS["lastSuccessAt"] = time.monotonic()


def metrics_snapshot():
    with METRICS_LOCK:
        return dict(METRICS)


def invalidate_health_cache():
    with HEALTH_CACHE_LOCK:
        HEALTH_CACHE["expiresAt"] = 0.0
        HEALTH_CACHE["ready"] = None


@contextlib.contextmanager
def filesystem_lock(path):
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    with open(path, "a+b") as lock_file:
        os.chmod(path, 0o600)
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


@contextlib.contextmanager
def global_storage_lock():
    with GLOBAL_STORAGE_THREAD_LOCK:
        with filesystem_lock(RETENTION_LOCK_FILE):
            yield


@contextlib.contextmanager
def client_lock(client_id):
    with CLIENT_LOCKS_GUARD:
        lock = CLIENT_LOCKS.get(client_id)
        if lock is None:
            lock = threading.Lock()
            CLIENT_LOCKS[client_id] = lock
    lock.acquire()
    try:
        os.makedirs(LOCK_ROOT, mode=0o700, exist_ok=True)
        with filesystem_lock(os.path.join(LOCK_ROOT, client_id + ".lock")):
            yield
    finally:
        lock.release()


def with_token_file_lock(callback):
    os.makedirs(ROOT, mode=0o700, exist_ok=True)
    for attempt in range(30):
        try:
            os.mkdir(TOKEN_LOCK_DIR)
            break
        except FileExistsError:
            try:
                if time.time() - os.stat(TOKEN_LOCK_DIR).st_mtime > TOKEN_LOCK_STALE_SECONDS:
                    os.rmdir(TOKEN_LOCK_DIR)
                    continue
            except (FileNotFoundError, OSError):
                pass
            if attempt == 29:
                raise TimeoutError("token lock timeout")
            time.sleep(1)
    try:
        return callback()
    finally:
        try:
            os.rmdir(TOKEN_LOCK_DIR)
        except FileNotFoundError:
            pass


def file_signature(path):
    try:
        stat = os.stat(path, follow_symlinks=False)
    except FileNotFoundError:
        return None
    return (path, stat.st_mtime_ns, stat.st_size, stat.st_ino)


def read_stable_lines(path):
    for _ in range(3):
        before = file_signature(path)
        if before is None:
            return (), None
        try:
            with open(path, "r", encoding="utf-8") as source_file:
                lines = tuple(source_file)
        except FileNotFoundError:
            continue
        after = file_signature(path)
        if before == after:
            return lines, after
    raise OSError("token map changed while reading")


def cached_file_value(path, cache, parser):
    with TOKEN_CACHE_LOCK:
        signature = file_signature(path)
        if cache["signature"] == signature:
            return cache["value"]
        lines, stable_signature = read_stable_lines(path)
        value = parser(lines)
        cache["signature"] = stable_signature
        cache["value"] = value
        return value


def invalidate_token_caches():
    with TOKEN_CACHE_LOCK:
        TOKEN_CACHE["signature"] = TOKEN_CACHE_UNSET
        LEGACY_TOKEN_CACHE["signature"] = TOKEN_CACHE_UNSET


def parse_tokens(lines):
    tokens = {}
    for line in lines:
        parts = line.rstrip("\n").split("\t")
        client_id = parts[0] if len(parts) > 0 else ""
        token = parts[1] if len(parts) > 1 else ""
        if client_id and token:
            tokens[client_id] = token
    return tokens


def load_tokens():
    return cached_file_value(TOKEN_FILE, TOKEN_CACHE, parse_tokens)


def parse_legacy_tokens(lines):
    legacy_tokens = set()
    for line in lines:
        parts = line.rstrip("\n").split("\t")
        if len(parts) < 3:
            continue
        client_id, token, scope = parts[0], parts[1], parts[2]
        if client_id and token and scope:
            legacy_tokens.add((client_id, token, scope))
    return frozenset(legacy_tokens)


def load_legacy_tokens():
    return cached_file_value(LEGACY_TOKEN_FILE, LEGACY_TOKEN_CACHE, parse_legacy_tokens)


def is_legacy_token(client_id, token):
    return [scope for saved_client_id, saved_token, scope in load_legacy_tokens()
            if saved_client_id == client_id and saved_token == token]


def resolve_legacy_client_id(source_ip):
    if not ALLOW_BOOTSTRAP or not CONTAINER_SCOPE:
        return ""
    legacy_map = os.path.join(LEGACY_ROOT, CONTAINER_SCOPE + ".tsv")

    def parse_legacy_map(lines):
        clients = {}
        for line in lines:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 2:
                continue
            vpn_ip, client_id = parts[0], parts[1]
            if vpn_ip and SAFE_CLIENT_ID.fullmatch(client_id):
                clients[vpn_ip] = client_id
        return clients

    return cached_file_value(legacy_map, LEGACY_MAP_CACHE, parse_legacy_map).get(source_ip, "")


def ensure_legacy_token(client_id):
    def update_token_files():
        tokens = dict(load_tokens())
        token = tokens.get(client_id)
        if not token:
            token = secrets.token_urlsafe(36)
            tokens[client_id] = token

        legacy_rows = []
        try:
            with open(LEGACY_TOKEN_FILE, "r", encoding="utf-8") as token_file:
                for line in token_file:
                    parts = line.rstrip("\n").split("\t")
                    if len(parts) >= 3 and not (parts[0] == client_id and parts[2] == CONTAINER_SCOPE):
                        legacy_rows.append(line.rstrip("\n"))
        except FileNotFoundError:
            pass
        legacy_rows.append("\t".join([client_id, token, CONTAINER_SCOPE]))

        token_rows = ["\t".join([key, value]) for key, value in sorted(tokens.items())]
        tokens_tmp = TOKEN_FILE + ".tmp"
        legacy_tmp = LEGACY_TOKEN_FILE + ".tmp"
        with open(tokens_tmp, "w", encoding="utf-8") as token_file:
            token_file.write("\n".join(token_rows))
            token_file.write("\n")
        with open(legacy_tmp, "w", encoding="utf-8") as token_file:
            token_file.write("\n".join(legacy_rows))
            token_file.write("\n")
        os.replace(legacy_tmp, LEGACY_TOKEN_FILE)
        os.replace(tokens_tmp, TOKEN_FILE)
        os.chmod(TOKEN_FILE, 0o600)
        os.chmod(LEGACY_TOKEN_FILE, 0o600)
        invalidate_token_caches()
        return token

    return with_token_file_lock(update_token_files)
)PY1");
    script += QStringLiteral(R"PY2(

def prune_client_dir(client_dir):
    files = []
    total = 0
    with os.scandir(client_dir) as entries:
        for entry in entries:
            if not entry.name.endswith(".log") or not entry.is_file(follow_symlinks=False):
                continue
            try:
                stat = entry.stat(follow_symlinks=False)
            except FileNotFoundError:
                continue
            files.append((stat.st_mtime, entry.path, stat.st_size))
            total += stat.st_size
    remaining_files = len(files)
    for _, path, size in sorted(files):
        if total <= MAX_CLIENT_BYTES and remaining_files <= MAX_FILES_PER_CLIENT:
            break
        try:
            os.remove(path)
            total -= size
            remaining_files -= 1
        except FileNotFoundError:
            pass


def collect_log_files():
    files = []
    if not os.path.isdir(LOG_ROOT):
        return files
    with os.scandir(LOG_ROOT) as client_entries:
        for client_entry in client_entries:
            if not client_entry.is_dir(follow_symlinks=False):
                continue
            with os.scandir(client_entry.path) as entries:
                for entry in entries:
                    if not entry.name.endswith(".log") or not entry.is_file(follow_symlinks=False):
                        continue
                    try:
                        stat = entry.stat(follow_symlinks=False)
                    except FileNotFoundError:
                        continue
                    files.append((stat.st_mtime, entry.path, stat.st_size))
    return files


def reserve_global_log_capacity_unlocked(reserve_bytes=0, reserve_files=0):
    if (reserve_bytes < 0 or reserve_files < 0
            or reserve_bytes > MAX_TOTAL_BYTES or reserve_files > MAX_TOTAL_FILES):
        return False
    now = time.time()
    files = collect_log_files()
    retained = []
    changed_directories = set()
    total = 0
    for modified_at, path, size in files:
        if modified_at < now - MAX_LOG_AGE_SECONDS:
            try:
                os.remove(path)
                changed_directories.add(os.path.dirname(path))
            except FileNotFoundError:
                pass
            continue
        retained.append((modified_at, path, size))
        total += size
    byte_limit = MAX_TOTAL_BYTES - reserve_bytes
    file_limit = MAX_TOTAL_FILES - reserve_files
    remaining_files = len(retained)
    for _, path, size in sorted(retained):
        if total <= byte_limit and remaining_files <= file_limit:
            break
        try:
            os.remove(path)
            changed_directories.add(os.path.dirname(path))
        except FileNotFoundError:
            pass
        total -= size
        remaining_files -= 1

    if os.path.isdir(LOG_ROOT):
        with os.scandir(LOG_ROOT) as client_entries:
            for client_entry in client_entries:
                if not client_entry.is_dir(follow_symlinks=False):
                    continue
                with os.scandir(client_entry.path) as entries:
                    for entry in entries:
                        if not entry.name.endswith(".tmp") and ".tmp-" not in entry.name:
                            continue
                        try:
                            stat = entry.stat(follow_symlinks=False)
                            if entry.is_file(follow_symlinks=False) and stat.st_mtime < now - MAX_TMP_AGE_SECONDS:
                                os.remove(entry.path)
                                changed_directories.add(os.path.dirname(entry.path))
                        except FileNotFoundError:
                            pass
    for directory in sorted(changed_directories):
        fsync_directory(directory)
    return total <= byte_limit and remaining_files <= file_limit


def prune_all_logs_unlocked():
    return reserve_global_log_capacity_unlocked()


def prune_all_logs():
    with global_storage_lock():
        prune_all_logs_unlocked()
    invalidate_health_cache()


def storage_summary():
    files = collect_log_files()
    return {
        "bytes": sum(item[2] for item in files),
        "files": len(files),
    }


def file_body_metadata(path):
    digest = hashlib.sha256()
    size = 0
    with open(path, "rb") as stored_file:
        while True:
            chunk = stored_file.read(64 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def stored_batch_metadata(client_dir, batch_id):
    suffix = "-" + batch_id + ".log"
    with os.scandir(client_dir) as entries:
        for entry in entries:
            if ((entry.name == batch_id + ".log" or entry.name.endswith(suffix))
                    and entry.is_file(follow_symlinks=False)):
                try:
                    return file_body_metadata(entry.path)
                except FileNotFoundError:
                    continue
    return None


def fsync_directory(path):
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    directory_fd = os.open(path, directory_flags)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def ensure_receipt_schema(connection):
    global RECEIPT_SCHEMA_READY
    with RECEIPT_SCHEMA_LOCK:
        if RECEIPT_SCHEMA_READY:
            return
        connection.execute("BEGIN IMMEDIATE")
        try:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS batch_receipts ("
                "client_id TEXT NOT NULL, batch_id TEXT NOT NULL, accepted_at INTEGER NOT NULL, "
                "body_sha256 TEXT, body_length INTEGER, "
                "PRIMARY KEY (client_id, batch_id))")
            columns = {
                row[1] for row in connection.execute("PRAGMA table_info(batch_receipts)")
            }
            if "body_sha256" not in columns:
                connection.execute("ALTER TABLE batch_receipts ADD COLUMN body_sha256 TEXT")
            if "body_length" not in columns:
                connection.execute("ALTER TABLE batch_receipts ADD COLUMN body_length INTEGER")
            connection.execute(
                "CREATE TABLE IF NOT EXISTS collector_health ("
                "singleton INTEGER PRIMARY KEY CHECK (singleton = 1), touched_at INTEGER NOT NULL)")
            connection.execute(
                "CREATE INDEX IF NOT EXISTS batch_receipts_age "
                "ON batch_receipts (accepted_at)")
            connection.execute(
                "CREATE INDEX IF NOT EXISTS batch_receipts_client_age "
                "ON batch_receipts (client_id, accepted_at DESC)")
            connection.commit()
            RECEIPT_SCHEMA_READY = True
        except Exception:
            connection.rollback()
            raise


def open_receipt_db():
    os.makedirs(ROOT, mode=0o700, exist_ok=True)
    database_existed = os.path.exists(RECEIPT_DB)
    connection = sqlite3.connect(RECEIPT_DB, timeout=30)
    try:
        connection.execute("PRAGMA busy_timeout=30000")
        connection.execute("PRAGMA synchronous=FULL")
        ensure_receipt_schema(connection)
        os.chmod(RECEIPT_DB, 0o600)
        if not database_existed:
            fsync_directory(ROOT)
        return connection
    except Exception:
        connection.close()
        raise


def batch_receipt_metadata(client_id, batch_id):
    with contextlib.closing(open_receipt_db()) as connection:
        row = connection.execute(
            "SELECT body_sha256, body_length FROM batch_receipts "
            "WHERE client_id = ? AND batch_id = ? LIMIT 1",
            (client_id, batch_id)).fetchone()
    return tuple(row) if row is not None else None


def batch_receipt_exists(client_id, batch_id):
    return batch_receipt_metadata(client_id, batch_id) is not None


def prune_batch_receipts():
    cutoff = int(time.time()) - RECEIPT_TTL_SECONDS
    with contextlib.closing(open_receipt_db()) as connection:
        connection.execute("DELETE FROM batch_receipts WHERE accepted_at < ?", (cutoff,))
        connection.execute(
            "DELETE FROM batch_receipts WHERE rowid IN ("
            "SELECT rowid FROM batch_receipts ORDER BY accepted_at DESC, rowid DESC "
            "LIMIT -1 OFFSET ?)",
            (MAX_TOTAL_RECEIPTS,))
        connection.commit()


def record_batch_receipt(client_id, batch_id, body_sha256, body_length):
    global RECEIPT_INSERTS_SINCE_MAINTENANCE
    if (not SAFE_CLIENT_ID.fullmatch(client_id) or not SAFE_BATCH_ID.fullmatch(batch_id)
            or not SAFE_BATCH_ID.fullmatch(body_sha256) or body_length <= 0
            or body_length > MAX_UPLOAD_BYTES):
        raise ValueError("invalid batch receipt metadata")
    with contextlib.closing(open_receipt_db()) as connection:
        connection.execute(
            "INSERT OR IGNORE INTO batch_receipts "
            "(client_id, batch_id, accepted_at, body_sha256, body_length) VALUES (?, ?, ?, ?, ?)",
            (client_id, batch_id, int(time.time()), body_sha256, body_length))
        connection.execute(
            "UPDATE batch_receipts SET body_sha256 = ?, body_length = ? "
            "WHERE client_id = ? AND batch_id = ? "
            "AND (body_sha256 IS NULL OR body_length IS NULL)",
            (body_sha256, body_length, client_id, batch_id))
        connection.execute(
            "DELETE FROM batch_receipts WHERE rowid IN ("
            "SELECT rowid FROM batch_receipts WHERE client_id = ? "
            "ORDER BY accepted_at DESC, rowid DESC LIMIT -1 OFFSET ?)",
            (client_id, MAX_RECEIPTS_PER_CLIENT))
        connection.commit()

    run_maintenance = False
    with RECEIPT_MAINTENANCE_LOCK:
        RECEIPT_INSERTS_SINCE_MAINTENANCE += 1
        if RECEIPT_INSERTS_SINCE_MAINTENANCE >= 256:
            RECEIPT_INSERTS_SINCE_MAINTENANCE = 0
            run_maintenance = True
    if run_maintenance:
        prune_batch_receipts()


def read_last_retention_at():
    try:
        with open(RETENTION_STATE_FILE, "r", encoding="ascii") as state_file:
            completed_at = float(state_file.read(64).strip())
    except (FileNotFoundError, OSError, ValueError):
        return 0.0
    now = time.time()
    if completed_at < 0 or completed_at > now + 5 * 60:
        return 0.0
    return completed_at


def write_last_retention_at(completed_at):
    tmp_path = RETENTION_STATE_FILE + ".tmp-" + secrets.token_hex(8)
    try:
        with open(tmp_path, "w", encoding="ascii") as state_file:
            state_file.write(f"{completed_at:.6f}\n")
            state_file.flush()
            os.fsync(state_file.fileno())
        os.replace(tmp_path, RETENTION_STATE_FILE)
        os.chmod(RETENTION_STATE_FILE, 0o600)
        fsync_directory(ROOT)
    finally:
        try:
            os.remove(tmp_path)
        except FileNotFoundError:
            pass


def run_retention_pass(force=False):
    global NEXT_RETENTION_CHECK_AT
    monotonic_now = time.monotonic()
    with RETENTION_RUNTIME_LOCK:
        if not force and monotonic_now < NEXT_RETENTION_CHECK_AT:
            return False
        NEXT_RETENTION_CHECK_AT = monotonic_now + RETENTION_CHECK_INTERVAL_SECONDS

    with global_storage_lock():
        now = time.time()
        if not force and now - read_last_retention_at() < RETENTION_INTERVAL_SECONDS:
            return False
        prune_all_logs_unlocked()
        prune_batch_receipts()
        write_last_retention_at(now)
    invalidate_health_cache()
    return True


def token_store_ready():
    lines, signature = read_stable_lines(TOKEN_FILE)
    if signature is None:
        return False
    for line in lines:
        stripped = line.rstrip("\n")
        if not stripped:
            continue
        parts = stripped.split("\t")
        if len(parts) != 2:
            return False
        client_id, token = parts
        if (not SAFE_CLIENT_ID.fullmatch(client_id) or not token
                or len(token) > 512 or not token.isascii()):
            return False
    return True


def receipt_store_ready():
    with contextlib.closing(open_receipt_db()) as connection:
        connection.execute("BEGIN IMMEDIATE")
        try:
            connection.execute(
                "INSERT OR REPLACE INTO collector_health (singleton, touched_at) VALUES (1, ?)",
                (int(time.time()),))
        finally:
            connection.rollback()
    return True


def log_store_ready():
    os.makedirs(LOG_ROOT, mode=0o700, exist_ok=True)
    probe_path = os.path.join(LOG_ROOT, ".health-" + secrets.token_hex(8) + ".tmp")
    descriptor = None
    try:
        descriptor = os.open(probe_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        if os.write(descriptor, b"1") != 1:
            raise OSError("short health probe write")
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.remove(probe_path)
        fsync_directory(LOG_ROOT)
        return True
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.remove(probe_path)
        except FileNotFoundError:
            pass


def global_log_quota_ready():
    if MAX_TOTAL_BYTES <= 0 or MAX_TOTAL_FILES <= 0:
        return False
    with global_storage_lock():
        summary = storage_summary()
        return (summary["bytes"] <= MAX_TOTAL_BYTES
                and summary["files"] <= MAX_TOTAL_FILES)


def cached_health_ready():
    now = time.monotonic()
    with HEALTH_CACHE_LOCK:
        if HEALTH_CACHE["ready"] is None or HEALTH_CACHE["expiresAt"] <= now:
            try:
                ready = (token_store_ready() and receipt_store_ready() and log_store_ready()
                         and global_log_quota_ready())
            except Exception:
                ready = False
            HEALTH_CACHE["ready"] = ready
            HEALTH_CACHE["expiresAt"] = now + HEALTH_CACHE_SECONDS
        return bool(HEALTH_CACHE["ready"])


def read_body_metadata(stream, content_length):
    remaining = content_length
    digest = hashlib.sha256()
    while remaining > 0:
        chunk = stream.read(min(64 * 1024, remaining))
        if not chunk:
            raise ConnectionError("short request body")
        digest.update(chunk)
        remaining -= len(chunk)
    return digest.hexdigest(), content_length


def retention_worker(stop_event, interval=RETENTION_CHECK_INTERVAL_SECONDS):
    while not stop_event.wait(interval):
        try:
            run_retention_pass()
        except Exception:
            increment_metric("errors")
)PY2");
    script += QStringLiteral(R"PY3(

class Handler(BaseHTTPRequestHandler):
    server_version = "AmneziaClientLogs/3.0"

    def send_no_content(self, batch_id="", replayed=False):
        self.send_response(204)
        self.send_header("Cache-Control", "no-store")
        if batch_id:
            self.send_header("X-Amnezia-Batch-Accepted", "1")
            self.send_header("X-Amnezia-Batch-Id", batch_id)
        if replayed:
            self.send_header("X-Amnezia-Batch-Replayed", "1")
        self.end_headers()

    def do_GET(self):
        if self.path != HEALTH_PATH:
            self.send_error(404)
            return
        if not HEALTH_SEMAPHORE.acquire(blocking=False):
            self.send_error(503)
            return
        try:
            ready = cached_health_ready()
            body = json.dumps({
                "status": "ok" if ready else "degraded",
                "collectorVersion": 3,
            }, separators=(",", ":")).encode("utf-8")
            self.send_response(200 if ready else 503)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
        except Exception:
            increment_metric("errors")
            self.send_error(503)
        finally:
            HEALTH_SEMAPHORE.release()

    def authenticate_client(self):
        client_id = self.headers.get("X-Amnezia-Client-Id", "")
        token = self.headers.get("X-Amnezia-Log-Token", "")
        if not SAFE_CLIENT_ID.match(client_id):
            self.send_error(400)
            return None
        if not token or len(token) > 512 or not token.isascii():
            self.send_error(403)
            return None
        try:
            saved_token = load_tokens().get(client_id, "")
            if (not saved_token or len(saved_token) > 512 or not saved_token.isascii()
                    or not secrets.compare_digest(saved_token, token)):
                self.send_error(403)
                return None
            legacy_scopes = is_legacy_token(client_id, token)
            if legacy_scopes:
                if not ALLOW_BOOTSTRAP or CONTAINER_SCOPE not in legacy_scopes:
                    self.send_error(403)
                    return None
                source_client_id = resolve_legacy_client_id(self.client_address[0])
                if source_client_id != client_id:
                    self.send_error(403)
                    return None
        except OSError:
            increment_metric("errors")
            self.send_error(503)
            return None
        return client_id

    def do_POST(self):
        self.connection.settimeout(30)
        if self.path == BOOTSTRAP_PATH:
            try:
                content_length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self.send_error(400)
                return
            if content_length < 0 or content_length > MAX_BOOTSTRAP_BYTES:
                self.send_error(413)
                return
            if not UPLOAD_SEMAPHORE.acquire(blocking=False):
                self.send_error(503)
                return
            try:
                self.bootstrap_client()
            finally:
                UPLOAD_SEMAPHORE.release()
            return
        if self.path != UPLOAD_PATH:
            self.send_error(404)
            return
        client_id = self.authenticate_client()
        if client_id is None:
            return
        kind = self.headers.get("X-Amnezia-Log-Kind", "client")
        installation_id = self.headers.get("X-Amnezia-Installation-Id", "unknown")
        batch_id = self.headers.get("X-Amnezia-Batch-Id", "")
        if not SAFE_KIND.match(kind):
            self.send_error(400)
            return
        if not SAFE_INSTALLATION_ID.match(installation_id):
            installation_id = "unknown"
        if not batch_id:
            self.send_error(428, "X-Amnezia-Batch-Id is required")
            return
        if not SAFE_BATCH_ID.fullmatch(batch_id):
            self.send_error(400)
            return
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error(400)
            return
        if content_length <= 0 or content_length > MAX_UPLOAD_BYTES:
            self.send_error(413)
            return

        if not UPLOAD_SEMAPHORE.acquire(blocking=False):
            self.send_error(503)
            return
        client_dir = os.path.join(LOG_ROOT, client_id)
        tmp_path = None
        try:
            with client_lock(client_id):
                os.makedirs(client_dir, mode=0o700, exist_ok=True)
                receipt_metadata = batch_receipt_metadata(client_id, batch_id)
                receipt_is_bound = (receipt_metadata is not None
                                    and receipt_metadata[0] is not None
                                    and receipt_metadata[1] is not None)
                stored_metadata = None
                if receipt_metadata is None or not receipt_is_bound:
                    stored_metadata = stored_batch_metadata(client_dir, batch_id)
                if receipt_metadata is not None or stored_metadata is not None:
                    incoming_metadata = read_body_metadata(self.rfile, content_length)
                    expected_metadata = receipt_metadata if receipt_is_bound else stored_metadata
                    if expected_metadata is not None:
                        expected_sha256, expected_length = expected_metadata
                        if (not isinstance(expected_sha256, str)
                                or not SAFE_BATCH_ID.fullmatch(expected_sha256)
                                or not isinstance(expected_length, int)
                                or expected_length <= 0
                                or expected_length > MAX_UPLOAD_BYTES):
                            raise OSError("invalid batch receipt metadata")
                        if (expected_length != incoming_metadata[1]
                                or not secrets.compare_digest(expected_sha256, incoming_metadata[0])):
                            increment_metric("errors")
                            self.send_error(409, "Batch body does not match the accepted receipt")
                            return
                    if stored_metadata is not None:
                        fsync_directory(client_dir)
                    if not receipt_is_bound:
                        record_batch_receipt(
                            client_id, batch_id, incoming_metadata[0], incoming_metadata[1])
                    increment_metric("replayed")
                    invalidate_health_cache()
                    self.send_no_content(batch_id=batch_id, replayed=True)
                    return
                stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
                batch_suffix = f"-{batch_id}" if batch_id else ""
                final_path = os.path.join(
                    client_dir,
                    f"{stamp}-{time.time_ns()}-{installation_id}-{kind}{batch_suffix}.log")
                tmp_path = final_path + ".tmp-" + secrets.token_hex(8)
                remaining = content_length
                body_digest = hashlib.sha256()
                with open(tmp_path, "wb") as log_file:
                    while remaining > 0:
                        chunk = self.rfile.read(min(64 * 1024, remaining))
                        if not chunk:
                            raise ConnectionError("short request body")
                        log_file.write(chunk)
                        body_digest.update(chunk)
                        remaining -= len(chunk)
                    log_file.flush()
                    os.fsync(log_file.fileno())
                with global_storage_lock():
                    if not reserve_global_log_capacity_unlocked(
                            reserve_bytes=content_length, reserve_files=1):
                        raise StorageQuotaExceeded()
                    os.replace(tmp_path, final_path)
                    tmp_path = None
                    fsync_directory(client_dir)
                    record_batch_receipt(
                        client_id, batch_id, body_digest.hexdigest(), content_length)
                    prune_client_dir(client_dir)
            run_retention_pass()
            increment_metric("accepted")
            invalidate_health_cache()
            self.send_no_content(batch_id=batch_id)
        except StorageQuotaExceeded:
            if tmp_path is not None:
                try:
                    os.remove(tmp_path)
                except FileNotFoundError:
                    pass
            increment_metric("errors")
            invalidate_health_cache()
            self.send_error(507, "Insufficient collector storage quota")
        except (ConnectionError, ValueError):
            if tmp_path is not None:
                try:
                    os.remove(tmp_path)
                except FileNotFoundError:
                    pass
            increment_metric("errors")
            self.send_error(400)
        except Exception:
            if tmp_path is not None:
                try:
                    os.remove(tmp_path)
                except FileNotFoundError:
                    pass
            increment_metric("errors")
            self.send_error(500)
        finally:
            UPLOAD_SEMAPHORE.release()

    def log_message(self, fmt, *args):
        return

    def bootstrap_client(self):
        if not ALLOW_BOOTSTRAP:
            self.send_error(404)
            return
        client_id = resolve_legacy_client_id(self.client_address[0])
        claimed_client_id = self.headers.get("X-Amnezia-Client-Id", "")
        if not client_id or (claimed_client_id and claimed_client_id != client_id):
            self.send_error(403)
            return
        token = ensure_legacy_token(client_id)
        body = json.dumps({
            "endpoint": f"http://172.29.172.251:{PORT}{UPLOAD_PATH}",
            "clientId": client_id,
            "token": token,
        }, separators=(",", ":")).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class LogServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 32

    def __init__(self, *args, **kwargs):
        self._handler_slots = threading.BoundedSemaphore(MAX_HANDLER_THREADS)
        self._handler_count_lock = threading.Lock()
        self._active_handler_count = 0
        super().__init__(*args, **kwargs)

    def active_handler_count(self):
        with self._handler_count_lock:
            return self._active_handler_count

    def reserve_handler(self):
        if not self._handler_slots.acquire(blocking=False):
            return False
        with self._handler_count_lock:
            self._active_handler_count += 1
        return True

    def release_handler(self):
        with self._handler_count_lock:
            self._active_handler_count -= 1
        self._handler_slots.release()

    def process_request(self, request, client_address):
        if not self.reserve_handler():
            try:
                request.settimeout(1)
                request.sendall(
                    b"HTTP/1.0 503 Service Unavailable\r\n"
                    b"Connection: close\r\nContent-Length: 0\r\n\r\n")
            except OSError:
                pass
            finally:
                self.shutdown_request(request)
            return

        try:
            request.settimeout(PRE_HEADER_TIMEOUT_SECONDS)
            super().process_request(request, client_address)
        except Exception:
            self.release_handler()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.release_handler()


def main():
    os.umask(0o077)
    os.makedirs(LOG_ROOT, mode=0o700, exist_ok=True)
    run_retention_pass()
    retention_stop = threading.Event()
    retention_thread = threading.Thread(
        target=retention_worker, args=(retention_stop,), daemon=True)
    retention_thread.start()
    server = LogServer(("0.0.0.0", PORT), Handler)
    try:
        server.serve_forever()
    finally:
        retention_stop.set()
        retention_thread.join(timeout=5)
        server.server_close()


if __name__ == "__main__":
    main()
)PY3");
    script.replace(QStringLiteral("__MAX_UPLOAD_BYTES__"), QString::number(protocols::clientLogs::maxBytesPerUpload));
    script.replace(QStringLiteral("__MAX_CLIENT_BYTES__"), QString::number(protocols::clientLogs::maxBytesPerClient));
    script.replace(QStringLiteral("__PORT__"), QString::number(protocols::clientLogs::syncPort));
    script.replace(QStringLiteral("__UPLOAD_PATH__"), QString::fromLatin1(protocols::clientLogs::uploadPath));
    script.replace(QStringLiteral("__BOOTSTRAP_PATH__"), QString::fromLatin1(protocols::clientLogs::bootstrapPath));
    return script.toUtf8();
}

QString clientLogsLegacyMapRefreshScript()
{
    QString script = QStringLiteral(R"LMAP(
legacy_dest='__HOST_DIRECTORY__/legacy/__CONTAINER_SCOPE__.tsv';
legacy_raw="$(mktemp)";
legacy_map="$(mktemp)";
legacy_stage="${legacy_dest}.$$.tmp";
legacy_ready=0;
legacy_read_ok=0;
legacy_install_failed=0;
legacy_attempt=0;
while [ "$legacy_attempt" -lt 6 ]; do
    legacy_attempt=$((legacy_attempt + 1));
    : > "$legacy_raw";
    : > "$legacy_map";
    if sudo docker exec '__VPN_CONTAINER__' sh -c '__WG_SHOW_BIN__ show all allowed-ips' > "$legacy_raw"; then
        legacy_read_ok=1;
        tr -d '\r' < "$legacy_raw" > "$legacy_raw.clean" && mv -f "$legacy_raw.clean" "$legacy_raw";
        while IFS="$(printf '\t')" read -r iface peer allowed_ips; do
            [ -n "$iface" ] && [ -n "$peer" ] && [ -n "$allowed_ips" ] || continue;
            for allowed_ip in $allowed_ips; do
                vpn_ip="${allowed_ip%%/*}";
                case "$vpn_ip" in ''|*:*|0.0.0.0|*[!0-9.]*) continue ;; esac;
                client_log_id="$(printf '%s\t%s' '__CONTAINER_SCOPE__' "$peer" | sha256sum | awk '{print $1}')";
                printf '%s\t%s\t%s\n' "$vpn_ip" "$client_log_id" "$peer" >> "$legacy_map";
            done;
        done < "$legacy_raw";
        legacy_raw_peers="$(awk -F '\t' 'NF >= 3 && $2 != "" {print $2}' "$legacy_raw" | sort -u | wc -l | tr -d '[:space:]')";
        legacy_mapped_peers="$(awk -F '\t' 'NF == 3 && $3 != "" {print $3}' "$legacy_map" | sort -u | wc -l | tr -d '[:space:]')";
        legacy_rows="$(wc -l < "$legacy_map" | tr -d '[:space:]')";
        legacy_unique_ips="$(awk -F '\t' 'NF == 3 && $1 != "" {print $1}' "$legacy_map" | sort -u | wc -l | tr -d '[:space:]')";
        legacy_expected_peers="$(sudo docker exec '__VPN_CONTAINER__' sh -c "grep -c '^\\[Peer\\]' '__WG_CONFIG_PATH__'" 2>/dev/null | tr -d '[:space:]')";
        if [ "$legacy_expected_peers" -gt 0 ] 2>/dev/null && [ "$legacy_raw_peers" -eq "$legacy_expected_peers" ] && [ "$legacy_mapped_peers" -eq "$legacy_expected_peers" ] && [ "$legacy_rows" -gt 0 ] && [ "$legacy_unique_ips" -eq "$legacy_rows" ]; then
            if sudo install -m 0600 "$legacy_map" "$legacy_stage" && sudo mv -f "$legacy_stage" "$legacy_dest"; then
                legacy_ready=1;
            else
                legacy_install_failed=1;
            fi;
            break;
        fi;
    fi;
    [ "$legacy_attempt" -ge 6 ] || sleep 1;
done;
if [ "$legacy_ready" != '1' ]; then
    sudo rm -f "$legacy_stage" >/dev/null 2>&1 || true;
    if [ "$legacy_install_failed" = '1' ]; then
        echo __ERROR_MARKER__:legacy_map_install;
    elif [ "$legacy_read_ok" = '1' ]; then
        echo __ERROR_MARKER__:legacy_map_empty;
    else
        echo __ERROR_MARKER__:legacy_map_read;
    fi;
fi;
rm -f "$legacy_raw" "$legacy_raw.clean" "$legacy_map";
)LMAP");
    script.replace(QLatin1Char('\n'), QLatin1Char(' '));
    return script;
}

QByteArray adminClientLogsDownloadScript(const QString &clientLogId)
{
    QString script = QStringLiteral(R"SH(
CLIENT_DIR='__HOST_DIRECTORY__/logs/__CLIENT_LOG_ID__'
if [ ! -d "$CLIENT_DIR" ]; then
    printf '0\n'
    exit 0
fi
TMP_LIST="$(mktemp)"
trap 'rm -f "$TMP_LIST"' EXIT
find "$CLIENT_DIR" -maxdepth 1 -type f -name '*.log' -printf '%T@ %p\n' | sort -n | cut -d' ' -f2- > "$TMP_LIST"
if [ ! -s "$TMP_LIST" ]; then
    printf '0\n'
    exit 0
fi
printf '1\n'
while IFS= read -r path; do
    printf '\n===== %s =====\n' "$(basename "$path")"
    cat "$path"
    printf '\n'
done < "$TMP_LIST" | base64 | tr -d '\n'
)SH");
    script.replace(QStringLiteral("__HOST_DIRECTORY__"), QString::fromLatin1(protocols::clientLogs::hostDirectory));
    script.replace(QStringLiteral("__CLIENT_LOG_ID__"), clientLogId);
    return script.toUtf8();
}

ErrorCode publishClientLogCollector(const ServerCredentials &credentials,
                                    DockerContainer container,
                                    const QString &clientLogId,
                                    const QString &token)
{
    const bool upsertToken = !clientLogId.isEmpty() && !token.isEmpty();
    if (clientLogId.isEmpty() != token.isEmpty()) {
        return ErrorCode::InternalError;
    }

    SshSession sshSession;
    ErrorCode errorCode = ErrorCode::NoError;

    const QString scriptTmpFileName = QStringLiteral("/tmp/%1.py").arg(Utils::getRandomString(16));
    errorCode = sshSession.uploadFileToHost(credentials, clientLogsCollectorScript(), scriptTmpFileName);
    if (errorCode != ErrorCode::NoError) {
        return errorCode;
    }

    const QString tokenTmpFileName = upsertToken ? QStringLiteral("/tmp/%1.tsv").arg(Utils::getRandomString(16)) : QString();
    auto cleanupTmpFiles = [&sshSession, &credentials, &scriptTmpFileName, &tokenTmpFileName]() {
        QStringList files;
        files.append(QStringLiteral("'%1'").arg(scriptTmpFileName));
        if (!tokenTmpFileName.isEmpty()) {
            files.append(QStringLiteral("'%1'").arg(tokenTmpFileName));
        }
        sshSession.runScript(credentials, QStringLiteral("sudo rm -f %1").arg(files.join(QLatin1Char(' '))));
    };
    if (upsertToken) {
        const QByteArray tokenLine = QStringLiteral("%1\t%2\n").arg(clientLogId, token).toUtf8();
        errorCode = sshSession.uploadFileToHost(credentials, tokenLine, tokenTmpFileName);
        if (errorCode != ErrorCode::NoError) {
            cleanupTmpFiles();
            return errorCode;
        }
    }

    const QString tunnelInterface = clientLogsTunnelInterface(container);
    const bool publishTunnelEndpoint = !tunnelInterface.isEmpty();
    const QString containerScope = ContainerUtils::containerToString(container);
    QString wgShowBin;
    QString wgConfigPath;
    if (container == DockerContainer::Awg2) {
        wgShowBin = QStringLiteral("awg");
        wgConfigPath = QString::fromLatin1(protocols::awg::serverConfigPath);
    } else if (container == DockerContainer::Awg || container == DockerContainer::WireGuard) {
        wgShowBin = QStringLiteral("wg");
        wgConfigPath = container == DockerContainer::Awg
                ? QString::fromLatin1(protocols::awg::serverLegacyConfigPath)
                : QString::fromLatin1(protocols::wireguard::serverConfigPath);
    }
    const bool allowLegacyBootstrap = !wgShowBin.isEmpty();
    const QString tunnelContainerName = QStringLiteral("%1-%2")
            .arg(QString::fromLatin1(protocols::clientLogs::tunnelContainerName),
                 ContainerUtils::containerToString(container));

    QString script = QStringLiteral(R"SH(
sudo install -d -m 0700 '__HOST_DIRECTORY__' '__HOST_DIRECTORY__/logs' '__HOST_DIRECTORY__/legacy' || echo __ERROR_MARKER__:mkdir
sudo install -m 0755 '__SCRIPT_TMP_FILE__' '__HOST_DIRECTORY__/collector.py' || echo __ERROR_MARKER__:script_install
sudo touch '__HOST_DIRECTORY__/tokens.tsv' || echo __ERROR_MARKER__:tokens_touch
if [ '__UPSERT_TOKEN__' = '1' ]; then sudo sh -c "i=0; while ! mkdir '__HOST_DIRECTORY__/tokens.lock' 2>/dev/null; do if [ -d '__HOST_DIRECTORY__/tokens.lock' ] && find '__HOST_DIRECTORY__/tokens.lock' -maxdepth 0 -mmin +1 -print -quit | grep -q .; then rmdir '__HOST_DIRECTORY__/tokens.lock' 2>/dev/null || true; fi; i=\$((i + 1)); [ \$i -lt 30 ] || { echo __ERROR_MARKER__:tokens_lock; exit 0; }; sleep 1; done; trap 'rm -rf \"__HOST_DIRECTORY__/tokens.lock\" \"__HOST_DIRECTORY__/tokens.tsv.__CLIENT_LOG_ID__.tmp\"' EXIT; grep -v '^__CLIENT_LOG_ID__[[:space:]]' '__HOST_DIRECTORY__/tokens.tsv' 2>/dev/null > '__HOST_DIRECTORY__/tokens.tsv.__CLIENT_LOG_ID__.tmp' || true; cat '__TOKEN_TMP_FILE__' >> '__HOST_DIRECTORY__/tokens.tsv.__CLIENT_LOG_ID__.tmp' || { echo __ERROR_MARKER__:token_append; exit 0; }; install -m 0600 '__HOST_DIRECTORY__/tokens.tsv.__CLIENT_LOG_ID__.tmp' '__HOST_DIRECTORY__/tokens.tsv' || echo __ERROR_MARKER__:tokens_install"; fi
sudo rm -f '__SCRIPT_TMP_FILE__' '__TOKEN_TMP_FILE__' || true
if sudo docker network inspect amnezia-dns-net >/dev/null 2>&1; then if ! sudo docker network inspect amnezia-dns-net --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}' | grep -qw '172.29.172.0/24'; then echo __ERROR_MARKER__:network_subnet; fi; else sudo docker network create --driver bridge --subnet=172.29.172.0/24 --opt com.docker.network.bridge.name=amn0 amnezia-dns-net || echo __ERROR_MARKER__:network_create; fi
if ! sudo docker image inspect '__COLLECTOR_IMAGE__' >/dev/null 2>&1; then sudo docker pull '__COLLECTOR_IMAGE__' >/dev/null || echo __ERROR_MARKER__:image_pull; fi
sudo docker rm -f '__BRIDGE_CONTAINER__' >/dev/null 2>&1 || true
sudo docker run -d --log-driver none --restart always --memory=96m --cpus=0.5 --pids-limit=64 --cap-drop ALL --security-opt no-new-privileges:true --read-only --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777 --network amnezia-dns-net --ip=__BRIDGE_HOST__ --name '__BRIDGE_CONTAINER__' -e PYTHONDONTWRITEBYTECODE=1 -e PYTHONUNBUFFERED=1 -e AMNEZIA_CLIENT_LOGS_BOOTSTRAP=0 -v __HOST_DIRECTORY__:/data:rw --entrypoint python '__COLLECTOR_IMAGE__' /data/collector.py || echo __ERROR_MARKER__:bridge_run
if [ '__PUBLISH_TUNNEL__' = '1' ]; then if sudo docker ps --format '{{.Names}}' | grep -qx '__VPN_CONTAINER__'; then if [ '__ALLOW_LEGACY_BOOTSTRAP__' = '1' ]; then __LEGACY_MAP_REFRESH__ fi; sudo docker rm -f '__TUNNEL_CONTAINER__' >/dev/null 2>&1 || true; sudo docker exec -i '__VPN_CONTAINER__' sh -c 'while iptables -t nat -D PREROUTING -i __TUNNEL_IFACE__ -d __BRIDGE_HOST__/32 -p tcp --dport __SYNC_PORT__ -j REDIRECT --to-ports __SYNC_PORT__ 2>/dev/null; do :; done; iptables -t nat -A PREROUTING -i __TUNNEL_IFACE__ -d __BRIDGE_HOST__/32 -p tcp --dport __SYNC_PORT__ -j REDIRECT --to-ports __SYNC_PORT__' >/dev/null 2>&1 || echo __ERROR_MARKER__:tunnel_redirect; sudo docker run -d --log-driver none --restart always --memory=96m --cpus=0.5 --pids-limit=64 --cap-drop ALL --security-opt no-new-privileges:true --read-only --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777 --network container:__VPN_CONTAINER__ --name '__TUNNEL_CONTAINER__' -e PYTHONDONTWRITEBYTECODE=1 -e PYTHONUNBUFFERED=1 -e AMNEZIA_CLIENT_LOGS_BOOTSTRAP=__ALLOW_LEGACY_BOOTSTRAP__ -e AMNEZIA_CLIENT_LOGS_SCOPE='__CONTAINER_SCOPE__' -v __HOST_DIRECTORY__:/data:rw --entrypoint python '__COLLECTOR_IMAGE__' /data/collector.py || echo __ERROR_MARKER__:tunnel_run; else echo __ERROR_MARKER__:missing_vpn_container; fi; fi
sleep 1
sudo docker ps --format '{{.Names}}' | grep -qx '__BRIDGE_CONTAINER__' || echo __ERROR_MARKER__:missing_bridge_container
if [ '__PUBLISH_TUNNEL__' = '1' ]; then sudo docker ps --format '{{.Names}}' | grep -qx '__TUNNEL_CONTAINER__' || echo __ERROR_MARKER__:missing_tunnel_container; fi
)SH");

    script.replace("__LEGACY_MAP_REFRESH__", clientLogsLegacyMapRefreshScript());
    script.replace("__HOST_DIRECTORY__", QString::fromLatin1(protocols::clientLogs::hostDirectory));
    script.replace("__SCRIPT_TMP_FILE__", scriptTmpFileName);
    script.replace("__TOKEN_TMP_FILE__", tokenTmpFileName);
    script.replace("__UPSERT_TOKEN__", upsertToken ? QStringLiteral("1") : QStringLiteral("0"));
    script.replace("__BRIDGE_CONTAINER__", QString::fromLatin1(protocols::clientLogs::containerName));
    script.replace("__TUNNEL_CONTAINER__", tunnelContainerName);
    script.replace("__COLLECTOR_IMAGE__", QString::fromLatin1(clientLogsCollectorImage));
    script.replace("__BRIDGE_HOST__", QString::fromLatin1(protocols::clientLogs::syncHost));
    script.replace("__SYNC_PORT__", QString::number(protocols::clientLogs::syncPort));
    script.replace("__PUBLISH_TUNNEL__", publishTunnelEndpoint ? QStringLiteral("1") : QStringLiteral("0"));
    script.replace("__VPN_CONTAINER__", ContainerUtils::containerToString(container));
    script.replace("__TUNNEL_IFACE__", tunnelInterface);
    script.replace("__WG_SHOW_BIN__", wgShowBin);
    script.replace("__WG_CONFIG_PATH__", wgConfigPath);
    script.replace("__CONTAINER_SCOPE__", containerScope);
    script.replace("__ALLOW_LEGACY_BOOTSTRAP__", allowLegacyBootstrap ? QStringLiteral("1") : QStringLiteral("0"));
    script.replace("__CLIENT_LOG_ID__", clientLogId);
    script.replace("__ERROR_MARKER__", QString::fromLatin1(clientLogsPublishErrorMarker));

    QString publishOutput;
    auto cbReadOutput = [&publishOutput](const QString &data, libssh::Client &) {
        publishOutput += data + QStringLiteral("\n");
        return ErrorCode::NoError;
    };

    errorCode = sshSession.runScript(credentials, script, cbReadOutput, cbReadOutput);
    cleanupTmpFiles();
    if (errorCode != ErrorCode::NoError) {
        return errorCode;
    }

    if (publishOutput.contains(QString::fromLatin1(clientLogsPublishErrorMarker))) {
        qWarning().noquote() << "ExportController client log collector publish failed:" << publishOutput;
        return ErrorCode::ServerDockerFailedError;
    }

    return ErrorCode::NoError;
}

void refreshClientLogCollector(const ServerCredentials &credentials, DockerContainer container)
{
    if (ContainerUtils::containerService(container) == ServiceType::Other) {
        return;
    }
    const ErrorCode errorCode = publishClientLogCollector(credentials, container, {}, {});
    if (errorCode != ErrorCode::NoError) {
        qWarning() << "ExportController client log collector refresh failed" << static_cast<int>(errorCode);
    }
}
}

ExportController::ExportController(SecureServersRepository* serversRepository,
                                   SecureAppSettingsRepository* appSettingsRepository,
                                   QObject *parent)
    : QObject(parent),
      m_serversRepository(serversRepository),
      m_appSettingsRepository(appSettingsRepository)
{
}

ExportController::ExportResult ExportController::generateFullAccessConfig(const QString &serverId)
{
    ExportResult result;

    auto adminConfig = m_serversRepository->selfHostedAdminConfig(serverId);
    if (!adminConfig.has_value()) {
        result.errorCode = ErrorCode::InternalError;
        return result;
    }
    for (auto it = adminConfig->containers.begin(); it != adminConfig->containers.end(); ++it) {
        it.value().protocolConfig.clearClientConfig();
    }

    QJsonObject serverJson = adminConfig->toJson();
    removeClientResolvedServerRoutingRules(serverJson);
    QByteArray compressedConfig = QJsonDocument(serverJson).toJson();
    compressedConfig = qCompress(compressedConfig, 8);
    result.config = generateVpnUrl(compressedConfig);
    result.qrCodes = generateQrCodesFromConfig(compressedConfig);

    return result;
}

ExportController::ExportResult ExportController::generateConnectionConfig(const QString &serverId, int containerIndex, const QString &clientName)
{
    ExportResult result;

    DockerContainer container = static_cast<DockerContainer>(containerIndex);
    auto adminConfig = m_serversRepository->selfHostedAdminConfig(serverId);
    if (!adminConfig.has_value()) {
        result.errorCode = ErrorCode::InternalError;
        return result;
    }
    const ServerCredentials credentials = adminConfig->credentials();
    if (!credentials.isValid()) {
        result.errorCode = ErrorCode::InternalError;
        return result;
    }
    ContainerConfig containerConfig = adminConfig->containerConfig(container);
    QJsonObject clientLogs;

    if (ContainerUtils::containerService(container) != ServiceType::Other) {
        SshSession sshSession;
        Proto protocol = ContainerUtils::defaultProtocol(container);

        DnsSettings dnsSettings = {
            m_appSettingsRepository->primaryDns(),
            m_appSettingsRepository->secondaryDns()
        };

        auto configurator = ConfiguratorBase::create(protocol, &sshSession);
        ProtocolConfig newProtocolConfig = configurator->createConfig(credentials, container, containerConfig, dnsSettings, result.errorCode);
        if (result.errorCode != ErrorCode::NoError) {
            return result;
        }

        containerConfig.protocolConfig = newProtocolConfig;
        
        QString clientId = newProtocolConfig.clientId();
        if (!clientId.isEmpty()) {
            emit appendClientRequested(serverId, clientId, clientName, container);

            if (!clientLogsTunnelInterface(container).isEmpty()) {
                const QString clientLogId = clientLogsStorageId(container, clientId);
                const QString clientLogToken = Utils::getRandomString(48);

                result.errorCode = publishClientLogCollector(credentials, container, clientLogId, clientLogToken);
                if (result.errorCode != ErrorCode::NoError) {
                    return result;
                }

                clientLogs = clientLogsUtils::explicitTarget(clientLogId, clientLogToken);
            }
        }
    }

    const QPair<QString, QString> dns = adminConfig->getDnsPair(m_appSettingsRepository->useAmneziaDns(),
                                                               m_appSettingsRepository->primaryDns(),
                                                               m_appSettingsRepository->secondaryDns());

    adminConfig->containers.clear();
    adminConfig->containers[container] = containerConfig;
    adminConfig->defaultContainer = container;
    adminConfig->userName.clear();
    adminConfig->password.clear();
    adminConfig->port = 0;

    adminConfig->dns1 = dns.first;
    adminConfig->dns2 = dns.second;
    adminConfig->clientLogs = clientLogs;

    QJsonObject serverJson = adminConfig->toJson();
    removeClientResolvedServerRoutingRules(serverJson);
    QByteArray compressedConfig = QJsonDocument(serverJson).toJson();
    compressedConfig = qCompress(compressedConfig, 8);
    result.config = generateVpnUrl(compressedConfig);
    result.qrCodes = generateQrCodesFromConfig(compressedConfig);

    return result;
}

ExportController::DownloadClientLogsResult ExportController::downloadClientLogs(const QString &serverId, DockerContainer container,
                                                                                const QString &clientId)
{
    DownloadClientLogsResult result;

    auto adminConfig = m_serversRepository->selfHostedAdminConfig(serverId);
    if (!adminConfig.has_value() || clientId.isEmpty()) {
        result.errorCode = ErrorCode::InternalError;
        return result;
    }

    const ServerCredentials credentials = adminConfig->credentials();
    if (!credentials.isValid()) {
        result.errorCode = ErrorCode::InternalError;
        return result;
    }
    if (ContainerUtils::containerService(container) == ServiceType::Other) {
        result.errorCode = ErrorCode::InternalError;
        return result;
    }

    refreshClientLogCollector(credentials, container);

    if (!remoteClientExists(credentials, container, clientId, result.errorCode)) {
        if (result.errorCode == ErrorCode::NoError) {
            result.errorCode = ErrorCode::InternalError;
        }
        return result;
    }

    SshSession sshSession;
    const QString scriptTmpFileName = QStringLiteral("/tmp/%1.sh").arg(Utils::getRandomString(16));
    result.errorCode = sshSession.uploadFileToHost(credentials, adminClientLogsDownloadScript(clientLogsStorageId(container, clientId)),
                                                   scriptTmpFileName);
    if (result.errorCode != ErrorCode::NoError) {
        return result;
    }

    QString downloadOutput;
    auto cbReadOutput = [&downloadOutput](const QString &data, libssh::Client &) {
        downloadOutput += data;
        return ErrorCode::NoError;
    };

    result.errorCode = sshSession.runScript(credentials, QStringLiteral("sudo sh '%1'").arg(scriptTmpFileName), cbReadOutput);
    sshSession.runScript(credentials, QStringLiteral("sudo rm -f '%1'").arg(scriptTmpFileName));
    if (result.errorCode != ErrorCode::NoError) {
        return result;
    }

    const qsizetype statusEnd = downloadOutput.indexOf(QLatin1Char('\n'));
    if (statusEnd < 0) {
        result.errorCode = ErrorCode::InternalError;
        return result;
    }

    const QString status = downloadOutput.left(statusEnd).trimmed();
    if (status == QLatin1String("0")) {
        result.logsFound = false;
        return result;
    }
    if (status != QLatin1String("1")) {
        result.errorCode = ErrorCode::InternalError;
        return result;
    }

    const auto decoded = QByteArray::fromBase64Encoding(downloadOutput.mid(statusEnd + 1).trimmed().toLatin1(),
                                                        QByteArray::AbortOnBase64DecodingErrors);
    if (decoded.decodingStatus != QByteArray::Base64DecodingStatus::Ok || decoded.decoded.isEmpty()) {
        result.errorCode = ErrorCode::InternalError;
        return result;
    }

    result.data = decoded.decoded;
    result.logsFound = !result.data.isEmpty();
    return result;
}

ExportController::NativeConfigResult ExportController::generateNativeConfig(const QString &serverId, DockerContainer container,
                                                                             const ContainerConfig &containerConfig,
                                                                             const QString &clientName)
{
    NativeConfigResult result;

    if (ContainerUtils::containerService(container) == ServiceType::Other) {
        return result;
    }

    Proto protocol = ContainerUtils::defaultProtocol(container);

    auto adminConfig = m_serversRepository->selfHostedAdminConfig(serverId);
    if (!adminConfig.has_value()) {
        result.errorCode = ErrorCode::InternalError;
        return result;
    }
    const ServerCredentials credentials = adminConfig->credentials();
    if (!credentials.isValid()) {
        result.errorCode = ErrorCode::InternalError;
        return result;
    }
    const QPair<QString, QString> dns = adminConfig->getDnsPair(m_appSettingsRepository->useAmneziaDns(),
                                                                m_appSettingsRepository->primaryDns(),
                                                                m_appSettingsRepository->secondaryDns());

    ContainerConfig modifiedContainerConfig = containerConfig;
    modifiedContainerConfig.container = container;

    DnsSettings dnsSettings = {
        m_appSettingsRepository->primaryDns(),
        m_appSettingsRepository->secondaryDns()
    };

    SshSession sshSession;
    auto configurator = ConfiguratorBase::create(protocol, &sshSession);

    ProtocolConfig newProtocolConfig = configurator->createConfig(credentials, container, modifiedContainerConfig, dnsSettings, result.errorCode);
    if (result.errorCode != ErrorCode::NoError) {
        return result;
    }

    ExportSettings exportSettings = { { dns.first, dns.second } };
    ProtocolConfig processedConfig = configurator->processConfigWithExportSettings(exportSettings, newProtocolConfig);

    if (protocol == Proto::OpenVpn || protocol == Proto::WireGuard || protocol == Proto::Awg) {
        result.jsonNativeConfig[configKey::config] = processedConfig.nativeConfig();
    } else {
        result.jsonNativeConfig = QJsonDocument::fromJson(processedConfig.nativeConfig().toUtf8()).object();
    }

    if (protocol == Proto::OpenVpn || protocol == Proto::WireGuard || protocol == Proto::Awg || protocol == Proto::Xray) {
        QString clientId = newProtocolConfig.clientId();
        if (!clientId.isEmpty()) {
            emit appendClientRequested(serverId, clientId, clientName, container);
        }
    }
    return result;
}

ExportController::ExportResult ExportController::generateOpenVpnConfig(const QString &serverId, const QString &clientName)
{
    ExportResult result;

    DockerContainer container = DockerContainer::OpenVpn;
    auto adminConfig = m_serversRepository->selfHostedAdminConfig(serverId);
    if (!adminConfig.has_value()) {
        result.errorCode = ErrorCode::InternalError;
        return result;
    }
    ContainerConfig containerConfig = adminConfig->containerConfig(container);

    auto nativeResult = generateNativeConfig(serverId, container, containerConfig, clientName);
    if (nativeResult.errorCode != ErrorCode::NoError) {
        result.errorCode = nativeResult.errorCode;
        return result;
    }

    QStringList lines = nativeResult.jsonNativeConfig.value(configKey::config).toString().replace("\r", "").split("\n");
    for (const QString &line : std::as_const(lines)) {
        result.config.append(line + "\n");
    }

    result.qrCodes = generateQrCodesFromConfig(result.config.toUtf8());
    return result;
}

ExportController::ExportResult ExportController::generateWireGuardConfig(const QString &serverId, const QString &clientName)
{
    ExportResult result;

    auto adminConfig = m_serversRepository->selfHostedAdminConfig(serverId);
    if (!adminConfig.has_value()) {
        result.errorCode = ErrorCode::InternalError;
        return result;
    }
    ContainerConfig containerConfig = adminConfig->containerConfig(DockerContainer::WireGuard);

    auto nativeResult = generateNativeConfig(serverId, DockerContainer::WireGuard, containerConfig, clientName);
    if (nativeResult.errorCode != ErrorCode::NoError) {
        result.errorCode = nativeResult.errorCode;
        return result;
    }

    QStringList lines = nativeResult.jsonNativeConfig.value(configKey::config).toString().replace("\r", "").split("\n");
    for (const QString &line : std::as_const(lines)) {
        result.config.append(line + "\n");
    }

    result.qrCodes << generateSingleQrCode(result.config.toUtf8());
    return result;
}

ExportController::ExportResult ExportController::generateAwgConfig(const QString &serverId, int containerIndex, const QString &clientName)
{
    ExportResult result;

    DockerContainer container = static_cast<DockerContainer>(containerIndex);
    if (container != DockerContainer::Awg && container != DockerContainer::Awg2) {
        result.errorCode = ErrorCode::InternalError;
        return result;
    }
    auto adminConfig = m_serversRepository->selfHostedAdminConfig(serverId);
    if (!adminConfig.has_value()) {
        result.errorCode = ErrorCode::InternalError;
        return result;
    }
    ContainerConfig containerConfig = adminConfig->containerConfig(container);

    auto nativeResult = generateNativeConfig(serverId, container, containerConfig, clientName);
    if (nativeResult.errorCode != ErrorCode::NoError) {
        result.errorCode = nativeResult.errorCode;
        return result;
    }

    QStringList lines = nativeResult.jsonNativeConfig.value(configKey::config).toString().replace("\r", "").split("\n");
    for (const QString &line : std::as_const(lines)) {
        result.config.append(line + "\n");
    }

    result.qrCodes << generateSingleQrCode(result.config.toUtf8());
    return result;
}


ExportController::ExportResult ExportController::generateXrayConfig(const QString &serverId, const QString &clientName)
{
    ExportResult result;

    auto adminConfig = m_serversRepository->selfHostedAdminConfig(serverId);
    if (!adminConfig.has_value()) {
        result.errorCode = ErrorCode::InternalError;
        return result;
    }
    ContainerConfig containerConfig = adminConfig->containerConfig(DockerContainer::Xray);

    auto nativeResult = generateNativeConfig(serverId, DockerContainer::Xray, containerConfig, clientName);
    if (nativeResult.errorCode != ErrorCode::NoError) {
        result.errorCode = nativeResult.errorCode;
        return result;
    }

    QStringList lines = QString(QJsonDocument(nativeResult.jsonNativeConfig).toJson()).replace("\r", "").split("\n");
    for (const QString &line : std::as_const(lines)) {
        result.config.append(line + "\n");
    }

    // Parse the Xray data to extract VLESS parameters and generate string
    QJsonObject xrayConfig = nativeResult.jsonNativeConfig;
    QJsonArray outbounds = xrayConfig.value(amnezia::protocols::xray::outbounds).toArray();

    if (outbounds.isEmpty()) {
        result.errorCode = ErrorCode::InternalError;
        return result;
    }

    QJsonObject outbound = outbounds[0].toObject();
    QJsonObject settings = outbound.value(amnezia::protocols::xray::settings).toObject();
    QJsonObject streamSettings = outbound.value(amnezia::protocols::xray::streamSettings).toObject();

    QJsonArray vnext = settings.value(amnezia::protocols::xray::vnext).toArray();
    if (vnext.isEmpty()) {
        result.errorCode = ErrorCode::InternalError;
        return result;
    }

    QJsonObject server = vnext[0].toObject();
    QJsonArray users = server.value(amnezia::protocols::xray::users).toArray();
    if (users.isEmpty()) {
        result.errorCode = ErrorCode::InternalError;
        return result;
    }

    QJsonObject user = users[0].toObject();

    amnezia::serialization::VlessServerObject vlessServer;
    vlessServer.address = server.value(amnezia::protocols::xray::address).toString();
    vlessServer.port = server.value(amnezia::protocols::xray::port).toInt();
    vlessServer.id = user.value(amnezia::protocols::xray::id).toString();
    vlessServer.flow = user.value(amnezia::protocols::xray::flow).toString("xtls-rprx-vision");
    vlessServer.encryption = user.value(amnezia::protocols::xray::encryption).toString("none");

    vlessServer.network = streamSettings.value(amnezia::protocols::xray::network).toString("tcp");
    vlessServer.security = streamSettings.value(amnezia::protocols::xray::security).toString("reality");

    if (vlessServer.security == "reality") {
        QJsonObject realitySettings = streamSettings.value(amnezia::protocols::xray::realitySettings).toObject();
        vlessServer.serverName = realitySettings.value(amnezia::protocols::xray::serverName).toString();
        vlessServer.publicKey = realitySettings.value(amnezia::protocols::xray::publicKey).toString();
        vlessServer.shortId = realitySettings.value(amnezia::protocols::xray::shortId).toString();
        vlessServer.fingerprint = realitySettings.value(amnezia::protocols::xray::fingerprint).toString("chrome");
        vlessServer.spiderX = realitySettings.value(amnezia::protocols::xray::spiderX).toString("");
    } else if (vlessServer.security == "tls") {
        QJsonObject tlsSettings = streamSettings.value("tlsSettings").toObject();
        vlessServer.serverName = tlsSettings.value(amnezia::protocols::xray::serverName).toString();
        vlessServer.fingerprint = tlsSettings.value(amnezia::protocols::xray::fingerprint).toString();
        // alpn: serialize array back to comma-separated for VLESS URI
        QJsonArray alpnArr = tlsSettings.value("alpn").toArray();
        QStringList alpnList;
        for (const QJsonValue &v : alpnArr) {
            alpnList << v.toString();
        }
        // alpn goes into vless URI query param — handled by Serialize via serverName/alpn fields
        // VlessServerObject doesn't have alpn field, so we embed in serverName if needed
    }

    result.nativeConfigString = amnezia::serialization::vless::Serialize(vlessServer, "AmneziaVPN");

    return result;
}

void ExportController::updateClientManagementModel(const QString &serverId, int containerIndex)
{
    DockerContainer container = static_cast<DockerContainer>(containerIndex);
    const auto adminConfig = m_serversRepository->selfHostedAdminConfig(serverId);
    if (adminConfig && adminConfig->hasCredentials()) {
        refreshClientLogCollector(adminConfig->credentials(), container);
    }
    emit updateClientsRequested(serverId, container);
}

void ExportController::revokeConfig(int row, const QString &serverId, int containerIndex)
{
    DockerContainer container = static_cast<DockerContainer>(containerIndex);
    emit revokeClientRequested(serverId, row, container);
}

void ExportController::renameClient(int row, const QString &clientName, const QString &serverId, int containerIndex)
{
    DockerContainer container = static_cast<DockerContainer>(containerIndex);
    emit renameClientRequested(serverId, row, clientName, container);
}

QString ExportController::generateVpnUrl(const QByteArray &compressedConfig)
{
    return QString("vpn://%1").arg(QString(compressedConfig.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals)));
}

QList<QString> ExportController::generateQrCodesFromConfig(const QByteArray &data)
{
    return qrCodeUtils::generateQrCodeImageSeries(data);
}

QString ExportController::generateSingleQrCode(const QByteArray &data)
{
    auto qr = qrCodeUtils::generateQrCode(data);
    return qrCodeUtils::svgToBase64(QString::fromStdString(toSvgString(qr, 1)));
}
