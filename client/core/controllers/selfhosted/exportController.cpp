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
}

constexpr char clientLogsPublishErrorMarker[] = "__AMNEZIA_CLIENT_LOGS_PUBLISH_ERROR__";
constexpr char clientLogsCollectorImage[] = "python:3.12-alpine";

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
    QString script = QStringLiteral(R"PY(
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import contextlib
import json
import os
import re
import secrets
import threading
import time

ROOT = "/data"
TOKEN_FILE = os.path.join(ROOT, "tokens.tsv")
TOKEN_LOCK_DIR = os.path.join(ROOT, "tokens.lock")
LEGACY_TOKEN_FILE = os.path.join(ROOT, "legacy_tokens.tsv")
LEGACY_ROOT = os.path.join(ROOT, "legacy")
LOG_ROOT = os.path.join(ROOT, "logs")
LOCK_ROOT = os.path.join(ROOT, "locks")
MAX_UPLOAD_BYTES = __MAX_UPLOAD_BYTES__
MAX_BOOTSTRAP_BYTES = 1024
MAX_CLIENT_BYTES = __MAX_CLIENT_BYTES__
PORT = __PORT__
UPLOAD_PATH = "__UPLOAD_PATH__"
BOOTSTRAP_PATH = "__BOOTSTRAP_PATH__"
ALLOW_BOOTSTRAP = os.environ.get("AMNEZIA_CLIENT_LOGS_BOOTSTRAP", "0") == "1"
CONTAINER_SCOPE = os.environ.get("AMNEZIA_CLIENT_LOGS_SCOPE", "")
SAFE_CLIENT_ID = re.compile(r"^[a-f0-9]{64}$")
SAFE_KIND = re.compile(r"^(android|client|service)$")
SAFE_INSTALLATION_ID = re.compile(r"^[A-Za-z0-9_.-]{1,80}$")
UPLOAD_SEMAPHORE = threading.BoundedSemaphore(4)
CLIENT_LOCKS = {}
CLIENT_LOCKS_GUARD = threading.Lock()


@contextlib.contextmanager
def client_lock(client_id):
    with CLIENT_LOCKS_GUARD:
        lock = CLIENT_LOCKS.get(client_id)
        if lock is None:
            lock = threading.Lock()
            CLIENT_LOCKS[client_id] = lock
    lock.acquire()
    lock_dir = os.path.join(LOCK_ROOT, client_id)
    try:
        os.makedirs(LOCK_ROOT, mode=0o700, exist_ok=True)
        for attempt in range(30):
            try:
                os.mkdir(lock_dir)
                break
            except FileExistsError:
                if attempt == 29:
                    raise TimeoutError("client lock timeout")
                time.sleep(1)
        yield
    finally:
        try:
            os.rmdir(lock_dir)
        except FileNotFoundError:
            pass
        lock.release()


def with_token_file_lock(callback):
    os.makedirs(ROOT, mode=0o700, exist_ok=True)
    for attempt in range(30):
        try:
            os.mkdir(TOKEN_LOCK_DIR)
            break
        except FileExistsError:
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


def load_tokens():
    tokens = {}
    try:
        with open(TOKEN_FILE, "r", encoding="utf-8") as token_file:
            for line in token_file:
                line = line.rstrip("\n")
                if not line:
                    continue
                parts = line.rstrip("\n").split("\t")
                client_id = parts[0] if len(parts) > 0 else ""
                token = parts[1] if len(parts) > 1 else ""
                if client_id and token:
                    tokens[client_id] = token
    except FileNotFoundError:
        pass
    return tokens


def load_legacy_tokens():
    legacy_tokens = set()
    try:
        with open(LEGACY_TOKEN_FILE, "r", encoding="utf-8") as token_file:
            for line in token_file:
                parts = line.rstrip("\n").split("\t")
                if len(parts) < 3:
                    continue
                client_id, token, scope = parts[0], parts[1], parts[2]
                if client_id and token and scope:
                    legacy_tokens.add((client_id, token, scope))
    except FileNotFoundError:
        pass
    return legacy_tokens


def is_legacy_token(client_id, token):
    return [scope for saved_client_id, saved_token, scope in load_legacy_tokens()
            if saved_client_id == client_id and saved_token == token]


def resolve_legacy_client_id(source_ip):
    if not ALLOW_BOOTSTRAP or not CONTAINER_SCOPE:
        return ""
    legacy_map = os.path.join(LEGACY_ROOT, CONTAINER_SCOPE + ".tsv")
    try:
        with open(legacy_map, "r", encoding="utf-8") as map_file:
            for line in map_file:
                parts = line.rstrip("\n").split("\t")
                if len(parts) < 2:
                    continue
                vpn_ip, client_id = parts[0], parts[1]
                if vpn_ip == source_ip and SAFE_CLIENT_ID.match(client_id):
                    return client_id
    except FileNotFoundError:
        pass
    return ""


def ensure_legacy_token(client_id):
    def update_token_files():
        tokens = load_tokens()
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
        os.replace(tokens_tmp, TOKEN_FILE)
        os.replace(legacy_tmp, LEGACY_TOKEN_FILE)
        os.chmod(TOKEN_FILE, 0o600)
        os.chmod(LEGACY_TOKEN_FILE, 0o600)
        return token

    return with_token_file_lock(update_token_files)


def prune_client_dir(client_dir):
    files = []
    total = 0
    for name in os.listdir(client_dir):
        path = os.path.join(client_dir, name)
        if not name.endswith(".log") or not os.path.isfile(path):
            continue
        stat = os.stat(path)
        files.append((stat.st_mtime, path, stat.st_size))
        total += stat.st_size
    for _, path, size in sorted(files):
        if total <= MAX_CLIENT_BYTES:
            break
        try:
            os.remove(path)
            total -= size
        except FileNotFoundError:
            pass


class Handler(BaseHTTPRequestHandler):
    server_version = "AmneziaClientLogs/1.0"

    def authenticate_client(self):
        client_id = self.headers.get("X-Amnezia-Client-Id", "")
        token = self.headers.get("X-Amnezia-Log-Token", "")
        if not SAFE_CLIENT_ID.match(client_id):
            self.send_error(400)
            return None
        if load_tokens().get(client_id) != token:
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
        if not SAFE_KIND.match(kind):
            self.send_error(400)
            return
        if not SAFE_INSTALLATION_ID.match(installation_id):
            installation_id = "unknown"
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
                stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
                final_path = os.path.join(client_dir, f"{stamp}-{time.time_ns()}-{installation_id}-{kind}.log")
                tmp_path = final_path + ".tmp"
                remaining = content_length
                with open(tmp_path, "wb") as log_file:
                    while remaining > 0:
                        chunk = self.rfile.read(min(64 * 1024, remaining))
                        if not chunk:
                            raise ConnectionError("short request body")
                        log_file.write(chunk)
                        remaining -= len(chunk)
                os.replace(tmp_path, final_path)
                prune_client_dir(client_dir)
            self.send_response(204)
            self.end_headers()
        except Exception:
            if tmp_path is not None:
                try:
                    os.remove(tmp_path)
                except FileNotFoundError:
                    pass
            self.send_error(400)
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


def main():
    os.umask(0o077)
    os.makedirs(LOG_ROOT, mode=0o700, exist_ok=True)
    LogServer(("0.0.0.0", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
)PY");
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
if [ '__UPSERT_TOKEN__' = '1' ]; then sudo sh -c "i=0; while ! mkdir '__HOST_DIRECTORY__/tokens.lock' 2>/dev/null; do i=\$((i + 1)); [ \$i -lt 30 ] || { echo __ERROR_MARKER__:tokens_lock; exit 0; }; sleep 1; done; trap 'rm -rf \"__HOST_DIRECTORY__/tokens.lock\" \"__HOST_DIRECTORY__/tokens.tsv.__CLIENT_LOG_ID__.tmp\"' EXIT; grep -v '^__CLIENT_LOG_ID__[[:space:]]' '__HOST_DIRECTORY__/tokens.tsv' 2>/dev/null > '__HOST_DIRECTORY__/tokens.tsv.__CLIENT_LOG_ID__.tmp' || true; cat '__TOKEN_TMP_FILE__' >> '__HOST_DIRECTORY__/tokens.tsv.__CLIENT_LOG_ID__.tmp' || { echo __ERROR_MARKER__:token_append; exit 0; }; install -m 0600 '__HOST_DIRECTORY__/tokens.tsv.__CLIENT_LOG_ID__.tmp' '__HOST_DIRECTORY__/tokens.tsv' || echo __ERROR_MARKER__:tokens_install"; fi
sudo rm -f '__SCRIPT_TMP_FILE__' '__TOKEN_TMP_FILE__' || true
if sudo docker network inspect amnezia-dns-net >/dev/null 2>&1; then if ! sudo docker network inspect amnezia-dns-net --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}' | grep -qw '172.29.172.0/24'; then echo __ERROR_MARKER__:network_subnet; fi; else sudo docker network create --driver bridge --subnet=172.29.172.0/24 --opt com.docker.network.bridge.name=amn0 amnezia-dns-net || echo __ERROR_MARKER__:network_create; fi
if ! sudo docker image inspect '__COLLECTOR_IMAGE__' >/dev/null 2>&1; then sudo docker pull '__COLLECTOR_IMAGE__' >/dev/null || echo __ERROR_MARKER__:image_pull; fi
sudo docker rm -f '__BRIDGE_CONTAINER__' >/dev/null 2>&1 || true
sudo docker run -d --log-driver none --restart always --memory=96m --cpus=0.5 --pids-limit=64 --network amnezia-dns-net --ip=__BRIDGE_HOST__ --name '__BRIDGE_CONTAINER__' -e AMNEZIA_CLIENT_LOGS_BOOTSTRAP=0 -v __HOST_DIRECTORY__:/data:rw --entrypoint python '__COLLECTOR_IMAGE__' /data/collector.py || echo __ERROR_MARKER__:bridge_run
if [ '__PUBLISH_TUNNEL__' = '1' ]; then if sudo docker ps --format '{{.Names}}' | grep -qx '__VPN_CONTAINER__'; then if [ '__ALLOW_LEGACY_BOOTSTRAP__' = '1' ]; then __LEGACY_MAP_REFRESH__ fi; sudo docker rm -f '__TUNNEL_CONTAINER__' >/dev/null 2>&1 || true; sudo docker exec -i '__VPN_CONTAINER__' sh -c 'while iptables -t nat -D PREROUTING -i __TUNNEL_IFACE__ -d __BRIDGE_HOST__/32 -p tcp --dport __SYNC_PORT__ -j REDIRECT --to-ports __SYNC_PORT__ 2>/dev/null; do :; done; iptables -t nat -A PREROUTING -i __TUNNEL_IFACE__ -d __BRIDGE_HOST__/32 -p tcp --dport __SYNC_PORT__ -j REDIRECT --to-ports __SYNC_PORT__' >/dev/null 2>&1 || echo __ERROR_MARKER__:tunnel_redirect; sudo docker run -d --log-driver none --restart always --memory=96m --cpus=0.5 --pids-limit=64 --network container:__VPN_CONTAINER__ --name '__TUNNEL_CONTAINER__' -e AMNEZIA_CLIENT_LOGS_BOOTSTRAP=__ALLOW_LEGACY_BOOTSTRAP__ -e AMNEZIA_CLIENT_LOGS_SCOPE='__CONTAINER_SCOPE__' -v __HOST_DIRECTORY__:/data:rw --entrypoint python '__COLLECTOR_IMAGE__' /data/collector.py || echo __ERROR_MARKER__:tunnel_run; else echo __ERROR_MARKER__:missing_vpn_container; fi; fi
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
