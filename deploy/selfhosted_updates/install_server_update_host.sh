#!/bin/sh
# This entrypoint is executed directly by POSIX sh; keep it LF-only.
set -eu

HOST_DIRECTORY="${1:-/opt/amnezia/client-updates}"
BRIDGE_HOST="${AMNEZIA_UPDATE_BRIDGE_HOST:-172.29.172.252}"
SYNC_PORT="${AMNEZIA_UPDATE_SYNC_PORT:-17865}"
CONTAINER_NAME="${AMNEZIA_UPDATE_CONTAINER_NAME:-amnezia-client-updates}"
HOST_CONTAINER_NAME="${AMNEZIA_UPDATE_HOST_CONTAINER_NAME:-${CONTAINER_NAME}-host}"
# Docker Official Image busybox:1.36.1 OCI index identity, verified 2026-07-26 with
# an authenticated request to the primary Docker Registry manifest endpoint:
# https://registry-1.docker.io/v2/library/busybox/manifests/1.36.1
# Content-Type: application/vnd.oci.image.index.v1+json
# Docker-Content-Digest: sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662
IMAGE_REPOSITORY="docker.io/library/busybox"
IMAGE_DIGEST="sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662"
IMAGE="${IMAGE_REPOSITORY}@${IMAGE_DIGEST}"
VPN_CONTAINER="${AMNEZIA_UPDATE_VPN_CONTAINER:-}"
PUBLISH_HOST_PORT="${AMNEZIA_UPDATE_PUBLISH_HOST_PORT:-1}"
HOST_BIND="${AMNEZIA_UPDATE_HOST_BIND:-0.0.0.0}"
EXPECTED_SUBNET="172.29.172.0/24"
AUTO_VPN_CONTAINERS="amnezia-awg2 amnezia-awg amnezia-wireguard amnezia-openvpn"

TRUST_ANCHOR='/opt'
LOCK_PARENT='/opt/amnezia'
LOCK_PATH="${LOCK_PARENT}/.client-update-host-installer.lock"
CID_PARENT="${LOCK_PARENT}/.client-update-host-cids"
FIREWALL_STATE_PATH="${LOCK_PARENT}/.client-update-host-firewall-state"
JOURNAL_PATH="${LOCK_PARENT}/.client-update-host-transaction"
LOCK_WAIT_SECONDS=60
TRUSTED_UID=0
TRUSTED_GID=0
TRANSACTION_LABEL_KEY='org.amnezia.client-update-host.transaction'
ROLE_LABEL_KEY='org.amnezia.client-update-host.role'
BIND_LABEL_KEY='org.amnezia.client-update-host.bind'
PROBE_LABEL_KEY='org.amnezia.client-update-host.probe'
PORT_LABEL_KEY='org.amnezia.client-update-host.port'
FIREWALL_STATE_VERSION=1
JOURNAL_VERSION=2

TRANSACTION_ID=""
TRANSACTION_STARTED=0
TRANSACTION_COMMITTED=0
BACKUP_RECORDS=""
NEW_CONTAINER_RECORDS=""
NEW_INTENT_RECORDS=""
VPN_RECORDS=""
TUNNEL_CONTAINERS=""
TUNNEL_CONTAINER_RECORDS=""
HEALTH_SENTINEL_PATH=""
HEALTH_SENTINEL_NAME=""
HEALTH_SENTINEL_CONTENT=""
HEALTH_SENTINEL_INTENT=0
HEALTH_SENTINEL_CREATED=0
NETWORK_NAME=""
NETWORK_CREATED=0
NETWORK_ID=""
FIREWALL_ACTIONS=""
FIREWALL_STATE_BACKUP=""
FIREWALL_STATE_TMP=""
FIREWALL_STATE_SWITCH_ATTEMPTED=0
FIREWALL_OLD_PRESENT=0
FIREWALL_OLD_BIND=""
FIREWALL_OLD_PORT=""
FIREWALL_OLD_UFW=0
FIREWALL_OLD_FIREWALLD_RUNTIME=0
FIREWALL_OLD_FIREWALLD_PERMANENT=0
FIREWALL_OLD_IPTABLES=0
FIREWALL_NEW_UFW=0
FIREWALL_NEW_FIREWALLD_RUNTIME=0
FIREWALL_NEW_FIREWALLD_PERMANENT=0
FIREWALL_NEW_IPTABLES=0
JOURNAL_PHASE=""
JOURNAL_TMP=""

die() {
    printf '%s\n' "$1" >&2
    exit 2
}

as_root() {
    sudo -n -- "$@"
}

is_ipv4_address() {
    candidate="$1"
    case "$candidate" in
        ""|*/*)
            return 1
            ;;
    esac

    old_ifs="$IFS"
    IFS=.
    set -- $candidate
    IFS="$old_ifs"

    [ "$#" -eq 4 ] || return 1
    for octet do
        case "$octet" in
            ""|*[!0-9]*)
                return 1
                ;;
        esac
        [ "$octet" -ge 0 ] 2>/dev/null && [ "$octet" -le 255 ] 2>/dev/null || return 1
    done
}

is_port() {
    case "$1" in
        ""|*[!0-9]*)
            return 1
            ;;
    esac
    [ "$1" -ge 1 ] 2>/dev/null && [ "$1" -le 65535 ] 2>/dev/null
}

is_container_name() {
    case "$1" in
        ""|*[!A-Za-z0-9_.-]*|*.amnezia-backup.*)
            return 1
            ;;
        [A-Za-z0-9]*)
            [ "${#1}" -le 128 ]
            ;;
        *)
            return 1
            ;;
    esac
}

require_trusted_directory() {
    trusted_path="$1"
    description="$2"
    as_root test -d "$trusted_path" && ! as_root test -L "$trusted_path" \
        || die "$description is not a trusted directory"
    trusted_metadata="$(as_root stat -c '%u:%g:%a' -- "$trusted_path")" \
        || die "Unable to inspect $description"
    trusted_uid="${trusted_metadata%%:*}"
    trusted_remainder="${trusted_metadata#*:}"
    trusted_gid="${trusted_remainder%%:*}"
    trusted_mode="${trusted_remainder##*:}"
    case "$trusted_mode" in
        ""|*[!0-7]*) die "$description has invalid mode metadata" ;;
    esac
    [ "$trusted_uid" = "$TRUSTED_UID" ] && [ "$trusted_gid" = "$TRUSTED_GID" ] \
        && [ $((0$trusted_mode & 0022)) -eq 0 ] && [ -x "$trusted_path" ] \
        || die "$description has unsafe ownership or mode"
}

prepare_installer_lock() {
    require_trusted_directory "$TRUST_ANCHOR" "installer trust anchor"
    if ! as_root test -e "$LOCK_PARENT" && ! as_root test -L "$LOCK_PARENT"; then
        as_root install -d -o "$TRUSTED_UID" -g "$TRUSTED_GID" -m 0755 -- "$LOCK_PARENT"
    fi
    require_trusted_directory "$LOCK_PARENT" "installer lock parent"

    if ! as_root test -e "$LOCK_PATH" && ! as_root test -L "$LOCK_PATH"; then
        lock_candidate="${LOCK_PATH}.candidate.$$"
        as_root install -o "$TRUSTED_UID" -g "$TRUSTED_GID" -m 0444 /dev/null "$lock_candidate"
        as_root ln -- "$lock_candidate" "$LOCK_PATH" 2>/dev/null || true
        as_root rm -f -- "$lock_candidate"
    fi
    as_root test -f "$LOCK_PATH" && ! as_root test -L "$LOCK_PATH" \
        || die "Installer lock is not a trusted regular file"
    [ "$(as_root stat -c '%u:%g:%a' -- "$LOCK_PATH")" = "${TRUSTED_UID}:${TRUSTED_GID}:444" ] \
        && [ -r "$LOCK_PATH" ] \
        || die "Installer lock has unsafe ownership or mode"

    exec 9<"$LOCK_PATH"
    flock -x -w "$LOCK_WAIT_SECONDS" 9 || die "Timed out waiting for update host installer lock"
}

persist_transaction_journal() {
    journal_phase_to_write="$1"
    [ "$TRANSACTION_STARTED" = 1 ] || return 0
    case "$journal_phase_to_write" in
        active|committed_pending_cleanup) ;;
        *) die "Invalid update-host transaction journal phase" ;;
    esac
    JOURNAL_TMP="${JOURNAL_PATH}.candidate.${TRANSACTION_ID}"
    as_root rm -f -- "$JOURNAL_TMP" \
        || die "Unable to clear update-host transaction journal staging path"
    as_root test ! -e "$JOURNAL_TMP" && ! as_root test -L "$JOURNAL_TMP" \
        || die "Transaction journal staging path is unsafe"
    as_root install -o "$TRUSTED_UID" -g "$TRUSTED_GID" -m 0600 /dev/null "$JOURNAL_TMP" \
        || die "Unable to create update-host transaction journal staging file"
    {
        printf 'version=%s\n' "$JOURNAL_VERSION"
        printf 'phase=%s\n' "$journal_phase_to_write"
        printf 'transaction_id=%s\n' "$TRANSACTION_ID"
        printf 'host_directory=%s\n' "$HOST_DIRECTORY"
        printf 'sync_port=%s\n' "$SYNC_PORT"
        printf 'host_bind=%s\n' "$HOST_BIND"
        printf 'host_probe_address=%s\n' "$HOST_PROBE_ADDRESS"
        printf 'health_sentinel_name=%s\n' "$HEALTH_SENTINEL_NAME"
        printf 'health_sentinel_intent=%s\n' "$HEALTH_SENTINEL_INTENT"
        printf 'health_sentinel_created=%s\n' "$HEALTH_SENTINEL_CREATED"
        printf 'network_name=%s\n' "$NETWORK_NAME"
        printf 'network_created=%s\n' "$NETWORK_CREATED"
        printf 'network_id=%s\n' "$NETWORK_ID"
        printf 'firewall_old_present=%s\n' "$FIREWALL_OLD_PRESENT"
        printf 'firewall_old_bind=%s\n' "$FIREWALL_OLD_BIND"
        printf 'firewall_old_port=%s\n' "$FIREWALL_OLD_PORT"
        printf 'firewall_old_ufw=%s\n' "$FIREWALL_OLD_UFW"
        printf 'firewall_old_firewalld_runtime=%s\n' "$FIREWALL_OLD_FIREWALLD_RUNTIME"
        printf 'firewall_old_firewalld_permanent=%s\n' "$FIREWALL_OLD_FIREWALLD_PERMANENT"
        printf 'firewall_old_iptables=%s\n' "$FIREWALL_OLD_IPTABLES"
        printf 'firewall_state_switch_attempted=%s\n' "$FIREWALL_STATE_SWITCH_ATTEMPTED"
        while IFS= read -r journal_record; do
            [ -n "$journal_record" ] && printf 'backup=%s\n' "$journal_record"
        done <<EOF
$BACKUP_RECORDS
EOF
        while IFS= read -r journal_record; do
            [ -n "$journal_record" ] && printf 'new_intent=%s\n' "$journal_record"
        done <<EOF
$NEW_INTENT_RECORDS
EOF
        while IFS= read -r journal_record; do
            [ -n "$journal_record" ] && printf 'firewall_action=%s\n' "$journal_record"
        done <<EOF
$FIREWALL_ACTIONS
EOF
    } | as_root tee -- "$JOURNAL_TMP" >/dev/null \
        || die "Unable to write update-host transaction journal"
    as_root chmod 0444 -- "$JOURNAL_TMP" \
        || die "Unable to seal update-host transaction journal"
    as_root sync -f -- "$JOURNAL_TMP" \
        || die "Unable to persist update-host transaction journal"
    as_root mv -fT -- "$JOURNAL_TMP" "$JOURNAL_PATH" \
        || die "Unable to switch update-host transaction journal"
    JOURNAL_TMP=""
    as_root sync -f -- "$LOCK_PARENT" \
        || die "Unable to persist update-host transaction journal switch"
    JOURNAL_PHASE="$journal_phase_to_write"
}

clear_transaction_journal() {
    [ -z "$JOURNAL_TMP" ] || as_root rm -f -- "$JOURNAL_TMP" || return 1
    JOURNAL_TMP=""
    as_root rm -f -- "$JOURNAL_PATH" || return 1
    as_root test ! -e "$JOURNAL_PATH" && ! as_root test -L "$JOURNAL_PATH" || return 1
    as_root sync -f -- "$LOCK_PARENT" || return 1
    JOURNAL_PHASE=""
}

append_loaded_record() {
    loaded_record_kind="$1"
    loaded_record_value="$2"
    case "$loaded_record_kind" in
        backup) loaded_current="$BACKUP_RECORDS" ;;
        new_intent) loaded_current="$NEW_INTENT_RECORDS" ;;
        firewall_action) loaded_current="$FIREWALL_ACTIONS" ;;
        *) die "Invalid transaction journal record kind" ;;
    esac
    if [ -n "$loaded_current" ]; then
        loaded_combined="$loaded_current
$loaded_record_value"
    else
        loaded_combined="$loaded_record_value"
    fi
    case "$loaded_record_kind" in
        backup) BACKUP_RECORDS="$loaded_combined" ;;
        new_intent) NEW_INTENT_RECORDS="$loaded_combined" ;;
        firewall_action) FIREWALL_ACTIONS="$loaded_combined" ;;
    esac
}

load_transaction_journal() {
    as_root test -f "$JOURNAL_PATH" && ! as_root test -L "$JOURNAL_PATH" \
        || die "Transaction journal is not a trusted regular file"
    [ "$(as_root stat -c '%u:%g:%a' -- "$JOURNAL_PATH")" = "${TRUSTED_UID}:${TRUSTED_GID}:444" ] \
        || die "Transaction journal has unsafe ownership or mode"

    BACKUP_RECORDS=""
    NEW_INTENT_RECORDS=""
    NEW_CONTAINER_RECORDS=""
    FIREWALL_ACTIONS=""
    journal_seen_version=0
    journal_seen_phase=0
    journal_seen_transaction=0
    journal_seen_host_directory=0
    journal_seen_sync_port=0
    journal_seen_host_bind=0
    journal_seen_probe=0
    journal_seen_sentinel=0
    journal_seen_sentinel_intent=0
    journal_seen_sentinel_created=0
    journal_seen_network_name=0
    journal_seen_network_created=0
    journal_seen_network_id=0
    journal_seen_old_present=0
    journal_seen_old_bind=0
    journal_seen_old_port=0
    journal_seen_old_ufw=0
    journal_seen_old_runtime=0
    journal_seen_old_permanent=0
    journal_seen_old_iptables=0
    journal_seen_switch=0
    while IFS='=' read -r journal_key journal_value; do
        case "$journal_key" in
            version) [ "$journal_seen_version" = 0 ] || die "Duplicate journal version"; journal_seen_version=1; [ "$journal_value" = "$JOURNAL_VERSION" ] || die "Unsupported transaction journal version" ;;
            phase) [ "$journal_seen_phase" = 0 ] || die "Duplicate journal phase"; journal_seen_phase=1; JOURNAL_PHASE="$journal_value" ;;
            transaction_id) [ "$journal_seen_transaction" = 0 ] || die "Duplicate journal transaction"; journal_seen_transaction=1; TRANSACTION_ID="$journal_value" ;;
            host_directory) [ "$journal_seen_host_directory" = 0 ] || die "Duplicate journal host directory"; journal_seen_host_directory=1; journal_host_directory="$journal_value" ;;
            sync_port) [ "$journal_seen_sync_port" = 0 ] || die "Duplicate journal sync port"; journal_seen_sync_port=1; journal_sync_port="$journal_value" ;;
            host_bind) [ "$journal_seen_host_bind" = 0 ] || die "Duplicate journal host bind"; journal_seen_host_bind=1; journal_host_bind="$journal_value" ;;
            host_probe_address) [ "$journal_seen_probe" = 0 ] || die "Duplicate journal probe address"; journal_seen_probe=1; journal_probe_address="$journal_value" ;;
            health_sentinel_name) [ "$journal_seen_sentinel" = 0 ] || die "Duplicate journal health sentinel"; journal_seen_sentinel=1; HEALTH_SENTINEL_NAME="$journal_value" ;;
            health_sentinel_intent) [ "$journal_seen_sentinel_intent" = 0 ] || die "Duplicate journal health sentinel intent"; journal_seen_sentinel_intent=1; HEALTH_SENTINEL_INTENT="$journal_value" ;;
            health_sentinel_created) [ "$journal_seen_sentinel_created" = 0 ] || die "Duplicate journal health sentinel creation flag"; journal_seen_sentinel_created=1; HEALTH_SENTINEL_CREATED="$journal_value" ;;
            network_name) [ "$journal_seen_network_name" = 0 ] || die "Duplicate journal network name"; journal_seen_network_name=1; NETWORK_NAME="$journal_value" ;;
            network_created) [ "$journal_seen_network_created" = 0 ] || die "Duplicate journal network creation flag"; journal_seen_network_created=1; NETWORK_CREATED="$journal_value" ;;
            network_id) [ "$journal_seen_network_id" = 0 ] || die "Duplicate journal network ID"; journal_seen_network_id=1; NETWORK_ID="$journal_value" ;;
            firewall_old_present) [ "$journal_seen_old_present" = 0 ] || die "Duplicate journal old firewall flag"; journal_seen_old_present=1; FIREWALL_OLD_PRESENT="$journal_value" ;;
            firewall_old_bind) [ "$journal_seen_old_bind" = 0 ] || die "Duplicate journal old firewall bind"; journal_seen_old_bind=1; FIREWALL_OLD_BIND="$journal_value" ;;
            firewall_old_port) [ "$journal_seen_old_port" = 0 ] || die "Duplicate journal old firewall port"; journal_seen_old_port=1; FIREWALL_OLD_PORT="$journal_value" ;;
            firewall_old_ufw) [ "$journal_seen_old_ufw" = 0 ] || die "Duplicate journal old ufw flag"; journal_seen_old_ufw=1; FIREWALL_OLD_UFW="$journal_value" ;;
            firewall_old_firewalld_runtime) [ "$journal_seen_old_runtime" = 0 ] || die "Duplicate journal old firewalld runtime flag"; journal_seen_old_runtime=1; FIREWALL_OLD_FIREWALLD_RUNTIME="$journal_value" ;;
            firewall_old_firewalld_permanent) [ "$journal_seen_old_permanent" = 0 ] || die "Duplicate journal old firewalld permanent flag"; journal_seen_old_permanent=1; FIREWALL_OLD_FIREWALLD_PERMANENT="$journal_value" ;;
            firewall_old_iptables) [ "$journal_seen_old_iptables" = 0 ] || die "Duplicate journal old iptables flag"; journal_seen_old_iptables=1; FIREWALL_OLD_IPTABLES="$journal_value" ;;
            firewall_state_switch_attempted) [ "$journal_seen_switch" = 0 ] || die "Duplicate journal firewall switch flag"; journal_seen_switch=1; FIREWALL_STATE_SWITCH_ATTEMPTED="$journal_value" ;;
            backup|new_intent|firewall_action) [ -n "$journal_value" ] || die "Empty transaction journal record"; append_loaded_record "$journal_key" "$journal_value" ;;
            *) die "Transaction journal contains an unknown field" ;;
        esac
    done <<EOF
$(as_root cat -- "$JOURNAL_PATH")
EOF
    [ "$journal_seen_version$journal_seen_phase$journal_seen_transaction$journal_seen_host_directory$journal_seen_sync_port$journal_seen_host_bind$journal_seen_probe$journal_seen_sentinel$journal_seen_sentinel_intent$journal_seen_sentinel_created$journal_seen_network_name$journal_seen_network_created$journal_seen_network_id$journal_seen_old_present$journal_seen_old_bind$journal_seen_old_port$journal_seen_old_ufw$journal_seen_old_runtime$journal_seen_old_permanent$journal_seen_old_iptables$journal_seen_switch" = 111111111111111111111 ] \
        || die "Transaction journal is incomplete"
    case "$JOURNAL_PHASE" in active|committed_pending_cleanup) ;; *) die "Transaction journal phase is invalid" ;; esac
    case "$TRANSACTION_ID" in ""|*[!0-9a-f]*) die "Transaction journal ID is invalid" ;; esac
    [ "${#TRANSACTION_ID}" -eq 48 ] || die "Transaction journal ID length is invalid"
    [ "$journal_host_directory" = "$HOST_DIRECTORY" ] \
        || die "Transaction recovery requires the original host directory"
    [ "$journal_sync_port" = "$SYNC_PORT" ] \
        || die "Transaction recovery requires the original sync port"
    [ "$journal_host_bind" = "$HOST_BIND" ] \
        || die "Transaction recovery requires the original host bind"
    [ "$journal_probe_address" = "$HOST_PROBE_ADDRESS" ] \
        || die "Transaction recovery requires the original host bind"
    [ "$HEALTH_SENTINEL_NAME" = "amnezia-update-health-${TRANSACTION_ID}" ] \
        || die "Transaction journal health sentinel identity is invalid"
    for journal_flag in "$HEALTH_SENTINEL_INTENT" "$HEALTH_SENTINEL_CREATED" \
        "$NETWORK_CREATED" "$FIREWALL_OLD_PRESENT" "$FIREWALL_OLD_UFW" \
        "$FIREWALL_OLD_FIREWALLD_RUNTIME" "$FIREWALL_OLD_FIREWALLD_PERMANENT" \
        "$FIREWALL_OLD_IPTABLES" "$FIREWALL_STATE_SWITCH_ATTEMPTED"; do
        case "$journal_flag" in 0|1) ;; *) die "Transaction journal contains an invalid flag" ;; esac
    done
    [ "$HEALTH_SENTINEL_CREATED" = 0 ] || [ "$HEALTH_SENTINEL_INTENT" = 1 ] \
        || die "Transaction journal records a sentinel without prior intent"
    if [ "$NETWORK_CREATED" = 1 ]; then
        is_container_name "$NETWORK_NAME" || die "Transaction journal has an invalid owned network name"
    else
        [ -z "$NETWORK_ID" ] || die "Transaction journal has an unexpected network ID"
    fi
    if [ "$FIREWALL_OLD_PRESENT" = 1 ]; then
        is_ipv4_address "$FIREWALL_OLD_BIND" && is_port "$FIREWALL_OLD_PORT" \
            || die "Transaction journal old firewall endpoint is invalid"
        FIREWALL_STATE_BACKUP="${FIREWALL_STATE_PATH}.backup.${TRANSACTION_ID}"
    else
        [ -z "$FIREWALL_OLD_BIND$FIREWALL_OLD_PORT" ] \
            || die "Transaction journal has unexpected old firewall endpoint"
        FIREWALL_STATE_BACKUP=""
    fi
    while IFS='|' read -r journal_original journal_backup journal_id journal_running journal_network journal_ip journal_health; do
        [ -n "$journal_original" ] || continue
        is_container_name "$journal_original" \
            || die "Transaction journal has an invalid backup original name"
        [ "$journal_backup" = "${journal_original}.amnezia-backup.${TRANSACTION_ID}" ] \
            || die "Transaction journal has an invalid backup name"
        [ -n "$journal_id" ] || die "Transaction journal has an empty backup container ID"
        case "$journal_running" in true|false) ;; *) die "Transaction journal has an invalid running state" ;; esac
        if [ -n "$journal_network" ]; then
            is_container_name "$journal_network" || die "Transaction journal has an invalid network name"
        fi
        if [ -n "$journal_ip" ]; then
            is_ipv4_address "$journal_ip" || die "Transaction journal has an invalid network address"
        fi
        is_ipv4_address "$journal_health" || die "Transaction journal has an invalid health address"
    done <<EOF
$BACKUP_RECORDS
EOF
    while IFS='|' read -r journal_action journal_backend journal_bind journal_port; do
        [ -n "$journal_action" ] || continue
        case "$journal_action" in added|removed) ;; *) die "Transaction journal has an invalid firewall action" ;; esac
        case "$journal_backend" in ufw|firewalld-runtime|firewalld-permanent|iptables) ;; *) die "Transaction journal has an invalid firewall backend" ;; esac
        is_ipv4_address "$journal_bind" && is_port "$journal_port" \
            || die "Transaction journal has an invalid firewall endpoint"
    done <<EOF
$FIREWALL_ACTIONS
EOF
    HEALTH_SENTINEL_PATH="${HOST_DIRECTORY}/${HEALTH_SENTINEL_NAME}"
    HEALTH_SENTINEL_CONTENT="amnezia-update-health-v1:${TRANSACTION_ID}"
    TRANSACTION_STARTED=1
}

CONTAINER_QUERY_VALUE=""

query_container_field() {
    query_ref="$1"
    query_template="$2"
    query_description="$3"
    CONTAINER_QUERY_VALUE=""
    query_status=0
    query_output="$(as_root docker container inspect -f "$query_template" "$query_ref" 2>&1)" \
        || query_status=$?
    if [ "$query_status" -eq 0 ]; then
        CONTAINER_QUERY_VALUE="$query_output"
        return 0
    fi
    case "$query_output" in
        *"No such object"*|*"No such container"*) return 1 ;;
        *) die "Docker failed while querying $query_description for $query_ref: $query_output" ;;
    esac
}

query_container_id() {
    query_container_field "$1" '{{.Id}}' 'container ID'
}

query_container_name() {
    query_container_field "$1" '{{.Name}}' 'container name' || return $?
    CONTAINER_QUERY_VALUE="${CONTAINER_QUERY_VALUE#/}"
}

query_container_label() {
    query_container_field "$1" "{{index .Config.Labels \"$2\"}}" 'container label'
}

query_container_image() {
    query_container_field "$1" '{{.Config.Image}}' 'container image'
}

query_container_www_mount() {
    query_container_field "$1" '{{range .Mounts}}{{if eq .Destination "/www"}}{{.Source}}|{{.RW}}{{println}}{{end}}{{end}}' 'container mount'
}

query_container_running() {
    query_container_field "$1" '{{.State.Running}}' 'container running state' || return $?
    case "$CONTAINER_QUERY_VALUE" in
        true|false) ;;
        *) die "Docker returned an invalid running state for $1" ;;
    esac
}

container_exists() {
    query_container_id "$1"
}

assert_container_id() {
    expected_id="$1"
    [ -n "$expected_id" ] || return 1
    query_container_id "$expected_id" || return $?
    [ "$CONTAINER_QUERY_VALUE" = "$expected_id" ]
}

assert_name_maps_to_id() {
    expected_name="$1"
    expected_id="$2"
    query_container_id "$expected_name" || return $?
    observed_id="$CONTAINER_QUERY_VALUE"
    query_container_name "$expected_id" || return $?
    observed_name="$CONTAINER_QUERY_VALUE"
    [ "$observed_id" = "$expected_id" ] && [ "$observed_name" = "$expected_name" ]
}

assert_transaction_container_identity() {
    expected_id="$1"
    expected_role="$2"
    assert_container_id "$expected_id" || return 1
    query_container_label "$expected_id" "$TRANSACTION_LABEL_KEY" || return 1
    [ "$CONTAINER_QUERY_VALUE" = "$TRANSACTION_ID" ] || return 1
    query_container_label "$expected_id" "$ROLE_LABEL_KEY" || return 1
    [ "$CONTAINER_QUERY_VALUE" = "$expected_role" ] || return 1
    query_container_label "$expected_id" "$BIND_LABEL_KEY" || return 1
    [ "$CONTAINER_QUERY_VALUE" = "$HOST_BIND" ] || return 1
    query_container_label "$expected_id" "$PROBE_LABEL_KEY" || return 1
    [ "$CONTAINER_QUERY_VALUE" = "$HOST_PROBE_ADDRESS" ] || return 1
    query_container_label "$expected_id" "$PORT_LABEL_KEY" || return 1
    [ "$CONTAINER_QUERY_VALUE" = "$SYNC_PORT" ] || return 1
    query_container_image "$expected_id" || return 1
    [ "$CONTAINER_QUERY_VALUE" = "$IMAGE" ] || return 1
    query_container_www_mount "$expected_id" || return 1
    [ "$CONTAINER_QUERY_VALUE" = "${HOST_DIRECTORY}|false" ]
}

assert_new_container_identity() {
    expected_id="$1"
    expected_name="$2"
    expected_role="$3"
    assert_transaction_container_identity "$expected_id" "$expected_role" || return 1
    assert_name_maps_to_id "$expected_name" "$expected_id"
}

is_running_container() {
    query_container_running "$1" || return $?
    [ "$CONTAINER_QUERY_VALUE" = true ]
}

query_container_network_ip() {
    network_container="$1"
    network_name="$2"
    query_container_field "$network_container" \
        "{{with index .NetworkSettings.Networks \"$network_name\"}}{{.IPAddress}}{{end}}" \
        'container network address'
}

NETWORK_QUERY_VALUE=""

query_network_field() {
    network_ref="$1"
    network_template="$2"
    network_description="$3"
    NETWORK_QUERY_VALUE=""
    network_query_status=0
    network_query_output="$(as_root docker network inspect -f "$network_template" "$network_ref" 2>&1)" \
        || network_query_status=$?
    if [ "$network_query_status" -eq 0 ]; then
        NETWORK_QUERY_VALUE="$network_query_output"
        return 0
    fi
    case "$network_query_output" in
        *"No such network"*|*"No such object"*) return 1 ;;
        *) die "Docker failed while querying $network_description for $network_ref: $network_query_output" ;;
    esac
}

query_network_id() {
    query_network_field "$1" '{{.Id}}' 'network ID'
}

query_network_name() {
    query_network_field "$1" '{{.Name}}' 'network name'
}

query_network_label() {
    query_network_field "$1" "{{index .Labels \"$2\"}}" 'network label'
}

query_network_subnets() {
    query_network_field "$1" '{{range .IPAM.Config}}{{println .Subnet}}{{end}}' 'network subnet'
}

find_transaction_network_id() {
    TRANSACTION_NETWORK_ID=""
    transaction_network_ids="$(as_root docker network ls -q --no-trunc \
        --filter "label=${TRANSACTION_LABEL_KEY}=${TRANSACTION_ID}" \
        --filter "label=${ROLE_LABEL_KEY}=network")" \
        || die "Docker failed while resolving the transaction network"
    set -- $transaction_network_ids
    [ "$#" -le 1 ] || die "Transaction labels resolve to multiple owned networks"
    [ "$#" -eq 0 ] || TRANSACTION_NETWORK_ID="$1"
}

assert_owned_network_identity() {
    owned_network_id="$1"
    owned_network_name="$2"
    query_network_id "$owned_network_id" || return 1
    [ "$NETWORK_QUERY_VALUE" = "$owned_network_id" ] || return 1
    query_network_id "$owned_network_name" || return 1
    [ "$NETWORK_QUERY_VALUE" = "$owned_network_id" ] || return 1
    query_network_name "$owned_network_id" || return 1
    [ "$NETWORK_QUERY_VALUE" = "$owned_network_name" ] || return 1
    query_network_label "$owned_network_id" "$TRANSACTION_LABEL_KEY" || return 1
    [ "$NETWORK_QUERY_VALUE" = "$TRANSACTION_ID" ] || return 1
    query_network_label "$owned_network_id" "$ROLE_LABEL_KEY" || return 1
    [ "$NETWORK_QUERY_VALUE" = network ] || return 1
    query_network_subnets "$owned_network_id" || return 1
    printf '%s\n' "$NETWORK_QUERY_VALUE" | grep -qx "$EXPECTED_SUBNET"
}

hydrate_owned_network_id() {
    [ "$NETWORK_CREATED" = 1 ] || return 0
    if [ -n "$NETWORK_ID" ]; then
        if query_network_id "$NETWORK_ID"; then
            assert_owned_network_identity "$NETWORK_ID" "$NETWORK_NAME" \
                || die "Journaled update-host network identity is invalid"
            return 0
        fi
        NETWORK_ID=""
    fi
    find_transaction_network_id
    NETWORK_ID="$TRANSACTION_NETWORK_ID"
    [ -z "$NETWORK_ID" ] || assert_owned_network_identity "$NETWORK_ID" "$NETWORK_NAME" \
        || die "Recovered update-host network identity is invalid"
}

rollback_owned_network() {
    [ "$NETWORK_CREATED" = 1 ] || return 0
    hydrate_owned_network_id
    [ -n "$NETWORK_ID" ] || return 0
    assert_owned_network_identity "$NETWORK_ID" "$NETWORK_NAME" || return 1
    as_root docker network rm "$NETWORK_ID" >/dev/null || return 1
    if query_network_id "$NETWORK_ID"; then
        return 1
    fi
    return 0
}

create_owned_network() {
    NETWORK_NAME="$1"
    network_bridge_name="$2"
    NETWORK_CREATED=1
    NETWORK_ID=""
    persist_transaction_journal active
    network_create_status=0
    if [ -n "$network_bridge_name" ]; then
        as_root docker network create --driver bridge --subnet="$EXPECTED_SUBNET" \
            --label "${TRANSACTION_LABEL_KEY}=${TRANSACTION_ID}" \
            --label "${ROLE_LABEL_KEY}=network" \
            --opt "com.docker.network.bridge.name=${network_bridge_name}" \
            "$NETWORK_NAME" >/dev/null || network_create_status=$?
    else
        as_root docker network create --driver bridge --subnet="$EXPECTED_SUBNET" \
            --label "${TRANSACTION_LABEL_KEY}=${TRANSACTION_ID}" \
            --label "${ROLE_LABEL_KEY}=network" \
            "$NETWORK_NAME" >/dev/null || network_create_status=$?
    fi
    hydrate_owned_network_id
    [ -n "$NETWORK_ID" ] || die "Docker did not expose the newly created update-host network ID"
    persist_transaction_journal active
    [ "$network_create_status" -eq 0 ] || die "Docker reported a failed update-host network creation"
}

image_present() {
    image_query_status=0
    image_query_output="$(as_root docker image inspect "$1" 2>&1)" || image_query_status=$?
    if [ "$image_query_status" -eq 0 ]; then
        return 0
    fi
    case "$image_query_output" in
        *"No such image"*|*"No such object"*) return 1 ;;
        *) die "Docker failed while querying pinned image identity: $image_query_output" ;;
    esac
}

wait_http_ready() {
    ready_container_id="$1"
    ready_address="$2"
    assert_container_id "$ready_container_id" || return 1
    as_root docker exec "$ready_container_id" sh -c \
        "i=0; while [ \$i -lt 20 ]; do body=\$(busybox wget -q -O - 'http://$ready_address:$SYNC_PORT/$HEALTH_SENTINEL_NAME' 2>/dev/null) && [ \"\$body\" = '$HEALTH_SENTINEL_CONTENT' ] && exit 0; i=\$((i + 1)); sleep 1; done; exit 1"
}

wait_host_http_ready() {
    if [ "$PUBLISH_HOST_PORT" != "1" ]; then
        return 0
    fi
    as_root docker run --rm \
        --log-driver none \
        --network host \
        --entrypoint sh \
        "$IMAGE" \
        -c "i=0; while [ \$i -lt 20 ]; do body=\$(busybox wget -q -O - 'http://$HOST_PROBE_ADDRESS:$SYNC_PORT/$HEALTH_SENTINEL_NAME' 2>/dev/null) && [ \"\$body\" = '$HEALTH_SENTINEL_CONTENT' ] && exit 0; i=\$((i + 1)); sleep 1; done; exit 1"
}

firewall_comment() {
    firewall_comment_bind="$(printf '%s' "$1" | tr '.' '_')"
    printf 'amnezia-client-updates-%s-%s\n' "$firewall_comment_bind" "$2"
}

firewall_ufw_destination() {
    if [ "$1" = "0.0.0.0" ]; then
        printf '%s\n' any
    else
        printf '%s\n' "$1"
    fi
}

firewall_cidr_destination() {
    if [ "$1" = "0.0.0.0" ]; then
        printf '%s\n' '0.0.0.0/0'
    else
        printf '%s\n' "$1"
    fi
}

firewalld_rule() {
    firewall_rule_cidr="$(firewall_cidr_destination "$1")"
    printf 'rule family="ipv4" destination address="%s" port port="%s" protocol="tcp" accept\n' \
        "$firewall_rule_cidr" "$2"
}

firewalld_running() {
    firewalld_state_status=0
    firewalld_state_output="$(as_root firewall-cmd --state 2>&1)" || firewalld_state_status=$?
    if [ "$firewalld_state_status" -eq 0 ] && [ "$firewalld_state_output" = running ]; then
        return 0
    fi
    case "$firewalld_state_output" in
        *"not running"*) return 1 ;;
        *) die "Unable to query firewalld state: $firewalld_state_output" ;;
    esac
}

firewall_rule_present() {
    firewall_present_backend="$1"
    firewall_present_bind="$2"
    firewall_present_port="$3"
    firewall_present_comment="$(firewall_comment "$firewall_present_bind" "$firewall_present_port")"
    firewall_present_ufw_destination="$(firewall_ufw_destination "$firewall_present_bind")"
    firewall_present_cidr="$(firewall_cidr_destination "$firewall_present_bind")"
    firewall_present_rich_rule="$(firewalld_rule "$firewall_present_bind" "$firewall_present_port")"
    case "$firewall_present_backend" in
        ufw)
            firewall_query_output="$(as_root env LC_ALL=C ufw show added 2>&1)" \
                || die "Unable to query ufw rules"
            printf '%s\n' "$firewall_query_output" | grep -F -- "$firewall_present_comment" >/dev/null
            ;;
        firewalld-runtime)
            firewall_query_status=0
            as_root firewall-cmd --query-rich-rule="$firewall_present_rich_rule" >/dev/null 2>&1 \
                || firewall_query_status=$?
            case "$firewall_query_status" in 0) return 0 ;; 1) return 1 ;; *) die "Unable to query firewalld runtime rules" ;; esac
            ;;
        firewalld-permanent)
            firewall_query_status=0
            as_root firewall-cmd --permanent --query-rich-rule="$firewall_present_rich_rule" >/dev/null 2>&1 \
                || firewall_query_status=$?
            case "$firewall_query_status" in 0) return 0 ;; 1) return 1 ;; *) die "Unable to query firewalld permanent rules" ;; esac
            ;;
        iptables)
            firewall_query_status=0
            as_root iptables -C INPUT -p tcp -d "$firewall_present_cidr" \
                --dport "$firewall_present_port" -m comment --comment "$firewall_present_comment" \
                -j ACCEPT >/dev/null 2>&1 || firewall_query_status=$?
            case "$firewall_query_status" in 0) return 0 ;; 1) return 1 ;; *) die "Unable to query iptables rules" ;; esac
            ;;
        *)
            return 2
            ;;
    esac
}

firewall_add_rule() {
    firewall_add_backend="$1"
    firewall_add_bind="$2"
    firewall_add_port="$3"
    firewall_add_comment="$(firewall_comment "$firewall_add_bind" "$firewall_add_port")"
    firewall_add_ufw_destination="$(firewall_ufw_destination "$firewall_add_bind")"
    firewall_add_cidr="$(firewall_cidr_destination "$firewall_add_bind")"
    firewall_add_rich_rule="$(firewalld_rule "$firewall_add_bind" "$firewall_add_port")"
    case "$firewall_add_backend" in
        ufw)
            as_root ufw allow proto tcp to "$firewall_add_ufw_destination" port "$firewall_add_port" \
                comment "$firewall_add_comment" >/dev/null || return 1
            ;;
        firewalld-runtime)
            as_root firewall-cmd --add-rich-rule="$firewall_add_rich_rule" >/dev/null || return 1
            ;;
        firewalld-permanent)
            as_root firewall-cmd --permanent --add-rich-rule="$firewall_add_rich_rule" >/dev/null || return 1
            ;;
        iptables)
            as_root iptables -I INPUT 1 -p tcp -d "$firewall_add_cidr" \
                --dport "$firewall_add_port" -m comment --comment "$firewall_add_comment" \
                -j ACCEPT >/dev/null || return 1
            ;;
        *)
            return 2
            ;;
    esac
    firewall_rule_present "$firewall_add_backend" "$firewall_add_bind" "$firewall_add_port"
}

firewall_remove_rule() {
    firewall_remove_backend="$1"
    firewall_remove_bind="$2"
    firewall_remove_port="$3"
    firewall_remove_comment="$(firewall_comment "$firewall_remove_bind" "$firewall_remove_port")"
    firewall_remove_ufw_destination="$(firewall_ufw_destination "$firewall_remove_bind")"
    firewall_remove_cidr="$(firewall_cidr_destination "$firewall_remove_bind")"
    firewall_remove_rich_rule="$(firewalld_rule "$firewall_remove_bind" "$firewall_remove_port")"
    case "$firewall_remove_backend" in
        ufw)
            as_root ufw --force delete allow proto tcp to "$firewall_remove_ufw_destination" \
                port "$firewall_remove_port" comment "$firewall_remove_comment" >/dev/null || return 1
            ;;
        firewalld-runtime)
            as_root firewall-cmd --remove-rich-rule="$firewall_remove_rich_rule" >/dev/null || return 1
            ;;
        firewalld-permanent)
            as_root firewall-cmd --permanent --remove-rich-rule="$firewall_remove_rich_rule" >/dev/null || return 1
            ;;
        iptables)
            as_root iptables -D INPUT -p tcp -d "$firewall_remove_cidr" \
                --dport "$firewall_remove_port" -m comment --comment "$firewall_remove_comment" \
                -j ACCEPT >/dev/null || return 1
            ;;
        *)
            return 2
            ;;
    esac
    ! firewall_rule_present "$firewall_remove_backend" "$firewall_remove_bind" "$firewall_remove_port"
}

append_firewall_action() {
    firewall_action_record="$1|$2|$3|$4"
    if [ -n "$FIREWALL_ACTIONS" ]; then
        FIREWALL_ACTIONS="$FIREWALL_ACTIONS
$firewall_action_record"
    else
        FIREWALL_ACTIONS="$firewall_action_record"
    fi
    persist_transaction_journal active
}

ensure_firewall_rule() {
    firewall_ensure_backend="$1"
    firewall_ensure_bind="$2"
    firewall_ensure_port="$3"
    FIREWALL_RULE_WAS_ADDED=0
    if ! firewall_rule_present "$firewall_ensure_backend" "$firewall_ensure_bind" "$firewall_ensure_port"; then
        append_firewall_action added "$firewall_ensure_backend" "$firewall_ensure_bind" "$firewall_ensure_port"
        firewall_add_rule "$firewall_ensure_backend" "$firewall_ensure_bind" "$firewall_ensure_port" \
            || die "Unable to add owned $firewall_ensure_backend firewall rule"
        FIREWALL_RULE_WAS_ADDED=1
    fi
}

remove_owned_firewall_rule() {
    firewall_owned_backend="$1"
    firewall_owned_bind="$2"
    firewall_owned_port="$3"
    if firewall_rule_present "$firewall_owned_backend" "$firewall_owned_bind" "$firewall_owned_port"; then
        append_firewall_action removed "$firewall_owned_backend" "$firewall_owned_bind" "$firewall_owned_port"
        firewall_remove_rule "$firewall_owned_backend" "$firewall_owned_bind" "$firewall_owned_port" \
            || die "Unable to remove owned $firewall_owned_backend firewall rule"
    fi
}

load_firewall_state() {
    FIREWALL_OLD_PRESENT=0
    if ! as_root test -e "$FIREWALL_STATE_PATH" && ! as_root test -L "$FIREWALL_STATE_PATH"; then
        return 0
    fi
    as_root test -f "$FIREWALL_STATE_PATH" && ! as_root test -L "$FIREWALL_STATE_PATH" \
        || die "Firewall ownership state is not a trusted regular file"
    [ "$(as_root stat -c '%u:%g:%a' -- "$FIREWALL_STATE_PATH")" = "${TRUSTED_UID}:${TRUSTED_GID}:444" ] \
        || die "Firewall ownership state has unsafe ownership or mode"

    firewall_seen_version=0
    firewall_seen_bind=0
    firewall_seen_port=0
    firewall_seen_ufw=0
    firewall_seen_firewalld_runtime=0
    firewall_seen_firewalld_permanent=0
    firewall_seen_iptables=0
    while IFS='=' read -r firewall_key firewall_value; do
        case "$firewall_key" in
            version) [ "$firewall_seen_version" = 0 ] || die "Duplicate firewall state version"; firewall_seen_version=1; [ "$firewall_value" = "$FIREWALL_STATE_VERSION" ] || die "Unsupported firewall state version" ;;
            bind) [ "$firewall_seen_bind" = 0 ] || die "Duplicate firewall state bind"; firewall_seen_bind=1; FIREWALL_OLD_BIND="$firewall_value" ;;
            port) [ "$firewall_seen_port" = 0 ] || die "Duplicate firewall state port"; firewall_seen_port=1; FIREWALL_OLD_PORT="$firewall_value" ;;
            ufw) [ "$firewall_seen_ufw" = 0 ] || die "Duplicate firewall state ufw"; firewall_seen_ufw=1; FIREWALL_OLD_UFW="$firewall_value" ;;
            firewalld_runtime) [ "$firewall_seen_firewalld_runtime" = 0 ] || die "Duplicate firewall state runtime"; firewall_seen_firewalld_runtime=1; FIREWALL_OLD_FIREWALLD_RUNTIME="$firewall_value" ;;
            firewalld_permanent) [ "$firewall_seen_firewalld_permanent" = 0 ] || die "Duplicate firewall state permanent"; firewall_seen_firewalld_permanent=1; FIREWALL_OLD_FIREWALLD_PERMANENT="$firewall_value" ;;
            iptables) [ "$firewall_seen_iptables" = 0 ] || die "Duplicate firewall state iptables"; firewall_seen_iptables=1; FIREWALL_OLD_IPTABLES="$firewall_value" ;;
            *) die "Firewall ownership state contains an unknown field" ;;
        esac
    done <<EOF
$(as_root cat -- "$FIREWALL_STATE_PATH")
EOF
    [ "$firewall_seen_version$firewall_seen_bind$firewall_seen_port$firewall_seen_ufw$firewall_seen_firewalld_runtime$firewall_seen_firewalld_permanent$firewall_seen_iptables" = 1111111 ] \
        || die "Firewall ownership state is incomplete"
    is_ipv4_address "$FIREWALL_OLD_BIND" && is_port "$FIREWALL_OLD_PORT" \
        || die "Firewall ownership state has an invalid endpoint"
    for firewall_old_flag in "$FIREWALL_OLD_UFW" "$FIREWALL_OLD_FIREWALLD_RUNTIME" \
        "$FIREWALL_OLD_FIREWALLD_PERMANENT" "$FIREWALL_OLD_IPTABLES"; do
        case "$firewall_old_flag" in 0|1) ;; *) die "Firewall ownership state has an invalid flag" ;; esac
    done
    FIREWALL_OLD_PRESENT=1
    FIREWALL_STATE_BACKUP="${FIREWALL_STATE_PATH}.backup.${TRANSACTION_ID}"
    as_root test ! -e "$FIREWALL_STATE_BACKUP" && ! as_root test -L "$FIREWALL_STATE_BACKUP" \
        || die "Firewall ownership backup path already exists"
    as_root install -o "$TRUSTED_UID" -g "$TRUSTED_GID" -m 0444 -- \
        "$FIREWALL_STATE_PATH" "$FIREWALL_STATE_BACKUP"
    persist_transaction_journal active
}

reconcile_firewall_rules() {
    load_firewall_state
    firewall_old_same=0
    if [ "$FIREWALL_OLD_PRESENT" = 1 ] && [ "$PUBLISH_HOST_PORT" = 1 ] \
        && [ "$FIREWALL_OLD_BIND" = "$HOST_BIND" ] && [ "$FIREWALL_OLD_PORT" = "$SYNC_PORT" ]; then
        firewall_old_same=1
    fi

    if [ "$FIREWALL_OLD_PRESENT" = 1 ] && [ "$firewall_old_same" = 0 ]; then
        [ "$FIREWALL_OLD_UFW" = 0 ] || remove_owned_firewall_rule ufw "$FIREWALL_OLD_BIND" "$FIREWALL_OLD_PORT"
        if [ "$FIREWALL_OLD_FIREWALLD_RUNTIME" = 1 ] || [ "$FIREWALL_OLD_FIREWALLD_PERMANENT" = 1 ]; then
            command -v firewall-cmd >/dev/null 2>&1 && firewalld_running \
                || die "Cannot reconcile owned firewalld rules while firewalld is unavailable"
        fi
        [ "$FIREWALL_OLD_FIREWALLD_RUNTIME" = 0 ] || remove_owned_firewall_rule firewalld-runtime "$FIREWALL_OLD_BIND" "$FIREWALL_OLD_PORT"
        [ "$FIREWALL_OLD_FIREWALLD_PERMANENT" = 0 ] || remove_owned_firewall_rule firewalld-permanent "$FIREWALL_OLD_BIND" "$FIREWALL_OLD_PORT"
        [ "$FIREWALL_OLD_IPTABLES" = 0 ] || remove_owned_firewall_rule iptables "$FIREWALL_OLD_BIND" "$FIREWALL_OLD_PORT"
    fi

    if [ "$PUBLISH_HOST_PORT" = 1 ]; then
        if command -v ufw >/dev/null 2>&1; then
            ensure_firewall_rule ufw "$HOST_BIND" "$SYNC_PORT"
            if [ "$firewall_old_same" = 1 ] && [ "$FIREWALL_OLD_UFW" = 1 ] \
                || [ "$FIREWALL_RULE_WAS_ADDED" = 1 ]; then
                FIREWALL_NEW_UFW=1
            fi
        fi
        if command -v firewall-cmd >/dev/null 2>&1 && firewalld_running; then
            ensure_firewall_rule firewalld-runtime "$HOST_BIND" "$SYNC_PORT"
            if [ "$firewall_old_same" = 1 ] && [ "$FIREWALL_OLD_FIREWALLD_RUNTIME" = 1 ] \
                || [ "$FIREWALL_RULE_WAS_ADDED" = 1 ]; then
                FIREWALL_NEW_FIREWALLD_RUNTIME=1
            fi
            ensure_firewall_rule firewalld-permanent "$HOST_BIND" "$SYNC_PORT"
            if [ "$firewall_old_same" = 1 ] && [ "$FIREWALL_OLD_FIREWALLD_PERMANENT" = 1 ] \
                || [ "$FIREWALL_RULE_WAS_ADDED" = 1 ]; then
                FIREWALL_NEW_FIREWALLD_PERMANENT=1
            fi
        elif [ "$firewall_old_same" = 1 ]; then
            FIREWALL_NEW_FIREWALLD_RUNTIME="$FIREWALL_OLD_FIREWALLD_RUNTIME"
            FIREWALL_NEW_FIREWALLD_PERMANENT="$FIREWALL_OLD_FIREWALLD_PERMANENT"
        fi
        if command -v iptables >/dev/null 2>&1; then
            ensure_firewall_rule iptables "$HOST_BIND" "$SYNC_PORT"
            if [ "$firewall_old_same" = 1 ] && [ "$FIREWALL_OLD_IPTABLES" = 1 ] \
                || [ "$FIREWALL_RULE_WAS_ADDED" = 1 ]; then
                FIREWALL_NEW_IPTABLES=1
            fi
        fi
    fi
}

switch_firewall_state() {
    FIREWALL_STATE_SWITCH_ATTEMPTED=1
    persist_transaction_journal active
    if [ "$PUBLISH_HOST_PORT" = 1 ]; then
        FIREWALL_STATE_TMP="${FIREWALL_STATE_PATH}.candidate.${TRANSACTION_ID}"
        as_root test ! -e "$FIREWALL_STATE_TMP" && ! as_root test -L "$FIREWALL_STATE_TMP" \
            || die "Firewall ownership staging path already exists"
        as_root install -o "$TRUSTED_UID" -g "$TRUSTED_GID" -m 0600 /dev/null "$FIREWALL_STATE_TMP"
        {
            printf 'version=%s\n' "$FIREWALL_STATE_VERSION"
            printf 'bind=%s\n' "$HOST_BIND"
            printf 'port=%s\n' "$SYNC_PORT"
            printf 'ufw=%s\n' "$FIREWALL_NEW_UFW"
            printf 'firewalld_runtime=%s\n' "$FIREWALL_NEW_FIREWALLD_RUNTIME"
            printf 'firewalld_permanent=%s\n' "$FIREWALL_NEW_FIREWALLD_PERMANENT"
            printf 'iptables=%s\n' "$FIREWALL_NEW_IPTABLES"
        } | as_root tee -- "$FIREWALL_STATE_TMP" >/dev/null
        as_root chmod 0444 -- "$FIREWALL_STATE_TMP"
        as_root sync -f -- "$FIREWALL_STATE_TMP"
        as_root mv -fT -- "$FIREWALL_STATE_TMP" "$FIREWALL_STATE_PATH"
        FIREWALL_STATE_TMP=""
    else
        as_root rm -f -- "$FIREWALL_STATE_PATH"
    fi
    as_root sync -f -- "$LOCK_PARENT"
}

rollback_firewall() {
    firewall_rollback_failed=0
    while IFS='|' read -r firewall_action firewall_backend firewall_bind firewall_port; do
        [ -n "$firewall_action" ] || continue
        if [ "$firewall_action" = added ] && firewall_rule_present "$firewall_backend" "$firewall_bind" "$firewall_port"; then
            firewall_remove_rule "$firewall_backend" "$firewall_bind" "$firewall_port" \
                || firewall_rollback_failed=1
        fi
    done <<EOF
$FIREWALL_ACTIONS
EOF
    while IFS='|' read -r firewall_action firewall_backend firewall_bind firewall_port; do
        [ -n "$firewall_action" ] || continue
        if [ "$firewall_action" = removed ] && ! firewall_rule_present "$firewall_backend" "$firewall_bind" "$firewall_port"; then
            firewall_add_rule "$firewall_backend" "$firewall_bind" "$firewall_port" \
                || firewall_rollback_failed=1
        fi
    done <<EOF
$FIREWALL_ACTIONS
EOF

    if [ "$FIREWALL_STATE_SWITCH_ATTEMPTED" = 1 ]; then
        if [ "$FIREWALL_OLD_PRESENT" = 1 ]; then
            if as_root test -f "$FIREWALL_STATE_BACKUP" && ! as_root test -L "$FIREWALL_STATE_BACKUP"; then
                as_root mv -fT -- "$FIREWALL_STATE_BACKUP" "$FIREWALL_STATE_PATH" \
                    || firewall_rollback_failed=1
            else
                firewall_rollback_failed=1
            fi
        else
            as_root rm -f -- "$FIREWALL_STATE_PATH" || firewall_rollback_failed=1
        fi
        as_root sync -f -- "$LOCK_PARENT" || firewall_rollback_failed=1
    fi
    [ -z "$FIREWALL_STATE_TMP" ] \
        || as_root rm -f -- "$FIREWALL_STATE_TMP" >/dev/null 2>&1 \
        || firewall_rollback_failed=1
    [ -z "$FIREWALL_STATE_BACKUP" ] \
        || as_root rm -f -- "$FIREWALL_STATE_BACKUP" >/dev/null 2>&1 \
        || firewall_rollback_failed=1
    [ "$firewall_rollback_failed" -eq 0 ]
}

finalize_firewall_state() {
    [ -z "$FIREWALL_STATE_TMP" ] || as_root rm -f -- "$FIREWALL_STATE_TMP" || return 1
    [ -z "$FIREWALL_STATE_BACKUP" ] || as_root rm -f -- "$FIREWALL_STATE_BACKUP" || return 1
    return 0
}

append_backup_record() {
    backup_record="$1|$2|$3|$4|$5|$6|$7"
    if [ -n "$BACKUP_RECORDS" ]; then
        BACKUP_RECORDS="$BACKUP_RECORDS
$backup_record"
    else
        BACKUP_RECORDS="$backup_record"
    fi
    persist_transaction_journal active
}

append_new_container_record() {
    new_container_record="$1|$2|$3"
    if [ -n "$NEW_CONTAINER_RECORDS" ]; then
        NEW_CONTAINER_RECORDS="$NEW_CONTAINER_RECORDS
$new_container_record"
    else
        NEW_CONTAINER_RECORDS="$new_container_record"
    fi
}

append_new_intent_record() {
    new_intent_record="$1|$2|$3"
    if [ -n "$NEW_INTENT_RECORDS" ]; then
        NEW_INTENT_RECORDS="$NEW_INTENT_RECORDS
$new_intent_record"
    else
        NEW_INTENT_RECORDS="$new_intent_record"
    fi
    persist_transaction_journal active
}

TRANSACTION_CONTAINER_ID=""

find_transaction_container_id() {
    transaction_role="$1"
    TRANSACTION_CONTAINER_ID=""
    transaction_ids="$(as_root docker ps -aq --no-trunc \
        --filter "label=${TRANSACTION_LABEL_KEY}=${TRANSACTION_ID}" \
        --filter "label=${ROLE_LABEL_KEY}=${transaction_role}")" \
        || die "Docker failed while resolving transaction role $transaction_role"
    set -- $transaction_ids
    [ "$#" -le 1 ] || die "Transaction labels resolve to multiple $transaction_role containers"
    [ "$#" -eq 0 ] || TRANSACTION_CONTAINER_ID="$1"
}

register_created_container() {
    register_cidfile="$1"
    register_name="$2"
    register_role="$3"
    register_run_status="$4"
    REGISTERED_CONTAINER_ID=""
    if as_root test -f "$register_cidfile" && ! as_root test -L "$register_cidfile"; then
        REGISTERED_CONTAINER_ID="$(as_root cat -- "$register_cidfile")" \
            || die "Unable to read Docker cidfile for $register_role"
    fi
    if [ -z "$REGISTERED_CONTAINER_ID" ]; then
        find_transaction_container_id "$register_role"
        REGISTERED_CONTAINER_ID="$TRANSACTION_CONTAINER_ID"
    fi
    if [ -n "$REGISTERED_CONTAINER_ID" ]; then
        assert_transaction_container_identity "$REGISTERED_CONTAINER_ID" "$register_role" \
            || die "Replacement $register_role container identity is invalid"
        append_new_container_record "$REGISTERED_CONTAINER_ID" "$register_name" "$register_role"
        assert_name_maps_to_id "$register_name" "$REGISTERED_CONTAINER_ID" \
            || die "Replacement $register_role container name does not map to its immutable ID"
    fi
    [ "$register_run_status" -eq 0 ] || die "Unable to create replacement $register_role container"
    [ -n "$REGISTERED_CONTAINER_ID" ] || die "Docker did not record the replacement $register_role container ID"
}

backup_container() {
    original_name="$1"
    disconnect_network="$2"
    prior_health_address="$3"
    backup_name="${original_name}.amnezia-backup.${TRANSACTION_ID}"
    container_exists "$backup_name" && die "Transactional backup container already exists: $backup_name"
    query_container_id "$original_name" \
        || die "Unable to resolve immutable container ID for $original_name"
    original_id="$CONTAINER_QUERY_VALUE"
    assert_name_maps_to_id "$original_name" "$original_id" \
        || die "Container identity changed before backup: $original_name"
    query_container_running "$original_id" \
        || die "Unable to determine prior running state for $original_name"
    prior_running="$CONTAINER_QUERY_VALUE"
    prior_ip=""
    if [ -n "$disconnect_network" ]; then
        query_container_network_ip "$original_id" "$disconnect_network" \
            || die "Unable to inspect prior network identity for $original_name"
        prior_ip="$CONTAINER_QUERY_VALUE"
    fi

    # Record intent first: Docker may complete a mutation and still return an error.
    append_backup_record "$original_name" "$backup_name" "$original_id" "$prior_running" \
        "$disconnect_network" "$prior_ip" "$prior_health_address"
    backup_mutation_status=0
    as_root docker rename "$original_id" "$backup_name" || backup_mutation_status=$?
    assert_name_maps_to_id "$backup_name" "$original_id" \
        || die "Container identity changed while renaming backup: $original_name"
    [ "$backup_mutation_status" -eq 0 ] || die "Docker reported a failed backup rename for $original_name"
    if [ "$prior_running" = "true" ]; then
        assert_name_maps_to_id "$backup_name" "$original_id" \
            || die "Container identity changed before stop: $original_name"
        as_root docker stop "$original_id" >/dev/null
        assert_name_maps_to_id "$backup_name" "$original_id" \
            || die "Container identity changed after stop: $original_name"
    fi
    if [ -n "$disconnect_network" ] && [ -n "$prior_ip" ]; then
        assert_name_maps_to_id "$backup_name" "$original_id" \
            || die "Container identity changed before network disconnect: $original_name"
        as_root docker network disconnect "$disconnect_network" "$original_id"
        assert_name_maps_to_id "$backup_name" "$original_id" \
            || die "Container identity changed after network disconnect: $original_name"
    fi
    printf 'backed_up_container=%s container_id=%s prior_running=%s\n' \
        "$original_name" "$original_id" "$prior_running"
}

remove_new_container_by_id() {
    remove_id="$1"
    remove_name="$2"
    remove_role="$3"
    if assert_container_id "$remove_id"; then
        assert_transaction_container_identity "$remove_id" "$remove_role" || return 1
        as_root docker rm -f "$remove_id" >/dev/null || return 1
        assert_container_id "$remove_id" && return 1
    else
        remove_name_id=""
        if query_container_id "$remove_name"; then
            remove_name_id="$CONTAINER_QUERY_VALUE"
        fi
        [ -z "$remove_name_id" ] || [ "$remove_name_id" != "$remove_id" ] || return 1
    fi
    return 0
}

restore_running_state() {
    restore_id="$1"
    restore_name="$2"
    expected_running="$3"
    restore_health_address="$4"
    assert_name_maps_to_id "$restore_name" "$restore_id" || return 1
    actual_running=""
    if query_container_running "$restore_id"; then
        actual_running="$CONTAINER_QUERY_VALUE"
    else
        return 1
    fi
    if [ "$expected_running" = "true" ]; then
        if [ "$actual_running" != "true" ]; then
            assert_name_maps_to_id "$restore_name" "$restore_id" || return 1
            as_root docker start "$restore_id" >/dev/null || return 1
        fi
        assert_name_maps_to_id "$restore_name" "$restore_id" || return 1
        wait_http_ready "$restore_id" "$restore_health_address" || return 1
    elif [ "$expected_running" = "false" ]; then
        if [ "$actual_running" = "true" ]; then
            assert_name_maps_to_id "$restore_name" "$restore_id" || return 1
            as_root docker stop "$restore_id" >/dev/null || return 1
        fi
    else
        return 1
    fi
}

rollback_transaction() {
    set +e
    rollback_failed=0
    rollback_firewall || rollback_failed=1
    while IFS='|' read -r new_id new_name new_role; do
        [ -n "$new_id" ] || continue
        remove_new_container_by_id "$new_id" "$new_name" "$new_role" || rollback_failed=1
    done <<EOF
$NEW_CONTAINER_RECORDS
EOF

    while IFS='|' read -r original_name backup_name original_id prior_running prior_network prior_ip prior_health_address; do
        [ -n "$original_name" ] || continue
        if assert_container_id "$original_id"; then
            query_container_name "$original_id" || {
                rollback_failed=1
                continue
            }
            rollback_current_name="$CONTAINER_QUERY_VALUE"
            if [ "$rollback_current_name" = "$backup_name" ]; then
                rollback_original_occupant=""
                if query_container_id "$original_name"; then
                    rollback_original_occupant="$CONTAINER_QUERY_VALUE"
                fi
                if [ -n "$rollback_original_occupant" ]; then
                    printf 'Rollback name collision for %s: expected %s, found %s\n' \
                        "$original_name" "$original_id" "$rollback_original_occupant" >&2
                    rollback_failed=1
                    continue
                fi
            elif [ "$rollback_current_name" != "$original_name" ]; then
                printf 'Rollback immutable ID %s has unexpected name %s\n' \
                    "$original_id" "$rollback_current_name" >&2
                rollback_failed=1
                continue
            fi
            if [ "$rollback_current_name" = "$backup_name" ] && [ -n "$prior_network" ] && [ -n "$prior_ip" ]; then
                assert_name_maps_to_id "$backup_name" "$original_id" || {
                    rollback_failed=1
                    continue
                }
                query_container_network_ip "$original_id" "$prior_network" || {
                    rollback_failed=1
                    continue
                }
                current_ip="$CONTAINER_QUERY_VALUE"
                if [ -z "$current_ip" ]; then
                    as_root docker network connect --ip "$prior_ip" "$prior_network" "$original_id" \
                        || rollback_failed=1
                elif [ "$current_ip" != "$prior_ip" ]; then
                    printf 'Rollback network identity mismatch for %s\n' "$original_name" >&2
                    rollback_failed=1
                fi
            fi
            if [ "$rollback_current_name" = "$backup_name" ]; then
                assert_name_maps_to_id "$backup_name" "$original_id" || {
                    rollback_failed=1
                    continue
                }
                as_root docker rename "$original_id" "$original_name" || rollback_failed=1
            fi
            if ! assert_name_maps_to_id "$original_name" "$original_id"; then
                printf 'Rollback name collision for %s\n' "$original_name" >&2
                rollback_failed=1
                continue
            fi
        else
            printf 'Rollback lost immutable container ID %s for %s\n' "$original_id" "$original_name" >&2
            rollback_failed=1
            continue
        fi
        restore_running_state "$original_id" "$original_name" "$prior_running" "$prior_health_address" \
            || rollback_failed=1
    done <<EOF
$BACKUP_RECORDS
EOF

    rollback_owned_network || rollback_failed=1

    [ "$rollback_failed" -eq 0 ]
}

finish_installer() {
    installer_status=$?
    trap - EXIT HUP INT TERM
    if [ "$installer_status" -ne 0 ] && [ "$TRANSACTION_STARTED" = "1" ] \
        && [ "$TRANSACTION_COMMITTED" = "0" ]; then
        if rollback_transaction; then
            rollback_postconditions_ok=1
            if [ "$HEALTH_SENTINEL_CREATED" = 1 ]; then
                remove_health_sentinel || rollback_postconditions_ok=0
            fi
            cleanup_transaction_cidfiles || rollback_postconditions_ok=0
            clear_transaction_journal || rollback_postconditions_ok=0
            if [ "$rollback_postconditions_ok" = 1 ]; then
                TRANSACTION_STARTED=0
                printf '%s\n' 'Previous update host containers restored after installer failure' >&2
            else
                printf '%s\n' 'CRITICAL: update host rollback completed but durable cleanup was incomplete' >&2
            fi
        else
            printf '%s\n' 'CRITICAL: update host container rollback was incomplete' >&2
        fi
    fi
    if [ "$HEALTH_SENTINEL_CREATED" = 1 ]; then
        as_root rm -f -- "$HEALTH_SENTINEL_PATH" >/dev/null 2>&1 || true
    fi
    [ -z "$FIREWALL_STATE_TMP" ] || as_root rm -f -- "$FIREWALL_STATE_TMP" >/dev/null 2>&1 || true
    if [ "$TRANSACTION_COMMITTED" = 1 ]; then
        [ -z "$FIREWALL_STATE_BACKUP" ] || as_root rm -f -- "$FIREWALL_STATE_BACKUP" >/dev/null 2>&1 || true
    fi
    flock -u 9 >/dev/null 2>&1 || true
    exec 9<&-
    exit "$installer_status"
}

cleanup_backups() {
    cleanup_failed=0
    while IFS='|' read -r _original_name backup_name original_id _prior_running _prior_network _prior_ip _prior_health_address; do
        [ -n "$backup_name" ] || continue
        cleanup_attempt=0
        while assert_container_id "$original_id" && [ "$cleanup_attempt" -lt 3 ]; do
            assert_name_maps_to_id "$backup_name" "$original_id" || {
                cleanup_failed=1
                break
            }
            cleanup_attempt=$((cleanup_attempt + 1))
            as_root docker rm "$original_id" >/dev/null 2>&1 || true
        done
        if assert_container_id "$original_id"; then
            cleanup_failed=1
        else
            cleanup_name_occupant=""
            if query_container_id "$backup_name"; then
                cleanup_name_occupant="$CONTAINER_QUERY_VALUE"
            fi
            [ -z "$cleanup_name_occupant" ] || cleanup_failed=1
        fi
    done <<EOF
$BACKUP_RECORDS
EOF
    [ "$cleanup_failed" -eq 0 ]
}

create_or_verify_health_sentinel() {
    expected_sentinel_sha="$(printf '%s' "$HEALTH_SENTINEL_CONTENT" | sha256sum | awk '{print $1}')"
    if as_root test -e "$HEALTH_SENTINEL_PATH" || as_root test -L "$HEALTH_SENTINEL_PATH"; then
        as_root test -f "$HEALTH_SENTINEL_PATH" && ! as_root test -L "$HEALTH_SENTINEL_PATH" \
            || die "Update-host health sentinel is not a regular file"
        [ "$(as_root stat -c '%u:%g:%a' -- "$HEALTH_SENTINEL_PATH")" = "${TRUSTED_UID}:${TRUSTED_GID}:444" ] \
            || die "Update-host health sentinel has unsafe ownership or mode"
        [ "$(as_root sha256sum -- "$HEALTH_SENTINEL_PATH" | awk '{print $1}')" = "$expected_sentinel_sha" ] \
            || die "Update-host health sentinel hash mismatch"
    else
        as_root install -o "$TRUSTED_UID" -g "$TRUSTED_GID" -m 0600 /dev/null "$HEALTH_SENTINEL_PATH"
        printf '%s' "$HEALTH_SENTINEL_CONTENT" | as_root tee -- "$HEALTH_SENTINEL_PATH" >/dev/null
        as_root chmod 0444 -- "$HEALTH_SENTINEL_PATH"
        [ "$(as_root sha256sum -- "$HEALTH_SENTINEL_PATH" | awk '{print $1}')" = "$expected_sentinel_sha" ] \
            || die "Update-host health sentinel hash mismatch"
    fi
    HEALTH_SENTINEL_CREATED=1
    as_root sync -f -- "$HEALTH_SENTINEL_PATH"
    as_root sync -f -- "$HOST_DIRECTORY"
}

remove_health_sentinel() {
    if as_root test -e "$HEALTH_SENTINEL_PATH" || as_root test -L "$HEALTH_SENTINEL_PATH"; then
        as_root test -f "$HEALTH_SENTINEL_PATH" && ! as_root test -L "$HEALTH_SENTINEL_PATH" \
            || return 1
        as_root rm -f -- "$HEALTH_SENTINEL_PATH" || return 1
    fi
    as_root test ! -e "$HEALTH_SENTINEL_PATH" && ! as_root test -L "$HEALTH_SENTINEL_PATH" \
        || return 1
    HEALTH_SENTINEL_CREATED=0
    as_root sync -f -- "$HOST_DIRECTORY" || return 1
}

recover_health_sentinel_for_rollback() {
    if [ "$HEALTH_SENTINEL_INTENT" = 0 ]; then
        as_root test ! -e "$HEALTH_SENTINEL_PATH" && ! as_root test -L "$HEALTH_SENTINEL_PATH" \
            || die "Unexpected health sentinel exists without journaled intent"
        HEALTH_SENTINEL_CREATED=0
        return 0
    fi
    if as_root test -e "$HEALTH_SENTINEL_PATH" || as_root test -L "$HEALTH_SENTINEL_PATH"; then
        create_or_verify_health_sentinel
        return 0
    fi
    if [ "$HEALTH_SENTINEL_CREATED" = 1 ] || [ -n "$BACKUP_RECORDS" ]; then
        create_or_verify_health_sentinel
    else
        HEALTH_SENTINEL_CREATED=0
    fi
}

hydrate_new_container_records() {
    hydrate_require_present="$1"
    NEW_CONTAINER_RECORDS=""
    while IFS='|' read -r intent_name intent_role intent_cidfile; do
        [ -n "$intent_name" ] || continue
        is_container_name "$intent_name" || die "Transaction journal has an invalid replacement name"
        case "$intent_role" in bridge|host|tunnel-*) ;; *) die "Transaction journal has an invalid replacement role" ;; esac
        case "$intent_cidfile" in
            "${CID_PARENT}/${TRANSACTION_ID}."*.cid) ;;
            *) die "Transaction journal has an invalid cidfile path" ;;
        esac
        hydrated_cidfile_id=""
        if as_root test -e "$intent_cidfile" || as_root test -L "$intent_cidfile"; then
            as_root test -f "$intent_cidfile" && ! as_root test -L "$intent_cidfile" \
                || die "Transaction cidfile is not a regular file"
            hydrated_cidfile_id="$(as_root cat -- "$intent_cidfile")" \
                || die "Unable to read transaction cidfile"
            if [ -n "$hydrated_cidfile_id" ] && ! assert_container_id "$hydrated_cidfile_id"; then
                hydrated_cidfile_id=""
            fi
        fi
        find_transaction_container_id "$intent_role"
        hydrated_label_id="$TRANSACTION_CONTAINER_ID"
        if [ -n "$hydrated_cidfile_id" ] && [ -n "$hydrated_label_id" ] \
            && [ "$hydrated_cidfile_id" != "$hydrated_label_id" ]; then
            die "Transaction cidfile and labels disagree about replacement identity"
        fi
        hydrated_id="${hydrated_cidfile_id:-$hydrated_label_id}"
        if [ -n "$hydrated_id" ]; then
            assert_transaction_container_identity "$hydrated_id" "$intent_role" \
                || die "Recovered replacement container identity is invalid"
            append_new_container_record "$hydrated_id" "$intent_name" "$intent_role"
            if [ "$hydrate_require_present" = 1 ]; then
                assert_name_maps_to_id "$intent_name" "$hydrated_id" \
                    || die "Committed replacement container name no longer maps to its immutable ID"
                is_running_container "$hydrated_id" \
                    || die "Committed replacement container is no longer running"
            fi
        elif [ "$hydrate_require_present" = 1 ]; then
            die "Committed replacement container is missing"
        fi
    done <<EOF
$NEW_INTENT_RECORDS
EOF
}

cleanup_transaction_cidfiles() {
    cid_cleanup_failed=0
    while IFS='|' read -r _intent_name _intent_role intent_cidfile; do
        [ -n "$intent_cidfile" ] || continue
        case "$intent_cidfile" in
            "${CID_PARENT}/${TRANSACTION_ID}."*.cid)
                as_root rm -f -- "$intent_cidfile" || cid_cleanup_failed=1
                ;;
            *)
                cid_cleanup_failed=1
                ;;
        esac
    done <<EOF
$NEW_INTENT_RECORDS
EOF
    [ "$cid_cleanup_failed" -eq 0 ]
}

reset_transaction_state_after_recovery() {
    TRANSACTION_ID=""
    TRANSACTION_STARTED=0
    TRANSACTION_COMMITTED=0
    BACKUP_RECORDS=""
    NEW_INTENT_RECORDS=""
    NEW_CONTAINER_RECORDS=""
    FIREWALL_ACTIONS=""
    FIREWALL_STATE_BACKUP=""
    FIREWALL_STATE_TMP=""
    FIREWALL_STATE_SWITCH_ATTEMPTED=0
    FIREWALL_OLD_PRESENT=0
    FIREWALL_OLD_BIND=""
    FIREWALL_OLD_PORT=""
    FIREWALL_OLD_UFW=0
    FIREWALL_OLD_FIREWALLD_RUNTIME=0
    FIREWALL_OLD_FIREWALLD_PERMANENT=0
    FIREWALL_OLD_IPTABLES=0
    NETWORK_NAME=""
    NETWORK_CREATED=0
    NETWORK_ID=""
    HEALTH_SENTINEL_PATH=""
    HEALTH_SENTINEL_NAME=""
    HEALTH_SENTINEL_CONTENT=""
    HEALTH_SENTINEL_INTENT=0
    HEALTH_SENTINEL_CREATED=0
}

recover_incomplete_transaction() {
    if ! as_root test -e "$JOURNAL_PATH" && ! as_root test -L "$JOURNAL_PATH"; then
        return 0
    fi
    load_transaction_journal
    if [ "$JOURNAL_PHASE" = committed_pending_cleanup ]; then
        TRANSACTION_COMMITTED=1
        hydrate_new_container_records 1
        cleanup_backups || die "Committed update-host recovery could not remove transactional backups"
        cleanup_transaction_cidfiles || die "Committed update-host recovery could not remove cidfiles"
        if [ "$HEALTH_SENTINEL_INTENT" = 1 ] \
            && { as_root test -e "$HEALTH_SENTINEL_PATH" || as_root test -L "$HEALTH_SENTINEL_PATH"; }; then
            create_or_verify_health_sentinel
            remove_health_sentinel || die "Committed update-host recovery could not remove health sentinel"
        fi
        finalize_firewall_state || die "Committed update-host recovery could not finalize firewall state"
        clear_transaction_journal \
            || die "Committed update-host recovery could not clear durable transaction journal"
        printf '%s\n' 'Recovered committed update-host transaction and completed cleanup'
        exit 0
    fi

    hydrate_new_container_records 0
    recover_health_sentinel_for_rollback
    if rollback_transaction; then
        remove_health_sentinel || die "Recovered rollback could not remove health sentinel"
        cleanup_transaction_cidfiles || die "Recovered rollback could not remove cidfiles"
        clear_transaction_journal \
            || die "Recovered rollback could not clear durable transaction journal"
        printf '%s\n' 'Recovered and rolled back incomplete update-host transaction' >&2
        reset_transaction_state_after_recovery
        exit 0
    else
        TRANSACTION_STARTED=0
        die "CRITICAL: durable update-host transaction recovery was incomplete"
    fi
}

[ -n "$HOST_DIRECTORY" ] || die "HOST_DIRECTORY must not be empty"
case "$HOST_DIRECTORY" in
    /*) ;;
    *) die "HOST_DIRECTORY must be an absolute path" ;;
esac
is_container_name "$CONTAINER_NAME" || die "AMNEZIA_UPDATE_CONTAINER_NAME is invalid"
is_container_name "$HOST_CONTAINER_NAME" || die "AMNEZIA_UPDATE_HOST_CONTAINER_NAME is invalid"
[ "$HOST_CONTAINER_NAME" != "$CONTAINER_NAME" ] || die "Update host container names must be distinct"
case "$HOST_CONTAINER_NAME" in
    "${CONTAINER_NAME}-vpn-"*) die "Host container name must not overlap the VPN sidecar namespace" ;;
esac
is_ipv4_address "$BRIDGE_HOST" || die "AMNEZIA_UPDATE_BRIDGE_HOST must be a single IPv4 address, not a CIDR route"
is_ipv4_address "$HOST_BIND" || die "AMNEZIA_UPDATE_HOST_BIND must be a single IPv4 address"
is_port "$SYNC_PORT" || die "AMNEZIA_UPDATE_SYNC_PORT must be an integer from 1 to 65535"
case "$PUBLISH_HOST_PORT" in
    0|1) ;;
    *) die "AMNEZIA_UPDATE_PUBLISH_HOST_PORT must be 0 or 1" ;;
esac
if [ -n "$VPN_CONTAINER" ]; then
    is_container_name "$VPN_CONTAINER" || die "AMNEZIA_UPDATE_VPN_CONTAINER is invalid"
fi
for required_tool in awk cat chmod date flock grep install ln mv od sha256sum stat sync tee tr; do
    command -v "$required_tool" >/dev/null 2>&1 || die "Required installer tool is missing: $required_tool"
done
printf '%s' "$HOST_DIRECTORY" | grep -q '[|[:cntrl:]]' \
    && die "HOST_DIRECTORY contains a journal-unsafe character"

as_root true || die "Passwordless noninteractive sudo is required"
prepare_installer_lock
trap finish_installer EXIT
trap 'exit 74' HUP INT TERM

if ! as_root test -e "$CID_PARENT" && ! as_root test -L "$CID_PARENT"; then
    as_root install -d -o "$TRUSTED_UID" -g "$TRUSTED_GID" -m 0755 -- "$CID_PARENT"
fi
require_trusted_directory "$CID_PARENT" "installer cidfile directory"

if [ "$HOST_BIND" = "0.0.0.0" ]; then
    HOST_PROBE_ADDRESS="127.0.0.1"
else
    HOST_PROBE_ADDRESS="$HOST_BIND"
fi
recover_incomplete_transaction

TRANSACTION_ID="$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')"
case "$TRANSACTION_ID" in
    ""|*[!0-9a-f]*) die "Unable to generate installer transaction identity" ;;
esac
[ "${#TRANSACTION_ID}" -eq 48 ] || die "Installer transaction identity has unexpected length"

# Preflight all immutable inputs and candidate runtime before touching a live endpoint.
as_root mkdir -p "$HOST_DIRECTORY/files"
if ! image_present "$IMAGE"; then
    as_root docker pull "$IMAGE" >/dev/null
fi
image_present "$IMAGE" \
    || die "Pinned update image identity verification failed"
as_root docker run --rm --log-driver none --entrypoint sh "$IMAGE" \
    -c "busybox --list | busybox grep -qx httpd" >/dev/null \
    || die "Pinned update image candidate preflight failed"

HEALTH_SENTINEL_NAME="amnezia-update-health-${TRANSACTION_ID}"
HEALTH_SENTINEL_PATH="${HOST_DIRECTORY}/${HEALTH_SENTINEL_NAME}"
HEALTH_SENTINEL_CONTENT="amnezia-update-health-v1:${TRANSACTION_ID}"
TRANSACTION_STARTED=1
persist_transaction_journal active
HEALTH_SENTINEL_INTENT=1
persist_transaction_journal active
create_or_verify_health_sentinel
persist_transaction_journal active

VPN_CONTAINER_EXPLICIT=0
if [ -n "$VPN_CONTAINER" ]; then
    VPN_CONTAINER_EXPLICIT=1
    is_running_container "$VPN_CONTAINER" \
        || die "AMNEZIA_UPDATE_VPN_CONTAINER must name a running VPN container"
    query_container_id "$VPN_CONTAINER" \
        || die "Unable to resolve explicit VPN container identity"
    vpn_id="$CONTAINER_QUERY_VALUE"
    assert_name_maps_to_id "$VPN_CONTAINER" "$vpn_id" \
        || die "Explicit VPN container identity changed during discovery"
    VPN_RECORDS="$VPN_CONTAINER|$vpn_id"
else
    for candidate in $AUTO_VPN_CONTAINERS; do
        if is_running_container "$candidate"; then
            query_container_id "$candidate" \
                || die "Unable to resolve VPN container identity: $candidate"
            candidate_id="$CONTAINER_QUERY_VALUE"
            assert_name_maps_to_id "$candidate" "$candidate_id" \
                || die "VPN container identity changed during discovery: $candidate"
            if [ -n "$VPN_RECORDS" ]; then
                VPN_RECORDS="$VPN_RECORDS
$candidate|$candidate_id"
            else
                VPN_RECORDS="$candidate|$candidate_id"
            fi
        fi
    done
fi

NETWORK_NAME="amnezia-dns-net"
if query_network_id "$NETWORK_NAME"; then
    query_network_subnets "$NETWORK_NAME" || die "Unable to inspect update-host network subnet"
    NETWORK_SUBNETS="$NETWORK_QUERY_VALUE"
    if ! printf '%s\n' "$NETWORK_SUBNETS" | grep -qx "$EXPECTED_SUBNET"; then
        NETWORK_NAME="${CONTAINER_NAME}-net"
        if query_network_id "$NETWORK_NAME"; then
            query_network_subnets "$NETWORK_NAME" || die "Unable to inspect fallback update-host network subnet"
            printf '%s\n' "$NETWORK_QUERY_VALUE" | grep -qx "$EXPECTED_SUBNET" \
                || die "Fallback update-host network has an unexpected subnet"
        else
            create_owned_network "$NETWORK_NAME" ""
        fi
    fi
else
    create_owned_network "$NETWORK_NAME" amn0
fi

ALL_CONTAINER_NAMES="$(as_root docker ps -a --format '{{.Names}}')"
for existing_name in $ALL_CONTAINER_NAMES; do
    case "$existing_name" in
        "${CONTAINER_NAME}.amnezia-backup."*|"${HOST_CONTAINER_NAME}.amnezia-backup."*|"${CONTAINER_NAME}-vpn-"*.amnezia-backup.*)
            die "Stale transactional update-host backup requires operator recovery: $existing_name"
            ;;
    esac
done

PRIOR_SIDECARS=""
while IFS='|' read -r vpn_name vpn_id; do
    [ -n "$vpn_name" ] || continue
    tunnel_name="${CONTAINER_NAME}-vpn-${vpn_name}"
    is_container_name "$tunnel_name" || die "Derived update VPN sidecar name is invalid"
    [ "$tunnel_name" != "$HOST_CONTAINER_NAME" ] \
        || die "Derived update VPN sidecar conflicts with host container name"
    if container_exists "$tunnel_name"; then
        if [ -n "$PRIOR_SIDECARS" ]; then
            PRIOR_SIDECARS="$PRIOR_SIDECARS $tunnel_name"
        else
            PRIOR_SIDECARS="$tunnel_name"
        fi
    fi
done <<EOF
$VPN_RECORDS
EOF

if container_exists "$CONTAINER_NAME"; then
    backup_container "$CONTAINER_NAME" "$NETWORK_NAME" "127.0.0.1"
fi
if container_exists "$HOST_CONTAINER_NAME"; then
    backup_container "$HOST_CONTAINER_NAME" "" "$HOST_PROBE_ADDRESS"
fi
for prior_sidecar in $PRIOR_SIDECARS; do
    backup_container "$prior_sidecar" "" "127.0.0.1"
done

main_cidfile="${CID_PARENT}/${TRANSACTION_ID}.bridge.cid"
append_new_intent_record "$CONTAINER_NAME" bridge "$main_cidfile"
main_run_status=0
as_root docker run -d \
    --cidfile "$main_cidfile" \
    --label "${TRANSACTION_LABEL_KEY}=${TRANSACTION_ID}" \
    --label "${ROLE_LABEL_KEY}=bridge" \
    --label "${BIND_LABEL_KEY}=${HOST_BIND}" \
    --label "${PROBE_LABEL_KEY}=${HOST_PROBE_ADDRESS}" \
    --label "${PORT_LABEL_KEY}=${SYNC_PORT}" \
    --log-driver none \
    --restart always \
    --network "$NETWORK_NAME" \
    --ip "$BRIDGE_HOST" \
    --name "$CONTAINER_NAME" \
    -v "$HOST_DIRECTORY:/www:ro" \
    --entrypoint sh \
    "$IMAGE" \
    -c "busybox httpd -f -p $SYNC_PORT -h /www" >/dev/null || main_run_status=$?
register_created_container "$main_cidfile" "$CONTAINER_NAME" bridge "$main_run_status"
NEW_MAIN_ID="$REGISTERED_CONTAINER_ID"

while IFS='|' read -r vpn_name vpn_id; do
    [ -n "$vpn_name" ] || continue
    assert_name_maps_to_id "$vpn_name" "$vpn_id" \
        || die "VPN container identity changed before sidecar creation: $vpn_name"
    is_running_container "$vpn_id" || die "VPN container stopped before sidecar creation: $vpn_name"
    tunnel_name="${CONTAINER_NAME}-vpn-${vpn_name}"
    tunnel_role="tunnel-${vpn_name}"
    tunnel_cidfile="${CID_PARENT}/${TRANSACTION_ID}.${vpn_name}.cid"
    append_new_intent_record "$tunnel_name" "$tunnel_role" "$tunnel_cidfile"
    tunnel_run_status=0
    as_root docker run -d \
        --cidfile "$tunnel_cidfile" \
        --label "${TRANSACTION_LABEL_KEY}=${TRANSACTION_ID}" \
        --label "${ROLE_LABEL_KEY}=${tunnel_role}" \
        --label "${BIND_LABEL_KEY}=${HOST_BIND}" \
        --label "${PROBE_LABEL_KEY}=${HOST_PROBE_ADDRESS}" \
        --label "${PORT_LABEL_KEY}=${SYNC_PORT}" \
        --log-driver none \
        --restart always \
        --network "container:$vpn_id" \
        --name "$tunnel_name" \
        -v "$HOST_DIRECTORY:/www:ro" \
        --entrypoint sh \
        "$IMAGE" \
        -c "busybox httpd -f -p $SYNC_PORT -h /www" >/dev/null || tunnel_run_status=$?
    register_created_container "$tunnel_cidfile" "$tunnel_name" "$tunnel_role" "$tunnel_run_status"
    if [ -n "$TUNNEL_CONTAINER_RECORDS" ]; then
        TUNNEL_CONTAINER_RECORDS="$TUNNEL_CONTAINER_RECORDS
$tunnel_name|$REGISTERED_CONTAINER_ID|$tunnel_role"
    else
        TUNNEL_CONTAINER_RECORDS="$tunnel_name|$REGISTERED_CONTAINER_ID|$tunnel_role"
    fi
    if [ -n "$TUNNEL_CONTAINERS" ]; then
        TUNNEL_CONTAINERS="$TUNNEL_CONTAINERS,$tunnel_name"
    else
        TUNNEL_CONTAINERS="$tunnel_name"
    fi
done <<EOF
$VPN_RECORDS
EOF

if [ "$PUBLISH_HOST_PORT" = "1" ]; then
    host_cidfile="${CID_PARENT}/${TRANSACTION_ID}.host.cid"
    append_new_intent_record "$HOST_CONTAINER_NAME" host "$host_cidfile"
    host_run_status=0
    as_root docker run -d \
        --cidfile "$host_cidfile" \
        --label "${TRANSACTION_LABEL_KEY}=${TRANSACTION_ID}" \
        --label "${ROLE_LABEL_KEY}=host" \
        --label "${BIND_LABEL_KEY}=${HOST_BIND}" \
        --label "${PROBE_LABEL_KEY}=${HOST_PROBE_ADDRESS}" \
        --label "${PORT_LABEL_KEY}=${SYNC_PORT}" \
        --log-driver none \
        --restart always \
        --network host \
        --name "$HOST_CONTAINER_NAME" \
        -v "$HOST_DIRECTORY:/www:ro" \
        --entrypoint sh \
        "$IMAGE" \
        -c "busybox httpd -f -p ${HOST_BIND}:${SYNC_PORT} -h /www" >/dev/null || host_run_status=$?
    register_created_container "$host_cidfile" "$HOST_CONTAINER_NAME" host "$host_run_status"
    NEW_HOST_ID="$REGISTERED_CONTAINER_ID"
fi

assert_new_container_identity "$NEW_MAIN_ID" "$CONTAINER_NAME" bridge \
    || die "Replacement bridge update container identity changed before health check"
is_running_container "$NEW_MAIN_ID" || die "Replacement bridge update container is not running"
wait_http_ready "$NEW_MAIN_ID" "127.0.0.1" || die "Bridge update endpoint did not serve the exact health sentinel"
while IFS='|' read -r new_id new_name new_role; do
    case "$new_role" in
        tunnel-*)
            assert_new_container_identity "$new_id" "$new_name" "$new_role" \
                || die "Replacement tunnel update container identity changed before health check"
            is_running_container "$new_id" || die "Replacement tunnel update container is not running: $new_name"
            wait_http_ready "$new_id" "127.0.0.1" \
                || die "Tunnel update endpoint did not serve the exact health sentinel: $new_name"
            ;;
    esac
done <<EOF
$NEW_CONTAINER_RECORDS
EOF
if [ "$PUBLISH_HOST_PORT" = "1" ]; then
    assert_new_container_identity "$NEW_HOST_ID" "$HOST_CONTAINER_NAME" host \
        || die "Replacement host update container identity changed before health check"
    is_running_container "$NEW_HOST_ID" || die "Replacement host update container is not running"
    wait_http_ready "$NEW_HOST_ID" "$HOST_PROBE_ADDRESS" \
        || die "Host update container did not serve the exact health sentinel"
fi
wait_host_http_ready || die "Host update endpoint did not serve the exact health sentinel"
reconcile_firewall_rules

remove_health_sentinel || die "Unable to remove update-host health sentinel"
switch_firewall_state

# The desired endpoints are now authoritative. Backup cleanup cannot be made atomic
# by Docker, so a cleanup error preserves the verified replacements and reports fail-closed.
persist_transaction_journal committed_pending_cleanup
TRANSACTION_COMMITTED=1
finalize_firewall_state || die "Verified update host is active, but firewall state cleanup failed"
cleanup_backups || die "Verified update host is active, but transactional backup cleanup failed"
cleanup_transaction_cidfiles || die "Verified update host is active, but cidfile cleanup failed"
clear_transaction_journal \
    || die "Verified update host is active, but durable transaction journal cleanup failed"

printf 'update_host_transaction=committed\ntransaction_id=%s\nimage=%s\nbridge_container=%s\nbridge_container_id=%s\nhost_container=%s\nhost_container_id=%s\nhost_bind=%s\nhost_probe_address=%s\nsync_port=%s\nnetwork_name=%s\nnetwork_id=%s\nvpn_sidecars=%s\n' \
    "$TRANSACTION_ID" "$IMAGE" "$CONTAINER_NAME" "$NEW_MAIN_ID" "$HOST_CONTAINER_NAME" \
    "${NEW_HOST_ID:-none}" "$HOST_BIND" "$HOST_PROBE_ADDRESS" "$SYNC_PORT" "$NETWORK_NAME" \
    "${NETWORK_ID:-existing}" "${TUNNEL_CONTAINERS:-none}"
while IFS='|' read -r tunnel_report_name tunnel_report_id tunnel_report_role; do
    [ -n "$tunnel_report_name" ] || continue
    printf 'vpn_sidecar=%s|%s|%s\n' "$tunnel_report_name" "$tunnel_report_id" "$tunnel_report_role"
done <<EOF
$TUNNEL_CONTAINER_RECORDS
EOF
