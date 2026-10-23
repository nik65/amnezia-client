#!/bin/bash
# ServerX-only diagnostic sidecar reconciliation. Never controls the VPN parent.
set -Eeuo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C
unset BASH_ENV ENV CDPATH

DOCKER=/usr/bin/docker
JQ=/usr/bin/jq
PROC_ROOT=/proc
ROOT=/opt/amnezia/client-logs
REQUIRED_UID=0
SOURCE=amnezia-awg2
ACTIVE=amnezia-client-logs-vpn-amnezia-awg2
CANDIDATE=amnezia-client-logs-vpn-amnezia-awg2-route-candidate
SOURCE_IMAGE=sha256:7dc728e8183a86eac6b9f8033511d4c16a135dff1e8aed7946470376600a685a
SOURCE_KEY=VoMDtwx77g/WR/KtVi48vs94syeRflU7GHarWkeDFCE=
COLLECTOR_IMAGE=python:3.12-alpine@sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df
COLLECTOR_IMAGE_ID=sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df
COLLECTOR_SHA256=a31814f2217aaea21c85b696cebac8442f4cfbb8c336f41497240147bca5e593
LEGACY_ID=e8cce8c8054edb8f8f4871725e81b3185df247ca7de7d863467568a70782e0e0
LABEL_KEY=org.amnezia.serverx-diagnostic-route
LABEL_VALUE=awg2-v1

fail() { printf 'ServerX diagnostic route refused: %s\n' "$1" >&2; exit 1; }
docker_cmd() { /usr/bin/timeout --signal=TERM --kill-after=2s 20s "$DOCKER" "$@"; }
inspect() {
    local data
    data=$(docker_cmd inspect "$1") || return 1
    [ "${#data}" -le 1048576 ] || return 1
    printf '%s' "$data"
}
field() { printf '%s' "$1" | "$JQ" -er "$2"; }
netns() { /usr/bin/readlink "$PROC_ROOT/$1/ns/net"; }

# A missing name is established by a successful inventory, never by suppressing
# a Docker permission/daemon/inspect error as though the container were absent.
container_id() {
    local data
    data=$(docker_cmd ps -a --filter "name=^/$1$" --format '{{.ID}}') || return 1
    if [ -z "$data" ]; then return 0; fi
    local snapshot
    snapshot=$(inspect "$1") || return 1
    field "$snapshot" 'if length == 1 then .[0].Id else error("singleton") end'
}

source_epoch() {
    local snapshot id pid started ns key fresh
    snapshot=$(inspect "$SOURCE") || return 1
    printf '%s' "$snapshot" | "$JQ" -e --arg name "/$SOURCE" --arg image "$SOURCE_IMAGE" '
      length == 1 and .[0].Name == $name and .[0].Image == $image
      and .[0].State.Running == true and .[0].State.Paused == false
      and (.[0].State.Pid | type == "number" and . > 0 and . == floor)
      and (.[0].Id | test("^[0-9a-f]{64}$"))
      and (.[0].State.StartedAt | type == "string" and length > 0)
    ' >/dev/null || return 1
    id=$(field "$snapshot" '.[0].Id')
    pid=$(field "$snapshot" '.[0].State.Pid')
    started=$(field "$snapshot" '.[0].State.StartedAt')
    ns=$(netns "$pid") || return 1
    key=$(docker_cmd exec "$id" awg show awg0 public-key) || return 1
    [ "$key" = "$SOURCE_KEY" ] || return 1
    # The key query itself crosses a process boundary. Recheck the incarnation
    # afterwards so a restart during that query cannot return a stale epoch.
    fresh=$(inspect "$SOURCE") || return 1
    [ "$(field "$fresh" '.[0].Id')" = "$id" ] || return 1
    [ "$(field "$fresh" '.[0].State.Pid')" = "$pid" ] || return 1
    [ "$(field "$fresh" '.[0].State.StartedAt')" = "$started" ] || return 1
    [ "$(field "$fresh" '.[0].State.Running')" = true ] || return 1
    [ "$(netns "$pid")" = "$ns" ] || return 1
    printf '%s\t%s\t%s\t%s\n' "$id" "$pid" "$started" "$ns"
}
source_unchanged() {
    local fresh
    fresh=$(source_epoch) || return 1
    [ "$fresh" = "$EPOCH" ]
}

collector_snapshot() {
    # stdout is private state consumed by the caller, never a diagnostic dump.
    local id=$1 name=$2 snapshot
    snapshot=$(inspect "$id") || return 1
    printf '%s' "$snapshot" | "$JQ" -e --arg id "$id" --arg name "/$name" \
      --arg image "$COLLECTOR_IMAGE" --arg imageid "$COLLECTOR_IMAGE_ID" \
      --arg root "$ROOT" --arg key "$LABEL_KEY" --arg value "$LABEL_VALUE" \
      --arg legacy "$LEGACY_ID" --arg active "/$ACTIVE" '
      length == 1 and .[0] as $c |
      $c.Id == $id and ($c.Id | test("^[0-9a-f]{64}$")) and $c.Name == $name
      and $c.Config.Image == $image and $c.Image == $imageid
      and $c.Config.Entrypoint == ["python"] and $c.Config.Cmd == ["/data/collector.py"]
      and (($c.Config.Env | map(select(startswith("AMNEZIA_CLIENT_LOGS_BOOTSTRAP=")))) == ["AMNEZIA_CLIENT_LOGS_BOOTSTRAP=1"])
      and (($c.Config.Env | map(select(startswith("AMNEZIA_CLIENT_LOGS_SCOPE=")))) == ["AMNEZIA_CLIENT_LOGS_SCOPE=amnezia-awg2"])
      and ($c.HostConfig.NetworkMode | test("^container:[0-9a-f]{64}$"))
      and $c.HostConfig.Privileged == false
      and ($c.Mounts | length == 1) and $c.Mounts[0].Type == "bind"
      and $c.Mounts[0].Source == $root and $c.Mounts[0].Destination == "/data"
      and $c.Mounts[0].RW == true
      and (($c.Config.Labels[$key] // "") == $value
           or ($c.Id == $legacy and $name == $active and (($c.Config.Labels[$key] // "") == "")))
    ' >/dev/null || return 1
    printf '%s' "$snapshot"
}

listener_owned() {
    local snapshot=$1 pid ns inode fd target
    [ "$(field "$snapshot" '.[0].State.Running')" = true ] || return 1
    pid=$(field "$snapshot" '.[0].State.Pid')
    [[ "$pid" =~ ^[1-9][0-9]*$ ]] || return 1
    ns=$(netns "$pid") || return 1
    [ "$ns" = "$SOURCE_NS" ] || return 1
    # Verify the inspected PID's exact command line and its own listening socket.
    /usr/bin/cmp -s "$PROC_ROOT/$pid/cmdline" <(printf 'python\0/data/collector.py\0') || return 1
    while IFS= read -r inode; do
        [[ "$inode" =~ ^[0-9]+$ ]] || continue
        for fd in "$PROC_ROOT/$pid/fd/"*; do
            target=$(/usr/bin/readlink "$fd") || continue
            [ "$target" = "socket:[$inode]" ] && return 0
        done
    done < <(/usr/bin/awk '$2 == "00000000:45CA" && $4 == "0A" {print $10}' "$PROC_ROOT/$pid/net/tcp")
    return 1
}

ready_collector() {
    local id=$1 name=$2 snapshot attempt
    for attempt in {1..10}; do
        source_unchanged || return 1
        snapshot=$(collector_snapshot "$id" "$name") || return 1
        if listener_owned "$snapshot"; then
            local fresh
            fresh=$(collector_snapshot "$id" "$name") || return 1
            [ "$(field "$fresh" '.[0].State.Pid')" = "$(field "$snapshot" '.[0].State.Pid')" ] || return 1
            [ "$(field "$fresh" '.[0].State.StartedAt')" = "$(field "$snapshot" '.[0].State.StartedAt')" ] || return 1
            source_unchanged || return 1
            printf '%s' "$fresh"
            return 0
        fi
        /usr/bin/sleep 1
    done
    return 1
}

[ "$#" -eq 0 ] || fail arguments
[ "$(/usr/bin/id -u)" -eq "$REQUIRED_UID" ] || fail root
[ ! -L "$ROOT" ] && [ -d "$ROOT" ] || fail directory
[ "$(/usr/bin/stat -c '%u:%a' "$ROOT")" = "$REQUIRED_UID:700" ] || fail directory_permissions
[ ! -L "$ROOT/collector.py" ] && [ -f "$ROOT/collector.py" ] || fail collector_file
[ "$(/usr/bin/stat -c '%u' "$ROOT/collector.py")" -eq "$REQUIRED_UID" ] || fail collector_owner
[ "$(/usr/bin/sha256sum "$ROOT/collector.py" | /usr/bin/cut -d ' ' -f 1)" = "$COLLECTOR_SHA256" ] || fail collector_hash
# The enclosing root-only directory prevents a non-root symlink substitution.
[ ! -L "$ROOT/serverx-route.lock" ] || fail lock_symlink
exec 9>"$ROOT/serverx-route.lock"
/usr/bin/flock -n 9 || exit 0

EPOCH=$(source_epoch) || fail source_identity
IFS=$'\t' read -r SOURCE_ID SOURCE_PID SOURCE_STARTED SOURCE_NS <<<"$EPOCH"
ACTIVE_ID=$(container_id "$ACTIVE") || fail active_inventory
CANDIDATE_ID=$(container_id "$CANDIDATE") || fail candidate_inventory
ACTIVE_SNAPSHOT=
if [ -n "$ACTIVE_ID" ]; then
    ACTIVE_SNAPSHOT=$(collector_snapshot "$ACTIVE_ID" "$ACTIVE") || fail active_ownership
fi
if [ -n "$CANDIDATE_ID" ]; then
    CANDIDATE_SNAPSHOT=$(collector_snapshot "$CANDIDATE_ID" "$CANDIDATE") || fail candidate_ownership
fi

# If the current active sidecar targets this parent, restore a lost namespace by
# restarting only that sidecar. A different parent ID requires a fresh sidecar.
if [ -n "$ACTIVE_ID" ] && [ "$(field "$ACTIVE_SNAPSHOT" '.[0].HostConfig.NetworkMode')" = "container:$SOURCE_ID" ]; then
    if ! listener_owned "$ACTIVE_SNAPSHOT"; then
        source_unchanged || fail source_changed
        docker_cmd restart "$ACTIVE_ID" >/dev/null || fail collector_restart
    fi
    CURRENT=$(ready_collector "$ACTIVE_ID" "$ACTIVE") || fail active_listener
    if [ -n "$CANDIDATE_ID" ]; then
        source_unchanged || fail source_changed
        collector_snapshot "$CANDIDATE_ID" "$CANDIDATE" >/dev/null || fail candidate_changed
        docker_cmd rm -f "$CANDIDATE_ID" >/dev/null || fail candidate_cleanup
    fi
else
    # Recover an interrupted replacement using its labelled candidate. No old
    # collector is removed until the replacement listener is proven live.
    if [ -n "$CANDIDATE_ID" ] && [ "$(field "$CANDIDATE_SNAPSHOT" '.[0].HostConfig.NetworkMode')" != "container:$SOURCE_ID" ]; then
        source_unchanged || fail source_changed
        collector_snapshot "$CANDIDATE_ID" "$CANDIDATE" >/dev/null || fail candidate_changed
        docker_cmd rm -f "$CANDIDATE_ID" >/dev/null || fail stale_candidate_cleanup
        CANDIDATE_ID=
    fi
    if [ -z "$CANDIDATE_ID" ]; then
        source_unchanged || fail source_changed
        CANDIDATE_ID=$(docker_cmd run -d --log-driver none --restart always --memory=96m --cpus=0.5 --pids-limit=64 \
            --cap-drop ALL --security-opt no-new-privileges:true --read-only \
            --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777 \
            --network "container:$SOURCE_ID" --name "$CANDIDATE" \
            --label "$LABEL_KEY=$LABEL_VALUE" -e PYTHONDONTWRITEBYTECODE=1 -e PYTHONUNBUFFERED=1 \
            -e AMNEZIA_CLIENT_LOGS_BOOTSTRAP=1 -e AMNEZIA_CLIENT_LOGS_SCOPE=amnezia-awg2 \
            -v "$ROOT:/data:rw" --entrypoint python "$COLLECTOR_IMAGE" /data/collector.py) || fail candidate_create
        [[ "$CANDIDATE_ID" =~ ^[0-9a-f]{64}$ ]] || fail candidate_id
    else
        snapshot=$(collector_snapshot "$CANDIDATE_ID" "$CANDIDATE") || fail candidate_changed
        if ! listener_owned "$snapshot"; then
            source_unchanged || fail source_changed
            docker_cmd restart "$CANDIDATE_ID" >/dev/null || fail candidate_restart
        fi
    fi
    CURRENT=$(ready_collector "$CANDIDATE_ID" "$CANDIDATE") || fail candidate_listener
    source_unchanged || fail source_changed
    if [ -n "$ACTIVE_ID" ]; then
        collector_snapshot "$ACTIVE_ID" "$ACTIVE" >/dev/null || fail active_changed
        docker_cmd rm -f "$ACTIVE_ID" >/dev/null || fail old_collector_cleanup
    fi
    # The candidate is already serving the endpoint; a failed rename leaves a
    # labelled, recoverable candidate for the next invocation, not a fake PASS.
    source_unchanged || fail source_changed
    docker_cmd rename "$CANDIDATE_ID" "$ACTIVE" || fail candidate_activate
    ACTIVE_ID=$CANDIDATE_ID
    CURRENT=$(ready_collector "$ACTIVE_ID" "$ACTIVE") || fail replacement_listener
fi

RULE=(PREROUTING -i awg0 -d 172.29.172.251/32 -p tcp --dport 17866 -j REDIRECT --to-ports 17866)
OWN_RULE=(PREROUTING -i awg0 -d 172.29.172.251/32 -p tcp --dport 17866 -m comment --comment amnezia-serverx-diag-route-v1 -j REDIRECT --to-ports 17866)
check_rule() {
    local status
    if docker_cmd exec "$SOURCE_ID" iptables -t nat -C "${RULE[@]}" >/dev/null 2>&1; then return 0; else status=$?; fi
    [ "$status" -eq 1 ] || return "$status"
    if docker_cmd exec "$SOURCE_ID" iptables -t nat -C "${OWN_RULE[@]}" >/dev/null 2>&1; then return 0; else status=$?; fi
    return "$status"
}
ADDED=0
rollback_rule() {
    if [ "$ADDED" -eq 1 ] && source_unchanged; then
        docker_cmd exec "$SOURCE_ID" iptables -t nat -D "${OWN_RULE[@]}" >/dev/null 2>&1 || true
    fi
}
trap 'rollback_rule' ERR
source_unchanged || fail source_changed
if check_rule; then code=0; else code=$?; fi
if [ "$code" -eq 1 ]; then
    source_unchanged || fail source_changed
    docker_cmd exec "$SOURCE_ID" iptables -t nat -A "${OWN_RULE[@]}" || fail rule_add
    ADDED=1
elif [ "$code" -ne 0 ]; then
    fail rule_check
fi
if ! check_rule \
    || ! source_unchanged \
    || ! FINAL=$(ready_collector "$ACTIVE_ID" "$ACTIVE") \
    || [ "$(field "$FINAL" '.[0].State.Pid')" != "$(field "$CURRENT" '.[0].State.Pid')" ] \
    || [ "$(field "$FINAL" '.[0].State.StartedAt')" != "$(field "$CURRENT" '.[0].State.StartedAt')" ]; then
    rollback_rule
    ADDED=0
    fail final_verification
fi
ADDED=0
trap - ERR
printf 'ServerX diagnostic route healthy; source=%s collector=%s added=%s\n' "$SOURCE_ID" "$ACTIVE_ID" "$code"
