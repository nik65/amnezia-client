#!/usr/bin/env bash
# Build-directory lock for parallel Amnezia builds.
#
# Two builds writing the same directory already produced
#     CPack Error: Problem removing toplevel directory
# (one cpack/clean step deleting the tree while the other build was still
# writing it).  This tool serialises access to a build directory:
#
#     Testing/build_lock.sh acquire deploy/build          # or deploy/build-linux
#     ... run the build ...
#     Testing/build_lock.sh release deploy/build
#
# Preferred, leak-proof form (releases even when the build fails or is killed):
#
#     Testing/build_lock.sh run deploy/build -- cmake --build deploy/build -j 24
#
# Lock design (why it is not just `flock <dir>/.lock`):
#   * the lease lives OUTSIDE the build directory, in the lock root
#     (default <repo>/.build-locks, override with AMNEZIA_BUILD_LOCK_ROOT),
#     because the failing scenario deletes the build directory itself -- a
#     lock file inside it would vanish and stop excluding anything.  Lock
#     files are named <basename>-<sha1(canonical dir)[:12]>.lock, so the
#     same directory reached through different spellings still maps to one
#     lease;
#   * acquisition is an atomic `mkdir` of the lease directory: portable
#     (git-bash on Windows has no flock) and exactly as atomic as O_EXCL
#     file creation;
#   * a `manual` lease (plain acquire/release) is held until it is released
#     -- it is never stolen automatically, because the acquiring process
#     exits immediately and PID liveness cannot apply to it.  Such a lease
#     needs `release`, `release --force`, or a new acquire with `--force`
#     (or `--max-age SECONDS`);
#   * a `pid` lease (`acquire --pid <pid>`, e.g. `--pid $$` from a build
#     script) and a `run` lease are bound to a live process: when that PID
#     is gone (same host and same environment) the lease is stale and the
#     next acquire steals it automatically with a warning;  `--no-steal`
#     forbids that;
#   * in `run` mode, when the `flock` utility exists (WSL/Linux), an advisory
#     kernel lock is held on <lease>/flock for the whole child command as
#     defence in depth.
#
# Exit codes: 0 ok, 2 usage/input error, 4 the directory is locked (or a stale
# lease was refused), anything else is the exit code of `run`'s command.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LOCK_ROOT="${AMNEZIA_BUILD_LOCK_ROOT:-$REPO_ROOT/.build-locks}"

usage() { # optional exit code (default 2)
    cat <<'EOF'
Usage:
  build_lock.sh acquire <dir> [--pid PID] [--wait SECONDS] [--max-age SECONDS]
                              [--force] [--no-steal] [--note TEXT]
  build_lock.sh release <dir> [--force]
  build_lock.sh status  <dir>
  build_lock.sh run     <dir> [--wait SECONDS] -- <command...>   (acquire, exec, release)

Options:
  --pid PID        bind the lease to a process; when that PID is gone the
                   lease is stale and the next acquire steals it automatically
  --wait SECONDS   wait up to SECONDS for the lease to become free (default 0)
  --max-age SECS   steal a manual lease older than SECS seconds (default 0 = never)
  --force          take over / release a lease even when its owner looks alive
  --no-steal       never steal leases automatically (still allows --force)
  --note TEXT      free-form note stored in the lease (e.g. the build target)
  --lock-root DIR  override the lock root (default: <repo>/.build-locks)

Environment:
  AMNEZIA_BUILD_LOCK_ROOT   lock root override (same as --lock-root)
EOF
    exit "${1:-2}"
}

die() { echo "build_lock: $*" >&2; exit 2; }

now_epoch() { date +%s; }
host_id() { hostname 2>/dev/null || echo unknown-host; }
env_id() {
    # Distinguishes WSL/Linux from git-bash/MSYS: PIDs are not comparable
    # across environments, so liveness must never be checked across them.
    local kernel
    kernel="$(uname -s 2>/dev/null || echo unknown)"
    case "$kernel" in
        MINGW*|MSYS*|CYGWIN*) kernel="msys" ;;
    esac
    echo "$kernel/$(host_id)"
}

slug_for() {
    local dir="$1" base hash
    base="$(basename "$dir" | tr -c 'A-Za-z0-9._-' '_' | cut -c1-40)"
    hash="$(printf '%s' "$dir" | sha1sum | cut -c1-12)"
    echo "${base:-dir}-${hash}"
}

canonical_dir() {
    local dir="$1"
    mkdir -p "$dir" || die "cannot create directory: $dir"
    ( cd "$dir" && pwd -P ) || die "cannot resolve directory: $dir"
}

canonical_dir_readonly() {
    local dir="$1"
    if [ -d "$dir" ]; then
        ( cd "$dir" && pwd -P ) || die "cannot resolve directory: $dir"
    else
        case "$dir" in
            /*|[A-Za-z]:[/\\]*) printf '%s' "$dir" ;;
            *) printf '%s' "$PWD/$dir" ;;
        esac
    fi
}

lease_dir_for() { echo "$LOCK_ROOT/$(slug_for "$1").lock"; }

read_field() { # $1 file, $2 key
    [ -f "$1" ] || return 1
    sed -n "s/^$2=//p" "$1" | head -n 1
}

owner_alive() { # $1 pid, $2 env -> 0 alive, 1 not alive, 2 foreign environment
    local pid="$1" env="$2"
    [ -n "$pid" ] || return 1
    [ "$env" = "$(env_id)" ] || return 2
    kill -0 "$pid" 2>/dev/null
}

describe_owner() {
    local lease="$1"
    local dir host env pid mode started note
    dir="$(read_field "$lease/owner" dir || true)"
    host="$(read_field "$lease/owner" host || true)"
    env="$(read_field "$lease/owner" env || true)"
    pid="$(read_field "$lease/owner" pid || true)"
    mode="$(read_field "$lease/owner" mode || true)"
    started="$(read_field "$lease/owner" started_at || true)"
    note="$(read_field "$lease/owner" note || true)"
    echo "dir=${dir:-?} mode=${mode:-?} host=${host:-?} env=${env:-?} pid=${pid:-?} started=${started:-?}${note:+ note=$note}"
}

lease_age() { # seconds since the lease was written; 0 when unknown
    local lease="$1" epoch age
    epoch="$(read_field "$lease/owner" epoch || true)"
    if [ -n "$epoch" ]; then
        age=$(( $(now_epoch) - epoch ))
        [ "$age" -ge 0 ] 2>/dev/null && { echo "$age"; return; }
    fi
    echo 0
}

write_owner_file() { # $1 lease, $2 dir, $3 mode, $4 pid, $5 note, $6 prev
    local lease="$1" dir="$2" mode="$3" pid="$4" note="$5" prev="$6"
    if [ -z "$lease" ] || [ -z "$dir" ]; then
        return 1
    fi
    {
        printf 'dir=%s\n' "$dir"
        printf 'mode=%s\n' "$mode"
        printf 'host=%s\n' "$(host_id)"
        printf 'env=%s\n' "$(env_id)"
        printf 'pid=%s\n' "$pid"
        printf 'started_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date)"
        printf 'epoch=%s\n' "$(now_epoch)"
        printf 'prev_owner=%s\n' "$prev"
        printf 'note=%s\n' "$note"
    } > "$lease/owner" 2>/dev/null || return 1
    return 0
}

steal_lease() {
    local lease="$1"
    [ -L "$lease" ] && die "refusing to touch symlinked lock path: $lease"
    rm -rf -- "$lease"
}

# try_acquire_once <dir> <note> <mode> <pid> <max_age> ; 0 acquired, 4 locked
# lock mode: none = never steal automatically, stale = steal dead owner,
#            force = steal regardless of owner state
try_acquire_once() {
    local dir="$1" note="$2" steal_mode="$3" bind_pid="$4" max_age="$5"
    local lease owner previous state alive_status age
    lease="$(lease_dir_for "$dir")"
    owner="$lease/owner"
    if mkdir -- "$lease" 2>/dev/null; then
        if ! write_owner_file "$lease" "$dir" "$([ -n "$bind_pid" ] && echo pid || echo manual)" "$bind_pid" "$note" ""; then
            echo "build_lock: cannot write lease metadata in $lease" >&2
            rm -rf -- "$lease"
            return 4
        fi
        return 0
    fi
    [ -d "$lease" ] || die "lock path exists but is not a directory: $lease"
    local pid recorded_env recorded_mode
    pid="$(read_field "$owner" pid || true)"
    recorded_env="$(read_field "$owner" env || true)"
    recorded_mode="$(read_field "$owner" mode || true)"
    if [ "$recorded_mode" = "manual" ]; then
        age="$(lease_age "$lease")"
        if [ "$max_age" -gt 0 ] && [ "$age" -ge "$max_age" ]; then
            state="expired"
        else
            state="held"   # held until released; a manual owner is not a live process
        fi
    elif [ -z "$pid" ]; then
        state="dead"       # no usable owner metadata: treat as stale
    else
        owner_alive "$pid" "$recorded_env"
        alive_status=$?
        case "$alive_status" in
            0) state="live" ;;
            2) state="foreign" ;;
            *) state="dead" ;;
        esac
    fi
    if [ "$steal_mode" != "force" ]; then
        case "$state" in
            held)
                echo "build_lock: LOCKED (manual lease; release it or use --force/--max-age): $(describe_owner "$lease")" >&2
                return 4 ;;
            live)
                echo "build_lock: LOCKED by a live owner (pid $pid): $(describe_owner "$lease")" >&2
                return 4 ;;
            foreign)
                echo "build_lock: LOCKED by another environment/host: $(describe_owner "$lease")" >&2
                echo "build_lock: use --force only if that build is really gone" >&2
                return 4 ;;
            dead)
                if [ "$steal_mode" = "none" ]; then
                    echo "build_lock: LOCKED by a build whose PID is gone (use --force): $(describe_owner "$lease")" >&2
                    return 4
                fi ;;
        esac
    fi
    previous="$(describe_owner "$lease" 2>/dev/null || true)"
    case "$state" in
        live) echo "build_lock: WARNING taking over a lease owned by a live process: $previous" >&2 ;;
        dead) echo "build_lock: WARNING stealing stale lease (owner PID is gone): $previous" >&2 ;;
        expired) echo "build_lock: WARNING stealing expired manual lease (age ${age}s >= ${max_age}s): $previous" >&2 ;;
        held) echo "build_lock: WARNING forcing takeover of a manual lease: $previous" >&2 ;;
        foreign) echo "build_lock: WARNING forcing takeover of a foreign lease: $previous" >&2 ;;
    esac
    steal_lease "$lease" || return 4
    mkdir -- "$lease" 2>/dev/null || return 4
    if ! write_owner_file "$lease" "$dir" "$([ -n "$bind_pid" ] && echo pid || echo manual)" "$bind_pid" "$note" "$previous"; then
        rm -rf -- "$lease"
        return 4
    fi
    return 0
}

cmd_acquire() {
    local dir="$1"; shift
    local wait_seconds=0 force=0 no_steal=0 note="" bind_pid="" max_age=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --wait) wait_seconds="${2:?--wait needs seconds}"; shift 2 ;;
            --max-age) max_age="${2:?--max-age needs seconds}"; shift 2 ;;
            --pid) bind_pid="${2:?--pid needs a PID}"; shift 2 ;;
            --force) force=1; shift ;;
            --no-steal) no_steal=1; shift ;;
            --note) note="${2:?--note needs text}"; shift 2 ;;
            *) die "unknown acquire option: $1" ;;
        esac
    done
    dir="$(canonical_dir "$dir")"
    mkdir -p "$LOCK_ROOT"
    local deadline=$(( $(now_epoch) + wait_seconds ))
    local steal_mode="stale"
    [ "$no_steal" -eq 1 ] && steal_mode="none"
    [ "$force" -eq 1 ] && steal_mode="force"
    local rc=0
    while :; do
        if try_acquire_once "$dir" "$note" "$steal_mode" "$bind_pid" "$max_age"; then
            echo "build_lock: ACQUIRED $(lease_dir_for "$dir")"
            if [ -n "$bind_pid" ]; then
                echo "build_lock: dir=$dir owner-pid=$bind_pid (lease released automatically when that process exits)"
            else
                echo "build_lock: dir=$dir manual lease held by pid $$ until 'release'"
            fi
            return 0
        else
            rc=$?
        fi
        [ "$rc" -ne 4 ] && return "$rc"
        if [ "$(now_epoch)" -ge "$deadline" ]; then
            echo "build_lock: could not acquire $dir within ${wait_seconds}s" >&2
            return 4
        fi
        sleep 2
    done
}

cmd_release() {
    local dir="$1"; shift
    local force=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --force) force=1; shift ;;
            *) die "unknown release option: $1" ;;
        esac
    done
    dir="$(canonical_dir "$dir")"
    local lease; lease="$(lease_dir_for "$dir")"
    if [ ! -e "$lease" ]; then
        echo "build_lock: no lease for $dir (already released)"
        return 0
    fi
    local pid recorded_env recorded_mode
    pid="$(read_field "$lease/owner" pid || true)"
    recorded_env="$(read_field "$lease/owner" env || true)"
    recorded_mode="$(read_field "$lease/owner" mode || true)"
    if [ "$force" -ne 1 ] && [ "$pid" != "$$" ] && [ "$recorded_mode" != "manual" ]; then
        if owner_alive "$pid" "$recorded_env"; then
            echo "build_lock: lease is held by a live process (pid $pid); use --force to release anyway" >&2
            return 4
        fi
    fi
    steal_lease "$lease"
    echo "build_lock: RELEASED $dir ($lease)"
}

cmd_status() {
    local dir; dir="$(canonical_dir_readonly "$1")"
    local lease; lease="$(lease_dir_for "$dir")"
    if [ ! -e "$lease" ]; then
        echo "build_lock: FREE $dir"
        return 0
    fi
    local pid recorded_env recorded_mode
    pid="$(read_field "$lease/owner" pid || true)"
    recorded_env="$(read_field "$lease/owner" env || true)"
    recorded_mode="$(read_field "$lease/owner" mode || true)"
    if [ "$recorded_mode" = "manual" ]; then
        echo "build_lock: LOCKED $dir (manual lease, age $(lease_age "$lease")s) :: $(describe_owner "$lease")"
        return 0
    fi
    if owner_alive "$pid" "$recorded_env"; then
        echo "build_lock: LOCKED $dir :: $(describe_owner "$lease")"
        return 0
    fi
    echo "build_lock: STALE $dir :: $(describe_owner "$lease")"
    return 0
}

cmd_run() {
    local dir="$1"; shift
    local wait_seconds=0
    while [ $# -gt 0 ] && [ "$1" != "--" ]; do
        case "$1" in
            --wait) wait_seconds="${2:?--wait needs seconds}"; shift 2 ;;
            *) die "unknown run option: $1 (use -- before the command)" ;;
        esac
    done
    [ "${1:-}" = "--" ] || die "run needs -- before the command"
    shift
    [ $# -gt 0 ] || die "run needs a command"
    cmd_acquire "$dir" --wait "$wait_seconds" --pid $$ --note "run: $*" || return $?
    local lease; lease="$(lease_dir_for "$(canonical_dir "$dir")")"
    RELEASE_DIR="$dir"
    release_on_exit() {
        cmd_release "$RELEASE_DIR" --force >/dev/null 2>&1 || true
    }
    trap release_on_exit EXIT INT TERM
    if command -v flock >/dev/null 2>&1; then
        exec 9>"$lease/flock" 2>/dev/null || true
        if ! flock -n 9 2>/dev/null; then
            echo "build_lock: WARNING advisory flock is held by another process" >&2
        fi
    fi
    "$@"
    local rc=$?
    return "$rc"
}

[ $# -ge 1 ] || usage
command_name="$1"; shift
case "$command_name" in
    acquire) [ $# -ge 1 ] || usage; cmd_acquire "$@" ;;
    release) [ $# -ge 1 ] || usage; cmd_release "$@" ;;
    status)  [ $# -ge 1 ] || usage; cmd_status "$@" ;;
    run)     [ $# -ge 1 ] || usage; cmd_run "$@" ;;
    -h|--help|help) usage 0 ;;
    *) usage ;;
esac
exit $?
