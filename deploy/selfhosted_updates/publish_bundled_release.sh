#!/bin/sh
# Bundled-client publisher for the fixed self-hosted update channel.
# Keep this file POSIX-sh compatible and LF-only.
set -eu

PINNED_ROOT='/opt/amnezia/client-updates'
PINNED_PARENT='/opt/amnezia'
TRUST_ANCHOR='/opt'
UPLOAD_PREFIX='/tmp/amnezia-client-updates.'
TRUSTED_UID=0
TRUSTED_GID=0
MARKER_NAME='.amnezia-update-channel-v1'
MARKER_TEXT='amnezia-selfhosted-update-channel-v1'
MARKER_SHA256='e7f84faa235a87b73f4876438a67069e5e460f405879138e5bb81527dd951bbb'
STATE_MAGIC='amnezia-bundled-publish-state-v1'
MAX_MANIFEST_BYTES=1048576
MAX_METADATA_BYTES=65536
MAX_FILES=64

fail() {
    code=$1
    shift
    printf '%s\n' "$*" >&2
    exit "$code"
}

as_root() {
    sudo -n -- "$@"
}

is_sha256() {
    [ "${#1}" -eq 64 ] && printf '%s\n' "$1" | grep -Eq '^[0-9a-f]{64}$'
}

is_run_id() {
    [ "${#1}" -eq 48 ] && printf '%s\n' "$1" | grep -Eq '^[0-9a-f]{48}$'
}

is_positive_decimal() {
    printf '%s\n' "$1" | grep -Eq '^[1-9][0-9]*$'
}

is_version() {
    printf '%s\n' "$1" | awk -F. '
        NF != 4 { exit 1 }
        {
            for (i = 1; i <= 4; ++i) {
                if ($i !~ /^(0|[1-9][0-9]*)$/ || length($i) > 10 || $i + 0 > 2147483647) {
                    exit 1
                }
            }
        }
    '
}

is_generation() {
    is_positive_decimal "$1" || return 1
    printf '%s\n' "$1" | awk 'length($0) < 16 || (length($0) == 16 && $0 <= "9007199254740991")'
}

require_tools() {
    for tool in awk diff find flock grep head install mv readlink sha256sum stat sync wc; do
        command -v "$tool" >/dev/null 2>&1 || fail 69 "required publisher tool is unavailable: $tool"
    done
    sync --help 2>&1 | grep -q -- '-f' || fail 69 'sync -f is required for durable publication'
}

check_trusted_directory() {
    checked=$1
    description=$2
    as_root test -d "$checked" && ! as_root test -L "$checked" \
        || fail 64 "$description is not a real directory"
    identity=$(as_root stat -Lc '%d:%i' -- "$checked") \
        || fail 64 "unable to identify $description"
    [ "$identity" != "$ROOT_IDENTITY" ] \
        || fail 64 "$description aliases filesystem root"
    trusted=$(as_root find "$checked" -maxdepth 0 -uid "$TRUSTED_UID" -gid "$TRUSTED_GID" \
        ! -perm /0022 -perm -0005 -print -quit) || fail 64 "unable to inspect $description"
    [ -n "$trusted" ] \
        || fail 64 "$description must be trusted, traversable, and not group/other-writable"
}

check_trusted_regular_file() {
    checked=$1
    description=$2
    as_root test -f "$checked" && ! as_root test -L "$checked" \
        || fail 64 "$description is not a regular file"
    trusted=$(as_root find "$checked" -maxdepth 0 -uid "$TRUSTED_UID" -gid "$TRUSTED_GID" \
        ! -perm /0022 -print -quit) || fail 64 "unable to inspect $description"
    [ -n "$trusted" ] || fail 64 "$description has unsafe ownership or mode"
}

validate_channel_layout() {
    [ -d "$PINNED_ROOT" ] || return 0
    for entry in "$PINNED_ROOT"/* "$PINNED_ROOT"/.[!.]* "$PINNED_ROOT"/..?*; do
        if ! as_root test -e "$entry" && ! as_root test -L "$entry"; then
            continue
        fi
        name=${entry##*/}
        case "$name" in
            files)
                check_trusted_directory "$entry" 'update channel files directory'
                files_unsafe=$(as_root find "$entry" ! -type d ! -type f -print -quit) \
                    || fail 64 'unable to inspect update channel files tree'
                [ -z "$files_unsafe" ] \
                    || fail 64 'update channel files tree contains a link or special file'
                files_mutable=$(as_root find "$entry" \
                    \( ! -uid "$TRUSTED_UID" -o ! -gid "$TRUSTED_GID" -o -perm /0022 \) \
                    -print -quit) || fail 64 'unable to inspect update channel files ownership'
                [ -z "$files_mutable" ] \
                    || fail 64 'update channel files tree has unsafe ownership or mode'
                ;;
            manifest.json|.manifest-publish.lock|"$MARKER_NAME")
                check_trusted_regular_file "$entry" "update channel entry $name"
                ;;
            .manifest.*)
                printf '%s\n' "$name" | grep -Eq '^\.manifest\.[0-9a-f]{48}$' \
                    || fail 64 'invalid manifest staging entry name'
                check_trusted_regular_file "$entry" 'manifest staging entry'
                size=$(as_root stat -c %s -- "$entry") || fail 64 'unable to size manifest staging entry'
                [ "$size" -le "$MAX_MANIFEST_BYTES" ] || fail 64 'oversized manifest staging entry'
                ;;
            .channel-marker.*)
                printf '%s\n' "$name" | grep -Eq '^\.channel-marker\.[0-9a-f]{48}$' \
                    || fail 64 'invalid marker staging entry name'
                check_trusted_regular_file "$entry" 'marker staging entry'
                ;;
            .publish-state.*)
                printf '%s\n' "$name" | grep -Eq '^\.publish-state\.[0-9a-f]{48}$' \
                    || fail 64 'invalid publication state entry name'
                check_trusted_regular_file "$entry" 'publication state entry'
                ;;
            .publish-state-tmp.*)
                printf '%s\n' "$name" | grep -Eq '^\.publish-state-tmp\.[0-9a-f]{48}$' \
                    || fail 64 'invalid publication state staging entry name'
                check_trusted_regular_file "$entry" 'publication state staging entry'
                ;;
            *)
                fail 64 "update directory is not a dedicated channel: $name"
                ;;
        esac
    done

    marker="$PINNED_ROOT/$MARKER_NAME"
    if as_root test -e "$marker" || as_root test -L "$marker"; then
        marker_sha=$(as_root sha256sum -- "$marker" | awk '{print $1}') \
            || fail 64 'unable to hash update channel marker'
        [ "$marker_sha" = "$MARKER_SHA256" ] || fail 64 'update channel marker has unexpected content'
    fi
}

validate_pinned_path() {
    supplied_root=$1
    [ "$supplied_root" = "$PINNED_ROOT" ] || fail 64 'publisher root is not the pinned update channel'
    ROOT_IDENTITY=$(as_root stat -Lc '%d:%i' -- /) || fail 64 'unable to identify filesystem root'
    resolved=$(as_root readlink -m -- "$PINNED_ROOT") || fail 64 'unable to resolve publisher root'
    [ "$resolved" = "$PINNED_ROOT" ] && [ "$resolved" != / ] \
        || fail 64 'publisher root resolves through a symlink or to filesystem root'
    resolved_parent=$(as_root readlink -m -- "$PINNED_PARENT") || fail 64 'unable to resolve publisher parent'
    [ "$resolved_parent" = "$PINNED_PARENT" ] \
        || fail 64 'publisher parent resolves through a symlink'
    check_trusted_directory "$TRUST_ANCHOR" 'publisher trust anchor'
    if as_root test -e "$PINNED_PARENT" || as_root test -L "$PINNED_PARENT"; then
        check_trusted_directory "$PINNED_PARENT" 'publisher parent'
    fi
    if as_root test -e "$PINNED_ROOT" || as_root test -L "$PINNED_ROOT"; then
        check_trusted_directory "$PINNED_ROOT" 'publisher root'
        validate_channel_layout
    fi
}

ensure_trusted_directory() {
    directory=$1
    description=$2
    if ! as_root test -e "$directory" && ! as_root test -L "$directory"; then
        as_root install -d -o "$TRUSTED_UID" -g "$TRUSTED_GID" -m 0755 -- "$directory" \
            || fail 73 "unable to create $description"
    fi
    check_trusted_directory "$directory" "$description"
}

current_manifest_sha() {
    manifest="$PINNED_ROOT/manifest.json"
    if as_root test -L "$manifest"; then
        fail 64 'published manifest must not be a symlink'
    fi
    if as_root test -f "$manifest"; then
        CURRENT_SHA=$(as_root sha256sum -- "$manifest" | awk '{print $1}') \
            || fail 64 'unable to hash published manifest'
        is_sha256 "$CURRENT_SHA" || fail 64 'published manifest hash is invalid'
    elif as_root test -e "$manifest"; then
        fail 64 'published manifest is not a regular file'
    else
        CURRENT_SHA=absent
    fi
}

check_cas() {
    expected=$1
    candidate=$2
    current_manifest_sha
    CAS_ALREADY_CURRENT=0
    if [ "$CURRENT_SHA" = "$candidate" ]; then
        CAS_ALREADY_CURRENT=1
        return 0
    fi
    [ "$CURRENT_SHA" = "$expected" ] \
        || fail 75 "manifest CAS conflict: expected $expected, found $CURRENT_SHA"
}

create_lock_and_acquire() {
    LOCK_PATH="$PINNED_ROOT/.manifest-publish.lock"
    as_root flock -x -w 60 "$LOCK_PATH" true || fail 75 'timed out creating publisher lock'
    as_root chown "$TRUSTED_UID:$TRUSTED_GID" -- "$LOCK_PATH" || fail 73 'unable to own publisher lock'
    as_root chmod 0644 -- "$LOCK_PATH" || fail 73 'unable to set publisher lock mode'
    check_trusted_regular_file "$LOCK_PATH" 'publisher lock'
    exec 9< "$LOCK_PATH" || fail 73 'unable to open publisher lock'
    flock -x -w 60 9 || fail 75 'timed out waiting for publisher lock'
    validate_pinned_path "$PINNED_ROOT"
}

install_channel_marker() {
    marker="$PINNED_ROOT/$MARKER_NAME"
    if as_root test -e "$marker" || as_root test -L "$marker"; then
        check_trusted_regular_file "$marker" 'update channel marker'
        marker_sha=$(as_root sha256sum -- "$marker" | awk '{print $1}')
        [ "$marker_sha" = "$MARKER_SHA256" ] || fail 64 'update channel marker has unexpected content'
        return 0
    fi

    if [ "$CURRENT_SHA" = absent ]; then
        legacy_file=$(as_root find "$PINNED_ROOT/files" -type f -print -quit) \
            || fail 64 'unable to inspect unmarked update directory'
        [ -z "$legacy_file" ] \
            || fail 64 'refusing to adopt an unmarked channel with files but no verified manifest'
    fi

    MARKER_TMP="$PINNED_ROOT/.channel-marker.$RUN_ID"
    if as_root test -e "$MARKER_TMP" || as_root test -L "$MARKER_TMP"; then
        fail 75 'random marker staging path already exists'
    fi
    as_root install -o "$TRUSTED_UID" -g "$TRUSTED_GID" -m 0600 /dev/null "$MARKER_TMP" \
        || fail 73 'unable to create marker staging file'
    printf '%s\n' "$MARKER_TEXT" | as_root tee -- "$MARKER_TMP" >/dev/null \
        || fail 73 'unable to write marker staging file'
    as_root chmod 0444 -- "$MARKER_TMP" || fail 73 'unable to seal marker staging file'
    marker_sha=$(as_root sha256sum -- "$MARKER_TMP" | awk '{print $1}')
    [ "$marker_sha" = "$MARKER_SHA256" ] || fail 65 'marker staging hash mismatch'
    as_root sync -f -- "$MARKER_TMP" || fail 74 'unable to persist marker staging file'
    as_root mv -T -n -- "$MARKER_TMP" "$marker" || fail 73 'unable to publish channel marker'
    if as_root test -e "$MARKER_TMP" || as_root test -L "$MARKER_TMP"; then
        fail 75 'channel marker appeared concurrently with different state'
    fi
    MARKER_TMP=
    as_root sync -f -- "$PINNED_ROOT" || fail 74 'unable to persist channel marker rename'
}

require_channel_marker() {
    marker="$PINNED_ROOT/$MARKER_NAME"
    check_trusted_regular_file "$marker" 'update channel marker'
    marker_sha=$(as_root sha256sum -- "$marker" | awk '{print $1}') \
        || fail 64 'unable to hash update channel marker'
    [ "$marker_sha" = "$MARKER_SHA256" ] || fail 64 'update channel marker has unexpected content'
}

validate_identity_args() {
    [ "$#" -eq 5 ] || fail 64 'publication identity requires RUN_ID EXPECTED CANDIDATE_SHA METADATA_SHA FILE_COUNT'
    RUN_ID=$1
    expected=$2
    candidate=$3
    metadata_sha=$4
    expected_file_count=$5
    is_run_id "$RUN_ID" || fail 64 'invalid publication run id'
    { [ "$expected" = absent ] || is_sha256 "$expected"; } || fail 64 'invalid expected manifest hash'
    is_sha256 "$candidate" || fail 64 'invalid candidate manifest hash'
    is_sha256 "$metadata_sha" || fail 64 'invalid publication metadata hash'
    is_positive_decimal "$expected_file_count" || fail 64 'invalid expected file count'
    [ "$expected_file_count" -le "$MAX_FILES" ] || fail 64 'too many bundled publication files'
    STATE_PATH="$PINNED_ROOT/.publish-state.$RUN_ID"
    STATE_TMP="$PINNED_ROOT/.publish-state-tmp.$RUN_ID"
}

read_publication_state() {
    STATE_PRESENT=0
    if ! as_root test -e "$STATE_PATH" && ! as_root test -L "$STATE_PATH"; then
        return 0
    fi
    check_trusted_regular_file "$STATE_PATH" 'publication state'
    exec 8< "$STATE_PATH" || fail 64 'unable to open publication state'
    tab=$(printf '\t')
    IFS="$tab" read -r state_magic state_run_id state_expected state_candidate \
        state_metadata_sha state_file_count state_phase state_extra <&8 \
        || fail 64 'unable to read publication state'
    if IFS= read -r state_trailing <&8; then
        fail 64 'publication state has trailing records'
    fi
    exec 8<&-
    [ "$state_magic" = "$STATE_MAGIC" ] || fail 64 'publication state schema is invalid'
    is_run_id "$state_run_id" || fail 64 'publication state run id is invalid'
    { [ "$state_expected" = absent ] || is_sha256 "$state_expected"; } \
        || fail 64 'publication state expected hash is invalid'
    is_sha256 "$state_candidate" || fail 64 'publication state candidate hash is invalid'
    is_sha256 "$state_metadata_sha" || fail 64 'publication state metadata hash is invalid'
    is_positive_decimal "$state_file_count" || fail 64 'publication state file count is invalid'
    [ "$state_file_count" -le "$MAX_FILES" ] || fail 64 'publication state file count exceeds limit'
    [ -z "$state_extra" ] || fail 64 'publication state has unexpected fields'
    case "$state_phase" in
        prepared|committing|committed|aborted|finalizing|finalized|abort_finalizing|finalized_aborted|\
        rollback_prepared|rolling_back|rolled_back|rollback_aborted|rollback_finalizing|rollback_finalized)
            ;;
        *) fail 64 'publication state phase is invalid' ;;
    esac
    STATE_PRESENT=1
}

state_identity_matches() {
    [ "$STATE_PRESENT" = 1 ] \
        && [ "$state_run_id" = "$RUN_ID" ] \
        && [ "$state_expected" = "$expected" ] \
        && [ "$state_candidate" = "$candidate" ] \
        && [ "$state_metadata_sha" = "$metadata_sha" ] \
        && [ "$state_file_count" = "$expected_file_count" ]
}

write_publication_state() {
    new_phase=$1
    STATE_TMP="$PINNED_ROOT/.publish-state-tmp.$RUN_ID"
    case "$new_phase" in
        prepared|committing|committed|aborted|finalizing|finalized|abort_finalizing|finalized_aborted|\
        rollback_prepared|rolling_back|rolled_back|rollback_aborted|rollback_finalizing|rollback_finalized)
            ;;
        *) fail 64 'refusing to write an invalid publication state phase' ;;
    esac
    if as_root test -e "$STATE_TMP" || as_root test -L "$STATE_TMP"; then
        check_trusted_regular_file "$STATE_TMP" 'publication state staging entry'
        as_root rm -f -- "$STATE_TMP" || fail 73 'unable to remove stale publication state staging entry'
    fi
    as_root install -o "$TRUSTED_UID" -g "$TRUSTED_GID" -m 0600 /dev/null "$STATE_TMP" \
        || fail 73 'unable to create publication state staging entry'
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$STATE_MAGIC" "$RUN_ID" "$expected" "$candidate" "$metadata_sha" "$expected_file_count" "$new_phase" \
        | as_root tee -- "$STATE_TMP" >/dev/null \
        || fail 73 'unable to write publication state staging entry'
    as_root chmod 0444 -- "$STATE_TMP" || fail 73 'unable to seal publication state staging entry'
    as_root sync -f -- "$STATE_TMP" || fail 74 'unable to persist publication state staging entry'
    as_root mv -fT -- "$STATE_TMP" "$STATE_PATH" || fail 73 'unable to replace publication state'
    as_root sync -f -- "$PINNED_ROOT" || fail 74 'unable to persist publication state replacement'
    STATE_TMP=
    state_magic=$STATE_MAGIC
    state_run_id=$RUN_ID
    state_expected=$expected
    state_candidate=$candidate
    state_metadata_sha=$metadata_sha
    state_file_count=$expected_file_count
    state_phase=$new_phase
    state_extra=
    STATE_PRESENT=1
}

emit_machine_receipt() {
    receipt_kind=$1
    receipt_result=$2
    receipt_phase=$3
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$receipt_kind" "$RUN_ID" "$expected" "$candidate" "$metadata_sha" \
        "$expected_file_count" "$receipt_result" "$receipt_phase"
}

probe_mode() {
    [ "$#" -eq 1 ] || fail 64 'probe requires ROOT'
    supplied_root=$1
    validate_pinned_path "$supplied_root"
    ensure_trusted_directory "$PINNED_PARENT" 'publisher parent'
    ensure_trusted_directory "$PINNED_ROOT" 'publisher root'
    create_lock_and_acquire
    manifest="$PINNED_ROOT/manifest.json"
    if ! as_root test -e "$manifest" && ! as_root test -L "$manifest"; then
        printf 'ABSENT\n'
        flock -u 9
        exec 9<&-
        return 0
    fi
    check_trusted_regular_file "$manifest" 'published manifest'
    printf 'PRESENT\n'
    as_root head -c "$((MAX_MANIFEST_BYTES + 1))" -- "$manifest"
    flock -u 9
    exec 9<&-
}

cleanup_prepare() {
    cleanup_status=$?
    trap - EXIT HUP INT TERM
    if [ -n "${MARKER_TMP:-}" ]; then
        as_root rm -f -- "$MARKER_TMP" >/dev/null 2>&1 || true
    fi
    if [ -n "${STATE_TMP:-}" ]; then
        as_root rm -f -- "$STATE_TMP" >/dev/null 2>&1 || true
    fi
    exit "$cleanup_status"
}

prepare_mode() {
    [ "$#" -eq 6 ] || fail 64 'prepare requires ROOT RUN_ID EXPECTED CANDIDATE_SHA METADATA_SHA FILE_COUNT'
    supplied_root=$1
    shift
    validate_identity_args "$@"
    validate_pinned_path "$supplied_root"
    ensure_trusted_directory "$PINNED_PARENT" 'publisher parent'
    ensure_trusted_directory "$PINNED_ROOT" 'publisher root'
    ensure_trusted_directory "$PINNED_ROOT/files" 'publisher files directory'
    ensure_trusted_directory "$PINNED_ROOT/files/artifacts" 'publisher artifacts directory'
    ensure_trusted_directory "$PINNED_ROOT/files/rollback" 'publisher rollback directory'
    MARKER_TMP=
    STATE_TMP=
    trap cleanup_prepare EXIT
    trap 'exit 74' HUP INT TERM
    create_lock_and_acquire
    if as_root test -e "$STATE_PATH" || as_root test -L "$STATE_PATH"; then
        fail 75 'publication run id already has durable state'
    fi
    check_cas "$expected" "$candidate"
    install_channel_marker
    write_publication_state prepared
    validate_pinned_path "$PINNED_ROOT"
    flock -u 9
    exec 9<&-
    trap - EXIT HUP INT TERM
    emit_machine_receipt AMNEZIA_PUBLISH_PREPARE_V1 READY prepared
}

validate_upload_stage() {
    UPLOAD_STAGE="${UPLOAD_PREFIX}${RUN_ID}"
    resolved_upload=$(readlink -m -- "$UPLOAD_STAGE") || fail 64 'unable to resolve upload stage'
    [ "$resolved_upload" = "$UPLOAD_STAGE" ] || fail 64 'upload stage resolves through a symlink'
    test -d "$UPLOAD_STAGE" && ! test -L "$UPLOAD_STAGE" || fail 64 'upload stage is not a real directory'
    upload_safe=$(find "$UPLOAD_STAGE" -maxdepth 0 -uid "$(id -u)" -gid "$(id -g)" ! -perm /0077 -print -quit) \
        || fail 64 'unable to inspect upload stage'
    [ -n "$upload_safe" ] || fail 64 'upload stage has unsafe ownership or mode'
    test -f "$UPLOAD_STAGE/manifest.json" && ! test -L "$UPLOAD_STAGE/manifest.json" \
        || fail 65 'uploaded candidate manifest is not a regular file'
    test -f "$UPLOAD_STAGE/publish.meta" && ! test -L "$UPLOAD_STAGE/publish.meta" \
        || fail 65 'uploaded publication metadata is not a regular file'
    test -d "$UPLOAD_STAGE/files" && ! test -L "$UPLOAD_STAGE/files" \
        || fail 65 'uploaded files tree is not a real directory'
    upload_unsafe=$(find "$UPLOAD_STAGE/files" ! -type d ! -type f -print -quit) \
        || fail 65 'unable to inspect uploaded files tree'
    [ -z "$upload_unsafe" ] || fail 65 'uploaded files tree contains a link or special file'
}

validate_immutable_tree() {
    tree=$1
    description=$2
    check_trusted_directory "$tree" "$description"
    unsafe=$(as_root find "$tree" ! -type d ! -type f -print -quit) \
        || fail 65 "unable to inspect $description"
    [ -z "$unsafe" ] || fail 65 "$description contains a link or special file"
    mutable=$(as_root find "$tree" \( ! -uid "$TRUSTED_UID" -o ! -gid "$TRUSTED_GID" -o -perm /0022 \) \
        -print -quit) || fail 65 "unable to inspect ownership for $description"
    [ -z "$mutable" ] || fail 65 "$description is not immutable"
    unreadable_dir=$(as_root find "$tree" -type d ! -perm -0005 -print -quit) \
        || fail 65 "unable to inspect directory modes for $description"
    [ -z "$unreadable_dir" ] || fail 65 "$description is not HTTP-traversable"
    unreadable_file=$(as_root find "$tree" -type f ! -perm -0004 -print -quit) \
        || fail 65 "unable to inspect file modes for $description"
    [ -z "$unreadable_file" ] || fail 65 "$description is not HTTP-readable"
}

publish_immutable_tree() {
    source_tree=$1
    target_tree=$2
    description=$3
    target_parent=${target_tree%/*}
    check_trusted_directory "$target_parent" "$description parent"
    if as_root test -e "$target_tree" || as_root test -L "$target_tree"; then
        validate_immutable_tree "$target_tree" "$description"
        as_root diff -qr -- "$source_tree" "$target_tree" >/dev/null \
            || fail 65 "$description already exists with different content"
        as_root rm -rf -- "$source_tree" || fail 73 "unable to remove duplicate staged $description"
        return 0
    fi
    as_root mv -T -n -- "$source_tree" "$target_tree" \
        || fail 73 "unable to publish $description"
    if as_root test -e "$source_tree" || as_root test -L "$source_tree"; then
        if as_root test -d "$target_tree" && ! as_root test -L "$target_tree" \
            && as_root diff -qr -- "$source_tree" "$target_tree" >/dev/null; then
            validate_immutable_tree "$target_tree" "$description"
            as_root rm -rf -- "$source_tree" || fail 73 "unable to remove raced staged $description"
        else
            fail 65 "failed to publish $description without overwriting"
        fi
    fi
    validate_immutable_tree "$target_tree" "$description"
    as_root sync -f -- "$target_parent" || fail 74 "unable to persist $description rename"
}

cleanup_commit() {
    cleanup_status=$?
    trap - EXIT HUP INT TERM
    if [ -n "${MANIFEST_TMP:-}" ]; then
        as_root rm -f -- "$MANIFEST_TMP" >/dev/null 2>&1 || true
    fi
    if [ -n "${WORK_ROOT:-}" ]; then
        as_root rm -rf -- "$WORK_ROOT" >/dev/null 2>&1 || true
    fi
    if [ -n "${STATE_TMP:-}" ]; then
        as_root rm -f -- "$STATE_TMP" >/dev/null 2>&1 || true
    fi
    exit "$cleanup_status"
}

commit_mode() {
    [ "$#" -eq 6 ] || fail 64 'commit requires ROOT RUN_ID EXPECTED CANDIDATE_SHA METADATA_SHA FILE_COUNT'
    supplied_root=$1
    shift
    validate_identity_args "$@"
    WORK_ROOT=
    MANIFEST_TMP=
    STATE_TMP=
    trap cleanup_commit EXIT
    trap 'exit 74' HUP INT TERM
    validate_pinned_path "$supplied_root"
    create_lock_and_acquire
    require_channel_marker
    read_publication_state
    state_identity_matches || fail 75 'publication state identity mismatch'
    [ "$state_phase" = prepared ] || fail 75 "publication state rejects commit from phase $state_phase"
    check_cas "$expected" "$candidate"
    write_publication_state committing
    validate_upload_stage
    work_root_candidate="$PINNED_ROOT/files/.publish.$RUN_ID"
    manifest_tmp_candidate="$PINNED_ROOT/.manifest.$RUN_ID"
    if as_root test -e "$work_root_candidate" || as_root test -L "$work_root_candidate" \
        || as_root test -e "$manifest_tmp_candidate" || as_root test -L "$manifest_tmp_candidate"; then
        fail 75 'random publication staging path already exists'
    fi
    WORK_ROOT=$work_root_candidate
    MANIFEST_TMP=$manifest_tmp_candidate

    as_root install -d -o "$TRUSTED_UID" -g "$TRUSTED_GID" -m 0755 -- "$WORK_ROOT" \
        || fail 73 'unable to create root-owned publication quarantine'
    as_root install -d -o "$TRUSTED_UID" -g "$TRUSTED_GID" -m 0755 -- "$WORK_ROOT/control" "$WORK_ROOT/trees" \
        || fail 73 'unable to create root-owned publication quarantine contents'
    CONTROL_META="$WORK_ROOT/control/publish.meta"
    CONTROL_MANIFEST="$WORK_ROOT/control/manifest.json"
    as_root install -o "$TRUSTED_UID" -g "$TRUSTED_GID" -m 0444 -- \
        "$UPLOAD_STAGE/publish.meta" "$CONTROL_META" || fail 73 'unable to snapshot publication metadata'
    as_root install -o "$TRUSTED_UID" -g "$TRUSTED_GID" -m 0444 -- \
        "$UPLOAD_STAGE/manifest.json" "$CONTROL_MANIFEST" || fail 73 'unable to snapshot candidate manifest'
    metadata_size=$(as_root stat -c %s -- "$CONTROL_META") || fail 65 'unable to size publication metadata'
    [ "$metadata_size" -gt 0 ] && [ "$metadata_size" -le "$MAX_METADATA_BYTES" ] \
        || fail 65 'publication metadata is empty or oversized'
    observed_metadata_sha=$(as_root sha256sum -- "$CONTROL_META" | awk '{print $1}')
    [ "$observed_metadata_sha" = "$metadata_sha" ] || fail 65 'publication metadata hash mismatch'
    manifest_size=$(as_root stat -c %s -- "$CONTROL_MANIFEST") || fail 65 'unable to size candidate manifest'
    [ "$manifest_size" -gt 0 ] && [ "$manifest_size" -le "$MAX_MANIFEST_BYTES" ] \
        || fail 65 'candidate manifest is empty or oversized'
    observed_candidate_sha=$(as_root sha256sum -- "$CONTROL_MANIFEST" | awk '{print $1}')
    [ "$observed_candidate_sha" = "$candidate" ] || fail 65 'candidate manifest hash mismatch'

    tab=$(printf '\t')
    exec 8< "$CONTROL_META" || fail 65 'unable to open publication metadata snapshot'
    IFS="$tab" read -r header header_candidate header_version header_schema header_generation header_count header_extra \
        <&8 || fail 65 'unable to read publication metadata header'
    [ "$header" = 'amnezia-bundled-publish-v1' ] || fail 65 'unexpected publication metadata schema'
    [ "$header_candidate" = "$candidate" ] || fail 65 'metadata candidate hash does not match manifest'
    is_version "$header_version" || fail 65 'metadata has a non-canonical signed version'
    case "$header_schema" in
        1) [ "$header_generation" = 0 ] || fail 65 'schema-1 metadata has a policy generation' ;;
        2) is_generation "$header_generation" || fail 65 'schema-2 metadata has an invalid generation' ;;
        *) fail 65 'metadata has an unsupported signed payload schema' ;;
    esac
    [ -z "$header_extra" ] || fail 65 'metadata header has unexpected fields'
    [ "$header_count" = "$expected_file_count" ] || fail 65 'metadata file count argument mismatch'

    record_count=0
    while IFS="$tab" read -r kind relative_path digest expected_size extra_one extra_two; do
        [ -n "$kind" ] || fail 65 'publication metadata contains a blank record'
        [ -z "$extra_one" ] && [ -z "$extra_two" ] || fail 65 'publication metadata record has unexpected fields'
        is_sha256 "$digest" || fail 65 'publication metadata contains an invalid file hash'
        is_positive_decimal "$expected_size" || fail 65 'publication metadata contains an invalid file size'
        printf '%s' "$relative_path" | grep -q '[[:cntrl:]]' \
            && fail 65 'publication metadata path contains a control character'
        source_file="$UPLOAD_STAGE/$relative_path"
        test -f "$source_file" && ! test -L "$source_file" || fail 65 'signed uploaded file is missing or linked'
        actual_size=$(stat -c %s -- "$source_file") || fail 65 'unable to size signed uploaded file'
        [ "$actual_size" = "$expected_size" ] || fail 65 'signed uploaded file size mismatch'
        actual_digest=$(sha256sum -- "$source_file" | awk '{print $1}')
        [ "$actual_digest" = "$digest" ] || fail 65 'signed uploaded file hash mismatch'

        case "$kind" in
            A)
                prefix="files/artifacts/$digest/"
                case "$relative_path" in "$prefix"*) file_name=${relative_path#"$prefix"} ;; *) fail 65 'invalid artifact path' ;; esac
                [ -n "$file_name" ] && [ "$file_name" != . ] && [ "$file_name" != .. ] \
                    && [ "${file_name#*/}" = "$file_name" ] || fail 65 'invalid artifact filename'
                destination_directory="$WORK_ROOT/trees/artifacts/$digest"
                destination_file="$destination_directory/$file_name"
                ;;
            R)
                [ "$header_schema" = 2 ] || fail 65 'schema-1 metadata contains rollback files'
                prefix='files/rollback/'
                case "$relative_path" in "$prefix"*) rollback_tail=${relative_path#"$prefix"} ;; *) fail 65 'invalid rollback path' ;; esac
                rollback_generation=${rollback_tail%%/*}
                rollback_tail_after_generation=${rollback_tail#*/}
                [ "$rollback_tail_after_generation" != "$rollback_tail" ] || fail 65 'invalid rollback path generation'
                rollback_version=${rollback_tail_after_generation%%/*}
                file_name=${rollback_tail_after_generation#*/}
                is_generation "$rollback_generation" || fail 65 'invalid rollback generation path'
                [ "$rollback_generation" = "$header_generation" ] || fail 65 'rollback path generation differs from signed policy'
                is_version "$rollback_version" || fail 65 'invalid rollback version path'
                [ -n "$file_name" ] && [ "$file_name" != "$rollback_tail_after_generation" ] \
                    && [ "$file_name" != . ] && [ "$file_name" != .. ] \
                    && [ "${file_name#*/}" = "$file_name" ] || fail 65 'invalid rollback filename'
                destination_directory="$WORK_ROOT/trees/rollback/$rollback_generation/$rollback_version"
                destination_file="$destination_directory/$file_name"
                ;;
            *)
                fail 65 'unknown publication metadata record kind'
                ;;
        esac
        if as_root test -e "$destination_file" || as_root test -L "$destination_file"; then
            fail 65 'publication metadata reuses a destination path'
        fi
        as_root install -d -o "$TRUSTED_UID" -g "$TRUSTED_GID" -m 0700 -- "$destination_directory" \
            || fail 73 'unable to create sealed publication directory'
        as_root install -o "$TRUSTED_UID" -g "$TRUSTED_GID" -m 0444 -- "$source_file" "$destination_file" \
            || fail 73 'unable to seal signed publication file'
        sealed_size=$(as_root stat -c %s -- "$destination_file") || fail 65 'unable to size sealed publication file'
        [ "$sealed_size" = "$expected_size" ] || fail 65 'sealed publication file size mismatch'
        sealed_digest=$(as_root sha256sum -- "$destination_file" | awk '{print $1}')
        [ "$sealed_digest" = "$digest" ] || fail 65 'sealed publication file hash mismatch'
        record_count=$((record_count + 1))
        [ "$record_count" -le "$MAX_FILES" ] || fail 65 'publication metadata exceeds file limit'
    done <&8
    exec 8<&-

    [ "$record_count" = "$expected_file_count" ] || fail 65 'publication metadata record count mismatch'
    actual_file_count=$(find "$UPLOAD_STAGE/files" -type f -printf . | wc -c | tr -d ' ')
    [ "$actual_file_count" = "$record_count" ] || fail 65 'uploaded files tree contains unsigned files'
    as_root find "$WORK_ROOT/trees" -type d -exec chmod 0755 {} + || fail 73 'unable to make sealed trees traversable'
    as_root sync -f -- "$WORK_ROOT" || fail 74 'unable to persist sealed publication trees'

    as_root install -o "$TRUSTED_UID" -g "$TRUSTED_GID" -m 0444 -- "$CONTROL_MANIFEST" "$MANIFEST_TMP" \
        || fail 73 'unable to create unique manifest staging file'
    installed_size=$(as_root stat -c %s -- "$MANIFEST_TMP") || fail 65 'unable to size manifest staging file'
    [ "$installed_size" = "$manifest_size" ] || fail 65 'manifest staging size mismatch'
    installed_sha=$(as_root sha256sum -- "$MANIFEST_TMP" | awk '{print $1}')
    [ "$installed_sha" = "$candidate" ] || fail 65 'manifest staging hash mismatch'
    as_root sync -f -- "$MANIFEST_TMP" || fail 74 'unable to persist manifest staging file'

    if as_root test -d "$WORK_ROOT/trees/artifacts"; then
        for source_tree in "$WORK_ROOT/trees/artifacts"/*; do
            as_root test -d "$source_tree" || continue
            digest=${source_tree##*/}
            is_sha256 "$digest" || fail 65 'sealed artifact group has an invalid digest'
            publish_immutable_tree "$source_tree" "$PINNED_ROOT/files/artifacts/$digest" "artifact $digest"
        done
    fi
    if as_root test -d "$WORK_ROOT/trees/rollback"; then
        for source_tree in "$WORK_ROOT/trees/rollback"/*; do
            as_root test -d "$source_tree" || continue
            generation=${source_tree##*/}
            is_generation "$generation" || fail 65 'sealed rollback group has an invalid generation'
            publish_immutable_tree "$source_tree" "$PINNED_ROOT/files/rollback/$generation" "rollback generation $generation"
        done
    fi

    check_cas "$expected" "$candidate"
    if [ "$CAS_ALREADY_CURRENT" = 1 ]; then
        as_root rm -f -- "$MANIFEST_TMP" || fail 73 'unable to remove duplicate manifest staging file'
        MANIFEST_TMP=
    else
        as_root mv -fT -- "$MANIFEST_TMP" "$PINNED_ROOT/manifest.json" \
            || fail 73 'unable to atomically switch candidate manifest'
        MANIFEST_TMP=
        as_root sync -f -- "$PINNED_ROOT" || fail 74 'unable to persist manifest switch'
    fi
    final_sha=$(as_root sha256sum -- "$PINNED_ROOT/manifest.json" | awk '{print $1}')
    [ "$final_sha" = "$candidate" ] || fail 65 'published manifest does not match candidate hash'
    validate_pinned_path "$PINNED_ROOT"
    write_publication_state committed
    as_root rm -rf -- "$WORK_ROOT" \
        || printf '%s\n' 'warning: unable to clean committed publication work tree' >&2
    WORK_ROOT=
    # Keep the unprivileged upload stage until the caller verifies the newly
    # published endpoint.  It contains the publisher itself and, when there
    # was a previous manifest, the sealed rollback input used by rollback.
    UPLOAD_STAGE=
    flock -u 9 || printf '%s\n' 'warning: unable to explicitly release publisher lock' >&2
    exec 9<&-
    trap - EXIT HUP INT TERM
    emit_machine_receipt AMNEZIA_PUBLISH_COMMIT_V1 APPLIED committed
}

reconcile_mode() {
    [ "$#" -eq 6 ] || fail 64 'reconcile requires ROOT RUN_ID EXPECTED CANDIDATE_SHA METADATA_SHA FILE_COUNT'
    supplied_root=$1
    shift
    validate_identity_args "$@"
    validate_pinned_path "$supplied_root"
    create_lock_and_acquire
    read_publication_state
    if [ "$STATE_PRESENT" != 1 ]; then
        emit_machine_receipt AMNEZIA_PUBLISH_RECONCILE_V1 INDETERMINATE missing
    elif ! state_identity_matches; then
        emit_machine_receipt AMNEZIA_PUBLISH_RECONCILE_V1 INDETERMINATE identity_mismatch
    else
        current_manifest_sha
        case "$state_phase" in
            committed|finalizing|finalized)
                if [ "$CURRENT_SHA" = "$candidate" ]; then
                    emit_machine_receipt AMNEZIA_PUBLISH_RECONCILE_V1 APPLIED "$state_phase"
                else
                    emit_machine_receipt AMNEZIA_PUBLISH_RECONCILE_V1 INDETERMINATE manifest_mismatch
                fi
                ;;
            prepared)
                if [ "$CURRENT_SHA" = "$expected" ]; then
                    write_publication_state aborted
                    emit_machine_receipt AMNEZIA_PUBLISH_RECONCILE_V1 NOT_APPLIED aborted
                else
                    emit_machine_receipt AMNEZIA_PUBLISH_RECONCILE_V1 INDETERMINATE manifest_mismatch
                fi
                ;;
            committing)
                if [ "$CURRENT_SHA" = "$candidate" ]; then
                    write_publication_state committed
                    emit_machine_receipt AMNEZIA_PUBLISH_RECONCILE_V1 APPLIED committed
                elif [ "$CURRENT_SHA" = "$expected" ]; then
                    write_publication_state aborted
                    emit_machine_receipt AMNEZIA_PUBLISH_RECONCILE_V1 NOT_APPLIED aborted
                else
                    emit_machine_receipt AMNEZIA_PUBLISH_RECONCILE_V1 INDETERMINATE manifest_mismatch
                fi
                ;;
            aborted|abort_finalizing|finalized_aborted)
                if [ "$CURRENT_SHA" = "$expected" ]; then
                    emit_machine_receipt AMNEZIA_PUBLISH_RECONCILE_V1 NOT_APPLIED "$state_phase"
                else
                    emit_machine_receipt AMNEZIA_PUBLISH_RECONCILE_V1 INDETERMINATE manifest_mismatch
                fi
                ;;
            *)
                emit_machine_receipt AMNEZIA_PUBLISH_RECONCILE_V1 INDETERMINATE "$state_phase"
                ;;
        esac
    fi
    flock -u 9
    exec 9<&-
}

cleanup_upload_stage_durably() {
    validate_upload_stage
    upload_parent=${UPLOAD_STAGE%/*}
    rm -rf -- "$UPLOAD_STAGE" || fail 73 'unable to clean publication upload stage'
    test ! -e "$UPLOAD_STAGE" && test ! -L "$UPLOAD_STAGE" \
        || fail 73 'publication upload stage still exists after cleanup'
    sync -f -- "$upload_parent" || fail 74 'unable to persist publication upload stage cleanup'
}

cleanup_root_staging_durably() {
    work_root="$PINNED_ROOT/files/.publish.$RUN_ID"
    manifest_tmp="$PINNED_ROOT/.manifest.$RUN_ID"
    state_tmp="$PINNED_ROOT/.publish-state-tmp.$RUN_ID"
    marker_tmp="$PINNED_ROOT/.channel-marker.$RUN_ID"
    if as_root test -e "$work_root" || as_root test -L "$work_root"; then
        as_root rm -rf -- "$work_root" || fail 73 'unable to clean publication work tree'
    fi
    for staging_file in "$manifest_tmp" "$state_tmp" "$marker_tmp"; do
        if as_root test -e "$staging_file" || as_root test -L "$staging_file"; then
            as_root rm -f -- "$staging_file" || fail 73 'unable to clean publication staging file'
        fi
    done
    as_root sync -f -- "$PINNED_ROOT/files" \
        || fail 74 'unable to persist publication work tree cleanup'
    as_root sync -f -- "$PINNED_ROOT" \
        || fail 74 'unable to persist publication staging cleanup'
}

cleanup_transaction_staging_durably() {
    cleanup_root_staging_durably
    UPLOAD_STAGE="${UPLOAD_PREFIX}${RUN_ID}"
    if test -e "$UPLOAD_STAGE" || test -L "$UPLOAD_STAGE"; then
        cleanup_upload_stage_durably
    fi
}

finalize_mode() {
    [ "$#" -eq 6 ] || fail 64 'finalize requires ROOT RUN_ID EXPECTED CANDIDATE_SHA METADATA_SHA FILE_COUNT'
    supplied_root=$1
    shift
    validate_identity_args "$@"
    validate_pinned_path "$supplied_root"
    create_lock_and_acquire
    require_channel_marker
    read_publication_state
    state_identity_matches || fail 75 'publication state identity mismatch during finalize'
    current_manifest_sha
    [ "$CURRENT_SHA" = "$candidate" ] \
        || fail 75 "manifest CAS conflict during finalize: expected $candidate, found $CURRENT_SHA"
    case "$state_phase" in
        finalized)
            cleanup_transaction_staging_durably
            ;;
        committed)
            write_publication_state finalizing
            cleanup_transaction_staging_durably
            write_publication_state finalized
            ;;
        finalizing)
            cleanup_transaction_staging_durably
            write_publication_state finalized
            ;;
        *) fail 75 "publication state rejects finalize from phase $state_phase" ;;
    esac
    flock -u 9
    exec 9<&-
    emit_machine_receipt AMNEZIA_PUBLISH_FINALIZE_V1 APPLIED finalized
}

finalize_abort_mode() {
    [ "$#" -eq 6 ] || fail 64 'finalize-abort requires ROOT RUN_ID EXPECTED CANDIDATE_SHA METADATA_SHA FILE_COUNT'
    supplied_root=$1
    shift
    validate_identity_args "$@"
    validate_pinned_path "$supplied_root"
    create_lock_and_acquire
    require_channel_marker
    read_publication_state
    state_identity_matches || fail 75 'publication state identity mismatch during abort finalize'
    current_manifest_sha
    [ "$CURRENT_SHA" = "$expected" ] \
        || fail 75 "manifest CAS conflict during abort finalize: expected $expected, found $CURRENT_SHA"
    case "$state_phase" in
        finalized_aborted)
            cleanup_transaction_staging_durably
            ;;
        aborted)
            write_publication_state abort_finalizing
            cleanup_transaction_staging_durably
            write_publication_state finalized_aborted
            ;;
        abort_finalizing)
            cleanup_transaction_staging_durably
            write_publication_state finalized_aborted
            ;;
        *) fail 75 "publication state rejects abort finalize from phase $state_phase" ;;
    esac
    flock -u 9
    exec 9<&-
    emit_machine_receipt AMNEZIA_PUBLISH_FINALIZE_ABORT_V1 NOT_APPLIED finalized_aborted
}

cleanup_rollback() {
    cleanup_status=$?
    trap - EXIT HUP INT TERM
    if [ -n "${ROLLBACK_TMP:-}" ]; then
        as_root rm -f -- "$ROLLBACK_TMP" >/dev/null 2>&1 || true
    fi
    if [ -n "${STATE_TMP:-}" ]; then
        as_root rm -f -- "$STATE_TMP" >/dev/null 2>&1 || true
    fi
    exit "$cleanup_status"
}

rollback_mode() {
    [ "$#" -eq 6 ] || fail 64 'rollback requires ROOT RUN_ID EXPECTED CANDIDATE_SHA METADATA_SHA FILE_COUNT'
    supplied_root=$1
    shift
    validate_identity_args "$@"
    validate_pinned_path "$supplied_root"
    ROLLBACK_TMP=
    STATE_TMP=
    trap cleanup_rollback EXIT
    trap 'exit 74' HUP INT TERM
    create_lock_and_acquire
    require_channel_marker
    read_publication_state
    state_identity_matches || fail 75 'publication state identity mismatch during rollback'
    [ "$state_phase" = committed ] || fail 75 "publication state rejects rollback from phase $state_phase"
    current_manifest_sha
    [ "$CURRENT_SHA" = "$candidate" ] \
        || fail 75 "manifest CAS conflict during rollback: expected $candidate, found $CURRENT_SHA"
    write_publication_state rollback_prepared
    validate_upload_stage

    if [ "$expected" != absent ]; then
        previous_source="$UPLOAD_STAGE/previous-manifest.json"
        test -f "$previous_source" && ! test -L "$previous_source" \
            || fail 65 'previous manifest rollback input is missing or linked'
        previous_size=$(stat -c %s -- "$previous_source") \
            || fail 65 'unable to size previous manifest rollback input'
        [ "$previous_size" -gt 0 ] && [ "$previous_size" -le "$MAX_MANIFEST_BYTES" ] \
            || fail 65 'previous manifest rollback input is empty or oversized'
        previous_observed=$(sha256sum -- "$previous_source" | awk '{print $1}')
        [ "$previous_observed" = "$expected" ] \
            || fail 65 'previous manifest rollback input hash mismatch'
    fi

    write_publication_state rolling_back
    current_manifest_sha
    [ "$CURRENT_SHA" = "$candidate" ] \
        || fail 75 "manifest CAS conflict before rollback switch: expected $candidate, found $CURRENT_SHA"
    if [ "$expected" = absent ]; then
        as_root rm -f -- "$PINNED_ROOT/manifest.json" \
            || fail 73 'unable to remove failed candidate manifest'
        as_root sync -f -- "$PINNED_ROOT" \
            || fail 74 'unable to persist failed candidate removal'
    else
        ROLLBACK_TMP="$PINNED_ROOT/.manifest.$RUN_ID"
        if as_root test -e "$ROLLBACK_TMP" || as_root test -L "$ROLLBACK_TMP"; then
            fail 75 'rollback manifest staging path already exists'
        fi
        as_root install -o "$TRUSTED_UID" -g "$TRUSTED_GID" -m 0444 -- \
            "$previous_source" "$ROLLBACK_TMP" \
            || fail 73 'unable to create previous manifest staging file'
        rollback_size=$(as_root stat -c %s -- "$ROLLBACK_TMP") \
            || fail 65 'unable to size previous manifest staging file'
        [ "$rollback_size" = "$previous_size" ] \
            || fail 65 'previous manifest staging size mismatch'
        rollback_sha=$(as_root sha256sum -- "$ROLLBACK_TMP" | awk '{print $1}')
        [ "$rollback_sha" = "$expected" ] \
            || fail 65 'previous manifest staging hash mismatch'
        as_root sync -f -- "$ROLLBACK_TMP" \
            || fail 74 'unable to persist previous manifest staging file'
        as_root mv -fT -- "$ROLLBACK_TMP" "$PINNED_ROOT/manifest.json" \
            || fail 73 'unable to atomically restore previous manifest'
        ROLLBACK_TMP=
        as_root sync -f -- "$PINNED_ROOT" \
            || fail 74 'unable to persist previous manifest restore'
    fi
    current_manifest_sha
    [ "$CURRENT_SHA" = "$expected" ] || fail 65 'restored manifest does not match previous hash'
    write_publication_state rolled_back
    flock -u 9
    exec 9<&-
    trap - EXIT HUP INT TERM
    emit_machine_receipt AMNEZIA_PUBLISH_ROLLBACK_V1 APPLIED rolled_back
}

reconcile_rollback_mode() {
    [ "$#" -eq 6 ] || fail 64 'reconcile-rollback requires ROOT RUN_ID EXPECTED CANDIDATE_SHA METADATA_SHA FILE_COUNT'
    supplied_root=$1
    shift
    validate_identity_args "$@"
    validate_pinned_path "$supplied_root"
    create_lock_and_acquire
    read_publication_state
    if [ "$STATE_PRESENT" != 1 ]; then
        emit_machine_receipt AMNEZIA_PUBLISH_RECONCILE_ROLLBACK_V1 INDETERMINATE missing
    elif ! state_identity_matches; then
        emit_machine_receipt AMNEZIA_PUBLISH_RECONCILE_ROLLBACK_V1 INDETERMINATE identity_mismatch
    else
        current_manifest_sha
        case "$state_phase" in
            rolled_back|rollback_finalizing|rollback_finalized)
                if [ "$CURRENT_SHA" = "$expected" ]; then
                    emit_machine_receipt AMNEZIA_PUBLISH_RECONCILE_ROLLBACK_V1 APPLIED "$state_phase"
                else
                    emit_machine_receipt AMNEZIA_PUBLISH_RECONCILE_ROLLBACK_V1 INDETERMINATE manifest_mismatch
                fi
                ;;
            committed|rollback_prepared)
                if [ "$CURRENT_SHA" = "$candidate" ]; then
                    write_publication_state rollback_aborted
                    emit_machine_receipt AMNEZIA_PUBLISH_RECONCILE_ROLLBACK_V1 NOT_APPLIED rollback_aborted
                else
                    emit_machine_receipt AMNEZIA_PUBLISH_RECONCILE_ROLLBACK_V1 INDETERMINATE manifest_mismatch
                fi
                ;;
            rolling_back)
                if [ "$CURRENT_SHA" = "$expected" ]; then
                    write_publication_state rolled_back
                    emit_machine_receipt AMNEZIA_PUBLISH_RECONCILE_ROLLBACK_V1 APPLIED rolled_back
                elif [ "$CURRENT_SHA" = "$candidate" ]; then
                    write_publication_state rollback_aborted
                    emit_machine_receipt AMNEZIA_PUBLISH_RECONCILE_ROLLBACK_V1 NOT_APPLIED rollback_aborted
                else
                    emit_machine_receipt AMNEZIA_PUBLISH_RECONCILE_ROLLBACK_V1 INDETERMINATE manifest_mismatch
                fi
                ;;
            rollback_aborted)
                if [ "$CURRENT_SHA" = "$candidate" ]; then
                    emit_machine_receipt AMNEZIA_PUBLISH_RECONCILE_ROLLBACK_V1 NOT_APPLIED rollback_aborted
                else
                    emit_machine_receipt AMNEZIA_PUBLISH_RECONCILE_ROLLBACK_V1 INDETERMINATE manifest_mismatch
                fi
                ;;
            *)
                emit_machine_receipt AMNEZIA_PUBLISH_RECONCILE_ROLLBACK_V1 INDETERMINATE "$state_phase"
                ;;
        esac
    fi
    flock -u 9
    exec 9<&-
}

finalize_rollback_mode() {
    [ "$#" -eq 6 ] || fail 64 'finalize-rollback requires ROOT RUN_ID EXPECTED CANDIDATE_SHA METADATA_SHA FILE_COUNT'
    supplied_root=$1
    shift
    validate_identity_args "$@"
    validate_pinned_path "$supplied_root"
    create_lock_and_acquire
    require_channel_marker
    read_publication_state
    state_identity_matches || fail 75 'publication state identity mismatch during rollback finalize'
    current_manifest_sha
    [ "$CURRENT_SHA" = "$expected" ] \
        || fail 75 "manifest CAS conflict during rollback finalize: expected $expected, found $CURRENT_SHA"
    case "$state_phase" in
        rollback_finalized)
            cleanup_transaction_staging_durably
            ;;
        rolled_back)
            write_publication_state rollback_finalizing
            cleanup_transaction_staging_durably
            write_publication_state rollback_finalized
            ;;
        rollback_finalizing)
            cleanup_transaction_staging_durably
            write_publication_state rollback_finalized
            ;;
        *) fail 75 "publication state rejects rollback finalize from phase $state_phase" ;;
    esac
    flock -u 9
    exec 9<&-
    emit_machine_receipt AMNEZIA_PUBLISH_FINALIZE_ROLLBACK_V1 APPLIED rollback_finalized
}

require_tools
mode=${1:-}
[ "$#" -gt 0 ] && shift
case "$mode" in
    probe) probe_mode "$@" ;;
    prepare) prepare_mode "$@" ;;
    commit) commit_mode "$@" ;;
    reconcile) reconcile_mode "$@" ;;
    finalize) finalize_mode "$@" ;;
    finalize-abort) finalize_abort_mode "$@" ;;
    rollback) rollback_mode "$@" ;;
    reconcile-rollback) reconcile_rollback_mode "$@" ;;
    finalize-rollback) finalize_rollback_mode "$@" ;;
    *) fail 64 'publisher mode is invalid' ;;
esac
