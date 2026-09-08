#!/usr/bin/env bash
set -Eeuo pipefail

# Host bootstrap for the dedicated WSL2 Ubuntu lab. This script has no default
# mutating mode: --check is read-only and --install is the explicit apt/user
# setup requested by an operator. It never starts QEMU or changes host network
# state.

readonly LAB_USER="amnezia-lab"
readonly LAB_GROUP="amnezia-lab"
readonly LAB_ROOT="/var/lib/amnezia-release-lab"
readonly REQUIRED_PACKAGES=(
  qemu-system-x86 qemu-utils qemu-system-gui ovmf swtpm swtpm-tools
  cloud-image-utils genisoimage openjdk-17-jdk-headless unzip ca-certificates curl gpgv jq xz-utils python3
)

usage() {
  cat <<'EOF'
Usage: bootstrap_wsl.sh [--check | --install]

  --check    inspect WSL/KVM/tool prerequisites without changing the host
  --install  apt install prerequisites and create the dedicated lab user/root

Run --install as root (for example through an operator-approved wsl -u root
command). QEMU must later be run as amnezia-lab, never as root.
EOF
}

die() { printf 'bootstrap-wsl: ERROR: %s\n' "$*" >&2; exit 1; }
log() { printf 'bootstrap-wsl: %s\n' "$*"; }

check_wsl() {
  [[ -r /proc/version ]] || die '/proc/version is unavailable'
  grep -qi microsoft /proc/version || die 'this is not a WSL kernel'
  [[ -e /dev/kvm ]] || die '/dev/kvm is unavailable; enable virtualization/KVM for this WSL VM'
  [[ -r /dev/kvm && -w /dev/kvm ]] || die '/dev/kvm is not readable/writable by root'
}

check_tools() {
  local missing=()
  local tool
  for tool in qemu-system-x86_64 qemu-img cloud-localds swtpm gpgv sha256sum; do
    [[ -x "/usr/bin/$tool" ]] || missing+=("/usr/bin/$tool")
    if [[ -e "/usr/bin/$tool" && "$(realpath -e "/usr/bin/$tool" 2>/dev/null || true)" != "/usr/bin/$tool" ]]; then
      die "refusing non-canonical executable: /usr/bin/$tool"
    fi
  done
  for tool in genisoimage java unzip; do
    [[ -x "/usr/bin/$tool" ]] || missing+=("/usr/bin/$tool")
  done
  if ((${#missing[@]})); then
    log "missing tools: ${missing[*]}"
    return 1
  fi
}

preflight_paths() {
  local path
  for path in /var /var/lib /home "$LAB_ROOT" "/home/$LAB_USER" "$LAB_ROOT/images" "$LAB_ROOT/guests" "$LAB_ROOT/runs" "$LAB_ROOT/locks"; do
    if [[ -L "$path" ]]; then
      die "refusing symlink path: $path"
    fi
    if [[ -e "$path" && "$(realpath -e "$path" 2>/dev/null || true)" != "$path" ]]; then
      die "refusing non-canonical path: $path"
    fi
  done
  if [[ -e "$LAB_ROOT" ]]; then
    [[ -d "$LAB_ROOT" ]] || die "state root exists but is not a directory: $LAB_ROOT"
    [[ -f "$LAB_ROOT/.amnezia-lab-root" ]] || die "existing state root has no ownership marker: $LAB_ROOT"
    id "$LAB_USER" >/dev/null 2>&1 || die "existing state root cannot be adopted before user $LAB_USER exists"
    [[ "$(stat -c %u "$LAB_ROOT")" == "$(id -u "$LAB_USER")" ]] || die "existing state root is not owned by $LAB_USER"
    local child
    for child in "$LAB_ROOT/images" "$LAB_ROOT/guests" "$LAB_ROOT/runs" "$LAB_ROOT/locks"; do
      if [[ -e "$child" ]]; then
        [[ -d "$child" ]] || die "state child exists but is not a directory: $child"
        [[ "$(stat -c %u "$child")" == "$(id -u "$LAB_USER")" ]] || die "existing state child is not owned by $LAB_USER: $child"
      fi
    done
  fi
  if [[ -e "/home/$LAB_USER" && -x "$(command -v stat)" ]]; then
    [[ "$(stat -c %F "/home/$LAB_USER")" == directory ]] || die "lab home exists but is not a directory"
    if id "$LAB_USER" >/dev/null 2>&1; then
      [[ "$(stat -c %u "/home/$LAB_USER")" == "$(id -u "$LAB_USER")" ]] || die "lab home is not owned by $LAB_USER"
    else
      die "existing lab home cannot be adopted before user $LAB_USER exists"
    fi
  fi
}

check_user_and_storage() {
  id "$LAB_USER" >/dev/null 2>&1 || { log "missing user: $LAB_USER"; return 1; }
  getent group kvm >/dev/null || { log 'missing group: kvm'; return 1; }
  id -nG "$LAB_USER" | tr ' ' '\n' | grep -qx kvm || { log "$LAB_USER is not in kvm"; return 1; }
  [[ -d "$LAB_ROOT" ]] || { log "missing state root: $LAB_ROOT"; return 1; }
  [[ -f "$LAB_ROOT/.amnezia-lab-root" ]] || { log "missing state root marker: $LAB_ROOT/.amnezia-lab-root"; return 1; }
  [[ "$(stat -c %u "$LAB_ROOT/.amnezia-lab-root")" == "$(id -u "$LAB_USER")" ]] || die 'root marker is not owned by lab user'
  grep -qx "owner=$LAB_USER" "$LAB_ROOT/.amnezia-lab-root" || die 'root marker owner identity mismatch'
  [[ "$(stat -c %F "$LAB_ROOT" 2>/dev/null || true)" == directory ]] || return 1
  local mode="$(stat -c %a "$LAB_ROOT" 2>/dev/null || true)"
  [[ "$mode" =~ ^[0-7]{3,4}$ ]] || die "cannot inspect permissions on $LAB_ROOT"
  local bits="${mode: -3}"
  (( (8#$bits & 022) == 0 )) || die "$LAB_ROOT is writable by group/others"
}

check_mode() {
  check_wsl
  if check_tools; then log 'all required executables are present'; else log 'run --install to install missing packages'; fi
  if check_user_and_storage; then log "dedicated user/storage ready: $LAB_USER:$LAB_GROUP at $LAB_ROOT"; else log 'dedicated user/storage is not ready'; fi
  log "KVM: $(stat -c '%A %U:%G' /dev/kvm)"
}

install_mode() {
  [[ "$EUID" -eq 0 ]] || die '--install must run as root'
  check_wsl
  preflight_paths
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install --yes --no-install-recommends "${REQUIRED_PACKAGES[@]}"

  getent group "$LAB_GROUP" >/dev/null || groupadd --system "$LAB_GROUP"
  id "$LAB_USER" >/dev/null 2>&1 || useradd --system --gid "$LAB_GROUP" --create-home --home-dir "/home/$LAB_USER" --shell /usr/sbin/nologin "$LAB_USER"
  usermod --append --groups kvm "$LAB_USER"
  install -d -o "$LAB_USER" -g "$LAB_GROUP" -m 0750 "$LAB_ROOT"
  install -d -o "$LAB_USER" -g "$LAB_GROUP" -m 0750 "$LAB_ROOT/images" "$LAB_ROOT/guests" "$LAB_ROOT/runs" "$LAB_ROOT/locks"
  # Make the ownership explicit even when an existing directory was retained.
  chown "$LAB_USER:$LAB_GROUP" "$LAB_ROOT" "$LAB_ROOT/images" "$LAB_ROOT/guests" "$LAB_ROOT/runs" "$LAB_ROOT/locks"
  if [[ ! -e "$LAB_ROOT/.amnezia-lab-root" ]]; then
    install -o "$LAB_USER" -g "$LAB_GROUP" -m 0640 /dev/null "$LAB_ROOT/.amnezia-lab-root"
    printf 'owner=%s\nuid=%s\n' "$LAB_USER" "$(id -u "$LAB_USER")" > "$LAB_ROOT/.amnezia-lab-root"
  fi
  [[ "$(stat -c %u "$LAB_ROOT/.amnezia-lab-root")" == "$(id -u "$LAB_USER")" ]] || die 'root marker ownership mismatch'
  check_tools || die 'installation completed but a required executable is still missing'
  check_user_and_storage || die 'installation completed but user/storage checks failed'
  log "ready; run QEMU as $LAB_USER and keep all state under $LAB_ROOT"
}

main() {
  [[ $# -eq 1 ]] || { usage; exit 2; }
  case "$1" in
    --check) check_mode ;;
    --install) install_mode ;;
    -h|--help) usage ;;
    *) usage >&2; exit 2 ;;
  esac
}
main "$@"
