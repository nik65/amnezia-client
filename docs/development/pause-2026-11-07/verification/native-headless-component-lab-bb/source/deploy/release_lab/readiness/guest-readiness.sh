#!/usr/bin/env bash
set -Eeuo pipefail

# Run inside a guest. This script only reads guest state and writes a receipt;
# it does not repair services, alter routes, or start an installer.
PROFILE=''
ARTIFACT=''
SEALED=0
die() { printf 'guest-readiness: ERROR: %s\n' "$*" >&2; exit 1; }
usage() { cat <<'EOF'
Usage: guest-readiness.sh --profile PROFILE --artifact FILE [--sealed]
Profiles: linux-headless, linux-gui, server-router, windows11 (Linux only).
--sealed asserts that the controller has removed WAN before candidate tests.
EOF
}
while (($#)); do
  case "$1" in
    --profile) PROFILE="${2:?}"; shift 2 ;;
    --artifact) ARTIFACT="${2:?}"; shift 2 ;;
    --sealed) SEALED=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done
[[ "$PROFILE" =~ ^(linux-headless|linux-headless-x64|linux-gui|linux-x64-gui|server-router)$ ]] || die 'this runner supports Linux guests only; use QGA checks for Windows'
[[ -n "$ARTIFACT" && "$ARTIFACT" = /* ]] || die '--artifact must be an absolute path'
command -v python3 >/dev/null || die 'python3 is required'

checks='[]'
add_check() {
  local name="$1" ok="$2" detail="$3"
  checks="$(python3 - "$checks" "$name" "$ok" "$detail" <<'PY'
import json,sys
items=json.loads(sys.argv[1]); items.append({'name':sys.argv[2], 'ok':sys.argv[3]=='true', 'detail':sys.argv[4]}); print(json.dumps(items,separators=(',',':')))
PY
)"
}
overall=true
if [[ -r /var/lib/amnezia-lab/READY ]]; then add_check guest_marker true /var/lib/amnezia-lab/READY; else add_check guest_marker false 'missing /var/lib/amnezia-lab/READY'; overall=false; fi
if [[ -r /etc/amnezia-lab/profile ]] && grep -q "profile=$PROFILE" /etc/amnezia-lab/profile; then add_check profile true /etc/amnezia-lab/profile; else add_check profile false 'profile marker mismatch'; overall=false; fi
if systemctl is-active --quiet qemu-guest-agent.service; then add_check qemu_guest_agent true active; else add_check qemu_guest_agent false inactive; overall=false; fi
if command -v cloud-init >/dev/null 2>&1 && cloud-init status --wait >/dev/null 2>&1; then add_check cloud_init true done; else add_check cloud_init false 'cloud-init is not done or is unavailable'; overall=false; fi
if grep -q 'candidate_credentials=absent' /var/lib/amnezia-lab/READY 2>/dev/null; then add_check candidate_credentials true absent; else add_check candidate_credentials false 'candidate credentials marker missing'; overall=false; fi
if ((SEALED)); then
  if ip route show default 2>/dev/null | grep -q .; then add_check wan_route false 'default route remains after seal'; overall=false; else add_check wan_route true 'no default route'; fi
else
  add_check wan_route true 'not evaluated before seal'
fi
mkdir -p "$(dirname -- "$ARTIFACT")"
python3 - "$ARTIFACT" "$PROFILE" "$overall" "$SEALED" "$checks" <<'PY'
import json,sys,datetime,os
path,profile,overall,sealed,checks=sys.argv[1:]
receipt={'schema':1,'profile':profile,'timestamp_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'sealed':sealed=='1','ready':overall=='true','checks':json.loads(checks)}
tmp=path+'.part'
with open(tmp,'w',encoding='utf-8') as fh: json.dump(receipt,fh,indent=2); fh.write('\n')
os.replace(tmp,path)
print(json.dumps(receipt,separators=(',',':')))
if not receipt['ready']: raise SystemExit(1)
PY
