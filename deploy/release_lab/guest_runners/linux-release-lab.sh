#!/bin/sh
set -eu

action=${1:?action}; profile=${2:?profile}; shift 2
run_id=''; expected_version=''; expected_sha256=''; artifact_path=''; receipt_path=''; provisioning_path=''
public_key=''; key_sha256=''; package_manifest_sha256=''; checksums_sha256=''; signed_manifest_sha256=''; verified_receipt=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --run-id) run_id=${2:?}; shift 2;;
    --expected-version) expected_version=${2:?}; shift 2;;
    --expected-sha256) expected_sha256=${2:?}; shift 2;;
    --artifact-path) artifact_path=${2:?}; shift 2;;
    --receipt-path) receipt_path=${2:?}; shift 2;;
    --provisioning-artifact-path) provisioning_path=${2:?}; shift 2;;
    --public-key) public_key=${2:?}; shift 2;;
    --key-sha256) key_sha256=${2:?}; shift 2;;
    --package-manifest-sha256) package_manifest_sha256=${2:?}; shift 2;;
    --checksums-sha256) checksums_sha256=${2:?}; shift 2;;
    --signed-manifest-sha256) signed_manifest_sha256=${2:?}; shift 2;;
    --verified-receipt) verified_receipt=${2:?}; shift 2;;
    *) printf '{"passed":false,"status":"FAIL","reason":"unknown runner argument"}\n'; exit 2;;
  esac
done

die() { printf '{"passed":false,"status":"FAIL","run_id":"%s","profile":"%s","action":"%s","reason":"%s"}\n' "$run_id" "$profile" "$action" "$1"; exit 1; }
case "$run_id" in ''|*[!A-Za-z0-9._-]*) die 'run id is required and must be a bounded lab identifier';; esac
[ "$profile" = linux-x64-gui ] || [ "$profile" = linux-headless-x64 ] || [ "$profile" = server-router ] || die 'unsupported Linux profile'
marker=/var/lib/amnezia-lab/READY
[ -f "$marker" ] || die 'guest readiness marker missing'
grep -q 'candidate_credentials=absent' "$marker" || die 'candidate credentials marker missing'
[ -n "$artifact_path" ] || artifact_path=$(find /tmp -maxdepth 1 -type f -name 'amnezia-release-lab-artifact*' -print -quit)
[ -n "$artifact_path" ] && [ -f "$artifact_path" ] && [ ! -L "$artifact_path" ] || die 'artifact was not uploaded through QGA'
[ -n "$receipt_path" ] || receipt_path=/run/amnezia-release-lab/$run_id/$profile/receipt.json
case "$artifact_path" in /tmp/amnezia-release-lab-artifact*) ;; *) die 'artifact path is outside the controller-owned upload area';; esac
artifact_name=$(basename "$artifact_path")
before_hash=$(sha256sum "$artifact_path" | awk '{print tolower($1)}')
[ -z "$expected_sha256" ] || [ "$before_hash" = "$(printf '%s' "$expected_sha256" | tr '[:upper:]' '[:lower:]')" ] || die 'uploaded artifact hash differs from planned hash'

version_of() {
  for binary in /usr/local/bin/amneziad /usr/local/bin/amnezia-cli /opt/AmneziaVPN/bin/AmneziaVPN; do
    [ -x "$binary" ] || continue
    if [ "$profile" = linux-x64-gui ] && [ "$binary" = /opt/AmneziaVPN/bin/AmneziaVPN ]; then
      gui_rc=0
      value=$(timeout 30 env DISPLAY=:0 XAUTHORITY=/run/user/1000/gdm/Xauthority QT_QPA_PLATFORM=xcb "$binary" --json --status 2>&1) || gui_rc=$?
      status_values=$(VALUE="$value" python3 - <<'PY'
import json
import os
import re

version_re = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$")
for line in reversed(os.environ.get("VALUE", "").splitlines()):
    try:
        item = json.loads(line)
    except json.JSONDecodeError:
        continue
    if item.get("schema") != "amnezia.operator.status.v1":
        continue
    version = item.get("version", "")
    error = item.get("error", "")
    if version_re.fullmatch(version):
        print(f"{version}|{error}")
        break
PY
      )
      status_version=${status_values%%|*}
      status_error=${status_values#*|}
      if [ -z "$status_values" ] || { [ "$gui_rc" -ne 0 ] && { [ "$gui_rc" -ne 4 ] || [ "$status_error" != application_not_running ]; }; }; then
        printf 'guest-runner: GUI status/version probe failed or timed out: %s (rc=%s)\n' "$binary" "$gui_rc" >&2
        continue
      fi
      printf '%s\n' "$status_version"
      return 0
    else
      if ! value=$(timeout 30 "$binary" --version 2>&1); then
        printf 'guest-runner: version probe failed or timed out: %s\n' "$binary" >&2
        continue
      fi
    fi
    detected=$(printf '%s\n' "$value" | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -n 1 || true)
    [ -n "$detected" ] && { printf '%s\n' "$detected"; return 0; }
  done
  return 1
}
installed_version=$(version_of 2>/dev/null || true)
service_name=AmneziaVPN.service
[ "$profile" = linux-headless-x64 ] && service_name=amneziad.service
service_state=$(systemctl show "$service_name" -p ActiveState --value 2>/dev/null || true)
service_enabled=$(systemctl is-enabled "$service_name" 2>/dev/null || true)
service_fragment=$(systemctl show "$service_name" -p FragmentPath --value 2>/dev/null || true)
user_data_state='missing'
[ -d /var/lib/amnezia ] && user_data_state='present'

emit_receipt() {
  status=$1; assertion_json=$2; step_json=$3
  mkdir -p "$(dirname "$receipt_path")"
  RUN_ID="$run_id" PROFILE="$profile" ARTIFACT_NAME="$artifact_name" ARTIFACT_SHA256="$before_hash" STATUS="$status" ASSERTION_JSON="$assertion_json" STEP_JSON="$step_json" RECEIPT_PATH="$receipt_path" python3 - <<'PY'
import json, os
from pathlib import Path
from datetime import datetime, timezone
receipt = {'schema': 1, 'run_id': os.environ['RUN_ID'], 'profile': os.environ['PROFILE'],
           'artifact': os.environ['ARTIFACT_NAME'], 'artifact_sha256': os.environ['ARTIFACT_SHA256'],
           'guest_marker': f"amnezia-release-lab:{os.environ['RUN_ID']}:{os.environ['PROFILE']}",
           'transport': 'qga', 'origin': 'guest', 'injected': False,
           'status': os.environ['STATUS'], 'assertion': json.loads(os.environ['ASSERTION_JSON']),
           'steps': [json.loads(os.environ['STEP_JSON'])],
           'observed_at': datetime.now(timezone.utc).isoformat().replace('+00:00','Z')}
path = Path(os.environ['RECEIPT_PATH'])
tmp = path.with_name(path.name + '.tmp')
tmp.write_text(json.dumps(receipt, sort_keys=True) + '\n', encoding='utf-8')
tmp.replace(path)
print(json.dumps(receipt['assertion'], sort_keys=True, separators=(',', ':')))
PY
}

pending() {
  reason=$1
  assertion=$(REASON="$reason" python3 -c 'import json,os; print(json.dumps({"passed":False,"status":"PENDING","reason":os.environ["REASON"]},separators=(",",":")))')
  emit_receipt PENDING "$assertion" "{\"id\":\"$action\",\"passed\":false,\"status\":\"PENDING\"}"
  exit 1
}

service_json=$(NAME="$service_name" RUNNING="$service_state" ENABLED="$service_enabled" FRAGMENT="$service_fragment" python3 - <<'PY'
import json, os
print(json.dumps({'name':os.environ['NAME'],'active':os.environ['RUNNING'],'enabled':os.environ['ENABLED'],'fragment':os.environ['FRAGMENT']}, separators=(',',':')))
PY
)
if [ "$action" = probe ]; then
  assertion=$(BEFORE="$before_hash" VERSION="$installed_version" SERVICE="$service_json" DATA="$user_data_state" python3 - <<'PY'
import json, os
print(json.dumps({'passed':True,'status':'observed','artifact_sha256_before':os.environ['BEFORE'],'installed_version':os.environ['VERSION'],'service':json.loads(os.environ['SERVICE']),'user_data':os.environ['DATA']}, separators=(',',':')))
PY
  )
  emit_receipt PASS "$assertion" '{"id":"probe","passed":true}'
  exit 0
fi
if [ "$action" = service-health ]; then
  [ "$service_state" = active ] || die "$service_name is not active"
  [ -n "$service_fragment" ] || die 'amneziad.service has no FragmentPath'
  [ -z "$expected_version" ] || [ "$installed_version" = "$expected_version" ] || die "installed version mismatch after health check: expected $expected_version, observed $installed_version"
  assertion=$(SERVICE="$service_json" VERSION="$installed_version" python3 - <<'PY'
import json, os
print(json.dumps({'passed':True,'status':'healthy','service':json.loads(os.environ['SERVICE']),'installed_version':os.environ['VERSION']}, separators=(',',':')))
PY
  )
  emit_receipt PASS "$assertion" '{"id":"service-health","passed":true}'
  exit 0
fi

if [ "$action" = reinstall ] || [ "$action" = update ]; then
  [ -n "$expected_version" ] || die 'expected version is required for installer operations'
  printf '%s' "$expected_version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || die 'expected version is invalid'
  printf '%s' "$expected_sha256" | grep -Eq '^[0-9a-fA-F]{64}$' || die 'expected SHA-256 is required for installer operations'
  if [ "$profile" = linux-x64-gui ]; then
    case "$artifact_name" in *.run) ;; *) die 'Linux GUI requires the verified QIF .run artifact';; esac
    chmod 700 "$artifact_path"
    log=/tmp/amnezia-release-lab-gui-installer.log
    set +e
    timeout 900 "$artifact_path" --accept-messages --accept-licenses --confirm-command install AmneziaSelfHostedUpdate=true >"$log" 2>&1
    rc=$?
    set -e
    [ "$rc" -eq 0 ] || die "Linux GUI installer exited with $rc"
  else
    if [ -z "$provisioning_path" ]; then
      pending 'headless upgrade requires the signed provisioning bundle and verified receipt; binary update tar is not an installer input'
    fi
    [ -f "$provisioning_path" ] && [ ! -L "$provisioning_path" ] || die 'provisioning bundle was not uploaded through QGA'
    [ -n "$public_key" ] && [ -n "$key_sha256" ] && [ -n "$package_manifest_sha256" ] && [ -n "$checksums_sha256" ] && [ -n "$signed_manifest_sha256" ] && [ -n "$verified_receipt" ] || pending 'signed headless trust inputs are not bootstrapped'
    work=$(mktemp -d /tmp/amnezia-release-lab-headless.XXXXXX)
    trap 'rm -rf "$work"' EXIT HUP INT TERM
    tar -xzf "$provisioning_path" -C "$work"
    package=$(find "$work" -type f -name install_headless.sh -print -quit)
    [ -n "$package" ] || die 'provisioning bundle has no official install_headless.sh'
    chmod 700 "$package"
    mode=fresh; [ "$action" = update ] && mode=upgrade
    "$package" "$public_key" "$key_sha256" "$mode" "$package_manifest_sha256" "$checksums_sha256" "$signed_manifest_sha256" "$verified_receipt"
  fi
  after_hash=$(sha256sum "$artifact_path" | awk '{print tolower($1)}')
  [ "$after_hash" = "$(printf '%s' "$expected_sha256" | tr '[:upper:]' '[:lower:]')" ] || die 'uploaded artifact changed during guest operation'
  after_version=$(version_of 2>/dev/null || true)
  [ -n "$after_version" ] || die 'version probe returned no version after installer operation'
  [ "$after_version" = "$expected_version" ] || die "installed version mismatch: expected $expected_version, observed $after_version"
  service_state_after=$(systemctl show "$service_name" -p ActiveState --value 2>/dev/null || true)
  service_enabled_after=$(systemctl is-enabled "$service_name" 2>/dev/null || true)
  service_fragment_after=$(systemctl show "$service_name" -p FragmentPath --value 2>/dev/null || true)
  service_json_after=$(NAME="$service_name" RUNNING="$service_state_after" ENABLED="$service_enabled_after" FRAGMENT="$service_fragment_after" python3 -c 'import json,os; print(json.dumps({"name":os.environ["NAME"],"active":os.environ["RUNNING"],"enabled":os.environ["ENABLED"],"fragment":os.environ["FRAGMENT"]},separators=(",",":")))')
  assertion=$(BEFORE="$before_hash" AFTER="$after_hash" VERSION="$after_version" SERVICE="$service_json_after" ACTION="$action" PROFILE="$profile" python3 -c 'import json,os; print(json.dumps({"passed":True,"status":"installed","action":os.environ["ACTION"],"profile":os.environ["PROFILE"],"artifact_sha256_before":os.environ["BEFORE"],"artifact_sha256_after":os.environ["AFTER"],"installed_version":os.environ["VERSION"],"service":json.loads(os.environ["SERVICE"]),"official_entrypoint":True},separators=(",",":")))')
  emit_receipt PASS "$assertion" "{\"id\":\"$action\",\"passed\":true,\"exit_code\":0}"
  exit 0
fi

die 'unsupported action'
