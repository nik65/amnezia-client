#!/bin/sh
set -eu

action=${1:?action}; profile=${2:?profile}; shift 2
run_id=''; baseline_version=''; candidate_version=''; expected_version=''; expected_sha256=''; artifact_path=''; receipt_path=''; provisioning_path=''
public_key=''; key_sha256=''; package_manifest_sha256=''; checksums_sha256=''; signed_manifest_sha256=''; verified_receipt=''; expected_artifact_role=''
guest_pid=''; guest_start=''; guest_uuid=''; guest_qga=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --run-id) run_id=${2:?}; shift 2;;
    --baseline-version) baseline_version=${2:?}; shift 2;;
    --candidate-version) candidate_version=${2:?}; shift 2;;
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
    --expected-artifact-role) expected_artifact_role=${2:?}; shift 2;;
    --guest-pid) guest_pid=${2:?}; shift 2;;
    --guest-start) guest_start=${2:?}; shift 2;;
    --guest-uuid) guest_uuid=${2:?}; shift 2;;
    --guest-qga) guest_qga=${2:?}; shift 2;;
    *) printf '{"passed":false,"status":"FAIL","reason":"unknown runner argument"}\n'; exit 2;;
  esac
done

receipt_path=${receipt_path:-/run/amnezia-release-lab/$run_id/$profile/receipt.json}
steps_path=$(dirname "$receipt_path")/steps.json
artifact_name='unresolved'; before_hash=''
artifact_size=0; artifact_role='candidate'; artifact_source='qga-upload'; artifact_source_hash_verified=false
marker_verified=0
failure_log=/tmp/amnezia-release-lab-${run_id}-${action}.failure.log
write_failure_receipt() {
  reason="$1"; class="${2:-runner_failure}"; code="${3:-1}"
  if [ -f "$failure_log" ]; then
      printf '%s\n' "$reason" >"${failure_log}.reason" 2>/dev/null || true
  else
      printf '%s\n' "$reason" >"$failure_log" 2>/dev/null || true
  fi
  log_hash=$(sha256sum "$failure_log" 2>/dev/null | awk '{print tolower($1)}' || true)
  [ -n "$log_hash" ] || log_hash=unavailable
  observed_baseline_version=$(version_of 2>/dev/null || true)
  baseline_service=$(systemctl show "${service_name:-AmneziaVPN.service}" -p ActiveState --value 2>/dev/null || true)
  mkdir -p "$(dirname "$receipt_path")" 2>/dev/null || return 0
  RUN_ID="$run_id" PROFILE="$profile" ACTION="$action" ARTIFACT="$artifact_name" ARTIFACT_PATH="$artifact_path" HASH="$before_hash" SIZE="$artifact_size" ROLE="$artifact_role" SOURCE="$artifact_source" SOURCE_HASH_VERIFIED="$artifact_source_hash_verified" REASON="$reason" CLASS="$class" CODE="$code" LOG_HASH="$log_hash" LOG_PATH="$failure_log" BASELINE_VERSION="$baseline_version" OBSERVED_BASELINE_VERSION="$observed_baseline_version" CANDIDATE_VERSION="$candidate_version" BASELINE_SERVICE="$baseline_service" RECEIPT_PATH="$receipt_path" STEPS_PATH="$steps_path" GUEST_PID="$guest_pid" GUEST_START="$guest_start" GUEST_UUID="$guest_uuid" GUEST_QGA="$guest_qga" python3 - <<'PY'
import json, os
from pathlib import Path
from datetime import datetime, timezone
receipt = {
    "schema": 1, "run_id": os.environ["RUN_ID"], "profile": os.environ["PROFILE"],
    "artifact": os.environ["ARTIFACT"], "artifact_sha256": os.environ["HASH"], "artifact_size": int(os.environ["SIZE"] or 0),
    "artifact_role": os.environ["ROLE"], "artifact_source": {"transport": "qga", "kind": os.environ["SOURCE"], "hash_verified": os.environ["SOURCE_HASH_VERIFIED"] == "true", "path": os.environ["ARTIFACT_PATH"]},
    "baseline_version": os.environ["BASELINE_VERSION"], "candidate_version": os.environ["CANDIDATE_VERSION"],
    "guest_marker": f"amnezia-release-lab:{os.environ['RUN_ID']}:{os.environ['PROFILE']}",
    "transport": "qga", "origin": "guest", "injected": False, "status": "FAIL",
    "guest_binding": {"pid": int(os.environ["GUEST_PID"]), "proc_start_time": os.environ["GUEST_START"], "uuid": os.environ["GUEST_UUID"], "qga_socket": os.environ["GUEST_QGA"]},
    "failure": {"class": os.environ["CLASS"], "exit_code": int(os.environ["CODE"]),
                 "reason": os.environ["REASON"], "fresh_log_sha256": os.environ["LOG_HASH"], "fresh_log_path": os.environ["LOG_PATH"],
                 "postfailure_baseline": {"planned_version": os.environ["BASELINE_VERSION"], "observed_version": os.environ["OBSERVED_BASELINE_VERSION"], "service_active": os.environ["BASELINE_SERVICE"]}},
    "assertion": {"passed": False, "status": "FAIL", "reason": os.environ["REASON"]},
    "steps": [],
    "observed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
}
path = Path(os.environ["RECEIPT_PATH"])
path.parent.mkdir(parents=True, exist_ok=True)
steps_dir=path.parent/"steps"; steps_dir.mkdir(mode=0o700,exist_ok=True)
if steps_dir.is_symlink() or not steps_dir.is_dir(): raise SystemExit("ambiguous immutable steps directory")
order=["probe","reinstall","update","service-health"]
for index,step_id in enumerate(order):
    prior_path=steps_dir/f"{index:02d}-{step_id}.json"
    if prior_path.is_symlink(): raise SystemExit("symlinked immutable guest step")
    if prior_path.exists(): receipt["steps"].append(json.loads(prior_path.read_text(encoding="utf-8")))
step={"id": os.environ["ACTION"], "passed": False, "failure_class": os.environ["CLASS"], "exit_code": int(os.environ["CODE"]), "artifact_sha256": receipt["artifact_sha256"], "artifact_size": receipt["artifact_size"], "artifact_role": receipt["artifact_role"], "artifact_source": receipt["artifact_source"], "transport": receipt["transport"], "run_id":receipt["run_id"], "profile":receipt["profile"], "guest_binding":receipt["guest_binding"], "raw_assertion":receipt["assertion"], "observed_at":receipt["observed_at"]}
if any(x.get("id")==step["id"] or x.get("guest_binding")!=receipt["guest_binding"] for x in receipt["steps"] if isinstance(x,dict)): raise SystemExit("stored failure step conflict")
step_path=steps_dir/f"{order.index(step['id']):02d}-{step['id']}.json"
payload=(json.dumps(step,sort_keys=True,separators=(",",":"))+"\n").encode(); flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL
if hasattr(os,"O_NOFOLLOW"): flags|=os.O_NOFOLLOW
fd=os.open(step_path,flags,0o600)
try:
    view=memoryview(payload)
    while view:
        count=os.write(fd,view)
        if not isinstance(count,int) or isinstance(count,bool) or count <= 0: raise SystemExit("short immutable failure step write")
        view=view[count:]
    os.fsync(fd)
finally: os.close(fd)
receipt["steps"].append(json.loads(step_path.read_text(encoding="utf-8")))
tmp = path.with_name(path.name + ".tmp")
tmp.write_text(json.dumps(receipt, sort_keys=True) + "\n", encoding="utf-8")
tmp.replace(path)
PY
}
die() { if [ "$marker_verified" -eq 1 ]; then write_failure_receipt "$1"; fi; printf '{"passed":false,"status":"FAIL","run_id":"%s","profile":"%s","action":"%s","reason":"%s"}\n' "$run_id" "$profile" "$action" "$1"; exit 1; }
case "$run_id" in ''|*[!A-Za-z0-9._-]*) die 'run id is required and must be a bounded lab identifier';; esac
[ "$profile" = linux-x64-gui ] || [ "$profile" = linux-headless-x64 ] || [ "$profile" = server-router ] || die 'unsupported Linux profile'
printf '%s' "$guest_pid" | grep -Eq '^[1-9][0-9]*$' || die 'outer guest PID binding is invalid'
[ -n "$guest_start" ] && [ -n "$guest_uuid" ] && [ -n "$guest_qga" ] || die 'outer guest incarnation binding is incomplete'
printf '%s' "$baseline_version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || die 'baseline version is required and invalid'
printf '%s' "$candidate_version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || die 'candidate version is required and invalid'
marker=/tmp/amnezia-release-lab-marker
marker_value=''
if [ -f "$marker" ] && [ ! -L "$marker" ]; then
  marker_value=$(tr -d '\r' < "$marker")
fi
[ "$marker_value" = "amnezia-release-lab:${run_id}:${profile}" ] || die 'guest marker identity is missing or mismatched'
case "$receipt_path" in /run/amnezia-release-lab/$run_id/$profile/*) ;; *) die 'receipt path is outside the owned run/profile directory';; esac
[ ! -L "$receipt_path" ] || die 'receipt path is a symlink'
marker_verified=1
rm -f -- "$failure_log" "${failure_log}.reason"
marker=/var/lib/amnezia-lab/READY
[ -f "$marker" ] || die 'guest readiness marker missing'
grep -q 'candidate_credentials=absent' "$marker" || die 'candidate credentials marker missing'
[ -n "$artifact_path" ] || artifact_path=$(find /tmp -maxdepth 1 -type f -name 'amnezia-release-lab-artifact*' -print -quit)
[ -n "$artifact_path" ] && [ -f "$artifact_path" ] && [ ! -L "$artifact_path" ] || die 'artifact was not uploaded through QGA'
[ -n "$receipt_path" ] || receipt_path=/run/amnezia-release-lab/$run_id/$profile/receipt.json
case "$artifact_path" in /tmp/amnezia-release-lab-artifact*) ;; *) die 'artifact path is outside the controller-owned upload area';; esac
artifact_name=$(basename "$artifact_path")
before_hash=$(sha256sum "$artifact_path" | awk '{print tolower($1)}')
artifact_size=$(stat -c %s "$artifact_path")
[ "$action" = reinstall ] && artifact_role=baseline || artifact_role=candidate
if [ -n "$expected_artifact_role" ]; then
  [ "$expected_artifact_role" = baseline ] || [ "$expected_artifact_role" = candidate ] || die 'expected artifact role is invalid'
  artifact_role=$expected_artifact_role
fi
printf '%s' "$expected_sha256" | grep -Eq '^[0-9a-fA-F]{64}$' || die 'planned artifact SHA-256 is required for every Linux guest step'
[ "$before_hash" = "$(printf '%s' "$expected_sha256" | tr '[:upper:]' '[:lower:]')" ] || die 'uploaded artifact hash differs from planned hash'
artifact_source_hash_verified=true

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
  if [ "$profile" = linux-x64-gui ]; then
    components=/opt/AmneziaVPN/components.xml
    if [ -f "$components" ] && [ ! -L "$components" ] && [ "$(stat -c %u "$components")" -eq 0 ]; then
      detected=$(python3 - "$components" <<'PY'
import re
import sys
import xml.etree.ElementTree as ET

root = ET.parse(sys.argv[1]).getroot()
versions = [node.text or "" for node in root.findall("./Package/Version")]
if len(versions) == 1 and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+", versions[0]):
    print(versions[0])
PY
      )
      [ -n "$detected" ] && { printf '%s\n' "$detected"; return 0; }
    fi
  fi
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
gui_proof='{}'
if [ "$profile" = linux-x64-gui ]; then
  gui_session_proof() {
    session=''; uid=''; user=''; seat=''; tty=''; type=''; active=''; state=''; class=''
    loginctl list-sessions --no-legend 2>/dev/null | while IFS=' ' read -r session uid user seat tty; do
      [ "$user" = lab ] || continue
      type=$(loginctl show-session "$session" -p Type --value 2>/dev/null || true)
      active=$(loginctl show-session "$session" -p Active --value 2>/dev/null || true)
      state=$(loginctl show-session "$session" -p State --value 2>/dev/null || true)
      class=$(loginctl show-session "$session" -p Class --value 2>/dev/null || true)
      [ "$type" = x11 ] && [ "$active" = yes ] && [ "$state" = active ] && [ "$class" = user ] || continue
      uid=$(loginctl show-user lab -p UID --value 2>/dev/null || true)
      printf '%s\n' "{\"session\":\"$session\",\"uid\":\"$uid\",\"user\":\"lab\",\"type\":\"$type\",\"active\":\"$active\",\"state\":\"$state\",\"class\":\"$class\"}"
      break
    done
  }
  gui_session_json=$(gui_session_proof || true)
  gui_user=''; gui_session=''; gui_uid=''; gui_type=''; gui_active=''; gui_state=''; gui_class=''
  if [ -n "$gui_session_json" ]; then
    gui_fields=$(GUI_SESSION="$gui_session_json" python3 - <<'PY'
import json, os
item = json.loads(os.environ["GUI_SESSION"])
print(*(item.get(key, "") for key in ("session", "uid", "user", "type", "active", "state", "class")))
PY
    )
    IFS=' ' read -r gui_session gui_uid gui_user gui_type gui_active gui_state gui_class <<EOF
$gui_fields
EOF
  fi
  gui_display_server=''; pgrep -x Xorg >/dev/null 2>&1 && gui_display_server=Xorg; [ -z "$gui_display_server" ] && pgrep -x Xwayland >/dev/null 2>&1 && gui_display_server=Xwayland
  gui_gnome='false'; pgrep -x gnome-shell >/dev/null 2>&1 && gui_gnome='true'
  gui_service_active=$(systemctl show "$service_name" -p ActiveState --value 2>/dev/null || true)
  gui_service_enabled=$(systemctl is-enabled "$service_name" 2>/dev/null || true)
  gui_proof=$(USER_NAME="$gui_user" USER_UID="$gui_uid" SESSION_ID="$gui_session" SESSION_TYPE="$gui_type" SESSION_ACTIVE="$gui_active" SESSION_STATE="$gui_state" SESSION_CLASS="$gui_class" DISPLAY_SERVER="$gui_display_server" GNOME="$gui_gnome" SERVICE_ACTIVE="$gui_service_active" SERVICE_ENABLED="$gui_service_enabled" VERSION="$installed_version" python3 - <<'PY'
import json, os
print(json.dumps({"active_user": os.environ["USER_NAME"], "uid": os.environ["USER_UID"], "session_id": os.environ["SESSION_ID"], "session_type": os.environ["SESSION_TYPE"], "session_active": os.environ["SESSION_ACTIVE"], "session_state": os.environ["SESSION_STATE"], "session_class": os.environ["SESSION_CLASS"], "display_server": os.environ["DISPLAY_SERVER"], "gnome_shell": os.environ["GNOME"] == "true", "service_active": os.environ["SERVICE_ACTIVE"], "service_enabled": os.environ["SERVICE_ENABLED"], "binary_version": os.environ["VERSION"]}, separators=(",", ":")))
PY
  )
  if [ "$action" = service-health ]; then
    [ "$gui_user" = lab ] && [ -n "$gui_uid" ] && [ -n "$gui_session" ] && [ "$gui_type" = x11 ] && [ "$gui_active" = yes ] && [ "$gui_state" = active ] && [ "$gui_class" = user ] || die 'GUI session proof is missing the owned active X11 lab session'
    [ -n "$gui_display_server" ] && [ "$gui_gnome" = true ] || die 'GUI session proof is missing GNOME/X11 processes'
  fi
fi

emit_receipt() {
  status=$1; assertion_json=$2; step_json=$3
  mkdir -p "$(dirname "$receipt_path")"
  RUN_ID="$run_id" PROFILE="$profile" BASELINE_VERSION="$baseline_version" CANDIDATE_VERSION="$candidate_version" ARTIFACT_NAME="$artifact_name" ARTIFACT_PATH="$artifact_path" ARTIFACT_SHA256="$before_hash" ARTIFACT_SIZE="$artifact_size" ARTIFACT_ROLE="$artifact_role" ARTIFACT_SOURCE="$artifact_source" ARTIFACT_SOURCE_HASH_VERIFIED="$artifact_source_hash_verified" STATUS="$status" ASSERTION_JSON="$assertion_json" STEP_JSON="$step_json" RECEIPT_PATH="$receipt_path" STEPS_PATH="$steps_path" GUEST_PID="$guest_pid" GUEST_START="$guest_start" GUEST_UUID="$guest_uuid" GUEST_QGA="$guest_qga" python3 - <<'PY'
import json, os
from pathlib import Path
from datetime import datetime, timezone
receipt = {'schema': 1, 'run_id': os.environ['RUN_ID'], 'profile': os.environ['PROFILE'],
           'artifact': os.environ['ARTIFACT_NAME'], 'artifact_sha256': os.environ['ARTIFACT_SHA256'], 'artifact_size': int(os.environ['ARTIFACT_SIZE'] or 0),
           'artifact_role': os.environ['ARTIFACT_ROLE'], 'artifact_source': {'transport': 'qga', 'kind': os.environ['ARTIFACT_SOURCE'], 'hash_verified': os.environ['ARTIFACT_SOURCE_HASH_VERIFIED'] == 'true', 'path': os.environ['ARTIFACT_PATH']},
           'baseline_version': os.environ['BASELINE_VERSION'], 'candidate_version': os.environ['CANDIDATE_VERSION'],
           'guest_marker': f"amnezia-release-lab:{os.environ['RUN_ID']}:{os.environ['PROFILE']}",
           'transport': 'qga', 'origin': 'guest', 'injected': False,
           'status': os.environ['STATUS'], 'assertion': json.loads(os.environ['ASSERTION_JSON']),
           'steps': [],
           'guest_binding': {'pid': int(os.environ['GUEST_PID']), 'proc_start_time': os.environ['GUEST_START'], 'uuid': os.environ['GUEST_UUID'], 'qga_socket': os.environ['GUEST_QGA']},
           'observed_at': datetime.now(timezone.utc).isoformat().replace('+00:00','Z')}
path = Path(os.environ['RECEIPT_PATH'])
steps_dir = path.parent / 'steps'
steps_dir.mkdir(mode=0o700, exist_ok=True)
if steps_dir.is_symlink() or not steps_dir.is_dir(): raise SystemExit('ambiguous immutable steps directory')
step = json.loads(os.environ['STEP_JSON'])
order = ['probe', 'reinstall', 'update', 'service-health']
receipt['steps'] = []
for index, step_id in enumerate(order):
    prior_path = steps_dir / f'{index:02d}-{step_id}.json'
    if prior_path.is_symlink(): raise SystemExit('symlinked immutable guest step')
    if prior_path.exists():
        prior = json.loads(prior_path.read_text(encoding='utf-8'))
        if not isinstance(prior, dict) or prior.get('id') != step_id: raise SystemExit('invalid immutable guest step')
        receipt['steps'].append(prior)
if step.get('id') not in order or any(not isinstance(x, dict) or x.get('id') not in order for x in receipt['steps']):
    raise SystemExit('noncanonical stored step')
if len({x['id'] for x in receipt['steps']}) != len(receipt['steps']) or any(x.get('guest_binding') != receipt['guest_binding'] or x.get('run_id') != receipt['run_id'] or x.get('profile') != receipt['profile'] for x in receipt['steps']):
    raise SystemExit('stored steps cross guest incarnation or conflict')
if step['id'] in {x['id'] for x in receipt['steps']}:
    raise SystemExit('duplicate immutable guest step')
present = [order.index(x['id']) for x in receipt['steps']]
if present != sorted(present) or (present and order.index(step['id']) <= present[-1]):
    raise SystemExit('guest step order conflict')
step.setdefault('artifact_sha256', receipt['artifact_sha256'])
step.setdefault('artifact_size', receipt['artifact_size'])
step.setdefault('artifact_role', receipt['artifact_role'])
step.setdefault('artifact_source', receipt['artifact_source'])
step.setdefault('transport', receipt['transport'])
step['run_id'] = receipt['run_id']; step['profile'] = receipt['profile']; step['guest_binding'] = receipt['guest_binding']
step['raw_assertion'] = receipt['assertion']; step['observed_at'] = receipt['observed_at']
step_path = steps_dir / f'{order.index(step["id"]):02d}-{step["id"]}.json'
payload=(json.dumps(step,sort_keys=True,separators=(',',':'))+'\n').encode()
flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL
if hasattr(os,'O_NOFOLLOW'): flags|=os.O_NOFOLLOW
fd=os.open(step_path,flags,0o600)
try:
    view=memoryview(payload)
    while view:
        count=os.write(fd,view)
        if count<=0: raise SystemExit('short immutable step write')
        view=view[count:]
    os.fsync(fd)
finally: os.close(fd)
receipt['steps'].append(json.loads(step_path.read_text(encoding='utf-8')))
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
  assertion=$(BEFORE="$before_hash" BASELINE="$baseline_version" CANDIDATE="$candidate_version" VERSION="$installed_version" SERVICE="$service_json" DATA="$user_data_state" GUI="$gui_proof" python3 - <<'PY'
import json, os
print(json.dumps({'passed':True,'status':'observed','baseline_version':os.environ['BASELINE'],'candidate_version':os.environ['CANDIDATE'],'artifact_sha256_before':os.environ['BEFORE'],'installed_version':os.environ['VERSION'],'service':json.loads(os.environ['SERVICE']),'user_data':os.environ['DATA'],'gui':json.loads(os.environ['GUI'])}, separators=(',',':')))
PY
  )
  emit_receipt PASS "$assertion" '{"id":"probe","passed":true}'
  exit 0
fi
if [ "$action" = service-health ]; then
  [ "$service_state" = active ] || die "$service_name is not active"
  [ -n "$service_fragment" ] || die 'amneziad.service has no FragmentPath'
  [ -z "$expected_version" ] || [ "$installed_version" = "$expected_version" ] || die "installed version mismatch after health check: expected $expected_version, observed $installed_version"
  assertion=$(BEFORE="$before_hash" SERVICE="$service_json" BASELINE="$baseline_version" CANDIDATE="$candidate_version" VERSION="$installed_version" GUI="$gui_proof" python3 - <<'PY'
import json, os
print(json.dumps({'passed':True,'status':'healthy','baseline_version':os.environ['BASELINE'],'candidate_version':os.environ['CANDIDATE'],'artifact_sha256_before':os.environ['BEFORE'],'service':json.loads(os.environ['SERVICE']),'installed_version':os.environ['VERSION'],'gui':json.loads(os.environ['GUI'])}, separators=(',',':')))
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
    failure_log=$log
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
    log=/tmp/amnezia-release-lab-headless-installer-${run_id}-${action}.log
    failure_log=$log
    set +e
    "$package" "$public_key" "$key_sha256" "$mode" "$package_manifest_sha256" "$checksums_sha256" "$signed_manifest_sha256" "$verified_receipt" >"$log" 2>&1
    rc=$?
    set -e
    [ "$rc" -eq 0 ] || die "headless installer exited with $rc"
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
  assertion=$(BEFORE="$before_hash" AFTER="$after_hash" BASELINE="$baseline_version" CANDIDATE="$candidate_version" VERSION="$after_version" SERVICE="$service_json_after" ACTION="$action" PROFILE="$profile" GUI="$gui_proof" python3 -c 'import json,os; print(json.dumps({"passed":True,"status":"installed","action":os.environ["ACTION"],"profile":os.environ["PROFILE"],"baseline_version":os.environ["BASELINE"],"candidate_version":os.environ["CANDIDATE"],"artifact_sha256_before":os.environ["BEFORE"],"artifact_sha256_after":os.environ["AFTER"],"installed_version":os.environ["VERSION"],"service":json.loads(os.environ["SERVICE"]),"gui":json.loads(os.environ["GUI"]),"official_entrypoint":True},separators=(",",":")))')
  emit_receipt PASS "$assertion" "{\"id\":\"$action\",\"passed\":true,\"exit_code\":0}"
  exit 0
fi

die 'unsupported action'
