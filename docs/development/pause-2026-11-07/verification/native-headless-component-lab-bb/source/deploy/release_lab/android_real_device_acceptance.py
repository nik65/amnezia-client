"""Live physical-phone predicate for the trusted full-matrix controller.

No receipt imports, caller-selected server/command or signatures are accepted.
The producer directly acquires current ADB bytes and a nonce-bound read-only
ServerX snapshot. Only the common trusted issuer may turn the complete matrix
into a publication permit; this module never signs or writes that permit.
"""
from __future__ import annotations

import base64
import calendar
from datetime import datetime, timezone
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import re
import secrets
import time
import uuid

from . import android_real_device_acquisition as device_capture

PINNED_PLINK = Path("C:/Program Files/PuTTY/plink.exe")
PINNED_KEY = Path("C:/keys/Base.ppk")
SERVER = "85.208.87.69"
HOST_KEY = "SHA256:2UtHIoVd4Lft+s4E/LZlA8+reysEexYyhkt03rg8Rdg"
MAX_RECORD_CLOCK_DELTA_MS = 5
SAFE_MESSAGE = re.compile(r"(?:Handle event: (?:STATISTICS_UPDATE|STATUS_CHANGED)|"
                          r"RemoteLogRedaction reason=0 count=\d+|Remote log bootstrap succeeded|"
                          r"Start traffic stats update|Handle protocol state: CONNECTED|"
                          r"Protocol state changed: CONNECTED|"
                          r"RemoteLogServiceSample connected=true counters=(?:unknown|"
                          r"fresh rxBytes=[0-9]{1,19} txBytes=[0-9]{1,19} "
                          r"sampleAgeMs=(?:[0-9]|[1-9][0-9]{1,3}|1[0-4][0-9]{3}|15000)))")
LOCAL_RECORD = re.compile(r"^\s*(\d{10}\.\d+)\s+(\d+)\s+(\d+)\s+([VDIWEAF])\s+"
                          r"(AmneziaActivity|AmneziaVpnService)\s*:\s*(.*)$")
SERVER_RECORD = re.compile(r"^(\d\d-\d\d \d\d:\d\d:\d\d\.\d{3})Z\s+(\d+)\s+(\d+)\s+"
                           r"([VDIWEAF])\s+\[[^\]\r\n]{1,128}\]\s+"
                           r"(AmneziaActivity|AmneziaVpnService):\s*(.*)$")


class AndroidAcceptanceError(RuntimeError):
    pass


SERVER_CAPTURE = r'''import base64,hashlib,json,os,pathlib,re,sqlite3,stat,time
p=PARAMETERS
root=pathlib.Path('/opt/amnezia/client-logs')
def regular(path,limit):
 for item in (path,*path.parents):
  s=item.lstat()
  if stat.S_ISLNK(s.st_mode):raise SystemExit('symlink in read-only server capture')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  a=os.fstat(fd)
  if not stat.S_ISREG(a.st_mode) or a.st_uid!=0 or a.st_mode&0o022 or not 0<a.st_size<=limit:raise SystemExit('server file bounds/ownership')
  chunks=[];remaining=a.st_size
  while remaining:
   b=os.read(fd,min(65536,remaining))
   if not b:raise SystemExit('short server file')
   chunks.append(b);remaining-=len(b)
  z=os.fstat(fd)
  if (a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)!=(z.st_dev,z.st_ino,z.st_size,z.st_mtime_ns,z.st_ctime_ns):raise SystemExit('server file changed')
  return b''.join(chunks)
 finally:os.close(fd)
if os.geteuid()!=0:raise SystemExit('read-only root identity required')
boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
now=int(time.time());cutoff=max(p['installed_after'],now-300)
database=root/'batch-receipts.sqlite3'
for item in (database,*database.parents):
 if stat.S_ISLNK(item.lstat().st_mode):raise SystemExit('receipt database symlink')
con=sqlite3.connect('file:'+str(database)+'?mode=ro',uri=True,timeout=5)
try:
 con.execute('PRAGMA query_only=ON')
 rows=con.execute('SELECT batch_id,accepted_at,body_sha256,body_length FROM batch_receipts WHERE client_id=? AND accepted_at>=? ORDER BY accepted_at DESC LIMIT 16',(p['client_id'],cutoff)).fetchall()
finally:con.close()
metadata={row[0]:dict(batch_id=row[0],accepted_at=row[1],body_sha256=row[2],body_length=row[3]) for row in rows}
pattern=re.compile(r'^\d{8}-\d{6}-\d+-'+re.escape(p['installation_id'])+r'-android-([0-9a-f]{64})\.log$')
matches={};count=0
with os.scandir(root/'logs'/p['client_id']) as entries:
 for entry in entries:
  count+=1
  if count>8192:raise SystemExit('server log directory bound')
  m=pattern.fullmatch(entry.name)
  if not m or m[1] not in metadata:continue
  if m[1] in matches:raise SystemExit('duplicate selected batch file')
  if not entry.is_file(follow_symlinks=False):raise SystemExit('selected log is not a regular file')
  matches[m[1]]=entry.name
files=[]
for batch,name in sorted(matches.items(),key=lambda pair:metadata[pair[0]]['accepted_at'],reverse=True)[:4]:
 data=regular(root/'logs'/p['client_id']/name,2*1024*1024)
 files.append(dict(name=name,receipt=metadata[batch],size=len(data),sha256=hashlib.sha256(data).hexdigest(),bytes_b64=base64.b64encode(data).decode()))
if pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()!=boot:raise SystemExit('server boot changed')
print(json.dumps(dict(schema=1,challenge=p['nonce'],server=SERVER_ADDRESS,boot_id=boot,uid=os.geteuid(),captured_at=now,client_id=p['client_id'],installation_id=p['installation_id'],files=files),sort_keys=True,separators=(',',':')))
'''


def _utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _timestamp(text):
    if not isinstance(text, str) or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", text):
        raise AndroidAcceptanceError("canonical UTC installation boundary required")
    return int(datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp())


def _strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise AndroidAcceptanceError("duplicate live capture key")
        result[key] = value
    return result


def _local_records(device, installed_after):
    originals = json.loads(device["raw_capture"], object_pairs_hook=_strict_object)
    pids = {p["pid"] for p in device["binding"]["processes"]}
    keys = set()
    uid_logs = [r for r in originals if r["label"] == "uid-logcat"]
    if len(uid_logs) != 1:
        raise AndroidAcceptanceError("fresh package-UID log capture required")
    uid_text = base64.b64decode(uid_logs[0]["stdout_b64"], validate=True).decode("utf-8")
    for line in uid_text.splitlines():
        stamp = re.match(r"^\s*(\d{10}\.\d+)\s", line)
        if stamp and Decimal(stamp[1]) >= installed_after and re.search(
                r"FATAL EXCEPTION|Fatal signal \d+|ANR in org\.amnezia\.vpn", line):
            raise AndroidAcceptanceError("post-install fatal/ANR record in live UID logs")
    for record in originals:
        if not record["label"].startswith("logcat:"):
            continue
        text = base64.b64decode(record["stdout_b64"], validate=True).decode("utf-8")
        for line in text.splitlines():
            match = LOCAL_RECORD.fullmatch(line)
            if not match or int(match[2]) not in pids or Decimal(match[1]) < installed_after:
                continue
            if SAFE_MESSAGE.fullmatch(match[6]):
                keys.add((int(Decimal(match[1])*1000), int(match[2]), int(match[3]), match[4], match[5], match[6]))
    if not keys:
        raise AndroidAcceptanceError("no current post-install phone record available for correlation")
    return keys


def _validate_server(server_raw, *, nonce, client_id, installation_id, installed_after, local_keys):
    if not isinstance(server_raw, bytes) or len(server_raw) > 16*1024*1024:
        raise AndroidAcceptanceError("server capture size/type")
    value = json.loads(server_raw, object_pairs_hook=_strict_object)
    if (not isinstance(value, dict) or set(value) != {"schema", "challenge", "server", "boot_id", "uid",
            "captured_at", "client_id", "installation_id", "files"}
            or type(value["schema"]) is not int or value["schema"] != 1
            or value["challenge"] != nonce or value["server"] != SERVER or value["uid"] != 0
            or type(value["uid"]) is not int or value["client_id"] != client_id
            or value["installation_id"] != installation_id or type(value["captured_at"]) is not int
            or abs(time.time()-value["captured_at"]) > 60
            or not isinstance(value["files"], list) or not 1 <= len(value["files"]) <= 4):
        raise AndroidAcceptanceError("server live challenge/identity/freshness mismatch")
    try:
        if str(uuid.UUID(value["boot_id"])) != value["boot_id"]:
            raise ValueError()
    except (ValueError, TypeError, AttributeError) as error:
        raise AndroidAcceptanceError("server boot identity invalid") from error
    matched = []
    for file in value["files"]:
        if not isinstance(file, dict) or set(file) != {"name", "receipt", "size", "sha256", "bytes_b64"}:
            raise AndroidAcceptanceError("server selected file shape")
        receipt = file["receipt"]
        if (not isinstance(receipt, dict) or set(receipt) != {"batch_id", "accepted_at", "body_sha256", "body_length"}
                or not isinstance(receipt["batch_id"], str) or not re.fullmatch(r"[0-9a-f]{64}", receipt["batch_id"])
                or type(receipt["accepted_at"]) is not int or receipt["accepted_at"] < max(installed_after, value["captured_at"]-300)
                or receipt["accepted_at"] > value["captured_at"]+1
                or type(receipt["body_length"]) is not int or type(file["size"]) is not int
                or not 0 < file["size"] <= 2*1024*1024):
            raise AndroidAcceptanceError("server receipt identity/time/bounds mismatch")
        name_pattern = r"\d{8}-\d{6}-\d+-"+re.escape(installation_id)+r"-android-"+receipt["batch_id"]+r"\.log"
        if not isinstance(file["name"], str) or not re.fullmatch(name_pattern, file["name"]):
            raise AndroidAcceptanceError("server filename installation/batch mismatch")
        data = base64.b64decode(file["bytes_b64"], validate=True)
        digest = hashlib.sha256(data).hexdigest()
        if (len(data) != file["size"] or len(data) != receipt["body_length"]
                or digest != file["sha256"] or digest != receipt["body_sha256"]):
            raise AndroidAcceptanceError("accepted database receipt/file bytes differ")
        text = data.decode("utf-8")
        if text.strip() == "[redacted sensitive line]":
            continue
        for line in text.splitlines():
            record = SERVER_RECORD.fullmatch(line)
            if not record or not SAFE_MESSAGE.fullmatch(record[6]):
                continue
            year = datetime.fromtimestamp(value["captured_at"], timezone.utc).year
            candidates = []
            for y in (year-1, year, year+1):
                try:
                    stamp = datetime.strptime(str(y)+"-"+record[1], "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=timezone.utc)
                    candidates.append(calendar.timegm(stamp.utctimetuple())*1000+stamp.microsecond//1000)
                except ValueError:
                    pass
            epoch_ms = min(candidates, key=lambda t: abs(t-value["captured_at"]*1000)) if candidates else -1
            key = (epoch_ms, int(record[2]), int(record[3]), record[4], record[5], record[6])
            # App-file formatting precedes NativeLog.println; a real record's
            # file/logcat timestamps commonly differ by1ms. Require an exact
            # PID/TID/priority/tag/safe-message match and one unique timestamp
            # within a small bound, rather than accepting arbitrary drift.
            phone_times = [k[0] for k in local_keys if k[1:] == key[1:]
                           and abs(k[0]-epoch_ms) <= MAX_RECORD_CLOCK_DELTA_MS]
            if (installed_after*1000 <= epoch_ms <= (receipt["accepted_at"]+1)*1000
                    and len(phone_times) == 1):
                matched.append({"batch_id": receipt["batch_id"], "accepted_at": receipt["accepted_at"],
                                "body_sha256": digest, "size": len(data), "pid": int(record[2]),
                                "record_epoch_ms": epoch_ms, "phone_record_epoch_ms": phone_times[0],
                                "clock_delta_ms": phone_times[0]-epoch_ms, "tag": record[5]})
                break
    if not matched:
        raise AndroidAcceptanceError("no fresh non-placeholder server delivery matches current phone records")
    return matched


class AndroidLiveProducer:
    """Fixed real-phone+ServerX producer; configuration selects only its subject.

    installed_after_utc must be the trusted controller's recorded start of the
    real replacement install. It is a freshness boundary, never a claimed PASS.
    The common issuer validates exact producer type/source and complete context.
    """
    def __init__(self, *, serial, client_id, installation_id, installed_after_utc):
        if (not isinstance(serial, str) or not device_capture.ID.fullmatch(serial)
                or serial.lower().startswith("emulator-") or not isinstance(client_id, str)
                or not re.fullmatch(r"[0-9a-f]{64}", client_id)):
            raise AndroidAcceptanceError("real phone/client subject invalid")
        try:
            if str(uuid.UUID(installation_id)) != installation_id:
                raise ValueError()
        except (ValueError, TypeError, AttributeError) as error:
            raise AndroidAcceptanceError("installation subject invalid") from error
        self.serial = serial
        self.client_id = client_id
        self.installation_id = installation_id
        self.installed_after = _timestamp(installed_after_utc)

    def acquire(self, context):
        started_at = _utc()
        # Revalidate mutable selectors at the live boundary, before either
        # transport is touched. Constructor validation alone is insufficient.
        if (not isinstance(self.serial, str) or not device_capture.ID.fullmatch(self.serial)
                or self.serial.lower().startswith("emulator-")
                or not isinstance(self.client_id, str) or not re.fullmatch(r"[0-9a-f]{64}", self.client_id)
                or type(self.installed_after) is not int):
            raise AndroidAcceptanceError("live producer subject/boundary mutated")
        try:
            if str(uuid.UUID(self.installation_id)) != self.installation_id:
                raise ValueError()
        except (ValueError, TypeError, AttributeError) as error:
            raise AndroidAcceptanceError("live installation subject mutated") from error
        if not 0 <= time.time()-self.installed_after <= 24*60*60:
            raise AndroidAcceptanceError("recorded real install boundary is not current")
        context.verify()
        producer = device_capture.file_record(Path(__file__).absolute())
        plink = device_capture.file_record(PINNED_PLINK)
        if not PINNED_KEY.is_file() or PINNED_KEY.is_symlink():
            raise AndroidAcceptanceError("existing pinned host credential unavailable")
        run_id = "android-real-"+secrets.token_hex(12)
        device = device_capture.acquire_android_device(run_id=run_id, serial=self.serial,
            candidate=context.candidate("android-arm64-v8a"), manifest=context.manifest,
            version=context.version, version_code=context.android_code)
        if (device["state"] != "acquired-not-accepted"
                or not any(p["name"] == device_capture.PACKAGE+":amneziaAwgService" for p in device["binding"]["processes"])
                or len(device["vpn_observations"]) != 1
                or not device["vpn_observations"][0]["validated"] or not device["vpn_observations"][0]["connected"]):
            raise AndroidAcceptanceError("live AWG service/validated VPN observations incomplete")
        local_keys = _local_records(device, self.installed_after)
        nonce = secrets.token_hex(32)
        parameters = {"client_id": self.client_id, "installation_id": self.installation_id,
                      "installed_after": self.installed_after, "nonce": nonce}
        script = ("import json\nPARAMETERS=json.loads("+repr(json.dumps(parameters))+ ")\nSERVER_ADDRESS="+repr(SERVER)+"\n"+SERVER_CAPTURE).encode()
        command = [str(PINNED_PLINK), "-batch", "-noagent", "-ssh", "-l", "nikitos", "-i", str(PINNED_KEY),
                   "-hostkey", HOST_KEY, SERVER,
                   "sudo -n /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C.UTF-8 PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -B -"]
        server = device_capture._bounded_process(command, timeout=30, max_output=16*1024*1024, input_bytes=script)
        if server.returncode != 0:
            raise AndroidAcceptanceError("fixed read-only server acquisition failed")
        matched = _validate_server(server.stdout, nonce=nonce, client_id=self.client_id,
            installation_id=self.installation_id, installed_after=self.installed_after, local_keys=local_keys)
        context.verify()
        for record in (producer, plink, device["producer"], device["adb"]):
            device_capture._verify_record(record)
        original = json.loads(device["raw_capture"], object_pairs_hook=_strict_object)
        closeout_records = [r for r in original if r["label"] == "challenge-after" or r["label"].startswith("after:") or r["label"] == "vpn-after"]
        if not closeout_records:
            raise AndroidAcceptanceError("original read-only device closeout missing")
        device_metadata = {k: v for k, v in device.items() if k not in {"raw_capture", "capture"}}
        raw = json.dumps({"device": device_metadata,
                          "device_original_bytes_b64": base64.b64encode(device["raw_capture"]).decode(),
                          "server_original_stdout_b64": base64.b64encode(server.stdout).decode(),
                          "server_original_stderr_b64": base64.b64encode(server.stderr).decode(),
                          "server_script_sha256": hashlib.sha256(script).hexdigest(),
                          "correlated_deliveries": matched}, sort_keys=True, separators=(",", ":")).encode()
        closeout = json.dumps({"original_device_closeout": closeout_records,
                               "source_context_reverified": True, "no_device_resources_created": True,
                               "server_readonly_script_sha256": hashlib.sha256(script).hexdigest()},
                              sort_keys=True, separators=(",", ":")).encode()
        return {"target": "android", "runId": run_id, "profileId": "android-real-device",
                "startedAt": started_at, "completedAt": _utc(), "rawCapture": raw, "cleanupCapture": closeout,
                "semantics": {"installedIdentity": True, "serviceIdentity": True, "vpnValidated": True,
                              "realLogDelivery": True, "noFatal": True, "readonlyCloseout": True},
                "provenance": [producer, device["producer"], device["adb"], plink]}
