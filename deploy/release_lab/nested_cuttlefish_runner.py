"""Transport-free, fail-closed contracts for nested ARM64 Cuttlefish.

The controller must obtain receipts from a freshly ownership-checked outer
guest over QGA. This module plans and validates; it never claims a live run.
"""
from __future__ import annotations

import base64, hashlib, json, re, shlex, time
from dataclasses import asdict, dataclass
from pathlib import PurePosixPath
from typing import BinaryIO, Callable, Iterator, Mapping, Sequence
from urllib.parse import quote

try:
    from .nested_cuttlefish_wayland_dependency import WaylandDependencyPlan, validate_install as validate_wayland_install, validate_runtime as validate_wayland_runtime
except ImportError:
    from nested_cuttlefish_wayland_dependency import WaylandDependencyPlan, validate_install as validate_wayland_install, validate_runtime as validate_wayland_runtime

# The bridge negotiates this ceiling with an exact write/readback probe and
# falls back to 64/32 KiB on an explicit frame, count, or hash failure.
MAX_CHUNK_SIZE = 256 * 1024
OWNED_ROOT = PurePosixPath("/var/lib/amnezia-release-lab")
NESTED_ROOT = OWNED_ROOT / "n"
SHA_RE = re.compile(r"[0-9a-f]{64}")
ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}")
PACKAGE_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+")
APK_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,158}\.apk")
NOBLE_DASH_SHA256 = "86d31f6fb799e91fa21bad341484564510ca287703a16e9e46c53338776f4f42"
NOBLE_VULKAN_DEB_SHA256 = "ccf4fe8f4461442f27ea2494c7ae650b60bd396fec2688b0c44a27d66a222f74"
NOBLE_VULKAN_LOADER_SHA256 = "e833b010f814b72c6aca0300c8b5f19b6106ffa06c24ddc95a293970c7d6058e"

class NestedCuttlefishError(RuntimeError): pass

def _id(label: str, value: str) -> None:
    if not ID_RE.fullmatch(value): raise NestedCuttlefishError(f"invalid {label}")

def _under(path: str, root: PurePosixPath) -> bool:
    value = PurePosixPath(path)
    try: value.relative_to(root)
    except ValueError: return False
    return value.is_absolute() and value != root

@dataclass(frozen=True)
class OuterOwnership:
    run_id: str; profile: str; attempt_nonce: str; pid: int; start_ticks: int
    uuid: str; qmp_socket: str; qga_socket: str
    def validate(self) -> None:
        _id("run id", self.run_id); _id("profile", self.profile); _id("attempt nonce", self.attempt_nonce)
        if self.profile != "linux-headless-x64" or self.pid <= 1 or self.start_ticks <= 0:
            raise NestedCuttlefishError("outer ownership is not a usable headless guest")
        try:
            import uuid; uuid.UUID(self.uuid)
        except (ValueError, AttributeError) as exc: raise NestedCuttlefishError("invalid outer UUID") from exc
        if not _under(self.qmp_socket, OWNED_ROOT) or not _under(self.qga_socket, OWNED_ROOT):
            raise NestedCuttlefishError("outer sockets are outside the owned lab root")

@dataclass(frozen=True)
class AssetSpec:
    name: str; source_path: str; size: int; sha256: str
    def validate(self) -> None:
        _id("asset name", self.name)
        if not PurePosixPath(self.source_path).is_absolute() or self.size <= 0 or not SHA_RE.fullmatch(self.sha256):
            raise NestedCuttlefishError(f"invalid asset {self.name}")

@dataclass(frozen=True)
class ApkSpec(AssetSpec):
    package: str; version_code: int
    def validate(self) -> None:
        # Release APK names legitimately contain '+'.  Keep this grammar
        # basename-only; separators, traversal, NUL and controls remain
        # impossible, while generic Cuttlefish asset names stay stricter.
        if (not APK_NAME_RE.fullmatch(self.name) or PurePosixPath(self.name).name != self.name
                or not PurePosixPath(self.source_path).is_absolute() or self.size <= 0
                or not SHA_RE.fullmatch(self.sha256)
                or not PACKAGE_RE.fullmatch(self.package) or self.version_code <= 0):
            raise NestedCuttlefishError("invalid exact APK identity")

@dataclass(frozen=True)
class InnerPlan:
    ownership: OuterOwnership; assets: tuple[AssetSpec, ...]; apk: ApkSpec
    vsock_cid: int; runtime_uid: int; adb_endpoint: str = "127.0.0.1:5053"
    boot_timeout_seconds: int = 1200; transfer_timeout_seconds: int = 1800
    launch_argv: tuple[str, ...] = ()
    qemu_aarch64_sha256: str = ""
    trusted_shell_sha256: str = NOBLE_DASH_SHA256
    vulkan_deb_path: str = "/mnt/c/Users/ivano/PycharmProjects/amnezia-client/dist/release-lab-fixtures/android-cvd-vulkan-noble-amd64-20260913/libvulkan1_1.3.275.0-1build1_amd64.deb"
    vulkan_deb_sha256: str = NOBLE_VULKAN_DEB_SHA256
    vulkan_deb_size: int = 142010
    vulkan_loader_sha256: str = NOBLE_VULKAN_LOADER_SHA256
    vulkan_loader_size: int = 510592
    @property
    def root(self) -> str:
        # Cuttlefish appends deep per-instance Unix socket names. Keep the
        # owned runtime path below sockaddr_un.sun_path while binding its
        # opaque directory to the full run/attempt through the marker.
        # Staging creates this directory exclusively and the full marker below
        # retains the complete run/nonce binding. Eight hex characters also
        # leave room for Cuttlefish's deepest generated Unix socket name.
        token=hashlib.sha256(f"{self.ownership.run_id}\0{self.ownership.attempt_nonce}".encode()).hexdigest()[:8]
        return str(NESTED_ROOT / token)
    @property
    def marker(self) -> str: return f"amnezia-release-lab:{self.ownership.run_id}:android-arm64-v8a:{self.ownership.attempt_nonce}"
    def validate(self) -> None:
        self.ownership.validate(); self.apk.validate()
        if self.runtime_uid <= 0 or not 3 <= self.vsock_cid <= 0x7fffffff:
            raise NestedCuttlefishError("invalid nested uid or vsock CID")
        match = re.fullmatch(r"127\.0\.0\.1:([1-9][0-9]{0,4})", self.adb_endpoint)
        if not match or int(match.group(1)) > 65535: raise NestedCuttlefishError("ADB must use a valid loopback port")
        if not 60 <= self.boot_timeout_seconds <= 1800 or not 60 <= self.transfer_timeout_seconds <= 3600:
            raise NestedCuttlefishError("lifecycle timeout is outside the bounded range")
        generated_socket_suffixes=(
            f"/runtime/tmp/cf_avd_{self.runtime_uid}/cvd-1/grpc_socket/GnssGrpcProxyServer.sock",
            f"/runtime/tmp/cf_avd_{self.runtime_uid}/cvd-1/internal/confui_sign.sock",
        )
        if any(len((self.root+s).encode("utf-8")) > 107 for s in generated_socket_suffixes):
            raise NestedCuttlefishError("nested generated runtime path exceeds Unix socket limit")
        if len(self.assets) != 3 or len({x.name for x in self.assets}) != 3:
            raise NestedCuttlefishError("exactly three unique Cuttlefish assets are required")
        for item in self.assets: item.validate()
        if (not self.assets[0].name.endswith(".tar.gz") or not self.assets[1].name.endswith(".zip")
                or not self.assets[2].name.endswith(".tar.gz") or not SHA_RE.fullmatch(self.qemu_aarch64_sha256)
                or not SHA_RE.fullmatch(self.trusted_shell_sha256)
                or not PurePosixPath(self.vulkan_deb_path).is_absolute()
                or self.vulkan_deb_sha256 != NOBLE_VULKAN_DEB_SHA256 or self.vulkan_deb_size != 142010
                or self.vulkan_loader_sha256 != NOBLE_VULKAN_LOADER_SHA256 or self.vulkan_loader_size != 510592):
            raise NestedCuttlefishError("Cuttlefish host/image asset roles are not canonical")
        _validate_launch(self)

def _flags(argv: Sequence[str]) -> dict[str, str]:
    result = {}
    for token in argv[1:]:
        if not token.startswith("-"): raise NestedCuttlefishError("noncanonical launch token")
        body = token.lstrip("-")
        if body == "noresume":
            key, value = body, "true"
        elif "=" in body:
            key, value = body.split("=", 1)
        else:
            raise NestedCuttlefishError("noncanonical launch token")
        if not key or key in result: raise NestedCuttlefishError("duplicate launch flag")
        result[key] = value
    return result

def _validate_launch(plan: InnerPlan) -> None:
    expected_exe = f"{plan.root}/runtime/host/bin/launch_cvd"
    if not plan.launch_argv or plan.launch_argv[0] != expected_exe:
        raise NestedCuttlefishError("launch executable escaped the exact staged runtime")
    required = {"instance_dir":f"{plan.root}/runtime/instance", "assembly_dir":f"{plan.root}/runtime/assembly",
        "system_image_dir":f"{plan.root}/runtime/images", "early_tmp_dir":f"{plan.root}/runtime/tmp",
        "vm_manager":"qemu_cli", "device_external_network":"slirp", "enable_tap_devices":"false",
        "enable_modem_simulator":"true", "start_gnss_proxy":"false", "enable_host_bluetooth":"false",
        "enable_host_nfc":"false", "enable_host_uwb":"false",
        "start_webrtc":"false", "report_anonymous_usage_stats":"n", "gpu_mode":"guest_swiftshader",
        "adb_mode":"vsock_half_tunnel", "run_adb_connector":"true", "cpus":"2", "memory_mb":"4096",
        "vsock_guest_cid":str(plan.vsock_cid),
        "qemu_binary_dir":f"{plan.root}/runtime/qemu",
        "noresume":"true"}
    if _flags(plan.launch_argv) != required: raise NestedCuttlefishError("launch argv differs from canonical isolated configuration")

def iter_asset_chunks(stream: BinaryIO, *, expected_size: int, deadline_monotonic: float,
                      chunk_size: int = MAX_CHUNK_SIZE, now: Callable[[], float] = time.monotonic) -> Iterator[dict]:
    if expected_size <= 0 or not 1 <= chunk_size <= MAX_CHUNK_SIZE: raise NestedCuttlefishError("invalid transfer bound")
    offset = seq = 0
    while offset < expected_size:
        if now() > deadline_monotonic: raise NestedCuttlefishError("asset transfer deadline expired")
        data = stream.read(min(chunk_size, expected_size-offset))
        if not data: raise NestedCuttlefishError("asset stream ended before expected size")
        yield {"sequence":seq,"offset":offset,"size":len(data),"sha256":hashlib.sha256(data).hexdigest(),
               "data_b64":base64.b64encode(data).decode(),"eof":False}
        offset += len(data); seq += 1
    if stream.read(1): raise NestedCuttlefishError("asset stream exceeds expected size")
    if now() > deadline_monotonic: raise NestedCuttlefishError("asset deadline expired before EOF")
    yield {"sequence":seq,"offset":offset,"size":0,"data_b64":"","eof":True}

def transcript_sha256(chunks: Sequence[Mapping]) -> str:
    rows=[{k:x.get(k) for k in ("sequence","offset","size","sha256","eof")} for x in chunks]
    return hashlib.sha256(json.dumps(rows,sort_keys=True,separators=(",",":")).encode()).hexdigest()

def _items(plan: InnerPlan) -> list[AssetSpec]:
    return [*plan.assets, AssetSpec(plan.apk.name,plan.apk.source_path,plan.apk.size,plan.apk.sha256)]

def build_stage_plan(plan: InnerPlan) -> dict:
    plan.validate()
    return {"schema":2,"operation":"nested-cuttlefish-stage","ownership":asdict(plan.ownership),"marker":plan.marker,
        "guest_root":plan.root,"chunk_size_max":MAX_CHUNK_SIZE,"transfer_timeout_seconds":plan.transfer_timeout_seconds,
        "assets":[{**asdict(x),"guest_path":f"{plan.root}/input/{x.name}","require_eof":True,
                   "require_guest_rehash":True,"require_transcript":True} for x in _items(plan)],
        "host_mounts":[],"host_network_mutation":False}

def _common(plan: InnerPlan, receipt: Mapping, operation: str) -> None:
    plan.validate()
    if receipt.get("schema") != 2 or receipt.get("operation") != operation: raise NestedCuttlefishError("invalid receipt schema")
    if (receipt.get("run_id"),receipt.get("profile"),receipt.get("attempt_nonce"),receipt.get("marker")) != \
       (plan.ownership.run_id,plan.ownership.profile,plan.ownership.attempt_nonce,plan.marker):
        raise NestedCuttlefishError("receipt identity mismatch")
    if receipt.get("guest_root") != plan.root or receipt.get("origin") != "guest" or receipt.get("transport") != "qga" or receipt.get("injected") is not False:
        raise NestedCuttlefishError("receipt is not authentic guest QGA evidence")
    if receipt.get("outer_ownership") != asdict(plan.ownership): raise NestedCuttlefishError("outer ownership binding mismatch")

def validate_native_crash_evidence(receipt: Mapping) -> dict:
    if not isinstance(receipt,Mapping) or receipt.get("schema")!=2 or set(receipt)!={"schema","package","expected_pid","observed_pid","launch_epoch","sources"}: raise NestedCuttlefishError("native crash evidence schema invalid")
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+",str(receipt.get("package",""))):raise NestedCuttlefishError("native crash package invalid")
    if isinstance(receipt.get("expected_pid"),bool) or not isinstance(receipt.get("expected_pid"),int) or receipt["expected_pid"]<=0: raise NestedCuttlefishError("native crash expected PID invalid")
    observed=receipt.get("observed_pid")
    if observed is not None and (isinstance(observed,bool) or not isinstance(observed,int) or observed<=0): raise NestedCuttlefishError("native crash observed PID invalid")
    epoch=str(receipt.get("launch_epoch",""))
    if not re.fullmatch(r"\d{10,}(?:\.\d{3})?",epoch): raise NestedCuttlefishError("native crash epoch invalid")
    sources=receipt.get("sources")
    if not isinstance(sources,list) or not 14<=len(sources)<=15: raise NestedCuttlefishError("native crash source count invalid")
    required=("crash","all-since-launch","tombstone-metadata","dropbox-data-app-native-crash","dropbox-data-app-crash","dropbox-system-tombstone","dropbox-system-tombstone-proto","dropbox-system-tombstone-proto-with-headers","capability-shell-id","capability-build-type","capability-debuggable","capability-secure","capability-debug-tools","capability-run-as")
    if tuple(x.get("label") if isinstance(x,Mapping) else None for x in sources[:14])!=required: raise NestedCuttlefishError("native crash source order invalid")
    metadata_script='for f in /data/tombstones/tombstone_*; do [ -e "$f" ] || continue; if [ -f "$f" ] && [ -r "$f" ]; then r=1; else r=0; fi; stat -Lc "%n|%F|%d|%i|%u|%g|%a|%s|%Y|$r" "$f" 2>&1; done'
    tool_script='for f in /system/bin/debuggerd /system/bin/crash_dump64 /system/bin/lldb-server /apex/com.android.runtime/bin/lldb-server /data/local/tmp/lldb-server; do if [ -e "$f" ]; then stat -c "%n|%F|%u|%g|%a|%s" "$f" 2>&1; sha256sum "$f" 2>&1; else printf "%s|missing\\n" "$f"; fi; done'
    expected={"crash":["logcat","-b","crash","-d","-T",epoch,"-v","threadtime"],"all-since-launch":["logcat","-b","all","-d","-T",epoch,"-t","1200","-v","threadtime"],"tombstone-metadata":["shell","sh","-c",metadata_script],"capability-shell-id":["shell","id"],"capability-build-type":["shell","getprop","ro.build.type"],"capability-debuggable":["shell","getprop","ro.debuggable"],"capability-secure":["shell","getprop","ro.secure"],"capability-debug-tools":["shell","sh","-c",tool_script],"capability-run-as":["shell","run-as",receipt.get("package"),"id"]}
    for tag in ("data_app_native_crash","data_app_crash","SYSTEM_TOMBSTONE","SYSTEM_TOMBSTONE_PROTO","SYSTEM_TOMBSTONE_PROTO_WITH_HEADERS"):expected["dropbox-"+tag.lower().replace("_","-")]=["shell","dumpsys","dropbox","--print",tag]
    caps={"crash":262144,"all-since-launch":1048576,"tombstone-metadata":131072,**{x:524288 for x in required[3:8]},**{x:16384 for x in ("capability-shell-id","capability-run-as")},**{x:4096 for x in ("capability-build-type","capability-debuggable","capability-secure")},"capability-debug-tools":131072,"tombstone-bytes":524288,"tombstone-rejected":524288}
    def bounded_bytes(value,cap):
        if not isinstance(value,Mapping) or isinstance(value.get("size"),bool) or not isinstance(value.get("size"),int) or not 0<=value["size"]<=cap or not SHA_RE.fullmatch(str(value.get("sha256",""))):return False
        if value.get("bytes_b64") is not None:
            try:data=base64.b64decode(value["bytes_b64"],validate=True)
            except Exception:return False
            return len(data)==value["size"] and hashlib.sha256(data).hexdigest()==value["sha256"]
        try:excerpt=base64.b64decode(value.get("excerpt_b64",""),validate=True)
        except Exception:return False
        return value.get("complete") is False and value.get("excerpt_size")==len(excerpt) and len(excerpt)<=4096 and hashlib.sha256(excerpt).hexdigest()==value.get("excerpt_sha256")
    def bounded_command(row):
        command=row.get("bounded_command")
        if not isinstance(command,Mapping) or not set(command)<=set(("argv","exit_code","capture_transport","capture_metadata","stdout","stderr")) or not isinstance(command.get("argv"),list) or command["argv"][-len(row["argv"]):]!=row["argv"]:return False
        prefix=command["argv"][:-len(row["argv"])]
        if len(prefix)!=5 or not isinstance(prefix[0],str) or not prefix[0].endswith("/runtime/host/bin/adb") or prefix[1]!="-P" or not re.fullmatch(r"\d{1,5}",str(prefix[2])) or prefix[3]!="-s" or not re.fullmatch(r"127\.0\.0\.1:\d{1,5}",str(prefix[4])):return False
        rc=command.get("exit_code")
        if rc is not None and (isinstance(rc,bool) or not isinstance(rc,int)):return False
        for key in ("stdout","stderr"):
            value=command.get(key)
            if value is not None and not bounded_bytes(value,caps[row["label"]]+1):return False
        transport=command.get("capture_transport")
        if transport is not None and (not isinstance(transport,Mapping) or set(transport)!={"stdout","stderr"} or not bounded_bytes(transport["stdout"],65536) or not bounded_bytes(transport["stderr"],65536)):return False
        meta=command.get("capture_metadata")
        if meta is not None and (not isinstance(meta,Mapping) or set(meta)!={"path","exit_code","timed_out","size","sha256"} or not isinstance(meta.get("path"),str) or isinstance(meta.get("size"),bool) or not isinstance(meta.get("size"),int) or meta["size"]<0 or not SHA_RE.fullmatch(str(meta.get("sha256",""))) or meta.get("timed_out") is not (meta.get("exit_code")==124)):return False
        return True
    for row in sources:
        if not isinstance(row,Mapping) or row.get("label") not in caps or not isinstance(row.get("argv"),list): raise NestedCuttlefishError("native crash source invalid")
        label=row["label"]
        if label in expected:
            argv=expected[label]
            if label=="capability-run-as":argv=["shell","run-as",str(receipt.get("package","")),"id"]
            if row["argv"]!=argv:raise NestedCuttlefishError("native crash argv binding invalid")
        elif label in ("tombstone-bytes","tombstone-rejected"):
            metadata=row.get("metadata");path=metadata.get("path") if isinstance(metadata,Mapping) else None
            read_script='exec 3<"$1" || exit 40; stat -Lc "AMNEZIA_FD|%F|%d|%i|%u|%g|%a|%s|%Y" /proc/self/fd/3 || exit 41; cat <&3'
            if not re.fullmatch(r"/data/tombstones/tombstone_\d+",str(path)) or row["argv"]!=["shell","sh","-c",read_script,"amnezia-tombstone",path]:raise NestedCuttlefishError("native crash tombstone argv invalid")
        output=row.get("output")
        if output is not None:
            allowed={"label","argv","exit_code","timed_out","output"}|({"metadata"} if label=="tombstone-bytes" else set())
            if set(row)!=allowed:raise NestedCuttlefishError("native crash source fields invalid")
            if set(output)!={"origin","transport","path","size","sha256","bytes_b64"} or output.get("origin")!="guest" or output.get("transport")!="qga-adb" or output.get("path")!="adb:native-crash-"+label or not isinstance(output.get("size"),int) or isinstance(output.get("size"),bool) or not 0<=output["size"]<=caps[row["label"]] or not SHA_RE.fullmatch(str(output.get("sha256",""))): raise NestedCuttlefishError("native crash raw bound invalid")
            try: raw=base64.b64decode(output.get("bytes_b64",""),validate=True)
            except Exception as exc: raise NestedCuttlefishError("native crash raw encoding invalid") from exc
            rc=row.get("exit_code")
            if len(raw)!=output["size"] or hashlib.sha256(raw).hexdigest()!=output["sha256"] or isinstance(rc,bool) or not isinstance(rc,int) or not 0<=rc<=255 or row.get("timed_out") is not (rc==124): raise NestedCuttlefishError("native crash source outcome invalid")
        elif label=="tombstone-rejected":
            if set(row)!={"label","argv","exit_code","timed_out","metadata","raw_size","raw_sha256","reason"} or row.get("reason")!="fd-identity-or-pid-mismatch" or isinstance(row.get("raw_size"),bool) or not isinstance(row.get("raw_size"),int) or not 0<=row["raw_size"]<=caps[label] or not SHA_RE.fullmatch(str(row.get("raw_sha256",""))):raise NestedCuttlefishError("native crash tombstone rejection invalid")
        else:
            error=row.get("capture_error")
            allowed={"label","argv","capture_error","bounded_command"}|({"metadata"} if label=="tombstone-bytes" else set())
            if set(row)!=allowed or not isinstance(error,Mapping) or set(error)!={"type","sha256"} or not isinstance(error.get("type"),str) or not error["type"] or not SHA_RE.fullmatch(str(error.get("sha256",""))) or not bounded_command(row): raise NestedCuttlefishError("native crash capture failure durability invalid")
    tomb=[x for x in sources if x.get("label") in ("tombstone-bytes","tombstone-rejected")]
    if len(tomb)>1:raise NestedCuttlefishError("multiple tombstone outcomes")
    if tomb:
        metadata=tomb[0].get("metadata")
        if not isinstance(metadata,Mapping) or set(metadata)!={"path","dev","inode","uid","gid","mode","reported_size","mtime","expected_pid"} or metadata.get("expected_pid")!=receipt["expected_pid"] or any(isinstance(metadata.get(k),bool) or not isinstance(metadata.get(k),int) or metadata[k]<(1 if k in ("dev","inode") else 0) for k in ("dev","inode","reported_size","mtime")) or not re.fullmatch(r"\d+",str(metadata.get("uid",""))) or not re.fullmatch(r"\d+",str(metadata.get("gid",""))) or not re.fullmatch(r"[0-7]{3,4}",str(metadata.get("mode",""))) or metadata["mtime"]<int(float(epoch)):raise NestedCuttlefishError("native crash tombstone binding invalid")
        metadata_output=sources[2].get("output")
        if not isinstance(metadata_output,Mapping):raise NestedCuttlefishError("native crash tombstone metadata unavailable")
        metadata_text=base64.b64decode(metadata_output["bytes_b64"],validate=True).decode("utf-8","replace").splitlines()
        expected_line="|".join((metadata["path"],"regular file",str(metadata["dev"]),str(metadata["inode"]),str(metadata["uid"]),str(metadata["gid"]),str(metadata["mode"]),str(metadata["reported_size"]),str(metadata["mtime"]),"1"))
        if metadata_text.count(expected_line)!=1:raise NestedCuttlefishError("native crash selected tombstone not metadata-bound")
        if tomb[0]["label"]=="tombstone-bytes" and "output" in tomb[0]:
            raw=base64.b64decode(tomb[0]["output"]["bytes_b64"]);first,sep,body=raw.partition(b"\n");identity=first.decode("utf-8","replace").split("|")
            expected_identity=["AMNEZIA_FD","regular file",str(metadata["dev"]),str(metadata["inode"]),str(metadata["uid"]),str(metadata["gid"]),str(metadata["mode"]),str(metadata["reported_size"]),str(metadata["mtime"])]
            if not sep or identity!=expected_identity or metadata["mtime"]<int(float(epoch)) or re.search(rb"(?m)^pid:\s*"+str(receipt["expected_pid"]).encode()+rb",",body) is None:raise NestedCuttlefishError("native crash tombstone identity/PID invalid")
    return dict(receipt)

def validate_stage_receipt(plan: InnerPlan, receipt: Mapping) -> dict:
    _common(plan,receipt,"nested-cuttlefish-stage")
    root_identity=receipt.get("guest_root_identity")
    if (not isinstance(root_identity,Mapping) or any(isinstance(root_identity.get(k),bool) or not isinstance(root_identity.get(k),int) or root_identity[k]<=0 for k in ("dev","inode"))
            or root_identity.get("uid")!=0 or root_identity.get("gid")!=0 or root_identity.get("mode")!="0711"):
        raise NestedCuttlefishError("staged guest root identity is missing")
    ancestry=receipt.get("guest_ancestry")
    rows=ancestry.get("ancestry") if isinstance(ancestry,Mapping) else None
    expected_paths=["/var/lib/amnezia-release-lab","/var/lib/amnezia-release-lab/n"]
    if not isinstance(rows,list) or len(rows)!=2:
        raise NestedCuttlefishError("staged guest ancestry evidence is missing")
    for row,path in zip(rows,expected_paths):
        before=row.get("before") if isinstance(row,Mapping) else None;after=row.get("after") if isinstance(row,Mapping) else None
        if (not isinstance(before,Mapping) or not isinstance(after,Mapping) or before.get("path")!=path or after.get("path")!=path
                or before.get("uid")!=0 or before.get("gid")!=0 or before.get("mode") not in ("0700","0711","0755") or after.get("mode")!="0711"
                or any(isinstance(before.get(k),bool) or not isinstance(before.get(k),int) or before[k]<=0 for k in ("dev","inode"))
                or {k:before.get(k) for k in ("dev","inode","uid","gid")}!={k:after.get(k) for k in ("dev","inode","uid","gid")}):
            raise NestedCuttlefishError("staged guest ancestry transition is invalid")
    attempt=ancestry.get("attempt")
    if (not isinstance(attempt,Mapping) or attempt.get("mode")!="0700" or {k:attempt.get(k) for k in ("dev","inode","uid","gid")}!={k:root_identity.get(k) for k in ("dev","inode","uid","gid")}):
        raise NestedCuttlefishError("staged attempt root phase chain is invalid")
    probe=ancestry.get("runtime_probe")
    if (not isinstance(probe,Mapping) or probe.get("euid")!=plan.runtime_uid or isinstance(probe.get("egid"),bool)
            or not isinstance(probe.get("egid"),int) or probe.get("egid",0)<=0 or probe.get("groups")!=[]
            or probe.get("paths")!=[{"path":p,"execute":True} for p in expected_paths]):
        raise NestedCuttlefishError("runtime uid cannot traverse staged ancestry")
    ownership=receipt.get("runtime_ownership");before=ownership.get("qemu_before") if isinstance(ownership,Mapping) else None;after=ownership.get("qemu_after") if isinstance(ownership,Mapping) else None
    directories=ownership.get("directories") if isinstance(ownership,Mapping) else None
    qemu_path=f"{plan.root}/runtime/qemu/qemu-system-aarch64"
    if (not isinstance(ownership,Mapping) or ownership.get("schema")!=1 or ownership.get("root")!=plan.root or ownership.get("runtime_uid")!=plan.runtime_uid
            or isinstance(ownership.get("primary_gid"),bool) or not isinstance(ownership.get("primary_gid"),int) or ownership.get("primary_gid",0)<=0
            or ownership.get("qemu_sha256")!=plan.qemu_aarch64_sha256 or ownership.get("access_exit_code")!=0 or ownership.get("access")!={"read":True,"execute":True} or ownership.get("origin")!="guest" or ownership.get("transport")!="qga" or ownership.get("injected") is not False
            or not isinstance(before,Mapping) or not isinstance(after,Mapping) or before.get("path")!=qemu_path or after.get("path")!=qemu_path
            or any(isinstance(before.get(k),bool) or not isinstance(before.get(k),int) or before[k]<=0 for k in ("dev","inode"))
            or {k:before.get(k) for k in ("path","dev","inode","mode")}!={k:after.get(k) for k in ("path","dev","inode","mode")}
            or after.get("uid")!=plan.runtime_uid or after.get("gid")!=ownership.get("primary_gid")
            or (ownership.get("root_before") or {}).get("mode")!="0700" or (ownership.get("root_after") or {}).get("mode")!="0711"
            or ownership.get("root_before")!=dict(attempt, path=plan.root) or ownership.get("root_after")!=dict(root_identity, path=plan.root)
            or {k:(ownership.get("root_before") or {}).get(k) for k in ("path","dev","inode","uid","gid")}!={k:(ownership.get("root_after") or {}).get(k) for k in ("path","dev","inode","uid","gid")}
            or not isinstance(directories,list) or [x.get("path") for x in directories if isinstance(x,Mapping)]!=[f"{plan.root}/runtime",f"{plan.root}/logs",f"{plan.root}/runtime/home",f"{plan.root}/runtime/tmp",f"{plan.root}/runtime/instance",f"{plan.root}/runtime/assembly"]
            or directories[0].get("created") is not False or any(x.get("created") not in (True,False) for x in directories[1:])
            or any(x.get("mode") not in ("0700","0755") for x in directories)
            or any(x.get("uid")!=0 or x.get("gid")!=0 or isinstance(x.get("dev"),bool) or not isinstance(x.get("dev"),int) or x.get("dev",0)<=0 or isinstance(x.get("inode"),bool) or not isinstance(x.get("inode"),int) or x.get("inode",0)<=0 for x in directories)):
        raise NestedCuttlefishError("runtime ownership receipt is invalid")
    mutable=[f"{plan.root}/runtime/{x}" for x in ("home","tmp","instance","assembly")]+[f"{plan.root}/logs"]
    if ownership.get("write_probe_exit_code")!=0 or ownership.get("write_probes")!=[{"path":p,"write_delete":True} for p in mutable]:
        raise NestedCuttlefishError("runtime mutable directory proof is invalid")
    records=receipt.get("assets")
    if not isinstance(records,list) or len(records)!=4: raise NestedCuttlefishError("incomplete staged asset set")
    by_name={x.get("name"):x for x in records if isinstance(x,Mapping)}
    if len(by_name)!=len(records): raise NestedCuttlefishError("malformed staged asset set")
    for spec in _items(plan):
        item=by_name.get(spec.name); expected_path=f"{plan.root}/input/{spec.name}"
        if not item or item.get("guest_path")!=expected_path or item.get("size")!=spec.size or item.get("received_size")!=spec.size or item.get("sha256")!=spec.sha256 or item.get("guest_sha256")!=spec.sha256 or item.get("eof") is not True:
            raise NestedCuttlefishError(f"staged bytes/path mismatch for {spec.name}")
        transfer=item.get("transfer")
        if (not isinstance(transfer,Mapping) or isinstance(transfer.get("chunk_count"),bool)
                or not isinstance(transfer.get("chunk_count"),int) or transfer["chunk_count"]<=0
                or transfer.get("received_size")!=spec.size or transfer.get("eof") is not True
                or not SHA_RE.fullmatch(str(transfer.get("transcript_sha256","")) )):
            raise NestedCuttlefishError("compact transfer transcript is invalid")
    if receipt.get("passed") is not True: raise NestedCuttlefishError("stage failed")
    return dict(receipt)

def build_launch_script(plan: InnerPlan) -> str:
    plan.validate()
    assemble=[f"{plan.root}/runtime/host/bin/assemble_cvd",*plan.launch_argv[1:]]
    assemble_argv=" ".join(shlex.quote(x) for x in assemble)
    run_cvd=shlex.quote(f"{plan.root}/runtime/host/bin/run_cvd")
    adapter_code=r'''import hashlib,json,os,pathlib,stat,sys
root=pathlib.Path(sys.argv[1]); uid=int(sys.argv[2]); alias=root/'runtime/assembly'; target1=root/'runtime/instance/assembly'; target2=root/'runtime/instance/instances/cvd-1'; paths=(alias/'cuttlefish_config.json',target1/'cuttlefish_config.json',target2/'cuttlefish_config.json'); targets=(target1/'cuttlefish_config.json',target2/'cuttlefish_config.json'); originals=[]
expected={'external_network_mode':'slirp','enable_modem_simulator':True,'ril_ipaddr':'','ril_gateway':'','ril_prefixlen':255,'ril_dns':''}; replacement={'ril_ipaddr':'10.0.2.15','ril_gateway':'10.0.2.2','ril_prefixlen':24,'ril_dns':'10.0.2.3'}
def atomic(path,data,mode):
 tmp=path.with_name(path.name+'.amnezia-network.tmp'); fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
 try:
  view=memoryview(data)
  while view:
   n=os.write(fd,view); view=view[n:]
  os.fsync(fd)
 finally: os.close(fd)
 os.replace(tmp,path); d=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW); os.fsync(d); os.close(d)
try:
 checks=((root,0,0o711),(root/'runtime',uid,0o755),(root/'runtime/instance',uid,0o700),(target1,uid,0o775),(root/'runtime/instance/instances',uid,0o775),(target2,uid,0o775))
 for path,owner,perm in checks:
  s=path.lstat()
  if not stat.S_ISDIR(s.st_mode) or path.is_symlink() or s.st_uid!=owner or s.st_gid!=owner or stat.S_IMODE(s.st_mode)!=perm: raise ValueError(f'ancestry identity:{path}:{s.st_uid}:{s.st_gid}:{stat.S_IMODE(s.st_mode):o}')
 ls=alias.lstat()
 if not stat.S_ISLNK(ls.st_mode) or ls.st_uid!=uid or ls.st_gid!=uid or os.readlink(alias)!=str(target1): raise ValueError('assembly alias identity')
 unique_originals=[]; unique_identities=[]
 for path in targets:
  s=path.lstat()
  if not stat.S_ISREG(s.st_mode) or path.is_symlink() or s.st_uid!=uid or s.st_gid!=uid or stat.S_IMODE(s.st_mode)!=0o600: raise ValueError('config identity')
  fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW); held=os.fstat(fd); chunks=[]
  try:
   while True:
    chunk=os.read(fd,1048576)
    if not chunk: break
    chunks.append(chunk)
  finally: os.close(fd)
  raw=b''.join(chunks)
  if (held.st_dev,held.st_ino,held.st_size)!=(s.st_dev,s.st_ino,len(raw)): raise ValueError('config changed')
  cfg=json.loads(raw); inst=cfg['instances']['1']
  if any(inst.get(k)!=v for k,v in expected.items()): raise ValueError('unexpected native network shape')
  unique_identities.append((held.st_dev,held.st_ino)); unique_originals.append((path,raw,cfg))
 if unique_identities[0]==unique_identities[1]: raise ValueError('config alias topology')
 originals=[(paths[0],unique_originals[0][1],unique_originals[0][2]),(paths[1],unique_originals[0][1],unique_originals[0][2]),(paths[2],unique_originals[1][1],unique_originals[1][2])]; identities=[unique_identities[0],unique_identities[0],unique_identities[1]]
 if len({raw for _,raw,_ in originals})!=1: raise ValueError('config bytes differ')
 updated=[]
 for _,_,cfg in originals[:1]:
  inst=cfg['instances']['1']; inst.update(replacement); updated.append((json.dumps(cfg,sort_keys=True,separators=(',',':'))+'\n').encode())
 data=updated[0]; unique=((targets[0],originals[0][1]),(targets[1],originals[2][1])); written=[]
 try:
  for path,raw in unique: written.append((path,raw)); atomic(path,data,0o600)
 except BaseException:
  rollback=[]
  for path,raw in reversed(written):
   try: atomic(path,raw,0o600); rollback.append(str(path))
   except BaseException: pass
  if len(rollback)!=len(written): raise RuntimeError('network adapter rollback incomplete')
  raise
 records=[]
 for order,(path,raw,_) in enumerate(originals,1):
  check=path.read_bytes()
  if check!=data: raise RuntimeError('network adapter readback mismatch')
  now=path.stat(); records.append({'order':order,'path':str(path),'target_order':1 if order<3 else 2,'before_dev':identities[order-1][0],'before_inode':identities[order-1][1],'after_dev':now.st_dev,'after_inode':now.st_ino,'before_sha256':hashlib.sha256(raw).hexdigest(),'before_size':len(raw),'after_sha256':hashlib.sha256(check).hexdigest(),'after_size':len(check)})
 if (records[0]['after_dev'],records[0]['after_inode'])!=(records[1]['after_dev'],records[1]['after_inode']) or (records[2]['after_dev'],records[2]['after_inode'])==(records[0]['after_dev'],records[0]['after_inode']): raise RuntimeError('network adapter alias readback mismatch')
 receipt={'schema':2,'records':records,'unique_target_writes':2,'alias':{'path':str(alias),'target':str(target1)},'before_identical':True,'after_identical':len({x['after_sha256'] for x in records})==1,'source_shape':expected,'applied':replacement}
 out=root/'runtime/network-config-adapter.json'; atomic(out,(json.dumps(receipt,sort_keys=True,separators=(',',':'))+'\n').encode(),0o600)
except BaseException as exc:
 print('network-config-adapter:'+type(exc).__name__,file=sys.stderr); raise
'''
    adapter_b64=base64.b64encode(adapter_code.encode()).decode()
    return f'''#!/bin/sh
set -eu
umask 077
root={shlex.quote(plan.root)}
[ "$(cat "$root/marker")" = {shlex.quote(plan.marker)} ] || {{ echo marker-mismatch >&2; exit 70; }}
cvd_entry=$(getent group cvdnetwork) || {{ echo cvdnetwork-missing >&2; exit 72; }}
old_ifs=$IFS; IFS=:; set -- $cvd_entry; IFS=$old_ifs; cvd_gid=$3
kvm_entry=$(getent group kvm) || {{ echo kvm-missing >&2; exit 72; }}
old_ifs=$IFS; IFS=:; set -- $kvm_entry; IFS=$old_ifs; kvm_gid=$3
case "$kvm_gid" in ''|*[!0-9]*) echo kvm-gid-invalid >&2; exit 72;; esac
[ "$(stat -c '%F:%u:%g:%a' /dev/vhost-vsock)" = "character special file:0:$kvm_gid:660" ] || {{ echo vhost-vsock-identity >&2; exit 72; }}
case "$cvd_gid" in ''|*[!0-9]*) echo cvdnetwork-gid-invalid >&2; exit 72;; esac
id -G {plan.runtime_uid} | tr ' ' '\n' | grep -Fx "$cvd_gid" >/dev/null || {{ echo runtime-not-cvdnetwork-member >&2; exit 72; }}
export HOME="$root/runtime/home" TMPDIR="$root/runtime/tmp" ANDROID_HOST_OUT="$root/runtime/host" ANDROID_PRODUCT_OUT="$root/runtime/images"
export LD_LIBRARY_PATH="$root/runtime/private-libs:$root/runtime/qemu:$root/runtime/host/lib64:$root/runtime/host/lib" ADB_SERVER_SOCKET=tcp:localhost:{plan.adb_endpoint.rsplit(':',1)[1]}
[ -d "$HOME" ] && [ -d "$TMPDIR" ] && [ -d "$root/runtime/instance" ] && [ -d "$root/runtime/assembly" ] && [ -d "$root/logs" ] || {{ echo runtime-directory-missing >&2; exit 71; }}
[ "$(stat -c '%u:%g:%a' "$HOME")" = "{plan.runtime_uid}:{plan.runtime_uid}:700" ] && [ "$(stat -c '%u:%g:%a' "$TMPDIR")" = "{plan.runtime_uid}:{plan.runtime_uid}:700" ] && [ "$(stat -c '%u:%g:%a' "$root/runtime/instance")" = "{plan.runtime_uid}:{plan.runtime_uid}:700" ] && [ "$(stat -c '%u:%g:%a' "$root/runtime/assembly")" = "{plan.runtime_uid}:{plan.runtime_uid}:700" ] && [ "$(stat -c '%u:%g:%a' "$root/logs")" = "{plan.runtime_uid}:{plan.runtime_uid}:700" ] || {{ echo runtime-directory-identity >&2; exit 71; }}
[ -x "$root/runtime/host/bin/launch_cvd" ] && [ -x "$root/runtime/host/bin/adb" ] && [ -x "$root/runtime/qemu/qemu-system-aarch64" ] || {{ echo executable-missing >&2; exit 71; }}
setpriv --reuid={plan.runtime_uid} --regid={plan.runtime_uid} --groups "$cvd_gid" test -x "$root/runtime/host/bin/launch_cvd"
setpriv --reuid={plan.runtime_uid} --regid={plan.runtime_uid} --groups "$cvd_gid" test -x "$root/runtime/host/bin/adb"
setpriv --reuid={plan.runtime_uid} --regid={plan.runtime_uid} --groups "$cvd_gid,$kvm_gid" test -r /dev/vhost-vsock
setpriv --reuid={plan.runtime_uid} --regid={plan.runtime_uid} --groups "$cvd_gid,$kvm_gid" test -w /dev/vhost-vsock
setpriv --reuid={plan.runtime_uid} --regid={plan.runtime_uid} --groups "$cvd_gid,$kvm_gid" test -x "$root/runtime/qemu/qemu-system-aarch64"
cgroup=/sys/fs/cgroup/amnezia-release-lab/{shlex.quote(plan.ownership.run_id)}/{shlex.quote(plan.ownership.attempt_nonce)}
install -d -m 0755 "$cgroup"
owned_exec='import os,sys; p=sys.argv[1]; a=sys.argv[2:]; fd=os.open(p,os.O_WRONLY); n=(str(os.getpid())+"\\n").encode(); w=os.write(fd,n); os.close(fd); w==len(n) or (_ for _ in ()).throw(OSError("short cgroup write")); os.execvp(a[0],a)'
python3 -c "$owned_exec" "$cgroup/cgroup.procs" setpriv --reuid={plan.runtime_uid} --regid={plan.runtime_uid} --groups "$cvd_gid" "$ANDROID_HOST_OUT/bin/adb" -L tcp:localhost:{plan.adb_endpoint.rsplit(':',1)[1]} server nodaemon >"$root/logs/adb.stdout" 2>"$root/logs/adb.stderr" &
printf '%s\n' "$!" >"$root/adb.pid"
cd "$root/runtime"
cat >"$root/runtime/start-cvd.sh" <<'AMNEZIA_CVD_START'
#!/bin/sh
set -eu
root={shlex.quote(plan.root)}
cd "$root/runtime"
{assemble_argv}
python3 -c "import base64;exec(compile(base64.b64decode('{adapter_b64}'),'network-config-adapter','exec'))" "$root" {plan.runtime_uid}
exec {run_cvd}
AMNEZIA_CVD_START
chmod 0700 "$root/runtime/start-cvd.sh"
chown {plan.runtime_uid}:{plan.runtime_uid} "$root/runtime/start-cvd.sh"
python3 -c "$owned_exec" "$cgroup/cgroup.procs" setpriv --reuid={plan.runtime_uid} --regid={plan.runtime_uid} --groups "$cvd_gid,$kvm_gid" setsid "$root/runtime/start-cvd.sh" >"$root/logs/launch.stdout" 2>"$root/logs/launch.stderr" &
printf '%s\n' "$!" >"$root/session-leader.pid"
'''

PROCESS_FIELDS=("pid","start_ticks","exe","exe_sha256","uid","groups","state","argv","cmdline_sha256","cgroup")
def _proc(plan: InnerPlan, role: str, item: object, cgroup: str, cvd_gid: int, kvm_gid: int) -> int:
    if not isinstance(item,Mapping) or any(k not in item for k in PROCESS_FIELDS): raise NestedCuttlefishError(f"incomplete {role} /proc identity")
    expected_groups=[cvd_gid] if role=="adb" else sorted([cvd_gid,kvm_gid])
    if (not isinstance(item["pid"],int) or item["pid"]<=1 or not isinstance(item["start_ticks"],int) or item["start_ticks"]<=0 or item["uid"]!=plan.runtime_uid
            or (item["groups"] not in ([cvd_gid],sorted([cvd_gid,kvm_gid])) if role=="aux" else item["groups"]!=expected_groups) or item["cgroup"]!=cgroup):
        raise NestedCuttlefishError(f"invalid {role} identity")
    if item["state"] in {"Z","X","x"} or not SHA_RE.fullmatch(str(item["exe_sha256"])) or not SHA_RE.fullmatch(str(item["cmdline_sha256"])): raise NestedCuttlefishError(f"unhashed/dead {role}")
    exe=str(item["exe"])
    roots=(PurePosixPath(plan.root)/"runtime/qemu",PurePosixPath(plan.root)/"runtime/host/bin") if role=="aux" else \
          (PurePosixPath(plan.root)/("runtime/qemu" if role=="qemu" else "runtime/host/bin"),)
    argv=item["argv"]
    trusted_launcher_shell=(role=="aux" and exe=="/usr/bin/dash" and item["exe_sha256"]==plan.trusted_shell_sha256
        and argv==["/bin/sh",f"{plan.root}/runtime/start-cvd.sh"])
    if not any(_under(exe,root) for root in roots) and not trusted_launcher_shell: raise NestedCuttlefishError(f"{role} executable escaped runtime")
    if (not isinstance(argv,list) or not argv or not all(isinstance(x,str) and x for x in argv)
            or (not any(_under(argv[0],root) for root in roots) and not trusted_launcher_shell)):
        raise NestedCuttlefishError(f"{role} argv is invalid")
    if role in {"cvd","adb","qemu"} and plan.root not in "\0".join(argv): raise NestedCuttlefishError(f"{role} argv is not root-bound")
    token={"cvd":"cvd","adb":"adb","qemu":"qemu-system-aarch64"}.get(role)
    if token and token not in PurePosixPath(exe).name.lower(): raise NestedCuttlefishError(f"unexpected {role} executable")
    if role=="qemu" and str(plan.vsock_cid) not in "\0".join(argv): raise NestedCuttlefishError("QEMU vsock mismatch")
    if role=="adb" and plan.adb_endpoint.rsplit(":",1)[1] not in "\0".join(argv): raise NestedCuttlefishError("ADB port mismatch")
    return item["pid"]

def validate_boot_receipt(plan: InnerPlan, receipt: Mapping) -> dict:
    _common(plan,receipt,"nested-cuttlefish-boot")
    containment=receipt.get("containment"); processes=receipt.get("processes"); roles=receipt.get("roles")
    cvd_gid=receipt.get("cvdnetwork_gid");kvm_gid=receipt.get("kvm_gid");vhost=receipt.get("vhost_vsock")
    if (isinstance(cvd_gid,bool) or not isinstance(cvd_gid,int) or cvd_gid<=0 or isinstance(kvm_gid,bool) or not isinstance(kvm_gid,int) or kvm_gid<=0
            or not isinstance(vhost,Mapping) or vhost.get("path")!="/dev/vhost-vsock" or any(isinstance(vhost.get(k),bool) or not isinstance(vhost.get(k),int) or vhost[k]<=0 for k in ("dev","inode","rdev"))
            or vhost.get("uid")!=0 or vhost.get("gid")!=kvm_gid or vhost.get("mode")!="0660" or vhost.get("char") is not True):
        raise NestedCuttlefishError("cvdnetwork/kvm/vhost binding missing")
    expected_cgroup=f"/amnezia-release-lab/{plan.ownership.run_id}/{plan.ownership.attempt_nonce}"
    if not isinstance(containment,Mapping) or containment.get("kind")!="cgroup-v2" or containment.get("path")!=expected_cgroup or not isinstance(containment.get("stable_reads"),int) or containment["stable_reads"]<2: raise NestedCuttlefishError("owned cgroup containment missing")
    if not isinstance(processes,list) or len(processes)<2 or not isinstance(roles,Mapping) or set(roles)!={"cvd","adb","qemu"} or (roles.get("cvd") is not None and roles.get("cvd") not in {x.get("pid") for x in processes if isinstance(x,Mapping)}): raise NestedCuttlefishError("complete process inventory/roles missing")
    by_pid={x.get("pid"):x for x in processes if isinstance(x,Mapping)}
    if len(by_pid)!=len(processes) or containment.get("member_pids")!=sorted(by_pid): raise NestedCuttlefishError("cgroup membership ambiguous")
    for item in processes: _proc(plan,"aux",item,expected_cgroup,cvd_gid,kvm_gid)
    pids=[_proc(plan,r,by_pid.get(roles[r]),expected_cgroup,cvd_gid,kvm_gid) for r in ("adb","qemu")]
    if roles.get("cvd") is not None: pids.append(_proc(plan,"cvd",by_pid.get(roles["cvd"]),expected_cgroup,cvd_gid,kvm_gid))
    if len(set(pids))!=len(pids): raise NestedCuttlefishError("role identities are ambiguous")
    boot=receipt.get("boot")
    if not isinstance(boot,Mapping) or boot.get("abi")!="arm64-v8a" or boot.get("boot_completed")!="1" or not ID_RE.fullmatch(str(boot.get("serial",""))): raise NestedCuttlefishError("ARM64 boot evidence incomplete")
    try:
        import uuid; uuid.UUID(str(boot.get("boot_id","")))
    except ValueError as exc: raise NestedCuttlefishError("invalid boot ID") from exc
    network=receipt.get("network")
    if not isinstance(network,Mapping) or {k:network.get(k) for k in ("adb_listen","host_mutation","host_mounts")}!={"adb_listen":plan.adb_endpoint,"host_mutation":False,"host_mounts":[]}: raise NestedCuttlefishError("private transport mismatch")
    netargv=network.get("qemu_netdev_argv"); frontends=network.get("qemu_frontend_argv"); native=network.get("native_config"); guest_network=network.get("guest_network")
    if not isinstance(netargv,list) or any(not isinstance(x,str) or "net=/255" in x or "host=," in x for x in netargv): raise NestedCuttlefishError("QEMU network argv was not proven")
    hostnet=[x for x in netargv if x.startswith("user,id=hostnet0,")]
    if hostnet!="user,id=hostnet0,net=10.0.2.15/24,host=10.0.2.2,dns=127.0.0.1".splitlines() or not isinstance(frontends,list) or len(frontends)!=1 or "netdev=hostnet0" not in frontends[0]: raise NestedCuttlefishError("native QEMU hostnet0 slirp wiring missing")
    if not isinstance(native,Mapping) or set(native)!={"schema","records","adapter"} or native.get("schema")!=1 or not isinstance(native.get("records"),list) or len(native["records"])!=3: raise NestedCuttlefishError("native config receipt missing")
    expected_order=[f"{plan.root}/runtime/assembly/cuttlefish_config.json",f"{plan.root}/runtime/instance/assembly/cuttlefish_config.json",f"{plan.root}/runtime/instance/instances/cvd-1/cuttlefish_config.json"]
    if [x.get("path") for x in native["records"] if isinstance(x,Mapping)]!=expected_order: raise NestedCuttlefishError("native config paths are not exact")
    for item in native["records"]:
        if not isinstance(item,Mapping) or set(item)!={"path","sha256","size","external_network_mode","enable_modem_simulator","ril_ipaddr","ril_gateway","ril_prefixlen","ril_dns"} or not SHA_RE.fullmatch(str(item.get("sha256",""))) or not isinstance(item.get("size"),int) or isinstance(item.get("size"),bool) or item["size"]<=0 or item.get("external_network_mode")!="slirp" or item.get("enable_modem_simulator") is not True or {k:item.get(k) for k in ("ril_ipaddr","ril_gateway","ril_prefixlen","ril_dns")}!={"ril_ipaddr":"10.0.2.15","ril_gateway":"10.0.2.2","ril_prefixlen":24,"ril_dns":"10.0.2.3"}: raise NestedCuttlefishError("native config binding invalid")
    if len({x["sha256"] for x in native["records"]})!=1: raise NestedCuttlefishError("native config bytes differ")
    adapter=native["adapter"]; adapter_receipt=adapter.get("receipt") if isinstance(adapter,Mapping) else None
    if not isinstance(adapter,Mapping) or set(adapter)!={"path","sha256","size","receipt"} or adapter.get("path")!=f"{plan.root}/runtime/network-config-adapter.json" or not SHA_RE.fullmatch(str(adapter.get("sha256",""))) or not isinstance(adapter.get("size"),int) or isinstance(adapter.get("size"),bool) or adapter["size"]<=0 or not isinstance(adapter_receipt,Mapping) or set(adapter_receipt)!={"schema","records","unique_target_writes","alias","before_identical","after_identical","source_shape","applied"} or adapter_receipt.get("schema")!=2 or adapter_receipt.get("unique_target_writes")!=2 or adapter_receipt.get("alias")!={"path":f"{plan.root}/runtime/assembly","target":f"{plan.root}/runtime/instance/assembly"} or adapter_receipt.get("before_identical") is not True or adapter_receipt.get("after_identical") is not True or adapter_receipt.get("source_shape")!={"external_network_mode":"slirp","enable_modem_simulator":True,"ril_ipaddr":"","ril_gateway":"","ril_prefixlen":255,"ril_dns":""} or adapter_receipt.get("applied")!={"ril_ipaddr":"10.0.2.15","ril_gateway":"10.0.2.2","ril_prefixlen":24,"ril_dns":"10.0.2.3"}: raise NestedCuttlefishError("network adapter receipt invalid")
    adapter_records=adapter_receipt.get("records")
    if not isinstance(adapter_records,list) or len(adapter_records)!=3 or [x.get("path") for x in adapter_records if isinstance(x,Mapping)]!=expected_order: raise NestedCuttlefishError("network adapter paths invalid")
    for index,(row,config) in enumerate(zip(adapter_records,native["records"]),1):
        if not isinstance(row,Mapping) or set(row)!={"order","path","target_order","before_dev","before_inode","after_dev","after_inode","before_sha256","before_size","after_sha256","after_size"} or row.get("order")!=index or row.get("target_order")!=(1 if index<3 else 2) or any(not isinstance(row.get(k),int) or isinstance(row.get(k),bool) or row[k]<=0 for k in ("before_dev","before_inode","after_dev","after_inode")) or not SHA_RE.fullmatch(str(row.get("before_sha256",""))) or not isinstance(row.get("before_size"),int) or isinstance(row.get("before_size"),bool) or row["before_size"]<=0 or row.get("after_sha256")!=config["sha256"] or row.get("after_size")!=config["size"]: raise NestedCuttlefishError("network adapter binding invalid")
    if (adapter_records[0]["before_dev"],adapter_records[0]["before_inode"])!=(adapter_records[1]["before_dev"],adapter_records[1]["before_inode"]) or (adapter_records[2]["before_dev"],adapter_records[2]["before_inode"])==(adapter_records[0]["before_dev"],adapter_records[0]["before_inode"]) or (adapter_records[0]["after_dev"],adapter_records[0]["after_inode"])!=(adapter_records[1]["after_dev"],adapter_records[1]["after_inode"]) or (adapter_records[2]["after_dev"],adapter_records[2]["after_inode"])==(adapter_records[0]["after_dev"],adapter_records[0]["after_inode"]): raise NestedCuttlefishError("network adapter alias topology invalid")
    if not isinstance(guest_network,Mapping) or set(guest_network)!={"link","address","rules","routes","routes_all","endpoint_route","ril_state","ril_log"}: raise NestedCuttlefishError("guest network proof missing")
    for row in guest_network.values():
        if (not isinstance(row,Mapping) or set(row)!={"argv","exit_code","stdout","stdout_size","stdout_sha256","stderr","stderr_size","stderr_sha256"}
                or not isinstance(row.get("argv"),list) or not row["argv"] or len(row["argv"])>32 or any(not isinstance(x,str) or len(x)>4096 for x in row["argv"])
                or not isinstance(row.get("exit_code"),int) or isinstance(row.get("exit_code"),bool)
                or not isinstance(row.get("stdout"),str) or len(row["stdout"])>4096 or not isinstance(row.get("stderr"),str) or len(row["stderr"])>4096
                or any(not SHA_RE.fullmatch(str(row.get(k,""))) for k in ("stdout_sha256","stderr_sha256"))
                or any(not isinstance(row.get(k),int) or isinstance(row.get(k),bool) or not 0<=row[k]<=1048576 for k in ("stdout_size","stderr_size"))
                or row["stdout_size"]<len(row["stdout"]) or row["stderr_size"]<len(row["stderr"])): raise NestedCuttlefishError("guest network command evidence invalid")
        for stream in ("stdout","stderr"):
            if row[f"{stream}_size"]<=4096 and (row[f"{stream}_size"]!=len(row[stream]) or row[f"{stream}_sha256"]!=hashlib.sha256(row[stream].encode()).hexdigest()): raise NestedCuttlefishError("guest network command evidence invalid")
    connection=network.get("adb_connection"); binding=connection.get("binding") if isinstance(connection,Mapping) else None
    if not isinstance(binding,Mapping) or not isinstance(binding.get("endpoint"),str) or not re.fullmatch(r"127\.0\.0\.1:([1-9][0-9]{3,4})",binding["endpoint"]): raise NestedCuttlefishError("derived ADB endpoint binding missing")
    endpoint=binding["endpoint"]; guest_port=int(endpoint.rsplit(":",1)[1])
    if guest_port>65535 or connection.get("endpoint")!=endpoint or boot.get("serial")!=endpoint.replace(":","_"): raise NestedCuttlefishError("derived ADB endpoint differs from boot")
    config_rows=binding.get("config_rows")
    if not isinstance(config_rows,list) or len(config_rows)!=3 or {x.get("path") for x in config_rows if isinstance(x,Mapping)}!=set(expected_order): raise NestedCuttlefishError("ADB generated config bindings missing")
    native_by_path={x["path"]:x for x in native["records"]}
    for item in config_rows:
        source=native_by_path.get(item.get("path"))
        if (not isinstance(item,Mapping) or source is None or item.get("sha256")!=source.get("sha256") or item.get("size")!=source.get("size")
                or item.get("adb_host_port")!=guest_port or item.get("adb_ip_and_port")!=f"0.0.0.0:{guest_port}"): raise NestedCuttlefishError("ADB generated config binding invalid")
    connector=by_pid.get(binding.get("connector_pid")); proxy=by_pid.get(binding.get("proxy_pid"))
    connector_argv=[f"{plan.root}/runtime/host/bin/adb_connector",f"--addresses=0.0.0.0:{guest_port}"]
    if connector is None or connector.get("argv")!=connector_argv or binding.get("connector_argv")!=connector_argv: raise NestedCuttlefishError("ADB connector process binding invalid")
    if proxy is None or PurePosixPath(str(proxy.get("exe",""))).name!="socket_vsock_proxy" or binding.get("proxy_argv")!=proxy.get("argv"): raise NestedCuttlefishError("ADB vsock proxy process binding invalid")
    proxy_flags={a[2:].split("=",1)[0]:a[2:].split("=",1)[1] for a in proxy["argv"][1:] if isinstance(a,str) and a.startswith("--") and "=" in a}
    if {k:proxy_flags.get(k) for k in ("server_type","server_tcp_port","client_type","client_vsock_port","client_vsock_id","label")}!={"server_type":"tcp","server_tcp_port":str(guest_port),"client_type":"vsock","client_vsock_port":"5555","client_vsock_id":str(plan.vsock_cid),"label":"adb"}: raise NestedCuttlefishError("ADB vsock proxy argv binding invalid")
    adb=f"{plan.root}/runtime/host/bin/adb"; server_port=plan.adb_endpoint.rsplit(":",1)[1]
    expected_commands=([adb,"-P",server_port,"devices"],[adb,"-P",server_port,"connect",endpoint],[adb,"-P",server_port,"devices"])
    for key,argv in zip(("before","connect","after"),expected_commands):
        row=connection.get(key)
        if (not isinstance(row,Mapping) or row.get("argv")!=argv or isinstance(row.get("exit_code"),bool) or row.get("exit_code")!=0
                or any(isinstance(row.get(k),bool) or not isinstance(row.get(k),int) or not 0<=row[k]<=1_048_576 for k in ("stdout_size","stderr_size"))
                or any(not SHA_RE.fullmatch(str(row.get(k,""))) for k in ("stdout_sha256","stderr_sha256"))
                or any(not isinstance(row.get(k),str) or len(row[k])>4096 for k in ("stdout","stderr"))): raise NestedCuttlefishError("ADB connection command receipt invalid")
    lines=connection["after"]["stdout"].splitlines(); devices=[x.split()[0] for x in lines[1:] if x.strip().endswith("device")]
    if devices!=[endpoint]: raise NestedCuttlefishError("derived ADB device was not registered")
    if receipt.get("vsock_cid")!=plan.vsock_cid or receipt.get("adb_endpoint")!=plan.adb_endpoint: raise NestedCuttlefishError("private transport mismatch")
    dependency=receipt.get("runtime_dependency"); provision=dependency.get("group_provisioning") if isinstance(dependency,Mapping) else None; installed=dependency.get("installed") if isinstance(dependency,Mapping) else None
    wayland_install=dependency.get("wayland_install") if isinstance(dependency,Mapping) else None;wayland_runtime=dependency.get("wayland_runtime") if isinstance(dependency,Mapping) else None
    wayland_plan=object.__new__(WaylandDependencyPlan)
    for key,value in (("run_id",plan.ownership.run_id),("profile",plan.ownership.profile),("attempt_nonce",plan.ownership.attempt_nonce),("runtime_uid",plan.runtime_uid),("outer",asdict(plan.ownership)),("qemu_sha256",plan.qemu_aarch64_sha256)):
        object.__setattr__(wayland_plan,key,value)
    qemu_path=f"{plan.root}/runtime/qemu/qemu-system-aarch64"
    try:
        validate_wayland_install(wayland_plan,wayland_install)
        validate_wayland_runtime(wayland_plan,wayland_install,wayland_runtime,qemu_path)
    except (TypeError,ValueError,RuntimeError) as exc:
        raise NestedCuttlefishError("frozen Wayland runtime dependency evidence missing") from exc
    loader=installed.get("loader") if isinstance(installed,Mapping) else None
    commands=provision.get("commands") if isinstance(provision,Mapping) else None; group_files=provision.get("files") if isinstance(provision,Mapping) else None
    if (not isinstance(dependency,Mapping) or not isinstance(provision,Mapping) or provision.get("schema")!=1
            or provision.get("uid")!=plan.runtime_uid or provision.get("created") is not True or provision.get("member") is not True
            or provision.get("cvdnetwork_gid")!=cvd_gid or provision.get("origin")!="guest" or provision.get("transport")!="qga" or provision.get("injected") is not False
            or provision.get("kvm_modified") is not False or provision.get("vhost_modified") is not False
            or not isinstance(group_files,list) or {x.get("path") for x in group_files if isinstance(x,Mapping)}!={"/etc/group","/etc/gshadow"}
            or any(not SHA_RE.fullmatch(str(x.get(k,""))) for x in group_files for k in ("before_sha256","after_sha256"))
            or any(x.get("before_sha256")==x.get("after_sha256") for x in group_files)
            or not isinstance(commands,list) or [x.get("argv") for x in commands] != [["/usr/sbin/groupadd","--system","cvdnetwork"],["/usr/sbin/usermod","-aG","cvdnetwork",provision.get("user")]]
            or any(x.get("exit_code")!=0 or not SHA_RE.fullmatch(str(x.get("exe_sha256",""))) for x in commands)
            or not isinstance(dependency.get("stage"),Mapping)
            or dependency["stage"].get("sha256")!=plan.vulkan_deb_sha256 or dependency["stage"].get("size")!=plan.vulkan_deb_size
            or not isinstance(dependency["stage"].get("guest_root_identity"),Mapping)
            or set(dependency["stage"]["guest_root_identity"])!={"dev","inode","uid","gid","mode"}
            or any(isinstance(dependency["stage"]["guest_root_identity"].get(k),bool) or not isinstance(dependency["stage"]["guest_root_identity"].get(k),int) or dependency["stage"]["guest_root_identity"][k]<0 for k in ("dev","inode","uid","gid"))
            or dependency["stage"]["guest_root_identity"].get("dev")<=0 or dependency["stage"]["guest_root_identity"].get("inode")<=0
            or dependency["stage"]["guest_root_identity"].get("uid")!=0 or dependency["stage"]["guest_root_identity"].get("gid")!=0 or dependency["stage"]["guest_root_identity"].get("mode")!="0711"
            or not isinstance(installed,Mapping) or installed.get("run_id")!=plan.ownership.run_id or installed.get("attempt_nonce")!=plan.ownership.attempt_nonce
            or installed.get("origin")!="guest" or installed.get("transport")!="qga" or installed.get("injected") is not False
            or not isinstance(loader,Mapping) or loader.get("path")!=f"{plan.root}/runtime/private-libs/libvulkan.so.1.3.275"
            or loader.get("sha256")!=plan.vulkan_loader_sha256 or loader.get("size")!=plan.vulkan_loader_size
            or loader.get("uid")!=0 or loader.get("mode")!="0644" or loader.get("directory_uid")!=0 or loader.get("directory_mode")!="0755"
            or installed.get("dlopen") is not True or installed.get("vkGetInstanceProcAddr") is not True
            or not isinstance(installed.get("graphics_detector"),Mapping)
            or installed["graphics_detector"].get("exit_code")!=0 or installed["graphics_detector"].get("assertion") is not False
            or installed["graphics_detector"].get("uid")!=plan.runtime_uid or installed["graphics_detector"].get("groups")!=[cvd_gid]
            or not SHA_RE.fullmatch(str(installed["graphics_detector"].get("stdout_sha256","")))
            or not SHA_RE.fullmatch(str(installed["graphics_detector"].get("stderr_sha256","")))
            or any(isinstance(installed["graphics_detector"].get(k),bool) or not isinstance(installed["graphics_detector"].get(k),int) or not 0<=installed["graphics_detector"][k]<=16384 for k in ("stdout_size","stderr_size"))
            or not isinstance(installed["graphics_detector"].get("output_file"),Mapping)
            or installed["graphics_detector"]["output_file"].get("path")!=f"{plan.root}/runtime/graphics-probe/availability.pbtxt"
            or installed["graphics_detector"]["output_file"].get("kind")!="regular"
            or installed["graphics_detector"]["output_file"].get("uid")!=plan.runtime_uid
            or installed["graphics_detector"]["output_file"].get("mode")!="0600"
            or any(isinstance(installed["graphics_detector"]["output_file"].get(k),bool) or not isinstance(installed["graphics_detector"]["output_file"].get(k),int) or installed["graphics_detector"]["output_file"][k]<=0 for k in ("dev","inode","gid"))
            or installed["graphics_detector"]["output_file"].get("eof") is not True
            or not SHA_RE.fullmatch(str(installed["graphics_detector"]["output_file"].get("sha256","")))
            or isinstance(installed["graphics_detector"]["output_file"].get("size"),bool) or not isinstance(installed["graphics_detector"]["output_file"].get("size"),int)
            or not 0<=installed["graphics_detector"]["output_file"]["size"]<=1048576):
        raise NestedCuttlefishError("frozen Vulkan runtime dependency evidence missing")
    if receipt.get("passed") is not True: raise NestedCuttlefishError("boot failed")
    return dict(receipt)

def receipt_sha(receipt: Mapping) -> str:
    return hashlib.sha256(json.dumps(dict(receipt),sort_keys=True,separators=(",",":")).encode()).hexdigest()

def _parse_focus_text(text: str) -> list[dict]:
 matches=[];legacy=re.findall(r"(?m)^\s*ACTIVITY ([^/ \t]+)/([^ \t]+).*?\bpid=([1-9]\d*)\b.*?\buid=([1-9]\d*)\b",text)
 packages=re.findall(r"\bpackageName=([^\s]+)",text);components=re.findall(r"\bmActivityComponent=([^/\s]+)/([^\s]+)",text);processes=re.findall(r"(?m)^\s*app=ProcessRecord\{[^}]*\s([1-9]\d*):([^/\s]+)/u(\d+)a(\d+)\}\s*$",text)
 states=re.findall(r"(?m)^\s*state=([A-Z_]+)\s+finishing=(true|false)\s*$",text);visible_requested=re.findall(r"\bmVisibleRequested=(true|false)\b",text);visible_now=re.findall(r"\bmVisible=(true|false)\b",text);client_visible=re.findall(r"\bmClientVisible=(true|false)\b",text);reported_visible=re.findall(r"\breportedVisible=(true|false)\b",text)
 first=re.findall(r"\bfirstWindowDrawn=(true|false)\b",text);reported=re.findall(r"\breportedDrawn=(true|false)\b",text);starting=re.findall(r"\bstartingDisplayed=(true|false)\b",text);starting_data=re.findall(r"\bstartingData=([^\s]+)",text);starting_objects=bool(re.search(r"\bstarting(?:Window|Surface)=",text))
 if legacy:return [{"package":x[0],"component":x[1],"pid":int(x[2]),"uid":int(x[3]),"format":"activity","state":"RESUMED","finishing":False,"visible":True,"drawn":False,"starting_displayed":False} for x in legacy[:32]]
 if all(len(x)==1 for x in (packages,components,processes,states,visible_requested,visible_now,client_visible,reported_visible,first,reported,starting_data)) and ((starting_data==["null"] and not starting_objects and not starting) or (starting_data!=["null"] and starting_objects and len(starting)==1)):
  package=packages[0];component_package,component=components[0];pid,process_package,user,app_id=processes[0]
  if package==component_package==process_package:matches=[{"package":package,"component":component,"pid":int(pid),"uid":int(user)*100000+10000+int(app_id),"format":"key-value","state":states[0][0],"finishing":states[0][1]=="true","visible":visible_requested==visible_now==client_visible==reported_visible==["true"],"drawn":first[0]==reported[0]=="true","starting_displayed":starting==["true"]}]
 return matches


def _validate_monkey_command(value: Any,package: str,path: str) -> None:
    output=value.get("output") if isinstance(value,Mapping) else None;argv=["shell","monkey","-p",package,"1"]
    if (not isinstance(value,Mapping) or set(value)!={"argv","exit_code","timed_out","output"} or value.get("argv")!=argv or value.get("exit_code") not in (0,124)
            or value.get("timed_out") is not (value["exit_code"]==124) or not isinstance(output,Mapping) or set(output)!={"origin","transport","path","size","sha256","bytes_b64"}
            or output.get("origin")!="guest" or output.get("transport")!="qga-adb" or output.get("path")!=path or not isinstance(output.get("size"),int) or isinstance(output.get("size"),bool)
            or not 0<=output["size"]<=65536 or not SHA_RE.fullmatch(str(output.get("sha256",""))) or not isinstance(output.get("bytes_b64"),str)):raise NestedCuttlefishError("bounded app launch command evidence missing")
    try:data=base64.b64decode(output["bytes_b64"],validate=True)
    except Exception as exc:raise NestedCuttlefishError("app launch command bytes invalid") from exc
    if len(data)!=output["size"] or hashlib.sha256(data).hexdigest()!=output["sha256"]:raise NestedCuttlefishError("app launch command bytes mismatch")

def validate_baseline_receipt(plan: InnerPlan, baseline: ApkSpec, receipt: Mapping) -> dict:
    _common(plan,receipt,"nested-baseline-setup")
    if receipt.get("artifact")!=asdict(baseline) or receipt.get("direct_install_is_update_evidence") is not False or receipt.get("passed") is not True:raise NestedCuttlefishError("baseline artifact receipt invalid")
    install=receipt.get("adb_install");ui=receipt.get("ui");focus=ui.get("focus_observations") if isinstance(ui,Mapping) else None
    if not isinstance(install,Mapping) or install.get("argv")!=["install","-r",receipt.get("guest_path")] or install.get("exit_code") not in (0,124) or isinstance(install.get("exit_code"),bool) or install.get("timed_out") is not (install.get("exit_code")==124) or install.get("requested_command_cap")!=180 or install.get("effective_child_timeout")!=180 or install.get("outer_transport_timeout")!=185 or isinstance(install.get("elapsed_seconds"),bool) or not isinstance(install.get("elapsed_seconds"),(int,float)) or not 0<=install["elapsed_seconds"]<=185:raise NestedCuttlefishError("baseline install command receipt invalid")
    install_bytes={}
    for key,path in (("output","adb:baseline-install"),("stderr","adb:baseline-install-stderr")):
        raw=install.get(key)
        if not isinstance(raw,Mapping) or raw.get("path")!=path or raw.get("origin")!="guest" or raw.get("transport")!="qga-adb" or not isinstance(raw.get("size"),int) or isinstance(raw.get("size"),bool) or not 0<=raw["size"]<=65536 or not SHA_RE.fullmatch(str(raw.get("sha256",""))) or not isinstance(raw.get("bytes_b64"),str):raise NestedCuttlefishError("baseline install raw receipt invalid")
        try:data=base64.b64decode(raw["bytes_b64"],validate=True)
        except Exception as exc:raise NestedCuttlefishError("baseline install raw bytes invalid") from exc
        if len(data)!=raw["size"] or hashlib.sha256(data).hexdigest()!=raw["sha256"]:raise NestedCuttlefishError("baseline install raw bytes mismatch")
        install_bytes[key]=data
    if install["exit_code"]==0 and (install.get("postcondition") is not None or b"Success" not in install_bytes["output"]):raise NestedCuttlefishError("baseline install success receipt invalid")
    post=install.get("postcondition")
    if install["exit_code"]==124 and (not isinstance(post,Mapping) or post.get("accepted_after_timeout") is not True or post.get("conflicts")!={} or not isinstance(post.get("sessions"),Mapping) or not isinstance(post.get("rows"),list) or len(post["rows"])!=2 or post["rows"][0].get("kind")!="package" or post["rows"][0].get("version_code")!=baseline.version_code or post["rows"][1].get("kind")!="sessions" or (post["rows"][1].get("receipt") or {}).get("argv")!=["shell","dumpsys","package","installs"] or (post["rows"][1].get("receipt") or {}).get("exit_code")!=0):raise NestedCuttlefishError("baseline timeout postcondition missing")
    if not isinstance(ui,Mapping) or ui.get("version_code")!=baseline.version_code or not isinstance(focus,list) or not 1<=len(focus)<=32 or (install["exit_code"]==124 and post["rows"][0].get("uid")!=ui.get("package_uid")):raise NestedCuttlefishError("baseline UI receipt invalid")
    _validate_monkey_command(ui.get("launch_probe"),baseline.package,"adb:baseline-monkey")
    row=focus[-1];raw=row.get("raw") if isinstance(row,Mapping) else None
    if (not isinstance(row,Mapping) or row.get("exit_code")!=0 or not isinstance(raw,Mapping) or raw.get("path")!="adb:activity-top-resumed" or raw.get("origin")!="guest" or raw.get("transport")!="qga-adb"
            or not isinstance(raw.get("size"),int) or isinstance(raw.get("size"),bool) or not 0<raw["size"]<=6144 or not SHA_RE.fullmatch(str(raw.get("sha256",""))) or not isinstance(raw.get("bytes_b64"),str)):raise NestedCuttlefishError("baseline final focus evidence invalid")
    try:data=base64.b64decode(raw["bytes_b64"],validate=True)
    except Exception as exc:raise NestedCuttlefishError("baseline focus bytes invalid") from exc
    matches=_parse_focus_text(data.decode("utf-8","replace"));top=matches[0] if len(matches)==1 else None
    if (len(data)!=raw["size"] or hashlib.sha256(data).hexdigest()!=raw["sha256"] or row.get("matches")!=matches or not isinstance(top,Mapping) or top.get("package")!=baseline.package
            or top.get("state")!="RESUMED" or top.get("finishing") is not False or top.get("visible") is not True or top.get("drawn") is not True or top.get("starting_displayed") is not False
            or ui.get("package_pid")!=top.get("pid") or ui.get("package_uid")!=top.get("uid") or ui.get("window_id")!=f"activity-top:{top.get('pid')}"):raise NestedCuttlefishError("baseline launch postcondition invalid")
    return dict(receipt)

def validate_app_update_receipt(plan: InnerPlan, boot: Mapping, receipt: Mapping) -> dict:
    validate_boot_receipt(plan,boot); _common(plan,receipt,"nested-cuttlefish-app-update")
    if receipt.get("timeout_seconds")!=600:raise NestedCuttlefishError("interactive app update timeout contract missing")
    if receipt.get("boot_binding_sha256")!=receipt_sha(boot): raise NestedCuttlefishError("app receipt not bound to boot")
    preflight=receipt.get("diagnostic_preflight");endpoint="10.8.1.0";port="17865"
    request_text=f"GET /healthz HTTP/1.1\r\nHost: {endpoint}:{port}\r\nConnection: close\r\n\r\n"
    request_b64=base64.b64encode(request_text.encode("ascii")).decode("ascii")
    health_script=shlex.quote(f"echo {request_b64} | toybox base64 -d | toybox nc -w 3 {endpoint} {port}")
    expected_preflight={"link":["shell","ip","-details","link","show"],"address":["shell","ip","-4","addr","show"],"routes":["shell","ip","-4","route","show"],"route":["shell","ip","-4","route","get",endpoint],"connect":["shell","toybox","nc","-z","-w","5",endpoint,port],"capability":["shell","toybox","nc","--help"],"ril_state":["shell","getprop","init.svc.vendor.ril-daemon"],"ril_log":["shell","logcat","-d","-t","200","-v","threadtime","-b","main","-b","system","-b","events","RIL*:V","libcuttlefish-rild:V","init:I","*:S"],"healthz":["shell","sh","-c",health_script]}
    if not isinstance(preflight,Mapping) or set(preflight)!={"window_seconds","attempt_limit","attempts","selected_attempt","commands","fixture_request","health_body"} or preflight.get("window_seconds")!=35 or preflight.get("attempt_limit")!=3 or not isinstance(preflight.get("attempts"),list) or not 1<=len(preflight["attempts"])<=3 or preflight.get("selected_attempt")!=len(preflight["attempts"]):raise NestedCuttlefishError("fixture diagnostic preflight missing")
    for index,attempt in enumerate(preflight["attempts"],1):
        if not isinstance(attempt,Mapping) or set(attempt)!={"index","commands","capture_error","health_result","health_body","fixture_request","ready"} or attempt.get("index")!=index or not isinstance(attempt.get("commands"),Mapping) or not set(attempt["commands"]).issubset(expected_preflight) or (index==len(preflight["attempts"]) and set(attempt["commands"])!=set(expected_preflight)):raise NestedCuttlefishError("fixture diagnostic attempt invalid")
        for label,row in attempt["commands"].items():
            argv=expected_preflight[label]
            if not isinstance(row,Mapping) or set(row)!={"argv","exit_code","timed_out","output","stderr"} or row.get("argv")!=argv or isinstance(row.get("exit_code"),bool) or not isinstance(row.get("exit_code"),int) or row.get("timed_out") is not (row["exit_code"]==124):raise NestedCuttlefishError("fixture diagnostic preflight invalid")
            for stream,path in (("output",f"adb:fixture-preflight-{label}"),("stderr",f"adb:fixture-preflight-{label}-stderr")):
                output=row.get(stream)
                if not isinstance(output,Mapping) or set(output)!={"origin","transport","path","size","sha256","bytes_b64"} or output.get("origin")!="guest" or output.get("transport")!="qga-adb" or output.get("path")!=path or isinstance(output.get("size"),bool) or not isinstance(output.get("size"),int) or not 0<=output["size"]<=65536 or not SHA_RE.fullmatch(str(output.get("sha256",""))) or not isinstance(output.get("bytes_b64"),str):raise NestedCuttlefishError("fixture diagnostic preflight invalid")
                try:data=base64.b64decode(output["bytes_b64"],validate=True)
                except Exception as exc:raise NestedCuttlefishError("fixture diagnostic preflight bytes invalid") from exc
                if len(data)!=output.get("size") or hashlib.sha256(data).hexdigest()!=output["sha256"]:raise NestedCuttlefishError("fixture diagnostic preflight bytes mismatch")
    selected=preflight["attempts"][-1]
    if selected.get("ready") is not True or selected.get("capture_error") is not None or preflight.get("commands")!=selected.get("commands") or preflight.get("fixture_request")!=selected.get("fixture_request") or preflight.get("health_body")!=selected.get("health_body"):raise NestedCuttlefishError("fixture diagnostic selected attempt invalid")
    body_record=preflight["health_body"]
    if not isinstance(body_record,Mapping) or set(body_record)!={"origin","transport","path","size","sha256","bytes_b64"}:raise NestedCuttlefishError("fixture health body missing")
    try:health_bytes=base64.b64decode(body_record["bytes_b64"],validate=True);health_value=json.loads(health_bytes.decode())
    except Exception as exc:raise NestedCuttlefishError("fixture health body invalid") from exc
    if body_record.get("path")!="adb:fixture-preflight-health-body" or body_record.get("size")!=len(health_bytes) or body_record.get("sha256")!=hashlib.sha256(health_bytes).hexdigest():raise NestedCuttlefishError("fixture health body mismatch")
    request=preflight["fixture_request"]
    if preflight["commands"]["healthz"]["exit_code"]!=0 or health_value!={"status":"ok","run_id":plan.ownership.run_id,"role":"consumer-fixture"} or not isinstance(request,Mapping) or set(request)!={"method","path","status","sha256","bytes","content_length","eof","peer","observed_at","run_id","attempt_nonce"} or request.get("run_id")!=plan.ownership.run_id or request.get("attempt_nonce")!=plan.ownership.attempt_nonce or request.get("method")!="GET" or request.get("path")!="/healthz" or request.get("status")!=200 or request.get("eof") is not True or not request.get("peer") or request.get("bytes")!=len(health_bytes) or request.get("content_length")!=len(health_bytes) or request.get("sha256")!=hashlib.sha256(health_bytes).hexdigest():raise NestedCuttlefishError("fixture diagnostic preflight semantic mismatch")
    package=receipt.get("package_installer"); exact={"package":plan.apk.package,"version_code":plan.apk.version_code,"artifact_sha256":plan.apk.sha256,"artifact_size":plan.apk.size}
    if not isinstance(package,Mapping) or any(package.get(k)!=v for k,v in exact.items()) or package.get("download_sha256")!=plan.apk.sha256 or not isinstance(package.get("session_id"),int) or isinstance(package.get("session_id"),bool) or package["session_id"]<0 or package.get("status")!="STATUS_SUCCESS" or package.get("method")!="PackageInstaller" or package.get("snapshot_argv")!=["shell","dumpsys","package","installs"]: raise NestedCuttlefishError("exact PackageInstaller evidence missing")
    def session_raw(row):
        if (not isinstance(row,Mapping) or set(row)!={"origin","transport","path","size","sha256","bytes_b64"} or row.get("origin")!="guest" or row.get("transport")!="qga-adb" or row.get("path")!="adb:dumpsys-package-installs" or not isinstance(row.get("size"),int) or isinstance(row.get("size"),bool) or not 0<=row["size"]<=1048576 or not SHA_RE.fullmatch(str(row.get("sha256",""))) or not isinstance(row.get("bytes_b64"),str)):raise NestedCuttlefishError("PackageInstaller session raw invalid")
        try:data=base64.b64decode(row["bytes_b64"],validate=True)
        except Exception as exc:raise NestedCuttlefishError("PackageInstaller session bytes invalid") from exc
        if len(data)!=row["size"] or hashlib.sha256(data).hexdigest()!=row["sha256"]:raise NestedCuttlefishError("PackageInstaller session bytes mismatch")
        parsed={};header=r"(?:(Active Child|Active|Orphaned|Finalized) )?Session ([1-9]\d*):"
        for match in re.finditer(rf"(?ms)^\s*{header}\s*$\n(.*?)(?=^\s*{header}\s*$|\Z)",data.decode("utf-8","replace")):
            prefix=match.group(1);sid=int(match.group(2));body=match.group(3)
            if sid in parsed:raise NestedCuttlefishError("ambiguous PackageInstaller session dump")
            if prefix is None:
                packages=re.findall(r"(?<![A-Za-z0-9_])mAppPackageName=([^\s]+)",body);statuses=re.findall(r"(?<![A-Za-z0-9_])mFinalStatus=(-?\d+)\b",body)
                if len(packages)!=1 or len(statuses)!=1:raise NestedCuttlefishError("ambiguous PackageInstaller historical session")
                parsed[sid]={"kind":"historical","package":packages[0],"final_status":int(statuses[0])}
            else:
                packages=re.findall(r"(?<![A-Za-z0-9_])appPackageName\s*=\s*([^\s]+)",body)
                if len(packages)>1:raise NestedCuttlefishError("ambiguous PackageInstaller active package")
                active_package=packages[0] if packages and re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+",packages[0]) else None
                parsed[sid]={"kind":prefix.lower().replace(" ","-"),"package":active_package,"final_status":None}
        return parsed
    session_evidence=package.get("session_evidence")
    if not isinstance(session_evidence,Mapping) or set(session_evidence)!={"before","after"} or not isinstance(session_evidence.get("after"),list) or not 1<=len(session_evidence["after"])<=10:raise NestedCuttlefishError("PackageInstaller session evidence missing")
    before_sessions=session_raw(session_evidence["before"]);final_sessions=None
    for observation in session_evidence["after"]:
        final_sessions=session_raw(observation);new=set(final_sessions)-set(before_sessions)
        if not new.issubset({package["session_id"]}) or (package["session_id"] in new and final_sessions[package["session_id"]]["package"] not in (None,plan.apk.package)):raise NestedCuttlefishError("foreign PackageInstaller session appeared")
    new_sessions=set(final_sessions)-set(before_sessions)
    if new_sessions!={package["session_id"]} or final_sessions[package["session_id"]]!={"kind":"historical","package":plan.apk.package,"final_status":1}:raise NestedCuttlefishError("exact PackageInstaller finalized session missing")
    http=receipt.get("http")
    if not isinstance(http,Mapping) or not ID_RE.fullmatch(str(http.get("fixture_nonce",""))) or not SHA_RE.fullmatch(str(http.get("manifest_sha256",""))): raise NestedCuttlefishError("authenticated HTTP evidence missing")
    requests=http.get("requests"); paths=["/manifest.json",f"/files/artifacts/{plan.apk.sha256}/{quote(plan.apk.name,safe='-._~')}"]
    if not isinstance(requests,list) or [x.get("path") for x in requests if isinstance(x,Mapping)]!=paths: raise NestedCuttlefishError("HTTP path/order mismatch")
    for item in requests:
        if item.get("method")!="GET" or item.get("status")!=200 or item.get("eof") is not True or not isinstance(item.get("bytes"),int) or item["bytes"]<=0 or not SHA_RE.fullmatch(str(item.get("sha256",""))): raise NestedCuttlefishError("HTTP transcript incomplete")
    if requests[1]["bytes"]!=plan.apk.size or requests[1]["sha256"]!=plan.apk.sha256: raise NestedCuttlefishError("HTTP APK differs from plan")
    ui=receipt.get("ui"); keys=("activity","window_id","window_title","package_pid","package_uid","version_code","screenshot_sha256")
    if not isinstance(ui,Mapping) or any(not ui.get(k) for k in keys) or ui.get("package")!=plan.apk.package or ui.get("version_code")!=plan.apk.version_code or not SHA_RE.fullmatch(str(ui.get("screenshot_sha256",""))): raise NestedCuttlefishError("semantic UI evidence incomplete")
    ui_captures=ui.get("ui_capture_observations");ui_remote=f"/data/local/tmp/amz-{plan.ownership.attempt_nonce[:12]}.xml"
    def ui_command(row,argv,path,maximum):
        output=row.get("output") if isinstance(row,Mapping) else None
        if (not isinstance(row,Mapping) or set(row)!={"argv","exit_code","timed_out","output"} or row.get("argv")!=argv or row.get("exit_code") not in (0,124) or row.get("timed_out") is not (row["exit_code"]==124)
                or not isinstance(output,Mapping) or set(output)!={"origin","transport","path","size","sha256","bytes_b64"} or output.get("origin")!="guest" or output.get("transport")!="qga-adb" or output.get("path")!=path
                or not isinstance(output.get("size"),int) or isinstance(output.get("size"),bool) or not 0<=output["size"]<=maximum or not SHA_RE.fullmatch(str(output.get("sha256",""))) or not isinstance(output.get("bytes_b64"),str)):raise NestedCuttlefishError("UI capture attempt invalid")
        try:data=base64.b64decode(output["bytes_b64"],validate=True)
        except Exception as exc:raise NestedCuttlefishError("UI capture attempt bytes invalid") from exc
        if len(data)!=output["size"] or hashlib.sha256(data).hexdigest()!=output["sha256"]:raise NestedCuttlefishError("UI capture attempt bytes mismatch")
    if not isinstance(ui_captures,list) or not 1<=len(ui_captures)<=64:raise NestedCuttlefishError("UI capture history missing")
    for capture in ui_captures:
        attempts=capture.get("attempts") if isinstance(capture,Mapping) else None
        if (not isinstance(capture,Mapping) or set(capture)!={"label","remote","attempts"} or not re.fullmatch(r"ui-[a-z-]+",str(capture.get("label",""))) or capture.get("remote")!=ui_remote
                or not isinstance(attempts,list) or not 1<=len(attempts)<=3):raise NestedCuttlefishError("UI capture history invalid")
        for index,attempt in enumerate(attempts):
            if not isinstance(attempt,Mapping) or set(attempt)!={"dump","cat"}:raise NestedCuttlefishError("UI capture pair invalid")
            ui_command(attempt["dump"],["shell","uiautomator","dump","--compressed",ui_remote],"adb:ui-dump",65536)
            if attempt["dump"]["exit_code"]==124:
                if attempt["cat"] is not None:raise NestedCuttlefishError("timed-out UI dump has cat evidence")
            else:
                ui_command(attempt["cat"],["shell","cat",ui_remote],"adb:ui-xml",1048576)
            if index<len(attempts)-1 and not (attempt["dump"]["exit_code"]==124 or (isinstance(attempt["cat"],Mapping) and attempt["cat"].get("exit_code")==124)):raise NestedCuttlefishError("UI capture retried without timeout")
        final=attempts[-1]
        if final["dump"]["exit_code"]!=0 or not isinstance(final["cat"],Mapping) or final["cat"].get("exit_code")!=0:raise NestedCuttlefishError("successful UI receipt ended in timeout")
    visual=ui.get("visual_handshake")
    if not isinstance(visual,list) or not 1<=len(visual)<=32:raise NestedCuttlefishError("visual handshake evidence missing")
    approved_update=False
    for sequence,row in enumerate(visual,1):
        request=row.get("request") if isinstance(row,Mapping) else None;controller=row.get("controller") if isinstance(row,Mapping) else None;decision=row.get("decision") if isinstance(row,Mapping) else None;input_row=row.get("input") if isinstance(row,Mapping) else None;display=request.get("display_owner") if isinstance(request,Mapping) else None;target=request.get("action_target") if isinstance(request,Mapping) else None
        if (not isinstance(row,Mapping) or set(row) not in ({"request","controller","decision","keyguard"},{"request","controller","decision","keyguard","freshness"},{"request","controller","decision","keyguard","freshness","input"},{"request","controller","decision","keyguard","freshness","input","back"})
                or not isinstance(request,Mapping) or request.get("run_id")!=plan.ownership.run_id or request.get("attempt_nonce")!=plan.ownership.attempt_nonce or request.get("sequence")!=sequence
                or request.get("artifact_sha256")!=plan.apk.sha256 or request.get("artifact_size")!=plan.apk.size or request.get("origin")!="guest" or request.get("transport")!="qga-adb"
                or request.get("kind") not in ("update","unknown-sources") or request.get("action")!={"update":"Update","unknown-sources":"Allow from this source"}.get(request.get("kind")) or request.get("state")!="operator-unclassified" or request.get("bounds") is not None
                or not isinstance(display,Mapping) or set(display)!={"package","activity","pid","uid"} or display.get("package") not in ((plan.apk.package,) if request.get("kind")=="update" else ("com.android.settings",)) or any(isinstance(display.get(x),bool) or not isinstance(display.get(x),int) or display.get(x)<=0 for x in ("pid","uid"))
                or target!={"package":plan.apk.package,"version_code":plan.apk.version_code-1,"artifact_sha256":plan.apk.sha256,"artifact_size":plan.apk.size}
                or not isinstance(request.get("created_at"),(int,float)) or not isinstance(request.get("expires_at"),(int,float)) or not 5<=request["expires_at"]-request["created_at"]<=90
                or not isinstance(controller,Mapping) or controller.get("origin")!="controller" or controller.get("immutable") is not True or controller.get("expires_at")!=request["expires_at"]
                or not SHA_RE.fullmatch(str(controller.get("request_sha256",""))) or not SHA_RE.fullmatch(str(controller.get("png_sha256",""))) or not isinstance(controller.get("png_width"),int) or not isinstance(controller.get("png_height"),int)
                or not isinstance(decision,Mapping) or decision.get("origin")!="controller" or decision.get("immutable") is not True or decision.get("input_only") is not True
                or decision.get("request_id")!=controller.get("request_id") or decision.get("request_sha256")!=controller.get("request_sha256") or decision.get("run_id")!=request["run_id"] or decision.get("attempt_nonce")!=request["attempt_nonce"]):
            raise NestedCuttlefishError("visual handshake binding invalid")
        bounds=decision.get("bounds");choice=decision.get("decision")
        if choice=="refresh":
            if bounds is not None or input_row is not None:raise NestedCuttlefishError("visual refresh caused input")
            continue
        freshness=row.get("freshness")
        if freshness!={"accepted":True,"max_seconds":45}:raise NestedCuttlefishError("visual approval freshness invalid")
        if (not isinstance(bounds,list) or len(bounds)!=4 or any(isinstance(x,bool) or not isinstance(x,int) for x in bounds) or not (0<=bounds[0]<bounds[2]<=controller["png_width"] and 0<=bounds[1]<bounds[3]<=controller["png_height"])
                or choice!="approve" or not isinstance(input_row,Mapping) or input_row.get("x")!=(bounds[0]+bounds[2])//2 or input_row.get("y")!=(bounds[1]+bounds[3])//2
                or input_row.get("argv")!=["shell","input","tap",str(input_row["x"]),str(input_row["y"])] or input_row.get("exit_code") not in (0,124) or input_row.get("timed_out") is not (input_row.get("exit_code")==124)):
            raise NestedCuttlefishError("approved visual input differs from exact bounds")
        back=row.get("back")
        if back is not None and (request["kind"]!="unknown-sources" or back.get("argv")!=["shell","input","keyevent","4"] or back.get("exit_code") not in (0,124) or back.get("timed_out") is not (back.get("exit_code")==124)):raise NestedCuttlefishError("Settings Back outcome invalid")
        if request["kind"]=="update":approved_update=True
    if not approved_update:raise NestedCuttlefishError("approved Update visual handshake missing")
    if ui.get("completion_action") not in ("Done","Open"):raise NestedCuttlefishError("exact completion action missing")
    restart=ui.get("update_check_restart")
    if not isinstance(restart,Mapping) or set(restart)!={"force_stop","keyguard","monkey","readiness"}:raise NestedCuttlefishError("update check restart evidence missing")
    for name,argv,path in (("force_stop",["shell","am","force-stop",plan.apk.package],"adb:update-check-force-stop"),):
        command=restart.get(name);output=command.get("output") if isinstance(command,Mapping) else None
        if (not isinstance(command,Mapping) or set(command)!={"argv","exit_code","output"} or command.get("argv")!=argv or command.get("exit_code")!=0
                or not isinstance(output,Mapping) or set(output)!={"origin","transport","path","size","sha256","bytes_b64"} or output.get("origin")!="guest" or output.get("transport")!="qga-adb" or output.get("path")!=path
                or not isinstance(output.get("size"),int) or isinstance(output.get("size"),bool) or not 0<=output["size"]<=65536 or not SHA_RE.fullmatch(str(output.get("sha256",""))) or not isinstance(output.get("bytes_b64"),str)):raise NestedCuttlefishError("update check restart command invalid")
        try:command_bytes=base64.b64decode(output["bytes_b64"],validate=True)
        except Exception as exc:raise NestedCuttlefishError("update check restart bytes invalid") from exc
        if len(command_bytes)!=output["size"] or hashlib.sha256(command_bytes).hexdigest()!=output["sha256"]:raise NestedCuttlefishError("update check restart bytes mismatch")
    _validate_monkey_command(restart.get("monkey"),plan.apk.package,"adb:update-check-monkey")
    keyguards=ui.get("keyguard");policy_argv=["shell","dumpsys","window","policy"];phases=["installer-monkey","update-tap","install-tap","completion-tap","launch-monkey"]
    if not isinstance(keyguards,list) or len(keyguards)!=len(phases) or [x.get("phase") for x in keyguards if isinstance(x,Mapping)]!=phases:raise NestedCuttlefishError("keyguard readiness evidence missing")
    def policy(row):
        raw=row.get("raw") if isinstance(row,Mapping) else None
        attempts=row.get("attempts") if isinstance(row,Mapping) else None
        if (not isinstance(row,Mapping) or set(row)!={"argv","showing","input_restricted","raw","attempts"} or row.get("argv")!=policy_argv or not isinstance(row.get("showing"),bool) or not isinstance(row.get("input_restricted"),bool)
                or not isinstance(attempts,list) or not 1<=len(attempts)<=3
                or not isinstance(raw,Mapping) or raw.get("origin")!="guest" or raw.get("transport")!="qga-adb" or raw.get("path")!="adb:keyguard-policy"
                or not isinstance(raw.get("size"),int) or isinstance(raw.get("size"),bool) or not 0<raw["size"]<=6144 or not SHA_RE.fullmatch(str(raw.get("sha256",""))) or not isinstance(raw.get("bytes_b64"),str)):raise NestedCuttlefishError("keyguard policy evidence invalid")
        try:data=base64.b64decode(raw["bytes_b64"],validate=True)
        except Exception as exc:raise NestedCuttlefishError("keyguard policy bytes invalid") from exc
        if len(data)!=raw["size"] or hashlib.sha256(data).hexdigest()!=raw["sha256"]:raise NestedCuttlefishError("keyguard policy bytes mismatch")
        for index,attempt in enumerate(attempts):
            attempt_raw=attempt.get("raw") if isinstance(attempt,Mapping) else None
            if (not isinstance(attempt,Mapping) or set(attempt)!={"exit_code","timed_out","raw"} or attempt.get("exit_code") not in (0,124) or attempt.get("timed_out") is not (attempt["exit_code"]==124)
                    or (index<len(attempts)-1 and attempt["exit_code"]!=124) or (index==len(attempts)-1 and attempt["exit_code"]!=0)
                    or not isinstance(attempt_raw,Mapping) or set(attempt_raw)!={"origin","transport","path","size","sha256","bytes_b64"} or attempt_raw.get("origin")!="guest" or attempt_raw.get("transport")!="qga-adb" or attempt_raw.get("path")!="adb:keyguard-policy"
                    or not isinstance(attempt_raw.get("size"),int) or isinstance(attempt_raw.get("size"),bool) or not 0<=attempt_raw["size"]<=6144 or not SHA_RE.fullmatch(str(attempt_raw.get("sha256",""))) or not isinstance(attempt_raw.get("bytes_b64"),str)):raise NestedCuttlefishError("keyguard policy attempt invalid")
            try:attempt_data=base64.b64decode(attempt_raw["bytes_b64"],validate=True)
            except Exception as exc:raise NestedCuttlefishError("keyguard policy attempt bytes invalid") from exc
            if len(attempt_data)!=attempt_raw["size"] or hashlib.sha256(attempt_data).hexdigest()!=attempt_raw["sha256"]:raise NestedCuttlefishError("keyguard policy attempt bytes mismatch")
        if attempts[-1]["raw"]!=raw:raise NestedCuttlefishError("keyguard final policy attempt differs")
        text=data.decode("utf-8","replace");showing=re.findall(r"(?m)^\s*showing=(true|false)\s*$",text);restricted=re.findall(r"(?m)^\s*inputRestricted=(true|false)\s*$",text)
        if showing!=[str(row["showing"]).lower()] or restricted!=[str(row["input_restricted"]).lower()]:raise NestedCuttlefishError("keyguard policy semantic mismatch")
    for entry in keyguards:
        if set(entry)!={"phase","receipt"}:raise NestedCuttlefishError("keyguard readiness evidence missing")
        keyguard=entry["receipt"]
        if not isinstance(keyguard,Mapping) or set(keyguard)!={"before","after_dismiss","commands","after","passed"} or keyguard.get("passed") is not True:raise NestedCuttlefishError("keyguard readiness evidence missing")
        policy(keyguard["before"]);policy(keyguard["after"])
        if keyguard["before"]["showing"] is False:
            expected_commands=[]
            if keyguard["after_dismiss"] is not None or keyguard["after"]!=keyguard["before"]:raise NestedCuttlefishError("unlocked keyguard receipt mutated")
        else:
            policy(keyguard["after_dismiss"]);intermediate=keyguard["after_dismiss"]
            expected_commands=[["shell","wm","dismiss-keyguard"]] if not intermediate["showing"] and not intermediate["input_restricted"] else [["shell","wm","dismiss-keyguard"],["shell","input","keyevent","82"]]
            if len(expected_commands)==1 and keyguard["after"]!=intermediate:raise NestedCuttlefishError("dismiss-only proof differs from intermediate")
        if keyguard["after"]["showing"] or keyguard["after"]["input_restricted"] or [x.get("argv") for x in keyguard["commands"] if isinstance(x,Mapping)]!=expected_commands:raise NestedCuttlefishError("keyguard was not safely dismissed")
        for command in keyguard["commands"]:
            raw=command.get("raw") if isinstance(command,Mapping) else None
            if (set(command)!={"argv","exit_code","timed_out","raw"} or command.get("exit_code") not in (0,124) or command.get("timed_out") is not (command["exit_code"]==124) or not isinstance(raw,Mapping) or raw.get("origin")!="guest" or raw.get("transport")!="qga-adb"
                    or raw.get("path")!="adb:keyguard-command" or not isinstance(raw.get("size"),int) or isinstance(raw.get("size"),bool) or not 0<=raw["size"]<=65536 or not SHA_RE.fullmatch(str(raw.get("sha256",""))) or not isinstance(raw.get("bytes_b64"),str)):raise NestedCuttlefishError("keyguard command evidence invalid")
            try:data=base64.b64decode(raw["bytes_b64"],validate=True)
            except Exception as exc:raise NestedCuttlefishError("keyguard command bytes invalid") from exc
            if len(data)!=raw["size"] or hashlib.sha256(data).hexdigest()!=raw["sha256"]:raise NestedCuttlefishError("keyguard command bytes mismatch")
    if restart["keyguard"]!=keyguards[0]["receipt"]:raise NestedCuttlefishError("update restart keyguard differs from launch-adjacent proof")
    candidate_focus=ui.get("focus_observations");restart_focus=restart.get("readiness");focus=(restart_focus+candidate_focus) if isinstance(restart_focus,list) and isinstance(candidate_focus,list) else None;focus_argv=["shell","dumpsys","activity","top-resumed"];receipt_log=receipt.get("logcat");lifecycle_epoch=str(receipt_log.get("started_at","")) if isinstance(receipt_log,Mapping) else ""
    if (not isinstance(restart_focus,list) or not 1<=len(restart_focus)<=12 or not isinstance(candidate_focus,list) or not 1<=len(candidate_focus)<=12 or not isinstance(focus,list) or not 2<=len(focus)<=24
            or any(not isinstance(row,Mapping) or set(row)!={"argv","exit_code","timed_out","size","sha256","raw","relevant_lines","matches","elapsed_ms","pidof","lifecycle","logcat"} or row.get("argv")!=focus_argv
                   or row.get("exit_code") not in (0,124) or row.get("timed_out") is not (row.get("exit_code")==124)
                   or not isinstance(row.get("size"),int) or isinstance(row.get("size"),bool) or not 0<=row["size"]<=6144 or (row["exit_code"]==0 and row["size"]==0)
                   or not SHA_RE.fullmatch(str(row.get("sha256",""))) or not isinstance(row.get("relevant_lines"),str) or len(row["relevant_lines"])>4096
                   or not isinstance(row.get("matches"),list) or len(row["matches"])>32 or not isinstance(row.get("elapsed_ms"),int) or isinstance(row.get("elapsed_ms"),bool) or not 0<=row["elapsed_ms"]<=300000 for row in focus)):
        raise NestedCuttlefishError("bounded foreground observation missing")
    for row in focus:
        raw=row["raw"]
        if (not isinstance(raw,Mapping) or set(raw)!={"origin","transport","path","size","sha256","bytes_b64"} or raw.get("origin")!="guest" or raw.get("transport")!="qga-adb" or raw.get("path")!="adb:activity-top-resumed"
                or raw.get("size")!=row["size"] or raw.get("sha256")!=row["sha256"] or not isinstance(raw.get("bytes_b64"),str)):raise NestedCuttlefishError("foreground raw evidence invalid")
        try:raw_bytes=base64.b64decode(raw["bytes_b64"],validate=True)
        except Exception as exc:raise NestedCuttlefishError("foreground raw bytes invalid") from exc
        if len(raw_bytes)!=raw["size"] or hashlib.sha256(raw_bytes).hexdigest()!=raw["sha256"]:raise NestedCuttlefishError("foreground raw bytes mismatch")
        def diagnostic_command(value,path,maximum,expected_argv):
            if isinstance(value,Mapping) and set(value)=={"argv","capture_error","command"}:
                error=value.get("capture_error");command=value.get("command")
                if (value.get("argv")!=expected_argv or not isinstance(error,Mapping) or set(error)!={"type","sha256"} or not isinstance(error.get("type"),str) or not error["type"] or not SHA_RE.fullmatch(str(error.get("sha256","")))
                        or not isinstance(command,Mapping) or len(json.dumps(command,sort_keys=True,separators=(",",":")))>32768 or not isinstance(command.get("argv"),list) or command["argv"][-len(expected_argv):]!=expected_argv):raise NestedCuttlefishError("foreground lifecycle diagnostic failure invalid")
                return
            output=value.get("output") if isinstance(value,Mapping) else None
            if (not isinstance(value,Mapping) or set(value)!={"argv","exit_code","timed_out","output"} or value.get("argv")!=expected_argv
                    or not isinstance(value.get("exit_code"),int) or isinstance(value.get("exit_code"),bool) or not -255<=value["exit_code"]<=255
                    or value.get("timed_out") is not (value["exit_code"]==124) or not isinstance(output,Mapping)
                    or set(output)!={"origin","transport","path","size","sha256","bytes_b64"} or output.get("origin")!="guest" or output.get("transport")!="qga-adb" or output.get("path")!=path
                    or not isinstance(output.get("size"),int) or isinstance(output.get("size"),bool) or not 0<=output["size"]<=maximum
                    or not SHA_RE.fullmatch(str(output.get("sha256",""))) or not isinstance(output.get("bytes_b64"),str)):raise NestedCuttlefishError("foreground lifecycle diagnostic invalid")
            try:data=base64.b64decode(output["bytes_b64"],validate=True)
            except Exception as exc:raise NestedCuttlefishError("foreground lifecycle diagnostic bytes invalid") from exc
            if len(data)!=output["size"] or hashlib.sha256(data).hexdigest()!=output["sha256"]:raise NestedCuttlefishError("foreground lifecycle diagnostic bytes mismatch")
        diagnostic_command(row["pidof"],"adb:focus-pidof",4096,["shell","pidof",plan.apk.package])
        lifecycle_argv=row["lifecycle"].get("argv") if isinstance(row["lifecycle"],Mapping) else None
        if (not isinstance(lifecycle_argv,list) or len(lifecycle_argv)!=23 or lifecycle_argv[:4]!=["shell","logcat","-d","-T"]
                or lifecycle_argv[4]!=lifecycle_epoch or not re.fullmatch(r"\d{10,}(?:\.\d{3})?",lifecycle_epoch) or lifecycle_argv[5:]!=["-t","200","-v","threadtime","-b","main","-b","system","-b","events","-b","crash","ActivityManager:I","ActivityTaskManager:I","AndroidRuntime:E","lmkd:I","lowmemorykiller:I","*:S"]):raise NestedCuttlefishError("foreground lifecycle argv invalid")
        diagnostic_command(row["lifecycle"],"adb:focus-lifecycle",65536,lifecycle_argv)
        raw_text=raw_bytes.decode("utf-8","replace");keep=("ACTIVITY ","packageName=","app=ProcessRecord{","Intent {","mActivityComponent=","state=","mVisibleRequested=","firstWindowDrawn=","reportedDrawn=","startingData=","startingWindow=","startingSurface=","startingDisplayed=","Splash Screen")
        expected_relevant="\n".join(line[:1024] for line in raw_text.splitlines() if any(token in line.lstrip() for token in keep))[:4096]
        if row["relevant_lines"]!=expected_relevant:raise NestedCuttlefishError("foreground relevant lines differ from raw")
        logcat=row["logcat"]
        if logcat is not None and (not isinstance(logcat,Mapping) or set(logcat)!={"argv","exit_code","size","sha256","fatal","relevant_lines"}
                or logcat.get("argv")!=["shell","logcat","-d","-t","40"] or logcat.get("exit_code") not in (0,124)
                or not isinstance(logcat.get("size"),int) or isinstance(logcat.get("size"),bool) or not 0<=logcat["size"]<=32768
                or not SHA_RE.fullmatch(str(logcat.get("sha256",""))) or not isinstance(logcat.get("fatal"),bool) or logcat["fatal"]
                or not isinstance(logcat.get("relevant_lines"),str) or len(logcat["relevant_lines"])>4096):raise NestedCuttlefishError("bounded foreground logcat evidence invalid")
        if row["exit_code"]!=0:
            if row["matches"] or logcat is not None:raise NestedCuttlefishError("timed-out foreground row has semantic claims")
            continue
        text=row["relevant_lines"];derived=_parse_focus_text(text)
        if derived!=row["matches"]:raise NestedCuttlefishError("activity-top semantic evidence mismatch")
    for phase_rows in (restart_focus,candidate_focus):
        phase_top=phase_rows[-1]["matches"][0] if phase_rows[-1]["exit_code"]==0 and len(phase_rows[-1]["matches"])==1 else None
        if (not isinstance(phase_top,Mapping) or phase_top.get("package")!=plan.apk.package or phase_top.get("state")!="RESUMED" or phase_top.get("finishing") is not False
                or phase_top.get("visible") is not True or phase_top.get("drawn") is not True or phase_top.get("starting_displayed") is not False):raise NestedCuttlefishError("readiness phase did not reach exact drawn foreground")
    final_matches=candidate_focus[-1]["matches"]
    top=final_matches[0] if len(final_matches)==1 else None
    if (focus[-1]["exit_code"]!=0 or not isinstance(top,Mapping) or set(top)!={"package","component","pid","uid","format","state","finishing","visible","drawn","starting_displayed"}
            or top.get("package")!=plan.apk.package or not isinstance(top.get("component"),str) or not top["component"]
            or not isinstance(top.get("pid"),int) or isinstance(top.get("pid"),bool) or top["pid"]<=0
            or not isinstance(top.get("uid"),int) or isinstance(top.get("uid"),bool) or top["uid"]<=0 or top.get("format") not in ("activity","key-value")
            or top.get("state")!="RESUMED" or top.get("finishing") is not False or top.get("visible") is not True or top.get("drawn") is not True or top.get("starting_displayed") is not False
            or ui.get("package_pid")!=top["pid"] or ui.get("package_uid")!=top["uid"] or ui.get("window_id")!=f"activity-top:{top['pid']}"):
        raise NestedCuttlefishError("exact activity-top binding missing")
    _validate_monkey_command(ui.get("launch_probe"),plan.apk.package,"adb:candidate-monkey")
    state=ui.get("package_state");dumpsys=state.get("dumpsys") if isinstance(state,Mapping) else None;uid_lookup=state.get("uid_lookup") if isinstance(state,Mapping) else None
    expected_dumpsys=["shell","dumpsys","package",plan.apk.package];expected_uid=["shell","cmd","package","list","packages","-U",plan.apk.package]
    if (not isinstance(state,Mapping) or state.get("version_code")!=plan.apk.version_code or state.get("uid")!=ui.get("package_uid")
            or not isinstance(dumpsys,Mapping) or dumpsys.get("argv")!=expected_dumpsys or dumpsys.get("exit_code")!=0
            or not isinstance(uid_lookup,Mapping) or uid_lookup.get("argv")!=expected_uid or uid_lookup.get("exit_code")!=0): raise NestedCuttlefishError("package state command binding missing")
    for command in (dumpsys,uid_lookup):
        raw=command.get("output")
        if (not isinstance(raw,Mapping) or raw.get("origin")!="guest" or raw.get("transport")!="qga-adb" or not isinstance(raw.get("size"),int) or isinstance(raw.get("size"),bool) or not 0<raw["size"]<=(1<<20)
                or not SHA_RE.fullmatch(str(raw.get("sha256",""))) or not isinstance(raw.get("bytes_b64"),str)):
            raise NestedCuttlefishError("package state bounded command evidence missing")
        try: decoded=base64.b64decode(raw["bytes_b64"],validate=True)
        except Exception as exc: raise NestedCuttlefishError("package state command bytes invalid") from exc
        if len(decoded)!=raw["size"] or hashlib.sha256(decoded).hexdigest()!=raw["sha256"]: raise NestedCuttlefishError("package state command bytes mismatch")
    dumpsys_bytes=base64.b64decode(dumpsys["output"]["bytes_b64"],validate=True);dump_versions=[int(x) for x in re.findall(rb"versionCode=(\d+)",dumpsys_bytes)]
    if dump_versions!=[plan.apk.version_code]: raise NestedCuttlefishError("package version evidence mismatch")
    uid_lines=base64.b64decode(uid_lookup["output"]["bytes_b64"],validate=True).decode("utf-8","strict").splitlines()
    if uid_lines!=[f"package:{plan.apk.package} uid:{ui['package_uid']}"] or not isinstance(ui.get("package_uid"),int) or isinstance(ui.get("package_uid"),bool) or ui["package_uid"]<=0: raise NestedCuttlefishError("package UID evidence mismatch")
    log=receipt.get("logcat")
    if not isinstance(log,Mapping) or not log.get("started_at") or not log.get("finished_at") or not SHA_RE.fullmatch(str(log.get("sha256",""))) or log.get("crashes")!=[]: raise NestedCuttlefishError("bounded crash-free logcat missing")
    if receipt.get("passed") is not True: raise NestedCuttlefishError("app/update failed")
    return dict(receipt)

def validate_runtime_receipt(plan: InnerPlan, receipt: Mapping) -> dict:
    """Legacy name now validates boot only; it cannot imply app acceptance."""
    return validate_boot_receipt(plan,receipt)

def build_cleanup_script(plan: InnerPlan, boot: Mapping) -> str:
    validate_boot_receipt(plan,boot)
    payload=repr(json.dumps({"root":plan.root,"root_identity":boot["runtime_dependency"]["stage"]["guest_root_identity"],"marker":plan.marker,"uid":plan.runtime_uid,"containment":boot["containment"],"processes":boot["processes"]},sort_keys=True,separators=(",",":")))
    return '''#!/usr/bin/env python3
import hashlib,json,os,pathlib,signal,stat,time
e=json.loads(%s); root=pathlib.Path(e['root'])
root_fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW); root_stat=os.fstat(root_fd);root_identity=(root_stat.st_dev,root_stat.st_ino,root_stat.st_uid,root_stat.st_gid,format(stat.S_IMODE(root_stat.st_mode),'04o'))
expected_root=e['root_identity']
if root_identity!=(expected_root['dev'],expected_root['inode'],expected_root['uid'],expected_root['gid'],expected_root['mode']): raise SystemExit('owned root identity changed before cleanup')
marker_fd=os.open('marker',os.O_RDONLY|os.O_NOFOLLOW,dir_fd=root_fd)
try: marker=os.read(marker_fd,4096).decode()
finally: os.close(marker_fd)
if marker!=e['marker']: raise SystemExit('marker mismatch')
def ident(pid):
 p=pathlib.Path('/proc')/str(pid); raw=p.joinpath('stat').read_text(); fields=raw[raw.rfind(')')+2:].split(); cmd=p.joinpath('cmdline').read_bytes(); exe=p.joinpath('exe').resolve(strict=True)
 cgroups=[line.split(':',2)[-1] for line in p.joinpath('cgroup').read_text().splitlines() if line.startswith('0::')]
 return {'pid':pid,'start_ticks':int(fields[19]),'state':fields[0],'uid':p.joinpath('status').stat().st_uid,'exe':str(exe),'exe_sha256':hashlib.sha256(exe.read_bytes()).hexdigest(),'cmdline_sha256':hashlib.sha256(cmd).hexdigest(),'cgroup':cgroups[0] if len(cgroups)==1 else ''}
def check(item):
 cur=ident(item['pid'])
 for key in ('pid','start_ticks','uid','exe','exe_sha256','cmdline_sha256','cgroup'):
  if cur[key]!=item[key]: raise SystemExit('process identity changed: '+key)
 return cur
items=list(e['processes']); known={x['pid'] for x in items}
cgroup_file=pathlib.Path('/sys/fs/cgroup'+e['containment']['path'])/'cgroup.procs'
actual={int(x) for x in cgroup_file.read_text().split()}
if actual!=known: raise SystemExit('owned cgroup membership is uncertain')
for item in sorted(items,key=lambda x:x['pid'],reverse=True): check(item); os.kill(item['pid'],signal.SIGTERM)
deadline=time.monotonic()+30
for item in items:
 while time.monotonic()<deadline:
  try:
   if ident(item['pid'])['state']=='Z': break
  except OSError: break
  time.sleep(.1)
 else:
  check(item); os.kill(item['pid'],signal.SIGKILL); end=time.monotonic()+10
  while time.monotonic()<end:
   try:
    if ident(item['pid'])['state']=='Z': break
   except OSError: break
   time.sleep(.1)
  else: raise SystemExit('owned process did not stop')
# Bind every stale UNIX socket under the authenticated root before deleting any.
sockets=[]
for parent,dirs,files,parent_fd in os.fwalk('.',topdown=True,follow_symlinks=False,dir_fd=root_fd):
 for name in files:
  st=os.stat(name,dir_fd=parent_fd,follow_symlinks=False)
  if stat.S_ISSOCK(st.st_mode): sockets.append((str(pathlib.PurePosixPath(parent)/name),st.st_dev,st.st_ino,st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode)))
def parent_fd_for(rel):
 fd=os.dup(root_fd)
 try:
  for part in pathlib.PurePosixPath(rel).parts[:-1]:
   nxt=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=nxt
  return fd
 except BaseException:
  os.close(fd);raise
for rel,dev,ino,uid,gid,mode in sockets:
 pfd=parent_fd_for(rel)
 try:
  name=pathlib.PurePosixPath(rel).name;st=os.stat(name,dir_fd=pfd,follow_symlinks=False)
  if (st.st_dev,st.st_ino,st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode))!=(dev,ino,uid,gid,mode) or not stat.S_ISSOCK(st.st_mode): raise SystemExit('owned socket identity changed')
  os.unlink(name,dir_fd=pfd);os.fsync(pfd)
 finally: os.close(pfd)
root_now=os.fstat(root_fd)
if (root_now.st_dev,root_now.st_ino,root_now.st_uid,root_now.st_gid,format(stat.S_IMODE(root_now.st_mode),'04o'))!=root_identity: raise SystemExit('owned root identity changed')
os.unlink('marker',dir_fd=root_fd);os.fsync(root_fd);os.close(root_fd)
print(json.dumps({'terminated_pids':sorted(known),'all_stopped':True,'marker_removed':True,'removed_sockets':len(sockets)}))
''' % payload

def validate_cleanup_receipt(plan: InnerPlan, receipt: Mapping, boot: Mapping) -> dict:
    validate_boot_receipt(plan,boot); _common(plan,receipt,"nested-cuttlefish-cleanup")
    expected=sorted(x["pid"] for x in boot["processes"]); observed=receipt.get("terminated_pids")
    if not isinstance(observed,list) or any(not isinstance(x,int) or isinstance(x,bool) or x<=1 for x in observed) or observed!=expected: raise NestedCuttlefishError("cleanup PID set mismatch")
    stopped=receipt.get("stopped_identities")
    if not isinstance(stopped,list) or sorted(x.get("pid") for x in stopped if isinstance(x,Mapping))!=expected or any(x.get("stopped") is not True for x in stopped): raise NestedCuttlefishError("stopped identity evidence missing")
    if receipt.get("unknown_survivors")!=[] or receipt.get("owned_sockets_remaining")!=[] or receipt.get("all_stopped") is not True or receipt.get("marker_removed") is not True or receipt.get("passed") is not True: raise NestedCuttlefishError("cleanup is incomplete or uncertain")
    return dict(receipt)
