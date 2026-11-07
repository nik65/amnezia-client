import base64, hashlib, json, subprocess
from pathlib import Path
import pytest

from deploy.release_lab.nested_cuttlefish_wayland_dependency import *


def receipt(plan):
    return {"schema":1,"operation":"nested-wayland-install","run_id":plan.run_id,"attempt_nonce":plan.attempt_nonce,
      "outer":dict(plan.outer),
      "origin":"guest","transport":"qga","injected":False,"supplement":{"sha256":SUPPLEMENT_SHA,"size":SUPPLEMENT_SIZE},
      "package":{"name":PACKAGE,"version":VERSION,"architecture":ARCH,"deb_sha256":DEB_SHA,"deb_size":DEB_SIZE,"binary_key":PACKAGE+":amd64","status":"ii "},
      "changed_packages":[PACKAGE+":amd64"],"unpack":{"exit_code":0},"configure":{"exit_code":0}}


def test_exact_constants_and_signed_stanza_are_embedded():
    assert SUPPLEMENT_SHA in INSTALL and DEB_SHA in INSTALL and DEB_NAME in INSTALL
    assert "expected_members" in INSTALL and "foreign dpkg delta" in INSTALL


def test_actual_immutable_56_row_verifier():
    path=Path(__file__).resolve().parents[2]/"dist/release-lab-fixtures/android-cvd-host-dependencies-noble-amd64-20260913/wayland-verifier-receipt.json"
    value=validate_wayland_verifier(path)
    assert len(value["packages"])==56
    row=[x for x in value["packages"] if x["package"]==PACKAGE]
    assert row==[{"architecture":ARCH,"file":DEB_NAME,"package":PACKAGE,"repository_path":"pool/main/w/wayland/"+DEB_NAME,"sha256":DEB_SHA,"signed_indexes":["noble"],"size":DEB_SIZE,"version":VERSION}]


def test_install_validator_rejects_foreign_delta_and_wrong_binding():
    p=object.__new__(WaylandDependencyPlan);object.__setattr__(p,"run_id","r");object.__setattr__(p,"attempt_nonce","a"*48);object.__setattr__(p,"outer",{"pid":1})
    r=receipt(p);assert validate_install(p,r)
    r["changed_packages"].append("foreign:amd64")
    with pytest.raises(WaylandDependencyError):validate_install(p,r)


def test_runtime_validator_requires_exact_qemu_and_clean_ldd():
    p=object.__new__(WaylandDependencyPlan)
    for k,v in {"run_id":"r","attempt_nonce":"a"*48,"runtime_uid":1000,"qemu_sha256":"9"*64,"outer":{"pid":1}}.items():object.__setattr__(p,k,v)
    install=receipt(p);path="/var/lib/amnezia-release-lab/n/abcd1234/runtime/qemu/qemu-system-aarch64"
    base=["/usr/bin/setpriv","--reuid=1000","--regid=1000","--clear-groups"]
    row=lambda argv,out: {"argv":argv,"exit_code":0,"stdout_sha256":"1"*64,"stderr_sha256":"2"*64,"stdout_size":len(out),"stderr_size":0,"stdout_excerpt":out,"stderr_excerpt":"","missing":[],"dependency_count":1}
    ld=":".join((path.split('/runtime/qemu/',1)[0]+"/runtime/private-libs",path.split('/runtime/qemu/',1)[0]+"/runtime/qemu",path.split('/runtime/qemu/',1)[0]+"/runtime/host/lib64",path.split('/runtime/qemu/',1)[0]+"/runtime/host/lib"))
    r={"schema":1,"operation":"nested-wayland-runtime-proof","run_id":"r","attempt_nonce":"a"*48,"outer":{"pid":1},"origin":"guest","transport":"qga","injected":False,"uid":1000,"primary_gid":1000,"ld_library_path":ld,
       "qemu":{"path":path,"sha256":"9"*64,"size":10},"ldd":row(base+["/usr/bin/ldd",path],"libwayland-server.so.0 => /lib/x"),"version":row(base+[path,"-version"],"QEMU 8.2")}
    assert validate_runtime(p,install,r,path)
    r["ldd"]["stdout_excerpt"]="libwayland-server.so.0 => not found"
    with pytest.raises(WaylandDependencyError):validate_runtime(p,install,r,path)
    r["ldd"]["stdout_excerpt"]="ok";r["ldd"]["missing"]=["late.so => not found"]
    with pytest.raises(WaylandDependencyError):validate_runtime(p,install,r,path)


def test_proof_is_actual_runtime_uid_and_not_bundled_text():
    assert "--clear-groups" in PROVE and "'/usr/bin/ldd',p" in PROVE and "[p,'-version']" in PROVE
    assert "runtime/private-libs" in PROVE and "env={'PATH'" in PROVE
    assert "while view:" in INSTALL and "short Wayland deb write" in INSTALL
    assert "clean-ldd.txt" not in PROVE and "qemu-version.txt" not in PROVE
    long_ldd=("libok.so => /lib/libok.so\n"*900)+"liblate.so => not found\n"
    assert len(long_ldd.encode())>16384 and "not found" not in long_ldd[:16384]
    assert [line.strip() for line in long_ldd.splitlines() if "not found" in line]==["liblate.so => not found"]
    assert "missing=[line.strip() for line in text.splitlines()" in PROVE

def test_runtime_failure_archives_full_guest_diagnostic_before_raising():
    repo=Path(__file__).resolve().parents[2];outer={"pid":1};nonce="a"*48
    plan=WaylandDependencyPlan("run","linux-headless-x64",nonce,1000,outer,
      str(repo/"dist/release-lab-fixtures/android-cvd-host-dependencies-noble-amd64-20260913/android-cvd-wayland-supplement-3b2a227c.tar"),
      str(repo/"dist/release-lab-fixtures/android-cvd-host-dependencies-noble-amd64-20260913/wayland-verifier-receipt.json"),"9"*64)
    path="/var/lib/amnezia-release-lab/n/abcd1234/runtime/qemu/qemu-system-aarch64"
    root=path.split('/runtime/qemu/',1)[0];ld=":".join((root+"/runtime/private-libs",root+"/runtime/qemu",root+"/runtime/host/lib64",root+"/runtime/host/lib"))
    base=["/usr/bin/setpriv","--reuid=1000","--regid=1000","--clear-groups"]
    diag={"schema":1,"operation":"nested-wayland-runtime-failure","run_id":"run","attempt_nonce":nonce,"outer":outer,"origin":"guest","transport":"qga","injected":False,"uid":1000,"primary_gid":1000,"ld_library_path":ld,"qemu":{"path":path,"sha256":"9"*64,"size":10},"acceptance":False,"probe_error":"QEMU dependency closure failed","ldd":{"argv":base+["/usr/bin/ldd",path],"exit_code":1,"missing":["libwayland-server.so.0 => not found"],"dependency_count":3,"stdout_size":17000,"stderr_size":0,"stdout_sha256":"1"*64,"stderr_sha256":"2"*64,"stdout_excerpt":"missing","stderr_excerpt":""},"version":None}
    class Q:
      def guest_exec_wait(self,*_,**__):return {"exitcode":0,"stdout":json.dumps(diag)}
    archived=[]
    def archive(run,value):archived.append((run,value));return {"origin":"controller","immutable":True}
    installer=WaylandDependencyInstaller(Q(),plan,lambda:outer,archive,archive)
    with pytest.raises(WaylandDependencyError,match="dependency closure"):installer.prove_runtime(receipt(plan),path)
    assert archived[0][0]=="run" and archived[0][1]["diagnostic"]==diag
    diag["ld_library_path"]="/wrong"
    with pytest.raises(WaylandDependencyError,match="binding invalid"):installer.prove_runtime(receipt(plan),path)
    diag["ld_library_path"]=ld;diag["ldd"]["stdout_size"]=1048577
    with pytest.raises(WaylandDependencyError,match="binding invalid"):installer.prove_runtime(receipt(plan),path)

def test_prove_failure_branch_is_real_json_subprocess_with_exact_run_id():
    wrapper='''import base64,hashlib,json,os,pathlib,sys,tempfile
root=pathlib.Path(tempfile.mkdtemp(prefix="wl-proof-"));p=root/"runtime/qemu/qemu-system-aarch64";p.parent.mkdir(parents=True);p.write_bytes(b"#!/bin/sh\\nexit 0\\n");p.chmod(0o755)
code=base64.b64decode(sys.argv[1]).decode();sys.argv=["prove",str(p),hashlib.sha256(p.read_bytes()).hexdigest(),str(os.getuid()),"run-exact","a"*48,json.dumps({"pid":7})];exec(code)
'''
    result=subprocess.run(["wsl.exe","python3","-c",wrapper,base64.b64encode(PROVE.encode()).decode()],capture_output=True,text=True)
    if result.returncode==127:pytest.skip("WSL unavailable")
    assert result.returncode==0,result.stderr
    value=json.loads(result.stdout);assert value["operation"]=="nested-wayland-runtime-failure" and value["run_id"]=="run-exact" and value["acceptance"] is False
