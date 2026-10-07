"""Build a private-UAPI AWG3 resource from already available pinned sources.

No downloads, installs, services or networking are performed by this builder.
Missing Go modules fail under GOPROXY=off and -mod=readonly.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import subprocess
import tempfile
import zipfile

SOURCE_SHA256 = "a95853baa25d438a3e92ea5207bd315e3a45143b5209488ebf7f0b44e2e2bcc3"
REF = "awg-go/3.1.20260814"
MODULE = "github.com/amnezia-vpn/amneziawg-go/v3"
SOCKET_DIRECTORY = "/run/amnezia/awg3"
LINKER_FLAG = f"-X {MODULE}/ipc.socketDirectory={SOCKET_DIRECTORY}"

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-archive", type=Path, required=True)
    parser.add_argument("--go", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source = args.source_archive.read_bytes()
    if hashlib.sha256(source).hexdigest() != SOURCE_SHA256:
        raise SystemExit("AWG3 source archive does not match the approved Conan recipe pin")
    toolchain = subprocess.check_output([str(args.go), "version"], text=True).strip()
    if "go1.26.0 " not in toolchain:
        raise SystemExit("AWG3 builder requires the approved Go 1.26.0 toolchain")
    args.output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="amnezia-awg3-source-") as temporary:
        root = Path(temporary)
        with zipfile.ZipFile(args.source_archive) as archive:
            entries = archive.infolist()
            prefixes = {entry.filename.split("/", 1)[0] for entry in entries}
            if len(prefixes) != 1 or sum(entry.file_size for entry in entries) > 128 * 1024 * 1024:
                raise SystemExit("AWG3 archive layout is invalid")
            for entry in entries:
                relative = Path(entry.filename)
                if relative.is_absolute() or ".." in relative.parts or (entry.external_attr >> 16) & 0o170000 == 0o120000:
                    raise SystemExit("AWG3 archive contains an unsafe path")
                archive.extract(entry, root)
        working = root / prefixes.pop()
        if not (working / "go.mod").read_text().startswith(f"module {MODULE}\n"):
            raise SystemExit("AWG3 source module does not match the pinned UAPI linker path")
        (working / "version.go").write_text('package main\n\nconst Version = "v3.1.20260814"\n')
        binary = args.output.resolve() / "amneziawg-go"
        env = dict(os.environ, GOOS="linux", GOARCH="amd64", CGO_ENABLED="0",
                   GOPROXY="off", GOSUMDB="off", GOTOOLCHAIN="local", GOENV="off", GOFLAGS="")
        command = [str(args.go.resolve()), "build", "-mod=readonly", "-trimpath", "-buildvcs=false",
                   "-ldflags", LINKER_FLAG, "-o", str(binary), "."]
        subprocess.run(command, cwd=working, env=env, check=True)
        data = binary.read_bytes()
        if data[:5] != b"\x7fELF\x02" or data[18:20] != b"\x3e\x00":
            raise SystemExit("AWG3 builder did not produce Linux x86_64 ELF")
        receipt = {"schema": 1, "reference": REF, "sourceArchiveSha256": SOURCE_SHA256,
                   "module": MODULE, "socketDirectory": SOCKET_DIRECTORY,
                   "linkerFlag": LINKER_FLAG, "toolchain": toolchain,
                   "toolchainSha256": hashlib.sha256(args.go.read_bytes()).hexdigest(),
                   "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
        (args.output / "awg3-resource-receipt.json").write_text(json.dumps(receipt, sort_keys=True) + "\n")
        print(json.dumps({"binary": str(binary), "receipt": str(args.output / "awg3-resource-receipt.json"), "sha256": receipt["sha256"]}))

if __name__ == "__main__":
    main()
