from conan import ConanFile
from conan.tools.cmake import cmake_layout, CMake, CMakeToolchain
from conan.tools.files import copy, replace_in_file
from conan.tools.env import VirtualBuildEnv, Environment
from conan.errors import ConanInvalidConfiguration
from conan.tools.scm import Git

import os
import platform
import shutil
import hashlib
import json
from pathlib import Path

UPSTREAM_COMMIT = "5c16489e2cd9ed3a0a7a27c7445bba5238132f86"
UPSTREAM_SUBMODULES = {
    "tunnel/tools/amneziawg-tools": "ee0f0a9aa34ff0a0da4b3433b9512781cfe02843",
    "tunnel/tools/elf-cleaner": "7efc05090675ec6161b7def862728086a26c3b1f",
}


def verify_prepared_source(source, contract_path, expected_contract_sha256, overlay):
    """Accept only an exact, reviewed Git-object export, never ambient source."""
    if not contract_path or not expected_contract_sha256:
        raise ValueError("AWG Android source override requires its frozen contract and SHA256")
    raw = Path(contract_path).read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_contract_sha256:
        raise ValueError("AWG Android source contract hash mismatch")
    contract = json.loads(raw)
    if contract.get("upstreamCommit") != UPSTREAM_COMMIT or contract.get("submodules") != UPSTREAM_SUBMODULES:
        raise ValueError("AWG Android source contract does not match approved upstream pins")
    source = Path(source).resolve()
    found = {}
    for path in source.rglob("*"):
        if path.is_symlink():
            if not path.resolve().is_relative_to(source):
                raise ValueError("AWG Android source symlink escapes prepared tree")
            data = os.readlink(path).encode("utf-8")
            mode = "120000"
        elif path.is_file():
            data = path.read_bytes()
            mode = "100755" if os.name != "nt" and path.stat().st_mode & 0o111 else "100644"
        else:
            continue
        found[path.relative_to(source).as_posix()] = (len(data), hashlib.sha256(data).hexdigest(), mode)
    entries = contract.get("files", [])
    expected = {}
    for item in entries:
        path = item["path"]
        if path in expected or path.startswith("/") or ".." in Path(path).parts or "\\" in path:
            raise ValueError("AWG Android source contract has an unsafe or duplicate path")
        expected[path] = (item["bytes"], item["sha256"], item["mode"])
    if not expected or found != expected:
        raise ValueError("AWG Android prepared source bytes/modes differ from frozen contract")
    tree = hashlib.sha256()
    for path, (_, digest, mode) in sorted(found.items()):
        tree.update(f"{path}\0{mode}\0{digest}\n".encode("utf-8"))
    if tree.hexdigest() != contract.get("sourceTreeSha256"):
        raise ValueError("AWG Android source tree fingerprint mismatch")
    overlay_hash = hashlib.sha256()
    overlay = Path(overlay)
    files = [overlay / "patch_union.py"] + sorted((overlay / "union").rglob("*"))
    for path in sorted(files):
        if path.is_file():
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            overlay_hash.update(f"{path.relative_to(overlay).as_posix()}\0{digest}\n".encode("utf-8"))
    if overlay_hash.hexdigest() != contract.get("overlayTreeSha256"):
        raise ValueError("AWG Android overlay differs from frozen contract")
    return contract

class AwgAndroid(ConanFile):
    name = "awg-android"
    version = "3.1.20260814"
    settings = "os", "arch", "build_type", "compiler"
    exports_sources = "patch_union.py", "union/*", "union/uniontun/*"

    def configure(self):
        self.settings.rm_safe("compiler.libcxx")
        self.settings.rm_safe("compiler.cppstd")

    def layout(self):
        cmake_layout(self)

    def build_requirements(self):
        self.tool_requires("cmake/[>=3.4.1 <4]")
        if platform.system() == "Windows":
            self.tool_requires("ninja/[*]")
            self.tool_requires("go/[*]")
            if not self.conf.get("tools.microsoft.bash:path", check_type=str):
                self.tool_requires("msys2/cci.latest")
        elif platform.system() == "Linux":
            # The upstream AWG Makefile downloads Go 1.24.2, while its
            # module requires Go >=1.25.5. Use the reproducible Conan Go
            # package and apply the Android runtime patch to a private copy.
            self.tool_requires("go/1.26.0")

    def validate(self):
        if self.settings.os != "Android":
            raise ConanInvalidConfiguration(f"{self.name} v{self.version} does not support {self.settings.os}")

    def source(self):
        source_dir = os.environ.get("AWG_ANDROID_SOURCE_DIR")
        if source_dir:
            if not os.path.isdir(source_dir):
                raise ConanInvalidConfiguration(f"AWG_ANDROID_SOURCE_DIR does not exist: {source_dir}")
            try:
                verify_prepared_source(source_dir, os.environ.get("AWG_ANDROID_SOURCE_CONTRACT"),
                                       os.environ.get("AWG_ANDROID_SOURCE_CONTRACT_SHA256"), self.export_sources_folder)
            except (ValueError, OSError, KeyError, TypeError) as error:
                raise ConanInvalidConfiguration(str(error)) from error
            shutil.copytree(source_dir, self.source_folder, dirs_exist_ok=True, symlinks=True)
        else:
            git = Git(self)
            git.clone(
                url="https://github.com/amnezia-vpn/amneziawg-android.git",
                target=".",
                args=["--recurse-submodules", "--branch", f"v{self.version}"]
            )
            if git.run("rev-parse HEAD").strip() != UPSTREAM_COMMIT:
                raise ConanInvalidConfiguration("AWG Android tag changed from the approved immutable commit")
            for path, commit in UPSTREAM_SUBMODULES.items():
                if git.run(f"-C {path} rev-parse HEAD").strip() != commit:
                    raise ConanInvalidConfiguration("AWG Android submodule differs from the approved immutable commit")
        import importlib.util
        spec = importlib.util.spec_from_file_location("awg_union_patch", os.path.join(self.export_sources_folder, "patch_union.py"))
        patch = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(patch)
        patch.install_union(Path(self.source_folder) / "tunnel/tools/libwg-go", Path(self.export_sources_folder) / "union")

    def generate(self):
        VirtualBuildEnv(self).generate()

        tc = CMakeToolchain(self)
        gradle_user_home = os.environ.get("AWG_ANDROID_GRADLE_USER_HOME")
        if not gradle_user_home:
            gradle_user_home = os.path.join(os.path.expanduser("~"), ".cache", "amnezia", "awg-android-gradle")
        os.makedirs(gradle_user_home, exist_ok=True)
        tc.variables["GRADLE_USER_HOME"] = gradle_user_home
        tc.variables["CMAKE_LIBRARY_OUTPUT_DIRECTORY"] = os.path.join(self.build_folder, "out")
        # not to warn in case of strtok() usage
        tc.extra_cflags = ["-Wno-deprecated-declarations"]
        tc.generate()

    def _patch_sources(self):
        if platform.system() == 'Darwin':
            replace_in_file(self,
                os.path.join(self.source_folder, "tunnel", "tools", "libwg-go", "Makefile"),
                'flock "$@.lock" -c \' \\\n',
                "",
            )
            replace_in_file(self,
                os.path.join(self.source_folder, "tunnel", "tools", "libwg-go", "Makefile"),
                'mv "$@.tmp" "$@"\'',
                'mv "$@.tmp" "$@"',
            )
            replace_in_file(self,
                os.path.join(self.source_folder, "tunnel", "tools", "libwg-go", "Makefile"),
                'touch "$@"\'',
                'touch "$@"',
            )
            replace_in_file(self,
                os.path.join(self.source_folder, "tunnel", "tools", "libwg-go", "Makefile"),
                'sha256sum -c',
                'shasum -a 256 -c'
            )
        elif platform.system() == 'Windows':
            # elf-cleaner uses sys/mman.h (POSIX only) and cannot be built on Windows;
            # skip it — DT_FLAGS_1 warnings only affect Android < 6.0
            replace_in_file(self,
                os.path.join(self.source_folder, "tunnel", "tools", "CMakeLists.txt"),
                '# Strip unwanted ELF sections to prevent DT_FLAGS_1 warnings on old Android versions\n'
                'file(GLOB ELF_CLEANER_SOURCES elf-cleaner/*.c elf-cleaner/*.cpp)\n'
                'add_custom_target(elf-cleaner COMMENT "Building elf-cleaner" VERBATIM COMMAND cc\n'
                '        -O2 -DPACKAGE_NAME="elf-cleaner" -DPACKAGE_VERSION="" -DCOPYRIGHT=""\n'
                '        -o "${CMAKE_CURRENT_BINARY_DIR}/elf-cleaner" ${ELF_CLEANER_SOURCES}\n'
                ')\n'
                'add_custom_command(TARGET libwg.so POST_BUILD VERBATIM COMMAND "${CMAKE_CURRENT_BINARY_DIR}/elf-cleaner"\n'
                '        --api-level "${ANDROID_NATIVE_API_LEVEL}" "$<TARGET_FILE:libwg.so>")\n'
                'add_dependencies(libwg.so elf-cleaner)\n'
                'add_custom_command(TARGET libwg-quick.so POST_BUILD VERBATIM COMMAND "${CMAKE_CURRENT_BINARY_DIR}/elf-cleaner"\n'
                '        --api-level "${ANDROID_NATIVE_API_LEVEL}" "$<TARGET_FILE:libwg-quick.so>")\n'
                'add_dependencies(libwg-quick.so elf-cleaner)',
                '',
            )
            # patch Makefile: skip Go download, use 'go' already in PATH from tool_requires
            replace_in_file(self,
                os.path.join(self.source_folder, "tunnel", "tools", "libwg-go", "Makefile"),
                '$(DESTDIR)/libwg-go.so: export PATH := $(BUILDDIR)/go-$(GO_VERSION)/bin/:$(PATH)\n$(DESTDIR)/libwg-go.so: $(BUILDDIR)/go-$(GO_VERSION)/.prepared go.mod',
                '$(DESTDIR)/libwg-go.so: go.mod',
            )
        elif platform.system() == 'Linux':
            makefile = Path(self.source_folder) / "tunnel/tools/libwg-go/Makefile"
            text = makefile.read_text(encoding="utf-8")
            old_version = "GO_VERSION := 1.24.2"
            if text.count(old_version) != 1:
                raise ConanInvalidConfiguration(
                    "AWG Makefile Go version anchor mismatch; refusing an unreviewed upstream source"
                )
            text = text.replace(old_version, "GO_VERSION := 1.26.0")
            old_prepare = (
                "$(BUILDDIR)/go-$(GO_VERSION)/.prepared: $(GRADLE_USER_HOME)/caches/golang/$(GO_TARBALL)\n"
                "\tmkdir -p \"$(dir $@)\"\n"
                "\tflock \"$@.lock\" -c ' \\\n"
                "\t[ -f \"$@\" ] && exit 0; \\\n"
                "\ttar -C \"$(dir $@)\" --strip-components=1 -xzf \"$^\" && \\\n"
                "\tpatch -p1 -f -N -r- -d \"$(dir $@)\" < goruntime-boottime-over-monotonic.diff && \\\n"
                "\ttouch \"$@\"'"
            )
            new_prepare = (
                "GO_RUNTIME_DIR ?= $(BUILDDIR)/go-$(GO_VERSION)\n"
                "$(GO_RUNTIME_DIR)/.prepared: go.mod\n"
                "\ttest -n \"$(AWG_GO_RUNTIME_ROOT)\"\n"
                "\ttest -x \"$(AWG_GO_RUNTIME_ROOT)/bin/go\"\n"
                "\trm -rf \"$(GO_RUNTIME_DIR)\"\n"
                "\tmkdir -p \"$(GO_RUNTIME_DIR)\"\n"
                "\tcp -a \"$(AWG_GO_RUNTIME_ROOT)/.\" \"$(GO_RUNTIME_DIR)/\"\n"
                "\tpatch -p1 -f -N -r- -d \"$(GO_RUNTIME_DIR)\" < goruntime-boottime-over-monotonic.diff\n"
                "\ttouch \"$@\""
            )
            if text.count(old_prepare) != 1:
                raise ConanInvalidConfiguration(
                    "AWG Makefile Go preparation anchor mismatch; refusing an unreviewed upstream source"
                )
            text = text.replace(old_prepare, new_prepare)
            old_target = (
                "$(DESTDIR)/libwg-go.so: export PATH := $(BUILDDIR)/go-$(GO_VERSION)/bin/:$(PATH)\n"
                "$(DESTDIR)/libwg-go.so: $(BUILDDIR)/go-$(GO_VERSION)/.prepared go.mod"
            )
            new_target = (
                "export GOTOOLCHAIN := local\n"
                "export GOROOT = $(GO_RUNTIME_DIR)\n"
                "$(DESTDIR)/libwg-go.so: export PATH := $(GO_RUNTIME_DIR)/bin/:$(PATH)\n"
                "$(DESTDIR)/libwg-go.so: $(GO_RUNTIME_DIR)/.prepared go.mod"
            )
            if text.count(old_target) != 1:
                raise ConanInvalidConfiguration(
                    "AWG Makefile Go target anchor mismatch; refusing an unreviewed upstream source"
                )
            makefile.write_text(text.replace(old_target, new_target), encoding="utf-8", newline="\n")

    def build(self):
        self._patch_sources()
        if platform.system() == "Linux":
            go = self.dependencies.build.get("go")
            if go is None:
                raise ConanInvalidConfiguration("Linux AWG Android build requires Conan go/1.26.0")
            os.environ["AWG_GO_RUNTIME_ROOT"] = str(go.package_folder)
            os.environ.setdefault(
                "GO_RUNTIME_DIR",
                str(Path.home() / ".cache" / "amnezia" / "awg-go-runtime" / self.version),
            )
            os.environ["GOTOOLCHAIN"] = "local"
        cmake = CMake(self)
        cmake.configure(build_script_folder=os.path.join(self.source_folder, "tunnel", "tools"))
        cmake.build(target=["libwg-go.so", "libwg.so", "libwg-quick.so"])

    def package(self):
        copy(self, "libwg-go.h", src=os.path.join(self.build_folder, "out"), dst=os.path.join(self.package_folder, "include"))
        copy(self, "libwg-go.so", src=os.path.join(self.build_folder, "out"), dst=os.path.join(self.package_folder, "lib"))
        copy(self, "libwg.so", src=os.path.join(self.build_folder, "out"), dst=os.path.join(self.package_folder, "bin"))
        copy(self, "libwg-quick.so", src=os.path.join(self.build_folder, "out"), dst=os.path.join(self.package_folder, "bin"))

    def package_info(self):
        self.cpp_info.set_property("cmake_target_name", "amnezia::awg-android")
        self.cpp_info.libs = [ "wg-go" ]
        self.cpp_info.set_property("cmake_extra_variables", {
            "AMNEZIA_ANDROID_LIBWG_PATH": Path(os.path.join(self.package_folder, "bin", "libwg.so")).as_posix(),
            "AMNEZIA_ANDROID_LIBWG_QUICK_PATH": Path(os.path.join(self.package_folder, "bin", "libwg-quick.so")).as_posix(),
        })
