from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


def test_linux_package_installs_shadertools_with_soname_chain() -> None:
    cmake = (REPO_ROOT / "client" / "CMakeLists.txt").read_text(encoding="utf-8")
    platform_guard = "if(LINUX AND NOT ANDROID)"
    install = 'install(FILES\n        "${_amnezia_shader_tools_real}"'
    assert cmake.count(install) == 1
    block = cmake[cmake.index(install):cmake.index("endif()", cmake.index(install))]
    assert '"${_amnezia_shader_tools_real}"' in block
    assert '"${_amnezia_shader_tools_soname}"' in block
    assert "IS_SYMLINK \"${_amnezia_shader_tools_soname}\"" in cmake
    assert "file(REAL_PATH" in cmake
    assert "Qt6::ShaderTools" not in cmake


def test_linux_package_installs_same_kit_offscreen_platform_plugin() -> None:
    cmake = (REPO_ROOT / "client" / "CMakeLists.txt").read_text(encoding="utf-8")
    target = "Qt6::QOffscreenIntegrationPlugin"
    install = 'install(FILES "${_amnezia_qt_offscreen_real}"'

    assert cmake.count(install) == 1
    assert f"if(NOT TARGET {target})" in cmake
    assert f"get_target_property(_amnezia_qt_offscreen_location {target} IMPORTED_LOCATION_RELEASE)" in cmake
    assert f"get_target_property(_amnezia_qt_offscreen_location {target} IMPORTED_LOCATION)" in cmake
    assert 'file(REAL_PATH "${_amnezia_qt_lib_dir}/../plugins/platforms"' in cmake
    assert "_amnezia_qt_offscreen_dir STREQUAL _amnezia_qt_platforms_dir" in cmake
    block = cmake[cmake.index(install):cmake.index(")", cmake.index(install)) + 1]
    assert 'DESTINATION "plugins/platforms"' in block
    assert "COMPONENT AmneziaVPN" in block


def test_linux_package_removes_unused_optional_tiff_plugin_fail_closed() -> None:
    cmake = (REPO_ROOT / "client" / "CMakeLists.txt").read_text(encoding="utf-8")
    cpack = (REPO_ROOT / "cmake" / "CPack.cmake").read_text(encoding="utf-8")
    hook = (REPO_ROOT / "cmake" / "prune_unused_qtiff.cmake.in").read_text(encoding="utf-8")
    assert "AMNEZIA_QTIFF_EXPECTED_SHA256" in cmake
    assert "list(APPEND CPACK_PRE_BUILD_SCRIPTS" in cpack
    assert "plugins/imageformats/libqtiff.so" in hook
    assert "7f454c46" in hook
    assert "file(SHA256" in hook and "file(REMOVE" in hook
    assert "_amnezia_packaged_qtiff" not in cmake


def test_linux_release_uses_complete_wsl_qt_root_and_rejects_stale_cache() -> None:
    local_release = (REPO_ROOT / "deploy/selfhosted_updates/local_release.ps1").read_text(
        encoding="utf-8"
    )
    setup = (REPO_ROOT / "deploy/selfhosted_updates/setup_release_workstation.ps1").read_text(
        encoding="utf-8"
    )

    assert "function Resolve-WslQtRootPath" in local_release
    assert "function Assert-WslQtReady" in local_release
    assert "function Assert-LinuxQtCacheBinding" in local_release
    assert '$linuxExports += "export QT_ROOT_PATH=$(Quote-Sh $wslQtRootPath)"' in local_release
    assert "Convert-ToWslPath $qtRootPath" not in local_release[
        local_release.index('if ($BuildPlatform -contains "linux")', local_release.index("if (-not $SkipBuild)")) :
        local_release.index('if ($BuildPlatform -contains "android")', local_release.index("if (-not $SkipBuild)"))
    ]
    assert "s/^Qt6_DIR:PATH=//p" in local_release
    assert "Recreate that build directory" in local_release
    assert "function Resolve-WslQtRoot" in setup
    assert '"`$env:WSL_QT_ROOT_PATH = $(Quote-PsSingle $resolvedWslQtRoot)"' in setup
    assert '"`$env:QT_ROOT_PATH = $(Quote-PsSingle (Join-Path $QtInstallDir $QtVersion))"' in setup
