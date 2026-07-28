/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "windowssplittunnel.h"

#include <qassert.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <string>
#include <vector>

#include "../windowscommons.h"
#include "../windowsservicemanager.h"
#include "logger.h"
#include "platforms/windows/daemon/windowsfirewall.h"
#include "platforms/windows/daemon/windowssplittunnel.h"
#include "platforms/windows/windowsutils.h"
#include "windowsfirewall.h"

#define PSAPI_VERSION 2
#include <Windows.h>
#include <psapi.h>

#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QNetworkInterface>
#include <QScopeGuard>
#include <QUrl>

#pragma region

// Driver Configuration structures
using CONFIGURATION_ENTRY = struct {
  // Offset into buffer region that follows all entries.
  // The image name uses the device path.
  SIZE_T ImageNameOffset;
  // Length of the String
  USHORT ImageNameLength;
};

using CONFIGURATION_HEADER = struct {
  // Number of entries immediately following the header.
  SIZE_T NumEntries;

  // Total byte length: header + entries + string buffer.
  SIZE_T TotalLength;
};

// Used to Configure Which IP is network/vpn
using IP_ADDRESSES_CONFIG = struct {
  IN_ADDR TunnelIpv4;
  IN_ADDR InternetIpv4;

  IN6_ADDR TunnelIpv6;
  IN6_ADDR InternetIpv6;
};

// Used to Define Which Processes are alive on activation
using PROCESS_DISCOVERY_HEADER = struct {
  SIZE_T NumEntries;
  SIZE_T TotalLength;
};

using PROCESS_DISCOVERY_ENTRY = struct {
  HANDLE ProcessId;
  HANDLE ParentProcessId;

  SIZE_T ImageNameOffset;
  USHORT ImageNameLength;
};

using ProcessInfo = struct {
  DWORD ProcessId;
  DWORD ParentProcessId;
  FILETIME CreationTime;
  std::wstring DevicePath;
};

#ifndef CTL_CODE

#  define FILE_ANY_ACCESS 0x0000

#  define METHOD_BUFFERED 0
#  define METHOD_IN_DIRECT 1
#  define METHOD_NEITHER 3

#  define CTL_CODE(DeviceType, Function, Method, Access) \
    (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))
#endif

// Known ControlCodes
#define IOCTL_INITIALIZE CTL_CODE(0x8000, 1, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_DEQUEUE_EVENT \
  CTL_CODE(0x8000, 2, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_REGISTER_PROCESSES \
  CTL_CODE(0x8000, 3, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_REGISTER_IP_ADDRESSES \
  CTL_CODE(0x8000, 4, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_GET_IP_ADDRESSES \
  CTL_CODE(0x8000, 5, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_SET_CONFIGURATION \
  CTL_CODE(0x8000, 6, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_GET_CONFIGURATION \
  CTL_CODE(0x8000, 7, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_CLEAR_CONFIGURATION \
  CTL_CODE(0x8000, 8, METHOD_NEITHER, FILE_ANY_ACCESS)

#define IOCTL_GET_STATE CTL_CODE(0x8000, 9, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_QUERY_PROCESS \
  CTL_CODE(0x8000, 10, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_ST_RESET CTL_CODE(0x8000, 11, METHOD_NEITHER, FILE_ANY_ACCESS)

constexpr static const auto DRIVER_SYMLINK = L"\\\\.\\MULLVADSPLITTUNNEL";
constexpr static const auto DRIVER_FILENAME = "mullvad-split-tunnel.sys";
constexpr static const auto DRIVER_SERVICE_NAME = L"AmneziaVPNSplitTunnel";
constexpr static const auto MV_SERVICE_NAME = L"MullvadVPN";
constexpr static const auto CONFIGURATION_HELPER_COMMAND =
    L"split-tunnel-config-helper";
constexpr static DWORD CONFIGURATION_HELPER_TIMEOUT_MS = 5000;
constexpr static DWORD CONFIGURATION_HELPER_MAX_BYTES = 16 * 1024 * 1024;

enum CONFIGURATION_HELPER_EXIT_CODE {
  CONFIGURATION_HELPER_SUCCESS = 0,
  CONFIGURATION_HELPER_INVALID_INPUT = 2,
  CONFIGURATION_HELPER_DRIVER_OPEN_FAILED = 3,
  CONFIGURATION_HELPER_IOCTL_FAILED = 4,
  CONFIGURATION_HELPER_ABORTED = 5,
};

#pragma endregion

namespace {
Logger logger("WindowsSplitTunnel");

QString inheritedHandleArgument(HANDLE handle) {
  return QString::number(static_cast<qulonglong>(
      reinterpret_cast<std::uintptr_t>(handle)));
}

HANDLE parseInheritedHandle(const QString& value) {
  bool ok = false;
  const qulonglong raw = value.toULongLong(&ok);
  if (!ok || raw == 0 ||
      raw > static_cast<qulonglong>(
                std::numeric_limits<std::uintptr_t>::max())) {
    return INVALID_HANDLE_VALUE;
  }
  return reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(raw));
}

HANDLE openSplitTunnelDriver() {
  return CreateFileW(DRIVER_SYMLINK, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                     OPEN_EXISTING, 0, nullptr);
}

HANDLE reopenSplitTunnelDriverBounded() {
  constexpr DWORD retryCount = 20;
  constexpr DWORD retryDelayMs = 50;
  for (DWORD attempt = 0; attempt < retryCount; ++attempt) {
    HANDLE driver = openSplitTunnelDriver();
    if (driver != INVALID_HANDLE_VALUE) {
      return driver;
    }
    Sleep(retryDelayMs);
  }
  return INVALID_HANDLE_VALUE;
}

ProcessInfo getProcessInfo(HANDLE process, const PROCESSENTRY32W& processMeta) {
  ProcessInfo pi;
  pi.ParentProcessId = processMeta.th32ParentProcessID;
  pi.ProcessId = processMeta.th32ProcessID;
  pi.CreationTime = {0, 0};
  pi.DevicePath = L"";

  FILETIME creationTime, null_time;
  auto ok = GetProcessTimes(process, &creationTime, &null_time, &null_time,
                            &null_time);
  if (ok) {
    pi.CreationTime = creationTime;
  }
  wchar_t imagepath[MAX_PATH + 1];
  if (K32GetProcessImageFileNameW(
          process, imagepath, sizeof(imagepath) / sizeof(*imagepath)) != 0) {
    pi.DevicePath = imagepath;
  }
  return pi;
}

QString normalizeExecutablePath(const QString& path) {
    QString normalized = path.trimmed();
  if (normalized.startsWith("file:", Qt::CaseInsensitive)) {
    const QString localPath = QUrl(normalized).toLocalFile();
    if (!localPath.isEmpty()) {
      normalized = localPath;
    }
  }
  normalized = QDir::fromNativeSeparators(normalized);
  normalized.replace('/', '\\');
  return normalized;
}

}  // namespace

bool WindowsSplitTunnel::resetForFirewallMigration() {
  if (!isInstalled()) {
    return true;
  }

  auto driverManager =
      WindowsServiceManager::open(QString::fromWCharArray(DRIVER_SERVICE_NAME));
  if (driverManager == nullptr) {
    logger.error() << "Unable to open the split-tunnel service before WFP "
                      "sublayer migration";
    return false;
  }
  if (driverManager->isStopped()) {
    return true;
  }
  if (!driverManager->isRunning()) {
    return driverManager->stopService();
  }

  HANDLE driverFile =
      CreateFileW(DRIVER_SYMLINK, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                  OPEN_EXISTING, 0, nullptr);
  if (driverFile != INVALID_HANDLE_VALUE) {
    const DRIVER_STATE state = getState(driverFile);
    if (state != STATE_UNKNOWN && state < STATE_INITIALIZED) {
      CloseHandle(driverFile);
      return true;
    }
    if (state >= STATE_INITIALIZED && resetDriver(driverFile)) {
      const DRIVER_STATE resetState = getState(driverFile);
      CloseHandle(driverFile);
      if (resetState != STATE_UNKNOWN && resetState < STATE_INITIALIZED) {
        logger.debug() << "Released split-tunnel WFP objects before sublayer "
                          "migration";
        return true;
      }
      logger.warning() << "Split-tunnel driver did not reach a safe state "
                          "after reset; unloading it";
    } else {
      CloseHandle(driverFile);
      logger.warning() << "Could not verify a safe split-tunnel driver reset; "
                          "unloading it";
    }
  } else {
    WindowsUtils::windowsLog(
        "Unable to open split-tunnel driver before WFP migration");
  }

  // Unloading the kernel driver closes its dynamic WFP session. create()
  // starts it again after WindowsFirewall has recreated the shared sublayers.
  if (!driverManager->stopService()) {
    logger.error() << "Failed to unload split-tunnel driver before WFP "
                      "sublayer migration";
    return false;
  }
  return true;
}

bool WindowsSplitTunnel::removeForUninstall() {
  if (!isInstalled()) {
    return true;
  }

  auto driverManager =
      WindowsServiceManager::open(QString::fromWCharArray(DRIVER_SERVICE_NAME));
  if (driverManager == nullptr) {
    logger.error() << "Unable to open split-tunnel service for uninstall";
    return false;
  }

  const bool sharedDeviceOwnedByAmnezia = !detectConflict();
  if (driverManager->isRunning() && sharedDeviceOwnedByAmnezia) {
    HANDLE driverFile =
        CreateFileW(DRIVER_SYMLINK, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                    OPEN_EXISTING, 0, nullptr);
    if (driverFile != INVALID_HANDLE_VALUE) {
      const DRIVER_STATE state = getState(driverFile);
      if (state >= STATE_INITIALIZED && !resetDriver(driverFile)) {
        logger.warning() << "Split-tunnel reset failed; forcing driver unload";
      }
      CloseHandle(driverFile);
    }
  }
  if (!driverManager->stopService()) {
    logger.error() << "Failed to unload split-tunnel driver during uninstall";
    return false;
  }

  // Release the service handle before requesting deletion.
  driverManager.reset();
  return uninstallDriver();
}

std::unique_ptr<WindowsSplitTunnel> WindowsSplitTunnel::create(
    WindowsFirewall* fw) {
  if (fw == nullptr) {
    // Pre-Condition:
    // Make sure the Windows Firewall has created the sublayer
    // otherwise the driver will fail to initialize
    logger.error() << "Failed to did not pass a WindowsFirewall obj"
                   << "The Driver cannot work with the sublayer not created";
    return nullptr;
  }
  // 00: Check if we conflict with mullvad, if so.
  if (detectConflict()) {
    logger.error() << "Conflict detected, abort Split-Tunnel init.";
    return nullptr;
  }
  // 01: Check if the driver is installed, if not do so.
  if (!isInstalled()) {
    logger.debug() << "Driver is not Installed, doing so";
    auto handle = installDriver();
    if (handle == INVALID_HANDLE_VALUE) {
      WindowsUtils::windowsLog("Failed to install Driver");
      return nullptr;
    }
    logger.debug() << "Driver installed";
    CloseServiceHandle(handle);
  } else {
    logger.debug() << "Driver was installed";
  }
  // 02: Now check if the service is running
  auto driver_manager =
      WindowsServiceManager::open(QString::fromWCharArray(DRIVER_SERVICE_NAME));
  if (Q_UNLIKELY(driver_manager == nullptr)) {
    // Let's be fair if we end up here,
    // after checking it exists and installing it,
    // this is super unlikeley
    Q_ASSERT(false);
    logger.error()
        << "WindowsServiceManager was unable fo find Split Tunnel service?";
    return nullptr;
  }
  if (!driver_manager->isRunning()) {
    logger.debug() << "Driver is not running, starting it";
    // Start the service
    if (!driver_manager->startService()) {
      logger.error() << "Failed to start Split Tunnel Service";
      return nullptr;
    };
  }
  // 03: Open the Driver Symlink
  auto driverFile = CreateFileW(DRIVER_SYMLINK, GENERIC_READ | GENERIC_WRITE, 0,
                                nullptr, OPEN_EXISTING, 0, nullptr);
  ;
  if (driverFile == INVALID_HANDLE_VALUE) {
    WindowsUtils::windowsLog("Failed to open Driver: ");
    // Only once, if the opening did not work. Try to reboot it. #
    logger.info()
        << "Failed to open driver, attempting only once to reboot driver";
    if (!driver_manager->stopService()) {
      logger.error() << "Unable stop driver";
      return nullptr;
    };
    logger.info() << "Stopped driver, starting it again.";
    if (!driver_manager->startService()) {
      logger.error() << "Unable start driver";
      return nullptr;
    };
    logger.info() << "Opening again.";
    driverFile = CreateFileW(DRIVER_SYMLINK, GENERIC_READ | GENERIC_WRITE, 0,
                             nullptr, OPEN_EXISTING, 0, nullptr);
    if (driverFile == INVALID_HANDLE_VALUE) {
      logger.error() << "Opening Failed again, sorry!";
      return nullptr;
    }
  }
  const SUBLAYER_GUIDS sublayerGuids = {
      WindowsFirewall::splitTunnelBaselineSublayerKey(),
      WindowsFirewall::splitTunnelDnsSublayerKey(),
  };
  if (!initDriver(driverFile, sublayerGuids)) {
    logger.error() << "Failed to init driver";
    CloseHandle(driverFile);
    return nullptr;
  }
  // We're ready to talk to the driver, it's alive and setup.
  auto splitTunnel = std::make_unique<WindowsSplitTunnel>(driverFile);
  splitTunnel->m_sublayerGuids = sublayerGuids;
  return splitTunnel;
}

bool WindowsSplitTunnel::initDriver(
    HANDLE driverIO, const SUBLAYER_GUIDS& sublayerGuids) {
  // We need to now check the state and init it, if required
  auto state = getState(driverIO);
  if (state == STATE_UNKNOWN) {
    logger.debug() << "Cannot check if driver is initialized";
    return false;
  }
  if (state >= STATE_INITIALIZED) {
    logger.debug() << "Driver already initialized: " << state;
    // Reset Driver as it has wfp handles probably >:(
    resetDriver(driverIO);

    auto newState = getState(driverIO);
    logger.debug() << "New state after reset:" << newState;
    if (newState >= STATE_INITIALIZED) {
      logger.debug() << "Reset unsuccesfull";
      return false;
    }
  }

  if (!sendInitializeIoctl(driverIO, sublayerGuids)) {
    auto err = GetLastError();
    logger.error() << "Driver init failed err -" << err;
    logger.error() << "State:" << getState(driverIO);

    return false;
  }
  logger.debug() << "Driver initialized" << getState(driverIO);
  return true;
}

WindowsSplitTunnel::WindowsSplitTunnel(HANDLE driverIO) : m_driver(driverIO) {
  logger.debug() << "Connected to the Driver";

  Q_ASSERT(getState() == STATE_INITIALIZED);
}

WindowsSplitTunnel::~WindowsSplitTunnel() {
  if (m_quarantinedHelperAbortEvent != nullptr) {
    SetEvent(m_quarantinedHelperAbortEvent);
  }
  // Never join or terminate a helper that is potentially stuck inside the
  // kernel driver. Its inherited abort event remains signaled after these
  // parent handles close, so a late IOCTL completion can clear its ruleset and
  // exit without blocking daemon shutdown.
  if (m_quarantinedHelperJob != nullptr) {
    CloseHandle(m_quarantinedHelperJob);
    m_quarantinedHelperJob = nullptr;
  }
  if (m_quarantinedHelperProcess != nullptr) {
    CloseHandle(m_quarantinedHelperProcess);
    m_quarantinedHelperProcess = nullptr;
  }
  if (m_quarantinedHelperAbortEvent != nullptr) {
    CloseHandle(m_quarantinedHelperAbortEvent);
    m_quarantinedHelperAbortEvent = nullptr;
  }
  if (m_driver != INVALID_HANDLE_VALUE) {
    const DRIVER_STATE state = getState(m_driver);
    if (state >= STATE_INITIALIZED && !resetDriver(m_driver)) {
      logger.warning() << "Failed to reset split-tunnel driver during shutdown";
    }
    CloseHandle(m_driver);
    m_driver = INVALID_HANDLE_VALUE;
  }
}

bool WindowsSplitTunnel::excludeApps(const QStringList& appPaths) {
  if (m_driver == INVALID_HANDLE_VALUE &&
      !reapQuarantinedConfigurationHelper()) {
    return false;
  }
  auto state = getState();
  if (state != STATE_READY && state != STATE_RUNNING) {
    logger.warning() << "Driver is not in the right State to set Rules"
                     << state;
    return false;
  }

  logger.debug() << "Pushing new Ruleset for Split-Tunnel " << state;
  auto config = generateAppConfiguration(appPaths);
  if (config.empty()) {
    logger.error() << "No valid split-tunnel application rules generated";
    return false;
  }

  if (!applyConfigurationBounded(config)) {
    return false;
  }
  logger.debug() << "New Configuration applied: " << stateString();
  return true;
}

bool WindowsSplitTunnel::sendInitializeIoctl(
    HANDLE driverIO, const SUBLAYER_GUIDS& sublayerGuids) {
  DWORD bytesReturned = 0;
  return DeviceIoControl(
             driverIO, IOCTL_INITIALIZE,
             const_cast<SUBLAYER_GUIDS*>(&sublayerGuids),
             sizeof(sublayerGuids), nullptr, 0, &bytesReturned, nullptr) !=
         FALSE;
}

int WindowsSplitTunnel::runConfigurationHelper(
    const QString& mappingHandleValue,
    const QString& configuredEventHandleValue,
    const QString& commitEventHandleValue,
    const QString& abortEventHandleValue,
    const QString& parentProcessHandleValue,
    const QString& configSizeValue) {
  HANDLE mappingHandle = parseInheritedHandle(mappingHandleValue);
  HANDLE configuredEvent = parseInheritedHandle(configuredEventHandleValue);
  HANDLE commitEvent = parseInheritedHandle(commitEventHandleValue);
  HANDLE abortEvent = parseInheritedHandle(abortEventHandleValue);
  HANDLE parentProcess = parseInheritedHandle(parentProcessHandleValue);
  bool sizeValid = false;
  const qulonglong rawConfigSize = configSizeValue.toULongLong(&sizeValid);
  if (mappingHandle == INVALID_HANDLE_VALUE ||
      configuredEvent == INVALID_HANDLE_VALUE ||
      commitEvent == INVALID_HANDLE_VALUE ||
      abortEvent == INVALID_HANDLE_VALUE || !sizeValid ||
      parentProcess == INVALID_HANDLE_VALUE ||
      rawConfigSize < sizeof(CONFIGURATION_HEADER) ||
      rawConfigSize > CONFIGURATION_HELPER_MAX_BYTES) {
    return CONFIGURATION_HELPER_INVALID_INPUT;
  }
  auto closeInheritedHandles = qScopeGuard([&] {
    CloseHandle(mappingHandle);
    CloseHandle(configuredEvent);
    CloseHandle(commitEvent);
    CloseHandle(abortEvent);
    CloseHandle(parentProcess);
  });

  const DWORD configSize = static_cast<DWORD>(rawConfigSize);
  const void* config =
      MapViewOfFile(mappingHandle, FILE_MAP_READ, 0, 0, configSize);
  if (config == nullptr) {
    return CONFIGURATION_HELPER_INVALID_INPUT;
  }
  auto unmapConfig =
      qScopeGuard([&] { UnmapViewOfFile(const_cast<void*>(config)); });
  const auto* header =
      reinterpret_cast<const CONFIGURATION_HEADER*>(config);
  if (header->TotalLength != configSize ||
      header->NumEntries >
          (configSize - sizeof(CONFIGURATION_HEADER)) /
              sizeof(CONFIGURATION_ENTRY)) {
    return CONFIGURATION_HELPER_INVALID_INPUT;
  }

  const auto* entries =
      reinterpret_cast<const CONFIGURATION_ENTRY*>(header + 1);
  const SIZE_T stringRegionOffset =
      sizeof(CONFIGURATION_HEADER) +
      header->NumEntries * sizeof(CONFIGURATION_ENTRY);
  const SIZE_T stringRegionSize = configSize - stringRegionOffset;
  for (SIZE_T i = 0; i < header->NumEntries; ++i) {
    const CONFIGURATION_ENTRY& entry = entries[i];
    if (entry.ImageNameLength == 0 ||
        entry.ImageNameLength % sizeof(wchar_t) != 0 ||
        entry.ImageNameOffset % sizeof(wchar_t) != 0 ||
        entry.ImageNameOffset > stringRegionSize ||
        entry.ImageNameLength > stringRegionSize - entry.ImageNameOffset) {
      return CONFIGURATION_HELPER_INVALID_INPUT;
    }
  }
  const auto parentStoppedOrAborted = [&]() {
    const std::array<HANDLE, 2> stopSignals = {abortEvent, parentProcess};
    const DWORD wait =
        WaitForMultipleObjects(static_cast<DWORD>(stopSignals.size()),
                               stopSignals.data(), FALSE, 0);
    // WAIT_TIMEOUT is the only result proving both the parent and request are
    // still live.  Invalid/inconclusive inherited state must fail closed.
    return wait != WAIT_TIMEOUT;
  };
  if (parentStoppedOrAborted()) {
    return CONFIGURATION_HELPER_ABORTED;
  }

  HANDLE driver = openSplitTunnelDriver();
  if (driver == INVALID_HANDLE_VALUE) {
    return CONFIGURATION_HELPER_DRIVER_OPEN_FAILED;
  }
  auto closeDriver = qScopeGuard([&] { CloseHandle(driver); });

  // Recheck immediately before the mutating IOCTL.  The service may have
  // exited while this helper was waiting for the driver's exclusive handle.
  if (parentStoppedOrAborted()) {
    return CONFIGURATION_HELPER_ABORTED;
  }

  DWORD bytesReturned = 0;
  const bool configured =
      DeviceIoControl(driver, IOCTL_SET_CONFIGURATION,
                      const_cast<void*>(config), configSize, nullptr, 0,
                      &bytesReturned, nullptr) != FALSE;
  if (!configured) {
    logger.error() << "Split-tunnel configuration helper IOCTL failed:"
                   << GetLastError();
    SetEvent(configuredEvent);
    return CONFIGURATION_HELPER_IOCTL_FAILED;
  }

  // Two-phase handoff closes the timeout race: a configuration is never
  // considered accepted until the parent explicitly commits it. On timeout,
  // abort wins if both control events become signaled together.
  SetEvent(configuredEvent);
  const std::array<HANDLE, 3> controlEvents = {abortEvent, parentProcess,
                                               commitEvent};
  const DWORD control =
      WaitForMultipleObjects(static_cast<DWORD>(controlEvents.size()),
                             controlEvents.data(), FALSE, INFINITE);
  if (control != WAIT_OBJECT_0 + 2) {
    // The parent already continued without split tunneling. If the original
    // request completed late, remove that late ruleset before releasing the
    // quarantined device handle. This is best effort because the v1.3 driver
    // ABI does not support cancelable/generation-bound requests.
    DeviceIoControl(driver, IOCTL_CLEAR_CONFIGURATION, nullptr, 0, nullptr, 0,
                    &bytesReturned, nullptr);
    return CONFIGURATION_HELPER_ABORTED;
  }
  return CONFIGURATION_HELPER_SUCCESS;
}

void WindowsSplitTunnel::quarantineConfigurationHelper(
    HANDLE job, HANDLE process, HANDLE abortEvent) {
  SetEvent(abortEvent);
  m_quarantinedHelperJob = job;
  m_quarantinedHelperProcess = process;
  m_quarantinedHelperAbortEvent = abortEvent;
  logger.error()
      << "Split-tunnel configuration timed out after"
      << CONFIGURATION_HELPER_TIMEOUT_MS
      << "ms; helper and driver quarantined while main VPN activation resumes; "
         "split-tunnel state is indeterminate until late cleanup completes";
}

bool WindowsSplitTunnel::reapQuarantinedConfigurationHelper() {
  if (m_quarantinedHelperProcess == nullptr) {
    return m_driver != INVALID_HANDLE_VALUE;
  }
  if (WaitForSingleObject(m_quarantinedHelperProcess, 0) != WAIT_OBJECT_0) {
    logger.warning() << "Split-tunnel helper is still quarantined";
    return false;
  }

  CloseHandle(m_quarantinedHelperJob);
  CloseHandle(m_quarantinedHelperProcess);
  CloseHandle(m_quarantinedHelperAbortEvent);
  m_quarantinedHelperJob = nullptr;
  m_quarantinedHelperProcess = nullptr;
  m_quarantinedHelperAbortEvent = nullptr;

  m_driver = reopenSplitTunnelDriverBounded();
  if (m_driver == INVALID_HANDLE_VALUE) {
    logger.error() << "Failed to reopen split-tunnel driver after quarantine";
    return false;
  }
  logger.info() << "Split-tunnel helper quarantine cleared";
  return true;
}

bool WindowsSplitTunnel::applyConfigurationBounded(
    const std::vector<uint8_t>& config) {
  if (m_driver == INVALID_HANDLE_VALUE ||
      m_quarantinedHelperJob != nullptr || config.empty() ||
      config.size() > CONFIGURATION_HELPER_MAX_BYTES ||
      config.size() > std::numeric_limits<DWORD>::max()) {
    logger.error() << "Refusing invalid or quarantined split-tunnel "
                      "configuration request";
    return false;
  }

  SECURITY_ATTRIBUTES inheritableAttributes{};
  inheritableAttributes.nLength = sizeof(inheritableAttributes);
  inheritableAttributes.bInheritHandle = TRUE;

  const DWORD configSize = static_cast<DWORD>(config.size());
  HANDLE mapping = CreateFileMappingW(INVALID_HANDLE_VALUE,
                                      &inheritableAttributes, PAGE_READWRITE,
                                      0, configSize, nullptr);
  if (mapping == nullptr) {
    WindowsUtils::windowsLog(
        "Failed to create split-tunnel helper memory mapping");
    return false;
  }
  auto closeMapping = qScopeGuard([&] { CloseHandle(mapping); });
  void* mappingView =
      MapViewOfFile(mapping, FILE_MAP_WRITE, 0, 0, configSize);
  if (mappingView == nullptr) {
    WindowsUtils::windowsLog(
        "Failed to map split-tunnel helper configuration");
    return false;
  }
  std::memcpy(mappingView, config.data(), configSize);
  UnmapViewOfFile(mappingView);

  HANDLE configuredEvent =
      CreateEventW(&inheritableAttributes, TRUE, FALSE, nullptr);
  HANDLE commitEvent =
      CreateEventW(&inheritableAttributes, TRUE, FALSE, nullptr);
  HANDLE abortEvent =
      CreateEventW(&inheritableAttributes, TRUE, FALSE, nullptr);
  if (configuredEvent == nullptr || commitEvent == nullptr ||
      abortEvent == nullptr) {
    if (configuredEvent != nullptr) {
      CloseHandle(configuredEvent);
    }
    if (commitEvent != nullptr) {
      CloseHandle(commitEvent);
    }
    if (abortEvent != nullptr) {
      CloseHandle(abortEvent);
    }
    WindowsUtils::windowsLog(
        "Failed to create split-tunnel helper control events");
    return false;
  }
  auto closeConfiguredEvent =
      qScopeGuard([&] { CloseHandle(configuredEvent); });
  auto closeCommitEvent = qScopeGuard([&] { CloseHandle(commitEvent); });
  auto closeAbortEvent = qScopeGuard([&] { CloseHandle(abortEvent); });

  HANDLE parentProcess =
      OpenProcess(SYNCHRONIZE, TRUE, GetCurrentProcessId());
  if (parentProcess == nullptr) {
    WindowsUtils::windowsLog(
        "Failed to create split-tunnel helper parent monitor");
    return false;
  }
  auto closeParentProcess = qScopeGuard([&] { CloseHandle(parentProcess); });

  HANDLE job = CreateJobObjectW(nullptr, nullptr);
  if (job == nullptr) {
    WindowsUtils::windowsLog("Failed to create split-tunnel helper job");
    return false;
  }
  auto closeJob = qScopeGuard([&] { CloseHandle(job); });
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION jobInfo{};
  jobInfo.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
  jobInfo.BasicLimitInformation.ActiveProcessLimit = 1;
  if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation,
                               &jobInfo, sizeof(jobInfo))) {
    WindowsUtils::windowsLog("Failed to constrain split-tunnel helper job");
    return false;
  }

  SIZE_T attributeListSize = 0;
  InitializeProcThreadAttributeList(nullptr, 1, 0, &attributeListSize);
  auto attributeStorage = std::make_unique<std::byte[]>(attributeListSize);
  auto* attributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(
      attributeStorage.get());
  if (!InitializeProcThreadAttributeList(attributeList, 1, 0,
                                         &attributeListSize)) {
    WindowsUtils::windowsLog(
        "Failed to initialize split-tunnel helper handle list");
    return false;
  }
  auto deleteAttributeList =
      qScopeGuard([&] { DeleteProcThreadAttributeList(attributeList); });
  const std::array<HANDLE, 5> inheritedHandles = {
      mapping, configuredEvent, commitEvent, abortEvent, parentProcess};
  if (!UpdateProcThreadAttribute(
          attributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
          const_cast<HANDLE*>(inheritedHandles.data()),
          sizeof(inheritedHandles), nullptr, nullptr)) {
    WindowsUtils::windowsLog(
        "Failed to restrict split-tunnel helper inherited handles");
    return false;
  }

  const std::wstring executable =
      QCoreApplication::applicationFilePath().toStdWString();
  std::wstring commandLine = L"\"" + executable + L"\" " +
                             CONFIGURATION_HELPER_COMMAND + L" " +
                             inheritedHandleArgument(mapping).toStdWString() +
                             L" " +
                             inheritedHandleArgument(configuredEvent)
                                 .toStdWString() +
                             L" " +
                             inheritedHandleArgument(commitEvent)
                                 .toStdWString() +
                             L" " +
                             inheritedHandleArgument(abortEvent).toStdWString() +
                             L" " +
                             inheritedHandleArgument(parentProcess)
                                 .toStdWString() +
                             L" " + std::to_wstring(configSize);
  std::vector<wchar_t> mutableCommandLine(commandLine.begin(),
                                          commandLine.end());
  mutableCommandLine.push_back(L'\0');

  STARTUPINFOEXW startupInfo{};
  startupInfo.StartupInfo.cb = sizeof(startupInfo);
  startupInfo.lpAttributeList = attributeList;
  PROCESS_INFORMATION processInfo{};

  // The helper must be the sole owner of the exclusive device handle while
  // SET_CONFIGURATION is in flight.
  CloseHandle(m_driver);
  m_driver = INVALID_HANDLE_VALUE;
  const bool created = CreateProcessW(
      executable.c_str(), mutableCommandLine.data(), nullptr, nullptr, TRUE,
      EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW | CREATE_SUSPENDED,
      nullptr, nullptr, &startupInfo.StartupInfo, &processInfo) != FALSE;
  if (!created) {
    WindowsUtils::windowsLog("Failed to start split-tunnel helper process");
    m_driver = reopenSplitTunnelDriverBounded();
    return false;
  }
  auto closeProcess = qScopeGuard([&] { CloseHandle(processInfo.hProcess); });
  auto closeThread = qScopeGuard([&] { CloseHandle(processInfo.hThread); });

  if (!AssignProcessToJobObject(job, processInfo.hProcess) ||
      ResumeThread(processInfo.hThread) == static_cast<DWORD>(-1)) {
    WindowsUtils::windowsLog("Failed to activate split-tunnel helper process");
    TerminateProcess(processInfo.hProcess, CONFIGURATION_HELPER_ABORTED);
    WaitForSingleObject(processInfo.hProcess, 1000);
    m_driver = reopenSplitTunnelDriverBounded();
    return false;
  }
  CloseHandle(processInfo.hThread);
  processInfo.hThread = nullptr;
  closeThread.dismiss();

  const std::array<HANDLE, 2> completionHandles = {configuredEvent,
                                                   processInfo.hProcess};
  const DWORD waitResult = WaitForMultipleObjects(
      static_cast<DWORD>(completionHandles.size()), completionHandles.data(),
      FALSE, CONFIGURATION_HELPER_TIMEOUT_MS);
  if (waitResult == WAIT_TIMEOUT || waitResult == WAIT_FAILED) {
    quarantineConfigurationHelper(job, processInfo.hProcess, abortEvent);
    closeJob.dismiss();
    closeProcess.dismiss();
    closeAbortEvent.dismiss();
    return false;
  }

  if (waitResult == WAIT_OBJECT_0) {
    SetEvent(commitEvent);
    if (WaitForSingleObject(processInfo.hProcess, 1000) != WAIT_OBJECT_0) {
      quarantineConfigurationHelper(job, processInfo.hProcess, abortEvent);
      closeJob.dismiss();
      closeProcess.dismiss();
      closeAbortEvent.dismiss();
      return false;
    }
  }

  DWORD exitCode = CONFIGURATION_HELPER_IOCTL_FAILED;
  if (!GetExitCodeProcess(processInfo.hProcess, &exitCode)) {
    exitCode = CONFIGURATION_HELPER_IOCTL_FAILED;
  }
  m_driver = reopenSplitTunnelDriverBounded();
  if (m_driver == INVALID_HANDLE_VALUE) {
    logger.error() << "Failed to reopen split-tunnel driver after helper";
    return false;
  }
  if (exitCode != CONFIGURATION_HELPER_SUCCESS) {
    logger.error() << "Split-tunnel configuration helper failed with code"
                   << exitCode;
    return false;
  }
  return getState() == STATE_RUNNING;
}

bool WindowsSplitTunnel::start(int inetAdapterIndex, int vpnAdapterIndex) {
  // To Start we need to send 2 things:
  // Network info (what is vpn what is network)
  logger.debug() << "Starting SplitTunnel";
  DWORD bytesReturned;

  if (m_driver == INVALID_HANDLE_VALUE &&
      !reapQuarantinedConfigurationHelper()) {
    return false;
  }

  if (getState() == STATE_STARTED) {
    logger.debug() << "Driver needs Init Call";
    if (!sendInitializeIoctl(m_driver, m_sublayerGuids)) {
      logger.error() << "Driver init failed. Error:" << GetLastError();
      return false;
    }
  }

  // Process Info (what is running already)
  if (getState() == STATE_INITIALIZED) {
    logger.debug() << "State is Init, requires process config";
    auto config = generateProcessBlob();
    if (config.empty()) {
      logger.error() << "Process configuration blob is empty";
      return false;
    }
    auto ok = DeviceIoControl(m_driver, IOCTL_REGISTER_PROCESSES, &config[0],
                              (DWORD)config.size(), nullptr, 0, &bytesReturned,
                              nullptr);
    if (!ok) {
      logger.error() << "Failed to set Process Config. Error:"
                     << GetLastError();
      return false;
    }
    logger.debug() << "Set Process Config ok || new State:" << stateString();
  }

  if (getState() == STATE_INITIALIZED) {
    logger.warning() << "Driver is still not ready after process list send";
    return false;
  }
  logger.debug() << "Driver is  ready || new State:" << stateString();

  auto config = generateIPConfiguration(inetAdapterIndex, vpnAdapterIndex);
  if (config.empty()) {
    logger.error() << "Network configuration blob is empty. Internet adapter:"
                   << inetAdapterIndex << "VPN adapter:" << vpnAdapterIndex;
    return false;
  }
  auto ok = DeviceIoControl(m_driver, IOCTL_REGISTER_IP_ADDRESSES, &config[0],
                            (DWORD)config.size(), nullptr, 0, &bytesReturned,
                            nullptr);
  if (!ok) {
    logger.error() << "Failed to set Network Config. Error:" << GetLastError();
    return false;
  }
  logger.debug() << "New Network Config Applied || new State:" << stateString();
  return true;
}

void WindowsSplitTunnel::stop() {
  if (m_driver == INVALID_HANDLE_VALUE) {
    if (!reapQuarantinedConfigurationHelper()) {
      logger.warning() << "Skipping split-tunnel stop for quarantined helper";
      return;
    }
  }
  DWORD bytesReturned;
  auto ok = DeviceIoControl(m_driver, IOCTL_CLEAR_CONFIGURATION, nullptr, 0,
                            nullptr, 0, &bytesReturned, nullptr);
  if (!ok) {
    logger.error() << "Stopping Split tunnel not successfull";
    return;
  }
  logger.debug() << "Stopping Split tunnel successfull";
}

bool WindowsSplitTunnel::resetDriver(HANDLE driverIO) {
  DWORD bytesReturned;
  auto ok = DeviceIoControl(driverIO, IOCTL_ST_RESET, nullptr, 0, nullptr, 0,
                            &bytesReturned, nullptr);
  if (!ok) {
    logger.error() << "Reset Split tunnel not successfull";
    return false;
  }
  logger.debug() << "Reset Split tunnel successfull";
  return true;
}

// static
WindowsSplitTunnel::DRIVER_STATE WindowsSplitTunnel::getState(HANDLE driverIO) {
  if (driverIO == INVALID_HANDLE_VALUE) {
    logger.debug() << "Can't query State from non Opened Driver";
    return STATE_UNKNOWN;
  }
  DWORD bytesReturned;
  SIZE_T outBuffer;
  bool ok = DeviceIoControl(driverIO, IOCTL_GET_STATE, nullptr, 0, &outBuffer,
                            sizeof(outBuffer), &bytesReturned, nullptr);
  if (!ok) {
    WindowsUtils::windowsLog("getState response failure");
    return STATE_UNKNOWN;
  }
  if (bytesReturned == 0) {
    WindowsUtils::windowsLog("getState response is empty");
    return STATE_UNKNOWN;
  }
  return static_cast<WindowsSplitTunnel::DRIVER_STATE>(outBuffer);
}
WindowsSplitTunnel::DRIVER_STATE WindowsSplitTunnel::getState() {
  return getState(m_driver);
}

std::vector<uint8_t> WindowsSplitTunnel::generateAppConfiguration(
    const QStringList& appPaths) {
  // Step 1: Calculate how much size the buffer will need
  size_t cummulated_string_size = 0;
  QStringList dosPaths;
  for (auto const& path : appPaths) {
    const QString normalizedPath = normalizeExecutablePath(path);
    auto dosPath = convertPath(normalizedPath);
    if (dosPath.isEmpty()) {
      logger.error() << "Rejecting split-tunnel app path with empty device "
                        "conversion:"
                     << normalizedPath;
      continue;
    }
    const auto stringLength =
        dosPath.toStdWString().size() * sizeof(wchar_t);
    if (stringLength > std::numeric_limits<USHORT>::max()) {
      logger.warning()
          << "Skipping split-tunnel app path with oversized device path"
          << dosPath;
      continue;
    }
    dosPaths.append(dosPath);
    cummulated_string_size += stringLength;
    logger.debug() << dosPath;
  }
  if (dosPaths.isEmpty()) {
    return {};
  }
  size_t bufferSize = sizeof(CONFIGURATION_HEADER) +
                      (sizeof(CONFIGURATION_ENTRY) * dosPaths.size()) +
                      cummulated_string_size;
  std::vector<uint8_t> outBuffer(bufferSize);

  auto header = (CONFIGURATION_HEADER*)&outBuffer[0];
  auto entry = (CONFIGURATION_ENTRY*)(header + 1);

  auto stringDest = &outBuffer[0] + sizeof(CONFIGURATION_HEADER) +
                    (sizeof(CONFIGURATION_ENTRY) * dosPaths.size());

  SIZE_T stringOffset = 0;

  for (const QString& path : dosPaths) {
    auto wstr = path.toStdWString();
    auto cstr = wstr.c_str();
    auto stringLength = wstr.size() * sizeof(wchar_t);

    entry->ImageNameLength = (USHORT)stringLength;
    entry->ImageNameOffset = stringOffset;

    memcpy(stringDest, cstr, stringLength);

    ++entry;
    stringDest += stringLength;
    stringOffset += stringLength;
  }

  header->NumEntries = dosPaths.size();
  header->TotalLength = bufferSize;

  return outBuffer;
}

std::vector<std::byte> WindowsSplitTunnel::generateIPConfiguration(
    int inetAdapterIndex, int vpnAdapterIndex) {
  std::vector<std::byte> out(sizeof(IP_ADDRESSES_CONFIG));

  auto config = reinterpret_cast<IP_ADDRESSES_CONFIG*>(&out[0]);

  if (vpnAdapterIndex == 0) {
    vpnAdapterIndex = WindowsCommons::VPNAdapterIndex();
  }
  // Always the VPN
  if (!getAddress(vpnAdapterIndex, &config->TunnelIpv4,
                  &config->TunnelIpv6)) {
    return {};
  }
  // 2nd best route is usually the internet adapter
  if (!getAddress(inetAdapterIndex, &config->InternetIpv4,
                  &config->InternetIpv6)) {
    return {};
  };
  return out;
}
bool WindowsSplitTunnel::getAddress(int adapterIndex, IN_ADDR* out_ipv4,
                                    IN6_ADDR* out_ipv6) {
  QNetworkInterface target =
      QNetworkInterface::interfaceFromIndex(adapterIndex);
  logger.debug() << "Getting adapter info for:" << target.humanReadableName();

  auto get = [&target](QAbstractSocket::NetworkLayerProtocol protocol) {
    for (auto address : target.addressEntries()) {
      if (address.ip().protocol() != protocol) {
        continue;
      }
      return address.ip().toString().toStdWString();
    }
    return std::wstring{};
  };
  auto ipv4 = get(QAbstractSocket::IPv4Protocol);
  auto ipv6 = get(QAbstractSocket::IPv6Protocol);

  if (InetPtonW(AF_INET, ipv4.c_str(), out_ipv4) != 1) {
    logger.debug() << "Ipv4 Conversation error" << WSAGetLastError();
    return false;
  }
  if (ipv6.empty()) {
    std::memset(out_ipv6, 0x00, sizeof(IN6_ADDR));
    return true;
  }
  if (InetPtonW(AF_INET6, ipv6.c_str(), out_ipv6) != 1) {
    logger.debug() << "Ipv6 Conversation error" << WSAGetLastError();
  }
  return true;
}

std::vector<uint8_t> WindowsSplitTunnel::generateProcessBlob() {
  // Get a Snapshot of all processes that are running:
  HANDLE snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snapshot_handle == INVALID_HANDLE_VALUE) {
    WindowsUtils::windowsLog("Creating Process snapshot failed");
    return std::vector<uint8_t>(0);
  }
  auto cleanup = qScopeGuard([&] { CloseHandle(snapshot_handle); });
  // Load the First Entry, later iterate over all
  PROCESSENTRY32W currentProcess;
  currentProcess.dwSize = sizeof(PROCESSENTRY32W);

  if (FALSE == (Process32First(snapshot_handle, &currentProcess))) {
    WindowsUtils::windowsLog("Cant read first entry");
  }

  QMap<DWORD, ProcessInfo> processes;

  do {
    auto process_handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                                      currentProcess.th32ProcessID);

    if (process_handle == nullptr) {
      continue;
    }
    ProcessInfo info = getProcessInfo(process_handle, currentProcess);
    processes.insert(info.ProcessId, info);
    CloseHandle(process_handle);

  } while (FALSE != (Process32NextW(snapshot_handle, &currentProcess)));

  auto process_list = processes.values();
  if (process_list.isEmpty()) {
    logger.debug() << "Process Snapshot list was empty";
    return std::vector<uint8_t>(0);
  }

  logger.debug() << "Reading Processes NUM: " << process_list.size();
  // Determine the Size of the outBuffer:
  size_t totalStringSize = 0;

  for (const auto& process : process_list) {
    totalStringSize += (process.DevicePath.size() * sizeof(wchar_t));
  }
  auto bufferSize = sizeof(PROCESS_DISCOVERY_HEADER) +
                    (sizeof(PROCESS_DISCOVERY_ENTRY) * processes.size()) +
                    totalStringSize;

  std::vector<uint8_t> out(bufferSize);

  auto header = reinterpret_cast<PROCESS_DISCOVERY_HEADER*>(&out[0]);
  auto entry = reinterpret_cast<PROCESS_DISCOVERY_ENTRY*>(header + 1);
  auto stringBuffer = reinterpret_cast<uint8_t*>(entry + processes.size());

  SIZE_T currentStringOffset = 0;

  for (const auto& process : process_list) {
    // Wierd DWORD -> Handle Pointer magic.
    entry->ProcessId = (HANDLE)((size_t)process.ProcessId);
    entry->ParentProcessId = (HANDLE)((size_t)process.ParentProcessId);

    if (process.DevicePath.empty()) {
      entry->ImageNameOffset = 0;
      entry->ImageNameLength = 0;
    } else {
      const auto imageNameLength = process.DevicePath.size() * sizeof(wchar_t);

      entry->ImageNameOffset = currentStringOffset;
      entry->ImageNameLength = static_cast<USHORT>(imageNameLength);

      RtlCopyMemory(stringBuffer + currentStringOffset, &process.DevicePath[0],
                    imageNameLength);

      currentStringOffset += imageNameLength;
    }
    ++entry;
  }

  header->NumEntries = processes.size();
  header->TotalLength = bufferSize;

  return out;
}

// static
SC_HANDLE WindowsSplitTunnel::installDriver() {
  LPCWSTR displayName = L"Amnezia Split Tunnel Service";
  QFileInfo driver(qApp->applicationDirPath() + "/" + DRIVER_FILENAME);
  if (!driver.exists()) {
    logger.error() << "Split Tunnel Driver File not found "
                   << driver.absoluteFilePath();
    return (SC_HANDLE)INVALID_HANDLE_VALUE;
  }
  auto path = driver.absolutePath() + "/" + DRIVER_FILENAME;
  auto binPath = (const wchar_t*)path.utf16();
  auto scm_rights = SC_MANAGER_ALL_ACCESS;
  auto serviceManager = OpenSCManager(nullptr,  // local computer
                                      nullptr,  // servicesActive database
                                      scm_rights);
  auto service = CreateService(
      serviceManager, DRIVER_SERVICE_NAME, displayName, SERVICE_ALL_ACCESS,
      SERVICE_KERNEL_DRIVER, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, binPath,
      nullptr, nullptr, nullptr, nullptr, nullptr);
  CloseServiceHandle(serviceManager);
  return service;
}
// static
bool WindowsSplitTunnel::uninstallDriver() {
  SC_HANDLE serviceManager =
      OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
  if (serviceManager == nullptr) {
    WindowsUtils::windowsLog("OpenSCManager failed while removing driver");
    return false;
  }
  auto closeManager =
      qScopeGuard([&] { CloseServiceHandle(serviceManager); });

  SC_HANDLE serviceHandle =
      OpenService(serviceManager, DRIVER_SERVICE_NAME, DELETE);
  if (serviceHandle == nullptr) {
    const DWORD error = GetLastError();
    return error == ERROR_SERVICE_DOES_NOT_EXIST;
  }
  auto closeService =
      qScopeGuard([&] { CloseServiceHandle(serviceHandle); });

  if (DeleteService(serviceHandle)) {
    logger.debug() << "Split Tunnel Driver Removed";
    return true;
  }
  const DWORD error = GetLastError();
  if (error == ERROR_SERVICE_MARKED_FOR_DELETE) {
    return true;
  }
  WindowsUtils::windowsLog("DeleteService failed while removing driver");
  return false;
}
// static
bool WindowsSplitTunnel::isInstalled() {
  // Driver ownership is established by our exact SCM service name. The device
  // symlink is shared with Mullvad and must never be treated as proof that the
  // Amnezia-owned driver is installed.
  SC_HANDLE serviceManager =
      OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
  if (serviceManager == nullptr) {
    WindowsUtils::windowsLog("Unable to query split-tunnel driver service");
    // Unknown must not be treated as safely absent by firewall migration or
    // uninstall cleanup.
    return true;
  }
  auto closeManager =
      qScopeGuard([&] { CloseServiceHandle(serviceManager); });
  SC_HANDLE serviceHandle = OpenService(
      serviceManager, DRIVER_SERVICE_NAME, SERVICE_QUERY_STATUS);
  if (serviceHandle != nullptr) {
    CloseServiceHandle(serviceHandle);
    return true;
  }
  const DWORD error = GetLastError();
  if (error != ERROR_SERVICE_DOES_NOT_EXIST) {
    WindowsUtils::windowsLog("Unable to inspect split-tunnel driver service");
    return true;
  }
  return false;
}

QString WindowsSplitTunnel::convertPath(const QString& path) {
  const QString normalizedPath = normalizeExecutablePath(path);
  if (normalizedPath.isEmpty()) {
    logger.error() << "Empty executable path for DOS device conversion";
    return "";
  }
  auto parts = normalizedPath.split("\\", Qt::SkipEmptyParts);
  if (parts.isEmpty()) {
    logger.error() << "Invalid executable path for DOS device conversion:"
                   << normalizedPath;
    return "";
  }
  QString driveLetter = parts.takeFirst();
  if (!driveLetter.contains(":") || parts.size() == 0) {
    // device should contain : for e.g C:
    logger.error() << "Invalid executable path for DOS device conversion:"
                   << normalizedPath;
    return "";
  }
  QByteArray buffer(2048 * sizeof(wchar_t), 0);
  DWORD ok = 0;
  DWORD err = ERROR_SUCCESS;
  for (int attempt = 0; attempt < 4; ++attempt) {
    ok = QueryDosDeviceW(reinterpret_cast<LPCWSTR>(driveLetter.utf16()),
                         reinterpret_cast<LPWSTR>(buffer.data()),
                         buffer.size() / sizeof(wchar_t));
    if (ok != 0) {
      break;
    }
    err = GetLastError();
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
      buffer.resize(buffer.size() * 2);
      buffer.fill(0);
      continue;
    }
    WindowsUtils::windowsLog("Err fetching dos path");
    logger.error() << "QueryDosDeviceW failed for" << driveLetter
                   << "error:" << err;
    return "";
  }
  if (ok == 0) {
    WindowsUtils::windowsLog("Err fetching dos path");
    logger.error() << "QueryDosDeviceW failed after buffer growth for"
                   << driveLetter << "error:" << err;
    return "";
  }
  QString deviceName;
  deviceName = QString::fromWCharArray((wchar_t*)buffer.data());
  parts.prepend(deviceName);

  return parts.join("\\");
}

// static
bool WindowsSplitTunnel::detectConflict() {
  auto serviceManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
  if (serviceManager == nullptr) {
    WindowsUtils::windowsLog("Unable to inspect split-tunnel services");
    return true;
  }
  auto cleanup = qScopeGuard([&] { CloseServiceHandle(serviceManager); });
  // Query for Mullvad Service.
  auto serviceHandle =
      OpenService(serviceManager, MV_SERVICE_NAME, SERVICE_QUERY_STATUS);
  if (serviceHandle != nullptr) {
    CloseServiceHandle(serviceHandle);
    logger.warning() << "Mullvad detected - disabling split tunnel";
    // Mullvad is installed, so we would certainly break things.
    return true;
  }
  DWORD error = GetLastError();
  if (error != ERROR_SERVICE_DOES_NOT_EXIST) {
    WindowsUtils::windowsLog("Unable to inspect Mullvad service");
    return true;
  }

  serviceHandle = OpenService(serviceManager, DRIVER_SERVICE_NAME,
                              SERVICE_QUERY_STATUS);
  if (serviceHandle != nullptr) {
    CloseServiceHandle(serviceHandle);
    return false;
  }
  error = GetLastError();
  if (error != ERROR_SERVICE_DOES_NOT_EXIST) {
    WindowsUtils::windowsLog("Unable to inspect Amnezia split-tunnel service");
    return true;
  }

  auto symlink = QFileInfo(QString::fromWCharArray(DRIVER_SYMLINK));
  if (!symlink.exists()) {
    // The driver is not loaded / installed.. MV is not installed, all good!
    logger.info() << "No Split-Tunnel Conflict detected, continue.";
    return false;
  }
  // A live shared device without either known SCM service is foreign/unknown.
  return true;
}

bool WindowsSplitTunnel::isRunning() { return getState() == STATE_RUNNING; }
QString WindowsSplitTunnel::stateString() {
  switch (getState()) {
    case STATE_UNKNOWN:
      return "STATE_UNKNOWN";
    case STATE_NONE:
      return "STATE_NONE";
    case STATE_STARTED:
      return "STATE_STARTED";
    case STATE_INITIALIZED:
      return "STATE_INITIALIZED";
    case STATE_READY:
      return "STATE_READY";
    case STATE_RUNNING:
      return "STATE_RUNNING";
    case STATE_ZOMBIE:
      return "STATE_ZOMBIE";
      break;
  }
  return {};
}
