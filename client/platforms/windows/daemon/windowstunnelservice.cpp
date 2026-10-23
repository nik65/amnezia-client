/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "windowstunnelservice.h"

#include <Windows.h>

#include <functional>

#include <QDateTime>
#include <QElapsedTimer>
#include <QScopeGuard>

#include "leakdetector.h"
#include "logger.h"
#include "platforms/windows/windowscommons.h"
#include "platforms/windows/windowsutils.h"
#include "windowsdaemon.h"
#include "windowstunnelservicepolicy.h"

#define TUNNEL_NAMED_PIPE \
  "\\\\."                 \
  "\\pipe\\ProtectedPrefix\\Administrators\\AmneziaWG\\AmneziaVPN"

constexpr uint32_t WINDOWS_TUNNEL_MONITOR_TIMEOUT_MSEC = 2000;
constexpr qsizetype WINDOWS_TUNNEL_UAPI_MAX_REPLY_BYTES = 64 * 1024;
constexpr qint64 WINDOWS_TUNNEL_START_RETRY_BUDGET_MSEC = 61 * 1000;
constexpr unsigned WINDOWS_TUNNEL_START_RETRY_BACKOFF_MSEC = 250;

namespace {
Logger logger("WindowsTunnelService");
}  // namespace

using ServiceCancellation = std::function<bool()>;
using ServiceDelay = std::function<void(unsigned)>;

static bool stopAndDeleteTunnelService(
    SC_HANDLE service, const ServiceCancellation& cancelled = {},
    const ServiceDelay& delay = {});
static bool waitForServiceStatus(SC_HANDLE service, DWORD expectedStatus,
                                 const ServiceCancellation& cancelled = {},
                                 const ServiceDelay& delay = {});

WindowsTunnelService::WindowsTunnelService(QObject* parent) : QObject(parent) {
  MZ_COUNT_CTOR(WindowsTunnelService);
  logger.debug() << "WindowsTunnelService created.";

  m_scm = OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
  if (m_scm == nullptr) {
    WindowsUtils::windowsLog("Failed to open SCManager");
  }

  // Is the service already running? Terminate it.
  SC_HANDLE service =
      OpenService((SC_HANDLE)m_scm, TUNNEL_SERVICE_NAME, SERVICE_ALL_ACCESS);
  if (service != nullptr) {
    logger.info() << "Tunnel already exists. Terminating it.";
    stopAndDeleteTunnelService(service);
    CloseServiceHandle(service);
  }

  connect(&m_timer, &QTimer::timeout, this, &WindowsTunnelService::timeout);
}

WindowsTunnelService::~WindowsTunnelService() {
  MZ_COUNT_DTOR(WindowsTunnelService);
  stop();
  if (m_scm != nullptr) {
    CloseServiceHandle((SC_HANDLE)m_scm);
  }
}

bool WindowsTunnelService::stop() {
  bool stopped = true;
  SC_HANDLE service = (SC_HANDLE)m_service;
  if (service) {
    stopped = stopAndDeleteTunnelService(service);
    CloseServiceHandle(service);
    m_service = nullptr;
  }

  m_timer.stop();

  if (m_logworker) {
    m_logthread.quit();
    m_logthread.wait();
    m_logworker = nullptr;
  }
  return stopped;
}

bool WindowsTunnelService::isRunning() {
  if (m_service == nullptr) {
    return false;
  }

  SERVICE_STATUS status;
  if (!QueryServiceStatus((SC_HANDLE)m_service, &status)) {
    return false;
  }

  return status.dwCurrentState == SERVICE_RUNNING;
}

void WindowsTunnelService::timeout() {
  // Ignore a queued monitor callback after an explicit stop.
  if (!m_timer.isActive()) {
    return;
  }

  const auto reportBackendFailure = [this] {
    // Keep cleanup retries alive, but avoid a two-second failure/log storm.
    // Schedule before emit: a synchronous receiver may stop, restart or delete us.
    const int interval = m_timer.interval();
    m_timer.setInterval(interval < 5000 ? 5000 : interval < 15000 ? 15000 : 60000);
    emit backendFailure();
  };

  if (m_service == nullptr) {
    logger.error() << "The service doesn't exist";
    reportBackendFailure();
    return;
  }

  SERVICE_STATUS status;
  if (!QueryServiceStatus((SC_HANDLE)m_service, &status)) {
    WindowsUtils::windowsLog("Failed to retrieve the service status");
    reportBackendFailure();
    return;
  }

  if (status.dwCurrentState == SERVICE_RUNNING) {
    // A recovered service starts a fresh normal monitor episode.
    if (m_timer.interval() != WINDOWS_TUNNEL_MONITOR_TIMEOUT_MSEC) {
      m_timer.setInterval(WINDOWS_TUNNEL_MONITOR_TIMEOUT_MSEC);
    }
    return;
  }

  logger.debug() << "The service is not active";
  reportBackendFailure();
}

bool WindowsTunnelService::start(const QString& configData) {
  logger.debug() << "Starting the tunnel service";

  m_logworker = new WindowsTunnelLogger([] { return WindowsCommons::tunnelLogFile(); });
  m_logworker->moveToThread(&m_logthread);
  connect(&m_logthread, &QThread::finished, m_logworker, &QObject::deleteLater);
  m_logthread.start();

  SC_HANDLE scm = (SC_HANDLE)m_scm;
  SC_HANDLE service = nullptr;
  auto guard = qScopeGuard([&] {
    if (service) {
      CloseServiceHandle(service);
    }
    m_logthread.quit();
    m_logthread.wait();
    delete m_logworker;
    m_logworker = nullptr;
  });

  QElapsedTimer startTimer;
  startTimer.start();
  const auto cancelled = [&] {
    return QThread::currentThread()->isInterruptionRequested() ||
           startTimer.elapsed() >= WINDOWS_TUNNEL_START_RETRY_BUDGET_MSEC;
  };
  const auto boundedSleep = [&](unsigned requested) {
    const qint64 remaining =
        WINDOWS_TUNNEL_START_RETRY_BUDGET_MSEC - startTimer.elapsed();
    if (remaining > 0) {
      QThread::msleep(static_cast<unsigned long>(
          qMin<qint64>(requested, remaining)));
    }
  };

  // Let's see if we have to delete a previous instance.
  service = OpenService(scm, TUNNEL_SERVICE_NAME, SERVICE_ALL_ACCESS);
  if (service) {
    logger.debug() << "An existing service has been detected. Let's close it.";
    if (!stopAndDeleteTunnelService(service, cancelled, boundedSleep)) {
      return false;
    }
    CloseServiceHandle(service);
    service = nullptr;
  }

  QString serviceCmdline;
  {
    QTextStream out(&serviceCmdline);
    out << "\"" << qApp->applicationFilePath() << "\" tunneldaemon \""
        << configData << "\"";
  }

  logger.debug() << "Service:" << qApp->applicationFilePath();

  SERVICE_DESCRIPTION sd = {
      (wchar_t*)L"Manages the Amnezia VPN tunnel connection"};
  SERVICE_SID_INFO ssi;
  ssi.dwServiceSidType = SERVICE_SID_TYPE_UNRESTRICTED;
  SERVICE_STATUS lastStatus{};
  bool lastStatusAvailable = false;
  SERVICE_STATUS firstFailureStatus{};
  bool firstFailureStatusAvailable = false;

  const auto attempt = [&]() -> amnezia::windowsTunnel::StartAttempt {
    lastStatusAvailable = false;
    if (cancelled()) {
      return {false, false, ERROR_TIMEOUT, 0};
    }

    service = CreateService(scm, TUNNEL_SERVICE_NAME, L"Amnezia VPN (tunnel)",
                            SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                            SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
                            (const wchar_t*)serviceCmdline.utf16(), nullptr, 0,
                            TEXT("Nsi\0TcpIp\0"), nullptr, nullptr);
    if (!service) {
      const DWORD error = GetLastError();
      WindowsUtils::windowsLog("Failed to create the tunnel service");
      return {false, false, error, 0};
    }

    if (!ChangeServiceConfig2(service, SERVICE_CONFIG_DESCRIPTION, &sd)) {
      const DWORD error = GetLastError();
      WindowsUtils::windowsLog(
          "Failed to set the description to the tunnel service");
      return {false, true, error, 0};
    }

    if (!ChangeServiceConfig2(service, SERVICE_CONFIG_SERVICE_SID_INFO,
                              &ssi)) {
      const DWORD error = GetLastError();
      WindowsUtils::windowsLog("Failed to set the SID to the tunnel service");
      return {false, true, error, 0};
    }

    if (!StartService(service, 0, nullptr)) {
      const DWORD error = GetLastError();
      WindowsUtils::windowsLog("Failed to start the service");
      return {false, true, error, 0};
    }

    if (waitForServiceStatus(service, SERVICE_RUNNING, cancelled,
                             boundedSleep)) {
      logger.debug() << "The tunnel service is up and running";
      return {true, true, 0, 0};
    }

    logger.error() << "Failed to run the tunnel service";
    SERVICE_STATUS status{};
    if (!QueryServiceStatus(service, &status)) {
      const DWORD error = GetLastError();
      WindowsUtils::windowsLog("Failed to retrieve the service status");
      return {false, true, error, 0};
    }

    lastStatus = status;
    lastStatusAvailable = true;
    if (!firstFailureStatusAvailable) {
      firstFailureStatus = status;
      firstFailureStatusAvailable = true;
    }
    logger.debug() << "The tunnel service exited with status:"
                   << status.dwWin32ExitCode << "-"
                   << exitCodeToFailure(&status);
    return {false, true, status.dwWin32ExitCode,
            status.dwServiceSpecificExitCode};
  };

  const auto cleanup = [&]() {
    if (service == nullptr) {
      return true;
    }
    const bool cleaned =
        stopAndDeleteTunnelService(service, cancelled, boundedSleep);
    CloseServiceHandle(service);
    service = nullptr;
    if (!cleaned) {
      logger.error() << "Failed to clean up the owned tunnel service";
    }
    return cleaned;
  };

  const auto lifecycle = amnezia::windowsTunnel::runStartLifecycle(
      attempt, cleanup,
      [&] {
        logger.warning()
            << "Retrying WinTun device creation after owned service cleanup";
        boundedSleep(WINDOWS_TUNNEL_START_RETRY_BACKOFF_MSEC);
      },
      cancelled);

  if (lifecycle.started) {
    guard.dismiss();
    m_service = service;
    m_timer.start(WINDOWS_TUNNEL_MONITOR_TIMEOUT_MSEC);
    return true;
  }

  if (firstFailureStatusAvailable || lastStatusAvailable) {
    const SERVICE_STATUS& diagnosticStatus =
        firstFailureStatusAvailable ? firstFailureStatus : lastStatus;
    logger.debug() << "The tunnel service diagnostic status:"
                   << diagnosticStatus.dwWin32ExitCode << "-"
                   << exitCodeToFailure(&diagnosticStatus);
  }
  emit backendFailure();
  return false;
}

static bool stopAndDeleteTunnelService(
    SC_HANDLE service, const ServiceCancellation& cancelled,
    const ServiceDelay& delay) {
  SERVICE_STATUS status;
  if (!QueryServiceStatus(service, &status)) {
    WindowsUtils::windowsLog("Failed to retrieve the service status");
    return false;
  }

  logger.debug() << "The current service is stopped:"
                 << (status.dwCurrentState == SERVICE_STOPPED);

  if (status.dwCurrentState != SERVICE_STOPPED) {
    if (cancelled && cancelled()) {
      logger.warning() << "Service cleanup cancelled before stop";
      return false;
    }
    logger.debug() << "The service is not stopped yet.";
    if (!ControlService(service, SERVICE_CONTROL_STOP, &status)) {
      WindowsUtils::windowsLog("Failed to control the service");
      return false;
    }

    if (!waitForServiceStatus(service, SERVICE_STOPPED, cancelled, delay)) {
      logger.error() << "Unable to stop the service";
      return false;
    }
  }

  logger.debug() << "Proceeding with the deletion";

  if (!DeleteService(service)) {
    WindowsUtils::windowsLog("Failed to delete the service");
    return false;
  }

  return true;
}

QString WindowsTunnelService::uapiCommand(const QString& command) {
  // Create a pipe to the tunnel service.
  LPTSTR tunnelName = (LPTSTR)TEXT(TUNNEL_NAMED_PIPE);
  HANDLE pipe = CreateFile(tunnelName, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                           OPEN_EXISTING, 0, nullptr);
  if (pipe == INVALID_HANDLE_VALUE) {
    return QString();
  }

  auto guard = qScopeGuard([&] { CloseHandle(pipe); });
  if (!WaitNamedPipe(tunnelName, 1000)) {
    WindowsUtils::windowsLog("Failed to wait for named pipes");
    return QString();
  }

  DWORD mode = PIPE_READMODE_BYTE;
  if (!SetNamedPipeHandleState(pipe, &mode, nullptr, nullptr)) {
    WindowsUtils::windowsLog("Failed to set the read-mode on pipe");
    return QString();
  }

  // Write the UAPI command into the pipe.
  QByteArray message = command.toLocal8Bit();
  while (!message.endsWith("\n\n")) {
    message.append('\n');
  }
  DWORD writtenTotal = 0;
  while (writtenTotal < static_cast<DWORD>(message.size())) {
    DWORD written = 0;
    const DWORD remaining = static_cast<DWORD>(message.size()) - writtenTotal;
    if (!WriteFile(pipe, message.constData() + writtenTotal, remaining,
                   &written, nullptr) || written == 0 || written > remaining) {
      WindowsUtils::windowsLog("Failed to write the complete UAPI request");
      return QString();
    }
    writtenTotal += written;
  }

  // Receive the response from the pipe.
  QByteArray reply;
  while (true) {
    const qsizetype frameEnd = reply.indexOf("\n\n");
    if (frameEnd >= 0) {
      if (frameEnd + 2 != reply.size()) {
        WindowsUtils::windowsLog("Unexpected data after UAPI response frame");
        return QString();
      }
      return QString::fromUtf8(reply.left(frameEnd));
    }

    char buffer[512];
    DWORD read = 0;
    if (!ReadFile(pipe, buffer, sizeof(buffer), &read, nullptr)) {
      WindowsUtils::windowsLog("Failed to read the complete UAPI response");
      return QString();
    }
    if (read == 0 || read > WINDOWS_TUNNEL_UAPI_MAX_REPLY_BYTES ||
        reply.size() > WINDOWS_TUNNEL_UAPI_MAX_REPLY_BYTES - read) {
      WindowsUtils::windowsLog("Invalid or oversized UAPI response");
      return QString();
    }

    reply.append(buffer, read);
  }
  return QString();
}

// static
static bool waitForServiceStatus(SC_HANDLE service, DWORD expectedStatus,
                                 const ServiceCancellation& cancelled,
                                 const ServiceDelay& delay) {
  int tries = 0;
  while (tries < 30) {
    SERVICE_STATUS status;
    if (!QueryServiceStatus(service, &status)) {
      WindowsUtils::windowsLog("Failed to retrieve the service status");
      return false;
    }

    if (status.dwCurrentState == expectedStatus) {
      return true;
    }

    if (cancelled && cancelled()) {
      logger.warning() << "Service status wait cancelled";
      return false;
    }

    logger.warning() << "The service is not in the right status yet.";

    if (delay) {
      delay(1000);
    } else {
      Sleep(1000);
    }
    ++tries;
  }

  return false;
}

// static
QString WindowsTunnelService::exitCodeToFailure(const void* status) {
  const SERVICE_STATUS* st = static_cast<const SERVICE_STATUS*>(status);
  if (st->dwWin32ExitCode != ERROR_SERVICE_SPECIFIC_ERROR) {
    return WindowsUtils::getErrorMessage(st->dwWin32ExitCode);
  }

  // The order of this error code is taken from wireguard.
  switch (st->dwServiceSpecificExitCode) {
    case 0:
      return "No error";
    case 1:
      return "Error when opening the ringlogger log file";
    case 2:
      return "Error while loading the WireGuard configuration file from "
             "path.";
    case 3:
      return "Error while creating a WinTun device.";
    case 4:
      return "Error while listening on a named pipe.";
    case 5:
      return "Error while resolving DNS hostname endpoints.";
    case 6:
      return "Error while manipulating firewall rules.";
    case 7:
      return "Error while setting the device configuration.";
    case 8:
      return "Error while binding sockets to default routes.";
    case 9:
      return "Unable to set interface addresses, routes, dns, and/or "
             "interface settings.";
    case 10:
      return "Error while determining current executable path.";
    case 11:
      return "Error while opening the NUL file.";
    case 12:
      return "Error while attempting to track tunnels.";
    case 13:
      return "Error while attempting to enumerate current sessions.";
    case 14:
      return "Error while dropping privileges.";
    case 15:
      return "Windows internal error.";
    default:
      return QString("Unknown error (%1)").arg(st->dwServiceSpecificExitCode);
  }
}
