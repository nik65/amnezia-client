/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "windowsnetworkwatcher.h"

#include <QNetworkInformation>
#include <QScopeGuard>

#include "leakdetector.h"
#include "logger.h"
#include "networkwatcherimpl.h"
#include "platforms/windows/windowsutils.h"

#pragma comment(lib, "Wlanapi.lib")
#pragma comment(lib, "windowsapp.lib")

namespace {
Logger logger("WindowsNetworkWatcher");
}

WindowsNetworkWatcher::WindowsNetworkWatcher(QObject* parent)
    : NetworkWatcherImpl(parent) {
  MZ_COUNT_CTOR(WindowsNetworkWatcher);
}

WindowsNetworkWatcher::~WindowsNetworkWatcher() {
  MZ_COUNT_DTOR(WindowsNetworkWatcher);

  if (m_wlanHandle) {
    WlanRegisterNotification(m_wlanHandle, WLAN_NOTIFICATION_SOURCE_NONE,
                             true, nullptr, nullptr, nullptr, nullptr);
    WlanCloseHandle(m_wlanHandle, nullptr);
  }
  if (m_powerWindow) DestroyWindow(m_powerWindow);
}

LRESULT WindowsNetworkWatcher::PowerWndProcCallback(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
  auto obj = reinterpret_cast<WindowsNetworkWatcher*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
  if (!obj){
    logger.debug() << "obj not casted";
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
  }
  switch (uMsg) {
  case WM_POWERBROADCAST:
    if (wParam == PBT_APMRESUMESUSPEND && obj->isActive()) {
        emit obj->wakeup();
    }
    break;
  default:
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
  }
  return 0;
}

void WindowsNetworkWatcher::initialize() {
  if (m_initialized) return;
  m_initialized = true;
  logger.debug() << "initialize";


  DWORD negotiatedVersion;
  const DWORD openResult = WlanOpenHandle(2, nullptr, &negotiatedVersion, &m_wlanHandle);
  if (openResult != ERROR_SUCCESS) {
    logger.error() << "Failed to open the WLAN handle" << "errorCode" << openResult
                   << WindowsUtils::getErrorMessage(openResult);
    initializeReachabilityFallback();
  } else {
    DWORD prefNotifSource;
    const DWORD notificationResult = WlanRegisterNotification(m_wlanHandle, WLAN_NOTIFICATION_SOURCE_MSM,
                               true /* ignore duplicates */,
                               (WLAN_NOTIFICATION_CALLBACK)wlanCallback, this,
                               nullptr, &prefNotifSource);
    if (notificationResult != ERROR_SUCCESS) {
      logger.warning() << "WLAN notifications unavailable; enabling network reachability fallback"
                       << "errorCode" << notificationResult
                       << WindowsUtils::getErrorMessage(notificationResult);
      initializeReachabilityFallback();
    }
  }

  // Power notifications are independent of optional WLAN permissions.
  const wchar_t* className = L"PowerMonitorClass";
  WNDCLASS wc = { 0 };
  wc.lpfnWndProc = &WindowsNetworkWatcher::PowerWndProcCallback;
  wc.hInstance = GetModuleHandle(NULL);
  wc.lpszClassName = className;
  wc.cbWndExtra = sizeof(WindowsNetworkWatcher*);

  if (!RegisterClass(&wc) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
    logger.debug() << "Failed to register window class in createPowerMonitorWindow.";
    return;
  }

  HWND hwnd = CreateWindowEx(0, className, L"Power Monitor", 0, 0, 0, 0, 0, NULL, NULL, GetModuleHandle(NULL), static_cast<LPVOID>(this));
  if (!hwnd) {
    logger.debug() << "Failed to create window in createPowerMonitorWindow.";
    return;
  }
  SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(this));
  m_powerWindow = hwnd;

  logger.debug() << "callback registered";
}

void WindowsNetworkWatcher::initializeReachabilityFallback() {
  if (!QNetworkInformation::loadDefaultBackend() || !QNetworkInformation::instance()) {
    logger.error() << "Network reachability fallback unavailable";
    return;
  }
  auto* information = QNetworkInformation::instance();
  // Global reachability can change because our own VPN was rebuilt. It is
  // diagnostic evidence, not permission to restart the tunnel in a loop.
  connect(information, &QNetworkInformation::reachabilityChanged, this,
          [](QNetworkInformation::Reachability reachability) {
    logger.debug() << "Network reachability changed" << static_cast<uint64_t>(reachability);
  });
  if (information->supports(QNetworkInformation::Feature::TransportMedium)) {
    m_lastTransportMedium = information->transportMedium();
    connect(information, &QNetworkInformation::transportMediumChanged, this,
            [this](QNetworkInformation::TransportMedium medium) {
      using Medium = QNetworkInformation::TransportMedium;
      const bool changed = medium != m_lastTransportMedium;
      const bool knownPrevious = m_lastTransportMedium != Medium::Unknown;
      m_lastTransportMedium = medium;
      if (changed && knownPrevious && medium != Medium::Unknown
          && isActive()) {
        emit networkChanged(QStringLiteral("transport-medium-changed"));
      }
    });
  } else {
    logger.warning() << "Network fallback does not support transport change detection; power monitoring remains active";
  }
  logger.info() << "Network reachability fallback active";
}

// static
void WindowsNetworkWatcher::wlanCallback(PWLAN_NOTIFICATION_DATA data,
                                         PVOID context) {
  logger.debug() << "Callback";

  WindowsNetworkWatcher* that = static_cast<WindowsNetworkWatcher*>(context);
  Q_ASSERT(that);

  // The OS invokes this callback outside the QObject thread. Only the public
  // header fields are needed; pData belongs to the callback and is not retained.
  WLAN_NOTIFICATION_DATA snapshot = *data;
  snapshot.pData = nullptr;
  snapshot.dwDataSize = 0;
  QMetaObject::invokeMethod(that, [that, snapshot]() mutable {
    that->processWlan(&snapshot);
  }, Qt::QueuedConnection);
}

void WindowsNetworkWatcher::processWlan(PWLAN_NOTIFICATION_DATA data) {
  logger.debug() << "Processing wlan data";

  if (!isActive()) {
    logger.debug() << "The watcher is off";
    return;
  }

  if (data->NotificationSource != WLAN_NOTIFICATION_SOURCE_MSM) {
    logger.debug() << "The wlan source is not MSM";
    return;
  }

  if (data->NotificationCode != wlan_notification_msm_connected) {
    logger.debug() << "Wlan unprocessed code: " << data->NotificationCode;
    return;
  }

  PWLAN_CONNECTION_ATTRIBUTES connectionInfo = nullptr;
  DWORD connectionInfoSize = sizeof(WLAN_CONNECTION_ATTRIBUTES);
  WLAN_OPCODE_VALUE_TYPE opCode = wlan_opcode_value_type_invalid;

  DWORD result = WlanQueryInterface(
      m_wlanHandle, &data->InterfaceGuid, wlan_intf_opcode_current_connection,
      nullptr, &connectionInfoSize, (PVOID*)&connectionInfo, &opCode);
  if (result != ERROR_SUCCESS) {
    logger.warning() << "Failed to query the WLAN interface" << "errorCode" << result
                     << WindowsUtils::getErrorMessage(result);
    return;
  }

  auto guard = qScopeGuard([&] { WlanFreeMemory(connectionInfo); });

  QString bssid;
  for (size_t i = 0;
       i < sizeof(connectionInfo->wlanAssociationAttributes.dot11Bssid); ++i) {
    if (i == 5) {
      bssid.append(QString::asprintf(
          "%.2X\n", connectionInfo->wlanAssociationAttributes.dot11Bssid[i]));
    } else {
      bssid.append(QString::asprintf(
          "%.2X-", connectionInfo->wlanAssociationAttributes.dot11Bssid[i]));
    }
  }
  if (bssid != m_lastBSSID) {
    emit networkChanged(bssid);
    m_lastBSSID = bssid;
  }

  if (connectionInfo->wlanSecurityAttributes.dot11AuthAlgorithm !=
          DOT11_AUTH_ALGO_80211_OPEN &&
      connectionInfo->wlanSecurityAttributes.dot11CipherAlgorithm !=
          DOT11_CIPHER_ALGO_WEP &&
      connectionInfo->wlanSecurityAttributes.dot11CipherAlgorithm !=
          DOT11_CIPHER_ALGO_WEP40 &&
      connectionInfo->wlanSecurityAttributes.dot11CipherAlgorithm !=
          DOT11_CIPHER_ALGO_WEP104) {
    logger.debug() << "The network is secure enough";
    return;
  }

  QString ssid;
  for (size_t i = 0;
       i < connectionInfo->wlanAssociationAttributes.dot11Ssid.uSSIDLength;
       ++i) {
    ssid.append(QString::asprintf(
        "%c",
        (char)connectionInfo->wlanAssociationAttributes.dot11Ssid.ucSSID[i]));
  }

  logger.debug() << "Unsecure network:" << logger.sensitive(ssid)
                 << "id:" << logger.sensitive(bssid);
  emit unsecuredNetwork(ssid, bssid);
}
