/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "windowsfirewall.h"

#include <winsock2.h>
#include <Ws2tcpip.h>
#include <windows.h>

#include <comdef.h>
#include <fwpmu.h>
#include <guiddef.h>
#include <initguid.h>
#include <netioapi.h>
#include <netfw.h>
#include <qaccessible.h>
#include <qassert.h>
#include <stdio.h>

#include <QApplication>
#include <QFileInfo>
#include <QHostAddress>
#include <QNetworkInterface>
#include <QObject>
#include <QScopeGuard>
#include <QSet>
#include <QtEndian>

#include "ipaddress.h"
#include "leakdetector.h"
#include "logger.h"
#include "platforms/windows/windowsutils.h"

#include "killswitch.h"

#define IPV6_ADDRESS_SIZE 16

// Shared sublayers expected by win-split-tunnel v1.2.5.0.
DEFINE_GUID(ST_DRIVER_BASELINE_SUBLAYER_KEY, 0xc78056ff, 0x2bc1, 0x4211, 0xaa,
            0xdd, 0x7f, 0x35, 0x8d, 0xef, 0x20, 0x2d);
// win-split-tunnel v1.2.5.0 uses this hardcoded DNS sublayer key.
DEFINE_GUID(ST_DRIVER_DNS_SUBLAYER_KEY, 0x60090787, 0xcca1, 0x4937, 0xaa, 0xce,
            0x51, 0x25, 0x6e, 0xf4, 0x81, 0xf3);
// Amnezia-specific provider ownership boundary. Never reuse a third-party
// provider GUID: startup reconciliation deletes every filter owned by this ID.
DEFINE_GUID(AMNEZIA_FW_PROVIDER_KEY, 0xbb154c25, 0x39f2, 0x4b4f, 0x92, 0x6e,
            0x5e, 0xb2, 0xad, 0xf0, 0x61, 0xc7);

namespace {
Logger logger("WindowsFirewall");
WindowsFirewall* s_instance = nullptr;

// Note Filter Weight may be between 0-15!
constexpr uint8_t LOW_WEIGHT = 0;
constexpr uint8_t MED_WEIGHT = 7;
constexpr uint8_t HIGH_WEIGHT = 13;
constexpr uint8_t MAX_WEIGHT = 15;
constexpr wchar_t AMNEZIA_SERVICE_NAME[] = L"AmneziaVPN-service";

QList<quint64> deduplicateFilterIds(const QList<quint64>& filterIds) {
  QList<quint64> result;
  QSet<quint64> seen;
  result.reserve(filterIds.size());
  seen.reserve(filterIds.size());
  for (quint64 filterId : filterIds) {
    if (!seen.contains(filterId)) {
      seen.insert(filterId);
      result.append(filterId);
    }
  }
  return result;
}

bool sublayerExists(HANDLE wfp, const GUID& key, const wchar_t* name,
                    bool requirePersistent,
                    bool requireProviderNeutral = false) {
  FWPM_SUBLAYER0* maybeLayer = nullptr;
  const DWORD result = FwpmSubLayerGetByKey0(wfp, &key, &maybeLayer);
  if (result == ERROR_SUCCESS) {
    const bool persistent =
        (maybeLayer->flags & FWPM_SUBLAYER_FLAG_PERSISTENT) != 0;
    const bool providerMatches =
        !requireProviderNeutral || maybeLayer->providerKey == nullptr;
    logger.debug() << "The Sublayer Already Exists:"
                   << QString::fromWCharArray(name)
                   << "persistent:" << persistent
                   << "provider matches:" << providerMatches;
    FwpmFreeMemory0((void**)&maybeLayer);
    return (!requirePersistent || persistent) && providerMatches;
  }
  return false;
}
}  // namespace

WindowsFirewall* WindowsFirewall::create(QObject* parent) {
  if (s_instance != nullptr) {
    // Only one instance of the firewall is allowed
//    Q_ASSERT(false);
    return s_instance;
  }
  HANDLE engineHandle = nullptr;
  DWORD result = ERROR_SUCCESS;
  // Killswitch policy must outlive the daemon. Every filter is persistent and
  // provider-owned, then reconciled transactionally when a new daemon starts.
  // A dynamic WFP session would remove the policy on a daemon crash and fail
  // open.
  FWPM_SESSION0 session = {};

  logger.debug() << "Opening the filter engine.";

  result = FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, &session,
                           &engineHandle);

  if (result != ERROR_SUCCESS) {
    WindowsUtils::windowsLog("FwpmEngineOpen0 failed");
    return nullptr;
  }
  logger.debug() << "Filter engine opened successfully.";
  if (!initSublayer()) {
    FwpmEngineClose0(engineHandle);
    return nullptr;
  }
  auto* firewall = new WindowsFirewall(engineHandle, parent);
  if (!firewall->loadProviderFilters()) {
    delete firewall;
    return nullptr;
  }
  s_instance = firewall;
  return s_instance;
}

bool WindowsFirewall::removePersistentPolicy() {
  HANDLE engineHandle = nullptr;
  FWPM_SESSION0 session = {};
  const DWORD openResult = FwpmEngineOpen0(
      nullptr, RPC_C_AUTHN_WINNT, nullptr, &session, &engineHandle);
  if (openResult != ERROR_SUCCESS) {
    logger.error() << "FwpmEngineOpen0 failed during uninstall cleanup:"
                   << openResult;
    return false;
  }

  WindowsFirewall firewall(engineHandle, nullptr);
  if (!firewall.loadProviderFilters()) {
    return false;
  }

  DWORD result = FwpmTransactionBegin0(engineHandle, 0);
  if (result != ERROR_SUCCESS) {
    logger.error() << "Failed to begin WFP metadata cleanup:" << result;
    return false;
  }
  auto rollback =
      qScopeGuard([&] { FwpmTransactionAbort0(engineHandle); });

  FilterIdList liveProviderRules;
  if (!firewall.enumerateProviderFilters(liveProviderRules) ||
      !firewall.deleteFilters(liveProviderRules)) {
    logger.error() << "Failed to delete Amnezia WFP filters during cleanup";
    return false;
  }

  // The baseline and DNS sublayers are shared with win-split-tunnel and are
  // deliberately provider-neutral. Uninstall removes only Amnezia-owned
  // filters and provider metadata, leaving the shared integration surface.
  result = FwpmProviderDeleteByKey0(engineHandle, &AMNEZIA_FW_PROVIDER_KEY);
  if (result != ERROR_SUCCESS && result != FWP_E_PROVIDER_NOT_FOUND) {
    logger.error() << "FwpmProviderDeleteByKey0 failed during uninstall "
                      "cleanup:"
                   << result;
    return false;
  }

  result = FwpmTransactionCommit0(engineHandle);
  if (result != ERROR_SUCCESS) {
    logger.error() << "Failed to commit WFP metadata cleanup:" << result;
    return false;
  }
  rollback.dismiss();
  return true;
}

WindowsFirewall::WindowsFirewall(HANDLE session, QObject* parent)
    : QObject(parent), m_sessionHandle(session) {
  MZ_COUNT_CTOR(WindowsFirewall);
}

WindowsFirewall::~WindowsFirewall() {
  MZ_COUNT_DTOR(WindowsFirewall);
  if (m_sessionHandle != nullptr &&
      m_sessionHandle != INVALID_HANDLE_VALUE) {
    const DWORD result = FwpmEngineClose0(m_sessionHandle);
    if (result != ERROR_SUCCESS) {
      logger.error() << "FwpmEngineClose0 failed. Return value:" << result;
    }
    m_sessionHandle = INVALID_HANDLE_VALUE;
  }
  if (s_instance == this) {
    s_instance = nullptr;
  }
}

// static
bool WindowsFirewall::initSublayer() {
  // win-split-tunnel soft permits and kill-switch blocks must live in these
  // same shared sublayers for WFP arbitration to preserve excluded-app
  // traffic. WindowsDaemon releases any surviving driver WFP session before
  // this migration runs.
  DWORD result = ERROR_SUCCESS;
  HANDLE wfp = INVALID_HANDLE_VALUE;
  FWPM_SESSION0 session = {};

  logger.debug() << "Opening the filter engine";
  result = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &wfp);
  if (result != ERROR_SUCCESS) {
    logger.error() << "FwpmEngineOpen0 failed. Return value:.\n" << result;
    return false;
  }
  auto cleanup = qScopeGuard([&] { FwpmEngineClose0(wfp); });

  const bool baselineExists = sublayerExists(
      wfp, ST_DRIVER_BASELINE_SUBLAYER_KEY,
      L"Amnezia-SplitTunnel-Baseline-Sublayer", true, true);
  const bool dnsExists = sublayerExists(
      wfp, ST_DRIVER_DNS_SUBLAYER_KEY,
      L"Amnezia-SplitTunnel-DNS-Sublayer", true, true);
  FWPM_PROVIDER0* existingProvider = nullptr;
  result =
      FwpmProviderGetByKey0(wfp, &AMNEZIA_FW_PROVIDER_KEY, &existingProvider);
  const bool providerExists = result == ERROR_SUCCESS;
  if (providerExists) {
    const bool providerPersistent =
        (existingProvider->flags & FWPM_PROVIDER_FLAG_PERSISTENT) != 0;
    const bool providerServiceMatches =
        existingProvider->serviceName != nullptr &&
        QString::fromWCharArray(existingProvider->serviceName) ==
            QString::fromWCharArray(AMNEZIA_SERVICE_NAME);
    FwpmFreeMemory0(reinterpret_cast<void**>(&existingProvider));
    if (!providerPersistent || !providerServiceMatches) {
      // Provider metadata is immutable. Refuse to delete an incompatible
      // provider here because its existing filters may be the only fail-closed
      // policy still protecting the host.
      logger.error() << "Existing Amnezia WFP provider is incompatible";
      return false;
    }
  } else if (result != FWP_E_PROVIDER_NOT_FOUND) {
    logger.error() << "FwpmProviderGetByKey0 failed. Return value:" << result;
    return false;
  }

  if (baselineExists && dnsExists && providerExists) {
    return true;
  }

  // Step 1: Start Transaction
  result = FwpmTransactionBegin(wfp, NULL);
  if (result != ERROR_SUCCESS) {
    logger.error() << "FwpmTransactionBegin0 failed. Return value:.\n"
                   << result;
    return false;
  }
  auto rollback = qScopeGuard([&] { FwpmTransactionAbort0(wfp); });

  auto addSublayerIfMissing = [&](const GUID& key, const wchar_t* name,
                                  const wchar_t* description, UINT16 weight) {
    FWPM_SUBLAYER0* maybeLayer = nullptr;
    result = FwpmSubLayerGetByKey0(wfp, &key, &maybeLayer);
    if (result == ERROR_SUCCESS) {
      const bool existingPersistent =
          (maybeLayer->flags & FWPM_SUBLAYER_FLAG_PERSISTENT) != 0;
      const bool providerNeutral = maybeLayer->providerKey == nullptr;
      FwpmFreeMemory0((void**)&maybeLayer);
      if (existingPersistent && providerNeutral) {
        logger.debug() << "The compatible sublayer already exists:"
                       << QString::fromWCharArray(name);
        return true;
      }
      result = FwpmSubLayerDeleteByKey0(wfp, &key);
      if (result != ERROR_SUCCESS) {
        logger.error() << "Failed to replace incompatible shared sublayer"
                       << QString::fromWCharArray(name)
                       << "error:" << result;
        return false;
      }
    }
    else if (result != FWP_E_SUBLAYER_NOT_FOUND) {
      logger.error() << "FwpmSubLayerGetByKey0 failed for"
                     << QString::fromWCharArray(name) << "Return value:.\n"
                     << result;
      return false;
    }

    FWPM_SUBLAYER0 subLayer;
    memset(&subLayer, 0, sizeof(subLayer));
    subLayer.subLayerKey = key;
    subLayer.displayData.name = (PWSTR)name;
    subLayer.displayData.description = (PWSTR)description;
    subLayer.providerKey = nullptr;
    subLayer.flags = FWPM_SUBLAYER_FLAG_PERSISTENT;
    subLayer.weight = weight;

    result = FwpmSubLayerAdd0(wfp, &subLayer, NULL);
    if (result != ERROR_SUCCESS) {
      logger.error() << "FwpmSubLayerAdd0 failed. Return value:.\n" << result;
      return false;
    }
    return true;
  };

  if (!providerExists) {
    FWPM_PROVIDER0 provider = {};
    provider.providerKey = AMNEZIA_FW_PROVIDER_KEY;
    provider.displayData.name =
        const_cast<PWSTR>(L"AmneziaVPN Windows Firewall Provider");
    provider.displayData.description = const_cast<PWSTR>(
        L"Owns crash-safe AmneziaVPN killswitch filters");
    provider.flags = FWPM_PROVIDER_FLAG_PERSISTENT;
    provider.serviceName = const_cast<PWSTR>(AMNEZIA_SERVICE_NAME);
    result = FwpmProviderAdd0(wfp, &provider, nullptr);
    if (result != ERROR_SUCCESS) {
      logger.error() << "FwpmProviderAdd0 failed. Return value:" << result;
      return false;
    }
  }

  if (!addSublayerIfMissing(
          ST_DRIVER_BASELINE_SUBLAYER_KEY,
          L"Amnezia-SplitTunnel-Baseline-Sublayer",
          L"Persistent filters shared with the split-tunnel driver", 0xFFFF) ||
      !addSublayerIfMissing(ST_DRIVER_DNS_SUBLAYER_KEY,
                            L"Amnezia-SplitTunnel-DNS-Sublayer",
                            L"Persistent DNS filters shared with the split-tunnel driver",
                            0xFFFE)) {
    return false;
  }

  // Step 4: Commit!
  result = FwpmTransactionCommit0(wfp);
  if (result != ERROR_SUCCESS) {
    logger.error() << "FwpmTransactionCommit0 failed. Return value:.\n"
                   << result;
    return false;
  }
  rollback.dismiss();
  logger.debug() << "Initialised Sublayer";
  return true;
}

bool WindowsFirewall::enableInterface(int vpnAdapterIndex) {
  logger.info() << "Enabling Killswitch Using Adapter:" << vpnAdapterIndex;

  quint64 candidateVpnInterfaceLuid = 0;
  if (vpnAdapterIndex >= 0) {
    NET_LUID interfaceLuid = {};
    const DWORD conversionResult = ConvertInterfaceIndexToLuid(
        static_cast<NET_IFINDEX>(vpnAdapterIndex), &interfaceLuid);
    if (conversionResult != NO_ERROR || interfaceLuid.Value == 0) {
      logger.error() << "Failed to resolve VPN interface LUID for index"
                     << vpnAdapterIndex << "error:" << conversionResult;
      return false;
    }
    candidateVpnInterfaceLuid = interfaceLuid.Value;
  }

  DWORD result = FwpmTransactionBegin0(m_sessionHandle, 0);
  if (result != ERROR_SUCCESS) {
    logger.error() << "FwpmTransactionBegin0 failed. Return value:" << result;
    return false;
  }
  auto rollback = qScopeGuard([&] { abortTransactionAndRecover(); });

  FilterIdList pendingBaseRules;
  FilterIdList pendingStrictRules;
  FilterIdList pendingActivationFenceRules;
  FilterIdList pendingAdapterRules;
  FilterIdList liveProviderRules;
  const bool enterStrictDisconnectedMode = vpnAdapterIndex < 0;
  const bool strictEnabled =
      enterStrictDisconnectedMode ||
      KillSwitch::instance()->isStrictKillSwitchEnabled();

  // Enumerating and replacing the provider generation in the same explicit
  // write transaction gives us a coherent WFP snapshot even if a previous
  // daemon or uninstall cleanup overlaps startup.
  if (!enumerateProviderFilters(liveProviderRules) ||
      !deleteFilters(liveProviderRules)) {
    return false;
  }

  if (strictEnabled &&
      (!blockTrafficTo(IPAddress("0.0.0.0/0"), MED_WEIGHT,
                       "Block Internet", pendingStrictRules) ||
       !blockTrafficTo(IPAddress("::/0"), MED_WEIGHT, "Block Internet",
                       pendingStrictRules))) {
    return false;
  }

  if (!enterStrictDisconnectedMode) {
    // Keep the tunnel permit in a strictly higher WFP weight bucket than the
    // strict block-all filters.
    if (!allowTrafficOfAdapter(candidateVpnInterfaceLuid, HIGH_WEIGHT,
                               "Allow usage of VPN Adapter",
                               pendingAdapterRules)) {
      return false;
    }

    // Non-strict activation is a two-phase interface/peer operation. Keep a
    // persistent block-all fence until enablePeerTraffic() atomically replaces
    // it with the peer-specific generation.
    if (!strictEnabled &&
        (!blockTrafficTo(IPAddress("0.0.0.0/0"), MED_WEIGHT,
                         "Block Internet during VPN activation",
                         pendingActivationFenceRules) ||
         !blockTrafficTo(IPAddress("::/0"), MED_WEIGHT,
                         "Block Internet during VPN activation",
                         pendingActivationFenceRules))) {
      return false;
    }
  }

  if (!allowDHCPTraffic(MED_WEIGHT, "Allow DHCP Traffic", pendingBaseRules) ||
      !allowHyperVTraffic(MAX_WEIGHT, "Allow Hyper-V Traffic",
                          pendingBaseRules) ||
      !allowTrafficForAppOnAll(getCurrentPath(), MAX_WEIGHT,
                               "Allow all for AmneziaVPN.exe",
                               pendingBaseRules) ||
      !blockTrafficOnPort(53, MED_WEIGHT, "Block all DNS",
                          ST_DRIVER_DNS_SUBLAYER_KEY, pendingBaseRules) ||
      !allowLoopbackTraffic(MED_WEIGHT,
                            "Allow Loopback traffic on device %1",
                            pendingBaseRules)) {
    return false;
  }

  result = FwpmTransactionCommit0(m_sessionHandle);
  if (result != ERROR_SUCCESS) {
    logger.error() << "FwpmTransactionCommit0 failed. Return value:" << result;
    rollback.dismiss();
    reloadProviderState();
    return false;
  }
  rollback.dismiss();

  m_orphanedRules.clear();
  m_baseRules = pendingBaseRules;
  m_strictRules = pendingStrictRules;
  m_adapterRules = pendingAdapterRules;
  m_activationFenceRules = pendingActivationFenceRules;
  m_peerRules.clear();
  m_ipv6BlockRules.clear();
  m_lanBypassRules.clear();
  m_allowedRangeRules.clear();
  m_policyStateKnown = true;
  if (enterStrictDisconnectedMode) {
    m_vpnInterfaceLuid = 0;
  } else {
    m_vpnInterfaceLuid = candidateVpnInterfaceLuid;
  }

  logger.debug() << "Killswitch on! Base rules:" << m_baseRules.length()
                 << "strict rules:" << m_strictRules.length()
                 << "adapter rules:" << m_adapterRules.length();
  return true;
}

// Allow unprotected traffic sent to the following local address ranges.
bool WindowsFirewall::enableLanBypass(const QList<IPAddress>& ranges) {
  if (!m_policyStateKnown || !m_orphanedRules.isEmpty() ||
      m_baseRules.isEmpty()) {
    logger.error() << "Firewall policy must be reconciled before LAN bypass";
    return false;
  }
  DWORD result = FwpmTransactionBegin0(m_sessionHandle, 0);
  if (result != ERROR_SUCCESS) {
    logger.error() << "FwpmTransactionBegin0 failed. Return value:" << result;
    return false;
  }
  auto rollback = qScopeGuard([&] { abortTransactionAndRecover(); });

  if (!verifyTrackedProviderGeneration()) {
    return false;
  }
  if (!deleteFilters(m_lanBypassRules)) {
    return false;
  }

  FilterIdList pendingRules;
  for (const IPAddress& prefix : ranges) {
    if (!allowTrafficTo(prefix, LOW_WEIGHT + 1, "Allow LAN bypass traffic",
                        pendingRules)) {
      return false;
    }
  }

  result = FwpmTransactionCommit0(m_sessionHandle);
  if (result != ERROR_SUCCESS) {
    logger.error() << "FwpmTransactionCommit0 failed with error:" << result;
    rollback.dismiss();
    reloadProviderState();
    return false;
  }

  rollback.dismiss();
  m_lanBypassRules = pendingRules;
  return true;
}

// Allow unprotected traffic sent to the following address ranges.
bool WindowsFirewall::allowTrafficRange(const QStringList& ranges) {
  if (!m_policyStateKnown || !m_orphanedRules.isEmpty() ||
      m_baseRules.isEmpty()) {
    logger.error() << "Firewall policy must be reconciled before exceptions";
    return false;
  }
  DWORD result = FwpmTransactionBegin0(m_sessionHandle, 0);
  if (result != ERROR_SUCCESS) {
    logger.error() << "FwpmTransactionBegin0 failed. Return value:" << result;
    return false;
  }
  auto rollback = qScopeGuard([&] { abortTransactionAndRecover(); });

  if (!verifyTrackedProviderGeneration()) {
    return false;
  }
  if (!deleteFilters(m_allowedRangeRules)) {
    return false;
  }

  FilterIdList pendingRules;
  for (const QString& addr : ranges) {
    logger.debug() << "Allow killswitch exclude: " << addr;
    const QHostAddress address(addr);
    if (address.protocol() != QAbstractSocket::IPv4Protocol &&
        address.protocol() != QAbstractSocket::IPv6Protocol) {
      logger.error() << "Invalid killswitch exception address";
      return false;
    }
    if (!allowTrafficTo(IPAddress(address), HIGH_WEIGHT,
                        "Allow killswitch bypass traffic", pendingRules)) {
      return false;
    }
  }

  result = FwpmTransactionCommit0(m_sessionHandle);
  if (result != ERROR_SUCCESS) {
    logger.error() << "FwpmTransactionCommit0 failed with error:" << result;
    rollback.dismiss();
    reloadProviderState();
    return false;
  }

  rollback.dismiss();
  m_allowedRangeRules = pendingRules;
  return true;
}


bool WindowsFirewall::enablePeerTraffic(const InterfaceConfig& config) {
  if (config.m_serverPublicKey.isEmpty()) {
    logger.error() << "Cannot install peer rules without a public key";
    return false;
  }
  if (!m_policyStateKnown || !m_orphanedRules.isEmpty() ||
      m_vpnInterfaceLuid == 0) {
    logger.error() << "Firewall policy and VPN interface must be reconciled "
                      "before peer rules";
    return false;
  }

  DWORD result = FwpmTransactionBegin0(m_sessionHandle, 0);
  if (result != ERROR_SUCCESS) {
    logger.error() << "FwpmTransactionBegin0 failed. Return value:" << result;
    return false;
  }
  auto rollback = qScopeGuard([&] { abortTransactionAndRecover(); });

  if (!verifyTrackedProviderGeneration()) {
    return false;
  }
  const FilterIdList previousRules =
      m_peerRules.values(config.m_serverPublicKey);
  const FilterIdList previousIpv6Rules =
      m_ipv6BlockRules.values(config.m_serverPublicKey);
  if (!deleteFilters(previousRules) || !deleteFilters(previousIpv6Rules) ||
      !deleteFilters(m_activationFenceRules)) {
    return false;
  }
  FilterIdList pendingRules;
  FilterIdList pendingIpv6Rules;

  // Build the firewall rules for this peer.
  logger.info() << "Enabling traffic for peer" << config.m_serverPublicKey;
  if (!blockTrafficTo(config.m_allowedIPAddressRanges, LOW_WEIGHT,
                      "Block Internet", pendingRules)) {
    return false;
  }

  const auto allowDns = [&](const QString& address,
                            const QString& title) -> bool {
    if (address.isEmpty()) {
      return true;
    }
    return allowDnsTrafficTo(QHostAddress(address), 53, HIGH_WEIGHT, title,
                             m_vpnInterfaceLuid, pendingRules);
  };

  if (!config.m_primaryDnsServer.isEmpty()) {
    if (!allowDns(config.m_primaryDnsServer, "Allow DNS-Server")) {
      return false;
    }
    // In some cases, we might configure a 2nd DNS server for IPv6, however
    // this should probably be cleaned up by converting m_dnsServer into
    // a QStringList instead.
    if (config.m_primaryDnsServer == config.m_serverIpv4Gateway &&
        !config.m_serverIpv6Gateway.isEmpty()) {
      if (!allowDns(config.m_serverIpv6Gateway,
                    "Allow extra IPv6 DNS-Server")) {
        return false;
      }
    }
  }

  if (!config.m_secondaryDnsServer.isEmpty()) {
    if (!allowDns(config.m_secondaryDnsServer, "Allow DNS-Server")) {
      return false;
    }
    // In some cases, we might configure a 2nd DNS server for IPv6, however
    // this should probably be cleaned up by converting m_dnsServer into
    // a QStringList instead.
    if (config.m_secondaryDnsServer == config.m_serverIpv4Gateway &&
        !config.m_serverIpv6Gateway.isEmpty()) {
      if (!allowDns(config.m_serverIpv6Gateway,
                    "Allow extra IPv6 DNS-Server")) {
        return false;
      }
    }
  }

  for (const QString& dns : config.m_allowedDnsServers) {
    logger.debug() << "Allow DNS: " << dns;
    if (!allowDns(dns, "Allow DNS-Server")) {
      return false;
    }
  }

  if (!config.m_excludedAddresses.empty()) {
    for (const QString& i : config.m_excludedAddresses) {
      logger.debug() << "excludedAddresses range: " << i;

      const IPAddress address(i);
      if ((address.type() != QAbstractSocket::IPv4Protocol &&
           address.type() != QAbstractSocket::IPv6Protocol) ||
          !allowTrafficTo(address, HIGH_WEIGHT,
                          "Allow Exclude route", pendingRules)) {
        return false;
      }
    }
  }

  if (config.m_blockIpv6Traffic &&
      !blockTrafficTo(IPAddress("::/0"), LOW_WEIGHT,
                      "Block unavailable IPv6", pendingIpv6Rules)) {
    return false;
  }

  result = FwpmTransactionCommit0(m_sessionHandle);
  if (result != ERROR_SUCCESS) {
    logger.error() << "FwpmTransactionCommit0 failed with error:" << result;
    rollback.dismiss();
    reloadProviderState();
    return false;
  }

  rollback.dismiss();
  m_peerRules.remove(config.m_serverPublicKey);
  for (quint64 filterId : pendingRules) {
    m_peerRules.insert(config.m_serverPublicKey, filterId);
  }
  m_ipv6BlockRules.remove(config.m_serverPublicKey);
  for (quint64 filterId : pendingIpv6Rules) {
    m_ipv6BlockRules.insert(config.m_serverPublicKey, filterId);
  }
  m_activationFenceRules.clear();
  return true;
}

bool WindowsFirewall::blockIpv6TrafficForPeer(const QString& peer) {
  if (peer.isEmpty() || !m_policyStateKnown ||
      !m_orphanedRules.isEmpty() || m_baseRules.isEmpty()) {
    return false;
  }
  if (m_ipv6BlockRules.contains(peer)) {
    return true;
  }

  DWORD result = FwpmTransactionBegin0(m_sessionHandle, 0);
  if (result != ERROR_SUCCESS) {
    logger.error() << "FwpmTransactionBegin0 failed. Return value:" << result;
    return false;
  }
  auto rollback = qScopeGuard([&] { abortTransactionAndRecover(); });

  if (!verifyTrackedProviderGeneration()) {
    return false;
  }
  FilterIdList pendingRules;
  if (!blockTrafficTo(IPAddress("::/0"), LOW_WEIGHT,
                      "Block unavailable IPv6", pendingRules)) {
    return false;
  }

  result = FwpmTransactionCommit0(m_sessionHandle);
  if (result != ERROR_SUCCESS) {
    logger.error() << "FwpmTransactionCommit0 failed with error:" << result;
    rollback.dismiss();
    reloadProviderState();
    return false;
  }

  rollback.dismiss();
  for (quint64 filterId : pendingRules) {
    m_ipv6BlockRules.insert(peer, filterId);
  }
  return true;
}

bool WindowsFirewall::disablePeerTraffic(const QString& pubkey) {
  if (!m_policyStateKnown || !m_orphanedRules.isEmpty()) {
    logger.error() << "Firewall policy must be reconciled before peer removal";
    return false;
  }
  FilterIdList peerRules = m_peerRules.values(pubkey);
  peerRules.append(m_ipv6BlockRules.values(pubkey));
  peerRules = deduplicateFilterIds(peerRules);
  if (peerRules.isEmpty()) {
    return true;
  }

  DWORD result = FwpmTransactionBegin0(m_sessionHandle, 0);
  if (result != ERROR_SUCCESS) {
    logger.error() << "FwpmTransactionBegin0 failed. Return value:" << result;
    return false;
  }
  auto rollback = qScopeGuard([&] { abortTransactionAndRecover(); });

  if (!verifyTrackedProviderGeneration()) {
    return false;
  }
  logger.info() << "Disabling traffic for peer" << pubkey;
  if (!deleteFilters(peerRules)) {
    return false;
  }

  result = FwpmTransactionCommit0(m_sessionHandle);
  if (result != ERROR_SUCCESS) {
    logger.error() << "FwpmTransactionCommit0 failed. Return value:" << result;
    rollback.dismiss();
    reloadProviderState();
    return false;
  }
  rollback.dismiss();
  m_peerRules.remove(pubkey);
  m_ipv6BlockRules.remove(pubkey);
  return true;
}

bool WindowsFirewall::disableKillSwitch() {
  return KillSwitch::instance()->disableKillSwitch();
}

bool WindowsFirewall::allowAllTraffic() {
  DWORD result = FwpmTransactionBegin0(m_sessionHandle, 0);
  if (result != ERROR_SUCCESS) {
    logger.error() << "FwpmTransactionBegin0 failed. Return value:" << result;
    return false;
  }
  auto rollback = qScopeGuard([&] { abortTransactionAndRecover(); });

  FilterIdList liveProviderRules;
  if (!enumerateProviderFilters(liveProviderRules) ||
      !deleteFilters(liveProviderRules)) {
    return false;
  }

  result = FwpmTransactionCommit0(m_sessionHandle);
  if (result != ERROR_SUCCESS) {
    logger.error() << "FwpmTransactionCommit0 failed. Return value:" << result;
    rollback.dismiss();
    reloadProviderState();
    return false;
  }
  rollback.dismiss();

  m_baseRules.clear();
  m_strictRules.clear();
  m_activationFenceRules.clear();
  m_adapterRules.clear();
  m_lanBypassRules.clear();
  m_allowedRangeRules.clear();
  m_orphanedRules.clear();
  m_peerRules.clear();
  m_ipv6BlockRules.clear();
  m_vpnInterfaceLuid = 0;
  m_policyStateKnown = true;
  logger.debug() << "Firewall Disabled!";
  return true;
}

bool WindowsFirewall::allowTrafficForAppOnAll(const QString& exePath,
                                              int weight,
                                              const QString& title,
                                              FilterIdList& target) {
  DWORD result = ERROR_SUCCESS;
  Q_ASSERT(weight <= 15);

  // Get the AppID for the Executable;
  QString appName = QFileInfo(exePath).baseName();
  std::wstring wstr = exePath.toStdWString();
  PCWSTR appPath = wstr.c_str();
  FWP_BYTE_BLOB* appID = NULL;
  result = FwpmGetAppIdFromFileName0(appPath, &appID);
  if (result != ERROR_SUCCESS) {
    WindowsUtils::windowsLog("FwpmGetAppIdFromFileName0 failure");
    return false;
  }
  auto freeAppId = qScopeGuard(
      [&] { FwpmFreeMemory0(reinterpret_cast<void**>(&appID)); });
  // Condition: Request must come from the .exe
  FWPM_FILTER_CONDITION0 conds;
  conds.fieldKey = FWPM_CONDITION_ALE_APP_ID;
  conds.matchType = FWP_MATCH_EQUAL;
  conds.conditionValue.type = FWP_BYTE_BLOB_TYPE;
  conds.conditionValue.byteBlob = appID;

  // Assemble the Filter base
  FWPM_FILTER0 filter;
  memset(&filter, 0, sizeof(filter));
  filter.filterCondition = &conds;
  filter.numFilterConditions = 1;
  filter.action.type = FWP_ACTION_PERMIT;
  filter.weight.type = FWP_UINT8;
  filter.weight.uint8 = weight;
  filter.subLayerKey = ST_DRIVER_BASELINE_SUBLAYER_KEY;
  filter.flags = FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT;  // Make this decision
                                                       // only blockable by veto
  // Build and add the Filters
  // #1 Permit outbound IPv4 traffic.
  {
    QString desc("Permit (out) IPv4 Traffic of: " + appName);
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    if (!enableFilter(&filter, title, desc, target)) {
      return false;
    }
  }
  // #2 Permit inbound IPv4 traffic.
  {
    QString desc("Permit (in) IPv4 Traffic of: " + appName);
    filter.layerKey = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4;
    if (!enableFilter(&filter, title, desc, target)) {
      return false;
    }
  }
  return true;
}

bool WindowsFirewall::allowTrafficOfAdapter(quint64 networkAdapterLuid,
                                            uint8_t weight,
                                            const QString& title,
                                            FilterIdList& target) {
  if (networkAdapterLuid == 0) {
    return false;
  }

  FWPM_FILTER_CONDITION0 conds = {};
  // ALE layers identify the route's local interface by its stable LUID.
  UINT64 interfaceLuid = networkAdapterLuid;
  conds.fieldKey = FWPM_CONDITION_IP_LOCAL_INTERFACE;
  conds.matchType = FWP_MATCH_EQUAL;
  conds.conditionValue.type = FWP_UINT64;
  conds.conditionValue.uint64 = &interfaceLuid;

  // Assemble the Filter base
  FWPM_FILTER0 filter;
  memset(&filter, 0, sizeof(filter));
  filter.filterCondition = &conds;
  filter.numFilterConditions = 1;
  filter.action.type = FWP_ACTION_PERMIT;
  filter.weight.type = FWP_UINT8;
  filter.weight.uint8 = weight;
  filter.subLayerKey = ST_DRIVER_BASELINE_SUBLAYER_KEY;

  QString description("Allow %1 traffic on adapter LUID %2");
  // #1 Permit outbound IPv4 traffic.
  filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
  if (!enableFilter(&filter, title,
                    description.arg("out").arg(networkAdapterLuid), target)) {
    return false;
  }
  // #2 Permit inbound IPv4 traffic.
  filter.layerKey = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4;
  if (!enableFilter(&filter, title,
                    description.arg("in").arg(networkAdapterLuid), target)) {
    return false;
  }
  // #3 Permit outbound IPv6 traffic.
  filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
  if (!enableFilter(&filter, title,
                    description.arg("out").arg(networkAdapterLuid), target)) {
    return false;
  }
  // #4 Permit inbound IPv6 traffic.
  filter.layerKey = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6;
  if (!enableFilter(&filter, title,
                    description.arg("in").arg(networkAdapterLuid), target)) {
    return false;
  }
  return true;
}

bool WindowsFirewall::allowTrafficTo(const IPAddress& addr, int weight,
                                     const QString& title,
                                     FilterIdList& target) {
  GUID layerKeyOut;
  GUID layerKeyIn;
  if (addr.type() == QAbstractSocket::IPv4Protocol) {
    layerKeyOut = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    layerKeyIn = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4;
  } else {
    layerKeyOut = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
    layerKeyIn = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6;
  }

  // Match the IP address range.
  FWPM_FILTER_CONDITION0 cond[1] = {};
  FWP_RANGE0 ipRange;
  QByteArray lowIpV6Buffer;
  QByteArray highIpV6Buffer;

  importAddress(addr.address(), ipRange.valueLow, &lowIpV6Buffer);
  importAddress(addr.broadcastAddress(), ipRange.valueHigh, &highIpV6Buffer);

  cond[0].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
  cond[0].matchType = FWP_MATCH_RANGE;
  cond[0].conditionValue.type = FWP_RANGE_TYPE;
  cond[0].conditionValue.rangeValue = &ipRange;

  // Assemble the Filter base
  FWPM_FILTER0 filter;
  memset(&filter, 0, sizeof(filter));
  filter.action.type = FWP_ACTION_PERMIT;
  filter.weight.type = FWP_UINT8;
  filter.weight.uint8 = weight;
  filter.subLayerKey = ST_DRIVER_BASELINE_SUBLAYER_KEY;
  filter.numFilterConditions = 1;
  filter.filterCondition = cond;

  // Send the filters down to the firewall.
  QString description = "Permit traffic %1 " + addr.toString();
  filter.layerKey = layerKeyOut;
  if (!enableFilter(&filter, title, description.arg("to"), target)) {
    return false;
  }
  filter.layerKey = layerKeyIn;
  if (!enableFilter(&filter, title, description.arg("from"), target)) {
    return false;
  }
  return true;
}

bool WindowsFirewall::allowDnsTrafficTo(const QHostAddress& targetIP,
                                        uint port, int weight,
                                        const QString& title,
                                        quint64 vpnInterfaceLuid,
                                        FilterIdList& target) {
  const auto protocol = targetIP.protocol();
  if ((protocol != QAbstractSocket::IPv4Protocol &&
       protocol != QAbstractSocket::IPv6Protocol) ||
      vpnInterfaceLuid == 0) {
    logger.error() << "Refusing invalid or unbound DNS firewall permit";
    return false;
  }

  const bool isIPv4 = protocol == QAbstractSocket::IPv4Protocol;
  const GUID layerOut =
      isIPv4 ? FWPM_LAYER_ALE_AUTH_CONNECT_V4 : FWPM_LAYER_ALE_AUTH_CONNECT_V6;

  // WFP combines conditions in a filter with AND. Protocol alternatives must
  // therefore be represented by separate filters rather than by requiring one
  // packet to be both UDP and TCP.
  FWPM_FILTER_CONDITION0 conds[4] = {};
  conds[0].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
  conds[0].matchType = FWP_MATCH_EQUAL;
  conds[0].conditionValue.type = FWP_UINT8;

  conds[1].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
  conds[1].matchType = FWP_MATCH_EQUAL;
  conds[1].conditionValue.type = FWP_UINT16;
  conds[1].conditionValue.uint16 = port;

  conds[2].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
  conds[2].matchType = FWP_MATCH_EQUAL;
  QByteArray buffer;
  // Will hold IPv6 address bytes if present.
  importAddress(targetIP, conds[2].conditionValue, &buffer);

  UINT64 interfaceLuid = vpnInterfaceLuid;
  conds[3].fieldKey = FWPM_CONDITION_IP_LOCAL_INTERFACE;
  conds[3].matchType = FWP_MATCH_EQUAL;
  conds[3].conditionValue.type = FWP_UINT64;
  conds[3].conditionValue.uint64 = &interfaceLuid;

  // Assemble the Filter base
  FWPM_FILTER0 filter = {};
  filter.filterCondition = conds;
  filter.numFilterConditions = 4;
  filter.action.type = FWP_ACTION_PERMIT;
  filter.weight.type = FWP_UINT8;
  filter.weight.uint8 = weight;
  filter.subLayerKey = ST_DRIVER_DNS_SUBLAYER_KEY;
  // Keep this a soft permit so lower-priority third-party policy can veto it.

  const auto enableProtocolFilters = [&](uint8_t protocol,
                                         const QString& protocolName) {
    conds[0].conditionValue.uint8 = protocol;

    const QString description(
        "Permit %1 traffic to %2 on port %3 via VPN LUID %4");
    filter.layerKey = layerOut;
    return enableFilter(
        &filter, title,
        description.arg(protocolName)
            .arg(targetIP.toString())
            .arg(port)
            .arg(vpnInterfaceLuid),
        target);
  };

  return enableProtocolFilters(IPPROTO_UDP, QStringLiteral("UDP")) &&
         enableProtocolFilters(IPPROTO_TCP, QStringLiteral("TCP"));
}

bool WindowsFirewall::allowDHCPTraffic(uint8_t weight, const QString& title,
                                       FilterIdList& target) {
  // Allow outbound DHCPv4
  {
    FWPM_FILTER_CONDITION0 conds[4];
    // Condition: Request must be targeting the TUN interface
    conds[0].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
    conds[0].matchType = FWP_MATCH_EQUAL;
    conds[0].conditionValue.type = FWP_UINT8;
    conds[0].conditionValue.uint8 = (IPPROTO_UDP);

    conds[1].fieldKey = FWPM_CONDITION_IP_LOCAL_PORT;
    conds[1].matchType = FWP_MATCH_EQUAL;
    conds[1].conditionValue.type = FWP_UINT16;
    conds[1].conditionValue.uint16 = (68);

    conds[2].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
    conds[2].matchType = FWP_MATCH_EQUAL;
    conds[2].conditionValue.type = FWP_UINT16;
    conds[2].conditionValue.uint16 = 67;

    conds[3].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
    conds[3].matchType = FWP_MATCH_EQUAL;
    conds[3].conditionValue.type = FWP_UINT32;
    conds[3].conditionValue.uint32 = (0xffffffff);

    // Assemble the Filter base
    FWPM_FILTER0 filter;
    memset(&filter, 0, sizeof(filter));
    filter.filterCondition = conds;
    filter.numFilterConditions = 4;
    filter.action.type = FWP_ACTION_PERMIT;
    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = weight;
    filter.subLayerKey = ST_DRIVER_BASELINE_SUBLAYER_KEY;

    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;

    if (!enableFilter(&filter, title, "Allow Outbound DHCP", target)) {
      return false;
    }
  }
  // Allow inbound DHCPv4
  {
    FWPM_FILTER_CONDITION0 conds[3];
    conds[0].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
    conds[0].matchType = FWP_MATCH_EQUAL;
    conds[0].conditionValue.type = FWP_UINT8;
    conds[0].conditionValue.uint8 = (IPPROTO_UDP);

    conds[1].fieldKey = FWPM_CONDITION_IP_LOCAL_PORT;
    conds[1].matchType = FWP_MATCH_EQUAL;
    conds[1].conditionValue.type = FWP_UINT16;
    conds[1].conditionValue.uint16 = (68);

    conds[2].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
    conds[2].matchType = FWP_MATCH_EQUAL;
    conds[2].conditionValue.type = FWP_UINT16;
    conds[2].conditionValue.uint16 = 67;

    // Assemble the Filter base
    FWPM_FILTER0 filter;
    memset(&filter, 0, sizeof(filter));
    filter.filterCondition = conds;
    filter.numFilterConditions = 3;
    filter.action.type = FWP_ACTION_PERMIT;
    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = weight;
    filter.subLayerKey = ST_DRIVER_BASELINE_SUBLAYER_KEY;
    filter.layerKey = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4;

    if (!enableFilter(&filter, title, "Allow inbound DHCP", target)) {
      return false;
    }
  }

  // Allow outbound DHCPv6
  {
    FWPM_FILTER_CONDITION0 conds[3];
    // Condition: Request must be targeting the TUN interface
    conds[0].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
    conds[0].matchType = FWP_MATCH_EQUAL;
    conds[0].conditionValue.type = FWP_UINT8;
    conds[0].conditionValue.uint8 = (IPPROTO_UDP);

    conds[1].fieldKey = FWPM_CONDITION_IP_LOCAL_PORT;
    conds[1].matchType = FWP_MATCH_EQUAL;
    conds[1].conditionValue.type = FWP_UINT16;
    conds[1].conditionValue.uint16 = (68);

    conds[2].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
    conds[2].matchType = FWP_MATCH_EQUAL;
    conds[2].conditionValue.type = FWP_UINT16;
    conds[2].conditionValue.uint16 = 67;

    // Assemble the Filter base
    FWPM_FILTER0 filter;
    memset(&filter, 0, sizeof(filter));
    filter.filterCondition = conds;
    filter.numFilterConditions = 3;
    filter.action.type = FWP_ACTION_PERMIT;
    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = weight;
    filter.subLayerKey = ST_DRIVER_BASELINE_SUBLAYER_KEY;
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;

    if (!enableFilter(&filter, title, "Allow outbound DHCPv6", target)) {
      return false;
    }
  }

  // Allow inbound DHCPv6
  {
    FWPM_FILTER_CONDITION0 conds[3];
    conds[0].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
    conds[0].matchType = FWP_MATCH_EQUAL;
    conds[0].conditionValue.type = FWP_UINT8;
    conds[0].conditionValue.uint8 = (IPPROTO_UDP);

    conds[1].fieldKey = FWPM_CONDITION_IP_LOCAL_PORT;
    conds[1].matchType = FWP_MATCH_EQUAL;
    conds[1].conditionValue.type = FWP_UINT16;
    conds[1].conditionValue.uint16 = (68);

    conds[2].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
    conds[2].matchType = FWP_MATCH_EQUAL;
    conds[2].conditionValue.type = FWP_UINT16;
    conds[2].conditionValue.uint16 = 67;

    // Assemble the Filter base
    FWPM_FILTER0 filter;
    memset(&filter, 0, sizeof(filter));
    filter.filterCondition = conds;
    filter.numFilterConditions = 3;
    filter.action.type = FWP_ACTION_PERMIT;
    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = weight;
    filter.subLayerKey = ST_DRIVER_BASELINE_SUBLAYER_KEY;
    filter.layerKey = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6;
    if (!enableFilter(&filter, title, "Allow inbound DHCPv6", target)) {
      return false;
    }
  }
  return true;
}

// Allows the internal Hyper-V Switches to work.
bool WindowsFirewall::allowHyperVTraffic(uint8_t weight, const QString& title,
                                         FilterIdList& target) {
  FWPM_FILTER_CONDITION0 cond;
  // Condition: Request must be targeting the TUN interface
  cond.fieldKey = FWPM_CONDITION_L2_FLAGS;
  cond.matchType = FWP_MATCH_EQUAL;
  cond.conditionValue.type = FWP_UINT32;
  cond.conditionValue.uint32 = FWP_CONDITION_L2_IS_VM2VM;

  // Assemble the Filter base
  FWPM_FILTER0 filter;
  memset(&filter, 0, sizeof(filter));
  filter.filterCondition = &cond;
  filter.numFilterConditions = 1;
  filter.action.type = FWP_ACTION_PERMIT;
  filter.weight.type = FWP_UINT8;
  filter.weight.uint8 = weight;
  filter.subLayerKey = ST_DRIVER_BASELINE_SUBLAYER_KEY;

  // #1 Permit Hyper-V => Hyper-V outbound.
  filter.layerKey = FWPM_LAYER_OUTBOUND_MAC_FRAME_NATIVE;
  if (!enableFilter(&filter, title, "Permit Hyper-V => Hyper-V outbound",
                    target)) {
    return false;
  }
  // #2 Permit Hyper-V => Hyper-V inbound.
  filter.layerKey = FWPM_LAYER_INBOUND_MAC_FRAME_NATIVE;
  if (!enableFilter(&filter, title, "Permit Hyper-V => Hyper-V inbound",
                    target)) {
    return false;
  }
  return true;
}

bool WindowsFirewall::blockTrafficTo(const IPAddress& addr, uint8_t weight,
                                     const QString& title,
                                     FilterIdList& target) {
  QString description("Block traffic %1 %2 ");

  auto lower = addr.address();
  auto upper = addr.broadcastAddress();

  const bool isV4 = addr.type() == QAbstractSocket::IPv4Protocol;
  const GUID layerKeyOut =
      isV4 ? FWPM_LAYER_ALE_AUTH_CONNECT_V4 : FWPM_LAYER_ALE_AUTH_CONNECT_V6;
  const GUID layerKeyIn = isV4 ? FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4
                               : FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6;

  // Assemble the Filter base
  FWPM_FILTER0 filter;
  memset(&filter, 0, sizeof(filter));
  filter.action.type = FWP_ACTION_BLOCK;
  filter.weight.type = FWP_UINT8;
  filter.weight.uint8 = weight;
  filter.subLayerKey = ST_DRIVER_BASELINE_SUBLAYER_KEY;

  FWPM_FILTER_CONDITION0 cond[1] = {};
  FWP_RANGE0 ipRange;
  QByteArray lowIpV6Buffer;
  QByteArray highIpV6Buffer;

  importAddress(lower, ipRange.valueLow, &lowIpV6Buffer);
  importAddress(upper, ipRange.valueHigh, &highIpV6Buffer);

  cond[0].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
  cond[0].matchType = FWP_MATCH_RANGE;
  cond[0].conditionValue.type = FWP_RANGE_TYPE;
  cond[0].conditionValue.rangeValue = &ipRange;

  filter.numFilterConditions = 1;
  filter.filterCondition = cond;

  filter.layerKey = layerKeyOut;
  if (!enableFilter(&filter, title, description.arg("to").arg(addr.toString()),
                    target)) {
    return false;
  }
  filter.layerKey = layerKeyIn;
  if (!enableFilter(&filter, title,
                    description.arg("from").arg(addr.toString()), target)) {
    return false;
  }
  return true;
}

bool WindowsFirewall::blockTrafficTo(const QList<IPAddress>& rangeList,
                                     uint8_t weight, const QString& title,
                                     FilterIdList& target) {
  for (auto range : rangeList) {
    if (!blockTrafficTo(range, weight, title, target)) {
      logger.info() << "Setting Range of" << range.toString() << "failed";
      return false;
    }
  }
  return true;
}

// Returns the Path of the Current Executable this runs in
QString WindowsFirewall::getCurrentPath() {
  const unsigned char initValue = 0xff;
  QByteArray buffer(2048, initValue);
  auto ok = GetModuleFileNameA(NULL, buffer.data(), buffer.size());

  if (ok == ERROR_INSUFFICIENT_BUFFER) {
    buffer.resize(buffer.size() * 2);
    ok = GetModuleFileNameA(NULL, buffer.data(), buffer.size());
  }
  if (ok == 0) {
    WindowsUtils::windowsLog("Err fetching dos path");
    return "";
  }

  return QString::fromLocal8Bit(buffer);
}

void WindowsFirewall::importAddress(const QHostAddress& addr,
                                    OUT FWP_VALUE0_& value,
                                    OUT QByteArray* v6DataBuffer) {
  const bool isV4 = addr.protocol() == QAbstractSocket::IPv4Protocol;
  if (isV4) {
    value.type = FWP_UINT32;
    value.uint32 = addr.toIPv4Address();
    return;
  }
  auto v6bytes = addr.toIPv6Address();
  v6DataBuffer->append((const char*)v6bytes.c, IPV6_ADDRESS_SIZE);
  value.type = FWP_BYTE_ARRAY16_TYPE;
  value.byteArray16 = (FWP_BYTE_ARRAY16*)v6DataBuffer->data();
}
void WindowsFirewall::importAddress(const QHostAddress& addr,
                                    OUT FWP_CONDITION_VALUE0_& value,
                                    OUT QByteArray* v6DataBuffer) {
  const bool isV4 = addr.protocol() == QAbstractSocket::IPv4Protocol;
  if (isV4) {
    value.type = FWP_UINT32;
    value.uint32 = addr.toIPv4Address();
    return;
  }
  auto v6bytes = addr.toIPv6Address();
  v6DataBuffer->append((const char*)v6bytes.c, IPV6_ADDRESS_SIZE);
  value.type = FWP_BYTE_ARRAY16_TYPE;
  value.byteArray16 = (FWP_BYTE_ARRAY16*)v6DataBuffer->data();
}

bool WindowsFirewall::blockTrafficOnPort(uint port, uint8_t weight,
                                         const QString& title,
                                         const GUID& subLayerKey,
                                         FilterIdList& target) {
  // WFP combines conditions in a filter with AND, so UDP and TCP need
  // independent block filters.
  FWPM_FILTER_CONDITION0 conds[2] = {};
  conds[0].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
  conds[0].matchType = FWP_MATCH_EQUAL;
  conds[0].conditionValue.type = FWP_UINT8;

  conds[1].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
  conds[1].matchType = FWP_MATCH_EQUAL;
  conds[1].conditionValue.type = FWP_UINT16;
  conds[1].conditionValue.uint16 = port;

  // Assemble the Filter base
  FWPM_FILTER0 filter = {};
  filter.filterCondition = conds;
  filter.numFilterConditions = 2;
  filter.action.type = FWP_ACTION_BLOCK;
  filter.weight.type = FWP_UINT8;
  filter.weight.uint8 = weight;
  filter.subLayerKey = subLayerKey;

  const auto enableProtocolFilters = [&](uint8_t protocol,
                                         const QString& protocolName) {
    conds[0].conditionValue.uint8 = protocol;
    const QString description("Block %1 %2 on port %3");

    const auto enableLayerFilter = [&](const GUID& layerKey,
                                       const QString& direction) {
      filter.layerKey = layerKey;
      return enableFilter(
          &filter, title,
          description.arg(protocolName).arg(direction).arg(port), target);
    };

    return enableLayerFilter(FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                             QStringLiteral("outgoing v6")) &&
           enableLayerFilter(FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                             QStringLiteral("outgoing v4")) &&
           enableLayerFilter(FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
                             QStringLiteral("incoming v4")) &&
           enableLayerFilter(FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
                             QStringLiteral("incoming v6"));
  };

  return enableProtocolFilters(IPPROTO_UDP, QStringLiteral("UDP")) &&
         enableProtocolFilters(IPPROTO_TCP, QStringLiteral("TCP"));
}

bool WindowsFirewall::enableFilter(FWPM_FILTER0* filter, const QString& title,
                                   const QString& description,
                                   FilterIdList& target) {
  quint64 filterID = 0;
  auto name = title.toStdWString();
  auto desc = description.toStdWString();
  filter->displayData.name = (PWSTR)name.c_str();
  filter->displayData.description = (PWSTR)desc.c_str();
  filter->providerKey = const_cast<GUID*>(&AMNEZIA_FW_PROVIDER_KEY);
  filter->flags |= FWPM_FILTER_FLAG_PERSISTENT;
  const DWORD result =
      FwpmFilterAdd0(m_sessionHandle, filter, nullptr, &filterID);
  if (result != ERROR_SUCCESS) {
    logger.error() << "Failed to enable filter: " << title << " "
                   << description << "error:" << result;
    return false;
  }
  logger.info() << "Filter added: " << title << ":" << description;
  target.append(filterID);
  return true;
}

bool WindowsFirewall::enumerateProviderFilters(FilterIdList& filterIds) {
  filterIds.clear();
  const GUID* layers[] = {
      &FWPM_LAYER_ALE_AUTH_CONNECT_V4,
      &FWPM_LAYER_ALE_AUTH_CONNECT_V6,
      &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
      &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
      &FWPM_LAYER_INBOUND_MAC_FRAME_NATIVE,
      &FWPM_LAYER_OUTBOUND_MAC_FRAME_NATIVE,
  };

  constexpr UINT32 pageSize = 128;
  for (const GUID* layer : layers) {
    FWPM_FILTER_ENUM_TEMPLATE0 enumTemplate = {};
    enumTemplate.providerKey =
        const_cast<GUID*>(&AMNEZIA_FW_PROVIDER_KEY);
    enumTemplate.layerKey = *layer;
    enumTemplate.enumType = FWP_FILTER_ENUM_FULLY_CONTAINED;
    enumTemplate.flags = FWP_FILTER_ENUM_FLAG_INCLUDE_BOOTTIME |
                         FWP_FILTER_ENUM_FLAG_INCLUDE_DISABLED;
    enumTemplate.actionMask = 0xFFFFFFFFu;

    HANDLE enumHandle = nullptr;
    DWORD result = FwpmFilterCreateEnumHandle0(
        m_sessionHandle, &enumTemplate, &enumHandle);
    if (result != ERROR_SUCCESS) {
      logger.error() << "FwpmFilterCreateEnumHandle0 failed. Return value:"
                     << result;
      return false;
    }
    auto destroyEnum = qScopeGuard(
        [&] { FwpmFilterDestroyEnumHandle0(m_sessionHandle, enumHandle); });

    while (true) {
      FWPM_FILTER0** filters = nullptr;
      UINT32 returned = 0;
      result = FwpmFilterEnum0(m_sessionHandle, enumHandle, pageSize, &filters,
                               &returned);
      auto freeFilters = qScopeGuard([&] {
        if (filters != nullptr) {
          FwpmFreeMemory0(reinterpret_cast<void**>(&filters));
        }
      });
      if (result != ERROR_SUCCESS) {
        logger.error() << "FwpmFilterEnum0 failed. Return value:" << result;
        return false;
      }
      for (UINT32 index = 0; index < returned; ++index) {
        filterIds.append(filters[index]->filterId);
      }
      if (returned < pageSize) {
        break;
      }
    }
  }

  filterIds = deduplicateFilterIds(filterIds);
  return true;
}

bool WindowsFirewall::loadProviderFilters() {
  m_policyStateKnown = false;
  m_orphanedRules.clear();
  if (!enumerateProviderFilters(m_orphanedRules)) {
    return false;
  }
  m_policyStateKnown = true;
  if (!m_orphanedRules.isEmpty()) {
    logger.warning() << "Found" << m_orphanedRules.size()
                     << "provider-owned filters to reconcile";
  }
  return true;
}

bool WindowsFirewall::reloadProviderState() {
  m_policyStateKnown = false;
  m_baseRules.clear();
  m_strictRules.clear();
  m_activationFenceRules.clear();
  m_adapterRules.clear();
  m_lanBypassRules.clear();
  m_allowedRangeRules.clear();
  m_orphanedRules.clear();
  m_peerRules.clear();
  m_ipv6BlockRules.clear();
  m_vpnInterfaceLuid = 0;

  if (m_sessionHandle != nullptr &&
      m_sessionHandle != INVALID_HANDLE_VALUE) {
    const DWORD closeResult = FwpmEngineClose0(m_sessionHandle);
    if (closeResult != ERROR_SUCCESS) {
      logger.error() << "FwpmEngineClose0 failed during policy reload:"
                     << closeResult;
    }
  }
  m_sessionHandle = INVALID_HANDLE_VALUE;

  FWPM_SESSION0 session = {};
  HANDLE replacement = nullptr;
  const DWORD openResult = FwpmEngineOpen0(
      nullptr, RPC_C_AUTHN_WINNT, nullptr, &session, &replacement);
  if (openResult != ERROR_SUCCESS) {
    logger.error() << "FwpmEngineOpen0 failed during policy reload:"
                   << openResult;
    return false;
  }
  m_sessionHandle = replacement;
  return loadProviderFilters();
}

void WindowsFirewall::abortTransactionAndRecover() {
  const DWORD abortResult = FwpmTransactionAbort0(m_sessionHandle);
  if (abortResult != ERROR_SUCCESS) {
    logger.error() << "FwpmTransactionAbort0 failed; reloading WFP state:"
                   << abortResult;
    reloadProviderState();
  }
}

bool WindowsFirewall::deleteFilters(const FilterIdList& filterIds) {
  const FilterIdList uniqueIds = deduplicateFilterIds(filterIds);
  for (quint64 filterId : uniqueIds) {
    const DWORD result = FwpmFilterDeleteById0(m_sessionHandle, filterId);
    if (result != ERROR_SUCCESS && result != FWP_E_FILTER_NOT_FOUND) {
      logger.error() << "FwpmFilterDeleteById0 failed for filter" << filterId
                     << "error:" << result;
      return false;
    }
  }
  return true;
}

bool WindowsFirewall::verifyTrackedProviderGeneration() {
  FilterIdList liveFilters;
  if (!enumerateProviderFilters(liveFilters)) {
    return false;
  }

  QSet<quint64> liveSet;
  for (quint64 filterId : liveFilters) {
    liveSet.insert(filterId);
  }
  QSet<quint64> trackedSet;
  for (quint64 filterId : allTrackedFilters()) {
    trackedSet.insert(filterId);
  }
  if (liveSet != trackedSet) {
    logger.error() << "Provider-owned WFP generation changed concurrently; "
                      "refusing incremental update";
    m_policyStateKnown = false;
    return false;
  }
  return true;
}

WindowsFirewall::FilterIdList WindowsFirewall::allTrackedFilters() const {
  FilterIdList filters = m_baseRules;
  filters.append(m_strictRules);
  filters.append(m_activationFenceRules);
  filters.append(m_adapterRules);
  filters.append(m_lanBypassRules);
  filters.append(m_allowedRangeRules);
  filters.append(m_orphanedRules);
  filters.append(m_peerRules.values());
  filters.append(m_ipv6BlockRules.values());
  return deduplicateFilterIds(filters);
}

bool WindowsFirewall::allowLoopbackTraffic(uint8_t weight,
                                           const QString& title,
                                           FilterIdList& target) {
  QList<QNetworkInterface> networkInterfaces =
      QNetworkInterface::allInterfaces();
  for (const auto& iface : networkInterfaces) {
    if (iface.type() != QNetworkInterface::Loopback) {
      continue;
    }
    NET_LUID interfaceLuid = {};
    const DWORD result = ConvertInterfaceIndexToLuid(
        static_cast<NET_IFINDEX>(iface.index()), &interfaceLuid);
    if (result != NO_ERROR || interfaceLuid.Value == 0 ||
        !allowTrafficOfAdapter(interfaceLuid.Value, weight,
                               title.arg(iface.name()), target)) {
      return false;
    }
  }
  return true;
}
