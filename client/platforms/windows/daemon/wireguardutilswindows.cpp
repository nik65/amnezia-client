/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "wireguardutilswindows.h"
#include "../../../../common/awgBackendObservation.h"

#include <WS2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2ipdef.h>

#include <QFileInfo>
#include <QCryptographicHash>
#include <QRegularExpression>
#include <QScopeGuard>

#include "leakdetector.h"
#include "logger.h"
#include "uapiresult.h"
#include "windowsfirewall.h"

#pragma comment(lib, "iphlpapi.lib")

namespace {
Logger logger("WireguardUtilsWindows");

bool isSuccessfulRouteDelete(DWORD result) {
  return result == NO_ERROR || result == ERROR_NOT_FOUND ||
         result == ERROR_FILE_NOT_FOUND;
}
};  // namespace

std::unique_ptr<WireguardUtilsWindows> WireguardUtilsWindows::create(
    WindowsFirewall* fw, QObject* parent) {
  if (!fw) {
    logger.error() << "WireguardUtilsWindows::create: no wfp handle";
    return {};
  }

  // Can't use make_unique here as the Constructor is private :(
  auto utils = new WireguardUtilsWindows(parent, fw);
  return std::unique_ptr<WireguardUtilsWindows>(utils);
}

WireguardUtilsWindows::WireguardUtilsWindows(QObject* parent, WindowsFirewall* fw)
    : WireguardUtils(parent), m_tunnel(this), m_firewall(fw) {
  MZ_COUNT_CTOR(WireguardUtilsWindows);
  logger.debug() << "WireguardUtilsWindows created.";

  connect(&m_tunnel, &WindowsTunnelService::backendFailure, this,
          [&] { emit backendFailure(); });
}

WireguardUtilsWindows::~WireguardUtilsWindows() {
  MZ_COUNT_DTOR(WireguardUtilsWindows);
  logger.debug() << "WireguardUtilsWindows destroyed.";
}

QList<WireguardUtils::PeerStatus> WireguardUtilsWindows::getPeerStatus() {
  QString reply = m_tunnel.uapiCommand("get=1");
  const int err = amnezia::uapi::errnoFromReply(reply);
  if (err != 0) {
    logger.error() << "Peer status query failed with UAPI errno:" << err;
    return {};
  }
  PeerStatus status;
  QList<PeerStatus> peerList;
  for (const QString& line : reply.split('\n')) {
    int eq = line.indexOf('=');
    if (eq <= 0) {
      continue;
    }
    QString name = line.left(eq);
    QString value = line.mid(eq + 1);

    if (name == "public_key") {
      if (!status.m_pubkey.isEmpty()) {
        peerList.append(status);
      }
      QByteArray pubkey = QByteArray::fromHex(value.toUtf8());
      status = PeerStatus(pubkey.toBase64());
    }

    if (name == "tx_bytes") {
      status.m_txBytes = value.toDouble();
    }
    if (name == "rx_bytes") {
      status.m_rxBytes = value.toDouble();
    }
    if (name == "last_handshake_time_sec") {
      status.m_handshake += value.toLongLong() * 1000;
    }
    if (name == "last_handshake_time_nsec") {
      status.m_handshake += value.toLongLong() / 1000000;
    }
  }
  if (!status.m_pubkey.isEmpty()) {
    peerList.append(status);
  }

  // Capability and key evidence belong to the device section. Do not accept
  // partial hex decoding or peer-section lookalikes as native confirmation.
  QMap<QString, QString> deviceFields;
  QSet<QString> duplicateFields;
  for (const auto &line : reply.split('\n')) {
    const int separator = line.indexOf('=');
    const auto name = line.left(separator);
    if (name == "public_key") break;
    if (deviceFields.contains(name)) duplicateFields.insert(name);
    deviceFields.insert(name, line.mid(separator + 1));
  }
  const auto validFlag = [&](const QString &name) {
    const auto value = deviceFields.value(name);
    return !duplicateFields.contains(name) &&
           (value == "true" || value == "false" || value == "0" || value == "1");
  };
  const bool awg3Capable = validFlag("random_trailers") && validFlag("disable_cookies");
  const auto key = deviceFields.value("header_protection_key");
  const bool validKey = !duplicateFields.contains("header_protection_key") &&
      QRegularExpression(QStringLiteral("^[0-9a-fA-F]{64}$")).match(key).hasMatch();
  const auto parameterDigests = amnezia::awgBackendObservation::parameterDigests(reply);
  for (auto &peer : peerList) {
    peer.m_parameterDigests = parameterDigests;
    peer.m_awg3Capable = awg3Capable;
    if (validKey) peer.m_headerProtectionKeyHash = QString::fromLatin1(QCryptographicHash::hash(
            QByteArray::fromHex(key.toUtf8()), QCryptographicHash::Sha256).toHex());
  }
  return peerList;
}

bool WireguardUtilsWindows::addInterface(const InterfaceConfig& config) {
  QStringList addresses;
  for (const IPAddress& ip : config.m_allowedIPAddressRanges) {
    addresses.append(ip.toString());
  }

  QMap<QString, QString> extraConfig;
  extraConfig["Table"] = "off";
  QString configString = config.toWgConf(extraConfig);
  if (configString.isEmpty()) {
    logger.error() << "Failed to create a config file";
    return false;
  }

  // We don't want to pass a peer just yet, that will happen later with
  // a UAPI command in WireguardUtilsWindows::updatePeer(), so truncate
  // the config file to remove the [Peer] section.
  qsizetype peerStart = configString.indexOf("[Peer]", 0, Qt::CaseSensitive);
  if (peerStart >= 0) {
    configString.truncate(peerStart);
  }

  if (!m_tunnel.start(configString)) {
    logger.error() << "Failed to activate the tunnel service";
    return false;
  }
  auto activationFailure = qScopeGuard([&] {
    if (m_routeMonitor) {
      delete m_routeMonitor;
      m_routeMonitor = nullptr;
    }
    m_luid = 0;
    m_tunnel.stop();
  });

  // Determine the interface LUID
  NET_LUID luid;
  QString ifAlias = interfaceName();
  DWORD result = ConvertInterfaceAliasToLuid((wchar_t*)ifAlias.utf16(), &luid);
  if (result != 0) {
    logger.error() << "Failed to lookup LUID:" << result;
    return false;
  }
  m_luid = luid.Value;
  m_routeMonitor = new WindowsRouteMonitor(luid.Value, this);

  if (config.m_killSwitchEnabled) {
    // Enable the windows firewall
    NET_IFINDEX ifindex = 0;
    result = ConvertInterfaceLuidToIndex(&luid, &ifindex);
    if (result != NO_ERROR || ifindex == 0 || m_firewall == nullptr ||
        !m_firewall->enableInterface(static_cast<int>(ifindex))) {
      logger.error() << "Failed to enable crash-safe Windows firewall policy";
      return false;
    }
  }

  activationFailure.dismiss();
  logger.debug() << "Registration completed";
  return true;
}

bool WireguardUtilsWindows::deleteInterface() {
  if (m_routeMonitor) {
    m_routeMonitor->deleteLater();
    m_routeMonitor = nullptr;
  }

  const bool firewallDisabled =
      m_firewall != nullptr && m_firewall->disableKillSwitch();
  const bool nativeStopped = m_tunnel.stop();
  m_luid = 0;
  m_configuredPeers.clear();
  return firewallDisabled && nativeStopped;
}

bool WireguardUtilsWindows::updatePeer(const InterfaceConfig& config) {
  QByteArray publicKey =
      QByteArray::fromBase64(qPrintable(config.m_serverPublicKey));
  QByteArray pskKey =
      QByteArray::fromBase64(qPrintable(config.m_serverPskKey));

  if (config.m_killSwitchEnabled) {
    // Enable the windows firewall for this peer.
    if (m_firewall == nullptr || !m_firewall->enablePeerTraffic(config)) {
      logger.error() << "Failed to enable Windows firewall peer policy";
      return false;
    }
  }
  if (config.m_blockIpv6Traffic) {
    if (m_firewall == nullptr ||
        !m_firewall->blockIpv6TrafficForPeer(config.m_serverPublicKey)) {
      logger.error() << "Failed to block unavailable IPv6 traffic";
      return false;
    }
  }
  logger.debug() << "Configuring peer" << publicKey.toHex()
                 << "via" << config.m_serverIpv4AddrIn;

  // Update/create the peer config
  QString message;
  QTextStream out(&message);
  out << "set=1\n";
  out << "public_key=" << QString(publicKey.toHex()) << "\n";
  if (!config.m_serverPskKey.isNull()) {
    out << "preshared_key=" << QString(pskKey.toHex()) << "\n";
  }
  if (!config.m_serverIpv4AddrIn.isNull()) {
    out << "endpoint=" << config.m_serverIpv4AddrIn << ":";
  } else if (!config.m_serverIpv6AddrIn.isNull()) {
    out << "endpoint=[" << config.m_serverIpv6AddrIn << "]:";
  } else {
    logger.warning() << "Failed to create peer with no endpoints";
    return false;
  }
  out << config.m_serverPort << "\n";

  out << "replace_allowed_ips=true\n";
  const QString persistentKeepalive = config.m_persistentKeepalive.isEmpty()
                                        ? QStringLiteral("60")
                                        : config.m_persistentKeepalive;
  out << "persistent_keepalive_interval=" << persistentKeepalive << "\n";
  for (const IPAddress& ip : config.m_allowedIPAddressRanges) {
    out << "allowed_ip=" << ip.toString() << "\n";
  }

  // Exclude the server address, except for multihop exit servers.
  bool endpointRoutesReady = true;
  if (m_routeMonitor && config.m_hopType != InterfaceConfig::MultiHopExit) {
    if (!config.m_serverIpv4AddrIn.isEmpty()) {
      endpointRoutesReady =
          m_routeMonitor->addExclusionRoute(
              IPAddress(config.m_serverIpv4AddrIn)) && endpointRoutesReady;
    }
    if (!config.m_serverIpv6AddrIn.isEmpty()) {
      endpointRoutesReady =
          m_routeMonitor->addExclusionRoute(
              IPAddress(config.m_serverIpv6AddrIn)) && endpointRoutesReady;
    }
  }
  if (!endpointRoutesReady) {
    logger.error() << "Failed to install peer endpoint exclusion route";
    return false;
  }

  QString reply = m_tunnel.uapiCommand(message);
  const int err = amnezia::uapi::errnoFromReply(reply);
  if (err != 0) {
    logger.error() << "Peer configuration failed with UAPI errno:" << err;
    return false;
  }
  m_configuredPeers.insert(config.m_serverPublicKey);
  return true;
}

bool WireguardUtilsWindows::deletePeer(const InterfaceConfig& config) {
  QByteArray publicKey =
      QByteArray::fromBase64(qPrintable(config.m_serverPublicKey));

  // The final peer's blocking policy must remain until deleteInterface()
  // stops the tunnel and atomically transitions the kill switch. During a
  // server switch another configured peer keeps the policy active, so the old
  // peer generation can be removed after its UAPI removal succeeds.
  const bool deferFirewallRemoval = m_configuredPeers.size() <= 1;

  QString message;
  QTextStream out(&message);
  out << "set=1\n";
  out << "public_key=" << QString(publicKey.toHex()) << "\n";
  out << "remove=true\n";

  QString reply = m_tunnel.uapiCommand(message);
  const int err = amnezia::uapi::errnoFromReply(reply);
  if (err != 0) {
    logger.error() << "Peer deletion failed with UAPI errno:" << err;
    return false;
  }

  // Clear exclusion routes only after native peer removal succeeds. If UAPI
  // fails, the route monitor retains ownership for a later cleanup.
  bool endpointRoutesClean = true;
  if (m_routeMonitor && config.m_hopType != InterfaceConfig::MultiHopExit) {
    if (!config.m_serverIpv4AddrIn.isEmpty()) {
      endpointRoutesClean =
          m_routeMonitor->deleteExclusionRoute(
              IPAddress(config.m_serverIpv4AddrIn)) && endpointRoutesClean;
    }
    if (!config.m_serverIpv6AddrIn.isEmpty()) {
      endpointRoutesClean =
          m_routeMonitor->deleteExclusionRoute(
              IPAddress(config.m_serverIpv6AddrIn)) && endpointRoutesClean;
    }
  }
  if (!endpointRoutesClean) {
    logger.error() << "Failed to remove peer endpoint exclusion route";
    return false;
  }

  if (!deferFirewallRemoval &&
      (m_firewall == nullptr ||
       !m_firewall->disablePeerTraffic(config.m_serverPublicKey))) {
    logger.error() << "Failed to disable Windows firewall peer policy";
    return false;
  }
  m_configuredPeers.remove(config.m_serverPublicKey);
  return true;
}

void WireguardUtilsWindows::buildMibForwardRow(const IPAddress& prefix,
                                               void* row) {
  MIB_IPFORWARD_ROW2* entry = (MIB_IPFORWARD_ROW2*)row;
  InitializeIpForwardEntry(entry);

  // Populate the next hop
  if (prefix.type() == QAbstractSocket::IPv6Protocol) {
    InetPtonA(AF_INET6, qPrintable(prefix.address().toString()),
              &entry->DestinationPrefix.Prefix.Ipv6.sin6_addr);
    entry->DestinationPrefix.Prefix.Ipv6.sin6_family = AF_INET6;
    entry->DestinationPrefix.PrefixLength = prefix.prefixLength();
  } else {
    InetPtonA(AF_INET, qPrintable(prefix.address().toString()),
              &entry->DestinationPrefix.Prefix.Ipv4.sin_addr);
    entry->DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
    entry->DestinationPrefix.PrefixLength = prefix.prefixLength();
  }
  entry->InterfaceLuid.Value = m_luid;
  entry->NextHop.si_family = entry->DestinationPrefix.Prefix.si_family;

  // Set the rest of the flags for a static route.
  entry->ValidLifetime = 0xffffffff;
  entry->PreferredLifetime = 0xffffffff;
  entry->Metric = 0;
  entry->Protocol = MIB_IPPROTO_NETMGMT;
  entry->Loopback = false;
  entry->AutoconfigureAddress = false;
  entry->Publish = false;
  entry->Immortal = false;
  entry->Age = 0;
}

bool WireguardUtilsWindows::updateRoutePrefix(const IPAddress& prefix) {
  if (m_routeMonitor && (prefix.prefixLength() == 0)) {
    // If we are setting up a default route, instruct the route monitor to
    // capture traffic to all non-excluded destinations
    m_routeMonitor->setDetaultRouteCapture(true);
  }
  // Build the route
  
  MIB_IPFORWARD_ROW2 entry;
  buildMibForwardRow(prefix, &entry);

  // Install the route
  DWORD result = CreateIpForwardEntry2(&entry);
  if (result == ERROR_OBJECT_ALREADY_EXISTS) {
    return true;
  }

  // Case for ipv6 route with disabled ipv6
  if (prefix.address().protocol() == QAbstractSocket::IPv6Protocol
      && result == ERROR_NOT_FOUND) {
    return true;
  }

  if (result != NO_ERROR) {
    logger.error() << "Failed to create route to"
                   << prefix.toString()
                   << "result:" << result;
  }
  return result == NO_ERROR;
}

bool WireguardUtilsWindows::deleteRoutePrefix(const IPAddress& prefix) {
  bool capturedRoutesClean = true;
  if (m_routeMonitor && (prefix.prefixLength() == 0)) {
    // Deactivate the route capture feature.
    capturedRoutesClean = m_routeMonitor->setDetaultRouteCapture(false);
  }
  // Build the route
  
  MIB_IPFORWARD_ROW2 entry;
  buildMibForwardRow(prefix, &entry);

  // Install the route
  DWORD result = DeleteIpForwardEntry2(&entry);
  if (!isSuccessfulRouteDelete(result)) {
    logger.error() << "Failed to delete route to"
                   << prefix.toString()
                   << "result:" << result;
  }
  return capturedRoutesClean && isSuccessfulRouteDelete(result);
}

bool WireguardUtilsWindows::addExclusionRoute(const IPAddress& prefix) {
  return m_routeMonitor->addExclusionRoute(prefix);
}

bool WireguardUtilsWindows::deleteExclusionRoute(const IPAddress& prefix) {
  return m_routeMonitor->deleteExclusionRoute(prefix);
}

amnezia::exclusionPolicy::Result WireguardUtilsWindows::replaceExclusionPolicy(
    const InterfaceConfig& before, const InterfaceConfig& after) {
  if (!m_routeMonitor || !m_tunnel.isRunning() ||
      m_configuredPeers.size() != 1 ||
      !m_configuredPeers.contains(before.m_serverPublicKey) ||
      before.m_serverPublicKey != after.m_serverPublicKey ||
      before.m_killSwitchEnabled != after.m_killSwitchEnabled) {
    return amnezia::exclusionPolicy::Unsupported;
  }
  const auto addRoute = [&](const QString& route) {
    return m_routeMonitor->addExclusionRoute(IPAddress(route));
  };
  const auto removeRoute = [&](const QString& route) {
    return m_routeMonitor->deleteExclusionRoute(IPAddress(route));
  };
  if (!before.m_killSwitchEnabled) {
    // KillSwitch-off has no deny fence. Keep this transition route-only and
    // preserve old bypasses until every new route has native readback.
    return amnezia::exclusionPolicy::replaceRoutes(
        before.m_excludedAddresses, after.m_excludedAddresses, addRoute,
        removeRoute);
  }
  if (!m_firewall) {
    return amnezia::exclusionPolicy::Unsupported;
  }
  return amnezia::exclusionPolicy::replace(
      before.m_excludedAddresses, after.m_excludedAddresses,
      [&](const QStringList& exclusions) {
        InterfaceConfig guarded = before;
        guarded.m_excludedAddresses = exclusions;
        return m_firewall->enablePeerTraffic(guarded);
      },
      addRoute, removeRoute);
}

bool WireguardUtilsWindows::excludeLocalNetworks(
    const QList<IPAddress>& addresses) {
  // If the interface isn't up then something went horribly wrong.
  Q_ASSERT(m_routeMonitor);
  // For each destination - attempt to exclude it from the VPN tunnel.
  bool result = true;
  for (const IPAddress& prefix : addresses) {
    if (!m_routeMonitor->addExclusionRoute(prefix)) {
      result = false;
    }
  }
  // Permit LAN traffic through the firewall.
  if (!m_firewall->enableLanBypass(addresses)) {
    result = false;
  }

  return result;
}
