/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
#include "localsocketcontroller.h"

#include <stdint.h>

#include <QCoreApplication>
#include <QDateTime>
#include <QDebug>
#include <QDir>
#include <QFileInfo>
#include <QHostAddress>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QLocalSocket>
#include <QObject>
#include <QStandardPaths>
#include <QStringList>
#include <QTimer>

#include "leakdetector.h"
#include "logger.h"
#include "daemon/daemonerrors.h"
#include "ipc.h"
#include "localpeerauthentication.h"
#include "windowsprivilegedpipe.h"
#include "version.h"

#include "core/utils/protocolEnum.h"
#include "core/utils/routeModes.h"
#include "core/protocols/protocolUtils.h"
#include "core/utils/constants/configKeys.h"
#include "core/utils/constants/protocolConstants.h"

// How many times do we try to reconnect.
constexpr int MAX_CONNECTION_RETRY = 10;

// How long do we wait between one try and the next one.
constexpr int CONNECTION_RETRY_TIMER_MSEC = 500;

namespace {
Logger logger("LocalSocketController");

bool canUseIpFamily(const QString& value, bool serverIpv6Available) {
  const QHostAddress address(value.trimmed());
  return serverIpv6Available || address.protocol() != QAbstractSocket::IPv6Protocol;
}
}

LocalSocketController::LocalSocketController() {
  MZ_COUNT_CTOR(LocalSocketController);

  m_socket = new QLocalSocket(this);
  m_socket->setReadBufferSize(amnezia::MaximumDaemonFrameSize + 1);
  connect(m_socket, &QLocalSocket::connected, this,
          &LocalSocketController::daemonConnected);
  connect(m_socket, &QLocalSocket::disconnected, this,
          [&] { errorOccurred(QLocalSocket::PeerClosedError); });
  connect(m_socket, &QLocalSocket::errorOccurred, this,
          &LocalSocketController::errorOccurred);
  connect(m_socket, &QLocalSocket::readyRead, this,
          &LocalSocketController::readData);

  m_initializingTimer.setSingleShot(true);
  connect(&m_initializingTimer, &QTimer::timeout, this,
          &LocalSocketController::initializeInternal);

  m_incompleteFrameTimer.setSingleShot(true);
  m_incompleteFrameTimer.setInterval(5000);
  connect(&m_incompleteFrameTimer, &QTimer::timeout, this, [&] {
    logger.error() << "Daemon IPC response frame timed out";
    m_socket->abort();
  });
}

LocalSocketController::~LocalSocketController() {
  MZ_COUNT_DTOR(LocalSocketController);
}

void LocalSocketController::errorOccurred(
    QLocalSocket::LocalSocketError error) {
  logger.error() << "Error occurred:" << error;

  if (m_daemonState == eInitializing) {
    if (m_initializingRetry++ < MAX_CONNECTION_RETRY) {
      m_initializingTimer.start(CONNECTION_RETRY_TIMER_MSEC);
      return;
    }

    emit initialized(false, false, QDateTime());
  }

  qCritical() << "ControllerError";
  disconnectInternal();
}

void LocalSocketController::disconnectInternal() {
  // We're still eReady as the Deamon is alive
  // and can make a new connection.
  m_daemonState = eReady;
  m_initializingRetry = 0;
  m_initializingTimer.stop();
  emit disconnected();
}

void LocalSocketController::initialize(const Device* device, const Keys* keys) {
  logger.debug() << "Initializing";

  Q_UNUSED(device);
  Q_UNUSED(keys);

  Q_ASSERT(m_daemonState == eUnknown);
  m_initializingRetry = 0;

  initializeInternal();
}

void LocalSocketController::initializeInternal() {
  m_daemonState = eInitializing;

  const QString path = amnezia::getDaemonServiceUrl();

  logger.debug() << "Connecting to:" << path;
#ifdef Q_OS_WIN
  QString connectionError;
  if (!amnezia::ipc::connectWindowsPrivilegedPipe(
          m_socket, path, CONNECTION_RETRY_TIMER_MSEC, &connectionError)) {
    logger.warning() << "Unable to connect hardened daemon IPC:" << connectionError;
    errorOccurred(QLocalSocket::ConnectionRefusedError);
    return;
  }
  // setSocketDescriptor adopts an already-connected HANDLE but intentionally
  // does not synthesize QLocalSocket::connected().
  daemonConnected();
#else
  m_socket->connectToServer(path);
#endif
}

void LocalSocketController::daemonConnected() {
  logger.debug() << "Daemon connected";
  Q_ASSERT(m_daemonState == eInitializing);

  QString authorizationError;
  if (!amnezia::ipc::authorizePrivilegedServer(
          m_socket, amnezia::ipc::installedServiceExecutablePath(),
          QStringLiteral(SERVICE_NAME), nullptr, &authorizationError)) {
    logger.error() << "Rejected untrusted VPN daemon:" << authorizationError;
    m_socket->abort();
    return;
  }
  checkStatus();
}

void LocalSocketController::activate(const QJsonObject &rawConfig) {
  QString protocolName = rawConfig.value("protocol").toString();

  int splitTunnelType = rawConfig.value("splitTunnelType").toInt();
  QJsonArray splitTunnelSites = rawConfig.value("splitTunnelSites").toArray();

  int appSplitTunnelType = rawConfig.value(amnezia::configKey::appSplitTunnelType).toInt();
  QJsonArray splitTunnelApps = rawConfig.value(amnezia::configKey::splitTunnelApps).toArray();
  QJsonArray allowedDns = rawConfig.value(amnezia::configKey::allowedDnsServers).toArray();

  QJsonObject wgConfig = rawConfig.value(protocolName + "_config_data").toObject();
  const bool serverIpv6Available = !rawConfig.contains(amnezia::configKey::serverIpv6Available)
      || rawConfig.value(amnezia::configKey::serverIpv6Available).toBool();

  QJsonObject json;
  json.insert("type", "activate");
  //  json.insert("hopindex", QJsonValue((double)hop.m_hopindex));
  json.insert("privateKey", wgConfig.value(amnezia::configKey::clientPrivKey));
  json.insert("deviceIpv4Address", wgConfig.value(amnezia::configKey::clientIp));
  m_deviceIpv4 = wgConfig.value(amnezia::configKey::clientIp).toString();

  // set up IPv6 unique-local-address, ULA, with "fd00::/8" prefix, not globally routable.
  // this will be default IPv6 gateway, OS recognizes that IPv6 link is local and switches to IPv4.
  // Otherwise some OSes (Linux) try IPv6 forever and hang.
  // https://en.wikipedia.org/wiki/Unique_local_address (RFC 4193)
  // https://man7.org/linux/man-pages/man5/gai.conf.5.html

  // simply "dead::1" is globally-routable, don't use it
  json.insert("deviceIpv6Address", "fd58:baa6:dead::1");

  json.insert("serverPublicKey", wgConfig.value(amnezia::configKey::serverPubKey));
  json.insert("serverPskKey", wgConfig.value(amnezia::configKey::pskKey));
  json.insert("serverIpv4AddrIn", wgConfig.value(amnezia::configKey::hostName));
  //  json.insert("serverIpv6AddrIn", QJsonValue(hop.m_server.ipv6AddrIn()));
  json.insert("deviceMTU", wgConfig.value(amnezia::configKey::mtu));

  json.insert("serverPort", wgConfig.value(amnezia::configKey::port).toInt());
  json.insert("serverIpv4Gateway", wgConfig.value(amnezia::configKey::hostName));
  //  json.insert("serverIpv6Gateway", QJsonValue(hop.m_server.ipv6Gateway()));

  if (canUseIpFamily(rawConfig.value(amnezia::configKey::dns1).toString(), serverIpv6Available)) {
    json.insert("primaryDnsServer", rawConfig.value(amnezia::configKey::dns1));
  }
  if (wgConfig.contains(amnezia::configKey::persistentKeepAlive)) {
    json.insert("persistentKeepalive",
                wgConfig.value(amnezia::configKey::persistentKeepAlive).toString());
  }

  // We don't use secondary DNS if primary DNS is AmneziaDNS
  if (!rawConfig.value(amnezia::configKey::dns1).toString().
    contains(amnezia::protocols::dns::amneziaDnsIp)
      && canUseIpFamily(rawConfig.value(amnezia::configKey::dns2).toString(), serverIpv6Available)) {
    json.insert("secondaryDnsServer", rawConfig.value(amnezia::configKey::dns2));
  }

  QJsonArray jsAllowedIPAddesses;
  auto appendAllowedIpRange = [&jsAllowedIPAddesses, serverIpv6Available](const QString& rawIpRange) {
    QString ipRange = rawIpRange.trimmed();
    if (ipRange.isEmpty()) {
      return;
    }

    QStringList ipRangeParts = ipRange.split('/');
    const QHostAddress address(ipRangeParts.at(0));
    const bool isIpv6 = address.protocol() == QAbstractSocket::IPv6Protocol;
    if (isIpv6 && !serverIpv6Available) {
      logger.warning() << "Skipping IPv6 allowed IP because server IPv6 egress is unavailable" << ipRange;
      return;
    }
    if (address.protocol() == QAbstractSocket::UnknownNetworkLayerProtocol) {
      logger.warning() << "Skipping invalid allowed IP range" << ipRange;
      return;
    }

    QJsonObject range;
    range.insert("address", ipRangeParts.at(0));
    if (ipRangeParts.size() > 1) {
      range.insert("range", atoi(ipRangeParts.at(1).toLocal8Bit()));
    } else {
      range.insert("range", isIpv6 ? 128 : 32);
    }
    range.insert("isIpv6", isIpv6);
    jsAllowedIPAddesses.append(range);
  };

  const bool allowedIpsMissing = !wgConfig.contains(amnezia::configKey::allowedIps);
  QJsonArray plainAllowedIP = wgConfig.value(amnezia::configKey::allowedIps).toArray();
  bool hasDefaultIpv4Route = allowedIpsMissing;
  bool hasDefaultIpv6Route = serverIpv6Available && allowedIpsMissing;
  for (const auto &allowedIpValue : plainAllowedIP) {
    const QString allowedIp = allowedIpValue.toString().trimmed();
    hasDefaultIpv4Route = hasDefaultIpv4Route || allowedIp == QStringLiteral("0.0.0.0/0");
    hasDefaultIpv6Route = hasDefaultIpv6Route || (serverIpv6Available && allowedIp == QStringLiteral("::/0"));
  }
  const bool hasDefaultAllowedRoute = hasDefaultIpv4Route || hasDefaultIpv6Route;
  const bool appSplitTunnelAllowsGlobalBlock = appSplitTunnelType == amnezia::AppsRouteMode::VpnAllApps;
  json.insert("blockIpv6Traffic", !serverIpv6Available && appSplitTunnelAllowsGlobalBlock
      && hasDefaultIpv4Route && (splitTunnelType == 0 || splitTunnelType == 2));

  if (!hasDefaultAllowedRoute && !plainAllowedIP.isEmpty()) {
    // Use AllowedIP list from WG config because of higher priority
    for (auto v : plainAllowedIP) {
      appendAllowedIpRange(v.toString());
    }
  } else {

    // Use APP split tunnel
      if (splitTunnelType == 0 || splitTunnelType == 2) {
        if (hasDefaultIpv4Route) {
          QJsonObject range_ipv4;
          range_ipv4.insert("address", "0.0.0.0");
          range_ipv4.insert("range", 0);
          range_ipv4.insert("isIpv6", false);
          jsAllowedIPAddesses.append(range_ipv4);
        }

        if (hasDefaultIpv6Route) {
          QJsonObject range_ipv6;
          range_ipv6.insert("address", "::");
          range_ipv6.insert("range", 0);
          range_ipv6.insert("isIpv6", true);
          jsAllowedIPAddesses.append(range_ipv6);
        }
      }

      if (splitTunnelType == 1) {
          for (auto v : splitTunnelSites) {
              appendAllowedIpRange(v.toString());
          }
      }
  }

  json.insert("allowedIPAddressRanges", jsAllowedIPAddesses);

  QJsonArray jsExcludedAddresses;
  jsExcludedAddresses.append(wgConfig.value(amnezia::configKey::hostName));
  if (splitTunnelType == 2) {
    for (auto v : splitTunnelSites) {
          QString ipRange = v.toString();
          jsExcludedAddresses.append(ipRange);
      }
  }

  json.insert("excludedAddresses", jsExcludedAddresses);

  json.insert("vpnDisabledApps", splitTunnelApps);

  QJsonArray filteredAllowedDns;
  for (const QJsonValue& dnsValue : allowedDns) {
    if (canUseIpFamily(dnsValue.toString(), serverIpv6Available)) {
      filteredAllowedDns.append(dnsValue);
    }
  }
  json.insert("allowedDnsServers", filteredAllowedDns);

  json.insert(amnezia::configKey::killSwitchOption, rawConfig.value(amnezia::configKey::killSwitchOption));

  const QStringList awgProtocolKeys = amnezia::configKey::awgProtocolKeys();

  for (const QString &key : awgProtocolKeys) {
    const QJsonValue value = wgConfig.value(key);
    if (value.isString() && !value.toString().isEmpty()) {
      json.insert(key, value);
    }
  }

  write(json);
}

void LocalSocketController::deactivate() {
  logger.debug() << "Deactivating";

  if (m_daemonState != eReady) {
    logger.debug() << "No disconnect, controller is not ready";
    emit disconnected();
    return;
  }

  QJsonObject json;
  json.insert("type", "deactivate");
  write(json);
  emit disconnected();
}

void LocalSocketController::checkStatus() {
  logger.debug() << "Check status";

  if (m_daemonState == eReady || m_daemonState == eInitializing) {
    Q_ASSERT(m_socket);

    QJsonObject json;
    json.insert("type", "status");
    write(json);
  }
}

void LocalSocketController::getBackendLogs(
    std::function<void(const QString&)>&& a_callback) {
  logger.debug() << "Backend logs";

  if (m_logCallback) {
    m_logCallback("");
    m_logCallback = nullptr;
  }

  if (m_daemonState != eReady) {
    std::function<void(const QString&)> callback = a_callback;
    callback("");
    return;
  }

  m_logCallback = std::move(a_callback);

  QJsonObject json;
  json.insert("type", "logs");
  write(json);
}

void LocalSocketController::cleanupBackendLogs() {
  logger.debug() << "Cleanup logs";

  if (m_logCallback) {
    m_logCallback("");
    m_logCallback = nullptr;
  }

  if (m_daemonState != eReady) {
    return;
  }

  QJsonObject json;
  json.insert("type", "cleanlogs");
  write(json);
}

void LocalSocketController::readData() {
  logger.debug() << "Reading";

  Q_ASSERT(m_socket);
  Q_ASSERT(m_daemonState == eInitializing || m_daemonState == eReady);
  while (m_socket->bytesAvailable() > 0) {
    const qsizetype remaining = amnezia::MaximumDaemonFrameSize + 1 - m_buffer.size();
    if (remaining <= 0) {
      logger.error() << "Daemon IPC response exceeded the frame limit";
      m_socket->abort();
      return;
    }
    const QByteArray input = m_socket->read(remaining);
    if (input.isEmpty()) {
      break;
    }
    m_buffer.append(input);

    while (true) {
      QByteArray command;
      const amnezia::DaemonFrameState frameState = amnezia::takeDaemonFrame(m_buffer, command);
      if (frameState == amnezia::DaemonFrameState::TooLarge) {
        logger.error() << "Daemon IPC response exceeded the frame limit";
        m_socket->abort();
        return;
      }
      if (frameState == amnezia::DaemonFrameState::NeedMoreData) {
        break;
      }

      command = command.trimmed();
      if (!command.isEmpty()) {
        parseCommand(command);
        if (m_socket->state() != QLocalSocket::ConnectedState) {
          return;
        }
      }
    }
  }

  if (m_buffer.isEmpty()) {
    m_incompleteFrameTimer.stop();
  } else if (!m_incompleteFrameTimer.isActive()) {
    m_incompleteFrameTimer.start();
  }
}

void LocalSocketController::parseCommand(const QByteArray& command) {
  QJsonDocument json = QJsonDocument::fromJson(command);
  if (!json.isObject()) {
    logger.error() << "Invalid JSON - object expected";
    m_socket->abort();
    return;
  }

  QJsonObject obj = json.object();
  const QJsonValue protocolVersion = obj.value(amnezia::DaemonProtocolVersionKey);
  if (!protocolVersion.isDouble()
      || protocolVersion.toInt(-1) != amnezia::PrivilegedIpcProtocolVersion) {
    logger.error() << "Daemon IPC protocol version mismatch";
    m_socket->abort();
    return;
  }
  QJsonValue typeValue = obj.value("type");
  if (!typeValue.isString()) {
    logger.error() << "Invalid JSON - no type";
    m_socket->abort();
    return;
  }
  QString type = typeValue.toString();

  logger.debug() << "Parse command:" << type;

  if (m_daemonState == eInitializing && type == "status") {
    m_daemonState = eReady;

    QJsonValue connected = obj.value("connected");
    if (!connected.isBool()) {
      logger.error() << "Invalid JSON for status - connected expected";
      return;
    }

    QDateTime datetime;
    if (connected.toBool()) {
      QJsonValue date = obj.value("date");
      if (!date.isString()) {
        logger.error() << "Invalid JSON for status - date expected";
        return;
      }

      datetime = QDateTime::fromString(date.toString());
      if (!datetime.isValid()) {
        logger.error() << "Invalid JSON for status - date is invalid";
        return;
      }
    }

    emit initialized(true, connected.toBool(), datetime);
    return;
  }

  if (m_daemonState != eReady) {
    logger.error() << "Unexpected command";
    m_socket->abort();
    return;
  }

  if (type == "status") {

    QJsonValue serverIpv4Gateway = obj.value("serverIpv4Gateway");
    if (!serverIpv4Gateway.isString()) {
      logger.error() << "Unexpected serverIpv4Gateway value";
      return;
    }

    QJsonValue deviceIpv4Address = obj.value("deviceIpv4Address");
    if (!deviceIpv4Address.isString()) {
      logger.error() << "Unexpected deviceIpv4Address value";
      return;
    }

    QJsonValue txBytes = obj.value("txBytes");
    if (!txBytes.isDouble()) {
      logger.error() << "Unexpected txBytes value";
      return;
    }

    QJsonValue rxBytes = obj.value("rxBytes");
    if (!rxBytes.isDouble()) {
      logger.error() << "Unexpected rxBytes value";
      return;
    }

    emit statusUpdated(serverIpv4Gateway.toString(),
                       deviceIpv4Address.toString(), txBytes.toDouble(),
                       rxBytes.toDouble());
    return;
  }

  if (type == "disconnected") {
    disconnectInternal();
    return;
  }

  if (type == "connected") {
    QJsonValue pubkey = obj.value("pubkey");
    if (!pubkey.isString()) {
      logger.error() << "Unexpected pubkey value";
      return;
    }

    logger.debug() << "Handshake completed with:"
                   << pubkey.toString();

    checkStatus();

    emit statusUpdated("", m_deviceIpv4, 0, 0);

    emit connected(pubkey.toString());
    return;
  }

  if (type == "backendFailure") {
    if (!obj.contains("errorCode")) {
      // report a generic error if we dont know what it is.
      logger.error() << "generic backend failure error";
      // REPORTERROR(ErrorHandler::ControllerError, "controller");
      return;
    }
    auto errorCode = static_cast<uint8_t>(obj["errorCode"].toInt());
    if (errorCode >= (uint8_t)DaemonError::DAEMON_ERROR_MAX) {
      // Also report a generic error if the code is invalid.
      logger.error() << "invalid backend failure error code";
      // REPORTERROR(ErrorHandler::ControllerError, "controller");
      return;
    }
    switch (static_cast<DaemonError>(errorCode)) {
      case DaemonError::ERROR_NONE:
        [[fallthrough]];
      case DaemonError::ERROR_FATAL:
        logger.error() << "generic backend failure error (fatal or error none)";
        // REPORTERROR(ErrorHandler::ControllerError, "controller");
        break;
      case DaemonError::ERROR_SPLIT_TUNNEL_INIT_FAILURE:
        [[fallthrough]];
      case DaemonError::ERROR_SPLIT_TUNNEL_START_FAILURE:
        [[fallthrough]];
      case DaemonError::ERROR_SPLIT_TUNNEL_EXCLUDE_FAILURE:
        logger.error() << "split tunnel backend failure error";
        //REPORTERROR(ErrorHandler::SplitTunnelError, "controller");
        break;
      case DaemonError::DAEMON_ERROR_MAX:
        // We should not get here.
        Q_ASSERT(false);
        break;
    }
  }

  if (type == "logs") {
    // We don't care if we are not waiting for logs.
    if (!m_logCallback) {
      return;
    }

    QJsonValue logs = obj.value("logs");
    m_logCallback(logs.isString() ? logs.toString().replace("|", "\n")
                                  : QString());
    m_logCallback = nullptr;
    return;
  }

  logger.warning() << "Invalid command received:" << command;
  m_socket->abort();
}

void LocalSocketController::write(const QJsonObject& json) {
  Q_ASSERT(m_socket);
  QJsonObject versioned = json;
  versioned.insert(amnezia::DaemonProtocolVersionKey, amnezia::PrivilegedIpcProtocolVersion);
  const QByteArray frame = QJsonDocument(versioned).toJson(QJsonDocument::Compact);
  if (frame.size() > amnezia::MaximumDaemonFrameSize) {
    logger.error() << "Refusing to write an oversized daemon IPC request";
    m_socket->abort();
    return;
  }
  m_socket->write(frame);
  m_socket->write("\n");
  m_socket->flush();
}
