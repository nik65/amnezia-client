/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "daemonlocalserverconnection.h"

#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QLocalSocket>

#include "daemon.h"
#include "ipc.h"
#include "leakdetector.h"
#include "logger.h"

namespace {
Logger logger("DaemonLocalServerConnection");
}

DaemonLocalServerConnection::DaemonLocalServerConnection(QObject* parent,
                                                         QLocalSocket* socket)
    : QObject(parent) {
  MZ_COUNT_CTOR(DaemonLocalServerConnection);

  logger.debug() << "Connection created";

  Q_ASSERT(socket);
  m_socket = socket;
  m_socket->setReadBufferSize(amnezia::MaximumDaemonFrameSize + 1);

  m_incompleteFrameTimer.setSingleShot(true);
  m_incompleteFrameTimer.setInterval(5000);
  connect(&m_incompleteFrameTimer, &QTimer::timeout, this, [this] {
    logger.warning() << "Closing daemon IPC connection before a complete frame was received";
    m_socket->abort();
  });
  // The active-connection cap must not be exhaustible by authenticated peers
  // that connect and then remain completely silent.
  m_incompleteFrameTimer.start();

  connect(m_socket, &QLocalSocket::readyRead, this,
          &DaemonLocalServerConnection::readData);

  Daemon* daemon = Daemon::instance();
  connect(daemon, &Daemon::connected, this,
          &DaemonLocalServerConnection::connected);
  connect(daemon, &Daemon::disconnected, this,
          &DaemonLocalServerConnection::disconnected);
  connect(daemon, &Daemon::backendFailure, this,
          &DaemonLocalServerConnection::backendFailure);
}

DaemonLocalServerConnection::~DaemonLocalServerConnection() {
  MZ_COUNT_DTOR(DaemonLocalServerConnection);

  logger.debug() << "Connection released";
}

void DaemonLocalServerConnection::readData() {
  logger.debug() << "Read Data";

  Q_ASSERT(m_socket);

  while (m_socket->bytesAvailable() > 0) {
    const qsizetype remaining = amnezia::MaximumDaemonFrameSize + 1 - m_buffer.size();
    if (remaining <= 0) {
      logger.warning() << "Closing daemon IPC connection with an oversized frame";
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
        logger.warning() << "Closing daemon IPC connection with an oversized frame";
        m_socket->abort();
        return;
      }
      if (frameState == amnezia::DaemonFrameState::NeedMoreData) {
        break;
      }

      command = command.trimmed();
      if (!command.isEmpty()) {
        if (parseCommand(command)) {
          m_receivedValidFrame = true;
        }
        if (m_socket->state() != QLocalSocket::ConnectedState) {
          return;
        }
      }
    }
  }

  if (m_buffer.isEmpty() && m_receivedValidFrame) {
    m_incompleteFrameTimer.stop();
  } else if (!m_incompleteFrameTimer.isActive()) {
    m_incompleteFrameTimer.start();
  }
}

bool DaemonLocalServerConnection::parseCommand(const QByteArray& data) {
  QJsonDocument json = QJsonDocument::fromJson(data);
  if (!json.isObject()) {
    logger.error() << "Invalid input";
    m_socket->abort();
    return false;
  }

  QJsonObject obj = json.object();
  const QJsonValue protocolVersion = obj.value(amnezia::DaemonProtocolVersionKey);
  if (!protocolVersion.isDouble()
      || protocolVersion.toInt(-1) != amnezia::PrivilegedIpcProtocolVersion) {
    logger.warning() << "Unsupported daemon IPC protocol version";
    m_socket->abort();
    return false;
  }
  QJsonValue typeValue = obj.value("type");
  if (!typeValue.isString()) {
    logger.warning() << "No daemon command type. Closing connection.";
    m_socket->abort();
    return false;
  }
  QString type = typeValue.toString();

  logger.debug() << "Command received:" << type;

  if (type == "activate") {
    InterfaceConfig config;
    if (!Daemon::parseConfig(obj, config)) {
      logger.error() << "Invalid configuration";
      emit disconnected();
      return false;
    }

    if (!Daemon::instance()->activate(config)) {
      logger.error() << "Failed to activate the interface";
      emit disconnected();
    }
    return true;
  }

  if (type == "deactivate") {
    Daemon::instance()->deactivate(true);
    return true;
  }

  if (type == "status") {
    QJsonObject obj = Daemon::instance()->getStatus();
    obj.insert("type", "status");
    write(obj);
    return true;
  }

  if (type == "logs") {
    QJsonObject obj;
    obj.insert("type", "logs");
    const qsizetype maximumLogCharacters = amnezia::MaximumDaemonFrameSize / 4;
    obj.insert("logs", Daemon::instance()->logs().right(maximumLogCharacters).replace("\n", "|"));
    write(obj);
    return true;
  }

  if (type == "cleanlogs") {
    Daemon::instance()->cleanLogs();
    return true;
  }

  logger.warning() << "Invalid command:" << type;
  m_socket->abort();
  return false;
}

void DaemonLocalServerConnection::connected(const QString& pubkey) {
  QJsonObject obj;
  obj.insert("type", "connected");
  obj.insert("pubkey", QJsonValue(pubkey));
  write(obj);
}

void DaemonLocalServerConnection::disconnected() {
  QJsonObject obj;
  obj.insert("type", "disconnected");
  write(obj);
}

void DaemonLocalServerConnection::backendFailure(DaemonError err) {
  QJsonObject obj;
  obj.insert("type", "backendFailure");
  obj.insert("errorCode", static_cast<int>(err));
  write(obj);
}

void DaemonLocalServerConnection::write(const QJsonObject& obj) {
  QJsonObject versioned = obj;
  versioned.insert(amnezia::DaemonProtocolVersionKey, amnezia::PrivilegedIpcProtocolVersion);
  const QByteArray frame = QJsonDocument(versioned).toJson(QJsonDocument::Compact);
  if (frame.size() > amnezia::MaximumDaemonFrameSize) {
    logger.error() << "Refusing to write an oversized daemon IPC frame";
    m_socket->abort();
    return;
  }
  m_socket->write(frame);
  m_socket->write("\n");
}
