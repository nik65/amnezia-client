/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "daemonlocalserver.h"

#include <QLocalSocket>
#include <QTimer>

#include "daemonlocalserverconnection.h"
#include "ipc.h"
#include "leakdetector.h"
#include "localpeerauthentication.h"
#include "logger.h"

namespace {
Logger logger("DaemonLocalServer");
}  // namespace

DaemonLocalServer::DaemonLocalServer(QObject* parent) : QObject(parent) {
  MZ_COUNT_CTOR(DaemonLocalServer);
}

DaemonLocalServer::~DaemonLocalServer() { MZ_COUNT_DTOR(DaemonLocalServer); }

bool DaemonLocalServer::initialize() {
  // Unelevated desktop users must be able to reach the root service; OS peer
  // identity is therefore enforced before any JSON bytes are parsed.
#ifndef Q_OS_WIN
  m_server.setSocketOptions(QLocalServer::WorldAccessOption);
#endif
  m_server.setMaxPendingConnections(16);
  m_server.setListenBacklogSize(1);

  QString path = daemonPath();
  logger.debug() << "Server path:" << path;

  QString runtimeError;
  if (!amnezia::ipc::preparePrivilegedIpcRuntime(&runtimeError)
      || !amnezia::ipc::removeStalePrivilegedSocket(path, &runtimeError)) {
    logger.error() << "Failed to prepare daemon IPC:" << runtimeError;
    return false;
  }

  if (!m_server.listen(path)) {
    logger.error() << "Failed to listen the daemon path";
    return false;
  }

  connect(&m_server, &amnezia::ipc::PrivilegedLocalServer::newConnection, [&] {
    logger.debug() << "New connection received";

    if (!m_server.hasPendingConnections()) {
      return;
    }

    QLocalSocket* socket = m_server.nextPendingConnection();
    Q_ASSERT(socket);

    if (m_activeConnections >= 16) {
      logger.warning() << "Rejecting daemon IPC connection: connection limit reached";
      socket->abort();
      socket->deleteLater();
      return;
    }

    QString authorizationError;
    amnezia::ipc::LocalPeerIdentity peerIdentity;
    if (!amnezia::ipc::authorizePrivilegedClient(
            socket, amnezia::ipc::installedClientExecutablePath(), &peerIdentity,
            &authorizationError)) {
      logger.warning() << "Rejected unauthorized daemon IPC connection:"
                       << authorizationError;
      socket->abort();
      socket->deleteLater();
      return;
    }

    DaemonLocalServerConnection* connection =
        new DaemonLocalServerConnection(&m_server, socket);
    auto *firstFrameTimer = new QTimer(connection);
    firstFrameTimer->setSingleShot(true);
    firstFrameTimer->setInterval(5000);
    connect(firstFrameTimer, &QTimer::timeout, socket, [socket] {
      logger.warning() << "Closing daemon IPC connection without a first frame";
      socket->abort();
    });
    connect(socket, &QLocalSocket::readyRead, firstFrameTimer, &QTimer::stop);
    firstFrameTimer->start();
    logger.debug() << "Accepted daemon IPC peer" << peerIdentity.userIdentifier
                   << "session" << peerIdentity.sessionId;
    ++m_activeConnections;
    connect(socket, &QLocalSocket::disconnected, connection,
            [this, connection] {
              --m_activeConnections;
              connection->deleteLater();
            });
  });

  return true;
}

QString DaemonLocalServer::daemonPath() const {
  return amnezia::getDaemonServiceUrl();
}
