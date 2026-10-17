/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "linuxnetworkwatcher.h"

#include <QTimer>

#include "leakdetector.h"
#include "linuxnetworkwatcherworker.h"
#include "logger.h"

namespace {
Logger logger("LinuxNetworkWatcher");
}

LinuxNetworkWatcher::LinuxNetworkWatcher(QObject* parent)
    : NetworkWatcherImpl(parent) {
  MZ_COUNT_CTOR(LinuxNetworkWatcher);

  m_thread.start();
}

LinuxNetworkWatcher::~LinuxNetworkWatcher() {
  MZ_COUNT_DTOR(LinuxNetworkWatcher);

  m_thread.quit();
  m_thread.wait();
  m_worker = nullptr;
}

void LinuxNetworkWatcher::initialize() {
  if (m_initialized) {
    logger.debug() << "initialize ignored: already initialized";
    return;
  }

  logger.debug() << "initialize";

  m_worker = new LinuxNetworkWatcherWorker(&m_thread);
  connect(&m_thread, &QThread::finished, m_worker, &QObject::deleteLater);

  connect(this, &LinuxNetworkWatcher::checkDevicesInThread, m_worker,
          &LinuxNetworkWatcherWorker::checkDevices);

  connect(m_worker, &LinuxNetworkWatcherWorker::unsecuredNetwork, this,
          &LinuxNetworkWatcher::unsecuredNetwork);

  connect(m_worker, &LinuxNetworkWatcherWorker::wakeup, this,
          &NetworkWatcherImpl::wakeup);

  connect(m_worker, &LinuxNetworkWatcherWorker::networkChanged, this,
          [this]() { emit networkChanged(""); });

  // Let's wait a few seconds to allow the UI to be fully loaded and shown.
  // This is not strictly needed, but it's better for user experience because
  // it makes the UI faster to appear, plus it gives a bit of delay between the
  // UI to appear and the first notification.
  QTimer::singleShot(2000, this, [this]() {
    QMetaObject::invokeMethod(m_worker, "initialize", Qt::QueuedConnection);
  });
  m_initialized = true;
}

void LinuxNetworkWatcher::start() {
  logger.debug() << "actived";
  NetworkWatcherImpl::start();
  emit checkDevicesInThread();
}
