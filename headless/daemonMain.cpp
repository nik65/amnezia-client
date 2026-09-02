#include <QCoreApplication>
#include <QCommandLineParser>
#include <QDir>
#include <QTextStream>

#include "daemon.h"

#ifndef Q_OS_WIN
#include <QSocketNotifier>
#include <QTimer>
#include <csignal>
#include <cstdlib>
#include <cstddef>
#include <cstring>
#include <sys/socket.h>
#include <sys/signalfd.h>
#include <sys/un.h>
#include <unistd.h>
#endif

namespace
{

#ifndef Q_OS_WIN
bool notifySystemd(const char *message)
{
    const char *socketPath = std::getenv("NOTIFY_SOCKET");
    if (!socketPath || !*socketPath) return true;
    sockaddr_un address {};
    address.sun_family = AF_UNIX;
    const size_t length = std::strlen(socketPath);
    if (length >= sizeof(address.sun_path)) return false;
    if (socketPath[0] == '@') {
        address.sun_path[0] = '\0';
        std::memcpy(address.sun_path + 1, socketPath + 1, length - 1);
    } else {
        std::memcpy(address.sun_path, socketPath, length + 1);
    }
    const socklen_t addressLength = static_cast<socklen_t>(
            offsetof(sockaddr_un, sun_path) + length + (socketPath[0] == '@' ? 0 : 1));
    const int fd = ::socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return false;
    const ssize_t sent = ::sendto(fd, message, std::strlen(message), MSG_NOSIGNAL,
                                  reinterpret_cast<const sockaddr *>(&address), addressLength);
    ::close(fd);
    return sent == static_cast<ssize_t>(std::strlen(message));
}

QSocketNotifier *installTerminationHandler(QCoreApplication &application)
{
    sigset_t signalSet;
    sigemptyset(&signalSet);
    sigaddset(&signalSet, SIGINT);
    sigaddset(&signalSet, SIGTERM);
    if (sigprocmask(SIG_BLOCK, &signalSet, nullptr) != 0) {
        return nullptr;
    }

    const int signalFd = signalfd(-1, &signalSet, SFD_NONBLOCK | SFD_CLOEXEC);
    if (signalFd < 0) {
        return nullptr;
    }

    auto *notifier = new QSocketNotifier(signalFd, QSocketNotifier::Read, &application);
    QObject::connect(notifier, &QSocketNotifier::activated, &application,
                     [notifier, &application](int) {
                         signalfd_siginfo signalInfo {};
                         if (::read(notifier->socket(), &signalInfo, sizeof(signalInfo))
                             == static_cast<ssize_t>(sizeof(signalInfo))) {
                             application.quit();
                         }
                     });
    QObject::connect(&application, &QCoreApplication::aboutToQuit,
                     [notifier]() {
                         notifier->setEnabled(false);
                         ::close(notifier->socket());
                     });
    return notifier;
}
#endif

} // namespace

int main(int argc, char *argv[])
{
    QCoreApplication application(argc, argv);
    QCoreApplication::setApplicationName(QStringLiteral("amneziad"));
    QCoreApplication::setApplicationVersion(QStringLiteral(AMNEZIA_HEADLESS_VERSION));

    QCommandLineParser parser;
    parser.setApplicationDescription(
        QStringLiteral("Headless AmneziaVPN user daemon"));
    parser.addHelpOption();
    parser.addVersionOption();
    QCommandLineOption socketOption(
        { QStringLiteral("s"), QStringLiteral("socket") },
        QStringLiteral("Unix socket path"), QStringLiteral("path"));
    QCommandLineOption storeOption(
        { QStringLiteral("p"), QStringLiteral("store") },
        QStringLiteral("Profile metadata store path"), QStringLiteral("path"));
    QCommandLineOption configRootOption(
        { QStringLiteral("c"), QStringLiteral("config-root") },
        QStringLiteral("Trusted directory containing VPN configuration files"), QStringLiteral("path"));
    QCommandLineOption requireRootOwnedConfigOption(
        QStringLiteral("require-root-owned-config"),
        QStringLiteral("Require root-owned, non-group/world-writable config files"));
    QCommandLineOption stagingRootOption(
        QStringLiteral("staging-root"),
        QStringLiteral("Writable root for staged full-tunnel VPN configs"), QStringLiteral("path"));
    parser.addOption(socketOption);
    parser.addOption(storeOption);
    parser.addOption(configRootOption);
    parser.addOption(requireRootOwnedConfigOption);
    parser.addOption(stagingRootOption);
    parser.process(application);

    const QString socketPath = parser.value(socketOption);
    const QString storePath = parser.value(storeOption);
    amnezia::headless::Daemon daemon(
        socketPath,
        storePath,
        {},
        parser.value(configRootOption),
        parser.isSet(requireRootOwnedConfigOption),
        nullptr,
        parser.value(stagingRootOption));
    QString error;
    if (!daemon.start(&error)) {
        QTextStream(stderr) << "amneziad: failed to start: " << error << Qt::endl;
        return 1;
    }

#ifndef Q_OS_WIN
    if (!notifySystemd("READY=1")) {
        QTextStream(stderr) << "amneziad: systemd readiness notification failed" << Qt::endl;
        daemon.stop();
        return 1;
    }
    QTimer watchdog;
    watchdog.setInterval(10'000);
    QObject::connect(&watchdog, &QTimer::timeout, &application, [] {
        notifySystemd("WATCHDOG=1");
    });
    watchdog.start();
#endif

    QObject::connect(&application, &QCoreApplication::aboutToQuit,
                     &daemon, &amnezia::headless::Daemon::stop);
#ifndef Q_OS_WIN
    if (!installTerminationHandler(application)) {
        QTextStream(stderr) << "amneziad: failed to install signal handler" << Qt::endl;
        daemon.stop();
        return 1;
    }
#endif

    return application.exec();
}
