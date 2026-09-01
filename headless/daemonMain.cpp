#include <QCoreApplication>
#include <QCommandLineParser>
#include <QDir>
#include <QTextStream>

#include "daemon.h"

#ifndef Q_OS_WIN
#include <QSocketNotifier>
#include <csignal>
#include <sys/signalfd.h>
#include <unistd.h>
#endif

namespace
{

#ifndef Q_OS_WIN
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
    parser.addOption(socketOption);
    parser.addOption(storeOption);
    parser.addOption(configRootOption);
    parser.addOption(requireRootOwnedConfigOption);
    parser.process(application);

    const QString socketPath = parser.value(socketOption);
    const QString storePath = parser.value(storeOption);
    amnezia::headless::Daemon daemon(
        socketPath,
        storePath,
        {},
        parser.value(configRootOption),
        parser.isSet(requireRootOwnedConfigOption));
    QString error;
    if (!daemon.start(&error)) {
        QTextStream(stderr) << "amneziad: failed to start: " << error << Qt::endl;
        return 1;
    }

    QObject::connect(&application, &QCoreApplication::aboutToQuit,
                     &daemon, &amnezia::headless::Daemon::stop);
#ifndef Q_OS_WIN
    installTerminationHandler(application);
#endif

    return application.exec();
}
