#include <QDir>

#include "version.h"
#include "localserver.h"
#include "logger.h"
#include "systemservice.h"
#include "core/utils/utilities.h"

#ifdef Q_OS_WIN
#include <qt_windows.h>

#include "platforms/windows/daemon/windowsdaemontunnel.h"
#include "platforms/windows/daemon/windowsfirewall.h"
#include "platforms/windows/daemon/windowssplittunnel.h"

namespace {
int s_argc = 0;
char** s_argv = nullptr;

constexpr auto CleanupServiceActiveExitCode = 2;

enum class CleanupServiceState {
    StoppedOrMissing,
    Active,
    QueryFailed,
};

CleanupServiceState cleanupServiceState()
{
    constexpr auto serviceName = L"AmneziaVPN-service";

    const SC_HANDLE serviceManager =
        OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (serviceManager == nullptr) {
        qCritical() << "Unable to open SCM before persistent firewall cleanup:"
                    << GetLastError();
        return CleanupServiceState::QueryFailed;
    }

    const SC_HANDLE service =
        OpenServiceW(serviceManager, serviceName, SERVICE_QUERY_STATUS);
    if (service == nullptr) {
        const DWORD error = GetLastError();
        CloseServiceHandle(serviceManager);
        if (error == ERROR_SERVICE_DOES_NOT_EXIST) {
            return CleanupServiceState::StoppedOrMissing;
        }

        qCritical() << "Unable to query the service before persistent firewall cleanup:"
                    << error;
        return CleanupServiceState::QueryFailed;
    }

    SERVICE_STATUS_PROCESS status {};
    DWORD bytesNeeded = 0;
    const bool queried = QueryServiceStatusEx(
        service, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&status),
        sizeof(status), &bytesNeeded) != FALSE;
    const DWORD error = queried ? ERROR_SUCCESS : GetLastError();

    CloseServiceHandle(service);
    CloseServiceHandle(serviceManager);

    if (!queried) {
        qCritical() << "Unable to read the service state before persistent firewall cleanup:"
                    << error;
        return CleanupServiceState::QueryFailed;
    }
    if (status.dwCurrentState != SERVICE_STOPPED) {
        qCritical() << "Refusing persistent firewall cleanup while the service state is"
                    << status.dwCurrentState;
        return CleanupServiceState::Active;
    }

    return CleanupServiceState::StoppedOrMissing;
}
}  // namespace

#endif

int runApplication(int argc, char** argv)
{
    QCoreApplication app(argc,argv);
    Logger::init(true);

#ifdef Q_OS_WIN
    if(argc > 2){
        s_argc = argc;
        s_argv = argv;
        QStringList tokens;
        for (int i = 1; i < argc; ++i) {
            tokens.append(QString(argv[i]));
        }

        if (!tokens.empty() && tokens[0] == "tunneldaemon") {
            WindowsDaemonTunnel *daemon = new WindowsDaemonTunnel();
            daemon->run(tokens);
        }
    }
#endif

    LocalServer localServer;
    return app.exec();

}


int main(int argc, char **argv)
{
    Utils::initializePath(Logger::systemLogDir());

#ifdef Q_OS_WIN
    if (argc == 8 &&
        QString::fromLocal8Bit(argv[1]) ==
            QStringLiteral("split-tunnel-config-helper")) {
        QCoreApplication app(argc, argv);
        Logger::init(true);
        return WindowsSplitTunnel::runConfigurationHelper(
            QString::fromLocal8Bit(argv[2]),
            QString::fromLocal8Bit(argv[3]),
            QString::fromLocal8Bit(argv[4]),
            QString::fromLocal8Bit(argv[5]),
            QString::fromLocal8Bit(argv[6]),
            QString::fromLocal8Bit(argv[7]));
    }
    if (argc == 2 && QString::fromLocal8Bit(argv[1]) == QStringLiteral("cleanup-firewall")) {
        QCoreApplication app(argc, argv);
        Logger::init(true);

        const CleanupServiceState serviceState = cleanupServiceState();
        if (serviceState == CleanupServiceState::Active) {
            return CleanupServiceActiveExitCode;
        }
        if (serviceState == CleanupServiceState::QueryFailed) {
            return EXIT_FAILURE;
        }

        const bool driverRemoved = WindowsSplitTunnel::removeForUninstall();
        const bool firewallRemoved =
            driverRemoved && WindowsFirewall::removePersistentPolicy();
        return firewallRemoved ? EXIT_SUCCESS : EXIT_FAILURE;
    }
#endif

    if (argc >= 2) {
        qInfo() << "Started as console application";
        return runApplication(argc, argv);
    }
    else {
        qInfo() << "Started as system service";
#ifdef Q_OS_WIN
        SystemService systemService(argc, argv);
        return systemService.exec();
#else
    return runApplication(argc, argv);
#endif

    }
}
