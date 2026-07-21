#include <QDebug>
#include <QTimer>
#include <libssh/libssh.h>

#include "amneziaApplication.h"
#include "core/utils/osSignalHandler.h"
#include "core/utils/migrations.h"
#include "version.h"

#ifdef Q_OS_WIN
    #include "Windows.h"
#endif

#if defined(Q_OS_IOS)
    #include "platforms/ios/QtAppDelegate-C-Interface.h"
#endif

#if !defined(Q_OS_ANDROID) && !defined(Q_OS_IOS) && !defined(MACOS_NE)
bool isAnotherInstanceRunning()
{
    if (AmneziaApplication::isTrustedPrimaryRunning(500)) {
        qWarning() << "AmneziaVPN is already running";
        return true;
    }
    return false;
}
#endif

#if !defined(Q_OS_ANDROID) && !defined(Q_OS_IOS)
bool isPublishBundledUpdatesOnceCommand(int argc, char *argv[])
{
    // This mode intentionally runs without the UI singleton. Keep that bypass
    // canonical and unambiguous: a token used as another option's value, after
    // `--`, or mixed with startup arguments must never disable Core ownership.
    return argc == 2
            && QString::fromLocal8Bit(argv[1])
                    == QStringLiteral("--publish-bundled-updates-once");
}
#endif

int main(int argc, char *argv[])
{
    const amnezia::operatorMode::CommandParseResult operatorArguments =
            amnezia::operatorMode::parseArguments(argc, argv);
    const bool operatorInvocation = operatorArguments.hasOperatorArguments;
#if !defined(Q_OS_ANDROID) && !defined(Q_OS_IOS)
    const bool publishBundledUpdatesOnce = isPublishBundledUpdatesOnceCommand(argc, argv);
#else
    const bool publishBundledUpdatesOnce = false;
#endif

#ifdef Q_OS_WIN
    AllowSetForegroundWindow(ASFW_ANY);
    if (operatorArguments.request.type == amnezia::operatorMode::CommandType::Watch) {
        // The GUI-subsystem binary is not attached to the invoking terminal by
        // default. Attach before installing the console control handler so
        // Ctrl+C is delivered without replacing redirected stdout/stderr.
        AttachConsole(ATTACH_PARENT_PROCESS);
    }
#endif

#ifdef Q_OS_ANDROID
    // QTBUG-95974 QTBUG-95764 QTBUG-102168
    qputenv("QT_ANDROID_DISABLE_ACCESSIBILITY", "1");
    qputenv("ANDROID_OPENSSL_SUFFIX", "_3");
#endif

#if defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID)
    // Local operator diagnostics must also work from a TTY on headless hosts.
    // Keep an explicitly selected QPA backend intact, but avoid requiring an
    // X11/Wayland session merely to construct the application object.
    if (operatorInvocation && !qEnvironmentVariableIsSet("QT_QPA_PLATFORM")) {
        qputenv("QT_QPA_PLATFORM", "offscreen");
    }
#endif

    // QApplication is allowed to consume and rewrite argc/argv. Pass the one
    // immutable pre-construction classification into every later mode decision
    // so Qt options cannot turn an operator invocation into an unlocked UI.
    AmneziaApplication app(argc, argv, operatorArguments, publishBundledUpdatesOnce);
    OsSignalHandler::setup(
            operatorArguments.request.type == amnezia::operatorMode::CommandType::Watch);

    int operatorExitCode = 0;
    if (AmneziaApplication::tryForwardOperatorCommand(operatorArguments, operatorExitCode)) {
        return operatorExitCode;
    }

#if !defined(Q_OS_ANDROID) && !defined(Q_OS_IOS)
    if (!operatorInvocation && publishBundledUpdatesOnce
        && !app.hasCoreOwnership()) {
        qCritical() << "Bundled update publishing requires exclusive access to Amnezia settings";
        return 1;
    }
#ifdef MACOS_NE
    if (!operatorInvocation && !publishBundledUpdatesOnce
        && !app.hasCoreOwnership()) {
        // The Network Extension build has no local operator endpoint, but it
        // still owns the same QSettings/update state and must fail closed when
        // another process already owns Core.
        qCritical() << "Unable to acquire authoritative Amnezia application ownership";
        return 1;
    }
#else
    if (!operatorInvocation && !publishBundledUpdatesOnce && isAnotherInstanceRunning()) {
        QTimer::singleShot(1000, &app, [&]() { app.quit(); });
        return app.exec();
    }
    if (!operatorInvocation && !publishBundledUpdatesOnce) {
        if (!app.startLocalServer()) {
            // The endpoint probe is advisory, while the settings-global lock
            // acquired in the constructor is authoritative. A cross-path race
            // loser may be unable to authenticate the winner's path-scoped
            // endpoint; it still exits before any shared settings migration or
            // Core/update initialization.
            if (isAnotherInstanceRunning()) {
                QTimer::singleShot(1000, &app, [&]() { app.quit(); });
                return app.exec();
            }
            qCritical() << "Unable to acquire authoritative Amnezia application ownership";
            return 1;
        }
    }
#endif
#endif

    // Operator commands are intentionally isolated from normal application
    // startup. In particular, read-only diagnostics must not migrate settings,
    // initialize SSH, auto-connect, start uploaders, or register a primary UI
    // instance merely because no GUI instance is currently running.
    if (!operatorInvocation) {
        Migrations migrationsManager;
        migrationsManager.doMigrations();

        ssh_init();
        QObject::connect(&app, &QCoreApplication::aboutToQuit, []() {
            ssh_finalize();
        });
    }

// Allow to raise app window if secondary instance launched
#ifdef Q_OS_WIN
    AllowSetForegroundWindow(0);
#endif

    if (!operatorInvocation) {
        app.registerTypes();
    }

    app.setApplicationName(APPLICATION_NAME);
    app.setOrganizationName(ORGANIZATION_NAME);
    app.setApplicationDisplayName(APPLICATION_NAME);

    if (!operatorInvocation) {
        app.loadFonts();
    }

    bool doExec = app.parseCommands();

    if (doExec) {
        app.init();

        qInfo().noquote() << QString("Started %1 version %2 %3").arg(APPLICATION_NAME, APP_VERSION, GIT_COMMIT_HASH);
        qInfo().noquote() << QString("%1 (%2)").arg(QSysInfo::prettyProductName(), QSysInfo::currentCpuArchitecture());

        const int eventLoopExitCode = app.exec();
        if (operatorArguments.request.type == amnezia::operatorMode::CommandType::Watch
            && eventLoopExitCode == 0 && OsSignalHandler::terminationExitCode() > 0) {
            return OsSignalHandler::terminationExitCode();
        }
        return eventLoopExitCode;
    }
    return app.commandExitCode();
}
