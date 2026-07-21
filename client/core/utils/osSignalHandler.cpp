#include "osSignalHandler.h"

#include <QCoreApplication>
#include <QMetaObject>
#include <QSocketNotifier>

#include "../amneziaApplication.h"

#include <atomic>
#include <csignal>

#if defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID)
    #include <pthread.h>
    #include <signal.h>
    #include <sys/signalfd.h>
    #include <unistd.h>
#elif defined(Q_OS_MACOS)
    #include <fcntl.h>
    #include <signal.h>
    #include <unistd.h>
#endif

#ifdef Q_OS_WIN
    #include <QAbstractNativeEventFilter>

    #include <windows.h>
#endif

namespace
{

    static bool initialized = false;
    static std::atomic_int receivedTerminationExitCode { 0 };

    static void rememberTerminationSignal(int signalNumber)
    {
        receivedTerminationExitCode.store(128 + signalNumber, std::memory_order_relaxed);
    }

#ifdef Q_OS_WIN
    class WindowsCloseFilter : public QAbstractNativeEventFilter
    {
    public:
        bool nativeEventFilter(const QByteArray &eventType, void *message, qintptr *result) override
        {
            MSG *msg = static_cast<MSG *>(message);

            switch (msg->message) {
            case WM_CLOSE: {
                const HWND active = GetActiveWindow();
                const HWND self = msg->hwnd;
                if (active != self) {
                    AmneziaApplication *app = qobject_cast<AmneziaApplication *>(QCoreApplication::instance());
                    if (app) {
                        QMetaObject::invokeMethod(app, "forceQuit", Qt::QueuedConnection);
                    }
                }
            }
            }
            return false;
        };
    };

    static WindowsCloseFilter *windowsFilter = nullptr;
    static bool consoleControlHandlerInstalled = false;

    static BOOL WINAPI consoleControlHandler(DWORD controlType)
    {
        switch (controlType) {
        case CTRL_C_EVENT:
        case CTRL_BREAK_EVENT:
            rememberTerminationSignal(SIGINT);
            break;
        case CTRL_CLOSE_EVENT:
        case CTRL_LOGOFF_EVENT:
        case CTRL_SHUTDOWN_EVENT:
            rememberTerminationSignal(SIGTERM);
            break;
        default:
            return FALSE;
        }
        QMetaObject::invokeMethod(QCoreApplication::instance(), "quit", Qt::QueuedConnection);
        return TRUE;
    }
#endif

#if defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID)
    static int signalFd = -1;
    static QSocketNotifier *socketNotifier = nullptr;

    static void setupUnixSignalHandler()
    {
        sigset_t set;
        sigemptyset(&set);
        sigaddset(&set, SIGINT);
        sigaddset(&set, SIGTERM);

        pthread_sigmask(SIG_BLOCK, &set, nullptr);

        signalFd = signalfd(-1, &set, SFD_NONBLOCK | SFD_CLOEXEC);
        if (signalFd < 0)
            return;

        socketNotifier = new QSocketNotifier(signalFd, QSocketNotifier::Read, QCoreApplication::instance());

        QObject::connect(socketNotifier, &QSocketNotifier::activated, QCoreApplication::instance(), [](int) {
            signalfd_siginfo fdsi;
            ::read(signalFd, &fdsi, sizeof(fdsi));

            if (fdsi.ssi_signo == SIGINT || fdsi.ssi_signo == SIGTERM) {
                rememberTerminationSignal(static_cast<int>(fdsi.ssi_signo));
                QCoreApplication::quit();
            }
        });
    }
#elif defined(Q_OS_MACOS)
    static int signalPipe[2] = { -1, -1 };
    static QSocketNotifier *socketNotifier = nullptr;

    static void macSignalHandler(int signalNumber)
    {
        if (signalPipe[1] >= 0) {
            const unsigned char ch = static_cast<unsigned char>(signalNumber);
            ::write(signalPipe[1], &ch, sizeof(ch));
        }
    }

    static void setupUnixSignalHandler()
    {
        if (::pipe(signalPipe) != 0)
            return;

        ::fcntl(signalPipe[0], F_SETFL, O_NONBLOCK);
        ::fcntl(signalPipe[1], F_SETFL, O_NONBLOCK);

        socketNotifier = new QSocketNotifier(signalPipe[0], QSocketNotifier::Read, QCoreApplication::instance());

        QObject::connect(socketNotifier, &QSocketNotifier::activated, QCoreApplication::instance(), [](int) {
            unsigned char buf[16] {};
            const ssize_t bytesRead = ::read(signalPipe[0], buf, sizeof(buf));
            if (bytesRead > 0) {
                rememberTerminationSignal(static_cast<int>(buf[bytesRead - 1]));
            }
            QCoreApplication::quit();
        });

        struct sigaction sa {};
        sa.sa_handler = macSignalHandler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;

        sigaction(SIGINT, &sa, nullptr);
        sigaction(SIGTERM, &sa, nullptr);
    }
#endif

    static void cleanupUnixSignalHandler()
    {
#if defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID)
        if (socketNotifier) {
            socketNotifier->setEnabled(false);
            socketNotifier->deleteLater();
            socketNotifier = nullptr;
        }

        if (signalFd >= 0) {
            ::close(signalFd);
            signalFd = -1;
        }

#elif defined(Q_OS_MACOS)
        struct sigaction sa {};
        sa.sa_handler = SIG_DFL;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;
        sigaction(SIGINT, &sa, nullptr);
        sigaction(SIGTERM, &sa, nullptr);

        if (socketNotifier) {
            socketNotifier->setEnabled(false);
            socketNotifier->deleteLater();
            socketNotifier = nullptr;
        }

        if (signalPipe[0] >= 0) {
            ::close(signalPipe[0]);
            signalPipe[0] = -1;
        }

        if (signalPipe[1] >= 0) {
            ::close(signalPipe[1]);
            signalPipe[1] = -1;
        }
#endif

#ifdef Q_OS_WIN
        if (consoleControlHandlerInstalled) {
            SetConsoleCtrlHandler(consoleControlHandler, FALSE);
            consoleControlHandlerInstalled = false;
        }
        if (windowsFilter) {
            QCoreApplication::instance()->removeNativeEventFilter(windowsFilter);
            delete windowsFilter;
            windowsFilter = nullptr;
        }
#endif
    }
}

OsSignalHandler::OsSignalHandler(QObject *parent) : QObject(parent)
{
}

void OsSignalHandler::setup(bool enableConsoleControlHandler)
{
    if (initialized)
        return;

    initialized = true;

#if (defined(Q_OS_LINUX) && !defined(Q_OS_ANDROID)) || defined(Q_OS_MACOS)
    setupUnixSignalHandler();
#endif

#ifdef Q_OS_WIN
    windowsFilter = new WindowsCloseFilter();
    QCoreApplication::instance()->installNativeEventFilter(windowsFilter);
    if (enableConsoleControlHandler) {
        consoleControlHandlerInstalled = SetConsoleCtrlHandler(consoleControlHandler, TRUE) != FALSE;
    }
#else
    Q_UNUSED(enableConsoleControlHandler)
#endif

    QObject::connect(QCoreApplication::instance(), &QCoreApplication::aboutToQuit, [] { cleanupUnixSignalHandler(); });
}

int OsSignalHandler::terminationExitCode()
{
    return receivedTerminationExitCode.load(std::memory_order_relaxed);
}
