#include <QCoreApplication>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QFile>
#include <QFileInfo>
#include <QProcessEnvironment>
#include <QTemporaryDir>
#include <QTextStream>
#include <QTimer>

#include <algorithm>
#include <limits>

#define private public
#include "ipcserverprocess.h"
#undef private

// Compile the production implementation into this focused harness so the native
// handle checks and bounded-buffer logic are exercised without a privileged service.
#include "../../../ipc/ipcserverprocess.cpp"

QString Utils::openVpnExecPath()
{
    return QString::fromUtf8(IPC_PROCESS_TEST_HELPER_PATH);
}

QString Utils::wireguardExecPath()
{
    return QString::fromUtf8(IPC_PROCESS_TEST_HELPER_PATH);
}

QString Utils::certUtilPath()
{
    return QString::fromUtf8(IPC_PROCESS_TEST_HELPER_PATH);
}

QString Utils::tun2socksPath()
{
    return QString::fromUtf8(IPC_PROCESS_TEST_HELPER_PATH);
}

namespace {
class TestRunner
{
public:
    void check(bool condition, const char *expression, int line)
    {
        ++m_assertions;
        if (!condition) {
            ++m_failures;
            QTextStream(stderr) << "FAIL line " << line << ": " << expression << Qt::endl;
        }
    }

    void skip(const QString &reason)
    {
        ++m_skips;
        QTextStream(stdout) << "SKIP: " << reason << Qt::endl;
    }

    int finish() const
    {
        QTextStream stream(m_failures == 0 ? stdout : stderr);
        stream << (m_failures == 0 ? "PASS" : "FAIL") << ": " << m_assertions
               << " assertions, " << m_failures << " failures, " << m_skips << " skips"
               << Qt::endl;
        return m_failures == 0 ? 0 : 1;
    }

private:
    int m_assertions = 0;
    int m_failures = 0;
    int m_skips = 0;
};

QStringList tun2SocksArguments(const QString &device)
{
    return { QStringLiteral("-device"), device, QStringLiteral("-proxy"),
             QStringLiteral("socks5://user:password@127.0.0.1:1080") };
}

QByteArray consumeStandardOutput(IpcServerProcess &process, TestRunner &runner)
{
    QByteArray output;
    for (;;) {
        const QByteArray chunk = process.readAll();
        runner.check(chunk.size() <= amnezia::MaximumProcessOutputChunk,
                     "chunk.size() <= amnezia::MaximumProcessOutputChunk", __LINE__);
        if (chunk.isEmpty()) {
            break;
        }
        output.append(chunk);
    }
    return output;
}

QByteArray consumeStandardError(IpcServerProcess &process, TestRunner &runner)
{
    QByteArray output;
    for (;;) {
        const QByteArray chunk = process.readAllStandardError();
        runner.check(chunk.size() <= amnezia::MaximumProcessOutputChunk,
                     "chunk.size() <= amnezia::MaximumProcessOutputChunk", __LINE__);
        if (chunk.isEmpty()) {
            break;
        }
        output.append(chunk);
    }
    return output;
}
}

#define CHECK(expression) runner.check((expression), #expression, __LINE__)

int main(int argc, char *argv[])
{
    QCoreApplication application(argc, argv);
    TestRunner runner;

    const QProcessEnvironment environment = trustedProcessEnvironment();
    CHECK(environment.contains(QStringLiteral("PATH")));
    CHECK(!environment.contains(QStringLiteral("LD_PRELOAD")));
    CHECK(!environment.contains(QStringLiteral("DYLD_INSERT_LIBRARIES")));
    CHECK(!environment.contains(QStringLiteral("PYTHONPATH")));
    CHECK(!environment.contains(QStringLiteral("BASH_ENV")));
#ifdef Q_OS_WIN
    CHECK(environment.contains(QStringLiteral("SystemRoot")));
    CHECK(environment.contains(QStringLiteral("COMSPEC")));
    CHECK(environment.contains(QStringLiteral("TEMP")));
#else
    CHECK(environment.value(QStringLiteral("HOME")) == QStringLiteral("/"));
    CHECK(environment.value(QStringLiteral("TMPDIR")) == QStringLiteral("/tmp"));
#endif

    QByteArray ring(3 * 1024 * 1024, 'A');
    appendBounded(ring, QByteArray(3 * 1024 * 1024, 'B'));
    CHECK(ring.size() == MaximumBufferedProcessOutput);
    CHECK(ring.left(1024 * 1024) == QByteArray(1024 * 1024, 'A'));
    CHECK(ring.mid(1024 * 1024) == QByteArray(3 * 1024 * 1024, 'B'));
    appendBounded(ring, QByteArray(5 * 1024 * 1024, 'C'));
    CHECK(ring == QByteArray(MaximumBufferedProcessOutput, 'C'));

    QTemporaryDir temporaryDirectory;
    CHECK(temporaryDirectory.isValid());
    const QString regularPath = temporaryDirectory.filePath(QStringLiteral("input.bin"));
    {
        QFile regular(regularPath);
        CHECK(regular.open(QIODevice::WriteOnly));
        CHECK(regular.write("safe-input") == 10);
    }

    QByteArray content;
    QString error;
    CHECK(readValidatedRegularFile(regularPath, 1024, content, error));
    CHECK(content == QByteArrayLiteral("safe-input"));
    CHECK(!readValidatedRegularFile(temporaryDirectory.path(), 1024, content, error));

    const QString oversizedPath = temporaryDirectory.filePath(QStringLiteral("oversized.bin"));
    {
        QFile oversized(oversizedPath);
        CHECK(oversized.open(QIODevice::WriteOnly));
        CHECK(oversized.write(QByteArray(1025, 'X')) == 1025);
    }
    CHECK(!readValidatedRegularFile(oversizedPath, 1024, content, error));

    const QString linkPath = temporaryDirectory.filePath(QStringLiteral("input-link.bin"));
#ifdef Q_OS_WIN
    constexpr DWORD allowUnprivilegedSymlink = 0x2;
    if (CreateSymbolicLinkW(reinterpret_cast<LPCWSTR>(linkPath.utf16()),
                            reinterpret_cast<LPCWSTR>(regularPath.utf16()),
                            allowUnprivilegedSymlink)) {
        CHECK(!readValidatedRegularFile(linkPath, 1024, content, error));
    } else {
        runner.skip(QStringLiteral("Windows symbolic-link creation is unavailable"));
    }
#else
    CHECK(::symlink(QFile::encodeName(regularPath).constData(),
                    QFile::encodeName(linkPath).constData()) == 0);
    CHECK(!readValidatedRegularFile(linkPath, 1024, content, error));

    const QString fifoPath = temporaryDirectory.filePath(QStringLiteral("input.fifo"));
    CHECK(::mkfifo(QFile::encodeName(fifoPath).constData(), 0600) == 0);
    QElapsedTimer fifoTimer;
    fifoTimer.start();
    CHECK(!readValidatedRegularFile(fifoPath, 1024, content, error));
    CHECK(fifoTimer.elapsed() < 500);
#endif

    IpcServerProcess stagingProcess;
    QString stagedPath;
    CHECK(stagingProcess.stageInputFile(regularPath, 1024, false, stagedPath, error));
    QFile staged(stagedPath);
    CHECK(staged.open(QIODevice::ReadOnly));
    CHECK(staged.readAll() == QByteArrayLiteral("safe-input"));

    IpcServerProcess waitProcess;
    waitProcess.setProgram(amnezia::PermittedProcess::Tun2Socks);
    waitProcess.setArguments(tun2SocksArguments(QStringLiteral("tun://wait")));
    waitProcess.start();
    CHECK(waitProcess.waitForStarted());
    QElapsedTimer waitTimer;
    waitTimer.start();
    CHECK(!waitProcess.waitForFinished(-1));
    CHECK(waitTimer.elapsed() < 250);
    waitTimer.restart();
    CHECK(!waitProcess.waitForFinished(std::numeric_limits<int>::max()));
    CHECK(waitTimer.elapsed() < 1500);
    waitProcess.kill();
    CHECK(waitProcess.waitForFinished());

    IpcServerProcess outputProcess;
    int stdoutSignals = 0;
    int stderrSignals = 0;
    bool outputFinished = false;
    QEventLoop outputLoop;
    QObject::connect(&outputProcess, &IpcServerProcess::readyReadStandardOutput,
                     [&stdoutSignals]() { ++stdoutSignals; });
    QObject::connect(&outputProcess, &IpcServerProcess::readyReadStandardError,
                     [&stderrSignals]() { ++stderrSignals; });
    QObject::connect(&outputProcess, &IpcServerProcess::finished,
                     [&outputFinished, &outputLoop]() {
                         outputFinished = true;
                         outputLoop.quit();
                     });
    QTimer::singleShot(10000, &outputLoop, &QEventLoop::quit);
    outputProcess.setProgram(amnezia::PermittedProcess::Tun2Socks);
    outputProcess.setArguments(tun2SocksArguments(QStringLiteral("tun://output")));
    outputProcess.start();
    outputLoop.exec();
    CHECK(outputFinished);
    CHECK(stdoutSignals > 0);
    CHECK(stderrSignals > 0);

    const QByteArray standardOutput = consumeStandardOutput(outputProcess, runner);
    const QByteArray standardError = consumeStandardError(outputProcess, runner);
    CHECK(standardOutput.size() == MaximumBufferedProcessOutput);
    CHECK(standardError.size() == MaximumBufferedProcessOutput);
    CHECK(standardOutput == QByteArray(MaximumBufferedProcessOutput, 'O'));
    CHECK(standardError == QByteArray(MaximumBufferedProcessOutput, 'E'));

    return runner.finish();
}
