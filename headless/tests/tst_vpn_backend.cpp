#include <QtTest>

#include <QDir>
#include <QDateTime>
#include <QFile>
#include <QTemporaryDir>

#include "profileStore.h"
#include "vpnBackend.h"

using namespace amnezia::headless;

namespace
{

class FakeCommandRunner final : public CommandRunner
{
public:
    struct Call
    {
        QString operation;
        QString id;
        QString program;
        QStringList arguments;
    };

    bool isAvailable(const QString &program) const override
    {
        return availablePrograms.contains(program);
    }

    QString resolveExecutable(const QStringList &candidates) const override
    {
        for (const QString &candidate : candidates) {
            if (isAvailable(candidate)) {
                return candidate;
            }
        }
        return {};
    }

    CommandResult run(const QString &program, const QStringList &arguments) override
    {
        calls.append({ QStringLiteral("run"), {}, program, arguments });
        return runResult;
    }

    CommandResult runCaptured(const QString &program,
                              const QStringList &arguments) override
    {
        if ((program == QStringLiteral("wg") || program == QStringLiteral("awg"))
            && arguments.contains(QStringLiteral("latest-handshakes"))) {
            handshakeRequested = true;
            return { true, 0, {}, handshakeOutput.isEmpty()
                ? QStringLiteral("peer %1\n").arg(QDateTime::currentSecsSinceEpoch() - 1)
                : handshakeOutput };
        }
        if ((program == QStringLiteral("wg") || program == QStringLiteral("awg"))
            && arguments.contains(QStringLiteral("showconf"))) {
            configProbeRequested = true;
            return { true, 0, {}, {} };
        }
        if (program == QStringLiteral("ip")
            && arguments.contains(QStringLiteral("addr"))) {
            return { true, 0, {}, QStringLiteral("7: %1    inet 10.8.1.2/32 scope global\n")
                                      .arg(arguments.constLast()) };
        }
        if (program == QStringLiteral("ip")
            && arguments.contains(QStringLiteral("link"))) {
            return { true, 0, {}, QStringLiteral("7: %1: <POINTOPOINT>\n")
                                      .arg(arguments.constLast()) };
        }
        return runResult;
    }

    CommandResult start(const QString &id, const QString &program,
                        const QStringList &arguments) override
    {
        calls.append({ QStringLiteral("start"), id, program, arguments });
        return startResult;
    }

    CommandResult stop(const QString &id) override
    {
        calls.append({ QStringLiteral("stop"), id, {}, {} });
        return stopResult;
    }

    bool isSessionAlive(const QString &) const override
    {
        return sessionAlive;
    }

    QSet<QString> availablePrograms;
    QList<Call> calls;
    bool configProbeRequested = false;
    bool handshakeRequested = false;
    QString handshakeOutput;
    bool sessionAlive = true;
    CommandResult runResult { true, {}, {} };
    CommandResult startResult { true, {}, {} };
    CommandResult stopResult { true, {}, {} };
};

Profile profile(const QString &id, const QString &protocol, const QString &configPath)
{
    return Profile { id, id, protocol, configPath };
}

} // namespace

class VpnBackendTest : public QObject
{
    Q_OBJECT

private slots:
    void wireGuardUsesWgQuickAndDisconnects()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString configPath = temporaryDirectory.filePath(QStringLiteral("work.conf"));
        QFile config(configPath);
        QVERIFY(config.open(QIODevice::WriteOnly));
        config.write("[Interface]\n[Peer]\nPublicKey = peer\n");
        config.close();

        auto runner = std::make_shared<FakeCommandRunner>();
        runner->availablePrograms.insert(QStringLiteral("wg-quick"));
        runner->availablePrograms.insert(QStringLiteral("wg"));
        runner->availablePrograms.insert(QStringLiteral("ip"));
        VpnBackend backend(runner);

        const Profile work = profile(QStringLiteral("work"), QStringLiteral("wireguard"), configPath);
        QVERIFY2(backend.connect(work).ok, qPrintable(backend.lastError().message));
        QVERIFY(backend.interfaceHealthy(QStringLiteral("wg0")));
        QVERIFY(runner->configProbeRequested);
        QVERIFY(!runner->handshakeRequested);
        QVERIFY(backend.sessionHealthyAfterRouting());
        QVERIFY(runner->handshakeRequested);
        QCOMPARE(runner->calls.size(), 1);
        QCOMPARE(runner->calls.constFirst().operation, QStringLiteral("run"));
        QCOMPARE(runner->calls.constFirst().program, QStringLiteral("wg-quick"));
        const QStringList expectedUpArguments {
            QStringLiteral("up"), configPath
        };
        QCOMPARE(runner->calls.constFirst().arguments, expectedUpArguments);
        QCOMPARE(backend.activeProfile(), QStringLiteral("work"));

        QVERIFY2(backend.disconnect().ok, qPrintable(backend.lastError().message));
        QCOMPARE(runner->calls.size(), 2);
        QCOMPARE(runner->calls.constLast().program, QStringLiteral("wg-quick"));
        const QStringList expectedDownArguments {
            QStringLiteral("down"), configPath
        };
        QCOMPARE(runner->calls.constLast().arguments, expectedDownArguments);
        QVERIFY(backend.activeProfile().isEmpty());
    }

    void nativeBackendDoesNotReportConnectedWithoutInterface()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString configPath = temporaryDirectory.filePath(QStringLiteral("work.conf"));
        QFile config(configPath);
        QVERIFY(config.open(QIODevice::WriteOnly));
        config.write("[Interface]\n");
        config.close();

        auto runner = std::make_shared<FakeCommandRunner>();
        runner->availablePrograms.insert(QStringLiteral("wg-quick"));
        VpnBackend backend(runner);
        const BackendResult result = backend.connect(
                profile(QStringLiteral("work"), QStringLiteral("wireguard"), configPath));
        QVERIFY(!result.ok);
        QCOMPARE(result.code, QStringLiteral("backend_not_ready"));
        QVERIFY(backend.activeProfile().isEmpty());
    }

    void amneziaWireGuardResolvesAwgQuickAlias()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString configPath = temporaryDirectory.filePath(QStringLiteral("awg.conf"));
        QFile config(configPath);
        QVERIFY(config.open(QIODevice::WriteOnly));
        config.write("[Interface]\n");
        config.close();

        auto runner = std::make_shared<FakeCommandRunner>();
        runner->availablePrograms.insert(QStringLiteral("awg-quick"));
        runner->availablePrograms.insert(QStringLiteral("awg"));
        runner->availablePrograms.insert(QStringLiteral("ip"));
        VpnBackend backend(runner);

        QVERIFY2(backend.connect(profile(QStringLiteral("awg"), QStringLiteral("amneziawg"), configPath)).ok,
                 qPrintable(backend.lastError().message));
        QCOMPARE(runner->calls.constFirst().program, QStringLiteral("awg-quick"));
    }

    void longRunningProtocolsUseStartAndStop()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString configPath = temporaryDirectory.filePath(QStringLiteral("xray.json"));
        QFile config(configPath);
        QVERIFY(config.open(QIODevice::WriteOnly));
        config.write("{}\n");
        config.close();

        auto runner = std::make_shared<FakeCommandRunner>();
        runner->availablePrograms.insert(QStringLiteral("xray"));
        VpnBackend backend(runner);

        QVERIFY2(backend.connect(profile(QStringLiteral("proxy"), QStringLiteral("xray"), configPath)).ok,
                 qPrintable(backend.lastError().message));
        QCOMPARE(runner->calls.constFirst().operation, QStringLiteral("start"));
        QCOMPARE(runner->calls.constFirst().program, QStringLiteral("xray"));
        const QStringList expectedArguments {
            QStringLiteral("run"), QStringLiteral("-c"), configPath
        };
        QCOMPARE(runner->calls.constFirst().arguments, expectedArguments);
        QVERIFY2(backend.disconnect().ok, qPrintable(backend.lastError().message));
        QCOMPARE(runner->calls.constLast().operation, QStringLiteral("stop"));
        QCOMPARE(runner->calls.constLast().id, QStringLiteral("proxy"));
    }

    void missingBackendDoesNotChangeState()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString configPath = temporaryDirectory.filePath(QStringLiteral("work.conf"));
        QFile config(configPath);
        QVERIFY(config.open(QIODevice::WriteOnly));
        config.close();

        auto runner = std::make_shared<FakeCommandRunner>();
        VpnBackend backend(runner);
        const BackendResult result = backend.connect(
            profile(QStringLiteral("work"), QStringLiteral("wireguard"), configPath));

        QVERIFY(!result.ok);
        QCOMPARE(result.code, QStringLiteral("backend_unavailable"));
        QVERIFY(backend.activeProfile().isEmpty());
        QVERIFY(runner->calls.isEmpty());
    }

    void restrictedConfigRootRejectsOutsideConfig()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString trustedDirectory = temporaryDirectory.filePath(QStringLiteral("profiles"));
        QVERIFY(QDir().mkpath(trustedDirectory));
        const QString outsideConfigPath = temporaryDirectory.filePath(QStringLiteral("outside.conf"));
        QFile config(outsideConfigPath);
        QVERIFY(config.open(QIODevice::WriteOnly));
        config.close();

        auto runner = std::make_shared<FakeCommandRunner>();
        runner->availablePrograms.insert(QStringLiteral("wg-quick"));
        runner->availablePrograms.insert(QStringLiteral("wg"));
        runner->availablePrograms.insert(QStringLiteral("ip"));
        VpnBackend backend(runner, trustedDirectory);
        const BackendResult result = backend.connect(
            profile(QStringLiteral("outside"), QStringLiteral("wireguard"), outsideConfigPath));

        QVERIFY(!result.ok);
        QCOMPARE(result.code, QStringLiteral("config_not_allowed"));
        QVERIFY(runner->calls.isEmpty());
        QVERIFY(backend.activeProfile().isEmpty());
    }

    void allExceptStagesNativeWireGuardWithDefaultAllowedIps()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString configPath = temporaryDirectory.filePath(QStringLiteral("source.conf"));
        QFile config(configPath);
        QVERIFY(config.open(QIODevice::WriteOnly));
        config.write("[Interface]\nPrivateKey = test\n[Peer]\nPublicKey = peer\n"
                     "AllowedIPs = 10.8.1.0/24\n");
        config.close();

        auto runner = std::make_shared<FakeCommandRunner>();
        runner->availablePrograms.insert(QStringLiteral("wg-quick"));
        runner->availablePrograms.insert(QStringLiteral("wg"));
        runner->availablePrograms.insert(QStringLiteral("ip"));
        VpnBackend backend(runner);
        Profile work = profile(QStringLiteral("work"), QStringLiteral("wireguard"), configPath);
        work.interfaceName = QStringLiteral("wg0");
        work.routingMode = QStringLiteral("all-except");
        work.serverRulesUrl = QStringLiteral("http://10.8.1.253:17864/rules.json");

        QVERIFY2(backend.connect(work).ok, qPrintable(backend.lastError().message));
        QCOMPARE(runner->calls.size(), 1);
        const QString stagedPath = runner->calls.constFirst().arguments.at(1);
        QVERIFY(stagedPath != configPath);
        QVERIFY(stagedPath.endsWith(QStringLiteral("wg0.conf")));
        QFile staged(stagedPath);
        QVERIFY(staged.open(QIODevice::ReadOnly));
        QVERIFY(QString::fromUtf8(staged.readAll()).contains(
                QStringLiteral("AllowedIPs = 0.0.0.0/0, ::/0")));
        staged.seek(0);
        QVERIFY(QString::fromUtf8(staged.readAll()).contains(QStringLiteral("Table = off")));

        QVERIFY2(backend.disconnect().ok, qPrintable(backend.lastError().message));
        QCOMPARE(runner->calls.constLast().arguments.at(0), QStringLiteral("down"));
        QCOMPARE(runner->calls.constLast().arguments.at(1), stagedPath);
        QVERIFY(!QFileInfo(QFileInfo(stagedPath).absolutePath()).exists());
    }

    void allExceptRejectsAmbiguousMultiPeerConfigBeforeStartingBackend()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString configPath = temporaryDirectory.filePath(QStringLiteral("source.conf"));
        QFile config(configPath);
        QVERIFY(config.open(QIODevice::WriteOnly));
        config.write("[Interface]\nPrivateKey = test\n"
                     "[Peer]\nPublicKey = peer-a\nAllowedIPs = 10.8.1.0/24\n"
                     "[Peer]\nPublicKey = peer-b\nAllowedIPs = 10.8.2.0/24\n");
        config.close();

        auto runner = std::make_shared<FakeCommandRunner>();
        runner->availablePrograms.insert(QStringLiteral("wg-quick"));
        runner->availablePrograms.insert(QStringLiteral("wg"));
        runner->availablePrograms.insert(QStringLiteral("ip"));
        VpnBackend backend(runner);
        Profile work = profile(QStringLiteral("work"), QStringLiteral("wireguard"), configPath);
        work.routingMode = QStringLiteral("all-except");

        const BackendResult result = backend.connect(work);
        QVERIFY(!result.ok);
        QCOMPARE(result.code, QStringLiteral("config_invalid"));
        QVERIFY(result.message.contains(QStringLiteral("exactly one peer")));
        QVERIFY(runner->calls.isEmpty());
        QVERIFY(backend.activeProfile().isEmpty());
    }

    void healthKeepsIdlePreviouslyHandshakenPeerAlive()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString configPath = temporaryDirectory.filePath(QStringLiteral("source.conf"));
        QFile config(configPath);
        QVERIFY(config.open(QIODevice::WriteOnly));
        config.write("[Interface]\n"
                     "[Peer]\nPublicKey = peer-a\n"
                     "[Peer]\nPublicKey = peer-b\n");
        config.close();

        auto runner = std::make_shared<FakeCommandRunner>();
        runner->availablePrograms.insert(QStringLiteral("wg-quick"));
        runner->availablePrograms.insert(QStringLiteral("wg"));
        runner->availablePrograms.insert(QStringLiteral("ip"));
        VpnBackend backend(runner);
        QVERIFY2(backend.connect(profile(QStringLiteral("work"), QStringLiteral("wireguard"), configPath)).ok,
                 qPrintable(backend.lastError().message));

        runner->handshakeOutput = QStringLiteral("peer-a 1\n");
        QVERIFY(!backend.sessionHealthyAfterRouting());
        runner->handshakeOutput = QStringLiteral("foreign-peer %1\n")
                .arg(QDateTime::currentSecsSinceEpoch() - 1);
        QVERIFY(!backend.sessionHealthyAfterRouting());
        runner->handshakeOutput = QStringLiteral("peer-a 1\npeer-b %1\n")
                .arg(QDateTime::currentSecsSinceEpoch() - 1);
        QVERIFY(backend.sessionHealthyAfterRouting());
        runner->handshakeOutput = QStringLiteral("peer-a 1\npeer-b 1\n");
        QVERIFY(backend.sessionHealthyAfterRouting());
    }

    void xrayImmediateExitIsNotReportedAsConnected()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString configPath = temporaryDirectory.filePath(QStringLiteral("xray.json"));
        QFile config(configPath);
        QVERIFY(config.open(QIODevice::WriteOnly));
        config.write("{}\n");
        config.close();

        auto runner = std::make_shared<FakeCommandRunner>();
        runner->availablePrograms.insert(QStringLiteral("xray"));
        runner->sessionAlive = false;
        VpnBackend backend(runner);
        const BackendResult result = backend.connect(
                profile(QStringLiteral("proxy"), QStringLiteral("xray"), configPath));
        QVERIFY(!result.ok);
        QCOMPARE(result.code, QStringLiteral("backend_not_ready"));
        QVERIFY(backend.activeProfile().isEmpty());
        QCOMPARE(runner->calls.size(), 2);
        QCOMPARE(runner->calls.constLast().operation, QStringLiteral("stop"));
    }

    void healthRejectsEmptyConfiguredPeerSet()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString configPath = temporaryDirectory.filePath(QStringLiteral("source.conf"));
        QFile config(configPath);
        QVERIFY(config.open(QIODevice::WriteOnly));
        config.write("[Interface]\n");
        config.close();

        auto runner = std::make_shared<FakeCommandRunner>();
        runner->availablePrograms.insert(QStringLiteral("wg-quick"));
        runner->availablePrograms.insert(QStringLiteral("wg"));
        runner->availablePrograms.insert(QStringLiteral("ip"));
        VpnBackend backend(runner);
        QVERIFY(backend.connect(profile(QStringLiteral("work"), QStringLiteral("wireguard"), configPath)).ok);
        QVERIFY(!backend.sessionHealthyAfterRouting());
    }

    void allExceptReportsUnwritableStagingRootWithoutStartingBackend()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString configPath = temporaryDirectory.filePath(QStringLiteral("source.conf"));
        QFile config(configPath);
        QVERIFY(config.open(QIODevice::WriteOnly));
        config.write("[Interface]\nPrivateKey = test\n[Peer]\nAllowedIPs = 10.8.1.0/24\n");
        config.close();
        const QString stagingRoot = temporaryDirectory.filePath(QStringLiteral("not-a-directory"));
        QFile stagingFile(stagingRoot);
        QVERIFY(stagingFile.open(QIODevice::WriteOnly));
        stagingFile.close();

        auto runner = std::make_shared<FakeCommandRunner>();
        runner->availablePrograms.insert(QStringLiteral("wg-quick"));
        runner->availablePrograms.insert(QStringLiteral("ip"));
        VpnBackend backend(runner, {}, false, stagingRoot);
        Profile work = profile(QStringLiteral("work"), QStringLiteral("wireguard"), configPath);
        work.interfaceName = QStringLiteral("wg0");
        work.routingMode = QStringLiteral("all-except");
        work.serverRulesUrl = QStringLiteral("http://10.8.1.253:17864/rules.json");

        const BackendResult result = backend.connect(work);
        QVERIFY(!result.ok);
        QCOMPARE(result.code, QStringLiteral("config_invalid"));
        QVERIFY(result.message.contains(QStringLiteral("staging root")));
        QVERIFY(runner->calls.isEmpty());
        QVERIFY(backend.activeProfile().isEmpty());
    }
};

QTEST_MAIN(VpnBackendTest)
#include "tst_vpn_backend.moc"
