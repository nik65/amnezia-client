#include <QtTest>

#include <QDir>
#include <QDateTime>
#include <QFile>
#include <QRegularExpression>
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
    void runBatchReturnsBoundedStderrAndExitCode()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString helperPath = temporaryDirectory.filePath(QStringLiteral("batch-helper"));
        QFile helper(helperPath);
        QVERIFY(helper.open(QIODevice::WriteOnly));
        QVERIFY(helper.write("#!/bin/sh\nprintf 'batch-contract-error\\n' >&2\nexit 17\n") > 0);
        helper.close();
        QVERIFY(QFile::setPermissions(helperPath, QFileDevice::ReadOwner
                                      | QFileDevice::WriteOwner
                                      | QFileDevice::ExeOwner));

        RealCommandRunner runner;
        const CommandResult result = runner.runBatch(helperPath,
                                                     { { QStringLiteral("noop") } });
        QVERIFY(!result.ok);
        QCOMPARE(result.exitCode, 17);
        QVERIFY(result.message.contains(QStringLiteral("batch-contract-error")));
        QVERIFY(result.message.size() <= 2200);
    }

    void runBatchUsesConfiguredRuntimeAndRemovesOwnerOnlyFile()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString markerPath = temporaryDirectory.filePath(QStringLiteral("batch-marker"));
        const QString helperPath = temporaryDirectory.filePath(QStringLiteral("batch-helper"));
        QFile helper(helperPath);
        QVERIFY(helper.open(QIODevice::WriteOnly));
        QVERIFY(helper.write("#!/bin/sh\nprintf '%s\\n' \"$2\" > \"") > 0);
        QVERIFY(helper.write(markerPath.toUtf8()) > 0);
        QVERIFY(helper.write("\"\nstat -c '%a' \"$2\" >> \"") > 0);
        QVERIFY(helper.write(markerPath.toUtf8()) > 0);
        QVERIFY(helper.write("\"\nexit 0\n") > 0);
        helper.close();
        QVERIFY(QFile::setPermissions(helperPath, QFileDevice::ReadOwner
                                      | QFileDevice::WriteOwner
                                      | QFileDevice::ExeOwner));

        RealCommandRunner runner(temporaryDirectory.path());
        const CommandResult result = runner.runBatch(helperPath,
                                                     { { QStringLiteral("noop") } });
        QVERIFY2(result.ok, qPrintable(result.message));
        QFile marker(markerPath);
        QVERIFY(marker.open(QIODevice::ReadOnly));
        const QStringList receipt = QString::fromUtf8(marker.readAll())
                .split(QLatin1Char('\n'), Qt::SkipEmptyParts);
        QCOMPARE(receipt.size(), 2);
        QVERIFY(receipt.constFirst().startsWith(temporaryDirectory.path()));
        QCOMPARE(receipt.constLast(), QStringLiteral("600"));
        QVERIFY(!QFileInfo::exists(receipt.constFirst()));
    }

    void runBatchRejectsInsecureConfiguredRuntime()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        QVERIFY(QFile::setPermissions(temporaryDirectory.path(),
                                      QFileDevice::ReadOwner | QFileDevice::WriteOwner
                                      | QFileDevice::ExeOwner | QFileDevice::WriteGroup));
        RealCommandRunner runner(temporaryDirectory.path());
        const CommandResult result = runner.runBatch(QStringLiteral("/bin/false"),
                                                     { { QStringLiteral("noop") } });
        QVERIFY(!result.ok);
        QVERIFY(result.message.contains(QStringLiteral("configured runtime rejected")));
    }

    void runCapturedReturnsCompleteLargeKernelProbe()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString helperPath = temporaryDirectory.filePath(QStringLiteral("probe-helper"));
        QFile helper(helperPath);
        QVERIFY(helper.open(QIODevice::WriteOnly));
        QVERIFY(helper.write(
                "#!/bin/sh\n"
                "i=1\n"
                "while [ \"$i\" -le 1212 ]; do\n"
                "  priority=$((1000 + i))\n"
                "  printf '%s: from all to 10.8.1.4/32 lookup main\\n' \"$priority\"\n"
                "  i=$((i + 1))\n"
                "done\n") > 0);
        helper.close();
        QVERIFY(QFile::setPermissions(helperPath, QFileDevice::ReadOwner
                                      | QFileDevice::WriteOwner
                                      | QFileDevice::ExeOwner));

        RealCommandRunner runner;
        const CommandResult result = runner.runCaptured(helperPath, {});
        QVERIFY2(result.ok, qPrintable(result.message));
        QVERIFY(result.output.size() > 8192);
        const QStringList lines = result.output.split(QLatin1Char('\n'), Qt::SkipEmptyParts);
        QCOMPARE(lines.size(), 1212);
        const QRegularExpression rulePattern(
                QStringLiteral(R"(^\d+: from all to 10\.8\.1\.4/32 lookup main$)"));
        for (const QString &line : lines) {
            QVERIFY2(rulePattern.match(line).hasMatch(), qPrintable(line));
        }
        QVERIFY(lines.constLast().startsWith(QStringLiteral("2212:")));
    }

    void runCapturedRejectsProbeOutputOverSafeLimit()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString helperPath = temporaryDirectory.filePath(QStringLiteral("oversized-probe-helper"));
        QFile helper(helperPath);
        QVERIFY(helper.open(QIODevice::WriteOnly));
        QVERIFY(helper.write(
                "#!/bin/sh\n"
                "dd if=/dev/zero bs=1048577 count=1 2>/dev/null\n") > 0);
        helper.close();
        QVERIFY(QFile::setPermissions(helperPath, QFileDevice::ReadOwner
                                      | QFileDevice::WriteOwner
                                      | QFileDevice::ExeOwner));

        RealCommandRunner runner;
        const CommandResult result = runner.runCaptured(helperPath, {});
        QVERIFY(!result.ok);
        QCOMPARE(result.message, QStringLiteral("probe output exceeded safe limit"));
        QVERIFY(result.output.isEmpty());
    }

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
        QCOMPARE(result.code, QStringLiteral("config_invalid"));
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
