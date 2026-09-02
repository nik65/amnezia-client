#include <QtTest>

#include <QFile>
#include <QTemporaryDir>

#include <algorithm>

#include "linuxRouteReconciler.h"
#include "serverRoutingPolicy.h"

using namespace amnezia::headless;

namespace
{

class FakeCommandRunner final : public CommandRunner
{
public:
    struct Call
    {
        QString operation;
        QString program;
        QStringList arguments;
    };

    bool isAvailable(const QString &program) const override
    {
        return program == QStringLiteral("ip");
    }

    QString resolveExecutable(const QStringList &candidates) const override
    {
        return candidates.contains(QStringLiteral("ip")) ? QStringLiteral("ip") : QString();
    }

    CommandResult run(const QString &program, const QStringList &arguments) override
    {
        calls.append({ QStringLiteral("run"), program, arguments });
        if (failAtCall > 0 && calls.size() == failAtCall) {
            failAtCall = -1;
            return { false, 1, QStringLiteral("simulated failure") };
        }
        return runResult;
    }

    CommandResult runCaptured(const QString &program,
                              const QStringList &arguments) override
    {
        ++capturedCalls;
        if (!capturedOutputs.isEmpty()) {
            return { true, 0, {}, capturedOutputs.value(capturedCalls - 1) };
        }
        if (capturedCalls <= 2) {
            return { true, 0, {}, {} };
        }
        const bool ipv6 = arguments.contains(QStringLiteral("-6"));
        return { true, 0, {}, ipv6
            ? QStringLiteral("1100: from all lookup 51821\n")
            : QStringLiteral("1000: to 10.8.1.4 lookup main\n1100: from all lookup 51821\n") };
    }

    CommandResult start(const QString &, const QString &, const QStringList &) override
    {
        return { false, -1, QStringLiteral("not used") };
    }

    CommandResult stop(const QString &) override
    {
        return { false, -1, QStringLiteral("not used") };
    }

    QList<Call> calls;
    CommandResult runResult { true, 0, {} };
    int capturedCalls = 0;
    int failAtCall = -1;
    QStringList capturedOutputs;
};

} // namespace

class ServerRoutingTest : public QObject
{
    Q_OBJECT

private slots:
    void parsesLegacyDirectRoutePolicy()
    {
        const QByteArray payload = R"json({
            "serverExcept": {"10.8.1.0/24": ""}
        })json";
        const ServerRoutingPolicyResult result = ServerRoutingPolicy::parse(payload);
        QVERIFY2(result.ok, qPrintable(result.message));
        QCOMPARE(result.policy.routes, QStringList { QStringLiteral("10.8.1.0/24") });
        QVERIFY(result.policy.unresolvedSites.isEmpty());
        QCOMPARE(result.policy.revision, result.policy.contentHash);
    }

    void preservesServerFallbackRouteForDomain()
    {
        const QByteArray payload = R"json({
            "managedSplitTunnelExceptSourceSites": {"gitea.local": ""},
            "serverExcept": {"gitea.local": "10.8.1.4"}
        })json";
        const ServerRoutingPolicyResult result = ServerRoutingPolicy::parse(payload);
        QVERIFY2(result.ok, qPrintable(result.message));
        QCOMPARE(result.policy.routes, QStringList { QStringLiteral("10.8.1.4") });
        QVERIFY(result.policy.unresolvedSites.isEmpty());
    }

    void acceptsWindowsServerExceptKey()
    {
        const QByteArray payload = R"json({
            "managedSplitTunnelExceptSourceSites": {"gitea.local": ""},
            "server.except": {"gitea.local": "10.8.1.4"}
        })json";
        const ServerRoutingPolicyResult result = ServerRoutingPolicy::parse(payload);
        QVERIFY2(result.ok, qPrintable(result.message));
        QCOMPARE(result.policy.routes, QStringList { QStringLiteral("10.8.1.4") });
        QVERIFY(result.policy.unresolvedSites.isEmpty());
    }

    void rejectsResolvedSiteOutsideSourceSet()
    {
        const QByteArray payload = R"json({
            "managedSplitTunnelExceptSourceSites": {"gitea.local": ""},
            "serverExcept": {"other.local": "10.8.1.4"}
        })json";
        const ServerRoutingPolicyResult result = ServerRoutingPolicy::parse(payload);
        QVERIFY(!result.ok);
        QCOMPARE(result.code, QStringLiteral("invalid_policy"));
    }

    void routeReconcilerAppliesAndClearsOwnedRoutes()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        auto runner = std::make_shared<FakeCommandRunner>();
        LinuxRouteReconciler reconciler(
                runner, temporaryDirectory.filePath(QStringLiteral("routes.json")));

        QVERIFY2(reconciler.apply(
                        QStringLiteral("amn0"), { QStringLiteral("10.8.1.0/24") }).ok,
                 "initial route apply failed");
        QCOMPARE(runner->calls.size(), 1);
        const QStringList initialArguments {
            QStringLiteral("route"), QStringLiteral("replace"),
            QStringLiteral("10.8.1.0/24"), QStringLiteral("dev"),
            QStringLiteral("amn0"), QStringLiteral("metric"), QStringLiteral("1")
        };
        QCOMPARE(runner->calls.constFirst().arguments, initialArguments);

        QVERIFY2(reconciler.apply(
                        QStringLiteral("amn0"), { QStringLiteral("10.8.1.15") }).ok,
                 "route replacement failed");
        QCOMPARE(runner->calls.size(), 3);
        QCOMPARE(runner->calls.at(1).arguments.at(1), QStringLiteral("replace"));
        QCOMPARE(runner->calls.at(2).arguments.at(1), QStringLiteral("del"));

        QVERIFY2(reconciler.clear().ok, "route clear failed");
        QCOMPARE(runner->calls.size(), 4);
        QCOMPARE(runner->calls.constLast().arguments.at(1), QStringLiteral("del"));
        QCOMPARE(reconciler.status().value(QStringLiteral("interface")).toString(), QString());
        QVERIFY(reconciler.status().value(QStringLiteral("routes")).toArray().isEmpty());
    }

    void routeReconcilerAppliesFullTunnelAndServerBypassRules()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        auto runner = std::make_shared<FakeCommandRunner>();
        LinuxRouteReconciler reconciler(
                runner, temporaryDirectory.filePath(QStringLiteral("routes.json")));

        const QStringList bypassRoutes { QStringLiteral("10.8.1.4") };
        QVERIFY2(reconciler.applyAllExcept(QStringLiteral("wg0"), bypassRoutes).ok,
                 "full-tunnel route apply failed");
        QCOMPARE(reconciler.status().value(QStringLiteral("mode")).toString(),
                 QStringLiteral("all-except"));
        const QJsonArray bypassStatus = reconciler.status()
                                                .value(QStringLiteral("bypassRoutes")).toArray();
        QCOMPARE(bypassStatus.size(), 1);
        QCOMPARE(bypassStatus.at(0).toString(), QStringLiteral("10.8.1.4"));

        QVERIFY(runner->calls.size() >= 7);
        const QStringList expectedV4Route {
            QStringLiteral("route"), QStringLiteral("replace"),
            QStringLiteral("0.0.0.0/1"), QStringLiteral("dev"),
            QStringLiteral("wg0"), QStringLiteral("table"), QStringLiteral("51821") };
        const QStringList expectedBypassRule {
            QStringLiteral("rule"), QStringLiteral("add"),
            QStringLiteral("priority"), QStringLiteral("1000"), QStringLiteral("to"),
            QStringLiteral("10.8.1.4"), QStringLiteral("lookup"), QStringLiteral("main") };
        const QStringList expectedFullRule {
            QStringLiteral("rule"), QStringLiteral("add"),
            QStringLiteral("priority"), QStringLiteral("1100"),
            QStringLiteral("lookup"), QStringLiteral("51821") };
        QCOMPARE(runner->calls.at(0).arguments, expectedV4Route);
        QCOMPARE(runner->calls.at(4).arguments, expectedBypassRule);
        QCOMPARE(runner->calls.at(5).arguments, expectedFullRule);

        QVERIFY2(reconciler.clear().ok, "full-tunnel route clear failed");
        QCOMPARE(reconciler.status().value(QStringLiteral("mode")).toString(),
                 QStringLiteral("only-forward"));
        QVERIFY(reconciler.status().value(QStringLiteral("bypassRoutes")).toArray().isEmpty());
        const QStringList expectedBypassDelete {
            QStringLiteral("rule"), QStringLiteral("del"),
            QStringLiteral("priority"), QStringLiteral("1000"), QStringLiteral("to"),
            QStringLiteral("10.8.1.4"), QStringLiteral("lookup"), QStringLiteral("main") };
        QCOMPARE(runner->calls.at(runner->calls.size() - 7).arguments,
                 expectedBypassDelete);
    }

    void foreignRulePrioritiesAreSkippedWithoutForeignMutation()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        auto runner = std::make_shared<FakeCommandRunner>();
        runner->capturedOutputs = {
            QStringLiteral("1000: from all lookup main\n1100: from all lookup main\n"),
            QStringLiteral("1000: from all lookup main\n1100: from all lookup main\n") };
        LinuxRouteReconciler reconciler(
                runner, temporaryDirectory.filePath(QStringLiteral("routes.json")));

        QVERIFY2(reconciler.applyAllExcept(QStringLiteral("wg0"),
                                           { QStringLiteral("10.8.1.4") }).ok,
                 "dynamic priorities should avoid foreign rules");
        QVERIFY(runner->calls.size() >= 7);
        for (const FakeCommandRunner::Call &call : runner->calls) {
            QVERIFY(!call.arguments.contains(QStringLiteral("1000"))
                    || call.arguments.contains(QStringLiteral("1001")));
            QVERIFY(!call.arguments.contains(QStringLiteral("1100"))
                    || call.arguments.contains(QStringLiteral("1101")));
            QVERIFY(!call.arguments.contains(QStringLiteral("del")));
        }
        QCOMPARE(reconciler.status().value(QStringLiteral("bypassRulePriority")).toInt(), 1001);
        QCOMPARE(reconciler.status().value(QStringLiteral("fullRulePriority")).toInt(), 1101);
    }

    void partialRuleFailureRollsBackRoutesAndRules()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        auto runner = std::make_shared<FakeCommandRunner>();
        runner->failAtCall = 6; // full-tunnel IPv4 rule after four routes and bypass rule
        LinuxRouteReconciler reconciler(
                runner, temporaryDirectory.filePath(QStringLiteral("routes.json")));

        const RouteReconcileResult result = reconciler.applyAllExcept(
                QStringLiteral("wg0"), { QStringLiteral("10.8.1.4") });
        QVERIFY(!result.ok);
        QCOMPARE(result.code, QStringLiteral("full_tunnel_rule_conflict"));
        QCOMPARE(reconciler.status().value(QStringLiteral("mode")).toString(),
                 QStringLiteral("only-forward"));
        QVERIFY(std::any_of(runner->calls.cbegin(), runner->calls.cend(), [](const auto &call) {
            return call.arguments.contains(QStringLiteral("del"))
                && call.arguments.contains(QStringLiteral("0.0.0.0/1"));
        }));
        QVERIFY(std::any_of(runner->calls.cbegin(), runner->calls.cend(), [](const auto &call) {
            return call.arguments.contains(QStringLiteral("del"))
                && call.arguments.contains(QStringLiteral("1000"));
        }));
    }

    void ownedPrioritiesReloadAndMissingKernelRuleIsRecreated()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString statePath = temporaryDirectory.filePath(QStringLiteral("routes.json"));
        auto firstRunner = std::make_shared<FakeCommandRunner>();
        LinuxRouteReconciler first(firstRunner, statePath);
        QVERIFY(first.applyAllExcept(QStringLiteral("wg0"),
                                     { QStringLiteral("10.8.1.4") }).ok);

        auto secondRunner = std::make_shared<FakeCommandRunner>();
        secondRunner->capturedOutputs = {
            QStringLiteral("1000: to 10.8.1.4 lookup main\n1100: from all lookup 51821\n"),
            QString() };
        LinuxRouteReconciler second(secondRunner, statePath);
        QVERIFY(second.applyAllExcept(QStringLiteral("wg0"),
                                      { QStringLiteral("10.8.1.4") }).ok);
        QVERIFY(std::any_of(secondRunner->calls.cbegin(), secondRunner->calls.cend(),
                            [](const auto &call) {
            return call.arguments.contains(QStringLiteral("-6"))
                && call.arguments.contains(QStringLiteral("add"))
                && call.arguments.contains(QStringLiteral("1100"));
        }));
        QCOMPARE(second.status().value(QStringLiteral("fullRulePriority")).toInt(), 1100);
    }

    void fullTunnelNeverTouchesUnderlayTable501()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        auto runner = std::make_shared<FakeCommandRunner>();
        LinuxRouteReconciler reconciler(
                runner, temporaryDirectory.filePath(QStringLiteral("routes.json")));
        QVERIFY(reconciler.applyAllExcept(QStringLiteral("wg0"), {}).ok);
        for (const FakeCommandRunner::Call &call : runner->calls) {
            QVERIFY(!call.arguments.contains(QStringLiteral("501")));
        }
    }
};

QTEST_MAIN(ServerRoutingTest)
#include "tst_server_routing.moc"
