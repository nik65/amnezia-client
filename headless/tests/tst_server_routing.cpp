#include <QtTest>

#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTemporaryDir>

#include <algorithm>

#include "linuxRouteReconciler.h"
#include "headlessRoutingController.h"
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
        return (program == QStringLiteral("ip") && ipAvailable)
            || (program == QStringLiteral("resolvectl") && resolvectlAvailable);
    }

    QString resolveExecutable(const QStringList &candidates) const override
    {
        if (candidates.contains(QStringLiteral("ip")) && ipAvailable) return QStringLiteral("ip");
        if (candidates.contains(QStringLiteral("resolvectl")) && resolvectlAvailable) {
            return QStringLiteral("resolvectl");
        }
        return QString();
    }

    CommandResult run(const QString &program, const QStringList &arguments) override
    {
        calls.append({ QStringLiteral("run"), program, arguments });
        if (failAtCall > 0 && calls.size() == failAtCall) {
            failAtCall = -1;
            return { false, 1, QStringLiteral("simulated failure") };
        }
        if (arguments.contains(QStringLiteral("table"))
            && arguments.contains(QStringLiteral("51821"))) {
            if (arguments.contains(QStringLiteral("replace"))) fullTunnelInstalled = true;
            if (arguments.contains(QStringLiteral("del"))) fullTunnelInstalled = false;
        }
        return runResult;
    }

    CommandResult runCaptured(const QString &program,
                              const QStringList &arguments) override
    {
        ++capturedCalls;
        if (program == QStringLiteral("ip")
            && arguments.endsWith(QStringLiteral("main"))) {
            return { true, 0, {}, mainRouteOutput };
        }
        if (!capturedOutputs.isEmpty()) {
            return { true, 0, {}, capturedOutputs.value(capturedCalls - 1) };
        }
        if (capturedCalls <= 2) {
            return { true, 0, {}, {} };
        }
        if (!fullTunnelInstalled) {
            return { true, 0, {}, {} };
        }
        if (arguments.contains(QStringLiteral("route"))) {
            const bool ipv6 = arguments.contains(QStringLiteral("-6"));
            return { true, 0, {}, ipv6
                ? QStringLiteral("::/1 dev wg0 proto 186\n8000::/1 dev wg0 proto 186\n")
                : QStringLiteral("0.0.0.0/1 dev wg0 proto 186\n128.0.0.0/1 dev wg0 proto 186\n") };
        }
        return { true, 0, {},
            capturedCalls > 4
                ? QStringLiteral("1000: to 10.8.1.4 lookup main\n1100: from all lookup 51821\n")
                : QString() };
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
    QString mainRouteOutput;
    bool fullTunnelInstalled = false;
    bool ipAvailable = true;
    bool resolvectlAvailable = true;
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

    void preservesPreviousDomainResolutionWhenLookupFails()
    {
        const QByteArray payload = R"json({
            "managedSplitTunnelExceptSourceSites": {"does-not-exist.invalid": ""},
            "serverExcept": {"does-not-exist.invalid": ""}
        })json";
        const ServerRoutingPolicyResult parsed = ServerRoutingPolicy::parse(payload);
        QVERIFY2(parsed.ok, qPrintable(parsed.message));
        const ServerRoutingPolicyResult resolved = ServerRoutingPolicy::resolve(
                parsed.policy, 50,
                QJsonObject { { QStringLiteral("does-not-exist.invalid"), QStringLiteral("10.8.1.4") } });
        QVERIFY2(resolved.ok, qPrintable(resolved.message));
        QVERIFY(resolved.policy.routes.contains(QStringLiteral("10.8.1.4")));
        QCOMPARE(resolved.policy.resolvedSites.value(QStringLiteral("does-not-exist.invalid")).toString(),
                 QStringLiteral("10.8.1.4"));
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
            QStringLiteral("amn0"), QStringLiteral("proto"), QStringLiteral("187"),
            QStringLiteral("metric"), QStringLiteral("1")
        };
        QCOMPARE(runner->calls.constFirst().arguments, initialArguments);

        runner->mainRouteOutput = QStringLiteral("10.8.1.0/24 dev amn0 proto 187 metric 1\n");
        QVERIFY2(reconciler.apply(
                        QStringLiteral("amn0"), { QStringLiteral("10.8.1.15") }).ok,
                 "route replacement failed");
        QCOMPARE(runner->calls.size(), 3);
        QCOMPARE(runner->calls.at(1).arguments.at(1), QStringLiteral("replace"));
        QCOMPARE(runner->calls.at(2).arguments.at(1), QStringLiteral("del"));

        runner->mainRouteOutput = QStringLiteral("10.8.1.15/32 dev amn0 proto 187 metric 1\n");
        QVERIFY2(reconciler.clear().ok, "route clear failed");
        QCOMPARE(runner->calls.size(), 3);
        QCOMPARE(runner->calls.constLast().arguments.at(1), QStringLiteral("del"));
        QCOMPARE(reconciler.status().value(QStringLiteral("interface")).toString(), QString());
        QVERIFY(reconciler.status().value(QStringLiteral("routes")).toArray().isEmpty());
    }

    void foreignMainRouteIsRejectedBeforeMutation()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        auto runner = std::make_shared<FakeCommandRunner>();
        runner->mainRouteOutput = QStringLiteral("10.8.1.0/24 dev amn0 proto 99 metric 1\n");
        LinuxRouteReconciler reconciler(
                runner, temporaryDirectory.filePath(QStringLiteral("routes.json")));
        const RouteReconcileResult result = reconciler.apply(
                QStringLiteral("amn0"), { QStringLiteral("10.8.1.0/24") });
        QVERIFY(!result.ok);
        QCOMPARE(result.code, QStringLiteral("only_forward_route_conflict"));
        QVERIFY(runner->calls.isEmpty());
    }

    void unfinishedMutationIntentFailsClosedAtStartup()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString statePath = temporaryDirectory.filePath(QStringLiteral("routes.json"));
        QFile intent(statePath + QStringLiteral(".mutation-intent"));
        QVERIFY(intent.open(QIODevice::WriteOnly));
        QVERIFY(intent.write("{\"version\":1,\"operation\":\"only-forward\"}") > 0);
        intent.close();
        auto runner = std::make_shared<FakeCommandRunner>();
        LinuxRouteReconciler reconciler(runner, statePath);
        QVERIFY(reconciler.status().value(QStringLiteral("recoveryRequired")).toBool());
        QVERIFY(runner->calls.isEmpty());
    }

    void startupFailsClosedWhenIpIsUnavailable()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        auto runner = std::make_shared<FakeCommandRunner>();
        runner->ipAvailable = false;
        LinuxRouteReconciler reconciler(
                runner, temporaryDirectory.filePath(QStringLiteral("routes.json")));
        QVERIFY(reconciler.status().value(QStringLiteral("recoveryRequired")).toBool());
        QVERIFY(runner->calls.isEmpty());
    }

    void routeOnlyStartupAllowsMissingResolvectl()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        auto runner = std::make_shared<FakeCommandRunner>();
        runner->resolvectlAvailable = false;
        LinuxRouteReconciler reconciler(
                runner, temporaryDirectory.filePath(QStringLiteral("routes.json")));
        QVERIFY(!reconciler.status().value(QStringLiteral("recoveryRequired")).toBool());
        QVERIFY(runner->calls.isEmpty());
    }

    void startupRequiresResolvectlForPersistedDnsReceipt()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString statePath = temporaryDirectory.filePath(QStringLiteral("routes.json"));
        QFile state(statePath);
        QVERIFY(state.open(QIODevice::WriteOnly));
        QVERIFY(state.write(QJsonDocument(QJsonObject {
            { QStringLiteral("version"), 2 },
            { QStringLiteral("mode"), QStringLiteral("only-forward") },
            { QStringLiteral("interface"), QString() },
            { QStringLiteral("routes"), QJsonArray() },
            { QStringLiteral("bypassRoutes"), QJsonArray() },
            { QStringLiteral("bypassRulePriority"), 1000 },
            { QStringLiteral("fullRulePriority"), 1100 },
            { QStringLiteral("dnsInterface"), QStringLiteral("custom0") },
            { QStringLiteral("dnsServers"), QJsonArray { QStringLiteral("10.0.0.53") } },
            { QStringLiteral("dnsDomains"), QJsonArray { QStringLiteral("~.") } },
        }).toJson(QJsonDocument::Compact)) > 0);
        state.close();
        auto runner = std::make_shared<FakeCommandRunner>();
        runner->resolvectlAvailable = false;
        LinuxRouteReconciler reconciler(runner, statePath);
        QVERIFY(reconciler.status().value(QStringLiteral("recoveryRequired")).toBool());
        QVERIFY(runner->calls.isEmpty());
    }

    void foreignRuleInOneFamilyCannotBeMaskedByOwnedRuleInOtherFamily()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString statePath = temporaryDirectory.filePath(QStringLiteral("routes.json"));
        QFile state(statePath);
        QVERIFY(state.open(QIODevice::WriteOnly));
        state.write(R"json({"version":2,"mode":"all-except","interface":"wg0",
            "routes":[],"bypassRoutes":[],"bypassRulePriority":1000,
            "fullRulePriority":1100})json");
        state.close();
        auto runner = std::make_shared<FakeCommandRunner>();
        runner->capturedOutputs = {
            QStringLiteral("1100: from all lookup main\n"),
            QStringLiteral("1100: from all lookup 51821\n"),
            QStringLiteral("0.0.0.0/1 dev wg0 proto 186\n128.0.0.0/1 dev wg0 proto 186\n"),
            QStringLiteral("::/1 dev wg0 proto 186\n8000::/1 dev wg0 proto 186\n"),
            QString(),
            QString()
        };
        LinuxRouteReconciler reconciler(runner, statePath);
        QVERIFY(reconciler.status().value(QStringLiteral("recoveryRequired")).toBool());
        QVERIFY(runner->calls.isEmpty());
    }

    void extraReservedRuleInOwnedFamilyFailsClosed()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString statePath = temporaryDirectory.filePath(QStringLiteral("routes.json"));
        QFile state(statePath);
        QVERIFY(state.open(QIODevice::WriteOnly));
        state.write(R"json({"version":2,"mode":"all-except","interface":"wg0",
            "routes":[],"bypassRoutes":[],"bypassRulePriority":1000,
            "fullRulePriority":1100})json");
        state.close();
        auto runner = std::make_shared<FakeCommandRunner>();
        runner->capturedOutputs = {
            QStringLiteral("1100: from all lookup 51821\n1100: from all lookup main\n"),
            QStringLiteral("1100: from all lookup 51821\n"),
            QStringLiteral("0.0.0.0/1 dev wg0 proto 186\n128.0.0.0/1 dev wg0 proto 186\n"),
            QStringLiteral("::/1 dev wg0 proto 186\n8000::/1 dev wg0 proto 186\n"),
            QString(), QString()
        };
        LinuxRouteReconciler reconciler(runner, statePath);
        QVERIFY(reconciler.status().value(QStringLiteral("recoveryRequired")).toBool());
        QVERIFY(runner->calls.isEmpty());
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
            QStringLiteral("wg0"), QStringLiteral("table"), QStringLiteral("51821"),
            QStringLiteral("proto"), QStringLiteral("186") };
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
        QVERIFY(std::any_of(runner->calls.cbegin(), runner->calls.cend(),
                            [&expectedBypassDelete](const auto &call) {
            return call.arguments == expectedBypassDelete;
        }));
    }

    void foreignRuleAtReservedPriorityFailsClosed()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        auto runner = std::make_shared<FakeCommandRunner>();
        runner->capturedOutputs = {
            QStringLiteral("1000: from all lookup main\n1100: from all lookup main\n"),
            QStringLiteral("1000: from all lookup main\n1100: from all lookup main\n"),
            QString(), QString(), QString(), QString() };
        LinuxRouteReconciler reconciler(
                runner, temporaryDirectory.filePath(QStringLiteral("routes.json")));
        const RouteReconcileResult result = reconciler.applyAllExcept(
                QStringLiteral("wg0"), { QStringLiteral("10.8.1.4") });
        QVERIFY(!result.ok);
        QCOMPARE(result.code, QStringLiteral("recovery_required"));
        QVERIFY(runner->calls.isEmpty());
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

    void ownedPrioritiesReloadWithCompleteKernelSnapshot()
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
            QStringLiteral("1100: from all lookup 51821\n"),
            QStringLiteral("0.0.0.0/1 dev wg0 proto 186\n128.0.0.0/1 dev wg0 proto 186\n"),
            QStringLiteral("::/1 dev wg0 proto 186\n8000::/1 dev wg0 proto 186\n"),
            QString() };
        // initializeState() and the subsequent apply both probe the kernel;
        // provide the same deterministic snapshot for each probe cycle.
        secondRunner->capturedOutputs += secondRunner->capturedOutputs;
        LinuxRouteReconciler second(secondRunner, statePath);
        const RouteReconcileResult secondResult = second.applyAllExcept(
                QStringLiteral("wg0"), { QStringLiteral("10.8.1.4") });
        QVERIFY2(secondResult.ok, qPrintable(secondResult.message));
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

    void allExceptKeepsVpnInternalPolicyEndpointOnTunnel()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString configPath = temporaryDirectory.filePath(QStringLiteral("wg.conf"));
        QFile config(configPath);
        QVERIFY(config.open(QIODevice::WriteOnly));
        QVERIFY(config.write(QByteArrayLiteral("[Peer]\nEndpoint = 8.8.8.9:51820\n")) > 0);
        config.close();

        Profile profile;
        profile.routingMode = QStringLiteral("all-except");
        profile.serverRulesUrl = QStringLiteral("http://10.8.1.4:17864/rules.json");
        profile.forwardRoutes = { QStringLiteral("10.8.1.0/24") };
        profile.dnsServers = { QStringLiteral("10.8.1.53") };
        profile.dnsDomains = { QStringLiteral("~.") };
        profile.configPath = configPath;

        bool valid = false;
        const QStringList bypass = allExceptBypassRoutes(
                profile, { QStringLiteral("10.8.1.7/32"), QStringLiteral("8.8.8.8/32") }, &valid);
        QVERIFY(valid);
        QVERIFY(bypass.contains(QStringLiteral("8.8.8.8")));
        QVERIFY(bypass.contains(QStringLiteral("8.8.8.9")));
        QVERIFY(!bypass.contains(QStringLiteral("10.8.1.0/24")));
        QVERIFY(!bypass.contains(QStringLiteral("10.8.1.7")));
        QVERIFY(!bypass.contains(QStringLiteral("10.8.1.53")));
        QVERIFY(!bypass.contains(QStringLiteral("10.8.1.4/32")));
    }

    void broadInternalOverlapFailsClosed()
    {
        Profile profile;
        profile.forwardRoutes = { QStringLiteral("10.8.1.0/24") };
        bool valid = true;
        QVERIFY(allExceptBypassRoutes(profile,
                                      { QStringLiteral("10.8.0.0/16") }, &valid).isEmpty());
        QVERIFY(!valid);
    }

    void ipv6UnderlayEndpointFailsClosed()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString configPath = temporaryDirectory.filePath(QStringLiteral("wg.conf"));
        QFile config(configPath);
        QVERIFY(config.open(QIODevice::WriteOnly));
        QVERIFY(config.write(QByteArrayLiteral("[Peer]\nEndpoint = [2001:db8::1]:51820\n")) > 0);
        config.close();

        Profile profile;
        profile.configPath = configPath;
        bool valid = true;
        QVERIFY(allExceptBypassRoutes(profile, {}, &valid).isEmpty());
        QVERIFY(!valid);
    }

    void emptyForwardRoutesStillHaveTunnelBootstrapPlan()
    {
        Profile profile;
        profile.routingMode = QStringLiteral("all-except");
        bool valid = false;
        const QStringList routes = allExceptBypassRoutes(
                profile, { QStringLiteral("8.8.8.8") }, &valid);
        QVERIFY(valid);
        QCOMPARE(routes, QStringList { QStringLiteral("8.8.8.8") });
    }

    void policyTransportAllowsOnlyDocumentedInternalHttp()
    {
        Profile profile;
        profile.forwardRoutes = { QStringLiteral("10.8.1.0/24") };
        QString error;
        QVERIFY(isSafePolicyEndpoint(profile,
                                     QStringLiteral("http://10.8.1.253:17864/rules.json"),
                                     &error));
        QVERIFY(!isSafePolicyEndpoint(profile,
                                      QStringLiteral("http://192.168.1.98/rules.json"),
                                      &error));
        QVERIFY(!isSafePolicyEndpoint(profile,
                                      QStringLiteral("http://policy.example/rules.json"),
                                      &error));
        QVERIFY(!isSafePolicyEndpoint(profile,
                                      QStringLiteral("https://127.0.0.1/rules.json"),
                                      &error));
        QVERIFY(!isSafePolicyEndpoint(profile,
                                      QStringLiteral("https://policy.example/rules.json"),
                                      &error));
        QVERIFY(isSafePolicyEndpoint(profile,
                                     QStringLiteral("https://8.8.8.8/rules.json"),
                                     &error));
    }

    void invalidRouteStateFailsClosedWithoutMutatingHost()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString statePath = temporaryDirectory.filePath(QStringLiteral("routes.json"));
        QFile state(statePath);
        QVERIFY(state.open(QIODevice::WriteOnly));
        QVERIFY(state.write(QByteArrayLiteral("not-json")) > 0);
        state.close();
        auto runner = std::make_shared<FakeCommandRunner>();
        LinuxRouteReconciler reconciler(runner, statePath);
        const RouteReconcileResult result = reconciler.applyAllExcept(
                QStringLiteral("wg0"), { QStringLiteral("8.8.8.8/32") });
        QVERIFY(!result.ok);
        QCOMPARE(result.code, QStringLiteral("recovery_required"));
        QVERIFY(runner->calls.isEmpty());
        QVERIFY(reconciler.status().value(QStringLiteral("recoveryRequired")).toBool());
    }

    void malformedEmptyInterfaceRouteReceiptFailsClosed()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString statePath = temporaryDirectory.filePath(QStringLiteral("routes.json"));
        QFile state(statePath);
        QVERIFY(state.open(QIODevice::WriteOnly));
        QVERIFY(state.write(QJsonDocument(QJsonObject {
            { QStringLiteral("version"), 2 },
            { QStringLiteral("mode"), QStringLiteral("only-forward") },
            { QStringLiteral("interface"), QString() },
            { QStringLiteral("routes"), QJsonArray { QStringLiteral("not-a-route") } },
            { QStringLiteral("bypassRoutes"), QJsonArray() },
            { QStringLiteral("bypassRulePriority"), 1000 },
            { QStringLiteral("fullRulePriority"), 1100 },
        }).toJson(QJsonDocument::Compact)) > 0);
        state.close();
        auto runner = std::make_shared<FakeCommandRunner>();
        LinuxRouteReconciler reconciler(runner, statePath);
        const RouteReconcileResult result = reconciler.applyAllExcept(
                QStringLiteral("wg0"), { QStringLiteral("8.8.8.8/32") });
        QVERIFY(!result.ok);
        QCOMPARE(result.code, QStringLiteral("recovery_required"));
        QVERIFY(runner->calls.isEmpty());
    }

    void foreignMarkedPriorityIsNotDeleted()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString statePath = temporaryDirectory.filePath(QStringLiteral("routes.json"));
        auto initialRunner = std::make_shared<FakeCommandRunner>();
        LinuxRouteReconciler initial(initialRunner, statePath);
        QVERIFY(initial.applyAllExcept(QStringLiteral("wg0"), {}).ok);

        auto runner = std::make_shared<FakeCommandRunner>();
        runner->capturedOutputs = {
            QStringLiteral("1000: to 10.8.1.4 lookup main protocol 999\n1100: from all lookup 51821 protocol 999\n"),
            QStringLiteral("1000: to 10.8.1.4 lookup main protocol 999\n1100: from all lookup 51821 protocol 999\n"),
            QStringLiteral("0.0.0.0/1 dev wg0 proto 186\n128.0.0.0/1 dev wg0 proto 186\n"),
            QStringLiteral("::/1 dev wg0 proto 186\n8000::/1 dev wg0 proto 186\n"),
            QString(), QString()
        };
        LinuxRouteReconciler reconciler(runner, statePath);
        const RouteReconcileResult result = reconciler.clear();
        QVERIFY(!result.ok);
        QCOMPARE(result.code, QStringLiteral("recovery_required"));
        QVERIFY(runner->calls.isEmpty());
    }

    void markedKernelInterfaceMustMatchReceipt()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString statePath = temporaryDirectory.filePath(QStringLiteral("routes.json"));
        QFile state(statePath);
        QVERIFY(state.open(QIODevice::WriteOnly));
        QVERIFY(state.write(QJsonDocument(QJsonObject {
            { QStringLiteral("version"), 2 },
            { QStringLiteral("mode"), QStringLiteral("all-except") },
            { QStringLiteral("interface"), QStringLiteral("wg0") },
            { QStringLiteral("routes"), QJsonArray() },
            { QStringLiteral("bypassRoutes"), QJsonArray { QStringLiteral("10.8.1.4") } },
            { QStringLiteral("bypassRulePriority"), 1000 },
            { QStringLiteral("fullRulePriority"), 1100 },
        }).toJson(QJsonDocument::Compact)) > 0);
        state.close();
        auto runner = std::make_shared<FakeCommandRunner>();
        runner->capturedOutputs = {
            QStringLiteral("1000: to 10.8.1.4 lookup main protocol 186\n1100: from all lookup 51821 protocol 186\n"),
            QStringLiteral("1000: to 10.8.1.4 lookup main protocol 186\n1100: from all lookup 51821 protocol 186\n"),
            QStringLiteral("0.0.0.0/1 dev wg1 proto 186\n128.0.0.0/1 dev wg1 proto 186\n"),
            QStringLiteral("::/1 dev wg1 proto 186\n8000::/1 dev wg1 proto 186\n"),
            QString(), QString()
        };
        LinuxRouteReconciler reconciler(runner, statePath);
        const RouteReconcileResult result = reconciler.applyAllExcept(
                QStringLiteral("wg0"), { QStringLiteral("10.8.1.4") });
        QVERIFY(!result.ok);
        QCOMPARE(result.code, QStringLiteral("recovery_required"));
        QVERIFY(runner->calls.isEmpty());
    }

    void onlyForwardPreflightRejectsBeforeClearingExistingFullTunnel()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString statePath = temporaryDirectory.filePath(QStringLiteral("routes.json"));
        QFile state(statePath);
        QVERIFY(state.open(QIODevice::WriteOnly));
        QVERIFY(state.write(QJsonDocument(QJsonObject {
            { QStringLiteral("version"), 2 },
            { QStringLiteral("mode"), QStringLiteral("all-except") },
            { QStringLiteral("interface"), QStringLiteral("wg0") },
            { QStringLiteral("routes"), QJsonArray() },
            { QStringLiteral("bypassRoutes"), QJsonArray() },
            { QStringLiteral("bypassRulePriority"), 1000 },
            { QStringLiteral("fullRulePriority"), 1100 },
        }).toJson(QJsonDocument::Compact)) > 0);
        state.close();

        auto runner = std::make_shared<FakeCommandRunner>();
        runner->capturedOutputs = {
            QStringLiteral("1100: from all lookup 51821\n"),
            QStringLiteral("1100: from all lookup 51821\n"),
            QStringLiteral("0.0.0.0/1 dev wg0 proto 186\n128.0.0.0/1 dev wg0 proto 186\n"),
            QStringLiteral("::/1 dev wg0 proto 186\n8000::/1 dev wg0 proto 186\n"),
            QString(), QString()
        };
        runner->mainRouteOutput = QStringLiteral("10.8.1.0/24 dev foreign proto 99 metric 1\n");
        LinuxRouteReconciler reconciler(runner, statePath);
        const RouteReconcileResult result = reconciler.apply(
                QStringLiteral("wg1"), { QStringLiteral("10.8.1.0/24") });
        QVERIFY(!result.ok);
        QCOMPARE(result.code, QStringLiteral("only_forward_route_conflict"));
        QVERIFY(runner->calls.isEmpty());
    }

    void foreignFullTunnelRouteIsNeverDeleted()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString statePath = temporaryDirectory.filePath(QStringLiteral("routes.json"));
        auto initialRunner = std::make_shared<FakeCommandRunner>();
        LinuxRouteReconciler initial(initialRunner, statePath);
        QVERIFY(initial.applyAllExcept(QStringLiteral("wg0"), {}).ok);

        auto runner = std::make_shared<FakeCommandRunner>();
        runner->capturedOutputs = {
            QString(), QString(),
            QStringLiteral("0.0.0.0/1 dev wg0 proto boot\n128.0.0.0/1 dev wg0 proto boot\n"),
            QStringLiteral("::/1 dev wg0 proto boot\n8000::/1 dev wg0 proto boot\n"),
            QString(), QString()
        };
        LinuxRouteReconciler reconciler(runner, statePath);
        const RouteReconcileResult result = reconciler.clear();
        QVERIFY(!result.ok);
        QCOMPARE(result.code, QStringLiteral("recovery_required"));
        QVERIFY(runner->calls.isEmpty());
    }

    void dnsDomainFailureRestoresPreviousReceipt()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        auto runner = std::make_shared<FakeCommandRunner>();
        LinuxRouteReconciler reconciler(
                runner, temporaryDirectory.filePath(QStringLiteral("routes.json")));
        QVERIFY(reconciler.configureDns(QStringLiteral("wg0"),
                                        { QStringLiteral("10.8.1.53") },
                                        { QStringLiteral("~.") }).ok);
        runner->failAtCall = runner->calls.size() + 2;
        const RouteReconcileResult result = reconciler.configureDns(
                QStringLiteral("wg0"), { QStringLiteral("10.8.1.54") },
                { QStringLiteral("~corp") });
        QVERIFY(!result.ok);
        QCOMPARE(result.code, QStringLiteral("dns_configure_failed"));
        QVERIFY(runner->calls.size() >= 7);
        const QStringList previousDnsArgs {
            QStringLiteral("dns"), QStringLiteral("wg0"), QStringLiteral("10.8.1.53")
        };
        const QStringList previousDomainArgs {
            QStringLiteral("domain"), QStringLiteral("wg0"), QStringLiteral("~.")
        };
        QCOMPARE(runner->calls.at(5).arguments, previousDnsArgs);
        QCOMPARE(runner->calls.at(6).arguments, previousDomainArgs);
    }

    void firstDnsDomainFailureRevertsCurrentInterface()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        auto runner = std::make_shared<FakeCommandRunner>();
        LinuxRouteReconciler reconciler(
                runner, temporaryDirectory.filePath(QStringLiteral("routes.json")));
        runner->failAtCall = 2; // DNS succeeds; domain assignment fails.

        const RouteReconcileResult result = reconciler.configureDns(
                QStringLiteral("custom0"), { QStringLiteral("10.0.0.53") },
                { QStringLiteral("~.") });
        QVERIFY(!result.ok);
        QCOMPARE(result.code, QStringLiteral("dns_configure_failed"));
        QVERIFY(runner->calls.size() >= 3);
        const QStringList revertArgs {
            QStringLiteral("revert"), QStringLiteral("custom0")
        };
        QCOMPARE(runner->calls.at(2).arguments, revertArgs);
    }

    void dnsOnlyConnectConfiguresResolver()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        auto runner = std::make_shared<FakeCommandRunner>();
        HeadlessRoutingController controller(
                runner, temporaryDirectory.filePath(QStringLiteral("routes.json")));
        Profile profile;
        profile.id = QStringLiteral("dns-only");
        profile.protocol = QStringLiteral("wireguard");
        profile.interfaceName = QStringLiteral("custom0");
        profile.dnsServers = { QStringLiteral("10.0.0.53") };
        profile.dnsDomains = { QStringLiteral("~.") };

        const RoutingResult result = controller.connect(profile);
        QVERIFY2(result.ok, qPrintable(result.message));
        const QJsonObject status = controller.status();
        QCOMPARE(status.value(QStringLiteral("dnsInterface")).toString(),
                 QStringLiteral("custom0"));
        QVERIFY(std::any_of(runner->calls.cbegin(), runner->calls.cend(),
                            [](const auto &call) {
            return call.arguments == QStringList { QStringLiteral("dns"),
                                                    QStringLiteral("custom0"),
                                                    QStringLiteral("10.0.0.53") };
        }));
        QVERIFY(std::any_of(runner->calls.cbegin(), runner->calls.cend(),
                            [](const auto &call) {
            return call.arguments == QStringList { QStringLiteral("domain"),
                                                    QStringLiteral("custom0"),
                                                    QStringLiteral("~.") };
        }));
    }

    void partialOwnedTableFailsClosedAtStartup()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString statePath = temporaryDirectory.filePath(QStringLiteral("routes.json"));
        QFile state(statePath);
        QVERIFY(state.open(QIODevice::WriteOnly));
        QVERIFY(state.write(QJsonDocument(QJsonObject {
            { QStringLiteral("version"), 2 },
            { QStringLiteral("mode"), QStringLiteral("all-except") },
            { QStringLiteral("interface"), QStringLiteral("wg0") },
            { QStringLiteral("routes"), QJsonArray() },
            { QStringLiteral("bypassRoutes"), QJsonArray() },
            { QStringLiteral("bypassRulePriority"), 1000 },
            { QStringLiteral("fullRulePriority"), 1100 },
        }).toJson(QJsonDocument::Compact)) > 0);
        state.close();
        auto runner = std::make_shared<FakeCommandRunner>();
        runner->capturedOutputs = {
            QString(), QString(),
            QStringLiteral("0.0.0.0/1 dev wg0 proto 186\n128.0.0.0/1 dev wg0 proto 186\n"),
            QString(), QString(), QString()
        };
        LinuxRouteReconciler reconciler(runner, statePath);
        QVERIFY(reconciler.status().value(QStringLiteral("recoveryRequired")).toBool());
        const RouteReconcileResult result = reconciler.applyAllExcept(QStringLiteral("wg0"), {});
        QVERIFY(!result.ok);
        QCOMPARE(result.code, QStringLiteral("recovery_required"));
        QVERIFY(runner->calls.isEmpty());
    }

    void domainOnlyDnsProfileIsRejectedAtStoreBoundary()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString configPath = temporaryDirectory.filePath(QStringLiteral("wg.conf"));
        QFile config(configPath);
        QVERIFY(config.open(QIODevice::WriteOnly));
        config.write("[Interface]\n");
        config.close();

        ProfileStore store(temporaryDirectory.filePath(QStringLiteral("profiles.json")));
        QVERIFY(store.load());
        Profile profile;
        profile.id = QStringLiteral("dns-only");
        profile.name = QStringLiteral("DNS only");
        profile.protocol = QStringLiteral("wireguard");
        profile.configPath = configPath;
        profile.dnsDomains = { QStringLiteral("~.") };
        QVERIFY(!store.add(profile));
        QVERIFY(store.lastError().contains(QStringLiteral("together")));
    }
};

QTEST_MAIN(ServerRoutingTest)
#include "tst_server_routing.moc"
