#include <QtTest>

#include <QFile>
#include <QFileInfo>
#include <QElapsedTimer>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>
#include <QSet>
#include <QTcpServer>
#include <QTcpSocket>
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
        if (failIndividual && arguments.contains(QStringLiteral("priority"))) {
            return { false, 1, QStringLiteral("simulated delete retry failure") };
        }
        if (program == QStringLiteral("resolvectl")
            && arguments == QStringList { QStringLiteral("revert"), QStringLiteral("wg0") }
            && dnsRevertFails) {
            return { false, 1, dnsFailureMessage, {} };
        }
        if (program == QStringLiteral("resolvectl")
            && arguments.size() >= 3
            && arguments.at(0) == QStringLiteral("dns")) {
            dnsInterface = arguments.at(1);
            dnsServers = arguments.mid(2);
        } else if (program == QStringLiteral("resolvectl")
                   && arguments.size() >= 3
                   && arguments.at(0) == QStringLiteral("domain")) {
            dnsInterface = arguments.at(1);
            dnsDomains = arguments.mid(2);
        } else if (program == QStringLiteral("resolvectl")
                   && arguments == QStringList { QStringLiteral("revert"), dnsInterface }) {
            dnsInterface.clear();
            dnsServers.clear();
            dnsDomains.clear();
        }
        if (failAtCall > 0 && calls.size() == failAtCall) {
            failAtCall = -1;
            return { false, 1, QStringLiteral("simulated failure") };
        }
        if (arguments.contains(QStringLiteral("table"))
            && arguments.contains(QStringLiteral("51821"))) {
            if (arguments.contains(QStringLiteral("replace"))) fullTunnelInstalled = true;
            if (arguments.contains(QStringLiteral("del"))) fullTunnelInstalled = false;
        }
        const int toIndex = arguments.indexOf(QStringLiteral("to"));
        if (toIndex >= 0 && toIndex + 1 < arguments.size()) {
            const QString route = arguments.at(toIndex + 1);
            const int priorityIndex = arguments.indexOf(QStringLiteral("priority"));
            if (priorityIndex >= 0 && priorityIndex + 1 < arguments.size()) {
                managedBypassPriority = arguments.at(priorityIndex + 1).toInt();
            }
            if (arguments.contains(QStringLiteral("add"))) managedBypassRoutes.insert(route);
            if (arguments.contains(QStringLiteral("del"))) managedBypassRoutes.remove(route);
        }
        return runResult;
    }

    CommandResult runBatch(const QString &program,
                           const QList<QStringList> &commands) override
    {
        ++batchCalls;
        batchContents.append(commands);
        if (failBatches) return { false, 1, QStringLiteral("simulated batch failure") };
        for (const QStringList &command : commands) {
            const CommandResult result = run(program, command);
            if (!result.ok) return result;
        }
        return { true, 0, {} };
    }

    CommandResult runCaptured(const QString &program,
                              const QStringList &arguments) override
    {
        capturedArguments.append(arguments);
        ++capturedCalls;
        if (program == QStringLiteral("ip")
            && arguments.size() == 4
            && arguments.at(0) == QStringLiteral("link")
            && arguments.at(1) == QStringLiteral("show")
            && arguments.at(2) == QStringLiteral("dev")) {
            if (dnsLinkAbsent) {
                return { false, 1,
                         missingDeviceMessage.arg(arguments.at(3)), {} };
            }
            return { true, 0, {}, QStringLiteral("5: %1: <%2>").arg(
                        arguments.at(3), linkDown ? QStringLiteral("POINTOPOINT,DOWN")
                                                   : QStringLiteral("POINTOPOINT")) };
        }
        if (program == QStringLiteral("resolvectl")
            && arguments.size() == 2
            && arguments.at(0) == QStringLiteral("status")) {
            if (dnsResolverProbeFails) {
                return { false, 1, dnsFailureMessage, {} };
            }
            if (dnsResolverBindingAbsent) return { true, 0, {}, QString() };
            const QStringList servers = dnsServers.isEmpty()
                    ? QStringList { QStringLiteral("10.8.1.53") } : dnsServers;
            const QStringList domains = dnsDomains.isEmpty()
                    ? QStringList { QStringLiteral("~.") } : dnsDomains;
            return { true, 0, {}, QStringLiteral("Link 5 (%1)\nCurrent Scopes: DNS\nDNS Servers: %2\nDNS Domain: %3\n")
                .arg(arguments.at(1), servers.join(QStringLiteral(" ")), domains.join(QStringLiteral(" "))) };
        }
        if (program == QStringLiteral("ip")
            && arguments.endsWith(QStringLiteral("main"))) {
            return { true, 0, {}, mainRouteOutput };
        }
        if (capturedCalls <= capturedOutputs.size()) {
            const QString output = capturedOutputs.value(capturedCalls - 1);
            if (program == QStringLiteral("ip")
                && arguments.contains(QStringLiteral("rule"))
                && !arguments.contains(QStringLiteral("-6"))) {
                const QRegularExpressionMatch priorityMatch = QRegularExpression(
                        QStringLiteral("^\\s*(\\d+):\\s+(?:from\\s+all\\s+)?to\\s+\\S+\\s+lookup\\s+main"))
                        .match(output);
                if (priorityMatch.hasMatch()) {
                    managedBypassPriority = priorityMatch.captured(1).toInt();
                }
            }
            return { true, 0, {}, output };
        }
        if (capturedCalls <= 2) {
            return { true, 0, {}, {} };
        }
        if (!fullTunnelInstalled && !emitBypassWithoutFullTunnel) {
            return { true, 0, {}, {} };
        }
        if (arguments.contains(QStringLiteral("route"))) {
            if (!fullTunnelInstalled) return { true, 0, {}, {} };
            const bool ipv6 = arguments.contains(QStringLiteral("-6"));
            const QString &capturedRouteOutput = ipv6
                    ? fullTunnelIpv6Output : fullTunnelIpv4Output;
            if (!capturedRouteOutput.isEmpty()) {
                return { true, 0, {}, capturedRouteOutput };
            }
            return { true, 0, {}, ipv6
                ? QStringLiteral("::/1 dev wg0 metric 1024 pref medium proto 186 scope link\n8000::/1 dev wg0 scope link metric 1024 pref high proto 186\n")
                : QStringLiteral("0.0.0.0/1 dev wg0 scope link metric 1024 proto 186\n128.0.0.0/1 dev wg0 metric 1024 scope link proto 186\n") };
        }
        if (fullTunnelInstalled || emitBypassWithoutFullTunnel) {
            QString rules;
            if (!arguments.contains(QStringLiteral("-6"))) {
                if (malformedPostcondition) {
                    rules += QStringLiteral("%1: from 10.0.0.0/8 lookup main\n")
                                     .arg(managedBypassPriority);
                } else {
                    for (const QString &route : managedBypassRoutes) {
                        const QString displayedRoute = explicitHostPrefixes
                                ? route + QStringLiteral("/32") : route;
                        rules += QStringLiteral("%1: from all to %2 lookup main\n")
                                         .arg(managedBypassPriority).arg(displayedRoute);
                    }
                }
                if (!foreignBypassRules.isEmpty()) {
                    rules += foreignBypassRules.join(QStringLiteral("\n"));
                    rules += QLatin1Char('\n');
                }
            }
            if (fullTunnelInstalled || emitFullTunnelRuleWithoutTable) {
                rules += QStringLiteral("1100: from all lookup 51821\n");
            }
            return { true, 0, {}, rules };
        }
        return { true, 0, {},
            QString() };
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
    QList<QStringList> capturedArguments;
    CommandResult runResult { true, 0, {} };
    int capturedCalls = 0;
    int failAtCall = -1;
    QStringList capturedOutputs;
    QString mainRouteOutput;
    QString fullTunnelIpv4Output;
    QString fullTunnelIpv6Output;
    bool fullTunnelInstalled = false;
    bool emitBypassWithoutFullTunnel = false;
    bool emitFullTunnelRuleWithoutTable = false;
    bool ipAvailable = true;
    bool resolvectlAvailable = true;
    int batchCalls = 0;
    QList<QList<QStringList>> batchContents;
    QSet<QString> managedBypassRoutes;
    QStringList foreignBypassRules;
    int managedBypassPriority = 1000;
    bool malformedPostcondition = false;
    bool explicitHostPrefixes = false;
    bool dnsRevertFails = false;
    bool dnsLinkAbsent = false;
    QString missingDeviceMessage = QStringLiteral("Cannot find device \"%1\"");
    bool linkDown = false;
    bool dnsResolverBindingAbsent = false;
    bool dnsResolverProbeFails = false;
    bool failBatches = false;
    bool failIndividual = false;
    QString dnsFailureMessage = QStringLiteral("simulated DNS failure");
    QString dnsInterface;
    QStringList dnsServers;
    QStringList dnsDomains;
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
        QVERIFY(std::any_of(runner->capturedArguments.cbegin(), runner->capturedArguments.cend(),
                            [](const QStringList &arguments) {
            return arguments.contains(QStringLiteral("-N"))
                && arguments.endsWith(QStringLiteral("main"));
        }));
        QCOMPARE(runner->calls.size(), 1);
        const QStringList initialArguments {
            QStringLiteral("route"), QStringLiteral("replace"),
            QStringLiteral("10.8.1.0/24"), QStringLiteral("dev"),
            QStringLiteral("amn0"), QStringLiteral("proto"), QStringLiteral("187"),
            QStringLiteral("metric"), QStringLiteral("1")
        };
        QCOMPARE(runner->calls.constFirst().arguments, initialArguments);

        runner->mainRouteOutput = QStringLiteral("10.8.1.0/24 dev amn0 metric 1 scope link proto 187\n");
                 QVERIFY2(reconciler.apply(
                        QStringLiteral("amn0"), { QStringLiteral("10.8.1.15") }).ok,
                 "route replacement failed");
        QCOMPARE(runner->calls.size(), 3);
        QCOMPARE(runner->calls.at(1).arguments.at(1), QStringLiteral("replace"));
        QCOMPARE(runner->calls.at(2).arguments.at(1), QStringLiteral("del"));

        runner->mainRouteOutput = QStringLiteral("10.8.1.15/32 dev amn0 src 10.8.1.15 pref medium metric 1 proto 187 scope link\n");
        QVERIFY2(reconciler.clear().ok, "route clear failed");
        QCOMPARE(runner->calls.size(), 4);
        QCOMPARE(runner->calls.constLast().arguments.at(1), QStringLiteral("del"));
        QCOMPARE(reconciler.status().value(QStringLiteral("interface")).toString(), QString());
        QVERIFY(reconciler.status().value(QStringLiteral("routes")).toArray().isEmpty());
    }

    void acceptsNumericLinkScopeInCapturedFullAndSplitRoutes()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        auto fullRunner = std::make_shared<FakeCommandRunner>();
        // Captured from `ip -N route show table 51821`; iproute2 may render
        // RT_SCOPE_LINK as its numeric value 253 and reorder IPv6 lines.
        fullRunner->fullTunnelIpv4Output = QStringLiteral(
                "0.0.0.0/1 dev amn0 proto 186 scope 253\n"
                "128.0.0.0/1 dev amn0 metric 1024 scope 253 proto 186\n");
        fullRunner->fullTunnelIpv6Output = QStringLiteral(
                "8000::/1 dev amn0 scope 253 metric 1024 pref high proto 186\n"
                "::/1 dev amn0 metric 1024 pref medium proto 186 scope 253\n");
        LinuxRouteReconciler fullReconciler(
                fullRunner, temporaryDirectory.filePath(QStringLiteral("full.json")));
        QVERIFY2(fullReconciler.applyAllExcept(
                              QStringLiteral("amn0"), { QStringLiteral("10.8.1.4") }).ok,
                 "numeric link scope full-tunnel readback failed");

        auto splitRunner = std::make_shared<FakeCommandRunner>();
        // Captured from `ip -N route show table main` for the managed split
        // route.  This exercises the same shared parser with proto 187.
        LinuxRouteReconciler splitReconciler(
                splitRunner, temporaryDirectory.filePath(QStringLiteral("split.json")));
        splitRunner->mainRouteOutput = QStringLiteral(
                "10.8.1.0/24 dev amn0 proto 187 metric 1 scope 253\n");
        QVERIFY2(splitReconciler.apply(
                              QStringLiteral("amn0"), { QStringLiteral("10.8.1.0/24") }).ok,
                 "numeric link scope split-route readback failed");
    }

    void acceptsOnlyManagedSemanticProtocolAliases()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());

        auto splitRunner = std::make_shared<FakeCommandRunner>();
        LinuxRouteReconciler splitReconciler(
                splitRunner, temporaryDirectory.filePath(QStringLiteral("split-alias.json")));
        splitRunner->mainRouteOutput = QStringLiteral(
                "10.8.1.0/24 dev amn0 proto isis scope link metric 1\n");
        QVERIFY2(splitReconciler.apply(
                              QStringLiteral("amn0"), { QStringLiteral("10.8.1.0/24") }).ok,
                 "semantic proto isis split-route readback failed");

        auto fullRunner = std::make_shared<FakeCommandRunner>();
        fullRunner->fullTunnelIpv4Output = QStringLiteral(
                "0.0.0.0/1 dev wg0 proto bgp scope link metric 1024\n"
                "128.0.0.0/1 dev wg0 metric 1024 scope link proto bgp\n");
        fullRunner->fullTunnelIpv6Output = QStringLiteral(
                "::/1 dev wg0 proto bgp scope link metric 1024\n"
                "8000::/1 dev wg0 metric 1024 scope link proto bgp\n");
        LinuxRouteReconciler fullReconciler(
                fullRunner, temporaryDirectory.filePath(QStringLiteral("full-alias.json")));
        QVERIFY2(fullReconciler.applyAllExcept(QStringLiteral("wg0"), {}).ok,
                 "semantic proto bgp full-tunnel readback failed");
    }

    void rejectsForeignProtocolAliasWithBoundedDiagnostic()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        auto runner = std::make_shared<FakeCommandRunner>();
        LinuxRouteReconciler reconciler(
                runner, temporaryDirectory.filePath(QStringLiteral("routes.json")));
        runner->mainRouteOutput = QStringLiteral(
                "10.8.1.0/24 dev amn0 proto bgp scope link metric 1\n");
        const RouteReconcileResult result = reconciler.apply(
                QStringLiteral("amn0"), { QStringLiteral("10.8.1.0/24") });
        QVERIFY(!result.ok);
        QCOMPARE(result.code, QStringLiteral("only_forward_route_conflict"));
        QVERIFY(runner->calls.isEmpty());
        QCOMPARE(result.diagnostics.value(QStringLiteral("rejectedProtocol")).toString(),
                 QStringLiteral("bgp"));
        QCOMPARE(result.diagnostics.value(QStringLiteral("expectedProtocol")).toString(),
                 QStringLiteral("187 or isis"));
        QVERIFY(result.diagnostics.value(QStringLiteral("rejectedProtocolLine"))
                        .toString().size() <= 512);
    }

    void rejectsOtherProtocolNamesForManagedOwnership()
    {
        const QStringList splitForeignProtocols {
            QStringLiteral("bgp"), QStringLiteral("static"), QStringLiteral("kernel") };
        for (const QString &protocol : splitForeignProtocols) {
            QTemporaryDir temporaryDirectory;
            QVERIFY(temporaryDirectory.isValid());
            auto runner = std::make_shared<FakeCommandRunner>();
            LinuxRouteReconciler reconciler(
                    runner, temporaryDirectory.filePath(QStringLiteral("routes.json")));
            runner->mainRouteOutput = QStringLiteral(
                    "10.8.1.0/24 dev amn0 proto %1 scope link metric 1\n").arg(protocol);
            const RouteReconcileResult result = reconciler.apply(
                    QStringLiteral("amn0"), { QStringLiteral("10.8.1.0/24") });
            QVERIFY(!result.ok);
            QCOMPARE(result.code, QStringLiteral("only_forward_route_conflict"));
            QVERIFY(runner->calls.isEmpty());
            QCOMPARE(result.diagnostics.value(QStringLiteral("rejectedProtocol")).toString(),
                     protocol);
            QVERIFY(result.diagnostics.value(QStringLiteral("rejectedProtocolLine"))
                            .toString().size() <= 512);
        }

        const QStringList fullForeignProtocols {
            QStringLiteral("isis"), QStringLiteral("static"), QStringLiteral("kernel") };
        for (const QString &protocol : fullForeignProtocols) {
            QTemporaryDir temporaryDirectory;
            QVERIFY(temporaryDirectory.isValid());
            const QString statePath = temporaryDirectory.filePath(QStringLiteral("routes.json"));
            auto initialRunner = std::make_shared<FakeCommandRunner>();
            LinuxRouteReconciler initial(initialRunner, statePath);
            QVERIFY2(initial.applyAllExcept(QStringLiteral("wg0"), {}).ok,
                     qPrintable(QStringLiteral("initial full-tunnel setup failed for %1").arg(protocol)));

            auto runner = std::make_shared<FakeCommandRunner>();
            runner->capturedOutputs = {
                QStringLiteral("1100: from all lookup 51821\n"),
                QStringLiteral("1100: from all lookup 51821\n"),
                QStringLiteral("0.0.0.0/1 dev wg0 proto 186\n128.0.0.0/1 dev wg0 proto 186\n"),
                QStringLiteral("::/1 dev wg0 proto 186\n8000::/1 dev wg0 proto 186\n"),
                QString(), QString() };
            LinuxRouteReconciler reconciler(runner, statePath);
            QVERIFY(!reconciler.status().value(QStringLiteral("recoveryRequired")).toBool());
            runner->fullTunnelInstalled = true;
            runner->fullTunnelIpv4Output = QStringLiteral(
                    "0.0.0.0/1 dev wg0 proto %1\n128.0.0.0/1 dev wg0 proto 186\n").arg(protocol);
            runner->fullTunnelIpv6Output = QStringLiteral(
                    "::/1 dev wg0 proto 186\n8000::/1 dev wg0 proto 186\n");
            const RouteReconcileResult result = reconciler.clear();
            QVERIFY(!result.ok);
            QCOMPARE(result.code, QStringLiteral("full_tunnel_ownership_ambiguous"));
            QVERIFY(runner->calls.isEmpty());
            QCOMPARE(result.diagnostics.value(QStringLiteral("rejectedProtocol")).toString(),
                     protocol);
            QVERIFY(result.diagnostics.value(QStringLiteral("rejectedProtocolLine"))
                            .toString().size() <= 512);
        }
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

    void ambiguousMainRouteAttributesAreRejectedBeforeMutation()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        auto runner = std::make_shared<FakeCommandRunner>();
        runner->mainRouteOutput = QStringLiteral(
                "10.8.1.0/24 dev amn0 metric 1 proto 187 mtu 1500\n");
        LinuxRouteReconciler reconciler(
                runner, temporaryDirectory.filePath(QStringLiteral("routes.json")));
        const RouteReconcileResult result = reconciler.apply(
                QStringLiteral("amn0"), { QStringLiteral("10.8.1.0/24") });
        QVERIFY(!result.ok);
        QCOMPARE(result.code, QStringLiteral("only_forward_route_conflict"));
        QVERIFY(runner->calls.isEmpty());
    }

    void missingReceiptPreservesForeignNarrowBypassAndUses1001()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        auto runner = std::make_shared<FakeCommandRunner>();
        runner->capturedOutputs = {
            QStringLiteral("1000: from all to 85.208.87.69 lookup main\n"),
            QString(), QString(), QString(), QString() };
        const QString statePath = temporaryDirectory.filePath(QStringLiteral("routes.json"));
        LinuxRouteReconciler reconciler(runner, statePath);
        QVERIFY(!reconciler.status().value(QStringLiteral("recoveryRequired")).toBool());

        const RouteReconcileResult result = reconciler.applyAllExcept(
                QStringLiteral("wg0"), { QStringLiteral("10.8.1.4") });
        QVERIFY2(result.ok, qPrintable(result.message));
        const QStringList expectedAdd {
            QStringLiteral("rule"), QStringLiteral("add"), QStringLiteral("priority"),
            QStringLiteral("1001"), QStringLiteral("to"), QStringLiteral("10.8.1.4"),
            QStringLiteral("lookup"), QStringLiteral("main") };
        QVERIFY(std::any_of(runner->calls.cbegin(), runner->calls.cend(),
                            [&expectedAdd](const auto &call) {
            return call.arguments == expectedAdd;
        }));
        QVERIFY(!std::any_of(runner->calls.cbegin(), runner->calls.cend(),
                             [](const auto &call) {
            return call.arguments.contains(QStringLiteral("1000"))
                && call.arguments.contains(QStringLiteral("del"));
        }));
    }

    void onlyForwardLegacyPriority1000IsNormalized()
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
        }).toJson(QJsonDocument::Compact)) > 0);
        state.close();
        auto runner = std::make_shared<FakeCommandRunner>();
        runner->capturedOutputs = {
            QStringLiteral("1000: from all to 85.208.87.69 lookup main\n"),
            QString(), QString(), QString(), QString() };
        LinuxRouteReconciler reconciler(runner, statePath);
        QVERIFY(!reconciler.status().value(QStringLiteral("recoveryRequired")).toBool());
        QCOMPARE(reconciler.status().value(QStringLiteral("bypassRulePriority")).toInt(), 1001);
        QFile normalized(statePath);
        QVERIFY(normalized.open(QIODevice::ReadOnly));
        const QJsonObject object = QJsonDocument::fromJson(normalized.readAll()).object();
        QCOMPARE(object.value(QStringLiteral("bypassRulePriority")).toInt(), 1001);
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
            QStringLiteral("priority"), QStringLiteral("1001"), QStringLiteral("to"),
            QStringLiteral("10.8.1.4"), QStringLiteral("lookup"), QStringLiteral("main") };
        const QStringList expectedFullRule {
            QStringLiteral("rule"), QStringLiteral("add"),
            QStringLiteral("priority"), QStringLiteral("1100"),
            QStringLiteral("lookup"), QStringLiteral("51821") };
        const QStringList expectedFullV6Rule {
            QStringLiteral("-6"), QStringLiteral("rule"), QStringLiteral("add"),
            QStringLiteral("priority"), QStringLiteral("1100"),
            QStringLiteral("lookup"), QStringLiteral("51821") };
        QCOMPARE(runner->calls.at(0).arguments, expectedV4Route);
        // The policy rule is enabled only after critical selectors are safe;
        // with no critical selectors this means full rule first, then the
        // ordinary policy batch.
        QCOMPARE(runner->calls.at(4).arguments, expectedFullRule);
        QCOMPARE(runner->calls.at(5).arguments, expectedFullV6Rule);
        QCOMPARE(runner->calls.at(6).arguments, expectedBypassRule);

        const RouteReconcileResult cleared = reconciler.clear();
        QVERIFY2(cleared.ok, "full-tunnel route clear failed");
        QCOMPARE(reconciler.status().value(QStringLiteral("mode")).toString(),
                 QStringLiteral("only-forward"));
        QVERIFY(reconciler.status().value(QStringLiteral("bypassRoutes")).toArray().isEmpty());
        const QStringList expectedBypassDelete {
            QStringLiteral("rule"), QStringLiteral("del"),
            QStringLiteral("priority"), QStringLiteral("1001"), QStringLiteral("to"),
            QStringLiteral("10.8.1.4"), QStringLiteral("lookup"), QStringLiteral("main") };
        QVERIFY(std::any_of(runner->calls.cbegin(), runner->calls.cend(),
                            [&expectedBypassDelete](const auto &call) {
            return call.arguments == expectedBypassDelete;
        }));
    }

    void derivesAllDirectPrivateUnderlaySubnets()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        auto runner = std::make_shared<FakeCommandRunner>();
        runner->mainRouteOutput = QStringLiteral(
                "default via 192.168.1.1 dev wlp9s0 proto dhcp metric 600\n"
                "192.168.1.0/24 dev wlp9s0 proto 2 scope 253 src 192.168.1.98 metric 600\n"
                "10.8.1.0/24 dev amn0 proto 2 scope 253 src 10.8.1.2 metric 50\n"
                "172.17.0.0/16 dev docker0 proto 2 scope 253 src 172.17.0.1 metric 0\n"
                "172.18.0.0/16 dev br-a1b2c3d4e5f6 proto 2 scope 253 src 172.18.0.1 metric 0\n"
                "192.168.1.1 via 192.168.1.1 dev wlp9s0 proto 2 scope 253 metric 600\n"
                "127.0.0.0/8 dev lo proto 2 scope 253 src 127.0.0.1 metric 0\n"
                "10.9.0.0/16 dev tun0 proto 2 scope 253 src 10.9.0.1 metric 0\n"
                "203.0.113.0/24 dev wlp9s0 proto 2 scope 253 src 203.0.113.2 metric 600\n"
                "192.168.2.0/24 dev wlp9s0 proto static scope 253 src 192.168.2.98 metric 600\n");
        LinuxRouteReconciler reconciler(
                runner, temporaryDirectory.filePath(QStringLiteral("routes.json")));
        QString error;
        const QStringList routes = reconciler.activeUnderlayProtectedRoutes(
                QStringLiteral("amn0"), { QStringLiteral("10.8.1.0/24") }, &error);
        QVERIFY2(error.isEmpty(), qPrintable(error));
        const QStringList expectedRoutes { QStringLiteral("192.168.1.0/24"),
                                           QStringLiteral("172.17.0.0/16"),
                                           QStringLiteral("172.18.0.0/16"),
                                           QStringLiteral("192.168.2.0/24") };
        QCOMPARE(routes, expectedRoutes);
    }

    void criticalBypassBatchPrecedesPolicyBatch()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        auto runner = std::make_shared<FakeCommandRunner>();
        runner->emitBypassWithoutFullTunnel = true;
        LinuxRouteReconciler reconciler(
                runner, temporaryDirectory.filePath(QStringLiteral("routes.json")));
        const RouteReconcileResult criticalResult = reconciler.applyAllExcept(
                              QStringLiteral("wg0"),
                              { QStringLiteral("192.168.1.0/24"), QStringLiteral("8.8.8.8") },
                              { QStringLiteral("192.168.1.0/24") });
        QVERIFY2(criticalResult.ok,
                 qPrintable(criticalResult.message + QStringLiteral(" ")
                            + QString::fromUtf8(QJsonDocument(criticalResult.diagnostics)
                                                        .toJson(QJsonDocument::Compact))));
        QCOMPARE(runner->batchContents.size(), 2);
        QCOMPARE(runner->batchContents.at(0).constFirst().value(5),
                 QStringLiteral("192.168.1.0/24"));
        QCOMPARE(runner->batchContents.at(1).constFirst().value(5),
                 QStringLiteral("8.8.8.8"));
        int criticalBatchIndex = -1;
        int fullRuleIndex = -1;
        int policyBatchIndex = -1;
        for (int index = 0; index < runner->calls.size(); ++index) {
            const auto &call = runner->calls.at(index);
            if (call.operation == QStringLiteral("run")
                && call.arguments.contains(QStringLiteral("priority"))
                && call.arguments.contains(QStringLiteral("192.168.1.0/24"))) {
                criticalBatchIndex = index;
            } else if (call.operation == QStringLiteral("run")
                       && call.arguments == QStringList {
                           QStringLiteral("rule"), QStringLiteral("add"),
                           QStringLiteral("priority"), QStringLiteral("1100"),
                           QStringLiteral("lookup"), QStringLiteral("51821") }) {
                fullRuleIndex = index;
            }
        }
        // Batch contents do not carry the parent call index; locate the
        // policy command through the recorded child calls below.
        for (int index = 0; index < runner->calls.size(); ++index) {
            const auto &call = runner->calls.at(index);
            if (call.operation == QStringLiteral("run")
                && call.arguments.contains(QStringLiteral("8.8.8.8"))) {
                policyBatchIndex = index;
                break;
            }
        }
        QVERIFY(criticalBatchIndex >= 0);
        QVERIFY(fullRuleIndex > criticalBatchIndex);
        QVERIFY(policyBatchIndex > fullRuleIndex);
        QCOMPARE(reconciler.status().value(QStringLiteral("criticalBypassRoutes")).toArray(),
                 QJsonArray { QStringLiteral("192.168.1.0/24") });
    }

    void largeBypassSetUsesBoundedBatchesAndExactReceipt()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        auto runner = std::make_shared<FakeCommandRunner>();
        LinuxRouteReconciler reconciler(
                runner, temporaryDirectory.filePath(QStringLiteral("routes.json")));
        QStringList routes;
        for (int index = 1; index <= 130; ++index) {
            routes.append(QStringLiteral("8.8.%1.%2")
                                  .arg(index / 255).arg(index % 255));
        }
        const RouteReconcileResult applied = reconciler.applyAllExcept(QStringLiteral("wg0"), routes);
        QVERIFY2(applied.ok, qPrintable(applied.message));
        QCOMPARE(runner->batchCalls, 9);
        QCOMPARE(runner->batchContents.size(), 9);
        QCOMPARE(reconciler.status().value(QStringLiteral("bypassRoutes")).toArray().size(), 130);
        const RouteReconcileResult cleared = reconciler.clear();
        QVERIFY2(cleared.ok, qPrintable(cleared.message));
        QCOMPARE(runner->batchCalls, 18);
    }

    void stateful1212BypassSetMatchesKernelWithoutRollback()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        auto runner = std::make_shared<FakeCommandRunner>();
        LinuxRouteReconciler reconciler(
                runner, temporaryDirectory.filePath(QStringLiteral("routes.json")));
        QStringList routes;
        for (int index = 1; index <= 1212; ++index) {
            routes.append(QStringLiteral("8.8.%1.%2")
                                  .arg(index / 255).arg(index % 255));
        }

        const RouteReconcileResult result = reconciler.applyAllExcept(
                QStringLiteral("wg0"), routes);
        QVERIFY2(result.ok, qPrintable(result.message));
        QCOMPARE(reconciler.status().value(QStringLiteral("bypassRoutes")).toArray().size(),
                 routes.size());
        QCOMPARE(runner->managedBypassRoutes.size(), routes.size());
        QCOMPARE(runner->batchCalls, (routes.size() + 15) / 16);
        QVERIFY(std::none_of(runner->calls.cbegin(), runner->calls.cend(),
                             [](const FakeCommandRunner::Call &call) {
            return call.arguments.contains(QStringLiteral("del"));
        }));
    }

    void bypassHostAndExplicitHostPrefixCompareIdentically()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        auto runner = std::make_shared<FakeCommandRunner>();
        runner->explicitHostPrefixes = true;
        LinuxRouteReconciler reconciler(
                runner, temporaryDirectory.filePath(QStringLiteral("routes.json")));
        const RouteReconcileResult result = reconciler.applyAllExcept(
                QStringLiteral("wg0"), { QStringLiteral("8.8.8.8") });
        QVERIFY2(result.ok, qPrintable(result.message));
        QCOMPARE(reconciler.status().value(QStringLiteral("bypassRoutes")).toArray(),
                 QJsonArray { QStringLiteral("8.8.8.8") });
    }

    void malformedSelectedPriorityFailsPostconditionClosed()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        auto runner = std::make_shared<FakeCommandRunner>();
        runner->malformedPostcondition = true;
        LinuxRouteReconciler reconciler(
                runner, temporaryDirectory.filePath(QStringLiteral("routes.json")));
        const RouteReconcileResult result = reconciler.applyAllExcept(
                QStringLiteral("wg0"), { QStringLiteral("10.8.1.4") });
        QVERIFY(!result.ok);
        QCOMPARE(result.code, QStringLiteral("full_tunnel_postcondition_failed"));
        QVERIFY(result.diagnostics.value(QStringLiteral("committedValid")).toBool());
        QCOMPARE(result.diagnostics.value(QStringLiteral("tableLineCount")).toInt(), 4);
        QCOMPARE(result.diagnostics.value(QStringLiteral("expectedPrefixCount")).toInt(), 4);
        QCOMPARE(result.diagnostics.value(QStringLiteral("fullV4Count")).toInt(), 1);
        QCOMPARE(result.diagnostics.value(QStringLiteral("fullV6Count")).toInt(), 1);
        QVERIFY(!result.diagnostics.value(QStringLiteral("selectedRulesValid")).toBool());
        QVERIFY(result.diagnostics.contains(QStringLiteral("selectedBypassPriority")));
        QVERIFY(result.diagnostics.contains(QStringLiteral("selectedFullPriority")));
        QVERIFY(!reconciler.status().value(QStringLiteral("recoveryRequired")).toBool());
        QVERIFY(reconciler.status().value(QStringLiteral("postconditionDiagnostics")).isObject());
    }

    void failedPostconditionRollbackLeavesRecoveryRequired()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        auto runner = std::make_shared<FakeCommandRunner>();
        runner->malformedPostcondition = true;
        // Four table routes, one bypass batch, and two policy rules precede
        // the first rollback route deletion.
        runner->failAtCall = 11;
        LinuxRouteReconciler reconciler(
                runner, temporaryDirectory.filePath(QStringLiteral("routes.json")));
        const RouteReconcileResult result = reconciler.applyAllExcept(
                QStringLiteral("wg0"), { QStringLiteral("10.8.1.4") });
        QVERIFY(!result.ok);
        QCOMPARE(result.code, QStringLiteral("recovery_required"));
        QVERIFY(reconciler.status().value(QStringLiteral("recoveryRequired")).toBool());
    }

    void postconditionFailureCanDegradeToOnlyForward()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        auto runner = std::make_shared<FakeCommandRunner>();
        runner->malformedPostcondition = true;
        HeadlessRoutingController controller(
                runner, temporaryDirectory.filePath(QStringLiteral("routes.json")));
        Profile profile;
        profile.id = QStringLiteral("degraded");
        profile.protocol = QStringLiteral("wireguard");
        profile.interfaceName = QStringLiteral("wg0");
        profile.routingMode = QStringLiteral("all-except");
        profile.serverRulesUrl = QStringLiteral("https://policy.example/rules.json");
        profile.forwardRoutes = { QStringLiteral("10.8.1.0/24") };
        const RoutingResult result = controller.connect(profile);
        QVERIFY(!result.ok);
        QCOMPARE(result.code, QStringLiteral("routing_degraded"));
        const QJsonObject status = controller.status();
        QCOMPARE(status.value(QStringLiteral("mode")).toString(),
                 QStringLiteral("only-forward"));
        QVERIFY(status.value(QStringLiteral("routingDegraded")).toBool());
        QVERIFY(!status.value(QStringLiteral("recoveryRequired")).toBool());
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
        runner->capturedOutputs += runner->capturedOutputs;
        LinuxRouteReconciler reconciler(
                runner, temporaryDirectory.filePath(QStringLiteral("routes.json")));
        const RouteReconcileResult result = reconciler.applyAllExcept(
                QStringLiteral("wg0"), { QStringLiteral("10.8.1.4") });
        QVERIFY(!result.ok);
        QCOMPARE(result.code, QStringLiteral("full_tunnel_rule_conflict"));
        QVERIFY(runner->calls.isEmpty());
    }

    void broadForeignMainRuleFailsBeforeHostMutation()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        auto runner = std::make_shared<FakeCommandRunner>();
        runner->capturedOutputs = {
            QStringLiteral("1000: from all lookup main\n"),
            QStringLiteral("1000: from all lookup main\n"),
            QString(), QString(), QString() };
        runner->capturedOutputs += runner->capturedOutputs;
        LinuxRouteReconciler reconciler(
                runner, temporaryDirectory.filePath(QStringLiteral("routes.json")));
        const RouteReconcileResult result = reconciler.applyAllExcept(
                QStringLiteral("wg0"), { QStringLiteral("85.208.87.69") });
        QVERIFY(!result.ok);
        QCOMPARE(result.code, QStringLiteral("full_tunnel_rule_conflict"));
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
                && call.arguments.contains(QStringLiteral("1001"));
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
            QStringLiteral("1001: to 10.8.1.4 lookup main\n1100: from all lookup 51821\n"),
            QStringLiteral("1100: from all lookup 51821\n"),
            QStringLiteral("0.0.0.0/1 dev wg0 proto 186\n128.0.0.0/1 dev wg0 proto 186\n"),
            QStringLiteral("::/1 dev wg0 proto 186\n8000::/1 dev wg0 proto 186\n"),
            QString() };
        // initializeState() and the subsequent apply both probe the kernel;
        // provide the same deterministic snapshot for each probe cycle.
        secondRunner->capturedOutputs += secondRunner->capturedOutputs;
        secondRunner->fullTunnelInstalled = true;
        secondRunner->managedBypassRoutes.insert(QStringLiteral("10.8.1.4"));
        LinuxRouteReconciler second(secondRunner, statePath);
        const RouteReconcileResult secondResult = second.applyAllExcept(
                QStringLiteral("wg0"), { QStringLiteral("10.8.1.4") });
        QVERIFY2(secondResult.ok, qPrintable(secondResult.message));
        QCOMPARE(second.status().value(QStringLiteral("fullRulePriority")).toInt(), 1100);
    }

    void legacyOfflineReceiptInfersAndPersistsNeedsReapply()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString statePath = temporaryDirectory.filePath(QStringLiteral("routes.json"));
        QFile state(statePath);
        QVERIFY(state.open(QIODevice::WriteOnly));
        QVERIFY(state.write(R"json({"version":2,"mode":"all-except","interface":"wg0",
            "routes":[],"bypassRoutes":[],"bypassRulePriority":1000,
            "fullRulePriority":1100})json") > 0);
        state.close();

        auto runner = std::make_shared<FakeCommandRunner>();
        runner->capturedOutputs = {
            QStringLiteral("1100: from all lookup 51821\n"),
            QStringLiteral("1100: from all lookup 51821\n"),
            QString(), QString(), QString(), QString() };
        runner->dnsLinkAbsent = true;
        LinuxRouteReconciler reconciler(runner, statePath);
        const QJsonObject status = reconciler.status();
        QVERIFY(!status.value(QStringLiteral("recoveryRequired")).toBool());
        QVERIFY(status.value(QStringLiteral("needsReapply")).toBool());
        QVERIFY(status.value(QStringLiteral("interfaceOffline")).toBool());

        QFile migrated(statePath);
        QVERIFY(migrated.open(QIODevice::ReadOnly));
        const QJsonDocument document = QJsonDocument::fromJson(migrated.readAll());
        QVERIFY(document.isObject());
        QVERIFY(document.object().value(QStringLiteral("needsReapply")).isBool());
        QVERIFY(document.object().value(QStringLiteral("needsReapply")).toBool());
    }

    void explicitFalseOfflineReceiptInfersAndReapplies()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString statePath = temporaryDirectory.filePath(QStringLiteral("routes.json"));
        QFile state(statePath);
        QVERIFY(state.open(QIODevice::WriteOnly));
        QVERIFY(state.write(R"json({"version":2,"mode":"all-except","interface":"wg0",
            "routes":[],"bypassRoutes":[],"bypassRulePriority":1000,
            "fullRulePriority":1100,"needsReapply":false})json") > 0);
        state.close();

        auto runner = std::make_shared<FakeCommandRunner>();
        runner->capturedOutputs = {
            QStringLiteral("1100: from all lookup 51821\n"),
            QStringLiteral("1100: from all lookup 51821\n"),
            QString(), QString(), QString(), QString() };
        runner->dnsLinkAbsent = true;
        LinuxRouteReconciler reconciler(runner, statePath);
        const QJsonObject offline = reconciler.status();
        QVERIFY(!offline.value(QStringLiteral("recoveryRequired")).toBool());
        QVERIFY(offline.value(QStringLiteral("needsReapply")).toBool());
        QVERIFY(offline.value(QStringLiteral("interfaceOffline")).toBool());

        // Once the native interface/table is back, an all-except reapply must
        // retire the startup-only marker and persist the healthy false value.
        runner->dnsLinkAbsent = false;
        runner->capturedOutputs += {
            QStringLiteral("1100: from all lookup 51821\n"),
            QStringLiteral("1100: from all lookup 51821\n"),
            QString(), QString(), QString() };
        const RouteReconcileResult reapplied = reconciler.applyAllExcept(
                QStringLiteral("wg0"), {});
        QVERIFY2(reapplied.ok, qPrintable(reapplied.message));
        QVERIFY(!reconciler.status().value(QStringLiteral("needsReapply")).toBool());
        QFile healthy(statePath);
        QVERIFY(healthy.open(QIODevice::ReadOnly));
        const QJsonDocument healthyDocument = QJsonDocument::fromJson(healthy.readAll());
        QVERIFY(healthyDocument.isObject());
        QVERIFY(!healthyDocument.object().value(QStringLiteral("needsReapply")).toBool());
    }

    void presentInterfaceWithEmptyTableFailsClosed()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString statePath = temporaryDirectory.filePath(QStringLiteral("routes.json"));
        QFile state(statePath);
        QVERIFY(state.open(QIODevice::WriteOnly));
        QVERIFY(state.write(R"json({"version":2,"mode":"all-except","interface":"wg0",
            "routes":[],"bypassRoutes":[],"bypassRulePriority":1000,
            "fullRulePriority":1100,"needsReapply":false})json") > 0);
        state.close();

        auto runner = std::make_shared<FakeCommandRunner>();
        runner->capturedOutputs = {
            QStringLiteral("1100: from all lookup 51821\n"),
            QStringLiteral("1100: from all lookup 51821\n"),
            QString(), QString(), QString() };
        LinuxRouteReconciler reconciler(runner, statePath);
        QVERIFY(reconciler.status().value(QStringLiteral("recoveryRequired")).toBool());
        QVERIFY(!reconciler.status().value(QStringLiteral("needsReapply")).toBool());
        QVERIFY(runner->calls.isEmpty());
    }

    void explicitlyDownInterfaceWithEmptyTableInfersReapply()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString statePath = temporaryDirectory.filePath(QStringLiteral("routes.json"));
        QFile state(statePath);
        QVERIFY(state.open(QIODevice::WriteOnly));
        QVERIFY(state.write(R"json({"version":2,"mode":"all-except","interface":"wg0",
            "routes":[],"bypassRoutes":[],"bypassRulePriority":1000,
            "fullRulePriority":1100,"needsReapply":false})json") > 0);
        state.close();

        auto runner = std::make_shared<FakeCommandRunner>();
        runner->capturedOutputs = {
            QStringLiteral("1100: from all lookup 51821\n"),
            QStringLiteral("1100: from all lookup 51821\n"),
            QString(), QString(), QString() };
        runner->linkDown = true;
        LinuxRouteReconciler reconciler(runner, statePath);
        QVERIFY(!reconciler.status().value(QStringLiteral("recoveryRequired")).toBool());
        QVERIFY(reconciler.status().value(QStringLiteral("needsReapply")).toBool());
        QVERIFY(reconciler.status().value(QStringLiteral("interfaceOffline")).toBool());
    }

    void offlineAllExceptWithMissingDnsBindingRetainsReceiptForReapply()
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
            { QStringLiteral("dnsInterface"), QStringLiteral("wg0") },
            { QStringLiteral("dnsServers"), QJsonArray { QStringLiteral("10.8.1.53") } },
            { QStringLiteral("dnsDomains"), QJsonArray { QStringLiteral("~.") } },
        }).toJson(QJsonDocument::Compact)) > 0);
        state.close();

        auto runner = std::make_shared<FakeCommandRunner>();
        runner->capturedOutputs = {
            QStringLiteral("1100: from all lookup 51821\n"),
            QStringLiteral("1100: from all lookup 51821\n"),
            QString(), QString(), QString(),
        };
        runner->dnsLinkAbsent = true;
        runner->dnsResolverBindingAbsent = true;
        LinuxRouteReconciler reconciler(runner, statePath);
        const QJsonObject offline = reconciler.status();
        QVERIFY(!offline.value(QStringLiteral("recoveryRequired")).toBool());
        QVERIFY(offline.value(QStringLiteral("needsReapply")).toBool());
        QVERIFY(offline.value(QStringLiteral("interfaceOffline")).toBool());
        QCOMPARE(offline.value(QStringLiteral("dnsInterface")).toString(), QStringLiteral("wg0"));
        QCOMPARE(offline.value(QStringLiteral("dnsServers")).toArray().at(0).toString(),
                 QStringLiteral("10.8.1.53"));
        QCOMPARE(offline.value(QStringLiteral("dnsDomains")).toArray().at(0).toString(),
                 QStringLiteral("~."));

        // Restore the native link/table, then prove the exact DNS readback as
        // the autoconnect path would do.  The startup marker is retired only
        // after the full-tunnel apply succeeds.
        runner->dnsLinkAbsent = false;
        runner->dnsResolverBindingAbsent = false;
        runner->capturedOutputs += {
            QString(), QString(),
            QStringLiteral("1100: from all lookup 51821\n"),
            QStringLiteral("1100: from all lookup 51821\n"),
            QString(), QString(), QString(),
        };
        const RouteReconcileResult reapplied = reconciler.applyAllExcept(
                QStringLiteral("wg0"), {});
        QVERIFY2(reapplied.ok, qPrintable(reapplied.message));
        const RouteReconcileResult dns = reconciler.configureDns(
                QStringLiteral("wg0"), { QStringLiteral("10.8.1.53") },
                { QStringLiteral("~.") });
        QVERIFY2(dns.ok, qPrintable(dns.message));
        QVERIFY(!reconciler.status().value(QStringLiteral("needsReapply")).toBool());

        const auto makeHealthyRunner = []() {
            auto healthy = std::make_shared<FakeCommandRunner>();
            healthy->capturedOutputs = {
                QStringLiteral("1100: from all lookup 51821\n"),
                QStringLiteral("1100: from all lookup 51821\n"),
                QStringLiteral("0.0.0.0/1 dev wg0 proto 186\n128.0.0.0/1 dev wg0 proto 186\n"),
                QStringLiteral("::/1 dev wg0 proto 186\n8000::/1 dev wg0 proto 186\n"),
                QString(),
            };
            healthy->fullTunnelInstalled = true;
            healthy->dnsServers = { QStringLiteral("10.8.1.53") };
            healthy->dnsDomains = { QStringLiteral("~.") };
            return healthy;
        };
        auto secondRunner = makeHealthyRunner();
        LinuxRouteReconciler secondRestart(secondRunner, statePath);
        QVERIFY(!secondRestart.status().value(QStringLiteral("recoveryRequired")).toBool());
        QVERIFY(!secondRestart.status().value(QStringLiteral("needsReapply")).toBool());
        QCOMPARE(secondRestart.status().value(QStringLiteral("dnsInterface")).toString(),
                 QStringLiteral("wg0"));
        auto thirdRunner = makeHealthyRunner();
        LinuxRouteReconciler thirdRestart(thirdRunner, statePath);
        QVERIFY(!thirdRestart.status().value(QStringLiteral("recoveryRequired")).toBool());
        QVERIFY(!thirdRestart.status().value(QStringLiteral("needsReapply")).toBool());
        QCOMPARE(thirdRestart.status().value(QStringLiteral("dnsServers")).toArray().at(0).toString(),
                 QStringLiteral("10.8.1.53"));
    }

    void exactLiveLike1216BypassReceiptInfersReapply()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString statePath = temporaryDirectory.filePath(QStringLiteral("routes.json"));

        QStringList bypassRoutes;
        for (int index = 1; index <= 1216; ++index) {
            bypassRoutes.append(QStringLiteral("8.8.%1.%2")
                                        .arg(index / 256).arg(index % 256));
        }
        const QStringList criticalRoutes = bypassRoutes.mid(0, 5);
        QFile state(statePath);
        QVERIFY(state.open(QIODevice::WriteOnly));
        const QJsonObject receipt {
            { QStringLiteral("version"), 2 },
            { QStringLiteral("mode"), QStringLiteral("all-except") },
            { QStringLiteral("interface"), QStringLiteral("wg0") },
            { QStringLiteral("routes"), QJsonArray() },
            { QStringLiteral("bypassRoutes"), QJsonArray::fromStringList(bypassRoutes) },
            { QStringLiteral("criticalBypassRoutes"), QJsonArray::fromStringList(criticalRoutes) },
            { QStringLiteral("bypassRulePriority"), 1001 },
            { QStringLiteral("fullRulePriority"), 1100 },
            { QStringLiteral("dnsInterface"), QStringLiteral("wg0") },
            { QStringLiteral("dnsServers"), QJsonArray { QStringLiteral("10.8.1.53") } },
            { QStringLiteral("dnsDomains"), QJsonArray { QStringLiteral("~.") } },
        };
        QVERIFY(state.write(QJsonDocument(receipt).toJson(QJsonDocument::Compact)) > 0);
        state.close();

        QString v4Rules;
        for (const QString &route : bypassRoutes) {
            v4Rules += QStringLiteral("1001: from all to %1 lookup main\n").arg(route);
        }
        v4Rules += QStringLiteral("1100: from all lookup 51821\n");
        auto runner = std::make_shared<FakeCommandRunner>();
        runner->capturedOutputs = {
            v4Rules,
            QStringLiteral("1100: from all lookup 51821\n"),
            QString(), QString(), QString(),
        };
        runner->dnsLinkAbsent = true;
        runner->missingDeviceMessage = QStringLiteral("Device \"%1\" does not exist");
        runner->dnsResolverBindingAbsent = true;
        LinuxRouteReconciler reconciler(runner, statePath);

        const QJsonObject status = reconciler.status();
        QVERIFY2(!status.value(QStringLiteral("recoveryRequired")).toBool(),
                 qPrintable(status.value(QStringLiteral("lastError")).toString()));
        QVERIFY(status.value(QStringLiteral("needsReapply")).toBool());
        QVERIFY(status.value(QStringLiteral("interfaceOffline")).toBool());
        QCOMPARE(status.value(QStringLiteral("bypassRoutes")).toArray().size(), 1216);
        QCOMPARE(status.value(QStringLiteral("criticalBypassRoutes")).toArray().size(), 5);
        QCOMPARE(status.value(QStringLiteral("dnsInterface")).toString(), QStringLiteral("wg0"));
        QVERIFY(status.value(QStringLiteral("lastError")).toString().isEmpty());
    }

    void invalidOfflineLkgReceiptFailsClosedWithoutMutation()
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
            { QStringLiteral("bypassRoutes"), QJsonArray { QStringLiteral("not-a-route") } },
            { QStringLiteral("criticalBypassRoutes"), QJsonArray() },
            { QStringLiteral("bypassRulePriority"), 1001 },
            { QStringLiteral("fullRulePriority"), 1100 },
            { QStringLiteral("needsReapply"), true },
        }).toJson(QJsonDocument::Compact)) > 0);
        state.close();

        auto runner = std::make_shared<FakeCommandRunner>();
        LinuxRouteReconciler reconciler(runner, statePath);
        const QJsonObject status = reconciler.status();
        QVERIFY(status.value(QStringLiteral("recoveryRequired")).toBool());
        QCOMPARE(status.value(QStringLiteral("lastError")).toString(),
                 QStringLiteral("load_state_rejected:receipt_bypass_routes"));
        QVERIFY(runner->calls.isEmpty());
    }

    void policyRefreshAdvancesReceiptWithoutClearingTunnel()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        QTcpServer server;
        QVERIFY(server.listen(QHostAddress::AnyIPv4));
        QByteArray response = QByteArrayLiteral(
                "{\"serverExcept\":{\"8.8.8.8\":\"\"}}\n");
        QObject::connect(&server, &QTcpServer::newConnection, &server, [&]() {
            while (server.hasPendingConnections()) {
                QTcpSocket *socket = server.nextPendingConnection();
                QObject::connect(socket, &QTcpSocket::readyRead, socket, [socket, &response]() {
                    socket->readAll();
                    const QByteArray body = response;
                    socket->write(QByteArrayLiteral("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ")
                                  + QByteArray::number(body.size())
                                  + QByteArrayLiteral("\r\nConnection: close\r\n\r\n") + body);
                    socket->disconnectFromHost();
                });
            }
        });

        auto runner = std::make_shared<FakeCommandRunner>();
        runner->mainRouteOutput = QStringLiteral(
                "default via 172.29.0.1 dev eth0 proto dhcp metric 100\n"
                "172.29.0.0/16 dev eth0 proto 2 scope 253 src 172.29.119.207 metric 100\n");
        const QString statePath = temporaryDirectory.filePath(QStringLiteral("routes.json"));
        HeadlessRoutingController controller(runner, statePath);
        Profile profile;
        profile.id = QStringLiteral("refresh-profile");
        profile.protocol = QStringLiteral("wireguard");
        profile.interfaceName = QStringLiteral("wg0");
        profile.routingMode = QStringLiteral("all-except");
        profile.forwardRoutes = { QStringLiteral("172.29.0.0/16") };
        profile.serverRulesUrl = QStringLiteral("http://172.29.119.207:%1/rules.json")
                .arg(server.serverPort());

        const RoutingResult connected = controller.connect(profile);
        QVERIFY2(connected.ok, qPrintable(connected.message));
        const QString firstRevision = controller.status()
                .value(QStringLiteral("policyRevision")).toString();
        QVERIFY(!firstRevision.isEmpty());
        QVERIFY(controller.status().value(QStringLiteral("policyLoaded")).toBool());

        response = QByteArrayLiteral("{\"serverExcept\":{\"8.8.8.9\":\"\"}}\n");
        const RoutingResult refreshed = controller.refresh(profile);
        QVERIFY2(refreshed.ok, qPrintable(refreshed.message));
        const QJsonObject status = controller.status();
        QVERIFY(status.value(QStringLiteral("policyLoaded")).toBool());
        QVERIFY(!status.value(QStringLiteral("policyRevision")).toString().isEmpty());
        QVERIFY(status.value(QStringLiteral("policyRevision")).toString() != firstRevision);
        QCOMPARE(status.value(QStringLiteral("mode")).toString(),
                 QStringLiteral("all-except"));
        QVERIFY(!status.value(QStringLiteral("recoveryRequired")).toBool());
    }

    void foreignEndpoint1000SurvivesOfflineReapplyAndRestarts()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString statePath = temporaryDirectory.filePath(QStringLiteral("routes.json"));

        QStringList bypassRoutes;
        for (int index = 1; index <= 1216; ++index) {
            bypassRoutes.append(QStringLiteral("8.8.%1.%2")
                                        .arg(index / 256).arg(index % 256));
        }
        const QString foreignRule =
                QStringLiteral("1000: from all to 85.208.87.69 lookup main");
        QFile state(statePath);
        QVERIFY(state.open(QIODevice::WriteOnly));
        QVERIFY(state.write(QJsonDocument(QJsonObject {
            { QStringLiteral("version"), 2 },
            { QStringLiteral("mode"), QStringLiteral("all-except") },
            { QStringLiteral("interface"), QStringLiteral("wg0") },
            { QStringLiteral("routes"), QJsonArray() },
            { QStringLiteral("bypassRoutes"), QJsonArray::fromStringList(bypassRoutes) },
            { QStringLiteral("criticalBypassRoutes"),
              QJsonArray::fromStringList(bypassRoutes.mid(0, 5)) },
            { QStringLiteral("bypassRulePriority"), 1001 },
            { QStringLiteral("fullRulePriority"), 1100 },
            { QStringLiteral("dnsInterface"), QStringLiteral("wg0") },
            { QStringLiteral("dnsServers"), QJsonArray { QStringLiteral("10.8.1.53") } },
            { QStringLiteral("dnsDomains"), QJsonArray { QStringLiteral("~.") } },
        }).toJson(QJsonDocument::Compact)) > 0);
        state.close();

        QString v4Rules;
        for (const QString &route : bypassRoutes) {
            v4Rules += QStringLiteral("1001: from all to %1 lookup main\n").arg(route);
        }
        v4Rules += foreignRule + QStringLiteral("\n1100: from all lookup 51821\n");
        auto runner = std::make_shared<FakeCommandRunner>();
        runner->capturedOutputs = {
            v4Rules,
            QStringLiteral("1100: from all lookup 51821\n"),
            QString(), QString(), QString(),
        };
        runner->foreignBypassRules = { foreignRule };
        for (const QString &route : bypassRoutes) runner->managedBypassRoutes.insert(route);
        runner->dnsLinkAbsent = true;
        runner->missingDeviceMessage = QStringLiteral("Device \"%1\" does not exist");
        runner->dnsResolverBindingAbsent = true;
        LinuxRouteReconciler reconciler(runner, statePath);

        const QJsonObject offline = reconciler.status();
        QVERIFY2(!offline.value(QStringLiteral("recoveryRequired")).toBool(),
                 qPrintable(offline.value(QStringLiteral("lastError")).toString()));
        QVERIFY(offline.value(QStringLiteral("needsReapply")).toBool());
        QVERIFY(offline.value(QStringLiteral("interfaceOffline")).toBool());
        QCOMPARE(offline.value(QStringLiteral("bypassRoutes")).toArray().size(), 1216);

        // Keep the receipt-bound rules visible while the managed table is
        // absent; the first route replacement below makes the table live
        // again in the fake kernel.
        runner->emitBypassWithoutFullTunnel = true;
        runner->emitFullTunnelRuleWithoutTable = true;
        runner->dnsLinkAbsent = false;
        runner->dnsResolverBindingAbsent = false;
        const RouteReconcileResult reapplied = reconciler.applyAllExcept(
                QStringLiteral("wg0"), bypassRoutes);
        QVERIFY2(reapplied.ok, qPrintable(reapplied.message));
        QVERIFY(!reconciler.status().value(QStringLiteral("needsReapply")).toBool());
        QCOMPARE(reconciler.status().value(QStringLiteral("bypassRoutes")).toArray().size(),
                 1216);
        QVERIFY(!QFileInfo::exists(statePath + QStringLiteral(".mutation-intent")));
        QVERIFY(!std::any_of(runner->calls.cbegin(), runner->calls.cend(), [](const auto &call) {
            return call.arguments.contains(QStringLiteral("del"))
                && call.arguments.contains(QStringLiteral("1000"));
        }));

        const auto makeHealthyRunner = [&bypassRoutes, &foreignRule]() {
            auto healthy = std::make_shared<FakeCommandRunner>();
            healthy->fullTunnelInstalled = true;
            healthy->managedBypassPriority = 1001;
            healthy->foreignBypassRules = { foreignRule };
            for (const QString &route : bypassRoutes) healthy->managedBypassRoutes.insert(route);
            QString v4Rules;
            for (const QString &route : bypassRoutes) {
                v4Rules += QStringLiteral("1001: from all to %1 lookup main\n").arg(route);
            }
            v4Rules += foreignRule + QStringLiteral("\n1100: from all lookup 51821\n");
            healthy->capturedOutputs = {
                v4Rules,
                QStringLiteral("1100: from all lookup 51821\n"),
                QStringLiteral("0.0.0.0/1 dev wg0 proto 186\n128.0.0.0/1 dev wg0 proto 186\n"),
                QStringLiteral("::/1 dev wg0 proto 186\n8000::/1 dev wg0 proto 186\n"),
                QString(),
            };
            healthy->dnsServers = { QStringLiteral("10.8.1.53") };
            healthy->dnsDomains = { QStringLiteral("~.") };
            return healthy;
        };
        auto secondRunner = makeHealthyRunner();
        LinuxRouteReconciler secondRestart(secondRunner, statePath);
        QVERIFY2(!secondRestart.status().value(QStringLiteral("recoveryRequired")).toBool(),
                 qPrintable(secondRestart.status().value(QStringLiteral("lastError")).toString()));
        QVERIFY(!secondRestart.status().value(QStringLiteral("needsReapply")).toBool());
        auto thirdRunner = makeHealthyRunner();
        LinuxRouteReconciler thirdRestart(thirdRunner, statePath);
        QVERIFY2(!thirdRestart.status().value(QStringLiteral("recoveryRequired")).toBool(),
                 qPrintable(thirdRestart.status().value(QStringLiteral("lastError")).toString()));
        QVERIFY(!thirdRestart.status().value(QStringLiteral("needsReapply")).toBool());
    }

    void orphanDynamicBypass1002StillFailsClosed()
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
            { QStringLiteral("bypassRoutes"), QJsonArray { QStringLiteral("8.8.8.8") } },
            { QStringLiteral("bypassRulePriority"), 1001 },
            { QStringLiteral("fullRulePriority"), 1100 },
        }).toJson(QJsonDocument::Compact)) > 0);
        state.close();
        auto runner = std::make_shared<FakeCommandRunner>();
        runner->capturedOutputs = {
            QStringLiteral("1001: from all to 8.8.8.8 lookup main\n"
                           "1002: from all to 8.8.8.9 lookup main\n"
                           "1100: from all lookup 51821\n"),
            QStringLiteral("1100: from all lookup 51821\n"),
            QStringLiteral("0.0.0.0/1 dev wg0 proto 186\n128.0.0.0/1 dev wg0 proto 186\n"),
            QStringLiteral("::/1 dev wg0 proto 186\n8000::/1 dev wg0 proto 186\n"),
            QString(),
        };
        LinuxRouteReconciler reconciler(runner, statePath);
        const QJsonObject status = reconciler.status();
        QVERIFY(status.value(QStringLiteral("recoveryRequired")).toBool());
        QCOMPARE(status.value(QStringLiteral("lastError")).toString(),
                 QStringLiteral("load_state_rejected:all_except_foreign_bypass_rule"));
        QVERIFY(runner->calls.isEmpty());
    }

    void liveLikeMissingBypassRuleReportsBoundedStartupReason()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString statePath = temporaryDirectory.filePath(QStringLiteral("routes.json"));
        const QStringList routes { QStringLiteral("8.8.8.8"), QStringLiteral("8.8.8.9") };
        QFile state(statePath);
        QVERIFY(state.open(QIODevice::WriteOnly));
        QVERIFY(state.write(QJsonDocument(QJsonObject {
            { QStringLiteral("version"), 2 },
            { QStringLiteral("mode"), QStringLiteral("all-except") },
            { QStringLiteral("interface"), QStringLiteral("wg0") },
            { QStringLiteral("routes"), QJsonArray() },
            { QStringLiteral("bypassRoutes"), QJsonArray::fromStringList(routes) },
            { QStringLiteral("criticalBypassRoutes"), QJsonArray() },
            { QStringLiteral("bypassRulePriority"), 1001 },
            { QStringLiteral("fullRulePriority"), 1100 },
        }).toJson(QJsonDocument::Compact)) > 0);
        state.close();
        auto runner = std::make_shared<FakeCommandRunner>();
        runner->capturedOutputs = {
            QStringLiteral("1001: from all to 8.8.8.8 lookup main\n1100: from all lookup 51821\n"),
            QStringLiteral("1100: from all lookup 51821\n"),
            QString(), QString(), QString(),
        };
        runner->dnsLinkAbsent = true;
        LinuxRouteReconciler reconciler(runner, statePath);
        const QJsonObject status = reconciler.status();
        QVERIFY(status.value(QStringLiteral("recoveryRequired")).toBool());
        QCOMPARE(status.value(QStringLiteral("lastError")).toString(),
                 QStringLiteral("load_state_rejected:all_except_bypass_missing"));
    }

    void presentInterfaceWithMissingDnsBindingFailsClosed()
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
            { QStringLiteral("dnsInterface"), QStringLiteral("wg0") },
            { QStringLiteral("dnsServers"), QJsonArray { QStringLiteral("10.8.1.53") } },
            { QStringLiteral("dnsDomains"), QJsonArray { QStringLiteral("~.") } },
        }).toJson(QJsonDocument::Compact)) > 0);
        state.close();

        auto runner = std::make_shared<FakeCommandRunner>();
        runner->capturedOutputs = {
            QStringLiteral("1100: from all lookup 51821\n"),
            QStringLiteral("1100: from all lookup 51821\n"),
            QStringLiteral("0.0.0.0/1 dev wg0 proto 186\n128.0.0.0/1 dev wg0 proto 186\n"),
            QStringLiteral("::/1 dev wg0 proto 186\n8000::/1 dev wg0 proto 186\n"),
            QString(),
        };
        runner->fullTunnelInstalled = true;
        runner->dnsResolverBindingAbsent = true;
        LinuxRouteReconciler reconciler(runner, statePath);
        QVERIFY(reconciler.status().value(QStringLiteral("recoveryRequired")).toBool());
        QVERIFY(!reconciler.status().value(QStringLiteral("needsReapply")).toBool());
    }

    void mismatchedDnsInterfaceFailsClosed()
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
            { QStringLiteral("dnsInterface"), QStringLiteral("eth0") },
            { QStringLiteral("dnsServers"), QJsonArray { QStringLiteral("10.8.1.53") } },
            { QStringLiteral("dnsDomains"), QJsonArray { QStringLiteral("~.") } },
        }).toJson(QJsonDocument::Compact)) > 0);
        state.close();

        auto runner = std::make_shared<FakeCommandRunner>();
        LinuxRouteReconciler reconciler(runner, statePath);
        QVERIFY(reconciler.status().value(QStringLiteral("recoveryRequired")).toBool());
        QVERIFY(runner->capturedArguments.isEmpty());
    }

    void staleTrueHealthyReceiptIsDerivedFalse()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString statePath = temporaryDirectory.filePath(QStringLiteral("routes.json"));
        QFile state(statePath);
        QVERIFY(state.open(QIODevice::WriteOnly));
        QVERIFY(state.write(R"json({"version":2,"mode":"all-except","interface":"wg0",
            "routes":[],"bypassRoutes":[],"bypassRulePriority":1000,
            "fullRulePriority":1100,"needsReapply":true})json") > 0);
        state.close();

        auto runner = std::make_shared<FakeCommandRunner>();
        runner->capturedOutputs = {
            QStringLiteral("1100: from all lookup 51821\n"),
            QStringLiteral("1100: from all lookup 51821\n"),
            QStringLiteral("0.0.0.0/1 dev wg0 proto 186\n128.0.0.0/1 dev wg0 proto 186\n"),
            QStringLiteral("::/1 dev wg0 proto 186\n8000::/1 dev wg0 proto 186\n"),
            QString() };
        LinuxRouteReconciler reconciler(runner, statePath);
        const QJsonObject healthy = reconciler.status();
        QVERIFY(!healthy.value(QStringLiteral("recoveryRequired")).toBool());
        QVERIFY(!healthy.value(QStringLiteral("needsReapply")).toBool());
        QFile rewritten(statePath);
        QVERIFY(rewritten.open(QIODevice::ReadOnly));
        const QJsonDocument document = QJsonDocument::fromJson(rewritten.readAll());
        QVERIFY(document.isObject());
        QVERIFY(!document.object().value(QStringLiteral("needsReapply")).toBool());
    }

    void staleControllerMarkerFollowsOfflineKernelEvidence()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString routeStatePath = temporaryDirectory.filePath(QStringLiteral("routes.json"));
        const QString controllerStatePath = temporaryDirectory.filePath(
                QStringLiteral("routing-controller.json"));
        QFile routeState(routeStatePath);
        QVERIFY(routeState.open(QIODevice::WriteOnly));
        QVERIFY(routeState.write(QJsonDocument(QJsonObject {
            { QStringLiteral("version"), 2 },
            { QStringLiteral("mode"), QStringLiteral("all-except") },
            { QStringLiteral("interface"), QStringLiteral("wg0") },
            { QStringLiteral("routes"), QJsonArray() },
            { QStringLiteral("bypassRoutes"), QJsonArray() },
            { QStringLiteral("criticalBypassRoutes"), QJsonArray() },
            { QStringLiteral("bypassRulePriority"), 1000 },
            { QStringLiteral("fullRulePriority"), 1100 },
            { QStringLiteral("needsReapply"), false },
        }).toJson(QJsonDocument::Compact)) > 0);
        routeState.close();
        QFile controllerState(controllerStatePath);
        QVERIFY(controllerState.open(QIODevice::WriteOnly));
        QVERIFY(controllerState.write(QJsonDocument(QJsonObject {
            { QStringLiteral("version"), 2 },
            { QStringLiteral("activeProfile"), QStringLiteral("offline") },
            { QStringLiteral("activeInterface"), QStringLiteral("wg0") },
            { QStringLiteral("policyRevision"), QString() },
            { QStringLiteral("policyContentHash"), QString() },
            { QStringLiteral("policySource"), QString() },
            { QStringLiteral("policyEndpoint"), QString() },
            { QStringLiteral("policyResolvedSites"), QJsonObject() },
            { QStringLiteral("policyLoaded"), false },
            { QStringLiteral("policyMetadata"), QJsonValue(QJsonValue::Null) },
            { QStringLiteral("routingDegraded"), false },
            { QStringLiteral("routingError"), QString() },
            { QStringLiteral("needsReapply"), false },
            { QStringLiteral("recoveryRequired"), false },
        }).toJson(QJsonDocument::Compact)) > 0);
        controllerState.close();

        auto runner = std::make_shared<FakeCommandRunner>();
        runner->capturedOutputs = {
            QStringLiteral("1100: from all lookup 51821\n"),
            QStringLiteral("1100: from all lookup 51821\n"),
            QString(), QString(), QString() };
        runner->dnsLinkAbsent = true;
        HeadlessRoutingController controller(runner, routeStatePath);
        const QJsonObject status = controller.status();
        QVERIFY(!status.value(QStringLiteral("recoveryRequired")).toBool());
        QVERIFY(status.value(QStringLiteral("needsReapply")).toBool());
        QVERIFY(status.value(QStringLiteral("interfaceOffline")).toBool());

        QFile rewritten(controllerStatePath);
        QVERIFY(rewritten.open(QIODevice::ReadOnly));
        const QJsonDocument document = QJsonDocument::fromJson(rewritten.readAll());
        QVERIFY(document.isObject());
        QVERIFY(document.object().value(QStringLiteral("needsReapply")).toBool());
    }

    void explicitFalseHealthyFullTunnelReceiptLoads()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString statePath = temporaryDirectory.filePath(QStringLiteral("routes.json"));
        QFile state(statePath);
        QVERIFY(state.open(QIODevice::WriteOnly));
        QVERIFY(state.write(R"json({"version":2,"mode":"all-except","interface":"wg0",
            "routes":[],"bypassRoutes":[],"bypassRulePriority":1000,
            "fullRulePriority":1100,"needsReapply":false})json") > 0);
        state.close();

        auto runner = std::make_shared<FakeCommandRunner>();
        runner->capturedOutputs = {
            QStringLiteral("1100: from all lookup 51821\n"),
            QStringLiteral("1100: from all lookup 51821\n"),
            QStringLiteral("0.0.0.0/1 dev wg0 proto 186\n128.0.0.0/1 dev wg0 proto 186\n"),
            QStringLiteral("::/1 dev wg0 proto 186\n8000::/1 dev wg0 proto 186\n"),
            QString(), QString() };
        LinuxRouteReconciler reconciler(runner, statePath);
        QVERIFY(!reconciler.status().value(QStringLiteral("recoveryRequired")).toBool());
        QVERIFY(!reconciler.status().value(QStringLiteral("needsReapply")).toBool());
        QVERIFY(!reconciler.status().value(QStringLiteral("interfaceOffline")).toBool());
    }

    void allExceptRetiresStaleAllowListBeforeReusingPriority()
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
            QStringLiteral("1000: to 10.8.1.4 lookup main\n1100: from all lookup 51821\n"),
            QStringLiteral("1100: from all lookup 51821\n"),
            QStringLiteral("0.0.0.0/1 dev wg0 proto 186\n128.0.0.0/1 dev wg0 proto 186\n"),
            QStringLiteral("::/1 dev wg0 proto 186\n8000::/1 dev wg0 proto 186\n"),
            QString(),
        };
        // The receipt load probes the kernel once, then applyAllExcept probes
        // it again. Feed both deterministic probe cycles to the fake runner.
        runner->capturedOutputs += runner->capturedOutputs;
        LinuxRouteReconciler reconciler(runner, statePath);
        const RouteReconcileResult result = reconciler.applyAllExcept(
                QStringLiteral("wg0"), { QStringLiteral("10.8.1.5") });
        QVERIFY2(result.ok, qPrintable(result.message));

        const QStringList staleDelete {
            QStringLiteral("rule"), QStringLiteral("del"),
            QStringLiteral("priority"), QStringLiteral("1000"), QStringLiteral("to"),
            QStringLiteral("10.8.1.4"), QStringLiteral("lookup"), QStringLiteral("main") };
        const QStringList replacementAdd {
            QStringLiteral("rule"), QStringLiteral("add"),
            QStringLiteral("priority"), QStringLiteral("1000"), QStringLiteral("to"),
            QStringLiteral("10.8.1.5"), QStringLiteral("lookup"), QStringLiteral("main") };
        int deleteIndex = -1;
        int addIndex = -1;
        for (int index = 0; index < runner->calls.size(); ++index) {
            if (runner->calls.at(index).arguments == staleDelete) deleteIndex = index;
            if (runner->calls.at(index).arguments == replacementAdd) addIndex = index;
        }
        QVERIFY(deleteIndex >= 0);
        QVERIFY(addIndex > deleteIndex);
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

    void emptyAllExceptPolicyReceiptRestartsSuccessfully()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        const QString routeStatePath = temporaryDirectory.filePath(QStringLiteral("routes.json"));
        const QString controllerStatePath = temporaryDirectory.filePath(QStringLiteral("routing-controller.json"));
        QFile routeState(routeStatePath);
        QVERIFY(routeState.open(QIODevice::WriteOnly));
        QVERIFY(routeState.write(QJsonDocument(QJsonObject {
            { QStringLiteral("version"), 2 },
            { QStringLiteral("mode"), QStringLiteral("all-except") },
            { QStringLiteral("interface"), QStringLiteral("wg0") },
            { QStringLiteral("routes"), QJsonArray() },
            { QStringLiteral("bypassRoutes"), QJsonArray() },
            { QStringLiteral("criticalBypassRoutes"), QJsonArray() },
            { QStringLiteral("bypassRulePriority"), 1001 },
            { QStringLiteral("fullRulePriority"), 1100 },
            { QStringLiteral("dnsInterface"), QString() },
            { QStringLiteral("dnsServers"), QJsonArray() },
            { QStringLiteral("dnsDomains"), QJsonArray() },
        }).toJson(QJsonDocument::Compact)) > 0);
        routeState.close();
        QFile controllerState(controllerStatePath);
        QVERIFY(controllerState.open(QIODevice::WriteOnly));
        QVERIFY(controllerState.write(QJsonDocument(QJsonObject {
            { QStringLiteral("version"), 2 },
            { QStringLiteral("activeProfile"), QStringLiteral("empty-policy") },
            { QStringLiteral("activeInterface"), QStringLiteral("wg0") },
            { QStringLiteral("policyRevision"), QString() },
            { QStringLiteral("policyContentHash"), QString() },
            { QStringLiteral("policySource"), QString() },
            { QStringLiteral("policyEndpoint"), QString() },
            { QStringLiteral("policyResolvedSites"), QJsonObject() },
            { QStringLiteral("policyLoaded"), false },
            { QStringLiteral("policyMetadata"), QJsonValue(QJsonValue::Null) },
            { QStringLiteral("routingDegraded"), false },
            { QStringLiteral("routingError"), QString() },
            { QStringLiteral("recoveryRequired"), false },
        }).toJson(QJsonDocument::Compact)) > 0);
        controllerState.close();

        auto runner = std::make_shared<FakeCommandRunner>();
        runner->capturedOutputs = {
            QStringLiteral("1100: from all lookup 51821\n"),
            QStringLiteral("1100: from all lookup 51821\n"),
            QStringLiteral("0.0.0.0/1 dev wg0 proto 186 scope link\n128.0.0.0/1 dev wg0 proto 186 scope link\n"),
            QStringLiteral("::/1 dev wg0 proto 186 scope link\n8000::/1 dev wg0 proto 186 scope link\n"),
            QString() };
        HeadlessRoutingController controller(runner, routeStatePath);
        QVERIFY2(!controller.status().value(QStringLiteral("recoveryRequired")).toBool(),
                 qPrintable(controller.status().value(QStringLiteral("lastError")).toString()));
        QCOMPARE(controller.status().value(QStringLiteral("mode")).toString(),
                 QStringLiteral("all-except"));
        QVERIFY(controller.status().value(QStringLiteral("bypassRoutes")).toArray().isEmpty());
        QVERIFY(!controller.status().value(QStringLiteral("policyLoaded")).toBool());
    }

    void malformedDegradedReceiptsFailClosed()
    {
        const QList<QJsonObject> malformed {
            QJsonObject { { QStringLiteral("activeProfile"), QString() },
                          { QStringLiteral("activeInterface"), QStringLiteral("wg0") },
                          { QStringLiteral("routingError"), QStringLiteral("failed") } },
            QJsonObject { { QStringLiteral("activeProfile"), QStringLiteral("profile") },
                          { QStringLiteral("activeInterface"), QString() },
                          { QStringLiteral("routingError"), QStringLiteral("failed") } },
            QJsonObject { { QStringLiteral("activeProfile"), QStringLiteral("profile") },
                          { QStringLiteral("activeInterface"), QStringLiteral("wg0") },
                          { QStringLiteral("routingError"), QString() } },
        };
        for (const QJsonObject &fields : malformed) {
            QTemporaryDir temporaryDirectory;
            QVERIFY(temporaryDirectory.isValid());
            const QString routeStatePath = temporaryDirectory.filePath(QStringLiteral("routes.json"));
            QFile receipt(temporaryDirectory.filePath(QStringLiteral("routing-controller.json")));
            QVERIFY(receipt.open(QIODevice::WriteOnly));
            QJsonObject state {
                { QStringLiteral("version"), 2 },
                { QStringLiteral("activeProfile"), fields.value(QStringLiteral("activeProfile")) },
                { QStringLiteral("activeInterface"), fields.value(QStringLiteral("activeInterface")) },
                { QStringLiteral("policyRevision"), QString() },
                { QStringLiteral("policyContentHash"), QString() },
                { QStringLiteral("policySource"), QString() },
                { QStringLiteral("policyEndpoint"), QString() },
                { QStringLiteral("policyResolvedSites"), QJsonObject() },
                { QStringLiteral("policyLoaded"), false },
                { QStringLiteral("policyMetadata"), QJsonValue(QJsonValue::Null) },
                { QStringLiteral("routingDegraded"), true },
                { QStringLiteral("routingError"), fields.value(QStringLiteral("routingError")) },
                { QStringLiteral("recoveryRequired"), false },
            };
            QVERIFY(receipt.write(QJsonDocument(state).toJson(QJsonDocument::Compact)) > 0);
            receipt.close();
            auto runner = std::make_shared<FakeCommandRunner>();
            HeadlessRoutingController controller(runner, routeStatePath);
            QVERIFY(controller.status().value(QStringLiteral("recoveryRequired")).toBool());
        }

        QTemporaryDir mismatchDirectory;
        QVERIFY(mismatchDirectory.isValid());
        const QString mismatchRouteState = mismatchDirectory.filePath(QStringLiteral("routes.json"));
        QFile mismatchReceipt(mismatchDirectory.filePath(QStringLiteral("routing-controller.json")));
        QVERIFY(mismatchReceipt.open(QIODevice::WriteOnly));
        QVERIFY(mismatchReceipt.write(QJsonDocument(QJsonObject {
            { QStringLiteral("version"), 2 },
            { QStringLiteral("activeProfile"), QStringLiteral("profile") },
            { QStringLiteral("activeInterface"), QStringLiteral("wg0") },
            { QStringLiteral("policyRevision"), QString() },
            { QStringLiteral("policyContentHash"), QString() },
            { QStringLiteral("policySource"), QString() },
            { QStringLiteral("policyEndpoint"), QString() },
            { QStringLiteral("policyResolvedSites"), QJsonObject() },
            { QStringLiteral("policyLoaded"), false },
            { QStringLiteral("policyMetadata"), QJsonValue(QJsonValue::Null) },
            { QStringLiteral("routingDegraded"), true },
            { QStringLiteral("routingError"), QStringLiteral("failed") },
            { QStringLiteral("recoveryRequired"), false },
        }).toJson(QJsonDocument::Compact)) > 0);
        mismatchReceipt.close();
        QFile routeReceipt(mismatchRouteState);
        QVERIFY(routeReceipt.open(QIODevice::WriteOnly));
        QVERIFY(routeReceipt.write(QJsonDocument(QJsonObject {
            { QStringLiteral("version"), 2 },
            { QStringLiteral("mode"), QStringLiteral("only-forward") },
            { QStringLiteral("interface"), QStringLiteral("wg0") },
            { QStringLiteral("routes"), QJsonArray { QStringLiteral("10.8.1.0/24") } },
            { QStringLiteral("bypassRoutes"), QJsonArray { QStringLiteral("10.8.1.4") } },
            { QStringLiteral("criticalBypassRoutes"), QJsonArray() },
            { QStringLiteral("bypassRulePriority"), 1001 },
            { QStringLiteral("fullRulePriority"), 1100 },
        }).toJson(QJsonDocument::Compact)) > 0);
        routeReceipt.close();
        auto mismatchRunner = std::make_shared<FakeCommandRunner>();
        HeadlessRoutingController mismatchController(mismatchRunner, mismatchRouteState);
        QVERIFY(mismatchController.status().value(QStringLiteral("recoveryRequired")).toBool());
    }

    void aggregateDeadlineCoversDeleteRetryAndProbe()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        auto runner = std::make_shared<FakeCommandRunner>();
        LinuxRouteReconciler reconciler(
                runner, temporaryDirectory.filePath(QStringLiteral("routes.json")));
        QVERIFY2(reconciler.applyAllExcept(QStringLiteral("wg0"),
                                           { QStringLiteral("10.8.1.4") }).ok,
                 "setup full tunnel failed");
        runner->failBatches = true;
        runner->failIndividual = true;
        QElapsedTimer elapsed;
        elapsed.start();
        const RouteReconcileResult result = reconciler.clear();
        QVERIFY(!result.ok);
        QVERIFY(result.code == QStringLiteral("full_tunnel_rule_conflict")
                || result.code == QStringLiteral("recovery_required"));
        QVERIFY(elapsed.elapsed() < 120'000);
        QVERIFY(runner->batchCalls >= 1);
        QVERIFY(std::any_of(runner->calls.cbegin(), runner->calls.cend(), [](const auto &call) {
            return call.arguments.contains(QStringLiteral("priority"))
                && call.arguments.contains(QStringLiteral("del"));
        }));
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

    void dnsClearAfterVanishedInterfaceRetiresReceipt()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        auto runner = std::make_shared<FakeCommandRunner>();
        LinuxRouteReconciler reconciler(
                runner, temporaryDirectory.filePath(QStringLiteral("routes.json")));
        QVERIFY(reconciler.configureDns(QStringLiteral("wg0"),
                                         { QStringLiteral("10.8.1.53") },
                                         { QStringLiteral("~.") }).ok);
        runner->dnsRevertFails = true;
        runner->dnsLinkAbsent = true;
        runner->dnsResolverBindingAbsent = true;
        const RouteReconcileResult result = reconciler.clearDns(QStringLiteral("wg0"));
        QVERIFY2(result.ok, qPrintable(result.message));
        QCOMPARE(reconciler.status().value(QStringLiteral("dnsInterface")).toString(), QString());
        QVERIFY(!reconciler.status().value(QStringLiteral("recoveryRequired")).toBool());
    }

    void dnsClearBackendFailureFailsClosed()
    {
        QTemporaryDir temporaryDirectory;
        QVERIFY(temporaryDirectory.isValid());
        auto runner = std::make_shared<FakeCommandRunner>();
        LinuxRouteReconciler reconciler(
                runner, temporaryDirectory.filePath(QStringLiteral("routes.json")));
        QVERIFY(reconciler.configureDns(QStringLiteral("wg0"),
                                         { QStringLiteral("10.8.1.53") },
                                         { QStringLiteral("~.") }).ok);
        runner->dnsRevertFails = true;
        runner->dnsFailureMessage = QStringLiteral("Access denied by resolver backend");
        const RouteReconcileResult result = reconciler.clearDns(QStringLiteral("wg0"));
        QVERIFY(!result.ok);
        QCOMPARE(result.code, QStringLiteral("dns_clear_failed"));
        QVERIFY(result.message.contains(QStringLiteral("Access denied")));
        QCOMPARE(reconciler.status().value(QStringLiteral("dnsInterface")).toString(),
                 QStringLiteral("wg0"));
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
