#include "installController.h"

#include "core/models/protocolConfig.h"

#include <QCryptographicHash>
#include <QDateTime>
#include <QCoreApplication>
#include <QDebug>
#include <QEventLoop>
#include <QFutureWatcher>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonParseError>
#include <QRegularExpression>
#include <QThread>
#include <QtConcurrent>

#include "core/configurators/configuratorBase.h"
#include "core/utils/containerEnum.h"
#include "core/utils/containers/containerUtils.h"
#include "core/utils/protocolEnum.h"
#include "core/utils/selfhosted/sshSession.h"
#include "core/installers/awgInstaller.h"
#include "core/installers/installerBase.h"
#include "core/installers/openvpnInstaller.h"
#include "core/installers/sftpInstaller.h"
#include "core/installers/socks5Installer.h"
#include "core/installers/mtProxyInstaller.h"
#include "core/installers/telemtInstaller.h"
#include "core/installers/torInstaller.h"
#include "core/installers/wireguardInstaller.h"
#include "core/installers/xrayInstaller.h"
#include "core/utils/networkUtilities.h"
#include "core/utils/api/apiUtils.h"
#include "core/repositories/secureServersRepository.h"
#include "core/repositories/secureAppSettingsRepository.h"
#include "core/utils/selfhosted/scriptsRegistry.h"
#include "core/utils/selfhosted/sshClient.h"
#include "logger.h"
#include "core/utils/protocolEnum.h"
#include "core/protocols/protocolUtils.h"
#include "core/utils/constants/configKeys.h"
#include "core/utils/constants/protocolConstants.h"
#include "core/models/containerConfig.h"
#include "core/models/protocols/mtProxyProtocolConfig.h"
#include "core/models/protocols/awgProtocolConfig.h"
#include "ui/models/protocols/wireguardConfigModel.h"
#include "core/utils/utilities.h"
#include <QDesktopServices>
#include <QDir>
#include <QProcess>
#include <QStandardPaths>
#include <QUrl>
#include <QSysInfo>
#ifdef Q_OS_WINDOWS
    #include <windows.h>
#endif

using namespace amnezia;
using namespace ProtocolUtils;

namespace
{
    Logger logger("InstallController");
    constexpr char serverRoutingRulesPublishErrorMarker[] = "__AMNEZIA_ROUTING_RULES_PUBLISH_ERROR__";
    constexpr char serverRoutingRulesPublishConflictMarker[] = "__AMNEZIA_ROUTING_RULES_PUBLISH_CONFLICT__";
    constexpr char serverRoutingRulesPublishSuccessMarker[] = "__AMNEZIA_ROUTING_RULES_PUBLISH_SUCCESS__";
    constexpr char serverRoutingRulesCandidateBeginMarker[] = "__AMNEZIA_ROUTING_RULES_CANDIDATE_BEGIN__";
    constexpr char serverRoutingRulesCandidateEndMarker[] = "__AMNEZIA_ROUTING_RULES_CANDIDATE_END__";
    constexpr char serverRoutingRulesImage[] = "busybox:1.36.1";
    constexpr char serverRoutingRulesSourceFileName[] = "rules-source.txt";
    constexpr char serverRoutingRulesScriptFileName[] = "rules-server.sh";
    constexpr char serverRoutingRulesReadyFileName[] = "rules-ready";
    constexpr int serverRoutingRulesResolveIntervalSeconds = 24 * 60 * 60;
    constexpr int serverRoutingRulesResolveJitterSeconds = 60 * 60;
    constexpr int serverRoutingRulesInitialResolveTimeoutSeconds = 90;
    constexpr int serverRoutingRulesInitialResolveRetrySeconds = 5;
    constexpr int serverRoutingRulesResolveQueryTimeoutSeconds = 3;
    constexpr int serverRoutingRulesRecoveryQueryTimeoutSeconds = 1;
    constexpr int serverRoutingRulesRecoveryInitialDelaySeconds = 15;
    constexpr int serverRoutingRulesRecoveryMaximumDelaySeconds = 5 * 60;
    constexpr int serverRoutingRulesRecoveryMaximumAttempts = 6;
    constexpr int serverRoutingRulesRecoveryAttemptBudgetSeconds = 30;
    constexpr int serverRoutingRulesPolicyLifetimeYears = 10;
    constexpr qint64 serverRoutingRulesMaximumJsonRevision = 9007199254740991LL;
    constexpr char serverRoutingRulesSigningBlocker[] =
            "Managed routing policy signing key and trusted public-key distribution are not configured";

    QString serverRoutingRulesTunnelInterface(DockerContainer container)
    {
        if (container == DockerContainer::Awg2) {
            return QStringLiteral("awg0");
        }
        if (container == DockerContainer::Awg || container == DockerContainer::WireGuard) {
            return QStringLiteral("wg0");
        }
        if (container == DockerContainer::OpenVpn) {
            return QStringLiteral("tun0");
        }
        return {};
    }

    QJsonObject normalizedServerRoutingRulesSites(const QJsonValue &value)
    {
        QJsonObject sites;
        if (value.isObject()) {
            const QJsonObject object = value.toObject();
            for (auto it = object.constBegin(); it != object.constEnd(); ++it) {
                const QString site = it.key().trimmed().toLower();
                if (!site.isEmpty()) {
                    sites.insert(site, it.value().toString());
                }
            }
            return sites;
        }
        if (!value.isArray()) {
            return sites;
        }

        const QJsonArray items = value.toArray();
        for (const QJsonValue &item : items) {
            if (!item.isObject()) {
                continue;
            }
            const QJsonObject siteObject = item.toObject();
            const QString site = siteObject.value("hostname").toString(siteObject.value("url").toString()).trimmed().toLower();
            if (!site.isEmpty()) {
                sites.insert(site, siteObject.value("ip").toString());
            }
        }
        return sites;
    }

    bool isServerRoutingRulesSitesValue(const QJsonValue &value)
    {
        return value.isObject() || value.isArray();
    }

    QJsonObject serverRoutingRulesExceptSites(const QJsonObject &rules)
    {
        QJsonValue sitesValue = rules.value(configKey::serverExcept);
        if (!isServerRoutingRulesSitesValue(sitesValue)) {
            sitesValue = rules.value(configKey::managedSplitTunnelExceptSites);
        }
        return normalizedServerRoutingRulesSites(sitesValue);
    }

    QJsonObject serverRoutingRulesSourceSites(const QJsonObject &rules)
    {
        QJsonValue sitesValue = rules.value(configKey::managedSplitTunnelExceptSourceSites);
        if (!sitesValue.isObject() && !sitesValue.isArray()) {
            sitesValue = rules.value(configKey::managedSplitTunnelExceptSites);
        }
        if (!sitesValue.isObject() && !sitesValue.isArray()) {
            sitesValue = rules.value(configKey::serverExcept);
        }
        return normalizedServerRoutingRulesSites(sitesValue);
    }

    bool hasServerRoutingRulesExceptSites(const QJsonObject &rules)
    {
        return isServerRoutingRulesSitesValue(rules.value(configKey::serverExcept))
               || isServerRoutingRulesSitesValue(rules.value(configKey::managedSplitTunnelExceptSourceSites))
               || isServerRoutingRulesSitesValue(rules.value(configKey::managedSplitTunnelExceptSites));
    }

    QJsonObject storedServerRoutingRules(const QJsonObject &payload)
    {
        QJsonObject rules;
        if (!hasServerRoutingRulesExceptSites(payload)) {
            return rules;
        }

        const QJsonObject exceptSites = serverRoutingRulesExceptSites(payload);
        const QJsonObject sourceSites = serverRoutingRulesSourceSites(payload);
        if (exceptSites.isEmpty() && sourceSites.isEmpty()) {
            return rules;
        }

        rules.insert(configKey::serverExcept, exceptSites.isEmpty() ? sourceSites : exceptSites);
        rules.insert(configKey::managedSplitTunnelExceptSourceSites, sourceSites.isEmpty() ? exceptSites : sourceSites);
        rules.insert(configKey::managedSplitTunnelExceptSites, sourceSites.isEmpty() ? exceptSites : sourceSites);
        if (payload.value(configKey::managedSplitTunnelForceEnabled).toBool(false)) {
            rules.insert(configKey::managedSplitTunnelForceEnabled, true);
        }
        return rules;
    }

    QJsonObject loadStoredServerRoutingRules(const ServerCredentials &credentials, SshSession &sshSession)
    {
        QString stdOut;
        auto cbReadStdOut = [&stdOut](const QString &data, libssh::Client &) {
            stdOut.append(data);
            return ErrorCode::NoError;
        };

        const QString rulesPath = QStringLiteral("%1/%2")
                .arg(QString::fromLatin1(protocols::serverRoutingRules::hostDirectory),
                     QString::fromLatin1(protocols::serverRoutingRules::fileName));
        const QString script = QStringLiteral("sudo test -s '%1' && sudo cat '%1' || true").arg(rulesPath);
        const ErrorCode errorCode = sshSession.runScript(credentials, script, cbReadStdOut);
        if (errorCode != ErrorCode::NoError) {
            qWarning() << "InstallController: unable to read server routing rules file" << errorCode;
            return {};
        }

        const QByteArray payload = stdOut.trimmed().toUtf8();
        if (payload.isEmpty()) {
            return {};
        }

        QJsonParseError parseError;
        const QJsonDocument document = QJsonDocument::fromJson(payload, &parseError);
        if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
            qWarning() << "InstallController: invalid server routing rules payload" << parseError.errorString();
            return {};
        }
        return storedServerRoutingRules(document.object());
    }

    bool mergeServerRoutingRules(QJsonObject &serverJson, const QJsonObject &rules)
    {
        if (rules.isEmpty()) {
            return false;
        }

        bool changed = false;
        const QStringList objectKeys = {
            QString(configKey::serverExcept),
            QString(configKey::managedSplitTunnelExceptSourceSites),
            QString(configKey::managedSplitTunnelExceptSites),
        };

        for (const QString &key : objectKeys) {
            const QJsonObject sites = rules.value(key).toObject();
            if (!sites.isEmpty() && serverJson.value(key).toObject() != sites) {
                serverJson.insert(key, sites);
                changed = true;
            }
        }

        const bool forceEnabled = rules.value(configKey::managedSplitTunnelForceEnabled).toBool(false);
        if (serverJson.value(configKey::managedSplitTunnelForceEnabled).toBool(false) != forceEnabled) {
            if (forceEnabled) {
                serverJson.insert(configKey::managedSplitTunnelForceEnabled, true);
            } else {
                serverJson.remove(configKey::managedSplitTunnelForceEnabled);
            }
            changed = true;
        }

        if (!changed) {
            return false;
        }

        return true;
    }

    QStringList splitTunnelStoredIps(const QString &value)
    {
        QStringList ips;
        const QStringList tokens = value.split(QRegularExpression("[,;\\s]+"), Qt::SkipEmptyParts);
        for (const QString &token : tokens) {
            const QString ip = token.trimmed();
            if (NetworkUtilities::checkIpSubnetFormat(ip) && !ips.contains(ip)) {
                ips.append(ip);
            }
        }
        return ips;
    }

    bool serverRoutingRulesRevision(const QJsonObject &rules, qint64 &revision, QString &errorMessage)
    {
        QJsonValue revisionValue = rules.value(QStringLiteral("policy")).toObject().value(QStringLiteral("revision"));
        if (revisionValue.isUndefined()) {
            revisionValue = rules.value(QStringLiteral("revision"));
        }
        if (revisionValue.isUndefined() || revisionValue.isNull()) {
            revision = 0;
            return true;
        }

        bool ok = false;
        qint64 parsedRevision = -1;
        if (revisionValue.isDouble()) {
            parsedRevision = revisionValue.toVariant().toLongLong(&ok);
        } else if (revisionValue.isString()) {
            parsedRevision = revisionValue.toString().trimmed().toLongLong(&ok);
        }
        if (!ok || parsedRevision < 0) {
            errorMessage = QStringLiteral("Server routing policy has an invalid revision");
            return false;
        }

        revision = parsedRevision;
        return true;
    }

    ErrorCode readServerRoutingRulesRevision(const ServerCredentials &credentials, SshSession &sshSession,
                                             qint64 &revision, QString &errorMessage)
    {
        QString stdOut;
        auto cbReadStdOut = [&stdOut](const QString &data, libssh::Client &) {
            stdOut.append(data);
            return ErrorCode::NoError;
        };

        const QString rulesPath = QStringLiteral("%1/%2")
                .arg(QString::fromLatin1(protocols::serverRoutingRules::hostDirectory),
                     QString::fromLatin1(protocols::serverRoutingRules::fileName));
        const QString script = QStringLiteral("sudo test -s '%1' && sudo cat '%1' || true").arg(rulesPath);
        const ErrorCode errorCode = sshSession.runScript(credentials, script, cbReadStdOut);
        if (errorCode != ErrorCode::NoError) {
            errorMessage = QStringLiteral("Unable to read the current server routing policy revision");
            return errorCode;
        }

        const QByteArray payload = stdOut.trimmed().toUtf8();
        if (payload.isEmpty()) {
            revision = 0;
            return ErrorCode::NoError;
        }

        QJsonParseError parseError;
        const QJsonDocument document = QJsonDocument::fromJson(payload, &parseError);
        if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
            errorMessage = QStringLiteral("Current server routing policy is not valid JSON: %1")
                                   .arg(parseError.errorString());
            return ErrorCode::ServerCheckFailed;
        }
        if (!serverRoutingRulesRevision(document.object(), revision, errorMessage)) {
            return ErrorCode::ServerCheckFailed;
        }
        return ErrorCode::NoError;
    }

    QJsonObject canonicalServerRoutingRulesContent(const QJsonObject &rules)
    {
        QJsonObject content;
        content.insert(QStringLiteral("schemaVersion"), 1);
        content.insert(configKey::managedSplitTunnelExceptSourceSites, serverRoutingRulesSourceSites(rules));
        content.insert(configKey::managedSplitTunnelForceEnabled,
                       rules.value(configKey::managedSplitTunnelForceEnabled).toBool(false));
        return content;
    }

    QJsonObject versionedServerRoutingRules(const QJsonObject &rules, qint64 revision,
                                            QString &contentSha256)
    {
        const QDateTime generatedAt = QDateTime::currentDateTimeUtc();
        const QDateTime expiresAt = generatedAt.addYears(serverRoutingRulesPolicyLifetimeYears);
        const QJsonObject content = canonicalServerRoutingRulesContent(rules);
        const QByteArray canonicalContent = QJsonDocument(content).toJson(QJsonDocument::Compact);
        const QByteArray digest = QCryptographicHash::hash(canonicalContent, QCryptographicHash::Sha256).toHex();
        contentSha256 = QStringLiteral("sha256:%1").arg(QString::fromLatin1(digest));

        QJsonObject policy;
        policy.insert(QStringLiteral("schemaVersion"), 1);
        policy.insert(QStringLiteral("revision"), revision);
        policy.insert(QStringLiteral("generatedAt"), generatedAt.toString(Qt::ISODateWithMs));
        // `issuedAt` is retained as an alias for clients that already understand
        // versioned managed-route policy metadata.
        policy.insert(QStringLiteral("issuedAt"), generatedAt.toString(Qt::ISODateWithMs));
        policy.insert(QStringLiteral("expiresAt"), expiresAt.toString(Qt::ISODateWithMs));
        policy.insert(QStringLiteral("contentSha256"), contentSha256);
        policy.insert(QStringLiteral("canonicalization"), QStringLiteral("qt-json-compact-v1"));
        policy.insert(QStringLiteral("content"), content);

        // This is deliberately metadata, not a signature. Advertising an
        // algorithm without producing a verifiable signature would give
        // consumers a false security signal.
        QJsonObject signing;
        signing.insert(QStringLiteral("status"), QStringLiteral("unavailable"));
        signing.insert(QStringLiteral("reason"), QString::fromLatin1(serverRoutingRulesSigningBlocker));
        policy.insert(QStringLiteral("signing"), signing);

        QJsonObject versionedRules = rules;
        versionedRules.insert(QStringLiteral("version"), 1);
        versionedRules.insert(QStringLiteral("policy"), policy);
        return versionedRules;
    }

    QString shellSingleQuoted(const QString &value)
    {
        QString escaped = value;
        escaped.replace(QLatin1Char('\''), QStringLiteral("'\"'\"'"));
        return QStringLiteral("'%1'").arg(escaped);
    }

    QByteArray serverRoutingRulesSourceData(const QJsonObject &rules)
    {
        QByteArray data;
        const QJsonObject sites = serverRoutingRulesSourceSites(rules);
        for (auto it = sites.constBegin(); it != sites.constEnd(); ++it) {
            const QString sourceValue = it.key().trimmed().toLower();
            if (sourceValue.isEmpty()) {
                continue;
            }

            const QString fallback = splitTunnelStoredIps(it.value().toString()).join(QStringLiteral(", "));

            const bool isIp = NetworkUtilities::checkIpSubnetFormat(sourceValue);
            data.append(isIp ? "I|" : "D|");
            data.append(sourceValue.toUtf8());
            data.append('|');
            data.append(fallback.toUtf8());
            data.append('\n');
        }
        return data;
    }

    QByteArray serverRoutingRulesResolverScript(const QJsonObject &rules)
    {
        const bool forceEnabled = rules.value(configKey::managedSplitTunnelForceEnabled).toBool(false);
        const QJsonObject policy = rules.value(QStringLiteral("policy")).toObject();
        const QString policyJson = policy.isEmpty()
                ? QString()
                : QString::fromUtf8(QJsonDocument(policy).toJson(QJsonDocument::Compact));
        QString script = QStringLiteral(R"SERVER_RULES_SH(#!/bin/sh
RULES_FILE="/www/__RULES_FILE__"
SOURCE_FILE="/www/__SOURCE_FILE__"
READY_FILE="/www/__READY_FILE__"
POLICY_JSON=__POLICY_JSON__
SERVER_EXCEPT_KEY="__SERVER_EXCEPT_KEY__"
MANAGED_EXCEPT_KEY="__MANAGED_EXCEPT_KEY__"
SOURCE_EXCEPT_KEY="__SOURCE_EXCEPT_KEY__"
FORCE_KEY="__FORCE_KEY__"
FORCE_ENABLED="__FORCE_ENABLED__"
RESOLVE_INTERVAL_SECONDS=__RESOLVE_INTERVAL_SECONDS__
RESOLVE_JITTER_SECONDS=__RESOLVE_JITTER_SECONDS__
INITIAL_RESOLVE_TIMEOUT_SECONDS=__INITIAL_RESOLVE_TIMEOUT_SECONDS__
INITIAL_RESOLVE_RETRY_SECONDS=__INITIAL_RESOLVE_RETRY_SECONDS__
RESOLVE_QUERY_TIMEOUT_SECONDS=__RESOLVE_QUERY_TIMEOUT_SECONDS__
RECOVERY_QUERY_TIMEOUT_SECONDS=__RECOVERY_QUERY_TIMEOUT_SECONDS__
RECOVERY_INITIAL_DELAY_SECONDS=__RECOVERY_INITIAL_DELAY_SECONDS__
RECOVERY_MAXIMUM_DELAY_SECONDS=__RECOVERY_MAXIMUM_DELAY_SECONDS__
RECOVERY_MAXIMUM_ATTEMPTS=__RECOVERY_MAXIMUM_ATTEMPTS__
RECOVERY_ATTEMPT_BUDGET_SECONDS=__RECOVERY_ATTEMPT_BUDGET_SECONDS__
resolve_deadline_seconds=0
last_unresolved_count=0

validate_source_file() {
    [ -f "$SOURCE_FILE" ] || return 1
    while IFS='|' read -r source_kind source_value source_fallback source_extra; do
        [ -z "$source_kind$source_value$source_fallback$source_extra" ] && continue
        [ -z "$source_extra" ] || return 1
        [ "$source_kind" = "I" ] || [ "$source_kind" = "D" ] || return 1
        [ -n "$source_value" ] || return 1
        printf '%s%s' "$source_value" "$source_fallback" | grep -q '[[:cntrl:]]' && return 1
    done < "$SOURCE_FILE"
    return 0
}

json_escape() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

regex_escape() {
    printf '%s' "$1" | sed 's#[][\\.^$*]#\\&#g'
}

stored_rule_ips() {
    [ -s "$RULES_FILE" ] || {
        printf ''
        return 0
    }
    server_key="$(regex_escape "$(json_escape "$SERVER_EXCEPT_KEY")")"
    lookup_key="$(regex_escape "$(json_escape "$1")")"
    server_rules_body="$(sed -n 's#.*"'"$server_key"'":{\([^}]*\)}.*#\1#p' "$RULES_FILE" | head -n 1)"
    printf '%s\n' "$server_rules_body" | sed -n 's#.*"'"$lookup_key"'":"\([^"]*\)".*#\1#p' | head -n 1
}

current_time_seconds() {
    date +%s 2>/dev/null || echo 0
}

resolve_timed_out() {
    [ "${resolve_deadline_seconds:-0}" -gt 0 ] || return 1
    now="$(current_time_seconds)"
    [ "$now" -gt 0 ] || return 1
    [ "$now" -ge "$resolve_deadline_seconds" ]
}

resolve_domain_ips() {
    query_timeout_seconds="${2:-$RESOLVE_QUERY_TIMEOUT_SECONDS}"
    if command -v timeout >/dev/null 2>&1; then
        resolver_output="$(timeout "$query_timeout_seconds" nslookup "$1" 2>/dev/null || true)"
    else
        resolver_output="$(nslookup "$1" 2>/dev/null || true)"
    fi
    resolved_list="$(printf '%s\n' "$resolver_output" | awk '/^Address[0-9 ]*:/ {print $NF}' | grep -E '^[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+$' | sort -u)"
    resolved_ips=""
    for resolved_ip in $resolved_list; do
        if [ -z "$resolved_ips" ]; then
            resolved_ips="$resolved_ip"
        else
            resolved_ips="$resolved_ips, $resolved_ip"
        fi
    done
    printf '%s' "$resolved_ips"
}

append_rule_entry() {
    file_var="$1"
    key="$(json_escape "$2")"
    value="$(json_escape "$3")"
    eval first=\"\${${file_var}_first}\"
    if [ "$first" = "1" ]; then
        eval ${file_var}_first=0
    else
        printf ',' >> "$(eval echo \$$file_var)"
    fi
    printf '"%s":"%s"' "$key" "$value" >> "$(eval echo \$$file_var)"
}

build_rules() {
    allow_unresolved="${1:-0}"
    query_timeout_seconds="${2:-$RESOLVE_QUERY_TIMEOUT_SECONDS}"
    last_unresolved_count=0
    [ -f "$SOURCE_FILE" ] || return 0

    resolved_body_file="/tmp/server-routing-rules-resolved.$$"
    source_body_file="/tmp/server-routing-rules-source.$$"
    : > "$resolved_body_file" || return 1
    : > "$source_body_file" || {
        rm -f "$resolved_body_file"
        return 1
    }
    resolved_body_file_first=1
    source_body_file_first=1
    unresolved_count=0
    dns_retry_count=0

    while IFS='|' read -r source_kind source_value source_fallback; do
        [ -z "$source_value" ] && continue
        if [ "$source_kind" = "I" ]; then
            append_rule_entry resolved_body_file "$source_value" ""
            append_rule_entry source_body_file "$source_value" ""
        elif [ "$source_kind" = "D" ]; then
            append_rule_entry source_body_file "$source_value" "$source_fallback"
            resolved_ips=""
            if ! resolve_timed_out; then
                resolved_ips="$(resolve_domain_ips "$source_value" "$query_timeout_seconds")"
            fi
            if [ -z "$resolved_ips" ]; then
                dns_retry_count=$((dns_retry_count + 1))
                resolved_ips="$(stored_rule_ips "$source_value")"
            fi
            if [ -z "$resolved_ips" ]; then
                resolved_ips="$source_fallback"
            fi
            if [ -z "$resolved_ips" ]; then
                unresolved_count=$((unresolved_count + 1))
                continue
            fi
            append_rule_entry resolved_body_file "$source_value" "$resolved_ips"
        fi
    done < "$SOURCE_FILE"
    last_unresolved_count="$dns_retry_count"

    if [ "$unresolved_count" -ne 0 ] && [ "$allow_unresolved" != "1" ]; then
        rm -f "$resolved_body_file" "$source_body_file"
        return 2
    fi

    tmp_file="${RULES_FILE}.tmp"
    if {
        printf '{"version":1'
        if [ -n "$POLICY_JSON" ]; then
            printf ',"policy":%s' "$POLICY_JSON"
        fi
        printf ',"%s":{' "$SERVER_EXCEPT_KEY"
        cat "$resolved_body_file"
        printf '},"%s":{' "$MANAGED_EXCEPT_KEY"
        cat "$source_body_file"
        printf '},"%s":{' "$SOURCE_EXCEPT_KEY"
        cat "$source_body_file"
        printf '}'
        if [ "$FORCE_ENABLED" = "1" ]; then
            printf ',"%s":true' "$FORCE_KEY"
        fi
        printf '}'
    } > "$tmp_file" && mv "$tmp_file" "$RULES_FILE"; then
        printf 'ready\n' > "$READY_FILE"
        rm -f "$resolved_body_file" "$source_body_file"
        return 0
    fi

    rm -f "$resolved_body_file" "$source_body_file" "$tmp_file"
    return 1
}

random_jitter() {
    jitter_seed="$(od -An -N2 -tu2 /dev/urandom 2>/dev/null | awk '{print $1}')"
    [ -n "$jitter_seed" ] || jitter_seed="$$"
    echo $((jitter_seed % RESOLVE_JITTER_SECONDS))
}

retry_unresolved_burst() {
    retry_attempt=0
    retry_delay="$RECOVERY_INITIAL_DELAY_SECONDS"
    while [ "${last_unresolved_count:-0}" -gt 0 ] \
          && [ "$retry_attempt" -lt "$RECOVERY_MAXIMUM_ATTEMPTS" ]; do
        sleep "$retry_delay"
        recovery_start_seconds="$(current_time_seconds)"
        if [ "$recovery_start_seconds" -gt 0 ]; then
            resolve_deadline_seconds=$((recovery_start_seconds + RECOVERY_ATTEMPT_BUDGET_SECONDS))
        fi
        build_rules 1 "$RECOVERY_QUERY_TIMEOUT_SECONDS" || true
        resolve_deadline_seconds=0
        retry_attempt=$((retry_attempt + 1))
        if [ "$retry_delay" -lt "$RECOVERY_MAXIMUM_DELAY_SECONDS" ]; then
            retry_delay=$((retry_delay * 2))
            if [ "$retry_delay" -gt "$RECOVERY_MAXIMUM_DELAY_SECONDS" ]; then
                retry_delay="$RECOVERY_MAXIMUM_DELAY_SECONDS"
            fi
        fi
    done
}

validate_source_file || exit 20

initial_start_seconds="$(current_time_seconds)"
if [ "$initial_start_seconds" -gt 0 ]; then
    resolve_deadline_seconds=$((initial_start_seconds + INITIAL_RESOLVE_TIMEOUT_SECONDS))
    while ! build_rules 0 "$RESOLVE_QUERY_TIMEOUT_SECONDS"; do
        if resolve_timed_out; then
            build_rules 1 "$RESOLVE_QUERY_TIMEOUT_SECONDS" && break
        fi
        sleep "$INITIAL_RESOLVE_RETRY_SECONDS"
    done
else
    build_rules 0 "$RESOLVE_QUERY_TIMEOUT_SECONDS" || build_rules 1 "$RESOLVE_QUERY_TIMEOUT_SECONDS"
fi
resolve_deadline_seconds=0

if [ "${VALIDATE_ONLY:-0}" = "1" ]; then
    [ -s "$RULES_FILE" ] && [ -s "$READY_FILE" ]
    exit $?
fi

while [ ! -s "$READY_FILE" ]; do
    build_rules 1 "$RESOLVE_QUERY_TIMEOUT_SECONDS" && break
    sleep 1
done

(
    retry_unresolved_burst
    while :; do
        jitter="$(random_jitter)"
        sleep $((RESOLVE_INTERVAL_SECONDS + jitter))
        build_rules 0 "$RESOLVE_QUERY_TIMEOUT_SECONDS" \
            || build_rules 1 "$RESOLVE_QUERY_TIMEOUT_SECONDS" \
            || true
        retry_unresolved_burst
    done
) &

busybox httpd -f -p __SYNC_PORT__ -h /www
)SERVER_RULES_SH");

        script.replace("__RULES_FILE__", QString::fromLatin1(protocols::serverRoutingRules::fileName));
        script.replace("__SOURCE_FILE__", QString::fromLatin1(serverRoutingRulesSourceFileName));
        script.replace("__READY_FILE__", QString::fromLatin1(serverRoutingRulesReadyFileName));
        script.replace("__POLICY_JSON__", shellSingleQuoted(policyJson));
        script.replace("__SERVER_EXCEPT_KEY__", QString(configKey::serverExcept));
        script.replace("__MANAGED_EXCEPT_KEY__", QString(configKey::managedSplitTunnelExceptSites));
        script.replace("__SOURCE_EXCEPT_KEY__", QString(configKey::managedSplitTunnelExceptSourceSites));
        script.replace("__FORCE_KEY__", QString(configKey::managedSplitTunnelForceEnabled));
        script.replace("__FORCE_ENABLED__", forceEnabled ? QStringLiteral("1") : QStringLiteral("0"));
        script.replace("__SYNC_PORT__", QString::number(protocols::serverRoutingRules::syncPort));
        script.replace("__RESOLVE_INTERVAL_SECONDS__", QString::number(serverRoutingRulesResolveIntervalSeconds));
        script.replace("__RESOLVE_JITTER_SECONDS__", QString::number(serverRoutingRulesResolveJitterSeconds));
        script.replace("__INITIAL_RESOLVE_TIMEOUT_SECONDS__", QString::number(serverRoutingRulesInitialResolveTimeoutSeconds));
        script.replace("__INITIAL_RESOLVE_RETRY_SECONDS__", QString::number(serverRoutingRulesInitialResolveRetrySeconds));
        script.replace("__RESOLVE_QUERY_TIMEOUT_SECONDS__", QString::number(serverRoutingRulesResolveQueryTimeoutSeconds));
        script.replace("__RECOVERY_QUERY_TIMEOUT_SECONDS__", QString::number(serverRoutingRulesRecoveryQueryTimeoutSeconds));
        script.replace("__RECOVERY_INITIAL_DELAY_SECONDS__", QString::number(serverRoutingRulesRecoveryInitialDelaySeconds));
        script.replace("__RECOVERY_MAXIMUM_DELAY_SECONDS__", QString::number(serverRoutingRulesRecoveryMaximumDelaySeconds));
        script.replace("__RECOVERY_MAXIMUM_ATTEMPTS__", QString::number(serverRoutingRulesRecoveryMaximumAttempts));
        script.replace("__RECOVERY_ATTEMPT_BUDGET_SECONDS__", QString::number(serverRoutingRulesRecoveryAttemptBudgetSeconds));
        return script.toUtf8();
    }

    bool dockerDaemonContainerMissing(const QString &out, const QString &containerDockerName)
    {
        if (!out.contains(QLatin1String("Error response from daemon"), Qt::CaseInsensitive)) {
            return false;
        }
        if (out.contains(QLatin1String("No such container"), Qt::CaseInsensitive)
            && out.contains(containerDockerName, Qt::CaseInsensitive)) {
            return true;
        }
        if (out.size() < 700 && out.contains(QLatin1String("is not running"), Qt::CaseInsensitive)) {
            return true;
        }
        return false;
    }

    QString buildRemoveContainerScript(const amnezia::ScriptVars &vars, bool removeDataVolume)
    {
        QString script = SshSession::replaceVars(amnezia::scriptData(SharedScriptType::remove_container), vars);
        if (removeDataVolume) {
            script += QLatin1String("\nsudo docker volume rm -f $CONTAINER_NAME-data 2>/dev/null || true");
            script = SshSession::replaceVars(script, vars);
        }
        return script;
    }

    QByteArray markedPayload(const QString &output, const QString &beginMarker, const QString &endMarker)
    {
        const int begin = output.indexOf(beginMarker);
        if (begin < 0) {
            return {};
        }
        const int payloadBegin = begin + beginMarker.size();
        const int end = output.indexOf(endMarker, payloadBegin);
        if (end < payloadBegin) {
            return {};
        }
        return output.mid(payloadBegin, end - payloadBegin).trimmed().toUtf8();
    }

    QString publishFailureReason(const QString &output)
    {
        const QRegularExpression expression(
                QStringLiteral("%1:([^\\r\\n]+)")
                        .arg(QRegularExpression::escape(QString::fromLatin1(serverRoutingRulesPublishErrorMarker))));
        const QRegularExpressionMatch match = expression.match(output);
        return match.hasMatch() ? match.captured(1).trimmed() : QString();
    }

    void updateRemoteRollbackResult(const QString &output, ServerRoutingRulesPublishResult &result)
    {
        const QRegularExpression expression(QStringLiteral("remote_rollback=(not_needed|restored|partial)"));
        const QRegularExpressionMatch match = expression.match(output);
        if (!match.hasMatch()) {
            return;
        }
        result.remoteRollbackStatus = match.captured(1);
        result.remoteRollbackAttempted = result.remoteRollbackStatus != QStringLiteral("not_needed");
        result.remoteRollbackSucceeded = result.remoteRollbackStatus == QStringLiteral("restored");
    }

    bool validateServerRoutingRulesCandidate(const QByteArray &payload, const QJsonObject &versionedRules,
                                             qint64 revision, const QString &contentSha256,
                                             QString &errorMessage)
    {
        QJsonParseError parseError;
        const QJsonDocument document = QJsonDocument::fromJson(payload, &parseError);
        if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
            errorMessage = QStringLiteral("Candidate resolver output is not valid JSON: %1")
                                   .arg(parseError.errorString());
            return false;
        }

        const QJsonObject candidate = document.object();
        if (candidate.value(QStringLiteral("version")).toInt(-1) != 1) {
            errorMessage = QStringLiteral("Candidate resolver output has an unsupported schema version");
            return false;
        }

        QString revisionError;
        qint64 candidateRevision = -1;
        if (!serverRoutingRulesRevision(candidate, candidateRevision, revisionError)
            || candidateRevision != revision) {
            errorMessage = revisionError.isEmpty()
                    ? QStringLiteral("Candidate resolver output has revision %1 instead of %2")
                              .arg(candidateRevision)
                              .arg(revision)
                    : revisionError;
            return false;
        }

        const QJsonObject expectedPolicy = versionedRules.value(QStringLiteral("policy")).toObject();
        const QJsonObject candidatePolicy = candidate.value(QStringLiteral("policy")).toObject();
        if (candidatePolicy != expectedPolicy
            || candidatePolicy.value(QStringLiteral("contentSha256")).toString() != contentSha256) {
            errorMessage = QStringLiteral("Candidate resolver output policy metadata or content hash differs from the candidate");
            return false;
        }

        const QJsonObject expectedSources = serverRoutingRulesSourceSites(versionedRules);
        if (!candidate.value(configKey::serverExcept).isObject()
            || candidate.value(configKey::managedSplitTunnelExceptSites).toObject() != expectedSources
            || candidate.value(configKey::managedSplitTunnelExceptSourceSites).toObject() != expectedSources
            || candidate.value(configKey::managedSplitTunnelForceEnabled).toBool(false)
                    != versionedRules.value(configKey::managedSplitTunnelForceEnabled).toBool(false)) {
            errorMessage = QStringLiteral("Candidate resolver output does not match the requested managed routing policy");
            return false;
        }

        return true;
    }
}

InstallController::InstallController(SecureServersRepository *serversRepository,
                                     SecureAppSettingsRepository* appSettingsRepository,
                                     QObject *parent)
    : QObject(parent),
      m_serversRepository(serversRepository),
      m_appSettingsRepository(appSettingsRepository),
      m_cancelInstallation(false)
{
}

InstallController::~InstallController()
{
    stopAllSftpMounts();
}

ErrorCode InstallController::publishServerRoutingRules(const ServerCredentials &credentials, const QJsonObject &rules,
                                                       DockerContainer container)
{
    return publishVersionedServerRoutingRules(credentials, rules, container).errorCode;
}

ServerRoutingRulesPublishResult InstallController::publishVersionedServerRoutingRules(
        const ServerCredentials &credentials, const QJsonObject &rules, DockerContainer container,
        qint64 expectedRevision)
{
    ServerRoutingRulesPublishResult result;
    result.expectedRevision = expectedRevision;
    result.signatureAvailable = false;
    result.signingBlocker = QString::fromLatin1(serverRoutingRulesSigningBlocker);
    result.remoteRollbackStatus = QStringLiteral("not_needed");

    bool managedContentValid = false;
    managedRoutePolicy::canonicalSourcePolicyContent(rules, &managedContentValid);
    if (!managedContentValid) {
        result.errorCode = ErrorCode::ServerCheckFailed;
        result.failureReason = QStringLiteral(
                "Managed routing policy contains an unsafe, malformed, or oversized route set");
        return result;
    }

    SshSession sshSession;
    QString revisionError;
    ErrorCode errorCode = readServerRoutingRulesRevision(credentials, sshSession, result.currentRevision, revisionError);
    if (errorCode != ErrorCode::NoError) {
        result.errorCode = errorCode;
        result.failureReason = revisionError;
        return result;
    }

    if (expectedRevision >= 0 && expectedRevision != result.currentRevision) {
        result.errorCode = ErrorCode::ServerCheckFailed;
        result.conflict = true;
        result.failureReason = QStringLiteral("Routing policy revision conflict: expected %1, server has %2")
                                       .arg(expectedRevision)
                                       .arg(result.currentRevision);
        return result;
    }

    const qint64 compareAndSwapRevision = result.currentRevision;
    result.expectedRevision = compareAndSwapRevision;
    if (compareAndSwapRevision >= serverRoutingRulesMaximumJsonRevision) {
        result.errorCode = ErrorCode::InternalError;
        result.failureReason = QStringLiteral("Routing policy revision counter exceeds the JSON safe integer range");
        return result;
    }

    const qint64 publishedRevision = compareAndSwapRevision + 1;
    const QJsonObject versionedRules = versionedServerRoutingRules(rules, publishedRevision, result.contentSha256);
    const QByteArray sourceData = serverRoutingRulesSourceData(versionedRules);
    const QByteArray resolverScript = serverRoutingRulesResolverScript(versionedRules);
    const QString sourceSha256 = QString::fromLatin1(
            QCryptographicHash::hash(sourceData, QCryptographicHash::Sha256).toHex());
    const QString scriptSha256 = QString::fromLatin1(
            QCryptographicHash::hash(resolverScript, QCryptographicHash::Sha256).toHex());
    const QString transactionId = Utils::getRandomString(16);
    const QString candidateDirectory = QStringLiteral("%1/.candidate-%2")
            .arg(QString::fromLatin1(protocols::serverRoutingRules::hostDirectory), transactionId);

    const QString sourceTmpFileName = QStringLiteral("/tmp/%1.txt").arg(Utils::getRandomString(16));
    errorCode = sshSession.uploadFileToHost(credentials, sourceData, sourceTmpFileName);
    if (errorCode != ErrorCode::NoError) {
        result.errorCode = errorCode;
        result.failureReason = QStringLiteral("Unable to upload managed routing policy source data");
        return result;
    }

    const QString scriptTmpFileName = QStringLiteral("/tmp/%1.sh").arg(Utils::getRandomString(16));
    errorCode = sshSession.uploadFileToHost(credentials, resolverScript, scriptTmpFileName);
    if (errorCode != ErrorCode::NoError) {
        sshSession.runScript(credentials,
                             QStringLiteral("sudo rm -f %1").arg(shellSingleQuoted(sourceTmpFileName)));
        result.errorCode = errorCode;
        result.failureReason = QStringLiteral("Unable to upload managed routing policy resolver");
        return result;
    }

    const QString tunnelInterface = serverRoutingRulesTunnelInterface(container);
    const bool publishTunnelEndpoint = !tunnelInterface.isEmpty();
    const QString tunnelContainerName = QStringLiteral("%1-%2")
            .arg(QString::fromLatin1(protocols::serverRoutingRules::tunnelContainerName),
                 ContainerUtils::containerToString(container));

    const QString hostDirectory = QString::fromLatin1(protocols::serverRoutingRules::hostDirectory);
    const QString lockFile = hostDirectory + QStringLiteral("/.publish.lock");
    auto replacePublishVariables = [&](QString &script) {
        script.replace("__HOST_DIRECTORY__", hostDirectory);
        script.replace("__LOCK_FILE__", lockFile);
        script.replace("__CANDIDATE_DIRECTORY__", candidateDirectory);
        script.replace("__TRANSACTION_ID__", transactionId);
        script.replace("__SOURCE_TMP_FILE__", sourceTmpFileName);
        script.replace("__SCRIPT_TMP_FILE__", scriptTmpFileName);
        script.replace("__SOURCE_FILE__", QString::fromLatin1(serverRoutingRulesSourceFileName));
        script.replace("__SCRIPT_FILE__", QString::fromLatin1(serverRoutingRulesScriptFileName));
        script.replace("__READY_FILE__", QString::fromLatin1(serverRoutingRulesReadyFileName));
        script.replace("__RULES_FILE__", QString::fromLatin1(protocols::serverRoutingRules::fileName));
        script.replace("__EXPECTED_REVISION__", QString::number(compareAndSwapRevision));
        script.replace("__PUBLISHED_REVISION__", QString::number(publishedRevision));
        script.replace("__CONTENT_SHA256__", result.contentSha256);
        script.replace("__SOURCE_SHA256__", sourceSha256);
        script.replace("__SCRIPT_SHA256__", scriptSha256);
        script.replace("__BRIDGE_CONTAINER__", QString::fromLatin1(protocols::serverRoutingRules::containerName));
        script.replace("__TUNNEL_CONTAINER__", tunnelContainerName);
        script.replace("__ROUTING_RULES_IMAGE__", QString::fromLatin1(serverRoutingRulesImage));
        script.replace("__BRIDGE_HOST__", QString::fromLatin1(protocols::serverRoutingRules::syncHost));
        script.replace("__SYNC_PORT__", QString::number(protocols::serverRoutingRules::syncPort));
        script.replace("__PUBLISH_TUNNEL__", publishTunnelEndpoint ? QStringLiteral("1") : QStringLiteral("0"));
        script.replace("__VPN_CONTAINER__", ContainerUtils::containerToString(container));
        script.replace("__TUNNEL_IFACE__", tunnelInterface);
        script.replace("__CANDIDATE_BEGIN_MARKER__", QString::fromLatin1(serverRoutingRulesCandidateBeginMarker));
        script.replace("__CANDIDATE_END_MARKER__", QString::fromLatin1(serverRoutingRulesCandidateEndMarker));
        script.replace("__SUCCESS_MARKER__", QString::fromLatin1(serverRoutingRulesPublishSuccessMarker));
        script.replace("__CONFLICT_MARKER__", QString::fromLatin1(serverRoutingRulesPublishConflictMarker));
        script.replace("__ERROR_MARKER__", QString::fromLatin1(serverRoutingRulesPublishErrorMarker));
    };

    auto runPublishingScript = [&](const QString &script, QString &output) {
        auto cbReadOutput = [&output](const QString &data, libssh::Client &) {
            // SSH delivers arbitrary chunks rather than logical lines. Keep
            // the exact byte-to-text sequence so a chunk boundary cannot add
            // whitespace inside the candidate JSON payload.
            output.append(data);
            return ErrorCode::NoError;
        };
        // Stage and commit are stateful shell programs: they use conditionals,
        // variables, traps and heredocs. Running them line by line would split
        // those constructs across unrelated remote shells.
        return sshSession.runScriptInSingleShell(credentials, script, cbReadOutput, cbReadOutput);
    };

    auto cleanupCandidate = [&]() {
        const QString cleanupScript = QStringLiteral("sudo rm -rf %1; sudo rm -f %2 %3")
                .arg(shellSingleQuoted(candidateDirectory), shellSingleQuoted(sourceTmpFileName),
                     shellSingleQuoted(scriptTmpFileName));
        sshSession.runScript(credentials, cleanupScript);
    };

    QString stageScript = QStringLiteral(R"STAGE_SH(
set -u
if ! sudo mkdir -p '__HOST_DIRECTORY__'; then
    echo __ERROR_MARKER__:stage_mkdir
    exit 0
fi
if ! sudo touch '__LOCK_FILE__'; then
    echo __ERROR_MARKER__:stage_lock_create
    exit 0
fi
stage_rc=0
sudo flock -w 30 '__LOCK_FILE__' sh -s <<'AMNEZIA_ROUTING_STAGE' || stage_rc=$?
set -u
stage_complete=0
candidate_ready=0
failure_reason=unexpected_stage_failure
cleanup_stage() {
    trap - EXIT HUP INT TERM
    rm -f '__SOURCE_TMP_FILE__' '__SCRIPT_TMP_FILE__' >/dev/null 2>&1 || true
    if [ "$candidate_ready" != '1' ]; then
        rm -rf '__CANDIDATE_DIRECTORY__' >/dev/null 2>&1 || true
    fi
    if [ "$stage_complete" != '1' ]; then
        echo __ERROR_MARKER__:$failure_reason
    fi
    exit 0
}
trap cleanup_stage EXIT
trap 'failure_reason=stage_interrupted; exit 1' HUP INT TERM
fail_stage() {
    failure_reason="$1"
    exit 1
}

current_revision="$(sed -n 's/.*"revision":[[:space:]]*\([0-9][0-9]*\).*/\1/p' '__HOST_DIRECTORY__/__RULES_FILE__' 2>/dev/null | head -n 1)"
[ -n "$current_revision" ] || current_revision=0
if [ "$current_revision" != '__EXPECTED_REVISION__' ]; then
    stage_complete=1
    echo __CONFLICT_MARKER__:$current_revision
    exit 0
fi

rm -rf '__CANDIDATE_DIRECTORY__' || fail_stage candidate_cleanup
mkdir -p '__CANDIDATE_DIRECTORY__' || fail_stage candidate_mkdir
if [ -s '__HOST_DIRECTORY__/__RULES_FILE__' ]; then
    install -m 0644 '__HOST_DIRECTORY__/__RULES_FILE__' '__CANDIDATE_DIRECTORY__/__RULES_FILE__' \
        || fail_stage candidate_lkg_seed
fi
install -m 0644 '__SOURCE_TMP_FILE__' '__CANDIDATE_DIRECTORY__/__SOURCE_FILE__' || fail_stage candidate_source_install
install -m 0755 '__SCRIPT_TMP_FILE__' '__CANDIDATE_DIRECTORY__/__SCRIPT_FILE__' || fail_stage candidate_script_install
rm -f '__SOURCE_TMP_FILE__' '__SCRIPT_TMP_FILE__' || fail_stage uploaded_file_cleanup
sh -n '__CANDIDATE_DIRECTORY__/__SCRIPT_FILE__' || fail_stage candidate_script_syntax

if ! docker network inspect amnezia-dns-net >/dev/null 2>&1; then
    docker network create --driver bridge --subnet=172.29.172.0/24 --opt com.docker.network.bridge.name=amn0 amnezia-dns-net >/dev/null \
        || fail_stage network_create
fi
if ! docker image inspect '__ROUTING_RULES_IMAGE__' >/dev/null 2>&1; then
    docker pull '__ROUTING_RULES_IMAGE__' >/dev/null || fail_stage image_pull
fi

if command -v timeout >/dev/null 2>&1; then
    timeout 150 docker run --rm --log-driver none --network amnezia-dns-net \
        -e VALIDATE_ONLY=1 -v '__CANDIDATE_DIRECTORY__:/www:rw' --entrypoint sh \
        '__ROUTING_RULES_IMAGE__' -c 'sh /www/__SCRIPT_FILE__' >/dev/null \
        || fail_stage candidate_resolver_run
else
    docker run --rm --log-driver none --network amnezia-dns-net \
        -e VALIDATE_ONLY=1 -v '__CANDIDATE_DIRECTORY__:/www:rw' --entrypoint sh \
        '__ROUTING_RULES_IMAGE__' -c 'sh /www/__SCRIPT_FILE__' >/dev/null \
        || fail_stage candidate_resolver_run
fi
test -s '__CANDIDATE_DIRECTORY__/__READY_FILE__' || fail_stage candidate_not_ready
test -s '__CANDIDATE_DIRECTORY__/__RULES_FILE__' || fail_stage candidate_rules_missing

candidate_ready=1
stage_complete=1
echo __CANDIDATE_BEGIN_MARKER__
cat '__CANDIDATE_DIRECTORY__/__RULES_FILE__'
echo
echo __CANDIDATE_END_MARKER__
exit 0
AMNEZIA_ROUTING_STAGE
if [ "$stage_rc" -ne 0 ]; then
    echo __ERROR_MARKER__:stage_lock_failed
fi
)STAGE_SH");
    replacePublishVariables(stageScript);

    QString stageOutput;
    errorCode = runPublishingScript(stageScript, stageOutput);

    const QRegularExpression conflictExpression(
            QStringLiteral("%1:([0-9]+)")
                    .arg(QRegularExpression::escape(QString::fromLatin1(serverRoutingRulesPublishConflictMarker))));
    QRegularExpressionMatch conflictMatch = conflictExpression.match(stageOutput);
    if (conflictMatch.hasMatch()) {
        bool parsed = false;
        const qint64 currentRevision = conflictMatch.captured(1).toLongLong(&parsed);
        if (parsed) {
            result.currentRevision = currentRevision;
        }
        result.errorCode = ErrorCode::ServerCheckFailed;
        result.conflict = true;
        result.failureReason = QStringLiteral("Routing policy changed during candidate validation: expected %1, server has %2")
                                       .arg(compareAndSwapRevision)
                                       .arg(result.currentRevision);
        cleanupCandidate();
        return result;
    }

    const QString stageFailure = publishFailureReason(stageOutput);
    if (errorCode != ErrorCode::NoError || !stageFailure.isEmpty()) {
        result.errorCode = errorCode != ErrorCode::NoError ? errorCode : ErrorCode::ServerDockerFailedError;
        result.failureReason = stageFailure.isEmpty()
                ? QStringLiteral("Unable to validate the managed routing policy candidate on the server")
                : QStringLiteral("Managed routing policy candidate validation failed: %1").arg(stageFailure);
        cleanupCandidate();
        return result;
    }

    const QByteArray candidatePayload = markedPayload(
            stageOutput, QString::fromLatin1(serverRoutingRulesCandidateBeginMarker),
            QString::fromLatin1(serverRoutingRulesCandidateEndMarker));
    QString candidateError;
    if (!validateServerRoutingRulesCandidate(candidatePayload, versionedRules, publishedRevision,
                                             result.contentSha256, candidateError)) {
        result.errorCode = ErrorCode::ServerCheckFailed;
        result.failureReason = candidateError;
        cleanupCandidate();
        return result;
    }
    result.candidateValidated = true;

    QString commitScript = QStringLiteral(R"COMMIT_SH(
set -u
commit_rc=0
sudo flock -w 30 '__LOCK_FILE__' sh -s <<'AMNEZIA_ROUTING_COMMIT' || commit_rc=$?
set -u
transaction_started=0
publication_verified=0
terminal_marker_emitted=0
failure_reason=unexpected_commit_failure
remote_rollback_status=not_needed
old_bridge_exists=0
old_bridge_running=0
old_tunnel_exists=0
old_tunnel_running=0
bridge_backed_up=0
tunnel_backed_up=0
new_bridge_created=0
new_tunnel_created=0
backup_directory='__HOST_DIRECTORY__/.rollback-__TRANSACTION_ID__'
bridge_backup='__BRIDGE_CONTAINER__-rollback-__TRANSACTION_ID__'
tunnel_backup='__TUNNEL_CONTAINER__-rollback-__TRANSACTION_ID__'

restore_file() {
    file_name="$1"
    if [ -e "$backup_directory/.had-$file_name" ]; then
        cp -p "$backup_directory/$file_name" '__HOST_DIRECTORY__/.restore-'"$file_name" || return 1
        mv -f '__HOST_DIRECTORY__/.restore-'"$file_name" '__HOST_DIRECTORY__/'"$file_name" || return 1
    else
        rm -f '__HOST_DIRECTORY__/'"$file_name" || return 1
    fi
    return 0
}

rollback_publish() {
    [ "$transaction_started" = '1' ] || {
        remote_rollback_status=not_needed
        return 0
    }
    rollback_ok=1
    if [ "$new_tunnel_created" = '1' ]; then
        docker rm -f '__TUNNEL_CONTAINER__' >/dev/null 2>&1 || rollback_ok=0
    fi
    if [ "$new_bridge_created" = '1' ]; then
        docker rm -f '__BRIDGE_CONTAINER__' >/dev/null 2>&1 || rollback_ok=0
    fi
    restore_file '__SOURCE_FILE__' || rollback_ok=0
    restore_file '__SCRIPT_FILE__' || rollback_ok=0
    restore_file '__RULES_FILE__' || rollback_ok=0
    restore_file '__READY_FILE__' || rollback_ok=0

    if [ "$bridge_backed_up" = '1' ]; then
        docker rename "$bridge_backup" '__BRIDGE_CONTAINER__' >/dev/null 2>&1 || rollback_ok=0
        if [ "$old_bridge_running" = '1' ]; then
            docker start '__BRIDGE_CONTAINER__' >/dev/null 2>&1 || rollback_ok=0
        fi
    fi
    if [ "$tunnel_backed_up" = '1' ]; then
        docker rename "$tunnel_backup" '__TUNNEL_CONTAINER__' >/dev/null 2>&1 || rollback_ok=0
        if [ "$old_tunnel_running" = '1' ]; then
            docker start '__TUNNEL_CONTAINER__' >/dev/null 2>&1 || rollback_ok=0
        fi
    fi

    if [ "$rollback_ok" = '1' ]; then
        remote_rollback_status=restored
        return 0
    fi
    remote_rollback_status=partial
    return 1
}

cleanup_commit() {
    exit_status=$?
    trap - EXIT HUP INT TERM
    if [ "$publication_verified" != '1' ] && [ "$terminal_marker_emitted" != '1' ]; then
        rollback_publish || true
        terminal_marker_emitted=1
        echo __ERROR_MARKER__:$failure_reason:remote_rollback=$remote_rollback_status
    fi
    rm -rf '__CANDIDATE_DIRECTORY__' >/dev/null 2>&1 || true
    if [ "$publication_verified" = '1' ] || [ "$remote_rollback_status" = 'restored' ] \
        || [ "$remote_rollback_status" = 'not_needed' ]; then
        rm -rf "$backup_directory" >/dev/null 2>&1 || true
    fi
    exit 0
}
trap cleanup_commit EXIT
trap 'failure_reason=commit_interrupted; exit 1' HUP INT TERM
fail_commit() {
    failure_reason="$1"
    exit 1
}

current_revision="$(sed -n 's/.*"revision":[[:space:]]*\([0-9][0-9]*\).*/\1/p' '__HOST_DIRECTORY__/__RULES_FILE__' 2>/dev/null | head -n 1)"
[ -n "$current_revision" ] || current_revision=0
if [ "$current_revision" != '__EXPECTED_REVISION__' ]; then
    terminal_marker_emitted=1
    echo __CONFLICT_MARKER__:$current_revision
    exit 0
fi

test -f '__CANDIDATE_DIRECTORY__/__SOURCE_FILE__' || fail_commit candidate_source_missing
test -s '__CANDIDATE_DIRECTORY__/__SCRIPT_FILE__' || fail_commit candidate_script_missing
test -s '__CANDIDATE_DIRECTORY__/__RULES_FILE__' || fail_commit candidate_rules_missing
sh -n '__CANDIDATE_DIRECTORY__/__SCRIPT_FILE__' || fail_commit candidate_script_syntax
command -v sha256sum >/dev/null 2>&1 || fail_commit sha256sum_missing
candidate_source_sha="$(sha256sum '__CANDIDATE_DIRECTORY__/__SOURCE_FILE__' | awk '{print $1}')"
candidate_script_sha="$(sha256sum '__CANDIDATE_DIRECTORY__/__SCRIPT_FILE__' | awk '{print $1}')"
[ "$candidate_source_sha" = '__SOURCE_SHA256__' ] || fail_commit candidate_source_hash
[ "$candidate_script_sha" = '__SCRIPT_SHA256__' ] || fail_commit candidate_script_hash
grep -Fq '"revision":__PUBLISHED_REVISION__' '__CANDIDATE_DIRECTORY__/__RULES_FILE__' \
    || fail_commit candidate_revision
grep -Fq '"contentSha256":"__CONTENT_SHA256__"' '__CANDIDATE_DIRECTORY__/__RULES_FILE__' \
    || fail_commit candidate_content_hash
docker network inspect amnezia-dns-net >/dev/null 2>&1 || fail_commit network_missing
docker image inspect '__ROUTING_RULES_IMAGE__' >/dev/null 2>&1 || fail_commit image_missing

rm -rf "$backup_directory" || fail_commit backup_cleanup
mkdir -p "$backup_directory" || fail_commit backup_mkdir
for file_name in '__SOURCE_FILE__' '__SCRIPT_FILE__' '__RULES_FILE__' '__READY_FILE__'; do
    if [ -e '__HOST_DIRECTORY__/'"$file_name" ]; then
        cp -p '__HOST_DIRECTORY__/'"$file_name" "$backup_directory/$file_name" || fail_commit backup_file
        touch "$backup_directory/.had-$file_name" || fail_commit backup_marker
    fi
done

transaction_started=1
if [ '__PUBLISH_TUNNEL__' = '1' ] && docker inspect '__TUNNEL_CONTAINER__' >/dev/null 2>&1; then
    old_tunnel_exists=1
    [ "$(docker inspect -f '{{.State.Running}}' '__TUNNEL_CONTAINER__')" = 'true' ] && old_tunnel_running=1
    docker rename '__TUNNEL_CONTAINER__' "$tunnel_backup" >/dev/null || fail_commit tunnel_backup_rename
    tunnel_backed_up=1
    docker stop "$tunnel_backup" >/dev/null || fail_commit tunnel_backup_stop
fi
if docker inspect '__BRIDGE_CONTAINER__' >/dev/null 2>&1; then
    old_bridge_exists=1
    [ "$(docker inspect -f '{{.State.Running}}' '__BRIDGE_CONTAINER__')" = 'true' ] && old_bridge_running=1
    docker rename '__BRIDGE_CONTAINER__' "$bridge_backup" >/dev/null || fail_commit bridge_backup_rename
    bridge_backed_up=1
    docker stop "$bridge_backup" >/dev/null || fail_commit bridge_backup_stop
fi

install -m 0644 '__CANDIDATE_DIRECTORY__/__SOURCE_FILE__' '__HOST_DIRECTORY__/.source-new-__TRANSACTION_ID__' \
    || fail_commit source_stage
mv -f '__HOST_DIRECTORY__/.source-new-__TRANSACTION_ID__' '__HOST_DIRECTORY__/__SOURCE_FILE__' \
    || fail_commit source_switch
install -m 0755 '__CANDIDATE_DIRECTORY__/__SCRIPT_FILE__' '__HOST_DIRECTORY__/.script-new-__TRANSACTION_ID__' \
    || fail_commit script_stage
mv -f '__HOST_DIRECTORY__/.script-new-__TRANSACTION_ID__' '__HOST_DIRECTORY__/__SCRIPT_FILE__' \
    || fail_commit script_switch
rm -f '__HOST_DIRECTORY__/__READY_FILE__' || fail_commit old_ready_remove

docker run -d --log-driver none --restart always --network amnezia-dns-net --ip=__BRIDGE_HOST__ \
    --name '__BRIDGE_CONTAINER__' -v '__HOST_DIRECTORY__:/www:rw' --entrypoint sh \
    '__ROUTING_RULES_IMAGE__' -c 'sh /www/__SCRIPT_FILE__' >/dev/null || fail_commit bridge_run
new_bridge_created=1
i=0
while [ "$i" -lt 120 ]; do
    [ -s '__HOST_DIRECTORY__/__READY_FILE__' ] && break
    i=$((i + 1))
    sleep 1
done
test -s '__HOST_DIRECTORY__/__READY_FILE__' || fail_commit rules_not_ready
test -s '__HOST_DIRECTORY__/__RULES_FILE__' || fail_commit rules_missing
grep -Fq '"revision":__PUBLISHED_REVISION__' '__HOST_DIRECTORY__/__RULES_FILE__' || fail_commit live_revision
grep -Fq '"contentSha256":"__CONTENT_SHA256__"' '__HOST_DIRECTORY__/__RULES_FILE__' || fail_commit live_content_hash
docker ps --format '{{.Names}}' | grep -qx '__BRIDGE_CONTAINER__' || fail_commit bridge_not_running
bridge_payload="$(docker exec '__BRIDGE_CONTAINER__' wget -qO- 'http://127.0.0.1:__SYNC_PORT__/__RULES_FILE__')" \
    || fail_commit bridge_readiness_probe
printf '%s' "$bridge_payload" | grep -Fq '"revision":__PUBLISHED_REVISION__' || fail_commit bridge_probe_revision
printf '%s' "$bridge_payload" | grep -Fq '"contentSha256":"__CONTENT_SHA256__"' || fail_commit bridge_probe_hash

if [ '__PUBLISH_TUNNEL__' = '1' ]; then
    docker ps --format '{{.Names}}' | grep -qx '__VPN_CONTAINER__' || fail_commit vpn_container_missing
    docker run -d --log-driver none --restart always --network container:__VPN_CONTAINER__ \
        --name '__TUNNEL_CONTAINER__' -v '__HOST_DIRECTORY__:/www:ro' --entrypoint sh \
        '__ROUTING_RULES_IMAGE__' -c 'busybox httpd -f -p __SYNC_PORT__ -h /www' >/dev/null \
        || fail_commit tunnel_run
    new_tunnel_created=1
    sleep 1
    docker ps --format '{{.Names}}' | grep -qx '__TUNNEL_CONTAINER__' || fail_commit tunnel_not_running
    tunnel_payload="$(docker exec '__TUNNEL_CONTAINER__' wget -qO- 'http://127.0.0.1:__SYNC_PORT__/__RULES_FILE__')" \
        || fail_commit tunnel_readiness_probe
    printf '%s' "$tunnel_payload" | grep -Fq '"revision":__PUBLISHED_REVISION__' || fail_commit tunnel_probe_revision
    printf '%s' "$tunnel_payload" | grep -Fq '"contentSha256":"__CONTENT_SHA256__"' || fail_commit tunnel_probe_hash
fi

[ "$(sha256sum '__HOST_DIRECTORY__/__SOURCE_FILE__' | awk '{print $1}')" = '__SOURCE_SHA256__' ] \
    || fail_commit live_source_hash
[ "$(sha256sum '__HOST_DIRECTORY__/__SCRIPT_FILE__' | awk '{print $1}')" = '__SCRIPT_SHA256__' ] \
    || fail_commit live_script_hash

publication_verified=1
terminal_marker_emitted=1
docker rm -f "$bridge_backup" >/dev/null 2>&1 || true
docker rm -f "$tunnel_backup" >/dev/null 2>&1 || true
echo __SUCCESS_MARKER__:__PUBLISHED_REVISION__:__CONTENT_SHA256__
exit 0
AMNEZIA_ROUTING_COMMIT
if [ "$commit_rc" -ne 0 ]; then
    echo __ERROR_MARKER__:commit_lock_failed:remote_rollback=not_needed
fi
)COMMIT_SH");
    replacePublishVariables(commitScript);

    QString publishOutput;
    // From this point the remote transaction may have started. Unless the
    // server returns a rollback receipt, its recovery state is unknown.
    result.remoteRollbackStatus = QStringLiteral("not_reported");
    errorCode = runPublishingScript(commitScript, publishOutput);

    conflictMatch = conflictExpression.match(publishOutput);
    if (conflictMatch.hasMatch()) {
        bool parsed = false;
        const qint64 currentRevision = conflictMatch.captured(1).toLongLong(&parsed);
        if (parsed) {
            result.currentRevision = currentRevision;
        }
        result.errorCode = ErrorCode::ServerCheckFailed;
        result.conflict = true;
        result.remoteRollbackStatus = QStringLiteral("not_needed");
        result.failureReason = QStringLiteral("Routing policy changed during publication: expected %1, server has %2")
                                       .arg(compareAndSwapRevision)
                                       .arg(result.currentRevision);
        cleanupCandidate();
        return result;
    }

    updateRemoteRollbackResult(publishOutput, result);
    const QString commitFailure = publishFailureReason(publishOutput);
    const QRegularExpression successExpression(
            QStringLiteral("%1:%2:%3")
                    .arg(QRegularExpression::escape(QString::fromLatin1(serverRoutingRulesPublishSuccessMarker)),
                         QString::number(publishedRevision), QRegularExpression::escape(result.contentSha256)));
    const bool verifiedSuccess = successExpression.match(publishOutput).hasMatch();
    if (errorCode != ErrorCode::NoError || !commitFailure.isEmpty() || !verifiedSuccess) {
        qWarning().noquote() << "InstallController::publishServerRoutingRules failed:" << publishOutput;
        result.errorCode = errorCode != ErrorCode::NoError ? errorCode : ErrorCode::ServerDockerFailedError;
        result.failureReason = commitFailure.isEmpty()
                ? QStringLiteral("Server did not return a verified managed routing policy publication receipt")
                : QStringLiteral("Managed routing policy publication failed: %1").arg(commitFailure);
        cleanupCandidate();
        return result;
    }

    result.errorCode = ErrorCode::NoError;
    result.currentRevision = publishedRevision;
    result.publishedRevision = publishedRevision;
    result.publicationVerified = true;
    result.remoteRollbackStatus = QStringLiteral("not_needed");
    qWarning().noquote() << "InstallController: verified managed routing policy revision" << publishedRevision
                         << "was published without a cryptographic signature:" << serverRoutingRulesSigningBlocker;
    return result;
}

ErrorCode InstallController::setupContainer(const ServerCredentials &credentials, DockerContainer container, ContainerConfig &config,
                                            bool isUpdate)
{
    qDebug().noquote() << "InstallController::setupContainer" << ContainerUtils::containerToString(container);
    SshSession sshSession;
    ErrorCode e = ErrorCode::NoError;

    e = isUserInSudo(credentials, sshSession);
    if (e)
        return e;

    e = isServerDpkgBusy(credentials, sshSession);
    if (e)
        return e;

    e = installDockerWorker(credentials, container, sshSession);
    if (e)
        return e;
    qDebug().noquote() << "InstallController::setupContainer installDockerWorker finished";

    if (!isUpdate) {
        e = isServerPortBusy(credentials, container, config, sshSession);
        if (e)
            return e;
    }

    e = prepareHostWorker(credentials, container, sshSession);
    if (e)
        return e;
    qDebug().noquote() << "InstallController::setupContainer prepareHostWorker finished";

    const amnezia::ScriptVars removeContainerVars =
            amnezia::genBaseVars(credentials, container, QString(), QString());
    const bool removeDataVolume = !isUpdate && (container == DockerContainer::MtProxy || container == DockerContainer::Telemt);
    sshSession.runScript(credentials, buildRemoveContainerScript(removeContainerVars, removeDataVolume));
    qDebug().noquote() << "InstallController::setupContainer removeContainer finished";

    qDebug().noquote() << "buildContainerWorker start";
    e = buildContainerWorker(credentials, container, config, sshSession);
    if (e)
        return e;
    qDebug().noquote() << "InstallController::setupContainer buildContainerWorker finished";

    e = runContainerWorker(credentials, container, config, sshSession);
    if (e)
        return e;
    qDebug().noquote() << "InstallController::setupContainer runContainerWorker finished";

    e = configureContainerWorker(credentials, container, config, sshSession);
    if (e)
        return e;
    qDebug().noquote() << "InstallController::setupContainer configureContainerWorker finished";

    setupServerFirewall(credentials, sshSession);
    qDebug().noquote() << "InstallController::setupContainer setupServerFirewall finished";

    return startupContainerWorker(credentials, container, config, sshSession);
}

ErrorCode InstallController::updateServerConfig(const QString &serverId, DockerContainer container, const ContainerConfig &oldConfig,
                                                ContainerConfig &newConfig)
{
    if (!isUpdateDockerContainerRequired(container, oldConfig, newConfig)) {
        auto adminConfig = m_serversRepository->selfHostedAdminConfig(serverId);
        if (!adminConfig.has_value()) {
            return ErrorCode::InternalError;
        }
        if (container == DockerContainer::MtProxy) {
            ServerCredentials credentials = adminConfig->credentials();
            SshSession sshSession;
            MtProxyInstaller::uploadClientSettingsSnapshot(sshSession, credentials, container, newConfig);
        } else if (container == DockerContainer::Telemt) {
            ServerCredentials credentials = adminConfig->credentials();
            SshSession sshSession;
            TelemtInstaller::uploadClientSettingsSnapshot(sshSession, credentials, container, newConfig);
        }
        adminConfig->updateContainerConfig(container, newConfig);
        m_serversRepository->editServer(serverId, adminConfig->toJson(), serverConfigUtils::ConfigType::SelfHostedAdmin);
        return ErrorCode::NoError;
    }

    auto adminConfig = m_serversRepository->selfHostedAdminConfig(serverId);
    if (!adminConfig.has_value()) {
        return ErrorCode::InternalError;
    }
    ServerCredentials credentials = adminConfig->credentials();
    if (!credentials.isValid()) {
        return ErrorCode::InternalError;
    }
    SshSession sshSession;

    bool reinstallRequired = isReinstallContainerRequired(container, oldConfig, newConfig);
    qDebug() << "InstallController::updateServerConfig for container" << container << "reinstall required is" << reinstallRequired;

    ErrorCode errorCode = ErrorCode::NoError;
    if (reinstallRequired) {
        errorCode = setupContainer(credentials, container, newConfig, true);
    } else {
        errorCode = configureContainerWorker(credentials, container, newConfig, sshSession);
        if (errorCode == ErrorCode::NoError) {
            errorCode = startupContainerWorker(credentials, container, newConfig, sshSession);
        }

        if (errorCode == ErrorCode::NoError
            && (container == DockerContainer::MtProxy || container == DockerContainer::Telemt)) {
            const QString containerName = ContainerUtils::containerToString(container);
            errorCode = sshSession.runScript(credentials, "sudo docker restart " + containerName);
        }
    }

    if (errorCode == ErrorCode::NoError) {
        if (container == DockerContainer::MtProxy) {
            MtProxyInstaller::uploadClientSettingsSnapshot(sshSession, credentials, container, newConfig);
        } else if (container == DockerContainer::Telemt) {
            TelemtInstaller::uploadClientSettingsSnapshot(sshSession, credentials, container, newConfig);
        }
        if (reinstallRequired) {
            clearCachedProfile(serverId, container);
        }
        adminConfig->updateContainerConfig(container, newConfig);
        m_serversRepository->editServer(serverId, adminConfig->toJson(), serverConfigUtils::ConfigType::SelfHostedAdmin);
    }

    return errorCode;
}

ErrorCode InstallController::updateClientConfig(const QString &serverId, DockerContainer container, ContainerConfig &newConfig)
{
    switch (m_serversRepository->serverKind(serverId)) {
    case serverConfigUtils::ConfigType::SelfHostedAdmin: {
        auto config = m_serversRepository->selfHostedAdminConfig(serverId);
        if (!config.has_value()) {
            return ErrorCode::InternalError;
        }
        config->updateContainerConfig(container, newConfig);
        m_serversRepository->editServer(serverId, config->toJson(), serverConfigUtils::ConfigType::SelfHostedAdmin);
        return ErrorCode::NoError;
    }
    case serverConfigUtils::ConfigType::SelfHostedUser: {
        auto config = m_serversRepository->selfHostedUserConfig(serverId);
        if (!config.has_value()) {
            return ErrorCode::InternalError;
        }
        config->updateContainerConfig(container, newConfig);
        m_serversRepository->editServer(serverId, config->toJson(), serverConfigUtils::ConfigType::SelfHostedUser);
        return ErrorCode::NoError;
    }
    case serverConfigUtils::ConfigType::Native: {
        auto config = m_serversRepository->nativeConfig(serverId);
        if (!config.has_value()) {
            return ErrorCode::InternalError;
        }
        config->updateContainerConfig(container, newConfig);
        m_serversRepository->editServer(serverId, config->toJson(), serverConfigUtils::ConfigType::Native);
        return ErrorCode::NoError;
    }
    default:
        return ErrorCode::InternalError;
    }
}

void InstallController::clearCachedProfile(const QString &serverId, DockerContainer container)
{
    if (ContainerUtils::containerService(container) == ServiceType::Other) {
        return;
    }

    auto adminConfig = m_serversRepository->selfHostedAdminConfig(serverId);
    if (!adminConfig.has_value()) {
        return;
    }

    const ContainerConfig containerConfigModel = adminConfig->containerConfig(container);

    adminConfig->clearCachedClientProfile(container);
    m_serversRepository->editServer(serverId, adminConfig->toJson(), serverConfigUtils::ConfigType::SelfHostedAdmin);

    emit clientRevocationRequested(serverId, containerConfigModel, container);
}

ErrorCode InstallController::validateAndPrepareConfig(const QString &serverId)
{
    const auto kind = m_serversRepository->serverKind(serverId);

    DockerContainer container = DockerContainer::None;
    ContainerConfig containerConfig;

    switch (kind) {
    case serverConfigUtils::ConfigType::SelfHostedAdmin: {
        const auto cfg = m_serversRepository->selfHostedAdminConfig(serverId);
        if (!cfg.has_value()) {
            return ErrorCode::InternalError;
        }
        container = cfg->defaultContainer;
        containerConfig = cfg->containerConfig(container);
        break;
    }
    case serverConfigUtils::ConfigType::SelfHostedUser: {
        const auto cfg = m_serversRepository->selfHostedUserConfig(serverId);
        if (!cfg.has_value()) {
            return ErrorCode::InternalError;
        }
        container = cfg->defaultContainer;
        containerConfig = cfg->containerConfig(container);
        break;
    }
    case serverConfigUtils::ConfigType::Native: {
        const auto cfg = m_serversRepository->nativeConfig(serverId);
        if (!cfg.has_value()) {
            return ErrorCode::InternalError;
        }
        container = cfg->defaultContainer;
        containerConfig = cfg->containerConfig(container);
        break;
    }
    default:
        return ErrorCode::InternalError;
    }

    if (container == DockerContainer::None) {
        return ErrorCode::NoInstalledContainersError;
    }

    if (containerConfig.protocolConfig.hasClientConfig()) {
        return ErrorCode::NoError;
    }

    if (kind != serverConfigUtils::ConfigType::SelfHostedAdmin) {
        return ErrorCode::InternalError;
    }

    auto adminConfig = m_serversRepository->selfHostedAdminConfig(serverId);
    if (!adminConfig.has_value()) {
        return ErrorCode::InternalError;
    }

    ServerCredentials credentials = adminConfig->credentials();
    if (!credentials.isValid()) {
        return ErrorCode::InternalError;
    }

    SshSession sshSession;
    const QString clientName = QString("Admin [%1]").arg(QSysInfo::prettyProductName());
    const ErrorCode errorCode = processContainerForAdmin(container, containerConfig, credentials, sshSession, serverId, clientName);
    if (errorCode != ErrorCode::NoError) {
        return errorCode;
    }

    adminConfig->updateContainerConfig(container, containerConfig);
    m_serversRepository->editServer(serverId, adminConfig->toJson(), serverConfigUtils::ConfigType::SelfHostedAdmin);

    return ErrorCode::NoError;
}

void InstallController::validateConfig(const QString &serverId)
{
    QFuture<ErrorCode> future = QtConcurrent::run([this, serverId]() {
        return validateAndPrepareConfig(serverId);
    });

    auto *watcher = new QFutureWatcher<ErrorCode>(this);
    connect(watcher, &QFutureWatcher<ErrorCode>::finished, this, [this, watcher]() {
        ErrorCode errorCode = watcher->result();
        watcher->deleteLater();

        if (errorCode == ErrorCode::NoError) {
            emit configValidated(true);
            return;
        }

        emit validationErrorOccurred(errorCode);
        emit configValidated(false);
    });
    watcher->setFuture(future);
}

void InstallController::addEmptyServer(const ServerCredentials &credentials)
{
    SelfHostedAdminServerConfig serverConfig;
    serverConfig.hostName = credentials.hostName;
    serverConfig.userName = credentials.userName;
    serverConfig.password = credentials.secretData;
    serverConfig.sshHostKeyFingerprint = credentials.sshHostKeyFingerprint;
    serverConfig.port = credentials.port;
    serverConfig.description = m_serversRepository->nextAvailableServerName();
    serverConfig.displayName = serverConfig.description.isEmpty() ? serverConfig.hostName : serverConfig.description;
    serverConfig.defaultContainer = DockerContainer::None;

    m_serversRepository->addServer(QString(), serverConfig.toJson(),
                                    serverConfigUtils::ConfigType::SelfHostedAdmin);
}

ErrorCode InstallController::prepareContainerConfig(DockerContainer container, const ServerCredentials &credentials, ContainerConfig &containerConfig, SshSession &sshSession)
{
    if (!ContainerUtils::isSupportedByCurrentPlatform(container)) {
        return ErrorCode::NoError;
    }

    if (ContainerUtils::containerService(container) != ServiceType::Other) {
        Proto protocol = ContainerUtils::defaultProtocol(container);

        DnsSettings dnsSettings = {
            m_appSettingsRepository->primaryDns(),
            m_appSettingsRepository->secondaryDns()
        };

        auto configurator = ConfiguratorBase::create(protocol, &sshSession);
        ErrorCode errorCode = ErrorCode::NoError;
        ProtocolConfig newProtocolConfig = configurator->createConfig(credentials, container, containerConfig, dnsSettings, errorCode);
        if (errorCode != ErrorCode::NoError) {
            return errorCode;
        }

        containerConfig.protocolConfig = newProtocolConfig;
    }

    return ErrorCode::NoError;
}

void InstallController::adminAppendRequested(const QString &serverId, DockerContainer container,
                                             const ContainerConfig &containerConfig, const QString &clientName)
{
    if (ContainerUtils::containerService(container) == ServiceType::Other
        || !containerConfig.protocolConfig.hasClientConfig()) {
        return;
    }
    QString clientId = containerConfig.protocolConfig.clientId();
    if (!clientId.isEmpty()) {
        emit clientAppendRequested(serverId, clientId, clientName, container);
    }
}

ErrorCode InstallController::processContainerForAdmin(DockerContainer container, ContainerConfig &containerConfig,
                                                      const ServerCredentials &credentials, SshSession &sshSession,
                                                      const QString &serverId, const QString &clientName)
{
    if (ContainerUtils::isSupportedByCurrentPlatform(container)) {
        ErrorCode errorCode = prepareContainerConfig(container, credentials, containerConfig, sshSession);
        if (errorCode != ErrorCode::NoError) {
            return errorCode;
        }
    }
    adminAppendRequested(serverId, container, containerConfig, clientName);
    return ErrorCode::NoError;
}

ErrorCode InstallController::buildContainerWorker(const ServerCredentials &credentials, DockerContainer container, const ContainerConfig &config, SshSession &sshSession)
{
    amnezia::ScriptVars baseVars = amnezia::genBaseVars(credentials, container, QString(), QString());
    
    QString dockerfilePath = "/opt/amnezia/" + ContainerUtils::containerToString(container) + "/Dockerfile";
    QString removeScript = QString("sudo rm %1").arg(dockerfilePath);
    
    ErrorCode errorCode = sshSession.runScript(credentials, sshSession.replaceVars(removeScript, baseVars));
    if (errorCode != ErrorCode::NoError) {
        return errorCode;
    }

    errorCode = sshSession.uploadFileToHost(credentials, amnezia::scriptData(ProtocolScriptType::dockerfile, container).toUtf8(), dockerfilePath);
    if (errorCode != ErrorCode::NoError) {
        return errorCode;
    }

    QString stdOut;
    auto cbReadStdOut = [&](const QString &data, libssh::Client &) {
        stdOut += data + "\n";
        return ErrorCode::NoError;
    };
    auto cbReadStdErr = [&](const QString &data, libssh::Client &) {
        stdOut += data + "\n";
        return ErrorCode::NoError;
    };

    amnezia::ScriptVars protocolVars = amnezia::genProtocolVarsForContainer(container, config);
    baseVars.append(protocolVars);
    ErrorCode error = sshSession.runScript(
            credentials, sshSession.replaceVars(amnezia::scriptData(SharedScriptType::build_container), baseVars), cbReadStdOut,
            cbReadStdErr);

    if (stdOut.contains("doesn't work on cgroups v2"))
        return ErrorCode::ServerDockerOnCgroupsV2;
    if (stdOut.contains("cgroup mountpoint does not exist"))
        return ErrorCode::ServerCgroupMountpoint;
    if (stdOut.contains("have reached") && stdOut.contains("pull rate limit"))
        return ErrorCode::DockerPullRateLimit;

    return error;
}

ErrorCode InstallController::runContainerWorker(const ServerCredentials &credentials, DockerContainer container, ContainerConfig &config, SshSession &sshSession)
{
    QString stdOut;
    auto cbReadStdOut = [&](const QString &data, libssh::Client &) {
        stdOut += data + "\n";
        return ErrorCode::NoError;
    };

    amnezia::ScriptVars baseVars = amnezia::genBaseVars(credentials, container, QString(), QString());
    amnezia::ScriptVars protocolVars = amnezia::genProtocolVarsForContainer(container, config);
    baseVars.append(protocolVars);
    ErrorCode e = sshSession.runScript(
            credentials, sshSession.replaceVars(amnezia::scriptData(ProtocolScriptType::run_container, container), baseVars),
            cbReadStdOut);

    if (stdOut.contains("address already in use"))
        return ErrorCode::ServerPortAlreadyAllocatedError;
    if (stdOut.contains("is already in use by container"))
        return ErrorCode::ServerPortAlreadyAllocatedError;
    if (stdOut.contains("invalid publish"))
        return ErrorCode::ServerDockerFailedError;

    return e;
}

ErrorCode InstallController::configureContainerWorker(const ServerCredentials &credentials, DockerContainer container, ContainerConfig &config, SshSession &sshSession)
{
    QString stdOut;
    auto cbReadStdOut = [&](const QString &data, libssh::Client &) {
        stdOut += data + "\n";
        return ErrorCode::NoError;
    };
    auto cbReadStdErr = [&](const QString &data, libssh::Client &) {
        stdOut += data + "\n";
        return ErrorCode::NoError;
    };

    amnezia::ScriptVars baseVars = amnezia::genBaseVars(credentials, container, QString(), QString());
    amnezia::ScriptVars protocolVars = amnezia::genProtocolVarsForContainer(container, config);
    baseVars.append(protocolVars);
    ErrorCode e = sshSession.runContainerScript(
            credentials, container,
            sshSession.replaceVars(amnezia::scriptData(ProtocolScriptType::configure_container, container), baseVars),
            cbReadStdOut, cbReadStdErr);

    if (e != ErrorCode::NoError) {
        return e;
    }

    if (dockerDaemonContainerMissing(stdOut, ContainerUtils::containerToString(container))) {
        qDebug() << "configureContainerWorker: Docker daemon reports container missing/stopped, output:" << stdOut;
        return ErrorCode::ServerContainerMissingError;
    }

    updateContainerConfigAfterInstallation(container, config, stdOut);

    if (container == DockerContainer::MtProxy) {
        MtProxyInstaller::uploadClientSettingsSnapshot(sshSession, credentials, container, config);
    } else if (container == DockerContainer::Telemt) {
        TelemtInstaller::uploadClientSettingsSnapshot(sshSession, credentials, container, config);
    }

    return ErrorCode::NoError;
}

ErrorCode InstallController::startupContainerWorker(const ServerCredentials &credentials, DockerContainer container, const ContainerConfig &config, SshSession &sshSession)
{
    QString script = amnezia::scriptData(ProtocolScriptType::container_startup, container);

    if (script.isEmpty()) {
        return ErrorCode::NoError;
    }

    amnezia::ScriptVars baseVars = amnezia::genBaseVars(credentials, container, QString(), QString());
    amnezia::ScriptVars protocolVars = amnezia::genProtocolVarsForContainer(container, config);
    baseVars.append(protocolVars);
    ErrorCode e = sshSession.uploadTextFileToContainer(container, credentials, sshSession.replaceVars(script, baseVars),
                                                                "/opt/amnezia/start.sh");
    if (e)
        return e;

    return sshSession.runScript(
            credentials,
            sshSession.replaceVars("sudo docker exec -d $CONTAINER_NAME sh -c \"chmod a+x /opt/amnezia/start.sh && "
                                            "/opt/amnezia/start.sh\"",
                                            baseVars));
}

ErrorCode InstallController::isServerPortBusy(const ServerCredentials &credentials, DockerContainer container, const ContainerConfig &config, SshSession &sshSession)
{
    if (container == DockerContainer::Dns) {
        return ErrorCode::NoError;
    }

    QString stdOut;
    auto cbReadStdOut = [&](const QString &data, libssh::Client &) {
        stdOut += data + "\n";
        return ErrorCode::NoError;
    };
    auto cbReadStdErr = [&](const QString &data, libssh::Client &) {
        stdOut += data + "\n";
        return ErrorCode::NoError;
    };

    const Proto protocol = ContainerUtils::defaultProtocol(container);
    QStringList fixedPorts = ContainerUtils::fixedPortsForContainer(container);

    QString port = config.protocolConfig.port();
    if (port.isEmpty()) {
        port = QString::number(ProtocolUtils::defaultPort(protocol));
    }
    QString transportProto = config.protocolConfig.transportProto();
    if (transportProto.isEmpty()) {
        transportProto = ProtocolUtils::transportProtoToString(ProtocolUtils::defaultTransportProto(protocol), protocol);
    }

    // TODO reimplement with netstat
    QString script = QString("which lsof > /dev/null 2>&1 || true && sudo lsof -i -P -n 2>/dev/null | grep -E ':%1 ").arg(port);
    for (auto &port : fixedPorts) {
        script = script.append("|:%1").arg(port);
    }

    if (transportProto == "tcpandudp") {
        QString tcpProtoScript = script;
        QString udpProtoScript = script;
        tcpProtoScript.append("' | grep -i tcp");
        udpProtoScript.append("' | grep -i udp");
        tcpProtoScript.append(" | grep LISTEN");

        ErrorCode errorCode = sshSession.runScript(
                credentials,
                sshSession.replaceVars(tcpProtoScript, amnezia::genBaseVars(credentials, container, QString(), QString())),
                cbReadStdOut, cbReadStdErr);
        if (errorCode != ErrorCode::NoError) {
            return errorCode;
        }

        errorCode = sshSession.runScript(
                credentials,
                sshSession.replaceVars(udpProtoScript, amnezia::genBaseVars(credentials, container, QString(), QString())),
                cbReadStdOut, cbReadStdErr);
        if (errorCode != ErrorCode::NoError) {
            return errorCode;
        }

        if (!stdOut.isEmpty()) {
            return ErrorCode::ServerPortAlreadyAllocatedError;
        }
        return ErrorCode::NoError;
    }

    script = script.append("' | grep -i %1").arg(transportProto);

    if (transportProto == "tcp") {
        script = script.append(" | grep LISTEN");
    }

    ErrorCode errorCode = sshSession.runScript(
            credentials, sshSession.replaceVars(script, amnezia::genBaseVars(credentials, container, QString(), QString())),
            cbReadStdOut, cbReadStdErr);
    if (errorCode != ErrorCode::NoError) {
        return errorCode;
    }

    if (!stdOut.isEmpty()) {
        return ErrorCode::ServerPortAlreadyAllocatedError;
    }
    return ErrorCode::NoError;
}

bool InstallController::isReinstallContainerRequired(DockerContainer container, const ContainerConfig &oldConfig, const ContainerConfig &newConfig)
{
    if (container == DockerContainer::OpenVpn) {
        const auto* oldOvpnConfig = oldConfig.getOpenVpnProtocolConfig();
        const auto* newOvpnConfig = newConfig.getOpenVpnProtocolConfig();
        
        if (oldOvpnConfig && newOvpnConfig) {
            if (!oldOvpnConfig->serverConfig.hasEqualServerSettings(newOvpnConfig->serverConfig)) {
                return true;
            }
        }
    }

    if (ContainerUtils::isAwgContainer(container)) {
        const auto* oldAwgConfig = oldConfig.getAwgProtocolConfig();
        const auto* newAwgConfig = newConfig.getAwgProtocolConfig();
        
        if (oldAwgConfig && newAwgConfig) {
            if (!oldAwgConfig->serverConfig.hasEqualServerSettings(newAwgConfig->serverConfig)) {
                return true;
            }
        }
    }

    if (container == DockerContainer::WireGuard) {
        const auto* oldWgConfig = oldConfig.getWireGuardProtocolConfig();
        const auto* newWgConfig = newConfig.getWireGuardProtocolConfig();
        
        if (oldWgConfig && newWgConfig) {
            if (!oldWgConfig->serverConfig.hasEqualServerSettings(newWgConfig->serverConfig)) {
                return true;
            }
        }
    }

    if (container == DockerContainer::Xray || container == DockerContainer::SSXray) {
        const auto *oldXrayConfig = oldConfig.getXrayProtocolConfig();
        const auto *newXrayConfig = newConfig.getXrayProtocolConfig();

        if (oldXrayConfig && newXrayConfig) {
            if (!oldXrayConfig->serverConfig.hasEqualServerSettings(newXrayConfig->serverConfig)) {
                return true;
            }
        }
    }

    if (container == DockerContainer::MtProxy) {
        const auto *oldMt = oldConfig.getMtProxyProtocolConfig();
        const auto *newMt = newConfig.getMtProxyProtocolConfig();
        if (oldMt && newMt) {
            const QString oldPort =
                    oldMt->port.isEmpty() ? QString(protocols::mtProxy::defaultPort) : oldMt->port;
            const QString newPort =
                    newMt->port.isEmpty() ? QString(protocols::mtProxy::defaultPort) : newMt->port;
            if (oldPort != newPort) {
                return true;
            }
        }
    }

    if (container == DockerContainer::Telemt) {
        const auto *oldT = oldConfig.getTelemtProtocolConfig();
        const auto *newT = newConfig.getTelemtProtocolConfig();
        if (oldT && newT) {
            const QString oldPort =
                    oldT->port.isEmpty() ? QString(protocols::telemt::defaultPort) : oldT->port;
            const QString newPort =
                    newT->port.isEmpty() ? QString(protocols::telemt::defaultPort) : newT->port;
            if (oldPort != newPort) {
                return true;
            }
        }
    }

    if (container == DockerContainer::Socks5Proxy) {
        return true;
    }

    return false;
}

void InstallController::cancelInstallation()
{
    m_cancelInstallation = true;
}

ErrorCode InstallController::installDockerWorker(const ServerCredentials &credentials, DockerContainer container, SshSession &sshSession)
{
    QString stdOut;
    auto cbReadStdOut = [&](const QString &data, libssh::Client &client) {
        stdOut += data + "\n";

        if (data.contains("Automatically restart Docker daemon?")) {
            return client.writeResponse("yes");
        }
        return ErrorCode::NoError;
    };
    auto cbReadStdErr = [&](const QString &data, libssh::Client &) {
        stdOut += data + "\n";
        return ErrorCode::NoError;
    };

    ErrorCode error = sshSession.runScript(
            credentials,
            sshSession.replaceVars(amnezia::scriptData(SharedScriptType::install_docker),
                                            amnezia::genBaseVars(credentials, DockerContainer::None, QString(), QString())),
            cbReadStdOut, cbReadStdErr);

    qDebug().noquote() << "InstallController::installDockerWorker" << stdOut;

    if (container == DockerContainer::MtProxy || container == DockerContainer::Telemt) {
        QString conntrackOut;
        auto cbConntrack = [&](const QString &data, libssh::Client &) {
            conntrackOut += data + "\n";
            return ErrorCode::NoError;
        };
        sshSession.runScript(
                credentials,
                sshSession.replaceVars(amnezia::scriptData(SharedScriptType::install_conntrack),
                                       amnezia::genBaseVars(credentials, DockerContainer::None, QString(), QString())),
                cbConntrack, cbConntrack);
        qDebug().noquote() << "InstallController::installDockerWorker install_conntrack:" << conntrackOut;
    }

    if (container == DockerContainer::Awg2) {
        QRegularExpression kernelVersionRegex(R"(Linux\s+(\d+)\.(\d+)[^\d]*)");
        QRegularExpressionMatch match = kernelVersionRegex.match(stdOut);
        if (match.hasMatch()) {
            int majorVersion = match.captured(1).toInt();
            int minorVersion = match.captured(2).toInt();

            if (majorVersion < 4 || (majorVersion == 4 && minorVersion < 14)) {
                return ErrorCode::ServerLinuxKernelTooOld;
            }
        }
    }

    if (stdOut.contains("lock"))
        return ErrorCode::ServerPacketManagerError;
    if (stdOut.contains("Container runtime is not supported"))
        return ErrorCode::ServerContainerRuntimeNotSupported;

    QRegularExpression notFoundRegex(
        R"(^.*(?:sudo:|docker:).*not found.*$)",
        QRegularExpression::MultilineOption);

    if (notFoundRegex.match(stdOut).hasMatch()) {
        return ErrorCode::ServerDockerFailedError;
    }

    if (stdOut.contains("Container runtime service not running"))
        return ErrorCode::ContainerRuntimeServiceNotRunning;

    return error;
}

ErrorCode InstallController::prepareHostWorker(const ServerCredentials &credentials, DockerContainer container, SshSession &sshSession)
{
    // create folder on host
    return sshSession.runScript(credentials,
                                         sshSession.replaceVars(amnezia::scriptData(SharedScriptType::prepare_host),
                                                                         amnezia::genBaseVars(credentials, container, QString(), QString())));
}

ErrorCode InstallController::isUserInSudo(const ServerCredentials &credentials, SshSession &sshSession)
{
    QString stdOut;
    auto cbReadStdOut = [&](const QString &data, libssh::Client &) {
        stdOut += data + "\n";
        return ErrorCode::NoError;
    };
    auto cbReadStdErr = [&](const QString &data, libssh::Client &) {
        stdOut += data + "\n";
        return ErrorCode::NoError;
    };

    const QString scriptData = amnezia::scriptData(SharedScriptType::check_user_in_sudo);
    ErrorCode error = sshSession.runScript(
            credentials,
            sshSession.replaceVars(scriptData, amnezia::genBaseVars(credentials, DockerContainer::None, QString(), QString())),
            cbReadStdOut, cbReadStdErr);

    if (credentials.userName != "root" && stdOut.contains("sudo:") && !stdOut.contains("uname:") && stdOut.contains("not found"))
        return ErrorCode::ServerSudoPackageIsNotPreinstalled;
    if (credentials.userName != "root" && !stdOut.contains("sudo") && !stdOut.contains("wheel"))
        return ErrorCode::ServerUserNotInSudo;
    if (stdOut.contains("can't cd to") || stdOut.contains("Permission denied") || stdOut.contains("No such file or directory"))
        return ErrorCode::ServerUserDirectoryNotAccessible;
    if (stdOut.contains(QRegularExpression(R"(\bsudoers\b)")) || stdOut.contains("is not allowed to") || stdOut.contains("can't do that"))
        return ErrorCode::ServerUserNotAllowedInSudoers;
    if (stdOut.contains("password is required") || stdOut.contains("authentication is required"))
        return ErrorCode::ServerUserPasswordRequired;

    return error;
}

ErrorCode InstallController::isServerDpkgBusy(const ServerCredentials &credentials, SshSession &sshSession)
{
    m_cancelInstallation = false;
    QString stdOut;
    auto cbReadStdOut = [&](const QString &data, libssh::Client &) {
        stdOut += data + "\n";
        return ErrorCode::NoError;
    };
    auto cbReadStdErr = [&](const QString &data, libssh::Client &) {
        stdOut += data + "\n";
        return ErrorCode::NoError;
    };

    QFutureWatcher<ErrorCode> watcher;

    QFuture<ErrorCode> future = QtConcurrent::run([this, &stdOut, &cbReadStdOut, &cbReadStdErr, &credentials, &sshSession]() {
        // max 100 attempts
        for (int i = 0; i < 30; ++i) {
            if (m_cancelInstallation) {
                return ErrorCode::ServerCancelInstallation;
            }
            stdOut.clear();
            sshSession.runScript(
                    credentials,
                    sshSession.replaceVars(amnezia::scriptData(SharedScriptType::check_server_is_busy),
                                                    amnezia::genBaseVars(credentials, DockerContainer::None, QString(), QString())),
                    cbReadStdOut, cbReadStdErr);

            if (stdOut.contains("Packet manager not found"))
                return ErrorCode::ServerPacketManagerError;
            if (stdOut.contains("fuser not installed") || stdOut.contains("cat not installed"))
                return ErrorCode::NoError;

            if (stdOut.isEmpty()) {
                return ErrorCode::NoError;
            } else {
#ifdef MZ_DEBUG
                qDebug().noquote() << stdOut;
#endif
                emit serverIsBusy(true);
                QThread::msleep(10000);
            }
        }
        return ErrorCode::ServerPacketManagerError;
    });

    QEventLoop wait;
    QObject::connect(&watcher, &QFutureWatcher<ErrorCode>::finished, &wait, &QEventLoop::quit);
    watcher.setFuture(future);
    wait.exec();

    emit serverIsBusy(false);

    return future.result();
}

ErrorCode InstallController::setupServerFirewall(const ServerCredentials &credentials, SshSession &sshSession)
{
    return sshSession.runScript(
            credentials,
            sshSession.replaceVars(amnezia::scriptData(SharedScriptType::setup_host_firewall),
                                            amnezia::genBaseVars(credentials, DockerContainer::None, QString(), QString())));
}

ErrorCode InstallController::rebootServer(const QString &serverId)
{
    const auto adminConfig = m_serversRepository->selfHostedAdminConfig(serverId);
    if (!adminConfig.has_value()) {
        return ErrorCode::InternalError;
    }
    ServerCredentials credentials = adminConfig->credentials();
    if (!credentials.isValid()) {
        return ErrorCode::InternalError;
    }
    SshSession sshSession;

    QString script = QString("sudo reboot");

    QString stdOut;
    auto cbReadStdOut = [&](const QString &data, libssh::Client &) {
        stdOut += data;
        return ErrorCode::NoError;
    };

    auto cbReadStdErr = [&](const QString &data, libssh::Client &) {
        stdOut += data + "\n";
        return ErrorCode::NoError;
    };

    return sshSession.runScript(credentials, script, cbReadStdOut, cbReadStdErr);
}

ErrorCode InstallController::removeAllContainers(const QString &serverId)
{
    auto adminConfig = m_serversRepository->selfHostedAdminConfig(serverId);
    if (!adminConfig.has_value()) {
        return ErrorCode::InternalError;
    }
    ServerCredentials credentials = adminConfig->credentials();
    if (!credentials.isValid()) {
        return ErrorCode::InternalError;
    }
    SshSession sshSession;
    ErrorCode errorCode = sshSession.runScript(credentials, amnezia::scriptData(SharedScriptType::remove_all_containers));

    if (errorCode == ErrorCode::NoError) {
        adminConfig->containers.clear();
        adminConfig->defaultContainer = DockerContainer::None;
        m_serversRepository->editServer(serverId, adminConfig->toJson(), serverConfigUtils::ConfigType::SelfHostedAdmin);
    }

    return errorCode;
}

ErrorCode InstallController::removeContainer(const QString &serverId, DockerContainer container)
{
    auto adminConfig = m_serversRepository->selfHostedAdminConfig(serverId);
    if (!adminConfig.has_value()) {
        return ErrorCode::InternalError;
    }
    ServerCredentials credentials = adminConfig->credentials();
    if (!credentials.isValid()) {
        return ErrorCode::InternalError;
    }
    SshSession sshSession;
    const amnezia::ScriptVars removeContainerVars =
            amnezia::genBaseVars(credentials, container, QString(), QString());
    const bool removeDataVolume = (container == DockerContainer::MtProxy || container == DockerContainer::Telemt);
    ErrorCode errorCode =
            sshSession.runScript(credentials, buildRemoveContainerScript(removeContainerVars, removeDataVolume));

    if (errorCode == ErrorCode::NoError) {
        QMap<DockerContainer, ContainerConfig> containers = adminConfig->containers;
        containers.remove(container);

        DockerContainer defaultContainer = adminConfig->defaultContainer;
        if (defaultContainer == container) {
            if (containers.isEmpty()) {
                defaultContainer = DockerContainer::None;
            } else {
                defaultContainer = containers.begin().key();
            }
        }

        adminConfig->containers = containers;
        adminConfig->defaultContainer = defaultContainer;
        m_serversRepository->editServer(serverId, adminConfig->toJson(), serverConfigUtils::ConfigType::SelfHostedAdmin);
    }

    return errorCode;
}

QScopedPointer<InstallerBase> InstallController::createInstaller(DockerContainer container)
{
    switch (container) {
    case DockerContainer::Awg: return QScopedPointer<InstallerBase>(new AwgInstaller(this));
    case DockerContainer::Awg2: return QScopedPointer<InstallerBase>(new AwgInstaller(this));
    case DockerContainer::WireGuard: return QScopedPointer<InstallerBase>(new WireguardInstaller(this));
    case DockerContainer::OpenVpn: return QScopedPointer<InstallerBase>(new OpenVpnInstaller(this));
    case DockerContainer::Xray:
    case DockerContainer::SSXray: return QScopedPointer<InstallerBase>(new XrayInstaller(this));
    case DockerContainer::TorWebSite: return QScopedPointer<InstallerBase>(new TorInstaller(this));
    case DockerContainer::Sftp: return QScopedPointer<InstallerBase>(new SftpInstaller(this));
    case DockerContainer::Socks5Proxy: return QScopedPointer<InstallerBase>(new Socks5Installer(this));
    case DockerContainer::MtProxy: return QScopedPointer<InstallerBase>(new MtProxyInstaller(this));
    case DockerContainer::Telemt: return QScopedPointer<InstallerBase>(new TelemtInstaller(this));
    default: return QScopedPointer<InstallerBase>(new InstallerBase(this));
    }
}

ContainerConfig InstallController::generateConfig(DockerContainer container, int port, TransportProto transportProto)
{
    auto installer = createInstaller(container);
    return installer->generateConfig(container, port, transportProto);
}

ErrorCode InstallController::installContainer(const ServerCredentials &credentials, DockerContainer container, int port,
                                              TransportProto transportProto, ContainerConfig &config)
{
    config = generateConfig(container, port, transportProto);
    return setupContainer(credentials, container, config, false);
}


bool InstallController::isUpdateDockerContainerRequired(DockerContainer container, const ContainerConfig &oldConfig, const ContainerConfig &newConfig)
{
    if (ContainerUtils::isAwgContainer(container)) {
        const auto* oldAwgConfig = oldConfig.getAwgProtocolConfig();
        const auto* newAwgConfig = newConfig.getAwgProtocolConfig();
        
        if (oldAwgConfig && newAwgConfig) {
            if (oldAwgConfig->serverConfig.hasEqualServerSettings(newAwgConfig->serverConfig)) {
                return false;
            }
        }
    } else if (container == DockerContainer::WireGuard) {
        const auto* oldWgConfig = oldConfig.getWireGuardProtocolConfig();
        const auto* newWgConfig = newConfig.getWireGuardProtocolConfig();
        
        if (oldWgConfig && newWgConfig) {
            if (oldWgConfig->serverConfig.hasEqualServerSettings(newWgConfig->serverConfig)) {
                return false;
            }
        }
    } else if (container == DockerContainer::MtProxy) {
        const auto *oldMt = oldConfig.getMtProxyProtocolConfig();
        const auto *newMt = newConfig.getMtProxyProtocolConfig();
        if (!oldMt || !newMt) {
            return true;
        }
        return !oldMt->equalsDockerDeploymentSettings(*newMt);
    } else if (container == DockerContainer::Telemt) {
        const auto *oldT = oldConfig.getTelemtProtocolConfig();
        const auto *newT = newConfig.getTelemtProtocolConfig();
        if (!oldT || !newT) {
            return true;
        }
        return !oldT->equalsDockerDeploymentSettings(*newT);
    }

    return true;
}

ErrorCode InstallController::scanServerForInstalledContainers(const QString &serverId)
{
    auto adminConfig = m_serversRepository->selfHostedAdminConfig(serverId);
    if (!adminConfig.has_value()) {
        return ErrorCode::InternalError;
    }
    ServerCredentials credentials = adminConfig->credentials();
    if (!credentials.isValid()) {
        return ErrorCode::InternalError;
    }
    SshSession sshSession;

    QMap<DockerContainer, ContainerConfig> installedContainers;
    ErrorCode errorCode = getAlreadyInstalledContainers(credentials, installedContainers, sshSession);
    if (errorCode != ErrorCode::NoError) {
        return errorCode;
    }

    QMap<DockerContainer, ContainerConfig> containers = adminConfig->containers;
    bool hasNewContainers = false;

    QString clientName = QString("Admin [%1]").arg(QSysInfo::prettyProductName());
    for (auto iterator = installedContainers.begin(); iterator != installedContainers.end(); iterator++) {
        if (!containers.contains(iterator.key())) {
            ContainerConfig containerConfig = iterator.value();
            errorCode = processContainerForAdmin(iterator.key(), containerConfig, credentials, sshSession,
                                                 serverId, clientName);
            if (errorCode != ErrorCode::NoError) {
                return errorCode;
            }
            containers.insert(iterator.key(), containerConfig);
            hasNewContainers = true;

            DockerContainer defaultContainer = adminConfig->defaultContainer;
            if (defaultContainer == DockerContainer::None
                && ContainerUtils::containerService(iterator.key()) != ServiceType::Other
                && ContainerUtils::isSupportedByCurrentPlatform(iterator.key())) {
                adminConfig->defaultContainer = iterator.key();
            }
        }
    }

    adminConfig->containers = containers;
    QJsonObject serverJson = adminConfig->toJson();
    const bool hasNewRoutingRules = mergeServerRoutingRules(serverJson,
                                                            loadStoredServerRoutingRules(credentials, sshSession));

    if (hasNewContainers || hasNewRoutingRules) {
        adminConfig->containers = containers;
        m_serversRepository->editServer(serverId, serverJson, serverConfigUtils::ConfigType::SelfHostedAdmin);
    }

    return ErrorCode::NoError;
}

ErrorCode InstallController::installServer(const ServerCredentials &credentials, DockerContainer container, int port,
                                           TransportProto transportProto, bool &wasContainerInstalled)
{
    SshSession sshSession;
    QMap<DockerContainer, ContainerConfig> installedContainers;
    ErrorCode errorCode = getAlreadyInstalledContainers(credentials, installedContainers, sshSession);
    if (errorCode) {
        return errorCode;
    }

    wasContainerInstalled = false;
    if (!installedContainers.contains(container)) {
        ContainerConfig config;
        errorCode = installContainer(credentials, container, port, transportProto, config);
        if (errorCode) {
            return errorCode;
        }

        installedContainers.insert(container, config);
        wasContainerInstalled = true;
    }

    QMap<DockerContainer, ContainerConfig> preparedContainers;
    for (auto iterator = installedContainers.begin(); iterator != installedContainers.end(); iterator++) {
        DockerContainer container = iterator.key();
        ContainerConfig containerConfig = iterator.value();

        if (ContainerUtils::isSupportedByCurrentPlatform(container)) {
            errorCode = prepareContainerConfig(container, credentials, containerConfig, sshSession);
            if (errorCode != ErrorCode::NoError) {
                return errorCode;
            }
        }
        preparedContainers.insert(container, containerConfig);
    }

    SelfHostedAdminServerConfig serverConfig;
    serverConfig.hostName = credentials.hostName;
    serverConfig.userName = credentials.userName;
    serverConfig.password = credentials.secretData;
    serverConfig.sshHostKeyFingerprint = credentials.sshHostKeyFingerprint;
    serverConfig.port = credentials.port;
    serverConfig.description = m_serversRepository->nextAvailableServerName();

    for (auto iterator = preparedContainers.begin(); iterator != preparedContainers.end(); iterator++) {
        serverConfig.containers.insert(iterator.key(), iterator.value());
    }

    serverConfig.defaultContainer = container;

    serverConfig.displayName = serverConfig.description.isEmpty() ? serverConfig.hostName : serverConfig.description;

    QJsonObject serverJson = serverConfig.toJson();
    mergeServerRoutingRules(serverJson, loadStoredServerRoutingRules(credentials, sshSession));

    const QString newServerId = m_serversRepository->addServer(QString(), serverJson,
                                                               serverConfigUtils::ConfigType::SelfHostedAdmin);
    QString clientName = QString("Admin [%1]").arg(QSysInfo::prettyProductName());
    for (auto iterator = preparedContainers.begin(); iterator != preparedContainers.end(); iterator++) {
        adminAppendRequested(newServerId, iterator.key(), iterator.value(), clientName);
    }

    return ErrorCode::NoError;
}

ErrorCode InstallController::installContainer(const QString &serverId, DockerContainer container, int port,
                                              TransportProto transportProto, bool &wasContainerInstalled)
{
    auto adminConfig = m_serversRepository->selfHostedAdminConfig(serverId);
    if (!adminConfig.has_value()) {
        return ErrorCode::InternalError;
    }
    ServerCredentials credentials = adminConfig->credentials();
    if (!credentials.isValid()) {
        return ErrorCode::InternalError;
    }
    SshSession sshSession;
    
    QMap<DockerContainer, ContainerConfig> installedContainers;
    ErrorCode errorCode = getAlreadyInstalledContainers(credentials, installedContainers, sshSession);
    if (errorCode) {
        return errorCode;
    }

    wasContainerInstalled = false;
    if (!installedContainers.contains(container)) {
        ContainerConfig config;
        errorCode = installContainer(credentials, container, port, transportProto, config);
        if (errorCode) {
            return errorCode;
        }

        installedContainers.insert(container, config);
        wasContainerInstalled = true;
    }

    QString clientName = QString("Admin [%1]").arg(QSysInfo::prettyProductName());
    for (auto iterator = installedContainers.begin(); iterator != installedContainers.end(); iterator++) {
        ContainerConfig existingConfigModel = adminConfig->containerConfig(iterator.key());
        if (existingConfigModel.container == DockerContainer::None) {
            ContainerConfig containerConfig = iterator.value();
            errorCode = processContainerForAdmin(iterator.key(), containerConfig, credentials, sshSession,
                                                 serverId, clientName);
            if (errorCode != ErrorCode::NoError) {
                return errorCode;
            }
            adminConfig->updateContainerConfig(iterator.key(), containerConfig);
            m_serversRepository->editServer(serverId, adminConfig->toJson(),
                                            serverConfigUtils::ConfigType::SelfHostedAdmin);
        }
    }

    return ErrorCode::NoError;
}

ErrorCode InstallController::checkSshConnection(ServerCredentials &credentials, QString &output,
                                                std::function<QString()> passphraseCallback)
{
    SshSession sshSession;
    ErrorCode errorCode = ErrorCode::NoError;

    if (credentials.secretData.contains("BEGIN") && credentials.secretData.contains("PRIVATE KEY")) {
        if (!passphraseCallback) {
            return ErrorCode::SshPrivateKeyError;
        }

        QString decryptedPrivateKey;
        errorCode = sshSession.getDecryptedPrivateKey(credentials, decryptedPrivateKey, passphraseCallback);
        if (errorCode != ErrorCode::NoError) {
            return errorCode;
        }
        credentials.secretData = decryptedPrivateKey;
    }

    output = sshSession.checkSshConnection(credentials, errorCode);
    return errorCode;
}

bool InstallController::isServerAlreadyExists(const ServerCredentials &credentials, int &existingServerIndex)
{
    int serversCount = m_serversRepository->serversCount();
    for (int i = 0; i < serversCount; i++) {
        const QString existingServerId = m_serversRepository->serverIdAt(i);
        const auto adminConfig = m_serversRepository->selfHostedAdminConfig(existingServerId);
        if (!adminConfig.has_value()) {
            continue;
        }
        const ServerCredentials existingCredentials = adminConfig->credentials();
        if (!existingCredentials.isValid()) {
            continue;
        }
        if (credentials.hostName == existingCredentials.hostName && credentials.port == existingCredentials.port) {
            existingServerIndex = i;
            return true;
        }
    }
    existingServerIndex = -1;
    return false;
}

ErrorCode InstallController::mountSftpDrive(const ServerCredentials &credentials, const QString &port, const QString &password,
                                            const QString &username)
{
    QString mountPath;
    QString cmd;
    QString hostname = credentials.hostName;

#ifdef Q_OS_WINDOWS
    mountPath = Utils::getNextDriverLetter() + ":";
    cmd = "C:\\Program Files\\SSHFS-Win\\bin\\sshfs.exe";
#elif defined AMNEZIA_DESKTOP
    mountPath = QString("%1/sftp:%2:%3").arg(QStandardPaths::writableLocation(QStandardPaths::HomeLocation), hostname, port);
    QDir dir(mountPath);
    if (!dir.exists()) {
        dir.mkpath(mountPath);
    }

    cmd = "/usr/local/bin/sshfs";

    QSharedPointer<QProcess> process(new QProcess(this));
    process->setProcessChannelMode(QProcess::MergedChannels);

    connect(process.get(), &QProcess::readyRead, this, [process, mountPath]() {
        QString s = process->readAll();
        if (s.contains("The service sshfs has been started")) {
            QDesktopServices::openUrl(QUrl("file:///" + mountPath));
        }
        qDebug() << s;
    });

    process->setProgram(cmd);

    QString args = QString("%1@%2:/ %3 "
                           "-o port=%4 "
                           "-f "
                           "-o reconnect "
                           "-o rellinks "
                           "-o fstypename=SSHFS "
                           "-o ssh_command=/usr/bin/ssh.exe "
                           "-o StrictHostKeyChecking=yes "
                           "-o password_stdin")
                           .arg(username, hostname, mountPath, port);

    process->setArguments(args.split(" ", Qt::SkipEmptyParts));
    process->start();
    process->waitForStarted(50);
    if (process->state() != QProcess::Running) {
        qDebug() << "mountSftpDrive process not started";
        qDebug() << args;
        return ErrorCode::ServerContainerMissingError;
    } else {
        process->write((password + "\n").toUtf8());
    }

    m_sftpMountProcesses.append(process);
#else
    Q_UNUSED(mountPath);
    Q_UNUSED(cmd);
    Q_UNUSED(password);
    return ErrorCode::NoError;
#endif

    return ErrorCode::NoError;
}

void InstallController::stopAllSftpMounts()
{
#ifdef Q_OS_WINDOWS
    for (QSharedPointer<QProcess> process : m_sftpMountProcesses) {
        Utils::signalCtrl(process->processId(), CTRL_C_EVENT);
        process->kill();
        process->waitForFinished();
    }
    m_sftpMountProcesses.clear();
#endif
}

void InstallController::updateContainerConfigAfterInstallation(DockerContainer container, ContainerConfig &containerConfig, const QString &stdOut)
{
    Proto mainProto = ContainerUtils::defaultProtocol(container);

    if (container == DockerContainer::TorWebSite) {
        if (auto* torProtocolConfig = containerConfig.getTorProtocolConfig()) {
            qDebug() << "amnezia-tor onions" << stdOut;

            QString onion = stdOut;
            onion.replace("\n", "");
            torProtocolConfig->serverConfig.site = onion;
        }
    } else if (container == DockerContainer::MtProxy) {
        if (auto* mtProxyConfig = containerConfig.getMtProxyProtocolConfig()) {
            qDebug() << "amnezia mtproxy" << stdOut;

            static const QRegularExpression reSecret(
                    QStringLiteral(R"(\[\*\]\s+Secret:\s+([0-9a-fA-F]{32}))"),
                    QRegularExpression::CaseInsensitiveOption);
            static const QRegularExpression reTgLink(QStringLiteral(R"(\[\*\]\s+tg://\s+link:\s+(tg://proxy\?[^\s]+))"));
            static const QRegularExpression reTmeLink(
                    QStringLiteral(R"(\[\*\]\s+t\.me\s+link:\s+(https://t\.me/proxy\?[^\s]+))"));

            const QRegularExpressionMatch mSecret = reSecret.match(stdOut);
            const QRegularExpressionMatch mTgLink = reTgLink.match(stdOut);
            const QRegularExpressionMatch mTmeLink = reTmeLink.match(stdOut);

            if (mSecret.hasMatch()) {
                mtProxyConfig->secret = mSecret.captured(1);
            }
            if (mTgLink.hasMatch()) {
                mtProxyConfig->tgLink = mTgLink.captured(1);
            }
            if (mTmeLink.hasMatch()) {
                mtProxyConfig->tmeLink = mTmeLink.captured(1);
            }
        }
    } else if (container == DockerContainer::Telemt) {
        if (auto *telemtConfig = containerConfig.getTelemtProtocolConfig()) {
            qDebug() << "amnezia-telemt configure stdout" << stdOut;

            static const QRegularExpression reSecret(
                    QStringLiteral(R"(\[\*\]\s+Secret:\s+([0-9a-fA-F]{32}))"),
                    QRegularExpression::CaseInsensitiveOption);
            static const QRegularExpression reTgLink(QStringLiteral(R"(\[\*\]\s+tg://\s+link:\s+(tg://proxy\?[^\s]+))"));
            static const QRegularExpression reTmeLink(
                    QStringLiteral(R"(\[\*\]\s+t\.me\s+link:\s+(https://t\.me/proxy\?[^\s]+))"));

            const QRegularExpressionMatch mSecret = reSecret.match(stdOut);
            const QRegularExpressionMatch mTgLink = reTgLink.match(stdOut);
            const QRegularExpressionMatch mTmeLink = reTmeLink.match(stdOut);

            if (mSecret.hasMatch()) {
                telemtConfig->secret = mSecret.captured(1);
            }
            if (mTgLink.hasMatch()) {
                telemtConfig->tgLink = mTgLink.captured(1);
            }
            if (mTmeLink.hasMatch()) {
                telemtConfig->tmeLink = mTmeLink.captured(1);
            }
        }
    }
}

ErrorCode InstallController::getAlreadyInstalledContainers(const ServerCredentials &credentials,
                                                           QMap<DockerContainer, ContainerConfig> &installedContainers, SshSession &sshSession)
{
    QString stdOut;
    auto cbReadStdOut = [&](const QString &data, libssh::Client &) {
        stdOut += data + "\n";
        return ErrorCode::NoError;
    };
    auto cbReadStdErr = [&](const QString &data, libssh::Client &) {
        stdOut += data + "\n";
        return ErrorCode::NoError;
    };

    QString script = QString("sudo docker ps --format '{{.Names}} {{.Ports}}'");
    ErrorCode errorCode = sshSession.runScript(credentials, script, cbReadStdOut, cbReadStdErr);
    if (errorCode != ErrorCode::NoError) {
        return errorCode;
    }

    const static QRegularExpression containerAndPortRegExp("(amnezia[-a-z0-9]*).*?:([0-9]*)->[0-9]*/(udp|tcp).*");
    const static QRegularExpression torOrDnsRegExp("(amnezia-(?:torwebsite|dns)).*?([0-9]*)/(udp|tcp).*");

    QStringList containerInfos = stdOut.split("\n");
    for (const QString &containerInfo : containerInfos) {
        if (containerInfo.isEmpty()) {
            continue;
        }

        QRegularExpressionMatch containerAndPortMatch = containerAndPortRegExp.match(containerInfo);
        if (containerAndPortMatch.hasMatch()) {
            QString name = containerAndPortMatch.captured(1);
            QString portStr = containerAndPortMatch.captured(2);
            QString transportProtoStr = containerAndPortMatch.captured(3);
            DockerContainer container = ContainerUtils::containerFromString(name);

            if (container == DockerContainer::None || ContainerUtils::isUnsupportedContainer(container)) {
                continue;
            }

            int port = portStr.toInt();
            TransportProto transportProto = ProtocolUtils::transportProtoFromString(transportProtoStr);

            auto installer = createInstaller(container);
            ContainerConfig config = installer->createBaseConfig(container, port, transportProto);
            ErrorCode extractError = installer->extractConfigFromContainer(container, credentials, &sshSession, config);

            if (extractError != ErrorCode::NoError && extractError != ErrorCode::ServerContainerMissingError) {
                return extractError;
            }

            installedContainers.insert(container, config);
        }

        QRegularExpressionMatch torOrDnsRegMatch = torOrDnsRegExp.match(containerInfo);
        if (torOrDnsRegMatch.hasMatch()) {
            QString name = torOrDnsRegMatch.captured(1);
            QString portStr = torOrDnsRegMatch.captured(2);
            QString transportProtoStr = torOrDnsRegMatch.captured(3);
            DockerContainer container = ContainerUtils::containerFromString(name);

            if (container == DockerContainer::None || ContainerUtils::isUnsupportedContainer(container)) {
                continue;
            }

            int port = portStr.toInt();
            TransportProto transportProto = ProtocolUtils::transportProtoFromString(transportProtoStr);

            auto installer = createInstaller(container);
            ContainerConfig config = installer->createBaseConfig(container, port, transportProto);
            ErrorCode extractError = installer->extractConfigFromContainer(container, credentials, &sshSession, config);

            if (extractError != ErrorCode::NoError && extractError != ErrorCode::ServerContainerMissingError) {
                return extractError;
            }

            installedContainers.insert(container, config);
        }
    }

    return ErrorCode::NoError;
}

ErrorCode InstallController::setDockerContainerEnabledState(const QString &serverId, DockerContainer container, bool enabled)
{
    if (container != DockerContainer::MtProxy && container != DockerContainer::Telemt) {
        return ErrorCode::InternalError;
    }
    auto adminConfig = m_serversRepository->selfHostedAdminConfig(serverId);
    if (!adminConfig.has_value()) {
        return ErrorCode::InternalError;
    }
    ServerCredentials credentials = adminConfig->credentials();
    if (!credentials.isValid()) {
        return ErrorCode::InternalError;
    }
    const QString containerName = ContainerUtils::containerToString(container);
    SshSession sshSession;
    const QString script = enabled ? QStringLiteral("sudo docker start %1").arg(containerName)
                                   : QStringLiteral("sudo docker stop %1").arg(containerName);
    const ErrorCode runError = sshSession.runScript(credentials, script);
    if (runError != ErrorCode::NoError) {
        return runError;
    }
    ContainerConfig currentConfig = adminConfig->containerConfig(container);
    bool persist = false;
    if (auto *mtConfig = currentConfig.getMtProxyProtocolConfig()) {
        mtConfig->isEnabled = enabled;
        persist = true;
    } else if (auto *telemtConfig = currentConfig.getTelemtProtocolConfig()) {
        telemtConfig->isEnabled = enabled;
        persist = true;
    }
    if (persist) {
        adminConfig->updateContainerConfig(container, currentConfig);
        m_serversRepository->editServer(serverId, adminConfig->toJson(), serverConfigUtils::ConfigType::SelfHostedAdmin);
    }
    return ErrorCode::NoError;
}

ErrorCode InstallController::queryDockerContainerStatus(const QString &serverId, DockerContainer container, int &statusOut)
{
    statusOut = 3;
    auto adminConfig = m_serversRepository->selfHostedAdminConfig(serverId);
    if (!adminConfig.has_value()) {
        return ErrorCode::InternalError;
    }
    ServerCredentials credentials = adminConfig->credentials();
    if (!credentials.isValid()) {
        return ErrorCode::InternalError;
    }
    const QString containerName = ContainerUtils::containerToString(container);
    QString stdOut;
    auto cbReadStdOut = [&](const QString &data, libssh::Client &) {
        stdOut += data;
        return ErrorCode::NoError;
    };
    SshSession sshSession;
    const QString script = QStringLiteral(
            "sudo docker inspect --format '{{.State.Status}}' %1 2>/dev/null || echo 'not_found'")
            .arg(containerName);
    const ErrorCode errorCode = sshSession.runScript(credentials, script, cbReadStdOut);
    if (errorCode != ErrorCode::NoError) {
        return errorCode;
    }
    const QString status = stdOut.trimmed();
    if (status == QLatin1String("running")) {
        statusOut = 1;
    } else if (status == QLatin1String("not_found") || status.isEmpty()) {
        statusOut = 0;
    } else if (status == QLatin1String("exited") || status == QLatin1String("created")
               || status == QLatin1String("paused")) {
        statusOut = 2;
    } else {
        statusOut = 3;
    }
    return ErrorCode::NoError;
}

ErrorCode InstallController::queryMtProxyDiagnostics(const QString &serverId, DockerContainer container, int listenPort,
                                                     MtProxyContainerDiagnostics &out)
{
    out = {};
    auto adminConfig = m_serversRepository->selfHostedAdminConfig(serverId);
    if (!adminConfig.has_value()) {
        return ErrorCode::InternalError;
    }
    ServerCredentials credentials = adminConfig->credentials();
    if (!credentials.isValid()) {
        return ErrorCode::InternalError;
    }
    SshSession sshSession;
    return MtProxyInstaller::queryDiagnostics(sshSession, credentials, container, listenPort, out);
}

QString InstallController::fetchDockerContainerSecret(const QString &serverId, DockerContainer container)
{
    if (container != DockerContainer::MtProxy && container != DockerContainer::Telemt) {
        return {};
    }
    auto adminConfig = m_serversRepository->selfHostedAdminConfig(serverId);
    if (!adminConfig.has_value()) {
        return {};
    }
    ServerCredentials credentials = adminConfig->credentials();
    if (!credentials.isValid()) {
        return {};
    }
    const QString containerName = ContainerUtils::containerToString(container);
    QString stdOut;
    auto cbReadStdOut = [&](const QString &data, libssh::Client &) {
        stdOut += data;
        return ErrorCode::NoError;
    };
    SshSession sshSession;
    const QString path = QStringLiteral("/data/secret");
    const QString cmd = QStringLiteral("sudo docker exec %1 cat %2").arg(containerName, path);
    const ErrorCode errorCode = sshSession.runScript(credentials, cmd, cbReadStdOut);
    if (errorCode != ErrorCode::NoError) {
        return {};
    }
    const QString secret = stdOut.trimmed();
    static const QRegularExpression hex32(QStringLiteral("^[0-9a-fA-F]{32}$"));
    return hex32.match(secret).hasMatch() ? secret : QString();
}
