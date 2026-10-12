#pragma once
#include <QCryptographicHash>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMap>
#include <QRegularExpression>
#include <QSettings>
#include <QSet>
#include <algorithm>
#include <functional>
#include <optional>

namespace installerDiagnosticProjection {
constexpr qint64 maximumBytes = 5 * 1024 * 1024;
constexpr int maximumFiles = 20;
constexpr int maximumSeen = 256;

inline bool importFailureTransition(int imported, bool &failed)
{
    const bool warn = imported < 0 && !failed;
    failed = imported < 0;
    return warn;
}

inline std::optional<QJsonObject> project(const QJsonObject &record, const QDateTime &now)
{
    if (record.value("schema") != QJsonValue(1) || !record.value("utc").isString()
            || !record.value("phase").isString()) return std::nullopt;
    const auto time = QDateTime::fromString(record.value("utc").toString(), Qt::ISODateWithMs);
    if (!time.isValid() || time < now.addDays(-14) || time > now.addSecs(3600)) return std::nullopt;
    const QString phase = record.value("phase").toString();
    const QSet<QString> phases {"installer-start", "existing-install-detected", "replacement-consent",
        "installation-started", "installation-finished", "installation-interrupted",
        "service-preflight", "service-preflight-restore", "service-journal-recovery",
        "service-journal-clear", "service-snapshot-root", "service-snapshot-transport",
        "legacy-uninstaller-start", "legacy-uninstaller-exit", "legacy-uninstaller-postcondition",
        "legacy-uninstaller-selection", "legacy-uninstaller-wait", "cleanup-verdict",
        "continuation-next", "continuation-commit"};
    if (!phases.contains(phase)) return std::nullopt;
    const auto detailValue = record.value("detail");
    QString detail;
    if (detailValue.isString()) detail = detailValue.toString();
    else if (detailValue.isDouble() && detailValue.toDouble() == detailValue.toInt(-1))
        detail = QString::number(detailValue.toInt(-1));
    else return std::nullopt;
    if (detail.size() > 512) return std::nullopt;
    QString result, reason;
    int exitCode = -1;
    if (detail == "complete" || detail == "prepared" || detail == "removed") {
        result = "success"; reason = "complete";
    } else if (detail == "failed" || detail == "blocked" || detail == "multiple"
               || detail == "timeout-active" || detail == "present-stopped") {
        result = "failure"; reason = detail;
    } else if (detail == "installer" || detail == "accepted" || detail == "automatic") {
        result = "observed"; reason = detail;
    } else if (phase == "legacy-uninstaller-exit") {
        bool ok = false; exitCode = detail.toInt(&ok);
        if (!ok || exitCode < 0 || exitCode > 65535) return std::nullopt;
        result = exitCode == 0 ? "success" : "failure"; reason = "process-exit";
    } else if (detail == "1" || detail == "0") {
        result = phase == "installation-interrupted" ? "failure"
                : phase == "installation-finished" ? "success" : "observed";
        reason = "lifecycle";
    } else {
        // Extract only known reason names and an optional bounded exit code.
        // Original details may contain PowerShell output, paths or credentials.
        const QRegularExpression failure(QStringLiteral(
            "^(service-journal-persist-failed|service-journal-invalid|service-journal-clear-failed|"
            "service-journal-service-query-failed|service-journal-restore-failed|"
            "service-config-snapshot-unavailable|recovery-disarm-failed|service-disable-failed|"
            "elevated-service-query-failed|service-query-failed|service-deletion-pending|"
            "admin-rights-unavailable)(?:-(unknown|[0-9]{1,5}))?(?:-|$)"));
        const auto match = failure.match(detail);
        if (!match.hasMatch()) return std::nullopt;
        reason = match.captured(1); result = "failure";
        if (!match.captured(2).isEmpty() && match.captured(2) != "unknown") {
            exitCode = match.captured(2).toInt();
            if (exitCode > 65535) return std::nullopt;
        }
    }
    QJsonObject projected {{"schema", 1}, {"source_kind", "updater"},
        {"utc", time.toUTC().toString(Qt::ISODateWithMs)}, {"phase", phase},
        {"result", result}, {"reason", reason}};
    if (exitCode >= 0) projected.insert("exitCode", exitCode);
    for (const QString key : {QStringLiteral("isElevated"), QStringLiteral("isSystem")})
        if (record.value(key).isBool()) projected.insert(key, record.value(key).toBool());
    return projected;
}

inline int importDirectory(const QString &root, QSettings &settings, const QDateTime &now,
                          const std::function<void(const QJsonObject &)> &emitRecord)
{
    const QFileInfo rootInfo(root);
    if (!rootInfo.isDir() || rootInfo.isSymLink()) return 0;
    const auto files = QDir(root).entryInfoList({"installer-*.jsonl"}, QDir::Files, QDir::Time);
    qint64 bytes = 0;
    int count = 0;
    QMap<QByteArray, QJsonObject> records;
    for (const auto &file : files) {
        if (count >= maximumFiles) break;
        if (file.isSymLink() || file.lastModified() < now.addDays(-14)
                || file.size() > 256 * 1024 || file.size() < 0) continue;
        if (bytes + file.size() > maximumBytes) break;
        bytes += file.size(); ++count;
        QFile input(file.filePath());
        if (!input.open(QIODevice::ReadOnly)) continue;
        const auto data = input.read(file.size());
        // Ignore an incomplete final append; consume it only after a newline.
        for (const auto &line : data.left(data.lastIndexOf('\n') + 1).split('\n')) {
            if (line.isEmpty() || line.size() > 4096) continue;
            QJsonParseError error;
            const auto document = QJsonDocument::fromJson(line, &error);
            if (error.error != QJsonParseError::NoError || !document.isObject()) continue;
            auto projected = project(document.object(), now);
            if (projected) {
                const auto canonical = QJsonDocument(*projected).toJson(QJsonDocument::Compact);
                records.insert(canonical, *projected);
            }
        }
    }
    QList<QJsonObject> newest = records.values();
    std::sort(newest.begin(), newest.end(), [](const auto &a, const auto &b) {
        if (a.value("utc") != b.value("utc")) return a.value("utc").toString() < b.value("utc").toString();
        return QJsonDocument(a).toJson(QJsonDocument::Compact) < QJsonDocument(b).toJson(QJsonDocument::Compact);
    });
    while (newest.size() > maximumSeen) newest.removeFirst();
    const QString key = QStringLiteral("Runtime/windowsInstallerDiagnostics/seen");
    QStringList seen = settings.value(key).toStringList();
    if (settings.status() != QSettings::NoError) return -1;
    while (seen.size() > maximumSeen) seen.removeFirst();
    QList<QJsonObject> pending;
    for (const auto &record : newest) {
        const auto canonical = QJsonDocument(record).toJson(QJsonDocument::Compact);
        const QString identity = QString::fromLatin1(QCryptographicHash::hash(canonical, QCryptographicHash::Sha256).toHex());
        if (seen.contains(identity)) continue;
        pending.append(record);
        seen.append(identity);
        while (seen.size() > maximumSeen) seen.removeFirst();
    }
    // Do not replay diagnostics indefinitely if their local dedup state cannot
    // be persisted. Only the projected records reach the callback after sync.
    settings.setValue(key, seen); settings.sync();
    if (settings.status() != QSettings::NoError) return -1;
    for (const auto &record : pending) emitRecord(record);
    return pending.size();
}
} // namespace installerDiagnosticProjection
