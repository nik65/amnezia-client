#ifndef AMNEZIA_HEADLESS_DIAGNOSTIC_EVENT_H
#define AMNEZIA_HEADLESS_DIAGNOSTIC_EVENT_H
#include <QDebug>
#include <QString>
#include <QJsonDocument>
#include <QJsonObject>
namespace amnezia::headless::diagnostics {
// Input codes may originate in a response. Never forward unknown text.
inline QString safeCode(const QString &value)
{
    static const char *const codes[] = {
        "permission_denied", "operation_in_progress", "invalid_parameters",
        "profile_not_found", "invalid_profile", "profile_rejected",
        "remote_log_rejected", "internal_error", "response_too_large",
        "config_permissions_or_size", "config_read_failed", "config_invalid",
        "config_write_failed", "state_read_failed", "state_write_failed",
        "state_quarantine_failed", "bootstrap_failed", "upload_failed",
        "ack_invalid", "receipt_mismatch", "config_target_invalid", "state_invalid",
        "state_field_invalid", "state_permissions_or_size", "source_permissions_or_size", "source_read_failed", "source_seek_failed",
        "source_path_changed_or_unsafe", "source_identity_changed",
        "sanitizer_lookbehind_failed", "cursor_anchor_mismatch",
        "cursor_anchor_failed", "source_epoch_changed_before_confirmation",
        "source_truncated_before_confirmation", "cleanup_failed", "recovery_required"
    };
    for (const char *code : codes)
        if (value == QLatin1String(code)) return QString::fromLatin1(code);
    return QStringLiteral("Other");
}
inline QString safeState(const QString &value)
{
    for (const char *state : {"connected", "disconnected", "connecting", "error",
                              "cleanup_failed", "recovery_required", "disabled", "pending", "healthy"})
        if (value == QLatin1String(state)) return QString::fromLatin1(state);
    return QStringLiteral("unknown");
}
inline void emitEvent(QJsonObject fields, bool warning = false)
{
    fields.insert(QStringLiteral("schema"), 1);
    fields.insert(QStringLiteral("severity"), warning ? "warning" : "info");
    const QString text = QStringLiteral("AmneziaDiagnostics ")
            + QString::fromUtf8(QJsonDocument(fields).toJson(QJsonDocument::Compact));
    if (warning) qWarning().noquote() << text;
    else qInfo().noquote() << text;
}
inline void failure(const char *source, const char *event, const QString &code)
{
    emitEvent({{"source_kind", QString::fromLatin1(source)},
               {"event", QString::fromLatin1(event)}, {"result", "error"},
               {"code", safeCode(code)}}, true);
}
}
#endif
