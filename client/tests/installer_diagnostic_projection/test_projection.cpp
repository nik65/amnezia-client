#include "installerDiagnosticProjection.h"
#include <QCoreApplication>
#include <QTemporaryDir>
#include <cassert>
using namespace installerDiagnosticProjection;

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    bool failureState = false;
    assert(importFailureTransition(-1, failureState));
    for (int poll = 0; poll < 120; ++poll) assert(!importFailureTransition(-1, failureState));
    assert(!importFailureTransition(0, failureState));
    assert(importFailureTransition(-1, failureState));
    const auto now = QDateTime::fromString("2026-10-12T20:00:00.000Z", Qt::ISODateWithMs);
    QJsonObject input {{"schema", 1}, {"utc", now.toString(Qt::ISODateWithMs)},
        {"phase", "service-preflight"}, {"detail", "service-journal-persist-failed-95-password=SECRET"},
        {"user", "PRIVATE_USER"}, {"sid", "PRIVATE_SID"}, {"profile", QJsonObject{{"token", "SECRET"}}},
        {"isElevated", true}, {"isSystem", "PRIVATE_SID"}};
    const auto projected = project(input, now);
    assert(projected && projected->value("exitCode").toInt() == 95);
    const auto encoded = QJsonDocument(*projected).toJson(QJsonDocument::Compact);
    assert(!encoded.contains("SECRET") && !encoded.contains("PRIVATE") && !encoded.contains("password"));
    assert(projected->value("isElevated").toBool() && !projected->contains("isSystem"));
    for (const auto &invalid : {QJsonValue("1"), QJsonValue(true), QJsonValue(1.5), QJsonValue(2)}) {
        auto changed = input; changed["schema"] = invalid; assert(!project(changed, now));
    }
    for (const auto &field : {QString("phase"), QString("detail"), QString("utc")}) {
        auto changed = input; changed[field] = QJsonObject{{"secret", "SECRET"}};
        assert(!project(changed, now));
    }
    auto changed = input; changed["phase"] = "secret-phase"; assert(!project(changed, now));
    changed = input; changed["detail"] = "unknown-error-SECRET"; assert(!project(changed, now));
    changed = input; changed["detail"] = "service-journal-persist-failed-99999"; assert(!project(changed, now));
    changed = input; changed["utc"] = now.addDays(-15).toString(Qt::ISODateWithMs); assert(!project(changed, now));
    changed = input; changed["utc"] = now.addSecs(3601).toString(Qt::ISODateWithMs); assert(!project(changed, now));

    QTemporaryDir directory; assert(directory.isValid());
    QSettings settings(directory.path()+"/state.ini", QSettings::IniFormat);
    int emitted = 0;
    auto emitRecord = [&](const QJsonObject &record) {
        ++emitted; assert(record.value("source_kind") == "updater");
        assert(!QJsonDocument(record).toJson().contains("SECRET"));
    };
    auto write = [&](const QString &name, const QByteArray &data) {
        QFile file(directory.path()+"/"+name); assert(file.open(QIODevice::WriteOnly));
        assert(file.write(data) == data.size()); file.close();
    };
    const auto raw = QJsonDocument(input).toJson(QJsonDocument::Compact);
    write("installer-a.jsonl", raw); // Incomplete append must not advance dedup.
    assert(importDirectory(directory.path(), settings, now, emitRecord) == 0);
    write("installer-a.jsonl", raw+"\n");
    assert(importDirectory(directory.path(), settings, now, emitRecord) == 1);
    assert(importDirectory(directory.path(), settings, now, emitRecord) == 0);
    QSettings restarted(directory.path()+"/state.ini", QSettings::IniFormat);
    assert(importDirectory(directory.path(), restarted, now, emitRecord) == 0);
    write("installer-a.jsonl", "");
    assert(importDirectory(directory.path(), restarted, now, emitRecord) == 0);
    write("installer-a.jsonl", raw+"\n"); // Truncation/replay must not duplicate.
    assert(importDirectory(directory.path(), restarted, now, emitRecord) == 0);
    write("installer-large.jsonl", QByteArray(256*1024+1, 'x')+raw+"\n");
    write("installer-invalid.jsonl", "{\"schema\":1,\"phase\":\"SECRET\"}\n");
    assert(importDirectory(directory.path(), restarted, now, emitRecord) == 0);

    // More than 256 stable events must not oscillate/replay each poll or restart.
    QByteArray many;
    for (int i=0; i<300; ++i) {
        auto record = input; record["utc"] = now.addSecs(-i).toString(Qt::ISODateWithMs);
        many += QJsonDocument(record).toJson(QJsonDocument::Compact)+"\n";
    }
    write("installer-many.jsonl", many);
    assert(importDirectory(directory.path(), restarted, now, emitRecord) == 255);
    assert(importDirectory(directory.path(), restarted, now, emitRecord) == 0);
    QSettings again(directory.path()+"/state.ini", QSettings::IniFormat);
    assert(importDirectory(directory.path(), again, now, emitRecord) == 0);
    assert(again.value("Runtime/windowsInstallerDiagnostics/seen").toStringList().size() == maximumSeen);
    assert(emitted == 256);

    QTemporaryDir bounded; assert(bounded.isValid());
    QSettings boundedState(bounded.path()+"/state.ini", QSettings::IniFormat);
    int boundedEmitted = 0;
    for (int i=0; i<21; ++i) {
        auto record = input; record["utc"] = now.addSecs(-i).toString(Qt::ISODateWithMs);
        QFile file(bounded.path()+QString("/installer-%1.jsonl").arg(i));
        assert(file.open(QIODevice::WriteOnly));
        file.write(QJsonDocument(record).toJson(QJsonDocument::Compact)+"\n");
        file.setFileTime(now.addSecs(-i), QFileDevice::FileModificationTime); file.close();
    }
    assert(importDirectory(bounded.path(), boundedState, now, [&](const auto &){++boundedEmitted;}) == maximumFiles);
    assert(boundedEmitted == maximumFiles);
    // A directory cannot be a QSettings INI file: no emission on durable-write failure.
    QSettings unwritable(bounded.path(), QSettings::IniFormat);
    int failedEmitted = 0;
    assert(importDirectory(bounded.path(), unwritable, now, [&](const auto &){++failedEmitted;}) == -1);
    assert(failedEmitted == 0);
    return 0;
}
