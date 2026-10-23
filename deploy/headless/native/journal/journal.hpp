#pragma once
#include <QJsonObject>
#include <QString>
#include <QStringList>
#include <functional>
#include <stdexcept>
#include <sys/types.h>

namespace headless_journal {
struct Error : std::runtime_error { using std::runtime_error::runtime_error; };
// Policy overrides are a library unit-test seam, never accepted by the CLI.
struct Policy { QString root = "/var/lib/amnezia"; uid_t uid = 0; };
struct State {
    QString phase, mode, backupDir, serviceTarget, serviceEnabled, serviceActive;
    bool groupPresent = false, groupCreated = false;
};
// Fault hook runs before a named syscall; throwing simulates failure. Not CLI-exposed.
using Fault = std::function<void(const char*)>;
QJsonObject snapshot(const Policy&, const State&);
State validate(const Policy&, const QJsonObject&);
QJsonObject read(const Policy&);
void validateBackup(const Policy&, const QJsonObject&);
void write(const Policy&, const State&, Fault = {});
QString recoveryLines(const Policy&, const QJsonObject&);
// Fixed production root/uid; no test policy or arbitrary output paths via argv.
int dispatch(const QStringList&);
}
