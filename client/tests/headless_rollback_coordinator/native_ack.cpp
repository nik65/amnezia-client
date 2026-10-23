#include "headlessUpdateManager.h"
#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QTemporaryDir>
#include <QLockFile>
#include <cassert>
#include <iostream>
#include <sys/stat.h>

using namespace amnezia::headless;
namespace {
int checks = 0;
void verify(bool value) { ++checks; if (!value) std::cerr << "failed owned fixture check=" << checks << '\n'; assert(value); }
QString digest(const QByteArray &value) { return QString::fromLatin1(QCryptographicHash::hash(value, QCryptographicHash::Sha256).toHex()); }
void write(const QString &path, const QByteArray &bytes, mode_t mode = 0600) {
    QFile file(path); assert(file.open(QIODevice::WriteOnly)); assert(file.write(bytes) == bytes.size()); file.close(); assert(::chmod(path.toUtf8().constData(), mode) == 0);
}
void json(const QString &path, const QJsonObject &value) { write(path, QJsonDocument(value).toJson(QJsonDocument::Compact)); }
QJsonObject read(const QString &path) { QFile f(path); assert(f.open(QIODevice::ReadOnly)); return QJsonDocument::fromJson(f.readAll()).object(); }
struct Fixture {
    QTemporaryDir temporary;
    QString root = temporary.path();
    QString state = root + "/state.json";
    QString updates = root + "/updates";
    QString rollback = updates + "/rollback-owned";
    QString previous = updates + "/rollback-current-owned";
    QString transaction = updates + "/transaction-owned";
    QString journal = updates + "/transaction.json";
    QJsonObject oldHashes {{ "amneziad", digest("old") }, { "amnezia-cli", digest("old") }};
    QJsonObject newHashes {{ "amneziad", digest("new") }, { "amnezia-cli", digest("new") }};
    QJsonObject sizes {{ "amneziad", 3 }, { "amnezia-cli", 3 }};
    Fixture() {
        assert(temporary.isValid()); assert(QDir().mkpath(rollback)); assert(QDir().mkpath(previous)); assert(QDir().mkpath(transaction));
        for (const auto &name : {"amneziad", "amnezia-cli"}) {
            write(root + "/" + name, "old", 0700); write(rollback + "/" + name, "old", 0700); write(previous + "/" + name, "new", 0700);
        }
        json(state, {{"version", 2}, {"state", "rollback_restart_pending"}, {"lastCheckedAt", ""}, {"lastAppliedVersion", "5.0.3.13"},
            {"rollbackDirectory", rollback}, {"rollbackVersion", "5.0.3.13"}, {"rollbackHashes", oldHashes},
            {"installDirectory", root}, {"updateRoot", updates}, {"lastError", ""}});
        json(journal, {{"version",1}, {"operation","rollback"}, {"phase","rollback_restart_pending"},
            {"candidateVersion","5.0.3.13"}, {"currentVersion","5.0.3.13"}, {"installDirectory",root},
            {"transactionDirectory",transaction}, {"rollbackDirectory",rollback}, {"rollbackHashes",oldHashes},
            {"candidateHashes",oldHashes}, {"candidateSizes",sizes}, {"previousDirectory",previous}, {"previousHashes",newHashes}, {"previousSizes",sizes}});
        json(updates + "/rollback-receipt.json", {{"version",1}, {"rollbackVersion","5.0.3.13"}, {"rollbackDirectory",rollback},
            {"rollbackHashes",oldHashes}, {"installDirectory",root}, {"updateRoot",updates}});
    }
};
}
int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    {
        Fixture f; HeadlessUpdateManager manager({}, f.state, f.root, false);
        const auto result = manager.checkAndApply(Profile {}, "5.0.3.13");
        if (!result.ok) std::cerr << result.code.toStdString() << ":" << result.message.toStdString() << '\n';
        verify(result.ok && result.code == "disabled");
        verify(!QFile::exists(f.journal));
        const auto state = read(f.state); verify(state.value("state").toString() == "disabled");
        verify(state.value("lastAppliedVersion").toString() == "5.0.3.13");
        verify(state.value("rollbackHashes").toObject().isEmpty());
        HeadlessUpdateManager reload({}, f.state, f.root, false);
        verify(!reload.status().value("recoveryRequired").toBool());
        verify(reload.status().value("lastAppliedVersion").toString() == "5.0.3.13");
    }
    {
        Fixture f; HeadlessUpdateManager manager({}, f.state, f.root, false);
        const auto result = manager.checkAndApply(Profile {}, "5.0.3.14");
        verify(!result.ok); verify(QFile::exists(f.journal));
    }
    {
        Fixture f; write(f.root + "/amnezia-cli", "new", 0700);
        HeadlessUpdateManager manager({}, f.state, f.root, false);
        verify(!manager.checkAndApply(Profile {}, "5.0.3.13").ok); verify(QFile::exists(f.journal));
    }
    {
        Fixture f; auto j = read(f.journal); auto sizes = j.value("candidateSizes").toObject(); sizes.insert("amnezia-cli", 4); j.insert("candidateSizes", sizes); json(f.journal,j);
        HeadlessUpdateManager manager({}, f.state, f.root, false);
        // Existing updater authorizes rollback by exact protected hash, then
        // reconstructs actual sizes. The coordinator must separately reject
        // conflicting expected-size evidence before calling this API.
        verify(manager.checkAndApply(Profile {}, "5.0.3.13").ok); verify(!QFile::exists(f.journal));
    }
    {
        Fixture f; QTemporaryDir wrong; HeadlessUpdateManager manager({}, f.state, wrong.path(), false);
        verify(!manager.checkAndApply(Profile {}, "5.0.3.13").ok); verify(QFile::exists(f.journal));
    }
    {
        Fixture f;
        const auto result=HeadlessUpdateManager::acknowledgeStoppedRollback(f.state,f.root,"5.0.3.13",{},false);
        verify(result.ok && result.code=="disabled"); verify(!QFile::exists(f.journal));
    }
    {
        Fixture f;const auto before=read(f.state);
        QLockFile lock(f.updates+"/update.lock");lock.setStaleLockTime(0);assert(lock.tryLock(0));
        const auto result=HeadlessUpdateManager::acknowledgeStoppedRollback(f.state,f.root,"5.0.3.13",{},false);
        verify(!result.ok&&result.code=="update_in_progress");verify(read(f.state)==before);verify(QFile::exists(f.journal));
    }
    {
        Fixture f;const auto result=HeadlessUpdateManager::acknowledgeStoppedRollback(f.state,f.root,"5.0.3.14",{},false);
        verify(!result.ok);verify(QFile::exists(f.journal));
    }
    std::cout << "actual updater ACK owned fixtures checks=" << checks << " production commands=0 network requests=0\n";
}
