// Owned user-space filesystem fixtures only. Policy overrides are library-only;
// no production anchor path or root filesystem operation is used by this test.
#include "anchor_storage.hpp"

#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QTemporaryDir>
#include <cassert>
#include <fcntl.h>
#include <iostream>
#include <string>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

using namespace headless_anchor;
namespace {
template<class F> void rejects(F call) {
    bool refused = false;
    try { call(); } catch (const std::exception&) { refused = true; }
    assert(refused);
}
std::string sha(const QByteArray& bytes) {
    return QCryptographicHash::hash(bytes, QCryptographicHash::Sha256).toHex().toStdString();
}
void put(const std::string& path, const QByteArray& bytes, mode_t mode = 0600) {
    QFile file(QString::fromStdString(path));
    assert(file.open(QIODevice::WriteOnly | QIODevice::Truncate));
    assert(file.write(bytes) == bytes.size());
    file.close();
    assert(::chmod(path.c_str(), mode) == 0);
}
QByteArray get(const std::string& path) {
    QFile file(QString::fromStdString(path));
    assert(file.open(QIODevice::ReadOnly));
    return file.readAll();
}
struct stat info(const std::string& path) {
    struct stat st {};
    assert(::lstat(path.c_str(), &st) == 0);
    return st;
}
struct Fixture {
    QTemporaryDir temporary {QDir::currentPath() + "/anchor-fixture-XXXXXX"};
    Policy policy;
    std::string base, source;
    QByteArray first = "#!/bin/sh\n# INERT TEST DATA. Storage must never execute this.\nexit 91\n";
    std::string pin;
    int sharedLock = -1;
    Fixture() {
        assert(temporary.isValid());
        base = temporary.path().toStdString();
        assert(::chmod(base.c_str(), 0700) == 0);
        policy.root = base + "/anchor-namespace/native-anchor";
        policy.transactionRoot = base + "/transactions";
        policy.expectedUid = ::geteuid();
        assert(::mkdir(policy.transactionRoot.c_str(), 0700) == 0);
        assert(::mkdir((policy.transactionRoot + "/updates").c_str(), 0700) == 0);
        policy.lockPath = policy.transactionRoot + "/updates/update.lock";
        put(policy.lockPath, {});
        sharedLock = ::open(policy.lockPath.c_str(), O_RDWR | O_CLOEXEC);
        assert(sharedLock >= 0 && ::flock(sharedLock, LOCK_EX | LOCK_NB) == 0);
        policy.lockFd = sharedLock;
        assert(::mkdir((base + "/source").c_str(), 0700) == 0);
        source = base + "/source/worker";
        put(source, first, 0755);
        pin = sha(first);
    }
    ~Fixture() { if (sharedLock >= 0) ::close(sharedLock); }
    std::string generation(const std::string& digest) const { return policy.root + "/payload-" + digest; }
    std::string currentPath() const { return policy.root + "/CURRENT"; }
    QByteArray current(const std::string& digest) const {
        return QByteArray("headless-journal-v1\n") + QByteArray::fromStdString(digest) + '\n';
    }
    void transactionRoot() const { assert(QFileInfo::exists(QString::fromStdString(policy.transactionRoot))); }
    void noPending() const {
        assert(QDir(QString::fromStdString(policy.root)).entryList(
            {".pending-*", ".CURRENT-*"}, QDir::AllEntries | QDir::Hidden | QDir::NoDotAndDotDot).isEmpty());
    }
    void verify(const std::string& digest, const QByteArray& bytes) const {
        assert(get(currentPath()) == current(digest));
        assert(get(generation(digest) + "/worker") == bytes);
        assert(get(generation(digest) + "/PIN") == QByteArray::fromStdString(digest) + '\n');
        assert((info(policy.root).st_mode & 07777) == 0700);
        assert((info(generation(digest)).st_mode & 07777) == 0700);
        assert((info(generation(digest) + "/worker").st_mode & 07777) == 0700);
        assert((info(generation(digest) + "/PIN").st_mode & 07777) == 0600);
        assert((info(currentPath()).st_mode & 07777) == 0600);
        noPending();
    }
};
}
int main() {
    int count = 0;
    const auto test = [&](auto body) { body(); ++count; };
    // Simulate stale temporary entries left by an earlier PID incarnation.
    // Exclusive retries preserve those bytes instead of deleting foreign state
    // or making an otherwise valid install depend on PID reuse.
    test([] {
        Fixture f;
        assert(::mkdir((f.base + "/anchor-namespace").c_str(), 0700) == 0);
        assert(::mkdir(f.policy.root.c_str(), 0700) == 0);
        const auto prefix = std::to_string(::getpid()) + "-";
        for (int number = 1; number <= 2; ++number) {
            const auto directory = f.policy.root + "/.pending-" + prefix + std::to_string(number);
            assert(::mkdir(directory.c_str(), 0700) == 0);
            put(directory + "/foreign", "preexisting directory; do not remove");
        }
        for (int number = 1; number <= 8; ++number)
            put(f.policy.root + "/.CURRENT-" + prefix + std::to_string(number), "preexisting record; do not remove");
        install(f.policy, f.source, f.pin);
        assert(get(f.currentPath()) == f.current(f.pin));
        assert(get(f.generation(f.pin) + "/worker") == f.first);
        for (int number = 1; number <= 2; ++number)
            assert(get(f.policy.root + "/.pending-" + prefix + std::to_string(number) + "/foreign")
                   == "preexisting directory; do not remove");
        for (int number = 1; number <= 8; ++number)
            assert(get(f.policy.root + "/.CURRENT-" + prefix + std::to_string(number))
                   == "preexisting record; do not remove");
    });
    test([] {
        Fixture f;
        auto missing = f.policy;
        missing.lockFd = -1;
        rejects([&] { install(missing, f.source, f.pin); });
        assert(!QFileInfo::exists(QString::fromStdString(f.policy.root)));
        const auto unrelated = f.base + "/unrelated-lock";
        put(unrelated, {});
        const int different = ::open(unrelated.c_str(), O_RDWR | O_CLOEXEC);
        assert(different >= 0);
        auto mismatch = f.policy;
        mismatch.lockFd = different;
        rejects([&] { install(mismatch, f.source, f.pin); });
        ::close(different);
        assert(!QFileInfo::exists(QString::fromStdString(f.policy.root)));
    });
    test([] {
        Fixture f;
        const int competitor = ::open(f.policy.lockPath.c_str(), O_RDWR | O_CLOEXEC);
        assert(competitor >= 0);
        auto wrongDescription = f.policy;
        wrongDescription.lockFd = competitor;
        rejects([&] { install(wrongDescription, f.source, f.pin); });
        assert(!QFileInfo::exists(QString::fromStdString(f.policy.root)));
        install(f.policy, f.source, f.pin);
        // The storage helper must leave its caller's inherited OFD locked.
        assert(::flock(competitor, LOCK_EX | LOCK_NB) != 0);
        ::close(competitor);
    });
    test([] {
        for (const auto* defect : {"mode", "hardlink", "symlink", "unlinked"}) {
            Fixture f;
            if (std::string(defect) == "mode") assert(::chmod(f.policy.lockPath.c_str(), 0644) == 0);
            if (std::string(defect) == "hardlink")
                assert(::link(f.policy.lockPath.c_str(), (f.base + "/lock-alias").c_str()) == 0);
            if (std::string(defect) == "symlink") {
                const auto original = f.base + "/original-lock";
                assert(::rename(f.policy.lockPath.c_str(), original.c_str()) == 0);
                assert(::symlink(original.c_str(), f.policy.lockPath.c_str()) == 0);
            }
            if (std::string(defect) == "unlinked") assert(::unlink(f.policy.lockPath.c_str()) == 0);
            rejects([&] { install(f.policy, f.source, f.pin); });
            assert(!QFileInfo::exists(QString::fromStdString(f.policy.root)));
        }
    });
    test([] {
        Fixture f;
        install(f.policy, f.source, f.pin);
        f.verify(f.pin, f.first);
        const auto inode = info(f.generation(f.pin) + "/worker").st_ino;
        install(f.policy, f.source, f.pin);
        f.verify(f.pin, f.first);
        assert(info(f.generation(f.pin) + "/worker").st_ino == inode);
    });
    test([] {
        Fixture f;
        install(f.policy, f.source, f.pin);
        const QByteArray next = f.first + "# second generation\n";
        put(f.source, next, 0700);
        const auto nextPin = sha(next);
        install(f.policy, f.source, nextPin);
        f.verify(nextPin, next);
        assert(get(f.generation(f.pin) + "/worker") == f.first);
    });
    test([] {
        for (const auto& digest : {std::string(), std::string(63, 'a'), std::string(64, 'A'), std::string(64, '/')}) {
            Fixture f;
            rejects([&] { install(f.policy, f.source, digest); });
            assert(!QFileInfo::exists(QString::fromStdString(f.policy.root)));
        }
    });
    test([] {
        Fixture f;
        rejects([&] { install(f.policy, f.source, std::string(64, '0')); });
        assert(!QFileInfo::exists(QString::fromStdString(f.currentPath())));
        f.noPending();
    });
    test([] {
        for (const mode_t mode : {0644, 0777, 04755, 02755, 01755}) {
            Fixture f;
            assert(::chmod(f.source.c_str(), mode) == 0);
            rejects([&] { install(f.policy, f.source, f.pin); });
        }
    });
    test([] {
        Fixture f;
        const QByteArray maximum(8 * 1024 * 1024, 'x');
        put(f.source, maximum, 0700);
        install(f.policy, f.source, sha(maximum));
        f.verify(sha(maximum), maximum);
    });
    test([] {
        Fixture f;
        const auto link = f.base + "/source/alias";
        assert(::symlink(f.source.c_str(), link.c_str()) == 0);
        rejects([&] { install(f.policy, link, f.pin); });
        const auto fifo = f.base + "/source/fifo";
        assert(::mkfifo(fifo.c_str(), 0700) == 0);
        rejects([&] { install(f.policy, fifo, f.pin); });
        put(f.source, {}, 0755);
        rejects([&] { install(f.policy, f.source, f.pin); });
        put(f.source, QByteArray(8 * 1024 * 1024 + 1, 'x'), 0755);
        rejects([&] { install(f.policy, f.source, f.pin); });
    });
    test([] {
        Fixture f;
        assert(::symlink((f.base + "/source").c_str(), (f.base + "/alias").c_str()) == 0);
        rejects([&] { install(f.policy, f.base + "/alias/worker", f.pin); });
        auto wrongOwner = f.policy;
        ++wrongOwner.expectedUid;
        rejects([&] { install(wrongOwner, f.source, f.pin); });
    });
    test([] {
        Fixture f;
        assert(::mkdir((f.base + "/anchor-namespace").c_str(), 0700) == 0);
        assert(::chmod((f.base + "/anchor-namespace").c_str(), 0770) == 0);
        rejects([&] { install(f.policy, f.source, f.pin); });
    });
    test([] {
        Fixture f;
        assert(::mkdir((f.base + "/anchor-namespace").c_str(), 0700) == 0);
        assert(::symlink((f.base + "/source").c_str(), f.policy.root.c_str()) == 0);
        rejects([&] { install(f.policy, f.source, f.pin); });
        assert(!QFileInfo::exists(QString::fromStdString(f.base + "/source/CURRENT")));
    });
    test([] {
        for (const auto* name : {".headless-provisioning-journal.json", ".headless-provisioning-recovery-required"}) {
            Fixture f;
            f.transactionRoot();
            const auto path = f.policy.transactionRoot + "/" + name;
            put(path, "active transaction TEST DATA");
            rejects([&] { install(f.policy, f.source, f.pin); });
            assert(::unlink(path.c_str()) == 0);
            assert(::symlink("missing", path.c_str()) == 0);
            rejects([&] { install(f.policy, f.source, f.pin); });
            assert(!QFileInfo::exists(QString::fromStdString(f.policy.root)));
        }
    });
    test([] {
        Fixture f;
        f.transactionRoot();
        install(f.policy, f.source, f.pin);
        const QByteArray next = f.first + "# second generation\n";
        put(f.source, next, 0755);
        const auto nextPin = sha(next);
        rejects([&] { install(f.policy, f.source, nextPin, [&](const char* point) {
            if (std::string(point) == "generation-published")
                put(f.policy.transactionRoot + "/.headless-provisioning-journal.json", "active");
        }); });
        f.verify(f.pin, f.first);
        assert(get(f.generation(nextPin) + "/worker") == next);
        assert(::unlink((f.policy.transactionRoot + "/.headless-provisioning-journal.json").c_str()) == 0);
        install(f.policy, f.source, nextPin);
        f.verify(nextPin, next);
    });
    test([] {
        for (const auto* defect : {"unlink", "replace"}) {
            Fixture f;
            install(f.policy, f.source, f.pin);
            const QByteArray next = f.first + "# second generation\n";
            put(f.source, next, 0755);
            rejects([&] { install(f.policy, f.source, sha(next), [&](const char* point) {
                if (std::string(point) != "generation-published") return;
                if (std::string(defect) == "replace") {
                    assert(::rename(f.policy.lockPath.c_str(), (f.base + "/old-lock").c_str()) == 0);
                    put(f.policy.lockPath, {});
                } else {
                    assert(::unlink(f.policy.lockPath.c_str()) == 0);
                }
            }); });
            // A previously valid inherited lock cannot authorize selection once
            // its fixed pathname no longer identifies that same protected inode.
            f.verify(f.pin, f.first);
            assert(get(f.generation(sha(next)) + "/worker") == next);
        }
    });
    test([] {
        for (const auto* step : {"worker-copy", "worker-fsync", "generation-fsync", "generation-rename",
                                 "generation-published", "current-rename"}) {
            Fixture f;
            install(f.policy, f.source, f.pin);
            const QByteArray next = f.first + "# second generation\n";
            put(f.source, next, 0755);
            rejects([&] { install(f.policy, f.source, sha(next), [&](const char* point) {
                if (std::string(point) == step) throw Error("injected storage failure");
            }); });
            f.verify(f.pin, f.first);
        }
    });
    test([] {
        Fixture f;
        install(f.policy, f.source, f.pin);
        const QByteArray next = f.first + "# second generation\n";
        put(f.source, next, 0755);
        rejects([&] { install(f.policy, f.source, sha(next), [](const char* point) {
            if (std::string(point) == "current-directory-fsync") throw Error("injected durability failure");
        }); });
        // A post-rename fsync failure remains an error. Either complete old/new
        // selection is possible after a crash; no partial record is accepted.
        f.verify(sha(next), next);
        install(f.policy, f.source, sha(next));
    });
    test([] {
        Fixture f;
        install(f.policy, f.source, f.pin);
        const int lock = ::open((f.policy.root + "/.install.lock").c_str(), O_RDWR | O_CLOEXEC);
        assert(lock >= 0 && ::flock(lock, LOCK_EX | LOCK_NB) == 0);
        rejects([&] { install(f.policy, f.source, f.pin); });
        ::close(lock);
        f.verify(f.pin, f.first);
    });
    test([] {
        for (const auto* name : {"worker", "PIN"}) {
            Fixture f;
            install(f.policy, f.source, f.pin);
            put(f.generation(f.pin) + "/" + name, "changed stored bytes", name == std::string("worker") ? 0700 : 0600);
            rejects([&] { install(f.policy, f.source, f.pin); });
            assert(get(f.currentPath()) == f.current(f.pin));
        }
    });
    test([] {
        Fixture f;
        install(f.policy, f.source, f.pin);
        put(f.generation(f.pin) + "/unexpected", "foreign data");
        rejects([&] { install(f.policy, f.source, f.pin); });
    });
    test([] {
        Fixture f;
        install(f.policy, f.source, f.pin);
        put(f.currentPath(), f.current(f.pin) + "extra\n");
        rejects([&] { install(f.policy, f.source, f.pin); });
        assert(::unlink(f.currentPath().c_str()) == 0);
        assert(::symlink("missing", f.currentPath().c_str()) == 0);
        rejects([&] { install(f.policy, f.source, f.pin); });
    });
    test([] {
        Fixture f;
        rejects([&] { install(f.policy, f.source, f.pin, [&](const char* point) {
            if (std::string(point) == "worker-copy") put(f.source, "changed during copy", 0755);
        }); });
        assert(!QFileInfo::exists(QString::fromStdString(f.currentPath())));
        f.noPending();
    });
    std::cout << "anchorOwnedFixtures=" << count
              << " passed=true productionRootOperations=0 workerExecutions=0\n";
}
