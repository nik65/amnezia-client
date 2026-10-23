#include "journal.hpp"
#include <QCryptographicHash>
#include <QDir>
#include <QFileInfo>
#include <QDateTime>
#include <QJsonDocument>
#include <QJsonParseError>
#include <QRegularExpression>
#include <QSet>
#include <array>
#include <algorithm>
#include <cerrno>
#include <cmath>
#include <cstdint>
#include <fcntl.h>
#include <limits>
#include <sys/stat.h>
#include <unistd.h>
#include <cstdio>

namespace headless_journal {
namespace {
constexpr const char* journalName = ".headless-provisioning-journal.json";
constexpr const char* baseName = ".headless-provisioning-transactions";
const QStringList names {"amneziad", "amnezia-cli", "amneziad.service", "update-public-key.pem"};
void check(bool v, const char* message) { if (!v) throw Error(message); }
struct Fd {
    int n;
    explicit Fd(int v): n(v) { check(n >= 0, "open refused"); }
    ~Fd() { close(n); }
    Fd(const Fd&) = delete;
};
struct stat info(int fd) { struct stat s{}; check(fstat(fd, &s) == 0, "fstat failed"); return s; }
void directory(int fd, uid_t uid, bool exact = false) {
    auto s = info(fd);
    check(S_ISDIR(s.st_mode) && s.st_uid == uid && !(s.st_mode & 0022)
          && (!exact || (s.st_mode & 07777) == 0700), "unsafe directory");
}
int openRoot(const Policy& p) {
    check(p.root.startsWith('/') && p.root != "/" && QDir::cleanPath(p.root) == p.root
          && !p.root.contains(QChar(0)), "unsafe root");
    int fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    check(fd >= 0, "root open");
    for (const auto& component : p.root.split('/', Qt::SkipEmptyParts)) {
        int next = openat(fd, component.toUtf8().constData(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        close(fd); fd = next;
        check(fd >= 0, "root path symlink or missing");
    }
    try { directory(fd, p.uid); } catch (...) { close(fd); throw; }
    return fd;
}
QString text(const QJsonObject& o, const QString& key) {
    auto v = o.value(key);
    check(v.isString(), "string field required");
    auto s = v.toString();
    check(!s.contains(QChar(0)) && !s.contains('\n') && !s.contains('\r'), "unsafe text field");
    return s;
}
QSet<QString> keys(const QJsonObject& o) {
    const auto k = o.keys(); return QSet<QString>(k.begin(), k.end());
}
qint64 integer(const QJsonObject& o, const QString& k, qint64 max = 9007199254740991LL) {
    const auto v = o.value(k); const double d = v.toDouble(-1);
    check(v.isDouble() && std::isfinite(d) && d >= 0 && d <= double(max) && std::floor(d) == d,
          "integer field required");
    return qint64(d);
}
bool boolean(const QJsonObject& o, const QString& k) { check(o.value(k).isBool(), "boolean required"); return o.value(k).toBool(); }
QString transactionName(const Policy& p, const QString& path) {
    const QString prefix = p.root + "/" + baseName + "/";
    check(path.startsWith(prefix) && QRegularExpression("^transaction\\.[A-Za-z0-9]+$").match(path.mid(prefix.size())).hasMatch(), "unsafe backup path");
    return path.mid(prefix.size());
}
bool exists(int fd, const QByteArray& name, struct stat* out = nullptr) {
    struct stat s{};
    if (fstatat(fd, name.constData(), &s, AT_SYMLINK_NOFOLLOW) != 0) {
        check(errno == ENOENT, "backup stat failed"); return false;
    }
    if (out) *out = s;
    return true;
}
QString hash(int parent, const QByteArray& name, const struct stat& observed) {
    Fd file(openat(parent, name.constData(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
    auto before = info(file.n);
    check(S_ISREG(before.st_mode) && before.st_dev == observed.st_dev && before.st_ino == observed.st_ino,
          "backup replaced before hashing");
    check(before.st_size == observed.st_size && before.st_mode == observed.st_mode
          && before.st_uid == observed.st_uid && before.st_gid == observed.st_gid,
          "backup metadata changed before hashing");
    QCryptographicHash h(QCryptographicHash::Sha256);
    std::array<char, 65536> b{};
    auto remaining = before.st_size;
    while (remaining > 0) {
        auto n = ::read(file.n, b.data(), std::size_t(std::min<off_t>(remaining,b.size())));
        if (n < 0 && errno == EINTR) continue;
        check(n > 0, "backup shortened/read failed");
        h.addData(QByteArrayView(b.data(), n));
        remaining -= n;
    }
    ssize_t extra;
    do { extra = ::read(file.n,b.data(),1); } while (extra < 0 && errno == EINTR);
    check(extra == 0,"backup grew/read failed");
    auto after = info(file.n);
    check(after.st_size == before.st_size && after.st_mtim.tv_sec == before.st_mtim.tv_sec
          && after.st_mtim.tv_nsec == before.st_mtim.tv_nsec && after.st_ctim.tv_sec == before.st_ctim.tv_sec
          && after.st_ctim.tv_nsec == before.st_ctim.tv_nsec, "backup changed during hashing");
    return QString::fromLatin1(h.result().toHex());
}
QJsonObject record(int parent, const QString& name, uid_t uid, bool& found) {
    const auto item = name.toUtf8(); const auto missing = (".missing-" + name).toUtf8();
    struct stat s{}; bool present = exists(parent, item, &s);
    struct stat ms{}; bool absent = exists(parent, missing, &ms);
    check(!(present && absent), "conflicting backup entries");
    found = present || absent; if (!found) return {};
    if (!present) s = ms;
    const bool link = S_ISLNK(s.st_mode);
    check(s.st_uid == uid && (link || !(s.st_mode & 0022)), "unsafe backup ownership/mode");
    check((present && (S_ISREG(s.st_mode) || link)) || (!present && S_ISREG(s.st_mode)), "unsupported backup type");
    QString target;
    if (link) {
        std::array<char, 4097> b{};
        auto n = readlinkat(parent, item.constData(), b.data(), b.size());
        check(n > 0 && n < qint64(b.size()), "invalid backup symlink");
        target = QString::fromUtf8(b.data(), n);
        // Canonicalize relative to our pinned backup-directory descriptor, not
        // a pathname that could have been renamed after open. Only self procfs.
        const auto pinned = QString("/proc/self/fd/%1/%2").arg(parent).arg(name);
        check(name == "amneziad.service" && QFileInfo(pinned).canonicalFilePath() == "/dev/null",
              "unsupported backup symlink");
        struct stat stable{};
        check(fstatat(parent,item.constData(),&stable,AT_SYMLINK_NOFOLLOW)==0
              && stable.st_dev==s.st_dev && stable.st_ino==s.st_ino
              && stable.st_ctim.tv_sec==s.st_ctim.tv_sec && stable.st_ctim.tv_nsec==s.st_ctim.tv_nsec,
              "backup symlink changed during validation");
    }
    check(s.st_size >= 0 && s.st_size <= 9007199254740991LL, "backup too large");
    QJsonObject r {{"present", present}, {"kind", !present ? "missing" : link ? "symlink" : "regular"},
                   {"sha256", link ? QString() : hash(parent, present ? item : missing, s)},
                   {"size", present && !link ? qint64(s.st_size) : 0},
                   {"mode", int(s.st_mode & 07777)}, {"owner", qint64(s.st_uid)}, {"group", qint64(s.st_gid)}};
    if (link) r.insert("target", target);
    return r;
}
QJsonObject backups(const Policy& p, const State& s) {
    Fd root(openRoot(p));
    const bool terminal = s.phase == "committing" || s.phase == "committed";
    if (!exists(root.n,baseName)) { check(terminal,"missing backup base"); return {}; }
    Fd base(openat(root.n, baseName, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)); directory(base.n, p.uid, true);
    auto name = transactionName(p, s.backupDir).toUtf8();
    if (!exists(base.n,name)) { check(terminal,"missing backup directory"); return {}; }
    Fd dir(openat(base.n, name.constData(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)); directory(dir.n, p.uid, true);
    QJsonObject records;
    for (const auto& item : names) { bool found; auto r = record(dir.n, item, p.uid, found); if (found) records.insert(item, r); }
    return records;
}
}

State validate(const Policy& p, const QJsonObject& o) {
    check(keys(o) == QSet<QString>{"schema","phase","mode","backupDir","serviceTarget","serviceEnabled","serviceActive","groupPresent","groupCreated","backupFiles"}, "journal schema keys");
    check(integer(o, "schema", 1) == 1, "journal schema");
    State s {text(o,"phase"), text(o,"mode"), text(o,"backupDir"), text(o,"serviceTarget"), text(o,"serviceEnabled"), text(o,"serviceActive"), boolean(o,"groupPresent"), boolean(o,"groupCreated")};
    check(QStringList{"starting","prepared","stopping","stopped","replacing","installed","verified","committing","committed"}.contains(s.phase), "journal phase");
    check(s.mode == "fresh" || s.mode == "upgrade", "journal mode");
    transactionName(p, s.backupDir);
    check(QStringList{"/etc/systemd/system/amneziad.service","/run/systemd/system/amneziad.service","/usr/local/lib/systemd/system/amneziad.service","/usr/lib/systemd/system/amneziad.service","/lib/systemd/system/amneziad.service"}.contains(s.serviceTarget), "journal service path");
    check(QStringList{"enabled","disabled","static","indirect","linked","linked-runtime","generated","transient","masked","not-found"}.contains(s.serviceEnabled), "enabled state");
    check(QStringList{"active","inactive","failed","not-found"}.contains(s.serviceActive), "active state");
    check(o.value("backupFiles").isObject(), "backup records type");
    auto records = o.value("backupFiles").toObject();
    for (auto i = records.begin(); i != records.end(); ++i) {
        check(names.contains(i.key()) && i.value().isObject(), "unknown backup record");
        auto r = i.value().toObject();
        auto k = text(r,"kind"); bool present = boolean(r,"present");
        QSet<QString> expected {"present","kind","sha256","size","mode","owner","group"};
        if (k == "symlink") expected.insert("target");
        check(keys(r) == expected, "backup record keys");
        check((present && (k == "regular" || k == "symlink")) || (!present && k == "missing"), "backup presence/kind");
        auto sha = text(r,"sha256");
        check(k == "symlink" ? sha.isEmpty() : QRegularExpression("^[0-9a-f]{64}$").match(sha).hasMatch(), "backup digest");
        if (k == "symlink") check(i.key() == "amneziad.service" && !text(r,"target").isEmpty(), "backup symlink target");
        const auto size = integer(r,"size"); check(k == "regular" || size == 0, "backup size");
        integer(r,"mode",07777); check(integer(r,"owner",UINT32_MAX) == p.uid, "backup owner"); integer(r,"group",UINT32_MAX);
    }
    if (s.phase != "starting" && s.phase != "committing" && s.phase != "committed")
        check(keys(records) == QSet<QString>(names.begin(), names.end()), "incomplete rollback backup");
    return s;
}
QJsonObject snapshot(const Policy& p, const State& s) {
    QJsonObject o {{"schema",1},{"phase",s.phase},{"mode",s.mode},{"backupDir",s.backupDir},{"serviceTarget",s.serviceTarget},
                   {"serviceEnabled",s.serviceEnabled},{"serviceActive",s.serviceActive},{"groupPresent",s.groupPresent},
                   {"groupCreated",s.groupCreated},{"backupFiles",QJsonObject{}}};
    auto envelope = o; envelope.insert("phase", "starting"); validate(p,envelope);
    o.insert("backupFiles",backups(p,s));
    validate(p,o);
    return o;
}
QJsonObject read(const Policy& p) {
    Fd root(openRoot(p));
    Fd fd(openat(root.n, journalName, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK));
    auto st = info(fd.n);
    check(S_ISREG(st.st_mode) && st.st_uid == p.uid && (st.st_mode & 07777) == 0600
          && st.st_nlink == 1 && st.st_size > 0 && st.st_size <= 65536, "unsafe journal file");
    QByteArray bytes; std::array<char,4096> b{};
    for (;;) {
        auto n = ::read(fd.n,b.data(),b.size());
        if (n < 0 && errno == EINTR) continue;
        check(n >= 0, "journal read"); if (!n) break;
        bytes.append(b.data(),n); check(bytes.size() <= 65536,"journal size");
    }
    auto after = info(fd.n);
    check(st.st_size == after.st_size && st.st_mtim.tv_sec == after.st_mtim.tv_sec
          && st.st_mtim.tv_nsec == after.st_mtim.tv_nsec && st.st_ctim.tv_sec == after.st_ctim.tv_sec
          && st.st_ctim.tv_nsec == after.st_ctim.tv_nsec, "journal changed while reading");
    QJsonParseError error;
    auto document = QJsonDocument::fromJson(bytes,&error);
    check(error.error == QJsonParseError::NoError && document.isObject(),"invalid journal JSON");
    auto object = document.object(); validate(p,object); return object;
}
void validateBackup(const Policy& p, const QJsonObject& o) {
    auto s = validate(p,o);
    auto expected = o.value("backupFiles").toObject();
    check(keys(expected) == QSet<QString>(names.begin(),names.end()),"incomplete backup metadata");
    auto actual = backups(p,s);
    check(actual == expected,"backup content/identity changed");
}
void write(const Policy& p, const State& s, Fault fault) {
    auto o = snapshot(p,s);
    auto bytes = QJsonDocument(o).toJson(QJsonDocument::Compact) + '\n';
    check(bytes.size() <= 65536,"journal too large");
    Fd root(openRoot(p));
    struct stat existing{};
    if (exists(root.n,journalName,&existing))
        check(S_ISREG(existing.st_mode) && existing.st_uid == p.uid && (existing.st_mode & 07777) == 0600
              && existing.st_nlink == 1,"unsafe existing journal");
    QByteArray temporary;
    int raw = -1;
    for (int attempt = 0; attempt < 32 && raw < 0; ++attempt) {
        temporary = QByteArray(".headless-journal.") + QByteArray::number(getpid()) + '.'
                    + QByteArray::number(quint64(QDateTime::currentMSecsSinceEpoch())) + '.' + QByteArray::number(attempt);
        raw = openat(root.n,temporary.constData(),O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,0600);
        if (raw < 0) check(errno == EEXIST,"journal temporary create");
    }
    Fd file(raw);
    auto step = [&](const char* name) { if (fault) fault(name); };
    try {
        check(fchmod(file.n,0600) == 0,"journal temporary permissions");
        std::size_t used = 0;
        while (used < std::size_t(bytes.size())) {
            step("write");
            auto n = ::write(file.n,bytes.constData()+used,std::size_t(bytes.size())-used);
            if (n < 0 && errno == EINTR) continue;
            check(n > 0,"journal write"); used += std::size_t(n);
        }
        step("file-fsync"); check(fsync(file.n) == 0,"journal file fsync");
        step("rename"); check(renameat(root.n,temporary.constData(),root.n,journalName) == 0,"journal replace");
        temporary.clear();
        step("directory-fsync"); check(fsync(root.n) == 0,"journal directory fsync");
    } catch (...) {
        if (!temporary.isEmpty()) unlinkat(root.n,temporary.constData(),0);
        throw;
    }
}
QString recoveryLines(const Policy& p,const QJsonObject& o) {
    auto s = validate(p,o);
    return s.phase+'\n'+s.mode+'\n'+s.backupDir+'\n'+s.serviceTarget+'\n'+s.serviceEnabled+'\n'
            +s.serviceActive+'\n'+(s.groupPresent ? "true\n" : "false\n")+(s.groupCreated ? "true\n" : "false\n");
}
int dispatch(const QStringList& args) {
    check(geteuid() == 0 && !args.isEmpty(),"root and explicit journal command required");
    Policy p;
    const auto command = args.at(0);
    if (command == "journal-write" && args.size() == 9) {
        check((args.at(7)=="true" || args.at(7)=="false") && (args.at(8)=="true" || args.at(8)=="false"),"strict boolean arguments");
        State s{args.at(1),args.at(2),args.at(3),args.at(4),args.at(5),args.at(6),args.at(7)=="true",args.at(8)=="true"};
        write(p,s);
    } else if (command == "journal-recovery-read" && args.size() == 1) {
        auto o = read(p); auto s = validate(p,o);
        if (s.phase != "starting" && s.phase != "committing" && s.phase != "committed") validateBackup(p,o);
        auto out = recoveryLines(p,o).toUtf8();
        check(fwrite(out.constData(),1,out.size(),stdout)==std::size_t(out.size()),"journal output failed");
    } else if (command == "journal-validate-backup" && args.size() == 1) {
        validateBackup(p,read(p));
    } else throw Error("invalid journal command/arguments");
    return 0;
}
}
