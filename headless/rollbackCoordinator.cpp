#include "rollbackCoordinator.h"
#include "headlessUpdateManager.h"
#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDateTime>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonParseError>
#include <QLocalSocket>
#include <QLockFile>
#include <QProcess>
#include <QProcessEnvironment>
#include <QRegularExpression>
#include <QSet>
#include <QVector>
#include <QVersionNumber>
#include <QTextStream>
#include <QThread>
#include <QUuid>
#include <fcntl.h>
#include <dirent.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <functional>

namespace amnezia::headless
{
    namespace
    {
        constexpr qint64 MaxFile = 64 * 1024 * 1024;
        constexpr qint64 MaxJson = 4 * 1024 * 1024;
        constexpr qint64 MaxProfiles = 16 * 1024 * 1024;
        constexpr qint64 MaxJournal = 48 * 1024 * 1024;
        const QString UnitName = QStringLiteral("amnezia-rollback-coordinator.service");
        struct Error : std::runtime_error
        {
            using std::runtime_error::runtime_error;
        };
        void require(bool v, const char *m)
        {
            if (!v)
                throw Error(m);
        }
        QString digest(const QByteArray &b)
        {
            return QString::fromLatin1(QCryptographicHash::hash(b, QCryptographicHash::Sha256).toHex());
        }
        struct Fd
        {
            int n;
            explicit Fd(int v) : n(v)
            {
                require(n >= 0, "protected file open failed");
            }
            ~Fd()
            {
                if (n >= 0)
                    ::close(n);
            }
            Fd(const Fd &) = delete;
            Fd(Fd &&other) noexcept : n(other.n)
            {
                other.n = -1;
            }
        };
        struct Read
        {
            QByteArray bytes;
            struct stat identity
            {
            };
        };
        bool same(const struct stat &a, const struct stat &b)
        {
            return a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_size == b.st_size
                    && a.st_mtim.tv_sec == b.st_mtim.tv_sec && a.st_mtim.tv_nsec == b.st_mtim.tv_nsec;
        }
        Fd parentFd(const QString &path, uid_t owner)
        {
            const QByteArray parent = QFile::encodeName(QFileInfo(path).absolutePath());
            Fd fd(::open(parent.constData(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
            struct stat s
            {
            };
            require(::fstat(fd.n, &s) == 0 && S_ISDIR(s.st_mode) && s.st_uid == owner && !(s.st_mode & 0022),
                    "unsafe protected parent");
            return fd;
        }
        Read readProtected(const QString &path, uid_t owner, qint64 limit = MaxJson)
        {
            auto parent = parentFd(path, owner);
            const QByteArray name = QFile::encodeName(QFileInfo(path).fileName());
            Fd fd(::openat(parent.n, name.constData(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
            Read r;
            require(::fstat(fd.n, &r.identity) == 0 && S_ISREG(r.identity.st_mode) && r.identity.st_uid == owner
                            && r.identity.st_nlink == 1 && !(r.identity.st_mode & 0022) && r.identity.st_size >= 0
                            && r.identity.st_size <= limit,
                    "unsafe protected file");
            QByteArray bytes;
            char data[65536];
            while (true) {
                ssize_t n = ::read(fd.n, data, sizeof(data));
                if (n < 0 && errno == EINTR)
                    continue;
                require(n >= 0, "protected read failed");
                if (!n)
                    break;
                bytes.append(data, static_cast<int>(n));
                require(bytes.size() <= limit, "protected file exceeds bound");
            }
            struct stat after
            {
            }, named {};
            require(::fstat(fd.n, &after) == 0 && ::fstatat(parent.n, name.constData(), &named, AT_SYMLINK_NOFOLLOW) == 0
                            && same(r.identity, after) && same(after, named),
                    "protected file changed during read");
            r.bytes = bytes;
            return r;
        }
        QJsonObject object(const QByteArray &b)
        {
            QJsonParseError e;
            auto d = QJsonDocument::fromJson(b, &e);
            require(e.error == QJsonParseError::NoError && d.isObject(), "protected JSON object invalid");
            return d.object();
        }
        QByteArray json(const QJsonObject &o)
        {
            return QJsonDocument(o).toJson(QJsonDocument::Compact);
        }
        void noUncertainCommit(const QString &directory, uid_t owner)
        {
            auto parent = parentFd(QDir(directory).filePath(".inspection"), owner);
            const int copy = ::dup(parent.n);
            require(copy >= 0, "coordinator conflict inspection failed");
            DIR *entries = ::fdopendir(copy);
            if (!entries) {
                ::close(copy);
                throw Error("coordinator conflict inspection failed");
            }
            bool conflict = false;
            errno = 0;
            while (const auto entry = ::readdir(entries)) {
                if (QByteArray(entry->d_name).startsWith(".coordinator-")) {
                    conflict = true;
                    break;
                }
            }
            const bool readFailed = errno != 0;
            ::closedir(entries);
            require(!readFailed && !conflict, "coordinator uncertain commit requires explicit private recovery");
        }
        void ensureRoot(const RollbackCoordinatorPaths &p)
        {
            require(::geteuid() == p.owner, "coordinator requires its trusted root owner");
            const auto parent = parentFd(p.root, p.owner);
            const auto name = QFile::encodeName(QFileInfo(p.root).fileName());
            if (::mkdirat(parent.n, name.constData(), 0700) < 0)
                require(errno == EEXIST, "coordinator root creation failed");
            Fd root(::openat(parent.n, name.constData(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
            struct stat st
            {
            };
            require(::fstat(root.n, &st) == 0 && st.st_uid == p.owner && (st.st_mode & 07777) == 0700,
                    "coordinator root not private");
            require(::fsync(parent.n) == 0, "coordinator root directory sync failed");
            noUncertainCommit(p.root, p.owner);
            noUncertainCommit(QFileInfo(p.profiles).absolutePath(), p.owner);
        }
        // Atomic replacement preserves displaced bytes. Cooperating product writers
        // hold the shared profile lock; an uncoordinated root edit is a visible conflict.
        void replace(const QString &path, const QByteArray &bytes, uid_t owner, const QByteArray *expected = nullptr,
                     mode_t mode = 0600)
        {
            auto parent = parentFd(path, owner);
            const auto name = QFile::encodeName(QFileInfo(path).fileName());
            const auto temp = QFile::encodeName(
                    QStringLiteral(".coordinator-%1").arg(QUuid::createUuid().toString(QUuid::WithoutBraces)));
            Fd fd(::openat(parent.n, temp.constData(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600));
            qsizetype used = 0;
            while (used < bytes.size()) {
                const auto n = ::write(fd.n, bytes.constData() + used, static_cast<size_t>(bytes.size() - used));
                if (n < 0 && errno == EINTR)
                    continue;
                require(n > 0, "coordinator write failed");
                used += n;
            }
            require(::fchmod(fd.n, mode) == 0 && ::fsync(fd.n) == 0, "coordinator file sync failed");
            if (expected) {
                const auto before = readProtected(path, owner, MaxFile);
                require(before.bytes == *expected, "coordinator policy conflict before commit");
                require(::syscall(SYS_renameat2, parent.n, temp.constData(), parent.n, name.constData(), 2) == 0,
                        "coordinator atomic exchange failed");
                require(::fsync(parent.n) == 0, "coordinator exchange directory sync failed");
                const auto displaced = readProtected(
                        QDir(QFileInfo(path).absolutePath()).filePath(QString::fromLocal8Bit(temp)), owner, MaxFile);
                require(displaced.bytes == *expected && same(displaced.identity, before.identity),
                        "coordinator policy conflict; displaced bytes preserved");
                require(::unlinkat(parent.n, temp.constData(), 0) == 0, "coordinator displaced file retirement failed");
            } else
                require(::syscall(SYS_renameat2, parent.n, temp.constData(), parent.n, name.constData(), 1) == 0,
                        "coordinator destination already exists");
            require(::fsync(parent.n) == 0, "coordinator directory sync failed");
        }
        QString recordPath(const RollbackCoordinatorPaths &p)
        {
            return QDir(p.root).filePath(QStringLiteral("coordinator.json"));
        }
        QString retainedPath(const RollbackCoordinatorPaths &p)
        {
            return QDir(p.root).filePath(QStringLiteral("amnezia-cli"));
        }
        QString timestamp()
        {
            return QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs);
        }
        QJsonObject load(const RollbackCoordinatorPaths &p)
        {
            auto r = object(readProtected(recordPath(p), p.owner, MaxJournal).bytes);
            require(r.value("schema").toInt() == 1 && r.value("authority").toString() == "retained14Coordinator"
                            && !r.value("operationId").toString().isEmpty(),
                    "coordinator record invalid");
            return r;
        }
        void save(const RollbackCoordinatorPaths &p, QJsonObject &r, const QString &phase)
        {
            const auto old = readProtected(recordPath(p), p.owner, MaxJournal).bytes;
            require(object(old).value("operationId") == r.value("operationId"), "coordinator operation changed");
            r.insert("phase", phase);
            r.insert("updatedAt", timestamp());
            replace(recordPath(p), json(r), p.owner, &old);
        }
        QString unitText(const RollbackCoordinatorPaths &p)
        {
            return QStringLiteral(
                           "[Unit]\nDescription=Amnezia rollback-with-pause recovery\nAfter=amneziad.service\n\n[Service]\nType=oneshot\nUser=root\nUMask=0077\nExecStart=%1 --rollback-coordinator run\nTimeoutStartSec=120\nNoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\nReadWritePaths=%2 %3\n\n[Install]\nWantedBy=multi-user.target\n")
                    .arg(retainedPath(p), QFileInfo(p.state).absolutePath(), p.install);
        }
        QString ownHash()
        {
            QFile f(QStringLiteral("/proc/self/exe"));
            require(f.open(QIODevice::ReadOnly) && f.size() <= MaxFile, "coordinator self executable unreadable");
            return digest(f.readAll());
        }
        void verifyRetained(const RollbackCoordinatorPaths &p, const QJsonObject &r, bool self)
        {
            require(digest(readProtected(retainedPath(p), p.owner, MaxFile).bytes) == r.value("retainedSha256").toString(),
                    "coordinator executable changed");
            require(readProtected(p.unit, p.owner).bytes == unitText(p).toUtf8(), "coordinator unit changed");
            if (self && p.verifySelfExecutable)
                require(ownHash() == r.value("retainedSha256").toString()
                                && QFileInfo(QStringLiteral("/proc/self/exe")).canonicalFilePath() == retainedPath(p),
                        "executing coordinator is not retained executable");
        }
        QJsonObject pair(const RollbackCoordinatorPaths &p, const QString &directory)
        {
            QJsonObject o;
            for (const auto &name : { QStringLiteral("amneziad"), QStringLiteral("amnezia-cli") }) {
                auto b = readProtected(QDir(directory).filePath(name), p.owner, MaxFile);
                o.insert(name, QJsonObject { { "sha256", digest(b.bytes) }, { "size", b.bytes.size() } });
            }
            return o;
        }
        void targetPair(const RollbackCoordinatorPaths &p, const QJsonObject &r)
        {
            require(pair(p, p.install) == r.value("targetPair").toObject(),
                    "installed pair differs from rollback target");
        }
        void pausedPolicy(const RollbackCoordinatorPaths &p, const QJsonObject &r)
        {
            require(digest(readProtected(p.profiles, p.owner, MaxProfiles).bytes)
                            == r.value("pausedProfilesSha256").toString(),
                    "paused profile policy changed");
        }
        void pendingEvidence(const RollbackCoordinatorPaths &p, const QJsonObject &r)
        {
            const auto state = object(readProtected(p.state, p.owner).bytes);
            const auto journal = object(
                    readProtected(QDir(QFileInfo(p.state).absolutePath()).filePath("updates/transaction.json"), p.owner)
                            .bytes);
            require(state.value("state") == "rollback_restart_pending"
                            && state.value("lastAppliedVersion") == r.value("targetVersion")
                            && journal.value("phase") == "rollback_restart_pending"
                            && journal.value("operation") == "rollback"
                            && journal.value("candidateVersion") == r.value("targetVersion")
                            && journal.value("currentVersion") == r.value("targetVersion")
                            && QFileInfo(journal.value("installDirectory").toString()).canonicalFilePath()
                                    == QFileInfo(p.install).canonicalFilePath(),
                    "actual rollback pending evidence missing");
            const auto hashes = journal.value("candidateHashes").toObject();
            const auto sizes = journal.value("candidateSizes").toObject();
            const auto target = r.value("targetPair").toObject();
            require(hashes.size() == 2 && sizes.size() == 2, "pending journal target file set invalid");
            for (const auto &name : target.keys()) {
                const auto file = target.value(name).toObject();
                require(hashes.value(name) == file.value("sha256") && sizes.value(name).isDouble()
                                && sizes.value(name).toInteger(-1) == file.value("size").toInteger(-2),
                        "pending journal target hash or size differs");
            }
        }
        // Qt validates JSON. This bounded token-span walk changes only the top-level
        // autoUpdate booleans of actual profile array members, preserving all raw bytes.
        struct Token
        {
            qsizetype begin, end;
            QByteArray text;
        };
        QByteArray pauseJson(const QByteArray &raw, QJsonArray &ids)
        {
            const auto doc = object(raw);
            require(doc.value("version").toInt() == 1 && doc.value("profiles").isArray(), "profile store schema invalid");
            QVector<Token> tokens;
            for (qsizetype i = 0; i < raw.size();) {
                const char c = raw[i];
                if (c == ' ' || c == '\n' || c == '\t' || c == '\r') {
                    ++i;
                    continue;
                }
                const auto b = i;
                if (c == '"') {
                    ++i;
                    while (i < raw.size()) {
                        if (raw[i] == '\\') {
                            i += 2;
                            continue;
                        }
                        if (raw[i++] == '"')
                            break;
                    }
                } else if (QByteArray("{}[]:,").contains(c))
                    ++i;
                else
                    while (i < raw.size() && !QByteArray(" \t\r\n{}[]:,").contains(raw[i]))
                        ++i;
                require(i <= raw.size(), "profile JSON token invalid");
                tokens.append({ b, i, raw.mid(b, i - b) });
            }
            QVector<Token> edits;
            qsizetype at = 0;
            int profileIndex = -1;
            std::function<void(bool, bool, int)> walk = [&](bool root, bool profile, int depth) {
                require(depth < 64 && at < tokens.size(), "profile JSON nesting invalid");
                auto t = tokens[at++].text;
                if (t == "{") {
                    QSet<QString> keys;
                    while (at < tokens.size() && tokens[at].text != "}") {
                        const auto keyToken = tokens[at++].text;
                        const auto keyDoc = QJsonDocument::fromJson("[" + keyToken + "]");
                        require(keyDoc.isArray() && keyDoc.array().size() == 1 && keyDoc.array()[0].isString(),
                                "profile JSON key invalid");
                        const auto key = keyDoc.array()[0].toString();
                        require(!keys.contains(key), "duplicate profile JSON key");
                        keys.insert(key);
                        require(at < tokens.size() && tokens[at++].text == ":", "profile JSON colon invalid");
                        if (profile && key == "autoUpdate") {
                            require(tokens[at].text == "true" || tokens[at].text == "false",
                                    "profile autoUpdate type invalid");
                            if (tokens[at].text == "true") {
                                edits.append(tokens[at]);
                                const auto profiles = doc.value("profiles").toArray();
                                require(profileIndex >= 0 && profileIndex < profiles.size(),
                                        "profile token identity invalid");
                                ids.append(profiles[profileIndex].toObject().value("id"));
                            }
                        }
                        if (root && key == "profiles") {
                            require(tokens[at++].text == "[", "profile array invalid");
                            while (tokens[at].text != "]") {
                                ++profileIndex;
                                require(tokens[at].text == "{", "profile object invalid");
                                walk(false, true, depth + 1);
                                if (tokens[at].text == ",")
                                    ++at;
                                else
                                    break;
                            }
                            require(tokens[at++].text == "]", "profile array end invalid");
                        } else
                            walk(false, false, depth + 1);
                        if (tokens[at].text == ",")
                            ++at;
                        else
                            break;
                    }
                    require(tokens[at++].text == "}", "profile object end invalid");
                } else if (t == "[") {
                    while (tokens[at].text != "]") {
                        walk(false, false, depth + 1);
                        if (tokens[at].text == ",")
                            ++at;
                        else
                            break;
                    }
                    require(tokens[at++].text == "]", "profile array end invalid");
                }
            };
            walk(true, false, 0);
            require(at == tokens.size(), "profile trailing JSON invalid");
            QByteArray result = raw;
            for (auto it = edits.crbegin(); it != edits.crend(); ++it)
                result.replace(it->begin, it->end - it->begin, "false");
            return result;
        }
        QByteArray command(const QString &program, const QStringList &args, int timeout = 10000)
        {
            QProcess p;
            QProcessEnvironment env;
            env.insert("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
            env.insert("LC_ALL", "C");
            p.setProcessEnvironment(env);
            p.start(program, args);
            require(p.waitForStarted(2000), "coordinator process start failed");
            QElapsedTimer clock;
            clock.start();
            QByteArray out, err;
            while (p.state() != QProcess::NotRunning) {
                p.waitForFinished(50);
                out += p.readAllStandardOutput();
                err += p.readAllStandardError();
                if (clock.elapsed() > timeout || out.size() + err.size() > 1024 * 1024) {
                    p.kill();
                    p.waitForFinished(2000);
                    throw Error("coordinator process bound exceeded");
                }
            }
            out += p.readAllStandardOutput();
            err += p.readAllStandardError();
            require(out.size() + err.size() <= 1024 * 1024 && p.exitStatus() == QProcess::NormalExit && p.exitCode() == 0,
                    "coordinator process failed");
            return out;
        }
        class RealPlatform final : public RollbackCoordinatorPlatform
        {
        public:
            QJsonObject observe(const RollbackCoordinatorPaths &p, QString *error) override
            {
                try {
                    const auto info =
                            command("/usr/bin/systemctl",
                                    { "show", "--property=MainPID,ActiveState,LoadState,FragmentPath,DropInPaths",
                                      "amneziad.service" },
                                    2000);
                    QMap<QByteArray, QByteArray> fields;
                    for (const auto &line : info.split('\n')) {
                        auto n = line.indexOf('=');
                        if (n > 0)
                            fields.insert(line.left(n), line.mid(n + 1));
                    }
                    bool ok = false;
                    const auto pid = fields.value("MainPID").toLongLong(&ok);
                    require(ok && pid > 1 && fields.value("ActiveState") == "active"
                                    && fields.value("LoadState") == "loaded" && fields.value("DropInPaths").isEmpty(),
                            "service not exact active managed unit");
                    const auto fragment = QString::fromUtf8(fields.value("FragmentPath"));
                    require(QStringList { "/etc/systemd/system/amneziad.service", "/run/systemd/system/amneziad.service",
                                          "/usr/local/lib/systemd/system/amneziad.service",
                                          "/usr/lib/systemd/system/amneziad.service",
                                          "/lib/systemd/system/amneziad.service" }
                                    .contains(fragment),
                            "service unit path invalid");
                    readProtected(fragment, p.owner);
                    const auto proc = QStringLiteral("/proc/%1").arg(pid);
                    auto statRead = [&]() {
                        QFile f(proc + "/stat");
                        require(f.open(QIODevice::ReadOnly), "service process stat unavailable");
                        auto bytes = f.read(16385);
                        require(bytes.size() <= 16384, "service process stat bound exceeded");
                        return bytes;
                    };
                    const auto before = statRead();
                    const auto tail = before.mid(before.lastIndexOf(')') + 2).split(' ');
                    require(tail.size() > 19, "service process stat invalid");
                    QFile status(proc + "/status");
                    require(status.open(QIODevice::ReadOnly), "service UID proof unavailable");
                    const auto statusBytes = status.read(65537);
                    require(statusBytes.size() <= 65536, "service status bound exceeded");
                    const auto uidMatch =
                            QRegularExpression("(?:^|\\n)Uid:\\s+([0-9]+)\\s+([0-9]+)\\s+([0-9]+)\\s+([0-9]+)(?:\\n|$)")
                                    .match(QString::fromUtf8(statusBytes));
                    require(uidMatch.hasMatch(), "service UID proof invalid");
                    for (int i = 1; i <= 4; ++i)
                        require(uidMatch.captured(i).toULongLong() == p.owner,
                                "service process is not root in every UID slot");
                    auto socketParent = parentFd(p.socket, p.owner);
                    struct stat socketIdentity
                    {
                    };
                    const auto socketName = QFile::encodeName(QFileInfo(p.socket).fileName());
                    require(::fstatat(socketParent.n, socketName.constData(), &socketIdentity, AT_SYMLINK_NOFOLLOW) == 0
                                    && S_ISSOCK(socketIdentity.st_mode) && socketIdentity.st_uid == p.owner
                                    && (socketIdentity.st_mode & 0777) == 0660,
                            "service socket identity invalid");
                    QLocalSocket peer;
                    peer.connectToServer(p.socket);
                    require(peer.waitForConnected(1000), "service peer connection failed");
                    struct ucred credentials
                    {
                    };
                    socklen_t credentialSize = sizeof(credentials);
                    require(::getsockopt(static_cast<int>(peer.socketDescriptor()), SOL_SOCKET, SO_PEERCRED,
                                         &credentials, &credentialSize)
                                            == 0
                                    && credentialSize == sizeof(credentials) && credentials.pid == pid
                                    && credentials.uid == p.owner,
                            "service socket peer differs from main PID");
                    peer.abort();
                    require(QFileInfo(proc + "/exe").canonicalFilePath() == QDir(p.install).filePath("amneziad"),
                            "service executable path invalid");
                    QFile exe(proc + "/exe");
                    require(exe.open(QIODevice::ReadOnly) && exe.size() <= MaxFile, "service executable unreadable");
                    const auto exeHash = digest(exe.readAll());
                    const auto installed = pair(p, p.install);
                    require(exeHash == installed.value("amneziad").toObject().value("sha256").toString(),
                            "running and installed daemon differ");
                    const auto versionOutput =
                            QString::fromUtf8(command(QDir(p.install).filePath("amnezia-cli"), { "--version" }, 2000))
                                    .trimmed();
                    const auto match =
                            QRegularExpression("(?:^|\\s)([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+)$").match(versionOutput);
                    require(match.hasMatch(), "installed CLI version invalid");
                    const auto doctor = object(command(QDir(p.install).filePath("amnezia-cli"),
                                                       { "--socket", p.socket, "--json", "doctor" }, 3000));
                    const auto after = statRead();
                    require(after.mid(after.lastIndexOf(')') + 2).split(' ').value(19) == tail[19],
                            "service process changed during observation");
                    require(pair(p, p.install) == installed, "installed pair changed during observation");
                    return { { "daemon_pid", pid },
                             { "start_ticks", QString::fromLatin1(tail[19]) },
                             { "pair", installed },
                             { "version", match.captured(1) },
                             { "doctor", doctor } };
                } catch (const std::exception &e) {
                    if (error)
                        *error = QString::fromUtf8(e.what());
                    return {};
                }
            }
            bool stop(QString *e) override
            {
                return action({ "stop", "amneziad.service" }, e) && stopped(e);
            }
            bool start(QString *e) override
            {
                return action({ "start", "amneziad.service" }, e);
            }
            bool stopped(QString *e) override
            {
                try {
                    bool ok = false;
                    const auto n = command("/usr/bin/systemctl",
                                           { "show", "--property=MainPID", "--value", "amneziad.service" }, 2000)
                                           .trimmed()
                                           .toLongLong(&ok);
                    require(ok && n == 0, "service still has a main PID");
                    return true;
                } catch (const std::exception &x) {
                    if (e)
                        *e = QString::fromUtf8(x.what());
                    return false;
                }
            }
            bool installUnit(QString *e) override
            {
                return action({ "daemon-reload" }, e) && action({ "enable", UnitName }, e);
            }
            bool startWorker(QString *e) override
            {
                return action({ "start", "--no-block", UnitName }, e);
            }
            bool retireUnit(QString *e) override
            {
                return action({ "disable", UnitName }, e);
            }
            bool stopObserved(const RollbackCoordinatorPaths &p, const QJsonObject &o, QString *e) override
            {
                const auto current = observe(p, e);
                if (current.isEmpty() || current.value("daemon_pid") != o.value("daemon_pid")
                    || current.value("start_ticks") != o.value("start_ticks")
                    || current.value("pair") != o.value("pair")) {
                    if (e)
                        *e = "service identity changed before stop";
                    return false;
                }
                if (!stop(e))
                    return false;
                return observedProcessGone(o, e);
            }
            bool observedProcessGone(const QJsonObject &o, QString *e) override
            {
                QFile f(QStringLiteral("/proc/%1/stat").arg(o.value("daemon_pid").toInteger()));
                if (!f.exists())
                    return true;
                if (!f.open(QIODevice::ReadOnly)) {
                    if (e)
                        *e = "old process death proof unavailable";
                    return false;
                }
                const auto bytes = f.read(16385);
                const auto ticks = bytes.mid(bytes.lastIndexOf(')') + 2).split(' ').value(19);
                if (bytes.size() <= 16384 && QString::fromLatin1(ticks) != o.value("start_ticks").toString())
                    return true;
                if (e)
                    *e = "old observed service process remains alive";
                return false;
            }
            bool acknowledge(const RollbackCoordinatorPaths &p, const QString &v, QString *e) override
            {
                try {
                    const auto r = HeadlessUpdateManager::acknowledgeStoppedRollback(p.state, p.install, v, {}, true);
                    require(r.ok && r.code == "disabled", "coordinator updater acknowledgement failed");
                    return true;
                } catch (const std::exception &x) {
                    if (e)
                        *e = QString::fromUtf8(x.what());
                    return false;
                }
            }

        private:
            bool action(const QStringList &a, QString *e)
            {
                try {
                    command("/usr/bin/systemctl", a, 20000);
                    return true;
                } catch (const std::exception &x) {
                    if (e)
                        *e = QString::fromUtf8(x.what());
                    return false;
                }
            }
        };
        void healthy(const QJsonObject &o, const QJsonObject &r, bool final)
        {
            require(!o.isEmpty() && o.value("daemon_pid").toDouble() > 1 && !o.value("start_ticks").toString().isEmpty()
                            && o.value("pair") == r.value("targetPair") && o.value("version") == r.value("targetVersion"),
                    "observed service is not rollback target");
            const auto d = o.value("doctor").toObject();
            const auto result = d.value("result").toObject();
            const auto updates = result.value("updates").toObject();
            require(d.value("ok").toBool() && result.value("ready").toBool()
                            && !updates.value("recoveryRequired").toBool(true) && updates.value("lastError").isString()
                            && updates.value("lastError").toString().isEmpty()
                            && updates.value("lastAppliedVersion") == r.value("targetVersion")
                            && updates.value("state").toString() == (final ? "disabled" : "rollback_restart_pending"),
                    "rollback target doctor is not healthy expected phase");
        }
        RollbackCoordinatorResult success(const QString &code, const QJsonObject &r)
        {
            // Public RPC/stdout never exposes private profiles, doctor payloads or paths.
            QJsonObject summary;
            for (const auto &key :
                 { "schema", "authority", "operationId", "phase", "createdAt", "updatedAt", "targetVersion",
                   "retainedSha256", "originalProfilesSha256", "pausedProfilesSha256", "acknowledgementAuthority" })
                if (r.contains(key))
                    summary.insert(key, r.value(key));
            summary.insert("pausedProfileCount", r.value("pausedProfileCount").toInt());
            return { true, code, {}, summary };
        }
    }

    bool RollbackCoordinatorPlatform::stopObserved(const RollbackCoordinatorPaths &p, const QJsonObject &o, QString *error)
    {
        const auto current = observe(p, error);
        if (current.isEmpty() || current.value("daemon_pid") != o.value("daemon_pid")
            || current.value("start_ticks") != o.value("start_ticks") || current.value("pair") != o.value("pair")) {
            if (error)
                *error = "service identity changed before stop";
            return false;
        }
        return stop(error) && stopped(error);
    }
    bool RollbackCoordinatorPlatform::observedProcessGone(const QJsonObject &, QString *error)
    {
        return stopped(error);
    }

    void RollbackCoordinatorPlatform::waitForObservationRetry()
    {
        QThread::msleep(250);
    }
    qint64 RollbackCoordinatorPlatform::monotonicMilliseconds()
    {
        struct timespec now
        {
        };
        require(::clock_gettime(CLOCK_MONOTONIC, &now) == 0, "coordinator monotonic clock failed");
        return static_cast<qint64>(now.tv_sec) * 1000 + now.tv_nsec / 1000000;
    }
    RollbackCoordinator::RollbackCoordinator(RollbackCoordinatorPaths paths,
                                             std::shared_ptr<RollbackCoordinatorPlatform> platform)
        : m_paths(std::move(paths)), m_platform(platform ? std::move(platform) : std::make_shared<RealPlatform>())
    {
    }
    QString RollbackCoordinator::profileWriterLockPath(const QString &p)
    {
        return p + QStringLiteral(".lock");
    }
    RollbackCoordinatorResult RollbackCoordinator::failure(const QString &c, const QString &m) const
    {
        return { false, c, m, {} };
    }

    RollbackCoordinatorResult RollbackCoordinator::prepare()
    {
        try {
            ensureRoot(m_paths);
            QLockFile lock(QDir(m_paths.root).filePath("operation.lock"));
            lock.setStaleLockTime(0);
            require(lock.tryLock(0), "coordinator operation in progress");
            if (QFileInfo::exists(recordPath(m_paths))) {
                auto r = load(m_paths);
                verifyRetained(m_paths, r, false);
                require(QStringList { "prepared", "pause_prepared", "profiles_paused" }.contains(
                                r.value("phase").toString()),
                        "coordinator operation already active");
                QString error;
                require(m_platform->installUnit(&error), "coordinator unit installation failed");
                return success(r.value("phase").toString(), r);
            }
            const auto state = object(readProtected(m_paths.state, m_paths.owner).bytes);
            const auto targetVersion = state.value("rollbackVersion").toString();
            require(QRegularExpression("^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$").match(targetVersion).hasMatch(),
                    "rollback version missing");
            const auto backup = QFileInfo(state.value("rollbackDirectory").toString()).canonicalFilePath();
            const auto updates = QDir(QFileInfo(m_paths.state).absolutePath()).filePath("updates");
            require(backup.startsWith(QFileInfo(updates).canonicalFilePath() + "/rollback-") && !backup.isEmpty(),
                    "rollback directory outside update root");
            const auto target = pair(m_paths, backup);
            const auto hashes = state.value("rollbackHashes").toObject();
            require(hashes.size() == 2, "rollback authority file set invalid");
            for (const auto &name : target.keys())
                require(target.value(name).toObject().value("sha256") == hashes.value(name),
                        "rollback backup hash mismatch");
            const auto source = readProtected(QDir(m_paths.install).filePath("amnezia-cli"), m_paths.owner, MaxFile);
            if (m_paths.verifySelfExecutable)
                require(ownHash() == digest(source.bytes), "prepare caller is not installed CLI");
            const auto original = pair(m_paths, m_paths.install);
            QString observeError;
            const auto observed = m_platform->observe(m_paths, &observeError);
            require(observed.value("pair").toObject() == original && observed.value("daemon_pid").toDouble() > 1
                            && !observed.value("start_ticks").toString().isEmpty(),
                    "original service identity unavailable");
            const auto originalVersion = observed.value("version").toString();
            require(!QVersionNumber::fromString(originalVersion).isNull()
                            && QVersionNumber::fromString(targetVersion) < QVersionNumber::fromString(originalVersion),
                    "rollback is not an older installed version");
            if (QFileInfo::exists(retainedPath(m_paths)))
                require(readProtected(retainedPath(m_paths), m_paths.owner, MaxFile).bytes == source.bytes,
                        "partial retained copy differs");
            else
                replace(retainedPath(m_paths), source.bytes, m_paths.owner, nullptr, 0500);
            const auto unit = unitText(m_paths).toUtf8();
            if (QFileInfo::exists(m_paths.unit))
                require(readProtected(m_paths.unit, m_paths.owner).bytes == unit, "existing coordinator unit differs");
            else
                replace(m_paths.unit, unit, m_paths.owner, nullptr, 0644);
            QJsonObject r { { "schema", 1 },
                            { "authority", "retained14Coordinator" },
                            { "operationId", QUuid::createUuid().toString(QUuid::WithoutBraces) },
                            { "phase", "prepared" },
                            { "createdAt", timestamp() },
                            { "retainedSha256", digest(source.bytes) },
                            { "targetVersion", targetVersion },
                            { "targetPair", target },
                            { "originalVersion", originalVersion },
                            { "originalService", observed },
                            { "originalPair", original } };
            replace(recordPath(m_paths), json(r), m_paths.owner);
            QString error;
            require(m_platform->installUnit(&error), "coordinator unit installation failed");
            return success("prepared", r);
        } catch (const std::exception &e) {
            return failure("coordinator_prepare_failed", QString::fromUtf8(e.what()));
        }
    }

    RollbackCoordinatorResult RollbackCoordinator::admitRollback()
    {
        try {
            ensureRoot(m_paths);
            QLockFile op(QDir(m_paths.root).filePath("operation.lock"));
            op.setStaleLockTime(0);
            require(op.tryLock(0), "coordinator operation in progress");
            auto r = load(m_paths);
            verifyRetained(m_paths, r, false);
            if (r.value("phase") == "profiles_paused") {
                pausedPolicy(m_paths, r);
                return success("profiles_paused", r);
            }
            require(QStringList { "prepared", "pause_prepared" }.contains(r.value("phase").toString()),
                    "coordinator not prepared");
            require(pair(m_paths, m_paths.install) == r.value("originalPair").toObject(),
                    "original managed pair changed");
            QLockFile profiles(profileWriterLockPath(m_paths.profiles));
            profiles.setStaleLockTime(0);
            require(profiles.tryLock(0), "profile store writer active");
            const auto original = readProtected(m_paths.profiles, m_paths.owner, MaxProfiles).bytes;
            QJsonArray ids;
            const auto paused = pauseJson(original, ids);
            require(paused.size() <= MaxProfiles, "paused profile store exceeds supported bound");
            if (r.value("phase") == "pause_prepared") {
                const auto savedOriginal =
                        QByteArray::fromBase64(r.value("originalProfilesBase64").toString().toLatin1());
                require(digest(savedOriginal) == r.value("originalProfilesSha256").toString(),
                        "saved original profile policy invalid");
                QJsonArray savedIds;
                const auto savedPaused = pauseJson(savedOriginal, savedIds);
                require(digest(savedPaused) == r.value("pausedProfilesSha256").toString(), "saved paused policy invalid");
                if (original == savedOriginal)
                    replace(m_paths.profiles, savedPaused, m_paths.owner, &original);
                else
                    require(original == savedPaused, "profile changed during interrupted pause");
                save(m_paths, r, "profiles_paused");
                return success("profiles_paused", r);
            }
            r.insert("originalProfilesBase64", QString::fromLatin1(original.toBase64()));
            r.insert("originalProfilesSha256", digest(original));
            r.insert("pausedProfilesSha256", digest(paused));
            r.insert("pausedProfileCount", ids.size());
            save(m_paths, r, "pause_prepared");
            replace(m_paths.profiles, paused, m_paths.owner, &original);
            save(m_paths, r, "profiles_paused");
            return success("profiles_paused", r);
        } catch (const std::exception &e) {
            return failure("coordinator_pause_failed", QString::fromUtf8(e.what()));
        }
    }

    RollbackCoordinatorResult RollbackCoordinator::rollbackRequested()
    {
        try {
            ensureRoot(m_paths);
            QLockFile op(QDir(m_paths.root).filePath("operation.lock"));
            op.setStaleLockTime(0);
            require(op.tryLock(0), "coordinator operation in progress");
            auto r = load(m_paths);
            verifyRetained(m_paths, r, false);
            pausedPolicy(m_paths, r);
            require(QStringList { "profiles_paused", "rollback_requested" }.contains(r.value("phase").toString()),
                    "coordinator not paused for rollback");
            pendingEvidence(m_paths, r);
            targetPair(m_paths, r);
            r.insert("pendingUpdaterJournalSha256",
                     digest(readProtected(
                                    QDir(QFileInfo(m_paths.state).absolutePath()).filePath("updates/transaction.json"),
                                    m_paths.owner)
                                    .bytes));
            save(m_paths, r, "rollback_requested");
            QString error;
            require(m_platform->startWorker(&error), "coordinator worker scheduling failed");
            return success("rollback_restart_pending", r);
        } catch (const std::exception &e) {
            return failure("coordinator_request_failed", QString::fromUtf8(e.what()));
        }
    }

    RollbackCoordinatorResult RollbackCoordinator::run()
    {
        try {
            ensureRoot(m_paths);
            QLockFile op(QDir(m_paths.root).filePath("operation.lock"));
            op.setStaleLockTime(0);
            require(op.tryLock(0), "coordinator operation in progress");
            auto r = load(m_paths);
            verifyRetained(m_paths, r, true);
            const auto phase = r.value("phase").toString();
            if (phase == "prepared" || phase == "resumed")
                return success(phase, r);
            if (phase == "resume_requested") {
                op.unlock();
                return resume();
            }
            if (phase == "pause_prepared") {
                op.unlock();
                return admitRollback();
            }
            pausedPolicy(m_paths, r);
            QString error;
            if (phase == "held") {
                healthy(m_platform->observe(m_paths, &error), r, true);
                return success("held", r);
            }
            require(QStringList { "profiles_paused", "rollback_requested", "old13_observed", "old13_stopped",
                                  "coordinator_commit_pending" }
                            .contains(phase),
                    "coordinator phase requires explicit recovery");
            auto state = object(readProtected(m_paths.state, m_paths.owner).bytes);
            if (phase == "profiles_paused" && state.value("state") != "rollback_restart_pending") {
                require(pair(m_paths, m_paths.install) == r.value("originalPair").toObject(),
                        "pause-only operation no longer has original managed pair");
                return success("profiles_paused", r); // retry official rollback or explicit resume
            }
            targetPair(m_paths, r);
            if (state.value("state") == "rollback_restart_pending") {
                pendingEvidence(m_paths, r);
                auto observed = r.value("observed13").toObject();
                if (!observed.isEmpty() && m_platform->stopped(&error)) {
                    healthy(observed, r, false);
                    require(m_platform->observedProcessGone(observed, &error),
                            "previous observed service is not proved gone");
                } else {
                    if (m_platform->stopped(&error))
                        require(m_platform->start(&error), "pending rollback service did not start");
                    // The manager schedules restart asynchronously. The oneshot may
                    // run while old14 is still active; observe only, never stop it.
                    const auto readinessStart = m_platform->monotonicMilliseconds();
                    bool ready = false;
                    while (m_platform->monotonicMilliseconds() - readinessStart < 15000) {
                        targetPair(m_paths, r);
                        pausedPolicy(m_paths, r);
                        pendingEvidence(m_paths, r);
                        observed = m_platform->observe(m_paths, &error);
                        try {
                            healthy(observed, r, false);
                            ready = true;
                        } catch (const Error &) { /* no authority is granted by a failed observation */
                        }
                        if (ready)
                            break;
                        if (m_platform->monotonicMilliseconds() - readinessStart < 15000)
                            m_platform->waitForObservationRetry();
                    }
                    require(ready, "rollback target readiness observation deadline exceeded");
                    r.insert("observed13", observed);
                    save(m_paths, r, "old13_observed");
                    require(m_platform->stopObserved(m_paths, observed, &error),
                            "verified rollback service did not stop");
                }
                require(m_platform->stopped(&error), "rollback service not stopped before commit");
                r.insert("stopEvidence",
                         QJsonObject { { "verifiedStopped", true },
                                       { "observedProcessGone", true },
                                       { "observedIdentity", observed },
                                       { "observedAt", timestamp() } });
                save(m_paths, r, "old13_stopped");
                targetPair(m_paths, r);
                pausedPolicy(m_paths, r);
                const auto pendingState = readProtected(m_paths.state, m_paths.owner).bytes;
                const auto pendingJournal =
                        readProtected(QDir(QFileInfo(m_paths.state).absolutePath()).filePath("updates/transaction.json"),
                                      m_paths.owner)
                                .bytes;
                r.insert("pendingEvidence",
                         QJsonObject { { "stateBytesBase64", QString::fromLatin1(pendingState.toBase64()) },
                                       { "stateSha256", digest(pendingState) },
                                       { "journalBytesBase64", QString::fromLatin1(pendingJournal.toBase64()) },
                                       { "journalSha256", digest(pendingJournal) },
                                       { "capturedAt", timestamp() } });
                save(m_paths, r, "coordinator_commit_pending");
                require(m_platform->acknowledge(m_paths, r.value("targetVersion").toString(), &error),
                        "coordinator rollback acknowledgement failed");
                const auto ackState = readProtected(m_paths.state, m_paths.owner).bytes;
                r.insert("coordinatorAcknowledgement",
                         QJsonObject { { "authority", "retained14Coordinator" },
                                       { "result", "disabled" },
                                       { "returnedSuccessfully", true },
                                       { "completedAt", timestamp() },
                                       { "postStateSha256", digest(ackState) } });
                save(m_paths, r, "coordinator_commit_pending");
            } else {
                require(state.value("state") == "disabled"
                                && state.value("lastAppliedVersion") == r.value("targetVersion")
                                && (phase == "coordinator_commit_pending" || phase == "old13_stopped"),
                        "updater state does not match coordinator commit");
                if (!r.contains("coordinatorAcknowledgement")) {
                    r.insert("coordinatorAcknowledgement",
                             QJsonObject { { "authority", "retained14Coordinator" },
                                           { "result", "recovered_disabled_poststate" },
                                           { "returnedSuccessfully", false },
                                           { "observedAt", timestamp() },
                                           { "postStateSha256",
                                             digest(readProtected(m_paths.state, m_paths.owner).bytes) } });
                    save(m_paths, r, "coordinator_commit_pending");
                }
            }
            state = object(readProtected(m_paths.state, m_paths.owner).bytes);
            require(state.value("state") == "disabled" && state.value("lastAppliedVersion") == r.value("targetVersion")
                            && state.value("lastError").toString().isEmpty(),
                    "coordinator commit state invalid");
            const auto journal = QDir(QFileInfo(m_paths.state).absolutePath()).filePath("updates/transaction.json");
            require(!QFileInfo::exists(journal) && !QFileInfo(journal).isSymLink(), "updater journal not retired");
            require(m_platform->start(&error), "acknowledged rollback service start failed");
            const auto final = m_platform->observe(m_paths, &error);
            healthy(final, r, true);
            const auto before = r.value("observed13").toObject();
            require(final.value("daemon_pid") != before.value("daemon_pid")
                            || final.value("start_ticks") != before.value("start_ticks"),
                    "rollback daemon did not reload coordinator commit");
            pausedPolicy(m_paths, r);
            r.insert("final13", final);
            r.insert("acknowledgementAuthority", "retained14Coordinator");
            save(m_paths, r, "held");
            return success("held", r);
        } catch (const std::exception &e) {
            return failure("coordinator_run_failed", QString::fromUtf8(e.what()));
        }
    }

    RollbackCoordinatorResult RollbackCoordinator::resume()
    {
        try {
            ensureRoot(m_paths);
            QLockFile op(QDir(m_paths.root).filePath("operation.lock"));
            op.setStaleLockTime(0);
            require(op.tryLock(0), "coordinator operation in progress");
            auto r = load(m_paths);
            verifyRetained(m_paths, r, true);
            const auto phase = r.value("phase").toString();
            require(QStringList { "held", "profiles_paused", "resume_requested", "resumed" }.contains(phase),
                    "coordinator not held for resume");
            const auto original = QByteArray::fromBase64(r.value("originalProfilesBase64").toString().toLatin1());
            require(digest(original) == r.value("originalProfilesSha256").toString(),
                    "coordinator original policy invalid");
            QString error;
            const bool abortOriginal = pair(m_paths, m_paths.install) == r.value("originalPair").toObject();
            if (!abortOriginal)
                targetPair(m_paths, r);
            const auto state = object(readProtected(m_paths.state, m_paths.owner).bytes);
            require(state.value("state") != "rollback_restart_pending" && state.value("lastError").isString()
                            && state.value("lastError").toString().isEmpty(),
                    "pending or unhealthy updater cannot resume");
            require(!QFileInfo::exists(QDir(QFileInfo(m_paths.state).absolutePath()).filePath("updates/transaction.json")),
                    "updater transaction still active during resume");
            QLockFile profiles(profileWriterLockPath(m_paths.profiles));
            profiles.setStaleLockTime(0);
            require(profiles.tryLock(0), "profile writer active during resume");
            const auto old = readProtected(m_paths.profiles, m_paths.owner, MaxProfiles).bytes;
            require(old == original || digest(old) == r.value("pausedProfilesSha256").toString(),
                    "profile policy changed before resume");
            if (phase == "resumed") {
                require(old == original, "completed resume policy changed");
                require(m_platform->retireUnit(&error), "coordinator unit retirement failed");
                return success("resumed", r);
            }
            if (!m_platform->stopped(&error)) {
                const auto observed = m_platform->observe(m_paths, &error);
                require(observed.value("pair").toObject() == pair(m_paths, m_paths.install),
                        "resume service pair changed");
                if (!abortOriginal)
                    healthy(observed, r, true);
                else
                    require(observed.value("version") == r.value("originalVersion")
                                    && observed.value("doctor").toObject().value("ok").toBool()
                                    && observed.value("doctor").toObject().value("result").toObject().value("ready").toBool(),
                            "original service is not healthy for aborted rollback resume");
                r.insert("resumeStoppedService", observed);
                save(m_paths, r, "resume_requested");
                require(m_platform->stopObserved(m_paths, observed, &error), "service did not stop for resume");
            } else {
                const auto observed = r.value("resumeStoppedService").toObject();
                require(phase == "resume_requested" && !observed.isEmpty()
                                && m_platform->observedProcessGone(observed, &error),
                        "resume stopped identity not proved");
            }
            require(m_platform->stopped(&error), "resume service not stopped");
            require(pair(m_paths, m_paths.install)
                            == (abortOriginal ? r.value("originalPair").toObject() : r.value("targetPair").toObject()),
                    "managed binaries changed while resuming");
            if (old != original)
                replace(m_paths.profiles, original, m_paths.owner, &old);
            require(m_platform->start(&error), "resumed service failed to start");
            const auto final = m_platform->observe(m_paths, &error);
            require(final.value("pair").toObject() == pair(m_paths, m_paths.install)
                            && final.value("version") == r.value(abortOriginal ? "originalVersion" : "targetVersion")
                            && final.value("doctor").toObject().value("ok").toBool()
                            && final.value("doctor").toObject().value("result").toObject().value("ready").toBool(),
                    "resumed service health or identity not confirmed");
            require(digest(readProtected(m_paths.profiles, m_paths.owner, MaxProfiles).bytes) == digest(original),
                    "resumed profile policy changed");
            r.insert("resumeObservedService", final);
            save(m_paths, r, "resumed");
            require(m_platform->retireUnit(&error), "coordinator unit retirement failed");
            return success("resumed", r);
        } catch (const std::exception &e) {
            return failure("coordinator_resume_failed", QString::fromUtf8(e.what()));
        }
    }

    RollbackCoordinatorResult RollbackCoordinator::status(bool self)
    {
        try {
            ensureRoot(m_paths);
            auto r = load(m_paths);
            verifyRetained(m_paths, r, self);
            if (QStringList { "profiles_paused", "rollback_requested", "old13_observed", "old13_stopped",
                              "coordinator_commit_pending", "held" }
                        .contains(r.value("phase").toString()))
                pausedPolicy(m_paths, r);
            return success(r.value("phase").toString(), r);
        } catch (const std::exception &e) {
            return failure("coordinator_status_failed", QString::fromUtf8(e.what()));
        }
    }
    int RollbackCoordinator::dispatch(const QStringList &a)
    {
        if (a.size() != 1 || !QStringList { "run", "resume", "status" }.contains(a[0])) {
            QTextStream(stderr) << "rollback coordinator requires run, resume or status" << Qt::endl;
            return 2;
        }
        RollbackCoordinator c;
        auto r = a[0] == "run" ? c.run() : (a[0] == "resume" ? c.resume() : c.status(true));
        QTextStream(r.ok ? stdout : stderr) << QJsonDocument(QJsonObject { { "ok", r.ok },
                                                                           { "code", r.code },
                                                                           { "message", r.message },
                                                                           { "coordinator", r.evidence } })
                                                       .toJson(QJsonDocument::Compact)
                                            << Qt::endl;
        return r.ok ? 0 : 1;
    }
}
