#include "linuxsystemdpeer.h"
#include "linuxsystemdbustransport.h"
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QLocalSocket>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <cstring>
#include <memory>

namespace amnezia::ipc::linuxSystemd {
namespace {
constexpr auto unitName = "AmneziaVPN.service";
constexpr auto unitPath = "/org/freedesktop/systemd1/unit/AmneziaVPN_2eservice";
constexpr auto executable = "/opt/AmneziaVPN/bin/AmneziaVPN-service";
constexpr auto fragment = "/etc/systemd/system/AmneziaVPN.service";
constexpr auto busPath = "/run/dbus/system_bus_socket";
constexpr auto expectedUnit = "[Unit]\nDescription=AmneziaVPN Service\nAfter=network.target\nStartLimitIntervalSec=0\n\n[Service]\nType=simple\nRestart=always\nRestartSec=1\nExecStart=/opt/AmneziaVPN/bin/AmneziaVPN-service\n\n[Install]\nWantedBy=multi-user.target\n";
struct Fd {
    int value = -1;
    ~Fd() { if (value >= 0) close(value); }
};
struct MessageDeleter { void operator()(sd_bus_message *m) const { sd_bus_message_unref(m); } };
using Message = std::unique_ptr<sd_bus_message, MessageDeleter>;

bool protectedParents(const QString &path)
{
    QDir directory = QFileInfo(path).absoluteDir();
    while (true) {
        struct stat info {};
        if (lstat(QFile::encodeName(directory.absolutePath()).constData(), &info) != 0
            || !S_ISDIR(info.st_mode) || info.st_uid != 0 || (info.st_mode & 0022)) return false;
        const auto previous = directory.absolutePath();
        if (!directory.cdUp() || directory.absolutePath() == previous) return true;
    }
}

bool protectedFile(const QString &path, QByteArray *contents = nullptr)
{
    if (!protectedParents(path)) return false;
    Fd fd {open(QFile::encodeName(path).constData(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)};
    struct stat before {}, after {}, named {};
    if (fd.value < 0 || fstat(fd.value, &before) != 0 || !S_ISREG(before.st_mode)
        || before.st_uid != 0 || (before.st_mode & 0022) || before.st_nlink != 1) return false;
    if (contents) {
        if (before.st_size < 0 || before.st_size > 4096) return false;
        contents->resize(qsizetype(before.st_size));
        if (read(fd.value, contents->data(), size_t(contents->size())) != contents->size()) return false;
    }
    return fstat(fd.value, &after) == 0 && lstat(QFile::encodeName(path).constData(), &named) == 0
        && before.st_dev == after.st_dev && before.st_ino == after.st_ino
        && before.st_size == after.st_size && before.st_mtim.tv_sec == after.st_mtim.tv_sec
        && before.st_mtim.tv_nsec == after.st_mtim.tv_nsec && before.st_mode == after.st_mode
        && before.st_uid == after.st_uid && before.st_nlink == after.st_nlink
        && named.st_dev == before.st_dev && named.st_ino == before.st_ino;
}

bool alive(int pidfd)
{
    pollfd value {pidfd, POLLIN, 0};
    return poll(&value, 1, 0) == 0;
}

bool credentials(QLocalSocket *socket, ucred &result)
{
    socklen_t size = sizeof(result);
    return socket && socket->socketDescriptor() >= 0
        && getsockopt(int(socket->socketDescriptor()), SOL_SOCKET, SO_PEERCRED, &result, &size) == 0
        && size == sizeof(result) && result.pid > 0 && result.uid == 0 && result.gid == 0;
}

int connectBus(uint64_t deadline)
{
    struct stat before {}, after {};
    if (!protectedParents(QString::fromLatin1(busPath)) || lstat(busPath, &before) != 0
        || !S_ISSOCK(before.st_mode) || before.st_uid != 0) return -1;
    Fd socket {::socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0)};
    if (socket.value < 0) return -1;
    sockaddr_un address {};
    address.sun_family = AF_UNIX;
    std::strcpy(address.sun_path, busPath);
    if (::connect(socket.value, reinterpret_cast<sockaddr *>(&address), sizeof(address)) != 0) {
        if (errno != EINPROGRESS && errno != EAGAIN) return -1;
        const auto now = monotonicUsec();
        if (!now || now >= deadline) return -1;
        pollfd wait {socket.value, POLLOUT, 0};
        if (poll(&wait, 1, int((deadline-now+999)/1000)) <= 0) return -1;
        int error = 0; socklen_t size = sizeof(error);
        if (getsockopt(socket.value, SOL_SOCKET, SO_ERROR, &error, &size) != 0 || error != 0) return -1;
    }
    if (lstat(busPath, &after) != 0 || before.st_dev != after.st_dev || before.st_ino != after.st_ino
        || before.st_uid != after.st_uid || before.st_mode != after.st_mode) return -1;
    const int result = socket.value;
    socket.value = -1;
    return result;
}

Message call(AsyncBus &bus, const QByteArray &destination, const char *path,
             const char *interface, const char *method, const char *argument)
{
    sd_bus_message *raw = nullptr;
    if (sd_bus_message_new_method_call(bus.get(), &raw, destination.constData(), path, interface, method) < 0) return {};
    Message request(raw);
    if (argument && sd_bus_message_append(raw, "s", argument) < 0) return {};
    Message response(bus.request(raw));
    const char *sender = response ? sd_bus_message_get_sender(response.get()) : nullptr;
    if (!sender || destination != sender) return {};
    return response;
}

bool text(sd_bus_message *message, QString &value, char type = 's')
{
    const char *raw = nullptr;
    if (sd_bus_message_read_basic(message, type, &raw) <= 0 || !raw || strnlen(raw, 4097) > 4096) return false;
    value = QString::fromUtf8(raw);
    return true;
}

QByteArray managerOwner(AsyncBus &bus)
{
    auto reply = call(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus",
                      "org.freedesktop.DBus", "GetNameOwner", "org.freedesktop.systemd1");
    QString owner;
    if (!reply || !text(reply.get(), owner) || !owner.startsWith(':') || owner.size() > 128) return {};
    return owner.toUtf8();
}

bool managerIdentity(AsyncBus &bus, const QByteArray &owner)
{
    for (const auto &pair : {std::pair{"GetConnectionUnixUser", uint32_t(0)},
                            std::pair{"GetConnectionUnixProcessID", uint32_t(1)}}) {
        auto response = call(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus",
                             "org.freedesktop.DBus", pair.first, owner.constData());
        uint32_t value = UINT32_MAX;
        if (!response || sd_bus_message_read(response.get(), "u", &value) <= 0 || value != pair.second) return false;
    }
    return true;
}

bool stringArray(sd_bus_message *message, QStringList &values)
{
    if (sd_bus_message_enter_container(message, 'a', "s") <= 0) return false;
    while (sd_bus_message_at_end(message, 0) == 0) {
        QString value;
        if (values.size() >= 64 || !text(message, value)) return false;
        values.append(value);
    }
    return sd_bus_message_exit_container(message) >= 0;
}

bool execStart(sd_bus_message *message, Snapshot &snapshot)
{
    if (sd_bus_message_enter_container(message, 'a', "(sasbttttuii)") <= 0
        || sd_bus_message_enter_container(message, 'r', "sasbttttuii") <= 0
        || !text(message, snapshot.executable) || !stringArray(message, snapshot.arguments)) return false;
    int ignore = 1, code = 0, status = 0;
    uint64_t realStart = 0, monoStart = 0, realEnd = 0, monoEnd = 0;
    uint32_t pid = 0;
    if (sd_bus_message_read(message, "bttttuii", &ignore, &realStart, &monoStart,
                            &realEnd, &monoEnd, &pid, &code, &status) <= 0
        || sd_bus_message_exit_container(message) < 0 || sd_bus_message_at_end(message, 0) != 1
        || sd_bus_message_exit_container(message) < 0) return false;
    snapshot.ignoreFailure = ignore != 0;
    snapshot.execPid = pid;
    snapshot.execStartMonotonic = monoStart;
    // ExecStart is a configured command augmented with expendable accounting.
    // systemd serializes MainPID/main_exec_status separately on reconstruction;
    // its command accounting can legitimately be entirely absent afterwards.
    // Current peer identity remains MainPID + invocation + socket-bound pidfd.
    snapshot.execAccountingAbsent = realStart == 0 && monoStart == 0 && realEnd == 0
        && monoEnd == 0 && pid == 0 && code == 0 && status == 0;
    const bool runningAccounting = realStart > 0 && monoStart > 0 && realEnd == 0
        && monoEnd == 0 && pid > 0 && code == 0 && status == 0;
    return snapshot.execAccountingAbsent || runningAccounting;
}

bool properties(AsyncBus &bus, const QByteArray &owner, bool service, Snapshot &snapshot,
                QString *failure = nullptr)
{
    const QString prefix = service ? QStringLiteral("Service.") : QStringLiteral("Unit.");
    if (failure) *failure = prefix + QStringLiteral("GetAll");
    auto response = call(bus, owner, unitPath, "org.freedesktop.DBus.Properties", "GetAll",
                         service ? "org.freedesktop.systemd1.Service" : "org.freedesktop.systemd1.Unit");
    if (!response || sd_bus_message_enter_container(response.get(), 'a', "{sv}") <= 0) return false;
    auto *message = response.get();
    auto &values = service ? snapshot.service : snapshot.unit;
    int count = 0;
    const QStringList strings {"Id", "LoadState", "ActiveState", "SubState", "FragmentPath", "Type", "User", "RootDirectory", "RootImage"};
    const QStringList booleans {"NeedDaemonReload", "Transient", "DynamicUser"};
    const QStringList arrays {"DropInPaths", "Environment"};
    while (sd_bus_message_at_end(message, 0) == 0) {
        if (++count > 1024 || sd_bus_message_enter_container(message, 'e', "sv") <= 0) return false;
        QString name;
        if (!text(message, name)) return false;
        if (failure) *failure = prefix + name;
        char type = 0; const char *signature = nullptr;
        if (sd_bus_message_peek_type(message, &type, &signature) <= 0 || type != 'v' || !signature) return false;
        const bool known = strings.contains(name) || booleans.contains(name) || arrays.contains(name)
            || name == "MainPID" || name == "InvocationID" || name == "ExecStart" || name == "Job";
        if (!known) {
            if (sd_bus_message_skip(message, "v") < 0) return false;
        } else {
            if (values.contains(name) || sd_bus_message_enter_container(message, 'v', signature) <= 0) return false;
            if (strings.contains(name)) {
                QString value; if (strcmp(signature, "s") || !text(message, value)) return false;
                values.insert(name, value);
            } else if (booleans.contains(name)) {
                int value = 0; if (strcmp(signature, "b") || sd_bus_message_read(message, "b", &value) <= 0) return false;
                values.insert(name, value != 0);
            } else if (arrays.contains(name)) {
                QStringList value; if (strcmp(signature, "as") || !stringArray(message, value)) return false;
                values.insert(name, value);
            } else if (name == "Job") {
                uint32_t id = 0; QString path;
                if (strcmp(signature,"(uo)") || sd_bus_message_enter_container(message,'r',"uo") <= 0
                    || sd_bus_message_read(message,"u",&id) <= 0 || !text(message,path,'o')
                    || sd_bus_message_exit_container(message) < 0 || id != 0 || path != "/") return false;
                values.insert(name,true);
            } else if (name == "MainPID") {
                uint32_t value = 0; if (strcmp(signature, "u") || sd_bus_message_read(message, "u", &value) <= 0) return false;
                values.insert(name, value);
            } else if (name == "InvocationID") {
                const void *bytes = nullptr; size_t size = 0;
                if (strcmp(signature, "ay") || sd_bus_message_read_array(message, 'y', &bytes, &size) <= 0 || size != 16) return false;
                values.insert(name, QByteArray(static_cast<const char *>(bytes), 16));
            } else {
                if (strcmp(signature, "a(sasbttttuii)") || !execStart(message, snapshot)) return false;
                values.insert(name, true);
            }
            if (sd_bus_message_exit_container(message) < 0) return false;
        }
        if (sd_bus_message_exit_container(message) < 0) return false;
    }
    if (sd_bus_message_exit_container(message) < 0) return false;
    if (failure) failure->clear();
    return true;
}
}

bool isPackagedUnit(const QByteArray &bytes)
{
    QByteArray normalized = bytes;
    normalized.replace("\r\n", "\n");
    return !normalized.contains('\r') && normalized == QByteArray(expectedUnit);
}

QString snapshotFailure(const Snapshot &s, qint64 peerPid)
{
    const auto exact = [](const QVariantMap &map, const char *name, const QVariant &expected) {
        const auto it = map.constFind(QString::fromLatin1(name));
        return it != map.constEnd() && it->metaType() == expected.metaType() && *it == expected;
    };
    if (peerPid <= 0 || peerPid > UINT32_MAX) return QStringLiteral("peer-pid");
    const QVariantMap expectedUnit {{"Id",QString::fromLatin1(unitName)}, {"LoadState",QStringLiteral("loaded")},
        {"ActiveState",QStringLiteral("active")},{"SubState",QStringLiteral("running")},
        {"FragmentPath",QString::fromLatin1(fragment)},{"DropInPaths",QStringList{}},
        {"NeedDaemonReload",false},{"Transient",false},{"Job",true}};
    const QVariantMap expectedService {{"MainPID",quint32(peerPid)},{"Type",QStringLiteral("simple")},
        {"User",QString{}},{"DynamicUser",false},{"RootDirectory",QString{}},{"RootImage",QString{}},
        {"Environment",QStringList{}},{"ExecStart",true}};
    for (auto it=expectedUnit.constBegin();it!=expectedUnit.constEnd();++it)
        if (!exact(s.unit,it.key().toLatin1().constData(),it.value())) return QStringLiteral("Unit.")+it.key();
    for (auto it=expectedService.constBegin();it!=expectedService.constEnd();++it)
        if (!exact(s.service,it.key().toLatin1().constData(),it.value())) return QStringLiteral("Service.")+it.key();
    const auto invocation=s.unit.value("InvocationID");
    if (invocation.metaType()!=QMetaType::fromType<QByteArray>() || invocation.toByteArray().size()!=16
        || invocation.toByteArray()==QByteArray(16,'\0')) return QStringLiteral("Unit.InvocationID");
    if (s.executable!=QString::fromLatin1(executable) || s.arguments!=QStringList{QString::fromLatin1(executable)}
        || s.ignoreFailure) return QStringLiteral("Service.ExecStart.definition");
    if (!(s.execAccountingAbsent
            ? s.execPid == 0 && s.execStartMonotonic == 0
            : s.execPid == peerPid && s.execStartMonotonic > 0)) return QStringLiteral("Service.ExecStart.accounting");
    return {};
}

bool validSnapshot(const Snapshot &s, qint64 peerPid)
{
    return snapshotFailure(s,peerPid).isEmpty();
}

bool authorize(QLocalSocket *socket, const QString &expected, LocalPeerIdentity &identity, QString *error)
{
    identity = {};
    const auto fail = [error](const char *reason) { if (error) *error = QString::fromLatin1(reason); return false; };
    const uint64_t now = monotonicUsec();
    if (!now) return fail("Linux service-manager clock unavailable");
    const uint64_t deadline = now + 1500000;
    if (expected != QString::fromLatin1(executable) || !protectedFile(expected)) return fail("Linux service-manager executable is unprotected or unsupported");
    ucred peer {};
    if (!credentials(socket, peer)) return fail("Linux service-manager peer is not root");
    // SO_PEERPIDFD (Linux 6.5+) binds to the actual connected peer, unlike
    // pidfd_open(SO_PEERCRED.pid), which permits PID reuse before first lookup.
    // Older kernels keep direct executable auth; this fallback fails closed.
    Fd peerFd;
    socklen_t fdSize = sizeof(peerFd.value);
    constexpr int peerPidFdOption = 77;
    if (getsockopt(int(socket->socketDescriptor()), SOL_SOCKET, peerPidFdOption, &peerFd.value, &fdSize) != 0
        || fdSize != sizeof(peerFd.value) || peerFd.value < 0) return fail("Linux service-manager peer pidfd unavailable (requires Linux 6.5+)");
    if (!alive(peerFd.value)) return fail("Linux service-manager peer exited");
    QByteArray unitBytes;
    if (!protectedFile(QString::fromLatin1(fragment), &unitBytes)
        || !isPackagedUnit(unitBytes)) return fail("Linux service-manager unit is not the protected packaged unit");
    AsyncBus bus(deadline);
    const int fd = connectBus(deadline);
    if (fd < 0 || !bus.start(fd)) return fail("Linux service-manager fixed system bus unavailable or timed out");
    const auto owner = managerOwner(bus);
    if (owner.isEmpty() || !managerIdentity(bus, owner)) return fail("Linux system manager identity is not root PID 1");
    auto unit = call(bus, owner, "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager", "GetUnit", unitName);
    QString foundPath;
    if (!unit || !text(unit.get(), foundPath, 'o') || foundPath != QString::fromLatin1(unitPath)) return fail("Linux service-manager unit identity mismatch");
    Snapshot before, after;
    QString field;
    if (!properties(bus, owner, false, before, &field) || !properties(bus, owner, true, before, &field))
        return fail((QStringLiteral("Linux service-manager property parse failure: ")+field).toLatin1().constData());
    field=snapshotFailure(before,peer.pid);
    if (!field.isEmpty()) return fail((QStringLiteral("Linux service-manager policy mismatch: ")+field).toLatin1().constData());
    QByteArray readback;
    if (!protectedFile(expected) || !protectedFile(QString::fromLatin1(fragment), &readback) || readback != unitBytes
        || !alive(peerFd.value) || !properties(bus, owner, false, after) || !properties(bus, owner, true, after)
        || before != after || !validSnapshot(after, peer.pid) || managerOwner(bus) != owner
        || !managerIdentity(bus, owner) || bus.expired()) return fail("Linux service-manager identity changed or timed out");
    ucred current {};
    if (!credentials(socket, current) || current.pid != peer.pid || current.uid != peer.uid || current.gid != peer.gid
        || !alive(peerFd.value)) return fail("Linux connected peer identity changed");
    // Root-admin service-manager attribution, analogous to Windows SCM. This
    // does NOT claim that /proc/<pid>/exe was readable or verified.
    identity.processId = peer.pid;
    identity.userIdentifier = QStringLiteral("0");
    identity.executablePath = expected;
    return true;
}
}
