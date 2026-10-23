// Standalone read-only diagnostic, not an application or IPC command sender.
#include "localpeerauthentication.h"
#include "candidate_source_hashes.h"
#include <QCoreApplication>
#include <QCryptographicHash>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLocalSocket>
#include <QTextStream>
#include <QElapsedTimer>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>

int main(int argc,char **argv)
{
    QCoreApplication app(argc,argv);
    QJsonObject evidence {{"schema","amnezia-linux-server-auth-verifier-v1"},
                          {"diagnosticOnly",true},{"releasePass",false},
                          {"sourceHashes",QJsonDocument::fromJson(candidateSourceHashes).object()},
                          {"callerUid",int(getuid())},{"callerEuid",int(geteuid())}};
    const auto finish=[&](const QString &reason,int code) {
        evidence["result"]=reason;
        QTextStream(stdout)<<QJsonDocument(evidence).toJson(QJsonDocument::Compact)<<Qt::endl;
        return code;
    };
    QFile binary(QCoreApplication::applicationFilePath());
    if(!binary.open(QIODevice::ReadOnly))return finish("verifier_binary_unreadable",2);
    QCryptographicHash hash(QCryptographicHash::Sha256);
    if(!hash.addData(&binary))return finish("verifier_binary_hash_failed",2);
    evidence["verifierSha256"]=QString::fromLatin1(hash.result().toHex());
    QFile callerStatus("/proc/self/status");
    if(!callerStatus.open(QIODevice::ReadOnly))return finish("caller_status_unavailable",2);
    QJsonObject capabilities;QByteArray uidLine;
    for(const auto &line:callerStatus.readAll().split('\n')) {
        if(line.startsWith("Uid:"))uidLine=line.mid(4).simplified();
        for(const auto *name:{"CapInh","CapPrm","CapEff","CapAmb"}) {
            const QByteArray key(name);
            if(line.startsWith(key+':'))capabilities[QString::fromLatin1(key)]=QString::fromLatin1(line.mid(key.size()+1).trimmed());
        }
    }
    evidence["callerCapabilities"]=capabilities;evidence["callerUidStatus"]=QString::fromLatin1(uidLine);
    const auto uids=uidLine.split(' ');bool plainUser=getuid()!=0&&geteuid()!=0&&uids.size()==4;
    for(const auto &uid:uids)plainUser=plainUser&&uid==QByteArray::number(getuid());
    for(const auto *name:{"CapInh","CapPrm","CapEff","CapAmb"}) {
        const QByteArray value=capabilities.value(QString::fromLatin1(name)).toString().toLatin1();
        plainUser=plainUser&&!value.isEmpty()&&value==QByteArray(value.size(),'0');
    }
    if(!plainUser)return finish("requires_plain_unprivileged_user_without_inheritable_permitted_effective_or_ambient_capabilities",2);
    if(argc!=2 || QByteArray(argv[1])!="--read-only-installed-service")return finish("explicit_read_only_mode_required",2);
    QLocalSocket socket;
    socket.connectToServer("/var/run/amneziavpn/control-v2.sock",QIODevice::ReadWrite);
    if(!socket.waitForConnected(1000))return finish("installed_service_socket_connection_failed",3);
    ucred peer{};socklen_t size=sizeof(peer);
    if(getsockopt(int(socket.socketDescriptor()),SOL_SOCKET,SO_PEERCRED,&peer,&size)!=0 || size!=sizeof(peer))return finish("peer_credentials_failed",3);
    evidence["peerPid"]=int(peer.pid);evidence["peerUid"]=int(peer.uid);evidence["peerGid"]=int(peer.gid);
    const QByteArray path=QByteArray("/proc/")+QByteArray::number(peer.pid)+"/exe";
    char target[4096];errno=0;const auto bytes=readlink(path.constData(),target,sizeof(target));const int failure=errno;
    evidence["readlinkResult"]=int(bytes);evidence["readlinkErrno"]=bytes<0?failure:0;
    if(bytes>=0)evidence["readlinkTarget"]=QString::fromUtf8(target,int(bytes));
    int pidfd=-1;socklen_t fdSize=sizeof(pidfd);errno=0;
    const int pidfdResult=getsockopt(int(socket.socketDescriptor()),SOL_SOCKET,77,&pidfd,&fdSize);
    evidence["peerPidfdAvailable"]=pidfdResult==0&&pidfd>=0;
    evidence["peerPidfdErrno"]=pidfdResult<0?errno:0;
    if(pidfd>=0)close(pidfd);
    if(peer.uid!=0 || peer.gid!=0 || bytes>=0 || (failure!=EACCES&&failure!=EPERM))return finish("does_not_exercise_confirmed_root_access_denial",3);
    amnezia::ipc::LocalPeerIdentity identity;QString error;QElapsedTimer timer;timer.start();
    const bool accepted=amnezia::ipc::authorizePrivilegedServer(&socket,
        "/opt/AmneziaVPN/bin/AmneziaVPN-service",QString{},&identity,&error);
    evidence["authorizeElapsedMilliseconds"]=double(timer.elapsed());
    evidence["authorized"]=accepted;evidence["authorizationError"]=error;
    evidence["identityPid"]=double(identity.processId);evidence["identityUser"]=identity.userIdentifier;
    evidence["identityExecutable"]=identity.executablePath;
    evidence["authorizationBasis"]="root-administrator-system-manager-attribution-not-proc-exe-observation";
    evidence["ipcPayloadBytesSent"]=0;
    char peek;errno=0;
    const auto available=recv(int(socket.socketDescriptor()),&peek,1,MSG_PEEK|MSG_DONTWAIT);
    evidence["peerSocketEof"]=available==0;
    evidence["peerSocketPeekErrno"]=available<0?errno:0;
    evidence["serverSideClientAcceptance"]="not-verified-helper-is-intentionally-not-the-installed-GUI";
    if(!accepted || identity.processId!=peer.pid || identity.userIdentifier!="0"
        || identity.executablePath!="/opt/AmneziaVPN/bin/AmneziaVPN-service")return finish("actual_server_authorization_failed",4);
    return finish("actual_server_authorization_accepted_diagnostic_only",0);
}
