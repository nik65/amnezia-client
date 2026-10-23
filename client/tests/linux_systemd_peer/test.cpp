#include "linuxsystemdpeer.h"
#include "linuxsystemdbustransport.h"
#include <QCoreApplication>
#include <QLocalSocket>
#include <QFile>
#include <QCryptographicHash>
#include <functional>
#include <iostream>
#include <sys/socket.h>
#include <thread>
#include <cstring>
using namespace amnezia::ipc::linuxSystemd;
int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    int checks = 0, failures = 0;
    const auto check = [&](bool result) { ++checks; if (!result) { ++failures; std::cerr<<"failed check="<<checks<<"\n"; } };
    check(isExecutableAccessDenied(-1,EACCES));check(isExecutableAccessDenied(-1,EPERM));
    for(int reason:{0,ENOENT,ESRCH,EIO})check(!isExecutableAccessDenied(-1,reason));
    check(!isExecutableAccessDenied(0,EACCES));check(!isExecutableAccessDenied(42,EACCES));
    QFile packagedUnit(PACKAGED_UNIT_FIXTURE);check(packagedUnit.open(QIODevice::ReadOnly));
    const QByteArray unitBytes=packagedUnit.readAll();
    check(unitBytes.size()==234);check(unitBytes.count("\r\n")==13);
    check(QCryptographicHash::hash(unitBytes,QCryptographicHash::Sha256).toHex()=="417220ca2efac7a0a0562e4addf3e1bab05eca9c337ceb0d41be9a72e2f4cd6d");
    check(isPackagedUnit(unitBytes));
    QByteArray lf=unitBytes;lf.replace("\r\n","\n");check(isPackagedUnit(lf));
    check(!isPackagedUnit(lf+"\r"));check(!isPackagedUnit("\r"+lf));
    check(!isPackagedUnit(lf+"\n"));check(!isPackagedUnit(" "+lf));
    auto wrong=unitBytes;wrong.replace("Type=simple","Type=forking");check(!isPackagedUnit(wrong));
    wrong=unitBytes;wrong.replace("\r\nDescription","\rDescription");check(!isPackagedUnit(wrong));
    const QString exe = "/opt/AmneziaVPN/bin/AmneziaVPN-service";
    Snapshot good;
    good.unit = {{"Id",QString("AmneziaVPN.service")},{"LoadState",QString("loaded")},
                 {"ActiveState",QString("active")},{"SubState",QString("running")},
                 {"FragmentPath",QString("/etc/systemd/system/AmneziaVPN.service")},
                 {"DropInPaths",QStringList{}},{"NeedDaemonReload",false},{"Transient",false},{"Job",true},
                 {"InvocationID",QByteArray(16,'x')}};
    good.service = {{"MainPID",quint32(123)},{"Type",QString("simple")},{"User",QString{}},
                    {"DynamicUser",false},{"RootDirectory",QString{}},{"RootImage",QString{}},
                    {"Environment",QStringList{}},{"ExecStart",true}};
    good.executable=exe;good.arguments={exe};good.execPid=123;
    good.execStartMonotonic=1;good.ignoreFailure=false;
    check(validSnapshot(good,123));
    auto absentAccounting=good;absentAccounting.execAccountingAbsent=true;
    absentAccounting.execPid=0;absentAccounting.execStartMonotonic=0;
    check(validSnapshot(absentAccounting,123));
    check(!validSnapshot(absentAccounting,124));
    auto inconsistentAccounting=absentAccounting;inconsistentAccounting.execPid=123;
    check(!validSnapshot(inconsistentAccounting,123));
    check(snapshotFailure(inconsistentAccounting,123)=="Service.ExecStart.accounting");
    auto wrongMainPid=good;wrongMainPid.service["MainPID"]=quint32(124);
    check(snapshotFailure(wrongMainPid,123)=="Service.MainPID");
    check(!validSnapshot(good,0));check(!validSnapshot(good,124));
    // Every required property must be present, with its exact D-Bus type.
    for (bool service : {false,true}) {
        const auto original=service?good.service:good.unit;
        for (auto it=original.constBegin();it!=original.constEnd();++it) {
            auto missing=good; (service?missing.service:missing.unit).remove(it.key());
            check(!validSnapshot(missing,123));
            auto wrongType=good; (service?wrongType.service:wrongType.unit)[it.key()]=QStringList{"forged"};
            check(!validSnapshot(wrongType,123));
        }
    }
    const std::function<void(Snapshot &)> mutations[] = {
        [](auto &s){s.unit["NeedDaemonReload"]=true;},[](auto &s){s.unit["Transient"]=true;},
        [](auto &s){s.unit["DropInPaths"]=QStringList{"/tmp/foreign.conf"};},
        [](auto &s){s.unit["FragmentPath"]=QString("/tmp/foreign.service");},
        [](auto &s){s.unit["InvocationID"]=QByteArray(16,'\0');},
        [](auto &s){s.service["MainPID"]=quint32(124);},[](auto &s){s.service["MainPID"]=QString("123");},
        [](auto &s){s.service["User"]=QString("lab");},[](auto &s){s.service["DynamicUser"]=true;},
        [](auto &s){s.service["RootDirectory"]=QString("/foreign");},
        [](auto &s){s.service["RootImage"]=QString("/foreign.img");},
        [](auto &s){s.service["Environment"]=QStringList{"LD_PRELOAD=/foreign"};},
        [](auto &s){s.service["Type"]=QString("forking");},
        [](auto &s){s.executable="/bin/sh";},[](auto &s){s.arguments.append("foreign");},
        [](auto &s){s.execPid=124;},[](auto &s){s.execStartMonotonic=0;},
        [](auto &s){s.ignoreFailure=true;},[](auto &s){s.unit["SubState"]=QString("exited");}
    };
    for(const auto &mutate:mutations){auto changed=good;mutate(changed);check(!validSnapshot(changed,123));check(changed!=good);}
    // Inert Unix peers only: initial AUTH stalled, closed and malformed.
    for(int mode=0;mode<3;++mode){
        int pair[2];check(socketpair(AF_UNIX,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0,pair)==0);
        std::thread fake([&,mode]{
            if(mode==1){close(pair[1]);return;}
            if(mode==2){const char *bad="REJECTED NONSENSE\r\n";send(pair[1],bad,strlen(bad),MSG_NOSIGNAL);}
            usleep(150000);close(pair[1]);
        });
        const auto start=monotonicUsec();
        {AsyncBus bus(start+60000);check(!bus.start(pair[0]));}
        check(monotonicUsec()-start<140000);
        fake.join();
    }
    std::cout<<"checks="<<checks<<" failures="<<failures<<" actual_system_bus_calls=0\n";
    return failures?1:0;
}
