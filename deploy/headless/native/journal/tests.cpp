#include "journal.hpp"
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QTemporaryDir>
#include <QProcess>
#include <cassert>
#include <iostream>
#include <sys/stat.h>
#include <unistd.h>
using namespace headless_journal;
namespace {
template<class F> void rejects(F f) { bool caught=false; try { f(); } catch(const std::exception&) {caught=true;} assert(caught); }
struct Fixture {
    QTemporaryDir temporary;
    Policy policy;
    State state;
    QString directory;
    Fixture(): policy{temporary.path(),getuid()} {
        assert(temporary.isValid());
        chmod(policy.root.toUtf8().constData(),0700);
        directory=policy.root+"/.headless-provisioning-transactions/transaction.A123";
        assert(QDir().mkpath(directory));
        chmod((policy.root+"/.headless-provisioning-transactions").toUtf8().constData(),0700);
        chmod(directory.toUtf8().constData(),0700);
        state={"prepared","upgrade",directory,"/etc/systemd/system/amneziad.service","enabled","active",true,false};
        for(const auto& name: {"amneziad","amnezia-cli","amneziad.service","update-public-key.pem"}) put(name,"original");
    }
    QString journal() const {return policy.root+"/.headless-provisioning-journal.json";}
    void put(const QString& name,const QByteArray& data) {
        QFile file(directory+'/'+name); assert(file.open(QIODevice::WriteOnly|QIODevice::Truncate));
        assert(file.write(data)==data.size()); file.close(); assert(file.setPermissions(QFile::ReadOwner|QFile::WriteOwner));
    }
    void store(const QJsonObject& o) {
        QFile file(journal()); assert(file.open(QIODevice::WriteOnly|QIODevice::Truncate));
        auto data=QJsonDocument(o).toJson(QJsonDocument::Compact); assert(file.write(data)==data.size());
        file.close(); chmod(journal().toUtf8().constData(),0600);
    }
};
}
int main() {
    int count=0;
    auto test=[&](auto f){f();++count;};
    test([]{Fixture f; write(f.policy,f.state); auto o=read(f.policy); validateBackup(f.policy,o); assert(recoveryLines(f.policy,o).split('\n').size()==9);});
    test([]{Fixture f; auto o=snapshot(f.policy,f.state); f.put("amneziad","tampered"); rejects([&]{validateBackup(f.policy,o);});});
    test([]{Fixture f; auto o=snapshot(f.policy,f.state); chmod((f.directory+"/amneziad").toUtf8().constData(),0644); rejects([&]{validateBackup(f.policy,o);});});
    test([]{Fixture f; QFile::remove(f.directory+"/amnezia-cli"); f.put(".missing-amnezia-cli",""); auto o=snapshot(f.policy,f.state); validateBackup(f.policy,o); f.put("amnezia-cli","conflict"); rejects([&]{snapshot(f.policy,f.state);});});
    test([]{Fixture f; QFile::remove(f.directory+"/amneziad.service"); assert(symlink("/dev/null",(f.directory+"/amneziad.service").toUtf8().constData())==0); auto o=snapshot(f.policy,f.state);validateBackup(f.policy,o);});
    test([]{Fixture f; QFile::remove(f.directory+"/amneziad"); assert(symlink("/dev/null",(f.directory+"/amneziad").toUtf8().constData())==0); rejects([&]{snapshot(f.policy,f.state);});});
    test([]{Fixture f; auto o=snapshot(f.policy,f.state); for(const auto& key: {"phase","mode","backupDir","serviceTarget","serviceEnabled","serviceActive"}) {auto bad=o;bad.insert(key,"../../untrusted\n");rejects([&]{validate(f.policy,bad);});}});
    test([]{Fixture f; auto o=snapshot(f.policy,f.state); auto bad=o;bad.insert("extra",true);rejects([&]{validate(f.policy,bad);});bad=o;bad.insert("schema",true);rejects([&]{validate(f.policy,bad);});bad=o;bad.insert("groupCreated","true");rejects([&]{validate(f.policy,bad);});});
    test([]{Fixture f; auto o=snapshot(f.policy,f.state); o.insert("backupFiles",QJsonObject{}); rejects([&]{validate(f.policy,o);});o.insert("phase","starting");validate(f.policy,o);rejects([&]{validateBackup(f.policy,o);});});
    test([]{Fixture f;write(f.policy,f.state);chmod(f.journal().toUtf8().constData(),0644);rejects([&]{read(f.policy);});});
    test([]{Fixture f; auto target=f.policy.root+"/foreign"; QFile x(target);assert(x.open(QIODevice::WriteOnly));x.write("foreign");x.close();assert(symlink(target.toUtf8().constData(),f.journal().toUtf8().constData())==0);rejects([&]{write(f.policy,f.state);});rejects([&]{read(f.policy);});});
    test([]{Fixture f; auto bad=f.state;bad.backupDir=f.directory+"/../transaction.A123";rejects([&]{snapshot(f.policy,bad);});});
    test([]{Fixture f;auto o=snapshot(f.policy,f.state);o.insert("groupCreated",1);f.store(o);rejects([&]{read(f.policy);});});
    test([]{Fixture f;auto o=snapshot(f.policy,f.state);auto records=o.value("backupFiles").toObject();auto r=records.value("amneziad").toObject();r.insert("size",true);records.insert("amneziad",r);o.insert("backupFiles",records);rejects([&]{validate(f.policy,o);});});
    test([]{for(const auto* point: {"write","file-fsync","rename","directory-fsync"}) {Fixture f;write(f.policy,f.state);auto changed=f.state;changed.phase="stopping";rejects([&]{write(f.policy,changed,[&](const char* step){if(QString(step)==point)throw Error("injected");});});auto got=validate(f.policy,read(f.policy));assert(got.phase==(QString(point)=="directory-fsync" ? "stopping" : "prepared"));assert(QDir(f.policy.root).entryList({".headless-journal.*"},QDir::Files|QDir::Hidden).isEmpty());}});
    test([]{Fixture f;f.state.phase="starting";QFile::remove(f.directory+"/amneziad");write(f.policy,f.state);assert(read(f.policy).value("backupFiles").toObject().size()==3);});
    test([]{Fixture f;write(f.policy,f.state);assert(QDir(f.directory).removeRecursively());assert(QDir().rmdir(f.policy.root+"/.headless-provisioning-transactions"));f.state.phase="committed";write(f.policy,f.state);assert(read(f.policy).value("backupFiles").toObject().isEmpty());});
    test([]{Fixture f;auto prior=umask(0777);try{write(f.policy,f.state);}catch(...){umask(prior);throw;}umask(prior);read(f.policy);});
    test([]{Fixture f;QFile::remove(f.directory+"/amnezia-cli");f.put(".missing-amnezia-cli","legacy marker");auto o=snapshot(f.policy,f.state);validateBackup(f.policy,o);});
    test([]{Fixture f;QFile::remove(f.directory+"/amneziad.service");auto relative=QDir(f.directory).relativeFilePath("/dev/null");assert(symlink(relative.toUtf8().constData(),(f.directory+"/amneziad.service").toUtf8().constData())==0);auto o=snapshot(f.policy,f.state);validateBackup(f.policy,o);});
    test([]{Fixture f;QFile::remove(f.directory+"/amneziad.service");assert(symlink("amneziad.service",(f.directory+"/amneziad.service").toUtf8().constData())==0);rejects([&]{snapshot(f.policy,f.state);});});
    test([]{Fixture f;QFile::remove(f.directory+"/amneziad.service");assert(symlink("amneziad",(f.directory+"/amneziad.service").toUtf8().constData())==0);rejects([&]{snapshot(f.policy,f.state);});});
    test([]{Fixture f; auto link=f.policy.root+"/alias";assert(symlink(f.directory.toUtf8().constData(),link.toUtf8().constData())==0);auto p=f.policy;p.root=link;rejects([&]{read(p);});});
    test([]{Fixture f;QFile::remove(f.directory+"/amnezia-cli");f.put(".missing-amnezia-cli","legacy marker");QFile::remove(f.directory+"/amneziad.service");auto alias=QDir(f.directory).relativeFilePath("/dev/null");assert(symlink(alias.toUtf8().constData(),(f.directory+"/amneziad.service").toUtf8().constData())==0);write(f.policy,f.state);QProcess python;python.start("python3",{JOURNAL_REFERENCE_TEST,f.journal(),f.directory,INSTALLER_REFERENCE});assert(python.waitForFinished(10000));if(python.exitCode())std::cerr<<python.readAllStandardError().constData();assert(python.exitStatus()==QProcess::NormalExit&&python.exitCode()==0);validateBackup(f.policy,read(f.policy));});
    std::cout<<"journalFixtures="<<count<<" passed=true pythonReferenceInterop=1 installerCommands=0\n";
}
