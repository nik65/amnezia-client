"""Compile actual updater download bodies against inert Qt fake replies.

No application, network, installer, service, or VPN is started.
"""
import argparse, pathlib, subprocess, sys

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('source', type=pathlib.Path)
parser.add_argument('output', type=pathlib.Path)
parser.add_argument('--generate-only', action='store_true')
parser.add_argument('--qt-prefix', type=pathlib.Path)
parser.add_argument('--asan', action='store_true')
args = parser.parse_args()
source = args.source.read_text()
out = args.output; out.mkdir(parents=True, exist_ok=True)
artifact = source[source.index('bool UpdateController::startArtifactDownload()'):source.index('UpdateController::InstallerHandoffResult UpdateController::launchDownloadedArtifact')]
legacy = source[source.index('    QObject::connect(reply, &QNetworkReply::finished,', source.index('bool UpdateController::runInstaller()')):]
legacy = legacy[:legacy.index('    return true;')]
prefix = r'''
#include <QCoreApplication>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QSaveFile>
#include <QCryptographicHash>
#include <QDir>
#include <QFileInfo>
#include <QTemporaryDir>
#include <QTimer>
#include <QDebug>
#include <memory>
#include <QPointer>
#include <dirent.h>
#include <unistd.h>
#include <cstring>
struct Logger { QDebug error() { return qDebug(); } } logger;
constexpr int kInstallerTransferTimeoutMs=100, kInstallerTotalDeadlineMs=100;
int launches=0;
struct FakeReply : QNetworkReply {
 FakeReply() { open(QIODevice::ReadOnly); setUrl(QUrl("https://fixture.invalid/artifact")); setAttribute(QNetworkRequest::HttpStatusCodeAttribute,200); }
 void abort() override { setError(OperationCanceledError,"aborted"); emit finished(); }
 QByteArray payload; qint64 offset=0;
 qint64 bytesAvailable() const override { return payload.size()-offset; }
 qint64 readData(char *p,qint64 n) override { auto size=qMin(n,payload.size()-offset); if(size<=0)return -1; memcpy(p,payload.constData()+offset,size);offset+=size;return size; }
 void fail() { setError(ConnectionRefusedError,"inert fixture error"); }
 void metadata(qint64 n) { setHeader(QNetworkRequest::ContentLengthHeader,n); emit metaDataChanged(); }
 void data() { emit readyRead(); }
 void complete() { emit finished(); }
};
struct Manager { FakeReply *next=nullptr; QNetworkReply *get(const QNetworkRequest&) { return next; } } manager;
struct App { Manager *networkManager() { return &manager; } } app;
App *amnApp=&app;
bool samePinnedUrl(const QUrl&a,const QUrl&b) { return a==b; }
QString normalizeSha256(const QString&s) { return s; }
int runLinuxInstaller(const QString&,const QString&,qint64) { ++launches; return 1; }
void scheduleDesktopQuitAfterInstallerStart() {}
struct UpdateController : QObject {
 enum class InstallerHandoffResult { Failed };
 struct Artifact { QUrl url=QUrl("https://fixture.invalid/artifact"); qint64 size=0; QString sha256=QString::fromLatin1(QCryptographicHash::hash({},QCryptographicHash::Sha256).toHex()); } m_selectedArtifact;
 QString path;
 explicit UpdateController(QString p):path(std::move(p)) {}
 QString localInstallerPath() { return path; }
 void finishSelfHostedInstallerAttempt(InstallerHandoffResult) {}
 InstallerHandoffResult launchDownloadedArtifact(const QString&) { ++launches; return InstallerHandoffResult::Failed; }
 bool startArtifactDownload();
 void legacy(QNetworkReply *reply) {
'''
suffix = r'''
int openStaging(const QString &directory) {
 int count=0; DIR *d=opendir("/proc/self/fd");
 while(auto *e=readdir(d)) { char buffer[4096]; const auto path=QByteArray("/proc/self/fd/")+e->d_name; auto n=readlink(path.constData(),buffer,sizeof(buffer)-1); if(n>0) {buffer[n]=0; if(QString::fromLocal8Bit(buffer).startsWith(directory)) ++count;} }
 closedir(d); return count;
}
int main(int argc,char**argv) {
 QCoreApplication core(argc,argv); QTemporaryDir temp;
 if(argc!=2||!temp.isValid())return 19;
 const QString mode=QString::fromLocal8Bit(argv[1]);
 auto *controller=new UpdateController(temp.path()+"/artifact");
 auto *reply=new FakeReply; manager.next=reply;
 const bool payloadMode=QStringList{"payload","ready","error","hash","size","large"}.contains(mode);
 if(payloadMode) {
  reply->payload="payload";
  controller->m_selectedArtifact.size=reply->payload.size();
  controller->m_selectedArtifact.sha256=QString::fromLatin1(QCryptographicHash::hash(reply->payload,QCryptographicHash::Sha256).toHex());
  if(mode=="hash")controller->m_selectedArtifact.sha256=QString(64,'0');
  if(mode=="size")controller->m_selectedArtifact.size=reply->payload.size()+1;
  if(!controller->startArtifactDownload())return 20;
  if(mode=="error")reply->fail();
  if(mode=="large")reply->metadata(reply->payload.size()+1);
  else {if(mode=="ready")reply->data();reply->complete();}
  const bool success=mode=="payload"||mode=="ready";
  if(launches!=(success?1:0))return 21;
  QFile committed(temp.path()+"/artifact");
  if(committed.exists()!=success)return 22;
  if(success&&(!committed.open(QIODevice::ReadOnly)||committed.readAll()!=reply->payload))return 23;
  committed.close();QCoreApplication::sendPostedEvents(nullptr,QEvent::DeferredDelete);delete controller;
  return openStaging(temp.path())?24:0;
 }
 if(mode=="legacy") { controller->legacy(reply); QPointer<FakeReply> guard(reply); delete controller; if(guard) { reply->complete(); delete reply; } return launches?10:0; }
 if(!controller->startArtifactDownload()) return 11;
 if(openStaging(temp.path())!=1) return 12;
 if(mode=="controller") { delete controller; if(openStaging(temp.path())) return 13; }
 else if(mode=="reply") { delete reply; delete controller; if(openStaging(temp.path())) return 14; }
 else if(mode=="timer") { QTimer::singleShot(150,&core,&QCoreApplication::quit); core.exec(); delete controller; if(openStaging(temp.path())) return 15; }
 else if(mode=="finished") { reply->complete(); QCoreApplication::sendPostedEvents(nullptr,QEvent::DeferredDelete); delete controller; if(openStaging(temp.path())) return 16; }
 else return 18;
 return 0;
}
'''
# Use the exact legacy callback and artifact method. Reparenting, when present,
# is part of the production setup immediately before the legacy callback.
if 'reply->setParent(this);' in source[source.index('bool UpdateController::runInstaller()'):source.index('bool UpdateController::startArtifactDownload()')]:
 legacy='    reply->setParent(this);\n'+legacy
cpp=prefix+legacy+'}\n};\n'+artifact+suffix
(out/'fixture.cpp').write_text(cpp)
if args.generate_only:
    sys.exit(0)
if args.qt_prefix is None:
    parser.error('use --qt-prefix to compile directly, or --generate-only for CMake')
qt=str(args.qt_prefix)
command=['g++','-std=c++17','-g','-fPIC',str(out/'fixture.cpp'),'-I'+qt+'/include','-I'+qt+'/include/QtCore','-I'+qt+'/include/QtNetwork','-L'+qt+'/lib','-Wl,-rpath,'+qt+'/lib','-lQt6Core','-lQt6Network','-o',str(out/'fixture')]
if args.asan:
    command[1:1]=['-fsanitize=address','-fno-omit-frame-pointer']
subprocess.run(command,check=True)
failed=False
for mode in ['legacy','controller','reply','timer','finished','payload','ready','error','hash','size','large']:
 result=subprocess.run([str(out/'fixture'),mode],capture_output=True,text=True,env={**__import__('os').environ,'ASAN_OPTIONS':'detect_leaks=0'})
 (out/(mode+'.log')).write_text(result.stdout+result.stderr)
 print(mode,result.returncode)
 failed |= result.returncode != 0
sys.exit(1 if failed else 0)
