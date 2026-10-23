#!/usr/bin/env python3
"""Compile unchanged AWG caller method against inert SSH and real Qt resources."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parents[3]


def run(command):
    subprocess.run([str(item) for item in command], check=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build-dir', type=Path, required=True)
    parser.add_argument('--qt-prefix', type=Path, required=True)
    args = parser.parse_args()
    build = args.build_dir.resolve()
    build.mkdir(parents=True, exist_ok=True)
    source_path = ROOT / 'client/core/controllers/selfhosted/installController.cpp'
    source = source_path.read_text()
    method = source[source.index('ErrorCode InstallController::prepareAwgMigration('):source.index('\nServerRoutingRulesPublishResult InstallController::publishVersionedServerRoutingRules(')]
    scaffold = r'''
#include <QCoreApplication>
#include <QResource>
#include <QTcpSocket>
#include <QFile>
#include <QRegularExpression>
#include <QStringList>
#include <QJsonDocument>
#include <QJsonObject>
#include <cassert>
#include <functional>
#include "@HEADER@"
namespace libssh { struct Client {}; }
enum class ErrorCode { NoError, InternalError, ServerCheckFailed, SshTimeoutError, SshInternalError };
enum class DockerContainer { Awg, Awg2 };
struct ServerCredentials {
 QString sshHostKeyFingerprint=QStringLiteral("fixture-key");
 QString hostName=QStringLiteral("unused.invalid"); int port=22;
 bool isValid() const { return true; }
};
namespace ContainerUtils { QString containerToString(DockerContainer) { return QStringLiteral("amnezia-awg2"); } }
namespace Utils { QString getRandomString(int) { return QStringLiteral("owned-fixture"); } }
struct SshSession {
 using Callback=std::function<ErrorCode(const QString&,libssh::Client&)>;
 inline static QString mode;
 inline static QStringList scripts, uploadedNames;
 inline static QList<QByteArray> uploads;
 ErrorCode uploadFileToHost(const ServerCredentials&, const QByteArray &bytes, const QString &name) {
  uploads.append(bytes);uploadedNames.append(name);
  return mode==QStringLiteral("uploadfail") && name.endsWith(QStringLiteral("native-feed.upload")) ? ErrorCode::InternalError : ErrorCode::NoError;
 }
 ErrorCode runScript(const ServerCredentials&,const QString &script,Callback output={},Callback={},int=0) {
  scripts.append(script);libssh::Client client;
  if(script==QStringLiteral("uname -m")) {
   const QString architecture=mode==QStringLiteral("badarch")?QStringLiteral("x86_64;false\n"):
      mode==QStringLiteral("oversizedarch")?QString(129,QLatin1Char('x')):QStringLiteral("x86_64\n");
   return output?output(architecture,client):ErrorCode::NoError;
  }
  if(script.startsWith(QStringLiteral("sudo install ")) && mode==QStringLiteral("stagefail"))return ErrorCode::InternalError;
  if(script.endsWith(QStringLiteral(" --preflight"))) {
   if(mode==QStringLiteral("preflightfail")) return output(QStringLiteral("{\"eligible\":false}"),client);
   if(mode==QStringLiteral("oversizedpreflight"))return output(QString(16385,QLatin1Char('x')),client);
   return output(QStringLiteral("{\"eligible\":true}"),client);
  }
  if(script.startsWith(QStringLiteral("sudo python3 -B"))) {
   if(mode==QStringLiteral("preparefail"))return ErrorCode::InternalError;
   return output(QStringLiteral("{\"prepared\":true}"),client);
  }
  return ErrorCode::NoError;
 }
};
struct ExportController {
 inline static int collectorCalls=0;
 static ErrorCode prepareMigrationSourceCollector(const ServerCredentials&,DockerContainer) {
  ++collectorCalls;
  return SshSession::mode==QStringLiteral("collectorfail")?ErrorCode::InternalError:ErrorCode::NoError;
 }
};
class InstallController {
 public:
 ErrorCode prepareAwgMigration(const ServerCredentials&,DockerContainer,const QString&,int,const QString&,qint64,QJsonObject&,bool);
};
@METHOD@
int main(int argc,char **argv) {
 QCoreApplication app(argc,argv);assert(argc==4);
 assert(QResource::registerResource(QString::fromLocal8Bit(argv[1])));
 SshSession::mode=QString::fromLocal8Bit(argv[2]);const QString mode=SshSession::mode;
 if(mode!=QStringLiteral("legacy"))assert(QResource::registerResource(QString::fromLocal8Bit(argv[3])));
 QJsonObject result;InstallController controller;
 const auto code=controller.prepareAwgMigration({},DockerContainer::Awg2,QStringLiteral("fixture.test"),51821,QStringLiteral("reviewed/image@sha256:")+QString(64,QLatin1Char('a')),1,result,false);
 const bool success=mode==QStringLiteral("legacy")||mode==QStringLiteral("native");
 assert((code==ErrorCode::NoError)==success);
 const bool early=mode==QStringLiteral("invalid")||mode==QStringLiteral("missingrole")||mode==QStringLiteral("missingarch")||mode==QStringLiteral("badarch")||mode==QStringLiteral("oversizedarch");
 if(early) {
  assert(SshSession::uploads.isEmpty());assert(ExportController::collectorCalls==0);
  assert(SshSession::scripts.size()==(mode==QStringLiteral("invalid")?0:1));
  return 0;
 }
 const bool native=mode!=QStringLiteral("legacy");
 assert(SshSession::uploads.size()==9);
 bool feedPython=false,binary=false,staged=false,cleaned=false;int preflight=0,prepared=0;
 for(qsizetype i=0;i<SshSession::uploadedNames.size();++i) {
  const QString name=SshSession::uploadedNames[i];
  feedPython|=name.endsWith(QStringLiteral("/feeds.py"));
  if(name.endsWith(QStringLiteral("/native-feed.upload"))) {
   binary=true;assert(SshSession::uploads[i].startsWith(QByteArray::fromHex("7f454c46")));
  }
 }
 assert(feedPython==!native);assert(binary==native);
 for(const QString &script:SshSession::scripts) {
  staged|=script.startsWith(QStringLiteral("sudo install -o 0 -g 0 -m 0755"));
  cleaned|=script.contains(QStringLiteral("rmdir '/tmp/amnezia-migration-owned-fixture'"));
  if(script.startsWith(QStringLiteral("sudo python3 -B"))) {
   if(script.endsWith(QStringLiteral(" --preflight")))++preflight;else ++prepared;
   assert(script.contains(QStringLiteral(" --native-feed "))==native);
   assert(script.contains(QStringLiteral(" --native-feed-sha256 "))==native);
   if(native) {
    const QString digest=QString::fromLatin1(QCryptographicHash::hash(SshSession::uploads.last(),QCryptographicHash::Sha256).toHex());
    assert(script.contains(QStringLiteral(" --native-feed-sha256 '")+digest+QLatin1Char('\'')));
    assert(script.contains(QStringLiteral(" --native-feed '/tmp/amnezia-migration-owned-fixture/native-feed'")));
   }
  }
 }
 assert(cleaned);assert(staged==(native&&mode!=QStringLiteral("uploadfail")));
 if(mode==QStringLiteral("uploadfail")||mode==QStringLiteral("stagefail")) {
  assert(preflight==0&&prepared==0&&ExportController::collectorCalls==0);
 } else if(mode==QStringLiteral("preflightfail")||mode==QStringLiteral("oversizedpreflight")) {
  assert(preflight==1&&prepared==0&&ExportController::collectorCalls==0);
 } else if(mode==QStringLiteral("collectorfail")) {
  assert(preflight==1&&prepared==0&&ExportController::collectorCalls==1);
 } else {assert(preflight==1&&prepared==1&&ExportController::collectorCalls==1);}
}
'''
    scaffold = scaffold.replace('@HEADER@', str(ROOT / 'client/core/utils/selfhosted/serverNativeBundle.h')).replace('@METHOD@', method)
    (build / 'fixture.cpp').write_text(scaffold)
    (build / 'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.25)\nproject(AwgFeedCaller LANGUAGES CXX)\nfind_package(Qt6 REQUIRED COMPONENTS Core Network)\nadd_executable(awg_feed_caller fixture.cpp)\ntarget_compile_features(awg_feed_caller PRIVATE cxx_std_17)\ntarget_compile_options(awg_feed_caller PRIVATE -UNDEBUG -Wall -Wextra -Wpedantic -Werror)\ntarget_link_libraries(awg_feed_caller PRIVATE Qt6::Core Qt6::Network)\n')
    def resource(name, entries):
        qrc = build / (name + '.qrc')
        qrc.write_text('<RCC><qresource prefix="/">'+''.join('<file alias="'+escape(alias)+'">'+escape(str(path))+'</file>' for alias,path in entries)+'</qresource></RCC>')
        output = build / (name + '.rcc')
        run([args.qt_prefix / 'libexec/rcc', '--binary', qrc, '-o', output])
        return output
    legacy = resource('legacy', [('server_scripts/awg_migration/'+name, ROOT/'client/server_scripts/awg_migration'/name) for name in ('prepare.py','automatic.py','trusted_image.py','service.py','target.py','policy.py','journal.py','feeds.py','ready_validation.py')])
    def bundle(name, role='awg-feed', machine=62, architecture='x86_64'):
        data=bytearray(256);data[:7]=bytes.fromhex('7f454c46020101')
        struct.pack_into('<HHI',data,16,2,machine,1)
        struct.pack_into('<QQ',data,24,0x400080,64)
        struct.pack_into('<HHH',data,52,64,56,1)
        struct.pack_into('<IIQQQQQQ',data,64,1,5,0,0x400000,0,256,256,4096)
        binary=build/(name+'.elf');binary.write_bytes(data)
        row={'role':role,'architecture':architecture,'path':architecture+'/'+role,'sha256':hashlib.sha256(data).hexdigest(),'size':len(data)}
        manifest=build/(name+'.json');manifest.write_text(json.dumps({'schema':1,'binaries':[row]},sort_keys=True,separators=(',',':')))
        return resource(name,[('server_native/manifest.json',manifest),('server_native/'+row['path'],binary)])
    native=bundle('native');missingrole=bundle('missingrole',role='collector');missingarch=bundle('missingarch',machine=183,architecture='aarch64')
    invalid_json=build/'invalid.json';invalid_json.write_text('{}')
    invalid=resource('invalid',[('server_native/manifest.json',invalid_json)])
    run(['cmake','-S',build,'-B',build/'cmake','-DCMAKE_PREFIX_PATH='+str(args.qt_prefix)])
    run(['cmake','--build',build/'cmake','--parallel','2'])
    cases={'legacy':legacy,'native':native,'invalid':invalid,'missingrole':missingrole,'missingarch':missingarch}
    cases.update({case:native for case in ('badarch','oversizedarch','uploadfail','stagefail','preflightfail','oversizedpreflight','collectorfail','preparefail')})
    for mode,bundle_path in cases.items():
        run([build/'cmake/awg_feed_caller',legacy,mode,bundle_path])
        print('PASS '+mode,flush=True)
    receipt={'passed':len(cases),'cases':list(cases),'source_sha256':hashlib.sha256(source_path.read_bytes()).hexdigest(),'resource_loader_sha256':hashlib.sha256((ROOT/'client/core/utils/selfhosted/serverNativeBundle.h').read_bytes()).hexdigest(),'method_sha256':hashlib.sha256(method.encode()).hexdigest(),'method_extracted_without_rewriting':True,'actual_resource_loader':True,'synthetic_elf_executed':False,'ssh_or_network_executed':False,'application_build':False}
    (build/'RECEIPT.json').write_text(json.dumps(receipt,indent=2)+'\n')


if __name__ == '__main__':
    main()
