#!/usr/bin/env python3
"""Compile the actual publication function with inert SSH; never execute its script."""
import argparse
import hashlib
import json
import io
import builtins
import types
from pathlib import Path
import struct
import subprocess
import xml.sax.saxutils

ROOT = Path(__file__).resolve().parents[3]

def run(command):
    subprocess.run([str(x) for x in command], check=True)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build-dir', type=Path, required=True)
    parser.add_argument('--qt-prefix', type=Path, required=True)
    args = parser.parse_args()
    build = args.build_dir.resolve()
    build.mkdir(parents=True, exist_ok=True)
    source = (ROOT / 'client/core/controllers/selfhosted/exportController.cpp').read_text()
    function = source[source.index('ErrorCode publishClientLogCollector('):source.index('\nvoid refreshClientLogCollector(')]
    constants = source[source.index('constexpr char clientLogsPublishErrorMarker'):source.index('\nQString clientLogsTunnelInterface')]
    scaffold = r"""
#include <QCoreApplication>
#include <QResource>
#include <QDebug>
#include <QFile>
#include <QDir>
#include <QStringList>
#include <QJsonDocument>
#include <QJsonObject>
#include <cassert>
#include <functional>
#include "@HEADER@"
using namespace amnezia;
namespace libssh { struct Client {}; }
enum class ErrorCode { NoError, InternalError, ServerCheckFailed, ServerDockerFailedError };
enum class DockerContainer { Awg2, Awg, WireGuard, OpenVpn };
struct ServerCredentials {};
namespace ContainerUtils { QString containerToString(DockerContainer) { return QStringLiteral("amnezia-awg2"); } }
namespace Utils { QString getRandomString(int) { static int n = 0; return QString::number(++n); } }
namespace protocols {
namespace awg { constexpr char serverConfigPath[]="/opt/amnezia/awg/awg0.conf"; constexpr char serverLegacyConfigPath[]="/opt/amnezia/awg/wg0.conf"; }
namespace wireguard { constexpr char serverConfigPath[]="/opt/amnezia/wireguard/wg0.conf"; }
namespace clientLogs { constexpr char hostDirectory[]="/opt/amnezia/client-logs"; constexpr char tunnelContainerName[]="amnezia-client-logs"; constexpr char containerName[]="amnezia-client-logs"; constexpr char syncHost[]="172.29.172.251"; constexpr int syncPort=17866; }
}
QString clientLogsTunnelInterface(DockerContainer) { return QStringLiteral("awg0"); }
QByteArray clientLogsCollectorScript() { return QByteArray("legacy collector fixture"); }
QString clientLogsLegacyMapRefreshScript() { return QStringLiteral("echo fixture-legacy-refresh;"); }
struct SshSession {
    using Callback=std::function<ErrorCode(const QString&,libssh::Client&)>;
    inline static QList<QByteArray> uploads;
    inline static QStringList uploadedNames;
    inline static QString script;
    inline static QString machine=QStringLiteral("x86_64\n");
    inline static int calls=0;
    ErrorCode uploadFileToHost(const ServerCredentials&,const QByteArray&data,const QString&name) { uploads.append(data); uploadedNames.append(name); return ErrorCode::NoError; }
    ErrorCode runScript(const ServerCredentials&,const QString&s,Callback out={},Callback={}) {
        ++calls;
        if (s==QStringLiteral("uname -m")) { libssh::Client c; if(out)out(machine,c); }
        else if (!s.startsWith(QStringLiteral("sudo rm -f "))) script=s;
        return ErrorCode::NoError;
    }
};
@CONSTANTS@
@FUNCTION@
int main(int argc,char**argv) {
    QCoreApplication app(argc,argv);
    assert(argc==5);
    assert(QResource::registerResource(QString::fromLocal8Bit(argv[1])));
    const QString mode=QString::fromLocal8Bit(argv[2]);
    if(mode!=QStringLiteral("legacy")) assert(QResource::registerResource(QString::fromLocal8Bit(argv[3])));
    if(mode==QStringLiteral("badarch")) SshSession::machine=QStringLiteral("x86_64; echo rejected\n");
    if(mode==QStringLiteral("oversized")) SshSession::machine=QString(129,QLatin1Char(' '))+QStringLiteral("x86_64");
    const auto result=publishClientLogCollector({},DockerContainer::Awg2,{},{});
    const bool pass=(mode==QStringLiteral("legacy")||mode==QStringLiteral("native"));
    assert((result==ErrorCode::NoError)==pass);
    if(!pass) { assert(SshSession::uploads.isEmpty()); if(mode==QStringLiteral("invalid"))assert(SshSession::calls==0); return 0; }
    assert(SshSession::uploads.size()==2);
    const QString script=SshSession::script;
    assert(!script.contains(QStringLiteral("__COLLECTOR_")) && !script.contains(QStringLiteral("__ROUTE_")));
    if(mode==QStringLiteral("native")) {
        assert(!script.contains(QStringLiteral("python3")));
        assert(!script.contains(QStringLiteral("ROUTE_GUARD")));
        const auto preflight=script.indexOf(QStringLiteral("--publication-preflight"));
        assert(preflight>script.indexOf(QStringLiteral("native_stage_hash")));
        assert(preflight<script.indexOf(QStringLiteral("sudo install -d")));
        assert(preflight<script.indexOf(QStringLiteral("sudo docker rm")));
    }
    QStringList runLines;
    for(const QString &line:script.split(QLatin1Char('\n')))
        if(line.contains(QStringLiteral("sudo docker run -d")))runLines.append(line);
    assert(runLines.size()==2);
    for(const QString &line:runLines) {
        assert(line.contains(QStringLiteral("--cap-drop ALL")));
        assert(line.contains(QStringLiteral("--security-opt no-new-privileges:true")));
        assert(line.contains(QStringLiteral("--read-only")));
        assert(line.contains(QStringLiteral("--tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777")));
        if(mode==QStringLiteral("native")) {
            assert(!line.contains(QStringLiteral("PYTHONDONTWRITEBYTECODE")));
            assert(!line.contains(QStringLiteral("PYTHONUNBUFFERED")));
            assert(line.contains(QStringLiteral("--label org.amnezia.client-logs.native-sha256=")));
            assert(line.contains(QStringLiteral("--entrypoint '/data/amnezia-client-logs-collector'")));
            assert(line.contains(QStringLiteral("--root /data")));
        } else {
            assert(line.contains(QStringLiteral("-e PYTHONDONTWRITEBYTECODE=1 -e PYTHONUNBUFFERED=1")));
            assert(line.contains(QStringLiteral("--entrypoint 'python'")));
            assert(line.contains(QStringLiteral("/data/collector.py")));
        }
    }
    if(mode==QStringLiteral("native")) {
        assert(SshSession::uploadedNames[0].endsWith(QStringLiteral(".bin")) && SshSession::uploadedNames[1].endsWith(QStringLiteral(".bin")));
        assert(SshSession::uploads[0].startsWith(QByteArray::fromHex("7f454c46")));
        assert(SshSession::uploads[1].startsWith(QByteArray::fromHex("7f454c46")));
        assert(script.contains(QStringLiteral("--entrypoint '/data/amnezia-client-logs-collector'")));
        assert(script.contains(QStringLiteral("--root /data")));
        assert(script.contains(QStringLiteral("ExecStart=/opt/amnezia/client-logs/amnezia-client-logs-route amnezia-awg2")));
        assert(script.contains(QStringLiteral("--publication-preflight")));
        assert(script.contains(QStringLiteral("installed_native_hash")) && script.contains(QStringLiteral("installed_route_hash")));
        assert(!script.contains(QStringLiteral("--entrypoint 'python'")));
    } else {
        assert(SshSession::uploadedNames[0].endsWith(QStringLiteral(".py")) && SshSession::uploadedNames[1].endsWith(QStringLiteral(".py")));
        assert(SshSession::uploads[0]==QByteArray("legacy collector fixture"));
        assert(script.contains(QStringLiteral("--entrypoint 'python'")));
        assert(script.contains(QStringLiteral("ExecStart=/usr/bin/python3 /opt/amnezia/client-logs/collector_route.py")));
    }
    QFile output(QString::fromLocal8Bit(argv[4]));assert(output.open(QIODevice::WriteOnly));output.write(script.toUtf8());
}
"""
    scaffold = scaffold.replace('@HEADER@', str(ROOT / 'client/core/utils/selfhosted/serverNativeBundle.h')).replace('@CONSTANTS@', constants).replace('@FUNCTION@', function)
    (build / 'fixture.cpp').write_text(scaffold)
    (build / 'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.25)\nproject(CollectorWiring LANGUAGES CXX)\nfind_package(Qt6 REQUIRED COMPONENTS Core)\nadd_executable(collector_wiring fixture.cpp)\ntarget_compile_features(collector_wiring PRIVATE cxx_std_17)\ntarget_compile_options(collector_wiring PRIVATE -UNDEBUG -Wall -Wextra -Wpedantic -Werror)\ntarget_link_libraries(collector_wiring PRIVATE Qt6::Core)\n')
    rcc = args.qt_prefix / 'libexec/rcc'
    def resource(name, rows):
        qrc = build / (name + '.qrc')
        qrc.write_text('<RCC><qresource prefix="/">' + ''.join('<file alias="'+xml.sax.saxutils.escape(alias)+'">'+xml.sax.saxutils.escape(str(path))+'</file>' for alias,path in rows) + '</qresource></RCC>')
        output=build/(name+'.rcc');run([rcc,'--binary',qrc,'-o',output]);return output
    legacy=resource('legacy',[('server_scripts/client_logs/collector_route.py',ROOT/'client/server_scripts/client_logs/collector_route.py')])
    data=bytearray(256);data[:7]=bytes.fromhex('7f454c46020101');struct.pack_into('<HHI',data,16,2,62,1);struct.pack_into('<QQ',data,24,0x400080,64);struct.pack_into('<HHH',data,52,64,56,1);struct.pack_into('<IIQQQQQQ',data,64,1,5,0,0x400000,0,256,256,4096)
    binary=build/'synthetic-never-executed-elf';binary.write_bytes(data)
    rows=[{'role':role,'architecture':'x86_64','path':'x86_64/'+role,'sha256':hashlib.sha256(data).hexdigest(),'size':len(data)} for role in ('collector','collector-route')]
    def bundle(name, entries):
        manifest=build/(name+'.json');manifest.write_text(json.dumps({'schema':1,'binaries':entries},sort_keys=True,separators=(',',':')))
        return resource(name,[('server_native/manifest.json',manifest)]+[('server_native/'+r['path'],binary) for r in entries])
    native=bundle('native',rows);missing=bundle('missing',rows[:1]);invalidfile=build/'invalid.json';invalidfile.write_text('{}');invalid=resource('invalid',[('server_native/manifest.json',invalidfile)])
    run(['cmake','-S',build,'-B',build/'cmake','-DCMAKE_PREFIX_PATH='+str(args.qt_prefix)])
    run(['cmake','--build',build/'cmake','--parallel','2'])
    for case,r in [('legacy',legacy),('native',native),('missing',missing),('invalid',invalid),('badarch',native),('oversized',native)]:
        shell=build/(case+'.sh');run([build/'cmake/collector_wiring',legacy,case,r,shell])
        if shell.exists():
            run(['bash','-n',shell])
            if case == 'native':
                native_script = shell.read_text()
                assert 'ROUTE_GUARD' not in native_script and 'python3' not in native_script
                assert '--publication-preflight' in native_script
                continue
            text=shell.read_text();guard=text.split("<<'ROUTE_GUARD'",1)[1].split('\nROUTE_GUARD',1)[0].split('\n',1)[1]
            compiled=compile(guard,str(shell)+':ROUTE_GUARD','exec')
            image=constants.split('"python:',1)[1].split('"',1)[0]
            for previous in ('legacy','native','tampered','wrong-command'):
                source_meta={'Id':'a'*64,'Name':'/amnezia-awg2','State':{'Running':True,'Pid':11}}
                labels={'org.amnezia.client-logs.route':'amnezia-awg2'}
                config={'Image':'python:'+image,'Labels':labels,'Env':['AMNEZIA_CLIENT_LOGS_SCOPE=amnezia-awg2'],'Entrypoint':['python'],'Cmd':['/data/collector.py']}
                if previous!='legacy':
                    config.update(Entrypoint=['/data/amnezia-client-logs-collector'],Cmd=['--root','/data'])
                    labels['org.amnezia.client-logs.native-sha256']=hashlib.sha256(b'abc').hexdigest()
                if previous=='wrong-command': config['Cmd']=['--root','/foreign']
                collector_meta={'Name':'/amnezia-client-logs-amnezia-awg2','State':{'Running':True,'Pid':42},'Config':config,'HostConfig':{'NetworkMode':'container:'+'a'*64},'Mounts':[{'Destination':'/data','Source':'/opt/amnezia/client-logs','RW':True}]}
                def fake_run(argv,**_):
                    assert argv[:2] in (['docker','inspect'],['docker','ps'])
                    if argv[1]=='inspect':
                        value=source_meta if argv[2]=='amnezia-awg2' else collector_meta
                        return types.SimpleNamespace(stdout=json.dumps([value]).encode())
                    return types.SimpleNamespace(stdout=b'amnezia-client-logs-amnezia-awg2\n')
                def fake_import(name,*a,**kw):
                    return types.SimpleNamespace(run=fake_run) if name=='subprocess' else builtins.__import__(name,*a,**kw)
                def fake_open(path,*_):
                    assert path=='/proc/42/exe'
                    return io.BytesIO(b'abd' if previous=='tampered' else b'abc')
                namespace={'__builtins__':dict(vars(builtins),__import__=fake_import,open=fake_open)}
                expected=(previous=='legacy' or (case=='native' and previous=='native'))
                try: exec(compiled,namespace)
                except ValueError:
                    assert not expected,(case,previous)
                else: assert expected,(case,previous)

    print('actualFunctionCases=6 legacyOwnershipGuardCases=4 nativePreflightWiring=1 passed=true liveSsh=0 scriptsExecuted=0 elfExecuted=0')
if __name__=='__main__': main()
