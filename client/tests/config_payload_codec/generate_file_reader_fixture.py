"""Compile actual desktop readFile overloads and main import-file call site.

Only the final protocol-import delegate/signals are inert seams. File IO, bounded
read/error/UTF-8 handling and ImportUiController's call selection are actual source.
Android code is retained in the extracted source but not executed by this fixture.
"""
from pathlib import Path
import hashlib
import re
import sys

root = Path(sys.argv[1])
output = Path(sys.argv[2])
source_path = root / 'ui/controllers/systemController.cpp'
header_path = root / 'ui/controllers/systemController.h'
ui_path = root / 'ui/controllers/importUiController.cpp'
source = source_path.read_text(encoding='utf8')
start = source.index('bool SystemController::readFile(const QString &fileName, QByteArray &data,')
end = source.index('\nQString SystemController::getFileName(', start)
functions = source[start:end]
declarations = re.findall(r'    static bool readFile\([^;]+;', header_path.read_text(encoding='utf8'))
if len(declarations) != 2:
    raise ValueError('expected actual byte-array and QString declarations')
ui = ui_path.read_text(encoding='utf8')
first = ui.index('bool ImportUiController::extractConfigFromFile(')
last = ui.index('\nbool ImportUiController::extractConfigFromData(', first)
caller = ui[first:last]
prefix = r'''
#include <QByteArray>
#include <QCoreApplication>
#include <QFile>
#include <QFileInfo>
#include <QJsonObject>
#include <QScopeGuard>
#include <QString>
#include <QTemporaryDir>
#include <cstdio>
#include <cstdlib>
#include <limits>
#include "core/utils/errorCodes.h"
#include "core/utils/configPayloadCodec.h"
class SystemController {
public:
'''
prefix += '\n'.join(declarations) + '\n};\n'
prefix += r'''
using namespace amnezia;
// Explicit inert protocol-import seam. The tested resource boundary occurs
// before this callback; no VPN/profile/server/application action is performed.
class DataImporter {
public:
 struct Result {
  ErrorCode errorCode=ErrorCode::NoError;
  QJsonObject config;
  QString configFileName,maliciousWarningText;
  bool isNativeWireGuardConfig=false;
 };
 int calls=0;
 QString lastText,lastName;
 Result extractConfigFromData(const QString &data,const QString &name) {
  ++calls;lastText=data;lastName=name;return {};
 }
};
class ImportUiController {
public:
 DataImporter *m_importController;
 QJsonObject m_config;
 QString m_configFileName,m_maliciousWarningText;
 bool m_isNativeWireGuardConfig=false;
 ErrorCode lastError=ErrorCode::NoError;
 int changed=0;
 explicit ImportUiController(DataImporter &importer):m_importController(&importer){}
 bool extractConfigFromFile(const QString&);
 void importErrorOccurred(ErrorCode code,bool){lastError=code;}
 void importConfigChanged(){++changed;}
};
'''
main = r'''
static int checks=0;
void check(bool condition,const char *description){
 ++checks;if(!condition){std::fprintf(stderr,"file reader failure%d: %s\n",checks,description);std::exit(1);}
}
void write(const QString &path,const QByteArray &data){
 QFile file(path);check(file.open(QIODevice::WriteOnly),"owned fixture open");
 check(file.write(data)==data.size(),"owned fixture write");
}
int main(int argc,char **argv){
 QCoreApplication app(argc,argv);
 QTemporaryDir owned;check(owned.isValid(),"owned temp directory");
 const QString unicodePath=owned.filePath(QString::fromUtf8(u8"профиль_日本.conf"));
 const QByteArray unicode=QString::fromUtf8(u8"данные 日本\n").toUtf8();
 write(unicodePath,unicode);
 QByteArray bytes="preserved";
 check(SystemController::readFile(unicodePath,bytes,unicode.size()),"byte limit exact succeeds");
 check(bytes==unicode,"Unicode bytes preserved");
 QString text="preserved";
 check(SystemController::readFile(unicodePath,text,unicode.size()),"QString exact byte limit succeeds");
 check(text==QString::fromUtf8(unicode),"UTF8 QString preserved");
 bytes="preserved";text="preserved";
 check(!SystemController::readFile(unicodePath,bytes,unicode.size()-1),"byte cap+1 rejects");
 check(bytes=="preserved","byte output unchanged on cap failure");
 check(!SystemController::readFile(unicodePath,text,unicode.size()-1),"QString cap+1 rejects");
 check(text=="preserved","QString output unchanged on cap failure");
 const QString missing=owned.filePath("missing");
 check(!SystemController::readFile(missing,bytes,1024)&&bytes=="preserved","missing bytes unchanged");
 check(!SystemController::readFile(missing,text,1024)&&text=="preserved","missing QString unchanged");
 check(!SystemController::readFile(owned.path(),bytes,1024)&&bytes=="preserved","directory/read failure unchanged");
 for(qint64 invalid:{qint64(-2),std::numeric_limits<qint64>::max(),qint64(QByteArray::maxSize())}){
  check(!SystemController::readFile(unicodePath,bytes,invalid)&&bytes=="preserved","invalid/overflow byte cap");
  check(!SystemController::readFile(unicodePath,text,invalid)&&text=="preserved","invalid/overflow QString cap");
 }
 const QString empty=owned.filePath("empty");write(empty,{});
 check(SystemController::readFile(empty,bytes,0)&&bytes.isEmpty(),"empty byte file at zero cap");
 check(SystemController::readFile(empty,text,0)&&text.isEmpty(),"empty QString file at zero cap");
 bytes="preserved";text="preserved";
 check(!SystemController::readFile(unicodePath,bytes,0)&&bytes=="preserved","nonempty zero cap rejects");
 check(SystemController::readFile(unicodePath,bytes)&&bytes==unicode,"legacy byte caller default retained");
 check(SystemController::readFile(unicodePath,text)&&text==QString::fromUtf8(unicode),"legacy QString default retained");
 constexpr auto cap=configPayloadCodec::maximumEncodedTextBytes;
 const QString sparse=owned.filePath("oversized-sparse.conf");
 {QFile file(sparse);check(file.open(QIODevice::WriteOnly),"sparse open");check(file.resize(cap+1),"sparse cap+1");}
 bytes="preserved";text="preserved";
 check(!SystemController::readFile(sparse,bytes,cap)&&bytes=="preserved","sparse bytes reject before full read");
 check(!SystemController::readFile(sparse,text,cap)&&text=="preserved","sparse QString reject before full read");
 const QString exact=owned.filePath("exact-sparse.conf");
 {QFile file(exact);check(file.open(QIODevice::WriteOnly),"exact file open");check(file.resize(4096),"exact file resize");}
 check(SystemController::readFile(exact,bytes,4096)&&bytes.size()==4096,"exact positive boundary");
 DataImporter importer;ImportUiController controller(importer);
 check(!controller.extractConfigFromFile(sparse),"actual main import rejects oversized file");
 check(importer.calls==0&&controller.lastError==ErrorCode::ImportOpenConfigError,"oversize never reaches parser delegate");
 check(controller.extractConfigFromFile(unicodePath),"actual main import normal file succeeds");
 check(importer.calls==1&&importer.lastText==QString::fromUtf8(unicode),"actual main delegate receives Unicode");
 check(importer.lastName==QFileInfo(unicodePath).fileName()&&controller.changed==1,"actual main filename and signal");
 std::printf("actual desktop file-reader/main import checks: %d\n",checks);
}
'''
provenance = ''
for path in (source_path, header_path, ui_path):
    provenance += '// Actual source SHA256 ' + str(path.relative_to(root)) + ': ' + hashlib.sha256(path.read_bytes()).hexdigest() + '\n'
output.write_text(provenance + prefix + functions + '\n' + caller + main, encoding='utf8')
