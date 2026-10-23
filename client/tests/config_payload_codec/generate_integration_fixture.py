"""Generate owned QtCore fixtures from actual data-import methods, without app startup.

Classification/delegation and format-version semantics are explicit inert seams;
codec, QR decode, file IO and subscription response methods are actual source.
The real ErrorCode enum, ImportResult and ProtocolData definitions are retained.
"""
from pathlib import Path
import argparse
import hashlib
import re

parser = argparse.ArgumentParser()
parser.add_argument('client_root', type=Path)
parser.add_argument('output', type=Path)
parser.add_argument('--old-subscription-source', type=Path)
parser.add_argument('--old-only', action='store_true')
args = parser.parse_args()
root = args.client_root


def method(path, start, end=None):
    text = path.read_text(encoding='utf8')
    first = text.index(start)
    if end is not None:
        return text[first:text.index(end, first)]
    brace = text.index('{', first)
    level = 1
    # Used only for readTextFile, whose fixed body contains no brace strings.
    cursor = brace + 1
    while level:
        if text[cursor] == '{':
            level += 1
        elif text[cursor] == '}':
            level -= 1
        cursor += 1
    return text[first:cursor]


def struct(path, name):
    text = path.read_text(encoding='utf8')
    match = re.search(r'    struct ' + name + r'\s*\{.*?\n    \};', text, re.S)
    if match is None:
        raise ValueError('missing actual struct ' + name)
    return match[0]


import_source = root / 'core/controllers/selfhosted/importController.cpp'
ui_source = root / 'ui/controllers/importUiController.cpp'
subscription_source = args.old_subscription_source or root / 'core/controllers/api/subscriptionController.cpp'
classifier = method(import_source, 'ConfigTypes checkConfigFormat(').replace('ConfigTypes checkConfigFormat(', 'ConfigTypes classifyFixture(')
qr = method(import_source, 'ImportController::ImportResult ImportController::extractConfigFromQr(',
            '\nvoid ImportController::startDecodingQr()')
reader = method(ui_source, 'QString ImportUiController::readTextFile(')
subscription = method(subscription_source, 'ErrorCode SubscriptionController::extractServerConfigJsonFromResponse(',
                      '\nvoid SubscriptionController::updateApiConfigInJson(')
import_header = root / 'core/controllers/selfhosted/importController.h'
enum_text = import_header.read_text(encoding='utf8')
enum = enum_text[enum_text.index('    enum class ConfigTypes'):]
enum = enum[:enum.index('};') + 2]
result = struct(import_header, 'ImportResult')
protocol = struct(root / 'core/controllers/api/subscriptionController.h', 'ProtocolData')
prefix = r'''
#include <QByteArray>
#include <QCoreApplication>
#include <QDebug>
#include <QDir>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QString>
#include <QTemporaryDir>
#include <cstdio>
#include <cstdlib>
#include "core/utils/errorCodes.h"
#include "core/utils/constants/configKeys.h"
#include "core/utils/configPayloadCodec.h"
using namespace amnezia;
'''
declarations = enum + '\n' + classifier + r'''
class ImportController {
public:
''' + result + r'''
 ImportResult extractConfigFromQr(const QByteArray&);
 // The classifier is extracted from actual source; only final delegation is inert.
 // Tests exercise bounded decoding and JSON, without full protocol app interpretation.
 ConfigTypes checkConfigFormat(const QString &data) const { return classifyFixture(data); }
 ImportResult extractConfigFromData(const QString &data, const QString &name) {
  ImportResult result;result.configFileName=name;result.config=QJsonDocument::fromJson(data.toUtf8()).object();
  if(result.config.isEmpty())result.errorCode=ErrorCode::ImportInvalidConfigError;
  else result.configType=ConfigTypes::Amnezia;
  return result;
 }
};
// Config-version handling is a semantic seam, not part of these decoder tests.
bool rejectUnsupportedFormatVersion(ImportController::ImportResult &) {return false;}
class ImportUiController { public: QString readTextFile(const QString&); };
// The AWG-only adapter compiles but is not executed; vless data decode is tested.
enum class DockerContainer { Awg };
namespace ContainerUtils { QString containerTypeToString(DockerContainer){return "awg";} }
class SubscriptionController {
public:
''' + protocol + r'''
 ErrorCode extractServerConfigJsonFromResponse(const QByteArray&,const QString&,const ProtocolData&,QJsonObject&);
};
'''
common = r'''
static int checks=0;
void check(bool condition,const char *description){
 ++checks;if(!condition){std::fprintf(stderr,"integration failure %d: %s\n",checks,description);std::exit(1);}
}
QByteArray encoded(const QByteArray &raw){return raw.toBase64(QByteArray::Base64UrlEncoding|QByteArray::OmitTrailingEquals);}
QByteArray apiResponse(const QByteArray &raw){
 return QJsonDocument(QJsonObject{{"config",QString::fromLatin1("vpn://"+encoded(raw))}}).toJson(QJsonDocument::Compact);
}
'''
old_main = r'''
int main(int argc,char **argv){
 QCoreApplication app(argc,argv);
 SubscriptionController subscription;
 for(const auto &raw:{QByteArray("bad"),QByteArray("{}"),QByteArray("[]"),QByteArray("null")}){
  QJsonObject output{{"preserved",true}};
  const auto status=subscription.extractServerConfigJsonFromResponse(apiResponse(raw),"vless",{},output);
  check(status==ErrorCode::NoError,"OLD malformed response reports success");
  check(output.isEmpty(),"OLD malformed response empties output");
 }
 std::printf("OLD subscription malformed-data bug reproduced: %d checks\n",checks);
}
'''
main = r'''
int main(int argc,char **argv){
 QCoreApplication app(argc,argv);
 ImportController importer;SubscriptionController subscription;ImportUiController ui;
 const QByteArray json=R"({"owned":true,"description":"sample"})";
 const QJsonObject expected=QJsonDocument::fromJson(json).object();
 const auto compressed=qCompress(json,9);
 const QByteArray classifiedJson=R"({"containers":[],"owned":true})";
 check(importer.extractConfigFromQr(qCompress(classifiedJson,0)).config==QJsonDocument::fromJson(classifiedJson).object(),
       "QR stored zlib bypasses plain-text classifier");
 for(const auto &raw:{json,encoded(json),compressed,encoded(compressed)}){
  const auto result=importer.extractConfigFromQr(raw);
  check(result.errorCode==ErrorCode::NoError,"QR accepted input family");
  check(result.config==expected,"QR JSON preserved");
 }
 for(const auto &raw:{json,compressed}){
  QJsonObject output{{"preserved",true}};
  check(subscription.extractServerConfigJsonFromResponse(apiResponse(raw),"vless",{},output)==ErrorCode::NoError,
        "subscription accepted input family");
  check(output==expected,"subscription JSON preserved");
 }
 // A valid plain JSON prefix with zlib-looking bytes at offsets4/5 stays raw.
 const QByteArray collision=R"({"xxx^":1})";
 check(importer.extractConfigFromQr(collision).config==QJsonDocument::fromJson(collision).object(),"QR raw JSON marker collision");
 QJsonObject collisionOutput;
 check(subscription.extractServerConfigJsonFromResponse(apiResponse(collision),"vless",{},collisionOutput)==ErrorCode::NoError,
       "subscription raw JSON marker collision");
 check(collisionOutput==QJsonDocument::fromJson(collision).object(),"collision data preserved");
 auto checksum=compressed;checksum[checksum.size()-1]^=1;
 const QList<QByteArray> damaged={checksum,compressed.first(6),compressed.first(compressed.size()-1),compressed+"junk"};
 for(const auto &raw:damaged){
  check(importer.extractConfigFromQr(raw).errorCode==ErrorCode::ImportInvalidConfigError,"QR corrupt/truncated stream rejects");
  check(importer.extractConfigFromQr(encoded(raw)).errorCode==ErrorCode::ImportInvalidConfigError,"QR base64 corrupt stream rejects");
  QJsonObject output{{"preserved",true}};const auto before=output;
  check(subscription.extractServerConfigJsonFromResponse(apiResponse(raw),"vless",{},output)==ErrorCode::ApiConfigEmptyError,
        "subscription corrupt/truncated stream rejects");
  check(output==before,"subscription failed inflate preserves output");
 }
 // Large valid encoded inputs exceed the raw decoded cap but fit the text cap.
 {
  QByteArray validLarge(12*1024*1024+32,'x');
  const QByteArray begin="{\"owned\":true,\"data\":\"";
  for(qsizetype i=0;i<begin.size();++i)validLarge[i]=begin[i];
  validLarge[validLarge.size()-2]='"';validLarge[validLarge.size()-1]='}';
  for(const auto &encodedLarge:{encoded(validLarge),encoded(qCompress(validLarge,0))}){
   check(encodedLarge.size()>configPayloadCodec::maximumDecodedBytes,"large base64 exceeds raw cap");
   check(encodedLarge.size()<=configPayloadCodec::maximumEncodedTextBytes,"large base64 fits encoded cap");
   const auto decodedLarge=importer.extractConfigFromQr(encodedLarge);
   check(decodedLarge.errorCode==ErrorCode::NoError,"QR accepts large valid encoded data");
   check(decodedLarge.config.value("owned").toBool(),"QR preserves large decoded JSON");
  }
 }
 // Only the current bounded helper sees this stream. Its forged size hint is1,
 // while its real stream contains >16MiB. No OLD qUncompress path receives it.
 QByteArray large(configPayloadCodec::maximumDecodedBytes+32,'x');
 const QByteArray begin="{\"owned\":\"";
 for(qsizetype i=0;i<begin.size();++i)large[i]=begin[i];
 large[large.size()-2]='"';large[large.size()-1]='}';
 check(importer.extractConfigFromQr(large).errorCode==ErrorCode::ImportInvalidConfigError,"QR plain raw JSON decoded cap");
 const auto classifiedLarge=QByteArray("{\"containers\":[],\"data\":\"")+QByteArray(configPayloadCodec::maximumDecodedBytes,'x')+"\"}";
 check(importer.extractConfigFromQr(classifiedLarge).errorCode==ErrorCode::ImportInvalidConfigError,"QR classified raw JSON decoded cap");
 auto overflow=qCompress(large,9);large=QByteArray();
 for(int i=0;i<3;++i){overflow[i]=0;}
 overflow[3]=1;
 check(importer.extractConfigFromQr(overflow).errorCode==ErrorCode::ImportInvalidConfigError,"QR forged hint actual overflow rejects");
 check(importer.extractConfigFromQr(encoded(overflow)).errorCode==ErrorCode::ImportInvalidConfigError,"QR base64 actual overflow rejects");
 QJsonObject overflowOutput{{"preserved",true}},beforeOverflow=overflowOutput;
 check(subscription.extractServerConfigJsonFromResponse(apiResponse(overflow),"vless",{},overflowOutput)==ErrorCode::ApiConfigEmptyError,
       "subscription forged hint actual overflow rejects");
 check(overflowOutput==beforeOverflow,"overflow leaves existing output intact");
 for(const auto &raw:{QByteArray("bad"),QByteArray("{}"),QByteArray("[]"),QByteArray("null")}){
  QJsonObject output{{"preserved",true}};const auto before=output;
  check(subscription.extractServerConfigJsonFromResponse(apiResponse(raw),"vless",{},output)==ErrorCode::ApiConfigEmptyError,
        "subscription malformed/nonobject/empty JSON rejects");
  check(output==before,"subscription invalid JSON preserves output");
 }
 QTemporaryDir owned;check(owned.isValid(),"owned temp directory");
 const auto unicodePath=owned.filePath(QString::fromUtf8(u8"профиль_日本.conf"));
 const QByteArray unicode=QString::fromUtf8(u8"данные 日本\n").toUtf8();
 {QFile file(unicodePath);check(file.open(QIODevice::WriteOnly),"owned Unicode file open");check(file.write(unicode)==unicode.size(),"Unicode file written");}
 check(ui.readTextFile(unicodePath)==QString::fromUtf8(unicode),"actual UI read Unicode contents");
 check(ui.readTextFile(owned.filePath("missing")).isEmpty(),"missing input empty result");
 const auto oversized=owned.filePath("oversized-sparse.conf");
 {QFile file(oversized);check(file.open(QIODevice::WriteOnly),"owned sparse file open");
  check(file.resize(configPayloadCodec::maximumEncodedTextBytes+1),"sparse file cap+1");}
 check(ui.readTextFile(oversized).isEmpty(),"actual UI rejects oversize before reading");
 std::printf("actual import/QR/subscription/file integration checks: %d\n",checks);
}
'''
provenance = '// Actual input source SHA256: ' + hashlib.sha256(import_source.read_bytes()).hexdigest()
provenance += '\n// Actual subscription source SHA256: ' + hashlib.sha256(subscription_source.read_bytes()).hexdigest() + '\n'
args.output.write_text(provenance + prefix + declarations + qr + '\n' + reader + '\n' + subscription + common
                       + (old_main if args.old_only else main), encoding='utf8')
