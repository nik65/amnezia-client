"""Compile actual parser state methods with an inert final JSON-decoder seam."""
from pathlib import Path
import sys

source = Path(sys.argv[1]).read_text(encoding='utf8')
start = source.index('void ImportController::startDecodingQr()')
end = source.index('\nvoid ImportController::importConfig(', start)
functions = source[start:end]
prefix = r'''
#include <QByteArray>
#include <QDataStream>
#include <QIODevice>
#include <QMap>
#include <QJsonObject>
#include <QJsonDocument>
#include <QString>
#include <cstdio>
#include <cstdlib>
#include "qrCodeUtils.h"
enum class ErrorCode { NoError, ImportInvalidConfigError };
class ImportController {
public:
 struct ImportResult { ErrorCode errorCode=ErrorCode::NoError; QJsonObject config; };
 struct QrParseResult { bool success=false; ImportResult importResult; int chunksReceived=0,chunksTotal=0; };
 void startDecodingQr(); QrParseResult parseQrCodeChunk(const QString&);
 bool isQrDecodingActive()const; int qrChunksReceived()const; int qrChunksTotal()const;
 ImportResult extractConfigFromQr(const QByteArray &raw) {
  ImportResult result; result.config=QJsonDocument::fromJson(raw).object();
  if(result.config.isEmpty())result.errorCode=ErrorCode::ImportInvalidConfigError;
  return result;
 }
 QMap<int,QByteArray> m_qrCodeChunks; bool m_isQrCodeProcessed=false;
 int m_totalQrCodeChunksCount=0,m_receivedQrCodeChunksCount=0;
};
'''
suffix = r'''
static int checks=0;
void check(bool value){++checks;if(!value){std::fprintf(stderr,"failed QR parser check %d\n",checks);std::exit(1);}}
QByteArray frame(quint8 count,quint8 id,const QByteArray&payload) {
 QByteArray data;QDataStream stream(&data,QIODevice::WriteOnly);stream<<qint16(1984)<<count<<id<<payload;return data;
}
QString encoded(const QByteArray &raw){return QString::fromLatin1(raw.toBase64(QByteArray::Base64UrlEncoding|QByteArray::OmitTrailingEquals));}
int main(){
 ImportController parser;parser.startDecodingQr();
 QByteArray valid=R"({"containers":[{"owned":true}]})";
 auto first=frame(2,0,valid.left(10)),second=frame(2,1,valid.mid(10));
 check(!parser.parseQrCodeChunk(encoded(first)).success);
 check(parser.qrChunksReceived()==1&&parser.qrChunksTotal()==2);
 auto badLength=frame(2,0,"x");for(qsizetype i=4;i<8;++i)badLength[i]=char(0xff);
 for(const auto &bad:{frame(0,0,"x"),frame(2,2,"x"),frame(2,255,"x"),frame(2,0,"x").left(4),
                      frame(2,0,"x").left(8),frame(2,0,"x")+"trailing",badLength}){
  check(!parser.parseQrCodeChunk(encoded(bad)).success);
  check(parser.qrChunksReceived()==1&&parser.qrChunksTotal()==2);
 }
 auto done=parser.parseQrCodeChunk(encoded(second));check(done.success);check(done.importResult.config.contains("containers"));
 check(!parser.isQrDecodingActive());check(!parser.parseQrCodeChunk(encoded(second)).success);
 parser.startDecodingQr();check(!parser.parseQrCodeChunk(encoded(second)).success);
 check(parser.parseQrCodeChunk(encoded(first)).success);
 parser.startDecodingQr();check(!parser.parseQrCodeChunk(encoded(first)).success);
 check(!parser.parseQrCodeChunk(encoded(first)).success);check(parser.qrChunksReceived()==1);
 check(parser.parseQrCodeChunk(encoded(second)).success);
 parser.startDecodingQr();check(parser.parseQrCodeChunk(QString::fromUtf8(valid)).success);
 std::printf("actual QR parser checks: %d\n",checks);
}
'''
Path(sys.argv[2]).write_text(prefix + functions + suffix, encoding='utf8')
