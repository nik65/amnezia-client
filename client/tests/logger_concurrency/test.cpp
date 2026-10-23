#include "logger.h"
#include <QCoreApplication>
#include <QTemporaryDir>
#include <QSet>
#include <atomic>
#include <iostream>
#include <thread>
#include <vector>
int main(int argc,char **argv) {
 QTemporaryDir root; if(!root.isValid())return 2;
 qputenv("XDG_DATA_HOME",root.path().toUtf8());
 QCoreApplication app(argc,argv); app.setApplicationName("LoggerConcurrencyProbe");app.setOrganizationName("OwnedTest");
 if (!Logger::userLogsFilePath().startsWith(root.path()+"/")) return 4;
 if(!Logger::init(false))return 3;
 constexpr int workers=8,lines=64; std::atomic<int> ready{0};std::atomic<bool> go{false};std::vector<std::thread> threads;
 for(int t=0;t<workers;++t)threads.emplace_back([&,t]{Logger local("ConcurrentProbe");++ready;while(!go.load())std::this_thread::yield();for(int i=0;i<lines;++i){
 const auto value=QString("body=begin-%1-%2|").arg(t).arg(i)+QString(2048,QChar('a'+t))+QString("|end-%1-%2").arg(t).arg(i);
 local.info()<<value;
 }});
 while(ready.load()!=workers)std::this_thread::yield();go=true;for(auto &t:threads)t.join();
 const QString data=Logger::getLogFile();Logger::clearLogs(false);
 Logger check("PostClear");check.info()<<"after-clear";
 const bool reopened=Logger::getLogFile().contains("after-clear");
 Logger::deInit();if(!reopened)return 5;QSet<QString> bodies;int malformed=0;
 for(const auto &row:data.split('\n')){const auto at=row.indexOf("body=");if(at>=0){if(bodies.contains(row.mid(at)))++malformed;bodies.insert(row.mid(at));}}
 int missing=0;for(int t=0;t<workers;++t)for(int i=0;i<lines;++i){const auto expected=QString("body=begin-%1-%2|").arg(t).arg(i)+QString(2048,QChar('a'+t))+QString("|end-%1-%2").arg(t).arg(i);if(!bodies.contains(expected))++missing;}
 std::cerr<<"CONCURRENCY_RESULT expected="<<workers*lines<<" observed="<<bodies.size()<<" missing="<<missing<<" duplicates="<<malformed<<" bytes="<<data.size()<<"\n";
 return missing||malformed||bodies.size()!=workers*lines?42:0;
}
