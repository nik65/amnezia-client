#include "profileStore.h"
#include "rollbackCoordinator.h"
#include <QCoreApplication>
#include <QTemporaryDir>
#include <QLockFile>
#include <QFile>
#include <cassert>
#include <iostream>
using namespace amnezia::headless;
QByteArray read(const QString &p){QFile f(p);assert(f.open(QIODevice::ReadOnly));return f.readAll();}
int main(int argc,char **argv){QCoreApplication app(argc,argv);QTemporaryDir temp;assert(temp.isValid());QString path=temp.path()+"/profiles.json";ProfileStore store(path);assert(store.load());Profile p;p.id="owned";p.name="Owned";p.protocol="wireguard";p.configPath=temp.path()+"/owned.conf";
QLockFile lock(RollbackCoordinator::profileWriterLockPath(path));lock.setStaleLockTime(0);assert(lock.tryLock(0));assert(!store.add(p));assert(!QFile::exists(path));assert(store.profiles().isEmpty());lock.unlock();assert(store.add(p));auto bytes=read(path);assert(lock.tryLock(0));assert(!store.remove(p.id));assert(read(path)==bytes);assert(store.contains(p.id));lock.unlock();assert(store.remove(p.id));ProfileStore reload(path);assert(reload.load());assert(reload.profiles().isEmpty());std::cout<<"actual ProfileStore shared lock checks=14\n";}
