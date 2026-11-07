// Actual production verifyLoadedControlMain with inert syscall boundaries.
// Never opens proc, a socket, a target ELF, a namespace or a service.
#include "control_pid1.h"
#include "control_loaded.h"
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <map>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

using namespace amnezia::awgMigration::controlPid1;
namespace {
std::string expectedSha, receipt;
bool collision = false;
int unexpected = 0, procFdOpens = 0;
std::map<int, std::size_t> offsets;
std::string bytes(int fd) {
    if (fd == 100) return receipt;
    if (fd == 101) {
        std::string raw = "1 (awg-feed) S";
        for (int field=3; field<22; ++field) raw += field==21 ? " 12345" : " 0";
        return raw;
    }
    if (fd == 102) return std::string(128, collision ? 'Y' : 'X');
    if (fd == 12 && collision) return std::string(128, 'X');
    return {};
}
int denied() { ++unexpected; errno=EPERM; return -1; }
}
extern "C" {
int __wrap_open(const char *path, int, ...) {
    const std::string p(path);
    int fd=-1;
    if (p=="fixture-receipt") fd=100;
    else if (p=="/proc/1/stat") fd=101;
    else if (p=="/proc/1/fd/12") { ++procFdOpens; fd=102; }
    else return denied();
    offsets[fd]=0;
    return fd;
}
int __wrap_fstat(int fd, struct stat *out) {
    const auto data=bytes(fd);
    if (data.empty()) { errno=EBADF; return -1; }
    std::memset(out,0,sizeof(*out));
    out->st_mode=S_IFREG|(fd==100 ? 0600 : 0500);
    out->st_uid=1000; out->st_gid=1000; out->st_nlink=1;
    out->st_dev=17; out->st_ino=static_cast<ino_t>(fd); out->st_size=data.size();
    return 0;
}
ssize_t __wrap_read(int fd,void *buffer,size_t size) {
    const auto data=bytes(fd); auto &offset=offsets[fd];
    if (data.empty()) { errno=EBADF; return -1; }
    const auto count=std::min(size,data.size()-std::min(offset,data.size()));
    std::memcpy(buffer,data.data()+std::min(offset,data.size()),count); offset+=count;
    return static_cast<ssize_t>(count);
}
ssize_t __wrap_pread(int fd,void *buffer,size_t size,off_t offset) {
    const auto data=bytes(fd);
    if (data.empty()||offset<0) { errno=EBADF; return -1; }
    const auto begin=std::min(static_cast<size_t>(offset),data.size());
    const auto count=std::min(size,data.size()-begin);
    std::memcpy(buffer,data.data()+begin,count); return static_cast<ssize_t>(count);
}
int __wrap_close(int) { return 0; }
uid_t __wrap_geteuid() { return 1000; }
int __wrap_fcntl(int fd,int command,...) {
    if ((fd==102||(fd==12&&collision))&&command==F_GET_SEALS) return requiredSeals;
    return denied();
}
int __wrap_socket(int,int,int) { return denied(); }
int __wrap_bind(int,const void*,unsigned) { return denied(); }
int __wrap_listen(int,int) { return denied(); }
int __wrap_accept4(int,void*,void*,int) { return denied(); }
int __wrap_poll(void*,unsigned long,int) { return denied(); }
ssize_t __wrap_send(int,const void*,size_t,int) { return denied(); }
int __wrap_shutdown(int,int) { return denied(); }
int __wrap_uname(void*) { return denied(); }
int __wrap_memfd_create(const char*,unsigned) { return denied(); }
int __wrap_fsync(int) { return denied(); }
int __wrap_fchmod(int,unsigned) { return denied(); }
int __wrap_unlink(const char*) { return denied(); }
int __wrap_rename(const char*,const char*) { return denied(); }
ssize_t __wrap_write(int,const void*,size_t) { return denied(); }
int __wrap_dup(int) { return denied(); }
}
int main(int argc,char **argv) {
    if(argc<2) return 2;
    expectedSha=argv[1];
    receipt=receiptJson(LoadedControl{"target","12345",expectedSha,12});
    int failures=0;
    for(bool attack : {false,true}) {
        collision=attack; offsets.clear(); procFdOpens=0;
        const int result=verifyLoadedControlMain("target",expectedSha,"fixture-receipt");
        const int expected=attack ? 3 : 0;
        const bool okay=result==expected && procFdOpens>0;
        std::cout<<(attack?"wrong-process-fd-collision":"valid-pid1-held-fd")
                 <<" actual="<<result<<" expected="<<expected
                 <<" target_proc_fd_opens="<<procFdOpens<<"\n";
        if(!okay) ++failures;
    }
    if(unexpected) { std::cerr<<"unexpected OS boundary calls="<<unexpected<<"\n"; ++failures; }
    if(argc==3&&std::string(argv[2])=="--fail-work") return 23;
    return failures ? 1 : 0;
}
