#include "routed_policy_epoch.h"
#include <algorithm>
#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <iostream>
#include <poll.h>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
namespace {
int mode=0, sockets=0;std::size_t offset=0;std::string sent;
const std::string hash="sha256:"+std::string(64,'a');
const std::string body="{\"policy\":{\"revision\":1,\"contentSha256\":\""+hash+"\"}}";
std::string wire;
constexpr int fakeFd=21991;
void require(bool value){if(!value)throw std::runtime_error("transport assertion");}
}
extern "C" int __wrap_socket(int domain,int type,int protocol){
    require(domain==AF_INET && (type&SOCK_STREAM) && (type&SOCK_NONBLOCK) && (type&SOCK_CLOEXEC) && protocol==0);++sockets;return fakeFd;
}
extern "C" int __wrap_connect(int fd,const sockaddr *address,socklen_t size){
    require(fd==fakeFd && size==sizeof(sockaddr_in));auto *a=reinterpret_cast<const sockaddr_in*>(address);
    in_addr expected{};require(inet_pton(AF_INET,"172.29.172.253",&expected)==1);
    require(a->sin_family==AF_INET && a->sin_port==htons(17864) && a->sin_addr.s_addr==expected.s_addr);
    if(mode==1){errno=ECONNREFUSED;return -1;}errno=EINPROGRESS;return -1;
}
extern "C" int __wrap_getsockopt(int fd,int level,int option,void *value,socklen_t *size){
    require(fd==fakeFd&&level==SOL_SOCKET&&option==SO_ERROR&&*size==sizeof(int));*static_cast<int*>(value)=0;return 0;
}
extern "C" int __wrap_poll(pollfd *fds,nfds_t count,int timeout){
    require(count==1&&fds[0].fd==fakeFd&&timeout>0);
    if(mode==2)return 0;
    if(mode==3)usleep(static_cast<useconds_t>(std::min(timeout,100)*1000));
    fds[0].revents=fds[0].events;return 1;
}
extern "C" ssize_t __wrap_send(int fd,const void *buffer,size_t size,int flags){
    require(fd==fakeFd&&flags==MSG_NOSIGNAL);if(mode==4){errno=EPIPE;return -1;}
    auto n=std::min<std::size_t>(size,7);sent.append(static_cast<const char*>(buffer),n);return static_cast<ssize_t>(n);
}
extern "C" ssize_t __wrap_recv(int fd,void *buffer,size_t size,int flags){
    require(fd==fakeFd&&flags==0);auto n=std::min<std::size_t>({size,wire.size()-offset,mode==3?1U:11U});
    std::memcpy(buffer,wire.data()+offset,n);offset+=n;return static_cast<ssize_t>(n);
}
extern "C" int __real_close(int);
extern "C" int __wrap_close(int fd){if(fd==fakeFd)return 0;return __real_close(fd);}
int main(){try{
    for(mode=0;mode<=6;++mode){
        offset=0;sent.clear();wire="HTTP/1.0 200 OK\r\nContent-Length: "+std::to_string(body.size())+"\r\n\r\n"+body;
        if(mode==5) { wire+='x'; }
        if(mode==6) { wire.pop_back(); }
        const auto start=std::chrono::steady_clock::now();auto result=amnezia::awgMigration::checkRoutedPolicyEpochMain("1",hash);
        auto elapsed=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-start).count();
        require(result==(mode==0?0:2));
        if(mode==0||mode>=5)require(sent=="GET /rules.json HTTP/1.0\r\nHost: 172.29.172.253:17864\r\nConnection: close\r\n\r\n");
        if(mode==3)require(elapsed>=4900&&elapsed<6100);
    }
    const auto prior=sockets;require(amnezia::awgMigration::checkRoutedPolicyEpochMain("01",hash)==2);require(sockets==prior);
    std::cout<<"8 transport cases passed\n";return 0;
}catch(const std::exception&e){std::cerr<<e.what()<<'\n';return 1;}}
