#include <android/multinetwork.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <poll.h>
#include <unistd.h>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <csignal>
#include <cerrno>
#include <climits>
static volatile sig_atomic_t stopping=0;
static void stop(int){stopping=1;}
static bool number(const char* text,unsigned long long& value){
 if(!text||!*text||*text=='-'||*text=='+')return false;
 char* end=nullptr;errno=0;value=strtoull(text,&end,10);
 return errno==0&&end&&!*end;
}
int main(int argc,char**argv){
 if(argc!=5)return 2;
 unsigned long long parsedNetwork=0,parsedPort=0,parsedSeconds=0;
 if(!number(argv[1],parsedNetwork)||!number(argv[3],parsedPort)||!number(argv[4],parsedSeconds)||
    parsedNetwork==0||parsedPort>UINT_MAX||parsedSeconds>UINT_MAX)return 2;
 const auto network=static_cast<net_handle_t>(parsedNetwork);
 const unsigned port=static_cast<unsigned>(parsedPort),seconds=static_cast<unsigned>(parsedSeconds);
 // An explicit zero keeps the diagnostic relay alive until signalled/device reboot.
 if(port<1024||port>65535||seconds>3600)return 2;
 int local=socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK,0),remote=socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK,0);
 if(local<0||remote<0)return 3;
 if(android_setsocknetwork(network,remote)){perror("bind mobile network");return 3;}
 sockaddr_in l{};l.sin_family=AF_INET;l.sin_port=htons(port);l.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
 sockaddr_in r{};r.sin_family=AF_INET;r.sin_port=htons(53);if(inet_pton(AF_INET,argv[2],&r.sin_addr)!=1)return 2;
 if(bind(local,reinterpret_cast<sockaddr*>(&l),sizeof(l))||connect(remote,reinterpret_cast<sockaddr*>(&r),sizeof(r))){perror("socket setup");return 3;}
 signal(SIGTERM,stop);signal(SIGINT,stop);
 auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(seconds);
 sockaddr_in peer{};bool havePeer=false;unsigned long queries=0,answers=0,errors=0;
 while(!stopping&&(seconds==0||std::chrono::steady_clock::now()<deadline)){
  pollfd p[2]={{local,POLLIN,0},{remote,POLLIN,0}};if(poll(p,2,250)<0)continue;
  unsigned char b[4096];
  if(p[0].revents&POLLIN){sockaddr_in sender{};socklen_t n=sizeof(sender);ssize_t size=recvfrom(local,b,sizeof(b),0,reinterpret_cast<sockaddr*>(&sender),&n);
   if(size<12||sender.sin_addr.s_addr!=htonl(INADDR_LOOPBACK))continue;
   if(havePeer&&sender.sin_port!=peer.sin_port)continue;
   peer=sender;havePeer=true;if(send(remote,b,size,0)==size)++queries;else ++errors;
  }
  if(p[1].revents&(POLLIN|POLLERR)){ssize_t size=recv(remote,b,sizeof(b),0);if(size>=12&&havePeer){if(sendto(local,b,size,0,reinterpret_cast<sockaddr*>(&peer),sizeof(peer))==size)++answers;else ++errors;}else ++errors;}
 }
 printf("network=%llu resolver=%s queries=%lu responses=%lu errors=%lu\n",(unsigned long long)network,argv[2],queries,answers,errors);
 close(local);close(remote);return 0;
}
