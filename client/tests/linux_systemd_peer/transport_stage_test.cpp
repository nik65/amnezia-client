#include "linuxsystemdbustransport.h"
#include <sys/socket.h>
#include <atomic>
#include <cassert>
#include <cstring>
#include <iostream>
#include <thread>
using namespace amnezia::ipc::linuxSystemd;
int main() {
  for (int mode=0; mode<2; ++mode) {
    int f[2]; assert(socketpair(AF_UNIX, SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0,f)==0);
    std::atomic<bool> stop=false;
    std::atomic<int> hello=0, calls=0;
    std::thread peer([&] {
      sd_bus *s=nullptr; assert(sd_bus_new(&s)>=0);
      sd_id128_t id=SD_ID128_NULL; assert(sd_id128_randomize(&id)>=0);
      assert(sd_bus_set_fd(s,f[1],f[1])>=0);
      assert(sd_bus_set_server(s,1,id)>=0); assert(sd_bus_start(s)>=0);
      while(!stop) {
        sd_bus_message *m=nullptr;
        int r=sd_bus_process(s,&m);
        if(r<0) break;
        if(m) {
          if(sd_bus_message_is_method_call(m,"org.freedesktop.DBus","Hello")>0) {
            ++hello;
            if(mode==1) assert(sd_bus_reply_method_return(m,"s",":1.8")>=0);
          } else ++calls;
          sd_bus_message_unref(m);
        }
        if(r==0) { pollfd p{sd_bus_get_fd(s),short(sd_bus_get_events(s)),0}; poll(&p,1,1); }
      }
      sd_bus_close(s); sd_bus_unref(s);
    });
    auto start=monotonicUsec();
    bool ready=false, replied=false;
    {
      AsyncBus b(start+100000);
      ready=b.start(f[0]);
      if(ready) {
        sd_bus_message *m=nullptr;
        assert(sd_bus_message_new_method_call(b.get(),&m,"org.example.Stall","/org/example/Stall","org.example.Stall","Wait")>=0);
        auto *reply=b.request(m); replied=reply!=nullptr;
        sd_bus_message_unref(reply); sd_bus_message_unref(m);
      }
    }
    auto elapsed=monotonicUsec()-start;
    stop=true; peer.join();
    assert(!replied && elapsed<200000 && hello>0);
    assert(ready==(mode==1));
    if(mode==1) assert(calls>0);
    std::cout<<"mode="<<mode<<" hello="<<hello<<" calls="<<calls<<" ready="<<ready<<" bounded_usec="<<elapsed<<"\n";
  }
}
