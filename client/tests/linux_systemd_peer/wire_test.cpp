#include "ipc/linuxsystemdpeer.cpp"
#include <atomic>
#include <cassert>
#include <iostream>
#include <thread>
#include <QFile>
#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>
using namespace amnezia::ipc::linuxSystemd;
int main() {
  QFile fixture(EXECSTART_ACCOUNTING_FIXTURE);assert(fixture.open(QIODevice::ReadOnly));
  const auto observed=QJsonDocument::fromJson(fixture.readAll()).object();
  assert(observed.value("signature").toString()=="a(sasbttttuii)");
  const auto tuple=observed.value("tuple").toArray();assert(tuple.size()==10);
  assert(tuple[0].toString()==QString::fromLatin1(executable));
  assert(tuple[1].toArray().size()==1 && tuple[1].toArray()[0].toString()==QString::fromLatin1(executable));
  assert(tuple[2].isBool() && !tuple[2].toBool());
  for(int i=3;i<10;++i)assert(tuple[i].toDouble()==0);
  for(int mode=0;mode<20;++mode) {
    int f[2];assert(socketpair(AF_UNIX,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0,f)==0);
    std::atomic<bool> stop=false;
    std::thread peer([&]{
      sd_bus *s=nullptr;assert(sd_bus_new(&s)>=0);
      sd_id128_t id=SD_ID128_NULL;assert(sd_id128_randomize(&id)>=0);
      assert(sd_bus_set_fd(s,f[1],f[1])>=0);assert(sd_bus_set_server(s,1,id)>=0);assert(sd_bus_start(s)>=0);
      while(!stop) {
        sd_bus_message *m=nullptr;int r=sd_bus_process(s,&m);if(r<0)break;
        if(m) {
          sd_bus_message *reply=nullptr;assert(sd_bus_message_new_method_return(m,&reply)>=0);
          const char *member=sd_bus_message_get_member(m);
          assert(sd_bus_message_set_sender(reply,mode==1?":1.999":!strcmp(member,"GetAll")?":1.42":"org.freedesktop.DBus")>=0);
          if(!strcmp(member,"Hello"))assert(sd_bus_message_append(reply,"s",":1.8")>=0);
          else if(!strcmp(member,"GetNameOwner"))assert(sd_bus_message_append(reply,"s",mode==4?"forged-not-unique":":1.42")>=0);
          else if(!strcmp(member,"GetConnectionUnixUser"))assert(sd_bus_message_append(reply,"u",mode==2?uint32_t(1000):uint32_t(0))>=0);
          else if(!strcmp(member,"GetConnectionUnixProcessID"))assert(sd_bus_message_append(reply,"u",mode==3?uint32_t(999):uint32_t(1))>=0);
          else if(!strcmp(member,"GetAll")) {
            assert(sd_bus_message_open_container(reply,'a',"{sv}")>=0);
            if(mode<=8 || mode>=13) {
              assert(sd_bus_message_open_container(reply,'e',"sv")>=0);
              assert(sd_bus_message_append(reply,"s","ExecStart")>=0);
              if(mode==8) {
                assert(sd_bus_message_open_container(reply,'v',"s")>=0);
                assert(sd_bus_message_append(reply,"s","forged")>=0);
              } else {
                assert(sd_bus_message_open_container(reply,'v',"a(sasbttttuii)")>=0);
                assert(sd_bus_message_open_container(reply,'a',"(sasbttttuii)")>=0);
                for(int j=0;j<(mode==6?0:mode==7?2:1);++j) {
                  assert(sd_bus_message_open_container(reply,'r',"sasbttttuii")>=0);
                  assert(sd_bus_message_append(reply,"s",executable)>=0);
                  assert(sd_bus_message_open_container(reply,'a',"s")>=0);
                  assert(sd_bus_message_append(reply,"s",executable)>=0);
                  assert(sd_bus_message_close_container(reply)>=0);
                  // Mode13 reconstructs exactly the observed absent accounting;
                  // remaining modes reject partial/contradictory accounting.
                  const bool absent=mode>=13;
                  const uint64_t realStart=absent?(mode==14?1:0):1;
                  const uint64_t monoStart=absent?(mode==19?1:0):2;
                  const uint64_t realEnd=mode==16?1:0;
                  const uint32_t pid=absent?(mode==15?123:0):123;
                  const int code=mode==17?1:0,status=mode==18?1:0;
                  assert(sd_bus_message_append(reply,"bttttuii",0,realStart,monoStart,realEnd,uint64_t(0),pid,code,status)>=0);
                  assert(sd_bus_message_close_container(reply)>=0);
                }
                assert(sd_bus_message_close_container(reply)>=0);
              }
              assert(sd_bus_message_close_container(reply)>=0);
              assert(sd_bus_message_close_container(reply)>=0);
            } else if(mode<=11) {
              assert(sd_bus_message_open_container(reply,'e',"sv")>=0);
              assert(sd_bus_message_append(reply,"s","Job")>=0);
              assert(sd_bus_message_open_container(reply,'v',"(uo)")>=0);
              assert(sd_bus_message_append(reply,"(uo)",uint32_t(mode==10?1:0),mode==11?"/foreign":"/")>=0);
              assert(sd_bus_message_close_container(reply)>=0);
              assert(sd_bus_message_close_container(reply)>=0);
            } else {
              for(int j=0;j<2;++j) {
                assert(sd_bus_message_open_container(reply,'e',"sv")>=0);
                assert(sd_bus_message_append(reply,"s","MainPID")>=0);
                assert(sd_bus_message_open_container(reply,'v',"u")>=0);
                assert(sd_bus_message_append(reply,"u",uint32_t(123))>=0);
                assert(sd_bus_message_close_container(reply)>=0);
                assert(sd_bus_message_close_container(reply)>=0);
              }
            }
            assert(sd_bus_message_close_container(reply)>=0);
          }
          else assert(false);
          assert(sd_bus_send(s,reply,nullptr)>=0);sd_bus_message_unref(reply);sd_bus_message_unref(m);
        }
        if(r==0){pollfd p{sd_bus_get_fd(s),short(sd_bus_get_events(s)),0};poll(&p,1,1);}
      }
      sd_bus_close(s);sd_bus_unref(s);
    });
    bool ownerOk=false, identityOk=false, propertiesOk=false;
    {
      AsyncBus b(monotonicUsec()+150000);assert(b.start(f[0]));
      const auto owner=managerOwner(b);ownerOk=!owner.isEmpty();
      if(ownerOk)identityOk=managerIdentity(b,owner);
      if(mode>=5) { Snapshot snap; propertiesOk=properties(b,owner,mode<=8||mode==12||mode>=13,snap);
        if(mode==13){assert(snap.execAccountingAbsent);assert(snap.execPid==0);assert(snap.execStartMonotonic==0);}
      }
    }
    stop=true;peer.join();
    assert(identityOk==(mode==0||mode>=5));
    if(mode>=5)assert(propertiesOk==(mode==5||mode==9||mode==13));
    if(mode==1||mode==4)assert(!ownerOk);
    std::cout<<"mode="<<mode<<" owner="<<ownerOk<<" identity="<<identityOk<<" properties="<<propertiesOk<<"\n";
  }
}
