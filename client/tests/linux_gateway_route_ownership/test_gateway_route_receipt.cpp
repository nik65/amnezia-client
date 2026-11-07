
#ifdef NDEBUG
#error "Ownership regression assertions must remain enabled"
#endif
#include "../../platforms/linux/daemon/linuxgatewayroutereceipt.h"
#include <cassert>
#include <vector>
#include <iostream>
using namespace amnezia::linux_routes;
using Bytes = std::vector<unsigned char>;
static constexpr uint32_t Seq = 71, Port = 1234;
static RouteReceipt receipt() { RouteReceipt r; r.priority=0; r.destination = 0x01020304; r.gateway = 0x05060708; r.interfaceIndex = 9; r.prefixLength = 32; return r; }
template<class T> static void append(Bytes &b, const T &v) { const auto *p = reinterpret_cast<const unsigned char *>(&v); b.insert(b.end(), p, p + sizeof(v)); }
static void attr(Bytes &b, uint16_t kind, uint32_t value) { rtattr a{}; a.rta_type = kind; a.rta_len = RTA_LENGTH(4); append(b,a); append(b,value); }
static Bytes message(uint16_t type, Bytes body = {}, uint16_t flags = NLM_F_MULTI) { nlmsghdr h{}; h.nlmsg_len = NLMSG_LENGTH(body.size()); h.nlmsg_type = type; h.nlmsg_flags = flags; h.nlmsg_seq = Seq; h.nlmsg_pid = Port; Bytes b; append(b,h); b.insert(b.end(),body.begin(),body.end()); b.resize(NLMSG_ALIGN(b.size())); return b; }
static Bytes route(RouteReceipt v = receipt(), bool gateway = true, bool oif = true, bool metric = false, bool overrideTable = false) { rtmsg r{}; r.rtm_family = AF_INET; r.rtm_dst_len = v.prefixLength; r.rtm_protocol = v.protocol; r.rtm_scope = v.scope; r.rtm_type = v.type; r.rtm_table = overrideTable ? RT_TABLE_UNSPEC : v.table; Bytes b; append(b,r); attr(b,RTA_DST,v.destination); if(gateway) attr(b,RTA_GATEWAY,v.gateway); if(oif) attr(b,RTA_OIF,v.interfaceIndex); if(metric) attr(b,RTA_PRIORITY,v.priority); if(overrideTable) attr(b,RTA_TABLE,v.table); return message(RTM_NEWROUTE,b); }
static Bytes done(int code = 0) { Bytes b; append(b,code); return message(NLMSG_DONE,b); }
static void join(Bytes &a, const Bytes &b) { a.insert(a.end(),b.begin(),b.end()); }
static void complete(RouteDumpParser &p) { auto d=done(); assert(p.consume(d.data(),d.size())); }
static void checkUnknown(Bytes b, uint32_t sender=0,int flags=0) { RouteDumpParser p(receipt(),Seq,Port); assert(!p.consume(b.data(),b.size(),sender,flags)); assert(p.result()==ReadbackResult::Unknown); assert(!p.complete()); }
int main() {
    static_assert(OwnedGatewayRoutePriority == 1 && TunnelRoutePriority == 2);
    static_assert(RouteReceipt{}.priority == OwnedGatewayRoutePriority);
    { auto own=receipt();own.priority=OwnedGatewayRoutePriority;auto foreign=own;foreign.priority=5;RouteDumpParser p(own,Seq,Port);auto b=route(foreign,true,true,true);join(b,route(own,true,true,true));assert(p.consume(b.data(),b.size()));complete(p);assert(p.result()==ReadbackResult::Match); }

    { RouteDumpParser p(receipt(),Seq,Port); assert(p.result()==ReadbackResult::Unknown); auto b=route(); assert(p.consume(b.data(),b.size())); assert(p.result()==ReadbackResult::Unknown); complete(p); assert(p.result()==ReadbackResult::Match); }
    { RouteDumpParser p(receipt(),Seq,Port); auto b=route(receipt(),true,true,true,true); join(b,done()); assert(p.consume(b.data(),b.size())); assert(p.result()==ReadbackResult::Match); }
    { RouteDumpParser p(receipt(),Seq,Port); complete(p); assert(p.result()==ReadbackResult::Absent); }
    for(int field=0;field<8;++field) { auto r=receipt(); switch(field) {case 0:++r.gateway;break;case 1:++r.interfaceIndex;break;case 2:++r.priority;break;case 3:++r.protocol;break;case 4:++r.scope;break;case 5:++r.type;break;case 6:break;case 7:break;} auto b=route(r,field!=6,field!=7,true); RouteDumpParser p(receipt(),Seq,Port); assert(p.consume(b.data(),b.size())); complete(p); assert(p.result()==(field==2 ? ReadbackResult::Absent : ReadbackResult::Changed)); }
    for(int field=0;field<3;++field) { auto r=receipt(); if(field==0)++r.destination; if(field==1)--r.prefixLength; if(field==2)r.table=RT_TABLE_LOCAL; auto b=route(r); RouteDumpParser p(receipt(),Seq,Port); assert(p.consume(b.data(),b.size())); complete(p); assert(p.result()==ReadbackResult::Absent); }
    { auto b=route();join(b,route());checkUnknown(b); }
    { auto b=route(); auto *h=reinterpret_cast<nlmsghdr *>(b.data()); attr(b,RTA_GATEWAY,receipt().gateway); h=reinterpret_cast<nlmsghdr *>(b.data()); h->nlmsg_len=b.size(); checkUnknown(b); }
    { auto b=route();reinterpret_cast<nlmsghdr *>(b.data())->nlmsg_seq++;checkUnknown(b); }
    { auto b=route();reinterpret_cast<nlmsghdr *>(b.data())->nlmsg_pid=0;checkUnknown(b); }
    checkUnknown(route(),1); checkUnknown(route(),0,MSG_TRUNC); checkUnknown(route(),0,MSG_CTRUNC);
    { auto b=route();reinterpret_cast<nlmsghdr *>(b.data())->nlmsg_flags|=NLM_F_DUMP_INTR;checkUnknown(b); }
    { auto b=done();reinterpret_cast<nlmsghdr *>(b.data())->nlmsg_flags|=NLM_F_DUMP_INTR;checkUnknown(b); }
    { auto b=done();reinterpret_cast<nlmsghdr *>(b.data())->nlmsg_flags|=NLM_F_DUMP_FILTERED;checkUnknown(b); }
    { Bytes body;int status=0;append(body,status);body.push_back(42);checkUnknown(message(NLMSG_DONE,body)); }
    checkUnknown(done(-5)); checkUnknown(message(NLMSG_ERROR));
    { auto b=route();b.pop_back();checkUnknown(b); }
    { auto b=route();reinterpret_cast<nlmsghdr *>(b.data())->nlmsg_len=4;checkUnknown(b); }
    { auto b=route();auto *a=reinterpret_cast<rtattr *>(b.data()+NLMSG_HDRLEN+sizeof(rtmsg));a->rta_len=3;checkUnknown(b); }
    { auto b=route();auto *a=reinterpret_cast<rtattr *>(b.data()+NLMSG_HDRLEN+sizeof(rtmsg));a->rta_len=1000;checkUnknown(b); }
    { auto b=done();join(b,route());checkUnknown(b); }
    { RouteDumpParser p(receipt(),Seq,Port);complete(p);auto b=done();assert(!p.consume(b.data(),b.size()));assert(p.result()==ReadbackResult::Unknown); }
    { Bytes b(1024*1024+1);checkUnknown(b); }
    { auto b=message(NLMSG_NOOP);Bytes many;for(int i=0;i<16385;++i)join(many,b);checkUnknown(many); }
    // Well formed IPv6 routes never count as IPv4 candidates.
    { rtmsg r{};r.rtm_family=AF_INET6;r.rtm_dst_len=128;Bytes body;append(body,r);auto b=message(RTM_NEWROUTE,body);RouteDumpParser p(receipt(),Seq,Port);assert(p.consume(b.data(),b.size()));complete(p);assert(p.result()==ReadbackResult::Absent); }
    // Attribute shape, relevant duplicates and non-ownable variants fail closed.
    for(uint16_t kind : {uint16_t(RTA_DST),uint16_t(RTA_OIF),uint16_t(RTA_PRIORITY),uint16_t(RTA_TABLE)}) {
        auto b=route(receipt(),true,true,true,true); attr(b,kind,0);
        reinterpret_cast<nlmsghdr *>(b.data())->nlmsg_len=b.size(); checkUnknown(b);
    }
    { auto b=route(); auto *a=reinterpret_cast<rtattr *>(b.data()+NLMSG_HDRLEN+sizeof(rtmsg)); a->rta_len=RTA_LENGTH(3); checkUnknown(b); }
    { Bytes body(1);checkUnknown(message(NLMSG_DONE,body)); }
    { Bytes body(sizeof(rtmsg)-1);checkUnknown(message(RTM_NEWROUTE,body)); }
    { auto b=route(); b.push_back(0); reinterpret_cast<nlmsghdr *>(b.data())->nlmsg_len=b.size();checkUnknown(b); }
    for(uint16_t kind : {uint16_t(RTA_MULTIPATH),uint16_t(RTA_VIA),uint16_t(RTA_NH_ID),uint16_t(RTA_SRC),uint16_t(RTA_IIF)}) {
        auto b=route();attr(b,kind,0);reinterpret_cast<nlmsghdr *>(b.data())->nlmsg_len=b.size();
        RouteDumpParser p(receipt(),Seq,Port);assert(p.consume(b.data(),b.size()));complete(p);assert(p.result()==ReadbackResult::Changed);
    }
    { auto r=receipt();r.destination=0;r.prefixLength=0;auto b=route(r);RouteDumpParser p(r,Seq,Port);assert(p.consume(b.data(),b.size()));complete(p);assert(p.result()==ReadbackResult::Match); }
    { auto b=route();reinterpret_cast<rtmsg *>(b.data()+NLMSG_HDRLEN)->rtm_tos=4;RouteDumpParser p(receipt(),Seq,Port);assert(p.consume(b.data(),b.size()));complete(p);assert(p.result()==ReadbackResult::Absent); }
    // Distinct FIB keys coexist without defeating ownership of metric zero.
    {
        auto foreign=receipt();foreign.priority=10;
        auto b=route(foreign,true,true,true);join(b,route());
        RouteDumpParser p(receipt(),Seq,Port);assert(p.consume(b.data(),b.size()));
        complete(p);assert(p.result()==ReadbackResult::Match);
    }
    {
        auto foreign=receipt();foreign.priority=10;
        auto b=route(foreign,true,true,true);
        RouteDumpParser p(receipt(),Seq,Port);assert(p.consume(b.data(),b.size()));
        complete(p);assert(p.result()==ReadbackResult::Absent);
    }
    {
        auto b=route();reinterpret_cast<rtmsg *>(b.data()+NLMSG_HDRLEN)->rtm_src_len=24;
        join(b,route());RouteDumpParser p(receipt(),Seq,Port);
        assert(p.consume(b.data(),b.size()));complete(p);assert(p.result()==ReadbackResult::Match);
    }
    // A realistic full main-table dump remains bounded and spans recvmsg datagrams.
    {
        RouteDumpParser p(receipt(),Seq,Port);
        Bytes datagram;
        size_t totalBytes=0, datagrams=0;
        constexpr size_t DatagramLimit=32*1024;
        const auto feed = [&]() {
            assert(!datagram.empty() && datagram.size()<=DatagramLimit);
            totalBytes+=datagram.size();++datagrams;
            assert(p.consume(datagram.data(),datagram.size()));datagram.clear();
        };
        for(uint32_t i=0;i<1254;++i) {
            auto r=receipt();
            if(i<1253)r.destination=0x10000000+i;
            const auto b=route(r);
            if(datagram.size()+b.size()>DatagramLimit)feed();
            join(datagram,b);
        }
        if(!datagram.empty())feed();
        const auto d=done();totalBytes+=d.size();
        assert(totalBytes<1024*1024 && datagrams>=2);
        assert(p.consume(d.data(),d.size()));assert(p.complete());
        assert(p.result()==ReadbackResult::Match);
    }
    std::cout << "gateway route receipt fixtures: PASS\n";
}






