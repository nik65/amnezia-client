#include "routed_policy_epoch.h"
#include "policy.h"
#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <climits>
#include <cstdint>
#include <iostream>
#include <map>
#include <memory>
#include <set>
#include <stdexcept>
#include <vector>
#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <rapidjson/reader.h>
#include <rapidjson/memorystream.h>
namespace amnezia::awgMigration {
namespace {
constexpr std::size_t headerLimit=8192, bodyLimit=1024*1024;
[[noreturn]] void reject() { throw std::runtime_error("client_policy_feed_epoch_changed"); }
void expected(const std::string &revision,const std::string &hash) {
    if (revision.empty() || revision.size()>16 || revision[0]=='0') reject();
    std::uint64_t n=0;
    for (unsigned char c:revision) { if(c<'0'||c>'9') reject(); n=n*10+c-'0'; }
    if (!n || n>9007199254740991ULL || hash.size()!=71 || hash.compare(0,7,"sha256:")!=0) reject();
    for (std::size_t i=7;i<hash.size();++i) if(!((hash[i]>='0'&&hash[i]<='9')||(hash[i]>='a'&&hash[i]<='f'))) reject();
}
struct Strict : rapidjson::BaseReaderHandler<rapidjson::UTF8<>,Strict> {
    std::vector<std::set<std::string>> stack;
    bool StartObject() { if(stack.size()>=32)return false;stack.emplace_back();return true; }
    bool StartArray() { return StartObject(); }
    bool EndObject(rapidjson::SizeType) { stack.pop_back();return true; }
    bool EndArray(rapidjson::SizeType n) { return EndObject(n); }
    bool String(const char*p,rapidjson::SizeType n,bool) { return std::string(p,n).find('\0')==std::string::npos; }
    bool Key(const char*p,rapidjson::SizeType n,bool) { return std::string(p,n).find('\0')==std::string::npos && stack.back().insert(std::string(p,n)).second; }
};
void bodyEpoch(const std::string &body,const std::string &revision,const std::string &hash) {
    if(body.empty()||body.size()>bodyLimit||body.find('\0')!=std::string::npos)reject();
    rapidjson::MemoryStream stream(body.data(),body.size());rapidjson::Reader parser;Strict strict;
    if(!parser.Parse<rapidjson::kParseValidateEncodingFlag>(stream,strict)||stream.Tell()!=body.size())reject();
    auto epoch=policy::clientPolicyEpoch(true,body);
    if(!epoch || epoch->revision<1 || epoch->revision>9007199254740991LL || std::to_string(epoch->revision)!=revision || epoch->contentSha256!=hash)reject();
}
struct Fd { int value=-1; ~Fd(){if(value>=0)::close(value);} };
using Clock=std::chrono::steady_clock;
void waitFd(int fd,short events,Clock::time_point end) {
    for(;;) {
        auto left=std::chrono::duration_cast<std::chrono::milliseconds>(end-Clock::now()).count();
        if(left<=0)reject();
        pollfd p{fd,events,0};int result=::poll(&p,1,static_cast<int>(std::min<long long>(left,INT_MAX)));
        if(result<0&&errno==EINTR)continue;
        if(result<=0 || (p.revents&POLLNVAL))reject();
        if(p.revents&(events|POLLHUP|POLLERR))return;
    }
}
void production(const std::string &revision,const std::string &hash) {
    expected(revision,hash);
    const auto end=Clock::now()+std::chrono::seconds(5);
    Fd fd;fd.value=::socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK,0);if(fd.value<0)reject();
    sockaddr_in address{};address.sin_family=AF_INET;address.sin_port=htons(17864);
    if(::inet_pton(AF_INET,"172.29.172.253",&address.sin_addr)!=1)reject();
    if(::connect(fd.value,reinterpret_cast<sockaddr*>(&address),sizeof(address))<0) {
        if(errno!=EINPROGRESS) { reject(); }
        waitFd(fd.value,POLLOUT,end);int error=0;socklen_t n=sizeof(error);
        if(::getsockopt(fd.value,SOL_SOCKET,SO_ERROR,&error,&n)<0||error)reject();
    }
    const std::string request="GET /rules.json HTTP/1.0\r\nHost: 172.29.172.253:17864\r\nConnection: close\r\n\r\n";
    std::size_t sent=0;
    while(sent<request.size()) {
        waitFd(fd.value,POLLOUT,end);auto n=::send(fd.value,request.data()+sent,request.size()-sent,MSG_NOSIGNAL);
        if(n<0&&(errno==EINTR||errno==EAGAIN||errno==EWOULDBLOCK)) { continue; }
        if(n<=0) { reject(); }
        sent+=static_cast<std::size_t>(n);
    }
    validateRoutedPolicyEpochResponse([&](){
        std::array<char,8192> buffer{};
        for(;;) {waitFd(fd.value,POLLIN,end);auto n=::recv(fd.value,buffer.data(),buffer.size(),0);
            if(n<0&&(errno==EINTR||errno==EAGAIN||errno==EWOULDBLOCK))continue;
            if(n<0) { reject(); }
            return std::string(buffer.data(),static_cast<std::size_t>(n));}
    },revision,hash);
}
}
void validateRoutedPolicyEpochResponse(const PolicyEpochReader &reader,const std::string &revision,const std::string &hash) {
    expected(revision,hash);std::string input;std::size_t split=std::string::npos;
    while((split=input.find("\r\n\r\n"))==std::string::npos) {
        auto next=reader();if(next.empty()||next.size()>8192||input.size()+next.size()>headerLimit+bodyLimit)reject();input+=next;
        split=input.find("\r\n\r\n");if(split==std::string::npos&&input.size()>headerLimit)reject();
    }
    if(split+4>headerLimit)reject();
    auto first=input.find("\r\n");if(first==std::string::npos)reject();
    const auto status=input.substr(0,first);if(status!="HTTP/1.0 200 OK"&&status!="HTTP/1.1 200 OK")reject();
    std::map<std::string,std::string> headers;std::size_t at=first+2;
    while(at<split) {
        auto end=input.find("\r\n",at);if(end==std::string::npos||end>split)reject();auto line=input.substr(at,end-at);auto colon=line.find(':');if(colon==0||colon==std::string::npos)reject();
        auto key=line.substr(0,colon);for(char &c:key){unsigned char u=static_cast<unsigned char>(c);if(!((u>='a'&&u<='z')||(u>='A'&&u<='Z')||(u>='0'&&u<='9')||std::string("!#$%&'*+-.^_`|~").find(c)!=std::string::npos))reject();if(c>='A'&&c<='Z')c=static_cast<char>(c-'A'+'a');}
        auto value=line.substr(colon+1);for(unsigned char c:value)if((c<32&&c!='\t')||c>=127)reject();
        auto begin=value.find_first_not_of(" \t");auto last=value.find_last_not_of(" \t");value=begin==std::string::npos?"":value.substr(begin,last-begin+1);
        if(!headers.emplace(key,value).second) { reject(); }
        at=end+2;
    }
    if(headers.count("transfer-encoding")||!headers.count("content-length"))reject();
    const auto lengthText=headers.at("content-length");if(lengthText.empty()||lengthText.size()>7)reject();std::size_t length=0;
    for(unsigned char c:lengthText){if(c<'0'||c>'9')reject();length=length*10+c-'0';}if(length>bodyLimit)reject();
    std::string body=input.substr(split+4);if(body.size()>length)reject();
    while(body.size()<length){auto next=reader();if(next.empty()||next.size()>8192||next.size()>length-body.size())reject();body+=next;}
    if(!reader().empty()) { reject(); }
    bodyEpoch(body,revision,hash);
}
int routedPolicyEpochCapabilityMain(){std::cout<<"{\"result\":{\"policyEpochVersion\":1}}\n";return 0;}
int checkRoutedPolicyEpochMain(const std::string &revision,const std::string &hash){try{production(revision,hash);return 0;}catch(...){return 2;}}
}
