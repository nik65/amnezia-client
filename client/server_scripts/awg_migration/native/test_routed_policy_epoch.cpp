#include "routed_policy_epoch.h"
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
using namespace amnezia::awgMigration;
namespace { int count=0; const std::string hash="sha256:"+std::string(64,'a');
std::string response(const std::string &body){return "HTTP/1.0 200 OK\r\nContent-Length: "+std::to_string(body.size())+"\r\n\r\n"+body;}
void test(const std::string &wire,bool accept,const std::string &revision="1",const std::string &expectedHash=hash,std::size_t chunk=17){
    ++count;std::size_t at=0;bool okay=true;try{validateRoutedPolicyEpochResponse([&](){auto value=wire.substr(at,chunk);at+=value.size();return value;},revision,expectedHash);}catch(...){okay=false;}
    if(okay!=accept)throw std::runtime_error("case "+std::to_string(count));
}
}
// No test invokes the production socket adapter.
int main(){try{
const std::string body="{\"policy\":{\"revision\":1,\"contentSha256\":\""+hash+"\"}}";
test(response(body),true);test(response(body),true,"1",hash,1);test(response(body),true,"1",hash,8192);
test(response(body),false,"01");test(response(body),false,"0");test(response(body),false,"9007199254740992");test(response(body),false,"+1");test(response(body),false,"1",std::string(64,'a'));
test(response(body),false,"2");test(response(body),false,"1","sha256:"+std::string(64,'b'));
for(const auto &rev:std::vector<std::string>{"true","1.0","1e0","-1","null","9007199254740992"})test(response("{\"policy\":{\"revision\":"+rev+",\"contentSha256\":\""+hash+"\"}}"),false);
test(response("{\"policy\":{\"revision\":2,\"revision\":1,\"contentSha256\":\""+hash+"\"}}"),false);
test(response("{\"policy\":{\"revision\":2,\"revis\\u0069on\":1,\"contentSha256\":\""+hash+"\"}}"),false);
test(response(body+"garbage"),false);test(response(body+" "),true);
test(response("{\"dns\":[\"mutable\"],\"policy\":{\"revision\":1,\"contentSha256\":\""+hash+"\"}}"),true);
test(response("{\"extra\":NaN,\"policy\":{\"revision\":1,\"contentSha256\":\""+hash+"\"}}"),false);
test(response("{\"extra\":\""+std::string(1,static_cast<char>(0xff))+"\",\"policy\":{\"revision\":1,\"contentSha256\":\""+hash+"\"}}"),false);
test(response(std::string(33,'[')+"0"+std::string(33,']')),false);
test("HTTP/1.0 302 Found\r\nContent-Length: 0\r\n\r\n",false);
test("HTTP/1.0 200 OK\r\n\r\n"+body,false);
test("HTTP/1.0 200 OK\r\nContent-Length: "+std::to_string(body.size())+"\r\ncontent-length: 0\r\n\r\n"+body,false);
test("HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n",false);
test("HTTP/1.0 200 OK\r\nContent-Length: -1\r\n\r\n",false);
test("HTTP/1.0 200 OK\r\nContent-Length: 1048577\r\n\r\n",false);
test(response(body)+"x",false);test(response(body).substr(0,response(body).size()-1),false);
test("HTTP/1.0 200 OK\r\nX: "+std::string(8192,'x')+"\r\nContent-Length: 0\r\n\r\n",false);
std::cout<<count<<" cases passed\n";return 0;
}catch(const std::exception&e){std::cerr<<e.what()<<'\n';return 1;}}
