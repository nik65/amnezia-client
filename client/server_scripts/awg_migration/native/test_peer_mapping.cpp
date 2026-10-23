#include "config_generation_runtime.h"
#include <json-c/json.h>
#include <iostream>
#include <stdexcept>
using namespace amnezia::awgMigration;
namespace {
unsigned count=0;
void check(bool value){++count;if(!value)throw std::runtime_error("check "+std::to_string(count));}
const std::string key=std::string(43,'B')+"=";
std::string config(const std::string &address){return "[Interface]\nPrivateKey = "+std::string(43,'A')+"=\nAddress = 10.0.0.1/24\n[Peer]\nPublicKey = "+key+"\nAllowedIPs = "+address+"\n";}
std::string request(const std::string &raw,const std::string &scope="amnezia-awg"){
 auto *r=json_object_new_object();json_object_object_add(r,"op",json_object_new_string("peer-mapping"));json_object_object_add(r,"scope",json_object_new_string(scope.c_str()));json_object_object_add(r,"source",json_object_new_string_len(raw.data(),static_cast<int>(raw.size())));
 std::string s=json_object_to_json_string_ext(r,JSON_C_TO_STRING_PLAIN);json_object_put(r);return s;
}
void rejected(const std::string &raw){bool failed=false;try{generationRuntimeRequest(raw);}catch(...){failed=true;}check(failed);}
}
int main(){try{
 check(generationRuntimeRequest("{\"op\":\"capability\"}")=="{\"result\":{\"peerMappingVersion\":1}}");
 for(const auto &address:{"10.0.0.2/32","10.0.0.2/032","10.0.0.2/255.255.255.255","10.0.0.2"}){
  auto out=generationRuntimeRequest(request(config(address)));auto*r=json_tokener_parse(out.c_str());json_object *result=nullptr,*peer=nullptr,*field=nullptr;
  check(json_object_object_get_ex(r,"result",&result));check(json_object_object_get_ex(result,key.c_str(),&peer));
  check(json_object_object_get_ex(peer,"sourceIp",&field)&&std::string(json_object_get_string(field))=="10.0.0.2");
  check(json_object_object_get_ex(peer,"clientAddress",&field)&&std::string(json_object_get_string(field))==address);json_object_put(r);
 }
 for(const auto &address:{"10.0.0.2/0.0.0.0","10.0.0.2/0","10.0.0.2/1","10.0.0.2/31","10.00.0.2/32","10.0.0.2/32,10.0.0.3/32","::1/128","10.0.0.1/32","10.1.0.2/32"})rejected(request(config(address)));
 check(generationRuntimeRequest(request(config("10.0.0.2/32"),"amnezia-awg")).find("1dd40097c1d8ecc2fc3ca8a78fbbb1db08e8d1bb13aed363250690e158312313") != std::string::npos);
 check(generationRuntimeRequest(request(config("10.0.0.2/32"),"amnezia-awg2")).find("ff81fc98bc6461990cc49a1b4722dab5d497c7e605c3525e55830d82732d0a03") != std::string::npos);
 const std::string extra="[Peer]\nPublicKey = "+std::string(43,'D')+"=\nAllowedIPs = 10.0.0.3/32\n";
 check(generationRuntimeRequest(request(config("10.0.0.2/32")+extra)).find(std::string(43,'D')+"=") != std::string::npos);
 rejected(request(config("10.0.0.2/32")+"[Peer]\nPublicKey = "+key+"\nAllowedIPs = 10.0.0.3/32\n"));
 rejected(request(config("10.0.0.2/32")+"[Peer]\nPublicKey = "+std::string(43,'D')+"=\nAllowedIPs = 10.0.0.2/32\n"));
 rejected(request("[Interface]\nPrivateKey="+std::string(43,'A')+"=\nAddress=10.0.0.1/24\n"));
 rejected(request(std::string(1024*1024+1,'x')));
 rejected(request(config("10.0.0.2/32")+std::string(1,static_cast<char>(0xff))));
 rejected(request(config("10.0.0.2/32"),"unknown"));rejected(request(config("10.0.0.2/32")+"PublicKey = "+key+"\n"));
 rejected("{\"op\":\"capability\",\"extra\":1}");rejected("{\"op\":\"capability\",\"op\":\"capability\"}");
 std::cout<<count<<" peer mapping checks passed\n";return 0;
}catch(const std::exception&e){std::cerr<<e.what()<<'\n';return 1;}}
