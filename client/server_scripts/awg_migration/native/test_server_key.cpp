// Public RFC7748 section6.1 vectors: https://www.rfc-editor.org/rfc/rfc7748.html#section-6.1
#include "config_generation_runtime.h"
#include <json-c/json.h>
#include <iostream>
#include <stdexcept>
using namespace amnezia::awgMigration;
namespace {
unsigned count=0;
void check(bool value){++count;if(!value)throw std::runtime_error("check "+std::to_string(count));}
std::string request(const std::string &key){
 auto *root=json_object_new_object();json_object_object_add(root,"op",json_object_new_string("server-key"));
 const std::string config="[Interface]\nPrivateKey="+key+"\nAddress=10.0.0.1/24\n[Peer]\nPublicKey="+std::string(43,'B')+"=\nAllowedIPs=10.0.0.2/32\n";
 json_object_object_add(root,"source",json_object_new_string_len(config.data(),static_cast<int>(config.size())));
 const std::string raw=json_object_to_json_string_ext(root,JSON_C_TO_STRING_PLAIN);json_object_put(root);return raw;
}
void rejects(const std::string &raw){bool rejected=false;try{generationRuntimeRequest(raw);}catch(...){rejected=true;}check(rejected);}
}
int main(){try{
 check(generationRuntimeRequest("{\"op\":\"server-key-capability\"}")=="{\"result\":{\"serverKeyVersion\":1}}");
 check(generationRuntimeRequest(request("dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo="))=="{\"result\":\"hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=\"}");
 check(generationRuntimeRequest(request("XasIfmJKikt54X+Lg4AO5m87sSkmGLb9HC+LJ/+I4Os="))=="{\"result\":\"3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08=\"}");
 for(const auto &key:{std::string(),std::string(42,'A')+"=",std::string(43,'A')+"==",std::string(42,'A')+"B=",std::string(43,'!')+"="}) rejects(request(key));
 rejects("{\"op\":\"server-key\",\"source\":true}");rejects("{\"op\":\"server-key-capability\",\"extra\":1}");
 std::cout<<count<<" server key checks passed\n";return 0;
}catch(const std::exception&e){std::cerr<<e.what()<<'\n';return 1;}}
