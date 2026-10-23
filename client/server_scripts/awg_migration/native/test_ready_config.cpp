#include "ready_config.h"
#include <iostream>
using namespace amnezia::awgMigration;
int main(){const std::string a(43,'A'),b(43,'B');const auto source="[Interface]\nPrivateKey="+a+"=\nAddress=10.0.0.1/24\n[Peer]\nPublicKey="+b+"=\nAllowedIPs=10.0.0.2/32\n";auto c=parseConfig(source);if(c.Peers.size()!=1||c.Interface.at("Address")!="10.0.0.1/24")return 1;try{parseConfig(source+"AllowedIPs=10.0.0.3/32\n");return 2;}catch(const ConfigError &e){if(std::string(e.code())!="duplicate configuration key")return 3;}
 // Address parsing must not pass a NUL-truncated host to inet_pton. Opaque
 // supported values still preserve NUL bytes, as in the Python parser.
 const std::string invalidHost=std::string("::1")+'\0'+"junk";
 for(const auto &validHost:{"10.0.0.1/24","10.0.0.2/32"}){
  auto invalid=source;invalid.replace(invalid.find(validHost),std::string(validHost).size(),invalidHost);
  try{parseConfig(invalid);return 4;}catch(const ConfigError &e){if(std::string(e.code())!="configuration address")return 5;}
 }
 const std::string opaque=std::string("prefix")+'\0'+"suffix";
 for(const auto &field:{"PostUp","DNS"}){
  auto preserved=source;preserved.insert(preserved.find("Address="),std::string(field)+'='+opaque+'\n');
  if(parseConfig(preserved).Interface.at(field)!=opaque)return 6;
 }
 std::cout<<"ready-config unit cases passed\n";}
