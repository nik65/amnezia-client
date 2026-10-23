#include "ready_config.h"
#include <iostream>
#include <iterator>
#include <iomanip>
using namespace amnezia::awgMigration;
static std::string hex(const std::string &v){std::string r;const char *h="0123456789abcdef";for(unsigned char c:v){r+=h[c>>4];r+=h[c&15];}return r;}
int main(){try{std::string s{std::istreambuf_iterator<char>(std::cin),{}};auto c=parseConfig(s);std::cout<<"OK\n";for(const auto &kv:c.Interface)std::cout<<"I\t"<<hex(kv.first)<<'\t'<<hex(kv.second)<<'\n';for(std::size_t n=0;n<c.Peers.size();++n){std::cout<<"P\t"<<n<<'\n';for(const auto &kv:c.Peers[n])std::cout<<"V\t"<<hex(kv.first)<<'\t'<<hex(kv.second)<<'\n';}}catch(const ConfigError &e){std::cout<<"ERR\t"<<e.code()<<'\n';return 2;}return 0;}
