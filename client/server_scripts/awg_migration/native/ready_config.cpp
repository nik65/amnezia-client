#include "ready_config.h"
#include <algorithm>
#include <cstdint>
#include <set>
#include <sstream>
#include <arpa/inet.h>
namespace amnezia::awgMigration {
namespace {
[[noreturn]] void fail(const char *s) { throw ConfigError(s); }
bool space(unsigned char c) { return c==' ' || (c>=9 && c<=13); }
bool unicodeSpace(std::uint32_t c) {
 return c==0x85||c==0xa0||c==0x1680||(c>=0x2000&&c<=0x200a)||c==0x2028||c==0x2029||c==0x202f||c==0x205f||c==0x3000||(c>=0x1c&&c<=0x1f)||(space(static_cast<unsigned char>(c))&&c<128);
}
struct Rune { std::uint32_t cp; std::size_t begin,end; };
std::vector<Rune> decode(std::string_view s) {
 std::vector<Rune> r;
 for(std::size_t i=0;i<s.size();) {
  auto begin=i;unsigned char ch=s[i++];std::uint32_t cp=ch;unsigned more=0;
  if(ch>=0xc2&&ch<=0xdf){cp=ch&31;more=1;}
  else if(ch>=0xe0&&ch<=0xef){cp=ch&15;more=2;}
  else if(ch>=0xf0&&ch<=0xf4){cp=ch&7;more=3;}
  else if(ch>=128)fail("invalid UTF-8");
  for(unsigned n=0;n<more;++n){if(i>=s.size()||(static_cast<unsigned char>(s[i])&0xc0)!=0x80)fail("invalid UTF-8");cp=(cp<<6)|(static_cast<unsigned char>(s[i++])&63);}
  if((more==1&&cp<128)||(more==2&&cp<2048)||(more==3&&cp<65536)||cp>0x10ffff||(cp>=0xd800&&cp<=0xdfff))fail("invalid UTF-8");
  r.push_back({cp,begin,i});
 }
 return r;
}
std::string trim(std::string s) {
 auto runes=decode(s);std::size_t first=0,last=runes.size();
 while(first<last&&unicodeSpace(runes[first].cp))++first;
 while(last>first&&unicodeSpace(runes[last-1].cp))--last;
 return first<last?s.substr(runes[first].begin,runes[last-1].end-runes[first].begin):std::string();
}
bool keyValid(const std::string &s) {
 return s.size()==44 && s.back()=='=' && std::all_of(s.begin(),s.end()-1,[](unsigned char c){
  return (c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='+'||c=='/';});
}
const std::string &field(const ConfigFields &f,const char *name) {
 auto i=f.find(name); if(i==f.end()) fail("missing field"); return i->second;
}
std::uint32_t ipv4(const std::string &s) {
 std::uint32_t v=0; std::size_t pos=0;
 for(int n=0;n<4;++n) {
  auto end=s.find('.',pos); if((n<3)==(end==std::string::npos)) fail("configuration address");
  auto t=s.substr(pos,end==std::string::npos ? end : end-pos);
  if(t.empty()||t.size()>3||(t.size()>1&&t[0]=='0')) fail("configuration address");
  unsigned value=0; for(unsigned char c:t){if(c<'0'||c>'9')fail("configuration address");value=value*10+c-'0';}
  if(value>255)fail("configuration address");
  v=(v<<8)|value;pos=end+1;
 }
 return v;
}
struct Address { std::uint32_t ip,mask; unsigned prefix; bool v6; };
Address address(const std::string &s) {
 if(s.find(':')!=std::string::npos) {
  auto slash=s.find('/');auto host=s.substr(0,slash);auto zone=host.find('%');
  if(zone!=std::string::npos){if(zone+1==host.size()||host.find('%',zone+1)!=std::string::npos)fail("configuration address");host.resize(zone);}
  // Reject a NUL before passing the host through inet_pton's C-string API.
  // The scope suffix is not passed to that API; keep its Python error semantics.
  if(host.find('\0')!=std::string::npos)fail("configuration address");
  in6_addr parsed{};if(inet_pton(AF_INET6,host.c_str(),&parsed)!=1)fail("configuration address");
  if(slash!=std::string::npos){auto t=s.substr(slash+1);unsigned bits=0;if(t.empty())fail("configuration address");for(unsigned char ch:t){if(ch<'0'||ch>'9'||bits>128)fail("configuration address");bits=bits*10+ch-'0';}if(bits>128)fail("configuration address");}
  return {0,0,0,true};
 }
 auto slash=s.find('/'); auto ip=ipv4(s.substr(0,slash));unsigned prefix=32;std::uint32_t mask=0xffffffffu;
 if(slash!=std::string::npos) {
  auto t=s.substr(slash+1);if(t.empty())fail("configuration address");
  if(t.find('.')!=std::string::npos) {
   mask=ipv4(t); auto contiguous=[](std::uint32_t x){auto inv=~x;return (inv&(inv+1))==0;};
   if(!contiguous(mask)){mask=~mask;if(!contiguous(mask))fail("configuration address");}
   prefix=0;for(auto x=mask;x;x<<=1)++prefix;
  } else {
   prefix=0;for(unsigned char c:t){if(c<'0'||c>'9'||prefix>32)fail("configuration address");prefix=prefix*10+c-'0';}
   if(prefix>32)fail("configuration address");
   mask=prefix==0?0u:0xffffffffu<<(32-prefix);
  }
 }
 return {ip,mask,prefix,false};
}
}
ReadyConfig parseConfig(std::string_view raw) {
 std::string records;
 for(auto r:decode(raw)) {
  if(r.cp==10||r.cp==13||r.cp==11||r.cp==12||r.cp==0x85||r.cp==0x2028||r.cp==0x2029||(r.cp>=0x1c&&r.cp<=0x1e))records+='\n';
  else records.append(raw.substr(r.begin,r.end-r.begin));
 }
 ReadyConfig c;ConfigFields *current=nullptr;std::istringstream input{records};std::string line;
 while(std::getline(input,line)) {
  line=trim(line);if(line.empty()||line[0]=='#')continue;
  if(line=="[Interface]"){if(!c.Interface.empty())fail("duplicate interface");current=&c.Interface;}
  else if(line=="[Peer]"){c.Peers.emplace_back();current=&c.Peers.back();}
  else {
   auto eq=line.find('=');if(!current||eq==std::string::npos)fail("configuration syntax");
   auto k=trim(line.substr(0,eq)),v=trim(line.substr(eq+1));
   if(current->count(k))fail("duplicate configuration key");
   current->emplace(k,v);
  }
 }
 auto priv=c.Interface.find("PrivateKey");if(c.Peers.empty()||priv==c.Interface.end()||!keyValid(priv->second))fail("missing identity");
 const std::set<std::string> allowed={"Jc","Jmin","Jmax","S1","S2","S3","S4","H1","H2","H3","H4","HeaderProtectionKey","ContentPaddingAddition","RekeyAfterTime","RekeyTimeout","RejectAfterTime","KeepaliveTimeout","MaxHandshakeAttempts","RandomTrailers","DisableCookies","PrivateKey","Address","ListenPort","MTU","PostUp","PostDown","SaveConfig","DNS","I1","I2","I3","I4","I5"};
 for(const auto &kv:c.Interface)if(!allowed.count(kv.first))fail("unknown interface key");
 const auto net=address(field(c.Interface,"Address"));if(net.v6)fail("only IPv4 isolation supported");
 std::set<std::string> identities;std::set<std::uint32_t> ips;bool duplicate=false;
 for(const auto &p:c.Peers) {
  for(const auto &kv:p)if(kv.first!="PublicKey"&&kv.first!="PresharedKey"&&kv.first!="AllowedIPs"&&kv.first!="PersistentKeepalive")fail("unsupported peer field");
  auto pub=p.find("PublicKey");if(pub==p.end()||!keyValid(pub->second)||!identities.insert(pub->second).second)fail("peer identity");
  auto psk=p.find("PresharedKey");if(psk!=p.end()&&!keyValid(psk->second))fail("PSK");
  const auto a=address(field(p,"AllowedIPs"));if(a.v6||a.prefix!=32||(a.ip&net.mask)!=(net.ip&net.mask)||a.ip==net.ip)fail("ambiguous peer route");
  if(!ips.insert(a.ip).second)duplicate=true;
 }
 if(duplicate)fail("duplicate peer address");
 return c;
}
}

