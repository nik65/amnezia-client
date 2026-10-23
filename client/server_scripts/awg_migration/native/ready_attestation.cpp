#include "ready_attestation.h"
#include <rapidjson/encodings.h>
#include <rapidjson/memorystream.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <iomanip>
#include <memory>
#include <set>
#include <sstream>

namespace amnezia::awgMigration {
namespace {
[[noreturn]] void drift() { throw ConfigError("migration_ready_drift"); }
void requireUtf8(const std::string &raw) {
 rapidjson::MemoryStream input(raw.data(),raw.size());
 while(input.Tell()<raw.size()) {
  unsigned codepoint=0;
  if(!rapidjson::UTF8<>::Decode(input,&codepoint))drift();
 }
}
json_object *member(json_object *v, const char *key) {
 json_object *out=nullptr;
 if(!v || !json_object_is_type(v,json_type_object) || !json_object_object_get_ex(v,key,&out)) drift();
 return out;
}
std::string str(json_object *v) {
 if(!v || !json_object_is_type(v,json_type_string)) drift();
 std::string result(json_object_get_string(v),json_object_get_string_len(v));
 if(result.find('\0')!=std::string::npos)drift();
 return result;
}
std::string scalar(json_object *v) {
 if(v && json_object_is_type(v,json_type_int)) return std::to_string(json_object_get_int64(v));
 return str(v);
}
std::string field(const ConfigFields &f,const std::string &k) {
 auto p=f.find(k);if(p==f.end())drift();return p->second;
}
ConfigFields parameters(json_object *v) {
 if(!v||!json_object_is_type(v,json_type_object))drift();
 ConfigFields result;
 json_object_object_foreach(v,k,item) {result.emplace(k,str(item));}
 return result;
}
std::string trim(std::string s) {
 auto ws=[](unsigned char c){return c==' '||(c>=9&&c<=13);};
 auto a=std::find_if_not(s.begin(),s.end(),ws);auto b=std::find_if_not(s.rbegin(),s.rend(),ws).base();
 return a<b?std::string(a,b):std::string();
}
std::vector<std::string> split(const std::string &s,char c) {
 std::vector<std::string> result;std::size_t start=0;
 for(;;){auto end=s.find(c,start);result.push_back(s.substr(start,end==std::string::npos?end:end-start));if(end==std::string::npos)break;start=end+1;}
 return result;
}
std::string digest(const std::string &s) {
 std::array<unsigned char,SHA256_DIGEST_LENGTH> bytes{};
 SHA256(reinterpret_cast<const unsigned char *>(s.data()),s.size(),bytes.data());
 std::ostringstream out;out<<std::hex<<std::setfill('0');for(auto b:bytes)out<<std::setw(2)<<static_cast<unsigned>(b);return out.str();
}
struct Fd {int fd;~Fd(){if(fd>=0)close(fd);}};
struct DirectoryPath {
 std::vector<std::unique_ptr<Fd>> nodes;
 std::vector<std::string> parts;
 explicit DirectoryPath(const std::string &path) {
  if(path.empty()||path.front()!='/'||path.back()=='/'||path.find('\0')!=std::string::npos)drift();
  nodes.emplace_back(new Fd{open("/",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)});
  if(nodes.back()->fd<0)drift();
  parts=split(path.substr(1),'/');
  for(const auto &part:parts) {
   if(part.empty()||part=="."||part=="..")drift();
   int next=openat(nodes.back()->fd,part.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
   if(next<0)drift();
   nodes.emplace_back(new Fd{next});
  }
 }
 int leaf() const {return nodes.back()->fd;}
 void verifyBinding() const {
  for(std::size_t i=0;i<parts.size();++i) {
   struct stat name{},pinned{};
   if(fstatat(nodes[i]->fd,parts[i].c_str(),&name,AT_SYMLINK_NOFOLLOW)||fstat(nodes[i+1]->fd,&pinned)||
      !S_ISDIR(name.st_mode)||name.st_dev!=pinned.st_dev||name.st_ino!=pinned.st_ino)drift();
  }
 }
};
std::int64_t generation(json_object *v) {
 if(!v||!json_object_is_type(v,json_type_int))drift();
 auto result=json_object_get_int64(v);if(result<1||result>9007199254740991LL)drift();return result;
}
std::string readTarget(const std::string &directory) {
 DirectoryPath dirs(directory);int dir=dirs.leaf();
 Fd file{openat(dir,"awg0.conf",O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC)};if(file.fd<0)drift();
 struct stat before{},after{};
 if(fstat(file.fd,&before)||!S_ISREG(before.st_mode)||before.st_nlink!=1||before.st_size<0||before.st_size>1024*1024)drift();
 std::string data(static_cast<std::size_t>(before.st_size),'\0');std::size_t done=0;
 while(done<data.size()){auto n=read(file.fd,data.data()+done,data.size()-done);if(n<0&&errno==EINTR)continue;if(n<=0)drift();done+=static_cast<std::size_t>(n);}
 char extra;if(read(file.fd,&extra,1)!=0||fstat(file.fd,&after))drift();
 struct stat path{};if(fstatat(dir,"awg0.conf",&path,AT_SYMLINK_NOFOLLOW))drift();
 if(before.st_dev!=after.st_dev||before.st_ino!=after.st_ino||before.st_size!=after.st_size||
    before.st_mtim.tv_sec!=after.st_mtim.tv_sec||before.st_mtim.tv_nsec!=after.st_mtim.tv_nsec||
    before.st_ctim.tv_sec!=after.st_ctim.tv_sec||before.st_ctim.tv_nsec!=after.st_ctim.tv_nsec||
    path.st_dev!=after.st_dev||path.st_ino!=after.st_ino||!S_ISREG(path.st_mode))drift();
 dirs.verifyBinding();
 DirectoryPath reopened(directory);struct stat pinnedDir{},currentDir{};
 if(fstat(dir,&pinnedDir)||fstat(reopened.leaf(),&currentDir)||pinnedDir.st_dev!=currentDir.st_dev||pinnedDir.st_ino!=currentDir.st_ino)drift();
 reopened.verifyBinding();
 return data;
}
}
void validateReadyTarget(ProcessRunner &run,json_object *state,const ReadyConfig &source,const ReadyConfig &target,bool automatic) {
 auto params=parameters(member(state,"parameters"));
 if(field(target.Interface,"PrivateKey")!=field(source.Interface,"PrivateKey")||
    field(target.Interface,"Address")!=field(source.Interface,"Address")||target.Peers!=source.Peers)drift();
 for(const auto &p:params)if(field(target.Interface,p.first)!=p.second)drift();
 auto container=str(member(state,"targetContainer"));
 auto dump=run.run({"docker","exec",container,"awg","show","awg0","dump"});if(dump.size()>16*1024*1024)drift();
 requireUtf8(dump);
 auto rows=split(trim(dump),'\n');
 if(rows.size()!=source.Peers.size()+1)drift();
 auto first=split(rows.front(),'\t');
 if(first.size()<3||first[1]!=str(member(state,"serverPublicKey"))||first[2]!=field(target.Interface,"ListenPort"))drift();
 std::map<std::string,std::vector<std::string>> observed;
 for(std::size_t n=1;n<rows.size();++n){auto row=split(rows[n],'\t');if(!observed.emplace(row[0],row).second)drift();}
 if(observed.size()!=source.Peers.size())drift();
 for(const auto &peer:source.Peers){auto it=observed.find(field(peer,"PublicKey"));if(it==observed.end())drift();const auto &r=it->second;
  auto psk=peer.find("PresharedKey");if(r.size()<4||r[1]!=(psk==peer.end()?"(none)":psk->second)||r[3]!=field(peer,"AllowedIPs"))drift();}
 ConfigFields accepted;
 auto showconf=run.run({"docker","exec",container,"awg","showconf","awg0"});if(showconf.size()>16*1024*1024)drift();
 requireUtf8(showconf);
 for(auto line:split(showconf,'\n')) {
  auto pos=line.find('=');if(pos==std::string::npos)continue;auto key=trim(line.substr(0,pos)),value=trim(line.substr(pos+1));
  if(!params.count(key))continue;
  if(key=="RandomTrailers"||key=="DisableCookies") {if(value=="false"||value=="off")value="0";if(value=="true"||value=="on")value="1";}
  if(!accepted.emplace(key,value).second)drift();
 }
 if(params.count("ContentPaddingAddition")&&params.at("ContentPaddingAddition")=="0")accepted.emplace("ContentPaddingAddition","0");
 if(accepted!=params)drift();
 if(automatic){auto live=run.run({"docker","exec",container,"sh","-c","set -eu; engine=$(cat /migration/engine.pid); case \"$engine\" in \"\"|*[!0-9]*) exit 1;; esac; kill -0 \"$engine\"; sha256sum \"/proc/$engine/exe\""});
  if(live.size()>4096)drift();
  requireUtf8(live);
  std::istringstream in(live);std::string hash,path,extra;if(!(in>>hash>>path)||in>>extra||hash!=TrustedBinarySha256)drift();}
}
void validateExistingTarget(const std::string &directory,json_object *value,json_object *ready,ProcessRunner &run) {
 auto source=str(member(value,"source"));if(source!="amnezia-awg"&&source!="amnezia-awg2")drift();
 auto target=str(member(value,"target"));auto targetId=str(member(member(member(value,"containers"),target.c_str()),"id"));
 auto request=member(value,"request");
 if(targetId.empty()||str(member(ready,"containerId"))!=source||str(member(ready,"targetContainer"))!=target||
    generation(member(ready,"generation"))!=generation(member(request,"generation"))||
    str(member(ready,"endpoint"))!=scalar(member(request,"host"))+":"+scalar(member(request,"port")))drift();
 auto raw=run.run({"docker","exec",str(member(value,"sourceId")),"cat",source=="amnezia-awg"?"/opt/amnezia/awg/wg0.conf":"/opt/amnezia/awg/awg0.conf"});
 if(raw.size()>1024*1024||digest(raw)!=str(member(value,"sourceDigest")))drift();
 auto sourceConfig=parseConfig(raw);auto targetRaw=readTarget(directory);
 if(run.run({"docker","exec",targetId,"cat","/migration/awg0.conf"})!=targetRaw)drift();
 auto targetConfig=parseConfig(targetRaw);if(field(targetConfig.Interface,"ListenPort")!=scalar(member(request,"port")))drift();
 auto mapping=member(ready,"peers");if(!json_object_is_type(mapping,json_type_object)||static_cast<std::size_t>(json_object_object_length(mapping))!=sourceConfig.Peers.size())drift();
 for(const auto &peer:sourceConfig.Peers){auto item=member(mapping,field(peer,"PublicKey").c_str());auto route=field(peer,"AllowedIPs");auto address=route.substr(0,route.find('/'));
  if(str(member(item,"sourceIp"))!=address||str(member(item,"targetIp"))!=address||str(member(item,"clientAddress"))!=route)drift();}
 auto native=parameters(member(ready,"parameters")); // Validate field types before making a private copy.
 (void)native;
 json_object *copy=nullptr;if(json_object_deep_copy(ready,&copy,nullptr)||!copy)drift();PlannerJson owner(copy);
 json_object_object_add(copy,"targetContainer",json_object_new_string(targetId.c_str()));
 validateReadyTarget(run,copy,sourceConfig,targetConfig,true);
}
}
