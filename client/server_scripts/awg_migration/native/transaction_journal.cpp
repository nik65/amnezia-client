#include "transaction_journal.h"
#include <openssl/evp.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <algorithm>
#include <cerrno>
#include <cctype>
#include <iomanip>
#include <regex>
#include <sstream>

namespace amnezia::awgMigration {
namespace {
using Json = std::shared_ptr<json_object>;
constexpr std::size_t kMaxJournalBytes=4*1024*1024;
Json adopt(json_object* p) { if (!p) throw JournalError("invalid journal JSON"); return Json(p, json_object_put); }
json_object* field(json_object* p, const char* key, json_type type) {
    json_object* v = nullptr;
    if (!p || !json_object_is_type(p, json_type_object) || !json_object_object_get_ex(p,key,&v)
        || !json_object_is_type(v,type)) throw JournalError(std::string("invalid journal field: ")+key);
    return v;
}
std::string str(json_object* p, const char* key) {
    auto* v=field(p,key,json_type_string);
    std::string s(json_object_get_string(v),static_cast<std::size_t>(json_object_get_string_len(v)));
    if (s.find('\0')!=std::string::npos) throw JournalError("embedded NUL in journal");
    return s;
}
bool boolean(json_object* p,const char* key) {return json_object_get_boolean(field(p,key,json_type_boolean));}
bool has(json_object* p,const char* key) {json_object* v=nullptr;return json_object_object_get_ex(p,key,&v);}
std::string optionalString(json_object* p,const char* key) {
    json_object* v=nullptr;
    if (!json_object_object_get_ex(p,key,&v)||!v) return {};
    return str(p,key);
}
void put(json_object* p,const char* k,const std::string& s) {json_object_object_add(p,k,json_object_new_string_len(s.data(),static_cast<int>(s.size())));}
Json parse(const std::string& raw) {
    if (raw.size()>kMaxJournalBytes) throw JournalError("journal JSON too large");
    auto* tok=json_tokener_new_ex(48);
    if (!tok) throw JournalError("JSON allocation");
    json_tokener_set_flags(tok,JSON_TOKENER_STRICT|JSON_TOKENER_VALIDATE_UTF8);
    auto* out=json_tokener_parse_ex(tok,raw.data(),static_cast<int>(raw.size()));
    bool valid=json_tokener_get_error(tok)==json_tokener_success;
    auto end=json_tokener_get_parse_end(tok);
    json_tokener_free(tok);
    if (!valid || !out || raw.find_first_not_of(" \r\n\t",end)!=std::string::npos) {
        if(out)json_object_put(out);
        throw JournalError("invalid journal JSON");
    }
    return adopt(out);
}
std::string readFd(int fd) {
    std::string out;char bytes[8192];
    while(true) {auto n=read(fd,bytes,sizeof bytes);if(n<0){if(errno==EINTR)continue;throw JournalError("journal read failed");}if(!n)break;
        out.append(bytes,static_cast<std::size_t>(n));if(out.size()>kMaxJournalBytes)throw JournalError("journal too large");}
    return out;
}
bool match(const std::string& s,const char* pattern) {return std::regex_match(s,std::regex(pattern));}
void containerId(const std::string& s) {if(!match(s,"[a-f0-9]{64}"))throw JournalError("invalid immutable container ID");}
void containerName(const std::string& s) {if(!match(s,"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}"))throw JournalError("invalid container name");}
void imageId(const std::string& s) {if(!match(s,"sha256:[a-f0-9]{64}"))throw JournalError("invalid immutable image ID");}
std::vector<std::string> names(json_object* object) {
    std::vector<std::string> out;
    json_object_object_foreach(object,key,val){(void)val;out.emplace_back(key);}
    return out;
}
bool suffix(const std::string& s,const std::string& tail) {return s.size()>=tail.size()&&s.compare(s.size()-tail.size(),tail.size(),tail)==0;}
// O_NOFOLLOW applies only to the last component of one open(). Walk from /
// instead, so an alias anywhere above the private migration root is rejected.
int openDirectoryWithoutSymlinks(const std::filesystem::path& path) {
    if(!path.is_absolute())throw JournalError("journal path is not absolute");
    int fd=open("/",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(fd<0)throw JournalError("journal filesystem root unavailable");
    try {
        for(const auto& part:path.relative_path()) {
            const auto name=part.string();
            if(name.empty()||name=="."||name=="..")throw JournalError("ambiguous journal path");
            int next=openat(fd,name.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
            if(next<0)throw JournalError("unsafe journal ancestor");
            close(fd);fd=next;
        }
        return fd;
    }catch(...){close(fd);throw;}
}
}
TransactionJournal::TransactionJournal(const std::filesystem::path& directory, JournalRunner runner,
    const std::string& initial,JournalFault fault):directory_(directory),runner_(std::move(runner)),fault_(std::move(fault)) {
    try {
        if(!runner_)throw JournalError("journal runner required");
        directory_=std::filesystem::absolute(directory);
        for(const auto& part:directory_.relative_path())
            if(part=="."||part=="..")throw JournalError("ambiguous journal path");
        auto rootPath=directory_.parent_path().parent_path();
        auto scope=directory_.parent_path().filename().string();
        auto generation=directory_.filename().string();
        containerName(scope);
        if(!match(generation,"[1-9][0-9]{0,15}"))throw JournalError("journal generation path");
        int rootFd=openDirectoryWithoutSymlinks(rootPath);
        int scopeFd=-1;
        struct stat st{};
        auto privateDirectory=[&](int fd){
            return fstat(fd,&st)==0&&S_ISDIR(st.st_mode)&&st.st_uid==geteuid()&&!(st.st_mode&0077);
        };
        try {
            if(!privateDirectory(rootFd))throw JournalError("unsafe journal root");
            scopeFd=openat(rootFd,scope.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
            if(scopeFd<0||!privateDirectory(scopeFd))throw JournalError("unsafe journal source directory");
            directoryFd_=openat(scopeFd,generation.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
            if(directoryFd_<0||!privateDirectory(directoryFd_))throw JournalError("unsafe journal directory");
            // Same global lock as prepare.py/maintenance.py, across all sources.
            lockFd_=openat(rootFd,".prepare.lock",O_RDWR|O_CREAT|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC,0600);
            if(lockFd_<0 || fstat(lockFd_,&st)<0 || !S_ISREG(st.st_mode)||st.st_nlink!=1
                || st.st_uid!=geteuid() || (st.st_mode&0077) || flock(lockFd_,LOCK_EX|LOCK_NB)<0)
                throw JournalError("journal lock unavailable");
            close(scopeFd);close(rootFd);
        }catch(...){if(scopeFd>=0)close(scopeFd);close(rootFd);throw;}
        if(initial.empty()) {
            int fd=openat(directoryFd_,"transaction.json",O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
            if(fd<0)throw JournalError("journal unavailable");
            try {if(fstat(fd,&st)<0||!S_ISREG(st.st_mode)||st.st_nlink!=1||st.st_uid!=geteuid()||(st.st_mode&0077))throw JournalError("unsafe journal metadata");
                value_=parse(readFd(fd));close(fd);
            }catch(...){close(fd);throw;}
        } else {
            if(fstatat(directoryFd_,"transaction.json",&st,AT_SYMLINK_NOFOLLOW)==0||errno!=ENOENT)
                throw JournalError("generation already exists; never overwrite");
            value_=parse(initial);
        }
        validate();
    }catch(...){if(lockFd_>=0)close(lockFd_);if(directoryFd_>=0)close(directoryFd_);throw;}
}
TransactionJournal::~TransactionJournal(){if(lockFd_>=0)close(lockFd_);if(directoryFd_>=0)close(directoryFd_);}
void TransactionJournal::validate() const {
    if(!match(str(value_.get(),"owner"),"[a-f0-9]{32}"))throw JournalError("journal owner");
    auto phase=str(value_.get(),"phase");
    if(phase!="preparing"&&phase!="creating"&&phase!="ready"&&phase!="activating"&&phase!="aborted")throw JournalError("journal phase");
    auto sourceName=str(value_.get(),"source");
    if(sourceName!="amnezia-awg"&&sourceName!="amnezia-awg2")throw JournalError("unsupported journal source");
    containerName(sourceName);
    if(directory_.parent_path().filename()!=str(value_.get(),"source"))throw JournalError("journal source directory");
    containerId(str(value_.get(),"sourceId"));
    containerName(str(value_.get(),"target"));
    auto iface=str(value_.get(),"sourceIface");if(iface!="wg0"&&iface!="awg0")throw JournalError("journal source interface");
    boolean(value_.get(),"sourceRules");
    if(!match(str(value_.get(),"sourceDigest"),"[a-f0-9]{64}"))throw JournalError("journal source digest");
    auto* request=field(value_.get(),"request",json_type_object);
    auto generation=json_object_get_int64(field(request,"generation",json_type_int));
    if(generation<1||generation>9007199254740991LL||directory_.filename()!=std::to_string(generation))throw JournalError("journal generation");
    if(str(value_.get(),"target")!=sourceName+"-migration-"+std::to_string(generation))throw JournalError("journal target generation");
    if(iface!=(sourceName=="amnezia-awg"?"wg0":"awg0"))throw JournalError("journal interface scope");
    auto port=json_object_get_int64(field(request,"port",json_type_int));
    if(port<1024||port>65535||!match(str(request,"host"),"[A-Za-z0-9.-]{1,253}"))throw JournalError("journal request");
    (void)str(request,"image");
    auto* containers=field(value_.get(),"containers",json_type_object);
    for(const auto& name:names(containers)) {
        const auto target=str(value_.get(),"target");
        if(name!=target&&name!=target+"-control"&&name!=target+"-source-control"&&name!=target+"-logs"&&name!=target+"-feeds")throw JournalError("journal component scope");
        containerName(name);auto* entry=field(containers,name.c_str(),json_type_object);
        imageId(str(entry,"image"));if(!has(entry,"id"))throw JournalError("journal container ID missing");auto id=optionalString(entry,"id");if(!id.empty()){containerId(id);if(id==str(value_.get(),"sourceId"))throw JournalError("owned component aliases source VPN");}
    }
}
void TransactionJournal::checkpoint(const std::string& point)const {if(fault_)fault_(point);}
std::string TransactionJournal::snapshot()const{return json_object_to_json_string_ext(value_.get(),JSON_C_TO_STRING_PLAIN);}
void TransactionJournal::save(const std::string& phase) {
    if(!phase.empty())put(value_.get(),"phase",phase);
    validate();auto raw=snapshot();
    // The writer must never commit a snapshot its own reader cannot reopen.
    // Validate the final serialization before creating even a staging file.
    if(raw.size()>kMaxJournalBytes)throw JournalError("journal JSON too large");
    std::string tmp;
    int fd=-1;
    for(unsigned n=0;n<100;++n){tmp=".transaction-"+std::to_string(getpid())+"-"+std::to_string(n);
        fd=openat(directoryFd_,tmp.c_str(),O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);if(fd>=0)break;if(errno!=EEXIST)throw JournalError("journal staging failed");}
    if(fd<0)throw JournalError("journal staging collision");
    try {
        checkpoint("save-created");std::size_t pos=0;
        while(pos<raw.size()){auto n=write(fd,raw.data()+pos,raw.size()-pos);if(n<0){if(errno==EINTR)continue;throw JournalError("journal write failed");}if(!n)throw JournalError("journal short write");pos+=static_cast<std::size_t>(n);}
        checkpoint("save-written");if(fsync(fd)<0)throw JournalError("journal file fsync failed");checkpoint("save-file-synced");
        if(close(fd)<0){fd=-1;throw JournalError("journal close failed");}fd=-1;
        if(renameat(directoryFd_,tmp.c_str(),directoryFd_,"transaction.json")<0)throw JournalError("journal replace failed");
        checkpoint("save-replaced");
        if(fsync(directoryFd_)<0)throw JournalError("journal directory fsync failed");
        checkpoint("save-directory-synced");
    }catch(...){if(fd>=0)close(fd);unlinkat(directoryFd_,tmp.c_str(),0);throw;}
}
CommandResult TransactionJournal::command(std::vector<std::string> args)const {
    auto result=runner_(args);if(result.status)throw JournalError("journal command unavailable");return result;
}
TransactionJournal::Json TransactionJournal::inspect(const std::string& id)const {
    auto result=runner_({"docker","inspect",id});
    if(result.status){auto err=result.error;std::transform(err.begin(),err.end(),err.begin(),[](unsigned char c){return static_cast<char>(std::tolower(c));});
        if(err.find("no such object")!=std::string::npos||err.find("no such container")!=std::string::npos)return {};
        throw JournalError("ownership inspection unavailable");}
    auto list=parse(result.output);
    if(!json_object_is_type(list.get(),json_type_array)||json_object_array_length(list.get())!=1)throw JournalError("ambiguous ownership");
    auto* item=json_object_array_get_idx(list.get(),0);if(!json_object_is_type(item,json_type_object))throw JournalError("invalid ownership inspection");
    return Json(json_object_get(item),json_object_put);
}
TransactionJournal::Json TransactionJournal::owned(const std::string& name)const {
    auto* entry=field(field(value_.get(),"containers",json_type_object),name.c_str(),json_type_object);
    auto id=optionalString(entry,"id");auto observed=inspect(id.empty()?name:id);if(!observed)return {};
    auto* config=field(observed.get(),"Config",json_type_object);auto* labels=field(config,"Labels",json_type_object);
    auto actualId=str(observed.get(),"Id");containerId(actualId);
    if(str(labels,"amnezia.migration.owner")!=str(value_.get(),"owner")||str(observed.get(),"Image")!=str(entry,"image")
        ||(!id.empty()&&actualId!=id)||str(observed.get(),"Name")!="/"+name)throw JournalError("ownership collision; human review required");
    field(observed.get(),"State",json_type_object);return observed;
}
void TransactionJournal::plan(const std::string& name,const std::string& image) {
    containerName(name);imageId(image);
    auto* containers=field(value_.get(),"containers",json_type_object);
    if(has(containers,name.c_str()))throw JournalError("container already planned");
    auto* item=json_object_new_object();put(item,"image",image);json_object_object_add(item,"id",nullptr);
    json_object_object_add(containers,name.c_str(),item);save("creating");
}
void TransactionJournal::record(const std::string& name) {
    auto observed=owned(name);if(!observed)throw JournalError("created container not found");
    put(field(field(value_.get(),"containers",json_type_object),name.c_str(),json_type_object),"id",str(observed.get(),"Id"));save();
}
void TransactionJournal::verifyRequest(const std::string& requestJson,const std::string& sourceBytes)const {
    auto request=parse(requestJson);
    if(!json_object_equal(request.get(),field(value_.get(),"request",json_type_object))||sha256(sourceBytes)!=str(value_.get(),"sourceDigest"))throw JournalError("same generation request drift");
}
std::string TransactionJournal::sha256(const std::string& bytes){unsigned char hash[EVP_MAX_MD_SIZE];unsigned length=0;
    if(EVP_Digest(bytes.data(),bytes.size(),hash,&length,EVP_sha256(),nullptr)!=1)throw JournalError("SHA256 unavailable");
    std::ostringstream out;for(unsigned i=0;i<length;++i)out<<std::hex<<std::setfill('0')<<std::setw(2)<<unsigned(hash[i]);return out.str();}
void TransactionJournal::sourceRules(bool remove) {
    auto source=inspect(str(value_.get(),"sourceId"));if(!source||str(source.get(),"Id")!=str(value_.get(),"sourceId")||str(source.get(),"Name")!="/"+str(value_.get(),"source"))throw JournalError("source namespace replaced");
    auto owner=str(value_.get(),"owner"),iface=str(value_.get(),"sourceIface");
    std::vector<std::pair<std::string,std::string>> rules={
        {"-I INPUT 1","-p tcp --dport 18082 -m comment --comment "+owner+" -j REJECT"},
        {"-I INPUT 1","-i "+iface+" -p tcp --dport 18082 -m comment --comment "+owner+" -j ACCEPT"},
        {"-t nat -A PREROUTING","-i "+iface+" -d 172.29.172.251/32 -p tcp --dport 18082 -m comment --comment "+owner+" -j REDIRECT --to-ports 18082"}};
    for(const auto& rule:rules){auto check=rule.first=="-I INPUT 1"?"-C INPUT":"-t nat -C PREROUTING";
        auto shell=remove?"iptables "+std::string(rule.first=="-I INPUT 1"?"-D INPUT":"-t nat -D PREROUTING")+" "+rule.second+" 2>/dev/null || true":
            "iptables "+std::string(check)+" "+rule.second+" 2>/dev/null || iptables "+rule.first+" "+rule.second;
        command({"docker","exec",str(value_.get(),"sourceId"),"sh","-c",shell});
        if(!remove)command({"docker","exec",str(value_.get(),"sourceId"),"sh","-c","iptables "+std::string(check)+" "+rule.second});}
}
void TransactionJournal::cleanup() {
    if(has(value_.get(),"controlMaintenance"))throw JournalError("control maintenance recovery required");
    auto entries=names(field(value_.get(),"containers",json_type_object));
    std::reverse(entries.begin(),entries.end());
    for(const auto& name:entries)(void)owned(name);
    if(boolean(value_.get(),"sourceRules")){
        auto source=inspect(str(value_.get(),"sourceId"));
        if(!source||str(source.get(),"Id")!=str(value_.get(),"sourceId")||str(source.get(),"Name")!="/"+str(value_.get(),"source"))throw JournalError("source namespace replaced");
    }
    for(const auto& name:entries){auto observed=owned(name);if(observed)command({"docker","rm","-f",str(observed.get(),"Id")});checkpoint("cleanup-container");}
    if(boolean(value_.get(),"sourceRules"))sourceRules(true);
    save("aborted");
}
void TransactionJournal::recoverReady(const std::function<void(const std::string&)>& attestListener) {
    if(str(value_.get(),"phase")!="ready")throw JournalError("journal is not ready");
    if(has(value_.get(),"controlMaintenance"))throw JournalError("control maintenance recovery required");
    auto entries=names(field(value_.get(),"containers",json_type_object));
    // Preflight the complete set before any mutation; a later collision must not
    // leave earlier containers running after a failed ownership inspection.
    for(const auto& name:entries) {
        auto observed=owned(name);
        if(!observed)throw JournalError("ready component missing; human review required");
        auto* state=field(observed.get(),"State",json_type_object);
        (void)boolean(state,"Running");(void)str(state,"StartedAt");
        if(suffix(name,"-source-control")&&!attestListener)throw JournalError("control listener attestor required");
    }
    auto source=inspect(str(value_.get(),"sourceId"));
    if(!source||str(source.get(),"Id")!=str(value_.get(),"sourceId")||str(source.get(),"Name")!="/"+str(value_.get(),"source"))throw JournalError("source namespace replaced");
    for(const auto& name:entries){auto observed=owned(name);if(!boolean(field(observed.get(),"State",json_type_object),"Running"))command({"docker","start",str(observed.get(),"Id")});checkpoint("ready-start");}
    if(boolean(value_.get(),"sourceRules"))sourceRules(false);
    auto sourceEpoch=str(field(source.get(),"State",json_type_object),"StartedAt");
    auto parent=str(value_.get(),"target");auto target=owned(parent);if(!target)throw JournalError("ready target missing");
    auto targetEpoch=str(field(target.get(),"State",json_type_object),"StartedAt");
    for(const auto& name:entries){auto observed=owned(name);
        bool sourceControl=suffix(name,"-source-control");
        if((sourceControl&&sourceEpoch!=optionalString(value_.get(),"sourceEpoch"))||(!sourceControl&&name!=parent&&targetEpoch!=optionalString(value_.get(),"targetEpoch")))command({"docker","restart",str(observed.get(),"Id")});
        checkpoint("ready-rejoin");
        if(sourceControl)attestListener(str(observed.get(),"Id"));
    }
    put(value_.get(),"sourceEpoch",sourceEpoch);put(value_.get(),"targetEpoch",targetEpoch);save("ready");
}
}
