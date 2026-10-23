#include "transaction_journal.h"
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fstream>
#include <iostream>
#include <map>

using namespace amnezia::awgMigration;
namespace fs=std::filesystem;
namespace {
void require(bool ok,const std::string& message){if(!ok)throw std::runtime_error(message);}
template<class F>void rejects(F f,const std::string& message){bool failed=false;try{f();}catch(const JournalError&){failed=true;}require(failed,message);}
struct Temp {
    fs::path root,dir;
    Temp(){char raw[]="/tmp/awg-journal-XXXXXX";auto* p=mkdtemp(raw);if(!p)throw std::runtime_error("mkdtemp");root=p;dir=root/"amnezia-awg"/"1";fs::create_directories(dir);chmod(dir.parent_path().c_str(),0700);chmod(dir.c_str(),0700);}
    ~Temp(){fs::remove_all(root);}
};
std::string quote(const std::string& s){auto* p=json_object_new_string(s.c_str());std::string out=json_object_to_json_string_ext(p,JSON_C_TO_STRING_PLAIN);json_object_put(p);return out;}
const std::string owner(32,'a'),sourceId(64,'1'),targetId(64,'2'),helperId(64,'3'),image="sha256:"+std::string(64,'b');
const std::string target="amnezia-awg-migration-1";
std::string initial(){return "{\"owner\":"+quote(owner)+",\"phase\":\"preparing\",\"source\":\"amnezia-awg\",\"sourceId\":"+quote(sourceId)+",\"sourceIface\":\"wg0\",\"sourceRules\":false,\"sourceDigest\":"+quote(TransactionJournal::sha256("source-config"))+",\"sourceEpoch\":\"epoch1\",\"targetEpoch\":\"epoch1\",\"target\":"+quote(target)+",\"containers\":{},\"request\":{\"generation\":1,\"port\":18082,\"host\":\"vpn.example\",\"image\":\"pinned-image\"}}";}
std::string observed(const std::string& name,const std::string& id,bool running=true,const std::string& who=owner,const std::string& epoch="epoch1"){
    return "[{\"Id\":"+quote(id)+",\"Name\":"+quote("/"+name)+",\"Image\":"+quote(image)+",\"Config\":{\"Labels\":{\"amnezia.migration.owner\":"+quote(who)+"}},\"State\":{\"Running\":"+(running?"true":"false")+",\"StartedAt\":"+quote(epoch)+"}}]";
}
struct FakeRunner {
    std::map<std::string,std::string> items;
    std::vector<std::vector<std::string>> commands;
    int failMutation=0,mutations=0;
    CommandResult operator()(const std::vector<std::string>& args){
        commands.push_back(args);
        if(args.size()==3&&args[0]=="docker"&&args[1]=="inspect"){
            auto found=items.find(args[2]);if(found==items.end())return {1,"","Error: No such object"};return {0,found->second,""};
        }
        ++mutations;if(failMutation&&mutations==failMutation)return {1,"","injected"};
        if(args[1]=="rm")items.erase(args.back());
        if(args[1]=="start") {
            auto& s=items[args.back()];auto p=s.find("\"Running\":false");if(p!=std::string::npos)s.replace(p,15,"\"Running\":true");
        }
        return {};
    }
    JournalRunner runner(){return [this](const auto& args){return (*this)(args);};}
};
void core(){
    Temp temp;FakeRunner run;
    {TransactionJournal j(temp.dir,run.runner(),initial());j.save();j.plan(target,image);
        run.items[target]=observed(target,targetId);j.record(target);run.items[targetId]=run.items[target];
        require(j.snapshot().find(targetId)!=std::string::npos,"record immutable ID");
        j.verifyRequest("{\"image\":\"pinned-image\",\"host\":\"vpn.example\",\"port\":18082,\"generation\":1}","source-config");
        rejects([&]{j.verifyRequest("{}","source-config");},"request mismatch");
        rejects([&]{j.verifyRequest("{\"image\":\"pinned-image\",\"host\":\"vpn.example\",\"port\":18082,\"generation\":1}","changed");},"digest mismatch");
        rejects([&]{TransactionJournal second(temp.dir,run.runner());},"exclusive lock");
        rejects([&]{j.plan(target,image);},"cannot overwrite owned plan");
        run.items[targetId]=observed(target,targetId,true,std::string(32,'c'));
        rejects([&]{j.cleanup();},"foreign owner refuses removal");require(run.mutations==0,"no foreign mutation");
        run.items[targetId]=observed(target,targetId);j.cleanup();require(run.mutations==1,"owned cleanup");
        auto& last=run.commands[run.commands.size()-1];require(last==std::vector<std::string>({"docker","rm","-f",targetId}),"remove by immutable ID");}
    TransactionJournal resumed(temp.dir,run.runner());require(resumed.snapshot().find("aborted")!=std::string::npos,"aborted durable");
    struct stat st{};require(stat((temp.dir/"transaction.json").c_str(),&st)==0&&(st.st_mode&0777)==0600,"private journal");
}
void faults(){
    for(const auto& point:{"save-created","save-written","save-file-synced","save-replaced","save-directory-synced"}){
        Temp temp;FakeRunner run;
        {TransactionJournal first(temp.dir,run.runner(),initial());first.save();}
        {TransactionJournal j(temp.dir,run.runner(),{},[&](const std::string& at){if(at==point)throw JournalError("power loss");});
            rejects([&]{j.plan(target,image);},std::string("fault injected ")+point);}
        TransactionJournal recovered(temp.dir,run.runner());auto raw=recovered.snapshot();
        const bool committed=std::string(point)=="save-replaced"||std::string(point)=="save-directory-synced";
        require((raw.find(target+"\"")!=std::string::npos),"valid snapshot after fault");
        require((raw.find("creating")!=std::string::npos)==committed,"atomic old/new snapshot boundary");
        for(const auto& entry:fs::directory_iterator(temp.dir))require(entry.path().filename().string().find(".transaction-")!=0,"staging removed on fault");
    }
}
void recovery(){
    Temp temp;FakeRunner run;
    {TransactionJournal j(temp.dir,run.runner(),initial());j.plan(target,image);run.items[target]=observed(target,targetId,false);j.record(target);run.items[targetId]=run.items[target];j.save("ready");}
    run.items[sourceId]=observed("amnezia-awg",sourceId);
    {TransactionJournal j(temp.dir,run.runner());j.recoverReady();require(run.mutations==1,"start stopped owned target");}
    run.items[targetId]=observed("foreign-name",targetId,false);
    {TransactionJournal j(temp.dir,run.runner());rejects([&]{j.recoverReady();},"collision before restart");require(run.mutations==1,"collision no mutation");}
}
void helperRecovery(){
    Temp temp;FakeRunner run;const auto name=target+"-source-control";
    {TransactionJournal j(temp.dir,run.runner(),initial());j.plan(target,image);run.items[target]=observed(target,targetId);j.record(target);run.items[targetId]=run.items[target];
        j.plan(name,image);run.items[name]=observed(name,helperId);j.record(name);run.items[helperId]=run.items[name];j.save("ready");}
    run.items[sourceId]=observed("amnezia-awg",sourceId,true,owner,"epoch2");
    TransactionJournal j(temp.dir,run.runner());rejects([&]{j.recoverReady();},"missing attestor");require(run.mutations==0,"attestor preflight");
    int attestations=0;j.recoverReady([&](const std::string& id){require(id==helperId,"attest owned ID");++attestations;});
    require(attestations==1&&run.mutations==1,"source epoch rejoins helper only");
    require(run.commands[run.commands.size()-1]==std::vector<std::string>({"docker","restart",helperId}),"never restart source VPN");
}
void malformed(){
    for(const auto& pair:std::vector<std::pair<std::string,std::string>>{{"\"generation\":1","\"generation\":true"},{"\"sourceRules\":false","\"sourceRules\":0"},{"\"owner\":\""+owner+"\"","\"owner\":\"x\""},{"\"sourceIface\":\"wg0\"","\"sourceIface\":\"x;touch /tmp/no\""}}){
        Temp t;FakeRunner run;auto raw=initial();raw.replace(raw.find(pair.first),pair.first.size(),pair.second);
        rejects([&]{TransactionJournal j(t.dir,run.runner(),raw);},"strict schema");require(run.commands.empty(),"invalid schema no runner");
    }
    Temp t;FakeRunner run;auto outside=t.root/"outside";{std::ofstream out(outside);out<<initial();}fs::create_symlink(outside,t.dir/"transaction.json");
    rejects([&]{TransactionJournal j(t.dir,run.runner());},"symlink journal rejected");
}
void cleanupFailure(){Temp t;FakeRunner run;{TransactionJournal j(t.dir,run.runner(),initial());j.plan(target,image);run.items[target]=observed(target,targetId);j.record(target);run.items[targetId]=run.items[target];run.failMutation=1;
    rejects([&]{j.cleanup();},"rm failure");require(j.snapshot().find("aborted")==std::string::npos,"failed cleanup never aborted");}
    run.failMutation=0;TransactionJournal j(t.dir,run.runner());j.cleanup();require(j.snapshot().find("aborted")!=std::string::npos,"retry cleanup");}
void transitionFaults(){
    for(const auto& point:{"cleanup-container","ready-start","ready-rejoin"}){
        Temp t;FakeRunner run;
        {TransactionJournal j(t.dir,run.runner(),initial());j.plan(target,image);run.items[target]=observed(target,targetId,false);j.record(target);run.items[targetId]=run.items[target];j.save("ready");}
        run.items[sourceId]=observed("amnezia-awg",sourceId);
        {TransactionJournal j(t.dir,run.runner(),{},[&](const std::string& at){if(at==point)throw JournalError("power loss");});
            rejects([&]{if(std::string(point)=="cleanup-container")j.cleanup();else j.recoverReady();},"mutation checkpoint failure");}
        TransactionJournal retry(t.dir,run.runner());
        if(std::string(point)=="cleanup-container")retry.cleanup();else retry.recoverReady();
        require(retry.snapshot().find(std::string(point)=="cleanup-container"?"aborted":"ready")!=std::string::npos,"retry persisted phase");
    }
}
void pathSafety(){
    {Temp t;FakeRunner run;chmod(t.dir.c_str(),0755);rejects([&]{TransactionJournal j(t.dir,run.runner(),initial());},"public generation directory");}
    {Temp t;FakeRunner run;auto moved=t.root/"elsewhere";fs::rename(t.dir,moved);fs::create_directory_symlink(moved,t.dir);rejects([&]{TransactionJournal j(t.dir,run.runner(),initial());},"symlink generation");}
    {Temp t;FakeRunner run;auto outside=t.root/"outside";{std::ofstream stream(outside);stream<<"do not alter";}fs::create_symlink(outside,t.root/".prepare.lock");rejects([&]{TransactionJournal j(t.dir,run.runner(),initial());},"symlink lock");}
    {Temp t;FakeRunner run;auto raw=initial();auto key=quote(target);raw.replace(raw.find(key),key.size(),quote("amnezia-awg"));rejects([&]{TransactionJournal j(t.dir,run.runner(),raw);},"target aliases source");}
    {Temp t;FakeRunner run;auto real=t.root/"real";auto nested=real/"root"/"amnezia-awg"/"1";fs::create_directories(nested);
        for(auto path=nested;path!=t.root;path=path.parent_path())chmod(path.c_str(),0700);
        fs::create_directory_symlink(real,t.root/"alias");
        rejects([&]{TransactionJournal j(t.root/"alias"/"root"/"amnezia-awg"/"1",run.runner(),initial());j.save();},"symlink ancestor above migration root");
        require(!fs::exists(nested/"transaction.json"),"alias refusal before any journal write");
        require(!fs::exists(real/"root"/".prepare.lock"),"alias refusal before lock creation");}
    {Temp t;FakeRunner run;require(mkfifo((t.dir/"transaction.json").c_str(),0600)==0,"create FIFO fixture");
        // Bound the regression even against the former blocking constructor.
        auto pid=fork();require(pid>=0,"fork FIFO regression");
        if(pid==0){alarm(2);try{TransactionJournal j(t.dir,run.runner());_exit(1);}catch(const JournalError&){_exit(0);}catch(...){_exit(2);}}
        int status=0;require(waitpid(pid,&status,0)==pid,"wait FIFO regression");
        require(WIFEXITED(status)&&WEXITSTATUS(status)==0,"FIFO rejected without blocking");}
}
void sizeBoundary(){
    constexpr std::size_t limit=4*1024*1024;
    for(const auto size:{limit-64,limit}){
        Temp t;FakeRunner run;auto raw=initial();raw.pop_back();raw+=",\"padding\":\"";
        require(raw.size()+2<size,"padding fixture size");raw.append(size-raw.size()-2,'p');raw+="\"}";
        int checkpoints=0;
        {TransactionJournal j(t.dir,run.runner(),raw,[&](const std::string&){++checkpoints;});
            require(j.snapshot().size()==size,"exact serialized boundary fixture");j.save();
            std::ifstream beforeStream(t.dir/"transaction.json",std::ios::binary);
            const std::string before{std::istreambuf_iterator<char>(beforeStream),{}};
            require(before.size()==size,"bounded initial snapshot committed");checkpoints=0;
            rejects([&]{j.plan(target,image);},"oversized snapshot growth rejected");
            require(checkpoints==0,"oversized save refused before staging transition");
            std::ifstream afterStream(t.dir/"transaction.json",std::ios::binary);
            const std::string after{std::istreambuf_iterator<char>(afterStream),{}};
            require(after==before,"oversized save preserves last good bytes");
            for(const auto& entry:fs::directory_iterator(t.dir))require(entry.path().filename().string().find(".transaction-")!=0,"oversized save creates no staging file");
        }
        TransactionJournal reopened(t.dir,run.runner());
        require(reopened.snapshot().size()==size,"last good snapshot reopens at boundary");
        require(run.commands.empty(),"boundary fixture never invokes runner");
    }
    Temp t;FakeRunner run;auto raw=initial();raw.append(limit+1-raw.size(),' ');
    rejects([&]{TransactionJournal j(t.dir,run.runner(),raw);},"oversized initial JSON rejected");
}

}
int main(){try{core();faults();recovery();helperRecovery();malformed();cleanupFailure();transitionFaults();pathSafety();sizeBoundary();std::cout<<"transaction journal: 9 groups passed; no live runner\n";return 0;}catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
