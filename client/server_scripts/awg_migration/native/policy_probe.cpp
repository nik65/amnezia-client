#include "policy.h"
#include <json-c/json.h>
#include <iostream>
#include <iterator>
#include <memory>
using namespace amnezia::awgMigration::policy;
namespace  {
    using Json=std::unique_ptr<json_object,decltype(&json_object_put)>;
    json_object *field(json_object *o,const char *k) {
        json_object *v=nullptr;
        json_object_object_get_ex(o,k,&v);
        return v;
    }
    std::string text(json_object *o) {
        return o?std::string(json_object_get_string(o),static_cast<std::size_t>(json_object_get_string_len(o))):"";
    }
    Lines list(json_object *o) {
        Lines r;
        for(std::size_t i=0;o&&i<json_object_array_length(o);++i)r.push_back(text(json_object_array_get_idx(o,i)));
        return r;
    }
    Fields fields(json_object *o) {
        Fields r;
        if(o) {
            json_object_object_foreach(o,k,v) {
                r[k]=text(v);
            }
        }
        return r;
    }
    json_object *array(const Lines &v) {
        auto a=json_object_new_array();
        for(const auto &s:v)json_object_array_add(a,json_object_new_string_len(s.data(),static_cast<int>(s.size())));
        return a;
    }
    json_object *object(const Fields &v) {
        auto o=json_object_new_object();
        for(const auto &kv:v)json_object_object_add(o,kv.first.c_str(),json_object_new_string(kv.second.c_str()));
        return o;
    }
    std::string joined(const Lines &v) {
        std::string r;
        for(const auto &s:v) {
            if(!r.empty())r+='\t';
            r+=s;
        }
        return r;
    }
}
int main() {
    std::string input {
        std::istreambuf_iterator<char>(std::cin), {
        }
    };
    Json in(json_tokener_parse(input.c_str()),json_object_put),out(json_object_new_object(),json_object_put);
    auto calls=json_object_new_array();
    json_object_object_add(out.get(),"calls",calls);
    try {
        auto op=text(field(in.get(),"op"));
        json_object *result=nullptr;
        auto iface=text(field(in.get(),"iface"));
        if(op=="mtu")result=json_object_new_int(mtu(text(field(in.get(),"value"))));
        else if(op=="normalize")result=json_object_new_string(normalize(text(field(in.get(),"rule")),iface).c_str());
        else if(op=="hooks") {
            validateHooks(fields(field(in.get(),"interface")),iface);
            result=json_object_new_null();
        }
        else if(op=="filter")result=array(standardFilter(iface,text(field(in.get(),"network"))));
        else if(op=="docker") {
            auto d=dockerDnsRules(list(field(in.get(),"lines")));
            result=json_object_new_array();
            json_object_array_add(result,array(d.remaining));
            json_object_array_add(result,json_object_new_boolean(d.present));
        }
        else if(op=="proxy")result=array(serverDnsProxyRules(list(field(in.get(),"lines")),text(field(in.get(),"address"))));
        else if(op=="epoch") {
            auto raw=field(in.get(),"raw");
            auto e=clientPolicyEpoch(json_object_get_boolean(field(in.get(),"exists")),raw&&json_object_get_type(raw)!=json_type_null?std::optional<std::string> {
                text(raw)
            }
            :std::nullopt);
            if(e) {
                result=json_object_new_object();
                json_object_object_add(result,"revision",json_object_new_int64(e->revision));
                json_object_object_add(result,"contentSha256",json_object_new_string(e->contentSha256.c_str()));
            }
            else result=json_object_new_null();
        }
        else if(op=="snapshot") {
            auto responses=field(in.get(),"responses");
            Runner run=[&](const Lines &args) {
                json_object_array_add(calls,array(args));
                Lines tail(args.begin()+3,args.end());
                auto v=field(responses,joined(tail).c_str());
                if(!v)throw Error("fixture runner missing command");
                return text(v);
            };
            auto s=namespaceSnapshot(run,"fixture-container",fields(field(in.get(),"interface")),iface,list(field(in.get(),"owned")));
            result=json_object_new_object();
            json_object_object_add(result,"mtu",json_object_new_int(s.mtu));
            json_object_object_add(result,"filter",array(s.filter));
            json_object_object_add(result,"nat",array(s.nat));
            json_object_object_add(result,"egress",object(s.egress));
            json_object_object_add(result,"dockerDns",json_object_new_boolean(s.dockerDns));
            json_object_object_add(result,"routes",array(s.routes));
        }
        else if(op=="firewall") {
            Snapshot s;
            s.filter=list(field(in.get(),"filter"));
            s.nat=list(field(in.get(),"nat"));
            result=json_object_new_string(firewallScript(s).c_str());
        }
        else throw Error("unknown operation");
        json_object_object_add(out.get(),"ok",result);
    }
    catch(const std::exception &e) {
        json_object_object_add(out.get(),"error",json_object_new_string(e.what()));
    }
    std::cout<<json_object_to_json_string_ext(out.get(),JSON_C_TO_STRING_PLAIN)<<'\n';
}
