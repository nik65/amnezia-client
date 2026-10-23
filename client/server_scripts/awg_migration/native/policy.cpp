#include "policy.h"
#include <algorithm>
#include <array>
#include <arpa/inet.h>
#include <filesystem>
#include <fstream>
#include <json-c/json.h>
#include <memory>
#include <regex>
#include <rapidjson/document.h>
#include <rapidjson/memorystream.h>
#include <cstring>
#include <set>
#include <sstream>
#include <cerrno>
#include <limits>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
namespace amnezia::awgMigration::policy  {
    namespace  {
        [[noreturn]] void fail(const char *s) {
            throw Error(s);
        }
        std::size_t whitespace(const std::string &s,std::size_t at) {
            const auto c=static_cast<unsigned char>(s[at]);
            if((c>=9&&c<=13)||(c>=0x1c&&c<=0x20))return 1;
            if(at+1<s.size()&&c==0xc2) {
                const auto next=static_cast<unsigned char>(s[at+1]);
                if(next==0x85||next==0xa0)return 2;
            }
            if(at+2>=s.size())return 0;
            const auto second=static_cast<unsigned char>(s[at+1]);
            const auto third=static_cast<unsigned char>(s[at+2]);
            if(c==0xe1&&second==0x9a&&third==0x80)return 3;
            if(c==0xe2&&((second==0x80&&((third>=0x80&&third<=0x8a)||third==0xa8||third==0xa9||third==0xaf))
                ||(second==0x81&&third==0x9f)))return 3;
            if(c==0xe3&&second==0x80&&third==0x80)return 3;
            return 0;
        }
        std::string trim(std::string s) {
            // Match Python str.strip's Unicode whitespace without changing the
            // spelling of any remaining command/output bytes.
            std::size_t begin=0;
            while(begin<s.size()) {const auto width=whitespace(s,begin);if(!width)break;begin+=width;}
            std::size_t end=begin;
            for(auto at=begin;at<s.size();) {
                const auto width=whitespace(s,at);
                if(width)at+=width;else end=++at;
            }
            return s.substr(begin,end-begin);
        }
        Lines lines(const std::string &s) {
            // Python decoded-text splitlines: CRLF is one separator, interior
            // empty records remain, and a final separator adds no extra record.
            Lines result;
            std::size_t begin=0;
            for(std::size_t at=0;at<s.size();) {
                const auto c=static_cast<unsigned char>(s[at]);
                std::size_t separator=0;
                if(c=='\r')separator=at+1<s.size()&&s[at+1]=='\n'?2:1;
                else if(c=='\n'||c=='\v'||c=='\f'||(c>=0x1c&&c<=0x1e))separator=1;
                else if(c==0xc2&&at+1<s.size()&&static_cast<unsigned char>(s[at+1])==0x85)separator=2;
                else if(c==0xe2&&at+2<s.size()&&static_cast<unsigned char>(s[at+1])==0x80
                    &&(static_cast<unsigned char>(s[at+2])==0xa8||static_cast<unsigned char>(s[at+2])==0xa9))separator=3;
                if(!separator){++at;continue;}
                result.push_back(s.substr(begin,at-begin));
                at+=separator;begin=at;
            }
            if(begin<s.size())result.push_back(s.substr(begin));
            return result;
        }
        Lines split(const std::string &s,char sep) {
            Lines r;
            std::istringstream in(s);
            std::string v;
            while(std::getline(in,v,sep))r.push_back(v);
            if(!s.empty()&&s.back()==sep)r.push_back("");
            return r;
        }
        std::string join(const Lines &v,const std::string &sep=" ") {
            std::string r;
            for(const auto &s:v) {
                if(&s!=&v.front())r+=sep;
                r+=s;
            }
            return r;
        }
        Lines shell(const std::string &s) {
            Lines r;
            std::string token;
            char quote=0;
            bool active=false;
            for(std::size_t i=0;i<s.size();++i) {
                char c=s[i];
                if(quote=='\'') {
                    if(c=='\'')quote=0;
                    else token+=c;
                    active=true;
                    continue;
                }
                if(c=='\\') {
                    if(i+1==s.size())fail("shell syntax");
                    char next=s[++i];
                    if(quote=='"'&&next!='"'&&next!='\\')token+='\\';
                    token+=next;
                    active=true;
                    continue;
                }
                if(c=='"'||c=='\'') {
                    if(!quote) {
                        quote=c;
                        active=true;
                        continue;
                    }
                    if(c==quote) {
                        quote=0;
                        continue;
                    }
                }
                if(!quote&&(c==' '||c=='\t'||c=='\r'||c=='\n')) {
                    if(active) {
                        r.push_back(token);
                        token.clear();
                        active=false;
                    }
                }
                else {
                    token+=c;
                    active=true;
                }
            }
            if(quote)fail("shell syntax");
            if(active)r.push_back(token);
            return r;
        }
        bool has(const Lines &v,const std::string &s) {
            return std::find(v.begin(),v.end(),s)!=v.end();
        }
        std::string get(const Fields &f,const std::string &k) {
            auto i=f.find(k);
            if(i==f.end())fail("missing field");
            return i->second;
        }
        std::string optional(const Fields &f,const std::string &k) {
            auto i=f.find(k);
            return i==f.end()?"":i->second;
        }
        struct Address  {
            int family;
            std::array<unsigned char,16> bytes {
            };
            unsigned prefix;
            std::string ip,network;
        };
        Address address(const std::string &value,bool strictNetwork=false) {
            Address a {
            };
            auto slash=value.find('/');
            auto host=value.substr(0,slash);
            a.family=host.find(':')==std::string::npos?AF_INET:AF_INET6;
            unsigned width=a.family==AF_INET?32:128;
            a.prefix=width;
            auto zone=host.find('%');
            if(zone!=std::string::npos) {
                if(a.family!=AF_INET6||zone+1==host.size())fail("configuration address");
                host.resize(zone);
            }
            if(host.find('\0')!=std::string::npos)fail("configuration address");
            if(inet_pton(a.family,host.c_str(),a.bytes.data())!=1)fail("configuration address");
            if(slash!=std::string::npos) {
                auto mask=value.substr(slash+1);
                if(mask.empty())fail("configuration address");
                if(mask.find('.')!=std::string::npos&&a.family==AF_INET) {
                    std::array<unsigned char,4> m {
                    };
                    if(mask.find('\0')!=std::string::npos)fail("configuration address");
                    if(inet_pton(AF_INET,mask.c_str(),m.data())!=1)fail("configuration address");
                    std::uint32_t n=0;
                    for(auto c:m)n=(n<<8)|c;
                    auto contiguous=[](std::uint32_t x) {
                        return ((~x)&((~x)+1))==0;
                    };
                    if(!contiguous(n)) {
                        n=~n;
                        if(!contiguous(n))fail("configuration address");
                    }
                    a.prefix=0;
                    for(;n;n<<=1)++a.prefix;
                }
                else {
                    a.prefix=0;
                    for(unsigned char c:mask) {
                        if(c<'0'||c>'9'||a.prefix>width)fail("configuration address");
                        a.prefix=a.prefix*10+c-'0';
                    }
                    if(a.prefix>width)fail("configuration address");
                }
            }
            char text[INET6_ADDRSTRLEN];
            inet_ntop(a.family,a.bytes.data(),text,sizeof(text));
            a.ip=text;
            auto masked=a.bytes;
            for(unsigned n=0;n<width;++n)if(n>=a.prefix)masked[n/8]&=static_cast<unsigned char>(~(1u<<(7-n%8)));
            if(strictNetwork&&masked!=a.bytes)fail("configuration address");
            inet_ntop(a.family,masked.data(),text,sizeof(text));
            a.network=std::string(text)+"/"+std::to_string(a.prefix);
            return a;
        }
        std::string ipv4(const std::string &s) {
            auto a=address(s);
            if(a.family!=AF_INET||s.find('/')!=std::string::npos)fail("configuration address");
            return a.ip;
        }
        using Set=std::set<std::string>;
        Set normalized(const Lines &v,const std::string &iface) {
            Set s;
            for(const auto &r:v)s.insert(normalize(r,iface));
            return s;
        }
        Lines groupFor(const Lines &v,const Set &chains) {
            Lines r;
            for(const auto &line:v) {
                for(const auto &t:shell(line))if(chains.count(t)) {
                    r.push_back(line);
                    break;
                }
            }
            return r;
        }
        using Captures=std::array<std::string,3>;
        bool digit(unsigned char c) { return c>='0'&&c<='9'; }
        bool asciiSpace(unsigned char c) { return c==' '||(c>=9&&c<=13); }
        bool word(unsigned char c) {
            return digit(c)||(c>='a'&&c<='z')||(c>='A'&&c<='Z')||c=='_';
        }
        // The accepted command-output grammar is fixed. Scan it without the
        // recursive std::regex engine: even rejected long numeric fields must
        // not consume the process stack. No extra field-length cap is needed.
        struct Cursor {
            const std::string &text;
            std::size_t at=0;
            bool take(std::string_view value) {
                if(text.compare(at,value.size(),value)!=0)return false;
                at+=value.size();return true;
            }
            bool number(std::string &value,bool dots=false) {
                const auto begin=at;
                while(at<text.size()&&(digit(static_cast<unsigned char>(text[at]))||(dots&&text[at]=='.')))++at;
                value=text.substr(begin,at-begin);return at>begin;
            }
            bool protocol(std::string &value) {
                if(take("tcp")){value="tcp";return true;}
                if(take("udp")){value="udp";return true;}
                return false;
            }
            std::size_t spaces() {
                const auto begin=at;
                while(at<text.size()&&asciiSpace(static_cast<unsigned char>(text[at])))++at;
                return at-begin;
            }
            bool end() const { return at==text.size(); }
        };
        bool dockerRule(const std::string &line,bool destination,Captures &m) {
            Cursor c{line};
            return c.take(destination?"-A DOCKER_OUTPUT -d 127.0.0.11/32 -p ":"-A DOCKER_POSTROUTING -s 127.0.0.11/32 -p ")
                &&c.protocol(m[1])&&c.take(" -m ")&&c.take(m[1])
                &&c.take(destination?" --dport 53 -j DNAT --to-destination 127.0.0.11:":" --sport ")
                &&c.number(m[2])&&(destination||c.take(" -j SNAT --to-source :53"))&&c.end();
        }
        enum class ProxyRule { Pre, Post, Dnat, Masquerade };
        bool proxyRule(const std::string &line,ProxyRule kind,Captures &m) {
            Cursor c{line};
            if(kind==ProxyRule::Pre)
                return c.take("-A PREROUTING -d ")&&c.number(m[1],true)&&c.take("/32 -p ")
                    &&c.protocol(m[2])&&c.take(" -m ")&&c.take(m[2])
                    &&c.take(" --dport 53 -j SERVERX_DNS_PROXY_PRE")&&c.end();
            if(kind==ProxyRule::Post)
                return c.take("-A POSTROUTING -p ")&&c.protocol(m[1])&&c.take(" -m ")&&c.take(m[1])
                    &&c.take(" --dport 53 -j SERVERX_DNS_PROXY_POST")&&c.end();
            if(kind==ProxyRule::Dnat)
                return c.take("-A SERVERX_DNS_PROXY_PRE -p ")&&c.protocol(m[1])
                    &&c.take(" -j DNAT --to-destination ")&&c.number(m[2],true)&&c.take(":53")&&c.end();
            return c.take("-A SERVERX_DNS_PROXY_POST -d ")&&c.number(m[1],true)
                &&c.take("/32 -j MASQUERADE")&&c.end();
        }
        bool lookupRule(const std::string &line,Captures &m) {
            Cursor c{line};c.spaces();
            if(!c.number(m[1])||!c.take(":")||!c.spaces()||!c.take("from all lookup "))return false;
            for(const auto name:{"local","main","default"}) {
                if(c.take(name)){m[2]=name;c.spaces();return c.end();}
            }
            return false;
        }
        std::optional<std::string> observedMtu(const std::string &line) {
            std::size_t at=0;
            while((at=line.find("mtu ",at))!=std::string::npos) {
                const auto begin=at+4;
                if(!at||!word(static_cast<unsigned char>(line[at-1]))) {
                    auto end=begin;
                    while(end<line.size()&&digit(static_cast<unsigned char>(line[end])))++end;
                    if(end>begin&&(end==line.size()||!word(static_cast<unsigned char>(line[end]))))
                        return line.substr(begin,end-begin);
                }
                at=begin;
            }
            return std::nullopt;
        }
    }
    int mtu(const std::string &v) {
        if(!std::regex_match(v,std::regex("[0-9]{3,4}")))fail("unsupported_mtu");
        int n=std::stoi(v);
        if(n<576||n>9000)fail("unsupported_mtu");
        return n;
    }
    Lines standardFilter(const std::string &i,const std::string &n) {
        return  {
            "-A INPUT -i "+i+" -j ACCEPT","-A FORWARD -i "+i+" -j ACCEPT","-A OUTPUT -o "+i+" -j ACCEPT","-A FORWARD -s "+n+" -i "+i+" -o eth0 -j ACCEPT","-A FORWARD -s "+n+" -i "+i+" -o eth1 -j ACCEPT","-A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT"
        };
    }
    std::string normalize(const std::string &rule,const std::string &iface) {
        auto tokens=shell(rule);
        for(auto &t:tokens)if(t==iface||t=="%i")t="awg0";
        for(const auto &name: {
            "--state","--ctstate"
        }) {
            auto i=std::find(tokens.begin(),tokens.end(),name);
            if(i!=tokens.end()) {
                if(++i==tokens.end())fail("missing state");
                auto v=split(*i,',');
                std::sort(v.begin(),v.end());
                *i=join(v,",");
            }
        }
        return join(tokens);
    }
    void validateHooks(const Fields &interface,const std::string &iface) {
        auto network=address(get(interface,"Address")).network;
        auto allowed=normalized(standardFilter(iface,network),iface);
        for(const auto &eth: {
            "eth0","eth1"
        })allowed.insert(normalize("-A FORWARD -i "+iface+" -o "+eth+" -j ACCEPT",iface));
        for(const auto &entry:std::array<std::pair<std::string,std::string>,2> {
            {
                {
                    "PostUp","-A"
                }, {
                    "PostDown","-D"
                }
            }
        })for(const auto &command:split(optional(interface,entry.first),';')) {
            if(trim(command).empty())continue;
            auto tokens=shell(command);
            if(tokens.empty()||tokens.front()!="iptables"||!has(tokens,entry.second))fail("unsupported_namespace_hook");
            tokens.erase(tokens.begin());
            *std::find(tokens.begin(),tokens.end(),entry.second)="-A";
            if(tokens.size()>=2&&tokens[0]=="-t"&&tokens[1]=="nat") {
                tokens.erase(tokens.begin(),tokens.begin()+2);
                Set nat;
                for(const auto &eth: {
                    "eth0","eth1"
                }) {
                    nat.insert(normalize("-A POSTROUTING -s "+network+" -o "+eth+" -j MASQUERADE",iface));
                    nat.insert(normalize(std::string("-A POSTROUTING -o ")+eth+" -j MASQUERADE",iface));
                }
                if(!nat.count(normalize(join(tokens),iface)))fail("unsupported_namespace_hook");
            }
            else if(!allowed.count(normalize(join(tokens),iface)))fail("unsupported_namespace_hook");
        }
    }
    DockerDns dockerDnsRules(const Lines &input) {
        auto group=groupFor(input, {
            "DOCKER_OUTPUT","DOCKER_POSTROUTING"
        });
        if(group.empty())return  {
            input,false
        };
        Set fixed= {
            "-N DOCKER_OUTPUT","-N DOCKER_POSTROUTING","-A OUTPUT -d 127.0.0.11/32 -j DOCKER_OUTPUT","-A POSTROUTING -d 127.0.0.11/32 -j DOCKER_POSTROUTING"
        };
        Set unique(group.begin(),group.end());
        if(group.size()!=8||unique.size()!=8||!std::includes(unique.begin(),unique.end(),fixed.begin(),fixed.end()))fail("unsupported_namespace_firewall");
        std::map<std::string,int> destinations,sources;
        for(const auto &line:group) {
            if(fixed.count(line))continue;
            Captures m;
            bool dest=dockerRule(line,true,m);
            if(!dest&&!dockerRule(line,false,m))fail("unsupported_namespace_firewall");
            auto &ports=dest?destinations:sources;
            unsigned long port=0;
            try {
                port=std::stoul(m[2]);
            }
            catch(...) {
                fail("unsupported_namespace_firewall");
            }
            if(ports.count(m[1])||port<1024||port>65535)fail("unsupported_namespace_firewall");
            ports[m[1]]=static_cast<int>(port);
        }
        if(destinations.size()!=2||sources!=destinations)fail("unsupported_namespace_firewall");
        Lines remaining;
        for(const auto &line:input)if(!unique.count(line))remaining.push_back(line);
        return  {
            remaining,true
        };
    }
    Lines serverDnsProxyRules(const Lines &input,const std::string &sourceAddress) {
        auto group=groupFor(input, {
            "SERVERX_DNS_PROXY_PRE","SERVERX_DNS_PROXY_POST"
        });
        if(group.empty())return  {
        };
        Set decl= {
            "-N SERVERX_DNS_PROXY_PRE","-N SERVERX_DNS_PROXY_POST"
        },unique(group.begin(),group.end());
        if(group.size()!=13||unique.size()!=13||!std::includes(unique.begin(),unique.end(),decl.begin(),decl.end()))fail("unsupported_namespace_firewall");
        std::map<std::string,Set> selectors;
        Set post;
        Fields destinations;
        std::string masquerade;
        for(const auto &line:group) {
            if(decl.count(line))continue;
            Captures m;
            if(proxyRule(line,ProxyRule::Pre,m)) {
                if(!selectors[m[1]].insert(m[2]).second)fail("unsupported_namespace_firewall");
            }
            else if(proxyRule(line,ProxyRule::Post,m)) {
                if(!post.insert(m[1]).second)fail("unsupported_namespace_firewall");
            }
            else if(proxyRule(line,ProxyRule::Dnat,m)) {
                if(!destinations.emplace(m[1],m[2]).second)fail("unsupported_namespace_firewall");
            }
            else if(proxyRule(line,ProxyRule::Masquerade,m)&&masquerade.empty())masquerade=m[1];
            else fail("unsupported_namespace_firewall");
        }
        Set addresses;
        for(const auto &v:selectors)addresses.insert(v.first);
        for(const auto &v:destinations)addresses.insert(v.second);
        addresses.insert(masquerade);
        for(const auto &s:addresses) {
            try {
                auto a=address(s);
                auto first=a.bytes[0];
                if(a.family!=AF_INET||a.ip!=s||(first>=224&&first<=239)||s=="0.0.0.0"||first==127||s=="255.255.255.255")fail("unsupported_namespace_firewall");
            }
            catch(...) {
                fail("unsupported_namespace_firewall");
            }
        }
        Set expected= {
            address(sourceAddress).ip,"1.0.0.1","172.29.172.254"
        },actual;
        for(const auto &v:selectors) {
            actual.insert(v.first);
            if(v.second!=Set {
                "tcp","udp"
            })fail("unsupported_namespace_firewall");
        }
        if(expected.size()!=3||actual!=expected||post!=Set {
            "tcp","udp"
        }
        ||destinations.size()!=2||destinations["tcp"]!="172.29.172.254"||destinations["udp"]!="172.29.172.254"||masquerade!="172.29.172.254")fail("unsupported_namespace_firewall");
        return group;
    }
    Snapshot namespaceSnapshot(const Runner &run,const std::string &container,const Fields &interface,const std::string &iface,const Lines &ownedComments) {
        validateHooks(interface,iface);
        auto network=address(get(interface,"Address")).network;
        auto exec=[&](Lines args) {
            Lines command= {
                "docker","exec",container
            };
            command.insert(command.end(),args.begin(),args.end());
            return run(command);
        };
        std::smatch match;
        auto link=exec( {
            "ip","-o","link","show","dev",iface
        });
        const auto observed=observedMtu(link);
        if(!observed)fail("source_mtu_unobserved");
        Snapshot s;
        s.mtu=mtu(*observed);
        if(interface.count("MTU")&&mtu(interface.at("MTU"))!=s.mtu)fail("source_mtu_drift");
        std::map<int,std::string> expected= {
            {
                0,"local"
            }, {
                32766,"main"
            }, {
                32767,"default"
            }
        };
        for(const auto &rule:lines(trim(exec( {
            "ip","rule","show"
        })))) {
            Captures ruleMatch;
            if(!lookupRule(rule,ruleMatch))fail("unsupported_namespace_ip_rule");
            int priority;
            try {
                priority=std::stoi(ruleMatch[1]);
            }
            catch(...) {
                fail("unsupported_namespace_ip_rule");
            }
            auto it=expected.find(priority);
            if(it==expected.end()||it->second!=ruleMatch[2])fail("unsupported_namespace_ip_rule");
            expected.erase(it);
        }
        if(!expected.empty())fail("incomplete_namespace_ip_rules");
        auto filter=normalized(standardFilter(iface,network),iface);
        filter.insert(normalize("-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",iface));
        Set nat;
        for(const auto &eth: {
            "eth0","eth1"
        }) {
            filter.insert(normalize("-A FORWARD -i "+iface+" -o "+eth+" -j ACCEPT",iface));
            nat.insert(normalize("-A POSTROUTING -s "+network+" -o "+eth+" -j MASQUERADE",iface));
            nat.insert(normalize(std::string("-A POSTROUTING -o ")+eth+" -j MASQUERADE",iface));
        }
        for(const auto &entry:std::array<std::pair<int,std::string>,3> {
            {
                {
                    17864,"172.29.172.253"
                }, {
                    17865,"172.29.172.252"
                }, {
                    17866,"172.29.172.251"
                }
            }
        })nat.insert(normalize("-A PREROUTING -d "+entry.second+"/32 -i "+iface+" -p tcp -m tcp --dport "+std::to_string(entry.first)+" -j REDIRECT --to-ports "+std::to_string(entry.first),iface));
        for(const auto &table: {
            "raw","mangle"
        })for(const auto &line:lines(exec( {
            "iptables","-t",table,"-S"
        }))) {
            auto tokens=shell(line);
            if(line.rfind("-P ",0)!=0||tokens.empty()||tokens.back()!="ACCEPT")fail("unsupported_namespace_firewall");
        }
        for(const auto &table: {
            "filter","nat"
        }) {
            auto raw=lines(exec( {
                "iptables","-t",table,"-S"
            }));
            auto allowed=std::string(table)=="filter"?filter:nat;
            Lines proxy;
            if(std::string(table)=="nat") {
                auto d=dockerDnsRules(raw);
                raw=d.remaining;
                s.dockerDns=d.present;
                proxy=serverDnsProxyRules(raw,get(interface,"Address"));
                for(const auto &r:proxy)allowed.insert(normalize(r,iface));
            }
            auto &output=std::string(table)=="filter"?s.filter:s.nat;
            for(const auto &line:raw) {
                auto tokens=shell(line);
                if(line.rfind("-P ",0)==0) {
                    if(tokens.empty()||tokens.back()!="ACCEPT")fail("unsupported_namespace_default_policy");
                    continue;
                }
                auto comment=std::find(tokens.begin(),tokens.end(),"--comment");
                if(comment!=tokens.end()) {
                    if(++comment==tokens.end())fail("missing state");
                    if(has(ownedComments,*comment)&&has(tokens,"18082"))continue;
                }
                auto rule=normalize(line,iface);
                if(!allowed.count(rule))fail("unsupported_namespace_firewall");
                output.push_back(rule);
            }
            if(proxy.empty())std::sort(output.begin(),output.end());
            else std::stable_partition(output.begin(),output.end(),[](const auto &r) {
                return r.rfind("-N ",0)==0;
            });
        }
        for(const auto &line:lines(exec( {
            "ip","route","show","table","main"
        }))) {
            auto t=shell(line);
            if(t.size()==5&&t[0]=="default"&&t[1]=="via"&&t[3]=="dev"&&(t[4]=="eth0"||t[4]=="eth1"))s.routes.push_back("default via "+ipv4(t[2])+" dev "+t[4]);
            else if(t.size()==9&&t[1]=="dev"&&t[3]=="proto"&&t[4]=="kernel"&&t[5]=="scope"&&t[6]=="link"&&t[7]=="src") {
                auto a=address(t[0],true);
                if(a.family!=AF_INET)fail("configuration address");
                ipv4(t[8]);
                if((t[2]!=iface&&t[2]!="eth0"&&t[2]!="eth1")||(t[2]==iface&&a.network!=network))fail("unsupported_namespace_route");
                s.routes.push_back(a.network+" dev "+(t[2]==iface?"awg0":t[2]));
            }
            else fail("unsupported_namespace_route");
        }
        std::sort(s.routes.begin(),s.routes.end());
        for(const auto &a: {
            "1.1.1.1","8.8.8.8","172.29.172.254","172.29.172.253"
        }) {
            auto route=exec( {
                "ip","route","get",a
            });
            if(!std::regex_search(route,match,std::regex(R"(\bdev (eth[01])\b)")))fail("unsupported_namespace_egress");
            s.egress[a]=match[1];
        }
        return s;
    }
    std::string firewallScript(const Snapshot &s) {
        std::string result;
        for(const auto &table: {
            "filter","nat"
        }) {
            auto rules=std::string(table)=="filter"?s.filter:s.nat;
            std::stable_partition(rules.begin(),rules.end(),[](const auto &r) {
                return r.rfind("-N ",0)==0;
            });
            for(const auto &r:rules)result+="iptables -t "+std::string(table)+" "+r+"\n";
        }
        return result.empty()?"\n":result;
    }
    std::optional<Epoch> clientPolicyEpoch(bool exists,const std::optional<std::string> &raw) {
        if(!exists)return  {
        };
        if(!raw)fail("managed_client_policy_not_ready");
        json_tokener *tok=json_tokener_new();
        if(!tok)fail("policy allocation");
        // Never silently narrow a Python integer into a different epoch.
        if(raw->size()>static_cast<std::size_t>(std::numeric_limits<int>::max())) {
            json_tokener_free(tok);
            fail("policy JSON");
        }
        json_tokener_set_flags(tok,JSON_TOKENER_STRICT | JSON_TOKENER_VALIDATE_UTF8);
        errno=0;
        json_object *parsed=json_tokener_parse_ex(tok,raw->data(),static_cast<int>(raw->size()));
        auto err=json_tokener_get_error(tok);
        const bool rangeError=errno==ERANGE;
        json_tokener_free(tok);
        std::unique_ptr<json_object,decltype(&json_object_put)> root(parsed,json_object_put);
        if(err!=json_tokener_success||!root)fail("policy JSON");
        if(rangeError)fail("policy revision range");
        // json-c bounds depth/range above, but its object keys use C strings.
        // Read required names/values from a lossless tree with Python last-wins semantics.
        rapidjson::MemoryStream stream(raw->data(),raw->size());
        rapidjson::Document lossless;
        lossless.ParseStream<rapidjson::kParseValidateEncodingFlag | rapidjson::kParseNanAndInfFlag>(stream);
        if(lossless.HasParseError()||stream.Tell()!=raw->size())fail("policy JSON");
        const auto last=[](const rapidjson::Value &object,const char *name)->const rapidjson::Value * {
            if(!object.IsObject())return nullptr;
            const rapidjson::Value *found=nullptr;
            const auto length=std::strlen(name);
            for(auto i=object.MemberBegin();i!=object.MemberEnd();++i)
                if(i->name.GetStringLength()==length&&std::memcmp(i->name.GetString(),name,length)==0)found=&i->value;
            return found;
        };
        const auto *policy=last(lossless,"policy");
        const auto *revision=policy?last(*policy,"revision"):nullptr;
        const auto *hash=policy?last(*policy,"contentSha256"):nullptr;
        if(revision&&revision->IsUint64()&&!revision->IsInt64())fail("policy revision range");
        if(!revision||!revision->IsInt64()||!hash||!hash->IsString())fail("managed_client_policy_not_versioned");
        std::string sha(hash->GetString(),hash->GetStringLength());
        if(!std::regex_match(sha,std::regex("sha256:[a-f0-9]{64}")))fail("managed_client_policy_not_versioned");
        return Epoch { revision->GetInt64(),sha };
    }
    std::optional<Epoch> clientPolicyEpoch(const std::string &directory) {
        constexpr std::size_t limit = 1024 * 1024;
        const auto reject = [] { fail("policy_source_untrusted"); };
        if (directory.empty() || directory.find('\0') != std::string::npos) reject();
        struct Descriptor {
            int fd;
            explicit Descriptor(int value) : fd(value) {}
            ~Descriptor() { if (fd >= 0) ::close(fd); }
            Descriptor(const Descriptor &) = delete;
            Descriptor &operator=(const Descriptor &) = delete;
        };
        const auto same = [](const struct stat &a, const struct stat &b) {
            return a.st_dev == b.st_dev && a.st_ino == b.st_ino &&
                a.st_mode == b.st_mode && a.st_nlink == b.st_nlink &&
                a.st_uid == b.st_uid && a.st_gid == b.st_gid && a.st_size == b.st_size &&
                a.st_mtim.tv_sec == b.st_mtim.tv_sec && a.st_mtim.tv_nsec == b.st_mtim.tv_nsec &&
                a.st_ctim.tv_sec == b.st_ctim.tv_sec && a.st_ctim.tv_nsec == b.st_ctim.tv_nsec;
        };
        std::vector<std::unique_ptr<Descriptor>> parents;
        std::vector<struct stat> parentStats;
        Lines names;
        parents.emplace_back(new Descriptor(::open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)));
        if (parents.back()->fd < 0) reject();
        struct stat rootStat{};
        if (::fstat(parents.back()->fd, &rootStat) != 0) reject();
        parentStats.push_back(rootStat);
        const auto absolute = std::filesystem::absolute(directory).lexically_normal();
        for (const auto &part : absolute.relative_path()) {
            const auto name = part.string();
            if (name.empty() || name == ".") continue;
            int fd = ::openat(parents.back()->fd, name.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (fd < 0) { if (errno == ENOENT) return {}; reject(); }
            parents.emplace_back(new Descriptor(fd));
            struct stat state{};
            if (::fstat(fd, &state) != 0 || !S_ISDIR(state.st_mode)) reject();
            parentStats.push_back(state);
            names.push_back(name);
        }
        Descriptor file(::openat(parents.back()->fd, "rules.json", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC));
        if (file.fd < 0) {
            if (errno == ENOENT) fail("managed_client_policy_not_ready");
            reject();
        }
        struct stat before{};
        if (::fstat(file.fd, &before) != 0 || !S_ISREG(before.st_mode) || before.st_nlink != 1 ||
            before.st_size < 0 || static_cast<std::uint64_t>(before.st_size) > limit) reject();
        std::string raw;
        std::array<char, 16384> buffer{};
        while (true) {
            const auto count = ::read(file.fd, buffer.data(), std::min(buffer.size(), limit + 1 - raw.size()));
            if (count < 0 && errno == EINTR) continue;
            if (count < 0) reject();
            if (count == 0) break;
            raw.append(buffer.data(), static_cast<std::size_t>(count));
            if (raw.size() > limit) reject();
        }
        // Coarse timestamps must not hide a same-size in-place rewrite.
        if (::lseek(file.fd, 0, SEEK_SET) < 0) reject();
        std::string confirmed;
        while (true) {
            const auto count = ::read(file.fd, buffer.data(), std::min(buffer.size(), limit + 1 - confirmed.size()));
            if (count < 0 && errno == EINTR) continue;
            if (count < 0) reject();
            if (count == 0) break;
            confirmed.append(buffer.data(), static_cast<std::size_t>(count));
            if (confirmed.size() > limit) reject();
        }
        if (confirmed != raw) reject();
        struct stat after{}, current{};
        if (::fstat(file.fd, &after) != 0 || !same(before, after) ||
            raw.size() != static_cast<std::uint64_t>(before.st_size) ||
            ::fstatat(parents.back()->fd, "rules.json", &current, AT_SYMLINK_NOFOLLOW) != 0 ||
            !same(before, current)) reject();
        // Verify the whole opened directory chain still names the pinned source.
        for (std::size_t i = 0; i < parents.size(); ++i) {
            struct stat state{};
            if (::fstat(parents[i]->fd, &state) != 0 || !same(parentStats[i], state)) reject();
            if (i && (::fstatat(parents[i - 1]->fd, names[i - 1].c_str(), &state, AT_SYMLINK_NOFOLLOW) != 0 ||
                      !same(parentStats[i], state))) reject();
        }
        return clientPolicyEpoch(true, raw);
    }
}
