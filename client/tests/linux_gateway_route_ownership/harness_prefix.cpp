
#ifdef NDEBUG
#error "Ownership regression assertions must remain enabled"
#endif
#include "linuxgatewayroutereceipt.h"
#include <cassert>
#include <cstring>
#include <cerrno>
#include <iostream>
#include <map>
#include <limits>
#include <string>
#include <vector>
#include <set>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
inline bool kernelPriorityMatches(unsigned request, unsigned route) { return request == 0 || request == route; }
struct Bytes  {
    std::string s;
    const char* constData()const {
        return s.c_str();
    }
};
struct QString  {
    std::string s;
    QString()=default;
    QString(const char*x):s(x) {
    };
    bool isEmpty()const {
        return s.empty();
    }
    Bytes toUtf8()const {
        return {
            s
        };
    }
    bool operator<(const QString&o)const {
        return s<o.s;
    }
    bool operator==(const QString&o)const {
        return s==o.s;
    }
};
struct Log  {
    Log debug() {
        return {
        };
    }
    Log warning() {
        return {
        };
    }
    template<class T>Log&operator<<(const T&) {
        return *this;
    }
}
logger;
namespace QAbstractSocket  {
    enum NetworkLayerProtocol {
        IPv4Protocol,IPv6Protocol
    };
}
struct IPAddress  {
    QString key;
    bool six=false;
    IPAddress(QString k,bool v6=false):key(k),six(v6) {
    }
    QString toString()const {
        return key;
    }
    QAbstractSocket::NetworkLayerProtocol type()const {
        return six?QAbstractSocket::IPv6Protocol:QAbstractSocket::IPv4Protocol;
    }
};
static unsigned liveIndex=7;
static bool validIface=true;
unsigned if_nametoindex(const char*) {
    return liveIndex;
}
struct QNetworkInterface  {
    QString n {
        "test0"
    };
    bool isValid()const {
        return validIface;
    }
    QString name()const {
        return n;
    }
    static QNetworkInterface interfaceFromName(const QString&n) {
        QNetworkInterface x;
        x.n=n;
        return x;
    }
};
namespace NetworkUtilities  {
    std::pair<QString,QNetworkInterface>getGatewayAndIface() {
        return {
            QString("10.0.0.1"),QNetworkInterface {
            }
        };
    }
}
template<class V>struct Map  {
    std::map<QString,V>m;
    struct iterator {
        typename std::map<QString,V>::iterator p;
        V&value() {
            return p->second;
        }
        bool operator==(iterator o)const {
            return p==o.p;
        }
        bool operator!=(iterator o)const {
            return p!=o.p;
        }
    };
    iterator find(const QString&k) {
        return {
            m.find(k)
        };
    }
    iterator end() {
        return {
            m.end()
        };
    }
    void insert(const QString&k,const V&v) {
        m[k]=v;
    }
    void erase(iterator i) {
        m.erase(i.p);
    }
    bool isEmpty()const {
        return m.empty();
    }
};
class LinuxRouteMonitor  {
    public:
    enum class EndpointRouteResult {
        Success,AlreadyExists,NotFound,Failed,Uncertain
    };
    enum class GatewayRouteOwner {
        Exclusion,Endpoint
    };
    struct EndpointRouteReceipt {
        QString gateway;
        QString interfaceName;
        unsigned interfaceIndex=0;uint32_t priority=amnezia::linux_routes::OwnedGatewayRoutePriority;
    };
    struct GatewayRouteState {
        EndpointRouteReceipt receipt;
        unsigned exclusionReferences=0;
        unsigned endpointReferences=0;
        bool uncertain=false;
        bool creationConfirmed=false;
    };
    int m_nlsock=3;
    Map<GatewayRouteState>m_ownedGatewayRoutes;
    bool multipleRoutes=false;
    std::set<QString>osRoutes;
    bool osRoute=false;
    bool foreign=false;
    bool foreignChangedTuple=false;
    std::set<unsigned> foreignOtherPriorities;
    int reads=0;
    EndpointRouteResult readback=EndpointRouteResult::Success;
    int creates=0,deletes=0,foreignDeletes=0;
    EndpointRouteResult nextCreate=EndpointRouteResult::Success,nextDelete=EndpointRouteResult::Success;
    static QString endpointRouteKey(const IPAddress&p) {
        return p.key;
    }
    bool addExclusionRoute(const IPAddress&);
    bool deleteExclusionRoute(const IPAddress&);
    EndpointRouteResult createEndpointRoute(const IPAddress&);
    EndpointRouteResult removeOwnedEndpointRoute(const IPAddress&);
    EndpointRouteResult acquireGatewayRoute(const IPAddress&,GatewayRouteOwner);
    EndpointRouteResult releaseGatewayRoute(const IPAddress&,GatewayRouteOwner);
    EndpointRouteResult verifyGatewayRoute(const IPAddress&prefix,const EndpointRouteReceipt&receipt) {
        if(receipt.priority!=amnezia::linux_routes::OwnedGatewayRoutePriority)return EndpointRouteResult::Uncertain;
        ++reads;
        return (multipleRoutes?osRoutes.count(prefix.key)!=0:osRoute)?readback:EndpointRouteResult::NotFound;
    }
    EndpointRouteResult rtmSendRoute(int action,int flags,int,const IPAddress&prefix,const EndpointRouteReceipt*receipt=nullptr) {
        assert(receipt&&receipt->interfaceIndex==7);
        assert(receipt->priority==amnezia::linux_routes::OwnedGatewayRoutePriority);
        if(multipleRoutes)osRoute=osRoutes.count(prefix.key)!=0;
        if(action==RTM_NEWROUTE) {
            ++creates;
            assert(flags&NLM_F_EXCL);
            assert(!(flags&NLM_F_REPLACE));
            if(osRoute || foreignOtherPriorities.count(receipt->priority))return EndpointRouteResult::AlreadyExists;
            if(nextCreate==EndpointRouteResult::Success||nextCreate==EndpointRouteResult::Uncertain)osRoute=true;
            if(multipleRoutes&&osRoute)osRoutes.insert(prefix.key);
            return nextCreate;
        }
        assert(action==RTM_DELROUTE);
        ++deletes;
        if (!osRoute) {
            for (auto metric : foreignOtherPriorities) {
                if (kernelPriorityMatches(receipt->priority, metric)) {
                    foreignOtherPriorities.erase(metric);
                    ++foreignDeletes;
                    return EndpointRouteResult::Success;
                }
            }
            return EndpointRouteResult::NotFound;
        }
        if(foreign&&foreignChangedTuple)return EndpointRouteResult::NotFound;
        assert(!foreign);
        if(nextDelete==EndpointRouteResult::Success||nextDelete==EndpointRouteResult::NotFound)osRoute=false;
        if(multipleRoutes&&!osRoute)osRoutes.erase(prefix.key);
        return nextDelete;
    }
};
#define Q_UNUSED(value) (void)value
class WireguardUtilsLinux  {
    public:
    struct EndpointRouteState  {
        QString endpoint;
        bool routeOwned=false;
        bool routeUncertain=false;
        bool peerRemoved=false;
    };
    LinuxRouteMonitor* m_rtmonitor=nullptr;
    bool cleanupEndpointRoute(const QString&,EndpointRouteState&);
};
