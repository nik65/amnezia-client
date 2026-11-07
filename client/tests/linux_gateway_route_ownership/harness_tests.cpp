int main() {
    using R=LinuxRouteMonitor::EndpointRouteResult;
    const IPAddress ip {
        QString("192.0.2.7/32")
    };
    int passed=0;
    for(bool genericFirst:{true,false}) {
        LinuxRouteMonitor x;
        if(genericFirst) {
            assert(x.addExclusionRoute(ip));
            assert(x.createEndpointRoute(ip)==R::Success);
        }
        else {
            assert(x.createEndpointRoute(ip)==R::Success);
            assert(x.addExclusionRoute(ip));
        }
        assert(x.creates==1);
        assert(x.removeOwnedEndpointRoute(ip)==R::Success);
        assert(x.osRoute&&x.deletes==0);
        assert(x.deleteExclusionRoute(ip));
        assert(!x.osRoute&&x.deletes==1&&x.m_ownedGatewayRoutes.isEmpty());
        ++passed;
    }
    {
        LinuxRouteMonitor x;
        assert(x.addExclusionRoute(ip));
        assert(x.createEndpointRoute(ip)==R::Success);
        assert(x.deleteExclusionRoute(ip));
        assert(x.osRoute&&x.deletes==0);
        assert(x.removeOwnedEndpointRoute(ip)==R::Success);
        assert(!x.osRoute&&x.deletes==1);
        ++passed;
    }
    {
        LinuxRouteMonitor x;
        assert(x.addExclusionRoute(ip));
        assert(x.createEndpointRoute(ip)==R::Success);
        assert(x.createEndpointRoute(ip)==R::Success);
        assert(x.removeOwnedEndpointRoute(ip)==R::Success);
        assert(x.deleteExclusionRoute(ip));
        assert(x.osRoute);
        assert(x.removeOwnedEndpointRoute(ip)==R::Success);
        assert(x.creates==1&&x.deletes==1);
        ++passed;
    }
    {
        LinuxRouteMonitor x;
        x.osRoute=x.foreign=true;
        assert(!x.addExclusionRoute(ip));
        assert(x.createEndpointRoute(ip)==R::AlreadyExists);
        assert(x.deleteExclusionRoute(ip));
        assert(x.removeOwnedEndpointRoute(ip)==R::Uncertain);
        assert(x.osRoute&&x.creates==2&&x.deletes==0&&x.m_ownedGatewayRoutes.isEmpty());
        ++passed;
    }
    {
        LinuxRouteMonitor x;
        assert(x.addExclusionRoute(ip));
        assert(x.createEndpointRoute(ip)==R::Success);
        /* simulated peer UAPI failure rollback */assert(x.removeOwnedEndpointRoute(ip)==R::Success);
        assert(x.osRoute);
        assert(x.deleteExclusionRoute(ip));
        assert(!x.osRoute);
        ++passed;
    }
    {
        LinuxRouteMonitor x;
        assert(x.createEndpointRoute(ip)==R::Success);
        x.nextDelete=R::Failed;
        assert(x.removeOwnedEndpointRoute(ip)==R::Failed);
        assert(!x.m_ownedGatewayRoutes.isEmpty());
        x.nextDelete=R::Success;
        assert(x.removeOwnedEndpointRoute(ip)==R::Success);
        assert(x.deletes==2&&x.m_ownedGatewayRoutes.isEmpty());
        ++passed;
    }
    {
        LinuxRouteMonitor x;
        x.nextCreate=R::Uncertain;
        assert(!x.addExclusionRoute(ip));
        assert(x.createEndpointRoute(ip)==R::Failed);
        assert(!x.deleteExclusionRoute(ip));
        assert(x.osRoute&&x.deletes==0&&!x.m_ownedGatewayRoutes.isEmpty());
        ++passed;
    }
    {
        LinuxRouteMonitor x;
        const IPAddress ip6 {
            QString("2001:db8::7/128"),true
        };
        assert(!x.addExclusionRoute(ip6));
        assert(x.createEndpointRoute(ip6)==R::Failed);
        assert(x.deleteExclusionRoute(ip6));
        assert(x.removeOwnedEndpointRoute(ip6)==R::Uncertain);
        assert(x.creates==0&&x.deletes==0);
        ++passed;
    }
    {
        LinuxRouteMonitor x;
        assert(x.createEndpointRoute(ip)==R::Success);
        liveIndex=8;
        assert(x.removeOwnedEndpointRoute(ip)==R::Uncertain);
        assert(x.deletes==0&&!x.m_ownedGatewayRoutes.isEmpty());
        liveIndex=7;
        assert(x.removeOwnedEndpointRoute(ip)==R::Success);
        ++passed;
    }
    {
        LinuxRouteMonitor x;
        assert(x.addExclusionRoute(ip));
        x.nextDelete=R::NotFound;
        assert(x.deleteExclusionRoute(ip));
        assert(x.m_ownedGatewayRoutes.isEmpty());
        ++passed;
    }
    {
        LinuxRouteMonitor x;
        assert(x.createEndpointRoute(ip)==R::Success);
        auto i=x.m_ownedGatewayRoutes.find(ip.key);
        i.value().endpointReferences=std::numeric_limits<unsigned>::max();
        assert(x.createEndpointRoute(ip)==R::Failed);
        assert(x.creates==1);
        ++passed;
    }
    {
        LinuxRouteMonitor x;
        assert(x.addExclusionRoute(ip));
        x.foreign=true;
        x.foreignChangedTuple=true;
        x.readback=R::AlreadyExists;
        assert(x.createEndpointRoute(ip)==R::AlreadyExists);
        assert(x.creates==1);
        assert(x.deleteExclusionRoute(ip));
        assert(x.osRoute&&x.foreign&&x.m_ownedGatewayRoutes.isEmpty());
        ++passed;
    }
    {
        LinuxRouteMonitor x;
        assert(x.addExclusionRoute(ip));
        x.readback=R::Uncertain;
        assert(x.createEndpointRoute(ip)==R::Failed);
        assert(x.reads==1&&x.creates==1);
        assert(x.m_ownedGatewayRoutes.find(ip.key).value().endpointReferences==0);
        assert(x.deleteExclusionRoute(ip));
        ++passed;
    }
    {
        LinuxRouteMonitor x;
        assert(x.addExclusionRoute(ip));
        x.osRoute=false;
        assert(x.createEndpointRoute(ip)==R::Failed);
        assert(x.creates==1);
        assert(x.deleteExclusionRoute(ip));
        assert(x.m_ownedGatewayRoutes.isEmpty());
        assert(x.createEndpointRoute(ip)==R::Success);
        assert(x.creates==2);
        ++passed;
    }
    {
        LinuxRouteMonitor x;
        assert(x.createEndpointRoute(ip)==R::Success);
        x.nextDelete=R::Uncertain;
        assert(x.removeOwnedEndpointRoute(ip)==R::Uncertain);
        assert(x.m_ownedGatewayRoutes.find(ip.key).value().creationConfirmed);
        x.nextDelete=R::Success;
        assert(x.removeOwnedEndpointRoute(ip)==R::Success);
        assert(x.deletes==2&&x.m_ownedGatewayRoutes.isEmpty());
        ++passed;
    }
    {
        LinuxRouteMonitor x;
        assert(x.addExclusionRoute(ip));
        assert(x.reads==0);
        assert(x.createEndpointRoute(ip)==R::Success);
        assert(x.reads==1);
        assert(x.removeOwnedEndpointRoute(ip)==R::Success);
        assert(x.deleteExclusionRoute(ip));
        assert(x.reads==1);
        ++passed;
    }
    {
        LinuxRouteMonitor x;
        assert(x.createEndpointRoute(ip)==R::Success);
        WireguardUtilsLinux backend;
        backend.m_rtmonitor=&x;
        WireguardUtilsLinux::EndpointRouteState state;
        state.endpoint=ip.key;
        state.routeOwned=true;
        x.nextDelete=R::Uncertain;
        assert(!backend.cleanupEndpointRoute(QString("peer"),state));
        assert(state.routeUncertain&&state.routeOwned);
        x.nextDelete=R::Success;
        assert(backend.cleanupEndpointRoute(QString("peer"),state));
        assert(!state.routeOwned&&!state.routeUncertain);
        ++passed;
    }
    {
        LinuxRouteMonitor x;
        WireguardUtilsLinux backend;
        backend.m_rtmonitor=&x;
        WireguardUtilsLinux::EndpointRouteState state;
        state.endpoint=ip.key;
        state.routeUncertain=true;
        assert(!backend.cleanupEndpointRoute(QString("peer"),state));
        assert(x.deletes==0);
        ++passed;
    }
    {
        LinuxRouteMonitor x;
        assert(x.addExclusionRoute(ip));
        x.m_nlsock=-1;
        assert(x.createEndpointRoute(ip)==R::Failed);
        assert(x.creates==1&&x.reads==0);
        ++passed;
    }
    {
        LinuxRouteMonitor x;
        x.multipleRoutes=true;
        std::vector<IPAddress>prefixes;
        for(int i=0;i<1253;++i) {
            QString key;
            key.s="test-prefix-"+std::to_string(i);
            prefixes.emplace_back(key);
            assert(x.addExclusionRoute(prefixes.back()));
        }
        assert(x.reads==0&&x.creates==1253);
        for(const auto&prefix:prefixes)assert(x.deleteExclusionRoute(prefix));
        assert(x.reads==0&&x.deletes==1253&&x.osRoutes.empty()&&x.m_ownedGatewayRoutes.isEmpty());
        ++passed;
    }
    // Kernel fib_table_delete applies priority only when fc_priority != 0.
    // This inert predicate is the kernel semantic missed by the V2 fake.
    {
        auto kernelSelects = [](unsigned requested, unsigned actual) {
            return kernelPriorityMatches(requested, actual);
        };
        assert(kernelSelects(0, 5)); // OLD RED: disappeared own0 can delete foreign5.
        assert(!kernelSelects(amnezia::linux_routes::OwnedGatewayRoutePriority, 5));
        assert(!kernelSelects(amnezia::linux_routes::OwnedGatewayRoutePriority, 0));
        assert(kernelSelects(amnezia::linux_routes::OwnedGatewayRoutePriority, 1));
        ++passed;
    }
    {
        LinuxRouteMonitor x;
        x.foreignOtherPriorities = {0, 5};
        assert(x.addExclusionRoute(ip));
        assert(x.createEndpointRoute(ip) == R::Success);
        assert(x.removeOwnedEndpointRoute(ip) == R::Success);
        assert(x.deleteExclusionRoute(ip));
        assert(x.foreignOtherPriorities == std::set<unsigned>({0, 5}));
        assert(x.creates == 1 && x.deletes == 1);
        ++passed;
    }
    {
        // Never issue DEL0 even if a future stale/migrated receipt appears.
        LinuxRouteMonitor x;
        assert(x.addExclusionRoute(ip));
        x.m_ownedGatewayRoutes.find(ip.key).value().receipt.priority = 0;
        assert(x.createEndpointRoute(ip) == R::Failed);
        assert(!x.deleteExclusionRoute(ip));
        assert(x.deletes == 0);
        ++passed;
    }
    {
        // Own exclusions retain preference for equal prefixes; /1 VPN split
        // routes still beat a /0 physical default by longest-prefix matching.
        using namespace amnezia::linux_routes;
        assert(OwnedGatewayRoutePriority > 0);
        assert(OwnedGatewayRoutePriority < TunnelRoutePriority);
        auto preferred = [](unsigned lengthA, unsigned metricA,
                            unsigned lengthB, unsigned metricB) {
            return lengthA > lengthB || (lengthA == lengthB && metricA < metricB);
        };
        assert(preferred(32, OwnedGatewayRoutePriority, 32, TunnelRoutePriority));
        assert(preferred(1, TunnelRoutePriority, 0, 0)); // 0.0.0.0/1
        assert(preferred(1, TunnelRoutePriority, 0, 0)); // 128.0.0.0/1
        assert(preferred(32, OwnedGatewayRoutePriority, 1, TunnelRoutePriority));
        ++passed;
    }
    {
        LinuxRouteMonitor x;
        assert(x.createEndpointRoute(ip) == R::Success);
        x.osRoute = false; // Own metric1 disappeared before cleanup.
        x.foreignOtherPriorities = {0, 5};
        assert(x.removeOwnedEndpointRoute(ip) == R::NotFound);
        assert(x.foreignDeletes == 0);
        assert(x.foreignOtherPriorities == std::set<unsigned>({0, 5}));
        ++passed;
    }
    {
        LinuxRouteMonitor x;
        x.foreignOtherPriorities = {1};
        assert(!x.addExclusionRoute(ip));
        assert(x.createEndpointRoute(ip) == R::AlreadyExists);
        assert(x.deleteExclusionRoute(ip));
        assert(x.deletes == 0 && x.foreignDeletes == 0);
        assert(x.foreignOtherPriorities.count(1));
        ++passed;
    }
    {
        LinuxRouteMonitor x;
        x.nextCreate = R::Uncertain;
        assert(x.createEndpointRoute(ip) == R::Uncertain); // Actual new mutation.
        const auto before = x.m_ownedGatewayRoutes.find(ip.key).value();
        assert(before.endpointReferences == 1 && !before.creationConfirmed);
        assert(x.createEndpointRoute(ip) == R::Failed); // No second mutation/hold.
        const auto after = x.m_ownedGatewayRoutes.find(ip.key).value();
        assert(after.endpointReferences == 1 && after.exclusionReferences == 0);
        assert(x.creates == 1 && x.reads == 0);
        ++passed;
    }
    {
        assert(productionAckClassification(0) == R::Success);
        assert(productionAckClassification(-EEXIST) == R::AlreadyExists);
        assert(productionAckClassification(-ENOENT) == R::NotFound);
        assert(productionAckClassification(-ESRCH) == R::NotFound);
        assert(productionAckClassification(-EPERM) == R::Failed);
        assert(productionAckClassification(-ENOENT, RTM_NEWROUTE) == R::Failed);
        assert(productionAckClassification(-ESRCH, RTM_NEWROUTE) == R::Failed);
        ++passed;
    }
    {
        LinuxRouteMonitor x;
        x.nextCreate = R::NotFound; // Defensive producer result: never a lease.
        assert(x.createEndpointRoute(ip) == R::Failed);
        assert(x.m_ownedGatewayRoutes.isEmpty());
        assert(x.deletes == 0);
        ++passed;
    }
    std::cout<<"PASS "<<passed<<" exact staged production ownership cases; no sockets/routes/network\n";
}
