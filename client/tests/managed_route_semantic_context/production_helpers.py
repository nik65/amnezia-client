"""Extract current production routing helpers for both component harnesses."""
from pathlib import Path

def function(text, signature):
    start = text.index(signature)
    brace = text.index('{', start)
    depth = 0
    for index in range(brace, len(text)):
        depth += (text[index] == '{') - (text[index] == '}')
        if depth == 0:
            return text[start:index + 1]
    raise ValueError(signature)


def routing_helpers(production, network):
    helper_names = ('QStringList splitTunnelStoredIps(', 'void appendSplitTunnelRoute(',
                    'void appendSplitTunnelRoutes(', 'void appendSplitTunnelSiteRoutes(',
                    'bool parseIpv4Route(', 'bool parseIpv4Host(', 'quint32 ipv4Mask(',
                    'bool routeOverlapsIpv4Range(', 'QString ipv4RouteToString(',
                    'QStringList normalizedSupportedIpv4Routes(', 'int trailingZeroBits(',
                    'QStringList ipv4RangeToRoutes(', 'QStringList subtractIpv4HostFromRoute(',
                    'QStringList splitRoutesKeepingHostsInVpn(', 'bool isRoutableSplitTunnelRoute(const QString &route)\n{')
    helpers = ['#include <QHostAddress>\n#include <QRegularExpression>\n',
               'class NetworkUtilities { public: static bool checkIPv4Format(const QString&); static bool checkIpSubnetFormat(const QString&); };',
               function(network, 'bool NetworkUtilities::checkIPv4Format('),
               function(network, 'bool NetworkUtilities::checkIpSubnetFormat('),
               'enum class SplitTunnelRouteSource { Client, ServerManaged };\nbool isRoutableSplitTunnelRoute(const QString&);']
    helpers += [function(production, signature) for signature in helper_names]
    if 'bool sameResolvedLocalRouteContext(' in production:
        helpers.append(function(production, 'bool sameResolvedLocalRouteContext('))
    return "\n".join(helpers)
