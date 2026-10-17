/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "windowsroutemonitor.h"

#include <QScopeGuard>

#include "leakdetector.h"
#include "logger.h"

namespace {
Logger logger("WindowsRouteMonitor");

bool isSuccessfulRouteDelete(DWORD result) {
  return result == NO_ERROR || result == ERROR_NOT_FOUND ||
         result == ERROR_FILE_NOT_FOUND;
}

bool isRouteAbsent(const MIB_IPFORWARD_ROW2& row) {
  MIB_IPFORWARD_ROW2 observed = row;
  const DWORD result = GetIpForwardEntry2(&observed);
  return result == ERROR_NOT_FOUND || result == ERROR_FILE_NOT_FOUND;
}

bool isZeroIpv6Address(const IN6_ADDR& address) {
  const IN6_ADDR zero = {};
  return memcmp(&address, &zero, sizeof(IN6_ADDR)) == 0;
}

quint32 ipv4PrefixAddress(const IP_ADDRESS_PREFIX& prefix) {
  return ntohl(prefix.Prefix.Ipv4.sin_addr.S_un.S_addr);
}

quint32 ipv4Mask(int prefixLength) {
  return prefixLength == 0 ? 0 : (0xffffffffu << (32 - prefixLength));
}

bool ipv4PrefixInRange(const IP_ADDRESS_PREFIX& prefix, quint32 base,
                       int rangePrefixLength) {
  if (prefix.Prefix.si_family != AF_INET) {
    return false;
  }
  const quint32 mask = ipv4Mask(rangePrefixLength);
  return (ipv4PrefixAddress(prefix) & mask) == (base & mask);
}

bool isPrivateOrSpecialIpv4Route(const IP_ADDRESS_PREFIX& prefix) {
  return ipv4PrefixInRange(prefix, 0x00000000u, 8) ||
         ipv4PrefixInRange(prefix, 0x0a000000u, 8) ||
         ipv4PrefixInRange(prefix, 0x64400000u, 10) ||
         ipv4PrefixInRange(prefix, 0x7f000000u, 8) ||
         ipv4PrefixInRange(prefix, 0xa9fe0000u, 16) ||
         ipv4PrefixInRange(prefix, 0xac100000u, 12) ||
         ipv4PrefixInRange(prefix, 0xc0000000u, 24) ||
         ipv4PrefixInRange(prefix, 0xc0000200u, 24) ||
         ipv4PrefixInRange(prefix, 0xc0a80000u, 16) ||
         ipv4PrefixInRange(prefix, 0xc6120000u, 15) ||
         ipv4PrefixInRange(prefix, 0xc6336400u, 24) ||
         ipv4PrefixInRange(prefix, 0xcb007100u, 24) ||
         ipv4PrefixInRange(prefix, 0xe0000000u, 4) ||
         ipv4PrefixInRange(prefix, 0xf0000000u, 4);
}

bool isOnLinkRoute(const MIB_IPFORWARD_ROW2* row) {
  if (row->NextHop.si_family == AF_UNSPEC) {
    return row->Protocol == MIB_IPPROTO_LOCAL ||
           isPrivateOrSpecialIpv4Route(row->DestinationPrefix);
  }

  if (row->DestinationPrefix.Prefix.si_family == AF_INET) {
    return row->NextHop.si_family == AF_INET &&
           row->NextHop.Ipv4.sin_addr.S_un.S_addr == 0 &&
           (row->Protocol == MIB_IPPROTO_LOCAL ||
            isPrivateOrSpecialIpv4Route(row->DestinationPrefix));
  }

  if (row->DestinationPrefix.Prefix.si_family == AF_INET6) {
    return row->NextHop.si_family == AF_INET6 &&
           isZeroIpv6Address(row->NextHop.Ipv6.sin6_addr) &&
           row->Protocol == MIB_IPPROTO_LOCAL;
  }

  return true;
}
};  // namespace

// Attempt to mark routing entries that we create with a relatively
// high metric. This ensures that we can skip over routes of our own
// creation when processing route changes, and ensures that we give
// way to other routing entries.
constexpr const ULONG EXCLUSION_ROUTE_METRIC = 0x5e72;

// Called by the kernel on route changes - perform some basic filtering and
// invoke the routeChanged slot to do the real work.
static void routeChangeCallback(PVOID context, PMIB_IPFORWARD_ROW2 row,
                                MIB_NOTIFICATION_TYPE type) {
  WindowsRouteMonitor* monitor = (WindowsRouteMonitor*)context;
  Q_UNUSED(type);

  if (row != nullptr) {
    // Ignore route changes that we created.
    if ((row->Protocol == MIB_IPPROTO_NETMGMT) &&
        (row->Metric == EXCLUSION_ROUTE_METRIC)) {
      return;
    }
    if (monitor->getLuid() == row->InterfaceLuid.Value) {
      return;
    }
  }

  monitor->notifyRouteChanged();
}

// Perform prefix matching comparison on IP addresses in host order.
static int prefixcmp(const void* a, const void* b, size_t bits) {
  size_t bytes = bits / 8;
  if (bytes > 0) {
    int diff = memcmp(a, b, bytes);
    if (diff != 0) {
      return diff;
    }
  }

  if (bits % 8) {
    quint8 avalue = *((const quint8*)a + bytes) >> (8 - bits % 8);
    quint8 bvalue = *((const quint8*)b + bytes) >> (8 - bits % 8);
    return avalue - bvalue;
  }

  return 0;
}

WindowsRouteMonitor::WindowsRouteMonitor(quint64 luid, QObject* parent)
    : QObject(parent), m_luid(luid) {
  MZ_COUNT_CTOR(WindowsRouteMonitor);
  logger.debug() << "WindowsRouteMonitor created.";

  m_routeChangeTimer.setSingleShot(true);
  m_routeChangeTimer.setInterval(300);
  connect(&m_routeChangeTimer, &QTimer::timeout,
          this, &WindowsRouteMonitor::processRouteChanges);

  NotifyRouteChange2(AF_UNSPEC, routeChangeCallback, this, FALSE, &m_routeHandle);
}

WindowsRouteMonitor::~WindowsRouteMonitor() {
  MZ_COUNT_DTOR(WindowsRouteMonitor);
  CancelMibChangeNotify2(m_routeHandle);

  flushRouteTable(m_exclusionRoutes);
  flushRouteTable(m_clonedRoutes);
  for (auto data : m_exclusionRoutes) delete data;
  for (auto data : m_clonedRoutes) delete data;
  m_exclusionRoutes.clear();
  m_clonedRoutes.clear();
  logger.debug() << "WindowsRouteMonitor destroyed.";
}

bool WindowsRouteMonitor::updateInterfaceMetrics(int family) {
  PMIB_IPINTERFACE_TABLE table;
  DWORD result = GetIpInterfaceTable(family, &table);
  if (result != NO_ERROR) {
    logger.warning() << "Failed to retrive interface table." << result;
    return false;
  }
  auto guard = qScopeGuard([&] { FreeMibTable(table); });

  // Flush the list of interfaces that are valid for routing.
  if ((family == AF_INET) || (family == AF_UNSPEC)) {
    m_interfaceMetricsIpv4.clear();
  }
  if ((family == AF_INET6) || (family == AF_UNSPEC)) {
    m_interfaceMetricsIpv6.clear();
  }

  // Rebuild the list of interfaces that are valid for routing.
  for (ULONG i = 0; i < table->NumEntries; i++) {
    MIB_IPINTERFACE_ROW* row = &table->Table[i];
    if (row->InterfaceLuid.Value == m_luid) {
      continue;
    }
    if (!row->Connected) {
      continue;
    }

    if (row->Family == AF_INET) {
      logger.debug() << "Interface" << row->InterfaceIndex
                     << "is valid for IPv4 routing";
      m_interfaceMetricsIpv4[row->InterfaceLuid.Value] = row->Metric;
    }
    if (row->Family == AF_INET6) {
      logger.debug() << "Interface" << row->InterfaceIndex
                     << "is valid for IPv6 routing";
      m_interfaceMetricsIpv6[row->InterfaceLuid.Value] = row->Metric;
    }
  }
  return true;
}

bool WindowsRouteMonitor::updateExclusionRoute(MIB_IPFORWARD_ROW2* data,
                                               void* ptable) {
  PMIB_IPFORWARD_TABLE2 table = reinterpret_cast<PMIB_IPFORWARD_TABLE2>(ptable);
  SOCKADDR_INET nexthop = {};
  quint64 bestLuid = 0;
  int bestMatch = -1;
  ULONG bestMetric = ULONG_MAX;

  nexthop.si_family = data->DestinationPrefix.Prefix.si_family;
  for (ULONG i = 0; i < table->NumEntries; i++) {
    MIB_IPFORWARD_ROW2* row = &table->Table[i];
    // Ignore routes into the VPN interface.
    if (row->InterfaceLuid.Value == m_luid) {
      continue;
    }
    if (row->DestinationPrefix.PrefixLength < bestMatch) {
      continue;
    }
    // Ignore routes of our own creation.
    if ((row->Protocol == data->Protocol) && (row->Metric == data->Metric)) {
      continue;
    }

    // Check if the routing table entry matches the destination.
    if (!routeContainsDest(&row->DestinationPrefix, &data->DestinationPrefix)) {
      continue;
    }

    // Compute the combined interface and routing metric.
    ULONG routeMetric = row->Metric;
    if (data->DestinationPrefix.Prefix.si_family == AF_INET6) {
      if (!m_interfaceMetricsIpv6.contains(row->InterfaceLuid.Value)) {
        continue;
      }
      routeMetric += m_interfaceMetricsIpv6[row->InterfaceLuid.Value];
    } else if (data->DestinationPrefix.Prefix.si_family == AF_INET) {
      if (!m_interfaceMetricsIpv4.contains(row->InterfaceLuid.Value)) {
        continue;
      }
      routeMetric += m_interfaceMetricsIpv4[row->InterfaceLuid.Value];
    } else {
      // Unsupported destination address family.
      continue;
    }
    if (routeMetric < row->Metric) {
      routeMetric = ULONG_MAX;
    }

    // Prefer routes with lower metric if we find multiple matches
    // with the same prefix length.
    if ((row->DestinationPrefix.PrefixLength == bestMatch) &&
        (routeMetric >= bestMetric)) {
      continue;
    }

    // If we got here, then this is the longest prefix match so far.
    memcpy(&nexthop, &row->NextHop, sizeof(SOCKADDR_INET));
    bestMatch = row->DestinationPrefix.PrefixLength;
    bestMetric = routeMetric;
    if (bestMatch == data->DestinationPrefix.PrefixLength) {
      bestLuid = 0;  // Don't write to the table if we find an exact match.
    } else {
      bestLuid = row->InterfaceLuid.Value;
    }
  }

  if (bestMatch < 0) {
    logger.error() << "No physical route available for exclusion";
    return false;
  }

  // A matching cached row is not an OS receipt. Recheck it after failed writes
  // and after external route changes before acknowledging this bypass.
  if (data->InterfaceLuid.Value == bestLuid &&
      memcmp(&nexthop, &data->NextHop, sizeof(SOCKADDR_INET)) == 0) {
    if (bestLuid == 0) return true; // an existing physical route is authoritative
    MIB_IPFORWARD_ROW2 observed = *data;
    if (GetIpForwardEntry2(&observed) == NO_ERROR) return true;
    const DWORD restored = CreateIpForwardEntry2(data);
    observed = *data;
    return (restored == NO_ERROR || restored == ERROR_OBJECT_ALREADY_EXISTS) &&
           GetIpForwardEntry2(&observed) == NO_ERROR;
  }

  // Delete the previous routing table entry, if any.
  if (data->InterfaceLuid.Value != 0) {
    DWORD result = DeleteIpForwardEntry2(data);
    if (!isSuccessfulRouteDelete(result)) {
      logger.error() << "Failed to delete route:" << result;
      return false;
    }
    if (!isRouteAbsent(*data)) {
      logger.error() << "Failed to confirm route deletion before update";
      return false;
    }
  }

  // Update the routing table entry.
  data->InterfaceLuid.Value = bestLuid;
  memcpy(&data->NextHop, &nexthop, sizeof(SOCKADDR_INET));
  if (data->InterfaceLuid.Value != 0) {
    DWORD result = CreateIpForwardEntry2(data);
    if (result != NO_ERROR) {
      logger.error() << "Failed to update route:" << result;
    }
    MIB_IPFORWARD_ROW2 observed = *data;
    return (result == NO_ERROR || result == ERROR_OBJECT_ALREADY_EXISTS) &&
           GetIpForwardEntry2(&observed) == NO_ERROR;
  }
  return true;
}

// static
bool WindowsRouteMonitor::routeContainsDest(const IP_ADDRESS_PREFIX* route,
                                            const IP_ADDRESS_PREFIX* dest) {
  if (route->Prefix.si_family != dest->Prefix.si_family) {
    return false;
  }
  if (route->PrefixLength > dest->PrefixLength) {
    return false;
  }
  if (route->Prefix.si_family == AF_INET) {
    return prefixcmp(&route->Prefix.Ipv4.sin_addr, &dest->Prefix.Ipv4.sin_addr,
                     route->PrefixLength) == 0;
  } else if (route->Prefix.si_family == AF_INET6) {
    return prefixcmp(&route->Prefix.Ipv6.sin6_addr,
                     &dest->Prefix.Ipv6.sin6_addr, route->PrefixLength) == 0;
  } else {
    return false;
  }
}

// static
QHostAddress WindowsRouteMonitor::prefixToAddress(
    const IP_ADDRESS_PREFIX* dest) {
  if (dest->Prefix.si_family == AF_INET6) {
    return QHostAddress(dest->Prefix.Ipv6.sin6_addr.s6_addr);
  } else if (dest->Prefix.si_family == AF_INET) {
    quint32 addr = htonl(dest->Prefix.Ipv4.sin_addr.s_addr);
    return QHostAddress(addr);
  } else {
    return QHostAddress();
  }
}

bool WindowsRouteMonitor::isRouteExcluded(const IP_ADDRESS_PREFIX* dest) const {
  auto i = m_exclusionRoutes.constBegin();
  while (i != m_exclusionRoutes.constEnd()) {
    const MIB_IPFORWARD_ROW2* row = i.value();
    if (routeContainsDest(&row->DestinationPrefix, dest)) {
      return true;
    }
    i++;
  }
  return false;
}

bool WindowsRouteMonitor::updateCapturedRoutes(int family) {
  if (!m_defaultRouteCapture) {
    return true;
  }

  PMIB_IPFORWARD_TABLE2 table;
  DWORD error = GetIpForwardTable2(family, &table);
  if (error == NO_ERROR) {
    const bool updated = updateCapturedRoutes(family, table);
    FreeMibTable(table);
    return updated;
  } else {
    logger.error() << "Failed to fetch routing table:" << error;
  }
  return false;
}

bool WindowsRouteMonitor::updateCapturedRoutes(int family, void* ptable) {
  PMIB_IPFORWARD_TABLE2 table = reinterpret_cast<PMIB_IPFORWARD_TABLE2>(ptable);
  if (!m_defaultRouteCapture) {
    return true;
  }
  bool updated = true;

  for (ULONG i = 0; i < table->NumEntries; i++) {
    MIB_IPFORWARD_ROW2* row = &table->Table[i];
    // Ignore routes into the VPN interface.
    if (row->InterfaceLuid.Value == m_luid) {
      continue;
    }
    // Ignore the default route
    if (row->DestinationPrefix.PrefixLength == 0) {
      continue;
    }
    // Ignore routes of our own creation.
    if ((row->Protocol == MIB_IPPROTO_NETMGMT) &&
        (row->Metric == EXCLUSION_ROUTE_METRIC)) {
      continue;
    }
    // Connected/on-link routes already belong to their physical interface.
    // Cloning them into the VPN pollutes the Windows table and can override
    // local DNS/LAN routing while site split tunneling is being applied.
    if (isOnLinkRoute(row)) {
      continue;
    }
    // Ignore routes which should be excluded.
    if (isRouteExcluded(&row->DestinationPrefix)) {
      continue;
    }
    QHostAddress destination = prefixToAddress(&row->DestinationPrefix);
    if (destination.isLoopback() || destination.isBroadcast() ||
        destination.isLinkLocal() || destination.isMulticast()) {
      continue;
    }

    // If we get here, this route should be cloned.
    IPAddress prefix(destination, row->DestinationPrefix.PrefixLength);
    MIB_IPFORWARD_ROW2* data = m_clonedRoutes.value(prefix, nullptr);
    if (data != nullptr) {
      // Count the number of matching entries in the main table.
      data->Age++;
      continue;
    }
    logger.debug() << "Capturing route to" << prefix.toString();

    // Clone the route and direct it into the VPN tunnel.
    data = new MIB_IPFORWARD_ROW2;
    InitializeIpForwardEntry(data);
    data->InterfaceLuid.Value = m_luid;
    data->DestinationPrefix = row->DestinationPrefix;
    data->NextHop.si_family = data->DestinationPrefix.Prefix.si_family;

    // Set the rest of the flags for a static route.
    data->ValidLifetime = 0xffffffff;
    data->PreferredLifetime = 0xffffffff;
    data->Metric = 0;
    data->Protocol = MIB_IPPROTO_NETMGMT;
    data->Loopback = false;
    data->AutoconfigureAddress = false;
    data->Publish = false;
    data->Immortal = false;
    data->Age = 0;

    // Route this traffic into the VPN tunnel.
    DWORD result = CreateIpForwardEntry2(data);
    if (result != NO_ERROR && result != ERROR_OBJECT_ALREADY_EXISTS) {
      logger.error() << "Failed to update route:" << result;
      delete data;
      updated = false;
      continue;
    }

    // A successful create (or an already-existing row) is not an OS receipt.
    // Keep the clone only after the route can be read back, otherwise a later
    // scan could treat a missing route as installed and never retry it.
    MIB_IPFORWARD_ROW2 observed = *data;
    if (GetIpForwardEntry2(&observed) != NO_ERROR) {
      logger.error() << "Failed to confirm captured route for"
                     << prefix.toString();
      delete data;
      updated = false;
      continue;
    }

    if (result == ERROR_OBJECT_ALREADY_EXISTS) {
      logger.warning() << "Adopting existing captured route for"
                       << prefix.toString();
    }
    m_clonedRoutes.insert(prefix, data);
    data->Age++;
  }

  // Finally scan for any routes which were removed from the table. We do this
  // by reusing the age field to count the number of matching entries in the
  // main table.
  auto i = m_clonedRoutes.begin();
  while (i != m_clonedRoutes.end()) {
    MIB_IPFORWARD_ROW2* data = i.value();
    if (data->Age > 0) {
      // Entry is in use, don't delete it.
      data->Age = 0;
      i++;
      continue;
    }
    if ((family != AF_UNSPEC) &&
        (data->DestinationPrefix.Prefix.si_family != family)) {
      // We are not processing updates to this address family.
      i++;
      continue;
    }

    logger.debug() << "Removing route capture for" << i.key().toString();

    // Otherwise, this route is no longer in use.
    DWORD result = DeleteIpForwardEntry2(data);
    if (!isSuccessfulRouteDelete(result)) {
      logger.error() << "Failed to delete route:" << result;
      updated = false;
      ++i;
      continue;
    }
    if (!isRouteAbsent(*data)) {
      logger.error() << "Failed to confirm captured route deletion for"
                     << i.key().toString();
      updated = false;
      ++i;
      continue;
    }
    delete data;
    i = m_clonedRoutes.erase(i);
  }
  return updated;
}

bool WindowsRouteMonitor::addExclusionRoute(const IPAddress& prefix) {
  logger.debug() << "Adding exclusion route for" << prefix.toString();

  // Silently ignore non-routeable addresses.
  QHostAddress addr = prefix.address();
  if (addr.protocol() == QAbstractSocket::UnknownNetworkLayerProtocol ||
      addr.isLoopback() || addr.isBroadcast() || addr.isLinkLocal() ||
      addr.isMulticast()) {
    return true;
  }

  if (m_exclusionRoutes.contains(prefix)) {
    PMIB_IPFORWARD_TABLE2 table;
    const int family = prefix.type() == QAbstractSocket::IPv6Protocol ? AF_INET6 : AF_INET;
    if (GetIpForwardTable2(family, &table) != NO_ERROR) return false;
    if (!updateInterfaceMetrics(family)) { FreeMibTable(table); return false; }
    const bool captured = updateCapturedRoutes(family, table);
    const bool routed = updateExclusionRoute(m_exclusionRoutes.value(prefix), table);
    FreeMibTable(table);
    return captured && routed;
  }

  // Allocate and initialize the MIB routing table row.
  MIB_IPFORWARD_ROW2* data = new MIB_IPFORWARD_ROW2;
  InitializeIpForwardEntry(data);
  if (prefix.address().protocol() == QAbstractSocket::IPv6Protocol) {
    Q_IPV6ADDR buf = prefix.address().toIPv6Address();

    memcpy(&data->DestinationPrefix.Prefix.Ipv6.sin6_addr, &buf, sizeof(buf));
    data->DestinationPrefix.Prefix.Ipv6.sin6_family = AF_INET6;
    data->DestinationPrefix.PrefixLength = prefix.prefixLength();
  } else {
    quint32 buf = prefix.address().toIPv4Address();

    data->DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr = htonl(buf);
    data->DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
    data->DestinationPrefix.PrefixLength = prefix.prefixLength();
  }
  data->NextHop.si_family = data->DestinationPrefix.Prefix.si_family;

  // Set the rest of the flags for a static route.
  data->ValidLifetime = 0xffffffff;
  data->PreferredLifetime = 0xffffffff;
  data->Metric = EXCLUSION_ROUTE_METRIC;
  data->Protocol = MIB_IPPROTO_NETMGMT;
  data->Loopback = false;
  data->AutoconfigureAddress = false;
  data->Publish = false;
  data->Immortal = false;
  data->Age = 0;

  PMIB_IPFORWARD_TABLE2 table;
  int family;
  if (prefix.address().protocol() == QAbstractSocket::IPv6Protocol) {
    family = AF_INET6;
  } else {
    family = AF_INET;
  }

  DWORD result = GetIpForwardTable2(family, &table);
  if (result != NO_ERROR) {
    logger.error() << "Failed to fetch routing table:" << result;
    delete data;
    return false;
  }
  if (!updateInterfaceMetrics(family)) {
    FreeMibTable(table);
    delete data;
    return false;
  }
  m_exclusionRoutes[prefix] = data;
  const bool captured = updateCapturedRoutes(family, table);
  const bool routed = updateExclusionRoute(data, table);
  FreeMibTable(table);

  return captured && routed;
}

bool WindowsRouteMonitor::deleteExclusionRoute(const IPAddress& prefix) {
  logger.debug() << "Deleting exclusion route for"
                 << prefix.address().toString();

  if (prefix.address().protocol() == QAbstractSocket::UnknownNetworkLayerProtocol) {
    return true;
  }

  MIB_IPFORWARD_ROW2* data = m_exclusionRoutes.value(prefix);
  if (data == nullptr) {
    return updateCapturedRoutes(prefix.type() == QAbstractSocket::IPv6Protocol ? AF_INET6 : AF_INET);
  }

  DWORD result = data->InterfaceLuid.Value == 0 ? NO_ERROR : DeleteIpForwardEntry2(data);
  if (!isSuccessfulRouteDelete(result)) {
    logger.error() << "Failed to delete route to"
                   << prefix.toString()
                   << "result:" << result;
    return false;
  }
  // A successful delete return is not an absence receipt. Keep ownership when
  // the row is still present or the readback is otherwise ambiguous so a
  // later cleanup/retry cannot discard a possibly installed route.
  if (data->InterfaceLuid.Value != 0 && !isRouteAbsent(*data)) {
    logger.error() << "Route delete was not confirmed for"
                   << prefix.toString();
    return false;
  }
  m_exclusionRoutes.remove(prefix);

  // Captured routes might have changed.
  const bool captured = updateCapturedRoutes(data->DestinationPrefix.Prefix.si_family);

  delete data;
  return captured;
}

bool WindowsRouteMonitor::flushRouteTable(
    QHash<IPAddress, MIB_IPFORWARD_ROW2*>& table) {
  bool cleaned = true;
  for (auto i = table.begin(); i != table.end();) {
    MIB_IPFORWARD_ROW2* data = i.value();
    const DWORD result = data->InterfaceLuid.Value == 0
                             ? NO_ERROR
                             : DeleteIpForwardEntry2(data);
    if (!isSuccessfulRouteDelete(result) ||
        (data->InterfaceLuid.Value != 0 && !isRouteAbsent(*data))) {
      logger.error() << "Failed to delete route to"
                     << i.key().toString()
                     << "result:" << result;
      cleaned = false;
      ++i;
      continue;
    }
    delete data;
    i = table.erase(i);
  }
  return cleaned;
}

bool WindowsRouteMonitor::setDetaultRouteCapture(bool enable) {
  m_defaultRouteCapture = enable;

  // Flush any captured routes when disabling the feature.
  if (!m_defaultRouteCapture) {
    return flushRouteTable(m_clonedRoutes);
  }
  return true;
}

void WindowsRouteMonitor::routeChanged() {
  if (!m_routeChangeTimer.isActive()) {
    m_routeChangeTimer.start();
  }
}

void WindowsRouteMonitor::notifyRouteChanged() {
  m_pendingRouteChanges.fetch_add(1, std::memory_order_relaxed);
  bool expected = false;
  if (m_routeChangeQueued.compare_exchange_strong(
          expected, true, std::memory_order_acq_rel)) {
    QMetaObject::invokeMethod(this, "routeChanged", Qt::QueuedConnection);
  }
}

void WindowsRouteMonitor::processRouteChanges() {
  PMIB_IPFORWARD_TABLE2 table;
  DWORD result = GetIpForwardTable2(AF_UNSPEC, &table);
  if (result != NO_ERROR) {
    logger.error() << "Failed to fetch routing table:" << result;
    if (!m_routeChangeTimer.isActive()) {
      m_routeChangeTimer.start();
    }
    return;
  }

  const int routeChangeCount =
      m_pendingRouteChanges.exchange(0, std::memory_order_acq_rel);
  logger.debug() << "Routes changed, processing" << routeChangeCount
                 << "coalesced notifications";

  bool updated = updateInterfaceMetrics(AF_UNSPEC);
  if (updated) {
    updated = updateCapturedRoutes(AF_UNSPEC, table) && updated;
    for (MIB_IPFORWARD_ROW2* data : m_exclusionRoutes) {
      updated = updateExclusionRoute(data, table) && updated;
    }
  }

  FreeMibTable(table);

  m_routeChangeQueued.store(false, std::memory_order_release);
  if (!updated && !m_routeChangeTimer.isActive()) {
    m_routeChangeTimer.start();
  }
  if (m_pendingRouteChanges.load(std::memory_order_acquire) > 0) {
    bool expected = false;
    if (m_routeChangeQueued.compare_exchange_strong(
            expected, true, std::memory_order_acq_rel)) {
      QMetaObject::invokeMethod(this, "routeChanged", Qt::QueuedConnection);
    }
  }
}
