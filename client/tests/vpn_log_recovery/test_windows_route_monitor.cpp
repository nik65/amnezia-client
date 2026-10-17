// Run the production WindowsRouteMonitor with an in-memory IP Helper API.
// Every route write and callback registration is replaced before inclusion.
#include <QtTest>
#include "platforms/windows/daemon/windowsroutemonitor.h"

namespace RouteApi {
QList<MIB_IPFORWARD_ROW2> rows;
DWORD createFailure = NO_ERROR, deleteFailure = NO_ERROR;
DWORD interfaceFailure = NO_ERROR;
bool loseCreatedRow = false, retainDeletedRow = false;
bool same(const MIB_IPFORWARD_ROW2& a, const MIB_IPFORWARD_ROW2& b) {
    return a.InterfaceLuid.Value == b.InterfaceLuid.Value &&
           a.DestinationPrefix.PrefixLength == b.DestinationPrefix.PrefixLength &&
           memcmp(&a.DestinationPrefix.Prefix, &b.DestinationPrefix.Prefix, sizeof(SOCKADDR_INET)) == 0;
}
DWORD create(const MIB_IPFORWARD_ROW2* row) {
    if (createFailure != NO_ERROR) return createFailure;
    for (const auto& existing : rows) if (same(*row, existing)) return ERROR_OBJECT_ALREADY_EXISTS;
    if (!loseCreatedRow) rows.append(*row);
    return NO_ERROR;
}
DWORD remove(const MIB_IPFORWARD_ROW2* row) {
    if (deleteFailure != NO_ERROR) return deleteFailure;
    for (int i = 0; i < rows.size(); ++i) {
        if (same(*row, rows[i])) {
            if (!retainDeletedRow) rows.removeAt(i);
            return NO_ERROR;
        }
    }
    return ERROR_NOT_FOUND;
}
DWORD get(MIB_IPFORWARD_ROW2* row) {
    for (const auto& existing : rows) {
        if (same(*row, existing)) { *row = existing; return NO_ERROR; }
    }
    return ERROR_NOT_FOUND;
}
DWORD table(ADDRESS_FAMILY, PMIB_IPFORWARD_TABLE2* result) {
    *result = static_cast<PMIB_IPFORWARD_TABLE2>(calloc(1, sizeof(MIB_IPFORWARD_TABLE2) + rows.size() * sizeof(MIB_IPFORWARD_ROW2)));
    (*result)->NumEntries = rows.size();
    for (int i = 0; i < rows.size(); ++i) (*result)->Table[i] = rows[i];
    return NO_ERROR;
}
DWORD interfaces(ADDRESS_FAMILY, PMIB_IPINTERFACE_TABLE* result) {
    if (interfaceFailure != NO_ERROR) return interfaceFailure;
    *result = static_cast<PMIB_IPINTERFACE_TABLE>(calloc(1, sizeof(MIB_IPINTERFACE_TABLE)));
    (*result)->NumEntries = 1;
    auto& row = (*result)->Table[0];
    row.Family = AF_INET; row.InterfaceLuid.Value = 2; row.Connected = true; row.Metric = 10;
    return NO_ERROR;
}
DWORD notify(ADDRESS_FAMILY, PIPFORWARD_CHANGE_CALLBACK, PVOID, BOOLEAN, HANDLE* result) {
    *result = reinterpret_cast<HANDLE>(1); return NO_ERROR;
}
DWORD cancel(HANDLE) { return NO_ERROR; }
void release(PVOID allocation) { free(allocation); }
void reset() {
    rows.clear(); createFailure = deleteFailure = NO_ERROR; loseCreatedRow = false;
    retainDeletedRow = false;
    interfaceFailure = NO_ERROR;
    MIB_IPFORWARD_ROW2 route = {};
    route.InterfaceLuid.Value = 2;
    route.DestinationPrefix.Prefix.si_family = AF_INET;
    route.NextHop.si_family = AF_INET;
    route.NextHop.Ipv4.sin_addr.s_addr = htonl(0xc0a80101);
    route.Metric = 3; route.Protocol = MIB_IPPROTO_NETMGMT;
    rows.append(route);
}

MIB_IPFORWARD_ROW2 capturedSourceRoute() {
    MIB_IPFORWARD_ROW2 route = rows.first();
    route.DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr = htonl(0x0a1f0001);
    route.DestinationPrefix.PrefixLength = 32;
    return route;
}

int countRoute(quint64 luid, quint32 address) {
    int count = 0;
    for (const auto& row : rows) {
        if (row.InterfaceLuid.Value == luid &&
            row.DestinationPrefix.Prefix.si_family == AF_INET &&
            row.DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr == htonl(address) &&
            row.DestinationPrefix.PrefixLength == 32) {
            ++count;
        }
    }
    return count;
}
}

#define CreateIpForwardEntry2 RouteApi::create
#define DeleteIpForwardEntry2 RouteApi::remove
#define GetIpForwardEntry2 RouteApi::get
#define GetIpForwardTable2 RouteApi::table
#define GetIpInterfaceTable RouteApi::interfaces
#define NotifyRouteChange2 RouteApi::notify
#define CancelMibChangeNotify2 RouteApi::cancel
#define FreeMibTable RouteApi::release
#include "platforms/windows/daemon/windowsroutemonitor.cpp"

class WindowsRouteMonitorTests : public QObject {
    Q_OBJECT
private slots:
    void init() { RouteApi::reset(); }
    void creationFailureIsRejectedAndRetryIsIdempotent() {
        WindowsRouteMonitor monitor(9, nullptr);
        RouteApi::createFailure = ERROR_ACCESS_DENIED;
        QVERIFY(!monitor.addExclusionRoute(IPAddress("10.31.0.1")));
        QCOMPARE(RouteApi::rows.size(), 1);
        RouteApi::createFailure = NO_ERROR;
        QVERIFY(monitor.addExclusionRoute(IPAddress("10.31.0.1")));
        QVERIFY(monitor.addExclusionRoute(IPAddress("10.31.0.1")));
        QCOMPARE(RouteApi::rows.size(), 2);
    }
    void acknowledgedCreateWithoutReadbackIsRejected() {
        WindowsRouteMonitor monitor(9, nullptr);
        RouteApi::loseCreatedRow = true;
        QVERIFY(!monitor.addExclusionRoute(IPAddress("10.31.0.1")));
        RouteApi::loseCreatedRow = false;
        QVERIFY(monitor.addExclusionRoute(IPAddress("10.31.0.1")));
    }
    void interfaceQueryFailureCannotReuseStaleMetrics() {
        WindowsRouteMonitor monitor(9, nullptr);
        QVERIFY(monitor.addExclusionRoute(IPAddress("10.31.0.1")));
        RouteApi::interfaceFailure = ERROR_ACCESS_DENIED;
        QVERIFY(!monitor.addExclusionRoute(IPAddress("10.31.0.2")));
        QCOMPARE(RouteApi::rows.size(), 2);
        RouteApi::interfaceFailure = NO_ERROR;
        QVERIFY(monitor.addExclusionRoute(IPAddress("10.31.0.2")));
    }
    void failedDeleteRetainsOwnershipForRetry() {
        WindowsRouteMonitor monitor(9, nullptr);
        QVERIFY(monitor.addExclusionRoute(IPAddress("10.31.0.1")));
        RouteApi::deleteFailure = ERROR_ACCESS_DENIED;
        QVERIFY(!monitor.deleteExclusionRoute(IPAddress("10.31.0.1")));
        QCOMPARE(RouteApi::rows.size(), 2);
        RouteApi::deleteFailure = NO_ERROR;
        QVERIFY(monitor.deleteExclusionRoute(IPAddress("10.31.0.1")));
        QVERIFY(monitor.deleteExclusionRoute(IPAddress("10.31.0.1")));
        QCOMPARE(RouteApi::rows.size(), 1);
    }
    void successfulDeleteWithoutAbsenceReadbackRetainsOwnershipForRetry() {
        WindowsRouteMonitor monitor(9, nullptr);
        QVERIFY(monitor.addExclusionRoute(IPAddress("10.31.0.1")));
        RouteApi::retainDeletedRow = true;
        QVERIFY(!monitor.deleteExclusionRoute(IPAddress("10.31.0.1")));
        QCOMPARE(RouteApi::rows.size(), 2);
        RouteApi::retainDeletedRow = false;
        QVERIFY(monitor.deleteExclusionRoute(IPAddress("10.31.0.1")));
        QCOMPARE(RouteApi::rows.size(), 1);
    }
    void exactPhysicalRouteIsPreserved() {
        auto physical = RouteApi::rows.first();
        physical.DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr = htonl(0x0a1f0001);
        physical.DestinationPrefix.PrefixLength = 32;
        RouteApi::rows.append(physical);
        WindowsRouteMonitor monitor(9, nullptr);
        QVERIFY(monitor.addExclusionRoute(IPAddress("10.31.0.1")));
        QVERIFY(monitor.deleteExclusionRoute(IPAddress("10.31.0.1")));
        QCOMPARE(RouteApi::rows.size(), 2);
    }
    void capturedRouteRequiresReadbackBeforeOwnership() {
        WindowsRouteMonitor monitor(9, nullptr);
        RouteApi::rows.append(RouteApi::capturedSourceRoute());
        monitor.setDetaultRouteCapture(true);

        RouteApi::loseCreatedRow = true;
        monitor.routeChanged();
        QTest::qWait(450);
        QCOMPARE(RouteApi::countRoute(9, 0x0a1f0001), 0);

        RouteApi::loseCreatedRow = false;
        monitor.routeChanged();
        QTest::qWait(450);
        QCOMPARE(RouteApi::countRoute(9, 0x0a1f0001), 1);
        monitor.setDetaultRouteCapture(false);
    }
    void capturedRouteDeleteKeepsOwnershipUntilAbsenceReadback() {
        WindowsRouteMonitor monitor(9, nullptr);
        RouteApi::rows.append(RouteApi::capturedSourceRoute());
        monitor.setDetaultRouteCapture(true);
        monitor.routeChanged();
        QTest::qWait(450);
        QCOMPARE(RouteApi::countRoute(9, 0x0a1f0001), 1);

        for (int i = RouteApi::rows.size() - 1; i >= 0; --i) {
            if (RouteApi::rows.at(i).InterfaceLuid.Value == 2 &&
                RouteApi::rows.at(i).DestinationPrefix.PrefixLength == 32) {
                RouteApi::rows.removeAt(i);
            }
        }
        RouteApi::retainDeletedRow = true;
        monitor.routeChanged();
        QTest::qWait(450);
        QCOMPARE(RouteApi::countRoute(9, 0x0a1f0001), 1);

        RouteApi::retainDeletedRow = false;
        monitor.routeChanged();
        QTest::qWait(450);
        QCOMPARE(RouteApi::countRoute(9, 0x0a1f0001), 0);
    }
    void disablingCaptureRetainsFailedCloneForRetry() {
        WindowsRouteMonitor monitor(9, nullptr);
        RouteApi::rows.append(RouteApi::capturedSourceRoute());
        monitor.setDetaultRouteCapture(true);
        monitor.routeChanged();
        QTest::qWait(450);
        QCOMPARE(RouteApi::countRoute(9, 0x0a1f0001), 1);

        RouteApi::retainDeletedRow = true;
        QVERIFY(!monitor.setDetaultRouteCapture(false));
        QCOMPARE(RouteApi::countRoute(9, 0x0a1f0001), 1);

        RouteApi::retainDeletedRow = false;
        QVERIFY(monitor.setDetaultRouteCapture(false));
        QCOMPARE(RouteApi::countRoute(9, 0x0a1f0001), 0);
    }
    void routeChangeFailureSchedulesRetry() {
        WindowsRouteMonitor monitor(9, nullptr);
        RouteApi::rows.append(RouteApi::capturedSourceRoute());
        monitor.setDetaultRouteCapture(true);

        RouteApi::createFailure = ERROR_ACCESS_DENIED;
        monitor.routeChanged();
        QTest::qWait(450);
        QCOMPARE(RouteApi::countRoute(9, 0x0a1f0001), 0);

        RouteApi::createFailure = NO_ERROR;
        QTest::qWait(500);
        QCOMPARE(RouteApi::countRoute(9, 0x0a1f0001), 1);
        monitor.setDetaultRouteCapture(false);
    }
};
QTEST_GUILESS_MAIN(WindowsRouteMonitorTests)
#include "test_windows_route_monitor.moc"
