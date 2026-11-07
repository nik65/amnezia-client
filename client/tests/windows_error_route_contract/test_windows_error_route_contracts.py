from __future__ import annotations

import re
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


def read_source(relative: str) -> str:
    return (REPOSITORY_ROOT / relative).read_text(encoding="utf-8")


def function_body(source: str, signature: str) -> str:
    start = source.index(signature)
    brace = source.index("{", start)
    depth = 0
    for index in range(brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[brace : index + 1]
    raise AssertionError(f"unterminated function: {signature}")


def compact(source: str) -> str:
    return re.sub(r"\s+", "", source)


class WindowsErrorAndRouteContracts(unittest.TestCase):
    def test_wlan_diagnostics_use_api_return_not_thread_last_error(self) -> None:
        source = read_source("client/platforms/windows/windowsnetworkwatcher.cpp")
        body = function_body(source, "void WindowsNetworkWatcher::initialize()")
        for variable, api in (("openResult", "WlanOpenHandle"),
                              ("notificationResult", "WlanRegisterNotification")):
            self.assertIn(f"const DWORD {variable} = {api}(", body)
            self.assertIn(f"if ({variable} != ERROR_SUCCESS)", body)
            self.assertIn(f'"errorCode" << {variable}', body)
            self.assertIn(f"WindowsUtils::getErrorMessage({variable})", body)
        self.assertNotIn("WindowsUtils::windowsLog(", body)
        wlan_body = body.split("// Power notifications", 1)[0]
        self.assertNotIn("GetLastError(", wlan_body)

    def test_route_delete_policy_accepts_only_idempotent_results(self) -> None:
        constants = {"NO_ERROR": 0, "ERROR_NOT_FOUND": 1168,
                     "ERROR_FILE_NOT_FOUND": 2}
        for filename in ("windowsroutemonitor.cpp", "wireguardutilswindows.cpp"):
            with self.subTest(filename=filename):
                source = read_source("client/platforms/windows/daemon/" + filename)
                helper = function_body(source, "bool isSuccessfulRouteDelete(DWORD result)")
                expression = re.fullmatch(r"\{return(.+);\}", compact(helper))
                self.assertIsNotNone(expression)
                clauses = expression.group(1).split("||")
                accepted = set()
                for clause in clauses:
                    match = re.fullmatch(r"result==([A-Z_]+)", clause)
                    self.assertIsNotNone(match, clause)
                    self.assertIn(match.group(1), constants)
                    accepted.add(constants[match.group(1)])
                self.assertEqual(len(clauses), 3)
                self.assertEqual(accepted, {0, 1168, 2})
                self.assertTrue(accepted.isdisjoint({5, 87, 1234}))

    def route_monitor_body(self, signature: str) -> str:
        source = read_source("client/platforms/windows/daemon/windowsroutemonitor.cpp")
        return compact(function_body(source, signature))

    def test_route_replacement_requires_delete_success_and_absence(self) -> None:
        body = self.route_monitor_body("bool WindowsRouteMonitor::updateExclusionRoute(")
        deletion = function_body(body, "if(data->InterfaceLuid.Value!=0)")
        self.assertIn("DeleteIpForwardEntry2(data)", deletion)
        for guard in ("if(!isSuccessfulRouteDelete(result))", "if(!isRouteAbsent(*data))"):
            self.assertIn("returnfalse;", function_body(deletion, guard))
        self.assertLess(body.index(deletion), body.index("data->InterfaceLuid.Value=bestLuid;"))

    def test_captured_route_cleanup_retains_failed_deletions(self) -> None:
        body = self.route_monitor_body(
            "bool WindowsRouteMonitor::updateCapturedRoutes(int family, void* ptable)"
        )
        deletion = body[body.index("DeleteIpForwardEntry2(data)"):]
        for guard in ("if(!isSuccessfulRouteDelete(result))", "if(!isRouteAbsent(*data))"):
            failure = function_body(deletion, guard)
            for action in ("updated=false;", "++i;", "continue;"):
                self.assertIn(action, failure)
            self.assertNotIn("deletedata;", failure)
            self.assertNotIn(".erase(", failure)
            self.assertLess(deletion.index(failure), deletion.index("deletedata;"))
        self.assertIn("i=m_clonedRoutes.erase(i);", deletion)
        self.assertTrue(deletion.endswith("returnupdated;}"))

    def test_exclusion_cleanup_preserves_ownership_until_confirmed(self) -> None:
        body = self.route_monitor_body("bool WindowsRouteMonitor::deleteExclusionRoute(")
        self.assertIn("data->InterfaceLuid.Value==0?NO_ERROR:DeleteIpForwardEntry2(data)", body)
        for guard in ("if(!isSuccessfulRouteDelete(result))",
                      "if(data->InterfaceLuid.Value!=0&&!isRouteAbsent(*data))"):
            failure = function_body(body, guard)
            self.assertIn("returnfalse;", failure)
            self.assertLess(body.index(failure), body.index("m_exclusionRoutes.remove(prefix);"))
        self.assertIn("constboolcaptured=updateCapturedRoutes(data->DestinationPrefix.Prefix.si_family);", body)
        self.assertTrue(body.endswith("deletedata;returncaptured;}"))

    def test_bulk_cleanup_keeps_unconfirmed_routes_for_retry(self) -> None:
        body = self.route_monitor_body("bool WindowsRouteMonitor::flushRouteTable(")
        self.assertIn("data->InterfaceLuid.Value==0?NO_ERROR:DeleteIpForwardEntry2(data)", body)
        guard = "if(!isSuccessfulRouteDelete(result)||(data->InterfaceLuid.Value!=0&&!isRouteAbsent(*data)))"
        failure = function_body(body, guard)
        for action in ("cleaned=false;", "++i;", "continue;"):
            self.assertIn(action, failure)
        self.assertNotIn("deletedata;", failure)
        self.assertNotIn(".erase(", failure)
        self.assertLess(body.index(failure), body.index("deletedata;"))
        self.assertIn("i=table.erase(i);", body)
        self.assertTrue(body.endswith("returncleaned;}"))

        disable = self.route_monitor_body("bool WindowsRouteMonitor::setDetaultRouteCapture(")
        self.assertIn("returnflushRouteTable(m_clonedRoutes);",
                      function_body(disable, "if(!m_defaultRouteCapture)"))

    def test_wireguard_cleanup_propagates_captured_route_failure(self) -> None:
        wireguard = read_source("client/platforms/windows/daemon/wireguardutilswindows.cpp")
        body = compact(function_body(
            wireguard, "bool WireguardUtilsWindows::deleteRoutePrefix("
        ))
        self.assertIn("boolcapturedRoutesClean=true;", body)
        capture = function_body(body, "if(m_routeMonitor&&(prefix.prefixLength()==0))")
        self.assertIn("capturedRoutesClean=m_routeMonitor->setDetaultRouteCapture(false);", capture)
        self.assertLess(body.index(capture), body.index("DeleteIpForwardEntry2(&entry)"))
        self.assertIn("logger.error()", function_body(
            body, "if(!isSuccessfulRouteDelete(result))"
        ))
        self.assertTrue(body.endswith(
            "returncapturedRoutesClean&&isSuccessfulRouteDelete(result);}"
        ))
        self.assertNotIn("returnresult==NO_ERROR;", body)

    def test_windows_error_message_is_unicode_and_has_safe_fallback(self) -> None:
        source = read_source("client/platforms/windows/windowsutils.cpp")
        body = function_body(source, "QString WindowsUtils::getErrorMessage(quint32 code)")

        self.assertIn("FormatMessageW(", body)
        self.assertNotIn("FormatMessageA(", body)
        self.assertIn("QString::fromWCharArray(messageBuffer, size)", body)
        self.assertIn("if (size != 0 && messageBuffer != nullptr)", body)
        self.assertIn('QStringLiteral("Windows error %1").arg(code)', body)
        self.assertLess(body.index("LocalFree(messageBuffer)"), body.index("return result;"))


if __name__ == "__main__":
    unittest.main()
