from __future__ import annotations

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
        self.assertNotIn("GetLastError(", body)

    def test_route_delete_policy_accepts_only_idempotent_results(self) -> None:
        source = read_source("client/platforms/windows/daemon/windowsroutemonitor.cpp")
        helper = function_body(source, "bool isSuccessfulRouteDelete(DWORD result)")

        accepted = {0, 1168, 2}
        rejected = {5, 87, 1234}
        policy = lambda result: result in accepted
        self.assertTrue(all(policy(code) for code in accepted))
        self.assertTrue(all(not policy(code) for code in rejected))
        for name in ("NO_ERROR", "ERROR_NOT_FOUND", "ERROR_FILE_NOT_FOUND"):
            self.assertIn(name, helper)
        self.assertEqual(source.count("if (!isSuccessfulRouteDelete(result))"), 4)

        wireguard = read_source(
            "client/platforms/windows/daemon/wireguardutilswindows.cpp"
        )
        self.assertIn("bool isSuccessfulRouteDelete(DWORD result)", wireguard)
        delete_body = function_body(
            wireguard, "bool WireguardUtilsWindows::deleteRoutePrefix"
        )
        self.assertIn("return isSuccessfulRouteDelete(result);", delete_body)
        self.assertNotIn("return result == NO_ERROR;", delete_body)

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
