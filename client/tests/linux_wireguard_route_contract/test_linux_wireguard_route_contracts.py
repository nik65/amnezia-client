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


class LinuxWireguardRouteContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        source = read_source(
            "client/platforms/linux/daemon/wireguardutilslinux.cpp"
        )
        cls.delete_route_body = function_body(
            source, "bool WireguardUtilsLinux::deleteRoutePrefix"
        )

    def test_non_default_prefix_uses_production_delete_method(self) -> None:
        body = self.delete_route_body
        non_default = body.split("if (prefix.prefixLength() > 0)", 1)[1]
        non_default = non_default.split("// Ensure that we do not replace", 1)[0]

        self.assertIn("return m_rtmonitor->deleteRoute(prefix);", non_default)
        self.assertNotIn("insertRoute", non_default)

    def test_ipv4_default_split_routes_are_deleted_by_production_method(self) -> None:
        body = self.delete_route_body
        ipv4 = body.split("if (prefix.type() == QAbstractSocket::IPv4Protocol)", 1)[1]
        ipv4 = ipv4.split("if (prefix.type() == QAbstractSocket::IPv6Protocol)", 1)[0]

        self.assertEqual(
            ipv4.count("m_rtmonitor->deleteRoute("),
            2,
        )
        self.assertIn('IPAddress("0.0.0.0/1")', ipv4)
        self.assertIn('IPAddress("128.0.0.0/1")', ipv4)
        self.assertNotIn("insertRoute", ipv4)

    def test_ipv6_default_split_routes_are_deleted_by_production_method(self) -> None:
        body = self.delete_route_body
        ipv6 = body.split("if (prefix.type() == QAbstractSocket::IPv6Protocol)", 1)[1]
        ipv6 = ipv6.split("} else {", 1)[0]

        self.assertEqual(
            ipv6.count("m_rtmonitor->deleteRoute("),
            2,
        )
        self.assertIn('IPAddress("::/1")', ipv6)
        self.assertIn('IPAddress("8000::/1")', ipv6)
        self.assertNotIn("insertRoute", ipv6)


if __name__ == "__main__":
    unittest.main()
