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


class WindowsUapiPeerContracts(unittest.TestCase):
    def setUp(self) -> None:
        self.source = read_source(
            "client/platforms/windows/daemon/wireguardutilswindows.cpp"
        )
        self.body = function_body(
            self.source, "bool WireguardUtilsWindows::updatePeer"
        )
        self.service_source = read_source(
            "client/platforms/windows/daemon/windowstunnelservice.cpp"
        )
        self.service_body = function_body(
            self.service_source, "QString WindowsTunnelService::uapiCommand"
        )
        self.parser_source = read_source(
            "client/platforms/windows/daemon/uapiresult.h"
        )

    def test_update_peer_requires_endpoint_routes_and_uapi_success(self) -> None:
        self.assertIn("bool endpointRoutesReady = true;", self.body)
        self.assertIn("endpointRoutesReady =", self.body)
        self.assertIn('"Failed to install peer endpoint exclusion route"', self.body)
        self.assertIn("amnezia::uapi::errnoFromReply(reply)", self.body)
        self.assertIn('"Peer configuration failed with UAPI errno:"', self.body)

        error_check = self.body.index("if (err != 0)")
        peer_insert = self.body.index("m_configuredPeers.insert")
        self.assertLess(error_check, peer_insert)

        route_failure = self.body.index("if (!endpointRoutesReady)")
        uapi_call = self.body.index("m_tunnel.uapiCommand(message)")
        self.assertLess(route_failure, uapi_call)

    def test_delete_and_status_reject_uapi_errors_before_state_changes(self) -> None:
        delete_body = function_body(
            self.source, "bool WireguardUtilsWindows::deletePeer"
        )
        status_body = function_body(
            self.source, "QList<WireguardUtils::PeerStatus> WireguardUtilsWindows::getPeerStatus"
        )
        self.assertIn("amnezia::uapi::errnoFromReply(reply)", delete_body)
        self.assertIn('"Peer deletion failed with UAPI errno:"', delete_body)
        self.assertLess(
            delete_body.index("if (err != 0)"),
            delete_body.index("m_configuredPeers.remove"),
        )
        self.assertIn(
            "const bool deferFirewallRemoval = m_configuredPeers.size() <= 1;",
            delete_body,
        )
        self.assertNotIn("m_nativeRemovedPeers", delete_body)
        self.assertLess(
            delete_body.index("if (!endpointRoutesClean)"),
            delete_body.index("m_configuredPeers.remove"),
        )
        self.assertIn("amnezia::uapi::errnoFromReply(reply)", status_body)
        self.assertIn('"Peer status query failed with UAPI errno:"', status_body)
        self.assertLess(status_body.index("if (err != 0)"), status_body.index("PeerStatus status"))
        self.assertNotIn('"DATA:"', self.source)

    def test_production_parser_has_fail_closed_terminal_errno_contract(self) -> None:
        self.assertIn("Qt::KeepEmptyParts", self.parser_source)
        self.assertIn("index != lines.size() - 1", self.parser_source)
        self.assertIn("character.isDigit()", self.parser_source)
        self.assertIn("return EINVAL;", self.parser_source)

    def test_uapi_pipe_rejects_short_writes_zero_reads_and_oversized_frames(self) -> None:
        self.assertIn("WINDOWS_TUNNEL_UAPI_MAX_REPLY_BYTES", self.service_source)
        self.assertIn("writtenTotal", self.service_body)
        self.assertIn("written == 0", self.service_body)
        self.assertIn('"Failed to write the complete UAPI request"', self.service_body)
        self.assertIn("read == 0", self.service_body)
        self.assertIn('"Invalid or oversized UAPI response"', self.service_body)
        self.assertIn('"Failed to read the complete UAPI response"', self.service_body)
        self.assertIn("Unexpected data after UAPI response frame", self.service_body)
        self.assertIn("frameEnd + 2 != reply.size()", self.service_body)
        self.assertNotIn("break;", self.service_body)
        self.assertLess(self.service_body.index("read == 0"), self.service_body.index("reply.append"))


if __name__ == "__main__":
    unittest.main()
