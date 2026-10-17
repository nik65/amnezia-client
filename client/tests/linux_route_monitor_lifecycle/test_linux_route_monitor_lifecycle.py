from __future__ import annotations

import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
SOURCE_PATH = REPOSITORY_ROOT / "client/platforms/linux/daemon/linuxroutemonitor.cpp"


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


class LinuxRouteMonitorLifecycleContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = SOURCE_PATH.read_text(encoding="utf-8")
        cls.constructor = function_body(cls.source, "LinuxRouteMonitor::LinuxRouteMonitor")
        cls.route_sender = function_body(
            cls.source, "LinuxRouteMonitor::EndpointRouteResult LinuxRouteMonitor::rtmSendRoute"
        )
        cls.socket_ready = function_body(cls.source, "void LinuxRouteMonitor::nlsockReady")

    def test_socket_creation_failure_stops_initialization(self) -> None:
        body = self.constructor
        failure = body.split('"Failed to create netlink socket:"', 1)[1]
        self.assertIn("return;", failure.split("struct sockaddr_nl", 1)[0])
        self.assertNotIn("QSocketNotifier", failure.split("struct sockaddr_nl", 1)[0])

    def test_bind_failure_closes_and_invalidates_descriptor(self) -> None:
        body = self.constructor
        failure = body.split('"Failed to bind netlink socket:"', 1)[1]
        failure = failure.split("m_notifier = new QSocketNotifier", 1)[0]
        self.assertIn("close(m_nlsock);", failure)
        self.assertIn("m_nlsock = -1;", failure)
        self.assertIn("return;", failure)

    def test_route_operations_fail_closed_without_a_socket(self) -> None:
        body = self.route_sender
        guard = body.split("constexpr size_t rtm_max_size", 1)[0]
        self.assertIn("if (m_nlsock < 0)", guard)
        self.assertIn("return EndpointRouteResult::Failed;", guard)

    def test_read_notifier_slot_ignores_invalid_socket(self) -> None:
        body = self.socket_ready
        guard = body.split("char buf[1024]", 1)[0]
        self.assertIn("if (m_nlsock < 0)", guard)
        self.assertIn("return;", guard)


if __name__ == "__main__":
    unittest.main()
