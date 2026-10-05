import unittest
from unittest.mock import AsyncMock, patch

from backend.monitoring.poll_devices import build_ping_command, ping_device


class BuildPingCommandTests(unittest.TestCase):
    @patch("backend.monitoring.poll_devices.platform.system", return_value="Windows")
    def test_uses_windows_ping_arguments(self, _):
        self.assertEqual(
            build_ping_command("192.0.2.10", 1.5),
            ["ping", "-n", "1", "-w", "1500", "192.0.2.10"],
        )

    @patch("backend.monitoring.poll_devices.platform.system", return_value="Linux")
    def test_uses_unix_ping_arguments(self, _):
        self.assertEqual(
            build_ping_command("192.0.2.10", 2.5),
            ["ping", "-c", "1", "-W", "2", "192.0.2.10"],
        )


class PingDeviceTests(unittest.IsolatedAsyncioTestCase):
    async def test_retries_then_returns_successful_latency(self):
        first_process = AsyncMock()
        first_process.returncode = 1
        second_process = AsyncMock()
        second_process.returncode = 0

        with patch(
            "backend.monitoring.poll_devices.asyncio.create_subprocess_exec",
            new=AsyncMock(side_effect=[first_process, second_process]),
        ) as create_process:
            result = await ping_device(
                {"id": 4, "ip": "192.0.2.10"},
                retries=1,
                timeout_seconds=0.1,
            )

        self.assertEqual(create_process.await_count, 2)
        self.assertEqual(result["status"], "online")
        self.assertIsInstance(result["latency_ms"], float)
        self.assertIsNone(result["error"])

    async def test_reports_offline_when_ping_cannot_start(self):
        with patch(
            "backend.monitoring.poll_devices.asyncio.create_subprocess_exec",
            new=AsyncMock(side_effect=FileNotFoundError("ping")),
        ):
            result = await ping_device(
                {"id": 5, "ip": "192.0.2.11"},
                retries=0,
                timeout_seconds=0.1,
            )

        self.assertEqual(result["status"], "offline")
        self.assertIsNone(result["latency_ms"])
        self.assertIn("Unable to run ping", result["error"])
