import unittest

from backend.monitoring.poll_snmp import build_interface_snapshots


class SnmpValue:
    def __init__(self, value):
        self.value = value

    def __int__(self):
        return int(self.value)

    def prettyPrint(self):
        return str(self.value)


class BuildInterfaceSnapshotsTests(unittest.TestCase):
    def test_builds_interface_snapshot_from_if_mib_columns(self):
        result = build_interface_snapshots(
            [
                {2: SnmpValue("Ethernet 1")},
                {2: SnmpValue(1)},
                {2: SnmpValue(1)},
                {2: SnmpValue(1000)},
                {2: SnmpValue(120000)},
                {2: SnmpValue(240000)},
            ]
        )

        self.assertEqual(
            result,
            [
                {
                    "interface_index": 2,
                    "name": "Ethernet 1",
                    "admin_status": "up",
                    "oper_status": "up",
                    "speed_mbps": 1000,
                    "in_octets": 120000,
                    "out_octets": 240000,
                }
            ],
        )

    def test_skips_interfaces_without_both_traffic_counters(self):
        result = build_interface_snapshots(
            [
                {1: SnmpValue("lo")},
                {1: SnmpValue(1)},
                {1: SnmpValue(1)},
                {1: SnmpValue(1000)},
                {1: SnmpValue(100)},
                {},
            ]
        )

        self.assertEqual(result, [])

    def test_unknown_status_code_maps_to_unknown(self):
        result = build_interface_snapshots(
            [
                {1: SnmpValue("port")},
                {1: SnmpValue(42)},
                {1: SnmpValue(42)},
                {},
                {1: SnmpValue(100)},
                {1: SnmpValue(200)},
            ]
        )

        self.assertEqual(result[0]["admin_status"], "unknown")
        self.assertEqual(result[0]["oper_status"], "unknown")
        self.assertEqual(result[0]["speed_mbps"], 0)
