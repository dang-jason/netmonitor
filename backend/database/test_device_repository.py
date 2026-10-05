import unittest
from unittest.mock import MagicMock, patch

from backend.database.device_repository import record_snmp_poll_results


class RecordSnmpPollResultsTests(unittest.TestCase):
    @patch("backend.database.device_repository.get_connection")
    def test_saves_interface_status_rates_and_utilization(self, get_connection):
        connection = MagicMock()
        cursor = connection.cursor.return_value.__enter__.return_value
        cursor.fetchone.side_effect = [
            (12, 10_000, 20_000, 2.0),
            (12,),
        ]
        get_connection.return_value = connection

        record_snmp_poll_results(
            [
                {
                    "device_id": 3,
                    "interfaces": [
                        {
                            "interface_index": 4,
                            "name": "Ethernet 1",
                            "admin_status": "up",
                            "oper_status": "up",
                            "speed_mbps": 10,
                            "in_octets": 13_000,
                            "out_octets": 25_000,
                        }
                    ],
                }
            ]
        )

        connection.commit.assert_called_once()
        inserted_metrics = cursor.executemany.call_args.args[1]
        self.assertEqual(
            inserted_metrics,
            [
                (3, 12, "interface_oper_status", 1, "boolean", "up"),
                (3, 12, "inbound_bps", 12_000.0, "bps", None),
                (3, 12, "outbound_bps", 20_000.0, "bps", None),
                (3, 12, "utilization", 0.2, "percent", None),
            ],
        )

    @patch("backend.database.device_repository.get_connection")
    def test_first_sample_records_status_without_calculated_rates(self, get_connection):
        connection = MagicMock()
        cursor = connection.cursor.return_value.__enter__.return_value
        cursor.fetchone.side_effect = [None, (12,)]
        get_connection.return_value = connection

        record_snmp_poll_results(
            [
                {
                    "device_id": 3,
                    "interfaces": [
                        {
                            "interface_index": 4,
                            "name": "Ethernet 1",
                            "admin_status": "up",
                            "oper_status": "down",
                            "speed_mbps": 10,
                            "in_octets": 13_000,
                            "out_octets": 25_000,
                        }
                    ],
                }
            ]
        )

        inserted_metrics = cursor.executemany.call_args.args[1]
        self.assertEqual(
            inserted_metrics,
            [(3, 12, "interface_oper_status", 0, "boolean", "down")],
        )
