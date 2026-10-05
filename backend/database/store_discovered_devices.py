import os

from backend.database.device_repository import bulk_upsert_devices, init_database
from backend.discovery.gather_devices import NetworkDiscovery


def main() -> None:
    """Discover devices on the configured network and save them to PostgreSQL."""
    network_range = os.getenv("DISCOVERY_NETWORK", "192.168.1.0/24")
    location_name = os.getenv("DEVICE_LOCATION", "default")

    init_database()
    discovery = NetworkDiscovery()
    devices = discovery.discover_network(network_range, include_port_scan=True)
    stored_device_ids = bulk_upsert_devices(devices, location_name=location_name)

    print(
        f"Discovered {len(devices)} devices and stored "
        f"{len(stored_device_ids)} records."
    )
    print(f"Location: {location_name}")

    for device in devices:
        print(
            f"- {device['ip']} | {device['hostname']} | "
            f"{device['type']} | {device['vendor']}"
        )


if __name__ == "__main__":
    main()
