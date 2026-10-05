import argparse
import asyncio
import logging
import os
import time
from typing import Any, Dict, Iterable, List, Optional

from pysnmp.error import PySnmpError

from backend.database.device_repository import (
    fetch_snmp_targets,
    init_database,
    record_snmp_poll_results,
)


logger = logging.getLogger("netmonitor.snmp")

IF_DESCR_OID = "1.3.6.1.2.1.2.2.1.2"
IF_ADMIN_STATUS_OID = "1.3.6.1.2.1.2.2.1.7"
IF_OPER_STATUS_OID = "1.3.6.1.2.1.2.2.1.8"
IF_HIGH_SPEED_OID = "1.3.6.1.2.1.31.1.1.1.15"
IF_HC_IN_OCTETS_OID = "1.3.6.1.2.1.31.1.1.1.6"
IF_HC_OUT_OCTETS_OID = "1.3.6.1.2.1.31.1.1.1.10"

STATUS_NAMES = {
    1: "up",
    2: "down",
    3: "testing",
    4: "unknown",
    5: "dormant",
    6: "not_present",
    7: "lower_layer_down",
}


async def walk_column(
    snmp_engine,
    auth_data,
    transport_target,
    context_data,
    column_oid: str,
) -> Dict[int, Any]:
    from pysnmp.hlapi.v3arch.asyncio import ObjectIdentity, ObjectType, walk_cmd

    values = {}
    async for indication, status, _, bindings in walk_cmd(
        snmp_engine,
        auth_data,
        transport_target,
        context_data,
        ObjectType(ObjectIdentity(column_oid)),
        lexicographicMode=False,
    ):
        if indication:
            raise RuntimeError(f"SNMP request failed: {indication}")
        if status:
            raise RuntimeError(f"SNMP agent returned an error: {status}")

        for object_name, value in bindings:
            suffix = object_name.prettyPrint().removeprefix(f"{column_oid}.")
            try:
                interface_index = int(suffix)
            except ValueError as exc:
                raise RuntimeError(
                    f"Unexpected SNMP interface OID: {object_name.prettyPrint()}"
                ) from exc
            values[interface_index] = value

    return values


def value_as_int(value: Any, default: Optional[int] = None) -> Optional[int]:
    if value is None:
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def build_interface_snapshots(columns: Iterable[Dict[int, Any]]) -> List[Dict[str, Any]]:
    (
        descriptions,
        admin_statuses,
        oper_statuses,
        speeds,
        inbound_counters,
        outbound_counters,
    ) = columns

    interfaces = []
    for index, description in descriptions.items():
        admin_code = value_as_int(admin_statuses.get(index))
        oper_code = value_as_int(oper_statuses.get(index))
        in_octets = value_as_int(inbound_counters.get(index))
        out_octets = value_as_int(outbound_counters.get(index))
        if in_octets is None or out_octets is None:
            continue

        interfaces.append(
            {
                "interface_index": index,
                "name": description.prettyPrint(),
                "admin_status": STATUS_NAMES.get(admin_code, "unknown"),
                "oper_status": STATUS_NAMES.get(oper_code, "unknown"),
                "speed_mbps": value_as_int(speeds.get(index), default=0),
                "in_octets": in_octets,
                "out_octets": out_octets,
            }
        )

    return interfaces


async def collect_device_interfaces(
    device: Dict[str, Any],
    community: str,
    port: int,
    timeout_seconds: float,
    retries: int,
) -> Dict[str, Any]:
    from pysnmp.hlapi.v3arch.asyncio import (
        CommunityData,
        ContextData,
        SnmpEngine,
        UdpTransportTarget,
    )

    snmp_engine = SnmpEngine()
    try:
        transport_target = await UdpTransportTarget.create(
            (device["ip"], port),
            timeout=timeout_seconds,
            retries=retries,
        )
        auth_data = CommunityData(community, mpModel=1)
        context_data = ContextData()
        columns = await asyncio.gather(
            *(
                walk_column(
                    snmp_engine,
                    auth_data,
                    transport_target,
                    context_data,
                    oid,
                )
                for oid in (
                    IF_DESCR_OID,
                    IF_ADMIN_STATUS_OID,
                    IF_OPER_STATUS_OID,
                    IF_HIGH_SPEED_OID,
                    IF_HC_IN_OCTETS_OID,
                    IF_HC_OUT_OCTETS_OID,
                )
            )
        )
        return {
            "device_id": device["id"],
            "ip": device["ip"],
            "interfaces": build_interface_snapshots(columns),
        }
    finally:
        snmp_engine.close_dispatcher()


async def poll_all_devices(
    devices: List[Dict[str, Any]],
    community: str,
    port: int,
    timeout_seconds: float,
    retries: int,
    concurrency: int,
) -> List[Dict[str, Any]]:
    semaphore = asyncio.Semaphore(concurrency)

    async def poll_limited(device):
        async with semaphore:
            try:
                return await collect_device_interfaces(
                    device,
                    community=community,
                    port=port,
                    timeout_seconds=timeout_seconds,
                    retries=retries,
                )
            except (OSError, PySnmpError, RuntimeError, asyncio.TimeoutError) as exc:
                logger.warning(
                    "SNMP polling failed for device %s (%s): %s",
                    device["id"],
                    device["ip"],
                    exc,
                )
                return {
                    "device_id": device["id"],
                    "ip": device["ip"],
                    "interfaces": [],
                    "error": str(exc),
                }

    return await asyncio.gather(*(poll_limited(device) for device in devices))


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def non_negative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("must not be negative")
    return parsed


def positive_float(value: str) -> float:
    parsed = float(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


async def run_monitor(
    community: str,
    port: int,
    timeout_seconds: float,
    retries: int,
    concurrency: int,
    interval_seconds: float,
    once: bool,
) -> None:
    await asyncio.to_thread(init_database)

    while True:
        cycle_started = time.perf_counter()
        targets = await asyncio.to_thread(fetch_snmp_targets)
        if not targets:
            logger.warning("No devices in inventory; import devices before polling SNMP")
        else:
            results = await poll_all_devices(
                targets,
                community=community,
                port=port,
                timeout_seconds=timeout_seconds,
                retries=retries,
                concurrency=concurrency,
            )
            successful = [result for result in results if "error" not in result]
            if successful:
                await asyncio.to_thread(record_snmp_poll_results, successful)
            logger.info(
                "Polled %d devices; received interface data from %d",
                len(targets),
                len(successful),
            )

        if once:
            return
        elapsed = time.perf_counter() - cycle_started
        await asyncio.sleep(max(0, interval_seconds - elapsed))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Collect interface status and traffic counters using SNMPv2c."
    )
    parser.add_argument(
        "--port",
        type=positive_int,
        default=int(os.getenv("SNMP_PORT", "161")),
        help="SNMP agent UDP port (default: 161)",
    )
    parser.add_argument(
        "--timeout",
        type=positive_float,
        default=float(os.getenv("SNMP_TIMEOUT_SECONDS", "2")),
        help="timeout for each SNMP request in seconds (default: 2)",
    )
    parser.add_argument(
        "--retries",
        type=non_negative_int,
        default=int(os.getenv("SNMP_RETRIES", "1")),
        help="retries for each SNMP request (default: 1)",
    )
    parser.add_argument(
        "--concurrency",
        type=positive_int,
        default=int(os.getenv("SNMP_CONCURRENCY", "20")),
        help="maximum devices polled at once (default: 20)",
    )
    parser.add_argument(
        "--interval",
        type=positive_float,
        default=float(os.getenv("SNMP_INTERVAL_SECONDS", "60")),
        help="seconds between poll cycles (default: 60)",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="run one poll cycle and exit",
    )
    args = parser.parse_args()
    community = os.getenv("SNMP_COMMUNITY", "").strip()
    if not community:
        parser.error(
            "SNMP_COMMUNITY is required; set a read-only SNMPv2c community in .env"
        )

    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    asyncio.run(
        run_monitor(
            community=community,
            port=args.port,
            timeout_seconds=args.timeout,
            retries=args.retries,
            concurrency=args.concurrency,
            interval_seconds=args.interval,
            once=args.once,
        )
    )


if __name__ == "__main__":
    main()
