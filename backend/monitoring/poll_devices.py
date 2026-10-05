import argparse
import asyncio
import logging
import os
import platform
import time
from typing import Any, Dict, Optional

from backend.database.device_repository import (
    fetch_monitor_targets,
    init_database,
    record_device_poll_results,
)


logger = logging.getLogger("netmonitor.monitor")


def build_ping_command(ip: str, timeout_seconds: float):
    timeout_ms = max(1, int(timeout_seconds * 1000))
    if platform.system().lower() == "windows":
        return ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    return ["ping", "-c", "1", "-W", str(max(1, int(timeout_seconds))), ip]


async def ping_device(
    device: Dict[str, Any],
    retries: int,
    timeout_seconds: float,
) -> Dict[str, Any]:
    last_error: Optional[str] = None

    for attempt in range(retries + 1):
        started_at = time.perf_counter()
        process = None
        try:
            process = await asyncio.create_subprocess_exec(
                *build_ping_command(device["ip"], timeout_seconds),
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                await asyncio.wait_for(
                    process.communicate(),
                    timeout=timeout_seconds + 2,
                )
            except asyncio.TimeoutError:
                if process.returncode is None:
                    process.kill()
                    await process.communicate()
                last_error = f"Ping process exceeded {timeout_seconds + 2:g}s timeout"
            else:
                if process.returncode == 0:
                    return {
                        "device_id": device["id"],
                        "ip": device["ip"],
                        "status": "online",
                        "latency_ms": round((time.perf_counter() - started_at) * 1000, 2),
                        "error": None,
                    }

                last_error = f"Ping returned exit code {process.returncode}"
        except OSError as exc:
            last_error = f"Unable to run ping: {exc}"
        finally:
            if process is not None and process.returncode is None:
                process.kill()
                await process.wait()

        if attempt < retries:
            await asyncio.sleep(0.25 * (attempt + 1))

    return {
        "device_id": device["id"],
        "ip": device["ip"],
        "status": "offline",
        "latency_ms": None,
        "error": last_error or "Ping failed",
    }


async def poll_all_devices(
    devices,
    concurrency: int,
    retries: int,
    timeout_seconds: float,
):
    semaphore = asyncio.Semaphore(concurrency)

    async def poll_limited(device):
        async with semaphore:
            return await ping_device(device, retries, timeout_seconds)

    return await asyncio.gather(*(poll_limited(device) for device in devices))


async def run_monitor(
    interval_seconds: float,
    concurrency: int,
    retries: int,
    timeout_seconds: float,
    once: bool,
):
    await asyncio.to_thread(init_database)

    while True:
        cycle_started = time.perf_counter()
        devices = await asyncio.to_thread(fetch_monitor_targets)

        if not devices:
            logger.warning("No devices in inventory; add devices before monitoring")
        else:
            results = await poll_all_devices(
                devices,
                concurrency=concurrency,
                retries=retries,
                timeout_seconds=timeout_seconds,
            )
            await asyncio.to_thread(record_device_poll_results, results)
            online_count = sum(result["status"] == "online" for result in results)
            logger.info(
                "Polled %d devices: %d online, %d offline",
                len(results),
                online_count,
                len(results) - online_count,
            )
            for result in results:
                if result["status"] == "offline":
                    logger.warning(
                        "Device %s (%s) is offline: %s",
                        result["device_id"],
                        result["ip"],
                        result["error"],
                    )

        if once:
            return

        elapsed = time.perf_counter() - cycle_started
        await asyncio.sleep(max(0, interval_seconds - elapsed))


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


def main():
    parser = argparse.ArgumentParser(description="Poll inventory devices by ping.")
    parser.add_argument(
        "--interval",
        type=positive_float,
        default=float(os.getenv("MONITOR_INTERVAL_SECONDS", "30")),
        help="seconds between poll cycles (default: 30)",
    )
    parser.add_argument(
        "--concurrency",
        type=positive_int,
        default=int(os.getenv("MONITOR_CONCURRENCY", "50")),
        help="maximum concurrent ping checks (default: 50)",
    )
    parser.add_argument(
        "--retries",
        type=non_negative_int,
        default=int(os.getenv("MONITOR_RETRIES", "1")),
        help="retries after the first failed ping (default: 1)",
    )
    parser.add_argument(
        "--timeout",
        type=positive_float,
        default=float(os.getenv("MONITOR_TIMEOUT_SECONDS", "2")),
        help="ping timeout in seconds (default: 2)",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="run one poll cycle and exit",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    asyncio.run(
        run_monitor(
            interval_seconds=args.interval,
            concurrency=args.concurrency,
            retries=args.retries,
            timeout_seconds=args.timeout,
            once=args.once,
        )
    )


if __name__ == "__main__":
    main()
