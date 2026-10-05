import os
from typing import Any, Dict, Iterable, Optional

from backend.config import PROJECT_ROOT


def get_connection():
    try:
        import psycopg2
    except ImportError as exc:
        raise RuntimeError(
            "psycopg2 is required for PostgreSQL support. Install it with "
            "'pip install -r backend/requirements.txt'."
        ) from exc

    return psycopg2.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=os.getenv("DB_PORT", "5432"),
        dbname=os.getenv("DB_NAME", "netmonitor"),
        user=os.getenv("DB_USER", "postgres"),
        password=os.getenv("DB_PASSWORD", ""),
    )


def init_database(schema_path: Optional[str] = None):
    if schema_path is None:
        schema_path = os.path.join(PROJECT_ROOT, "backend", "database", "schema.sql")

    with open(schema_path, "r", encoding="utf-8") as schema_file:
        schema_sql = schema_file.read()

    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(schema_sql)
        conn.commit()
    finally:
        conn.close()


def ensure_location(conn, location_name: Optional[str]) -> Optional[int]:
    if not location_name:
        return None

    with conn.cursor() as cursor:
        cursor.execute(
            "SELECT id FROM locations WHERE name = %s",
            (location_name,),
        )
        row = cursor.fetchone()
        if row:
            return row[0]

        cursor.execute(
            "INSERT INTO locations (name) VALUES (%s) RETURNING id",
            (location_name,),
        )
        return cursor.fetchone()[0]


def upsert_device(device: Dict[str, Any], location_name: Optional[str] = None):
    conn = get_connection()
    try:
        location_id = ensure_location(conn, location_name)
        with conn.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO devices (
                    ip_address,
                    hostname,
                    mac_address,
                    vendor,
                    device_type,
                    status,
                    last_seen,
                    location_id,
                    open_ports,
                    notes
                ) VALUES (%s, %s, %s, %s, %s, %s, NOW(), %s, %s, %s)
                ON CONFLICT (ip_address)
                DO UPDATE SET
                    hostname = EXCLUDED.hostname,
                    mac_address = EXCLUDED.mac_address,
                    vendor = EXCLUDED.vendor,
                    device_type = EXCLUDED.device_type,
                    status = EXCLUDED.status,
                    last_seen = NOW(),
                    location_id = EXCLUDED.location_id,
                    open_ports = EXCLUDED.open_ports,
                    notes = EXCLUDED.notes
                RETURNING id
                """,
                (
                    device.get("ip"),
                    device.get("hostname") or "Unknown",
                    device.get("mac_address"),
                    device.get("vendor") or "Unknown",
                    device.get("type") or "Unknown Device",
                    "discovered",
                    location_id,
                    device.get("open_ports") or [],
                    None,
                ),
            )
            device_id = cursor.fetchone()[0]
        conn.commit()
        return device_id
    finally:
        conn.close()


def bulk_upsert_devices(
    devices: Iterable[Dict[str, Any]],
    location_name: Optional[str] = None,
):
    inserted = []
    for device in devices:
        inserted.append(upsert_device(device, location_name=location_name))
    return inserted


def fetch_devices(limit: Optional[int] = None):
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            if limit:
                cursor.execute(
                    """
                    SELECT id, ip_address, hostname, mac_address, vendor,
                           device_type, status, last_seen
                    FROM devices
                    ORDER BY last_seen DESC
                    LIMIT %s
                    """,
                    (limit,),
                )
            else:
                cursor.execute(
                    """
                    SELECT id, ip_address, hostname, mac_address, vendor,
                           device_type, status, last_seen
                    FROM devices
                    ORDER BY last_seen DESC
                    """
                )
            rows = cursor.fetchall()
            return [
                {
                    "id": row[0],
                    "ip": str(row[1]),
                    "hostname": row[2],
                    "mac_address": str(row[3]) if row[3] else None,
                    "vendor": row[4],
                    "type": row[5],
                    "status": row[6],
                    "last_seen": row[7],
                }
                for row in rows
            ]
    finally:
        conn.close()


def fetch_monitor_targets():
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT id, host(ip_address) FROM devices ORDER BY id"
            )
            return [{"id": row[0], "ip": row[1]} for row in cursor.fetchall()]
    finally:
        conn.close()


def fetch_snmp_targets():
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, host(ip_address) FROM devices ORDER BY id")
            return [{"id": row[0], "ip": row[1]} for row in cursor.fetchall()]
    finally:
        conn.close()


def record_snmp_poll_results(results):
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            for result in results:
                device_id = result["device_id"]
                for interface in result["interfaces"]:
                    cursor.execute(
                        """
                        SELECT id, in_octets, out_octets,
                               EXTRACT(EPOCH FROM (NOW() - sampled_at))
                        FROM interfaces
                        WHERE device_id = %s AND interface_index = %s
                        """,
                        (device_id, interface["interface_index"]),
                    )
                    previous = cursor.fetchone()

                    cursor.execute(
                        """
                        INSERT INTO interfaces (
                            device_id, interface_index, name, description,
                            admin_status, oper_status, speed_mbps,
                            in_octets, out_octets, sampled_at, last_seen
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, NOW(), NOW())
                        ON CONFLICT (device_id, interface_index)
                        DO UPDATE SET
                            name = EXCLUDED.name,
                            description = EXCLUDED.description,
                            admin_status = EXCLUDED.admin_status,
                            oper_status = EXCLUDED.oper_status,
                            speed_mbps = EXCLUDED.speed_mbps,
                            in_octets = EXCLUDED.in_octets,
                            out_octets = EXCLUDED.out_octets,
                            sampled_at = NOW(),
                            last_seen = NOW()
                        RETURNING id
                        """,
                        (
                            device_id,
                            interface["interface_index"],
                            interface["name"],
                            interface["name"],
                            interface["admin_status"],
                            interface["oper_status"],
                            interface["speed_mbps"],
                            interface["in_octets"],
                            interface["out_octets"],
                        ),
                    )
                    interface_id = cursor.fetchone()[0]
                    metrics = [
                        (
                            device_id,
                            interface_id,
                            "interface_oper_status",
                            1 if interface["oper_status"] == "up" else 0,
                            "boolean",
                            interface["oper_status"],
                        )
                    ]

                    if previous and previous[3] and previous[3] > 0:
                        elapsed_seconds = previous[3]
                        in_delta = interface["in_octets"] - previous[1]
                        out_delta = interface["out_octets"] - previous[2]
                        if in_delta >= 0:
                            metrics.append(
                                (
                                    device_id,
                                    interface_id,
                                    "inbound_bps",
                                    in_delta * 8 / elapsed_seconds,
                                    "bps",
                                    None,
                                )
                            )
                        if out_delta >= 0:
                            metrics.append(
                                (
                                    device_id,
                                    interface_id,
                                    "outbound_bps",
                                    out_delta * 8 / elapsed_seconds,
                                    "bps",
                                    None,
                                )
                            )
                        if (
                            interface["speed_mbps"] > 0
                            and in_delta >= 0
                            and out_delta >= 0
                        ):
                            utilization = (
                                max(in_delta, out_delta)
                                * 8
                                / elapsed_seconds
                                / (interface["speed_mbps"] * 1_000_000)
                                * 100
                            )
                            metrics.append(
                                (
                                    device_id,
                                    interface_id,
                                    "utilization",
                                    min(utilization, 100.0),
                                    "percent",
                                    None,
                                )
                            )

                    cursor.executemany(
                        """
                        INSERT INTO device_metrics (
                            device_id, interface_id, metric_name, metric_value,
                            unit, details
                        ) VALUES (%s, %s, %s, %s, %s, %s)
                        """,
                        metrics,
                    )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def record_device_poll_results(results):
    conn = get_connection()
    try:
        with conn.cursor() as cursor:
            for result in results:
                is_online = result["status"] == "online"
                cursor.execute(
                    """
                    UPDATE devices
                    SET status = %s,
                        last_seen = CASE WHEN %s THEN NOW() ELSE last_seen END
                    WHERE id = %s
                    """,
                    (result["status"], is_online, result["device_id"]),
                )
                cursor.executemany(
                    """
                    INSERT INTO device_metrics (
                        device_id, metric_name, metric_value, unit, details
                    ) VALUES (%s, %s, %s, %s, %s)
                    """,
                    [
                        (
                            result["device_id"],
                            "availability",
                            1 if is_online else 0,
                            "boolean",
                            result["error"],
                        ),
                        (
                            result["device_id"],
                            "latency",
                            result["latency_ms"],
                            "ms",
                            None,
                        ),
                    ],
                )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
