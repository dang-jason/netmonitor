# NetMonitor

NetMonitor is a practical network operations dashboard project for learning
network discovery, monitoring, and full-stack application fundamentals.

## Current status

This repository contains a Python network discovery prototype with PostgreSQL
device inventory, ping-based health monitoring, optional SNMP interface
collection, an authenticated Node.js REST API, and a React dashboard.

## Current prototype features

- Ping sweep across a subnet
- ARP table discovery
- Hostname lookups
- OUI vendor mapping via local `oui_database.json`
- Basic device classification
- Manual device addition helper
- PostgreSQL inventory for devices, interfaces, and locations
- Ping-based availability and latency history
- Optional SNMP interface status and traffic metrics
- Authenticated REST API for inventory and metrics

## PostgreSQL setup

The PostgreSQL schema stores discovered devices, their interfaces, and locations.

1. Install PostgreSQL and create a database named `netmonitor`.
2. Install Python dependencies:
   ```bash
   python -m pip install -r backend/requirements.txt
   ```
3. Copy the example environment file and edit it with your PostgreSQL password:
   ```powershell
   Copy-Item .env.example .env
   notepad .env
   ```
   `.env` is ignored by Git and should never be committed. The example file
   also documents the optional discovery and monitoring settings.
4. Initialize the schema:
   ```bash
   python -c "from backend.database.device_repository import init_database; init_database()"
   ```
5. Verify the tables from the `netmonitor` database prompt:
   ```powershell
   psql -h localhost -U postgres -d netmonitor
   ```
   If `psql` is not on `PATH`, run it from the PostgreSQL `bin` directory, for
   example:
   ```powershell
   & "C:\Program Files\PostgreSQL\18\bin\psql.exe" -h localhost -U postgres -d netmonitor
   ```
   At the database prompt, list the tables:
   ```text
   \dt
   ```

### Import discovered devices

```bash
python -m backend.database.store_discovered_devices
```

Run this command from the repository root. Set `DISCOVERY_NETWORK` in `.env`
to a subnet you own or are authorized to scan. `DEVICE_LOCATION` labels the
inventory location.

## Device health monitoring

The monitoring service checks each inventory device using ping, updates its
`online`/`offline` status, and records timestamped availability and latency
measurements in `device_metrics`.

Run one poll cycle:

```bash
python -m backend.monitoring.poll_devices --once
```

Run continuously (polling every 30 seconds by default):

```bash
python -m backend.monitoring.poll_devices
```

Options can be supplied as command-line flags or configured in `.env` with
`MONITOR_INTERVAL_SECONDS`, `MONITOR_CONCURRENCY`, `MONITOR_RETRIES`, and
`MONITOR_TIMEOUT_SECONDS`.

## SNMP interface monitoring

The SNMP collector reads interface descriptions, administrative and operating
status, speed, and 64-bit traffic counters using SNMPv2c and the standard IF-MIB.
It stores interface snapshots and status history. After a second successful
sample, it also records inbound/outbound bit rates and utilization. Utilization
is calculated as the larger traffic direction divided by the interface speed.

Enable SNMP on the devices you administer, configure a read-only community,
and set `SNMP_COMMUNITY` in `.env` to match. SNMPv2c sends the community string
without encryption; use it only on a trusted management network. SNMPv3 support
is not implemented yet.

Run one SNMP collection cycle:

```bash
python -m backend.monitoring.poll_snmp --once
```

Run continuously (every 60 seconds by default):

```bash
python -m backend.monitoring.poll_snmp
```

Tune `SNMP_PORT`, `SNMP_TIMEOUT_SECONDS`, `SNMP_RETRIES`,
`SNMP_CONCURRENCY`, and `SNMP_INTERVAL_SECONDS` in `.env` if needed. Devices
that do not respond to SNMP are reported in the logs; the existing ping monitor
remains separate and continues to work without SNMP.

## REST API

The Express API provides authenticated device CRUD endpoints and device
metrics/interface reads. Generate a private API token and add it to `.env`:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Copy the generated value into `API_TOKEN`. Keep it secret; requests must send
it in an `Authorization: Bearer <token>` header. Add `API_TOKEN` to the
repository-root `.env` file; the generated value is not automatically copied
into PowerShell's environment. The API binds to `127.0.0.1:3000` by default,
so it is available only from this computer.

Confirm `DB_PASSWORD` in `.env` is the current password for the PostgreSQL
`DB_USER`. The API and Python services use the same database credentials.

Install Node.js dependencies and start the API from the repository root:

```powershell
npm install
npm run start:api
```

Check the API and database connection at `http://127.0.0.1:3000/healthz`.
Authenticated endpoints:

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/devices` | List devices (`limit` and `offset` supported) |
| `POST` | `/api/devices` | Add a device |
| `GET` | `/api/devices/:id` | Get a device |
| `PUT` | `/api/devices/:id` | Update supplied device fields |
| `DELETE` | `/api/devices/:id` | Delete a device and its related data |
| `GET` | `/api/devices/:id/interfaces` | List interfaces |
| `GET` | `/api/devices/:id/metrics` | List recent metrics (`limit` supported) |

Example request from PowerShell:

```powershell
$token = Read-Host "Enter the API token from .env"
$headers = @{ Authorization = "Bearer $token" }
Invoke-RestMethod -Uri "http://127.0.0.1:3000/api/devices" -Headers $headers
```

Run API tests with `npm run test:api`. API configuration is documented in
`.env.example`.

## React dashboard

Install the dashboard dependencies once:

```powershell
npm install --prefix frontend
```

Start the API in one PowerShell window:

```powershell
npm run start:api
```

Start the dashboard in a second window:

```powershell
npm run dev:dashboard
```

Open `http://127.0.0.1:5173`. Enter the `API_TOKEN` from `.env` when prompted;
the dashboard keeps it only in the current browser session. The development
server proxies API requests to the local Node.js server. The dashboard shows
inventory, status counts, interfaces, and recent metrics; it refreshes device
data every 30 seconds. Use the search/filter controls, select a device for
details, or add an inventory entry from the page. Run `npm run build:dashboard`
to create a production build in `frontend/dist`.

## Planned next steps

- Production deployment and authentication hardening
- Charts for historical latency and interface utilization
