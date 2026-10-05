import { useCallback, useEffect, useMemo, useState } from "react";

const TOKEN_STORAGE_KEY = "netmonitor-api-token";

async function apiRequest(path, token, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: {
      authorization: `Bearer ${token}`,
      ...(options.body ? { "content-type": "application/json" } : {}),
      ...options.headers,
    },
  });

  if (response.status === 204) return null;
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(payload.error || `Request failed (${response.status}).`);
    error.status = response.status;
    throw error;
  }
  return payload;
}

function formatDate(value) {
  if (!value) return "Never";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Unknown";
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}

function formatMetric(metric) {
  if (metric.metric_value === null || metric.metric_value === undefined) {
    return "No sample";
  }
  if (metric.unit === "boolean") {
    return Number(metric.metric_value) === 1 ? "Reachable" : "Unreachable";
  }
  const value = Number(metric.metric_value);
  if (!Number.isFinite(value)) return String(metric.metric_value);
  if (metric.unit === "bps") {
    if (value >= 1_000_000_000) return `${(value / 1_000_000_000).toFixed(2)} Gbps`;
    if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(2)} Mbps`;
    if (value >= 1_000) return `${(value / 1_000).toFixed(2)} Kbps`;
    return `${value.toFixed(0)} bps`;
  }
  if (metric.unit === "percent") return `${value.toFixed(1)}%`;
  if (metric.unit === "ms") return `${value.toFixed(1)} ms`;
  return `${value.toLocaleString()}${metric.unit ? ` ${metric.unit}` : ""}`;
}

function StatusBadge({ status }) {
  const normalized = (status || "unknown").toLowerCase();
  return (
    <span className={`status-badge status-${normalized}`}>
      <span className="status-dot" />
      {normalized}
    </span>
  );
}

function TokenGate({ onConnect, error }) {
  const [value, setValue] = useState("");

  function submit(event) {
    event.preventDefault();
    const token = value.trim();
    if (token) onConnect(token);
  }

  return (
    <main className="gate-page">
      <section className="gate-card">
        <div className="brand-mark">N</div>
        <p className="eyebrow">LOCAL NETWORK CONSOLE</p>
        <h1>Connect to NetMonitor</h1>
        <p className="muted">
          Enter the API token from your local <code>.env</code> file. It stays in
          this browser tab and is never saved to the project.
        </p>
        <form onSubmit={submit} className="token-form">
          <label htmlFor="api-token">API token</label>
          <input
            id="api-token"
            type="password"
            autoComplete="current-password"
            value={value}
            onChange={(event) => setValue(event.target.value)}
            placeholder="Paste your API_TOKEN"
            required
          />
          {error && <p className="form-error">{error}</p>}
          <button className="primary-button" type="submit">
            Connect dashboard <span aria-hidden="true">→</span>
          </button>
        </form>
        <p className="gate-footnote">
          The API must be running on this computer at 127.0.0.1:3000.
        </p>
      </section>
    </main>
  );
}

function AddDeviceDialog({ token, onClose, onCreated }) {
  const [ipAddress, setIpAddress] = useState("");
  const [hostname, setHostname] = useState("");
  const [isSaving, setIsSaving] = useState(false);
  const [error, setError] = useState("");

  async function submit(event) {
    event.preventDefault();
    setIsSaving(true);
    setError("");
    try {
      await apiRequest("/api/devices", token, {
        method: "POST",
        body: JSON.stringify({
          ip_address: ipAddress.trim(),
          ...(hostname.trim() ? { hostname: hostname.trim() } : {}),
        }),
      });
      await onCreated();
      onClose();
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setIsSaving(false);
    }
  }

  return (
    <div className="dialog-backdrop" onMouseDown={onClose}>
      <section
        aria-labelledby="add-device-title"
        aria-modal="true"
        className="dialog-card"
        onMouseDown={(event) => event.stopPropagation()}
        role="dialog"
      >
        <div className="dialog-heading">
          <div>
            <p className="eyebrow">INVENTORY</p>
            <h2 id="add-device-title">Add a device</h2>
          </div>
          <button className="icon-button" onClick={onClose} aria-label="Close">
            ×
          </button>
        </div>
        <form className="device-form" onSubmit={submit}>
          <label htmlFor="device-ip">IP address</label>
          <input
            id="device-ip"
            autoFocus
            value={ipAddress}
            onChange={(event) => setIpAddress(event.target.value)}
            placeholder="192.168.1.25"
            required
          />
          <label htmlFor="device-hostname">Name <span>Optional</span></label>
          <input
            id="device-hostname"
            value={hostname}
            onChange={(event) => setHostname(event.target.value)}
            placeholder="Living room access point"
          />
          {error && <p className="form-error">{error}</p>}
          <div className="dialog-actions">
            <button className="secondary-button" type="button" onClick={onClose}>
              Cancel
            </button>
            <button className="primary-button" disabled={isSaving} type="submit">
              {isSaving ? "Adding..." : "Add device"}
            </button>
          </div>
        </form>
      </section>
    </div>
  );
}

function DeviceDetails({ device, interfaces, metrics, isLoading, onClose }) {
  if (!device) {
    return (
      <aside className="details-panel details-empty">
        <div className="empty-icon">⌁</div>
        <h3>Select a device</h3>
        <p>Choose a device from your inventory to see its interfaces and recent metrics.</p>
      </aside>
    );
  }

  return (
    <aside className="details-panel">
      <div className="details-heading">
        <div className="device-avatar">{(device.hostname || device.device_type || "D")[0].toUpperCase()}</div>
        <button className="icon-button mobile-close" onClick={onClose} aria-label="Close details">
          ×
        </button>
        <div className="details-device-title">
          <h2>{device.hostname || device.device_type || "Unnamed device"}</h2>
          <code>{device.ip_address}</code>
        </div>
      </div>
      <div className="details-status-row">
        <StatusBadge status={device.status} />
        <span>Last seen {formatDate(device.last_seen)}</span>
      </div>
      <div className="details-meta">
        <div><span>Vendor</span><strong>{device.vendor || "Unknown"}</strong></div>
        <div><span>Type</span><strong>{device.device_type || "Unknown"}</strong></div>
        <div><span>MAC address</span><strong>{device.mac_address || "Not available"}</strong></div>
      </div>
      <section className="detail-section">
        <div className="section-heading">
          <h3>Interfaces</h3>
          <span className="count-pill">{interfaces.length}</span>
        </div>
        {isLoading ? (
          <p className="muted">Loading interfaces...</p>
        ) : interfaces.length ? (
          <div className="interface-list">
            {interfaces.map((item) => (
              <div className="interface-row" key={item.id}>
                <div className="interface-icon">⇄</div>
                <div className="interface-name">
                  <strong>{item.name}</strong>
                  <span>{item.speed_mbps ? `${item.speed_mbps} Mbps` : "Speed unavailable"}</span>
                </div>
                <StatusBadge status={item.oper_status} />
              </div>
            ))}
          </div>
        ) : (
          <p className="empty-copy">No interface data yet. SNMP support is optional.</p>
        )}
      </section>
      <section className="detail-section">
        <div className="section-heading">
          <h3>Recent metrics</h3>
          <span className="count-pill">{metrics.length}</span>
        </div>
        {isLoading ? (
          <p className="muted">Loading metrics...</p>
        ) : metrics.length ? (
          <div className="metric-list">
            {metrics.slice(0, 8).map((metric) => (
              <div className="metric-row" key={metric.id}>
                <div>
                  <strong>{metric.metric_name.replaceAll("_", " ")}</strong>
                  <span>{formatDate(metric.collected_at)}</span>
                </div>
                <b>{formatMetric(metric)}</b>
              </div>
            ))}
          </div>
        ) : (
          <p className="empty-copy">No measurements yet. Run the ping monitor to collect availability data.</p>
        )}
      </section>
    </aside>
  );
}

function Dashboard({ token, onDisconnect }) {
  const [devices, setDevices] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [interfaces, setInterfaces] = useState([]);
  const [metrics, setMetrics] = useState([]);
  const [detailLoading, setDetailLoading] = useState(false);
  const [loading, setLoading] = useState(true);
  const [refreshVersion, setRefreshVersion] = useState(0);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [showAddDialog, setShowAddDialog] = useState(false);
  const [refreshedAt, setRefreshedAt] = useState(null);

  const selectedDevice = devices.find((device) => device.id === selectedId) || null;

  const loadDevices = useCallback(async () => {
    setError("");
    setLoading(true);
    try {
      const payload = await apiRequest("/api/devices?limit=500", token);
      setDevices(payload.data);
      setRefreshedAt(new Date());
      setRefreshVersion((version) => version + 1);
      setSelectedId((currentId) =>
        payload.data.some((device) => device.id === currentId)
          ? currentId
          : payload.data[0]?.id ?? null,
      );
    } catch (requestError) {
      if (requestError.status === 401) onDisconnect();
      setError(requestError.message);
    } finally {
      setLoading(false);
    }
  }, [onDisconnect, token]);

  useEffect(() => {
    loadDevices();
  }, [loadDevices]);

  useEffect(() => {
    const intervalId = window.setInterval(loadDevices, 30_000);
    return () => window.clearInterval(intervalId);
  }, [loadDevices]);

  useEffect(() => {
    if (!selectedId) {
      setInterfaces([]);
      setMetrics([]);
      return undefined;
    }
    const controller = new AbortController();
    setDetailLoading(true);

    async function loadDetails() {
      try {
        const [interfacePayload, metricPayload] = await Promise.all([
          apiRequest(`/api/devices/${selectedId}/interfaces`, token, {
            signal: controller.signal,
          }),
          apiRequest(`/api/devices/${selectedId}/metrics?limit=30`, token, {
            signal: controller.signal,
          }),
        ]);
        setInterfaces(interfacePayload.data);
        setMetrics(metricPayload.data);
      } catch (requestError) {
        if (requestError.name !== "AbortError") setError(requestError.message);
      } finally {
        if (!controller.signal.aborted) setDetailLoading(false);
      }
    }

    loadDetails();
    return () => controller.abort();
  }, [refreshVersion, selectedId, token]);

  const counts = useMemo(
    () => ({
      total: devices.length,
      online: devices.filter((device) => device.status === "online").length,
      offline: devices.filter((device) => device.status === "offline").length,
      unknown: devices.filter((device) => !["online", "offline"].includes(device.status)).length,
    }),
    [devices],
  );

  const filteredDevices = useMemo(() => {
    const normalizedSearch = search.trim().toLowerCase();
    return devices.filter((device) => {
      const matchesStatus = statusFilter === "all" || device.status === statusFilter;
      const searchable = [
        device.ip_address,
        device.hostname,
        device.vendor,
        device.device_type,
      ].join(" ").toLowerCase();
      return matchesStatus && (!normalizedSearch || searchable.includes(normalizedSearch));
    });
  }, [devices, search, statusFilter]);

  return (
    <div className="app-shell">
      <header className="topbar">
        <a className="brand" href="/" aria-label="NetMonitor home">
          <span className="brand-mark">N</span>
          <span>net<span className="brand-light">monitor</span></span>
        </a>
        <div className="topbar-right">
          <span className="local-indicator"><i /> Local environment</span>
          <button className="text-button" onClick={onDisconnect}>Disconnect</button>
          <div className="user-avatar" aria-hidden="true">N</div>
        </div>
      </header>

      <main className="main-content">
        <section className="page-heading">
          <div>
            <p className="eyebrow">NETWORK OPERATIONS</p>
            <h1>Device overview</h1>
            <p className="muted">A live view of the devices in your network inventory.</p>
          </div>
          <div className="heading-actions">
            <span className="refresh-label">
              {refreshedAt ? `Updated ${refreshedAt.toLocaleTimeString()}` : "Not updated yet"}
            </span>
            <button className="secondary-button" disabled={loading} onClick={loadDevices}>
              <span className={loading ? "refresh-icon spinning" : "refresh-icon"}>↻</span>
              Refresh
            </button>
            <button className="primary-button" onClick={() => setShowAddDialog(true)}>
              <span>＋</span> Add device
            </button>
          </div>
        </section>

        <section className="stat-grid" aria-label="Device status summary">
          <StatCard label="Total devices" value={counts.total} icon="⌘" accent="slate" />
          <StatCard label="Online" value={counts.online} icon="↗" accent="green" />
          <StatCard label="Offline" value={counts.offline} icon="↘" accent="red" />
          <StatCard label="Unmonitored" value={counts.unknown} icon="◷" accent="amber" />
        </section>

        {error && (
          <div className="error-banner" role="alert">
            <span>{error}</span>
            <button className="text-button" onClick={() => setError("")}>Dismiss</button>
          </div>
        )}

        <section className="workspace">
          <div className="inventory-card">
            <div className="inventory-heading">
              <div>
                <div className="section-heading">
                  <h2>Device inventory</h2>
                  <span className="count-pill">{filteredDevices.length}</span>
                </div>
                <p className="muted">Devices discovered or added to this network.</p>
              </div>
            </div>
            <div className="table-toolbar">
              <label className="search-box">
                <span aria-hidden="true">⌕</span>
                <input
                  aria-label="Search devices"
                  value={search}
                  onChange={(event) => setSearch(event.target.value)}
                  placeholder="Search name, IP, vendor..."
                />
              </label>
              <select
                aria-label="Filter by status"
                value={statusFilter}
                onChange={(event) => setStatusFilter(event.target.value)}
              >
                <option value="all">All statuses</option>
                <option value="online">Online</option>
                <option value="offline">Offline</option>
                <option value="unknown">Unmonitored</option>
                <option value="discovered">Discovered</option>
              </select>
            </div>
            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th>Device</th>
                    <th>IP address</th>
                    <th>Type</th>
                    <th>Status</th>
                    <th>Last seen</th>
                  </tr>
                </thead>
                <tbody>
                  {loading ? (
                    <tr><td className="table-message" colSpan="5">Loading inventory...</td></tr>
                  ) : filteredDevices.length ? (
                    filteredDevices.map((device) => (
                      <tr
                        aria-selected={selectedId === device.id}
                        className={selectedId === device.id ? "selected-row" : ""}
                        key={device.id}
                        tabIndex={0}
                        onClick={() => setSelectedId(device.id)}
                        onKeyDown={(event) => {
                          if (event.key === "Enter" || event.key === " ") {
                            event.preventDefault();
                            setSelectedId(device.id);
                          }
                        }}
                      >
                        <td>
                          <div className="table-device">
                            <span className="device-avatar-small">
                              {(device.hostname || device.device_type || "D")[0].toUpperCase()}
                            </span>
                            <strong>{device.hostname || "Unnamed device"}</strong>
                          </div>
                        </td>
                        <td><code>{device.ip_address}</code></td>
                        <td>{device.device_type || "Unknown"}</td>
                        <td><StatusBadge status={device.status} /></td>
                        <td className="date-cell">{formatDate(device.last_seen)}</td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td className="table-message" colSpan="5">
                        {devices.length
                          ? "No devices match those filters."
                          : "No devices yet. Add one or run network discovery to get started."}
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
            <div className="inventory-footer">
              <span>Showing {filteredDevices.length} of {devices.length} devices</span>
              <span>Data is stored in your local PostgreSQL database</span>
            </div>
          </div>
          <DeviceDetails
            device={selectedDevice}
            interfaces={interfaces}
            metrics={metrics}
            isLoading={detailLoading}
            onClose={() => setSelectedId(null)}
          />
        </section>
      </main>

      {showAddDialog && (
        <AddDeviceDialog
          token={token}
          onClose={() => setShowAddDialog(false)}
          onCreated={loadDevices}
        />
      )}
    </div>
  );
}

function StatCard({ label, value, icon, accent }) {
  return (
    <article className="stat-card">
      <span className={`stat-icon icon-${accent}`}>{icon}</span>
      <div className="stat-copy">
        <span>{label}</span>
        <strong>{value}</strong>
      </div>
      <span className={`stat-accent accent-${accent}`} />
    </article>
  );
}

export default function App() {
  const [token, setToken] = useState(
    () => window.sessionStorage.getItem(TOKEN_STORAGE_KEY) || "",
  );
  const [connectionError, setConnectionError] = useState("");

  const disconnect = useCallback(() => {
    window.sessionStorage.removeItem(TOKEN_STORAGE_KEY);
    setToken("");
    setConnectionError("Your API token was rejected. Enter the current token to reconnect.");
  }, []);

  function connect(value) {
    window.sessionStorage.setItem(TOKEN_STORAGE_KEY, value);
    setConnectionError("");
    setToken(value);
  }

  if (!token) return <TokenGate onConnect={connect} error={connectionError} />;
  return <Dashboard token={token} onDisconnect={disconnect} />;
}
