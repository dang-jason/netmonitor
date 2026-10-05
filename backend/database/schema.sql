CREATE TABLE IF NOT EXISTS locations (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    site VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS devices (
    id SERIAL PRIMARY KEY,
    ip_address INET NOT NULL UNIQUE,
    hostname VARCHAR(255),
    mac_address MACADDR,
    vendor VARCHAR(255),
    device_type VARCHAR(80),
    status VARCHAR(30) NOT NULL DEFAULT 'unknown',
    discovered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    location_id INT REFERENCES locations(id) ON DELETE SET NULL,
    open_ports INTEGER[] NOT NULL DEFAULT ARRAY[]::INTEGER[],
    notes TEXT
);

CREATE TABLE IF NOT EXISTS interfaces (
    id SERIAL PRIMARY KEY,
    device_id INT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    interface_index INTEGER,
    name VARCHAR(255) NOT NULL,
    description VARCHAR(255),
    admin_status VARCHAR(30) NOT NULL DEFAULT 'unknown',
    oper_status VARCHAR(30) NOT NULL DEFAULT 'unknown',
    speed_mbps INT,
    in_octets BIGINT,
    out_octets BIGINT,
    sampled_at TIMESTAMPTZ,
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS device_metrics (
    id BIGSERIAL PRIMARY KEY,
    device_id INT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    interface_id INT REFERENCES interfaces(id) ON DELETE CASCADE,
    metric_name VARCHAR(80) NOT NULL,
    metric_value DOUBLE PRECISION,
    unit VARCHAR(30),
    collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    details TEXT
);

ALTER TABLE interfaces ADD COLUMN IF NOT EXISTS interface_index INTEGER;
ALTER TABLE interfaces ADD COLUMN IF NOT EXISTS in_octets BIGINT;
ALTER TABLE interfaces ADD COLUMN IF NOT EXISTS out_octets BIGINT;
ALTER TABLE interfaces ADD COLUMN IF NOT EXISTS sampled_at TIMESTAMPTZ;
ALTER TABLE interfaces DROP CONSTRAINT IF EXISTS interfaces_device_id_name_key;
ALTER TABLE device_metrics
    ADD COLUMN IF NOT EXISTS interface_id INT REFERENCES interfaces(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_devices_location_id ON devices(location_id);
CREATE INDEX IF NOT EXISTS idx_devices_vendor ON devices(vendor);
CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status);
CREATE INDEX IF NOT EXISTS idx_interfaces_device_id ON interfaces(device_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_interfaces_device_index
    ON interfaces(device_id, interface_index);
CREATE INDEX IF NOT EXISTS idx_device_metrics_device_time
    ON device_metrics(device_id, collected_at DESC);
CREATE INDEX IF NOT EXISTS idx_device_metrics_interface_time
    ON device_metrics(interface_id, collected_at DESC)
    WHERE interface_id IS NOT NULL;
