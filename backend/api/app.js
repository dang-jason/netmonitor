const express = require("express");
const net = require("node:net");
const { timingSafeEqual } = require("node:crypto");

const DEVICE_COLUMNS = {
  hostname: "hostname",
  mac_address: "mac_address",
  vendor: "vendor",
  device_type: "device_type",
  location_id: "location_id",
  open_ports: "open_ports",
  notes: "notes",
};

function isPositiveInteger(value) {
  return Number.isInteger(value) && value > 0;
}

function isValidMacAddress(value) {
  return (
    typeof value === "string" &&
    /^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(value)
  );
}

function validateDeviceInput(body, { requireIp = false } = {}) {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return "Request body must be a JSON object.";
  }

  const allowedFields = new Set(["ip_address", ...Object.keys(DEVICE_COLUMNS)]);
  const unsupportedFields = Object.keys(body).filter(
    (field) => !allowedFields.has(field),
  );
  if (unsupportedFields.length > 0) {
    return `Unsupported device field(s): ${unsupportedFields.join(", ")}.`;
  }

  if (requireIp || Object.hasOwn(body, "ip_address")) {
    if (typeof body.ip_address !== "string" || net.isIP(body.ip_address) === 0) {
      return "ip_address must be a valid IPv4 or IPv6 address.";
    }
  }

  for (const field of ["hostname", "vendor", "device_type", "notes"]) {
    if (
      Object.hasOwn(body, field) &&
      body[field] !== null &&
      typeof body[field] !== "string"
    ) {
      return `${field} must be a string or null.`;
    }
  }

  if (
    Object.hasOwn(body, "mac_address") &&
    body.mac_address !== null &&
    !isValidMacAddress(body.mac_address)
  ) {
    return "mac_address must use the format 00:11:22:33:44:55 or be null.";
  }

  if (
    Object.hasOwn(body, "location_id") &&
    body.location_id !== null &&
    !isPositiveInteger(body.location_id)
  ) {
    return "location_id must be a positive integer or null.";
  }

  if (
    Object.hasOwn(body, "open_ports") &&
    (!Array.isArray(body.open_ports) ||
      body.open_ports.some(
        (port) => !Number.isInteger(port) || port < 1 || port > 65535,
      ))
  ) {
    return "open_ports must be an array of port numbers from 1 to 65535.";
  }

  return null;
}

function createApp({ pool, apiToken }) {
  if (!pool || typeof pool.query !== "function") {
    throw new TypeError("createApp requires a PostgreSQL pool.");
  }
  if (typeof apiToken !== "string" || apiToken.length < 32) {
    throw new Error("API_TOKEN must be configured with at least 32 characters.");
  }

  const app = express();
  app.disable("x-powered-by");
  app.use(express.json({ limit: "32kb" }));

  app.get("/healthz", async (_request, response) => {
    try {
      await pool.query("SELECT 1");
      response.json({ status: "ok", database: "connected" });
    } catch (error) {
      console.error("Health check database connection failed:", error.message);
      response.status(503).json({
        error: "Database is unavailable.",
        code: "DATABASE_UNAVAILABLE",
      });
    }
  });

  app.use("/api", (request, response, next) => {
    const authorization = request.get("authorization") || "";
    const match = /^Bearer (.+)$/i.exec(authorization);
    if (!match) {
      return response.status(401).json({
        error: "A bearer API token is required.",
        code: "UNAUTHORIZED",
      });
    }

    const supplied = Buffer.from(match[1]);
    const expected = Buffer.from(apiToken);
    if (
      supplied.length !== expected.length ||
      !timingSafeEqual(supplied, expected)
    ) {
      return response.status(401).json({
        error: "The API token is invalid.",
        code: "UNAUTHORIZED",
      });
    }

    return next();
  });

  app.get("/api/devices", async (request, response, next) => {
    const limit = request.query.limit === undefined ? 100 : Number(request.query.limit);
    const offset = request.query.offset === undefined ? 0 : Number(request.query.offset);
    if (!Number.isInteger(limit) || limit < 1 || limit > 500) {
      return response.status(400).json({
        error: "limit must be an integer between 1 and 500.",
        code: "INVALID_QUERY",
      });
    }
    if (!Number.isInteger(offset) || offset < 0) {
      return response.status(400).json({
        error: "offset must be a non-negative integer.",
        code: "INVALID_QUERY",
      });
    }

    try {
      const result = await pool.query(
        `
          SELECT id, host(ip_address) AS ip_address, hostname, mac_address,
                 vendor, device_type, status, discovered_at, last_seen,
                 location_id, open_ports, notes
          FROM devices
          ORDER BY id
          LIMIT $1 OFFSET $2
        `,
        [limit, offset],
      );
      return response.json({
        data: result.rows,
        pagination: { limit, offset, count: result.rowCount },
      });
    } catch (error) {
      return next(error);
    }
  });

  app.post("/api/devices", async (request, response, next) => {
    const validationError = validateDeviceInput(request.body, { requireIp: true });
    if (validationError) {
      return response.status(400).json({
        error: validationError,
        code: "INVALID_DEVICE",
      });
    }

    const body = request.body;
    try {
      const result = await pool.query(
        `
          INSERT INTO devices (
            ip_address, hostname, mac_address, vendor, device_type,
            location_id, open_ports, notes
          )
          VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
          RETURNING id, host(ip_address) AS ip_address, hostname, mac_address,
                    vendor, device_type, status, discovered_at, last_seen,
                    location_id, open_ports, notes
        `,
        [
          body.ip_address,
          body.hostname ?? "Unknown",
          body.mac_address ?? null,
          body.vendor ?? "Unknown",
          body.device_type ?? "Unknown Device",
          body.location_id ?? null,
          body.open_ports ?? [],
          body.notes ?? null,
        ],
      );
      return response.status(201).json({ data: result.rows[0] });
    } catch (error) {
      if (error.code === "23505") {
        return response.status(409).json({
          error: "A device with that IP address already exists.",
          code: "DEVICE_ALREADY_EXISTS",
        });
      }
      if (error.code === "23503") {
        return response.status(400).json({
          error: "location_id does not refer to an existing location.",
          code: "INVALID_LOCATION",
        });
      }
      return next(error);
    }
  });

  app.get("/api/devices/:id", async (request, response, next) => {
    const deviceId = Number(request.params.id);
    if (!isPositiveInteger(deviceId)) {
      return response.status(400).json({
        error: "Device id must be a positive integer.",
        code: "INVALID_ID",
      });
    }

    try {
      const result = await pool.query(
        `
          SELECT id, host(ip_address) AS ip_address, hostname, mac_address,
                 vendor, device_type, status, discovered_at, last_seen,
                 location_id, open_ports, notes
          FROM devices
          WHERE id = $1
        `,
        [deviceId],
      );
      if (result.rowCount === 0) {
        return response.status(404).json({
          error: "Device not found.",
          code: "DEVICE_NOT_FOUND",
        });
      }
      return response.json({ data: result.rows[0] });
    } catch (error) {
      return next(error);
    }
  });

  app.put("/api/devices/:id", async (request, response, next) => {
    const deviceId = Number(request.params.id);
    if (!isPositiveInteger(deviceId)) {
      return response.status(400).json({
        error: "Device id must be a positive integer.",
        code: "INVALID_ID",
      });
    }

    const validationError = validateDeviceInput(request.body);
    if (validationError) {
      return response.status(400).json({
        error: validationError,
        code: "INVALID_DEVICE",
      });
    }
    if (Object.keys(request.body).length === 0) {
      return response.status(400).json({
        error: "Provide at least one device field to update.",
        code: "EMPTY_UPDATE",
      });
    }

    const fields = Object.keys(request.body);
    const assignments = fields.map(
      (field, index) => `${field === "ip_address" ? "ip_address" : DEVICE_COLUMNS[field]} = $${index + 1}`,
    );
    const values = fields.map((field) => request.body[field]);
    values.push(deviceId);

    try {
      const result = await pool.query(
        `
          UPDATE devices
          SET ${assignments.join(", ")}
          WHERE id = $${values.length}
          RETURNING id, host(ip_address) AS ip_address, hostname, mac_address,
                    vendor, device_type, status, discovered_at, last_seen,
                    location_id, open_ports, notes
        `,
        values,
      );
      if (result.rowCount === 0) {
        return response.status(404).json({
          error: "Device not found.",
          code: "DEVICE_NOT_FOUND",
        });
      }
      return response.json({ data: result.rows[0] });
    } catch (error) {
      if (error.code === "23505") {
        return response.status(409).json({
          error: "A device with that IP address already exists.",
          code: "DEVICE_ALREADY_EXISTS",
        });
      }
      if (error.code === "23503") {
        return response.status(400).json({
          error: "location_id does not refer to an existing location.",
          code: "INVALID_LOCATION",
        });
      }
      return next(error);
    }
  });

  app.delete("/api/devices/:id", async (request, response, next) => {
    const deviceId = Number(request.params.id);
    if (!isPositiveInteger(deviceId)) {
      return response.status(400).json({
        error: "Device id must be a positive integer.",
        code: "INVALID_ID",
      });
    }

    try {
      const result = await pool.query(
        "DELETE FROM devices WHERE id = $1 RETURNING id",
        [deviceId],
      );
      if (result.rowCount === 0) {
        return response.status(404).json({
          error: "Device not found.",
          code: "DEVICE_NOT_FOUND",
        });
      }
      return response.status(204).end();
    } catch (error) {
      return next(error);
    }
  });

  app.get("/api/devices/:id/metrics", async (request, response, next) => {
    const deviceId = Number(request.params.id);
    if (!isPositiveInteger(deviceId)) {
      return response.status(400).json({
        error: "Device id must be a positive integer.",
        code: "INVALID_ID",
      });
    }

    const limit = request.query.limit === undefined ? 100 : Number(request.query.limit);
    if (!Number.isInteger(limit) || limit < 1 || limit > 1000) {
      return response.status(400).json({
        error: "limit must be an integer between 1 and 1000.",
        code: "INVALID_QUERY",
      });
    }

    try {
      const result = await pool.query(
        `
          SELECT id, device_id, interface_id, metric_name, metric_value, unit,
                 collected_at, details
          FROM device_metrics
          WHERE device_id = $1
          ORDER BY collected_at DESC
          LIMIT $2
        `,
        [deviceId, limit],
      );
      return response.json({ data: result.rows });
    } catch (error) {
      return next(error);
    }
  });

  app.get("/api/devices/:id/interfaces", async (request, response, next) => {
    const deviceId = Number(request.params.id);
    if (!isPositiveInteger(deviceId)) {
      return response.status(400).json({
        error: "Device id must be a positive integer.",
        code: "INVALID_ID",
      });
    }

    try {
      const result = await pool.query(
        `
          SELECT d.id AS device_id, i.id, i.interface_index, i.name,
                 i.description, i.admin_status, i.oper_status, i.speed_mbps,
                 i.in_octets, i.out_octets, i.sampled_at, i.last_seen
          FROM devices AS d
          LEFT JOIN interfaces AS i ON i.device_id = d.id
          WHERE d.id = $1
          ORDER BY i.interface_index
        `,
        [deviceId],
      );
      if (result.rowCount === 0) {
        return response.status(404).json({
          error: "Device not found.",
          code: "DEVICE_NOT_FOUND",
        });
      }
      return response.json({
        data: result.rows.filter((row) => row.id !== null),
      });
    } catch (error) {
      return next(error);
    }
  });

  app.use((error, _request, response, _next) => {
    if (error.type === "entity.parse.failed") {
      return response.status(400).json({
        error: "Request body contains invalid JSON.",
        code: "INVALID_JSON",
      });
    }
    if (error.type === "entity.too.large") {
      return response.status(413).json({
        error: "Request body exceeds the 32 KB limit.",
        code: "REQUEST_TOO_LARGE",
      });
    }

    console.error("API request failed:", error);
    return response.status(500).json({
      error: "An unexpected server error occurred.",
      code: "INTERNAL_SERVER_ERROR",
    });
  });

  return app;
}

module.exports = { createApp };
