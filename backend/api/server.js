const path = require("node:path");
const dotenv = require("dotenv");
const { Pool } = require("pg");
const { createApp } = require("./app");

dotenv.config({ path: path.resolve(__dirname, "../../.env") });

const apiToken = process.env.API_TOKEN;
if (!apiToken || apiToken.length < 32) {
  throw new Error(
    "Set API_TOKEN to a secret of at least 32 characters in the repository-root .env file.",
  );
}

const pool = new Pool({
  host: process.env.DB_HOST || "localhost",
  port: Number(process.env.DB_PORT || 5432),
  database: process.env.DB_NAME || "netmonitor",
  user: process.env.DB_USER || "postgres",
  password: process.env.DB_PASSWORD || "",
});

pool.on("error", (error) => {
  console.error("Unexpected PostgreSQL pool error:", error);
});

const app = createApp({ pool, apiToken });
const port = Number(process.env.API_PORT || 3000);
const host = process.env.API_HOST || "127.0.0.1";

const server = app.listen(port, host, () => {
  console.log(`NetMonitor API listening at http://${host}:${port}`);
});

async function shutdown(signal) {
  console.log(`${signal} received; closing the API server.`);
  server.close(async (serverError) => {
    try {
      await pool.end();
    } catch (poolError) {
      console.error("Failed to close PostgreSQL pool:", poolError);
      process.exitCode = 1;
    }

    if (serverError) {
      console.error("Failed to close API server:", serverError);
      process.exitCode = 1;
    }
  });
}

process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));
