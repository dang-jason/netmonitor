const assert = require("node:assert/strict");
const { after, before, describe, it } = require("node:test");
const { createApp } = require("./app");

const API_TOKEN = "test-token-with-more-than-thirty-two-characters";

function createPool(queryImplementation = async () => ({ rows: [], rowCount: 0 })) {
  return {
    query: queryImplementation,
  };
}

describe("NetMonitor API", () => {
  let server;
  let baseUrl;
  let pool;

  before(async () => {
    pool = createPool();
    server = createApp({ pool, apiToken: API_TOKEN }).listen(0, "127.0.0.1");
    await new Promise((resolve) => server.once("listening", resolve));
    baseUrl = `http://127.0.0.1:${server.address().port}`;
  });

  after(async () => {
    await new Promise((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
  });

  it("reports API and database health", async () => {
    const response = await fetch(`${baseUrl}/healthz`);

    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), {
      status: "ok",
      database: "connected",
    });
  });

  it("requires a bearer token for API routes", async () => {
    const response = await fetch(`${baseUrl}/api/devices`);

    assert.equal(response.status, 401);
    assert.equal((await response.json()).code, "UNAUTHORIZED");
  });

  it("validates device input before making a database call", async () => {
    let queryCalled = false;
    pool = createPool(async () => {
      queryCalled = true;
      return { rows: [], rowCount: 0 };
    });
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
    server = createApp({ pool, apiToken: API_TOKEN }).listen(0, "127.0.0.1");
    await new Promise((resolve) => server.once("listening", resolve));
    baseUrl = `http://127.0.0.1:${server.address().port}`;

    const response = await fetch(`${baseUrl}/api/devices`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${API_TOKEN}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ ip_address: "not-an-ip" }),
    });

    assert.equal(response.status, 400);
    assert.equal((await response.json()).code, "INVALID_DEVICE");
    assert.equal(queryCalled, false);
  });

  it("creates devices using parameterized SQL", async () => {
    let queryCall;
    pool = createPool(async (...args) => {
      queryCall = args;
      return {
        rows: [{ id: 9, ip_address: "192.0.2.15", hostname: "lab-switch" }],
        rowCount: 1,
      };
    });
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
    server = createApp({ pool, apiToken: API_TOKEN }).listen(0, "127.0.0.1");
    await new Promise((resolve) => server.once("listening", resolve));
    baseUrl = `http://127.0.0.1:${server.address().port}`;

    const response = await fetch(`${baseUrl}/api/devices`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${API_TOKEN}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        ip_address: "192.0.2.15",
        hostname: "lab-switch",
      }),
    });

    assert.equal(response.status, 201);
    assert.deepEqual(queryCall[1], [
      "192.0.2.15",
      "lab-switch",
      null,
      "Unknown",
      "Unknown Device",
      null,
      [],
      null,
    ]);
    assert.equal((await response.json()).data.id, 9);
  });

  it("uses parameterized SQL for device-list pagination", async () => {
    let queryCall;
    pool = createPool(async (...args) => {
      queryCall = args;
      return {
        rows: [{ id: 1, ip_address: "192.0.2.10" }],
        rowCount: 1,
      };
    });
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
    server = createApp({ pool, apiToken: API_TOKEN }).listen(0, "127.0.0.1");
    await new Promise((resolve) => server.once("listening", resolve));
    baseUrl = `http://127.0.0.1:${server.address().port}`;

    const response = await fetch(`${baseUrl}/api/devices?limit=20&offset=5`, {
      headers: { authorization: `Bearer ${API_TOKEN}` },
    });

    assert.equal(response.status, 200);
    assert.deepEqual(queryCall[1], [20, 5]);
    assert.deepEqual((await response.json()).pagination, {
      limit: 20,
      offset: 5,
      count: 1,
    });
  });

  it("returns recent device metrics", async () => {
    let queryCall;
    pool = createPool(async (...args) => {
      queryCall = args;
      return {
        rows: [{ metric_name: "availability", metric_value: 1 }],
        rowCount: 1,
      };
    });
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
    server = createApp({ pool, apiToken: API_TOKEN }).listen(0, "127.0.0.1");
    await new Promise((resolve) => server.once("listening", resolve));
    baseUrl = `http://127.0.0.1:${server.address().port}`;

    const response = await fetch(
      `${baseUrl}/api/devices/9/metrics?limit=25`,
      { headers: { authorization: `Bearer ${API_TOKEN}` } },
    );

    assert.equal(response.status, 200);
    assert.deepEqual(queryCall[1], [9, 25]);
    assert.equal((await response.json()).data[0].metric_name, "availability");
  });

  it("rejects malformed JSON with a client error", async () => {
    const response = await fetch(`${baseUrl}/api/devices`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${API_TOKEN}`,
        "content-type": "application/json",
      },
      body: "{invalid",
    });

    assert.equal(response.status, 400);
    assert.equal((await response.json()).code, "INVALID_JSON");
  });
});
