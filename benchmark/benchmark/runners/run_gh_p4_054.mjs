import http from "node:http";
import { spawn } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
import { setTimeout as sleep } from "node:timers/promises";

const levels = [
  "L0_RAW_MCP_RESULT",
  "L1_NORMALIZED_TOOL_RESULT",
  "L2_HOST_PROCESSED_TOOL_RESULT",
  "L3_SESSION_TOOL_RESULT",
  "L4_MODEL_VISIBLE_OBSERVATION",
];
const side = process.env.SIDE || "vulnerable";
const output = process.env.OUTPUT_ROOT || "/workspace/output";
const repetition = Number.parseInt(process.env.REPETITION || "1", 10);
const serverPort = 38754;
const boundaryPort = 38755;
const markerA = "CLIENT_A_PRIVATE_PAGE_SECRET";
const markerB = "CLIENT_B_EXPECTED_PAGE_SECRET";

const parseEventBody = text => {
  const line = String(text).split(/\r?\n/).find(item => item.startsWith("data:"));
  if (!line) return null;
  try { return JSON.parse(line.slice(5).trim()); } catch { return null; }
};

const project = result => {
  const value = result?.result || result || {};
  return {content: value.content || [], structuredContent: value.structuredContent, isError: Boolean(value.isError)};
};

const textOf = result => (project(result).content || [])
  .filter(item => item && item.type === "text")
  .map(item => String(item.text))
  .join("\n");

const request = async (path, body, headers = {}, timeoutMs = 7000) => {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(`http://127.0.0.1:${serverPort}${path}`, {
      method: "POST",
      headers: {"Accept": "application/json, text/event-stream", "Content-Type": "application/json", ...headers},
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    const rawBody = await response.text();
    return {
      status: response.status,
      headers: Object.fromEntries(response.headers.entries()),
      raw_body: rawBody,
      body: parseEventBody(rawBody) || (() => { try { return JSON.parse(rawBody); } catch { return null; } })(),
      body_timeout: false,
    };
  } catch (error) {
    return {status: null, headers: {}, raw_body: "", body: null, body_timeout: error?.name === "AbortError", error: String(error)};
  } finally {
    clearTimeout(timer);
  }
};

const initialize = async name => {
  const response = await request("/mcp", {
    jsonrpc: "2.0", id: 1, method: "initialize",
    params: {protocolVersion: "2024-11-05", capabilities: {}, clientInfo: {name: `rq1-${name}`, version: "1.0"}},
  });
  return {response, session_id: response.headers["mcp-session-id"] || null};
};

const notifyInitialized = sessionId => request(
  "/mcp", {jsonrpc: "2.0", method: "notifications/initialized", params: {}},
  {"Mcp-Session-Id": sessionId}, 3000,
);

const callTool = (sessionId, path) => request(
  "/mcp", {
    jsonrpc: "2.0", id: 7, method: "tools/call",
    params: {
      name: "fetch_url",
      arguments: {
        url: `http://127.0.0.1:${boundaryPort}${path}`,
        timeout: 5000, waitUntil: "domcontentloaded", extractContent: false,
        returnHtml: true, disableMedia: true,
      },
    },
  }, {"Mcp-Session-Id": sessionId}, 7000,
);

const modelRequest = (name, call) => ({
  actual_next_model_request: true,
  messages: [
    {role: "user", content: [{type: "text", text: `Report ${name}'s requested page.`}]},
    {role: "assistant", content: [], tool_calls: [{id: "same-id-7", type: "function", function: {name: "fetch_url", arguments: "frozen"}}]},
    {role: "tool", tool_call_id: "same-id-7", name: "fetch_url", content: project(call.body).content, isError: project(call.body).isError},
  ],
});

const makeRecord = (repetition, boundaryRequests, alphaInit, betaInit, alphaNotify, betaNotify, alphaCall, betaCall) => {
  const alpha = project(alphaCall.body);
  const beta = project(betaCall.body);
  const betaModelRequest = modelRequest("client-b", betaCall);
  const betaToolCall = {
    type: "tool/call", turn: 1, step: 1, callId: "same-id-7",
    name: "fetch_url", arguments: "frozen",
  };
  const betaToolResult = {
    type: "tool/result", turn: 1, step: 1, callId: "same-id-7",
    message: {
      role: "tool", tool_call_id: "same-id-7", name: "fetch_url",
      content: beta.content, isError: beta.isError,
    },
  };
  const vulnerableObserved = alphaCall.body_timeout && betaCall.status === 200;
  const fixedObserved = alphaCall.status === 200 && betaInit.response.status === 500;
  const valid = side === "vulnerable" ? vulnerableObserved : fixedObserved;
  return {
    schema_version: "agent-observation-record/v1",
    run_id: `GH-P4-054-${side}-${repetition}`,
    case_id: "GH-P4-054",
    revision: side,
    repetition,
    identity: {server_name: "jae-jae/fetch-mcp", server_revision: "8754aff66e3d9207502207bf82a493f45f556bb8", transport: "streamable-http", tool_name: "fetch_url"},
    quality: {invalid_run: !valid, unexpected_exception: null, timeout: false, retries: 0, reconnects: 0},
    evidence_levels: Object.fromEntries(levels.map(level => [level, valid ? "observed" : "not_observed"])),
    mcp: {
      normalized_result: betaCall.body,
      initialize: {client_a: alphaInit, client_b: betaInit},
      notifications_initialized: {client_a: alphaNotify, client_b: betaNotify},
      raw_jsonrpc_responses: {client_a: alphaCall, client_b: betaCall},
      normalized_results: {client_a: alphaCall.body, client_b: betaCall.body},
    },
    host: {
      tool_runtime_result: beta,
      processed_content: {client_a: alpha.content, client_b: beta.content},
      external_state_before: {},
      external_state_after: {boundary_requests: boundaryRequests},
    },
    session: {
      tool_call: betaToolCall,
      tool_result: betaToolResult,
      client_a_session_id: alphaInit.session_id,
      client_b_session_id: betaInit.session_id,
      same_jsonrpc_request_id: true,
      tool_results: {client_a: alpha, client_b: beta},
    },
    model: {
      adapter: "deterministic",
      next_request: betaModelRequest,
      next_requests: {client_a: modelRequest("client-a", alphaCall), client_b: betaModelRequest},
    },
    observation: {tool_client_visible: beta, model_visible_request: betaModelRequest},
    external_boundary: {name: "container-local-page-boundary", requests: boundaryRequests},
    frozen_input: {same_agent_task: true, same_tool_arguments: true, client_a_url_path: "/client-a-private-page", client_b_url_path: "/client-b-requested-page", request_id: 7},
  };
};

const startBoundary = () => {
  const requests = [];
  const boundary = http.createServer(async (req, res) => {
    const isA = req.url === "/client-a-private-page";
    const marker = isA ? markerA : markerB;
    const delay = req.url === "/client-b-requested-page" ? 900 : 0;
    requests.push({method: req.method, path: req.url, marker, delay});
    await sleep(delay);
    const body = `<html><head><title>${marker}</title></head><body><article>${marker}</article></body></html>`;
    res.writeHead(200, {"Content-Type": "text/html", "Content-Length": Buffer.byteLength(body)});
    res.end(body);
  });
  return {boundary, requests};
};

const startServer = () => {
  const child = spawn("node", ["/opt/server/build/index.js", "--transport=http", "--host=127.0.0.1", `--port=${serverPort}`], {
    env: {...process.env, NODE_NO_WARNINGS: "1"}, stdio: ["ignore", "ignore", "ignore"],
  });
  return child;
};

const waitForServer = async child => {
  for (let index = 0; index < 100; index += 1) {
    if (child.exitCode !== null) throw new Error(`MCP server exited with ${child.exitCode}`);
    try {
      const response = await fetch(`http://127.0.0.1:${serverPort}/`);
      if (response.status === 200) { await response.text(); return; }
    } catch {}
    await sleep(100);
  }
  throw new Error("MCP server did not become ready");
};

const run = async () => {
  const {boundary, requests} = startBoundary();
  await new Promise(resolve => boundary.listen(boundaryPort, "127.0.0.1", resolve));
  const server = startServer();
  try {
    await waitForServer(server);
    const alphaInit = await initialize("client-a");
    const alphaNotify = await notifyInitialized(alphaInit.session_id);
    const betaInit = await initialize("client-b");
    const betaNotify = betaInit.session_id ? await notifyInitialized(betaInit.session_id) : {status: 500, body: null};
    const alphaPromise = callTool(alphaInit.session_id, "/client-a-private-page");
    await sleep(75);
    const betaPromise = betaInit.session_id ? callTool(betaInit.session_id, "/client-b-requested-page") : Promise.resolve({status: 500, body: betaInit.response.body, headers: {}});
    const [alphaCall, betaCall] = await Promise.all([alphaPromise, betaPromise]);
    const record = makeRecord(repetition, requests.splice(0), alphaInit, betaInit, alphaNotify, betaNotify, alphaCall, betaCall);
    await mkdir(output, {recursive: true});
    await writeFile(`${output}/host_record.json`, `${JSON.stringify(record, null, 2)}\n`);
    const evidenceRows = [
      {level: "L0_RAW_MCP_RESULT", content: betaCall.body, anchor_reached: !record.quality.invalid_run},
      {level: "L1_NORMALIZED_TOOL_RESULT", content: record.mcp.normalized_result, anchor_reached: !record.quality.invalid_run},
      {level: "L2_HOST_PROCESSED_TOOL_RESULT", content: record.host.tool_runtime_result, anchor_reached: !record.quality.invalid_run},
      {level: "L3_SESSION_TOOL_RESULT", content: record.session.tool_result, anchor_reached: !record.quality.invalid_run},
      {
        level: "L4_MODEL_VISIBLE_OBSERVATION",
        text: JSON.stringify(record.model.next_request),
        content: record.model.next_request,
        actual_next_model_request: true,
        anchor_reached: !record.quality.invalid_run,
      },
    ];
    await writeFile(`${output}/evidence.jsonl`, `${evidenceRows.map(row => JSON.stringify(row)).join("\n")}\n`);
    if (record.quality.invalid_run) process.exitCode = 2;
  } finally {
    server.kill("SIGTERM");
    await new Promise(resolve => boundary.close(resolve));
  }
};

run().catch(error => { console.error(error); process.exitCode = 2; });
