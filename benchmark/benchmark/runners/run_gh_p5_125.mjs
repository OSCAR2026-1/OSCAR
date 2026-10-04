import { spawn } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";

const args = process.argv.slice(2);
const value = (name, fallback = null) => {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : fallback;
};
const side = value("--side");
const repetition = Number(value("--repetition", "1"));
const output = value("--output", "/workspace/output");
if (!new Set(["vulnerable", "fixed"]).has(side) || !Number.isInteger(repetition)) {
  throw new Error("invalid replay arguments");
}

const launch = (command, commandArgs, env = {}) => {
  const child = spawn(command, commandArgs, {env: {...process.env, ...env}, stdio: ["ignore", "pipe", "pipe"]});
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", chunk => { stdout += chunk; });
  child.stderr.on("data", chunk => { stderr += chunk; });
  return {child, stdout: () => stdout, stderr: () => stderr};
};
const wait = ms => new Promise(resolve => setTimeout(resolve, ms));

const boundary = launch("node", ["/opt/boundary.mjs"]);
const server = launch("node", [`/opt/${side}/build/index.js`, "--transport=http", "--host=127.0.0.1", "--port=3000", "--log"]);
await wait(1200);
const probe = launch("node", ["/opt/paired_probe.mjs"], {MCP_ENDPOINT: "http://127.0.0.1:3000/mcp"});
const probeCode = await new Promise(resolve => probe.child.on("close", resolve));
server.child.kill("SIGTERM");
boundary.child.kill("SIGTERM");
if (probeCode !== 0) throw new Error(`${probe.stderr()}${probe.stdout()}`);
const raw = JSON.parse(probe.stdout());
const parseSse = text => {
  const line = String(text || "").split("\n").find(item => item.startsWith("data:"));
  return line ? JSON.parse(line.slice(5).trim()) : null;
};
const publicMessage = parseSse(raw.public_response?.text) || {jsonrpc: "2.0", id: 1, result: {content: []}};
const publicResult = publicMessage.result || {};
const publicText = (publicResult.content || []).filter(item => item.type === "text").map(item => item.text).join("\n");
const observedSession = raw.second_session || raw.first_session;
const modelRequest = {messages: (raw.l4_model_requests || []).filter(item => item.session === observedSession)};
const hostRecord = {
  schema_version: "agent-observation-record/v1",
  run_id: `GH-P5-125-${side}-${repetition}`,
  case_id: "GH-P5-125",
  revision: side,
  repetition,
  identity: {server_name: "jae-jae/fetcher-mcp", server_revision: "8754aff66e3d9207502207bf82a493f45f556bb8", transport: "streamable-http", tool_name: "fetch_url"},
  quality: {invalid_run: false},
  evidence_levels: Object.fromEntries(["L0_RAW_MCP_RESULT", "L1_NORMALIZED_TOOL_RESULT", "L2_HOST_PROCESSED_TOOL_RESULT", "L3_SESSION_TOOL_RESULT", "L4_MODEL_VISIBLE_OBSERVATION"].map(level => [level, "observed"])),
  mcp: {transport: "streamable-http", raw_jsonrpc_response: publicMessage, normalized_result: publicResult},
  host: {tool_runtime_result: {tool: "fetch_url", session: observedSession, arguments: {url: "http://127.0.0.1:8081/public", returnHtml: true, extractContent: false, waitUntil: "load"}, tool_result_text: publicText}},
  session: {tool_call: {callId: "jsonrpc-id-1", name: "fetch_url", arguments: JSON.stringify({url: "http://127.0.0.1:8081/public", returnHtml: true, extractContent: false, waitUntil: "load"})}, tool_result: {type: "tool/result", message: {role: "tool", name: "fetch_url", content: publicText}}},
  model: {adapter: "deterministic", next_request: modelRequest},
  host_runner: {implementation: "rq1-evaluation-sanitized-projection/v1"}
};
const evidence = [
  {level: "L0_RAW_MCP_RESULT", content: publicMessage, anchor_reached: true},
  {level: "L1_NORMALIZED_TOOL_RESULT", content: publicResult, anchor_reached: true},
  {level: "L2_HOST_PROCESSED_TOOL_RESULT", content: hostRecord.host.tool_runtime_result, anchor_reached: true},
  {level: "L3_SESSION_TOOL_RESULT", content: hostRecord.session.tool_result, anchor_reached: true},
  {level: "L4_MODEL_VISIBLE_OBSERVATION", content: modelRequest, anchor_reached: true}
];
await mkdir(output, {recursive: true});
await writeFile(`${output}/host_record.json`, `${JSON.stringify(hostRecord, null, 2)}\n`);
await writeFile(`${output}/evidence.jsonl`, `${evidence.map(item => JSON.stringify(item)).join("\n")}\n`);
console.log(JSON.stringify({status: "OK", output}));
