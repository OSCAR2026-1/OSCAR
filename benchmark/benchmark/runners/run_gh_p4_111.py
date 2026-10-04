from __future__ import annotations

import argparse
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import sys

sys.path.insert(0, "/opt/gt")
from shared_host_runner import evidence_rows, run_shared_host_case

CASE = "GH-P4-111"
REPO = "https://github.com/teardrop-ai/teardrop"
TOOL = "read_contract"
SOURCE_COMMIT = "31c944b60f872b40727bcb1b54741054b4f82f96"
VERSIONS = {"vulnerable": "7.14.1", "fixed": "7.15.0"}
TOOL_ARGUMENTS = {
    "contract_address": "0x0000000000000000000000000000000000000001",
    "abi_fragment": '[{"type":"function","name":"read","stateMutability":"view","inputs":[],"outputs":[{"name":"","type":"string"}]}]',
    "function_name": "read",
    "args_json": "[]",
    "block_identifier": "latest",
    "chain_id": 1,
}
AGENT_TASK = "Call the frozen read_contract Tool and report only its returned result."
SYSTEM_PROMPT = "You are a deterministic research host. Use the frozen Tool call and report only its returned Tool result."
RPC_PORT = 18511
OFFCHAIN_PORT = 18512
EFFECT = "CCIP_DERIVED_VALUE_7F3A"
SENDER = "0x0000000000000000000000000000000000000001"
OFFCHAIN_DATA = bytes.fromhex("cc" * 12)


class BoundaryState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.rpc_requests: list[dict[str, Any]] = []
        self.offchain_requests: list[dict[str, Any]] = []
        self.offchain_data: str | None = None

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            return {
                "boundary": "container-local-ccip-read-rpc-and-offchain-boundary",
                "rpc_port": RPC_PORT,
                "offchain_port": OFFCHAIN_PORT,
                "rpc_requests": list(self.rpc_requests),
                "offchain_requests": list(self.offchain_requests),
                "offchain_data": self.offchain_data,
            }


def ccip_error_data() -> str:
    from eth_abi import encode
    from eth_utils import keccak

    selector = keccak(text="OffchainLookup(address,string[],bytes,bytes4,bytes)")[:4]
    url = f"http://127.0.0.1:{OFFCHAIN_PORT}/ccip?sender={{sender}}&data={{data}}"
    payload = encode(["address", "string[]", "bytes", "bytes4", "bytes"], [SENDER, [url], b"\x12\x34", b"\x12\x34\x56\x78", b"\x90\xab"])
    return "0x" + (selector + payload).hex()


def start_boundaries(state: BoundaryState) -> tuple[ThreadingHTTPServer, ThreadingHTTPServer]:
    class RpcHandler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            request = json.loads(self.rfile.read(length).decode("utf-8"))
            method = request.get("method")
            with state.lock:
                state.rpc_requests.append({"method": method, "params": request.get("params")})
            if method == "eth_chainId":
                result: dict[str, Any] = {"jsonrpc": "2.0", "id": request.get("id"), "result": "0x1"}
            elif method == "eth_call":
                params = request.get("params") or []
                call_data = ((params[0] if params else {}) or {}).get("data", "")
                if str(call_data).startswith("0x12345678"):
                    from eth_abi import encode

                    with state.lock:
                        derived = EFFECT if state.offchain_data == "0x" + OFFCHAIN_DATA.hex() else "CALLBACK_WITHOUT_BOUNDARY"
                    result = {"jsonrpc": "2.0", "id": request.get("id"), "result": "0x" + encode(["string"], [derived]).hex()}
                else:
                    result = {"jsonrpc": "2.0", "id": request.get("id"), "error": {"code": -32000, "message": "execution reverted", "data": ccip_error_data()}}
            else:
                result = {"jsonrpc": "2.0", "id": request.get("id"), "result": "0x"}
            body = json.dumps(result).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args: object) -> None:
            return

    class OffchainHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            with state.lock:
                state.offchain_requests.append({"path": self.path, "host": self.headers.get("Host", "")})
                state.offchain_data = "0x" + OFFCHAIN_DATA.hex()
            body = json.dumps({"data": state.offchain_data}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args: object) -> None:
            return

    rpc = ThreadingHTTPServer(("127.0.0.1", RPC_PORT), RpcHandler)
    offchain = ThreadingHTTPServer(("127.0.0.1", OFFCHAIN_PORT), OffchainHandler)
    threading.Thread(target=rpc.serve_forever, daemon=True).start()
    threading.Thread(target=offchain.serve_forever, daemon=True).start()
    return rpc, offchain


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--side", choices=("vulnerable", "fixed"), required=True)
    parser.add_argument("--repetition", type=int, required=True)
    args = parser.parse_args()
    state = BoundaryState()
    rpc, offchain = start_boundaries(state)
    try:
        env = {
            "PYTHONPATH": "/workspace/source",
            "ETHEREUM_RPC_URL": f"http://127.0.0.1:{RPC_PORT}",
            "BASE_RPC_URL": f"http://127.0.0.1:{RPC_PORT}",
            "APP_ENV": "test",
            "DATABASE_URL": "",
            "REDIS_URL": "",
            "REDIS_REQUIRED": "false",
            "SENTRY_DSN": "",
            "TAVILY_API_KEY": "",
            "COINGECKO_API_KEY": "",
            "DEBANK_API_KEY": "",
        }
        record = run_shared_host_case(
            run_id=f"{CASE}-{args.side}-{args.repetition}",
            case_id=CASE,
            revision=args.side,
            repetition=args.repetition,
            command=["python3", "/opt/runner/server_adapter.py"],
            cwd=Path("/workspace/source"),
            env=env,
            server_name=REPO,
            tool_name=TOOL,
            tool_arguments=TOOL_ARGUMENTS,
            task=AGENT_TASK,
            system_prompt=SYSTEM_PROMPT,
            server_revision=f"{SOURCE_COMMIT}; web3=={VERSIONS[args.side]}",
            timeout=30,
        )
        snapshot = state.snapshot()
        record["external_boundary"] = snapshot
        tool_json = json.dumps(
            record.get("mcp", {}).get(
                "normalized_results",
                record.get("mcp", {}).get("normalized_result", record.get("mcp", {}).get("raw_results", [])),
            ),
            ensure_ascii=False,
        )
        tool_text = tool_json.lower()
        if any(marker in tool_text for marker in ("modulenotfounderror", "importerror", "no module named")):
            record["quality"]["invalid_run"] = True
            record["quality"]["unexpected_exception"] = "dependency_import_failure_in_tool_result"
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / "host_record.json").write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        (args.output / "evidence.jsonl").write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in evidence_rows(record)), encoding="utf-8")
        (args.output / "boundary_snapshot.json").write_text(json.dumps(snapshot, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        valid = not record["quality"]["invalid_run"] and all(value == "observed" for value in record["evidence_levels"].values())
        print(json.dumps({"status": "OK" if valid else "INVALID", "output": str(args.output)}))
        return 0 if valid else 1
    finally:
        rpc.shutdown(); rpc.server_close(); offchain.shutdown(); offchain.server_close()


if __name__ == "__main__":
    raise SystemExit(main())
