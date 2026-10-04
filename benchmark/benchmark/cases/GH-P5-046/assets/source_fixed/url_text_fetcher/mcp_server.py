from mcp.server.fastmcp import FastMCP
import requests
from bs4 import BeautifulSoup
from typing import List
import asyncio
import sys


mcp = FastMCP("URL Text Fetcher")


@mcp.tool()
def fetch_url_text(url: str) -> str:
    """Download all visible text from a URL."""
    resp = requests.get(url, timeout=10)
    resp.raise_for_status()
    soup = BeautifulSoup(resp.text, "html.parser")
    return soup.get_text(separator="\n", strip=True)


@mcp.tool()
def fetch_page_links(url: str) -> List[str]:
    """Return a list of all links on the page."""
    resp = requests.get(url, timeout=10)
    resp.raise_for_status()
    soup = BeautifulSoup(resp.text, "html.parser")
    return [a['href'] for a in soup.find_all('a', href=True)]


def main():
    # Note: Write startup/shutdown messages to stderr to avoid corrupting MCP stdio JSON-RPC on stdout
    sys.stderr.write("MCP Server started for LM Studio...\n")
    sys.stderr.flush()
    try:
        mcp.run()
        return 0
    except (KeyboardInterrupt, asyncio.CancelledError):
        return 0
    finally:
        sys.stderr.write("Server Stopped\n")
        sys.stderr.flush()


if __name__ == "__main__":
    main()


