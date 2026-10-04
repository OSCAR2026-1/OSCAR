### URL Text Fetcher MCP Server

Tiny MCP server for LM Studio that adds two tools:
- `fetch_url_text(url)`: returns visible page text
- `fetch_page_links(url)`: returns all page links

---

### Quick start
```bash
cd /Users/lex/Learning/URL-Fetcher-LM-Studio-MCP-Server
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip setuptools wheel
python -m pip install -e .
```

---

### LM Studio setup (paste this into `mcp.json`)
Use the absolute interpreter to avoid ENOENT errors.

```json
{
  "mcpServers": {
    "url-text-fetcher": {
      "command": "/Users/lex/Learning/URL-Fetcher-LM-Studio-MCP-Server/.venv/bin/python",
      "args": ["-m", "url_text_fetcher.mcp_server"],
      "cwd": "/Users/lex/Learning/URL-Fetcher-LM-Studio-MCP-Server"
    }
  }
}
```

Alternative using the console script:

```json
{
  "mcpServers": {
    "url-text-fetcher": {
      "command": "/Users/lex/Learning/URL-Fetcher-LM-Studio-MCP-Server/.venv/bin/url-text-fetcher",
      "args": [],
      "cwd": "/Users/lex/Learning/URL-Fetcher-LM-Studio-MCP-Server"
    }
  }
}
```

After saving, restart LM Studio if the tool does not appear.

---

### Working prompts (use inside LM Studio)
- **Summarize a real page**: “Use `url-text-fetcher.fetch_url_text` on `https://httpbin.org/html`. Give a two‑sentence summary.”
- **List links from a real site**: “Call `url-text-fetcher.fetch_page_links` for `https://www.python.org/` and return the first 10 HTTPS links.”
- **Answer using content**: 
“Fetch text from `https://docs.python.org/3/whatsnew/3.12.html`. What is one notable change in Python 3.12?”
"Fetch text from https://www.python.org/. What’s the latest Python release mentioned and when was it announced?"

---

### Troubleshooting
- ENOENT `spawn python`: Use the absolute interpreter shown above in `mcp.json`.
- Network/SSL errors: try another URL; some sites block scripted fetches.

---

### Local run (optional)
```bash
source /Users/lex/Learning/URL-Fetcher-LM-Studio-MCP-Server/.venv/bin/activate
python -m url_text_fetcher.mcp_server
```