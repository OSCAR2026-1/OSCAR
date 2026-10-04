# MCP-Server-FetchPlus

一个符合 MCP（Model Context Protocol）标准的服务器，用于获取网页内容并转换为 Markdown 格式。

## 功能

- 根据用户输入的 URL 获取网页内容
- 将网页内容转换为 Markdown 格式
- 保留图片
- 自动拆分过长的文档以适应大语言模型的上下文长度限制

## 工程目录

```plaintext
mcp-server-fetchplus
├── .env
├── README.md
├── pyproject.toml
├── src
│   └── mcp_server_fetchplus
│       ├── __init__.py
│       ├── __pycache__
│       ├── fetch.py
│       ├── markdown_converter.py
│       └── server.py
└── test
    ├── fetch_service.log
    └── test_client.py
``` 

## 安装

```bash
pip install mcp-server-fetchplus
```

## 使用示例

### 调用`fetch`工具获取首块内容
```bash
curl -X POST "http://localhost:8000/mcp/tool/fetch" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```