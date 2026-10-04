"""Run the frozen Zilliz MCP server over stdio JSON-RPC."""

from zilliz_mcp_server.app import zilliz_mcp
from zilliz_mcp_server.tools.milvus import milvus_tools  # noqa: F401
from zilliz_mcp_server.tools.zilliz import zilliz_tools  # noqa: F401


zilliz_mcp.run(transport="stdio")
