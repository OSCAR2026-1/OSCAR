"""MCP server for fetching web content and converting to markdown."""

import logging
import os
from typing import Dict, Any, List, Optional
from mcp.server.fastmcp import FastMCP

from mcp_server_fetchplus.fetch import WebFetcher
from pydantic_settings import BaseSettings  # Updated import

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# 创建 MCP 服务器
mcp_server = FastMCP("ftech plus", version="0.0.1", description="MCP server for fetch web url and convert to markdown by pieces.")

# 创建 WebFetcher
class Settings(BaseSettings):
    max_token_length: int = 8192  # 默认DeepSeek-R1值
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

# 初始化时读取配置
settings = Settings()
web_fetcher = WebFetcher(max_token_length=settings.max_token_length)  # 使用配置值

@mcp_server.tool()
async def fetch_url(url: str) -> Dict[str, Any]:
    """获取 URL 并转换为 markdown。
    
    Args:
        url: 要获取的 URL
        
    Returns:
        包含 markdown 内容的字典
    """
    try:
        # 验证 URL
        if not url.startswith(("http://", "https://")):
            raise ValueError("URL 必须以 http:// 或 https:// 开头")
        
        logger.info(f"正在获取 URL: {url}")
        
        # 获取并转换 URL
        markdown_chunks = web_fetcher.fetch_and_convert(url)
        
        # 如果只有一个块，直接返回
        if len(markdown_chunks) == 1:
            return {
                "markdown": markdown_chunks[0],
                "url": url,
                "chunks": 1,
            }
        
        # 如果有多个块，返回第一个块并指示总块数
        return {
            "markdown": markdown_chunks[0],
            "url": url,
            "chunks": len(markdown_chunks),
            "message": f"内容已被分割为 {len(markdown_chunks)} 个块。这是第一个块。"
        }
    
    except ValueError as e:
        logger.error(f"值错误: {str(e)}")
        raise ValueError(str(e))
    except Exception as e:
        logger.error(f"处理请求时出错: {str(e)}")
        raise Exception(f"处理请求失败: {str(e)}")

@mcp_server.tool()
async def fetch_chunk(url: str, chunk_index: int) -> Dict[str, Any]:
    """获取特定的 Markdown 内容块。
    
    Args:
        url: 要获取的 URL
        chunk_index: 要获取的块索引（从 1 开始）
        
    Returns:
        包含指定块的 markdown 内容的字典
    """
    try:
        # 验证 URL
        if not url.startswith(("http://", "https://")):
            raise ValueError("URL 必须以 http:// 或 https:// 开头")
        
        # 验证块索引
        if chunk_index < 1:
            raise ValueError("块索引必须大于等于 1")
        
        logger.info(f"正在获取 URL: {url} 的第 {chunk_index} 块")
        
        # 获取并转换 URL
        markdown_chunks = web_fetcher.fetch_and_convert(url)
        
        # 验证块索引
        if chunk_index > len(markdown_chunks):
            raise ValueError(f"块索引超出范围。总块数: {len(markdown_chunks)}")
        
        # 返回指定块
        return {
            "markdown": markdown_chunks[chunk_index - 1],
            "url": url,
            "chunk_index": chunk_index,
            "total_chunks": len(markdown_chunks)
        }
    
    except ValueError as e:
        logger.error(f"值错误: {str(e)}")
        raise ValueError(str(e))
    except Exception as e:
        logger.error(f"处理请求时出错: {str(e)}")
        raise Exception(f"处理请求失败: {str(e)}")

def main():
    """运行服务器。"""
    logger.info("Starting MCP fetch plus Server...")
    mcp_server.run()

if __name__ == "__main__":
    main()