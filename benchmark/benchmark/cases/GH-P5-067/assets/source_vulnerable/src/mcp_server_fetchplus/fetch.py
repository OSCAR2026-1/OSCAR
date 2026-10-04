"""Module for fetching web content."""

import logging
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup
from typing import Tuple, List, Optional
import html2markdown
import re
from urllib.parse import urljoin

from mcp_server_fetchplus.markdown_converter import MarkdownConverter
import markdownify  # 新增导入

# Add this line to create a module-level logger
logger = logging.getLogger(__name__)

from logging.handlers import RotatingFileHandler

class WebFetcher:
    """Class for fetching web content and converting to markdown."""
    
    def __init__(self, max_token_length: int = 8192):  # 调整为DeepSeek-R1典型上下文长度
        """Initialize the WebFetcher.
        
        Args:
            max_token_length: Maximum token length for each chunk (DeepSeek-R1建议8192)
        """
        self.max_token_length = max_token_length
        # 1 token ≈ 4字符（英文），中文需调整为1 token≈1字符（根据模型实际分词规则）
        self.max_char_length = max_token_length * 4  # 英文场景
        # 若需支持中文，可添加参数控制：self.max_char_length = max_token_length  # 中文场景
        self.markdown_converter = MarkdownConverter()
        # 配置重试策略（新增）
        self.retry_strategy = Retry(
            total=3,  # 总重试次数
            backoff_factor=1,  # 背退因子（重试间隔 = backoff_factor * (2 ** (retry - 1))）
            status_forcelist=[429, 500, 502, 503, 504]  # 遇到这些状态码时重试
        )
        self.adapter = HTTPAdapter(max_retries=self.retry_strategy)
        self.session = requests.Session()
        self.session.mount("https://", self.adapter)
        self.session.mount("http://", self.adapter)
        
        # 新增：配置日志文件输出（示例）
        log_handler = RotatingFileHandler(
            filename="fetch_service.log",  # 日志文件路径（当前目录下）
            maxBytes=10*1024*1024,  # 单个文件最大10MB
            backupCount=5,  # 保留5个历史文件
            encoding="utf-8"
        )
        log_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        log_handler.setFormatter(log_formatter)
        logger.addHandler(log_handler)  # Now 'logger' is properly defined
        logger.setLevel(logging.DEBUG)  # 设置日志级别
    
    def fetch_url(self, url: str) -> Tuple[str, str]:
        """Fetch content from URL.
        
        Args:
            url: URL to fetch
            
        Returns:
            Tuple of (title, html_content)
            
        Raises:
            ValueError: If URL is invalid or content cannot be fetched
        """
        try:
            # 新增：更完整的浏览器请求头（模拟真实用户）
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',  # 更新为最新Chrome版本
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'none',
                'Sec-Fetch-User': '?1'
            }
            # 使用 session 发送请求，超时延长至20秒
            response = self.session.get(url, headers=headers, timeout=20)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Get title
            title = soup.title.string if soup.title else "Untitled Page"
            
            # Clean up HTML before conversion
            # Remove script and style elements
            for script in soup(["script", "style"]):
                script.extract()
                
            return title, str(soup)
        except Exception as e:
            logger.error(f"Error fetching URL {url}: {str(e)}")
            raise ValueError(f"Failed to fetch content from {url}: {str(e)}")
    
    def html_to_markdown(self, html_content: str, base_url: str) -> str:
        """Convert HTML to Markdown.
        
        Args:
            html_content: HTML content to convert
            base_url: Base URL for resolving relative links
            
        Returns:
            Markdown content
        """
        logger.debug(f"转换前HTML长度: {len(html_content)}")
        try:
            # 替换为markdownify（保留换行和代码块）
            markdown = markdownify.markdownify(html_content, heading_style="ATX")
            logger.debug(f"转换后Markdown长度: {len(markdown)}")
            logger.debug(f"转换后Markdown前500字符: {markdown[:500].replace(chr(10), '\\n')}")
        except Exception as e:
            logger.error(f"HTML转Markdown失败，错误信息: {str(e)}")
            raise ValueError(f"HTML转Markdown失败: {str(e)}")
        
        markdown = self._fix_image_urls(markdown, base_url)
        return markdown
    
    def _fix_image_urls(self, markdown: str, base_url: str) -> str:
        """Fix image URLs to absolute (支持更多协议，记录无法修复的链接)."""
        img_pattern = r'!\[(.*?)\]\((.*?)\)'
        
        def replace_url(match):
            alt_text = match.group(1)
            url = match.group(2)
            valid_protocols = ('http://', 'https://', 'data:', 'ftp://')  # 新增ftp支持
            
            if not url.startswith(valid_protocols):
                try:
                    url = urljoin(base_url, url)
                    # 修复后仍无效则记录日志
                    if not url.startswith(valid_protocols):
                        logger.warning(f"无法修复图片链接: {url} (base_url: {base_url})")
                except Exception as e:
                    logger.error(f"图片链接修复失败: {url}, 错误: {str(e)}")
            return f'![{alt_text}]({url})'
        
        return re.sub(img_pattern, replace_url, markdown)
    
    def split_markdown(self, markdown: str, title: str) -> List[str]:
        """Split markdown into chunks if it's too long.
        
        Args:
            markdown: Markdown content
            title: Title of the page
            
        Returns:
            List of markdown chunks
        """
        # 使用MarkdownConverter的方法来分割内容
        return self.markdown_converter.split_content_by_headers(markdown, self.max_token_length)
    
    def fetch_and_convert(self, url: str) -> List[str]:
        """Fetch URL and convert to markdown.
        
        Args:
            url: URL to fetch
            
        Returns:
            List of markdown chunks
        """
        title, html_content = self.fetch_url(url)
        markdown = self.html_to_markdown(html_content, url)
        return self.split_markdown(markdown, title)