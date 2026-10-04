"""Module for converting HTML to Markdown with image preservation."""

import re
import logging  # 新增：显式导入logging
from typing import Dict, Any, List
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from logging.handlers import RotatingFileHandler  # 新增：导入日志处理器

# 新增：配置文件日志输出（与fetch.py保持一致）
logger = logging.getLogger(__name__)
log_handler = RotatingFileHandler(
    filename="fetch_service.log",  # 与fetch.py使用相同日志文件
    maxBytes=10*1024*1024,
    backupCount=5,
    encoding="utf-8"
)
log_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
log_handler.setFormatter(log_formatter)
logger.addHandler(log_handler)  # 添加文件处理器
logger.setLevel(logging.DEBUG)  # 设置日志级别

class MarkdownConverter:
    """Class for converting HTML to Markdown with image preservation."""
    
    @staticmethod
    def extract_metadata(soup: BeautifulSoup) -> Dict[str, Any]:
        """Extract metadata from HTML.
        
        Args:
            soup: BeautifulSoup object
            
        Returns:
            Dictionary of metadata
        """
        metadata = {
            "title": "",
            "description": "",
            "author": "",
            "date": "",
        }
        
        # Extract title
        if soup.title:
            metadata["title"] = soup.title.string.strip()
        
        # Extract meta description
        meta_desc = soup.find("meta", attrs={"name": "description"})
        if meta_desc and meta_desc.get("content"):
            metadata["description"] = meta_desc["content"].strip()
        
        # Extract author
        meta_author = soup.find("meta", attrs={"name": "author"})
        if meta_author and meta_author.get("content"):
            metadata["author"] = meta_author["content"].strip()
        
        # Extract date
        meta_date = soup.find("meta", attrs={"name": "date"})
        if meta_date and meta_date.get("content"):
            metadata["date"] = meta_date["content"].strip()
        
        return metadata
    
    @staticmethod
    def estimate_tokens(text: str) -> int:
        """Estimate the number of tokens in text.
        
        Args:
            text: Text to estimate tokens for
            
        Returns:
            Estimated token count
        """
        # Simple estimation: 1 token ≈ 4 characters for English text
        # This is a rough approximation
        return len(text) // 4
    
    @staticmethod
    def format_metadata_as_markdown(metadata: Dict[str, Any]) -> str:
        """Format metadata as markdown.
        
        Args:
            metadata: Dictionary of metadata
            
        Returns:
            Markdown formatted metadata
        """
        md = f"# {metadata['title']}\n\n"
        
        if metadata["description"]:
            md += f"> {metadata['description']}\n\n"
        
        meta_line = []
        if metadata["author"]:
            meta_line.append(f"Author: {metadata['author']}")
        if metadata["date"]:
            meta_line.append(f"Date: {metadata['date']}")
        
        if meta_line:
            md += f"*{' | '.join(meta_line)}*\n\n"
        
        md += "---\n\n"
        return md
    
    @staticmethod
    def split_content_by_headers(markdown: str, max_tokens: int = 8192) -> List[str]:
        """Split markdown content by headers/tokens to fit DeepSeek-R1 limits."""
        import logging  # 确保日志模块已导入
        logger = logging.getLogger(__name__)
        logger.debug(f"开始分块，输入Markdown长度: {len(markdown)}，max_tokens: {max_tokens}")  # 新增日志
        
        header_pattern = r'^#{1,6}\s+.+$'
        lines = markdown.split('\n')
        chunks = []
        current_chunk = []
        current_token_count = 0
    
        for line in lines:
            line_token_count = MarkdownConverter.estimate_tokens(line)
            logger.debug(f"处理行: '{line[:50]}'（token数: {line_token_count}）")  # 新增日志
            
            # 优化：无标题时按段落拆分（空行分隔）
            if not re.match(header_pattern, line) and line.strip() == "":
                if current_token_count > max_tokens // 2:
                    logger.debug(f"遇到空行，当前token数{current_token_count} > {max_tokens//2}，触发分块")  # 新增日志
                    chunks.append('\n'.join(current_chunk))
                    current_chunk = []
                    current_token_count = 0
    
            current_chunk.append(line)
            current_token_count += line_token_count
            logger.debug(f"当前块累计token数: {current_token_count}")  # 新增日志
    
            # 严格限制不超过max_tokens
            if current_token_count >= max_tokens:
                logger.debug(f"当前token数{current_token_count} >= {max_tokens}，触发分块")  # 新增日志
                chunks.append('\n'.join(current_chunk))
                current_chunk = []
                current_token_count = 0
    
        if current_chunk:
            logger.debug(f"剩余内容，token数{current_token_count}，加入分块")  # 新增日志
            chunks.append('\n'.join(current_chunk))
        
        logger.debug(f"分块完成，总块数: {len(chunks)}")  # 新增日志
        return chunks