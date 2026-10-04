"""测试MCP服务的客户端脚本"""

import asyncio
import json
import os  # 新增：导入os模块用于获取环境变量
from mcp import ClientSession, StdioServerParameters, types
from mcp.client.stdio import stdio_client

# 获取当前PYTHONPATH（若不存在则为空字符串）
current_pythonpath = os.environ.get("PYTHONPATH", "")
# 拼接新的PYTHONPATH（原路径 + 项目src目录）
new_pythonpath = f"{current_pythonpath};d:/09.coding/ai/aicoding/MCP/Server/mcp-server-fetchplus/src"

# Create server parameters for stdio connection
server_params = StdioServerParameters(
    command="E:\\soft/tools\\anaconda3\\envs\\llm_learn\\python",  # Executable
    args=["D:\\09.coding\\ai\\aicoding\\MCP\\Server\\mcp-server-fetchplus\\src\\mcp_server_fetchplus\\server.py"],  # Optional command line arguments
    env={
        "PYTHONPATH": new_pythonpath,  # 使用动态拼接的路径
        "max_token_length": "3000"
    },  # Optional environment variables
)

async def test_fetch_service():
    """测试fetch服务功能"""
    print("开始测试MCP服务...")
    
    # 创建MCP客户端
    async with stdio_client(server_params) as (read, write):
        print("已创建stdio客户端，获取read/write流")  # 添加调试日志
        async with ClientSession(read, write) as session:
            print("已创建ClientSession，开始初始化连接")  # 添加调试日志
            # Initialize the connection
            await session.initialize()
            print("连接初始化完成")  # 添加调试日志
    
            # 测试URL
            test_url = "https://towardsdatascience.com/understanding-llms-from-scratch-using-middle-school-math-e602d27ec876/"
            #test_url = "https://www.artificialintelligence-news.com/"
            
            try:
                # List available tools（获取包含工具列表的结果对象）
                tools_result = await session.list_tools()
                tools = tools_result.tools  # 从结果对象中提取工具列表
                
                for tool in tools:  # 遍历实际的工具列表
                    print(f"工具名称: {tool.name}")
                    print(f"工具描述: {tool.description}")
                    # 修复：inputSchema 是字典，直接使用 json.dumps 处理
                    print(f"参数: {json.dumps(tool.inputSchema, indent=2)}")  # 移除 .dict() 调用
                    print("-" * 40)  # 分隔线

                # 调用fetch工具
                print(f"正在获取URL: {test_url}")
                response = await session.call_tool("fetch_url", {"url": test_url})
                
                # 检查是否为错误响应
                if response.isError:
                    error_message = response.content[0].text if response.content else "未知错误"
                    print(f"\n获取失败! 错误信息: {error_message}")
                    return False  # 提前终止测试
                
                # 成功响应解析：content 是 TextContent 列表，text 字段为 JSON 格式的 Markdown 内容
                if response.content:
                    # 提取第一个内容块的 text 字段（假设是 JSON 字符串）
                    content_text = response.content[0].text
                    try:
                        # 解析 JSON 内容（假设服务端返回的是 {"markdown": "..."} 格式）
                        content_data = json.loads(content_text)
                        markdown = content_data.get("markdown", "")
                        # 关键修改：从响应中获取总块数（而非通过content长度判断）
                        total_chunks = content_data.get("chunks", 1)
                        
                        # 打印摘要
                        print("\n获取成功! 响应内容摘要:")
                        print(f"URL: {test_url}")
                        print(f"总块数: {total_chunks}")  # 显示服务端返回的总块数
                        print(f"Markdown内容预览: {markdown[:200]}...")
                    except json.JSONDecodeError:
                        print("\n获取成功! 但内容非 JSON 格式，原始内容预览:")
                        print(f"{content_text[:200]}...")
                else:
                    print("\n获取成功! 但无内容返回")

                # 分块获取逻辑（根据服务端返回的总块数判断）
                if total_chunks > 1:  # 使用服务端返回的总块数判断
                    print("\n正在获取第2块...")
                    chunk_response = await session.call_tool("fetch_chunk", {
                        "url": test_url,
                        "chunk_index": 2
                    })
                    # 检查 chunk_response 是否为错误响应
                    if chunk_response.isError:
                        chunk_error = chunk_response.content[0].text if chunk_response.content else "未知错误"
                        print(f"第2块获取失败! 错误信息: {chunk_error}")
                        return False
                    # 解析 chunk_response 的 content（假设结构与主响应一致）
                    chunk_content = chunk_response.content[0].text if chunk_response.content else ""
                    # 从 chunk_response 中获取总块数（确保一致性）
                    chunk_data = json.loads(chunk_content) if chunk_content else {}
                    chunk_total = chunk_data.get("total_chunks", total_chunks)
                    print(f"第2块获取成功! 总块数: {chunk_total}")  # 显示当前块的总块数
                    print(f"第2块内容预览: {chunk_content[:200]}...")  # 显示块内容预览
                else:
                    print("\n内容未分块，无需获取后续块")
                
                print("\n测试完成!")
                return True
            except Exception as e:
                print(f"测试失败: {str(e)}")
                return False

if __name__ == "__main__":
    asyncio.run(test_fetch_service())