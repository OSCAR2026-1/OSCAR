import argparse
import asyncio
import json
import os
import sys

from google import genai
from google.genai import types
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


def main():
    # Argument parsing
    parser = argparse.ArgumentParser(
        description="Use AI to interact with REST APIs via MCP"
    )
    parser.add_argument(
        "--question",
        "-q",
        type=str,
        required=False,
        help="Your question/request for the AI to process",
    )
    parser.add_argument(
        "--model",
        "-m",
        type=str,
        default="gemini-2.0-flash-exp",
        help="AI model to use (default: gemini-2.0-flash-exp)",
    )
    parser.add_argument(
        "--temperature",
        "-t",
        type=float,
        default=0.1,
        help="AI temperature setting (default: 0.1)",
    )
    args = parser.parse_args()

    # Get API key
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        print("Error: GEMINI_API_KEY environment variable not set")
        sys.exit(1)

    # Default prompt if none provided
    prompt = args.question or input("Enter your question: ")

    if not prompt.strip():
        print("No question provided. Exiting.")
        sys.exit(1)

    # Run the async client
    asyncio.run(run_client(prompt, args.model, args.temperature, api_key))


async def run_client(prompt: str, model: str, temperature: float, api_key: str):
    """Run the MCP client with AI integration"""

    # Initialize Gemini client
    try:
        client = genai.Client(api_key=api_key)
    except Exception as e:
        print(f"Error initializing Gemini client: {e}")
        return

    # Launch MCP server via stdio
    server_params = StdioServerParameters(
        command="python",
        args=["server.py"],
        env=os.environ.copy(),
    )

    try:
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                # Initialize MCP session
                await session.initialize()

                # Get available tools from MCP server
                mcp_tools = await session.list_tools()
                print(
                    f"Connected to MCP server with {len(mcp_tools.tools)} tools available"
                )

                # Convert MCP tools to Gemini format
                tools = [
                    types.Tool(
                        function_declarations=[
                            {
                                "name": tool.name,
                                "description": tool.description,
                                "parameters": {
                                    k: v
                                    for k, v in tool.inputSchema.items()
                                    if k not in ["additionalProperties", "$schema"]
                                },
                            }
                        ]
                    )
                    for tool in mcp_tools.tools
                ]

                print(f"\nQuestion: {prompt}")
                print("-" * 50)

                # Generate response with AI
                try:
                    response = client.models.generate_content(
                        model=model,
                        contents=prompt,
                        config=types.GenerateContentConfig(
                            temperature=temperature,
                            tools=tools,
                        ),
                    )
                except Exception as e:
                    print(f"Error generating AI response: {e}")
                    return

                # Process the response
                if (
                    response.candidates
                    and response.candidates[0].content.parts
                    and response.candidates[0].content.parts[0].function_call
                ):

                    # AI wants to call a function
                    function_call = (
                        response.candidates[0].content.parts[0].function_call
                    )
                    print(f"AI is calling function: {function_call.name}")
                    print(f"Arguments: {dict(function_call.args)}")
                    print("-" * 50)

                    try:
                        # Execute the function call via MCP
                        result = await session.call_tool(
                            function_call.name, arguments=dict(function_call.args)
                        )

                        print("Result:")
                        # Try to format as JSON if possible
                        try:
                            result_text = result.content[0].text
                            result_data = json.loads(result_text)
                            print(json.dumps(result_data, indent=2, ensure_ascii=False))
                        except (json.JSONDecodeError, KeyError, IndexError):
                            # If not JSON, print as-is
                            if hasattr(result, "content") and result.content:
                                print(result.content[0].text)
                            else:
                                print(str(result))

                    except Exception as e:
                        print(f"Error executing function call: {e}")

                else:
                    # AI responded without function calls
                    print("AI Response:")
                    if hasattr(response, "text") and response.text:
                        print(response.text)
                    else:
                        print("No response generated")

    except Exception as e:
        print(f"Error connecting to MCP server: {e}")
        print("Make sure server.py is in the current directory and accessible")


if __name__ == "__main__":
    main()
