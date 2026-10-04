import httpx
from fastmcp import FastMCP


def main():
    petstore_server: FastMCP = setup_fastmcp_server_from_openapi_spec(
        spec_link="https://petstore3.swagger.io/api/v3/openapi.json",
        base_url="https://petstore3.swagger.io/api/v3",
        server_name="Petstore MCP Server",
    )
    petstore_server.run(transport="streamable-http", host="0.0.0.0", port=8000)


def setup_fastmcp_server_from_openapi_spec(
    spec_link: str,
    base_url: str,
    server_name: str,
) -> FastMCP:
    open_api_spec = httpx.get(
        spec_link,
    ).json()

    client = httpx.AsyncClient(base_url=base_url)

    return FastMCP.from_openapi(
        openapi_spec=open_api_spec,
        client=client,
        name=server_name,
    )


if __name__ == "__main__":
    main()
