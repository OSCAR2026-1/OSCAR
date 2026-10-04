from typing import Any, Dict, Optional, Union

import requests
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("GenericRESTClient")


@mcp.tool()
def call_rest_api(
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    data: Optional[Union[Dict[str, Any], str]] = None,
    params: Optional[Dict[str, Any]] = None,
    timeout: int = 30,
) -> str:
    """
    Make a REST API call to any endpoint.

    Args:
        url: The complete API endpoint URL
        method: HTTP method (GET, POST, PUT, DELETE, PATCH)
        headers: Optional HTTP headers as key-value pairs
        data: Request body data (dict for JSON, string for raw data)
        params: URL query parameters as key-value pairs
        timeout: Request timeout in seconds

    Returns:
        API response as string
    """

    try:
        # Prepare headers
        request_headers = headers or {}

        # If data is a dict, set JSON content type
        if isinstance(data, dict) and "Content-Type" not in request_headers:
            request_headers["Content-Type"] = "application/json"

        # Make the request
        response = requests.request(
            method=method.upper(),
            url=url,
            headers=request_headers,
            json=data if isinstance(data, dict) else None,
            data=data if isinstance(data, str) else None,
            params=params,
            timeout=timeout,
        )

        # Raise exception for HTTP errors
        response.raise_for_status()

        return response.text

    except requests.exceptions.Timeout:
        return f"Request timed out after {timeout} seconds"
    except requests.exceptions.ConnectionError:
        return f"Failed to connect to {url}"
    except requests.exceptions.HTTPError as e:
        return f"HTTP error {response.status_code}: {response.text}"
    except requests.exceptions.RequestException as e:
        return f"Request failed: {str(e)}"
    except Exception as e:
        return f"Unexpected error: {str(e)}"


if __name__ == "__main__":
    mcp.run()
