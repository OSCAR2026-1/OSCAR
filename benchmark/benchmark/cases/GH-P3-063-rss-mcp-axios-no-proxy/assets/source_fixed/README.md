# RSS MCP Server

[![NPM Version](https://img.shields.io/npm/v/rss-mcp.svg)](https://www.npmjs.com/package/rss-mcp)

This is a Model Context Protocol (MCP) server built with TypeScript. It provides a versatile tool to fetch and parse any standard RSS/Atom feed, and also includes special support for [RSSHub](https://docs.rsshub.app/) feeds. With this server, language models or other MCP clients can easily retrieve structured content from various web sources.

<a href="https://glama.ai/mcp/servers/@veithly/rss-mcp">
  <img width="380" height="200" src="https://glama.ai/mcp/servers/@veithly/rss-mcp/badge" alt="RSS Server MCP server" />
</a>

The server comes with a built-in list of public RSSHub instances and supports a polling mechanism to automatically select an available instance, significantly improving the success rate and stability of data retrieval.

## ✨ Features

- **Universal Feed Parsing**: Fetch and parse any standard RSS/Atom feed from a given URL.
- **Enhanced RSSHub Support**: Provides a tool named `get_feed` to fetch any RSSHub-supported feed via MCP, with multi-instance support.
- **Customizable Item Count**: Specify the number of feed items to retrieve, with support for fetching all items.
- **Multi-instance Support**: Includes a list of public RSSHub instances and automatically polls to find an available service.
- **Smart URL Parsing**: Supports standard RSSHub URLs and a simplified `rsshub://` protocol format.
- **Priority Instance Configuration**: Allows setting a preferred RSSHub instance via the `PRIORITY_RSSHUB_INSTANCE` environment variable.
- **Robust Error Handling**: If a request to one instance fails, it automatically tries the next one until it succeeds or all instances have failed.
- **Content Cleaning**: Uses Cheerio to clean the feed content and extract plain text descriptions.
- **Standardized Output**: Converts the fetched RSS feed into a structured JSON format.

## 📦 Installation

First, clone the project repository, then install the required dependencies.

```bash
git clone https://github.com/veithly/rss-mcp.git
cd rss-mcp
npm install
```

## 🚀 Usage

### 1. Build the Project

Before running, you need to compile the TypeScript code into JavaScript:

```bash
npm run build
```

### 2. Run the Server

After a successful build, start the MCP server:

```bash
npm start
```

The server will then communicate with the parent process (e.g., Cursor) via Stdio.

### 3. Configure a Priority Instance (Optional)

You can create a `.env` file to specify a priority RSSHub instance. This is very useful for users who have a private, stable instance.

Create a `.env` file in the project root directory and add the following content:

```env
PRIORITY_RSSHUB_INSTANCE=https://my-rsshub.example.com
```

The server will automatically load this configuration on startup and place it at the top of the polling list.

## 🔧 MCP Server Configuration

To use this server with an MCP client like Cursor, you need to add it to your configuration file.

### Method 1: Using `npx` (Recommended)

This package is published on npm, so you can use `npx` to run the server without a local installation. This is the easiest method.

1.  **Direct Invocation**:
    You can run the server directly from your terminal using `npx`:

    ```bash
    npx rss-mcp
    ```

2.  **MCP Client Configuration**:
    To integrate with an MCP client like Cursor, add the following to your configuration file (e.g., `~/.cursor/mcp_settings.json`):

    ```json
    {
      "name": "rss",
      "command": ["npx", "rss-mcp"],
      "type": "stdio"
    }
    ```

### Method 2: Local Installation

If you have cloned the repository locally, you can run it directly with `node`.

1.  **Clone and build the project** as described in the "Installation" and "Usage" sections.
2.  **Locate your MCP configuration file.**
3.  Add the following server entry, making sure to use the **absolute path** to the compiled `index.js` file:

    ```json
    {
      "name": "rss",
      "command": ["node", "/path/to/your/rss-mcp/dist/index.js"],
      "type": "stdio"
    }
    ```

    **Important:** Replace `/path/to/your/rss-mcp/dist/index.js` with the correct absolute path on your system.

After adding the configuration, **restart your MCP client** (e.g., Cursor) for the changes to take effect. The `rss` server will then be available, and you can call the `get_feed` tool.

## 🛠️ Tool Definition

### `get_feed`

Fetches and parses an RSS feed from a given URL. It supports both standard RSS/Atom feeds and RSSHub feeds.

#### Input Parameters

- `url` (string, required): The URL of the RSS feed to fetch. Two formats are supported:
    1.  **Standard URL**: `https://rsshub.app/bilibili/user/dynamic/208259`
    2.  **`rsshub://` protocol**: `rsshub://bilibili/user/dynamic/208259` (the server will automatically match an available instance)
- `count` (number, optional): The number of RSS feed items to retrieve.
    - **Default**: `1`
    - **Retrieve all**: `0`

#### Output

Returns a JSON string containing the feed information, with the following structure:

```json
{
  "title": "bilibili User Dynamics",
  "link": "https://space.bilibili.com/208259",
  "description": "bilibili User Dynamics",
  "items": [
    {
      "title": "[Dynamic Title]",
      "description": "Plain text content of the dynamic...",
      "link": "https://t.bilibili.com/1234567890",
      "guid": "https://t.bilibili.com/1234567890",
      "pubDate": "2024-05-20T12:30:00.000Z",
      "author": "Author Name",
      "category": ["Category1", "Category2"]
    }
  ]
}
```

## 📜 Main Dependencies

- [@modelcontextprotocol/sdk](https://www.npmjs.com/package/@modelcontextprotocol/sdk): For building the MCP server.
- [axios](https://www.npmjs.com/package/axios): For making HTTP requests.
- [rss-parser](https://www.npmjs.com/package/rss-parser): For parsing RSS/Atom feeds.
- [cheerio](https://www.npmjs.com/package/cheerio): For parsing and manipulating HTML content.
- [date-fns-tz](https://www.npmjs.com/package/date-fns-tz): For handling time-zone-related date formatting.
- [dotenv](https://www.npmjs.com/package/dotenv): For loading environment variables from a `.env` file.

## 📄 License

This project is licensed under the Apache-2.0 License.