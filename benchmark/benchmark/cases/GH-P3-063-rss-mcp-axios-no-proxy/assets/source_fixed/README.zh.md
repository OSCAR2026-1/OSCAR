# RSS MCP 服务器

[![NPM Version](https://img.shields.io/npm/v/rss-mcp.svg)](https://www.npmjs.com/package/rss-mcp)

这是一个基于 TypeScript 构建的 Model Context Protocol (MCP) 服务器。它提供了一个通用的工具来获取和解析任何标准的 RSS/Atom feed，并且还特别支持 [RSSHub](https://docs.rsshub.app/) 的 feed。通过此服务器，语言模型或其他 MCP 客户端可以轻松地从各种网络来源检索结构化内容。

服务器内置了多个公共 RSSHub 实例列表，并支持通过轮询机制自动选择可用的实例，大大提高了数据获取的成功率和稳定性。

## ✨ 功能特性

- **通用 Feed 解析**: 从给定的 URL 获取和解析任何标准的 RSS/Atom feed。
- **增强的 RSSHub 支持**: 提供一个名为 `get_feed` 的工具，通过 MCP 获取任何 RSSHub 支持的 feed，并支持多实例。
- **可自定义的条目数量**: 可指定要检索的 feed 条目数量，并支持获取所有条目。
- **多实例支持**: 内置多个公共 RSSHub 实例地址，并自动轮询以查找可用服务。
- **智能 URL 解析**: 支持标准的 RSSHub URL 和简化的 `rsshub://` 协议格式。
- **优先实例配置**: 允许通过环境变量 `PRIORITY_RSSHUB_INSTANCE` 设置一个优先使用的 RSSHub 实例。
- **健壮的错误处理**: 如果一个实例请求失败，会自动尝试下一个，直到成功或所有实例都失败。
- **内容清洗**: 使用 Cheerio 清理 feed 内容，提取纯文本描述。
- **标准化输出**: 将获取的 RSS feed 转换为结构化的 JSON 格式返回。

## 📦 安装

首先，克隆该项目仓库，然后安装所需的依赖项。

```bash
git clone https://github.com/your-username/rss-mcp.git
cd rss-mcp
npm install
```

## 🚀 使用

### 1. 编译项目

在运行之前，需要先将 TypeScript 代码编译成 JavaScript：

```bash
npm run build
```

### 2. 运行服务器

编译成功后，启动 MCP 服务器：

```bash
npm start
```

服务器启动后，将通过 Stdio 与父进程（例如 Cursor）进行通信。

### 3. 配置优先实例 (可选)

您可以创建一个 `.env` 文件来指定一个优先使用的 RSSHub 实例。这对于拥有私有、稳定实例的用户非常有用。

在项目根目录下创建 `.env` 文件，并添加以下内容：

```env
PRIORITY_RSSHUB_INSTANCE=https://my-rsshub.example.com
```

服务器启动时会自动加载此配置，并将其置于轮询列表的首位。

## 🔧 MCP 服务器配置

要将此服务器与像 Cursor 这样的 MCP 客户端一起使用，您需要将其添加到您的配置文件中。

### 方法一：使用 `npx` (推荐)

该软件包已发布到 npm，您可以使用 `npx` 来运行服务器，而无需在本地安装。这是最简单的方法。

1.  **直接调用**:
    您可以直接在终端中使用 `npx` 运行服务器：

    ```bash
    npx rss-mcp
    ```

2.  **MCP 客户端配置**:
    要与像 Cursor 这样的 MCP 客户端集成，请将以下内容添加到您的配置文件中 (例如 `~/.cursor/mcp_settings.json`):

    ```json
    {
      "name": "rss",
      "command": ["npx", "rss-mcp"],
      "type": "stdio"
    }
    ```

### 方法二：本地安装

如果您已在本地克隆了仓库，则可以直接使用 `node` 运行它。

1.  **克隆并构建项目**，如“安装”和“使用”部分所述。
2.  **找到您的 MCP 配置文件。**
3.  添加以下服务器条目，确保使用已编译的 `index.js` 文件的**绝对路径**：

    ```json
    {
      "name": "rss",
      "command": ["node", "/path/to/your/rss-mcp/dist/index.js"],
      "type": "stdio"
    }
    ```

    **重要提示：** 请将 `/path/to/your/rss-mcp/dist/index.js` 替换为您系统上的正确绝对路径。

添加配置后，**重新启动您的 MCP 客户端**（例如 Cursor）以使更改生效。然后 `rss` 服务器将变为可用状态，您便可以调用 `get_feed` 工具。

## 🛠️ 工具定义

### `get_feed`

从给定的 URL 获取和解析 RSS feed。它支持标准的 RSS/Atom feed 和 RSSHub feed。

#### 输入参数

- `url` (string, required): 要获取的 RSS feed 的 URL。支持两种格式：
    1.  **标准 URL**: `https://rsshub.app/bilibili/user/dynamic/208259`
    2.  **`rsshub://` 协议**: `rsshub://bilibili/user/dynamic/208259` (服务器会自动匹配可用的实例)
- `count` (number, optional): 要检索的 RSS feed 条目数。
    - **默认值**: `1`
    - **检索全部**: `0`

#### 输出

返回一个包含 feed 信息的 JSON 字符串，结构如下：

```json
{
  "title": "bilibili 用户动态",
  "link": "https://space.bilibili.com/208259",
  "description": "bilibili 用户动态",
  "items": [
    {
      "title": "【动态标题】",
      "description": "动态的纯文本内容...",
      "link": "https://t.bilibili.com/1234567890",
      "guid": "https://t.bilibili.com/1234567890",
      "pubDate": "2024-05-20T12:30:00.000Z",
      "author": "作者名",
      "category": ["分类1", "分类2"]
    }
  ]
}
```

## 📜 主要依赖

- [@modelcontextprotocol/sdk](https://www.npmjs.com/package/@modelcontextprotocol/sdk): 用于构建 MCP 服务器。
- [axios](https://www.npmjs.com/package/axios): 用于发送 HTTP 请求。
- [rss-parser](https://www.npmjs.com/package/rss-parser): 用于解析 RSS/Atom feeds。
- [cheerio](https://www.npmjs.com/package/cheerio): 用于解析和处理 HTML 内容。
- [date-fns-tz](https://www.npmjs.com/package/date-fns-tz): 用于处理时区相关的日期格式化。
- [dotenv](https://www.npmjs.com/package/dotenv): 用于从 `.env` 文件加载环境变量。

## 📄 许可证

本项目采用 Apache-2.0 许可证。