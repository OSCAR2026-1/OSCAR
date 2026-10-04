# mammoth-mcp

[![NPM version](https://img.shields.io/npm/v/mammoth-mcp.svg?style=flat)](https://npmjs.com/package/mammoth-mcp)
[![NPM downloads](http://img.shields.io/npm/dm/mammoth-mcp.svg?style=flat)](https://npmjs.com/package/mammoth-mcp)

A Model Context Protocol (MCP) server for converting DOCX files to HTML using [mammoth.js](https://github.com/mwilliamson/mammoth.js).

## Features

- **convert_docx_to_html**: Convert DOCX files to clean HTML with advanced styling options
- **convert_docx_to_html_with_images**: Convert DOCX files to HTML with embedded base64 images
- **extract_raw_text**: Extract plain text content from DOCX files
- **convert_docx_to_markdown**: Convert DOCX files to Markdown format

## Installation

```bash
$ pnpm install
```

## Development

```bash
$ npm run dev
$ npm run build
```

## Usage

### Configure MCP Client

Add the server to your MCP client configuration (e.g., Claude Desktop).

The configuration file is located at:
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

#### Option 1: Using npx (Recommended)

This will automatically install and run the latest version:

```json
{
  "mcpServers": {
    "mammoth": {
      "command": "npx",
      "args": ["-y", "mammoth-mcp"]
    }
  }
}
```

#### Option 2: Using local installation

If you've cloned the repository locally:

```json
{
  "mcpServers": {
    "mammoth": {
      "command": "node",
      "args": ["/absolute/path/to/mammoth-mcp/dist/esm/index.js"]
    }
  }
}
```

After updating the configuration, restart Claude Desktop for the changes to take effect.

### Available Tools

#### convert_docx_to_html

Convert a DOCX file to HTML.

**Parameters:**
- `filePath` (string, required): Absolute path to the DOCX file
- `styleMap` (string, optional): Custom style map to control Word styles to HTML conversion
- `ignoreEmptyParagraphs` (boolean, optional): Whether to ignore empty paragraphs (default: true)
- `idPrefix` (string, optional): Prefix for generated IDs (bookmarks, footnotes, endnotes)
- `includeDefaultStyleMap` (boolean, optional): Whether to include default style map (default: true)
- `includeEmbeddedStyleMap` (boolean, optional): Whether to include embedded style map from document (default: true)

**Example:**
```typescript
{
  "filePath": "/path/to/document.docx",
  "styleMap": "p[style-name='Section Title'] => h1:fresh\nb[style-name='Emphasis'] => em",
  "ignoreEmptyParagraphs": false,
  "idPrefix": "doc-"
}
```

#### convert_docx_to_html_with_images

Convert a DOCX file to HTML with images embedded as base64 data URIs.

**Parameters:**
- `filePath` (string, required): Absolute path to the DOCX file
- `styleMap` (string, optional): Custom style map to control Word styles to HTML conversion
- `ignoreEmptyParagraphs` (boolean, optional): Whether to ignore empty paragraphs (default: true)
- `idPrefix` (string, optional): Prefix for generated IDs (bookmarks, footnotes, endnotes)
- `includeDefaultStyleMap` (boolean, optional): Whether to include default style map (default: true)
- `includeEmbeddedStyleMap` (boolean, optional): Whether to include embedded style map from document (default: true)

**Example:**
```typescript
{
  "filePath": "/path/to/document-with-images.docx",
  "styleMap": "p[style-name='Code'] => pre:separator('\\n')"
}
```

#### extract_raw_text

Extract raw text from a DOCX file, ignoring all formatting. Useful for indexing, search, or text analysis.

**Parameters:**
- `filePath` (string, required): Absolute path to the DOCX file

**Example:**
```typescript
{
  "filePath": "/path/to/document.docx"
}
```

#### convert_docx_to_markdown

Convert a DOCX file to Markdown format. Note: This feature is deprecated by mammoth.js but remains functional.

**Parameters:**
- `filePath` (string, required): Absolute path to the DOCX file
- `styleMap` (string, optional): Custom style map to control Word styles to Markdown conversion
- `ignoreEmptyParagraphs` (boolean, optional): Whether to ignore empty paragraphs (default: true)
- `idPrefix` (string, optional): Prefix for generated IDs (bookmarks, footnotes, endnotes)
- `includeDefaultStyleMap` (boolean, optional): Whether to include default style map (default: true)
- `includeEmbeddedStyleMap` (boolean, optional): Whether to include embedded style map from document (default: true)

**Example:**
```typescript
{
  "filePath": "/path/to/document.docx",
  "styleMap": "p[style-name='Heading 1'] => # "
}
```

## How It Works

This MCP server uses mammoth.js to convert DOCX documents to clean, semantic HTML or Markdown. The conversion preserves:

- Headings
- Paragraphs
- Lists
- Tables
- Bold/italic/underline formatting
- Images (when using the `with_images` variant)
- Custom style mappings (via styleMap parameter)

### Style Maps

Style maps allow you to control how Word styles are converted to HTML/Markdown. Each line in a style map represents a mapping from a Word style to an HTML/Markdown element.

**Example style map:**
```
p[style-name='Section Title'] => h1:fresh
p[style-name='Subsection Title'] => h2:fresh
p[style-name='Code'] => pre:separator('\n')
```

For more information on style maps, see the [mammoth.js documentation](https://github.com/mwilliamson/mammoth.js#writing-style-maps).

## LICENSE

MIT
