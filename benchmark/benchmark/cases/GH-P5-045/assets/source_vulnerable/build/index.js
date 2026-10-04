#!/usr/bin/env node
/**
 * RSS Reader MCP Server
 *
 * This MCP server provides RSS feed reading capabilities by fetching and parsing RSS feeds from URLs.
 * It implements a single tool 'get_items' that takes an RSS feed URL and returns a list of RSS items
 * with their title, link, description, publication date, and other metadata.
 *
 * The server uses the rss-parser library to handle RSS/Atom feed parsing and axios for HTTP requests.
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema, } from "@modelcontextprotocol/sdk/types.js";
import Parser from 'rss-parser';
import axios from 'axios';
/**
 * Create RSS parser instance with custom fields to extract additional metadata
 */
const parser = new Parser({
    customFields: {
        item: [
            ['media:content', 'mediaContent'],
            ['media:thumbnail', 'mediaThumbnail'],
            ['dc:creator', 'creator'],
            ['content:encoded', 'contentEncoded']
        ]
    }
});
/**
 * Create an MCP server with RSS reading capabilities
 */
const server = new Server({
    name: "rss-reader-server",
    version: "0.1.0",
}, {
    capabilities: {
        tools: {},
    },
});
/**
 * Handler that lists available tools.
 * Exposes a single "get_items" tool that fetches RSS feed items from a given URL.
 */
server.setRequestHandler(ListToolsRequestSchema, async () => {
    return {
        tools: [
            {
                name: "get_items",
                description: "Fetch RSS feed items from a given URL",
                inputSchema: {
                    type: "object",
                    properties: {
                        url: {
                            type: "string",
                            description: "The URL of the RSS feed to fetch"
                        }
                    },
                    required: ["url"]
                }
            }
        ]
    };
});
/**
 * Validates if a URL is properly formatted
 */
function isValidUrl(url) {
    try {
        new URL(url);
        return true;
    }
    catch {
        return false;
    }
}
/**
 * Fetches and parses RSS feed from the given URL
 * Returns a list of RSS items with metadata
 */
async function fetchRssItems(url) {
    // Validate URL format
    if (!isValidUrl(url)) {
        throw new Error(`Invalid URL format: ${url}`);
    }
    try {
        // Fetch the RSS feed with a reasonable timeout and user agent
        const response = await axios.get(url, {
            timeout: 10000, // 10 second timeout
            headers: {
                'User-Agent': 'RSS-Reader-MCP-Server/1.0',
                'Accept': 'application/rss+xml, application/xml, text/xml, application/atom+xml'
            }
        });
        // Parse the RSS feed
        const feed = await parser.parseString(response.data);
        // Transform feed items to our RssItem interface
        const items = feed.items.map((item) => ({
            title: item.title,
            link: item.link,
            description: item.contentSnippet || item.summary,
            pubDate: item.pubDate || item.isoDate,
            author: item.creator || item['dc:creator'] || item.author,
            guid: item.guid,
            categories: item.categories,
            content: item.contentEncoded || item['content:encoded'] || item.content,
            contentSnippet: item.contentSnippet,
            enclosure: item.enclosure ? {
                url: item.enclosure.url,
                type: item.enclosure.type,
                length: String(item.enclosure.length)
            } : undefined
        }));
        return items;
    }
    catch (error) {
        if (axios.isAxiosError(error)) {
            if (error.code === 'ECONNABORTED') {
                throw new Error(`Request timeout while fetching RSS feed from: ${url}`);
            }
            else if (error.response) {
                throw new Error(`HTTP ${error.response.status}: Failed to fetch RSS feed from ${url}`);
            }
            else if (error.request) {
                throw new Error(`Network error: Unable to reach RSS feed at ${url}`);
            }
        }
        if (error instanceof Error) {
            throw new Error(`RSS parsing error: ${error.message}`);
        }
        throw new Error(`Unknown error occurred while fetching RSS feed from: ${url}`);
    }
}
/**
 * Handler for the get_items tool.
 * Fetches RSS feed items from the provided URL and returns them as a formatted list.
 */
server.setRequestHandler(CallToolRequestSchema, async (request) => {
    switch (request.params.name) {
        case "get_items": {
            const url = String(request.params.arguments?.url);
            if (!url) {
                throw new Error("URL parameter is required");
            }
            try {
                const items = await fetchRssItems(url);
                // Format the response as JSON for easy consumption
                const formattedItems = items.map((item, index) => ({
                    index: index + 1,
                    title: item.title || 'No title',
                    link: item.link || 'No link',
                    description: item.description || 'No description',
                    pubDate: item.pubDate || 'No date',
                    author: item.author || 'Unknown author',
                    categories: item.categories || [],
                    hasEnclosure: !!item.enclosure
                }));
                return {
                    content: [{
                            type: "text",
                            text: JSON.stringify({
                                feedUrl: url,
                                itemCount: items.length,
                                items: formattedItems
                            }, null, 2)
                        }]
                };
            }
            catch (error) {
                return {
                    content: [{
                            type: "text",
                            text: `Error fetching RSS feed: ${error instanceof Error ? error.message : 'Unknown error'}`
                        }],
                    isError: true
                };
            }
        }
        default:
            throw new Error(`Unknown tool: ${request.params.name}`);
    }
});
/**
 * Start the server using stdio transport.
 * This allows the server to communicate via standard input/output streams.
 */
async function main() {
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error("RSS Reader MCP server running on stdio");
}
main().catch((error) => {
    console.error("Server error:", error);
    process.exit(1);
});
