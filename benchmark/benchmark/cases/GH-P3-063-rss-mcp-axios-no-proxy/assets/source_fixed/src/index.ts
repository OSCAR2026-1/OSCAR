import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import axios from 'axios';
import Parser from 'rss-parser';
import * as cheerio from 'cheerio';
import { formatInTimeZone } from 'date-fns-tz';
import 'dotenv/config';

// Add a global error handler for uncaught synchronous exceptions
process.on('uncaughtException', (error) => {
    console.error('Uncaught Exception:', error);
    process.exit(1); // Exit the process to prevent an unstable state
});

// Add a global error handler for uncaught promise rejections
process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
    // Optionally, you can exit the process to prevent an unstable state
    // process.exit(1);
});

// Load instances from environment variable first, if available
const priorityInstance = process.env.PRIORITY_RSSHUB_INSTANCE;

let RSSHUB_INSTANCES = [
    "https://rsshub.app",
    "https://rsshub.rssforever.com",
    "https://rsshub.feeded.xyz",
    "https://hub.slarker.me",
    "https://rsshub.liumingye.cn",
    "https://rsshub-instance.zeabur.app",
    "https://rss.fatpandac.com",
    "https://rsshub.pseudoyu.com",
    "https://rsshub.friesport.ac.cn",
    "https://rsshub.atgw.io",
    "https://rsshub.rss.tips",
    "https://rsshub.mubibai.com",
    "https://rsshub.ktachibana.party",
    "https://rsshub.woodland.cafe",
    "https://rsshub.aierliz.xyz",
    "http://localhost:1200"
];

// If a priority instance is set, add it to the front of the list
if (priorityInstance) {
    // Remove it from the list if it already exists to avoid duplicates
    RSSHUB_INSTANCES = RSSHUB_INSTANCES.filter(url => url !== priorityInstance);
    RSSHUB_INSTANCES.unshift(priorityInstance);
}


function convertRsshubUrl(url: string): string[] {
    if (url.startsWith('rsshub://')) {
        const path = url.substring(9);
        return RSSHUB_INSTANCES.map(instance => `${instance}/${path}`);
    }

    for (const instance of RSSHUB_INSTANCES) {
        if (url.startsWith(instance)) {
            const path = url.substring(instance.length).replace(/^\//, '');
            return RSSHUB_INSTANCES.map(inst => `${inst}/${path}`);
        }
    }

    return [url];
}

interface RssFeed {
    title?: string;
    link?: string;
    description?: string;
    items: RssItem[];
}

interface RssItem {
    title?: string;
    description?: string;
    link?: string;
    guid?: string;
    pubDate?: string;
    author?: string;
    category?: string[];
}


const server = new McpServer({
    name: "rss",
    version: "1.0.0"
});

export async function get_feed(params: { url: string, count?: number }): Promise<RssFeed> {
    try {
        let currentUrl = params.url;

        if (typeof currentUrl !== 'string') {
            throw new Error("URL must be a string.");
        }

        // Handle JSON string input
        try {
            const parsed = JSON.parse(currentUrl);
            if (parsed && typeof parsed === 'object' && parsed.url) {
                currentUrl = parsed.url;
            }
        } catch (e) {
            // Not a JSON string, use as is
        }

        if (!currentUrl.includes('://')) {
            currentUrl = `rsshub://${currentUrl}`;
        }

        const urls = convertRsshubUrl(currentUrl);

        const userAgents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0"
        ];

        const headers = {
            "User-Agent": userAgents[Math.floor(Math.random() * userAgents.length)],
            "Accept": "application/rss+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Accept-Encoding": "gzip, deflate, br"
        };

        let lastError: Error | null = null;

        for (const u of urls) {
            try {
                console.error(`Attempting to fetch from ${u}...`);
                const response = await axios.get(u, {
                    headers,
                    timeout: 15000, // Reduced timeout to fail faster
                    maxRedirects: 3,
                    validateStatus: (status) => status >= 200 && status < 300,
                    responseType: 'text', // Ensure response is treated as text
                });

                if (!response.data) {
                    throw new Error("Empty response data");
                }

                const parser = new Parser({
                    timeout: 10000, // Parser timeout
                    maxRedirects: 3,
                });
                const feed = await parser.parseString(response.data);

                if (!feed || !feed.items) {
                    throw new Error("Cannot parse RSS feed, feed or feed.items is undefined.");
                }

                const feedInfo: RssFeed = {
                    title: feed.title,
                    link: feed.link,
                    description: feed.description,
                    items: []
                };

                const itemsToProcess = params.count === 0 ? feed.items : feed.items.slice(0, params.count ?? 1);

                for (const item of itemsToProcess) {
                    let description = '';
                    if (item.content) {
                        const $ = cheerio.load(item.content);
                        description = $.text().replace(/\s+/g, ' ').trim();
                    } else if (item.contentSnippet) {
                        description = item.contentSnippet;
                    }

                    let pubDate: string | undefined = undefined;
                    if (item.pubDate) {
                        try {
                            pubDate = formatInTimeZone(new Date(item.pubDate), 'UTC', "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
                        } catch (e) {
                            console.error(`Date parse error: ${e}`);
                            pubDate = item.pubDate;
                        }
                    }

                    const feedItem: RssItem = {
                        title: item.title,
                        description: description,
                        link: item.link,
                        guid: item.guid || item.link,
                        pubDate: pubDate,
                        author: item.creator,
                        category: item.categories
                    };
                    feedInfo.items.push(feedItem);
                }

                return feedInfo;

            } catch (error) {
                lastError = error as Error;
                const errorMsg = error instanceof Error ? error.message : String(error);
                console.error(`Attempt to access ${u} failed: ${errorMsg}`);

                // Add a small delay between retries to avoid overwhelming servers
                if (urls.indexOf(u) < urls.length - 1) {
                    await new Promise(resolve => setTimeout(resolve, 100));
                }
                continue;
            }
        }

        const finalError = lastError?.message || 'Unknown error';
        console.error(`All RSSHub instances failed. Last error: ${finalError}`);
        throw new Error(`All RSSHub instances failed: ${finalError}`);
    } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'An unknown error occurred';
        console.error(`Unexpected error in get_feed: ${errorMessage}`);
        throw error; // Re-throw the error to be caught by the tool handler
    }
}

// Register the get_feed tool using the modern McpServer API
server.registerTool(
    "get_feed",
    {
        description: "Get RSS feed from any URL, including RSSHub feeds.",
        inputSchema: {
            url: z.string().describe("URL of the RSS feed. For RSSHub, you can use 'rsshub://' protocol (e.g., 'rsshub://bilibili/user/dynamic/208259')."),
            count: z.number().optional().describe("Number of RSS feed items to retrieve. Defaults to 1. Set to 0 to retrieve all items.")
        }
    },
    async ({ url, count }) => {
        try {
            console.error(`Tool called with URL: ${url} and count: ${count}`);
            const feedResult = await get_feed({ url, count });
            console.error(`Tool completed successfully for URL: ${url}`);
            return {
                content: [{ type: "text", text: JSON.stringify(feedResult, null, 2) }]
            };
        } catch (error) {
            const errorMessage = error instanceof Error ? error.message : 'An unknown error occurred';
            console.error(`Tool error for URL ${url}: ${errorMessage}`);

            // Always return a valid response, never throw
            return {
                content: [{ type: "text", text: `Error fetching RSS feed: ${errorMessage}` }],
                isError: true
            };
        }
    }
);


async function run() {
    try {
        const transport = new StdioServerTransport();

        // Add error handling for transport
        transport.onerror = (error) => {
            console.error('Transport error:', error);
        };

        transport.onclose = () => {
            console.error('Transport closed');
        };

        await server.connect(transport);
        console.error('RSS MCP Server started via stdio');

        // Keep the process alive and handle graceful shutdown
        const shutdown = () => {
            console.error('Shutting down RSS MCP Server...');
            transport.close();
            process.exit(0);
        };

        process.on('SIGINT', shutdown);
        process.on('SIGTERM', shutdown);
        process.on('SIGQUIT', shutdown);

    } catch (error) {
        console.error('Failed to start server:', error);
        process.exit(1);
    }
}

// Start the server if this file is run directly
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);

if (process.argv[1] === __filename) {
    run();
}