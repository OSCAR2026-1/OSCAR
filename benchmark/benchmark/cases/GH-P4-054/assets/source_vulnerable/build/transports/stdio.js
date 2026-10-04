import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { logger } from "../utils/logger.js";
/**
 * Stdio Transport Provider implementation
 * Handles MCP communication via standard input/output
 */
export class StdioTransportProvider {
    transport = null;
    /**
     * Connect server to Stdio transport
     * @param server MCP server instance
     */
    async connect(server) {
        logger.info("[Transport] Connecting server using Stdio transport");
        this.transport = new StdioServerTransport();
        await server.connect(this.transport);
        logger.info("[Transport] Stdio transport connected");
    }
    /**
     * Close Stdio transport connection
     */
    async close() {
        if (this.transport) {
            logger.info("[Transport] Closing Stdio transport");
            this.transport.close();
            this.transport = null;
        }
    }
}
