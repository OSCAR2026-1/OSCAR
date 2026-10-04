import { StdioTransportProvider } from "./stdio.js";
import { HttpTransportProvider } from "./http.js";
import { logger } from "../utils/logger.js";
/**
 * Factory function to create transport providers
 * @param config Transport configuration
 * @returns Transport provider instance
 */
export function createTransportProvider(config) {
    logger.info(`[Transport] Creating ${config.type} transport provider`);
    if (config.type === "http") {
        return new HttpTransportProvider(config.host || "localhost", config.port || 3000);
    }
    // Default to Stdio transport
    return new StdioTransportProvider();
}
export * from "./types.js";
