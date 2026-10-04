import { parseTransportConfig, isDebugMode } from "./args.js";
/**
 * Get application configuration
 */
export function getConfig() {
    return {
        transport: parseTransportConfig(),
        debug: isDebugMode(),
    };
}
export { isDebugMode };
