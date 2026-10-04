import { parseTransportConfig, isDebugMode } from "./args.js";
import { TransportConfig } from "../transports/types.js";

/**
 * Get application configuration
 */
export function getConfig(): {
  transport: TransportConfig;
  debug: boolean;
} {
  return {
    transport: parseTransportConfig(),
    debug: isDebugMode(),
  };
}

export { isDebugMode };
