class Logger {
    logMode;
    constructor(options = {}) {
        this.logMode = options.logMode || false;
    }
    log(level, message) {
        if (!this.logMode)
            return;
        const timestamp = new Date().toISOString();
        const logMessage = `${timestamp} [${level}] ${message}`;
        console.error(logMessage);
    }
    info(message) {
        this.log("INFO", message);
    }
    warn(message) {
        this.log("WARN", message);
    }
    error(message) {
        this.log("ERROR", message);
    }
    debug(message) {
        this.log("DEBUG", message);
    }
}
// Create default logger instance
export const logger = new Logger({
    logMode: process.argv.includes("--log"),
});
