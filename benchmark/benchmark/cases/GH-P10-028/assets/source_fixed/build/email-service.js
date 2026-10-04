import nodemailer from 'nodemailer';
/**
 * Email service for sending emails via SMTP
 */
export class EmailService {
    transporter;
    fromEmail;
    debug;
    /**
     * Create a new EmailService instance
     * @param config SMTP configuration
     */
    constructor(config) {
        this.debug = config.debug || false;
        if (this.debug) {
            console.error('[Setup] Initializing email service...');
        }
        this.fromEmail = config.auth.user;
        this.transporter = nodemailer.createTransport({
            host: config.host,
            port: config.port,
            secure: config.secure, // true for 465, false for other ports
            auth: {
                user: config.auth.user,
                pass: config.auth.pass,
            },
        });
    }
    /**
     * Send an email
     * @param message Email message to send
     * @returns Promise resolving to the send result
     */
    async sendEmail(message) {
        if (this.debug) {
            console.error(`[Email] Sending email to: ${message.to}`);
        }
        try {
            const info = await this.transporter.sendMail({
                from: this.fromEmail,
                to: message.to,
                cc: message.cc,
                bcc: message.bcc,
                subject: message.subject,
                text: !message.isHtml ? message.body : undefined,
                html: message.isHtml ? message.body : undefined,
            });
            if (this.debug) {
                console.error(`[Email] Email sent successfully: ${info.messageId}`);
            }
            return { success: true, info };
        }
        catch (error) {
            console.error(`[Error] Failed to send email: ${error instanceof Error ? error.message : String(error)}`);
            throw error;
        }
    }
    /**
     * Verify SMTP connection
     * @returns Promise resolving to true if connection is successful
     */
    async verifyConnection() {
        if (this.debug) {
            console.error('[Setup] Verifying SMTP connection...');
        }
        try {
            await this.transporter.verify();
            if (this.debug) {
                console.error('[Setup] SMTP connection verified successfully');
            }
            return true;
        }
        catch (error) {
            console.error(`[Error] SMTP connection verification failed: ${error instanceof Error ? error.message : String(error)}`);
            throw error;
        }
    }
}
