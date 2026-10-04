const nodemailer = require("nodemailer");
const { McpServer } = require("@modelcontextprotocol/sdk/server/mcp.js");
const {
	StdioServerTransport,
} = require("@modelcontextprotocol/sdk/server/stdio.js");
const { z } = require("zod");

const email = process.env.GOOGLE_EMAIL;
const appPassword = process.env.GOOGLE_APP_PASSWORD;

if (!email | !appPassword) {
	console.error(
		"No email or password provided. Please set environment variable correctly",
	);
	process.exit(1);
}

const transporter = nodemailer.createTransport({
	service: "gmail",
	auth: {
		user: email,
		pass: appPassword,
	},
});

const server = new McpServer({
	name: "nodemailer-mcp",
	version: "1.0.0",
});

server.registerTool(
	"send_email",
	{
		title: "Send Email",
		description: "send email using gmail",
		inputSchema: {
			from: z.string().describe("The e-mail address of the sender").optional(),
			to: z.string().email().array().describe("Recipient email address"),
			subject: z.string().describe("Email subject line"),
			text: z.string().describe("The plaintext version of the message"),
			html: z.string().describe(" The HTML version of the message"),
		},
	},
	async ({ from, to, subject, text, html }) => {
		if (!to) {
			throw new Error("to argument must be provided.");
		}

		try {
			const response = await transporter.sendMail({
				from,
				to,
				subject,
				text,
				html,
			});

			return {
				content: [
					{
						type: "text",
						text: `Email sent successfully! ${JSON.stringify(response.response)}`,
					},
				],
			};
		} catch (error) {
			throw new Error(`Email failed to send: ${JSON.stringify(error)}`);
		}
	},
);

// Start server
async function startServer() {
	try {
		const transport = new StdioServerTransport();
		await server.connect(transport);
		console.error("🚀 Local Machine MCP Server running");
	} catch (error) {
		console.error("❌ Failed to start:", error);
		process.exit(1);
	}
}

startServer();
