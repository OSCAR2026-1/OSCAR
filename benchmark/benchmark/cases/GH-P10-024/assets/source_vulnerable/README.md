# Nodemailer MCP Server

MCP server for sending emails via Gmail using Claude.

## Setup

1. Install dependencies:
```bash
npm install
```

2. Create Gmail App Password:
   - Go to [Google Account Settings](https://myaccount.google.com/)
   - Security → 2-Step Verification → App passwords
   - Generate password

3. Configure Claude Desktop in `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "mailer": {
      "command": "node",
      "args": ["path/to/nodemailer-mcp/index.js"],
      "env": {
        "GOOGLE_EMAIL": "your-email@gmail.com",
        "GOOGLE_APP_PASSWORD": "your-16-digit-app-password"
      }
    }
  }
}
```

4. Restart Claude Desktop

## Usage

Ask Claude to send emails:
```
"Send email to user@example.com with subject 'Hello' and message 'Hi there!'"
```

## Dependencies

- nodemailer
- @modelcontextprotocol/sdk
- zod