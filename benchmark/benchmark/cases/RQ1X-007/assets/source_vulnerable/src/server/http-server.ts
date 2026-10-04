// src/server/http-server.ts
import express from "express";
import { CVMCPServer } from "./index.js";

const app = express();
const port = process.env.PORT || 4000;

// Middleware
app.use(express.json());

// Add basic CORS headers manually if needed
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
  
  if (req.method === 'OPTIONS') {
    res.sendStatus(200);
  } else {
    next();
  }
});

// Create MCP server instance
const mcpServer = new CVMCPServer();

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Main MCP endpoint
app.post("/mcp", async (req, res) => {
  try {
    // Validate JSON-RPC request structure
    const request = req.body;
    
    if (!request.jsonrpc || request.jsonrpc !== "2.0") {
      return res.status(400).json({
        jsonrpc: "2.0",
        id: request.id || null,
        error: {
          code: -32600,
          message: "Invalid Request - missing or invalid jsonrpc version"
        }
      });
    }

    if (!request.method) {
      return res.status(400).json({
        jsonrpc: "2.0",
        id: request.id || null,
        error: {
          code: -32600,
          message: "Invalid Request - missing method"
        }
      });
    }

    // Handle the request
    const result = await mcpServer.handleJsonRpc(request);
    res.json(result);

  } catch (error) {
    console.error('MCP request error:', error);
    
    let message = "Internal server error";
    if (error instanceof Error) {
      message = error.message;
    }
    
    res.status(500).json({
      jsonrpc: "2.0",
      id: req.body?.id || null,
      error: {
        code: -32603,
        message: message
      }
    });
  }
});

// Example endpoints for testing
app.get('/tools', async (req, res) => {
  try {
    const request = {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/list",
      params: {}
    };
    
    const result = await mcpServer.handleJsonRpc(request);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error instanceof Error ? error.message : 'Unknown error' });
  }
});

app.post('/call-tool', async (req, res) => {
  try {
    const { name, arguments: args } = req.body;
    
    const request = {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: {
        name,
        arguments: args || {}
      }
    };
    
    const result = await mcpServer.handleJsonRpc(request);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error instanceof Error ? error.message : 'Unknown error' });
  }
});

// Start server
app.listen(port, () => {
  console.log(`🚀 MCP HTTP server listening at http://localhost:${port}`);
  console.log(`📚 Available endpoints:`);
  console.log(`   POST /mcp           - Main MCP JSON-RPC endpoint`);
  console.log(`   GET  /health        - Health check`);
  console.log(`   GET  /tools         - List available tools`);
  console.log(`   POST /call-tool     - Call a tool (simplified interface)`);
  console.log(`\n📋 Example usage:`);
  console.log(`   curl -X POST http://localhost:${port}/call-tool \\`);
  console.log(`     -H "Content-Type: application/json" \\`);
  console.log(`     -d '{"name": "get_cv_summary", "arguments": {}}'`);
});

export default app;