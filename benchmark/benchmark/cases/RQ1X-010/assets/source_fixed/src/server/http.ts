// src/server/http.ts
import express from "express";
import cors from "cors";
import { CVMCPServer } from "./index.js";
import { JSONRPCRequest } from "@modelcontextprotocol/sdk/types.js";

const app = express();
const port = process.env.PORT || 4000;

// Middleware
// app.use(cors()); // Comment out if cors is causing issues
app.use(express.json());

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
    const request: JSONRPCRequest = req.body;
    
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
    const request: JSONRPCRequest = {
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
    
    const request: JSONRPCRequest = {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: {
        name,
        arguments: args
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
});

export default app;