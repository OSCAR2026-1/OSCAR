import { fileURLToPath } from 'url';
import path from 'path';
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

import { spawn } from 'child_process';

interface MCPRequest {
  jsonrpc: string;
  id: number;
  method: string;
  params: any;
}

interface MCPResponse {
  jsonrpc: string;
  id: number;
  result?: any;
  error?: any;
}

class MCPTestClient {
  private serverProcess: any;
  private requestId: number = 1;

  async startServer() {
    const serverPath = path.join(__dirname, '..', 'dist', 'server', 'index.js');
    this.serverProcess = spawn('node', [serverPath], {
      stdio: ['pipe', 'pipe', 'pipe']
    });

    let responseBuffer = '';

    this.serverProcess.stdout.on('data', (data: Buffer) => {
      responseBuffer += data.toString();
    });

    this.serverProcess.stderr.on('data', (data: Buffer) => {
      // Optionally handle errors
    });

    await new Promise(resolve => setTimeout(resolve, 1000));
  }

  async sendRequest(method: string, params: any = {}) {
    const request: MCPRequest = {
      jsonrpc: '2.0',
      id: this.requestId++,
      method,
      params
    };

    console.log('📨 Sending Request:', JSON.stringify(request, null, 2));
    this.serverProcess.stdin.write(JSON.stringify(request) + '\n');

    await new Promise(resolve => setTimeout(resolve, 2000));
  }

  async cleanup() {
    if (this.serverProcess) {
      this.serverProcess.kill();
    }
  }
}

// Test scenarios
async function runTests() {
  const client = new MCPTestClient();

  try {
    console.log('🚀 Starting MCP Server...');
    await client.startServer();

    console.log('\n1️⃣ Testing Initialization...');
    await client.sendRequest('initialize', {
      protocolVersion: '2024-11-05',
      capabilities: {},
      clientInfo: {
        name: 'test-client',
        version: '1.0.0'
      }
    });

    console.log('\n2️⃣ Testing List Tools...');
    await client.sendRequest('tools/list');

    console.log('\n3️⃣ Testing CV Query...');
    await client.sendRequest('tools/call', {
      name: 'query_cv',
      arguments: {
        question: 'What was my last position?'
      }
    });

    console.log('\n4️⃣ Testing CV Summary...');
    await client.sendRequest('tools/call', {
      name: 'get_cv_summary',
      arguments: {}
    });

    console.log('\n5️⃣ Testing Skills Query...');
    await client.sendRequest('tools/call', {
      name: 'query_cv',
      arguments: {
        question: 'What skills do I have?'
      }
    });

    // Email test commented out to avoid sending real emails
    // console.log('\n6️⃣ Testing Email (Dry Run)...');
    // await client.sendRequest('tools/call', {
    //   name: 'send_email',
    //   arguments: {
    //     recipient: 'test@example.com',
    //     subject: 'Test Email',
    //     body: 'This is a test email from the MCP server.'
    //   }
    // });

  } catch (error) {
    console.error('❌ Test failed:', error);
  } finally {
    await client.cleanup();
    console.log('\n✅ Tests completed');
  }
}

if (require.main === module) {
  runTests().catch(console.error);
}

export { MCPTestClient };

