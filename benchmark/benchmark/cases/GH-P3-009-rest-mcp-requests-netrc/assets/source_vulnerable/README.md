# RestMCP - AI-Powered REST API Client

RestMCP is a simple yet powerful tool that lets you interact with any REST API using natural language. It combines the Model Context Protocol (MCP) with Google's Gemini AI to understand your requests and automatically make the appropriate API calls.

## Features

- 🤖 **Natural Language Interface**: Ask questions in plain English
- 🔌 **Universal REST API Support**: Works with any REST API endpoint
- 🧠 **AI-Powered**: Uses Google Gemini to understand and execute requests
- 🛠️ **Flexible**: Supports all HTTP methods (GET, POST, PUT, DELETE, PATCH)
- 📊 **Smart Formatting**: Automatically formats JSON responses
- ⚡ **Fast Setup**: Get started in minutes

## Quick Start

### Prerequisites

- Python 3.8 or higher
- Google AI API key (get it from [Google AI Studio](https://aistudio.google.com/))

### Installation

1. Clone this repository:
```bash
git clone https://github.com/lumenghe/rest-mcp.git
cd restmcp
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Set your Google AI API key:
```bash
export GEMINI_API_KEY="your-api-key-here"
```

### Usage

#### Basic Usage

Run with a question:
```bash
python client.py --question "Get user data from https://jsonplaceholder.typicode.com/users/1"
```

Or run interactively:
```bash
python client.py
# Enter your question when prompted
```

#### Example Queries

**Simple GET request:**
```bash
python client.py -q "Fetch data from https://api.github.com/users/octocat"
```

**POST request with data:**
```bash
python client.py -q "Post this data {\"title\": \"Hello\", \"body\": \"World\"} to https://jsonplaceholder.typicode.com/posts"
```

**API with authentication:**
```bash
python client.py -q "Get my repositories from GitHub API using bearer token abc123"
```

**Complex queries:**
```bash
python client.py -q "Search for 'python' repositories on GitHub API and limit to 5 results"
```

### Command Line Options

- `--question, -q`: Your question/request for the AI
- `--model, -m`: AI model to use (default: gemini-2.0-flash-exp)
- `--temperature, -t`: AI temperature setting (default: 0.1)

### Example Usage Scenarios

#### 1. API Testing
```bash
python client.py -q "Test if https://httpbin.org/get is responding"
```

#### 2. Data Fetching
```bash
python client.py -q "Get weather data from OpenWeatherMap API for London"
```

#### 3. CRUD Operations
```bash
python client.py -q "Create a new post with title 'Test' and body 'Content' on JSONPlaceholder API"
```

#### 4. API Exploration
```bash
python client.py -q "What endpoints are available at https://api.github.com"
```

## How It Works

1. **You ask a question** in natural language about what API call you want to make
2. **Gemini AI analyzes** your request and determines the appropriate REST API call
3. **MCP server executes** the HTTP request with the right parameters
4. **Results are formatted** and displayed in a readable format

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   client.py     │────│   Gemini AI     │────│   server.py     │
│  (Your Query)   │    │ (Understanding) │    │  (API Calls)    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                                       │
                                                       ▼
                                               ┌─────────────────┐
                                               │   REST APIs     │
                                               │  (Any endpoint) │
                                               └─────────────────┘
```

## Configuration

### Environment Variables

- `GEMINI_API_KEY`: Your Google AI API key (required)

### Customization

You can modify `server.py` to add custom headers, authentication, or preprocessing logic for specific APIs you frequently use.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## License

MIT License - see LICENSE file for details.

## Troubleshooting

### Common Issues

**"GEMINI_API_KEY not set"**
- Make sure you've exported your API key: `export GEMINI_API_KEY="your-key"`

**"Error connecting to MCP server"**
- Ensure `server.py` is in the same directory as `client.py`
- Check that all dependencies are installed: `pip install -r requirements.txt`

**"Request failed"**
- Check your internet connection
- Verify the API endpoint URL is correct
- Some APIs require authentication or specific headers

### Getting Help

- Check existing issues on GitHub
- Create a new issue with details about your problem
- Include the full error message and your command

## Examples Repository

Check out [examples repository](https://github.com/lumenghe) for more advanced usage patterns and real-world scenarios.

---

**RestMCP** - Making REST APIs accessible through natural language ✨
