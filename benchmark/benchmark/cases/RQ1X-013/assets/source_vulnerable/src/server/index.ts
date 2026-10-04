// src/server/index.ts
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
  JSONRPCRequest,
  JSONRPCResponse,
} from "@modelcontextprotocol/sdk/types.js";
import fs from 'fs/promises';
import path from 'path';
import nodemailer from 'nodemailer';

interface CVData {
  personalInfo: {
    name: string;
    email: string;
    phone: string;
    location: string;
    linkedin?: string;
    github?: string;
  };
  experience: Array<{
    position: string;
    company: string;
    duration: string;
    description: string;
    location?: string;
  }>;
  education: Array<{
    degree: string;
    institution: string;
    year: string;
    location?: string;
    description?: string;
  }>;
  projects?: Array<{
    name: string;
    description: string;
    tech: string[];
  }>;
  skills: {
    programmingLanguages: string[];
    frameworksAndTech: string[];
    expertise: string[];
    additionalSkills: string[];
  };
  certifications?: string[];
  activities?: string[];
  careerObjective?: string;
}

class CVMCPServer {
  private server: Server;
  private cvData: CVData | null = null;
  private emailTransporter: nodemailer.Transporter;

  constructor() {
    this.server = new Server(
      {
        name: "cv-email-server",
        version: "0.1.0",
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    // Initialize email transporter
    this.emailTransporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    this.setupToolHandlers();
    this.loadCVData();
  }

  private async loadCVData() {
    try {
      const cvPath = path.join(process.cwd(), 'data', 'cv.json');
      const cvContent = await fs.readFile(cvPath, 'utf-8');
      this.cvData = JSON.parse(cvContent);
    } catch (error) {
      console.error('Failed to load CV data:', error);
      // Create sample CV data if file doesn't exist
      this.cvData = {
        personalInfo: {
          name: "John Doe",
          email: "john.doe@example.com",
          phone: "+1-555-0123",
          location: "San Francisco, CA"
        },
        experience: [
          {
            position: "Senior Software Engineer",
            company: "Tech Corp",
            duration: "2022 - Present",
            description: "Led development of microservices architecture, mentored junior developers"
          },
          {
            position: "Software Engineer",
            company: "StartupXYZ",
            duration: "2020 - 2022",
            description: "Built full-stack applications using React and Node.js"
          }
        ],
        education: [
          {
            degree: "Bachelor of Science in Computer Science",
            institution: "University of California",
            year: "2020"
          }
        ],
        skills: ["JavaScript", "TypeScript", "React", "Node.js", "Python", "AWS"]
      };
    }
  }

  private setupToolHandlers() {
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      return {
        tools: [
          {
            name: "query_cv",
            description: "Query information about the CV/resume",
            inputSchema: {
              type: "object",
              properties: {
                question: {
                  type: "string",
                  description: "Question about the CV (e.g., 'What was my last position?', 'What skills do I have?')",
                },
              },
              required: ["question"],
            },
          },
          {
            name: "send_email",
            description: "Send an email notification",
            inputSchema: {
              type: "object",
              properties: {
                recipient: {
                  type: "string",
                  description: "Email recipient address",
                },
                subject: {
                  type: "string",
                  description: "Email subject",
                },
                body: {
                  type: "string",
                  description: "Email body content",
                },
              },
              required: ["recipient", "subject", "body"],
            },
          },
          {
            name: "get_cv_summary",
            description: "Get a complete summary of the CV",
            inputSchema: {
              type: "object",
              properties: {},
            },
          },
        ],
      };
    });

    this.server.setRequestHandler(CallToolRequestSchema, async (request): Promise<{ content: { type: string; text: string; }[]; }> => {
      const { name, arguments: args } = request.params;

      if (!args) {
        return {
          content: [
            {
              type: "text",
              text: "No arguments provided.",
            },
          ],
        };
      }

      try {
        switch (name) {
          case "query_cv":
            return await this.handleCVQuery(args.question as string);

          case "send_email":
            return await this.handleSendEmail(
              args.recipient as string,
              args.subject as string,
              args.body as string
            );

          case "get_cv_summary":
            return await this.handleGetCVSummary();

          default:
            throw new McpError(
              ErrorCode.MethodNotFound,
              `Unknown tool: ${name}`
            );
        }
      } catch (error) {
        let msg = "Unknown error";
        if (error instanceof Error) {
          msg = error.message;
        }
        throw new McpError(
          ErrorCode.InternalError,
          `Error executing tool ${name}: ${msg}`
        );
      }
    });
  }

  private async handleCVQuery(question: string) {
    if (!this.cvData) {
      throw new Error("CV data not loaded");
    }

    const lowerQuestion = question.toLowerCase();
    let response = "";

    // Parse different types of questions
    if (lowerQuestion.includes("last position") || lowerQuestion.includes("current role") || lowerQuestion.includes("latest job")) {
      const lastJob = this.cvData.experience[0];
      response = `Your last/current position is ${lastJob.position} at ${lastJob.company} (${lastJob.duration}). ${lastJob.description}`;
    
    } else if (lowerQuestion.includes("skill") || lowerQuestion.includes("technology")) {
      response = `Your skills include: ${[
        ...this.cvData.skills.programmingLanguages,
        ...this.cvData.skills.frameworksAndTech,
        ...this.cvData.skills.expertise,
        ...this.cvData.skills.additionalSkills,
      ].join(", ")}`;
    
    } else if (lowerQuestion.includes("experience") || lowerQuestion.includes("work history")) {
      response = "Your work experience:\n" + this.cvData.experience.map(exp => 
        `• ${exp.position} at ${exp.company} (${exp.duration}) - ${exp.description}`
      ).join("\n");
    
    } else if (lowerQuestion.includes("education") || lowerQuestion.includes("degree")) {
      response = "Your education:\n" + this.cvData.education.map(edu => 
        `• ${edu.degree} from ${edu.institution} (${edu.year})`
      ).join("\n");
    
    } else if (lowerQuestion.includes("contact") || lowerQuestion.includes("email") || lowerQuestion.includes("phone")) {
      const info = this.cvData.personalInfo;
      response = `Contact information: ${info.name}, Email: ${info.email}, Phone: ${info.phone}, Location: ${info.location}`;
    
    } else if (lowerQuestion.includes("name")) {
      response = `Your name is ${this.cvData.personalInfo.name}`;
    
    } else {
      // General search through all CV data
      response = this.searchCVContent(question);
    }

    return {
      content: [
        {
          type: "text",
          text: response,
        },
      ],
    };
  }

  private searchCVContent(query: string): string {
    if (!this.cvData) return "CV data not available";
    
    const searchTerms = query.toLowerCase().split(' ');
    const allContent = JSON.stringify(this.cvData).toLowerCase();

    const relevantSections = [];

    if (searchTerms.some(term => allContent.includes(term))) {
      if (searchTerms.some(term => JSON.stringify(this.cvData!.experience).toLowerCase().includes(term))) {
        relevantSections.push("Experience: " + this.cvData!.experience.map(exp =>
          `${exp.position} at ${exp.company}`).join(", "));
      }
      if (searchTerms.some(term => JSON.stringify(this.cvData!.skills).toLowerCase().includes(term))) {
        relevantSections.push("Skills: " + this.cvData!.skills.join(", "));
      }
      if (searchTerms.some(term => JSON.stringify(this.cvData!.education).toLowerCase().includes(term))) {
        relevantSections.push("Education: " + this.cvData!.education.map(edu => edu.degree).join(", "));
      }
    }

    return relevantSections.length > 0
      ? `Based on your query, here's what I found:\n${relevantSections.join("\n")}`
      : "I couldn't find specific information related to your query. Try asking about experience, skills, education, or contact information.";
  }

  private async handleSendEmail(recipient: string, subject: string, body: string) {
    try {
      const mailOptions = {
        from: process.env.EMAIL_USER,
        to: recipient,
        subject: subject,
        text: body,
        html: `<div style="font-family: Arial, sans-serif;"><p>${body.replace(/\n/g, '<br>')}</p></div>`,
      };

      const info = await this.emailTransporter.sendMail(mailOptions);
      
      return {
        content: [
          {
            type: "text",
            text: `Email sent successfully to ${recipient}. Message ID: ${info.messageId}`,
          },
        ],
      };
    } catch (error) {
      let msg = "Unknown error";
      if (error instanceof Error) {
        msg = error.message;
      } else {
        msg = String(error);
      }
      throw new Error(`Failed to send email: ${msg}`);
    }
  }

  private async handleGetCVSummary() {
    if (!this.cvData) {
      throw new Error("CV data not loaded");
    }

    const summary = `
**${this.cvData.personalInfo.name}**
📧 ${this.cvData.personalInfo.email} | 📱 ${this.cvData.personalInfo.phone}
📍 ${this.cvData.personalInfo.location}

**Experience:**
${this.cvData.experience.map(exp => `• ${exp.position} at ${exp.company} (${exp.duration})\n  ${exp.description}`).join('\n')}

**Education:**
${this.cvData.education.map(edu => `• ${edu.degree}, ${edu.institution} (${edu.year})`).join('\n')}

**Skills:**
${this.cvData.skills.join(' • ')}
    `.trim();

    return {
      content: [
        {
          type: "text",
          text: summary,
        },
      ],
    };
  }

  // Proper HTTP JSON-RPC handler
  async handleJsonRpc(request: JSONRPCRequest): Promise<JSONRPCResponse> {
    try {
      let result: any;

      switch (request.method) {
        case "tools/list":
          result = await this.server.request(ListToolsRequestSchema, request.params || {});
          break;
        case "tools/call":
          result = await this.server.request(CallToolRequestSchema, request.params || {});
          break;
        default:
          return {
            jsonrpc: "2.0",
            id: request.id,
            error: {
              code: -32601,
              message: "Method not found"
            }
          };
      }

      return {
        jsonrpc: "2.0",
        id: request.id,
        result
      };
    } catch (error) {
      let message = "Unknown error";
      let code = -32603;
      if (error instanceof Error) message = error.message;
      return {
        jsonrpc: "2.0",
        id: request.id,
        error: {
          code,
          message
        }
      };
    }
  }

  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error("CV & Email MCP server running on stdio");
  }
}

const server = new CVMCPServer();
server.run().catch(console.error);

export { CVMCPServer };