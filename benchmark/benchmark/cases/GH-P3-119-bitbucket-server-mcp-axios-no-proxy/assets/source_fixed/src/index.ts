#!/usr/bin/env node
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
} from '@modelcontextprotocol/sdk/types.js';
import axios, { AxiosInstance } from 'axios';
import winston from 'winston';

// Configuration du logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [
    new winston.transports.File({ filename: 'bitbucket.log' })
  ]
});

interface BitbucketActivity {
  action: string;
  [key: string]: unknown;
}

interface BitbucketConfig {
  baseUrl: string;
  token?: string;
  username?: string;
  password?: string;
  defaultProject?: string;
  defaultRepository?: string;
  defaultRepoPath?: string;
}

interface RepositoryParams {
  project?: string;
  repository?: string;
}

interface PullRequestParams extends RepositoryParams {
  prId: number;
}

interface MergeOptions {
  message?: string;
  strategy?: 'merge-commit' | 'squash' | 'fast-forward';
}

interface CommentOptions {
  text: string;
  parentId?: number;
}

interface PullRequestInput extends RepositoryParams {
  title: string;
  description: string;
  sourceBranch: string;
  targetBranch: string;
  reviewers?: string[];
}

class BitbucketServer {
  private readonly server: Server;
  private readonly api: AxiosInstance;
  private readonly config: BitbucketConfig;

  constructor() {
    this.server = new Server(
      {
        name: 'bitbucket-server-mcp-server',
        version: '1.0.0',
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    // Configuration initiale à partir des variables d'environnement
    this.config = {
      baseUrl: process.env.BITBUCKET_URL ?? '',
      token: process.env.BITBUCKET_TOKEN,
      username: process.env.BITBUCKET_USERNAME,
      password: process.env.BITBUCKET_PASSWORD,
      defaultProject: process.env.BITBUCKET_DEFAULT_PROJECT,
      defaultRepository: process.env.BITBUCKET_DEFAULT_REPOSITORY,
      defaultRepoPath: process.env.GIT_DEFAULT_REPO_PATH
    };

    if (!this.config.baseUrl) {
      throw new Error('BITBUCKET_URL is required');
    }

    if (!this.config.token && !(this.config.username && this.config.password)) {
      throw new Error('Either BITBUCKET_TOKEN or BITBUCKET_USERNAME/PASSWORD is required');
    }

    // Configuration de l'instance Axios
    this.api = axios.create({
      baseURL: `${this.config.baseUrl}/rest/api/1.0`,
      headers: this.config.token 
        ? { Authorization: `Bearer ${this.config.token}` }
        : {},
      auth: this.config.username && this.config.password
        ? { username: this.config.username, password: this.config.password }
        : undefined,
    });

    this.setupToolHandlers();
    
    this.server.onerror = (error) => logger.error('[MCP Error]', error);
  }

  private isPullRequestInput(args: unknown): args is PullRequestInput {
    const input = args as Partial<PullRequestInput>;
    return typeof args === 'object' &&
      args !== null &&
      (input.project === undefined || typeof input.project === 'string') &&
      (input.repository === undefined || typeof input.repository === 'string') &&
      typeof input.title === 'string' &&
      typeof input.sourceBranch === 'string' &&
      typeof input.targetBranch === 'string' &&
      (input.description === undefined || typeof input.description === 'string') &&
      (input.reviewers === undefined || Array.isArray(input.reviewers));
  }

  private applyDefaultParams<T extends RepositoryParams>(params: T): T & Required<RepositoryParams> {
    const result = {
      ...params,
      project: params.project ?? this.config.defaultProject,
      repository: params.repository ?? this.config.defaultRepository
    };

    if (!result.project) {
      throw new McpError(
        ErrorCode.InvalidParams,
        'Project must be provided either as a parameter or through BITBUCKET_DEFAULT_PROJECT environment variable'
      );
    }

    if (!result.repository) {
      throw new McpError(
        ErrorCode.InvalidParams,
        'Repository must be provided either as a parameter or through BITBUCKET_DEFAULT_REPOSITORY environment variable'
      );
    }

    return result as T & Required<RepositoryParams>;
  }

  private setupToolHandlers() {
    this.server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: [
        {
          name: 'create_pull_request',
          description: 'Create a new pull request',
          inputSchema: {
            type: 'object',
            properties: {
              project: { type: 'string', description: 'Bitbucket project key (optional if default is set)' },
              repository: { type: 'string', description: 'Repository slug (optional if default is set)' },
              title: { type: 'string', description: 'PR title' },
              description: { type: 'string', description: 'PR description' },
              sourceBranch: { type: 'string', description: 'Source branch name' },
              targetBranch: { type: 'string', description: 'Target branch name' },
              reviewers: {
                type: 'array',
                items: { type: 'string' },
                description: 'List of reviewer usernames'
              }
            },
            required: ['title', 'sourceBranch', 'targetBranch']
          }
        },
        {
          name: 'get_pull_request',
          description: 'Get pull request details',
          inputSchema: {
            type: 'object',
            properties: {
              project: { type: 'string', description: 'Bitbucket project key (optional if default is set)' },
              repository: { type: 'string', description: 'Repository slug (optional if default is set)' },
              prId: { type: 'number', description: 'Pull request ID' }
            },
            required: ['prId']
          }
        },
        {
          name: 'merge_pull_request',
          description: 'Merge a pull request',
          inputSchema: {
            type: 'object',
            properties: {
              project: { type: 'string', description: 'Bitbucket project key (optional if default is set)' },
              repository: { type: 'string', description: 'Repository slug (optional if default is set)' },
              prId: { type: 'number', description: 'Pull request ID' },
              message: { type: 'string', description: 'Merge commit message' },
              strategy: {
                type: 'string',
                enum: ['merge-commit', 'squash', 'fast-forward'],
                description: 'Merge strategy to use'
              }
            },
            required: ['prId']
          }
        },
        {
          name: 'decline_pull_request',
          description: 'Decline a pull request',
          inputSchema: {
            type: 'object',
            properties: {
              project: { type: 'string', description: 'Bitbucket project key (optional if default is set)' },
              repository: { type: 'string', description: 'Repository slug (optional if default is set)' },
              prId: { type: 'number', description: 'Pull request ID' },
              message: { type: 'string', description: 'Reason for declining' }
            },
            required: ['prId']
          }
        },
        {
          name: 'add_comment',
          description: 'Add a comment to a pull request',
          inputSchema: {
            type: 'object',
            properties: {
              project: { type: 'string', description: 'Bitbucket project key (optional if default is set)' },
              repository: { type: 'string', description: 'Repository slug (optional if default is set)' },
              prId: { type: 'number', description: 'Pull request ID' },
              text: { type: 'string', description: 'Comment text' },
              parentId: { type: 'number', description: 'Parent comment ID for replies' }
            },
            required: ['prId', 'text']
          }
        },
        {
          name: 'get_diff',
          description: 'Get pull request diff',
          inputSchema: {
            type: 'object',
            properties: {
              project: { type: 'string', description: 'Bitbucket project key (optional if default is set)' },
              repository: { type: 'string', description: 'Repository slug (optional if default is set)' },
              prId: { type: 'number', description: 'Pull request ID' },
              contextLines: { type: 'number', description: 'Number of context lines' }
            },
            required: ['prId']
          }
        },
        {
          name: 'get_reviews',
          description: 'Get pull request reviews',
          inputSchema: {
            type: 'object',
            properties: {
              project: { type: 'string', description: 'Bitbucket project key (optional if default is set)' },
              repository: { type: 'string', description: 'Repository slug (optional if default is set)' },
              prId: { type: 'number', description: 'Pull request ID' }
            },
            required: ['prId']
          }
        }
      ]
    }));

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      try {
        logger.info(`Called tool: ${request.params.name}`, { arguments: request.params.arguments });
        const args = request.params.arguments ?? {};
        
        switch (request.params.name) {
          case 'create_pull_request':
            if (!this.isPullRequestInput(args)) {
              throw new McpError(
                ErrorCode.InvalidParams,
                'Invalid pull request input parameters'
              );
            }
            
            const pullRequestInput: PullRequestInput = {
              project: args.project as string,
              repository: args.repository as string,
              title: args.title as string,
              description: (args.description as string) ?? '',
              sourceBranch: args.sourceBranch as string,
              targetBranch: args.targetBranch as string,
              reviewers: args.reviewers as string[] | undefined
            };
            
            return await this.createPullRequest(this.applyDefaultParams(pullRequestInput));
          case 'get_pull_request': {
            const params: PullRequestParams = {
              project: args.project as string,
              repository: args.repository as string,
              prId: args.prId as number
            };
            return await this.getPullRequest(this.applyDefaultParams(params));
          }
          case 'merge_pull_request': {
            const params: PullRequestParams = {
              project: args.project as string,
              repository: args.repository as string,
              prId: args.prId as number
            };
            return await this.mergePullRequest(
              this.applyDefaultParams(params), 
              {
                message: args.message as string,
                strategy: args.strategy as 'merge-commit' | 'squash' | 'fast-forward'
              }
            );
          }
          case 'decline_pull_request': {
            const params: PullRequestParams = {
              project: args.project as string,
              repository: args.repository as string,
              prId: args.prId as number
            };
            return await this.declinePullRequest(
              this.applyDefaultParams(params), 
              args.message as string
            );
          }
          case 'add_comment': {
            const params: PullRequestParams = {
              project: args.project as string,
              repository: args.repository as string,
              prId: args.prId as number
            };
            return await this.addComment(
              this.applyDefaultParams(params), 
              {
                text: args.text as string,
                parentId: args.parentId as number
              }
            );
          }
          case 'get_diff': {
            const params: PullRequestParams = {
              project: args.project as string,
              repository: args.repository as string,
              prId: args.prId as number
            };
            return await this.getDiff(
              this.applyDefaultParams(params), 
              args.contextLines as number
            );
          }
          case 'get_reviews': {
            const params: PullRequestParams = {
              project: args.project as string,
              repository: args.repository as string,
              prId: args.prId as number
            };
            return await this.getReviews(this.applyDefaultParams(params));
          }
          default:
            throw new McpError(
              ErrorCode.MethodNotFound,
              `Unknown tool: ${request.params.name}`
            );
        }
      } catch (error) {
        logger.error('Tool execution error', { error });
        if (axios.isAxiosError(error)) {
          throw new McpError(
            ErrorCode.InternalError,
            `Bitbucket API error: ${error.response?.data.message ?? error.message}`
          );
        }
        throw error;
      }
    });
  }

  private async createPullRequest(input: PullRequestInput & Required<RepositoryParams>) {
    const response = await this.api.post(
      `/projects/${input.project}/repos/${input.repository}/pull-requests`,
      {
        title: input.title,
        description: input.description,
        fromRef: {
          id: `refs/heads/${input.sourceBranch}`,
          repository: {
            slug: input.repository,
            project: { key: input.project }
          }
        },
        toRef: {
          id: `refs/heads/${input.targetBranch}`,
          repository: {
            slug: input.repository,
            project: { key: input.project }
          }
        },
        reviewers: input.reviewers?.map(username => ({ user: { name: username } }))
      }
    );

    return {
      content: [{ type: 'text', text: JSON.stringify(response.data, null, 2) }]
    };
  }

  private async getPullRequest(params: PullRequestParams & Required<RepositoryParams>) {
    const { project, repository, prId } = params;
    const response = await this.api.get(
      `/projects/${project}/repos/${repository}/pull-requests/${prId}`
    );

    return {
      content: [{ type: 'text', text: JSON.stringify(response.data, null, 2) }]
    };
  }

  private async mergePullRequest(
    params: PullRequestParams & Required<RepositoryParams>, 
    options: MergeOptions = {}
  ) {
    const { project, repository, prId } = params;
    const { message, strategy = 'merge-commit' } = options;
    
    const response = await this.api.post(
      `/projects/${project}/repos/${repository}/pull-requests/${prId}/merge`,
      {
        version: -1,
        message,
        strategy
      }
    );

    return {
      content: [{ type: 'text', text: JSON.stringify(response.data, null, 2) }]
    };
  }

  private async declinePullRequest(
    params: PullRequestParams & Required<RepositoryParams>, 
    message?: string
  ) {
    const { project, repository, prId } = params;
    const response = await this.api.post(
      `/projects/${project}/repos/${repository}/pull-requests/${prId}/decline`,
      {
        version: -1,
        message
      }
    );

    return {
      content: [{ type: 'text', text: JSON.stringify(response.data, null, 2) }]
    };
  }

  private async addComment(
    params: PullRequestParams & Required<RepositoryParams>, 
    options: CommentOptions
  ) {
    const { project, repository, prId } = params;
    const { text, parentId } = options;
    
    const response = await this.api.post(
      `/projects/${project}/repos/${repository}/pull-requests/${prId}/comments`,
      {
        text,
        parent: parentId ? { id: parentId } : undefined
      }
    );

    return {
      content: [{ type: 'text', text: JSON.stringify(response.data, null, 2) }]
    };
  }

  private async getDiff(
    params: PullRequestParams & Required<RepositoryParams>, 
    contextLines: number = 10
  ) {
    const { project, repository, prId } = params;
    const response = await this.api.get(
      `/projects/${project}/repos/${repository}/pull-requests/${prId}/diff`,
      {
        params: { contextLines },
        headers: { Accept: 'text/plain' }
      }
    );

    return {
      content: [{ type: 'text', text: response.data }]
    };
  }

  private async getReviews(params: PullRequestParams & Required<RepositoryParams>) {
    const { project, repository, prId } = params;
    const response = await this.api.get(
      `/projects/${project}/repos/${repository}/pull-requests/${prId}/activities`
    );

    const reviews = response.data.values.filter(
      (activity: BitbucketActivity) => activity.action === 'APPROVED' || activity.action === 'REVIEWED'
    );

    return {
      content: [{ type: 'text', text: JSON.stringify(reviews, null, 2) }]
    };
  }

  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    logger.info('Bitbucket MCP server running on stdio');
  }
}

const server = new BitbucketServer();
server.run().catch((error) => {
  logger.error('Server error', error);
  process.exit(1);
});