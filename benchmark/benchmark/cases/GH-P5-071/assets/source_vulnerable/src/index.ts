#!/usr/bin/env node

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import mammoth from 'mammoth';
import * as fs from 'fs/promises';
import * as path from 'path';
import { z } from 'zod';
import { omitBy, isUndefined } from 'lodash-es';

interface MammothOptions {
  styleMap?: string;
  ignoreEmptyParagraphs?: boolean;
  idPrefix?: string;
  includeDefaultStyleMap?: boolean;
  includeEmbeddedStyleMap?: boolean;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  convertImage?: any;
}

const commonOptionsSchema = {
  styleMap: z
    .string()
    .optional()
    .describe('Custom style map to control Word styles to HTML conversion. Each line represents a style mapping.'),
  ignoreEmptyParagraphs: z.boolean().optional().describe('Whether to ignore empty paragraphs (default: true)'),
  idPrefix: z.string().optional().describe('Prefix for generated IDs (bookmarks, footnotes, endnotes)'),
  includeDefaultStyleMap: z.boolean().optional().describe('Whether to include default style map (default: true)'),
  includeEmbeddedStyleMap: z
    .boolean()
    .optional()
    .describe('Whether to include embedded style map from document (default: true)'),
};

function buildMammothOptions(params: Partial<MammothOptions>): MammothOptions {
  return omitBy(params, isUndefined) as MammothOptions;
}

interface ConversionResult {
  value: string;
  messages: Array<{ type: string; message: string }>;
}

function formatConversionOutput(
  absolutePath: string,
  result: ConversionResult,
  title: string,
  codeBlockType: string
): string {
  let output = `# ${title}\n\n`;
  output += `**File**: ${absolutePath}\n\n`;
  output += `## ${codeBlockType} Output:\n\n\`\`\`${codeBlockType.toLowerCase()}\n${result.value}\n\`\`\`\n\n`;

  if (result.messages.length > 0) {
    output += `## Messages:\n\n`;
    result.messages.forEach((msg) => {
      output += `- ${msg.type}: ${msg.message}\n`;
    });
  }

  return output;
}

function createSuccessResponse(formattedText: string, rawData?: object) {
  const content: Array<{ type: 'text'; text: string }> = [{ type: 'text' as const, text: formattedText }];

  if (rawData) {
    content.push({
      type: 'text' as const,
      text: `\n---\n\n## Raw Data (JSON)\n\n\`\`\`json\n${JSON.stringify(rawData, null, 2)}\n\`\`\``,
    });
  }

  return { content };
}

interface NodeError extends Error {
  code?: string;
  path?: string;
  syscall?: string;
}

function getErrorDetails(error: unknown): { message: string; suggestions: string[] } {
  if (!(error instanceof Error)) {
    return {
      message: String(error),
      suggestions: [],
    };
  }

  const nodeError = error as NodeError;
  const suggestions: string[] = [];

  // 权限错误
  if (nodeError.code === 'EPERM' || nodeError.code === 'EACCES') {
    suggestions.push(
      '**Permission denied.** This is likely a macOS security restriction.',
      '**Solutions:**',
      '1. Grant Full Disk Access to your Terminal/IDE in System Settings → Privacy & Security',
      '2. Move the file to an unrestricted location (e.g., ~/Documents)',
      '3. Ensure the file is not open in another application (like Microsoft Word)',
      `4. Check file permissions: \`ls -l "${nodeError.path || 'file'}"\``
    );
  }
  // 文件不存在
  else if (nodeError.code === 'ENOENT') {
    suggestions.push(
      '**File not found.**',
      '**Check:**',
      '1. The file path is correct (use absolute path)',
      '2. The file has not been moved or deleted',
      `3. Path: \`${nodeError.path || 'unknown'}\``
    );
  }
  // 文件正在使用
  else if (nodeError.code === 'EBUSY') {
    suggestions.push(
      '**File is busy or locked.**',
      '1. Close the file in any applications that might have it open',
      '2. Try again after a moment'
    );
  }
  // 不支持的文件格式或损坏
  else if (error.message.includes('not a valid') || error.message.includes('corrupt')) {
    suggestions.push(
      '**Invalid or corrupted file.**',
      '1. Ensure the file is a valid .docx file',
      '2. Try opening the file in Microsoft Word to verify it is not corrupted',
      '3. Re-download or re-save the file if possible'
    );
  }

  return {
    message: error.message,
    suggestions,
  };
}

function createErrorResponse(error: unknown, context: string) {
  const { message, suggestions } = getErrorDetails(error);

  let errorText = `# ❌ Error ${context}\n\n`;
  errorText += `**Error Message:**\n\`\`\`\n${message}\n\`\`\`\n\n`;

  if (suggestions.length > 0) {
    errorText += `## 💡 Troubleshooting\n\n`;
    suggestions.forEach((suggestion) => {
      errorText += `${suggestion}\n`;
    });
  }

  return {
    content: [
      {
        type: 'text' as const,
        text: errorText,
      },
    ],
    isError: true,
  };
}

const server = new McpServer({
  name: 'mammoth-mcp',
  version: process.env.PACKAGE_VERSION || '1.0.0',
});

server.registerTool(
  'convert_docx_to_html',
  {
    description:
      'Convert a DOCX file to HTML using mammoth. Supports reading from a file path and returns the HTML content.',
    inputSchema: {
      filePath: z.string().describe('Absolute path to the DOCX file to convert'),
      ...commonOptionsSchema,
    },
  },
  async ({ filePath, styleMap, ignoreEmptyParagraphs, idPrefix, includeDefaultStyleMap, includeEmbeddedStyleMap }) => {
    try {
      const absolutePath = path.resolve(filePath);
      await fs.access(absolutePath);

      const options = buildMammothOptions({
        styleMap,
        ignoreEmptyParagraphs,
        idPrefix,
        includeDefaultStyleMap,
        includeEmbeddedStyleMap,
      });

      const result = await mammoth.convertToHtml({ path: absolutePath }, options);
      const output = formatConversionOutput(absolutePath, result, 'Conversion Result', 'HTML');

      return createSuccessResponse(output, {
        filePath: absolutePath,
        html: result.value,
        messages: result.messages,
      });
    } catch (error) {
      return createErrorResponse(error, 'converting DOCX file');
    }
  }
);

server.registerTool(
  'convert_docx_to_html_with_images',
  {
    description: 'Convert a DOCX file to HTML with embedded images as base64 data URIs',
    inputSchema: {
      filePath: z.string().describe('Absolute path to the DOCX file to convert'),
      ...commonOptionsSchema,
    },
  },
  async ({ filePath, styleMap, ignoreEmptyParagraphs, idPrefix, includeDefaultStyleMap, includeEmbeddedStyleMap }) => {
    try {
      const absolutePath = path.resolve(filePath);
      await fs.access(absolutePath);

      const options = buildMammothOptions({
        styleMap,
        ignoreEmptyParagraphs,
        idPrefix,
        includeDefaultStyleMap,
        includeEmbeddedStyleMap,
        convertImage: mammoth.images.imgElement(async (image: any) => {
          const buffer = await image.read();
          const base64 = buffer.toString('base64');
          const contentType = image.contentType || 'image/png';
          return {
            src: `data:${contentType};base64,${base64}`,
          };
        }),
      });

      const result = await mammoth.convertToHtml({ path: absolutePath }, options);
      const output = formatConversionOutput(absolutePath, result, 'Conversion Result (with images)', 'HTML');

      return createSuccessResponse(output, {
        filePath: absolutePath,
        html: result.value,
        messages: result.messages,
        hasImages: true,
      });
    } catch (error) {
      return createErrorResponse(error, 'converting DOCX file with images');
    }
  }
);

server.registerTool(
  'extract_raw_text',
  {
    description:
      'Extract raw text from a DOCX file, ignoring all formatting. Each paragraph is followed by two newlines.',
    inputSchema: {
      filePath: z.string().describe('Absolute path to the DOCX file to extract text from'),
    },
  },
  async ({ filePath }) => {
    try {
      const absolutePath = path.resolve(filePath);
      await fs.access(absolutePath);

      const result = await mammoth.extractRawText({ path: absolutePath });
      const output = formatConversionOutput(absolutePath, result, 'Raw Text Extraction', 'Text Content');

      return createSuccessResponse(output, {
        filePath: absolutePath,
        text: result.value,
        messages: result.messages,
      });
    } catch (error) {
      return createErrorResponse(error, 'extracting raw text from DOCX file');
    }
  }
);

server.registerTool(
  'convert_docx_to_markdown',
  {
    description:
      'Convert a DOCX file to Markdown. Note: Markdown support is deprecated by mammoth.js, but still functional.',
    inputSchema: {
      filePath: z.string().describe('Absolute path to the DOCX file to convert'),
      ...commonOptionsSchema,
    },
  },
  async ({ filePath, styleMap, ignoreEmptyParagraphs, idPrefix, includeDefaultStyleMap, includeEmbeddedStyleMap }) => {
    try {
      const absolutePath = path.resolve(filePath);
      await fs.access(absolutePath);

      const options = buildMammothOptions({
        styleMap,
        ignoreEmptyParagraphs,
        idPrefix,
        includeDefaultStyleMap,
        includeEmbeddedStyleMap,
      });

      const result = await (mammoth as any).convertToMarkdown({ path: absolutePath }, options);
      const output = formatConversionOutput(absolutePath, result, 'Conversion Result (Markdown)', 'Markdown');

      return createSuccessResponse(output, {
        filePath: absolutePath,
        markdown: result.value,
        messages: result.messages,
      });
    } catch (error) {
      return createErrorResponse(error, 'converting DOCX file to Markdown');
    }
  }
);

async function main() {
  await server.connect(new StdioServerTransport());
}

main().catch((error) => {
  console.error('Server error:', error);
  process.exit(1);
});
