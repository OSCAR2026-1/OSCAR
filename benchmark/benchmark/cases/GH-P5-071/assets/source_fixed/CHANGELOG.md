# mammoth-mcp

## 1.1.1

### Patch Changes

- Update usage documentation with standard npx configuration for MCP. Added recommended npx-based setup and corrected local installation path from dist/cjs to dist/esm.

## 1.1.0

### Minor Changes

- Add new conversion tools and expand mammoth options support
  - Add `extract_raw_text` tool for extracting plain text from DOCX files
  - Add `convert_docx_to_markdown` tool for converting DOCX to Markdown format
  - Expand all tools with advanced mammoth options: styleMap, ignoreEmptyParagraphs, idPrefix, includeDefaultStyleMap, includeEmbeddedStyleMap
  - Improve error handling with detailed troubleshooting suggestions
  - Add ESM support and modernize build configuration

## 1.0.3

### Patch Changes

- Fix workflow to prevent pnpm errors by removing changesets auto-publish

## 1.0.2

### Patch Changes

- cfe2be5: Enable OIDC trusted publishing for automated releases

## 1.0.0

### Initial Release

- **convert_docx_to_html**: Convert DOCX files to clean HTML
- **convert_docx_to_html_with_images**: Convert DOCX files to HTML with embedded base64 images
