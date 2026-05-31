/**
 * Type declarations for @modelcontextprotocol/sdk subpath exports
 * These augment the SDK's type definitions for proper TypeScript resolution
 */

declare module '@modelcontextprotocol/sdk/server/mcp.js' {
  import { Server, ServerOptions } from '@modelcontextprotocol/sdk/server';

  export interface McpServerOptions extends ServerOptions {}

  export class McpServer {
    constructor(serverInfo: { name: string; version: string }, options?: McpServerOptions);
    readonly server: Server;
    connect(transport: unknown): Promise<void>;
    close(): Promise<void>;
    tool(
      name: string,
      description: string,
      inputSchema: unknown,
      handler: (params: unknown) => Promise<unknown>
    ): void;
  }

  export class ResourceTemplate {
    constructor(uriTemplate: string, callbacks: {
      list?: () => Promise<unknown>;
      complete?: (params: unknown) => Promise<unknown>;
    });
  }
}

declare module '@modelcontextprotocol/sdk/server/stdio.js' {
  export class StdioServerTransport {
    constructor();
  }
}
