import { describe, it, expect } from 'vitest';
import { createServer } from '@/server';

describe('MCP Server', () => {
  describe('createServer', () => {
    it('should create an MCP server instance', () => {
      const server = createServer();

      expect(server).toBeDefined();
      expect(server.connect).toBeDefined();
      expect(server.close).toBeDefined();
    });

    it('should expose underlying server with correct configuration', () => {
      const mcpServer = createServer();

      expect(mcpServer.server).toBeDefined();
      expect(mcpServer.server.connect).toBeDefined();
    });
  });
});
