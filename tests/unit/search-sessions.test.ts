import { describe, it, expect } from 'vitest';
import { searchSessions } from '@/controllers/sessions';
import type { ArkimeClient } from '@/services/arkime-client';
import { McpError, ErrorCode } from '@/utils/errors';
import type { SessionsResponse } from '@/types/arkime';

describe('searchSessions controller', () => {
  it('should return formatted sessions for valid query', async () => {
    const mockResponse: SessionsResponse = {
      data: [
        {
          id: 'session-1',
          lastPacket: 1704067200000,
          source: { ip: '192.168.1.100', port: 45678 },
          destination: { ip: '10.0.0.50', port: 443 },
          ipProtocol: 6,
        },
      ],
      recordsTotal: 1,
      recordsFiltered: 1,
    };

    const client = {
      searchSessions: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await searchSessions(client, {
      expression: 'ip.src == 192.168.1.100',
      limit: 100,
    });

    expect(result.isError).toBeUndefined();
    expect(result.content[0].type).toBe('text');
    expect(result.content[0].text).toContain('Found 1 sessions');
  });

  it('should return message for no results', async () => {
    const mockResponse: SessionsResponse = {
      data: [],
      recordsTotal: 0,
      recordsFiltered: 0,
    };

    const client = {
      searchSessions: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await searchSessions(client, {
      expression: 'ip.src == 1.2.3.4',
      limit: 100,
    });

    expect(result.content[0].text).toContain('No sessions found');
  });

  it('should propagate errors', async () => {
    const client = {
      searchSessions: async () => { throw new Error('Network error'); },
    } as unknown as ArkimeClient;

    await expect(searchSessions(client, {
      expression: 'invalid',
      limit: 100,
    })).rejects.toThrow('Network error');
  });
});

describe('API error handling', () => {
  it('should propagate 500 Internal Server Error', async () => {
    const client = {
      searchSessions: async () => {
        const error: McpError = new McpError(ErrorCode.API_ERROR, 'Internal Server Error');
        throw error;
      },
    } as unknown as ArkimeClient;

    await expect(searchSessions(client, {
      expression: 'ip.src == 192.168.1.1',
      limit: 100,
    })).rejects.toThrow(McpError);

    try {
      await searchSessions(client, {
        expression: 'ip.src == 192.168.1.1',
        limit: 100,
      });
    } catch (error) {
      expect(error).toBeInstanceOf(McpError);
      expect((error as McpError).code).toBe(ErrorCode.API_ERROR);
      expect((error as McpError).message).toContain('Internal Server Error');
    }
  });

  it('should propagate 401 Unauthorized error', async () => {
    const client = {
      searchSessions: async () => {
        const error: McpError = new McpError(ErrorCode.AUTH_INVALID, 'Unauthorized: invalid credentials');
        throw error;
      },
    } as unknown as ArkimeClient;

    await expect(searchSessions(client, {
      expression: 'ip.src == 192.168.1.1',
      limit: 100,
    })).rejects.toThrow(McpError);

    try {
      await searchSessions(client, {
        expression: 'ip.src == 192.168.1.1',
        limit: 100,
      });
    } catch (error) {
      expect(error).toBeInstanceOf(McpError);
      expect((error as McpError).code).toBe(ErrorCode.AUTH_INVALID);
      expect((error as McpError).message).toContain('Unauthorized');
    }
  });

  it('should propagate 403 Forbidden error', async () => {
    const client = {
      searchSessions: async () => {
        const error: McpError = new McpError(ErrorCode.API_ERROR, 'Forbidden: access denied');
        throw error;
      },
    } as unknown as ArkimeClient;

    await expect(searchSessions(client, {
      expression: 'ip.src == 192.168.1.1',
      limit: 100,
    })).rejects.toThrow(McpError);

    try {
      await searchSessions(client, {
        expression: 'ip.src == 192.168.1.1',
        limit: 100,
      });
    } catch (error) {
      expect(error).toBeInstanceOf(McpError);
      expect((error as McpError).code).toBe(ErrorCode.API_ERROR);
      expect((error as McpError).message).toContain('Forbidden');
    }
  });

  it('should propagate connection timeout error', async () => {
    const client = {
      searchSessions: async () => {
        const error: McpError = new McpError(ErrorCode.NETWORK_ERROR, 'Connection timed out');
        throw error;
      },
    } as unknown as ArkimeClient;

    await expect(searchSessions(client, {
      expression: 'ip.src == 192.168.1.1',
      limit: 100,
    })).rejects.toThrow(McpError);

    try {
      await searchSessions(client, {
        expression: 'ip.src == 192.168.1.1',
        limit: 100,
      });
    } catch (error) {
      expect(error).toBeInstanceOf(McpError);
      expect((error as McpError).code).toBe(ErrorCode.NETWORK_ERROR);
      expect((error as McpError).message).toContain('timed out');
    }
  });
});
