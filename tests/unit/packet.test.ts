import { describe, it, expect } from 'vitest';
import { getPacket } from '@/controllers/packet.js';
import { ArkimeClient } from '@/services/arkime-client.js';
import { McpError, ErrorCode } from '@/utils/errors.js';

describe('getPacket', () => {
  it('should throw McpError with NOT_FOUND when session not found', async () => {
    const client = {
      getSession: async () => {
        throw new Error('Session not found');
      },
    } as unknown as ArkimeClient;

    await expect(getPacket(client, {
      sessionId: 'nonexistent-id',
    })).rejects.toThrow(McpError);

    try {
      await getPacket(client, {
        sessionId: 'nonexistent-id',
      });
    } catch (error) {
      expect(error).toBeInstanceOf(McpError);
      expect((error as McpError).code).toBe(ErrorCode.NOT_FOUND);
      expect((error as McpError).message).toContain('nonexistent-id');
    }
  });

  it('should throw McpError with NOT_FOUND when getSession fails for node@id format', async () => {
    const client = {
      getSession: async () => {
        throw new Error('Session not found');
      },
      getPcap: async () => Buffer.from('packet-data'),
    } as unknown as ArkimeClient;

    // When getSession fails, getPacket should throw NOT_FOUND
    // instead of silently creating a stub session from the ID
    try {
      await getPacket(client, {
        sessionId: 'mynode@251118-ABCDEF123456789',
      });
      expect(true).toBe(false); // should not reach here
    } catch (error) {
      expect(error).toBeInstanceOf(McpError);
      expect((error as McpError).code).toBe(ErrorCode.NOT_FOUND);
    }
  });

  it('should parse node@id format correctly when session resolved', async () => {
    let capturedPcapUrl = '';
    const client = {
      getSession: async () => ({
        id: '251118-ABCDEF123456789',
        lastPacket: 1704067200000,
        node: 'mynode',
      }),
      getPcap: async (url: string) => {
        capturedPcapUrl = url;
        return Buffer.from('packet-data');
      },
    } as unknown as ArkimeClient;

    const result = await getPacket(client, {
      sessionId: 'mynode@251118-ABCDEF123456789',
    });

    expect(result.content).toHaveLength(2);
    expect(result.content[0].type).toBe('text');
    expect(result.content[0].text).toContain('mynode');
    expect(result.content[0].text).toContain('Size: 11 bytes');

    // Verify the expression uses the short ID
    const decodedUrl = decodeURIComponent(capturedPcapUrl);
    expect(decodedUrl).toContain('id=="251118-ABCDEF123456789"');
  });

  it('should return "No PCAP data found" for empty PCAP response', async () => {
    const client = {
      getSession: async () => ({
        id: 'session-1',
        lastPacket: 1704067200000,
        node: 'capture1',
      }),
      getPcap: async () => Buffer.from(''),
    } as unknown as ArkimeClient;

    const result = await getPacket(client, {
      sessionId: 'session-1',
    });

    expect(result.content).toHaveLength(1);
    expect(result.content[0].type).toBe('text');
    expect(result.content[0].text).toContain('No PCAP data found');
    expect(result.content[0].text).toContain('session-1');
  });

  it('should return size and node info for valid PCAP', async () => {
    const pcapData = Buffer.from('packet-bytes-here');
    const client = {
      getSession: async () => ({
        id: 'session-42',
        lastPacket: 1704067200000,
        node: 'capture-node-3',
      }),
      getPcap: async () => pcapData,
    } as unknown as ArkimeClient;

    const result = await getPacket(client, {
      sessionId: 'capture-node-3@251118-session-42',
    });

    expect(result.content).toHaveLength(2);
    expect(result.content[0].type).toBe('text');
    expect(result.content[0].text).toContain('PCAP extracted from session');
    expect(result.content[0].text).toContain('capture-node-3@251118-session-42');
    expect(result.content[0].text).toContain('Node: capture-node-3');
    expect(result.content[0].text).toContain('Size: 17 bytes');

    // Verify resource uses { uri, mimeType } with data URI
    expect(result.content[1].type).toBe('resource');
    expect(result.content[1].resource.mimeType).toBe('application/vnd.tcpdump.pcap');
    expect(result.content[1].resource.uri).toBeDefined();
    expect(result.content[1].resource.uri).toBe(`data:application/vnd.tcpdump.pcap;base64,${pcapData.toString('base64')}`);
    expect(result.content[1].resource.text).toBeUndefined();
  });

  it('should use session from client.getSession when available', async () => {
    const client = {
      getSession: async () => ({
        id: 'resolved-session',
        lastPacket: 1704067200000,
        node: 'resolved-node',
      }),
      getPcap: async () => Buffer.from('data'),
    } as unknown as ArkimeClient;

    const result = await getPacket(client, {
      sessionId: 'some-id',
    });

    expect(result.content[0].text).toContain('Node: resolved-node');
  });

  it('should handle session ID with multiple @ symbols when session resolved', async () => {
    const client = {
      getSession: async () => ({
        id: '251118-XYZ',
        lastPacket: 1704067200000,
        node: 'node',
      }),
      getPcap: async () => Buffer.from('data'),
    } as unknown as ArkimeClient;

    const result = await getPacket(client, {
      sessionId: 'node@extra@251118-XYZ',
    });

    expect(result.content[0].text).toContain('Node: node');
    expect(result.content[0].text).toContain('Size: 4 bytes');
  });

  it('should throw NOT_FOUND when session has no node field', async () => {
    const client = {
      getSession: async () => ({
        id: 'partial-session',
        lastPacket: 1704067200000,
      }),
    } as unknown as ArkimeClient;

    try {
      await getPacket(client, {
        sessionId: 'partial-session',
      });
      // Should not reach here
      expect(true).toBe(false);
    } catch (error) {
      expect(error).toBeInstanceOf(McpError);
      expect((error as McpError).code).toBe(ErrorCode.NOT_FOUND);
    }
  });

  describe('API error handling', () => {
    it('should propagate 500 Internal Server Error from getPcap', async () => {
      const client = {
        getSession: async () => ({
          id: 'session-1',
          lastPacket: 1704067200000,
          node: 'capture1',
        }),
        getPcap: async () => {
          const error: McpError = new McpError(ErrorCode.API_ERROR, 'Internal Server Error');
          throw error;
        },
      } as unknown as ArkimeClient;

      await expect(getPacket(client, {
        sessionId: 'session-1',
      })).rejects.toThrow(McpError);

      try {
        await getPacket(client, {
          sessionId: 'session-1',
        });
      } catch (error) {
        expect(error).toBeInstanceOf(McpError);
        expect((error as McpError).code).toBe(ErrorCode.API_ERROR);
        expect((error as McpError).message).toContain('Internal Server Error');
      }
    });

    it('should propagate 401 Unauthorized error from getSession', async () => {
      const client = {
        getSession: async () => {
          const error: McpError = new McpError(ErrorCode.AUTH_INVALID, 'Unauthorized: invalid credentials');
          throw error;
        },
      } as unknown as ArkimeClient;

      await expect(getPacket(client, {
        sessionId: 'session-1',
      })).rejects.toThrow(McpError);

      try {
        await getPacket(client, {
          sessionId: 'session-1',
        });
      } catch (error) {
        expect(error).toBeInstanceOf(McpError);
        expect((error as McpError).code).toBe(ErrorCode.NOT_FOUND);
      }
    });

    it('should propagate 403 Forbidden error from getPcap', async () => {
      const client = {
        getSession: async () => ({
          id: 'session-1',
          lastPacket: 1704067200000,
          node: 'capture1',
        }),
        getPcap: async () => {
          const error: McpError = new McpError(ErrorCode.API_ERROR, 'Forbidden: access denied');
          throw error;
        },
      } as unknown as ArkimeClient;

      await expect(getPacket(client, {
        sessionId: 'session-1',
      })).rejects.toThrow(McpError);

      try {
        await getPacket(client, {
          sessionId: 'session-1',
        });
      } catch (error) {
        expect(error).toBeInstanceOf(McpError);
        expect((error as McpError).code).toBe(ErrorCode.API_ERROR);
        expect((error as McpError).message).toContain('Forbidden');
      }
    });

    it('should propagate connection timeout error from getPcap', async () => {
      const client = {
        getSession: async () => ({
          id: 'session-1',
          lastPacket: 1704067200000,
          node: 'capture1',
        }),
        getPcap: async () => {
          const error: McpError = new McpError(ErrorCode.NETWORK_ERROR, 'Connection timed out');
          throw error;
        },
      } as unknown as ArkimeClient;

      await expect(getPacket(client, {
        sessionId: 'session-1',
      })).rejects.toThrow(McpError);

      try {
        await getPacket(client, {
          sessionId: 'session-1',
        });
      } catch (error) {
        expect(error).toBeInstanceOf(McpError);
        expect((error as McpError).code).toBe(ErrorCode.NETWORK_ERROR);
        expect((error as McpError).message).toContain('timed out');
      }
    });
  });
});
