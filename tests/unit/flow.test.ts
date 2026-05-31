import { describe, it, expect } from 'vitest';
import { getFlow } from '@/controllers/flow.js';
import { ArkimeClient } from '@/services/arkime-client.js';
import { McpError, ErrorCode } from '@/utils/errors.js';

describe('getFlow', () => {
  it('should add ip.protocol == 6 for TCP protocol', async () => {
    let capturedUrl = '';
    const client = {
      getPcap: async (url: string) => {
        capturedUrl = url;
        return Buffer.from('flow-data');
      },
    } as unknown as ArkimeClient;

    await getFlow(client, {
      sourceIp: '10.0.0.1',
      destIp: '10.0.0.2',
      protocol: 'tcp',
    });

    const urlObj = new URL(capturedUrl, 'http://localhost');
    const expression = urlObj.searchParams.get('expression');
    expect(expression).toContain('ip.protocol == 6');
  });

  it('should add ip.protocol == 17 for UDP protocol', async () => {
    let capturedUrl = '';
    const client = {
      getPcap: async (url: string) => {
        capturedUrl = url;
        return Buffer.from('flow-data');
      },
    } as unknown as ArkimeClient;

    await getFlow(client, {
      sourceIp: '10.0.0.1',
      destIp: '10.0.0.2',
      protocol: 'udp',
    });

    const urlObj = new URL(capturedUrl, 'http://localhost');
    const expression = urlObj.searchParams.get('expression');
    expect(expression).toContain('ip.protocol == 17');
  });

  it('should not add protocol filter for "any" protocol', async () => {
    let capturedUrl = '';
    const client = {
      getPcap: async (url: string) => {
        capturedUrl = url;
        return Buffer.from('flow-data');
      },
    } as unknown as ArkimeClient;

    await getFlow(client, {
      sourceIp: '10.0.0.1',
      destIp: '10.0.0.2',
      protocol: 'any',
    });

    const urlObj = new URL(capturedUrl, 'http://localhost');
    const expression = urlObj.searchParams.get('expression');
    expect(expression).not.toContain('ip.protocol');
  });

  it('should return "No flow data found" for empty response', async () => {
    const client = {
      getPcap: async () => Buffer.from(''),
    } as unknown as ArkimeClient;

    const result = await getFlow(client, {
      sourceIp: '192.168.1.100',
      destIp: '10.0.0.50',
      destPort: 445,
    });

    expect(result.content).toHaveLength(1);
    expect(result.content[0].type).toBe('text');
    expect(result.content[0].text).toContain('No flow data found');
    expect(result.content[0].text).toContain('192.168.1.100');
    expect(result.content[0].text).toContain('10.0.0.50');
  });

  it('should include port info in "No flow data found" message', async () => {
    const client = {
      getPcap: async () => Buffer.from(''),
    } as unknown as ArkimeClient;

    const result = await getFlow(client, {
      sourceIp: '192.168.1.100',
      destIp: '10.0.0.50',
      sourcePort: 45678,
      destPort: 445,
    });

    expect(result.content[0].text).toContain('192.168.1.100:45678');
    expect(result.content[0].text).toContain('10.0.0.50:445');
  });

  it('should return "Flow too large" when response exceeds maxBytes', async () => {
    const largeBuffer = Buffer.alloc(20000000);
    const client = {
      getPcap: async () => largeBuffer,
    } as unknown as ArkimeClient;

    const result = await getFlow(client, {
      sourceIp: '10.0.0.1',
      destIp: '10.0.0.2',
      maxBytes: 5000000,
    });

    expect(result.content).toHaveLength(1);
    expect(result.content[0].type).toBe('text');
    expect(result.content[0].text).toContain('Flow too large');
    expect(result.content[0].text).toContain('5000000 bytes');
  });

  it('should extract md5 and size for valid flow', async () => {
    const flowData = Buffer.from('some-flow-pcap-data');
    const client = {
      getPcap: async () => flowData,
    } as unknown as ArkimeClient;

    const result = await getFlow(client, {
      sourceIp: '10.0.0.1',
      destIp: '10.0.0.2',
      destPort: 443,
      protocol: 'tcp',
    });

    expect(result.content).toHaveLength(2);
    expect(result.content[0].type).toBe('text');
    expect(result.content[0].text).toContain('Flow extracted successfully');
    expect(result.content[0].text).toContain('Size: 19 bytes');
    expect(result.content[0].text).toContain('MD5:');

    const md5Match = result.content[0].text.match(/MD5: ([a-f0-9]{32})/);
    expect(md5Match).not.toBeNull();

    expect(result.content[1].type).toBe('resource');
    expect(result.content[1].resource.mimeType).toBe('application/vnd.tcpdump.pcap');
    expect(result.content[1].resource.uri).toBeDefined();
    expect(result.content[1].resource.uri).toMatch(/^data:application\/vnd.tcpdump.pcap;base64,/);
    expect(result.content[1].resource.text).toBeUndefined();
  });

  it('should include sourcePort condition when specified', async () => {
    let capturedUrl = '';
    const client = {
      getPcap: async (url: string) => {
        capturedUrl = url;
        return Buffer.from('data');
      },
    } as unknown as ArkimeClient;

    await getFlow(client, {
      sourceIp: '10.0.0.1',
      destIp: '10.0.0.2',
      sourcePort: 12345,
    });

    const urlObj = new URL(capturedUrl, 'http://localhost');
    const expression = urlObj.searchParams.get('expression');
    expect(expression).toContain('port.src == 12345');
  });

  it('should include destPort condition when specified', async () => {
    let capturedUrl = '';
    const client = {
      getPcap: async (url: string) => {
        capturedUrl = url;
        return Buffer.from('data');
      },
    } as unknown as ArkimeClient;

    await getFlow(client, {
      sourceIp: '10.0.0.1',
      destIp: '10.0.0.2',
      destPort: 445,
    });

    const urlObj = new URL(capturedUrl, 'http://localhost');
    const expression = urlObj.searchParams.get('expression');
    expect(expression).toContain('port.dst == 445');
  });

  it('should include both port conditions when both specified', async () => {
    let capturedUrl = '';
    const client = {
      getPcap: async (url: string) => {
        capturedUrl = url;
        return Buffer.from('data');
      },
    } as unknown as ArkimeClient;

    await getFlow(client, {
      sourceIp: '10.0.0.1',
      destIp: '10.0.0.2',
      sourcePort: 54321,
      destPort: 22,
    });

    const urlObj = new URL(capturedUrl, 'http://localhost');
    const expression = urlObj.searchParams.get('expression');
    expect(expression).toContain('port.src == 54321');
    expect(expression).toContain('port.dst == 22');
  });

  it('should build complete expression with all conditions', async () => {
    let capturedUrl = '';
    const client = {
      getPcap: async (url: string) => {
        capturedUrl = url;
        return Buffer.from('data');
      },
    } as unknown as ArkimeClient;

    await getFlow(client, {
      sourceIp: '192.168.1.100',
      destIp: '10.0.0.50',
      sourcePort: 45000,
      destPort: 445,
      protocol: 'tcp',
    });

    const urlObj = new URL(capturedUrl, 'http://localhost');
    const expression = urlObj.searchParams.get('expression');
    expect(expression).toContain('ip.src == 192.168.1.100');
    expect(expression).toContain('ip.dst == 10.0.0.50');
    expect(expression).toContain('port.src == 45000');
    expect(expression).toContain('port.dst == 445');
    expect(expression).toContain('ip.protocol == 6');
  });

  it('should use default maxBytes of 10000000', async () => {
    const largeBuffer = Buffer.alloc(20000000);
    const client = {
      getPcap: async () => largeBuffer,
    } as unknown as ArkimeClient;

    const result = await getFlow(client, {
      sourceIp: '10.0.0.1',
      destIp: '10.0.0.2',
    });

    expect(result.content[0].text).toContain('10000000 bytes');
  });

  describe('API error handling', () => {
    it('should propagate 500 Internal Server Error', async () => {
      const client = {
        getPcap: async () => {
          const error: McpError = new McpError(ErrorCode.API_ERROR, 'Internal Server Error');
          throw error;
        },
      } as unknown as ArkimeClient;

      await expect(getFlow(client, {
        sourceIp: '10.0.0.1',
        destIp: '10.0.0.2',
      })).rejects.toThrow(McpError);

      try {
        await getFlow(client, {
          sourceIp: '10.0.0.1',
          destIp: '10.0.0.2',
        });
      } catch (error) {
        expect(error).toBeInstanceOf(McpError);
        expect((error as McpError).code).toBe(ErrorCode.API_ERROR);
        expect((error as McpError).message).toContain('Internal Server Error');
      }
    });

    it('should propagate 401 Unauthorized error', async () => {
      const client = {
        getPcap: async () => {
          const error: McpError = new McpError(ErrorCode.AUTH_INVALID, 'Unauthorized: invalid credentials');
          throw error;
        },
      } as unknown as ArkimeClient;

      await expect(getFlow(client, {
        sourceIp: '10.0.0.1',
        destIp: '10.0.0.2',
      })).rejects.toThrow(McpError);

      try {
        await getFlow(client, {
          sourceIp: '10.0.0.1',
          destIp: '10.0.0.2',
        });
      } catch (error) {
        expect(error).toBeInstanceOf(McpError);
        expect((error as McpError).code).toBe(ErrorCode.AUTH_INVALID);
        expect((error as McpError).message).toContain('Unauthorized');
      }
    });

    it('should propagate 403 Forbidden error', async () => {
      const client = {
        getPcap: async () => {
          const error: McpError = new McpError(ErrorCode.API_ERROR, 'Forbidden: access denied');
          throw error;
        },
      } as unknown as ArkimeClient;

      await expect(getFlow(client, {
        sourceIp: '10.0.0.1',
        destIp: '10.0.0.2',
      })).rejects.toThrow(McpError);

      try {
        await getFlow(client, {
          sourceIp: '10.0.0.1',
          destIp: '10.0.0.2',
        });
      } catch (error) {
        expect(error).toBeInstanceOf(McpError);
        expect((error as McpError).code).toBe(ErrorCode.API_ERROR);
        expect((error as McpError).message).toContain('Forbidden');
      }
    });

    it('should propagate connection timeout error', async () => {
      const client = {
        getPcap: async () => {
          const error: McpError = new McpError(ErrorCode.NETWORK_ERROR, 'Connection timed out');
          throw error;
        },
      } as unknown as ArkimeClient;

      await expect(getFlow(client, {
        sourceIp: '10.0.0.1',
        destIp: '10.0.0.2',
      })).rejects.toThrow(McpError);

      try {
        await getFlow(client, {
          sourceIp: '10.0.0.1',
          destIp: '10.0.0.2',
        });
      } catch (error) {
        expect(error).toBeInstanceOf(McpError);
        expect((error as McpError).code).toBe(ErrorCode.NETWORK_ERROR);
        expect((error as McpError).message).toContain('timed out');
      }
    });
  });
});
