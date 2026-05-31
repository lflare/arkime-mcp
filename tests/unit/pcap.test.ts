import { describe, it, expect } from 'vitest';
import { getPcap } from '@/controllers/pcap.js';
import { ArkimeClient } from '@/services/arkime-client.js';
import { McpError, ErrorCode } from '@/utils/errors.js';

describe('getPcap', () => {
  it('should return "No PCAP data found" for empty response', async () => {
    const client = {
      getPcap: async () => Buffer.from(''),
    } as unknown as ArkimeClient;

    const result = await getPcap(client, {
      expression: 'ip.src == 192.168.1.1',
    });

    expect(result.content).toHaveLength(1);
    expect(result.content[0].type).toBe('text');
    expect(result.content[0].text).toContain('No PCAP data found');
  });

  it('should return "PCAP too large" when response exceeds maxBytes', async () => {
    const largeBuffer = Buffer.alloc(2000);
    const client = {
      getPcap: async () => largeBuffer,
    } as unknown as ArkimeClient;

    const result = await getPcap(client, {
      expression: 'ip.src == 10.0.0.1',
      maxBytes: 1000,
    });

    expect(result.content).toHaveLength(1);
    expect(result.content[0].type).toBe('text');
    expect(result.content[0].text).toContain('PCAP too large');
    expect(result.content[0].text).toContain('2000 bytes');
    expect(result.content[0].text).toContain('1000 bytes');
  });

  it('should return md5 hash and size for valid PCAP', async () => {
    const pcapData = Buffer.from('test-pcap-data');
    const client = {
      getPcap: async () => pcapData,
    } as unknown as ArkimeClient;

    const result = await getPcap(client, {
      expression: 'ip.src == 192.168.1.100',
    });

    expect(result.content).toHaveLength(2);
    expect(result.content[0].type).toBe('text');
    expect(result.content[0].text).toContain('PCAP extracted successfully');
    expect(result.content[0].text).toContain('Size: 14 bytes');
    expect(result.content[0].text).toContain('MD5:');

    // Verify md5 is a valid hex string
    const md5Match = result.content[0].text.match(/MD5: ([a-f0-9]{32})/);
    expect(md5Match).not.toBeNull();

    // Verify resource uses { uri, mimeType } with data URI
    expect(result.content[1].type).toBe('resource');
    expect(result.content[1].resource.mimeType).toBe('application/vnd.tcpdump.pcap');
    expect(result.content[1].resource.uri).toBeDefined();
    expect(result.content[1].resource.uri).toBe(`data:application/vnd.tcpdump.pcap;base64,${pcapData.toString('base64')}`);
    expect(result.content[1].resource.text).toBeUndefined();
  });

  it('should include expression in results', async () => {
    const client = {
      getPcap: async () => Buffer.from('data'),
    } as unknown as ArkimeClient;

    const result = await getPcap(client, {
      expression: 'port.dst == 443 && ip.src == 10.0.0.5',
    });

    expect(result.content[0].text).toContain('Expression: port.dst == 443 && ip.src == 10.0.0.5');
  });

  it('should convert startTime to timestamp in URL', async () => {
    let capturedUrl = '';
    const client = {
      getPcap: async (url: string) => {
        capturedUrl = url;
        return Buffer.from('data');
      },
    } as unknown as ArkimeClient;

    await getPcap(client, {
      expression: 'ip.src == 1.2.3.4',
      startTime: '2025-01-15T10:00:00Z',
    });

    // startTime should be converted to unix timestamp and set as startTime param
    expect(capturedUrl).toContain('startTime=');
    const startTimeMatch = capturedUrl.match(/startTime=(\d+)/);
    expect(startTimeMatch).not.toBeNull();
    // 2025-01-15T10:00:00Z = 1736935200
    if (startTimeMatch) {
      expect(parseInt(startTimeMatch[1], 10)).toBeGreaterThan(0);
    }
    // date parameter should be removed when startTime is set
    expect(capturedUrl).not.toContain('date=');
  });

  it('should convert endTime to stopTime in URL', async () => {
    let capturedUrl = '';
    const client = {
      getPcap: async (url: string) => {
        capturedUrl = url;
        return Buffer.from('data');
      },
    } as unknown as ArkimeClient;

    await getPcap(client, {
      expression: 'ip.src == 1.2.3.4',
      endTime: '2025-01-15T12:00:00Z',
    });

    expect(capturedUrl).toContain('stopTime=');
    expect(capturedUrl).not.toContain('date=');
  });

  it('should include both startTime and stopTime when both are provided', async () => {
    let capturedUrl = '';
    const client = {
      getPcap: async (url: string) => {
        capturedUrl = url;
        return Buffer.from('data');
      },
    } as unknown as ArkimeClient;

    await getPcap(client, {
      expression: 'ip.src == 1.2.3.4',
      startTime: '2025-01-15T10:00:00Z',
      endTime: '2025-01-15T12:00:00Z',
    });

    expect(capturedUrl).toContain('startTime=');
    expect(capturedUrl).toContain('stopTime=');
    expect(capturedUrl).not.toContain('date=');
  });

  it('should use default date=1440 when no time parameters provided', async () => {
    let capturedUrl = '';
    const client = {
      getPcap: async (url: string) => {
        capturedUrl = url;
        return Buffer.from('data');
      },
    } as unknown as ArkimeClient;

    await getPcap(client, {
      expression: 'ip.src == 1.2.3.4',
    });

    expect(capturedUrl).toContain('date=1440');
  });

  it('should use default maxBytes of 1000000', async () => {
    const largeBuffer = Buffer.alloc(2000000);
    const client = {
      getPcap: async () => largeBuffer,
    } as unknown as ArkimeClient;

    const result = await getPcap(client, {
      expression: 'ip.src == 10.0.0.1',
    });

    expect(result.content[0].text).toContain('1000000 bytes');
  });

  describe('API error handling', () => {
    it('should propagate 500 Internal Server Error', async () => {
      const client = {
        getPcap: async () => {
          const error: McpError = new McpError(ErrorCode.API_ERROR, 'Internal Server Error');
          throw error;
        },
      } as unknown as ArkimeClient;

      await expect(getPcap(client, {
        expression: 'ip.src == 192.168.1.1',
      })).rejects.toThrow(McpError);

      try {
        await getPcap(client, {
          expression: 'ip.src == 192.168.1.1',
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
          const error: McpError = new McpError(ErrorCode.AUTH_INVALID, 'Unauthorized: Invalid credentials');
          throw error;
        },
      } as unknown as ArkimeClient;

      await expect(getPcap(client, {
        expression: 'ip.src == 192.168.1.1',
      })).rejects.toThrow(McpError);

      try {
        await getPcap(client, {
          expression: 'ip.src == 192.168.1.1',
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
          const error: McpError = new McpError(ErrorCode.API_ERROR, 'Forbidden: Access denied');
          throw error;
        },
      } as unknown as ArkimeClient;

      await expect(getPcap(client, {
        expression: 'ip.src == 192.168.1.1',
      })).rejects.toThrow(McpError);

      try {
        await getPcap(client, {
          expression: 'ip.src == 192.168.1.1',
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

      await expect(getPcap(client, {
        expression: 'ip.src == 192.168.1.1',
      })).rejects.toThrow(McpError);

      try {
        await getPcap(client, {
          expression: 'ip.src == 192.168.1.1',
        });
      } catch (error) {
        expect(error).toBeInstanceOf(McpError);
        expect((error as McpError).code).toBe(ErrorCode.NETWORK_ERROR);
        expect((error as McpError).message).toContain('timed out');
      }
    });
  });
});
