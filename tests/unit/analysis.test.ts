import { describe, it, expect } from 'vitest';
import { analyzeTraffic, huntSuspicious } from '@/controllers/analysis.js';
import { ArkimeClient } from '@/services/arkime-client.js';
import { McpError, ErrorCode } from '@/utils/errors.js';
import type { SessionsResponse, Session } from '@/types/arkime.js';

describe('analyzeTraffic', () => {
  it('should analyze top talkers', async () => {
    const mockResponse: SessionsResponse = {
      data: [
        {
          id: 'session-1',
          lastPacket: 1704067200000,
          source: { ip: '192.168.1.100', port: 45678, bytes: 1000, packets: 10 },
          destination: { ip: '10.0.0.50', port: 443, bytes: 5000, packets: 50 },
          ipProtocol: 6,
        },
        {
          id: 'session-2',
          lastPacket: 1704067200000,
          source: { ip: '192.168.1.100', port: 45679, bytes: 2000, packets: 20 },
          destination: { ip: '10.0.0.51', port: 80, bytes: 3000, packets: 30 },
          ipProtocol: 6,
        },
        {
          id: 'session-3',
          lastPacket: 1704067200000,
          source: { ip: '192.168.1.101', port: 45680, bytes: 500, packets: 5 },
          destination: { ip: '10.0.0.50', port: 443, bytes: 1000, packets: 10 },
          ipProtocol: 6,
        },
      ],
      recordsTotal: 3,
      recordsFiltered: 3,
    };

    const client = {
      searchSessions: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await analyzeTraffic(client, {
      analysisType: 'top-talkers',
      limit: 10,
    });

    expect(result.isError).toBeUndefined();
    expect(result.content[0].type).toBe('text');
    expect(result.content[0].text).toContain('Top Talkers Analysis');
    expect(result.content[0].text).toContain('192.168.1.100');
  });

  it('should analyze protocols', async () => {
    const mockResponse: SessionsResponse = {
      data: [
        { id: 's1', lastPacket: 1, ipProtocol: 6 },
        { id: 's2', lastPacket: 1, ipProtocol: 6 },
        { id: 's3', lastPacket: 1, ipProtocol: 17 },
        { id: 's4', lastPacket: 1, ipProtocol: 1 },
      ],
      recordsTotal: 4,
      recordsFiltered: 4,
    };

    const client = {
      searchSessions: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await analyzeTraffic(client, {
      analysisType: 'protocols',
      limit: 10,
    });

    expect(result.content[0].text).toContain('Protocol Analysis');
    expect(result.content[0].text).toContain('TCP');
  });

  it('should analyze ports', async () => {
    const mockResponse: SessionsResponse = {
      data: [
        { id: 's1', lastPacket: 1, destination: { port: 443 } },
        { id: 's2', lastPacket: 1, destination: { port: 443 } },
        { id: 's3', lastPacket: 1, destination: { port: 80 } },
      ],
      recordsTotal: 3,
      recordsFiltered: 3,
    };

    const client = {
      searchSessions: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await analyzeTraffic(client, {
      analysisType: 'ports',
      limit: 10,
    });

    expect(result.content[0].text).toContain('Port Analysis');
    expect(result.content[0].text).toContain('443');
  });

  it('should analyze connections', async () => {
    const mockResponse: SessionsResponse = {
      data: [
        {
          id: 's1',
          lastPacket: 1,
          source: { ip: '192.168.1.1' },
          destination: { ip: '10.0.0.1', port: 443 },
        },
        {
          id: 's2',
          lastPacket: 1,
          source: { ip: '192.168.1.1' },
          destination: { ip: '10.0.0.2', port: 80 },
        },
      ],
      recordsTotal: 2,
      recordsFiltered: 2,
    };

    const client = {
      searchSessions: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await analyzeTraffic(client, {
      analysisType: 'connections',
      limit: 10,
    });

    expect(result.content[0].text).toContain('Connection Pairs');
  });

  it('should handle empty results', async () => {
    const mockResponse: SessionsResponse = {
      data: [],
      recordsTotal: 0,
      recordsFiltered: 0,
    };

    const client = {
      searchSessions: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await analyzeTraffic(client, {
      analysisType: 'top-talkers',
      limit: 10,
    });

    expect(result.content[0].text).toContain('No sessions found');
  });
});

describe('huntSuspicious', () => {
  it('should hunt for port scanners', async () => {
    const sessions: Session[] = [];
    for (let i = 0; i < 150; i++) {
      sessions.push({
        id: `s${i}`,
        lastPacket: 1,
        source: { ip: '192.168.1.100' },
        destination: { ip: '10.0.0.1', port: i + 1 },
      });
    }

    const mockResponse: SessionsResponse = {
      data: sessions,
      recordsTotal: 150,
      recordsFiltered: 150,
    };

    const client = {
      searchSessions: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await huntSuspicious(client, {
      huntType: 'port-scanners',
      threshold: 100,
    });

    expect(result.content[0].text).toContain('Port Scanners');
    expect(result.content[0].text).toContain('192.168.1.100');
  });

  it('should hunt for data exfiltration', async () => {
    const mockResponse: SessionsResponse = {
      data: [
        {
          id: 's1',
          lastPacket: 1,
          source: { ip: '192.168.1.100', bytes: 100000000 },
          destination: { ip: '10.0.0.1', port: 443 },
        },
        {
          id: 's2',
          lastPacket: 1,
          source: { ip: '192.168.1.100', bytes: 50000000 },
          destination: { ip: '10.0.0.2', port: 443 },
        },
      ],
      recordsTotal: 2,
      recordsFiltered: 2,
    };

    const client = {
      searchSessions: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await huntSuspicious(client, {
      huntType: 'data-exfil',
      threshold: 50,
    });

    expect(result.content[0].text).toContain('Data Exfiltration');
    expect(result.content[0].text).toContain('192.168.1.100');
  });

  it('should return empty when no suspicious activity found', async () => {
    const mockResponse: SessionsResponse = {
      data: [
        {
          id: 's1',
          lastPacket: 1,
          source: { ip: '192.168.1.100' },
          destination: { ip: '10.0.0.1', port: 443 },
        },
      ],
      recordsTotal: 1,
      recordsFiltered: 1,
    };

    const client = {
      searchSessions: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await huntSuspicious(client, {
      huntType: 'port-scanners',
      threshold: 100,
    });

    expect(result.content[0].text).toContain('No port scanners detected');
  });

  it('should hunt for beaconing patterns', async () => {
    const sessions: Session[] = [];
    const baseTime = 1704067200000;
    for (let i = 0; i < 10; i++) {
      sessions.push({
        id: `s${i}`,
        firstPacket: baseTime + i * 60000, // Every 60 seconds
        lastPacket: baseTime + i * 60000,
        source: { ip: '192.168.1.100' },
        destination: { ip: '10.0.0.50', port: 443 },
        network: { bytes: 500 },
      });
    }

    const mockResponse: SessionsResponse = {
      data: sessions,
      recordsTotal: 10,
      recordsFiltered: 10,
    };

    const client = {
      searchSessions: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await huntSuspicious(client, {
      huntType: 'beaconing',
      threshold: 5,
    });

    expect(result.content[0].text).toContain('Beaconing');
    expect(result.content[0].text).toContain('192.168.1.100');
  });

  it('should return no beaconing when intervals are irregular', async () => {
    const sessions: Session[] = [
      { id: 's1', firstPacket: 1000, lastPacket: 1000, source: { ip: '192.168.1.100' }, destination: { ip: '10.0.0.1', port: 443 }, network: { bytes: 100 } },
      { id: 's2', firstPacket: 2000, lastPacket: 2000, source: { ip: '192.168.1.100' }, destination: { ip: '10.0.0.1', port: 443 }, network: { bytes: 100 } },
      { id: 's3', firstPacket: 5000, lastPacket: 5000, source: { ip: '192.168.1.100' }, destination: { ip: '10.0.0.1', port: 443 }, network: { bytes: 100 } },
      { id: 's4', firstPacket: 30000, lastPacket: 30000, source: { ip: '192.168.1.100' }, destination: { ip: '10.0.0.1', port: 443 }, network: { bytes: 100 } },
      { id: 's5', firstPacket: 500000, lastPacket: 500000, source: { ip: '192.168.1.100' }, destination: { ip: '10.0.0.1', port: 443 }, network: { bytes: 100 } },
    ];

    const mockResponse: SessionsResponse = {
      data: sessions,
      recordsTotal: 5,
      recordsFiltered: 5,
    };

    const client = {
      searchSessions: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await huntSuspicious(client, {
      huntType: 'beaconing',
      threshold: 3,
    });

    expect(result.content[0].text).toContain('No beaconing');
  });

  it('should hunt for lateral movement', async () => {
    const sessions: Session[] = [];
    // Generate sessions from one internal IP to multiple internal IPs on suspicious ports
    for (let i = 0; i < 20; i++) {
      sessions.push({
        id: `s${i}`,
        lastPacket: 1,
        source: { ip: '192.168.1.50' },
        destination: { ip: `10.0.0.${i}`, port: 445 },
      });
    }

    const mockResponse: SessionsResponse = {
      data: sessions,
      recordsTotal: 20,
      recordsFiltered: 20,
    };

    const client = {
      searchSessions: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await huntSuspicious(client, {
      huntType: 'lateral-movement',
      threshold: 50,
    });

    expect(result.content[0].text).toContain('Lateral Movement');
    expect(result.content[0].text).toContain('192.168.1.50');
  });

  it('should return no lateral movement for external traffic only', async () => {
    const mockResponse: SessionsResponse = {
      data: [
        {
          id: 's1',
          lastPacket: 1,
          source: { ip: '8.8.8.8' },
          destination: { ip: '192.168.1.100', port: 443 },
        },
      ],
      recordsTotal: 1,
      recordsFiltered: 1,
    };

    const client = {
      searchSessions: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await huntSuspicious(client, {
      huntType: 'lateral-movement',
      threshold: 50,
    });

    expect(result.content[0].text).toContain('No lateral movement');
  });

  it('should throw McpError for unknown hunt type', async () => {
    const client = {} as unknown as ArkimeClient;

    await expect(huntSuspicious(client, {
      huntType: 'nonexistent' as any,
      threshold: 10,
    })).rejects.toThrow(McpError);
  });

  it('should include error code in unknown hunt type error', async () => {
    const client = {} as unknown as ArkimeClient;

    try {
      await huntSuspicious(client, {
        huntType: 'made-up-type' as any,
        threshold: 10,
      });
      expect('should have thrown').toBe('failed');
    } catch (error) {
      expect(error).toBeInstanceOf(McpError);
      const mcpError = error as McpError;
      expect(mcpError.code).toBe(ErrorCode.INVALID_INPUT);
      expect(mcpError.message).toContain('made-up-type');
    }
  });

  it('should detect beaconing with jitter (58-62s intervals)', async () => {
    // Simulate C2 beaconing with realistic jitter (e.g., 60s beacon +/- 10%)
    const sessions: Session[] = [];
    const baseTime = 1704067200000;
    const jitterPattern = [58, 62, 59, 61, 58, 60, 62, 59, 61, 58, 60, 59, 62, 61, 58];
    let currentTime = baseTime;
    for (let i = 0; i < jitterPattern.length; i++) {
      sessions.push({
        id: `s${i}`,
        firstPacket: currentTime,
        lastPacket: currentTime,
        source: { ip: '192.168.1.50' },
        destination: { ip: '203.0.113.100', port: 443 },
        network: { bytes: 256 },
      });
      currentTime += jitterPattern[i] * 1000;
    }

    const mockResponse: SessionsResponse = {
      data: sessions,
      recordsTotal: sessions.length,
      recordsFiltered: sessions.length,
    };

    const client = {
      searchSessions: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await huntSuspicious(client, {
      huntType: 'beaconing',
      threshold: 5,
    });

    // Should detect as beaconing despite jitter (high regularity)
    expect(result.content[0].text).toContain('Beaconing');
    expect(result.content[0].text).toContain('192.168.1.50');
  });

  it('should detect slow-low data exfiltration with small transfers', async () => {
    // Simulate slow-low exfiltration: many small outbound transfers
    // that cumulatively exceed threshold
    const sessions: Session[] = [];
    for (let i = 0; i < 50; i++) {
      sessions.push({
        id: `s${i}`,
        lastPacket: 1,
        source: { ip: '192.168.1.200', bytes: 1500000 }, // ~1.5MB each
        destination: { ip: `198.51.100.${i % 10 + 1}`, port: 443 },
      });
    }

    const mockResponse: SessionsResponse = {
      data: sessions,
      recordsTotal: 50,
      recordsFiltered: 50,
    };

    const client = {
      searchSessions: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await huntSuspicious(client, {
      huntType: 'data-exfil',
      threshold: 50, // 50 MB threshold
    });

    // 50 * 1.5MB = 75MB outbound, should exceed 50MB threshold
    expect(result.content[0].text).toContain('Data Exfiltration');
    expect(result.content[0].text).toContain('192.168.1.200');
  });

  it('should detect DNS tunneling indicators (many DNS sessions to single domain)', async () => {
    // DNS tunneling: many DNS sessions from one internal host to the same
    // external resolver querying increasingly long/unique subdomains
    const sessions: Session[] = [];
    for (let i = 0; i < 100; i++) {
      sessions.push({
        id: `dns-${i}`,
        lastPacket: 1704067200000 + i * 1000,
        firstPacket: 1704067200000 + i * 1000,
        source: { ip: '192.168.1.75' },
        destination: { ip: '198.51.100.53', port: 53 },
        ipProtocol: 17,
        network: { bytes: 512 },
        dns: { host: `data${i}.tunnel.example.com` },
      });
    }

    const mockResponse: SessionsResponse = {
      data: sessions,
      recordsTotal: 100,
      recordsFiltered: 100,
    };

    const client = {
      searchSessions: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await huntSuspicious(client, {
      huntType: 'beaconing',
      threshold: 10,
    });

    // Many frequent DNS sessions to same destination should show as beaconing
    expect(result.content[0].text).toContain('Beaconing');
    expect(result.content[0].text).toContain('192.168.1.75');
  });

  describe('API error handling', () => {
    it('should propagate 500 Internal Server Error', async () => {
      const client = {
        searchSessions: async () => {
          const error: McpError = new McpError(ErrorCode.API_ERROR, 'Internal Server Error');
          throw error;
        },
      } as unknown as ArkimeClient;

      await expect(analyzeTraffic(client, {
        analysisType: 'top-talkers',
        limit: 10,
      })).rejects.toThrow(McpError);

      try {
        await analyzeTraffic(client, {
          analysisType: 'top-talkers',
          limit: 10,
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

      await expect(analyzeTraffic(client, {
        analysisType: 'top-talkers',
        limit: 10,
      })).rejects.toThrow(McpError);

      try {
        await analyzeTraffic(client, {
          analysisType: 'top-talkers',
          limit: 10,
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

      await expect(analyzeTraffic(client, {
        analysisType: 'top-talkers',
        limit: 10,
      })).rejects.toThrow(McpError);

      try {
        await analyzeTraffic(client, {
          analysisType: 'top-talkers',
          limit: 10,
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

      await expect(analyzeTraffic(client, {
        analysisType: 'top-talkers',
        limit: 10,
      })).rejects.toThrow(McpError);

      try {
        await analyzeTraffic(client, {
          analysisType: 'top-talkers',
          limit: 10,
        });
      } catch (error) {
        expect(error).toBeInstanceOf(McpError);
        expect((error as McpError).code).toBe(ErrorCode.NETWORK_ERROR);
        expect((error as McpError).message).toContain('timed out');
      }
    });
  });
});
