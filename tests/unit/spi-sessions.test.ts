import { describe, it, expect } from 'vitest';
import { getSessionSpi } from '@/controllers/sessions';
import type { ArkimeClient } from '@/services/arkime-client';
import type { SessionsResponse } from '@/types/arkime';

describe('getSessionSpi', () => {
  it('should format sessions with DNS SPI data', async () => {
    const mockResponse: SessionsResponse = {
      data: [
        {
          id: 'session-1',
          lastPacket: 1704067200000,
          source: { ip: '192.168.1.100', port: 54321 },
          destination: { ip: '8.8.8.8', port: 53 },
          ipProtocol: 17,
          dns: { host: 'example.com', ip: '93.184.216.34' },
        },
      ],
      recordsTotal: 1,
      recordsFiltered: 1,
    };

    const client = {
      searchSessions: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await getSessionSpi(client, {
      expression: 'dns.host contains example',
      categories: ['dns'],
      limit: 10,
    });

    expect(result.content[0].type).toBe('text');
    expect(result.content[0].text).toContain('Session SPI Data (1 sessions)');
    expect(result.content[0].text).toContain('session-1');
    expect(result.content[0].text).toContain('192.168.1.100');
    expect(result.content[0].text).toContain('8.8.8.8');
    expect(result.content[0].text).toContain('[DNS]');
    expect(result.content[0].text).toContain('dns.host: example.com');
    expect(result.content[0].text).toContain('dns.ip: 93.184.216.34');
  });

  it('should format sessions with HTTP SPI data', async () => {
    const mockResponse: SessionsResponse = {
      data: [
        {
          id: 'session-2',
          lastPacket: 1704067200000,
          source: { ip: '10.0.0.5', port: 12345 },
          destination: { ip: '172.16.0.1', port: 443 },
          ipProtocol: 6,
          http: { uri: '/api/login', method: 'POST', host: 'app.example.com' },
        },
      ],
      recordsTotal: 1,
      recordsFiltered: 1,
    };

    const client = {
      searchSessions: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await getSessionSpi(client, {
      expression: 'http.uri contains /api',
      categories: ['http'],
      limit: 10,
    });

    expect(result.content[0].text).toContain('[HTTP]');
    expect(result.content[0].text).toContain('http.uri: /api/login');
    expect(result.content[0].text).toContain('http.method: POST');
    expect(result.content[0].text).toContain('http.host: app.example.com');
  });

  it('should format sessions with TLS SPI data', async () => {
    const mockResponse: SessionsResponse = {
      data: [
        {
          id: 'session-3',
          lastPacket: 1704067200000,
          source: { ip: '10.0.0.5', port: 54321 },
          destination: { ip: '203.0.113.50', port: 443 },
          ipProtocol: 6,
          tls: { sni: 'secure.example.com', cn: 'secure.example.com', version: 'TLSv1.3' },
        },
      ],
      recordsTotal: 1,
      recordsFiltered: 1,
    };

    const client = {
      searchSessions: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await getSessionSpi(client, {
      expression: 'tls.sni contains secure',
      categories: ['tls'],
      limit: 10,
    });

    expect(result.content[0].text).toContain('[TLS]');
    expect(result.content[0].text).toContain('tls.sni: secure.example.com');
    expect(result.content[0].text).toContain('tls.cn: secure.example.com');
    expect(result.content[0].text).toContain('tls.version: TLSv1.3');
  });

  it('should format sessions with multiple SPI categories', async () => {
    const mockResponse: SessionsResponse = {
      data: [
        {
          id: 'session-multi',
          lastPacket: 1704067200000,
          source: { ip: '10.0.0.5', port: 54321 },
          destination: { ip: '203.0.113.50', port: 443 },
          ipProtocol: 6,
          http: { uri: '/api/data', method: 'GET' },
          tls: { sni: 'api.example.com', version: 'TLSv1.2' },
        },
      ],
      recordsTotal: 1,
      recordsFiltered: 1,
    };

    const client = {
      searchSessions: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await getSessionSpi(client, {
      expression: 'ip.dst == 203.0.113.50',
      categories: ['http', 'tls'],
      limit: 10,
    });

    expect(result.content[0].text).toContain('[HTTP]');
    expect(result.content[0].text).toContain('[TLS]');
    expect(result.content[0].text).toContain('http.uri: /api/data');
    expect(result.content[0].text).toContain('tls.sni: api.example.com');
  });

  it('should include all categories when "all" is specified', async () => {
    const mockResponse: SessionsResponse = {
      data: [
        {
          id: 'session-all',
          lastPacket: 1704067200000,
          source: { ip: '10.0.0.5', port: 54321 },
          destination: { ip: '203.0.113.50', port: 443 },
          ipProtocol: 6,
          dns: { host: 'example.com' },
          http: { uri: '/index.html' },
          tls: { sni: 'example.com' },
        },
      ],
      recordsTotal: 1,
      recordsFiltered: 1,
    };

    const client = {
      searchSessions: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await getSessionSpi(client, {
      expression: 'ip.dst == 203.0.113.50',
      categories: ['all'],
      limit: 10,
    });

    expect(result.content[0].text).toContain('[DNS]');
    expect(result.content[0].text).toContain('[HTTP]');
    expect(result.content[0].text).toContain('[TLS]');
  });

  it('should return empty message for no results', async () => {
    const mockResponse: SessionsResponse = {
      data: [],
      recordsTotal: 0,
      recordsFiltered: 0,
    };

    const client = {
      searchSessions: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await getSessionSpi(client, {
      expression: 'dns.host contains nonexistent',
      categories: ['dns'],
      limit: 10,
    });

    expect(result.content[0].text).toContain('No sessions found matching');
    expect(result.content[0].text).toContain('nonexistent');
  });

  it('should handle session with no SPI data for requested categories', async () => {
    const mockResponse: SessionsResponse = {
      data: [
        {
          id: 'session-nospi',
          lastPacket: 1704067200000,
          source: { ip: '10.0.0.5', port: 54321 },
          destination: { ip: '203.0.113.50', port: 80 },
          ipProtocol: 6,
        },
      ],
      recordsTotal: 1,
      recordsFiltered: 1,
    };

    const client = {
      searchSessions: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await getSessionSpi(client, {
      expression: 'ip.dst == 203.0.113.50',
      categories: ['dns'],
      limit: 10,
    });

    expect(result.content[0].text).toContain('Session SPI Data (1 sessions)');
    expect(result.content[0].text).toContain('session-nospi');
    expect(result.content[0].text).not.toContain('[DNS]');
  });

  it('should handle multiple sessions', async () => {
    const mockResponse: SessionsResponse = {
      data: [
        {
          id: 'session-1',
          lastPacket: 1704067200000,
          source: { ip: '10.0.0.1', port: 5000 },
          destination: { ip: '8.8.8.8', port: 53 },
          dns: { host: 'one.com' },
        },
        {
          id: 'session-2',
          lastPacket: 1704067201000,
          source: { ip: '10.0.0.2', port: 5001 },
          destination: { ip: '8.8.4.4', port: 53 },
          dns: { host: 'two.com' },
        },
      ],
      recordsTotal: 2,
      recordsFiltered: 2,
    };

    const client = {
      searchSessions: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await getSessionSpi(client, {
      expression: 'port.dst == 53',
      categories: ['dns'],
      limit: 10,
    });

    expect(result.content[0].text).toContain('Session SPI Data (2 sessions)');
    expect(result.content[0].text).toContain('session-1');
    expect(result.content[0].text).toContain('session-2');
    expect(result.content[0].text).toContain('one.com');
    expect(result.content[0].text).toContain('two.com');
  });

  it('should truncate long SPI values at 200 characters', async () => {
    const longValue = 'x'.repeat(300);
    const mockResponse: SessionsResponse = {
      data: [
        {
          id: 'session-long',
          lastPacket: 1704067200000,
          source: { ip: '10.0.0.5', port: 54321 },
          destination: { ip: '203.0.113.50', port: 443 },
          http: { uri: longValue },
        },
      ],
      recordsTotal: 1,
      recordsFiltered: 1,
    };

    const client = {
      searchSessions: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await getSessionSpi(client, {
      expression: 'http.uri contains x',
      categories: ['http'],
      limit: 10,
    });

    expect(result.content[0].text).toContain('http.uri:');
    expect(result.content[0].text).toContain('...');
    const lines = result.content[0].text.split('\n');
    const uriLine = lines.find((l) => l.includes('http.uri'));
    expect(uriLine).toBeDefined();
    // The displayed value should be truncated to 200 chars + "..."
    expect(uriLine!.split('http.uri: ')[1]).toHaveLength(203); // 200 + "..."
  });

  it('should handle array SPI values by joining with comma', async () => {
    const mockResponse: SessionsResponse = {
      data: [
        {
          id: 'session-array',
          lastPacket: 1704067200000,
          source: { ip: '10.0.0.5', port: 54321 },
          destination: { ip: '8.8.8.8', port: 53 },
          dns: { host: ['a.com', 'b.com', 'c.com'] },
        },
      ],
      recordsTotal: 1,
      recordsFiltered: 1,
    };

    const client = {
      searchSessions: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await getSessionSpi(client, {
      expression: 'dns.host contains com',
      categories: ['dns'],
      limit: 10,
    });

    expect(result.content[0].text).toContain('dns.host: a.com, b.com, c.com');
  });

  it('should propagate errors from client', async () => {
    const client = {
      searchSessions: async () => { throw new Error('API timeout'); },
    } as unknown as ArkimeClient;

    await expect(getSessionSpi(client, {
      expression: 'dns.host contains example',
      categories: ['dns'],
      limit: 10,
    })).rejects.toThrow('API timeout');
  });

  it('should filter out empty and null SPI values', async () => {
    const mockResponse: SessionsResponse = {
      data: [
        {
          id: 'session-empty',
          lastPacket: 1704067200000,
          source: { ip: '10.0.0.5', port: 54321 },
          destination: { ip: '8.8.8.8', port: 53 },
          dns: { host: 'example.com', ip: null, ans: [], ns: {} },
        },
      ],
      recordsTotal: 1,
      recordsFiltered: 1,
    };

    const client = {
      searchSessions: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await getSessionSpi(client, {
      expression: 'dns.host contains example',
      categories: ['dns'],
      limit: 10,
    });

    expect(result.content[0].text).toContain('dns.host: example.com');
    expect(result.content[0].text).not.toContain('dns.ip:');
    expect(result.content[0].text).not.toContain('dns.ans:');
    expect(result.content[0].text).not.toContain('dns.ns:');
  });

  it('should skip categories with no data in output', async () => {
    const mockResponse: SessionsResponse = {
      data: [
        {
          id: 'session-skip',
          lastPacket: 1704067200000,
          source: { ip: '10.0.0.5', port: 54321 },
          destination: { ip: '203.0.113.50', port: 443 },
          http: { uri: '/test' },
        },
      ],
      recordsTotal: 1,
      recordsFiltered: 1,
    };

    const client = {
      searchSessions: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await getSessionSpi(client, {
      expression: 'http.uri contains test',
      categories: ['http', 'tls', 'dns'],
      limit: 10,
    });

    expect(result.content[0].text).toContain('[HTTP]');
    expect(result.content[0].text).not.toContain('[TLS]');
    expect(result.content[0].text).not.toContain('[DNS]');
  });

  it('should handle session with missing source/destination', async () => {
    const mockResponse: SessionsResponse = {
      data: [
        {
          id: 'session-nosrc',
          lastPacket: 1704067200000,
          dns: { host: 'orphan.com' },
        },
      ],
      recordsTotal: 1,
      recordsFiltered: 1,
    };

    const client = {
      searchSessions: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await getSessionSpi(client, {
      expression: 'dns.host contains orphan',
      categories: ['dns'],
      limit: 10,
    });

    expect(result.content[0].text).toContain('Source: -');
    expect(result.content[0].text).toContain('Dest: -');
    expect(result.content[0].text).toContain('orphan.com');
  });
});
