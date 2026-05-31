import { describe, it, expect } from 'vitest';
import {
  topTalkers,
  reverseDns,
  dnsLookups,
  geoSummary,
  captureStatus,
  pcapFiles,
} from '@/controllers/explorer.js';
import { formatUniqueTable } from '@/utils/formatters.js';
import { ArkimeClient } from '@/services/arkime-client.js';
import type { UniqueResponse, ClusterResponse, FilesResponse, SessionsResponse } from '@/types/arkime.js';

describe('topTalkers', () => {
  it('should return formatted top values', async () => {
    const mockResponse: UniqueResponse = {
      success: true,
      totalInPeriod: 1500,
      totalOverall: 5000,
      value: [
        { value: '192.168.1.100', count: 500 },
        { value: '10.0.0.50', count: 300 },
        { value: '172.16.0.1', count: 200 },
      ],
    };

    const client = {
      getUniqueField: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await topTalkers(client, {
      field: 'sourceIP',
      limit: 10,
    });

    expect(result.isError).toBeUndefined();
    expect(result.content[0].type).toBe('text');
    expect(result.content[0].text).toContain('Top values for');
    expect(result.content[0].text).toContain('sourceIP');
    expect(result.content[0].text).toContain('1500 in period');
    expect(result.content[0].text).toContain('5000 overall');
    expect(result.content[0].text).toContain('192.168.1.100');
    expect(result.content[0].text).toContain('500');
  });

  it('should handle empty results', async () => {
    const mockResponse: UniqueResponse = {
      success: true,
      totalInPeriod: 0,
      totalOverall: 0,
      value: [],
    };

    const client = {
      getUniqueField: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await topTalkers(client, {
      field: 'nonExistent',
    });

    expect(result.content[0].text).toContain('No values found for field');
  });
});

describe('formatUniqueTable', () => {
  it('should format values as a table', () => {
    const values = [
      { value: 'alpha', count: 100 },
      { value: 'beta', count: 50 },
    ];

    const table = formatUniqueTable(values);

    expect(table).toContain('Count');
    expect(table).toContain('Value');
    expect(table).toContain('alpha');
    expect(table).toContain('100');
    expect(table).toContain('beta');
    expect(table).toContain('50');
  });
});

describe('reverseDns', () => {
  it('should return reverse DNS records', async () => {
    const mockResponse: UniqueResponse = {
      success: true,
      totalInPeriod: 200,
      totalOverall: 800,
      value: [
        { value: 'server1.example.com', count: 150 },
        { value: 'server2.example.com', count: 50 },
      ],
    };

    const client = {
      getUniqueField: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await reverseDns(client, {
      ipAddress: '10.0.0.1',
    });

    expect(result.content[0].text).toContain('Reverse DNS for 10.0.0.1');
    expect(result.content[0].text).toContain('server1.example.com');
  });

  it('should handle no reverse DNS records', async () => {
    const mockResponse: UniqueResponse = {
      success: true,
      totalInPeriod: 0,
      totalOverall: 0,
      value: [],
    };

    const client = {
      getUniqueField: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await reverseDns(client, {
      ipAddress: '10.0.0.99',
    });

    expect(result.content[0].text).toContain('No reverse DNS records found for 10.0.0.99');
  });
});

describe('dnsLookups', () => {
  it('should return DNS query analysis', async () => {
    const mockResponse: SessionsResponse = {
      data: [
        {
          id: 'dns-1',
          lastPacket: 1704067200,
          firstPacket: 1704067100,
          source: { ip: '192.168.1.100' },
          destination: { ip: '10.0.0.53' },
          dns: {
            host: 'example.com',
            question: 'example.com',
            questionType: 'A',
            ans: '93.184.216.34',
          },
        },
        {
          id: 'dns-2',
          lastPacket: 1704067300,
          firstPacket: 1704067200,
          source: { ip: '192.168.1.101' },
          destination: { ip: '10.0.0.53' },
          dns: {
            host: 'google.com',
            question: 'google.com',
            questionType: 'AAAA',
            ans: '2607:f8b0:4004:800::2004',
          },
        },
      ],
      recordsTotal: 2,
      recordsFiltered: 2,
    };

    const client = {
      searchSessions: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await dnsLookups(client, {});

    expect(result.content[0].text).toContain('DNS Query Analysis');
    expect(result.content[0].text).toContain('example.com');
    expect(result.content[0].text).toContain('93.184.216.34');
    expect(result.content[0].text).toContain('Total: 2 DNS queries');
  });

  it('should handle empty DNS results', async () => {
    const mockResponse: SessionsResponse = {
      data: [],
      recordsTotal: 0,
      recordsFiltered: 0,
    };

    const client = {
      searchSessions: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await dnsLookups(client, {});

    expect(result.content[0].text).toContain('No DNS queries found');
  });

  it('should filter by domain pattern and source IP', async () => {
    const mockResponse: SessionsResponse = {
      data: [
        {
          id: 'dns-1',
          lastPacket: 1704067200,
          firstPacket: 1704067100,
          source: { ip: '192.168.1.100' },
          destination: { ip: '10.0.0.53' },
          dns: { host: 'test.example.com', question: 'test.example.com', questionType: 'A' },
        },
      ],
      recordsTotal: 1,
      recordsFiltered: 1,
    };

    const client = {
      searchSessions: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await dnsLookups(client, {
      domainPattern: 'example.com',
      sourceIp: '192.168.1.100',
    });

    expect(result.content[0].text).toContain('DNS Query Analysis');
  });
});

describe('geoSummary', () => {
  it('should return geo summary with percentages', async () => {
    const mockResponse: UniqueResponse = {
      success: true,
      totalInPeriod: 1000,
      totalOverall: 3000,
      value: [
        { value: 'US', count: 500 },
        { value: 'DE', count: 250 },
        { value: 'CN', count: 150 },
        { value: 'GB', count: 100 },
      ],
    };

    const client = {
      getUniqueField: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await geoSummary(client, {});

    expect(result.content[0].text).toContain('Destination Traffic by Country');
    expect(result.content[0].text).toContain('US');
    expect(result.content[0].text).toContain('50.0%');
    expect(result.content[0].text).toContain('DE');
    expect(result.content[0].text).toContain('Total sessions with geo data: 1000');
  });

  it('should handle no geo data', async () => {
    const mockResponse: UniqueResponse = {
      success: true,
      totalInPeriod: 0,
      totalOverall: 0,
      value: [],
    };

    const client = {
      getUniqueField: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await geoSummary(client, {});

    expect(result.content[0].text).toContain('No geo data found');
  });
});

describe('captureStatus', () => {
  it('should return cluster status', async () => {
    const now = Date.now() / 1000;
    const mockResponse: ClusterResponse = {
      success: true,
      viewerNodes: [
        {
          host: 'viewer1.example.com',
          version: '4.2.0',
          roles: ['viewer', 'scheduler'],
          started: now - 86400,
          updated: now,
        },
      ],
      captureNodes: [
        {
          host: 'capture1.example.com',
          version: '4.2.0',
          roles: ['capture', 'reader'],
          started: now - 172800,
          updated: now,
        },
        {
          host: 'capture2.example.com',
          version: '4.2.0',
          roles: ['capture'],
          started: now - 3600,
          updated: now,
        },
      ],
    };

    const client = {
      getClusters: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await captureStatus(client, {});

    expect(result.content[0].text).toContain('Arkime Cluster Status');
    expect(result.content[0].text).toContain('Viewer Nodes: 1');
    expect(result.content[0].text).toContain('Capture Nodes: 2');
    expect(result.content[0].text).toContain('viewer1.example.com');
    expect(result.content[0].text).toContain('capture1.example.com');
    expect(result.content[0].text).toContain('v4.2.0');
    expect(result.content[0].text).toContain('uptime:');
  });

  it('should handle empty cluster', async () => {
    const mockResponse: ClusterResponse = {
      success: true,
      viewerNodes: [],
      captureNodes: [],
    };

    const client = {
      getClusters: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await captureStatus(client, {});

    expect(result.content[0].text).toContain('Arkime Cluster Status');
    expect(result.content[0].text).toContain('Viewer Nodes: 0');
    expect(result.content[0].text).toContain('Capture Nodes: 0');
  });
});

describe('pcapFiles', () => {
  it('should return PCAP files list', async () => {
    const mockResponse: FilesResponse = {
      success: true,
      total: 250,
      files: [
        {
          filename: 'capture1_20250101.pcap',
          node: 'capture1',
          sessions: 15000,
          totalLen: 2147483648,
          dateFirst: 1704067200,
          dateLast: 1704153600,
        },
        {
          filename: 'capture2_20250102.pcap',
          node: 'capture2',
          sessions: 500,
          totalLen: 1048576,
          dateFirst: 1704153600,
          dateLast: 1704240000,
        },
      ],
    };

    const client = {
      getFiles: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await pcapFiles(client, {});

    expect(result.content[0].text).toContain('PCAP Files');
    expect(result.content[0].text).toContain('250 total');
    expect(result.content[0].text).toContain('capture1_20250101.pcap');
    expect(result.content[0].text).toContain('2.00 GB');
    expect(result.content[0].text).toContain('capture2_20250102.pcap');
    expect(result.content[0].text).toContain('1.0 MB');
  });

  it('should handle no PCAP files', async () => {
    const mockResponse: FilesResponse = {
      success: true,
      total: 0,
      files: [],
    };

    const client = {
      getFiles: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await pcapFiles(client, {});

    expect(result.content[0].text).toContain('No PCAP files found');
  });

  it('should format bytes correctly', async () => {
    const mockResponse: FilesResponse = {
      success: true,
      total: 1,
      files: [
        {
          filename: 'small.pcap',
          node: 'node1',
          sessions: 10,
          totalLen: 512,
          dateFirst: 1704067200,
          dateLast: 1704067300,
        },
      ],
    };

    const client = {
      getFiles: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await pcapFiles(client, {});

    expect(result.content[0].text).toContain('512 B');
  });
});
