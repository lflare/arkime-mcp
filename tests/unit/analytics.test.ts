import { describe, it, expect } from 'vitest';
import {
  spiGraph,
  spiGraphHierarchy,
  buildQuery,
  listDecodings,
} from '@/controllers/analytics.js';
import { ArkimeClient } from '@/services/arkime-client.js';
import type {
  SpiGraphResponse,
  SpiGraphHierarchyResponse,
  BuildQueryResponse,
  DecodingsResponse,
} from '@/types/arkime.js';

describe('spiGraph', () => {
  it('should return formatted SPI graph items sorted by count', async () => {
    const mockResponse: SpiGraphResponse = {
      success: true,
      recordsTotal: 1000,
      recordsFiltered: 750,
      items: [
        { name: '10.0.0.50', count: 120 },
        { name: '192.168.1.100', count: 540 },
        { name: '172.16.0.1', count: 300 },
      ],
    };

    const client = {
      getSpiGraph: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await spiGraph(client, { field: 'destination.ip', size: 10 });

    expect(result.content[0].type).toBe('text');
    const text = result.content[0].text;
    expect(text).toContain('SPI Graph: destination.ip');
    expect(text).toContain('1,000');
    expect(text).toContain('750');
    expect(text).toContain('192.168.1.100');
    expect(text).toContain('540');
    // sorted by count desc: 540 should appear before 300 and 120
    expect(text.indexOf('192.168.1.100')).toBeLessThan(text.indexOf('172.16.0.1'));
    expect(text.indexOf('172.16.0.1')).toBeLessThan(text.indexOf('10.0.0.50'));
  });

  it('should handle empty SPI graph results', async () => {
    const mockResponse: SpiGraphResponse = {
      success: true,
      recordsTotal: 0,
      recordsFiltered: 0,
      items: [],
    };

    const client = {
      getSpiGraph: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await spiGraph(client, { field: 'dns.host', size: 10 });

    expect(result.content[0].type).toBe('text');
    expect(result.content[0].text).toContain("No SPI graph data found for 'dns.host'.");
  });

  it('should handle undefined items', async () => {
    const mockResponse: SpiGraphResponse = {
      success: true,
    };

    const client = {
      getSpiGraph: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await spiGraph(client, { field: 'destination.port', size: 10 });

    expect(result.content[0].text).toContain("No SPI graph data found for 'destination.port'.");
  });
});

describe('spiGraphHierarchy', () => {
  it('should render tableResults when present', async () => {
    const mockResponse: SpiGraphHierarchyResponse = {
      success: true,
      tableResults: [
        { 'source.ip': '192.168.1.1', 'destination.ip': '10.0.0.1', count: 42 },
        { 'source.ip': '192.168.1.2', 'destination.ip': '10.0.0.2', count: 17 },
      ],
    };

    const client = {
      getSpiGraphHierarchy: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await spiGraphHierarchy(client, {
      fields: ['source.ip', 'destination.ip'],
    });

    expect(result.content[0].type).toBe('text');
    const text = result.content[0].text;
    expect(text).toContain('SPI Graph Hierarchy: source.ip > destination.ip');
    expect(text).toContain('192.168.1.1');
    expect(text).toContain('2');
  });

  it('should render hierarchicalResults when no tableResults', async () => {
    const mockResponse: SpiGraphHierarchyResponse = {
      success: true,
      hierarchicalResults: {
        name: 'root',
        children: [{ name: '192.168.1.1', size: 10 }],
      },
    };

    const client = {
      getSpiGraphHierarchy: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await spiGraphHierarchy(client, {
      fields: ['source.ip'],
    });

    const text = result.content[0].text;
    expect(text).toContain('SPI Graph Hierarchy: source.ip');
    expect(text).toContain('children');
    expect(text).toContain('192.168.1.1');
  });

  it('should handle no hierarchy data', async () => {
    const mockResponse: SpiGraphHierarchyResponse = {
      success: true,
    };

    const client = {
      getSpiGraphHierarchy: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await spiGraphHierarchy(client, {
      fields: ['source.ip', 'destination.ip'],
    });

    expect(result.content[0].text).toContain('No hierarchy data found.');
  });
});

describe('buildQuery', () => {
  it('should return the compiled esquery', async () => {
    const mockResponse: BuildQueryResponse = {
      success: true,
      esquery: {
        query: {
          bool: {
            filter: [{ term: { 'source.ip': '1.2.3.4' } }],
          },
        },
      },
      indices: ['sessions3-250101', 'sessions3-250102'],
    };

    const client = {
      getBuildQuery: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await buildQuery(client, { expression: 'ip.src == 1.2.3.4' });

    expect(result.content[0].type).toBe('text');
    const text = result.content[0].text;
    expect(text).toContain('Compiled query for: ip.src == 1.2.3.4');
    expect(text).toContain('Indices:');
    expect(text).toContain('sessions3-250101');
    expect(text).toContain('bool');
    expect(text).toContain('1.2.3.4');
  });

  it('should handle a response without esquery or indices', async () => {
    const mockResponse: BuildQueryResponse = {
      success: true,
    };

    const client = {
      getBuildQuery: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await buildQuery(client, { expression: 'port == 443' });

    const text = result.content[0].text;
    expect(text).toContain('Compiled query for: port == 443');
    // falls back to formatJson(response)
    expect(text).toContain('success');
  });
});

describe('listDecodings', () => {
  it('should list available packet decodings', async () => {
    const mockResponse: DecodingsResponse = {
      gzip: { title: 'Uncompress GZIP bodies', name: 'gzip' },
      smtp: { title: 'Decode SMTP', name: 'smtp' },
    };

    const client = {
      getDecodings: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await listDecodings(client, {});

    expect(result.content[0].type).toBe('text');
    const text = result.content[0].text;
    expect(text).toContain('Available Packet Decodings');
    expect(text).toContain('gzip: Uncompress GZIP bodies');
    expect(text).toContain('smtp: Decode SMTP');
  });

  it('should fall back to name when title is absent', async () => {
    const mockResponse: DecodingsResponse = {
      foo: { name: 'foo-decoder' },
    };

    const client = {
      getDecodings: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await listDecodings(client, {});

    expect(result.content[0].text).toContain('foo: foo-decoder');
  });

  it('should handle no decodings available', async () => {
    const mockResponse: DecodingsResponse = {};

    const client = {
      getDecodings: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await listDecodings(client, {});

    expect(result.content[0].text).toContain('No decodings available.');
  });
});
