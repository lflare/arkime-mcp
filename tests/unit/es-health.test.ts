import { describe, it, expect } from 'vitest';
import {
  esHealth,
  esStats,
  esIndices,
  esShards,
  esTasks,
  esRecovery,
  nodeDstats,
  appVersion,
} from '@/controllers/es-health.js';
import type { ArkimeClient } from '@/services/arkime-client.js';

describe('esHealth', () => {
  it('should return formatted ES health with labeled fields', async () => {
    const client = {
      getEsHealth: async () => ({
        status: 'green',
        number_of_nodes: 3,
        number_of_data_nodes: 2,
        active_primary_shards: 50,
        active_shards: 100,
        relocating_shards: 1,
        initializing_shards: 0,
        unassigned_shards: 4,
      }),
    } as unknown as ArkimeClient;

    const result = await esHealth(client, {});

    expect(result.content[0].type).toBe('text');
    expect(result.content[0].text).toContain('Elasticsearch/OpenSearch Health');
    expect(result.content[0].text).toContain('Status: green');
    expect(result.content[0].text).toContain('Nodes: 3');
    expect(result.content[0].text).toContain('Data Nodes: 2');
    expect(result.content[0].text).toContain('Active Primary Shards: 50');
    expect(result.content[0].text).toContain('Active Shards: 100');
    expect(result.content[0].text).toContain('Relocating: 1');
    expect(result.content[0].text).toContain('Initializing: 0');
    expect(result.content[0].text).toContain('Unassigned: 4');
  });

  it('should handle minimal response with only status', async () => {
    const client = {
      getEsHealth: async () => ({ status: 'yellow' }),
    } as unknown as ArkimeClient;

    const result = await esHealth(client, {});

    expect(result.content[0].text).toContain('Elasticsearch/OpenSearch Health');
    expect(result.content[0].text).toContain('Status: yellow');
    expect(result.content[0].text).not.toContain('Nodes:');
  });
});

describe('esStats', () => {
  it('should return formatted node stats list', async () => {
    const client = {
      getEsStats: async () => ({
        data: [{ name: 'node-1', docs: 1000 }, { name: 'node-2', docs: 2000 }],
        recordsTotal: 2,
      }),
    } as unknown as ArkimeClient;

    const result = await esStats(client, {});

    expect(result.content[0].text).toContain('Elasticsearch Node Stats');
    expect(result.content[0].text).toContain('Total: 2');
    expect(result.content[0].text).toContain('node-1');
    expect(result.content[0].text).toContain('node-2');
  });

  it('should handle empty stats', async () => {
    const client = {
      getEsStats: async () => ({ recordsTotal: 0 }),
    } as unknown as ArkimeClient;

    const result = await esStats(client, {});

    expect(result.content[0].text).toContain('No ES stats available.');
  });
});

describe('esIndices', () => {
  it('should return formatted indices list', async () => {
    const client = {
      getEsIndices: async () => ({
        data: [{ index: 'sessions2-250101', docsCount: 5000 }],
        recordsTotal: 1,
      }),
    } as unknown as ArkimeClient;

    const result = await esIndices(client, {});

    expect(result.content[0].text).toContain('Elasticsearch Indices');
    expect(result.content[0].text).toContain('Total: 1');
    expect(result.content[0].text).toContain('sessions2-250101');
  });

  it('should handle no indices', async () => {
    const client = {
      getEsIndices: async () => ({ recordsTotal: 0 }),
    } as unknown as ArkimeClient;

    const result = await esIndices(client, {});

    expect(result.content[0].text).toContain('No indices found.');
  });
});

describe('esShards', () => {
  it('should return formatted shards list', async () => {
    const client = {
      getEsShards: async () => ({
        data: [{ index: 'sessions2', shard: '0', state: 'STARTED' }],
        recordsTotal: 1,
      }),
    } as unknown as ArkimeClient;

    const result = await esShards(client, {});

    expect(result.content[0].text).toContain('Elasticsearch Shards');
    expect(result.content[0].text).toContain('Total: 1');
    expect(result.content[0].text).toContain('STARTED');
  });

  it('should fall back to dumping a keyed object when no data array', async () => {
    const client = {
      getEsShards: async () => ({
        success: true,
        nodes: { 'node-1': { shards: 10 } },
        nodeExcludes: [],
      }),
    } as unknown as ArkimeClient;

    const result = await esShards(client, {});

    expect(result.content[0].text).toContain('Elasticsearch Shards');
    expect(result.content[0].text).toContain('node-1');
  });

  it('should handle completely empty shard data', async () => {
    const client = {
      getEsShards: async () => ({ success: true, recordsTotal: 0 }),
    } as unknown as ArkimeClient;

    const result = await esShards(client, {});

    expect(result.content[0].text).toContain('No shard data available.');
  });
});

describe('esTasks', () => {
  it('should return formatted tasks list', async () => {
    const client = {
      getEsTasks: async () => ({
        data: [{ action: 'indices:data/write/bulk', node: 'node-1' }],
        recordsTotal: 1,
      }),
    } as unknown as ArkimeClient;

    const result = await esTasks(client, {});

    expect(result.content[0].text).toContain('Elasticsearch Tasks');
    expect(result.content[0].text).toContain('Total: 1');
    expect(result.content[0].text).toContain('indices:data/write/bulk');
  });

  it('should handle no running tasks', async () => {
    const client = {
      getEsTasks: async () => ({ recordsTotal: 0 }),
    } as unknown as ArkimeClient;

    const result = await esTasks(client, {});

    expect(result.content[0].text).toContain('No running tasks.');
  });
});

describe('esRecovery', () => {
  it('should return formatted recovery list', async () => {
    const client = {
      getEsRecovery: async () => ({
        data: [{ index: 'sessions2', stage: 'DONE', sourceNode: 'node-1' }],
        recordsTotal: 1,
      }),
    } as unknown as ArkimeClient;

    const result = await esRecovery(client, {});

    expect(result.content[0].text).toContain('Elasticsearch Shard Recovery');
    expect(result.content[0].text).toContain('Total: 1');
    expect(result.content[0].text).toContain('DONE');
  });

  it('should handle no recovery data', async () => {
    const client = {
      getEsRecovery: async () => ({ recordsTotal: 0 }),
    } as unknown as ArkimeClient;

    const result = await esRecovery(client, {});

    expect(result.content[0].text).toContain('No recovery data.');
  });
});

describe('nodeDstats', () => {
  it('should return formatted time-series stats', async () => {
    const client = {
      getDstats: async () => [
        { time: 1704067200, deltaPackets: 100 },
        { time: 1704067260, deltaPackets: 200 },
      ],
    } as unknown as ArkimeClient;

    const result = await nodeDstats(client, { nodeName: 'ALL' });

    expect(result.content[0].text).toContain('Node Time-Series Stats (ALL)');
    expect(result.content[0].text).toContain('deltaPackets');
  });

  it('should handle empty array of points', async () => {
    const client = {
      getDstats: async () => [],
    } as unknown as ArkimeClient;

    const result = await nodeDstats(client, { nodeName: 'ALL' });

    expect(result.content[0].text).toContain('Node Time-Series Stats (ALL)');
    expect(result.content[0].text).toContain('No time-series data returned.');
  });
});

describe('appVersion', () => {
  it('should return formatted version info', async () => {
    const client = {
      getAppVersion: async () => ({ version: '5.0.0', esVersion: '7.17.0' }),
    } as unknown as ArkimeClient;

    const result = await appVersion(client, {});

    expect(result.content[0].text).toContain('Arkime Version');
    expect(result.content[0].text).toContain('Viewer Version: 5.0.0');
    expect(result.content[0].text).toContain('ES Version: 7.17.0');
  });

  it('should handle minimal response with no fields', async () => {
    const client = {
      getAppVersion: async () => ({}),
    } as unknown as ArkimeClient;

    const result = await appVersion(client, {});

    expect(result.content[0].text).toContain('Arkime Version');
    expect(result.content[0].text).not.toContain('Viewer Version:');
    expect(result.content[0].text).not.toContain('ES Version:');
  });
});
