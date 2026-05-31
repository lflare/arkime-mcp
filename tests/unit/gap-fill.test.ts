import { describe, it, expect } from 'vitest';
import {
  sessionsSummary,
  multiUnique,
  connections,
  spiSessions,
  sessionDetail,
  huntList,
  viewList,
  shortcutList,
  appInfo,
  nodeStats,
  sessionFile,
} from '@/controllers/gap-fill.js';
import { ArkimeClient } from '@/services/arkime-client.js';
import { McpError, ErrorCode } from '@/utils/errors.js';
import type {
  SessionsSummaryResponse,
  ConnectionsResponse,
  SpiViewResponse,
  SessionDetailResponse,
  HuntsResponse,
  ViewsResponse,
  ShortcutsResponse,
  AppInfoResponse,
  StatsResponse,
} from '@/types/arkime.js';

describe('sessionsSummary', () => {
  it('should format summary stats', async () => {
    const mockResponse: SessionsSummaryResponse = {
      success: true,
      sessions: 15000,
      connections: 8000,
      packets: 450000,
      dataBytes: 2_147_483_648,
      totDataBytes: 5_368_709_120,
    };

    const client = {
      getSessionsSummary: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await sessionsSummary(client, {});

    expect(result.content[0].text).toContain('Sessions Summary');
    expect(result.content[0].text).toContain('15,000');
    expect(result.content[0].text).toContain('8,000');
    expect(result.content[0].text).toContain('450,000');
    expect(result.content[0].text).toContain('2.00 GB');
    expect(result.content[0].text).toContain('5.00 GB');
  });

  it('should format histograms', async () => {
    const mockResponse: SessionsSummaryResponse = {
      success: true,
      sessions: 100,
      histograms: {
        protocol: [
          { key: 'tcp', count: 80 },
          { key: 'udp', count: 20 },
        ],
      },
    };

    const client = {
      getSessionsSummary: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await sessionsSummary(client, {});

    expect(result.content[0].text).toContain('protocol histogram');
    expect(result.content[0].text).toContain('tcp');
    expect(result.content[0].text).toContain('udp');
  });

  it('should handle empty response', async () => {
    const mockResponse: SessionsSummaryResponse = { success: true };
    const client = { getSessionsSummary: async () => mockResponse } as unknown as ArkimeClient;
    const result = await sessionsSummary(client, {});
    expect(result.content[0].text).toContain('Sessions Summary');
  });

  it('should propagate errors from the API client', async () => {
    const client = {
      getSessionsSummary: async () => { throw new Error('API timeout'); },
    } as unknown as ArkimeClient;
    await expect(sessionsSummary(client, {})).rejects.toThrow('API timeout');
  });
});

describe('multiUnique', () => {
  it('should format multi-field unique values', async () => {
    const mockResponse: Record<string, unknown> = {
      success: true,
      sourceIP: [
        { value: '192.168.1.100', count: 500 },
        { value: '10.0.0.50', count: 300 },
      ],
      protocol: [
        { value: 'tcp', count: 400 },
        { value: 'udp', count: 400 },
      ],
    };

    const client = {
      getMultiUnique: async () => mockResponse as never,
    } as unknown as ArkimeClient;

    const result = await multiUnique(client, {
      fields: ['sourceIP', 'protocol'],
    });

    expect(result.content[0].text).toContain('Multi-Unique Values (2 fields)');
    expect(result.content[0].text).toContain('sourceIP');
    expect(result.content[0].text).toContain('192.168.1.100');
    expect(result.content[0].text).toContain('500');
    expect(result.content[0].text).toContain('protocol');
    expect(result.content[0].text).toContain('tcp');
  });

  it('should handle field with no data', async () => {
    const mockResponse: Record<string, unknown> = {
      success: true,
      sourceIP: [{ value: '1.2.3.4', count: 10 }],
      emptyField: false,
    };

    const client = {
      getMultiUnique: async () => mockResponse as never,
    } as unknown as ArkimeClient;

    const result = await multiUnique(client, {
      fields: ['sourceIP', 'emptyField'],
    });

    expect(result.content[0].text).toContain('emptyField: (no data)');
  });

  it('should propagate errors from the API client', async () => {
    const client = {
      getMultiUnique: async () => { throw new Error('Connection refused'); },
    } as unknown as ArkimeClient;
    await expect(multiUnique(client, { fields: ['sourceIP'] })).rejects.toThrow('Connection refused');
  });
});

describe('connections', () => {
  it('should format connection graph', async () => {
    const mockResponse: ConnectionsResponse = {
      success: true,
      nodes: [
        { id: '1', label: '192.168.1.100', sessions: 500, packets: 1000, bytes: 2_000_000 },
        { id: '2', label: '10.0.0.50', sessions: 300, packets: 600, bytes: 1_000_000 },
      ],
      links: [
        { source: '192.168.1.100', target: '10.0.0.50', sessions: 200, packets: 400, bytes: 500_000 },
      ],
    };

    const client = {
      getConnections: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await connections(client, {});

    expect(result.content[0].text).toContain('Network Connections');
    expect(result.content[0].text).toContain('Nodes: 2');
    expect(result.content[0].text).toContain('Links: 1');
    expect(result.content[0].text).toContain('192.168.1.100');
    expect(result.content[0].text).toContain('Top Nodes by Sessions');
    expect(result.content[0].text).toContain('Top Links by Sessions');
  });

  it('should handle empty connections', async () => {
    const mockResponse: ConnectionsResponse = {
      success: true,
      nodes: [],
      links: [],
    };

    const client = {
      getConnections: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await connections(client, {});

    expect(result.content[0].text).toContain('Network Connections');
    expect(result.content[0].text).toContain('Nodes: 0');
  });

  it('should propagate errors from the API client', async () => {
    const client = {
      getConnections: async () => { throw new Error('API error'); },
    } as unknown as ArkimeClient;
    await expect(connections(client, {})).rejects.toThrow('API error');
  });
});

describe('spiSessions', () => {
  it('should format SPI data grouped by field', async () => {
    const mockResponse: SpiViewResponse = {
      recordsTotal: 1000,
      recordsFiltered: 500,
      items: [
        { field: 'dns.host', value: 'example.com', count: 50 },
        { field: 'dns.host', value: 'google.com', count: 30 },
        { field: 'http.uri', value: '/api/login', count: 20 },
      ],
    };

    const client = {
      getSpiview: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await spiSessions(client, {});

    expect(result.content[0].text).toContain('Session Protocol Information');
    expect(result.content[0].text).toContain('Total: 1000');
    expect(result.content[0].text).toContain('dns.host (2 values)');
    expect(result.content[0].text).toContain('example.com');
    expect(result.content[0].text).toContain('http.uri (1 values)');
  });

  it('should handle empty SPI data', async () => {
    const mockResponse: SpiViewResponse = {
      recordsTotal: 0,
      recordsFiltered: 0,
      items: [],
    };

    const client = {
      getSpiview: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await spiSessions(client, {});

    expect(result.content[0].text).toContain('No SPI data found');
  });

  it('should propagate errors from the API client', async () => {
    const client = {
      getSpiview: async () => { throw new Error('Network failure'); },
    } as unknown as ArkimeClient;
    await expect(spiSessions(client, {})).rejects.toThrow('Network failure');
  });
});

describe('sessionDetail', () => {
  it('should format session detail fields', async () => {
    const mockResponse: SessionDetailResponse = {
      success: true,
      data: {
        source: { ip: '192.168.1.100', port: 12345 },
        destination: { ip: '10.0.0.50', port: 443 },
        protocol: 6,
        tags: ['tls', 'https'],
        duration: 30,
      },
    };

    const client = {
      getSessionDetail: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await sessionDetail(client, {
      nodeId: '3',
      sessionId: '251118-GwHllt-BE65AZ49KusloBKxl',
    });

    expect(result.content[0].text).toContain('Session Detail');
    expect(result.content[0].text).toContain('251118-GwHllt-BE65AZ49KusloBKxl');
    expect(result.content[0].text).toContain('protocol');
    expect(result.content[0].text).toContain('6');
    expect(result.content[0].text).toContain('source');
  });

  it('should propagate errors from the API client', async () => {
    const client = {
      getSessionDetail: async () => { throw new Error('Session not found'); },
    } as unknown as ArkimeClient;
    await expect(sessionDetail(client, {
      nodeId: '3',
      sessionId: '251118-GwHllt-BE65AZ49KusloBKxl',
    })).rejects.toThrow('Session not found');
  });
});

describe('huntList', () => {
  it('should format hunt list', async () => {
    const mockResponse: HuntsResponse = {
      success: true,
      hunts: [
        {
          id: 'hunt-1',
          name: 'Detect Beacons',
          expression: 'http.uri contains "beacon"',
          status: 'active',
          creator: 'admin',
          matches: 150,
          createdAt: 1704067200,
          updatedAt: 1704153600,
        },
      ],
    };

    const client = {
      getHunts: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await huntList(client, {});

    expect(result.content[0].text).toContain('Active Packet Hunts');
    expect(result.content[0].text).toContain('Detect Beacons');
    expect(result.content[0].text).toContain('active');
    expect(result.content[0].text).toContain('150');
    expect(result.content[0].text).toContain('Total: 1 hunts');
  });

  it('should handle no hunts', async () => {
    const mockResponse: HuntsResponse = { success: true, hunts: [] };
    const client = { getHunts: async () => mockResponse } as unknown as ArkimeClient;
    const result = await huntList(client, {});
    expect(result.content[0].text).toContain('No active hunts found');
  });

  it('should propagate errors from the API client', async () => {
    const client = {
      getHunts: async () => { throw new Error('Server error'); },
    } as unknown as ArkimeClient;
    await expect(huntList(client, {})).rejects.toThrow('Server error');
  });
});

describe('viewList', () => {
  it('should format view list', async () => {
    const mockResponse: ViewsResponse = {
      success: true,
      views: [
        { id: 'view-1', name: 'SMB Traffic', expression: 'port.dst == 445', creator: 'admin', shared: true },
        { id: 'view-2', name: 'DNS Exfil', expression: 'port.dst == 53 AND totDataBytes > 10000', creator: 'analyst', shared: false },
      ],
    };

    const client = {
      getViews: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await viewList(client, {});

    expect(result.content[0].text).toContain('Saved Views');
    expect(result.content[0].text).toContain('SMB Traffic');
    expect(result.content[0].text).toContain('port.dst == 445');
    expect(result.content[0].text).toContain('Total: 2 views');
  });

  it('should handle no views', async () => {
    const mockResponse: ViewsResponse = { success: true, views: [] };
    const client = { getViews: async () => mockResponse } as unknown as ArkimeClient;
    const result = await viewList(client, {});
    expect(result.content[0].text).toContain('No saved views found');
  });

  it('should propagate errors from the API client', async () => {
    const client = {
      getViews: async () => { throw new Error('Views API down'); },
    } as unknown as ArkimeClient;
    await expect(viewList(client, {})).rejects.toThrow('Views API down');
  });
});

describe('shortcutList', () => {
  it('should format shortcut list', async () => {
    const mockResponse: ShortcutsResponse = {
      success: true,
      shortcuts: [
        { id: 'sc-1', key: 'smb', expression: 'port.dst == 445' },
        { id: 'sc-2', key: 'dns', expression: 'port.dst == 53' },
      ],
    };

    const client = {
      getShortcuts: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await shortcutList(client, {});

    expect(result.content[0].text).toContain('Saved Shortcuts');
    expect(result.content[0].text).toContain('smb: port.dst == 445');
    expect(result.content[0].text).toContain('dns: port.dst == 53');
    expect(result.content[0].text).toContain('Total: 2 shortcuts');
  });

  it('should handle no shortcuts', async () => {
    const mockResponse: ShortcutsResponse = { success: true, shortcuts: [] };
    const client = { getShortcuts: async () => mockResponse } as unknown as ArkimeClient;
    const result = await shortcutList(client, {});
    expect(result.content[0].text).toContain('No saved shortcuts found');
  });

  it('should propagate errors from the API client', async () => {
    const client = {
      getShortcuts: async () => { throw new Error('Shortcuts API error'); },
    } as unknown as ArkimeClient;
    await expect(shortcutList(client, {})).rejects.toThrow('Shortcuts API error');
  });
});

describe('appInfo', () => {
  it('should format app info', async () => {
    const mockResponse: AppInfoResponse = {
      success: true,
      currentuser: { name: 'admin', roles: ['admin', 'viewer'] },
      eshealth: 'green',
      viewCount: 42,
      clusters: {
        success: true,
        viewerNodes: [{ host: 'viewer1', version: '4.2.0', roles: ['viewer'], started: 1704000000, updated: 1704100000 }],
        captureNodes: [{ host: 'capture1', version: '4.2.0', roles: ['capture'], started: 1704000000, updated: 1704100000 }],
      },
    };

    const client = {
      getAppInfo: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await appInfo(client, {});

    expect(result.content[0].text).toContain('Arkime App Info');
    expect(result.content[0].text).toContain('admin');
    expect(result.content[0].text).toContain('green');
    expect(result.content[0].text).toContain('Views Total: 42');
    expect(result.content[0].text).toContain('Viewer Nodes: 1');
  });

  it('should handle minimal response', async () => {
    const mockResponse: AppInfoResponse = { success: true };
    const client = { getAppInfo: async () => mockResponse } as unknown as ArkimeClient;
    const result = await appInfo(client, {});
    expect(result.content[0].text).toContain('Arkime App Info');
  });

  it('should propagate errors from the API client', async () => {
    const client = {
      getAppInfo: async () => { throw new Error('App info unavailable'); },
    } as unknown as ArkimeClient;
    await expect(appInfo(client, {})).rejects.toThrow('App info unavailable');
  });
});

describe('nodeStats', () => {
  it('should format node stats', async () => {
    const mockResponse: StatsResponse = {
      success: true,
      stats: {
        'viewer1': { host: 'viewer1', roles: ['viewer', 'scheduler'], packets: 500000, bytes: 1_073_741_824, sessions: 50000 },
        'capture1': { host: 'capture1', roles: ['capture'], packets: 2_000_000, bytes: 5_368_709_120, sessions: 200000 },
      },
    };

    const client = {
      getStats: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await nodeStats(client, {});

    expect(result.content[0].text).toContain('Node Statistics');
    expect(result.content[0].text).toContain('viewer1');
    expect(result.content[0].text).toContain('500,000');
    expect(result.content[0].text).toContain('1.00 GB');
    expect(result.content[0].text).toContain('50,000');
    expect(result.content[0].text).toContain('capture1');
  });

  it('should handle empty stats', async () => {
    const mockResponse: StatsResponse = { success: true, stats: {} };
    const client = { getStats: async () => mockResponse } as unknown as ArkimeClient;
    const result = await nodeStats(client, {});
    expect(result.content[0].text).toContain('No stats available');
  });

  it('should propagate errors from the API client', async () => {
    const client = {
      getStats: async () => { throw new Error('Stats endpoint down'); },
    } as unknown as ArkimeClient;
    await expect(nodeStats(client, {})).rejects.toThrow('Stats endpoint down');
  });
});

describe('sessionFile', () => {
  it('should return base64 encoded file data', async () => {
    const mockData = Buffer.from('test file content');
    const client = {
      getSessionBodyHash: async () => mockData,
    } as unknown as ArkimeClient;

    const result = await sessionFile(client, {
      nodeId: '3',
      sessionId: '251118-test',
      hash: 'd41d8cd98f00b204e9800998ecf8427e',
    });

    expect(result.content[0].text).toContain('Session file extracted');
    expect(result.content[0].text).toContain('d41d8cd98f00b204e9800998ecf8427e');
    expect(result.content[0].text).toContain('Data included as resource');
    expect(result.content[1].type).toBe('resource');
    expect(result.content[1].resource.mimeType).toBe('application/octet-stream');
    expect(result.content[1].resource.uri).toBeDefined();
    expect(result.content[1].resource.uri).toBe(`data:application/octet-stream;base64,dGVzdCBmaWxlIGNvbnRlbnQ=`);
    expect(result.content[1].resource.text).toBeUndefined();
  });

  it('should propagate errors from the API client', async () => {
    const client = {
      getSessionBodyHash: async () => { throw new Error('File fetch failed'); },
    } as unknown as ArkimeClient;
    await expect(sessionFile(client, {
      nodeId: '3',
      sessionId: '251118-test',
      hash: 'd41d8cd98f00b204e9800998ecf8427e',
    })).rejects.toThrow('File fetch failed');
  });
});

describe('API error handling', () => {
  it('should propagate 500 Internal Server Error from sessionsSummary', async () => {
    const client = {
      getSessionsSummary: async () => {
        const error: McpError = new McpError(ErrorCode.API_ERROR, 'Internal Server Error');
        throw error;
      },
    } as unknown as ArkimeClient;

    await expect(sessionsSummary(client, {})).rejects.toThrow(McpError);

    try {
      await sessionsSummary(client, {});
    } catch (error) {
      expect(error).toBeInstanceOf(McpError);
      expect((error as McpError).code).toBe(ErrorCode.API_ERROR);
      expect((error as McpError).message).toContain('Internal Server Error');
    }
  });

  it('should propagate 401 Unauthorized error from sessionsSummary', async () => {
    const client = {
      getSessionsSummary: async () => {
        const error: McpError = new McpError(ErrorCode.AUTH_INVALID, 'Unauthorized: invalid credentials');
        throw error;
      },
    } as unknown as ArkimeClient;

    await expect(sessionsSummary(client, {})).rejects.toThrow(McpError);

    try {
      await sessionsSummary(client, {});
    } catch (error) {
      expect(error).toBeInstanceOf(McpError);
      expect((error as McpError).code).toBe(ErrorCode.AUTH_INVALID);
      expect((error as McpError).message).toContain('Unauthorized');
    }
  });

  it('should propagate 403 Forbidden error from connections', async () => {
    const client = {
      getConnections: async () => {
        const error: McpError = new McpError(ErrorCode.API_ERROR, 'Forbidden: access denied');
        throw error;
      },
    } as unknown as ArkimeClient;

    await expect(connections(client, {})).rejects.toThrow(McpError);

    try {
      await connections(client, {});
    } catch (error) {
      expect(error).toBeInstanceOf(McpError);
      expect((error as McpError).code).toBe(ErrorCode.API_ERROR);
      expect((error as McpError).message).toContain('Forbidden');
    }
  });

  it('should propagate connection timeout error from sessionsSummary', async () => {
    const client = {
      getSessionsSummary: async () => {
        const error: McpError = new McpError(ErrorCode.NETWORK_ERROR, 'Connection timed out');
        throw error;
      },
    } as unknown as ArkimeClient;

    await expect(sessionsSummary(client, {})).rejects.toThrow(McpError);

    try {
      await sessionsSummary(client, {});
    } catch (error) {
      expect(error).toBeInstanceOf(McpError);
      expect((error as McpError).code).toBe(ErrorCode.NETWORK_ERROR);
      expect((error as McpError).message).toContain('timed out');
    }
  });
});
