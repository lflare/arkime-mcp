import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import { createServer } from '@/server';
import { searchSessions, getSession, getSessionSpi } from '@/controllers/sessions.js';
import { huntSuspicious } from '@/controllers/analysis.js';
import { buildAttackTimeline, trackLateralMovement, extractIocs } from '@/controllers/forensics.js';
import { getPacket } from '@/controllers/packet.js';
import type { SessionsResponse, Session } from '@/types/arkime.js';
import type { ArkimeClient } from '@/services/arkime-client.js';

// ---------------------------------------------------------------------------
// Area 1 - Tool Registration Verification
// ---------------------------------------------------------------------------

describe('MCP tool registration', () => {
  it('should register exactly 55 tools', () => {
    const toolsIndex = readFileSync(
      resolve(__dirname, '../../src/tools/index.ts'),
      'utf-8',
    );
    const matches = toolsIndex.match(/server\.tool\(/g);
    expect(matches).not.toBeNull();
    expect(matches!.length).toBe(55);
  });

  it('should register each tool with a non-empty description', () => {
    const toolsIndex = readFileSync(
      resolve(__dirname, '../../src/tools/index.ts'),
      'utf-8',
    );

    // Each server.tool call follows: server.tool('name', 'desc', shape, handler)
    const toolBlockRegex = /server\.tool\(\s*(['"])([\w-]+)\1,[ \t]*\n?[ \t]*(['"])(.+?)\3/g;
    const descriptions = new Map<string, string>();

    let m: RegExpExecArray | null;
    while ((m = toolBlockRegex.exec(toolsIndex)) !== null) {
      const name = m[2];
      const desc = m[4];
      descriptions.set(name, desc);
    }

    expect(descriptions.size).toBe(55);

    for (const [name, desc] of descriptions.entries()) {
      expect(
        desc.trim().length,
        `Tool "${name}" has an empty description`,
      ).toBeGreaterThan(0);
    }
  });

  it('should register each tool with a valid Zod schema shape', () => {
    const toolsIndex = readFileSync(
      resolve(__dirname, '../../src/tools/index.ts'),
      'utf-8',
    );

    // Each server.tool should reference S.<name>Schema.shape
    const shapeRefRegex = /S\.(\w+)Schema\.shape/g;
    const schemaNames = [...toolsIndex.matchAll(shapeRefRegex)].map((m) => m[1]);

    expect(schemaNames.length).toBe(55);

    const unique = new Set(schemaNames);
    expect(unique.size).toBe(55);
  });

  it('should create an MCP server instance with all tools wired', () => {
    const server = createServer();

    expect(server).toBeDefined();
    expect(server.connect).toBeDefined();
    expect(server.close).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// Area 2 - Multi-step Forensics Workflows
// ---------------------------------------------------------------------------

/**
 * Build a minimal ArkimeClient mock from a map of method names to async
 * handlers.
 */
function mockClient(responses: Record<string, () => unknown>): ArkimeClient {
  const client = {} as ArkimeClient;
  for (const [method, fn] of Object.entries(responses)) {
    (client as any)[method] = fn;
  }
  return client;
}

// ---------------------------------------------------------------------------
// Workflow 1: Search -> Session Detail -> SPI
// ---------------------------------------------------------------------------

describe('workflow: search -> session detail -> SPI', () => {
  it('should chain session search, detail lookup and SPI extraction', async () => {
    const searchResponse: SessionsResponse = {
      data: [
        {
          id: '250101-AbCdEf12',
          lastPacket: 1704067200,
          firstPacket: 1704067100,
          source: { ip: '192.168.1.50', port: 45678 },
          destination: { ip: '10.0.0.5', port: 445 },
          ipProtocol: 6,
        },
      ],
      recordsTotal: 1,
      recordsFiltered: 1,
    };

    const sessionDetail: Session = {
      id: '250101-AbCdEf12',
      lastPacket: 1704067200,
      firstPacket: 1704067100,
      node: '3',
      source: { ip: '192.168.1.50', port: 45678 },
      destination: { ip: '10.0.0.5', port: 445 },
      ipProtocol: 6,
    };

    const spiResponse: SessionsResponse = {
      data: [
        {
          id: '250101-AbCdEf12',
          lastPacket: 1704067200,
          source: { ip: '192.168.1.50' },
          destination: { ip: '10.0.0.5', port: 443 },
          http: { host: 'internal.corp.local', uri: '/admin/console', method: 'POST', statuscode: 200 },
          dns: { host: 'internal.corp.local', ans: '10.0.0.5' },
          tls: { sni: 'internal.corp.local' },
        },
      ],
      recordsTotal: 1,
      recordsFiltered: 1,
    };

    let searchCallCount = 0;

    const client = mockClient({
      searchSessions: async () => {
        searchCallCount++;
        if (searchCallCount === 1) return searchResponse;
        return spiResponse;
      },
      getSession: async () => sessionDetail,
    });

    // Step 1: search sessions
    const searchResult = await searchSessions(client, {
      expression: 'ip.src == 192.168.1.50',
      limit: 10,
    });
    expect(searchResult.content[0].text).toContain('Found 1 sessions');

    // Step 2: get session detail
    const detailResult = await getSession(client, {
      id: '250101-AbCdEf12',
    });
    expect(detailResult.content[0].text).toContain('192.168.1.50');

    // Step 3: get SPI
    const spiResult = await getSessionSpi(client, {
      expression: 'id==250101-AbCdEf12',
      categories: ['all'],
      limit: 10,
    });
    expect(spiResult.content[0].text).toContain('Session SPI Data');
    expect(spiResult.content[0].text).toContain('internal.corp.local');
    expect(spiResult.content[0].text).toContain('HTTP');
  });

  it('should handle empty search results gracefully in the chain', async () => {
    const emptyResponse: SessionsResponse = {
      data: [],
      recordsTotal: 0,
      recordsFiltered: 0,
    };

    const client = mockClient({
      searchSessions: async () => emptyResponse,
    });

    const result = await searchSessions(client, {
      expression: 'ip.src == 1.2.3.4',
      limit: 10,
    });
    expect(result.content[0].text).toContain('No sessions found');
  });
});

// ---------------------------------------------------------------------------
// Workflow 2: Hunt Suspicious -> Extract IOCs
// ---------------------------------------------------------------------------

describe('workflow: hunt suspicious -> extract IOCs', () => {
  it('should detect port scanners then extract IOCs from the same traffic', async () => {
    // Build sessions where one host scans many ports on many targets
    const sessions: Session[] = [];
    for (let i = 0; i < 200; i++) {
      sessions.push({
        id: `scan-${i}`,
        lastPacket: 1704067200 + i,
        source: { ip: '192.168.1.100' },
        destination: {
          ip: `203.0.113.${(i % 200) + 1}`,
          port: i + 1,
        },
      });
    }

    const scanResponse: SessionsResponse = {
      data: sessions,
      recordsTotal: 200,
      recordsFiltered: 200,
    };

    const client = mockClient({
      searchSessions: async () => scanResponse,
    });

    // Step 1: hunt for port scanners
    const huntResult = await huntSuspicious(client, {
      huntType: 'port-scanners',
      threshold: 150,
    });
    expect(huntResult.content[0].text).toContain('Port Scanners');
    expect(huntResult.content[0].text).toContain('192.168.1.100');

    // Step 2: extract IOCs from the same traffic pattern
    const iocResult = await extractIocs(client, {
      expression: 'ip.src == 192.168.1.100',
      iocTypes: ['ip', 'domain'],
    });
    expect(iocResult.content[0].text).toContain('IOC Extraction');
    // External IPs should be extracted (203.0.113.x are public)
    expect(iocResult.content[0].text).toContain('203.0.113');
  });
});

// ---------------------------------------------------------------------------
// Workflow 3: Session Search -> Get Packet
// ---------------------------------------------------------------------------

describe('workflow: session search -> get packet', () => {
  it('should find a session then extract its PCAP data', async () => {
    const searchResponse: SessionsResponse = {
      data: [
        {
          id: '250101-SmbSession1',
          lastPacket: 1704067200,
          firstPacket: 1704067100,
          node: '3',
          source: { ip: '192.168.1.50', port: 45678 },
          destination: { ip: '10.0.0.5', port: 445 },
          ipProtocol: 6,
        },
      ],
      recordsTotal: 1,
      recordsFiltered: 1,
    };

    const sessionObj: Session = {
      id: '250101-SmbSession1',
      lastPacket: 1704067200,
      firstPacket: 1704067100,
      node: '3',
      source: { ip: '192.168.1.50', port: 45678 },
      destination: { ip: '10.0.0.5', port: 445 },
      ipProtocol: 6,
    };

    let searchCallCount = 0;
    let capturedPcapUrl = '';

    const client = mockClient({
      searchSessions: async () => {
        searchCallCount++;
        return searchResponse;
      },
      getSession: async () => sessionObj,
      getPcap: async (url: string) => {
        capturedPcapUrl = url;
        return Buffer.from('fake-pcap-data');
      },
    });

    // Step 1: search for SMB sessions
    const searchResult = await searchSessions(client, {
      expression: 'port.dst == 445',
      limit: 10,
    });
    expect(searchResult.content[0].text).toContain('Found 1 sessions');
    expect(searchResult.content[0].text).toContain('250101-SmbSession1');

    // Step 2: extract PCAP for the found session
    const packetResult = await getPacket(client, {
      sessionId: '250101-SmbSession1',
    });
    expect(packetResult.content[0].text).toContain('PCAP extracted');
    expect(packetResult.content[0].text).toContain('Node: 3');
    expect(packetResult.content[1].type).toBe('resource');
    expect(packetResult.content[1].resource.mimeType).toBe('application/vnd.tcpdump.pcap');
  });
});

// ---------------------------------------------------------------------------
// Workflow 4: Attack Timeline -> Lateral Movement
// ---------------------------------------------------------------------------

describe('workflow: attack timeline -> lateral movement', () => {
  it('should build timeline then track lateral movement from same attacker', async () => {
    // Timeline sessions: SMB auth, LDAP bind, RDP
    const timelineSessions: Session[] = [
      {
        id: 's1',
        lastPacket: 1704067200,
        firstPacket: 1704067100,
        source: { ip: '192.168.1.100' },
        destination: { ip: '10.0.0.1', port: 445 },
        smb: { user: 'admin', domain: 'CORP', host: 'DC01' },
      },
      {
        id: 's2',
        lastPacket: 1704067300,
        firstPacket: 1704067200,
        source: { ip: '192.168.1.100' },
        destination: { ip: '10.0.0.2', port: 389 },
        ldap: { bindname: 'CN=admin,OU=Users,DC=corp' },
      },
      {
        id: 's3',
        lastPacket: 1704067400,
        firstPacket: 1704067300,
        source: { ip: '192.168.1.100' },
        destination: { ip: '10.0.0.3', port: 3389 },
      },
    ];

    // Lateral movement: same attacker hitting many internal hosts
    const movementSessions: Session[] = [];
    for (let i = 1; i <= 8; i++) {
      movementSessions.push({
        id: `m${i}`,
        lastPacket: 1704067200 + i * 1000,
        source: { ip: '192.168.1.100' },
        destination: { ip: `10.0.0.${i}`, port: 445 },
        smb: { user: 'admin', domain: 'CORP', host: `HOST${i}` },
      });
    }

    let callCount = 0;

    const client = mockClient({
      searchSessions: async () => {
        callCount++;
        if (callCount === 1) {
          return {
            data: timelineSessions,
            recordsTotal: timelineSessions.length,
            recordsFiltered: timelineSessions.length,
          };
        }
        return {
          data: movementSessions,
          recordsTotal: movementSessions.length,
          recordsFiltered: movementSessions.length,
        };
      },
    });

    // Step 1: build attack timeline
    const timelineResult = await buildAttackTimeline(client, {
      suspectIp: '192.168.1.100',
    });
    expect(timelineResult.content[0].text).toContain('Attack Timeline');
    expect(timelineResult.content[0].text).toContain('SMB Authentication');
    expect(timelineResult.content[0].text).toContain('LDAP Bind');
    expect(timelineResult.content[0].text).toContain('RDP Connection');
    expect(timelineResult.content[0].text).toContain('Risk Summary');

    // Step 2: track lateral movement
    const movementResult = await trackLateralMovement(client, {
      sourceIp: '192.168.1.100',
      minConnections: 2,
    });
    expect(movementResult.content[0].text).toContain('Lateral Movement');
    expect(movementResult.content[0].text).toContain('192.168.1.100');
    expect(movementResult.content[0].text).toContain('GraphViz');
  });
});
