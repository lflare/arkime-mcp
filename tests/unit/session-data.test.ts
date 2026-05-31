import { describe, it, expect } from 'vitest';
import {
  sessionPackets,
  sessionPcap,
  sessionRaw,
  sessionBody,
} from '@/controllers/session-data.js';
import type { ArkimeClient } from '@/services/arkime-client.js';
import type { SessionPacketsResponse } from '@/types/arkime.js';

describe('sessionPackets', () => {
  it('should return decoded packets as text', async () => {
    const mockResponse: SessionPacketsResponse = {
      success: true,
      packets: [{ ts: 1, len: 60 }],
    };

    const client = {
      getSessionPackets: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await sessionPackets(client, {
      nodeId: '3',
      sessionId: '250101-abc',
    });

    expect(result.content[0].type).toBe('text');
    expect(result.content[0].text).toContain('Decoded Packets (250101-abc on 3)');
    expect(result.content[0].text).toContain('Packets: 1');
    expect(result.content[0].text).toContain('"ts": 1');
    expect(result.content[0].text).toContain('"len": 60');
  });

  it('should handle empty packets array', async () => {
    const mockResponse: SessionPacketsResponse = {
      success: true,
      packets: [],
    };

    const client = {
      getSessionPackets: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await sessionPackets(client, {
      nodeId: '3',
      sessionId: '250101-empty',
    });

    expect(result.content[0].type).toBe('text');
    expect(result.content[0].text).toContain('Decoded Packets (250101-empty on 3)');
    expect(result.content[0].text).toContain('No decoded packets returned.');
  });

  it('should render full response when packets missing', async () => {
    const mockResponse: SessionPacketsResponse = {
      success: false,
      error: 'boom',
    };

    const client = {
      getSessionPackets: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await sessionPackets(client, {
      nodeId: '3',
      sessionId: '250101-noerr',
    });

    expect(result.content[0].type).toBe('text');
    expect(result.content[0].text).toContain('"error": "boom"');
  });
});

describe('sessionPcap', () => {
  it('should return entire PCAP as a base64 resource', async () => {
    const client = {
      getSessionEntirePcap: async () => Buffer.from('PCAPDATA'),
    } as unknown as ArkimeClient;

    const result = await sessionPcap(client, {
      nodeId: '3',
      sessionId: '250101-abc',
    });

    expect(result.content[0].type).toBe('text');
    expect(result.content[0].text).toContain('Entire session PCAP extracted');
    expect(result.content[0].text).toContain('250101-abc');
    expect(result.content[0].text).toContain('Wireshark');

    const resource = result.content.find((c) => c.type === 'resource');
    expect(resource).toBeDefined();
    if (resource && resource.type === 'resource') {
      expect(resource.resource.uri.startsWith('data:')).toBe(true);
      expect(resource.resource.uri).toContain('base64,');
      expect(resource.resource.mimeType).toBe('application/vnd.tcpdump.pcap');
    }
  });
});

describe('sessionRaw', () => {
  it('should return raw payload as a base64 resource', async () => {
    const client = {
      getSessionRaw: async () => Buffer.from('RAWBYTES'),
    } as unknown as ArkimeClient;

    const result = await sessionRaw(client, {
      nodeId: '3',
      sessionId: '250101-raw',
    });

    expect(result.content[0].type).toBe('text');
    expect(result.content[0].text).toContain('Raw session payload extracted');
    expect(result.content[0].text).toContain('250101-raw');

    const resource = result.content.find((c) => c.type === 'resource');
    expect(resource).toBeDefined();
    if (resource && resource.type === 'resource') {
      expect(resource.resource.uri.startsWith('data:')).toBe(true);
      expect(resource.resource.uri).toContain('base64,');
      expect(resource.resource.mimeType).toBe('application/octet-stream');
    }
  });
});

describe('sessionBody', () => {
  it('should return session body as a base64 resource', async () => {
    const client = {
      getSessionBody: async () => Buffer.from('BODYDATA'),
    } as unknown as ArkimeClient;

    const result = await sessionBody(client, {
      nodeId: '3',
      sessionId: '250101-body',
      bodyType: 'file',
      bodyNum: 0,
      bodyName: 'evil.exe',
    });

    expect(result.content[0].type).toBe('text');
    expect(result.content[0].text).toContain("Session body 'evil.exe' extracted");
    expect(result.content[0].text).toContain('250101-body');

    const resource = result.content.find((c) => c.type === 'resource');
    expect(resource).toBeDefined();
    if (resource && resource.type === 'resource') {
      expect(resource.resource.uri.startsWith('data:')).toBe(true);
      expect(resource.resource.uri).toContain('base64,');
      expect(resource.resource.mimeType).toBe('application/octet-stream');
    }
  });
});
