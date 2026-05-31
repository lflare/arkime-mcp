import { describe, it, expect } from 'vitest';
import { getPcap } from '@/controllers/pcap.js';
import { investigateNtlm } from '@/controllers/investigation.js';
import { ArkimeClient } from '@/services/arkime-client.js';
import { McpError, ErrorCode } from '@/utils/errors.js';
import type { SessionsResponse } from '@/types/arkime.js';

describe('getPcap', () => {
  it('should handle empty results', async () => {
    const mockResponse: SessionsResponse = {
      data: [],
      recordsTotal: 0,
      recordsFiltered: 0,
    };

    const client = {
      getPcap: async () => Buffer.from([]),
      searchSessions: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await getPcap(client, {
      expression: 'port.dst == 99999',
      maxBytes: 1000000,
    });

    expect(result.content[0].type).toBe('text');
    expect(result.content[0].text).toContain('No PCAP data found');
  });

  it('should reject oversized PCAP', async () => {
    const largeBuffer = Buffer.alloc(2000000, 0);
    const client = {
      getPcap: async () => largeBuffer,
    } as unknown as ArkimeClient;

    const result = await getPcap(client, {
      expression: 'port.dst == 445',
      maxBytes: 1000000,
    });

    expect(result.content[0].text).toContain('PCAP too large');
  });

  it('should return valid PCAP data', async () => {
    const pcapHeader = Buffer.from([
      0xd4, 0xc3, 0xb2, 0xa1,
      0x02, 0x00, 0x04, 0x00,
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      0xff, 0xff, 0x00, 0x00,
      0x01, 0x00, 0x00, 0x00,
    ]);

    const client = {
      getPcap: async () => pcapHeader,
    } as unknown as ArkimeClient;

    const result = await getPcap(client, {
      expression: 'port.dst == 445',
      maxBytes: 10000000,
    });

    expect(result.content).toHaveLength(2);
    expect(result.content[0].type).toBe('text');
    expect(result.content[0].text).toContain('PCAP extracted');
    expect(result.content[1].type).toBe('resource');
  });
});

describe('investigateNtlm', () => {
  it('should handle no results', async () => {
    const mockResponse: SessionsResponse = {
      data: [],
      recordsTotal: 0,
      recordsFiltered: 0,
    };

    const client = {
      searchSessions: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await investigateNtlm(client, {});

    expect(result.content[0].text).toContain('No NTLM/LDAP/Kerberos');
  });

  it('should analyze SMB traffic', async () => {
    const mockResponse: SessionsResponse = {
      data: [
        {
          id: 's1',
          lastPacket: 1704067200000,
          firstPacket: 1704067100000,
          source: { ip: '192.168.1.100' },
          destination: { ip: '10.0.0.1', port: 445 },
          smb: { user: 'admin', domain: 'CORP', host: 'DC01' },
        },
        {
          id: 's2',
          lastPacket: 1704067200000,
          firstPacket: 1704067100000,
          source: { ip: '192.168.1.100' },
          destination: { ip: '10.0.0.2', port: 445 },
          smb: { user: 'admin', domain: 'CORP' },
        },
        {
          id: 's3',
          lastPacket: 1704067200000,
          firstPacket: 1704067100000,
          source: { ip: '192.168.1.101' },
          destination: { ip: '10.0.0.1', port: 389 },
          ldap: { bindname: 'CN=jdoe,OU=Users,DC=corp' },
        },
      ],
      recordsTotal: 3,
      recordsFiltered: 3,
    };

    const client = {
      searchSessions: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await investigateNtlm(client, { suspectIp: '192.168.1.100' });

    expect(result.content[0].text).toContain('NTLM/Lateral Movement');
    expect(result.content[0].text).toContain('192.168.1.100');
    expect(result.content[0].text).toContain('Authentication Activity');
  });

  it('should detect pivot patterns', async () => {
    const sessions = [];
    for (let i = 1; i <= 10; i++) {
      sessions.push({
        id: `s${i}`,
        lastPacket: 1704067200000,
        firstPacket: 1704067100000,
        source: { ip: '192.168.1.100' },
        destination: { ip: `10.0.0.${i}`, port: 445 },
        smb: { user: 'admin' },
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

    const result = await investigateNtlm(client, { suspectIp: '192.168.1.100' });

    expect(result.content[0].text).toContain('Potential Pivot Points');
    expect(result.content[0].text).toContain('192.168.1.100');
  });

  it('should detect Pass-the-Hash with same user from multiple source IPs', async () => {
    // Compromised credential being used from multiple machines (Pass-the-Hash)
    const sessions = [];
    const sourceIps = ['192.168.1.50', '192.168.1.51', '192.168.1.52', '192.168.1.53', '192.168.1.54'];
    for (const srcIp of sourceIps) {
      for (let t = 1; t <= 3; t++) {
        sessions.push({
          id: `ptth-${srcIp}-${t}`,
          lastPacket: 1704067200 + t * 100,
          firstPacket: 1704067200 + t * 100,
          source: { ip: srcIp },
          destination: { ip: `10.0.0.${t}`, port: 445 },
          smb: { user: 'admin', domain: 'CORP' },
        });
      }
    }

    const mockResponse: SessionsResponse = {
      data: sessions,
      recordsTotal: sessions.length,
      recordsFiltered: sessions.length,
    };

    const client = {
      searchSessions: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await investigateNtlm(client, { suspectUser: 'admin' });

    expect(result.content[0].text).toContain('NTLM/Lateral Movement');
    expect(result.content[0].text).toContain('admin');
    // Should show user observed across multiple source IPs
    expect(result.content[0].text).toContain('Source IPs');
    // Should show 5 different source IPs for this user
    expect(result.content[0].text).toContain('5');
  });

  it('should detect mixed protocol auth (SMB + LDAP + Kerberos)', async () => {
    // Attacker using multiple auth protocols from one compromised host
    const sessions = [
      // SMB authentications
      {
        id: 'smb-1',
        lastPacket: 1704067200,
        firstPacket: 1704067200,
        source: { ip: '192.168.1.100' },
        destination: { ip: '10.0.0.1', port: 445 },
        smb: { user: 'admin', domain: 'CORP' },
      },
      {
        id: 'smb-2',
        lastPacket: 1704067210,
        firstPacket: 1704067210,
        source: { ip: '192.168.1.100' },
        destination: { ip: '10.0.0.2', port: 445 },
        smb: { user: 'admin', domain: 'CORP' },
      },
      // LDAP binds
      {
        id: 'ldap-1',
        lastPacket: 1704067220,
        firstPacket: 1704067220,
        source: { ip: '192.168.1.100' },
        destination: { ip: '10.0.0.10', port: 389 },
        ldap: { bindname: 'CN=admin,OU=Users,DC=corp' },
      },
      {
        id: 'ldap-2',
        lastPacket: 1704067230,
        firstPacket: 1704067230,
        source: { ip: '192.168.1.100' },
        destination: { ip: '10.0.0.10', port: 636 },
        ldap: { bindname: 'CN=admin,OU=Users,DC=corp' },
      },
      // Kerberos
      {
        id: 'krb-1',
        lastPacket: 1704067240,
        firstPacket: 1704067240,
        source: { ip: '192.168.1.100' },
        destination: { ip: '10.0.0.1', port: 88 },
        krb5: { cname: 'admin@CORP.LOCAL', realm: 'CORP.LOCAL', sname: 'cifs/FILESRV' },
      },
    ];

    const mockResponse: SessionsResponse = {
      data: sessions,
      recordsTotal: sessions.length,
      recordsFiltered: sessions.length,
    };

    const client = {
      searchSessions: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await investigateNtlm(client, { suspectIp: '192.168.1.100' });

    expect(result.content[0].text).toContain('NTLM/Lateral Movement');
    expect(result.content[0].text).toContain('192.168.1.100');
    // Should show auth activity across multiple targets
    expect(result.content[0].text).toContain('Authentication Activity');
    // Multiple unique targets from this source
    expect(result.content[0].text).toContain('Unique Targets');
  });

  describe('API error handling', () => {
    it('should propagate 500 Internal Server Error', async () => {
      const client = {
        searchSessions: async () => {
          const error: McpError = new McpError(ErrorCode.API_ERROR, 'Internal Server Error');
          throw error;
        },
      } as unknown as ArkimeClient;

      await expect(investigateNtlm(client, {})).rejects.toThrow(McpError);

      try {
        await investigateNtlm(client, {});
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

      await expect(investigateNtlm(client, {})).rejects.toThrow(McpError);

      try {
        await investigateNtlm(client, {});
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

      await expect(investigateNtlm(client, {})).rejects.toThrow(McpError);

      try {
        await investigateNtlm(client, {});
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

      await expect(investigateNtlm(client, {})).rejects.toThrow(McpError);

      try {
        await investigateNtlm(client, {});
      } catch (error) {
        expect(error).toBeInstanceOf(McpError);
        expect((error as McpError).code).toBe(ErrorCode.NETWORK_ERROR);
        expect((error as McpError).message).toContain('timed out');
      }
    });
  });
});
