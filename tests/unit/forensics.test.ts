import { describe, it, expect } from 'vitest';
import { buildAttackTimeline, trackLateralMovement, extractIocs } from '@/controllers/forensics.js';
import { investigateNtlm } from '@/controllers/investigation.js';
import { ArkimeClient } from '@/services/arkime-client.js';
import { McpError, ErrorCode } from '@/utils/errors.js';
import type { SessionsResponse } from '@/types/arkime.js';

describe('buildAttackTimeline', () => {
  it('should handle empty results', async () => {
    const mockResponse: SessionsResponse = {
      data: [],
      recordsTotal: 0,
      recordsFiltered: 0,
    };

    const client = {
      searchSessions: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await buildAttackTimeline(client, {});

    expect(result.content[0].text).toContain('No events found');
  });

  it('should build timeline from SMB events', async () => {
    const mockResponse: SessionsResponse = {
      data: [
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
      ],
      recordsTotal: 3,
      recordsFiltered: 3,
    };

    const client = {
      searchSessions: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await buildAttackTimeline(client, { suspectIp: '192.168.1.100' });

    expect(result.content[0].text).toContain('Attack Timeline');
    expect(result.content[0].text).toContain('SMB Authentication');
    expect(result.content[0].text).toContain('LDAP Bind');
    expect(result.content[0].text).toContain('RDP Connection');
    expect(result.content[0].text).toContain('Risk Summary');
  });

  it('should mark admin-related events as high risk', async () => {
    const mockResponse: SessionsResponse = {
      data: [
        {
          id: 's1',
          lastPacket: 1704067200,
          firstPacket: 1704067100,
          source: { ip: '192.168.1.100' },
          destination: { ip: '10.0.0.1', port: 445 },
          smb: { user: 'Administrator' },
        },
      ],
      recordsTotal: 1,
      recordsFiltered: 1,
    };

    const client = {
      searchSessions: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await buildAttackTimeline(client, {});

    expect(result.content[0].text).toContain('High:');
  });
});

describe('trackLateralMovement', () => {
  it('should handle empty results', async () => {
    const mockResponse: SessionsResponse = {
      data: [],
      recordsTotal: 0,
      recordsFiltered: 0,
    };

    const client = {
      searchSessions: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await trackLateralMovement(client, {});

    expect(result.content[0].text).toContain('No lateral movement');
  });

  it('should build movement graph', async () => {
    const sessions = [];
    for (let i = 1; i <= 5; i++) {
      sessions.push({
        id: `s${i}`,
        lastPacket: 1704067200,
        source: { ip: '192.168.1.100' },
        destination: { ip: `10.0.0.${i}`, port: 445 },
        smb: { user: 'admin' },
      });
    }

    const mockResponse: SessionsResponse = {
      data: sessions,
      recordsTotal: 5,
      recordsFiltered: 5,
    };

    const client = {
      searchSessions: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await trackLateralMovement(client, { sourceIp: '192.168.1.100' });

    expect(result.content[0].text).toContain('Lateral Movement');
    expect(result.content[0].text).toContain('Potential Pivot Points');
    expect(result.content[0].text).toContain('192.168.1.100');
    expect(result.content[0].text).toContain('GraphViz');
    expect(result.content[0].text).toContain('digraph');
  });

  it('should identify pivot points', async () => {
    const sessions = [];
    for (let i = 1; i <= 10; i++) {
      sessions.push({
        id: `s${i}`,
        lastPacket: 1704067200,
        source: { ip: '192.168.1.100' },
        destination: { ip: `10.0.0.${i}`, port: 445 },
        smb: { user: ['admin', 'user1', 'user2'][i % 3] },
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

    const result = await trackLateralMovement(client, {});

    expect(result.content[0].text).toContain('Outbound: 10');
  });
});

describe('extractIocs', () => {
  it('should handle empty results', async () => {
    const mockResponse: SessionsResponse = {
      data: [],
      recordsTotal: 0,
      recordsFiltered: 0,
    };

    const client = {
      searchSessions: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await extractIocs(client, { expression: 'port.dst == 443' });

    expect(result.content[0].text).toContain('No sessions found');
  });

  it('should extract external IPs', async () => {
    const mockResponse: SessionsResponse = {
      data: [
        {
          id: 's1',
          lastPacket: 1704067200,
          source: { ip: '192.168.1.100' },
          destination: { ip: '8.8.8.8', port: 443 },
        },
        {
          id: 's2',
          lastPacket: 1704067200,
          source: { ip: '10.0.0.1' },
          destination: { ip: '1.1.1.1', port: 443 },
        },
      ],
      recordsTotal: 2,
      recordsFiltered: 2,
    };

    const client = {
      searchSessions: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await extractIocs(client, { 
      expression: 'port.dst == 443',
      iocTypes: ['ip'],
    });

    expect(result.content[0].text).toContain('8.8.8.8');
    expect(result.content[0].text).toContain('1.1.1.1');
    expect(result.content[0].text).not.toContain('192.168.1.100');
    expect(result.content[0].text).not.toContain('10.0.0.1');
  });

  it('should extract domains', async () => {
    const mockResponse: SessionsResponse = {
      data: [
        {
          id: 's1',
          lastPacket: 1704067200,
          dns: { host: 'malicious.example.com' },
        },
        {
          id: 's2',
          lastPacket: 1704067200,
          http: { host: 'evil.com', uri: '/payload.exe' },
        },
      ],
      recordsTotal: 2,
      recordsFiltered: 2,
    };

    const client = {
      searchSessions: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await extractIocs(client, { 
      expression: 'dns.host exists',
      iocTypes: ['domain', 'url'],
    });

    expect(result.content[0].text).toContain('malicious.example.com');
    expect(result.content[0].text).toContain('evil.com');
  });

  it('should extract hashes', async () => {
    const mockResponse: SessionsResponse = {
      data: [
        {
          id: 's1',
          lastPacket: 1704067200,
          http: { md5: 'd41d8cd98f00b204e9800998ecf8427e' },
        },
      ],
      recordsTotal: 1,
      recordsFiltered: 1,
    };

    const client = {
      searchSessions: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await extractIocs(client, {
      expression: 'http.md5 exists',
      iocTypes: ['hash'],
    });

    expect(result.content[0].text).toContain('d41d8cd98f00b204e9800998ecf8427e');
  });

  it('should construct URLs from HTTP host and URI', async () => {
    const mockResponse: SessionsResponse = {
      data: [
        {
          id: 's1',
          lastPacket: 1704067200,
          http: { host: 'malware-c2.example.com', uri: '/gate.php' },
        },
        {
          id: 's2',
          lastPacket: 1704067200,
          http: { host: 'evil.example.org', uri: '/beacon' },
        },
        {
          id: 's3',
          lastPacket: 1704067200,
          http: { host: 'evil.example.org', uri: 'http://evil.example.org/full/path' },
        },
      ],
      recordsTotal: 3,
      recordsFiltered: 3,
    };

    const client = {
      searchSessions: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await extractIocs(client, {
      expression: 'http.host exists',
      iocTypes: ['url'],
    });

    // Should construct full URLs from host + URI
    expect(result.content[0].text).toContain('http://malware-c2.example.com/gate.php');
    expect(result.content[0].text).toContain('http://evil.example.org/beacon');
    // Already full URL should pass through
    expect(result.content[0].text).toContain('http://evil.example.org/full/path');
  });

  it('should extract TLS SNI domains', async () => {
    const mockResponse: SessionsResponse = {
      data: [
        {
          id: 's1',
          lastPacket: 1704067200,
          destination: { ip: '203.0.113.50', port: 443 },
          tls: { sni: 'c2-server.darknet.io' },
        },
        {
          id: 's2',
          lastPacket: 1704067200,
          destination: { ip: '203.0.113.51', port: 8443 },
          tls: { sni: 'exfil.shadowrealm.com' },
        },
      ],
      recordsTotal: 2,
      recordsFiltered: 2,
    };

    const client = {
      searchSessions: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await extractIocs(client, {
      expression: 'tls.sni exists',
      iocTypes: ['domain'],
    });

    expect(result.content[0].text).toContain('c2-server.darknet.io');
    expect(result.content[0].text).toContain('exfil.shadowrealm.com');
    expect(result.content[0].text).toContain('Domains');
  });
});

describe('buildAttackTimeline - Kerberos golden ticket', () => {
  it('should detect many Kerberos TGT requests from one source', async () => {
    // Golden ticket indicator: many Kerberos sessions (port 88) from one
    // source IP requesting TGTs, suggesting a forged ticket being reused
    const sessions = [];
    for (let i = 0; i < 25; i++) {
      sessions.push({
        id: `krb-${i}`,
        lastPacket: 1704067200 + i * 30,
        firstPacket: 1704067200 + i * 30,
        source: { ip: '192.168.1.99' },
        destination: { ip: '10.0.0.1', port: 88 },
        krb5: {
          cname: `administrator@CORP.LOCAL`,
          realm: 'CORP.LOCAL',
          sname: `krbtgt/CORP.LOCAL@CORP.LOCAL`,
        },
      });
    }

    const mockResponse: SessionsResponse = {
      data: sessions,
      recordsTotal: 25,
      recordsFiltered: 25,
    };

    const client = {
      searchSessions: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await buildAttackTimeline(client, { suspectIp: '192.168.1.99' });

    expect(result.content[0].text).toContain('Attack Timeline');
    expect(result.content[0].text).toContain('Kerberos Auth');
    expect(result.content[0].text).toContain('192.168.1.99');
    expect(result.content[0].text).toContain('krbtgt/CORP.LOCAL');
  });
});

describe('trackLateralMovement - Pass-the-Hash', () => {
  it('should detect Pass-the-Hash pattern (SMB auth to many targets)', async () => {
    // Pass-the-Hash: one source authenticating via SMB to many targets
    // without Kerberos pre-auth (reusing NTLM hash)
    const sessions = [];
    for (let i = 1; i <= 15; i++) {
      sessions.push({
        id: `ptth-${i}`,
        lastPacket: 1704067200 + i * 10,
        firstPacket: 1704067200 + i * 10,
        source: { ip: '192.168.1.50' },
        destination: { ip: `10.0.0.${i}`, port: 445 },
        smb: { user: 'svc_backup', domain: 'CORP', host: `WORKSTATION${i}` },
      });
    }

    const mockResponse: SessionsResponse = {
      data: sessions,
      recordsTotal: 15,
      recordsFiltered: 15,
    };

    const client = {
      searchSessions: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await trackLateralMovement(client, { sourceIp: '192.168.1.50' });

    expect(result.content[0].text).toContain('Lateral Movement');
    expect(result.content[0].text).toContain('192.168.1.50');
    // Should identify the source as a pivot point with high outbound
    expect(result.content[0].text).toContain('Outbound: 15');
    // Should show the repeated user across connections
    expect(result.content[0].text).toContain('svc_backup');
  });
});

describe('extractIocs - comprehensive IOC types', () => {
  it('should extract domains from multiple SPI sources simultaneously', async () => {
    const mockResponse: SessionsResponse = {
      data: [
        {
          id: 's1',
          lastPacket: 1704067200,
          dns: { host: 'dns-discovered.malware.com' },
        },
        {
          id: 's2',
          lastPacket: 1704067200,
          http: { host: 'http-discovered.malware.com', uri: '/data' },
        },
        {
          id: 's3',
          lastPacket: 1704067200,
          tls: { sni: 'tls-discovered.malware.com' },
        },
      ],
      recordsTotal: 3,
      recordsFiltered: 3,
    };

    const client = {
      searchSessions: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await extractIocs(client, {
      expression: 'host == malware.com',
      iocTypes: ['domain'],
    });

    // All three sources should contribute domains
    expect(result.content[0].text).toContain('dns-discovered.malware.com');
    expect(result.content[0].text).toContain('http-discovered.malware.com');
    expect(result.content[0].text).toContain('tls-discovered.malware.com');
  });
});

describe('investigateNtlm - LDAP enumeration', () => {
  it('should detect LDAP user enumeration patterns', async () => {
    // LDAP enumeration: many binds with different users from one source
    const sessions = [];
    const userNames = ['admin', 'administrator', 'root', 'svc_account', 'jdoe', 'jsmith', 'guest', 'test', 'backup', 'operator'];
    for (let i = 0; i < userNames.length; i++) {
      sessions.push({
        id: `ldap-${i}`,
        lastPacket: 1704067200 + i * 5,
        firstPacket: 1704067200 + i * 5,
        source: { ip: '192.168.1.150' },
        destination: { ip: '10.0.0.10', port: 389 },
        ldap: { bindname: `CN=${userNames[i]},OU=Users,DC=corp,DC=local`, authtype: 'simple' },
      });
    }

    const mockResponse: SessionsResponse = {
      data: sessions,
      recordsTotal: userNames.length,
      recordsFiltered: userNames.length,
    };

    const client = {
      searchSessions: async () => mockResponse,
    } as unknown as ArkimeClient;

    const result = await investigateNtlm(client, { suspectIp: '192.168.1.150' });

    expect(result.content[0].text).toContain('NTLM/Lateral Movement');
    expect(result.content[0].text).toContain('192.168.1.150');
    // Should detect enumeration (many unique users from one source)
    expect(result.content[0].text).toContain('Users Seen');
  });
});

describe('API error handling', () => {
  it('should propagate 500 Internal Server Error from buildAttackTimeline', async () => {
    const client = {
      searchSessions: async () => {
        const error: McpError = new McpError(ErrorCode.API_ERROR, 'Internal Server Error');
        throw error;
      },
    } as unknown as ArkimeClient;

    await expect(buildAttackTimeline(client, {})).rejects.toThrow(McpError);

    try {
      await buildAttackTimeline(client, {});
    } catch (error) {
      expect(error).toBeInstanceOf(McpError);
      expect((error as McpError).code).toBe(ErrorCode.API_ERROR);
      expect((error as McpError).message).toContain('Internal Server Error');
    }
  });

  it('should propagate 401 Unauthorized error from trackLateralMovement', async () => {
    const client = {
      searchSessions: async () => {
        const error: McpError = new McpError(ErrorCode.AUTH_INVALID, 'Unauthorized: invalid credentials');
        throw error;
      },
    } as unknown as ArkimeClient;

    await expect(trackLateralMovement(client, {})).rejects.toThrow(McpError);

    try {
      await trackLateralMovement(client, {});
    } catch (error) {
      expect(error).toBeInstanceOf(McpError);
      expect((error as McpError).code).toBe(ErrorCode.AUTH_INVALID);
      expect((error as McpError).message).toContain('Unauthorized');
    }
  });

  it('should propagate 403 Forbidden error from extractIocs', async () => {
    const client = {
      searchSessions: async () => {
        const error: McpError = new McpError(ErrorCode.API_ERROR, 'Forbidden: access denied');
        throw error;
      },
    } as unknown as ArkimeClient;

    await expect(extractIocs(client, { expression: 'ip.src == 1.2.3.4' })).rejects.toThrow(McpError);

    try {
      await extractIocs(client, { expression: 'ip.src == 1.2.3.4' });
    } catch (error) {
      expect(error).toBeInstanceOf(McpError);
      expect((error as McpError).code).toBe(ErrorCode.API_ERROR);
      expect((error as McpError).message).toContain('Forbidden');
    }
  });

  it('should propagate connection timeout error from buildAttackTimeline', async () => {
    const client = {
      searchSessions: async () => {
        const error: McpError = new McpError(ErrorCode.NETWORK_ERROR, 'Connection timed out');
        throw error;
      },
    } as unknown as ArkimeClient;

    await expect(buildAttackTimeline(client, {})).rejects.toThrow(McpError);

    try {
      await buildAttackTimeline(client, {});
    } catch (error) {
      expect(error).toBeInstanceOf(McpError);
      expect((error as McpError).code).toBe(ErrorCode.NETWORK_ERROR);
      expect((error as McpError).message).toContain('timed out');
    }
  });
});
