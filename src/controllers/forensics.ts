import type { ArkimeClient } from '@/services/arkime-client.js';
import type { Session } from '@/types/arkime.js';
import { getProtocolFromPort, isPrivateIp, isoToTimestamp, unixToISO } from '@/utils/formatters.js';
import type { BuildTimelineParams, ExtractIocsParams, TrackMovementParams } from '@/tools/schemas.js';

interface TimelineEvent {
  timestamp: number;
  isoTime: string;
  sessionId: string;
  sourceIp: string;
  destinationIp: string;
  destinationPort: number;
  protocol: string;
  event: string;
  details: Record<string, unknown>;
  risk: 'low' | 'medium' | 'high';
}

export async function buildAttackTimeline(
  client: ArkimeClient,
  params: BuildTimelineParams
): Promise<{ content: Array<{ type: 'text'; text: string }> }> {
  const expressions: string[] = [];
  
  if (params.suspectIp) {
    expressions.push(`(ip.src == ${params.suspectIp} || ip.dst == ${params.suspectIp})`);
  }
  if (params.suspectHost) {
    expressions.push(`(host.smb == "${params.suspectHost}" || http.host == "${params.suspectHost}")`);
  }
  if (params.suspectUser) {
    expressions.push(`(smb.user == "${params.suspectUser}" || ldap.bindname contains "${params.suspectUser}" || email.src contains "${params.suspectUser}")`);
  }

  const baseExpression = expressions.length > 0 
    ? expressions.join(' AND ')
    : 'port.dst IN [88,139,389,443,445,636,3389,5985,5986]';

  const fields = [
    'id', 'firstPacket', 'lastPacket',
    'source.ip', 'destination.ip', 'destination.port', 'ipProtocol',
    'smb.user', 'smb.domain', 'smb.host', 'smb.share', 'smb.fn',
    'ldap.bindname', 'ldap.authtype',
    'krb5.cname', 'krb5.realm', 'krb5.sname',
    'http.uri', 'http.method', 'http.statuscode', 'http.host',
    'dns.host', 'dns.ans',
    'tls.sni',
    'email.src', 'email.dst', 'email.subject',
  ];

  const response = await client.searchSessions({
    expression: baseExpression,
    startTime: params.startTime ? isoToTimestamp(params.startTime) : undefined,
    endTime: params.endTime ? isoToTimestamp(params.endTime) : undefined,
    length: 1000,
    fields,
  });

  if (response.data.length === 0) {
    return {
      content: [{ type: 'text', text: 'No events found for timeline construction.' }],
    };
  }

  const events = buildTimelineEvents(response.data);
  events.sort((a, b) => a.timestamp - b.timestamp);

  const lines = formatTimeline(events, params);
  
  return {
    content: [{ type: 'text', text: lines.join('\n') }],
  };
}

function buildTimelineEvents(sessions: Session[]): TimelineEvent[] {
  const events: TimelineEvent[] = [];

  for (const session of sessions) {
    const baseEvent = {
      timestamp: session.firstPacket || 0,
      isoTime: unixToISO(session.firstPacket || 0),
      sessionId: session.id,
      sourceIp: session.source?.ip || 'unknown',
      destinationIp: session.destination?.ip || 'unknown',
      destinationPort: session.destination?.port || 0,
    };

    const port = session.destination?.port;
    const smb = session.smb as Record<string, unknown> | undefined;
    const ldap = session.ldap as Record<string, unknown> | undefined;
    const krb5 = session.krb5 as Record<string, unknown> | undefined;
    const http = session.http as Record<string, unknown> | undefined;
    const dns = session.dns as Record<string, unknown> | undefined;
    const tls = session.tls as Record<string, unknown> | undefined;
    const email = session.email as Record<string, unknown> | undefined;

    if (port === 445 || port === 139) {
      if (smb?.user) {
        events.push({
          ...baseEvent,
          protocol: 'SMB',
          event: 'SMB Authentication',
          details: { 
            user: smb.user, 
            domain: smb.domain,
            host: smb.host,
            share: smb.share 
          },
          risk: smb.user?.toString().toLowerCase().includes('admin') ? 'high' : 'medium',
        });
      }
      if (smb?.fn) {
        events.push({
          ...baseEvent,
          protocol: 'SMB',
          event: 'File Access',
          details: { filename: smb.fn, share: smb.share },
          risk: 'low',
        });
      }
    }

    if (port === 389 || port === 636 || port === 3268 || port === 3269) {
      if (ldap?.bindname) {
        events.push({
          ...baseEvent,
          protocol: 'LDAP',
          event: 'LDAP Bind',
          details: { bindname: ldap.bindname, authtype: ldap.authtype },
          risk: 'medium',
        });
      }
    }

    if (port === 88) {
      if (krb5?.cname) {
        events.push({
          ...baseEvent,
          protocol: 'Kerberos',
          event: 'Kerberos Auth',
          details: { 
            client: krb5.cname, 
            realm: krb5.realm,
            service: krb5.sname 
          },
          risk: 'medium',
        });
      }
    }

    if (port === 443 || port === 80) {
      if (http?.uri) {
        events.push({
          ...baseEvent,
          protocol: 'HTTP',
          event: `${http.method || 'GET'} Request`,
          details: { 
            uri: http.uri, 
            host: http.host,
            status: http.statuscode 
          },
          risk: String(http.uri).includes('admin') ? 'high' : 'low',
        });
      }
    }

    if (port === 3389) {
      events.push({
        ...baseEvent,
        protocol: 'RDP',
        event: 'RDP Connection',
        details: {},
        risk: 'high',
      });
    }

    if (port === 5985 || port === 5986) {
      events.push({
        ...baseEvent,
        protocol: 'WinRM',
        event: 'WinRM Connection',
        details: {},
        risk: 'high',
      });
    }

    if (dns?.host) {
      events.push({
        ...baseEvent,
        protocol: 'DNS',
        event: 'DNS Query',
        details: { query: dns.host, answer: dns.ans },
        risk: 'low',
      });
    }

    if (tls?.sni) {
      events.push({
        ...baseEvent,
        protocol: 'TLS',
        event: 'TLS Handshake',
        details: { sni: tls.sni },
        risk: 'low',
      });
    }

    if (email?.subject) {
      events.push({
        ...baseEvent,
        protocol: 'SMTP',
        event: 'Email Sent',
        details: { 
          from: email.src, 
          to: email.dst,
          subject: email.subject 
        },
        risk: 'medium',
      });
    }
  }

  return events;
}

function formatTimeline(events: TimelineEvent[], params: BuildTimelineParams): string[] {
  const lines: string[] = [
    'Attack Timeline Reconstruction',
    '='.repeat(80),
    '',
    `Filter: IP=${params.suspectIp || 'any'} User=${params.suspectUser || 'any'} Host=${params.suspectHost || 'any'}`,
    `Events: ${events.length}`,
    '',
  ];

  const riskColors = { high: '🔴', medium: '🟡', low: '⚪' };

  let currentDate = '';
  for (const event of events) {
    const date = event.isoTime.split('T')[0];
    const time = event.isoTime.split('T')[1].split('.')[0];

    if (date !== currentDate) {
      currentDate = date;
      lines.push(`\n## ${date}`);
    }

    const riskIcon = riskColors[event.risk];
    const details = Object.entries(event.details)
      .filter(([, v]) => v !== undefined && v !== null)
      .map(([k, v]) => `${k}=${v}`)
      .join(', ');

    lines.push(
      `  ${time} ${riskIcon} [${event.protocol.padEnd(10)}] ${event.sourceIp} → ${event.destinationIp}:${event.destinationPort}`
    );
    lines.push(`       ${event.event}${details ? ` | ${details}` : ''}`);
  }

  lines.push('');
  lines.push('## Risk Summary');
  const highCount = events.filter(e => e.risk === 'high').length;
  const medCount = events.filter(e => e.risk === 'medium').length;
  const lowCount = events.filter(e => e.risk === 'low').length;
  lines.push(`  🔴 High: ${highCount}  🟡 Medium: ${medCount}  ⚪ Low: ${lowCount}`);

  return lines;
}

interface HostNode {
  ip: string;
  hostname?: string;
  users: Set<string>;
  outboundConnections: number;
  inboundConnections: number;
  protocols: Set<string>;
}

interface ConnectionEdge {
  source: string;
  target: string;
  count: number;
  protocols: string[];
  users: string[];
  ports: number[];
}

export async function trackLateralMovement(
  client: ArkimeClient,
  params: TrackMovementParams
): Promise<{ content: Array<{ type: 'text'; text: string }> }> {
  const protocols = params.protocols || ['smb', 'ldap', 'rdp', 'winrm', 'ssh'];
  
  const portMap: Record<string, number[]> = {
    smb: [139, 445],
    ldap: [389, 636, 3268, 3269],
    rdp: [3389],
    winrm: [5985, 5986],
    ssh: [22],
  };

  const ports = protocols.flatMap(p => portMap[p] || []);
  const expression = `port.dst IN [${ports.join(',')}]`;
  
  const fields = [
    'id', 'source.ip', 'destination.ip', 'destination.port',
    'smb.user', 'smb.host', 'smb.domain',
    'ldap.bindname',
    'host.smb',
  ];

  const response = await client.searchSessions({
    expression: params.sourceIp 
      ? `(${expression}) AND (ip.src == ${params.sourceIp} || ip.dst == ${params.sourceIp})`
      : expression,
    length: 2000,
    fields,
  });

  if (response.data.length === 0) {
    return {
      content: [{ type: 'text', text: 'No lateral movement patterns found.' }],
    };
  }

  const { nodes, edges } = buildMovementGraph(response.data, params.minConnections || 2);
  const lines = formatMovementGraph(nodes, edges, params);
  
  return {
    content: [{ type: 'text', text: lines.join('\n') }],
  };
}

function buildMovementGraph(
  sessions: Session[],
  minConnections: number
): { nodes: Map<string, HostNode>; edges: ConnectionEdge[] } {
  const nodes = new Map<string, HostNode>();
  const edgeMap = new Map<string, ConnectionEdge>();

  for (const session of sessions) {
    const srcIp = session.source?.ip || 'unknown';
    const dstIp = session.destination?.ip || 'unknown';
    const port = session.destination?.port || 0;
    const smb = session.smb as Record<string, unknown> | undefined;
    const ldap = session.ldap as Record<string, unknown> | undefined;

    const protocol = getProtocolFromPort(port);
    const user = (smb?.user as string) || (ldap?.bindname as string)?.split(',')[0]?.replace('CN=', '');
    const hostname = smb?.host as string;

    if (!nodes.has(srcIp)) {
      nodes.set(srcIp, { 
        ip: srcIp, 
        users: new Set(), 
        outboundConnections: 0, 
        inboundConnections: 0,
        protocols: new Set(),
      });
    }
    if (!nodes.has(dstIp)) {
      nodes.set(dstIp, { 
        ip: dstIp, 
        users: new Set(), 
        outboundConnections: 0, 
        inboundConnections: 0,
        protocols: new Set(),
      });
    }

    nodes.get(srcIp)!.outboundConnections++;
    nodes.get(srcIp)!.protocols.add(protocol);
    if (hostname && !nodes.get(dstIp)!.hostname) {
      nodes.get(dstIp)!.hostname = hostname;
    }
    if (user) {
      nodes.get(srcIp)!.users.add(user);
    }

    nodes.get(dstIp)!.inboundConnections++;

    const edgeKey = `${srcIp}→${dstIp}`;
    if (!edgeMap.has(edgeKey)) {
      edgeMap.set(edgeKey, {
        source: srcIp,
        target: dstIp,
        count: 0,
        protocols: [],
        users: [],
        ports: [],
      });
    }
    const edge = edgeMap.get(edgeKey)!;
    edge.count++;
    if (!edge.protocols.includes(protocol)) edge.protocols.push(protocol);
    if (user && !edge.users.includes(user)) edge.users.push(user);
    if (!edge.ports.includes(port)) edge.ports.push(port);
  }

  const edges = Array.from(edgeMap.values()).filter(e => e.count >= minConnections);
  
  return { nodes, edges };
}

function formatMovementGraph(
  nodes: Map<string, HostNode>,
  edges: ConnectionEdge[],
  _params: TrackMovementParams
): string[] {
  const lines: string[] = [
    'Lateral Movement Analysis',
    '='.repeat(80),
    '',
    `Nodes: ${nodes.size} | Connections: ${edges.length}`,
    '',
  ];

  const sortedNodes = Array.from(nodes.values())
    .sort((a, b) => b.outboundConnections - a.outboundConnections);

  lines.push('## Potential Pivot Points (High Outbound)');
  for (const node of sortedNodes.filter(n => n.outboundConnections >= 3).slice(0, 10)) {
    const marker = node.ip === _params.sourceIp ? ' ⚠️ SUSPECT' : '';
    lines.push(`  ${node.ip}${marker}`);
    lines.push(`    Outbound: ${node.outboundConnections} | Inbound: ${node.inboundConnections}`);
    lines.push(`    Protocols: ${[...node.protocols].join(', ')}`);
    if (node.users.size > 0) {
      lines.push(`    Users: ${[...node.users].slice(0, 3).join(', ')}${node.users.size > 3 ? '...' : ''}`);
    }
    lines.push('');
  }

  lines.push('## Movement Paths');
  const sortedEdges = edges.sort((a, b) => b.count - a.count);
  
  for (const edge of sortedEdges.slice(0, 20)) {
    const marker = edge.source === _params.sourceIp ? '⚠️ ' : '  ';
    lines.push(`${marker}${edge.source} → ${edge.target}`);
    lines.push(`     Count: ${edge.count} | Protocols: ${edge.protocols.join(', ')}`);
    if (edge.users.length > 0) {
      lines.push(`     Users: ${edge.users.slice(0, 3).join(', ')}`);
    }
    lines.push('');
  }

  lines.push('## GraphViz (for visualization)');
  lines.push('```');
  lines.push('digraph lateral_movement {');
  lines.push('  rankdir=LR;');
  for (const edge of sortedEdges.slice(0, 30)) {
    const label = `${edge.protocols.join(',')}\\n${edge.count}x`;
    lines.push(`  "${edge.source}" -> "${edge.target}" [label="${label}"];`);
  }
  lines.push('}');
  lines.push('```');

  return lines;
}

export async function extractIocs(
  client: ArkimeClient,
  params: ExtractIocsParams
): Promise<{ content: Array<{ type: 'text'; text: string }> }> {
  const iocTypes = params.iocTypes || ['ip', 'domain', 'hash', 'url', 'email'];
  
  const fields = [
    'id', 'source.ip', 'destination.ip',
    'dns.host', 'dns.ans',
    'http.host', 'http.uri', 'http.referer',
    'tls.sni',
    'email.src', 'email.dst',
    'http.md5', 'email.bodymagic',
  ];

  const response = await client.searchSessions({
    expression: params.expression,
    length: 1000,
    fields,
  });

  if (response.data.length === 0) {
    return {
      content: [{ type: 'text', text: 'No sessions found for IOC extraction.' }],
    };
  }

  const iocs = collectIocs(response.data, iocTypes);
  const lines = formatIocs(iocs, params.expression);
  
  return {
    content: [{ type: 'text', text: lines.join('\n') }],
  };
}

interface IocCollection {
  ips: Set<string>;
  domains: Set<string>;
  urls: Set<string>;
  hashes: Set<string>;
  emails: Set<string>;
}

function collectIocs(sessions: Session[], types: string[]): IocCollection {
  const iocs: IocCollection = {
    ips: new Set(),
    domains: new Set(),
    urls: new Set(),
    hashes: new Set(),
    emails: new Set(),
  };

  const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  const hashRegex = /^[a-fA-F0-9]{32,64}$/;
  const domainRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

  for (const session of sessions) {
    if (types.includes('ip')) {
      if (session.source?.ip && !isPrivateIp(session.source.ip)) {
        iocs.ips.add(session.source.ip);
      }
      if (session.destination?.ip && !isPrivateIp(session.destination.ip)) {
        iocs.ips.add(session.destination.ip);
      }
    }

    const dns = session.dns as Record<string, unknown> | undefined;
    const http = session.http as Record<string, unknown> | undefined;
    const tls = session.tls as Record<string, unknown> | undefined;
    const email = session.email as Record<string, unknown> | undefined;

    if (types.includes('domain')) {
      if (dns?.host && domainRegex.test(String(dns.host))) {
        iocs.domains.add(String(dns.host));
      }
      if (http?.host && domainRegex.test(String(http.host))) {
        iocs.domains.add(String(http.host));
      }
      if (tls?.sni && domainRegex.test(String(tls.sni))) {
        iocs.domains.add(String(tls.sni));
      }
    }

    if (types.includes('url') && http?.uri) {
      const uri = String(http.uri);
      if (uri.startsWith('http')) {
        iocs.urls.add(uri);
      } else if (http.host) {
        iocs.urls.add(`http://${http.host}${uri}`);
      }
    }

    if (types.includes('hash')) {
      if (http?.md5 && hashRegex.test(String(http.md5))) {
        iocs.hashes.add(String(http.md5));
      }
    }

    if (types.includes('email')) {
      if (email?.src && emailRegex.test(String(email.src))) {
        iocs.emails.add(String(email.src));
      }
      if (email?.dst && emailRegex.test(String(email.dst))) {
        iocs.emails.add(String(email.dst));
      }
    }
  }

  return iocs;
}


function formatIocs(iocs: IocCollection, expression: string): string[] {
  const lines: string[] = [
    'IOC Extraction Report',
    '='.repeat(80),
    '',
    `Source Expression: ${expression}`,
    '',
  ];

  if (iocs.ips.size > 0) {
    lines.push('## IP Addresses');
    for (const ip of [...iocs.ips].sort()) {
      lines.push(`  - ${ip}`);
    }
    lines.push('');
  }

  if (iocs.domains.size > 0) {
    lines.push('## Domains');
    for (const domain of [...iocs.domains].sort()) {
      lines.push(`  - ${domain}`);
    }
    lines.push('');
  }

  if (iocs.urls.size > 0) {
    lines.push('## URLs');
    for (const url of [...iocs.urls].sort()) {
      lines.push(`  - ${url}`);
    }
    lines.push('');
  }

  if (iocs.hashes.size > 0) {
    lines.push('## File Hashes');
    for (const hash of [...iocs.hashes].sort()) {
      lines.push(`  - ${hash}`);
    }
    lines.push('');
  }

  if (iocs.emails.size > 0) {
    lines.push('## Email Addresses');
    for (const email of [...iocs.emails].sort()) {
      lines.push(`  - ${email}`);
    }
    lines.push('');
  }

  lines.push('## Summary');
  lines.push(`  IPs: ${iocs.ips.size} | Domains: ${iocs.domains.size} | URLs: ${iocs.urls.size}`);
  lines.push(`  Hashes: ${iocs.hashes.size} | Emails: ${iocs.emails.size}`);

  return lines;
}
