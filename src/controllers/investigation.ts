import type { ArkimeClient } from '@/services/arkime-client.js';
import type { Session } from '@/types/arkime.js';
import { formatTable, isPrivateIp } from '@/utils/formatters.js';
import type { InvestigateNtlmParams } from '@/tools/schemas.js';

interface AuthEvent {
  timestamp: number;
  sourceIp: string;
  destinationIp: string;
  destinationPort: number;
  protocol: string;
  user?: string;
  domain?: string;
  host?: string;
  os?: string;
}

export async function investigateNtlm(
  client: ArkimeClient,
  params: InvestigateNtlmParams
): Promise<{ content: Array<{ type: 'text'; text: string }> }> {
  const expressions: string[] = [];
  
  if (params.suspectIp) {
    expressions.push(`(ip.src == ${params.suspectIp} || ip.dst == ${params.suspectIp})`);
  }
  
  if (params.suspectUser) {
    expressions.push(`(smb.user == "${params.suspectUser}" || ldap.bindname == "${params.suspectUser}")`);
  }
  
  const authPorts = 'port.dst IN [88,139,389,445,636,3268,3269]';
  
  const baseExpression = expressions.length > 0 
    ? `(${expressions.join(' AND ')}) AND (${authPorts})`
    : authPorts;
  
  const finalExpression = params.expression 
    ? `(${baseExpression}) AND (${params.expression})`
    : baseExpression;

  const fields = [
    'id', 'firstPacket', 'lastPacket',
    'source.ip', 'destination.ip', 'destination.port', 'ipProtocol',
    'smb.user', 'smb.domain', 'smb.host', 'smb.os', 'smb.share', 'smb.fn',
    'ldap.bindname', 'ldap.authtype',
  ];

  const response = await client.searchSessions({
    expression: finalExpression,
    length: 500,
    fields,
  });

  if (response.data.length === 0) {
    return {
      content: [{
        type: 'text',
        text: 'No NTLM/LDAP/Kerberos authentication events found for the specified criteria.',
      }],
    };
  }

  const authEvents = extractAuthEvents(response.data);
  const lines: string[] = [
    'NTLM/Lateral Movement Investigation Report',
    '='.repeat(70),
    '',
    `Search Expression: ${finalExpression}`,
    `Sessions Analyzed: ${response.data.length}`,
    '',
  ];

  lines.push(...generateAnalysisReport(authEvents, params.suspectIp, params.suspectUser));

  return {
    content: [{
      type: 'text',
      text: lines.join('\n'),
    }],
  };
}

function extractAuthEvents(sessions: Session[]): AuthEvent[] {
  return sessions.map(session => {
    const smbData = session.smb as Record<string, unknown> | undefined;
    const ldapData = session.ldap as Record<string, unknown> | undefined;
    
    let protocol = 'TCP';
    if (session.destination?.port === 445 || session.destination?.port === 139) {
      protocol = 'SMB';
    } else if (session.destination?.port === 389 || session.destination?.port === 636) {
      protocol = 'LDAP';
    } else if (session.destination?.port === 88) {
      protocol = 'Kerberos';
    } else if (session.destination?.port === 3268 || session.destination?.port === 3269) {
      protocol = 'GC';
    }

    return {
      timestamp: session.firstPacket || 0,
      sourceIp: session.source?.ip || 'unknown',
      destinationIp: session.destination?.ip || 'unknown',
      destinationPort: session.destination?.port || 0,
      protocol,
      user: (smbData?.user as string) || (ldapData?.bindname as string),
      domain: smbData?.domain as string,
      host: (smbData?.host as string) || (smbData?.['host.smb'] as string),
      os: smbData?.os as string,
    };
  });
}

function generateAnalysisReport(
  events: AuthEvent[],
  suspectIp?: string,
  suspectUser?: string
): string[] {
  const lines: string[] = [];
  
  const bySource = new Map<string, AuthEvent[]>();
  const byUser = new Map<string, AuthEvent[]>();
  const byTarget = new Map<string, Set<string>>();
  
  for (const event of events) {
    const srcList = bySource.get(event.sourceIp) || [];
    srcList.push(event);
    bySource.set(event.sourceIp, srcList);
    
    if (event.user) {
      const userList = byUser.get(event.user) || [];
      userList.push(event);
      byUser.set(event.user, userList);
    }
    
    const targetKey = `${event.destinationIp}:${event.destinationPort}`;
    if (!byTarget.has(event.sourceIp)) {
      byTarget.set(event.sourceIp, new Set());
    }
    byTarget.get(event.sourceIp)!.add(targetKey);
  }

  lines.push('## Authentication Activity by Source IP', '');

  const sortedSources = Array.from(bySource.entries())
    .sort((a, b) => b[1].length - a[1].length);

  const sourceTableData = sortedSources.slice(0, 15).map(([ip, ipEvents]) => {
    const targets = byTarget.get(ip)?.size || 0;
    const users = new Set(ipEvents.filter(e => e.user).map(e => e.user)).size;
    const marker = ip === suspectIp ? ' ⚠️' : '';
    return {
      'Source IP': ip + marker,
      Events: ipEvents.length,
      'Unique Targets': targets,
      'Users Seen': users,
    };
  });

  lines.push(formatTable(sourceTableData, ['Source IP', 'Events', 'Unique Targets', 'Users Seen']));
  lines.push('');

  if (byUser.size > 0) {
    lines.push('## Users Observed', '');

    const sortedUsers = Array.from(byUser.entries())
      .sort((a, b) => b[1].length - a[1].length);

    const userTableData = sortedUsers.slice(0, 10).map(([user, userEvents]) => {
      const srcIps = new Set(userEvents.map(e => e.sourceIp)).size;
      const dstIps = new Set(userEvents.map(e => e.destinationIp)).size;
      const marker = user === suspectUser ? ' ⚠️' : '';
      return {
        Username: (user || '').substring(0, 20) + marker,
        Events: userEvents.length,
        'Source IPs': srcIps,
        'Target IPs': dstIps,
      };
    });

    lines.push(formatTable(userTableData, ['Username', 'Events', 'Source IPs', 'Target IPs']));
    lines.push('');
  }

  const pivotCandidates = findPivotCandidates(bySource, byTarget);
  if (pivotCandidates.length > 0) {
    lines.push('## Potential Pivot Points', '');
    lines.push('Hosts with internal-to-internal lateral movement patterns:', '');
    
    for (const candidate of pivotCandidates.slice(0, 5)) {
      const marker = candidate.ip === suspectIp ? ' ⚠️ SUSPECT' : '';
      lines.push(`  ${candidate.ip}${marker}`);
      lines.push(`    - Targets: ${candidate.targetCount} internal hosts`);
      lines.push(`    - Ports: ${candidate.ports.join(', ')}`);
      lines.push(`    - Users: ${candidate.users.join(', ')}`);
      lines.push('');
    }
  }

  const enumeration = findEnumerationPatterns(bySource);
  if (enumeration.length > 0) {
    lines.push('## Possible User/Computer Enumeration', '');
    
    for (const e of enumeration.slice(0, 5)) {
      const marker = e.ip === suspectIp ? ' ⚠️' : '';
      lines.push(`  ${e.ip}${marker}: ${e.userCount} unique users queried via ${e.protocol}`);
    }
    lines.push('');
  }

  return lines;
}

function findPivotCandidates(
  bySource: Map<string, AuthEvent[]>,
  byTarget: Map<string, Set<string>>
): Array<{ ip: string; targetCount: number; ports: number[]; users: string[] }> {
  const candidates: Array<{ ip: string; targetCount: number; ports: number[]; users: string[] }> = [];
  
  for (const [ip, events] of bySource) {
    if (!isPrivateIp(ip)) continue;
    
    const internalTargets = events.filter(e => isPrivateIp(e.destinationIp));
    
    if (internalTargets.length >= 3) {
      const uniqueTargets = new Set(internalTargets.map(e => e.destinationIp));
      const ports = [...new Set(internalTargets.map(e => e.destinationPort))];
      const users = [...new Set(internalTargets.filter(e => e.user).map(e => e.user!))];
      
      if (uniqueTargets.size >= 2) {
        candidates.push({
          ip,
          targetCount: uniqueTargets.size,
          ports,
          users: users.slice(0, 5),
        });
      }
    }
  }
  
  return candidates.sort((a, b) => b.targetCount - a.targetCount);
}

function findEnumerationPatterns(
  bySource: Map<string, AuthEvent[]>
): Array<{ ip: string; userCount: number; protocol: string }> {
  const results: Array<{ ip: string; userCount: number; protocol: string }> = [];
  
  for (const [ip, events] of bySource) {
    const ldapEvents = events.filter(e => e.destinationPort === 389 || e.destinationPort === 636);
    if (ldapEvents.length >= 5) {
      const uniqueUsers = new Set(ldapEvents.filter(e => e.user).map(e => e.user));
      if (uniqueUsers.size >= 3) {
        results.push({ ip, userCount: uniqueUsers.size, protocol: 'LDAP' });
      }
    }
  }
  
  return results.sort((a, b) => b.userCount - a.userCount);
}
