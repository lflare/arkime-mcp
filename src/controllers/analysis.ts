import { ArkimeClient } from '@/services/arkime-client.js';
import { McpError, ErrorCode } from '@/utils/errors.js';
import { formatBytes, formatTable, isPrivateIp, isoToTimestamp, PROTOCOL_MAP, LATERAL_MOVEMENT_PORTS } from '@/utils/formatters.js';
import type { AnalyzeTrafficParams, HuntSuspiciousParams } from '@/tools/schemas.js';
import type { Session } from '@/types/arkime.js';

interface IpStats {
  ip: string;
  connections: number;
  bytesIn: number;
  bytesOut: number;
  packetsIn: number;
  packetsOut: number;
  ports: Set<number>;
  protocols: Set<number>;
}

interface PortStats {
  port: number;
  connections: number;
  bytes: number;
  protocols: Set<number>;
  sources: Set<string>;
}

interface ConnectionPair {
  source: string;
  destination: string;
  count: number;
  bytes: number;
}

export async function analyzeTraffic(
  client: ArkimeClient,
  params: AnalyzeTrafficParams
): Promise<{ content: Array<{ type: 'text'; text: string }> }> {
  const fields = [
    'source.ip', 'source.port', 'source.bytes', 'source.packets',
    'destination.ip', 'destination.port', 'destination.bytes', 'destination.packets',
    'ipProtocol', 'network.bytes', 'network.packets'
  ];

  const response = await client.searchSessions({
    expression: params.expression,
    startTime: params.startTime ? isoToTimestamp(params.startTime) : undefined,
    endTime: params.endTime ? isoToTimestamp(params.endTime) : undefined,
    length: 1000,
    fields,
  });

  const sessions = response.data;

  if (sessions.length === 0) {
    return {
      content: [{
        type: 'text',
        text: 'No sessions found matching criteria for analysis.',
      }],
    };
  }

  switch (params.analysisType) {
    case 'top-talkers':
      return analyzeTopTalkers(sessions, params.limit) as { content: Array<{ type: 'text'; text: string }> };
    case 'protocols':
      return analyzeProtocols(sessions, params.limit) as { content: Array<{ type: 'text'; text: string }> };
    case 'ports':
      return analyzePorts(sessions, params.limit) as { content: Array<{ type: 'text'; text: string }> };
    case 'connections':
      return analyzeConnections(sessions, params.limit) as { content: Array<{ type: 'text'; text: string }> };
    default:
      throw new McpError(ErrorCode.INVALID_INPUT, `Unknown analysis type: ${params.analysisType}`);
  }
}

function analyzeTopTalkers(sessions: Session[], limit: number) {
  const ipStats = new Map<string, IpStats>();

  for (const session of sessions) {
    const srcIp = session.source?.ip || 'unknown';
    const dstIp = session.destination?.ip || 'unknown';

    if (!ipStats.has(srcIp)) {
      ipStats.set(srcIp, { ip: srcIp, connections: 0, bytesIn: 0, bytesOut: 0, packetsIn: 0, packetsOut: 0, ports: new Set(), protocols: new Set() });
    }
    if (!ipStats.has(dstIp)) {
      ipStats.set(dstIp, { ip: dstIp, connections: 0, bytesIn: 0, bytesOut: 0, packetsIn: 0, packetsOut: 0, ports: new Set(), protocols: new Set() });
    }

    const srcStats = ipStats.get(srcIp)!;
    const dstStats = ipStats.get(dstIp)!;

    srcStats.connections++;
    dstStats.connections++;
    srcStats.bytesOut += session.source?.bytes || 0;
    dstStats.bytesIn += session.destination?.bytes || 0;
    srcStats.packetsOut += session.source?.packets || 0;
    dstStats.packetsIn += session.destination?.packets || 0;

    if (session.source?.port) srcStats.ports.add(session.source.port);
    if (session.destination?.port) dstStats.ports.add(session.destination.port);
    if (session.ipProtocol !== undefined) {
      srcStats.protocols.add(session.ipProtocol);
      dstStats.protocols.add(session.ipProtocol);
    }
  }

  const sortedIps = Array.from(ipStats.values())
    .sort((a, b) => b.connections - a.connections)
    .slice(0, limit);

  const tableData = sortedIps.map(stat => ({
    'IP Address': stat.ip,
    Connections: stat.connections,
    'Bytes Out': formatBytes(stat.bytesOut),
    'Bytes In': formatBytes(stat.bytesIn),
    Ports: stat.ports.size,
    Protocols: Array.from(stat.protocols).map(p => PROTOCOL_MAP[p] || p).join(','),
  }));

  const lines = [
    `Top Talkers Analysis (${sessions.length} sessions analyzed)`,
    '='.repeat(60),
    '',
    formatTable(tableData, ['IP Address', 'Connections', 'Bytes Out', 'Bytes In', 'Ports', 'Protocols']),
  ];

  return { content: [{ type: 'text', text: lines.join('\n') }] };
}

function analyzeProtocols(sessions: Session[], _limit: number) {
  const protoStats = new Map<number, { count: number; bytes: number; packets: number }>();

  for (const session of sessions) {
    const proto = session.ipProtocol || 0;
    if (!protoStats.has(proto)) {
      protoStats.set(proto, { count: 0, bytes: 0, packets: 0 });
    }
    const stats = protoStats.get(proto)!;
    stats.count++;
    stats.bytes += (session.source?.bytes || 0) + (session.destination?.bytes || 0);
    stats.packets += (session.source?.packets || 0) + (session.destination?.packets || 0);
  }

  const sortedProtos = Array.from(protoStats.entries())
    .sort((a, b) => b[1].count - a[1].count);

  const tableData = sortedProtos.map(([proto, stats]) => ({
    Protocol: PROTOCOL_MAP[proto] || `Unknown(${proto})`,
    Sessions: stats.count,
    Bytes: formatBytes(stats.bytes),
    Packets: stats.packets,
  }));

  const lines = [
    `Protocol Analysis (${sessions.length} sessions)`,
    '='.repeat(50),
    '',
    formatTable(tableData, ['Protocol', 'Sessions', 'Bytes', 'Packets']),
  ];

  return { content: [{ type: 'text', text: lines.join('\n') }] };
}

function analyzePorts(sessions: Session[], limit: number) {
  const portStats = new Map<number, PortStats>();

  for (const session of sessions) {
    const port = session.destination?.port;
    if (!port) continue;

    if (!portStats.has(port)) {
      portStats.set(port, { port, connections: 0, bytes: 0, protocols: new Set(), sources: new Set() });
    }
    const stats = portStats.get(port)!;
    stats.connections++;
    stats.bytes += (session.source?.bytes || 0) + (session.destination?.bytes || 0);
    if (session.ipProtocol !== undefined) stats.protocols.add(session.ipProtocol);
    if (session.source?.ip) stats.sources.add(session.source.ip);
  }

  const sortedPorts = Array.from(portStats.values())
    .sort((a, b) => b.connections - a.connections)
    .slice(0, limit);

  const tableData = sortedPorts.map(stat => ({
    Port: stat.port,
    Connections: stat.connections,
    'Total Bytes': formatBytes(stat.bytes),
    'Unique Sources': stat.sources.size,
  }));

  const lines = [
    `Port Analysis (${sessions.length} sessions)`,
    '='.repeat(60),
    '',
    formatTable(tableData, ['Port', 'Connections', 'Total Bytes', 'Unique Sources']),
  ];

  return { content: [{ type: 'text', text: lines.join('\n') }] };
}

function analyzeConnections(sessions: Session[], limit: number) {
  const connections = new Map<string, ConnectionPair>();

  for (const session of sessions) {
    const srcIp = session.source?.ip || 'unknown';
    const dstIp = session.destination?.ip || 'unknown';
    const key = `${srcIp}->${dstIp}`;

    if (!connections.has(key)) {
      connections.set(key, { source: srcIp, destination: dstIp, count: 0, bytes: 0 });
    }
    const conn = connections.get(key)!;
    conn.count++;
    conn.bytes += (session.source?.bytes || 0) + (session.destination?.bytes || 0);
  }

  const sortedConns = Array.from(connections.values())
    .sort((a, b) => b.count - a.count)
    .slice(0, limit);

  const tableData = sortedConns.map(conn => ({
    'Source IP': conn.source,
    'Destination IP': conn.destination,
    Sessions: conn.count,
    Bytes: formatBytes(conn.bytes),
  }));

  const lines = [
    `Connection Pairs (${sessions.length} sessions)`,
    '='.repeat(70),
    '',
    formatTable(tableData, ['Source IP', 'Destination IP', 'Sessions', 'Bytes']),
  ];

  return { content: [{ type: 'text', text: lines.join('\n') }] };
}

export async function huntSuspicious(
  client: ArkimeClient,
  params: HuntSuspiciousParams
): Promise<{ content: Array<{ type: 'text'; text: string }> }> {
  const baseFields = [
    'source.ip', 'source.port',
    'destination.ip', 'destination.port',
    'ipProtocol', 'network.bytes', 'network.packets'
  ];

  switch (params.huntType) {
    case 'port-scanners':
      return huntPortScanners(client, params, baseFields);
    case 'beaconing':
      return huntBeaconing(client, params, baseFields);
    case 'data-exfil':
      return huntDataExfil(client, params, baseFields);
    case 'lateral-movement':
      return huntLateralMovement(client, params, baseFields);
    default:
      throw new McpError(ErrorCode.INVALID_INPUT, `Unknown hunt type: ${params.huntType}`);
  }
}

async function huntPortScanners(
  client: ArkimeClient,
  params: HuntSuspiciousParams,
  fields: string[]
): Promise<{ content: Array<{ type: 'text'; text: string }> }> {
  const response = await client.searchSessions({
    expression: params.expression,
    length: 2000,
    fields,
  });

  const scannerStats = new Map<string, { ports: Set<number>; targets: Set<string>; sessions: number }>();

  for (const session of response.data) {
    const srcIp = session.source?.ip;
    if (!srcIp) continue;

    if (!scannerStats.has(srcIp)) {
      scannerStats.set(srcIp, { ports: new Set(), targets: new Set(), sessions: 0 });
    }
    const stats = scannerStats.get(srcIp)!;
    stats.sessions++;
    if (session.destination?.port) stats.ports.add(session.destination.port);
    if (session.destination?.ip) stats.targets.add(session.destination.ip);
  }

  const potentialScanners = Array.from(scannerStats.entries())
    .filter(([_, stats]) => stats.ports.size >= params.threshold || stats.targets.size >= 10)
    .sort((a, b) => b[1].ports.size - a[1].ports.size);

  if (potentialScanners.length === 0) {
    return {
      content: [{
        type: 'text',
        text: `No port scanners detected (threshold: ${params.threshold} unique ports).`,
      }],
    };
  }

  const lines = [
    `Potential Port Scanners Detected (threshold: ${params.threshold} ports)`,
    '='.repeat(70),
    '',
    '| Source IP | Unique Ports | Unique Targets | Total Sessions |',
    '|-----------|--------------|----------------|----------------|',
  ];

  for (const [ip, stats] of potentialScanners.slice(0, 20)) {
    lines.push(`| ${ip.padEnd(15)} | ${String(stats.ports.size).padStart(12)} | ${String(stats.targets.size).padStart(14)} | ${String(stats.sessions).padStart(14)} |`);
  }

  return { content: [{ type: 'text', text: lines.join('\n') }] };
}

async function huntBeaconing(
  client: ArkimeClient,
  params: HuntSuspiciousParams,
  fields: string[]
): Promise<{ content: Array<{ type: 'text'; text: string }> }> {
  const response = await client.searchSessions({
    expression: params.expression,
    length: 2000,
    fields: [...fields, 'firstPacket', 'lastPacket'],
  });

  const beaconStats = new Map<string, { sessions: number; intervals: number[]; totalBytes: number }>();

  // Group sessions by connection pair
  const connectionMap = new Map<string, Session[]>();
  for (const session of response.data) {
    if (!session.firstPacket) continue;
    const srcIp = session.source?.ip;
    const dstIp = session.destination?.ip;
    if (!srcIp || !dstIp) continue;
    const key = `${srcIp}->${dstIp}`;
    if (!connectionMap.has(key)) {
      connectionMap.set(key, []);
    }
    connectionMap.get(key)!.push(session);
  }

  // Calculate intervals within each connection pair
  for (const [key, sessions] of connectionMap) {
    if (sessions.length < 2) continue;
    sessions.sort((a, b) => (a.firstPacket || 0) - (b.firstPacket || 0));

    if (!beaconStats.has(key)) {
      beaconStats.set(key, { sessions: 0, intervals: [], totalBytes: 0 });
    }
    const stats = beaconStats.get(key)!;

    for (const session of sessions) {
      stats.sessions++;
      stats.totalBytes += (session.network?.bytes || 0);
    }

    for (let i = 1; i < sessions.length; i++) {
      const interval = Math.abs((sessions[i].firstPacket || 0) - (sessions[i - 1].firstPacket || 0));
      if (interval > 0) {
        stats.intervals.push(interval);
      }
    }
  }

  const potentialBeacons = Array.from(beaconStats.entries())
    .filter(([_, stats]) => stats.sessions >= params.threshold && stats.intervals.length > 0)
    .map(([key, stats]) => {
      const avgInterval = stats.intervals.reduce((a, b) => a + b, 0) / stats.intervals.length;
      const variance = stats.intervals.reduce((sum, i) => sum + Math.pow(i - avgInterval, 2), 0) / stats.intervals.length;
      const stdDev = Math.sqrt(variance);
      const regularity = avgInterval > 0 ? (1 - stdDev / avgInterval) * 100 : 0;
      return { key, ...stats, avgInterval, regularity: Math.max(0, regularity) };
    })
    .filter(b => b.regularity > 50)
    .sort((a, b) => b.regularity - a.regularity);

  if (potentialBeacons.length === 0) {
    return {
      content: [{
        type: 'text',
        text: `No beaconing patterns detected (threshold: ${params.threshold} sessions, 50% regularity).`,
      }],
    };
  }

  const lines = [
    `Potential C2 Beaconing Detected`,
    '='.repeat(70),
    '',
    '| Connection | Sessions | Avg Interval (s) | Regularity | Bytes |',
    '|------------|----------|------------------|------------|-------|',
  ];

  for (const beacon of potentialBeacons.slice(0, 20)) {
    const avgSec = Math.round(beacon.avgInterval / 1000);
    lines.push(`| ${beacon.key.padEnd(26)} | ${String(beacon.sessions).padStart(8)} | ${String(avgSec).padStart(16)} | ${beacon.regularity.toFixed(1).padStart(8)}% | ${formatBytes(beacon.totalBytes).padStart(5)} |`);
  }

  return { content: [{ type: 'text', text: lines.join('\n') }] };
}

async function huntDataExfil(
  client: ArkimeClient,
  params: HuntSuspiciousParams,
  fields: string[]
): Promise<{ content: Array<{ type: 'text'; text: string }> }> {
  const response = await client.searchSessions({
    expression: params.expression,
    length: 2000,
    fields,
  });

  const exfilStats = new Map<string, { bytesOut: number; bytesIn: number; sessions: number; destinations: Set<string> }>();

  for (const session of response.data) {
    const srcIp = session.source?.ip;
    if (!srcIp) continue;

    if (!exfilStats.has(srcIp)) {
      exfilStats.set(srcIp, { bytesOut: 0, bytesIn: 0, sessions: 0, destinations: new Set() });
    }
    const stats = exfilStats.get(srcIp)!;
    stats.sessions++;
    stats.bytesOut += session.source?.bytes || 0;
    stats.bytesIn += session.destination?.bytes || 0;
    if (session.destination?.ip) stats.destinations.add(session.destination.ip);
  }

  const potentialExfil = Array.from(exfilStats.entries())
    .filter(([_, stats]) => stats.bytesOut > params.threshold * 1024 * 1024 && stats.bytesOut > stats.bytesIn * 3)
    .sort((a, b) => b[1].bytesOut - a[1].bytesOut);

  if (potentialExfil.length === 0) {
    return {
      content: [{
        type: 'text',
        text: `No data exfiltration patterns detected (threshold: ${params.threshold} MB outbound, 3:1 ratio).`,
      }],
    };
  }

  const lines = [
    `Potential Data Exfiltration Detected`,
    '='.repeat(70),
    '',
    '| Source IP | Bytes Out | Bytes In | Ratio | Destinations |',
    '|-----------|-----------|----------|-------|--------------|',
  ];

  for (const [ip, stats] of potentialExfil.slice(0, 20)) {
    const ratio = stats.bytesIn > 0 ? (stats.bytesOut / stats.bytesIn).toFixed(1) : '∞';
    lines.push(`| ${ip.padEnd(15)} | ${formatBytes(stats.bytesOut).padStart(9)} | ${formatBytes(stats.bytesIn).padStart(8)} | ${ratio.padStart(5)} | ${String(stats.destinations.size).padStart(12)} |`);
  }

  return { content: [{ type: 'text', text: lines.join('\n') }] };
}

async function huntLateralMovement(
  client: ArkimeClient,
  params: HuntSuspiciousParams,
  fields: string[]
): Promise<{ content: Array<{ type: 'text'; text: string }> }> {
  const suspiciousPorts = LATERAL_MOVEMENT_PORTS;

  const expression = params.expression
    ? `(${params.expression}) AND (port.dst IN [${suspiciousPorts.join(',')}])`
    : `port.dst IN [${suspiciousPorts.join(',')}]`;

  const response = await client.searchSessions({
    expression,
    length: 2000,
    fields,
  });

  const movementStats = new Map<string, { targets: Set<string>; ports: Set<number>; sessions: number }>();

  for (const session of response.data) {
    const srcIp = session.source?.ip;
    const dstIp = session.destination?.ip;
    if (!srcIp || !dstIp) continue;

    const isInternalSrc = isPrivateIp(srcIp);
    const isInternalDst = isPrivateIp(dstIp);

    if (isInternalSrc && isInternalDst) {
      if (!movementStats.has(srcIp)) {
        movementStats.set(srcIp, { targets: new Set(), ports: new Set(), sessions: 0 });
      }
      const stats = movementStats.get(srcIp)!;
      stats.sessions++;
      stats.targets.add(dstIp);
      if (session.destination?.port) stats.ports.add(session.destination.port);
    }
  }

  const potentialMovement = Array.from(movementStats.entries())
    .filter(([_, stats]) => stats.targets.size >= Math.min(params.threshold / 10, 5))
    .sort((a, b) => b[1].targets.size - a[1].targets.size);

  if (potentialMovement.length === 0) {
    return {
      content: [{
        type: 'text',
        text: `No lateral movement patterns detected.`,
      }],
    };
  }

  const lines = [
    `Potential Lateral Movement Detected`,
    '='.repeat(70),
    '',
    '| Source IP | Targets | Ports Used | Sessions |',
    '|-----------|---------|------------|----------|',
  ];

  for (const [ip, stats] of potentialMovement.slice(0, 20)) {
    const ports = Array.from(stats.ports).join(',');
    lines.push(`| ${ip.padEnd(15)} | ${String(stats.targets.size).padStart(7)} | ${ports.padEnd(10)} | ${String(stats.sessions).padStart(8)} |`);
  }

  return { content: [{ type: 'text', text: lines.join('\n') }] };
}
