import type { ArkimeClient } from '@/services/arkime-client.js';
import type { UniqueValue, ClusterNode } from '@/types/arkime.js';
import { formatBytes, formatUniqueTable, unixToISO } from '@/utils/formatters.js';
import type { TopTalkersParams, ReverseDnsParams, DnsLookupsParams, GeoSummaryParams, PcapFilesParams, CaptureStatusParams } from '@/tools/schemas.js';

export async function topTalkers(
  client: ArkimeClient,
  params: TopTalkersParams
): Promise<{ content: Array<{ type: 'text'; text: string }> }> {
  const limit = params.limit ?? 100;
  const response = await client.getUniqueField(params.field, {
    expression: params.expression,
    date: params.dateRange,
    limit,
    counts: true,
  });

  if (response.value.length === 0) {
    return {
      content: [{ type: 'text', text: `No values found for field '${params.field}'.` }],
    };
  }

  const lines = [
    `Top values for '${params.field}' (${response.totalInPeriod} in period, ${response.totalOverall} overall)`,
    '',
  ];

  const table = formatUniqueTable(response.value);
  lines.push(table);

  return {
    content: [{ type: 'text', text: lines.join('\n') }],
  };
}

export async function reverseDns(
  client: ArkimeClient,
  params: ReverseDnsParams
): Promise<{ content: Array<{ type: 'text'; text: string }> }> {
  const response = await client.getUniqueField('reverseDNS', {
    expression: `ip.src == ${params.ipAddress}`,
    date: params.dateRange,
    limit: 100,
    counts: true,
  });

  if (response.value.length === 0) {
    return {
      content: [{ type: 'text', text: `No reverse DNS records found for ${params.ipAddress}.` }],
    };
  }

  const lines = [
    `Reverse DNS for ${params.ipAddress}`,
    '',
    formatUniqueTable(response.value),
  ];

  return {
    content: [{ type: 'text', text: lines.join('\n') }],
  };
}

export async function dnsLookups(
  client: ArkimeClient,
  params: DnsLookupsParams
): Promise<{ content: Array<{ type: 'text'; text: string }> }> {
  const expressions: string[] = ['port.dst == 53'];
  if (params.domainPattern) {
    expressions.push(`dns.host contains "${params.domainPattern}"`);
  }
  if (params.sourceIp) {
    expressions.push(`ip.src == ${params.sourceIp}`);
  }

  const fields = [
    'id', 'firstPacket', 'source.ip', 'destination.ip',
    'dns.host', 'dns.question', 'dns.questionType', 'dns.ans', 'dns.type',
  ];

  const response = await client.searchSessions({
    expression: expressions.join(' AND '),
    length: params.limit ?? 200,
    fields,
  });

  if (response.data.length === 0) {
    return {
      content: [{ type: 'text', text: 'No DNS queries found.' }],
    };
  }

  const lines = ['DNS Query Analysis', '='.repeat(70), ''];

  for (const session of response.data) {
    const dns = session.dns as Record<string, unknown> | undefined;
    const time = session.firstPacket
      ? unixToISO(session.firstPacket)
      : 'unknown';
    lines.push(`${time} ${session.source?.ip || '?'} -> ${session.destination?.ip || '?'}`);
    lines.push(`  Query: ${dns?.question || dns?.host || 'N/A'} (Type: ${dns?.questionType || 'N/A'})`);
    if (dns?.ans) {
      lines.push(`  Answer: ${dns.ans}`);
    }
    lines.push('');
  }

  lines.push(`Total: ${response.data.length} DNS queries`);

  return {
    content: [{ type: 'text', text: lines.join('\n') }],
  };
}

export async function geoSummary(
  client: ArkimeClient,
  params: GeoSummaryParams
): Promise<{ content: Array<{ type: 'text'; text: string }> }> {
  const response = await client.getUniqueField('geo.country', {
    expression: params.expression,
    date: params.dateRange,
    limit: params.limit ?? 50,
    counts: true,
  });

  if (response.value.length === 0) {
    return {
      content: [{ type: 'text', text: 'No geo data found.' }],
    };
  }

  const total = response.value.reduce((sum: number, v: UniqueValue) => sum + v.count, 0);
  const lines = [
    'Destination Traffic by Country',
    '='.repeat(50),
    '',
    '     | Count      | Country',
    '-'.repeat(50),
  ];

  for (const [i, v] of response.value.entries()) {
    const pct = total > 0 ? ((v.count / total) * 100).toFixed(1) : '0.0';
    lines.push(`${String(i + 1).padStart(4)} | ${String(v.count).padStart(10)} (${pct}%) | ${v.value}`);
  }

  lines.push('');
  lines.push(`Total sessions with geo data: ${total}`);

  return {
    content: [{ type: 'text', text: lines.join('\n') }],
  };
}

export async function captureStatus(
  client: ArkimeClient,
  _params: CaptureStatusParams
): Promise<{ content: Array<{ type: 'text'; text: string }> }> {
  const response = await client.getClusters();

  const lines = [
    'Arkime Cluster Status',
    '='.repeat(60),
    '',
  ];

  const now = Date.now() / 1000;

  lines.push(`Viewer Nodes: ${response.viewerNodes.length}`);
  for (const node of response.viewerNodes) {
    lines.push(formatClusterNode(node, now));
  }

  lines.push('');
  lines.push(`Capture Nodes: ${response.captureNodes.length}`);
  for (const node of response.captureNodes) {
    lines.push(formatClusterNode(node, now));
  }

  return {
    content: [{ type: 'text', text: lines.join('\n') }],
  };
}

function formatClusterNode(node: ClusterNode, now: number): string {
  const uptime = Math.floor(now - node.started);
  const hours = Math.floor(uptime / 3600);
  const days = Math.floor(hours / 24);
  const uptimeStr = days > 0 ? `${days}d ${hours % 24}h` : `${hours}h`;
  return `  ${node.host} v${node.version} [${node.roles.join(', ')}] uptime: ${uptimeStr}`;
}

export async function pcapFiles(
  client: ArkimeClient,
  params: PcapFilesParams
): Promise<{ content: Array<{ type: 'text'; text: string }> }> {
  const response = await client.getFiles({
    limit: params.limit ?? 100,
    sort: params.sort ?? 'dateFirst',
    order: 'desc',
  });

  if (response.files.length === 0) {
    return {
      content: [{ type: 'text', text: 'No PCAP files found.' }],
    };
  }

  const lines = [
    `PCAP Files (${response.total} total)`,
    '='.repeat(80),
    '',
  ];

  for (const f of response.files) {
    const size = formatBytes(f.totalLen);
    const first = unixToISO(f.dateFirst);
    lines.push(`${f.filename}`);
    lines.push(`  Node: ${f.node} | Sessions: ${f.sessions.toLocaleString()} | Size: ${size}`);
    lines.push(`  First: ${first}`);
    lines.push('');
  }

  return {
    content: [{ type: 'text', text: lines.join('\n') }],
  };
}
