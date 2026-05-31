import type { ArkimeClient } from '@/services/arkime-client.js';
import { formatBytes, formatNum, unixToISO } from '@/utils/formatters.js';
import type {
  AppInfoParams,
  ConnectionsParams,
  HuntListParams,
  MultiUniqueParams,
  NodeStatsParams,
  SessionDetailParams,
  SessionFileParams,
  SessionsSummaryParams,
  ShortcutListParams,
  SpiSessionsParams,
  ViewListParams,
} from '@/tools/schemas.js';
import type {
  SessionsSummaryResponse,
  MultiUniqueResponse,
  ConnectionsResponse,
  SpiViewResponse,
  SessionDetailResponse,
  HuntsResponse,
  ViewsResponse,
  ShortcutsResponse,
  AppInfoResponse,
  StatsResponse,
  SummaryBucket,
  ConnectionNode,
  ConnectionLink,
  FieldValue,
  Hunt,
  View,
  Shortcut,
  NodeStat,
} from '@/types/arkime.js';

// --- sessions-summary ---

export async function sessionsSummary(
  client: ArkimeClient,
  params: SessionsSummaryParams
): Promise<{ content: Array<{ type: 'text'; text: string }> }> {
  const response = await client.getSessionsSummary({
    expression: params.expression,
    date: params.dateRange,
    field: params.field,
    buckets: params.buckets,
  });

  const lines = ['Sessions Summary', '='.repeat(60), ''];

  if (response.sessions) lines.push(`Sessions: ${formatNum(response.sessions)}`);
  if (response.connections) lines.push(`Connections: ${formatNum(response.connections)}`);
  if (response.packets) lines.push(`Packets: ${formatNum(response.packets)}`);
  if (response.dataBytes) lines.push(`Data Bytes: ${formatBytes(response.dataBytes)}`);
  if (response.totDataBytes) lines.push(`Total Bytes: ${formatBytes(response.totDataBytes)}`);

  if (response.histograms) {
    for (const [histName, buckets] of Object.entries(response.histograms)) {
      lines.push('');
      lines.push(`${histName} histogram:`);
      lines.push('-'.repeat(40));
      for (const b of buckets) {
        const bar = '#'.repeat(Math.min(40, Math.max(1, Math.floor((b.count / (buckets[0]?.count || 1)) * 40))));
        lines.push(`  ${b.key.padEnd(12)} | ${String(b.count).padStart(8)} | ${bar}`);
        if (b.sum !== undefined) lines.push(`                     (sum: ${formatNum(b.sum)})`);
      }
    }
  }

  return { content: [{ type: 'text', text: lines.join('\n') }] };
}

// --- multi-unique ---

export async function multiUnique(
  client: ArkimeClient,
  params: MultiUniqueParams
): Promise<{ content: Array<{ type: 'text'; text: string }> }> {
  const response = await client.getMultiUnique(params.fields, {
    expression: params.expression,
    date: params.dateRange,
    limit: params.limit,
  });

  const lines = [`Multi-Unique Values (${params.fields.length} fields)`, '='.repeat(60), ''];

  for (const field of params.fields) {
    const values = response[field];
    if (!Array.isArray(values)) {
      lines.push(`${field}: (no data)`);
      lines.push('');
      continue;
    }

    const valueArr = values as Array<{ value: string; count: number }>;
    lines.push(`${field} (${valueArr.length} unique values)`);
    lines.push('-'.repeat(50));

    for (const v of valueArr.slice(0, 100)) {
      lines.push(`  ${String(v.count).padStart(8)}  ${v.value}`);
    }

    if (valueArr.length > 100) {
      lines.push(`  ... and ${valueArr.length - 100} more`);
    }
    lines.push('');
  }

  return { content: [{ type: 'text', text: lines.join('\n') }] };
}

// --- connections ---

export async function connections(
  client: ArkimeClient,
  params: ConnectionsParams
): Promise<{ content: Array<{ type: 'text'; text: string }> }> {
  const response = await client.getConnections({
    expression: params.expression,
    date: params.dateRange,
    limit: params.limit,
  });

  const lines = [
    'Network Connections',
    '='.repeat(60),
    `Nodes: ${response.nodes.length}  |  Links: ${response.links.length}`,
    '',
  ];

  // Top nodes by sessions
  const topNodes = [...response.nodes]
    .sort((a, b) => b.sessions - a.sessions)
    .slice(0, 20);

  if (topNodes.length > 0) {
    lines.push('Top Nodes by Sessions');
    lines.push('-'.repeat(60));
    for (const node of topNodes) {
      lines.push(`  ${node.label.padEnd(20)} | Sessions: ${String(node.sessions).padStart(6)} | Bytes: ${formatBytes(node.bytes)}`);
    }
    lines.push('');
  }

  // Top links by sessions
  const topLinks = [...response.links]
    .sort((a, b) => b.sessions - a.sessions)
    .slice(0, 20);

  if (topLinks.length > 0) {
    lines.push('Top Links by Sessions');
    lines.push('-'.repeat(60));
    for (const link of topLinks) {
      lines.push(`  ${link.source} -> ${link.target.padEnd(15)} | Sessions: ${String(link.sessions).padStart(6)} | Bytes: ${formatBytes(link.bytes)}`);
    }
    lines.push('');
  }

  return { content: [{ type: 'text', text: lines.join('\n') }] };
}

// --- spi-sessions ---

export async function spiSessions(
  client: ArkimeClient,
  params: SpiSessionsParams
): Promise<{ content: Array<{ type: 'text'; text: string }> }> {
  const response = await client.getSpiview({
    expression: params.expression,
    fields: params.fields,
    limit: params.limit,
  });

  if (response.items.length === 0) {
    return { content: [{ type: 'text', text: 'No SPI data found.' }] };
  }

  const lines = [
    'Session Protocol Information',
    `Total: ${response.recordsTotal}  |  Filtered: ${response.recordsFiltered}`,
    `Items: ${response.items.length}`,
    '='.repeat(60),
    '',
  ];

  // Group by field
  const grouped: Record<string, FieldValue[]> = {};
  for (const item of response.items) {
    if (!grouped[item.field]) grouped[item.field] = [];
    grouped[item.field].push(item);
  }

  for (const [field, items] of Object.entries(grouped)) {
    lines.push(`${field} (${items.length} values)`);
    lines.push('-'.repeat(40));
    for (const item of items.slice(0, 50)) {
      const countStr = item.count !== undefined ? ` (${item.count})` : '';
      lines.push(`  ${item.value}${countStr}`);
    }
    if (items.length > 50) {
      lines.push(`  ... and ${items.length - 50} more`);
    }
    lines.push('');
  }

  return { content: [{ type: 'text', text: lines.join('\n') }] };
}

// --- session-detail ---

export async function sessionDetail(
  client: ArkimeClient,
  params: SessionDetailParams
): Promise<{ content: Array<{ type: 'text'; text: string }> }> {
  const response = await client.getSessionDetail(params.nodeId, params.sessionId);

  const lines = [
    `Session Detail (${params.sessionId} on ${params.nodeId})`,
    '='.repeat(60),
    '',
  ];

  const data = response.data;
  const keys = Object.keys(data).sort();

  for (const key of keys) {
    const val = data[key];
    if (typeof val === 'object' && val !== null) {
      lines.push(`${key}:`);
      for (const [k, v] of Object.entries(val)) {
        lines.push(`  ${k}: ${JSON.stringify(v)}`);
      }
    } else {
      lines.push(`${key}: ${JSON.stringify(val)}`);
    }
  }

  return { content: [{ type: 'text', text: lines.join('\n') }] };
}

// --- hunt-list ---

export async function huntList(
  client: ArkimeClient,
  params: HuntListParams
): Promise<{ content: Array<{ type: 'text'; text: string }> }> {
  const response = await client.getHunts();

  if (response.hunts.length === 0) {
    return { content: [{ type: 'text', text: 'No active hunts found.' }] };
  }

  const lines = [
    'Active Packet Hunts',
    '='.repeat(70),
    '',
  ];

  for (const hunt of response.hunts) {
    const created = hunt.createdAt ? unixToISO(hunt.createdAt) : 'unknown';
    lines.push(`${hunt.name}`);
    lines.push(`  ID: ${hunt.id}`);
    lines.push(`  Status: ${hunt.status}`);
    lines.push(`  Expression: ${hunt.expression}`);
    lines.push(`  Creator: ${hunt.creator}`);
    lines.push(`  Matches: ${formatNum(hunt.matches)}`);
    lines.push(`  Created: ${created}`);
    lines.push('');
  }

  lines.push(`Total: ${response.hunts.length} hunts`);

  return { content: [{ type: 'text', text: lines.join('\n') }] };
}

// --- view-list ---

export async function viewList(
  client: ArkimeClient,
  params: ViewListParams
): Promise<{ content: Array<{ type: 'text'; text: string }> }> {
  const response = await client.getViews();

  if (response.views.length === 0) {
    return { content: [{ type: 'text', text: 'No saved views found.' }] };
  }

  const lines = [
    'Saved Views',
    '='.repeat(70),
    '',
  ];

  for (const view of response.views) {
    lines.push(`${view.name}`);
    lines.push(`  ID: ${view.id}`);
    lines.push(`  Expression: ${view.expression}`);
    lines.push(`  Creator: ${view.creator}`);
    if (view.shared !== undefined) lines.push(`  Shared: ${view.shared}`);
    lines.push('');
  }

  lines.push(`Total: ${response.views.length} views`);

  return { content: [{ type: 'text', text: lines.join('\n') }] };
}

// --- shortcut-list ---

export async function shortcutList(
  client: ArkimeClient,
  params: ShortcutListParams
): Promise<{ content: Array<{ type: 'text'; text: string }> }> {
  const response = await client.getShortcuts();

  if (response.shortcuts.length === 0) {
    return { content: [{ type: 'text', text: 'No saved shortcuts found.' }] };
  }

  const lines = [
    'Saved Shortcuts',
    '='.repeat(70),
    '',
  ];

  for (const shortcut of response.shortcuts) {
    lines.push(`${shortcut.key}: ${shortcut.expression}`);
  }
  lines.push('');
  lines.push(`Total: ${response.shortcuts.length} shortcuts`);

  return { content: [{ type: 'text', text: lines.join('\n') }] };
}

// --- app-info ---

export async function appInfo(
  client: ArkimeClient,
  params: AppInfoParams
): Promise<{ content: Array<{ type: 'text'; text: string }> }> {
  const response = await client.getAppInfo();

  const lines = [
    'Arkime App Info',
    '='.repeat(60),
    '',
  ];

  if (response.currentuser) {
    lines.push('Current User:');
    for (const [k, v] of Object.entries(response.currentuser)) {
      lines.push(`  ${k}: ${JSON.stringify(v)}`);
    }
    lines.push('');
  }

  if (response.eshealth) {
    lines.push(`ES Health: ${response.eshealth}`);
    lines.push('');
  }

  if (response.viewCount !== undefined) {
    lines.push(`Views Total: ${response.viewCount}`);
  }

  if (response.clusters) {
    lines.push(`Viewer Nodes: ${response.clusters.viewerNodes.length}`);
    lines.push(`Capture Nodes: ${response.clusters.captureNodes.length}`);
    lines.push('');
  }

  return { content: [{ type: 'text', text: lines.join('\n') }] };
}

// --- node-stats ---

export async function nodeStats(
  client: ArkimeClient,
  params: NodeStatsParams
): Promise<{ content: Array<{ type: 'text'; text: string }> }> {
  const response = await client.getStats();

  const statsEntries = Object.entries(response.stats);

  if (statsEntries.length === 0) {
    return { content: [{ type: 'text', text: 'No stats available.' }] };
  }

  const lines = [
    'Node Statistics',
    '='.repeat(70),
    '',
  ];

  for (const [nodeId, stat] of statsEntries) {
    lines.push(`${stat.host || nodeId} [${(stat.roles as string[])?.join(', ') || '?'}]`);
    lines.push(`  Packets: ${formatNum(stat.packets as number)}`);
    lines.push(`  Bytes: ${formatBytes(stat.bytes as number)}`);
    lines.push(`  Sessions: ${formatNum(stat.sessions as number)}`);
    lines.push('');
  }

  return { content: [{ type: 'text', text: lines.join('\n') }] };
}

// --- session-file ---

export async function sessionFile(
  client: ArkimeClient,
  params: SessionFileParams
): Promise<{ content: Array<{ type: 'text'; text: string } | { type: 'resource'; resource: { uri: string; mimeType: string } }> }> {
  const data = await client.getSessionBodyHash(params.nodeId, params.sessionId, params.hash);
  const dataUri = `data:application/octet-stream;base64,${data.toString('base64')}`;

  return {
    content: [
      {
        type: 'text',
        text: `Session file extracted (${(data.length / 1024).toFixed(1)} KB, hash: ${params.hash})\n\nData included as resource. Save and inspect the file content.`,
      },
      {
        type: 'resource',
        resource: {
          uri: dataUri,
          mimeType: 'application/octet-stream',
        },
      },
    ],
  };
}
