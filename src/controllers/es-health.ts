import type { ArkimeClient } from '@/services/arkime-client.js';
import { formatJson } from '@/utils/formatters.js';
import type {
  EsHealthParams,
  EsStatsParams,
  EsIndicesParams,
  EsShardsParams,
  EsTasksParams,
  EsRecoveryParams,
  NodeDstatsParams,
  AppVersionParams,
} from '@/tools/schemas.js';
import type { ArkimeListResponse, EsHealthResponse, AppVersionResponse } from '@/types/arkime.js';

// Renders a {data: [...], recordsTotal} list response, falling back to dumping
// the whole object for endpoints (e.g. esShards) that key data differently.
function renderList(title: string, response: ArkimeListResponse, emptyMsg: string): string {
  const items = Array.isArray(response.data) ? response.data : [];
  if (items.length === 0) {
    const keys = Object.keys(response).filter((k) => k !== 'success' && k !== 'recordsTotal' && k !== 'recordsFiltered');
    if (keys.length === 0) return `${title}\n${'='.repeat(60)}\n\n${emptyMsg}`;
    return `${title}\n${'='.repeat(60)}\n\n${formatJson(response)}`;
  }
  return `${title}\n${'='.repeat(60)}\n\nTotal: ${items.length}\n\n${formatJson(items)}`;
}

// --- es-health ---

export async function esHealth(
  client: ArkimeClient,
  _params: EsHealthParams
): Promise<{ content: Array<{ type: 'text'; text: string }> }> {
  const response: EsHealthResponse = await client.getEsHealth();

  const lines = ['Elasticsearch/OpenSearch Health', '='.repeat(60), ''];

  if (response.status !== undefined) lines.push(`Status: ${response.status}`);
  if (response.number_of_nodes !== undefined) lines.push(`Nodes: ${response.number_of_nodes}`);
  if (response.number_of_data_nodes !== undefined) lines.push(`Data Nodes: ${response.number_of_data_nodes}`);
  if (response.active_primary_shards !== undefined) lines.push(`Active Primary Shards: ${response.active_primary_shards}`);
  if (response.active_shards !== undefined) lines.push(`Active Shards: ${response.active_shards}`);
  if (response.relocating_shards !== undefined) lines.push(`Relocating: ${response.relocating_shards}`);
  if (response.initializing_shards !== undefined) lines.push(`Initializing: ${response.initializing_shards}`);
  if (response.unassigned_shards !== undefined) lines.push(`Unassigned: ${response.unassigned_shards}`);

  lines.push('');
  lines.push(formatJson(response));

  return { content: [{ type: 'text', text: lines.join('\n') }] };
}

// --- es-stats ---

export async function esStats(
  client: ArkimeClient,
  _params: EsStatsParams
): Promise<{ content: Array<{ type: 'text'; text: string }> }> {
  const response = await client.getEsStats();
  return { content: [{ type: 'text', text: renderList('Elasticsearch Node Stats', response, 'No ES stats available.') }] };
}

// --- es-indices ---

export async function esIndices(
  client: ArkimeClient,
  _params: EsIndicesParams
): Promise<{ content: Array<{ type: 'text'; text: string }> }> {
  const response = await client.getEsIndices();
  return { content: [{ type: 'text', text: renderList('Elasticsearch Indices', response, 'No indices found.') }] };
}

// --- es-shards ---

export async function esShards(
  client: ArkimeClient,
  _params: EsShardsParams
): Promise<{ content: Array<{ type: 'text'; text: string }> }> {
  const response = await client.getEsShards();
  return { content: [{ type: 'text', text: renderList('Elasticsearch Shards', response, 'No shard data available.') }] };
}

// --- es-tasks ---

export async function esTasks(
  client: ArkimeClient,
  _params: EsTasksParams
): Promise<{ content: Array<{ type: 'text'; text: string }> }> {
  const response = await client.getEsTasks();
  return { content: [{ type: 'text', text: renderList('Elasticsearch Tasks', response, 'No running tasks.') }] };
}

// --- es-recovery ---

export async function esRecovery(
  client: ArkimeClient,
  _params: EsRecoveryParams
): Promise<{ content: Array<{ type: 'text'; text: string }> }> {
  const response = await client.getEsRecovery();
  return { content: [{ type: 'text', text: renderList('Elasticsearch Shard Recovery', response, 'No recovery data.') }] };
}

// --- node-dstats ---

export async function nodeDstats(
  client: ArkimeClient,
  params: NodeDstatsParams
): Promise<{ content: Array<{ type: 'text'; text: string }> }> {
  const response = await client.getDstats({
    nodeName: params.nodeName,
    name: params.name,
    start: params.start,
    stop: params.stop,
    interval: params.interval,
  });

  const lines = [`Node Time-Series Stats (${params.nodeName})`, '='.repeat(60), ''];

  if (Array.isArray(response) && response.length === 0) {
    lines.push('No time-series data returned.');
  } else {
    lines.push(formatJson(response));
  }

  return { content: [{ type: 'text', text: lines.join('\n') }] };
}

// --- app-version ---

export async function appVersion(
  client: ArkimeClient,
  _params: AppVersionParams
): Promise<{ content: Array<{ type: 'text'; text: string }> }> {
  const response: AppVersionResponse = await client.getAppVersion();

  const lines = ['Arkime Version', '='.repeat(60), ''];

  if (response.version !== undefined) lines.push(`Viewer Version: ${response.version}`);
  if (response.esVersion !== undefined) lines.push(`ES Version: ${response.esVersion}`);

  lines.push('');
  lines.push(formatJson(response));

  return { content: [{ type: 'text', text: lines.join('\n') }] };
}
