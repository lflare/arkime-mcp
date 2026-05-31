import type { ArkimeClient } from '@/services/arkime-client.js';
import { formatJson, formatNum } from '@/utils/formatters.js';
import type {
  SpiGraphParams,
  SpiGraphHierarchyParams,
  BuildQueryParams,
  ListDecodingsParams,
} from '@/tools/schemas.js';
import type {
  SpiGraphResponse,
  SpiGraphHierarchyResponse,
  BuildQueryResponse,
  DecodingsResponse,
} from '@/types/arkime.js';

// --- spi-graph ---

export async function spiGraph(
  client: ArkimeClient,
  params: SpiGraphParams
): Promise<{ content: Array<{ type: 'text'; text: string }> }> {
  const response: SpiGraphResponse = await client.getSpiGraph(params.field, {
    expression: params.expression,
    date: params.dateRange,
    size: params.size,
  });

  const items = response.items;
  if (!items || items.length === 0) {
    return {
      content: [{ type: 'text', text: `No SPI graph data found for '${params.field}'.` }],
    };
  }

  const lines = [`SPI Graph: ${params.field}`, '='.repeat(60)];

  if (response.recordsTotal !== undefined || response.recordsFiltered !== undefined) {
    lines.push(
      `Total: ${formatNum(response.recordsTotal ?? 0)}  |  Filtered: ${formatNum(response.recordsFiltered ?? 0)}`
    );
  }
  lines.push('');

  const sorted = [...items].sort((a, b) => b.count - a.count);
  for (const item of sorted) {
    lines.push(`  ${String(item.count).padStart(10)} | ${item.name}`);
  }

  return { content: [{ type: 'text', text: lines.join('\n') }] };
}

// --- spi-graph-hierarchy ---

export async function spiGraphHierarchy(
  client: ArkimeClient,
  params: SpiGraphHierarchyParams
): Promise<{ content: Array<{ type: 'text'; text: string }> }> {
  const response: SpiGraphHierarchyResponse = await client.getSpiGraphHierarchy(
    params.fields.join(','),
    {
      expression: params.expression,
      date: params.dateRange,
    }
  );

  const lines = [`SPI Graph Hierarchy: ${params.fields.join(' > ')}`, '='.repeat(60), ''];

  if (Array.isArray(response.tableResults) && response.tableResults.length > 0) {
    lines.push(`Table rows: ${response.tableResults.length}`);
    lines.push('');
    lines.push(formatJson(response.tableResults));
  } else if (response.hierarchicalResults !== undefined) {
    lines.push(formatJson(response.hierarchicalResults));
  } else {
    return { content: [{ type: 'text', text: 'No hierarchy data found.' }] };
  }

  return { content: [{ type: 'text', text: lines.join('\n') }] };
}

// --- build-query ---

export async function buildQuery(
  client: ArkimeClient,
  params: BuildQueryParams
): Promise<{ content: Array<{ type: 'text'; text: string }> }> {
  const response: BuildQueryResponse = await client.getBuildQuery({
    expression: params.expression,
    date: params.dateRange,
  });

  const lines = [`Compiled query for: ${params.expression}`, '='.repeat(60), ''];

  if (response.indices !== undefined) {
    lines.push(`Indices: ${JSON.stringify(response.indices)}`);
    lines.push('');
  }

  lines.push(formatJson(response.esquery ?? response));

  return { content: [{ type: 'text', text: lines.join('\n') }] };
}

// --- list-decodings ---

export async function listDecodings(
  client: ArkimeClient,
  _params: ListDecodingsParams
): Promise<{ content: Array<{ type: 'text'; text: string }> }> {
  const response: DecodingsResponse = await client.getDecodings();

  const keys = Object.keys(response);
  if (keys.length === 0) {
    return { content: [{ type: 'text', text: 'No decodings available.' }] };
  }

  const lines = ['Available Packet Decodings', '='.repeat(60), ''];

  for (const key of keys) {
    const obj = response[key];
    const label = (obj?.title as string | undefined) ?? (obj?.name as string | undefined) ?? '';
    lines.push(`  ${key}: ${label}`);
  }

  return { content: [{ type: 'text', text: lines.join('\n') }] };
}
