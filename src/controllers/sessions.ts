import type { ArkimeClient } from '@/services/arkime-client.js';
import { formatTable, formatSession, isoToTimestamp } from '@/utils/formatters.js';
import type { SearchSessionsParams, GetSessionParams, GetSessionSpiParams } from '@/tools/schemas.js';

export async function searchSessions(client: ArkimeClient, params: SearchSessionsParams) {
  const response = await client.searchSessions({
    expression: params.expression,
    startTime: params.startTime ? isoToTimestamp(params.startTime) : undefined,
    endTime: params.endTime ? isoToTimestamp(params.endTime) : undefined,
    length: params.limit,
    fields: params.fields,
  });

  if (response.data.length === 0) {
    return {
      content: [
        {
          type: 'text' as const,
          text: 'No sessions found matching the search criteria.',
        },
      ],
    };
  }

  const displayFields = params.fields && params.fields.length > 0
    ? params.fields
    : ['id', 'source.ip', 'source.port', 'destination.ip', 'destination.port', 'ipProtocol'];

  const table = formatTable(response.data, displayFields);

  return {
    content: [
      {
        type: 'text' as const,
        text: `Found ${response.data.length} sessions (showing ${response.recordsFiltered} of ${response.recordsTotal} total):\n\n${table}`,
      },
    ],
  };
}

export async function getSession(client: ArkimeClient, params: GetSessionParams) {
  // Strip node@ prefix if present (e.g., "3@260127-GwFt1w7eKJREbKdq8VYTsuEk" -> "260127-GwFt1w7eKJREbKdq8VYTsuEk")
  const parts = params.id.split('@');
  const sessionId = parts.length >= 2 ? parts.slice(1).join('@') : params.id;
  const session = await client.getSession(sessionId);

  return {
    content: [
      {
        type: 'text' as const,
        text: formatSession(session),
      },
    ],
  };
}

const SPI_FIELD_MAP: Record<string, string[]> = {
  dns: ['dns.host', 'dns.ip', 'dns.ans', 'dns.ns', 'dns.mx', 'dns.cname', 'dns.rr'],
  http: ['http.uri', 'http.host', 'http.method', 'http.referer', 'http.useragent', 'http.statuscode', 'http.md5'],
  tls: ['tls.sni', 'tls.cn', 'tls.issuer', 'tls.serial', 'tls.version', 'tls.cipher'],
  email: ['email.subject', 'email.src', 'email.dst', 'email.filename', 'email.bodypost'],
  file: ['file.name', 'file.magic', 'file.md5', 'file.sha256', 'file.size'],
  socks: ['socks.ip', 'socks.host', 'socks.port'],
  ssh: ['ssh.key', 'ssh.version', 'ssh.hassh'],
};

export async function getSessionSpi(client: ArkimeClient, params: GetSessionSpiParams) {
    const categories = params.categories?.includes('all') 
      ? Object.keys(SPI_FIELD_MAP) 
      : (params.categories || ['all']);
    
    const fields = ['id', 'source.ip', 'destination.ip', 'destination.port', ...categories.flatMap(c => SPI_FIELD_MAP[c] || [])];
    
    const response = await client.searchSessions({
      expression: params.expression,
      length: params.limit || 10,
      fields,
    });

    if (response.data.length === 0) {
      return {
        content: [
          {
            type: 'text' as const,
            text: `No sessions found matching: ${params.expression}`,
          },
        ],
      };
    }

    const lines: string[] = [`Session SPI Data (${response.data.length} sessions)`, '='.repeat(50), ''];

    for (const session of response.data) {
      lines.push(`--- Session: ${session.id} ---`);
      lines.push(`Source: ${session.source?.ip || '-'} -> Dest: ${session.destination?.ip || '-'}:${session.destination?.port || '-'}`);
      lines.push('');

      for (const [category, categoryFields] of Object.entries(SPI_FIELD_MAP)) {
        if (!categories.includes(category) && !categories.includes('all')) continue;
        
        const data: Record<string, unknown> = {};
        for (const field of categoryFields) {
          const parts = field.split('.');
          let value: unknown = session;
          for (const part of parts) {
            value = (value as Record<string, unknown>)?.[part];
          }
          if (value !== undefined && value !== null && 
              !(Array.isArray(value) && value.length === 0) &&
              !(typeof value === 'object' && Object.keys(value as object).length === 0)) {
            data[field] = value;
          }
        }
        
        if (Object.keys(data).length > 0) {
          lines.push(`[${category.toUpperCase()}]`);
          for (const [field, value] of Object.entries(data)) {
            const displayValue = Array.isArray(value) ? value.join(', ') : String(value);
            if (displayValue.length > 200) {
              lines.push(`  ${field}: ${displayValue.substring(0, 200)}...`);
            } else {
              lines.push(`  ${field}: ${displayValue}`);
            }
          }
          lines.push('');
        }
      }
    }

    return {
      content: [
        {
          type: 'text' as const,
          text: lines.join('\n'),
        },
      ],
    };
}
