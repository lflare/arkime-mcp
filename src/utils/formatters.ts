import type { Session, FieldDefinition, UniqueValue } from '@/types/arkime.js';

export function escapeExpressionValue(value: string): string {
  return value.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

export function validateIPv4(value: string): boolean {
  const parts = value.split('.');
  if (parts.length !== 4) return false;
  return parts.every((part) => {
    const num = Number(part);
    return Number.isInteger(num) && num >= 0 && num <= 255 && part === String(num);
  });
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

export function formatNum(n: number): string {
  return n.toLocaleString();
}

export function isoToTimestamp(isoString: string): number {
  return Math.floor(new Date(isoString).getTime() / 1000);
}

export function unixToISO(ts: number): string {
  return new Date(ts * 1000).toISOString();
}

export function isPrivateIp(ip: string): boolean {
  if (ip.startsWith('10.')) return true;
  if (ip.startsWith('192.168.')) return true;
  if (ip.startsWith('127.')) return true;
  if (ip.startsWith('169.254.')) return true;
  if (ip.startsWith('172.')) {
    const second = Number(ip.split('.')[1]);
    return second >= 16 && second <= 31;
  }
  return false;
}

// Standard ports for common lateral movement / remote access protocols
export const LATERAL_MOVEMENT_PORTS = [22, 23, 135, 139, 445, 636, 3389, 5900, 5901, 5902, 4444, 6667] as const;

// Standard ports for authentication protocols
export const AUTH_PORTS = [88, 139, 389, 443, 445, 636, 3268, 3269] as const;

// Port-to-protocol mapping for lateral movement detection
export const PORT_PROTOCOL_MAP: Record<number, string> = {
  139: 'smb',
  445: 'smb',
  389: 'ldap',
  636: 'ldaps',
  3268: 'ldap',
  3269: 'ldaps',
  3389: 'rdp',
  5985: 'winrm',
  5986: 'winrms',
  22: 'ssh',
};

// Port-to-protocol lookup for lateral movement ports
export function getProtocolFromPort(port: number): string {
  return PORT_PROTOCOL_MAP[port] || `port-${port}`;
}

function getNestedValue(obj: unknown, path: string): string {
  const keys = path.split('.');
  let current: unknown = obj;

  for (const key of keys) {
    if (current === null || current === undefined) return '-';
    if (typeof current === 'object') {
      current = (current as Record<string, unknown>)[key];
    } else {
      return '-';
    }
  }

  if (current === null || current === undefined) return '-';
  if (typeof current === 'object') return JSON.stringify(current);
  return String(current);
}

export function formatTable(data: unknown[], columns: string[]): string {
  if (data.length === 0) return 'No data';

  const rows = data.map((item) => columns.map((col) => getNestedValue(item, col)));

  const widths = columns.map((col, i) => {
    const headerLen = col.length;
    const maxDataLen = Math.max(...rows.map((row) => row[i].length));
    return Math.max(headerLen, maxDataLen);
  });

  const header = columns.map((col, i) => col.padEnd(widths[i])).join(' | ');
  const separator = widths.map((w) => '-'.repeat(w)).join('-+-');

  const dataRows = rows.map((row) => row.map((cell, i) => cell.padEnd(widths[i])).join(' | '));

  return [header, separator, ...dataRows].join('\n');
}

export const PROTOCOL_MAP: Record<number, string> = {
  1: 'ICMP',
  6: 'TCP',
  17: 'UDP',
  47: 'GRE',
  50: 'ESP',
  51: 'AH',
  58: 'ICMPv6',
  89: 'OSPF',
  132: 'SCTP',
};

export function formatSession(session: Session): string {
  const lines: string[] = [];

  lines.push(`Session ID: ${session.id}`);
  lines.push('');

  if (session.source?.ip || session.source?.port) {
    lines.push(`Source: ${session.source.ip || '-'}:${session.source.port || '-'}`);
  }

  if (session.destination?.ip || session.destination?.port) {
    lines.push(`Destination: ${session.destination.ip || '-'}:${session.destination.port || '-'}`);
  }

  if (session.ipProtocol !== undefined) {
    const protoName = PROTOCOL_MAP[session.ipProtocol] || `Unknown(${session.ipProtocol})`;
    lines.push(`Protocol: ${protoName} (${session.ipProtocol})`);
  }

  if (session.source?.bytes !== undefined || session.destination?.bytes !== undefined) {
    const srcBytes = session.source?.bytes || 0;
    const dstBytes = session.destination?.bytes || 0;
    lines.push(`Bytes: ${srcBytes} ↑ / ${dstBytes} ↓`);
  }

  if (session.source?.packets !== undefined || session.destination?.packets !== undefined) {
    const srcPackets = session.source?.packets || 0;
    const dstPackets = session.destination?.packets || 0;
    lines.push(`Packets: ${srcPackets} ↑ / ${dstPackets} ↓`);
  }

  if (session.node) {
    lines.push(`Node: ${session.node}`);
  }

  if (session.tags && session.tags.length > 0) {
    lines.push(`Tags: ${session.tags.join(', ')}`);
  }

  return lines.join('\n');
}

export function formatFieldList(fields: FieldDefinition[]): string {
  if (fields.length === 0) return 'No fields available';

  const grouped: Record<string, FieldDefinition[]> = {};

  for (const field of fields) {
    if (!grouped[field.group]) {
      grouped[field.group] = [];
    }
    grouped[field.group].push(field);
  }

  const lines: string[] = [];

  for (const [group, groupFields] of Object.entries(grouped).sort()) {
    lines.push(`\n[${group}]`);

    for (const field of groupFields.sort((a, b) => a.dbName.localeCompare(b.dbName))) {
      const desc = field.description ? ` - ${field.description}` : '';
      lines.push(`  ${field.dbName} (${field.type}): ${field.friendlyName}${desc}`);
    }
  }

  return lines.join('\n');
}

export function formatUniqueTable(values: UniqueValue[]): string {
  const rows = values.map((v, i) => `${String(i + 1).padStart(4)} | ${String(v.count).padStart(10)} | ${v.value}`);
  return '     | Count      | Value\n' + '-'.repeat(50) + '\n' + rows.join('\n');
}

// Pretty-prints arbitrary API data, truncating to stay token-efficient.
// Used by thin-wrapper tools whose response shapes vary across Arkime versions.
export function formatJson(value: unknown, maxChars = 4000): string {
  let str: string;
  try {
    str = JSON.stringify(value, null, 2);
  } catch {
    str = String(value);
  }
  if (str === undefined) str = String(value);
  if (str.length > maxChars) {
    return `${str.slice(0, maxChars)}\n... (truncated, ${str.length} chars total)`;
  }
  return str;
}
