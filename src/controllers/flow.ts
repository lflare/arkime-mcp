import type { ArkimeClient } from '@/services/arkime-client.js';
import { isoToTimestamp } from '@/utils/formatters.js';
import * as crypto from 'crypto';
import type { GetFlowParams } from '@/tools/schemas.js';

export async function getFlow(
  client: ArkimeClient,
  params: GetFlowParams
): Promise<{ content: Array<{ type: 'text'; text: string } | { type: 'resource'; resource: { uri: string; mimeType: string } }> }> {
  const maxBytes = params.maxBytes || 10000000; // 10MB default

  // Build expression for the flow
  // Arkime uses && for AND, and ip.src/ip.dst for addresses
  const conditions: string[] = [];

  // Source IP
  conditions.push(`ip.src == ${params.sourceIp}`);

  // Destination IP
  conditions.push(`ip.dst == ${params.destIp}`);

  // Source port (if specified)
  if (params.sourcePort !== undefined) {
    conditions.push(`port.src == ${params.sourcePort}`);
  }

  // Destination port (if specified)
  if (params.destPort !== undefined) {
    conditions.push(`port.dst == ${params.destPort}`);
  }

  // Protocol filter
  if (params.protocol === 'tcp') {
    conditions.push(`ip.protocol == 6`);
  } else if (params.protocol === 'udp') {
    conditions.push(`ip.protocol == 17`);
  }
  // 'any' or undefined means no protocol filter

  const expression = conditions.join(' && ');

  // Build time parameters
  const searchParams = new URLSearchParams();
  searchParams.set('expression', expression);

  if (params.startTime && params.endTime) {
    searchParams.set('startTime', String(isoToTimestamp(params.startTime)));
    searchParams.set('stopTime', String(isoToTimestamp(params.endTime)));
  } else if (params.startTime) {
    searchParams.set('startTime', String(isoToTimestamp(params.startTime)));
  } else if (params.endTime) {
    searchParams.set('stopTime', String(isoToTimestamp(params.endTime)));
  } else {
    searchParams.set('date', '-1'); // All time
  }

  const pcapUrl = `/api/sessions/pcap?${searchParams.toString()}`;
  const pcapBuffer = await client.getPcap(pcapUrl);

  if (pcapBuffer.length === 0) {
    return {
      content: [{
        type: 'text',
        text: `No flow data found for:\n` +
              `  Source: ${params.sourceIp}${params.sourcePort ? `:${params.sourcePort}` : ''}\n` +
              `  Dest: ${params.destIp}${params.destPort ? `:${params.destPort}` : ''}\n` +
              `  Protocol: ${params.protocol || 'any'}`,
      }],
    };
  }

  if (pcapBuffer.length > maxBytes) {
    return {
      content: [{
        type: 'text',
        text: `Flow too large: ${pcapBuffer.length} bytes exceeds limit of ${maxBytes} bytes.\n` +
              `Try narrowing the time range or adding port filters.`,
      }],
    };
  }

  const base64Pcap = pcapBuffer.toString('base64');
  const md5 = crypto.createHash('md5').update(pcapBuffer).digest('hex');

  // Create a data URI for the PCAP file
  const dataUri = `data:application/vnd.tcpdump.pcap;base64,${base64Pcap}`;

  return {
    content: [
      {
        type: 'text',
        text: `Flow extracted successfully:\n` +
              `  Source: ${params.sourceIp}${params.sourcePort ? `:${params.sourcePort}` : ''}\n` +
              `  Dest: ${params.destIp}${params.destPort ? `:${params.destPort}` : ''}\n` +
              `  Protocol: ${params.protocol || 'any'}\n` +
              `  Size: ${pcapBuffer.length} bytes\n` +
              `  MD5: ${md5}\n` +
              `\nPCAP data included as resource. Decode the base64 data and save as .pcap to open in Wireshark.`,
      },
      {
        type: 'resource',
        resource: {
          uri: dataUri,
          mimeType: 'application/vnd.tcpdump.pcap',
        },
      },
    ],
  };
}
