import type { ArkimeClient } from '@/services/arkime-client.js';
import { formatJson } from '@/utils/formatters.js';
import type {
  GetSessionPacketsParams,
  GetSessionPcapParams,
  GetSessionRawParams,
  GetSessionBodyParams,
} from '@/tools/schemas.js';
import type { SessionPacketsResponse } from '@/types/arkime.js';

// --- session-packets ---

export async function sessionPackets(
  client: ArkimeClient,
  params: GetSessionPacketsParams
): Promise<{ content: Array<{ type: 'text'; text: string }> }> {
  const response: SessionPacketsResponse = await client.getSessionPackets(params.nodeId, params.sessionId);

  const lines = [
    `Decoded Packets (${params.sessionId} on ${params.nodeId})`,
    '='.repeat(60),
    '',
  ];

  if (Array.isArray(response.packets) && response.packets.length > 0) {
    lines.push(`Packets: ${response.packets.length}`);
    lines.push('');
    lines.push(formatJson(response.packets));
  } else if (Array.isArray(response.packets)) {
    lines.push('No decoded packets returned.');
  } else {
    lines.push(formatJson(response));
  }

  return { content: [{ type: 'text', text: lines.join('\n') }] };
}

// --- session-pcap ---

export async function sessionPcap(
  client: ArkimeClient,
  params: GetSessionPcapParams
): Promise<{ content: Array<{ type: 'text'; text: string } | { type: 'resource'; resource: { uri: string; mimeType: string } }> }> {
  const data = await client.getSessionEntirePcap(params.nodeId, params.sessionId);
  const dataUri = `data:application/octet-stream;base64,${data.toString('base64')}`;

  return {
    content: [
      {
        type: 'text',
        text: `Entire session PCAP extracted (${(data.length / 1024).toFixed(1)} KB) for ${params.sessionId} on ${params.nodeId}. Data included as resource; open in Wireshark.`,
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

// --- session-raw ---

export async function sessionRaw(
  client: ArkimeClient,
  params: GetSessionRawParams
): Promise<{ content: Array<{ type: 'text'; text: string } | { type: 'resource'; resource: { uri: string; mimeType: string } }> }> {
  const data = await client.getSessionRaw(params.nodeId, params.sessionId);
  const dataUri = `data:application/octet-stream;base64,${data.toString('base64')}`;

  return {
    content: [
      {
        type: 'text',
        text: `Raw session payload extracted (${(data.length / 1024).toFixed(1)} KB) for ${params.sessionId} on ${params.nodeId}.`,
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

// --- session-body ---

export async function sessionBody(
  client: ArkimeClient,
  params: GetSessionBodyParams
): Promise<{ content: Array<{ type: 'text'; text: string } | { type: 'resource'; resource: { uri: string; mimeType: string } }> }> {
  const data = await client.getSessionBody(
    params.nodeId,
    params.sessionId,
    params.bodyType,
    params.bodyNum,
    params.bodyName
  );
  const dataUri = `data:application/octet-stream;base64,${data.toString('base64')}`;

  return {
    content: [
      {
        type: 'text',
        text: `Session body '${params.bodyName}' extracted (${(data.length / 1024).toFixed(1)} KB) from ${params.sessionId} on ${params.nodeId}.`,
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
