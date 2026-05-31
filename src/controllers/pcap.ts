import type { ArkimeClient } from '@/services/arkime-client.js';
import type { GetPcapParams } from '@/tools/schemas.js';
import { isoToTimestamp } from '@/utils/formatters.js';
import * as crypto from 'crypto';

export async function getPcap(
  client: ArkimeClient,
  params: GetPcapParams
): Promise<{ content: Array<{ type: 'text'; text: string } | { type: 'resource'; resource: { uri: string; mimeType: string } }> }> {
  const maxBytes = params.maxBytes || 1000000;

  const searchParams = new URLSearchParams();
  searchParams.set('date', '1440');

  if (params.expression) {
    searchParams.set('expression', params.expression);
  }

  if (params.startTime) {
    searchParams.set('startTime', String(isoToTimestamp(params.startTime)));
    searchParams.delete('date');
  }

  if (params.endTime) {
    // Arkime's PCAP API uses `stopTime`, not `endTime`.
    searchParams.set('stopTime', String(isoToTimestamp(params.endTime)));
    searchParams.delete('date');
  }

  const pcapBuffer = await client.getPcap(`/api/sessions/pcap?${searchParams.toString()}`);

  if (pcapBuffer.length === 0) {
    return {
      content: [{
        type: 'text',
        text: 'No PCAP data found for the specified criteria.',
      }],
    };
  }

  if (pcapBuffer.length > maxBytes) {
    return {
      content: [{
        type: 'text',
        text: `PCAP too large: ${pcapBuffer.length} bytes exceeds limit of ${maxBytes} bytes. ` +
              `Narrow your search expression to reduce the result set.`,
      }],
    };
  }

  const base64Pcap = pcapBuffer.toString('base64');
  const md5 = crypto.createHash('md5').update(pcapBuffer).digest('hex');
  const dataUri = `data:application/vnd.tcpdump.pcap;base64,${base64Pcap}`;

  return {
    content: [
      {
        type: 'text',
        text: `PCAP extracted successfully:\n` +
              `  Size: ${pcapBuffer.length} bytes\n` +
              `  MD5: ${md5}\n` +
              `  Expression: ${params.expression}\n` +
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
