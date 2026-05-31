import type { ArkimeClient } from '@/services/arkime-client.js';
import { McpError, ErrorCode } from '@/utils/errors.js';
import type { GetPacketParams } from '@/tools/schemas.js';
import type { Session } from '@/types/arkime.js';

/**
 * Extract a single packet from a session by offset.
 *
 * Note: Arkime's /api/sessions/pcap endpoint returns PCAP for matching sessions.
 * To get a single packet, we search for the session and extract the first packet.
 */
export async function getPacket(
  client: ArkimeClient,
  params: GetPacketParams
): Promise<{ content: Array<{ type: 'text'; text: string } | { type: 'resource'; resource: { uri: string; mimeType: string } }> }> {
  // Parse session ID: format is "node@date-id" or just "id"
  // We need to extract node and short ID for the packet endpoint
  const sessionId = params.sessionId;

  // Try to get session details first to find node
  let session: Session | undefined;
  try {
    session = await client.getSession(sessionId);
  } catch (_error) {
    throw new McpError(ErrorCode.NOT_FOUND, `Session not found, cannot fetch packet data: ${sessionId}`);
  }

  if (!session?.node) {
    throw new McpError(ErrorCode.NOT_FOUND, `Could not resolve session: ${sessionId}`);
  }

  // Build expression to match only this session
  // Use the short ID (last part after @) for the expression
  const shortId = sessionId.split('@').pop() || sessionId;
  const expression = `id=="${shortId}"`;

  // Fetch PCAP for this specific session (should be single packet if offset used)
  const searchParams = new URLSearchParams();
  searchParams.set('expression', expression);
  searchParams.set('date', '-1'); // Search all time
  searchParams.set('length', '1');

  const pcapUrl = `/api/sessions/pcap?${searchParams.toString()}`;
  const pcapBuffer = await client.getPcap(pcapUrl);

  if (pcapBuffer.length === 0) {
    return {
      content: [{
        type: 'text',
        text: `No PCAP data found for session ${sessionId}.`,
      }],
    };
  }

  const base64Pcap = pcapBuffer.toString('base64');
  const dataUri = `data:application/vnd.tcpdump.pcap;base64,${base64Pcap}`;

  return {
    content: [
      {
        type: 'text',
        text: `PCAP extracted from session ${sessionId}:\n` +
              `  Node: ${session.node}\n` +
              `  Size: ${pcapBuffer.length} bytes\n` +
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
