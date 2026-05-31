import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { ArkimeClient } from '@/services/arkime-client.js';
import { loadValidatedConfig } from '@/services/config.js';
import { searchSessions, getSession, getSessionSpi } from '@/controllers/sessions.js';
import { listFields } from '@/controllers/fields.js';
import { analyzeTraffic, huntSuspicious } from '@/controllers/analysis.js';
import { getPcap } from '@/controllers/pcap.js';
import { getPacket } from '@/controllers/packet.js';
import { getFlow } from '@/controllers/flow.js';
import { buildAttackTimeline, trackLateralMovement, extractIocs } from '@/controllers/forensics.js';
import { investigateNtlm } from '@/controllers/investigation.js';
import { topTalkers, reverseDns, dnsLookups, geoSummary, captureStatus, pcapFiles } from '@/controllers/explorer.js';
import { sessionsSummary, multiUnique, connections, spiSessions, sessionDetail, huntList, viewList, shortcutList, appInfo, nodeStats, sessionFile } from '@/controllers/gap-fill.js';
import { spiGraph, spiGraphHierarchy, buildQuery, listDecodings } from '@/controllers/analytics.js';
import { cronList, notifierList, shareableList, historyList, remoteClusters, currentUser, userRoles, valueActions, fieldActions } from '@/controllers/metadata.js';
import { esHealth, esStats, esIndices, esShards, esTasks, esRecovery, nodeDstats, appVersion } from '@/controllers/es-health.js';
import { sessionPackets, sessionPcap, sessionRaw, sessionBody } from '@/controllers/session-data.js';
import * as S from '@/tools/schemas.js';

let client: ArkimeClient | null = null;

// MCP SDK's handler signature is (params: unknown) => Promise<unknown>.
// This wrapper preserves the inferred type from the Zod schema shape,
// so we get compile-time checking without scattering `as any`.
function wrapHandler<T>(handler: (params: T) => Promise<unknown>): (params: unknown) => Promise<unknown> {
  return (params: unknown) => handler(params as T);
}

function getClient(): ArkimeClient {
  if (!client) {
    const config = loadValidatedConfig();
    client = new ArkimeClient(config);
  }
  return client;
}

export function registerTools(server: McpServer): void {
  server.tool(
    'search-sessions',
    'Search network sessions in Arkime. Use expressions like "ip.src == 192.168.1.1" or "port.dst == 443". Supports filtering by SMB traffic with "port.dst == 445" or "ipProtocol == 6". Returns session details in a table format.',
    S.searchSessionsSchema.shape,
    wrapHandler((params: S.SearchSessionsParams) => searchSessions(getClient(), params))
  );

  server.tool(
    'get-session',
    'Get detailed information about a specific network session by ID. Shows source/destination IPs, ports, protocol, bytes transferred, and other metadata. Session ID format: "date-shortid" (e.g., "260127-GwFt1w7eKJREbKdq8VYTsuEk") or just the short ID. The date is YYYYMMDD format. Use search-sessions first to find valid session IDs.',
    S.getSessionSchema.shape,
    wrapHandler((params: S.GetSessionParams) => getSession(getClient(), params))
  );

  server.tool(
    'list-fields',
    'List available database fields in Arkime. Use this to discover which fields you can query or include in search results. Fields are grouped by category (general, http, dns, etc.).',
    S.listFieldsSchema.shape,
    wrapHandler((params: S.ListFieldsParams) => listFields(getClient(), params))
  );

  server.tool(
    'analyze-traffic',
    'Analyze network traffic patterns. Supports: top-talkers (IPs with most connections), protocols (traffic breakdown by protocol), ports (most used destination ports), connections (source-destination pairs). Essential for network forensics and threat hunting.',
    S.analyzeTrafficSchema.shape,
    wrapHandler((params: S.AnalyzeTrafficParams) => analyzeTraffic(getClient(), params))
  );

  server.tool(
    'hunt-suspicious',
    'Hunt for suspicious network activity patterns. Types: port-scanners (hosts scanning many ports), beaconing (potential C2 communication with regular intervals), data-exfil (large outbound data transfers), lateral-movement (internal host-to-host connections on suspicious ports).',
    S.huntSuspiciousSchema.shape,
    wrapHandler((params: S.HuntSuspiciousParams) => huntSuspicious(getClient(), params))
  );

  server.tool(
    'get-session-spi',
    'Search sessions and extract Session Protocol Information (SPI) data - parsed application-layer data like DNS queries, HTTP URIs, TLS SNI, email headers, and file transfers. Use expressions like "dns.host contains google" or "http.uri contains /login" to find relevant sessions.',
    S.getSessionSpiSchema.shape,
    wrapHandler((params: S.GetSessionSpiParams) => getSessionSpi(getClient(), params))
  );

  server.tool(
    'get-pcap',
    'Extract raw PCAP data for matching sessions. Returns base64-encoded PCAP file for deep packet analysis in Wireshark. Use narrow expressions (e.g., specific IP, port, time window) to reduce size. For single-packet analysis: combine tight time windows (startTime/endTime) with specific IP/port filters. PCAP size limited to 10MB.',
    S.getPcapSchema.shape,
    wrapHandler((params: S.GetPcapParams) => getPcap(getClient(), params))
  );

  server.tool(
    'get-packet',
    'Extract PCAP data for a specific session by session ID. Returns raw PCAP data for deep packet analysis. Use when you need to inspect packet-level details that Arkime did not parse (e.g., SMB share names, HTTP headers). Session ID format: "node@date-id" or just the short ID.',
    S.getPacketSchema.shape,
    wrapHandler((params: S.GetPacketParams) => getPacket(getClient(), params))
  );

  server.tool(
    'get-flow',
    'Extract all packets for a TCP/UDP flow between two endpoints. Returns PCAP containing the complete flow for analysis in Wireshark. Use sourceIp/destIp to identify the flow, optionally filter by ports and protocol. Ideal for analyzing complete TCP streams or UDP exchanges.',
    S.getFlowSchema.shape,
    wrapHandler((params: S.GetFlowParams) => getFlow(getClient(), params))
  );

  server.tool(
    'investigate-ntlm',
    'Investigate NTLM authentication and lateral movement. Searches SMB (445), LDAP (389/636), and Kerberos (88) traffic for suspicious authentication patterns, user enumeration, and domain reconnaissance. Essential for detecting compromised credential use.',
    S.investigateNtlmSchema.shape,
    wrapHandler((params: S.InvestigateNtlmParams) => investigateNtlm(getClient(), params))
  );

  server.tool(
    'build-attack-timeline',
    'Build chronological timeline of network events for attack reconstruction. Correlates SMB auth, LDAP queries, Kerberos tickets, HTTP requests, DNS queries across time. Identifies attack phases and progression.',
    S.buildTimelineSchema.shape,
    wrapHandler((params: S.BuildTimelineParams) => buildAttackTimeline(getClient(), params))
  );

  server.tool(
    'track-lateral-movement',
    'Analyze lateral movement patterns across hosts. Builds relationship graph showing which hosts connected to which, via what protocols, using what accounts. Outputs GraphViz for visualization.',
    S.trackMovementSchema.shape,
    wrapHandler((params: S.TrackMovementParams) => trackLateralMovement(getClient(), params))
  );

  server.tool(
    'extract-iocs',
    'Extract Indicators of Compromise from matching sessions: external IPs, domains, URLs, file hashes, email addresses. Filters private/internal IPs automatically.',
    S.extractIocsSchema.shape,
    wrapHandler((params: S.ExtractIocsParams) => extractIocs(getClient(), params))
  );

  server.tool(
    'top-talkers',
    'Get top N values for any Arkime database field by session count. Use field names like sourceIP, destinationIP, domain, tlsSNI, httpHost, protocol. Great for finding top hosts, ports, domains, etc.',
    S.topTalkersSchema.shape,
    wrapHandler((params: S.TopTalkersParams) => topTalkers(getClient(), params))
  );

  server.tool(
    'reverse-dns',
    'Get reverse DNS (PTR) records for an IP address from captured traffic. Shows domain names resolved for the given IP.',
    S.reverseDnsSchema.shape,
    wrapHandler((params: S.ReverseDnsParams) => reverseDns(getClient(), params))
  );

  server.tool(
    'dns-lookups',
    'Search DNS queries captured in traffic. Filter by domain pattern or source IP. Shows query name, type, and answers.',
    S.dnsLookupsSchema.shape,
    wrapHandler((params: S.DnsLookupsParams) => dnsLookups(getClient(), params))
  );

  server.tool(
    'geo-summary',
    'Get destination traffic breakdown by country using geo IP data. Shows session counts and percentages per country.',
    S.geoSummarySchema.shape,
    wrapHandler((params: S.GeoSummaryParams) => geoSummary(getClient(), params))
  );

  server.tool(
    'capture-status',
    'Get Arkime cluster health status. Shows viewer and capture nodes, their versions, roles, and uptime.',
    S.captureStatusSchema.shape,
    wrapHandler((params: S.CaptureStatusParams) => captureStatus(getClient(), params))
  );

  server.tool(
    'pcap-files',
    'List PCAP capture files with sizes, session counts, and time ranges. Useful for understanding capture coverage and storage.',
    S.pcapFilesSchema.shape,
    wrapHandler((params: S.PcapFilesParams) => pcapFiles(getClient(), params))
  );

  server.tool(
    'sessions-summary',
    'Get aggregate statistics for matching sessions including histograms, connection counts, bytes, and packets. Use field parameter to group by a specific field (e.g., protocol, sourceIP).',
    S.sessionsSummarySchema.shape,
    wrapHandler((params: S.SessionsSummaryParams) => sessionsSummary(getClient(), params))
  );

  server.tool(
    'multi-unique',
    'Get unique values for multiple Arkime database fields in a single API call. More efficient than calling top-talkers multiple times. Returns up to 100 values per field.',
    S.multiUniqueSchema.shape,
    wrapHandler((params: S.MultiUniqueParams) => multiUnique(getClient(), params))
  );

  server.tool(
    'connections',
    'Get network connection graph showing nodes (IPs) and links (connections between them). Shows session counts, packets, and bytes per node and link. Ideal for visualizing network topology.',
    S.connectionsSchema.shape,
    wrapHandler((params: S.ConnectionsParams) => connections(getClient(), params))
  );

  server.tool(
    'spi-sessions',
    'Get Session Protocol Information (SPI) - parsed application-layer data from matching sessions. Shows DNS queries, HTTP URIs, TLS SNI, email headers, file hashes, and other extracted protocol data grouped by field.',
    S.spiSessionsSchema.shape,
    wrapHandler((params: S.SpiSessionsParams) => spiSessions(getClient(), params))
  );

  server.tool(
    'session-detail',
    'Get all parsed fields for a specific session. Unlike get-session which returns search results, this returns the complete session object with every field Arkime has extracted. Requires nodeId and sessionId from search results.',
    S.sessionDetailSchema.shape,
    wrapHandler((params: S.SessionDetailParams) => sessionDetail(getClient(), params))
  );

  server.tool(
    'hunt-list',
    'List all active packet hunts configured in Arkime. Hunts are real-time packet monitoring rules that match expressions against live traffic. Shows hunt names, expressions, match counts, and status.',
    S.huntListSchema.shape,
    wrapHandler((params: S.HuntListParams) => huntList(getClient(), params))
  );

  server.tool(
    'view-list',
    'List all saved views (saved searches) in Arkime. Views are user-defined queries saved for repeated use. Shows view names, expressions, and creators.',
    S.viewListSchema.shape,
    wrapHandler((params: S.ViewListParams) => viewList(getClient(), params))
  );

  server.tool(
    'shortcut-list',
    'List all saved query shortcuts in Arkime. Shortcuts provide quick access to frequently used search expressions.',
    S.shortcutListSchema.shape,
    wrapHandler((params: S.ShortcutListParams) => shortcutList(getClient(), params))
  );

  server.tool(
    'app-info',
    'Get comprehensive Arkime application information in a single call. Includes current user details, Elasticsearch health, cluster status, and view counts.',
    S.appInfoSchema.shape,
    wrapHandler((params: S.AppInfoParams) => appInfo(getClient(), params))
  );

  server.tool(
    'node-stats',
    'Get per-node statistics for all Arkime cluster nodes. Shows packets processed, bytes captured, sessions created, and node roles.',
    S.nodeStatsSchema.shape,
    wrapHandler((params: S.NodeStatsParams) => nodeStats(getClient(), params))
  );

  server.tool(
    'session-file',
    'Extract a file transferred within a specific session by its hash. Useful for downloading malware samples, documents, or other files captured in network traffic.',
    S.sessionFileSchema.shape,
    wrapHandler((params: S.SessionFileParams) => sessionFile(getClient(), params))
  );

  // --- Analytics ---

  server.tool(
    'spi-graph',
    'Aggregate a single field across matching sessions, returning value counts (a spigraph). Use field names like destination.ip, destination.port, or dns.host to see the top values for that field over a time range.',
    S.spiGraphSchema.shape,
    wrapHandler((params: S.SpiGraphParams) => spiGraph(getClient(), params))
  );

  server.tool(
    'spi-graph-hierarchy',
    'Aggregate multiple fields as a hierarchy (treemap/pie data). Provide an ordered list of fields (e.g., ["source.ip", "destination.ip"]) to see nested value breakdowns. Useful for drill-down analysis.',
    S.spiGraphHierarchySchema.shape,
    wrapHandler((params: S.SpiGraphHierarchyParams) => spiGraphHierarchy(getClient(), params))
  );

  server.tool(
    'build-query',
    'Compile an Arkime search expression into the underlying OpenSearch/Elasticsearch query without running it. Use this to validate expression syntax (catches mistakes like AND vs && or source.ip vs ip.src) and to understand how a query is interpreted.',
    S.buildQuerySchema.shape,
    wrapHandler((params: S.BuildQueryParams) => buildQuery(getClient(), params))
  );

  server.tool(
    'list-decodings',
    'List the packet decodings (e.g., gzip, base64) Arkime can apply when extracting session data.',
    S.listDecodingsSchema.shape,
    wrapHandler((params: S.ListDecodingsParams) => listDecodings(getClient(), params))
  );

  // --- Metadata listings ---

  server.tool(
    'cron-list',
    'List periodic (cron) queries configured in Arkime. These are saved expressions that run on a schedule to tag matching sessions.',
    S.cronListSchema.shape,
    wrapHandler((params: S.CronListParams) => cronList(getClient(), params))
  );

  server.tool(
    'notifier-list',
    'List configured notifiers (Slack, email, webhook, etc.) used by Arkime to send alerts.',
    S.notifierListSchema.shape,
    wrapHandler((params: S.NotifierListParams) => notifierList(getClient(), params))
  );

  server.tool(
    'shareable-list',
    'List shareable links/items configured in Arkime.',
    S.shareableListSchema.shape,
    wrapHandler((params: S.ShareableListParams) => shareableList(getClient(), params))
  );

  server.tool(
    'history-list',
    'List recent API request history (audit log) for the current user. Shows past searches and actions.',
    S.historyListSchema.shape,
    wrapHandler((params: S.HistoryListParams) => historyList(getClient(), params))
  );

  server.tool(
    'remote-clusters',
    'List remote Arkime clusters known to this viewer (for cross-cluster search and session forwarding).',
    S.remoteClustersSchema.shape,
    wrapHandler((params: S.RemoteClustersParams) => remoteClusters(getClient(), params))
  );

  server.tool(
    'current-user',
    'Get the current authenticated Arkime user, including user ID, name, and assigned roles/permissions.',
    S.currentUserSchema.shape,
    wrapHandler((params: S.CurrentUserParams) => currentUser(getClient(), params))
  );

  server.tool(
    'user-roles',
    'List the roles the current user is allowed to see or assign.',
    S.userRolesSchema.shape,
    wrapHandler((params: S.UserRolesParams) => userRoles(getClient(), params))
  );

  server.tool(
    'value-actions',
    'List configured right-click value actions (custom menu actions on field values) in Arkime.',
    S.valueActionsSchema.shape,
    wrapHandler((params: S.ValueActionsParams) => valueActions(getClient(), params))
  );

  server.tool(
    'field-actions',
    'List configured field actions (custom menu actions on fields) in Arkime.',
    S.fieldActionsSchema.shape,
    wrapHandler((params: S.FieldActionsParams) => fieldActions(getClient(), params))
  );

  // --- ES / cluster health ---

  server.tool(
    'es-health',
    'Get Elasticsearch/OpenSearch cluster health: status (green/yellow/red), node counts, and shard counts. Quick check for backend datastore health.',
    S.esHealthSchema.shape,
    wrapHandler((params: S.EsHealthParams) => esHealth(getClient(), params))
  );

  server.tool(
    'es-stats',
    'Get per-node Elasticsearch/OpenSearch statistics (heap, disk, document counts, load).',
    S.esStatsSchema.shape,
    wrapHandler((params: S.EsStatsParams) => esStats(getClient(), params))
  );

  server.tool(
    'es-indices',
    'List Elasticsearch/OpenSearch indices backing Arkime, with sizes and document counts.',
    S.esIndicesSchema.shape,
    wrapHandler((params: S.EsIndicesParams) => esIndices(getClient(), params))
  );

  server.tool(
    'es-shards',
    'Show Elasticsearch/OpenSearch shard allocation across nodes, including any allocation excludes.',
    S.esShardsSchema.shape,
    wrapHandler((params: S.EsShardsParams) => esShards(getClient(), params))
  );

  server.tool(
    'es-tasks',
    'List currently running Elasticsearch/OpenSearch tasks. Useful for spotting long-running or stuck operations.',
    S.esTasksSchema.shape,
    wrapHandler((params: S.EsTasksParams) => esTasks(getClient(), params))
  );

  server.tool(
    'es-recovery',
    'Show Elasticsearch/OpenSearch shard recovery status (shards relocating or initializing).',
    S.esRecoverySchema.shape,
    wrapHandler((params: S.EsRecoveryParams) => esRecovery(getClient(), params))
  );

  server.tool(
    'node-dstats',
    'Get time-series statistics for a capture node (or ALL nodes), such as deltaPackets or deltaBytes over a time window. Useful for spotting capture gaps or load spikes.',
    S.nodeDstatsSchema.shape,
    wrapHandler((params: S.NodeDstatsParams) => nodeDstats(getClient(), params))
  );

  server.tool(
    'app-version',
    'Get the Arkime viewer version and backend Elasticsearch/OpenSearch version.',
    S.appVersionSchema.shape,
    wrapHandler((params: S.AppVersionParams) => appVersion(getClient(), params))
  );

  // --- Session binary data ---

  server.tool(
    'get-session-packets',
    'Get decoded packet data for a specific session (the per-packet breakdown Arkime parsed). Returns structured packet JSON. Requires nodeId and sessionId from search results.',
    S.getSessionPacketsSchema.shape,
    wrapHandler((params: S.GetSessionPacketsParams) => sessionPackets(getClient(), params))
  );

  server.tool(
    'get-session-pcap',
    'Extract the entire PCAP for a single session as a base64 resource for analysis in Wireshark. Requires nodeId and sessionId.',
    S.getSessionPcapSchema.shape,
    wrapHandler((params: S.GetSessionPcapParams) => sessionPcap(getClient(), params))
  );

  server.tool(
    'get-session-raw',
    'Extract the raw packet payload bytes for a single session as a base64 resource. Requires nodeId and sessionId.',
    S.getSessionRawSchema.shape,
    wrapHandler((params: S.GetSessionRawParams) => sessionRaw(getClient(), params))
  );

  server.tool(
    'get-session-body',
    'Extract a specific transferred body/file from a session by its body type and index, as a base64 resource. Requires nodeId, sessionId, bodyType, bodyNum, and bodyName.',
    S.getSessionBodySchema.shape,
    wrapHandler((params: S.GetSessionBodyParams) => sessionBody(getClient(), params))
  );
}
