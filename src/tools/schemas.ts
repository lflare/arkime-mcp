import { z } from 'zod';
import { validateIPv4 } from '@/utils/formatters.js';

export const searchSessionsSchema = z.object({
  expression: z.string()
    .max(10000)
    .optional()
    .describe('Arkime search expression (e.g., "ip.src == 192.168.1.1" or "port.dst == 443")'),
  startTime: z.string()
    .datetime()
    .optional()
    .describe('ISO 8601 start time (e.g., "2025-01-01T00:00:00Z"). DEFAULT: If omitted, searches last 24 hours (1440 minutes).'),
  endTime: z.string()
    .datetime()
    .optional()
    .describe('ISO 8601 end time (e.g., "2025-12-31T23:59:59Z"). DEFAULT: If omitted, searches last 24 hours (1440 minutes).'),
  limit: z.number()
    .int()
    .min(1)
    .max(1000)
    .default(100)
    .describe('Maximum number of sessions to return (1-1000)'),
  fields: z.array(z.string())
    .optional()
    .describe('Database field names to include in results (e.g., ["source.ip", "destination.ip"])'),
});

export const getSessionSchema = z.object({
  id: z.string()
    .min(1)
    .describe('Session ID from Arkime (e.g., "260127-GwFt1w7eKJREbKdq8VYTsuEk" or "GwFt1w7eKJREbKdq8VYTsuEk"). The date portion is YYYYMMDD format. Get valid IDs from search-sessions results.'),
});

export const listFieldsSchema = z.object({
  group: z.string()
    .optional()
    .describe('Filter fields by group (e.g., "general", "http", "dns")'),
});

export const analyzeTrafficSchema = z.object({
  expression: z.string()
    .max(10000)
    .optional()
    .describe('Arkime search expression to filter sessions'),
  startTime: z.string()
    .datetime()
    .optional()
    .describe('ISO 8601 start time (e.g., "2025-01-01T00:00:00Z"). DEFAULT: If omitted, searches last 24 hours (1440 minutes).'),
  endTime: z.string()
    .datetime()
    .optional()
    .describe('ISO 8601 end time (e.g., "2025-12-31T23:59:59Z"). DEFAULT: If omitted, searches last 24 hours (1440 minutes).'),
  analysisType: z.enum(['top-talkers', 'protocols', 'ports', 'connections'])
    .default('top-talkers')
    .describe('Type of analysis to perform'),
  limit: z.number()
    .int()
    .min(1)
    .max(500)
    .default(100)
    .describe('Number of top items to return'),
});

export const huntSuspiciousSchema = z.object({
  huntType: z.enum(['port-scanners', 'beaconing', 'data-exfil', 'lateral-movement'])
    .describe('Type of suspicious activity to hunt for'),
  expression: z.string()
    .max(10000)
    .optional()
    .describe('Additional Arkime search expression to narrow the hunt'),
  threshold: z.number()
    .int()
    .min(1)
    .max(10000)
    .default(100)
    .describe('Threshold for detection (e.g., min connections, min bytes)'),
});

export const getPcapSchema = z.object({
  expression: z.string()
    .max(10000)
    .describe('Arkime search expression to filter sessions for PCAP extraction (e.g., "ip.src == 192.168.1.1" or "port.dst == 443"). Use narrow expressions to reduce PCAP size.'),
  startTime: z.string()
    .datetime()
    .optional()
    .describe('ISO 8601 start time for search range'),
  endTime: z.string()
    .datetime()
    .optional()
    .describe('ISO 8601 end time for search range'),
  maxBytes: z.number()
    .int()
    .min(1)
    .max(10000000)
    .default(1000000)
    .describe('Maximum PCAP file size in bytes (default: 1MB, max: 10MB)'),
});

export const getPacketSchema = z.object({
  sessionId: z.string()
    .min(1)
    .describe('Session ID from Arkime (e.g., "3@251118-GwHllt-BE65AZ49KusloBKxl" or just "BE65AZ49KusloBKxl")'),
});

export const getFlowSchema = z.object({
  sourceIp: z.string()
    .refine((v) => validateIPv4(v), { message: 'Must be a valid IPv4 address' })
    .describe('Source IP address of the flow (IPv4)'),
  destIp: z.string()
    .refine((v) => validateIPv4(v), { message: 'Must be a valid IPv4 address' })
    .describe('Destination IP address of the flow (IPv4)'),
  sourcePort: z.number()
    .int()
    .min(0)
    .max(65535)
    .optional()
    .describe('Source port (optional, omit to match any source port)'),
  destPort: z.number()
    .int()
    .min(0)
    .max(65535)
    .optional()
    .describe('Destination port (e.g., 445 for SMB, 22 for SSH)'),
  protocol: z.enum(['tcp', 'udp', 'any'])
    .default('any')
    .describe('Protocol filter: tcp, udp, or any'),
  startTime: z.string()
    .datetime()
    .optional()
    .describe('ISO 8601 start time for flow'),
  endTime: z.string()
    .datetime()
    .optional()
    .describe('ISO 8601 end time for flow'),
  maxBytes: z.number()
    .int()
    .min(1)
    .max(10000000)
    .default(10000000)
    .describe('Maximum PCAP file size in bytes (default: 10MB, max: 10MB)'),
});

export type SearchSessionsParams = z.infer<typeof searchSessionsSchema>;
export type GetSessionParams = z.infer<typeof getSessionSchema>;
export type ListFieldsParams = z.infer<typeof listFieldsSchema>;
export type AnalyzeTrafficParams = z.infer<typeof analyzeTrafficSchema>;
export type HuntSuspiciousParams = z.infer<typeof huntSuspiciousSchema>;
export type GetPcapParams = z.infer<typeof getPcapSchema>;
export type GetPacketParams = z.infer<typeof getPacketSchema>;
export type GetFlowParams = z.infer<typeof getFlowSchema>;

// Session SPI
export const getSessionSpiSchema = z.object({
  expression: z.string()
    .max(10000)
    .describe('Arkime search expression to find sessions (e.g., "dns.host contains microsoft" or "http.uri contains /api")'),
  categories: z.array(z.enum(['dns', 'http', 'tls', 'email', 'file', 'socks', 'ssh', 'all']))
    .default(['all'])
    .describe('SPI categories to include: dns, http, tls, email, file, socks, ssh, or all'),
  limit: z.number()
    .int()
    .min(1)
    .max(50)
    .default(10)
    .describe('Maximum sessions to return (1-50)'),
});

// Investigation tools
export const investigateNtlmSchema = z.object({
  suspectIp: z.string()
    .optional()
    .describe('IP address to investigate as pivot point'),
  suspectUser: z.string()
    .optional()
    .describe('Username to investigate for suspicious activity'),
  expression: z.string()
    .max(10000)
    .optional()
    .describe('Additional Arkime search expression to narrow investigation'),
});

export const buildTimelineSchema = z.object({
  suspectIp: z.string()
    .optional()
    .describe('Filter timeline by source/destination IP'),
  suspectUser: z.string()
    .optional()
    .describe('Filter timeline by username in SMB/LDAP/email'),
  suspectHost: z.string()
    .optional()
    .describe('Filter timeline by hostname'),
  startTime: z.string()
    .datetime()
    .optional()
    .describe('ISO 8601 start time for timeline'),
  endTime: z.string()
    .datetime()
    .optional()
    .describe('ISO 8601 end time for timeline'),
});

export const trackMovementSchema = z.object({
  sourceIp: z.string()
    .optional()
    .describe('Starting IP for lateral movement analysis'),
  protocols: z.array(z.enum(['smb', 'ldap', 'rdp', 'winrm', 'ssh']))
    .default(['smb', 'ldap', 'rdp', 'winrm'])
    .describe('Protocols to include in movement analysis'),
  minConnections: z.number()
    .int()
    .min(1)
    .max(100)
    .default(2)
    .describe('Minimum connections to include in graph'),
});

export const extractIocsSchema = z.object({
  expression: z.string()
    .max(10000)
    .describe('Arkime search expression to find sessions for IOC extraction'),
  iocTypes: z.array(z.enum(['ip', 'domain', 'hash', 'url', 'email']))
    .default(['ip', 'domain', 'url', 'hash'])
    .describe('Types of IOCs to extract'),
});

// Explorer tools
export const topTalkersSchema = z.object({
  field: z.string()
    .min(1)
    .describe('Database field name (e.g., sourceIP, domain, destination.port)'),
  expression: z.string()
    .max(10000)
    .optional()
    .describe('Arkime search expression to filter results'),
  dateRange: z.number()
    .optional()
    .describe('Date range in hours (e.g., -24 for last 24h, -168 for 7 days, 0 for all time)'),
  limit: z.number()
    .int()
    .min(1)
    .max(1000)
    .default(100)
    .describe('Maximum values to return'),
});

export const reverseDnsSchema = z.object({
  ipAddress: z.string()
    .min(1)
    .describe('IP address to look up (e.g., 10.0.0.1)'),
  dateRange: z.number()
    .optional()
    .describe('Date range in hours (e.g., -24 for last 24h, 0 for all time)'),
});

export const dnsLookupsSchema = z.object({
  domainPattern: z.string()
    .optional()
    .describe('Filter DNS queries containing this domain pattern'),
  sourceIp: z.string()
    .optional()
    .describe('Filter DNS queries from this source IP'),
  dateRange: z.number()
    .optional()
    .describe('Date range in hours (e.g., -24 for last 24h, 0 for all time)'),
  limit: z.number()
    .int()
    .min(1)
    .max(1000)
    .default(200)
    .describe('Maximum DNS queries to return'),
});

export const geoSummarySchema = z.object({
  expression: z.string()
    .max(10000)
    .optional()
    .describe('Arkime search expression to filter sessions'),
  dateRange: z.number()
    .optional()
    .describe('Date range in hours (e.g., -24 for last 24h, 0 for all time)'),
  limit: z.number()
    .int()
    .min(1)
    .max(250)
    .default(50)
    .describe('Maximum countries to show'),
});

export const captureStatusSchema = z.object({});

// No-param tools (gap-fill)
export const huntListSchema = z.object({});
export const viewListSchema = z.object({});
export const shortcutListSchema = z.object({});
export const appInfoSchema = z.object({});
export const nodeStatsSchema = z.object({});

export const pcapFilesSchema = z.object({
  limit: z.number()
    .int()
    .min(1)
    .max(1000)
    .default(100)
    .describe('Maximum files to list'),
  sort: z.enum(['dateFirst', 'dateLast', 'sessions', 'totalLen', 'filename'])
    .optional()
    .describe('Sort field'),
});

// Gap-fill tools
export const sessionsSummarySchema = z.object({
  expression: z.string()
    .max(10000)
    .optional()
    .describe('Arkime search expression to filter sessions'),
  dateRange: z.number()
    .optional()
    .describe('Date range in hours (e.g., -24 for last 24h, 0 for all time)'),
  field: z.string()
    .optional()
    .describe('Field to build histogram on (e.g., sourceIP, protocol)'),
  buckets: z.number()
    .int()
    .min(1)
    .max(1000)
    .optional()
    .describe('Number of histogram buckets'),
});

export const multiUniqueSchema = z.object({
  fields: z.array(z.string())
    .min(1)
    .max(20)
    .describe('Database field names to query (e.g., ["sourceIP", "protocol", "destination.port"])'),
  expression: z.string()
    .max(10000)
    .optional()
    .describe('Arkime search expression to filter results'),
  dateRange: z.number()
    .optional()
    .describe('Date range in hours (e.g., -24 for last 24h, 0 for all time)'),
  limit: z.number()
    .int()
    .min(1)
    .max(1000)
    .optional()
    .describe('Maximum values per field'),
});

export const connectionsSchema = z.object({
  expression: z.string()
    .max(10000)
    .optional()
    .describe('Arkime search expression to filter connections'),
  dateRange: z.number()
    .optional()
    .describe('Date range in hours (e.g., -24 for last 24h, 0 for all time)'),
  limit: z.number()
    .int()
    .min(1)
    .max(1000)
    .optional()
    .describe('Maximum connections to return'),
});

export const spiSessionsSchema = z.object({
  expression: z.string()
    .max(10000)
    .optional()
    .describe('Arkime search expression to find sessions'),
  fields: z.array(z.string())
    .optional()
    .describe('SPI field names to include (e.g., ["dns.host", "http.uri"])'),
  limit: z.number()
    .int()
    .min(1)
    .max(1000)
    .optional()
    .describe('Maximum SPI items to return'),
});

export const sessionDetailSchema = z.object({
  nodeId: z.string()
    .min(1)
    .describe('Node identifier from the session (e.g., "3" from session ID "3@251118-GwHllt-BE65AZ49KusloBKxl")'),
  sessionId: z.string()
    .min(1)
    .describe('Session ID (e.g., "251118-GwHllt-BE65AZ49KusloBKxl")'),
});

export const sessionFileSchema = z.object({
  nodeId: z.string()
    .min(1)
    .describe('Node identifier from the session'),
  sessionId: z.string()
    .min(1)
    .describe('Session ID containing the file transfer'),
  hash: z.string()
    .min(1)
    .describe('File hash (e.g., MD5, SHA1) of the file to download'),
});

// Type exports for new schemas
export type GetSessionSpiParams = z.infer<typeof getSessionSpiSchema>;
export type InvestigateNtlmParams = z.infer<typeof investigateNtlmSchema>;
export type BuildTimelineParams = z.infer<typeof buildTimelineSchema>;
export type TrackMovementParams = z.infer<typeof trackMovementSchema>;
export type ExtractIocsParams = z.infer<typeof extractIocsSchema>;
export type TopTalkersParams = z.infer<typeof topTalkersSchema>;
export type ReverseDnsParams = z.infer<typeof reverseDnsSchema>;
export type DnsLookupsParams = z.infer<typeof dnsLookupsSchema>;
export type GeoSummaryParams = z.infer<typeof geoSummarySchema>;
export type PcapFilesParams = z.infer<typeof pcapFilesSchema>;
export type CaptureStatusParams = z.infer<typeof captureStatusSchema>;
export type HuntListParams = z.infer<typeof huntListSchema>;
export type ViewListParams = z.infer<typeof viewListSchema>;
export type ShortcutListParams = z.infer<typeof shortcutListSchema>;
export type AppInfoParams = z.infer<typeof appInfoSchema>;
export type NodeStatsParams = z.infer<typeof nodeStatsSchema>;
export type SessionsSummaryParams = z.infer<typeof sessionsSummarySchema>;
export type MultiUniqueParams = z.infer<typeof multiUniqueSchema>;
export type ConnectionsParams = z.infer<typeof connectionsSchema>;
export type SpiSessionsParams = z.infer<typeof spiSessionsSchema>;
export type SessionDetailParams = z.infer<typeof sessionDetailSchema>;
export type SessionFileParams = z.infer<typeof sessionFileSchema>;

// === Read-only endpoint tools ===

// --- Analytics ---
export const spiGraphSchema = z.object({
  field: z.string()
    .min(1)
    .describe('Database field to aggregate (e.g., destination.ip, destination.port, dns.host)'),
  expression: z.string()
    .max(10000)
    .optional()
    .describe('Arkime search expression to filter sessions'),
  dateRange: z.number()
    .optional()
    .describe('Date range in hours (e.g., -24 for last 24h, 0 for all time)'),
  size: z.number()
    .int()
    .min(1)
    .max(1000)
    .default(100)
    .describe('Maximum number of values to return'),
});

export const spiGraphHierarchySchema = z.object({
  fields: z.array(z.string())
    .min(1)
    .max(10)
    .describe('Ordered list of fields defining the hierarchy (e.g., ["source.ip", "destination.ip"])'),
  expression: z.string()
    .max(10000)
    .optional()
    .describe('Arkime search expression to filter sessions'),
  dateRange: z.number()
    .optional()
    .describe('Date range in hours (e.g., -24 for last 24h, 0 for all time)'),
});

export const buildQuerySchema = z.object({
  expression: z.string()
    .min(1)
    .max(10000)
    .describe('Arkime search expression to compile (e.g., "ip.src == 1.2.3.4 && port.dst == 443"). Returns the underlying OpenSearch/Elasticsearch query, so it also validates expression syntax.'),
  dateRange: z.number()
    .optional()
    .describe('Date range in hours (e.g., -24 for last 24h, 0 for all time)'),
});

export const listDecodingsSchema = z.object({});

// --- Metadata listings ---
export const cronListSchema = z.object({});
export const notifierListSchema = z.object({});
export const shareableListSchema = z.object({});
export const remoteClustersSchema = z.object({});
export const currentUserSchema = z.object({});
export const userRolesSchema = z.object({});
export const valueActionsSchema = z.object({});
export const fieldActionsSchema = z.object({});

export const historyListSchema = z.object({
  limit: z.number()
    .int()
    .min(1)
    .max(1000)
    .default(100)
    .describe('Maximum number of history entries to return'),
});

// --- ES / cluster health ---
export const esHealthSchema = z.object({});
export const esStatsSchema = z.object({});
export const esIndicesSchema = z.object({});
export const esShardsSchema = z.object({});
export const esTasksSchema = z.object({});
export const esRecoverySchema = z.object({});
export const appVersionSchema = z.object({});

export const nodeDstatsSchema = z.object({
  nodeName: z.string()
    .default('ALL')
    .describe('Node to fetch time-series stats for, or "ALL" for cluster-wide'),
  name: z.string()
    .optional()
    .describe('Stat name to graph (e.g., deltaPackets, deltaBytes, deltaSessions)'),
  start: z.number()
    .optional()
    .describe('Unix epoch seconds for the start of the window'),
  stop: z.number()
    .optional()
    .describe('Unix epoch seconds for the end of the window'),
  interval: z.number()
    .optional()
    .describe('Aggregation interval in seconds'),
});

// --- Session binary data ---
export const getSessionPacketsSchema = z.object({
  nodeId: z.string()
    .min(1)
    .describe('Node identifier from the session (e.g., "3")'),
  sessionId: z.string()
    .min(1)
    .describe('Session ID (e.g., "251118-GwHllt-BE65AZ49KusloBKxl")'),
});

export const getSessionPcapSchema = z.object({
  nodeId: z.string()
    .min(1)
    .describe('Node identifier from the session'),
  sessionId: z.string()
    .min(1)
    .describe('Session ID to extract the entire PCAP for'),
});

export const getSessionRawSchema = z.object({
  nodeId: z.string()
    .min(1)
    .describe('Node identifier from the session'),
  sessionId: z.string()
    .min(1)
    .describe('Session ID to extract raw packet payload for'),
});

export const getSessionBodySchema = z.object({
  nodeId: z.string()
    .min(1)
    .describe('Node identifier from the session'),
  sessionId: z.string()
    .min(1)
    .describe('Session ID containing the body to extract'),
  bodyType: z.string()
    .min(1)
    .describe('Body type as reported by Arkime (e.g., "file", "body")'),
  bodyNum: z.number()
    .int()
    .min(0)
    .describe('Body index within the session'),
  bodyName: z.string()
    .min(1)
    .describe('Name to assign to the extracted body'),
});

// Type exports for read-only endpoint tools
export type SpiGraphParams = z.infer<typeof spiGraphSchema>;
export type SpiGraphHierarchyParams = z.infer<typeof spiGraphHierarchySchema>;
export type BuildQueryParams = z.infer<typeof buildQuerySchema>;
export type ListDecodingsParams = z.infer<typeof listDecodingsSchema>;
export type CronListParams = z.infer<typeof cronListSchema>;
export type NotifierListParams = z.infer<typeof notifierListSchema>;
export type ShareableListParams = z.infer<typeof shareableListSchema>;
export type RemoteClustersParams = z.infer<typeof remoteClustersSchema>;
export type CurrentUserParams = z.infer<typeof currentUserSchema>;
export type UserRolesParams = z.infer<typeof userRolesSchema>;
export type ValueActionsParams = z.infer<typeof valueActionsSchema>;
export type FieldActionsParams = z.infer<typeof fieldActionsSchema>;
export type HistoryListParams = z.infer<typeof historyListSchema>;
export type EsHealthParams = z.infer<typeof esHealthSchema>;
export type EsStatsParams = z.infer<typeof esStatsSchema>;
export type EsIndicesParams = z.infer<typeof esIndicesSchema>;
export type EsShardsParams = z.infer<typeof esShardsSchema>;
export type EsTasksParams = z.infer<typeof esTasksSchema>;
export type EsRecoveryParams = z.infer<typeof esRecoverySchema>;
export type AppVersionParams = z.infer<typeof appVersionSchema>;
export type NodeDstatsParams = z.infer<typeof nodeDstatsSchema>;
export type GetSessionPacketsParams = z.infer<typeof getSessionPacketsSchema>;
export type GetSessionPcapParams = z.infer<typeof getSessionPcapSchema>;
export type GetSessionRawParams = z.infer<typeof getSessionRawSchema>;
export type GetSessionBodyParams = z.infer<typeof getSessionBodySchema>;
