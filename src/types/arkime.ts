export interface SessionEndpoint {
  ip?: string;
  port?: number;
  packets?: number;
  bytes?: number;
  as?: Record<string, unknown>;
  geo?: Record<string, unknown>;
}

export interface Session {
  id: string;
  lastPacket: number;
  firstPacket?: number;
  ipProtocol?: number;
  node?: string;
  source?: SessionEndpoint;
  destination?: SessionEndpoint;
  client?: { bytes?: number };
  server?: { bytes?: number };
  network?: { packets?: number; bytes?: number };
  totDataBytes?: number;
  tags?: string[];
  // Protocol-specific fields
  dns?: Record<string, unknown>;
  email?: Record<string, unknown>;
  http?: Record<string, unknown>;
  krb5?: Record<string, unknown>;
  ldap?: Record<string, unknown>;
  smb?: Record<string, unknown>;
  tls?: Record<string, unknown>;
}

export interface FieldDefinition {
  dbName: string;
  friendlyName: string;
  type: string;
  group: string;
  description?: string;
}

export interface SessionsResponse {
  data: Session[];
  recordsTotal: number;
  recordsFiltered: number;
}

export interface SessionsQuery {
  expression?: string;
  startTime?: number;
  endTime?: number;
  start?: number;
  length?: number;
  fields?: string[];
}

export interface FieldValue {
  field: string;
  value: string;
  count: number;
}

export interface SpiViewResponse {
  recordsTotal: number;
  recordsFiltered: number;
  items: FieldValue[];
}

export interface GetPacketParams {
  sessionId: string;
}

export function isSession(value: unknown): value is Session {
  if (typeof value !== 'object' || value === null) return false;
  const obj = value as Record<string, unknown>;
  return typeof obj.id === 'string' && typeof obj.lastPacket === 'number';
}

export function isFieldDefinition(value: unknown): value is FieldDefinition {
  if (typeof value !== 'object' || value === null) return false;
  const obj = value as Record<string, unknown>;
  return (
    typeof obj.dbName === 'string' &&
    typeof obj.friendlyName === 'string' &&
    typeof obj.type === 'string' &&
    typeof obj.group === 'string'
  );
}

export function isSessionsResponse(value: unknown): value is SessionsResponse {
  if (typeof value !== 'object' || value === null) return false;
  const obj = value as Record<string, unknown>;
  if (!Array.isArray(obj.data)) return false;
  if (typeof obj.recordsTotal !== 'number') return false;
  if (typeof obj.recordsFiltered !== 'number') return false;
  return obj.data.every(isSession);
}

export interface UniqueValue {
  value: string;
  count: number;
}

export interface UniqueResponse {
  success: boolean;
  totalInPeriod: number;
  totalOverall: number;
  value: UniqueValue[];
}

export interface ClusterNode {
  host: string;
  version: string;
  roles: string[];
  started: number;
  updated: number;
}

export interface ClusterResponse {
  success: boolean;
  viewerNodes: ClusterNode[];
  captureNodes: ClusterNode[];
}

export interface PcapFile {
  dateFirst: number;
  dateLast: number;
  filename: string;
  node: string;
  sessions: number;
  totalLen: number;
}

export interface FilesResponse {
  success: boolean;
  total: number;
  files: PcapFile[];
}

// Sessions summary
export interface SummaryBucket {
  key: string;
  count: number;
  sum?: number;
}

export interface SessionsSummaryResponse {
  success: boolean;
  histograms?: Record<string, SummaryBucket[]>;
  connections?: number;
  dataBytes?: number;
  packets?: number;
  sessions?: number;
  totDataBytes?: number;
}

// Reverse DNS
export interface ReverseDnsEntry {
  ip: string;
  name: string;
}

export interface ReverseDnsResponse {
  success: boolean;
  data: ReverseDnsEntry[];
}

// Multi-unique
export interface MultiUniqueResponse {
  success: boolean;
  [field: string]: UniqueValue[] | boolean;
}

// Connections (network graph)
export interface ConnectionNode {
  id: string;
  label: string;
  sessions: number;
  packets: number;
  bytes: number;
}

export interface ConnectionLink {
  source: string;
  target: string;
  sessions: number;
  packets: number;
  bytes: number;
}

export interface ConnectionsResponse {
  success: boolean;
  nodes: ConnectionNode[];
  links: ConnectionLink[];
}

// Session detail
export interface SessionDetailResponse {
  success: boolean;
  data: Record<string, unknown>;
}

// Hunt
export interface Hunt {
  id: string;
  name: string;
  expression: string;
  status: string;
  creator: string;
  matches: number;
  createdAt: number;
  updatedAt: number;
}

export interface HuntsResponse {
  success: boolean;
  hunts: Hunt[];
}

// View (saved search)
export interface View {
  id: string;
  name: string;
  expression: string;
  creator: string;
  shared?: boolean;
}

export interface ViewsResponse {
  success: boolean;
  views: View[];
}

// Shortcut (saved query)
export interface Shortcut {
  id: string;
  key: string;
  expression: string;
}

export interface ShortcutsResponse {
  success: boolean;
  shortcuts: Shortcut[];
}

// App info
export interface AppInfoResponse {
  success: boolean;
  viewsTotal?: number;
  viewCount?: number;
  clusters?: ClusterResponse;
  eshealth?: string;
  currentuser?: Record<string, unknown>;
}

// Stats
export interface NodeStat {
  host: string;
  roles: string[];
  packets: number;
  bytes: number;
  sessions: number;
  [key: string]: unknown;
}

export interface StatsResponse {
  success: boolean;
  stats: Record<string, NodeStat>;
}

// === Read-only endpoint responses ===
// Shapes vary across Arkime versions, so these are intentionally permissive;
// controllers format defensively and fall back to JSON for unknown fields.

// Generic list response shared by many endpoints ({ data: [...] }).
export interface ArkimeListResponse<T = Record<string, unknown>> {
  success?: boolean;
  data?: T[];
  recordsTotal?: number;
  recordsFiltered?: number;
  [key: string]: unknown;
}

// Analytics
export interface SpiGraphItem {
  name: string;
  count: number;
  [key: string]: unknown;
}

export interface SpiGraphResponse {
  success?: boolean;
  recordsTotal?: number;
  recordsFiltered?: number;
  items?: SpiGraphItem[];
  [key: string]: unknown;
}

export interface SpiGraphHierarchyResponse {
  success?: boolean;
  hierarchicalResults?: Record<string, unknown>;
  tableResults?: Array<Record<string, unknown>>;
  [key: string]: unknown;
}

export interface BuildQueryResponse {
  success?: boolean;
  esquery?: Record<string, unknown>;
  indices?: unknown;
  [key: string]: unknown;
}

export type DecodingsResponse = Record<string, Record<string, unknown>>;

// Metadata
export interface UserResponse {
  userId?: string;
  userName?: string;
  roles?: string[];
  [key: string]: unknown;
}

export interface UserRolesResponse {
  roles?: string[];
  [key: string]: unknown;
}

export interface RemoteClustersResponse {
  [cluster: string]: unknown;
}

// Cluster / ES health
export interface EsHealthResponse {
  status?: string;
  number_of_nodes?: number;
  number_of_data_nodes?: number;
  active_primary_shards?: number;
  active_shards?: number;
  relocating_shards?: number;
  initializing_shards?: number;
  unassigned_shards?: number;
  [key: string]: unknown;
}

export interface AppVersionResponse {
  version?: string;
  esVersion?: string;
  [key: string]: unknown;
}

// Session decoded packets
export interface SessionPacketsResponse {
  success?: boolean;
  packets?: Array<Record<string, unknown>>;
  [key: string]: unknown;
}
