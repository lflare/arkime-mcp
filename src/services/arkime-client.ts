import axios, { AxiosInstance } from 'axios';
import { createHash, randomBytes } from 'crypto';
import { McpError, ErrorCode } from '@/utils/errors.js';
import type { ArkimeConfig } from './config.js';
import type {
  SessionsQuery,
  SessionsResponse,
  Session,
  FieldDefinition,
  UniqueResponse,
  ClusterResponse,
  FilesResponse,
  SessionsSummaryResponse,
  ReverseDnsResponse,
  MultiUniqueResponse,
  ConnectionsResponse,
  SpiViewResponse,
  SessionDetailResponse,
  HuntsResponse,
  ViewsResponse,
  ShortcutsResponse,
  AppInfoResponse,
  StatsResponse,
  ArkimeListResponse,
  SpiGraphResponse,
  SpiGraphHierarchyResponse,
  BuildQueryResponse,
  DecodingsResponse,
  UserResponse,
  UserRolesResponse,
  RemoteClustersResponse,
  EsHealthResponse,
  AppVersionResponse,
  SessionPacketsResponse,
} from '@/types/arkime.js';

function md5(str: string): string {
  return createHash('md5').update(str).digest('hex');
}

export class ArkimeClient {
  static readonly MAX_AUTH_RETRIES = 2;

  private readonly axios: AxiosInstance;
  private readonly host: string;
  private readonly user: string;
  private readonly password: string;
  private nonce: string | null = null;
  private realm: string | null = null;
  private qop: string | null = null;
  private authRetries = 0;

  constructor(config: ArkimeConfig) {
    this.host = config.host.replace(/\/$/, '');
    this.user = config.user;
    this.password = config.password;

    this.axios = axios.create({
      baseURL: this.host,
      timeout: config.timeout,
      maxContentLength: 50 * 1024 * 1024,
      maxBodyLength: 50 * 1024 * 1024,
      headers: {
        'Accept': 'application/json',
      },
    });
  }

  private buildDigestAuth(method: string, uri: string): string {
    if (!this.nonce || !this.realm || !this.qop) {
      throw new Error('Digest auth not initialized');
    }

    const cnonce = randomBytes(16).toString('hex');
    const nc = '00000001';

    const ha1 = md5(`${this.user}:${this.realm}:${this.password}`);
    const ha2 = md5(`${method}:${uri}`);
    const response = md5(`${ha1}:${this.nonce}:${nc}:${cnonce}:${this.qop}:${ha2}`);

    return `Digest username="${this.user}", realm="${this.realm}", nonce="${this.nonce}", uri="${uri}", cnonce="${cnonce}", nc=${nc}, qop=${this.qop}, response="${response}"`;
  }

  private async request<T>(method: string, url: string, options?: { responseType?: 'arraybuffer' }): Promise<T> {
    const parsedUrl = new URL(url, this.host);
    const uri = parsedUrl.pathname + parsedUrl.search;
    const responseType = options?.responseType;

    if (!this.nonce) {
      try {
        let response;
        if (responseType === 'arraybuffer') {
          response = await this.axios.request({
            method,
            url,
            responseType,
          });
          return Buffer.from(response.data) as T;
        }
        response = await this.axios.request<T>({ method, url });
        return response.data as T;
      } catch (error) {
        if (axios.isAxiosError(error) && error.response?.status === 401) {
          const authHeader = error.response.headers['www-authenticate'] as string;
          if (!authHeader) throw error;

          const realmMatch = authHeader.match(/realm="([^"]+)"/);
          const nonceMatch = authHeader.match(/nonce="([^"]+)"/);
          const qopMatch = authHeader.match(/qop="([^"]+)"/);

          if (realmMatch) this.realm = realmMatch[1];
          if (nonceMatch) this.nonce = nonceMatch[1];
          if (qopMatch) this.qop = qopMatch[1];

          if (!this.nonce) throw error;
        } else {
          throw this.handleError(error);
        }
      }
    }

    const auth = this.buildDigestAuth(method, uri);
    try {
      if (responseType === 'arraybuffer') {
        const response = await this.axios.request({
          method,
          url,
          responseType,
          headers: { Authorization: auth },
        });
        this.authRetries = 0;
        return Buffer.from(response.data) as T;
      }
      const response = await this.axios.request<T>({
        method,
        url,
        headers: { Authorization: auth },
      });
      this.authRetries = 0;
      return response.data as T;
    } catch (error) {
      if (axios.isAxiosError(error) && error.response?.status === 401) {
        this.authRetries++;
        if (this.authRetries > ArkimeClient.MAX_AUTH_RETRIES) {
          throw new McpError(ErrorCode.AUTH_INVALID, 'Authentication retry limit exceeded');
        }
        this.nonce = null;
        return this.request<T>(method, url, options);
      }
      throw this.handleError(error);
    }
  }

  async searchSessions(query: SessionsQuery): Promise<SessionsResponse> {
    const params = new URLSearchParams();
    params.set('date', '1440');

    if (query.expression) {
      params.set('expression', query.expression);
    }

    if (query.startTime) {
      params.set('startTime', String(query.startTime));
      params.delete('date');
    }

    if (query.endTime) {
      // Arkime's API parameter is named `stopTime`, not `endTime`.
      params.set('stopTime', String(query.endTime));
      params.delete('date');
    }

    if (query.start !== undefined) {
      params.set('start', String(query.start));
    }

    if (query.length !== undefined) {
      params.set('length', String(query.length));
    }

    if (query.fields && query.fields.length > 0) {
      params.set('fields', query.fields.join(','));
    }

    return this.request<SessionsResponse>('GET', `/api/sessions?${params.toString()}`);
  }

  async getSession(id: string): Promise<Session> {
    const encodedId = encodeURIComponent(id);
    const params = new URLSearchParams();
    params.set('expression', `id==${encodedId}`);
    params.set('length', '1');
    // Search all time; without this, Arkime defaults to a ~1h window and
    // returns nothing for historical sessions.
    params.set('date', '-1');

    const response = await this.request<SessionsResponse>('GET', `/api/sessions?${params.toString()}`);
    
    if (response.data.length === 0) {
      throw new McpError(ErrorCode.NOT_FOUND, `Session not found: ${id}`);
    }
    
    return response.data[0];
  }

  async getFields(): Promise<FieldDefinition[]> {
    const response = await this.request<Record<string, Omit<FieldDefinition, 'dbName'>>>('GET', '/api/fields');
    return Object.entries(response).map(([dbName, field]) => ({
      dbName,
      ...field,
    }));
  }

  async getPcap(url: string): Promise<Buffer> {
    return this.request<Buffer>('GET', url, { responseType: 'arraybuffer' });
  }

  async getUniqueField(field: string, options?: {
    expression?: string;
    date?: number;
    limit?: number;
    counts?: boolean;
  }): Promise<UniqueResponse> {
    const params = new URLSearchParams();
    params.set('counts', options?.counts ? '1' : '0');
    if (options?.expression) params.set('expression', options.expression);
    if (options?.date !== undefined) params.set('date', String(options.date));
    if (options?.limit) params.set('limit', String(options.limit));
    return this.request<UniqueResponse>('GET', `/api/unique/${encodeURIComponent(field)}?${params}`);
  }

  async getClusters(): Promise<ClusterResponse> {
    return this.request<ClusterResponse>('GET', '/api/clusters');
  }

  async getFiles(options?: {
    limit?: number;
    offset?: number;
    sort?: string;
    order?: string;
  }): Promise<FilesResponse> {
    const params = new URLSearchParams();
    if (options?.limit) params.set('limit', String(options.limit));
    if (options?.offset) params.set('offset', String(options.offset));
    if (options?.sort) params.set('sort', options.sort);
    if (options?.order) params.set('order', options.order);
    const url = params.toString() ? `/api/files?${params}` : '/api/files';
    return this.request<FilesResponse>('GET', url);
  }

  async getSessionsSummary(options?: {
    expression?: string;
    date?: number;
    field?: string;
    buckets?: number;
  }): Promise<SessionsSummaryResponse> {
    const params = new URLSearchParams();
    if (options?.expression) params.set('expression', options.expression);
    if (options?.date !== undefined) params.set('date', String(options.date));
    if (options?.field) params.set('field', options.field);
    if (options?.buckets) params.set('buckets', String(options.buckets));
    const url = params.toString() ? `/api/sessions/summary?${params}` : '/api/sessions/summary';
    return this.request<SessionsSummaryResponse>('GET', url);
  }

  async getReversedns(ip: string): Promise<ReverseDnsResponse> {
    return this.request<ReverseDnsResponse>('GET', `/api/reversedns?ip=${encodeURIComponent(ip)}`);
  }

  async getMultiUnique(fields: string[], options?: {
    expression?: string;
    date?: number;
    limit?: number;
  }): Promise<MultiUniqueResponse> {
    const params = new URLSearchParams();
    params.set('fields', fields.join(','));
    if (options?.expression) params.set('expression', options.expression);
    if (options?.date !== undefined) params.set('date', String(options.date));
    if (options?.limit) params.set('limit', String(options.limit));
    return this.request<MultiUniqueResponse>('GET', `/api/multiunique?${params}`);
  }

  async getConnections(options?: {
    expression?: string;
    date?: number;
    limit?: number;
  }): Promise<ConnectionsResponse> {
    const params = new URLSearchParams();
    if (options?.expression) params.set('expression', options.expression);
    if (options?.date !== undefined) params.set('date', String(options.date));
    if (options?.limit) params.set('limit', String(options.limit));
    const url = params.toString() ? `/api/connections?${params}` : '/api/connections';
    return this.request<ConnectionsResponse>('GET', url);
  }

  async getSpiview(options?: {
    expression?: string;
    fields?: string[];
    limit?: number;
  }): Promise<SpiViewResponse> {
    const params = new URLSearchParams();
    if (options?.expression) params.set('expression', options.expression);
    if (options?.fields?.length) params.set('fields', options.fields.join(','));
    if (options?.limit) params.set('limit', String(options.limit));
    const url = params.toString() ? `/api/spiview?${params}` : '/api/spiview';
    return this.request<SpiViewResponse>('GET', url);
  }

  async getSessionDetail(nodeId: string, sessionId: string): Promise<SessionDetailResponse> {
    return this.request<SessionDetailResponse>('GET', `/api/session/${encodeURIComponent(nodeId)}/${encodeURIComponent(sessionId)}/detail`);
  }

  async getSessionBody(nodeId: string, sessionId: string, bodyType: string, bodyNum: number, bodyName: string): Promise<Buffer> {
    return this.getPcap(`/api/session/${encodeURIComponent(nodeId)}/${encodeURIComponent(sessionId)}/body/${bodyType}/${bodyNum}/${encodeURIComponent(bodyName)}`);
  }

  async getSessionBodyHash(nodeId: string, sessionId: string, hash: string): Promise<Buffer> {
    return this.getPcap(`/api/session/${encodeURIComponent(nodeId)}/${encodeURIComponent(sessionId)}/bodyhash/${encodeURIComponent(hash)}`);
  }

  async getSessionEntirePcap(nodeId: string, sessionId: string): Promise<Buffer> {
    return this.getPcap(`/api/session/entire/${encodeURIComponent(nodeId)}/${encodeURIComponent(sessionId)}/pcap`);
  }

  async getSessionRaw(nodeId: string, sessionId: string): Promise<Buffer> {
    return this.getPcap(`/api/session/raw/${encodeURIComponent(nodeId)}/${encodeURIComponent(sessionId)}`);
  }

  async getHunts(): Promise<HuntsResponse> {
    return this.request<HuntsResponse>('GET', '/api/hunts');
  }

  async getViews(): Promise<ViewsResponse> {
    return this.request<ViewsResponse>('GET', '/api/views');
  }

  async getShortcuts(): Promise<ShortcutsResponse> {
    return this.request<ShortcutsResponse>('GET', '/api/shortcuts');
  }

  async getAppInfo(): Promise<AppInfoResponse> {
    return this.request<AppInfoResponse>('GET', '/api/appinfo');
  }

  async getStats(): Promise<StatsResponse> {
    return this.request<StatsResponse>('GET', '/api/stats');
  }

  // --- analytics ---

  async getSpiGraph(field: string, options?: {
    expression?: string;
    date?: number;
    size?: number;
  }): Promise<SpiGraphResponse> {
    const params = new URLSearchParams();
    params.set('field', field);
    if (options?.expression) params.set('expression', options.expression);
    if (options?.date !== undefined) params.set('date', String(options.date));
    if (options?.size) params.set('size', String(options.size));
    return this.request<SpiGraphResponse>('GET', `/api/spigraph?${params}`);
  }

  async getSpiGraphHierarchy(exp: string, options?: {
    expression?: string;
    date?: number;
  }): Promise<SpiGraphHierarchyResponse> {
    const params = new URLSearchParams();
    params.set('exp', exp);
    if (options?.expression) params.set('expression', options.expression);
    if (options?.date !== undefined) params.set('date', String(options.date));
    return this.request<SpiGraphHierarchyResponse>('GET', `/api/spigraphhierarchy?${params}`);
  }

  async getBuildQuery(options: {
    expression: string;
    date?: number;
  }): Promise<BuildQueryResponse> {
    const params = new URLSearchParams();
    params.set('expression', options.expression);
    if (options.date !== undefined) params.set('date', String(options.date));
    return this.request<BuildQueryResponse>('GET', `/api/buildquery?${params}`);
  }

  async getDecodings(): Promise<DecodingsResponse> {
    return this.request<DecodingsResponse>('GET', '/api/sessions/decodings');
  }

  // --- metadata ---

  async getCrons(): Promise<ArkimeListResponse> {
    return this.request<ArkimeListResponse>('GET', '/api/crons');
  }

  async getNotifiers(): Promise<ArkimeListResponse> {
    return this.request<ArkimeListResponse>('GET', '/api/notifiers');
  }

  async getShareables(): Promise<ArkimeListResponse> {
    return this.request<ArkimeListResponse>('GET', '/api/shareables');
  }

  async getHistories(options?: { length?: number }): Promise<ArkimeListResponse> {
    const params = new URLSearchParams();
    if (options?.length) params.set('length', String(options.length));
    const url = params.toString() ? `/api/histories?${params}` : '/api/histories';
    return this.request<ArkimeListResponse>('GET', url);
  }

  async getRemoteClusters(): Promise<RemoteClustersResponse> {
    return this.request<RemoteClustersResponse>('GET', '/api/remoteclusters');
  }

  async getCurrentUser(): Promise<UserResponse> {
    return this.request<UserResponse>('GET', '/api/user');
  }

  async getUserRoles(): Promise<UserRolesResponse> {
    return this.request<UserRolesResponse>('GET', '/api/user/roles');
  }

  async getValueActions(): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>('GET', '/api/valueactions');
  }

  async getFieldActions(): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>('GET', '/api/fieldactions');
  }

  // --- ES / cluster health ---

  async getEsHealth(): Promise<EsHealthResponse> {
    return this.request<EsHealthResponse>('GET', '/api/eshealth');
  }

  async getEsStats(): Promise<ArkimeListResponse> {
    return this.request<ArkimeListResponse>('GET', '/api/esstats');
  }

  async getEsIndices(): Promise<ArkimeListResponse> {
    return this.request<ArkimeListResponse>('GET', '/api/esindices');
  }

  async getEsShards(): Promise<ArkimeListResponse> {
    return this.request<ArkimeListResponse>('GET', '/api/esshards');
  }

  async getEsTasks(): Promise<ArkimeListResponse> {
    return this.request<ArkimeListResponse>('GET', '/api/estasks');
  }

  async getEsRecovery(): Promise<ArkimeListResponse> {
    return this.request<ArkimeListResponse>('GET', '/api/esrecovery');
  }

  async getDstats(options?: {
    nodeName?: string;
    start?: number;
    stop?: number;
    interval?: number;
    name?: string;
  }): Promise<unknown> {
    const params = new URLSearchParams();
    params.set('nodeName', options?.nodeName ?? 'ALL');
    if (options?.start !== undefined) params.set('start', String(options.start));
    if (options?.stop !== undefined) params.set('stop', String(options.stop));
    if (options?.interval !== undefined) params.set('interval', String(options.interval));
    if (options?.name) params.set('name', options.name);
    return this.request<unknown>('GET', `/api/dstats?${params}`);
  }

  async getAppVersion(): Promise<AppVersionResponse> {
    return this.request<AppVersionResponse>('GET', '/api/appversion');
  }

  // --- session decoded packets ---

  async getSessionPackets(nodeId: string, sessionId: string): Promise<SessionPacketsResponse> {
    return this.request<SessionPacketsResponse>(
      'GET',
      `/api/session/${encodeURIComponent(nodeId)}/${encodeURIComponent(sessionId)}/packets`
    );
  }

  private handleError(error: unknown): McpError {
    if (axios.isAxiosError(error)) {
      if (!error.response) {
        return new McpError(
          ErrorCode.NETWORK_ERROR,
          `Network error: ${error.message}`
        );
      }

      const { status, statusText } = error.response;

      if (status === 401) {
        return new McpError(
          ErrorCode.AUTH_INVALID,
          `Authentication failed: ${status} ${statusText}`
        );
      }

      if (status === 404) {
        return new McpError(
          ErrorCode.NOT_FOUND,
          `Resource not found: ${status} ${statusText}`
        );
      }

      return new McpError(
        ErrorCode.API_ERROR,
        `Arkime API error: ${status} ${statusText}`
      );
    }

    if (error instanceof Error) {
      return new McpError(ErrorCode.API_ERROR, error.message);
    }

    return new McpError(ErrorCode.API_ERROR, 'Unknown error occurred');
  }
}
