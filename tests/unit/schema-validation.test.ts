import { describe, it, expect } from 'vitest';
import {
  searchSessionsSchema,
  getSessionSchema,
  listFieldsSchema,
  analyzeTrafficSchema,
  huntSuspiciousSchema,
  getPcapSchema,
  getPacketSchema,
  getFlowSchema,
  getSessionSpiSchema,
  investigateNtlmSchema,
  buildTimelineSchema,
  trackMovementSchema,
  extractIocsSchema,
  topTalkersSchema,
  reverseDnsSchema,
  dnsLookupsSchema,
  geoSummarySchema,
  captureStatusSchema,
  huntListSchema,
  viewListSchema,
  shortcutListSchema,
  appInfoSchema,
  nodeStatsSchema,
  pcapFilesSchema,
  sessionsSummarySchema,
  multiUniqueSchema,
  connectionsSchema,
  spiSessionsSchema,
  sessionDetailSchema,
  sessionFileSchema,
} from '@/tools/schemas';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Produce a string longer than the 10,000-char expression limit. */
function overMaxExpression(): string {
  return 'x'.repeat(10001);
}

/** A valid ISO 8601 datetime string. */
const VALID_DATE = '2025-01-01T00:00:00Z';

/** An invalid datetime string. */
const INVALID_DATE = 'not-a-date';

// ---------------------------------------------------------------------------
// searchSessionsSchema
// ---------------------------------------------------------------------------

describe('searchSessionsSchema', () => {
  it('should accept valid input', () => {
    const result = searchSessionsSchema.safeParse({
      expression: 'ip.src == 192.168.1.1',
      limit: 50,
    });
    expect(result.success).toBe(true);
  });

  it('should reject expression over 10000 chars', () => {
    const result = searchSessionsSchema.safeParse({
      expression: overMaxExpression(),
    });
    expect(result.success).toBe(false);
  });

  it('should reject negative limit', () => {
    const result = searchSessionsSchema.safeParse({
      limit: -1,
    });
    expect(result.success).toBe(false);
  });

  it('should reject limit above 1000', () => {
    const result = searchSessionsSchema.safeParse({
      limit: 1001,
    });
    expect(result.success).toBe(false);
  });

  it('should reject invalid datetime for startTime', () => {
    const result = searchSessionsSchema.safeParse({
      startTime: INVALID_DATE,
    });
    expect(result.success).toBe(false);
  });

  it('should reject invalid datetime for endTime', () => {
    const result = searchSessionsSchema.safeParse({
      endTime: INVALID_DATE,
    });
    expect(result.success).toBe(false);
  });

  it('should apply default limit of 100', () => {
    const result = searchSessionsSchema.parse({});
    expect(result.limit).toBe(100);
  });

  it('should accept empty object with defaults', () => {
    const result = searchSessionsSchema.safeParse({});
    expect(result.success).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// getSessionSchema
// ---------------------------------------------------------------------------

describe('getSessionSchema', () => {
  it('should accept valid session id', () => {
    const result = getSessionSchema.safeParse({
      id: '260127-GwFt1w7eKJREbKdq8VYTsuEk',
    });
    expect(result.success).toBe(true);
  });

  it('should reject empty id', () => {
    const result = getSessionSchema.safeParse({
      id: '',
    });
    expect(result.success).toBe(false);
  });

  it('should reject missing id', () => {
    const result = getSessionSchema.safeParse({});
    expect(result.success).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// listFieldsSchema
// ---------------------------------------------------------------------------

describe('listFieldsSchema', () => {
  it('should accept valid group', () => {
    const result = listFieldsSchema.safeParse({
      group: 'general',
    });
    expect(result.success).toBe(true);
  });

  it('should accept empty object (all fields optional)', () => {
    const result = listFieldsSchema.safeParse({});
    expect(result.success).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// analyzeTrafficSchema
// ---------------------------------------------------------------------------

describe('analyzeTrafficSchema', () => {
  it('should accept valid input', () => {
    const result = analyzeTrafficSchema.safeParse({
      expression: 'ip.src == 10.0.0.1',
      analysisType: 'protocols',
      limit: 50,
      startTime: VALID_DATE,
      endTime: VALID_DATE,
    });
    expect(result.success).toBe(true);
  });

  it('should reject expression over 10000 chars', () => {
    const result = analyzeTrafficSchema.safeParse({
      expression: overMaxExpression(),
    });
    expect(result.success).toBe(false);
  });

  it('should reject invalid enum for analysisType', () => {
    const result = analyzeTrafficSchema.safeParse({
      analysisType: 'invalid-type',
    });
    expect(result.success).toBe(false);
  });

  it('should reject negative limit', () => {
    const result = analyzeTrafficSchema.safeParse({
      limit: -5,
    });
    expect(result.success).toBe(false);
  });

  it('should reject limit above 500', () => {
    const result = analyzeTrafficSchema.safeParse({
      limit: 501,
    });
    expect(result.success).toBe(false);
  });

  it('should reject invalid datetime', () => {
    const result = analyzeTrafficSchema.safeParse({
      startTime: INVALID_DATE,
    });
    expect(result.success).toBe(false);
  });

  it('should apply default analysisType of top-talkers', () => {
    const result = analyzeTrafficSchema.parse({});
    expect(result.analysisType).toBe('top-talkers');
  });

  it('should apply default limit of 100', () => {
    const result = analyzeTrafficSchema.parse({});
    expect(result.limit).toBe(100);
  });

  it('should accept empty object with defaults', () => {
    const result = analyzeTrafficSchema.safeParse({});
    expect(result.success).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// huntSuspiciousSchema
// ---------------------------------------------------------------------------

describe('huntSuspiciousSchema', () => {
  it('should accept valid input', () => {
    const result = huntSuspiciousSchema.safeParse({
      huntType: 'port-scanners',
    });
    expect(result.success).toBe(true);
  });

  it('should reject invalid enum for huntType', () => {
    const result = huntSuspiciousSchema.safeParse({
      huntType: 'malware',
    });
    expect(result.success).toBe(false);
  });

  it('should reject expression over 10000 chars', () => {
    const result = huntSuspiciousSchema.safeParse({
      huntType: 'beaconing',
      expression: overMaxExpression(),
    });
    expect(result.success).toBe(false);
  });

  it('should reject negative threshold', () => {
    const result = huntSuspiciousSchema.safeParse({
      huntType: 'data-exfil',
      threshold: -1,
    });
    expect(result.success).toBe(false);
  });

  it('should reject threshold above 10000', () => {
    const result = huntSuspiciousSchema.safeParse({
      huntType: 'lateral-movement',
      threshold: 10001,
    });
    expect(result.success).toBe(false);
  });

  it('should reject missing required huntType', () => {
    const result = huntSuspiciousSchema.safeParse({});
    expect(result.success).toBe(false);
  });

  it('should apply default threshold of 100', () => {
    const result = huntSuspiciousSchema.parse({
      huntType: 'port-scanners',
    });
    expect(result.threshold).toBe(100);
  });
});

// ---------------------------------------------------------------------------
// getPcapSchema
// ---------------------------------------------------------------------------

describe('getPcapSchema', () => {
  it('should accept valid input', () => {
    const result = getPcapSchema.safeParse({
      expression: 'ip.src == 192.168.1.1',
      startTime: VALID_DATE,
      endTime: VALID_DATE,
      maxBytes: 500000,
    });
    expect(result.success).toBe(true);
  });

  it('should reject expression over 10000 chars', () => {
    const result = getPcapSchema.safeParse({
      expression: overMaxExpression(),
    });
    expect(result.success).toBe(false);
  });

  it('should reject missing required expression', () => {
    const result = getPcapSchema.safeParse({});
    expect(result.success).toBe(false);
  });

  it('should reject invalid datetime for startTime', () => {
    const result = getPcapSchema.safeParse({
      expression: 'ip.src == 1.2.3.4',
      startTime: INVALID_DATE,
    });
    expect(result.success).toBe(false);
  });

  it('should reject invalid datetime for endTime', () => {
    const result = getPcapSchema.safeParse({
      expression: 'ip.src == 1.2.3.4',
      endTime: INVALID_DATE,
    });
    expect(result.success).toBe(false);
  });

  it('should reject maxBytes below 1', () => {
    const result = getPcapSchema.safeParse({
      expression: 'ip.src == 1.2.3.4',
      maxBytes: 0,
    });
    expect(result.success).toBe(false);
  });

  it('should reject maxBytes above 10000000', () => {
    const result = getPcapSchema.safeParse({
      expression: 'ip.src == 1.2.3.4',
      maxBytes: 10000001,
    });
    expect(result.success).toBe(false);
  });

  it('should apply default maxBytes of 1000000', () => {
    const result = getPcapSchema.parse({
      expression: 'ip.src == 1.2.3.4',
    });
    expect(result.maxBytes).toBe(1000000);
  });
});

// ---------------------------------------------------------------------------
// getPacketSchema
// ---------------------------------------------------------------------------

describe('getPacketSchema', () => {
  it('should accept valid session id', () => {
    const result = getPacketSchema.safeParse({
      sessionId: 'BE65AZ49KusloBKxl',
    });
    expect(result.success).toBe(true);
  });

  it('should reject empty sessionId', () => {
    const result = getPacketSchema.safeParse({
      sessionId: '',
    });
    expect(result.success).toBe(false);
  });

  it('should reject missing sessionId', () => {
    const result = getPacketSchema.safeParse({});
    expect(result.success).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// getFlowSchema
// ---------------------------------------------------------------------------

describe('getFlowSchema', () => {
  it('should accept valid input', () => {
    const result = getFlowSchema.safeParse({
      sourceIp: '192.168.1.1',
      destIp: '10.0.0.1',
      destPort: 445,
      protocol: 'tcp',
    });
    expect(result.success).toBe(true);
  });

  it('should reject invalid IPv4 in sourceIp', () => {
    const result = getFlowSchema.safeParse({
      sourceIp: 'not-an-ip',
      destIp: '10.0.0.1',
    });
    expect(result.success).toBe(false);
  });

  it('should reject invalid IPv4 in destIp', () => {
    const result = getFlowSchema.safeParse({
      sourceIp: '192.168.1.1',
      destIp: 'invalid',
    });
    expect(result.success).toBe(false);
  });

  it('should reject missing required sourceIp', () => {
    const result = getFlowSchema.safeParse({
      destIp: '10.0.0.1',
    });
    expect(result.success).toBe(false);
  });

  it('should reject missing required destIp', () => {
    const result = getFlowSchema.safeParse({
      sourceIp: '192.168.1.1',
    });
    expect(result.success).toBe(false);
  });

  it('should reject invalid enum for protocol', () => {
    const result = getFlowSchema.safeParse({
      sourceIp: '192.168.1.1',
      destIp: '10.0.0.1',
      protocol: 'icmp',
    });
    expect(result.success).toBe(false);
  });

  it('should reject sourcePort above 65535', () => {
    const result = getFlowSchema.safeParse({
      sourceIp: '192.168.1.1',
      destIp: '10.0.0.1',
      sourcePort: 65536,
    });
    expect(result.success).toBe(false);
  });

  it('should reject destPort below 0', () => {
    const result = getFlowSchema.safeParse({
      sourceIp: '192.168.1.1',
      destIp: '10.0.0.1',
      destPort: -1,
    });
    expect(result.success).toBe(false);
  });

  it('should reject invalid datetime', () => {
    const result = getFlowSchema.safeParse({
      sourceIp: '192.168.1.1',
      destIp: '10.0.0.1',
      startTime: INVALID_DATE,
    });
    expect(result.success).toBe(false);
  });

  it('should reject maxBytes below 1', () => {
    const result = getFlowSchema.safeParse({
      sourceIp: '192.168.1.1',
      destIp: '10.0.0.1',
      maxBytes: 0,
    });
    expect(result.success).toBe(false);
  });

  it('should apply default protocol of any', () => {
    const result = getFlowSchema.parse({
      sourceIp: '192.168.1.1',
      destIp: '10.0.0.1',
    });
    expect(result.protocol).toBe('any');
  });

  it('should apply default maxBytes of 10000000', () => {
    const result = getFlowSchema.parse({
      sourceIp: '192.168.1.1',
      destIp: '10.0.0.1',
    });
    expect(result.maxBytes).toBe(10000000);
  });
});

// ---------------------------------------------------------------------------
// getSessionSpiSchema
// ---------------------------------------------------------------------------

describe('getSessionSpiSchema', () => {
  it('should accept valid input', () => {
    const result = getSessionSpiSchema.safeParse({
      expression: 'dns.host contains microsoft',
      categories: ['dns', 'http'],
      limit: 5,
    });
    expect(result.success).toBe(true);
  });

  it('should reject expression over 10000 chars', () => {
    const result = getSessionSpiSchema.safeParse({
      expression: overMaxExpression(),
    });
    expect(result.success).toBe(false);
  });

  it('should reject missing required expression', () => {
    const result = getSessionSpiSchema.safeParse({});
    expect(result.success).toBe(false);
  });

  it('should reject invalid enum in categories', () => {
    const result = getSessionSpiSchema.safeParse({
      expression: 'ip.src == 1.2.3.4',
      categories: ['invalid-cat'],
    });
    expect(result.success).toBe(false);
  });

  it('should reject limit below 1', () => {
    const result = getSessionSpiSchema.safeParse({
      expression: 'ip.src == 1.2.3.4',
      limit: 0,
    });
    expect(result.success).toBe(false);
  });

  it('should reject limit above 50', () => {
    const result = getSessionSpiSchema.safeParse({
      expression: 'ip.src == 1.2.3.4',
      limit: 51,
    });
    expect(result.success).toBe(false);
  });

  it('should apply default categories of all', () => {
    const result = getSessionSpiSchema.parse({
      expression: 'ip.src == 1.2.3.4',
    });
    expect(result.categories).toEqual(['all']);
  });

  it('should apply default limit of 10', () => {
    const result = getSessionSpiSchema.parse({
      expression: 'ip.src == 1.2.3.4',
    });
    expect(result.limit).toBe(10);
  });
});

// ---------------------------------------------------------------------------
// investigateNtlmSchema
// ---------------------------------------------------------------------------

describe('investigateNtlmSchema', () => {
  it('should accept valid input', () => {
    const result = investigateNtlmSchema.safeParse({
      suspectIp: '10.0.0.1',
      suspectUser: 'admin',
      expression: 'ntlm.domain == CORP',
    });
    expect(result.success).toBe(true);
  });

  it('should reject expression over 10000 chars', () => {
    const result = investigateNtlmSchema.safeParse({
      expression: overMaxExpression(),
    });
    expect(result.success).toBe(false);
  });

  it('should accept empty object (all fields optional)', () => {
    const result = investigateNtlmSchema.safeParse({});
    expect(result.success).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// buildTimelineSchema
// ---------------------------------------------------------------------------

describe('buildTimelineSchema', () => {
  it('should accept valid input', () => {
    const result = buildTimelineSchema.safeParse({
      suspectIp: '10.0.0.1',
      startTime: VALID_DATE,
      endTime: VALID_DATE,
    });
    expect(result.success).toBe(true);
  });

  it('should reject invalid datetime for startTime', () => {
    const result = buildTimelineSchema.safeParse({
      startTime: INVALID_DATE,
    });
    expect(result.success).toBe(false);
  });

  it('should reject invalid datetime for endTime', () => {
    const result = buildTimelineSchema.safeParse({
      endTime: INVALID_DATE,
    });
    expect(result.success).toBe(false);
  });

  it('should accept empty object (all fields optional)', () => {
    const result = buildTimelineSchema.safeParse({});
    expect(result.success).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// trackMovementSchema
// ---------------------------------------------------------------------------

describe('trackMovementSchema', () => {
  it('should accept valid input', () => {
    const result = trackMovementSchema.safeParse({
      sourceIp: '10.0.0.1',
      protocols: ['smb', 'ssh'],
      minConnections: 5,
    });
    expect(result.success).toBe(true);
  });

  it('should reject invalid enum in protocols', () => {
    const result = trackMovementSchema.safeParse({
      protocols: ['http'],
    });
    expect(result.success).toBe(false);
  });

  it('should reject minConnections below 1', () => {
    const result = trackMovementSchema.safeParse({
      minConnections: 0,
    });
    expect(result.success).toBe(false);
  });

  it('should reject minConnections above 100', () => {
    const result = trackMovementSchema.safeParse({
      minConnections: 101,
    });
    expect(result.success).toBe(false);
  });

  it('should apply default protocols', () => {
    const result = trackMovementSchema.parse({});
    expect(result.protocols).toEqual(['smb', 'ldap', 'rdp', 'winrm']);
  });

  it('should apply default minConnections of 2', () => {
    const result = trackMovementSchema.parse({});
    expect(result.minConnections).toBe(2);
  });

  it('should accept empty object with defaults', () => {
    const result = trackMovementSchema.safeParse({});
    expect(result.success).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// extractIocsSchema
// ---------------------------------------------------------------------------

describe('extractIocsSchema', () => {
  it('should accept valid input', () => {
    const result = extractIocsSchema.safeParse({
      expression: 'ip.src == 1.2.3.4',
      iocTypes: ['ip', 'domain'],
    });
    expect(result.success).toBe(true);
  });

  it('should reject expression over 10000 chars', () => {
    const result = extractIocsSchema.safeParse({
      expression: overMaxExpression(),
    });
    expect(result.success).toBe(false);
  });

  it('should reject missing required expression', () => {
    const result = extractIocsSchema.safeParse({});
    expect(result.success).toBe(false);
  });

  it('should reject invalid enum in iocTypes', () => {
    const result = extractIocsSchema.safeParse({
      expression: 'ip.src == 1.2.3.4',
      iocTypes: ['phone'],
    });
    expect(result.success).toBe(false);
  });

  it('should apply default iocTypes', () => {
    const result = extractIocsSchema.parse({
      expression: 'ip.src == 1.2.3.4',
    });
    expect(result.iocTypes).toEqual(['ip', 'domain', 'url', 'hash']);
  });
});

// ---------------------------------------------------------------------------
// topTalkersSchema
// ---------------------------------------------------------------------------

describe('topTalkersSchema', () => {
  it('should accept valid input', () => {
    const result = topTalkersSchema.safeParse({
      field: 'sourceIP',
      expression: 'ip.src == 10.0.0.1',
      limit: 50,
    });
    expect(result.success).toBe(true);
  });

  it('should reject empty field', () => {
    const result = topTalkersSchema.safeParse({
      field: '',
    });
    expect(result.success).toBe(false);
  });

  it('should reject missing required field', () => {
    const result = topTalkersSchema.safeParse({});
    expect(result.success).toBe(false);
  });

  it('should reject expression over 10000 chars', () => {
    const result = topTalkersSchema.safeParse({
      field: 'sourceIP',
      expression: overMaxExpression(),
    });
    expect(result.success).toBe(false);
  });

  it('should reject limit below 1', () => {
    const result = topTalkersSchema.safeParse({
      field: 'sourceIP',
      limit: 0,
    });
    expect(result.success).toBe(false);
  });

  it('should reject limit above 1000', () => {
    const result = topTalkersSchema.safeParse({
      field: 'sourceIP',
      limit: 1001,
    });
    expect(result.success).toBe(false);
  });

  it('should apply default limit of 100', () => {
    const result = topTalkersSchema.parse({
      field: 'sourceIP',
    });
    expect(result.limit).toBe(100);
  });
});

// ---------------------------------------------------------------------------
// reverseDnsSchema
// ---------------------------------------------------------------------------

describe('reverseDnsSchema', () => {
  it('should accept valid input', () => {
    const result = reverseDnsSchema.safeParse({
      ipAddress: '10.0.0.1',
    });
    expect(result.success).toBe(true);
  });

  it('should reject empty ipAddress', () => {
    const result = reverseDnsSchema.safeParse({
      ipAddress: '',
    });
    expect(result.success).toBe(false);
  });

  it('should reject missing ipAddress', () => {
    const result = reverseDnsSchema.safeParse({});
    expect(result.success).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// dnsLookupsSchema
// ---------------------------------------------------------------------------

describe('dnsLookupsSchema', () => {
  it('should accept valid input', () => {
    const result = dnsLookupsSchema.safeParse({
      domainPattern: 'example.com',
      sourceIp: '10.0.0.1',
      limit: 50,
    });
    expect(result.success).toBe(true);
  });

  it('should reject limit below 1', () => {
    const result = dnsLookupsSchema.safeParse({
      limit: 0,
    });
    expect(result.success).toBe(false);
  });

  it('should reject limit above 1000', () => {
    const result = dnsLookupsSchema.safeParse({
      limit: 1001,
    });
    expect(result.success).toBe(false);
  });

  it('should apply default limit of 200', () => {
    const result = dnsLookupsSchema.parse({});
    expect(result.limit).toBe(200);
  });

  it('should accept empty object with defaults', () => {
    const result = dnsLookupsSchema.safeParse({});
    expect(result.success).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// geoSummarySchema
// ---------------------------------------------------------------------------

describe('geoSummarySchema', () => {
  it('should accept valid input', () => {
    const result = geoSummarySchema.safeParse({
      expression: 'ip.src == 1.2.3.4',
      limit: 25,
    });
    expect(result.success).toBe(true);
  });

  it('should reject expression over 10000 chars', () => {
    const result = geoSummarySchema.safeParse({
      expression: overMaxExpression(),
    });
    expect(result.success).toBe(false);
  });

  it('should reject limit below 1', () => {
    const result = geoSummarySchema.safeParse({
      limit: 0,
    });
    expect(result.success).toBe(false);
  });

  it('should reject limit above 250', () => {
    const result = geoSummarySchema.safeParse({
      limit: 251,
    });
    expect(result.success).toBe(false);
  });

  it('should apply default limit of 50', () => {
    const result = geoSummarySchema.parse({});
    expect(result.limit).toBe(50);
  });

  it('should accept empty object with defaults', () => {
    const result = geoSummarySchema.safeParse({});
    expect(result.success).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// captureStatusSchema (empty schema)
// ---------------------------------------------------------------------------

describe('captureStatusSchema', () => {
  it('should accept empty object', () => {
    const result = captureStatusSchema.safeParse({});
    expect(result.success).toBe(true);
  });

  it('should accept extra fields (passthrough by default)', () => {
    const result = captureStatusSchema.safeParse({ foo: 'bar' });
    expect(result.success).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// huntListSchema (empty schema)
// ---------------------------------------------------------------------------

describe('huntListSchema', () => {
  it('should accept empty object', () => {
    const result = huntListSchema.safeParse({});
    expect(result.success).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// viewListSchema (empty schema)
// ---------------------------------------------------------------------------

describe('viewListSchema', () => {
  it('should accept empty object', () => {
    const result = viewListSchema.safeParse({});
    expect(result.success).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// shortcutListSchema (empty schema)
// ---------------------------------------------------------------------------

describe('shortcutListSchema', () => {
  it('should accept empty object', () => {
    const result = shortcutListSchema.safeParse({});
    expect(result.success).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// appInfoSchema (empty schema)
// ---------------------------------------------------------------------------

describe('appInfoSchema', () => {
  it('should accept empty object', () => {
    const result = appInfoSchema.safeParse({});
    expect(result.success).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// nodeStatsSchema (empty schema)
// ---------------------------------------------------------------------------

describe('nodeStatsSchema', () => {
  it('should accept empty object', () => {
    const result = nodeStatsSchema.safeParse({});
    expect(result.success).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// pcapFilesSchema
// ---------------------------------------------------------------------------

describe('pcapFilesSchema', () => {
  it('should accept valid input', () => {
    const result = pcapFilesSchema.safeParse({
      limit: 50,
      sort: 'filename',
    });
    expect(result.success).toBe(true);
  });

  it('should reject invalid enum for sort', () => {
    const result = pcapFilesSchema.safeParse({
      sort: 'random',
    });
    expect(result.success).toBe(false);
  });

  it('should reject limit below 1', () => {
    const result = pcapFilesSchema.safeParse({
      limit: 0,
    });
    expect(result.success).toBe(false);
  });

  it('should reject limit above 1000', () => {
    const result = pcapFilesSchema.safeParse({
      limit: 1001,
    });
    expect(result.success).toBe(false);
  });

  it('should apply default limit of 100', () => {
    const result = pcapFilesSchema.parse({});
    expect(result.limit).toBe(100);
  });

  it('should accept empty object with defaults', () => {
    const result = pcapFilesSchema.safeParse({});
    expect(result.success).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// sessionsSummarySchema
// ---------------------------------------------------------------------------

describe('sessionsSummarySchema', () => {
  it('should accept valid input', () => {
    const result = sessionsSummarySchema.safeParse({
      expression: 'ip.src == 1.2.3.4',
      field: 'sourceIP',
      buckets: 10,
    });
    expect(result.success).toBe(true);
  });

  it('should reject expression over 10000 chars', () => {
    const result = sessionsSummarySchema.safeParse({
      expression: overMaxExpression(),
    });
    expect(result.success).toBe(false);
  });

  it('should reject buckets below 1', () => {
    const result = sessionsSummarySchema.safeParse({
      buckets: 0,
    });
    expect(result.success).toBe(false);
  });

  it('should reject buckets above 1000', () => {
    const result = sessionsSummarySchema.safeParse({
      buckets: 1001,
    });
    expect(result.success).toBe(false);
  });

  it('should accept empty object (all fields optional)', () => {
    const result = sessionsSummarySchema.safeParse({});
    expect(result.success).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// multiUniqueSchema
// ---------------------------------------------------------------------------

describe('multiUniqueSchema', () => {
  it('should accept valid input', () => {
    const result = multiUniqueSchema.safeParse({
      fields: ['sourceIP', 'protocol'],
      expression: 'ip.src == 1.2.3.4',
      limit: 50,
    });
    expect(result.success).toBe(true);
  });

  it('should reject empty fields array', () => {
    const result = multiUniqueSchema.safeParse({
      fields: [],
    });
    expect(result.success).toBe(false);
  });

  it('should reject fields array with more than 20 items', () => {
    const result = multiUniqueSchema.safeParse({
      fields: Array.from({ length: 21 }, (_, i) => `field${i}`),
    });
    expect(result.success).toBe(false);
  });

  it('should reject missing required fields', () => {
    const result = multiUniqueSchema.safeParse({});
    expect(result.success).toBe(false);
  });

  it('should reject expression over 10000 chars', () => {
    const result = multiUniqueSchema.safeParse({
      fields: ['sourceIP'],
      expression: overMaxExpression(),
    });
    expect(result.success).toBe(false);
  });

  it('should reject limit below 1', () => {
    const result = multiUniqueSchema.safeParse({
      fields: ['sourceIP'],
      limit: 0,
    });
    expect(result.success).toBe(false);
  });

  it('should reject limit above 1000', () => {
    const result = multiUniqueSchema.safeParse({
      fields: ['sourceIP'],
      limit: 1001,
    });
    expect(result.success).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// connectionsSchema
// ---------------------------------------------------------------------------

describe('connectionsSchema', () => {
  it('should accept valid input', () => {
    const result = connectionsSchema.safeParse({
      expression: 'ip.src == 1.2.3.4',
      limit: 50,
    });
    expect(result.success).toBe(true);
  });

  it('should reject expression over 10000 chars', () => {
    const result = connectionsSchema.safeParse({
      expression: overMaxExpression(),
    });
    expect(result.success).toBe(false);
  });

  it('should reject limit below 1', () => {
    const result = connectionsSchema.safeParse({
      limit: 0,
    });
    expect(result.success).toBe(false);
  });

  it('should reject limit above 1000', () => {
    const result = connectionsSchema.safeParse({
      limit: 1001,
    });
    expect(result.success).toBe(false);
  });

  it('should accept empty object (all fields optional)', () => {
    const result = connectionsSchema.safeParse({});
    expect(result.success).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// spiSessionsSchema
// ---------------------------------------------------------------------------

describe('spiSessionsSchema', () => {
  it('should accept valid input', () => {
    const result = spiSessionsSchema.safeParse({
      expression: 'ip.src == 1.2.3.4',
      fields: ['dns.host', 'http.uri'],
      limit: 50,
    });
    expect(result.success).toBe(true);
  });

  it('should reject expression over 10000 chars', () => {
    const result = spiSessionsSchema.safeParse({
      expression: overMaxExpression(),
    });
    expect(result.success).toBe(false);
  });

  it('should reject limit below 1', () => {
    const result = spiSessionsSchema.safeParse({
      limit: 0,
    });
    expect(result.success).toBe(false);
  });

  it('should reject limit above 1000', () => {
    const result = spiSessionsSchema.safeParse({
      limit: 1001,
    });
    expect(result.success).toBe(false);
  });

  it('should accept empty object (all fields optional)', () => {
    const result = spiSessionsSchema.safeParse({});
    expect(result.success).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// sessionDetailSchema
// ---------------------------------------------------------------------------

describe('sessionDetailSchema', () => {
  it('should accept valid input', () => {
    const result = sessionDetailSchema.safeParse({
      nodeId: '3',
      sessionId: '251118-GwHllt-BE65AZ49KusloBKxl',
    });
    expect(result.success).toBe(true);
  });

  it('should reject empty nodeId', () => {
    const result = sessionDetailSchema.safeParse({
      nodeId: '',
      sessionId: '251118-GwHllt-BE65AZ49KusloBKxl',
    });
    expect(result.success).toBe(false);
  });

  it('should reject empty sessionId', () => {
    const result = sessionDetailSchema.safeParse({
      nodeId: '3',
      sessionId: '',
    });
    expect(result.success).toBe(false);
  });

  it('should reject missing nodeId', () => {
    const result = sessionDetailSchema.safeParse({
      sessionId: '251118-GwHllt-BE65AZ49KusloBKxl',
    });
    expect(result.success).toBe(false);
  });

  it('should reject missing sessionId', () => {
    const result = sessionDetailSchema.safeParse({
      nodeId: '3',
    });
    expect(result.success).toBe(false);
  });

  it('should reject empty object', () => {
    const result = sessionDetailSchema.safeParse({});
    expect(result.success).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// sessionFileSchema
// ---------------------------------------------------------------------------

describe('sessionFileSchema', () => {
  it('should accept valid input', () => {
    const result = sessionFileSchema.safeParse({
      nodeId: '3',
      sessionId: '251118-GwHllt-BE65AZ49KusloBKxl',
      hash: 'd41d8cd98f00b204e9800998ecf8427e',
    });
    expect(result.success).toBe(true);
  });

  it('should reject empty nodeId', () => {
    const result = sessionFileSchema.safeParse({
      nodeId: '',
      sessionId: 'abc',
      hash: 'def',
    });
    expect(result.success).toBe(false);
  });

  it('should reject empty sessionId', () => {
    const result = sessionFileSchema.safeParse({
      nodeId: '3',
      sessionId: '',
      hash: 'def',
    });
    expect(result.success).toBe(false);
  });

  it('should reject empty hash', () => {
    const result = sessionFileSchema.safeParse({
      nodeId: '3',
      sessionId: 'abc',
      hash: '',
    });
    expect(result.success).toBe(false);
  });

  it('should reject missing nodeId', () => {
    const result = sessionFileSchema.safeParse({
      sessionId: 'abc',
      hash: 'def',
    });
    expect(result.success).toBe(false);
  });

  it('should reject missing sessionId', () => {
    const result = sessionFileSchema.safeParse({
      nodeId: '3',
      hash: 'def',
    });
    expect(result.success).toBe(false);
  });

  it('should reject missing hash', () => {
    const result = sessionFileSchema.safeParse({
      nodeId: '3',
      sessionId: 'abc',
    });
    expect(result.success).toBe(false);
  });

  it('should reject empty object', () => {
    const result = sessionFileSchema.safeParse({});
    expect(result.success).toBe(false);
  });
});
