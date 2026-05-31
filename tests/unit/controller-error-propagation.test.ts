import { describe, it, expect } from 'vitest';
import { analyzeTraffic, huntSuspicious } from '@/controllers/analysis';
import { buildAttackTimeline, trackLateralMovement, extractIocs } from '@/controllers/forensics';
import { topTalkers, reverseDns, dnsLookups, geoSummary, captureStatus, pcapFiles } from '@/controllers/explorer';
import { McpError, ErrorCode } from '@/utils/errors';
import type { ArkimeClient } from '@/services/arkime-client';

function createMockClient(throwError: Error) {
  return {
    searchSessions: async () => { throw throwError; },
    getUniqueField: async () => { throw throwError; },
    getReversedns: async () => { throw throwError; },
    getClusters: async () => { throw throwError; },
    getFiles: async () => { throw throwError; },
  } as unknown as ArkimeClient;
}

describe('analyzeTraffic error propagation', () => {
  it('should propagate API_ERROR from client', async () => {
    const client = createMockClient(
      new McpError(ErrorCode.API_ERROR, 'Internal Server Error')
    );

    try {
      await analyzeTraffic(client, { analysisType: 'top-talkers' });
      expect('should have thrown').toBe('failed');
    } catch (error) {
      expect(error).toBeInstanceOf(McpError);
      expect((error as McpError).code).toBe(ErrorCode.API_ERROR);
      expect((error as McpError).message).toContain('Internal Server Error');
    }
  });

  it('should propagate NETWORK_ERROR from client', async () => {
    const client = createMockClient(
      new McpError(ErrorCode.NETWORK_ERROR, 'Connection refused')
    );

    try {
      await analyzeTraffic(client, { analysisType: 'top-talkers' });
      expect('should have thrown').toBe('failed');
    } catch (error) {
      expect(error).toBeInstanceOf(McpError);
      expect((error as McpError).code).toBe(ErrorCode.NETWORK_ERROR);
      expect((error as McpError).message).toContain('Connection refused');
    }
  });
});

describe('huntSuspicious error propagation', () => {
  it('should propagate API_ERROR from client', async () => {
    const client = createMockClient(
      new McpError(ErrorCode.API_ERROR, 'Internal Server Error')
    );

    try {
      await huntSuspicious(client, { huntType: 'port-scanners' });
      expect('should have thrown').toBe('failed');
    } catch (error) {
      expect(error).toBeInstanceOf(McpError);
      expect((error as McpError).code).toBe(ErrorCode.API_ERROR);
      expect((error as McpError).message).toContain('Internal Server Error');
    }
  });

  it('should propagate NETWORK_ERROR from client', async () => {
    const client = createMockClient(
      new McpError(ErrorCode.NETWORK_ERROR, 'Connection refused')
    );

    try {
      await huntSuspicious(client, { huntType: 'port-scanners' });
      expect('should have thrown').toBe('failed');
    } catch (error) {
      expect(error).toBeInstanceOf(McpError);
      expect((error as McpError).code).toBe(ErrorCode.NETWORK_ERROR);
      expect((error as McpError).message).toContain('Connection refused');
    }
  });
});

describe('buildAttackTimeline error propagation', () => {
  it('should propagate API_ERROR from client', async () => {
    const client = createMockClient(
      new McpError(ErrorCode.API_ERROR, 'Internal Server Error')
    );

    try {
      await buildAttackTimeline(client, {});
      expect('should have thrown').toBe('failed');
    } catch (error) {
      expect(error).toBeInstanceOf(McpError);
      expect((error as McpError).code).toBe(ErrorCode.API_ERROR);
      expect((error as McpError).message).toContain('Internal Server Error');
    }
  });

  it('should propagate NETWORK_ERROR from client', async () => {
    const client = createMockClient(
      new McpError(ErrorCode.NETWORK_ERROR, 'Connection refused')
    );

    try {
      await buildAttackTimeline(client, {});
      expect('should have thrown').toBe('failed');
    } catch (error) {
      expect(error).toBeInstanceOf(McpError);
      expect((error as McpError).code).toBe(ErrorCode.NETWORK_ERROR);
      expect((error as McpError).message).toContain('Connection refused');
    }
  });
});

describe('trackLateralMovement error propagation', () => {
  it('should propagate API_ERROR from client', async () => {
    const client = createMockClient(
      new McpError(ErrorCode.API_ERROR, 'Internal Server Error')
    );

    try {
      await trackLateralMovement(client, {});
      expect('should have thrown').toBe('failed');
    } catch (error) {
      expect(error).toBeInstanceOf(McpError);
      expect((error as McpError).code).toBe(ErrorCode.API_ERROR);
      expect((error as McpError).message).toContain('Internal Server Error');
    }
  });

  it('should propagate NETWORK_ERROR from client', async () => {
    const client = createMockClient(
      new McpError(ErrorCode.NETWORK_ERROR, 'Connection refused')
    );

    try {
      await trackLateralMovement(client, {});
      expect('should have thrown').toBe('failed');
    } catch (error) {
      expect(error).toBeInstanceOf(McpError);
      expect((error as McpError).code).toBe(ErrorCode.NETWORK_ERROR);
      expect((error as McpError).message).toContain('Connection refused');
    }
  });
});

describe('extractIocs error propagation', () => {
  it('should propagate API_ERROR from client', async () => {
    const client = createMockClient(
      new McpError(ErrorCode.API_ERROR, 'Internal Server Error')
    );

    try {
      await extractIocs(client, { expression: 'ip.src == 1.2.3.4' });
      expect('should have thrown').toBe('failed');
    } catch (error) {
      expect(error).toBeInstanceOf(McpError);
      expect((error as McpError).code).toBe(ErrorCode.API_ERROR);
      expect((error as McpError).message).toContain('Internal Server Error');
    }
  });

  it('should propagate NETWORK_ERROR from client', async () => {
    const client = createMockClient(
      new McpError(ErrorCode.NETWORK_ERROR, 'Connection refused')
    );

    try {
      await extractIocs(client, { expression: 'ip.src == 1.2.3.4' });
      expect('should have thrown').toBe('failed');
    } catch (error) {
      expect(error).toBeInstanceOf(McpError);
      expect((error as McpError).code).toBe(ErrorCode.NETWORK_ERROR);
      expect((error as McpError).message).toContain('Connection refused');
    }
  });
});

describe('topTalkers error propagation', () => {
  it('should propagate API_ERROR from client', async () => {
    const client = createMockClient(
      new McpError(ErrorCode.API_ERROR, 'Internal Server Error')
    );

    try {
      await topTalkers(client, { field: 'sourceIP' });
      expect('should have thrown').toBe('failed');
    } catch (error) {
      expect(error).toBeInstanceOf(McpError);
      expect((error as McpError).code).toBe(ErrorCode.API_ERROR);
      expect((error as McpError).message).toContain('Internal Server Error');
    }
  });

  it('should propagate NETWORK_ERROR from client', async () => {
    const client = createMockClient(
      new McpError(ErrorCode.NETWORK_ERROR, 'Connection refused')
    );

    try {
      await topTalkers(client, { field: 'sourceIP' });
      expect('should have thrown').toBe('failed');
    } catch (error) {
      expect(error).toBeInstanceOf(McpError);
      expect((error as McpError).code).toBe(ErrorCode.NETWORK_ERROR);
      expect((error as McpError).message).toContain('Connection refused');
    }
  });
});

describe('reverseDns error propagation', () => {
  it('should propagate API_ERROR from client', async () => {
    const client = createMockClient(
      new McpError(ErrorCode.API_ERROR, 'Internal Server Error')
    );

    try {
      await reverseDns(client, { ipAddress: '10.0.0.1' });
      expect('should have thrown').toBe('failed');
    } catch (error) {
      expect(error).toBeInstanceOf(McpError);
      expect((error as McpError).code).toBe(ErrorCode.API_ERROR);
      expect((error as McpError).message).toContain('Internal Server Error');
    }
  });

  it('should propagate NETWORK_ERROR from client', async () => {
    const client = createMockClient(
      new McpError(ErrorCode.NETWORK_ERROR, 'Connection refused')
    );

    try {
      await reverseDns(client, { ipAddress: '10.0.0.1' });
      expect('should have thrown').toBe('failed');
    } catch (error) {
      expect(error).toBeInstanceOf(McpError);
      expect((error as McpError).code).toBe(ErrorCode.NETWORK_ERROR);
      expect((error as McpError).message).toContain('Connection refused');
    }
  });
});

describe('dnsLookups error propagation', () => {
  it('should propagate API_ERROR from client', async () => {
    const client = createMockClient(
      new McpError(ErrorCode.API_ERROR, 'Internal Server Error')
    );

    try {
      await dnsLookups(client, {});
      expect('should have thrown').toBe('failed');
    } catch (error) {
      expect(error).toBeInstanceOf(McpError);
      expect((error as McpError).code).toBe(ErrorCode.API_ERROR);
      expect((error as McpError).message).toContain('Internal Server Error');
    }
  });

  it('should propagate NETWORK_ERROR from client', async () => {
    const client = createMockClient(
      new McpError(ErrorCode.NETWORK_ERROR, 'Connection refused')
    );

    try {
      await dnsLookups(client, {});
      expect('should have thrown').toBe('failed');
    } catch (error) {
      expect(error).toBeInstanceOf(McpError);
      expect((error as McpError).code).toBe(ErrorCode.NETWORK_ERROR);
      expect((error as McpError).message).toContain('Connection refused');
    }
  });
});

describe('geoSummary error propagation', () => {
  it('should propagate API_ERROR from client', async () => {
    const client = createMockClient(
      new McpError(ErrorCode.API_ERROR, 'Internal Server Error')
    );

    try {
      await geoSummary(client, {});
      expect('should have thrown').toBe('failed');
    } catch (error) {
      expect(error).toBeInstanceOf(McpError);
      expect((error as McpError).code).toBe(ErrorCode.API_ERROR);
      expect((error as McpError).message).toContain('Internal Server Error');
    }
  });

  it('should propagate NETWORK_ERROR from client', async () => {
    const client = createMockClient(
      new McpError(ErrorCode.NETWORK_ERROR, 'Connection refused')
    );

    try {
      await geoSummary(client, {});
      expect('should have thrown').toBe('failed');
    } catch (error) {
      expect(error).toBeInstanceOf(McpError);
      expect((error as McpError).code).toBe(ErrorCode.NETWORK_ERROR);
      expect((error as McpError).message).toContain('Connection refused');
    }
  });
});

describe('captureStatus error propagation', () => {
  it('should propagate API_ERROR from client', async () => {
    const client = createMockClient(
      new McpError(ErrorCode.API_ERROR, 'Internal Server Error')
    );

    try {
      await captureStatus(client, {});
      expect('should have thrown').toBe('failed');
    } catch (error) {
      expect(error).toBeInstanceOf(McpError);
      expect((error as McpError).code).toBe(ErrorCode.API_ERROR);
      expect((error as McpError).message).toContain('Internal Server Error');
    }
  });

  it('should propagate NETWORK_ERROR from client', async () => {
    const client = createMockClient(
      new McpError(ErrorCode.NETWORK_ERROR, 'Connection refused')
    );

    try {
      await captureStatus(client, {});
      expect('should have thrown').toBe('failed');
    } catch (error) {
      expect(error).toBeInstanceOf(McpError);
      expect((error as McpError).code).toBe(ErrorCode.NETWORK_ERROR);
      expect((error as McpError).message).toContain('Connection refused');
    }
  });
});

describe('pcapFiles error propagation', () => {
  it('should propagate API_ERROR from client', async () => {
    const client = createMockClient(
      new McpError(ErrorCode.API_ERROR, 'Internal Server Error')
    );

    try {
      await pcapFiles(client, {});
      expect('should have thrown').toBe('failed');
    } catch (error) {
      expect(error).toBeInstanceOf(McpError);
      expect((error as McpError).code).toBe(ErrorCode.API_ERROR);
      expect((error as McpError).message).toContain('Internal Server Error');
    }
  });

  it('should propagate NETWORK_ERROR from client', async () => {
    const client = createMockClient(
      new McpError(ErrorCode.NETWORK_ERROR, 'Connection refused')
    );

    try {
      await pcapFiles(client, {});
      expect('should have thrown').toBe('failed');
    } catch (error) {
      expect(error).toBeInstanceOf(McpError);
      expect((error as McpError).code).toBe(ErrorCode.NETWORK_ERROR);
      expect((error as McpError).message).toContain('Connection refused');
    }
  });
});
