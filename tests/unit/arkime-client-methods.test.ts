import { describe, it, expect, vi, beforeEach } from 'vitest';
import axios, { AxiosError } from 'axios';
import { ArkimeClient } from '@/services/arkime-client';
import { McpError, ErrorCode } from '@/utils/errors';
import type { ArkimeConfig } from '@/services/config';

const refusableConfig: ArkimeConfig = {
  host: 'http://127.0.0.1:1',
  user: 'admin',
  password: 'secret',
  timeout: 2000,
};

function initDigestAuth(client: ArkimeClient): void {
  (client as any).nonce = 'test-nonce';
  (client as any).realm = 'test-realm';
  (client as any).qop = 'auth';
}

function makeAxiosError(status: number, statusText: string): AxiosError {
  const err = new AxiosError(`${status} ${statusText}`, 'ERR_BAD_RESPONSE', undefined, undefined, {
    status,
    statusText,
    headers: {},
    config: { baseURL: refusableConfig.host, url: '' },
    data: {},
  } as any);
  return err;
}

describe('ArkimeClient Buffer-returning methods', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  describe('getSessionBody', () => {
    it('should throw McpError when connection refused', async () => {
      const client = new ArkimeClient(refusableConfig);
      await expect(
        client.getSessionBody('node1', 'session1', 'full', 0, 'body.dat')
      ).rejects.toThrow(McpError);
    });

    it('should throw NETWORK_ERROR when connection refused', async () => {
      const client = new ArkimeClient(refusableConfig);
      try {
        await client.getSessionBody('node1', 'session1', 'full', 0, 'body.dat');
        expect.fail('should have thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(McpError);
        expect((error as McpError).code).toBe(ErrorCode.NETWORK_ERROR);
      }
    });

    it('should encode special characters in nodeId, sessionId, and bodyName', async () => {
      const client = new ArkimeClient(refusableConfig);
      initDigestAuth(client);

      const mockBuffer = Buffer.from('body data');
      const axiosInstance = (client as any).axios;
      vi.spyOn(axiosInstance, 'request').mockResolvedValue({ data: mockBuffer });

      await client.getSessionBody('node with spaces', 'session id 123', 'full', 0, 'my body.dat');

      expect(axiosInstance.request).toHaveBeenCalledWith(
        expect.objectContaining({
          method: 'GET',
          url: '/api/session/node%20with%20spaces/session%20id%20123/body/full/0/my%20body.dat',
          responseType: 'arraybuffer',
          headers: expect.objectContaining({ Authorization: expect.any(String) }),
        })
      );
    });
  });

  describe('getSessionBodyHash', () => {
    it('should throw McpError when connection refused', async () => {
      const client = new ArkimeClient(refusableConfig);
      await expect(
        client.getSessionBodyHash('node1', 'session1', 'abc123')
      ).rejects.toThrow(McpError);
    });

    it('should throw NETWORK_ERROR when connection refused', async () => {
      const client = new ArkimeClient(refusableConfig);
      try {
        await client.getSessionBodyHash('node1', 'session1', 'abc123');
        expect.fail('should have thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(McpError);
        expect((error as McpError).code).toBe(ErrorCode.NETWORK_ERROR);
      }
    });

    it('should encode special characters in nodeId, sessionId, and hash', async () => {
      const client = new ArkimeClient(refusableConfig);
      initDigestAuth(client);

      const mockBuffer = Buffer.from('hash data');
      const axiosInstance = (client as any).axios;
      vi.spyOn(axiosInstance, 'request').mockResolvedValue({ data: mockBuffer });

      await client.getSessionBodyHash('node@1', 'session id', 'hash with spaces');

      expect(axiosInstance.request).toHaveBeenCalledWith(
        expect.objectContaining({
          method: 'GET',
          url: '/api/session/node%401/session%20id/bodyhash/hash%20with%20spaces',
          responseType: 'arraybuffer',
          headers: expect.objectContaining({ Authorization: expect.any(String) }),
        })
      );
    });
  });

  describe('getSessionEntirePcap', () => {
    it('should throw McpError when connection refused', async () => {
      const client = new ArkimeClient(refusableConfig);
      await expect(
        client.getSessionEntirePcap('node1', 'session1')
      ).rejects.toThrow(McpError);
    });

    it('should throw NETWORK_ERROR when connection refused', async () => {
      const client = new ArkimeClient(refusableConfig);
      try {
        await client.getSessionEntirePcap('node1', 'session1');
        expect.fail('should have thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(McpError);
        expect((error as McpError).code).toBe(ErrorCode.NETWORK_ERROR);
      }
    });

    it('should encode special characters in nodeId and sessionId', async () => {
      const client = new ArkimeClient(refusableConfig);
      initDigestAuth(client);

      const mockBuffer = Buffer.from('pcap data');
      const axiosInstance = (client as any).axios;
      vi.spyOn(axiosInstance, 'request').mockResolvedValue({ data: mockBuffer });

      await client.getSessionEntirePcap('node/1', 'session@id');

      expect(axiosInstance.request).toHaveBeenCalledWith(
        expect.objectContaining({
          method: 'GET',
          url: '/api/session/entire/node%2F1/session%40id/pcap',
          responseType: 'arraybuffer',
          headers: expect.objectContaining({ Authorization: expect.any(String) }),
        })
      );
    });
  });

  describe('getSessionRaw', () => {
    it('should throw McpError when connection refused', async () => {
      const client = new ArkimeClient(refusableConfig);
      await expect(
        client.getSessionRaw('node1', 'session1')
      ).rejects.toThrow(McpError);
    });

    it('should throw NETWORK_ERROR when connection refused', async () => {
      const client = new ArkimeClient(refusableConfig);
      try {
        await client.getSessionRaw('node1', 'session1');
        expect.fail('should have thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(McpError);
        expect((error as McpError).code).toBe(ErrorCode.NETWORK_ERROR);
      }
    });

    it('should encode special characters in nodeId and sessionId', async () => {
      const client = new ArkimeClient(refusableConfig);
      initDigestAuth(client);

      const mockBuffer = Buffer.from('raw data');
      const axiosInstance = (client as any).axios;
      vi.spyOn(axiosInstance, 'request').mockResolvedValue({ data: mockBuffer });

      await client.getSessionRaw('node:1', 'session#id');

      expect(axiosInstance.request).toHaveBeenCalledWith(
        expect.objectContaining({
          method: 'GET',
          url: '/api/session/raw/node%3A1/session%23id',
          responseType: 'arraybuffer',
          headers: expect.objectContaining({ Authorization: expect.any(String) }),
        })
      );
    });
  });

  describe('getPcap', () => {
    it('should throw McpError when connection refused', async () => {
      const client = new ArkimeClient(refusableConfig);
      await expect(
        client.getPcap('/api/sessions/pcap')
      ).rejects.toThrow(McpError);
    });

    it('should throw NETWORK_ERROR when connection refused', async () => {
      const client = new ArkimeClient(refusableConfig);
      try {
        await client.getPcap('/api/sessions/pcap');
        expect.fail('should have thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(McpError);
        expect((error as McpError).code).toBe(ErrorCode.NETWORK_ERROR);
      }
    });

    it('should request with arraybuffer response type', async () => {
      const client = new ArkimeClient(refusableConfig);
      initDigestAuth(client);

      const mockBuffer = Buffer.from('pcap data');
      const axiosInstance = (client as any).axios;
      vi.spyOn(axiosInstance, 'request').mockResolvedValue({ data: mockBuffer });

      await client.getPcap('/api/test/pcap');

      expect(axiosInstance.request).toHaveBeenCalledWith(
        expect.objectContaining({
          method: 'GET',
          url: '/api/test/pcap',
          responseType: 'arraybuffer',
          headers: expect.objectContaining({ Authorization: expect.any(String) }),
        })
      );
    });

    it('should return a Buffer on success', async () => {
      const client = new ArkimeClient(refusableConfig);
      initDigestAuth(client);

      const mockBuffer = Buffer.from('fake pcap data');
      const axiosInstance = (client as any).axios;
      vi.spyOn(axiosInstance, 'request').mockResolvedValue({ data: mockBuffer });

      const result = await client.getPcap('/api/test/pcap');

      expect(result).toBeInstanceOf(Buffer);
      expect(result).toEqual(mockBuffer);
    });
  });
});

describe('ArkimeClient handleError', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('should throw NETWORK_ERROR when no response (connection refused)', async () => {
    const client = new ArkimeClient(refusableConfig);

    try {
      await client.searchSessions({});
      expect.fail('should have thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(McpError);
      expect((error as McpError).code).toBe(ErrorCode.NETWORK_ERROR);
      expect((error as McpError).message).toContain('Network error');
    }
  });

  it('should throw AUTH_INVALID for 401 status after exhausting retries', async () => {
    const client = new ArkimeClient(refusableConfig);
    initDigestAuth(client);
    (client as any).authRetries = ArkimeClient.MAX_AUTH_RETRIES;

    const axiosInstance = (client as any).axios;
    const axiosError = makeAxiosError(401, 'Unauthorized');

    vi.spyOn(axiosInstance, 'request').mockRejectedValue(axiosError);

    try {
      await client.searchSessions({});
      expect.fail('should have thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(McpError);
      expect((error as McpError).code).toBe(ErrorCode.AUTH_INVALID);
      expect((error as McpError).message).toContain('retry limit exceeded');
    }
  });

  it('should throw NOT_FOUND for 404 status', async () => {
    const client = new ArkimeClient(refusableConfig);
    initDigestAuth(client);

    const axiosInstance = (client as any).axios;
    const axiosError = makeAxiosError(404, 'Not Found');

    vi.spyOn(axiosInstance, 'request').mockRejectedValue(axiosError);

    try {
      await client.searchSessions({});
      expect.fail('should have thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(McpError);
      expect((error as McpError).code).toBe(ErrorCode.NOT_FOUND);
      expect((error as McpError).message).toContain('404');
    }
  });

  it('should throw API_ERROR for 500 status', async () => {
    const client = new ArkimeClient(refusableConfig);
    initDigestAuth(client);

    const axiosInstance = (client as any).axios;
    const axiosError = makeAxiosError(500, 'Internal Server Error');

    vi.spyOn(axiosInstance, 'request').mockRejectedValue(axiosError);

    try {
      await client.searchSessions({});
      expect.fail('should have thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(McpError);
      expect((error as McpError).code).toBe(ErrorCode.API_ERROR);
      expect((error as McpError).message).toContain('500');
    }
  });

  it('should throw API_ERROR for generic Error (non-AxiosError)', async () => {
    const client = new ArkimeClient(refusableConfig);
    initDigestAuth(client);

    const axiosInstance = (client as any).axios;
    const plainError = new Error('Something went wrong');

    vi.spyOn(axiosInstance, 'request').mockRejectedValue(plainError);

    try {
      await client.searchSessions({});
      expect.fail('should have thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(McpError);
      expect((error as McpError).code).toBe(ErrorCode.API_ERROR);
      expect((error as McpError).message).toContain('Something went wrong');
    }
  });

  it('should throw API_ERROR with "Unknown error occurred" for string errors', async () => {
    const client = new ArkimeClient(refusableConfig);
    initDigestAuth(client);

    const axiosInstance = (client as any).axios;

    vi.spyOn(axiosInstance, 'request').mockRejectedValue('string error');

    try {
      await client.searchSessions({});
      expect.fail('should have thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(McpError);
      expect((error as McpError).code).toBe(ErrorCode.API_ERROR);
      expect((error as McpError).message).toContain('Unknown error occurred');
    }
  });
});
