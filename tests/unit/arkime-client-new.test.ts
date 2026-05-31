import { describe, it, expect } from 'vitest';
import { ArkimeClient } from '@/services/arkime-client';
import type { ArkimeConfig } from '@/services/config';

describe('ArkimeClient new methods', () => {
  // Use a non-routable localhost port so connection refuses immediately.
  const config: ArkimeConfig = {
    host: 'http://127.0.0.1:1',
    user: 'admin',
    password: 'secret',
    timeout: 2000,
  };

  describe('getUniqueField', () => {
    it('should throw when server unavailable', async () => {
      const client = new ArkimeClient(config);
      await expect(client.getUniqueField('sourceIP', { limit: 10 })).rejects.toThrow();
    });

    it('should throw with expression option', async () => {
      const client = new ArkimeClient(config);
      await expect(
        client.getUniqueField('sourceIP', {
          expression: 'ip.src == 192.168.1.1',
          limit: 10,
        })
      ).rejects.toThrow();
    });
  });

  describe('getClusters', () => {
    it('should throw when server unavailable', async () => {
      const client = new ArkimeClient(config);
      await expect(client.getClusters()).rejects.toThrow();
    });
  });

  describe('getFiles', () => {
    it('should throw when server unavailable', async () => {
      const client = new ArkimeClient(config);
      await expect(client.getFiles({ limit: 10 })).rejects.toThrow();
    });

    it('should throw with no options', async () => {
      const client = new ArkimeClient(config);
      await expect(client.getFiles()).rejects.toThrow();
    });
  });

  describe('getSessionsSummary', () => {
    it('should throw when server unavailable', async () => {
      const client = new ArkimeClient(config);
      await expect(client.getSessionsSummary({ expression: 'tcp' })).rejects.toThrow();
    });
  });

  describe('getReversedns', () => {
    it('should throw when server unavailable', async () => {
      const client = new ArkimeClient(config);
      await expect(client.getReversedns('10.0.0.1')).rejects.toThrow();
    });
  });

  describe('getMultiUnique', () => {
    it('should throw when server unavailable', async () => {
      const client = new ArkimeClient(config);
      await expect(client.getMultiUnique(['sourceIP', 'protocol'])).rejects.toThrow();
    });
  });

  describe('getConnections', () => {
    it('should throw when server unavailable', async () => {
      const client = new ArkimeClient(config);
      await expect(client.getConnections()).rejects.toThrow();
    });
  });

  describe('getSpiview', () => {
    it('should throw when server unavailable', async () => {
      const client = new ArkimeClient(config);
      await expect(client.getSpiview({ expression: 'tcp' })).rejects.toThrow();
    });
  });

  describe('getSessionDetail', () => {
    it('should throw when server unavailable', async () => {
      const client = new ArkimeClient(config);
      await expect(client.getSessionDetail('3', 'test-id')).rejects.toThrow();
    });
  });

  describe('getHunts', () => {
    it('should throw when server unavailable', async () => {
      const client = new ArkimeClient(config);
      await expect(client.getHunts()).rejects.toThrow();
    });
  });

  describe('getViews', () => {
    it('should throw when server unavailable', async () => {
      const client = new ArkimeClient(config);
      await expect(client.getViews()).rejects.toThrow();
    });
  });

  describe('getShortcuts', () => {
    it('should throw when server unavailable', async () => {
      const client = new ArkimeClient(config);
      await expect(client.getShortcuts()).rejects.toThrow();
    });
  });

  describe('getAppInfo', () => {
    it('should throw when server unavailable', async () => {
      const client = new ArkimeClient(config);
      await expect(client.getAppInfo()).rejects.toThrow();
    });
  });

  describe('getStats', () => {
    it('should throw when server unavailable', async () => {
      const client = new ArkimeClient(config);
      await expect(client.getStats()).rejects.toThrow();
    });
  });
});
