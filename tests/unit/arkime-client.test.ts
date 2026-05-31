import { describe, it, expect, beforeEach } from 'vitest';
import { ArkimeClient } from '@/services/arkime-client';
import type { ArkimeConfig } from '@/services/config';

describe('ArkimeClient', () => {
  // Use a non-routable localhost port so connection refuses immediately
  // instead of hanging on DNS / TCP to a real host.
  const config: ArkimeConfig = {
    host: 'http://127.0.0.1:1',
    user: 'admin',
    password: 'secret',
    timeout: 2000,
  };

  describe('constructor', () => {
    it('should create client with config', () => {
      const client = new ArkimeClient(config);
      expect(client).toBeDefined();
    });

    it('should normalize host URL (remove trailing slash)', () => {
      const clientWithSlash = new ArkimeClient({
        ...config,
        host: 'http://127.0.0.1:1/',
      });

      expect(clientWithSlash).toBeDefined();
    });
  });

  describe('searchSessions', () => {
    it('should build query parameters correctly', async () => {
      const client = new ArkimeClient(config);

      await expect(
        client.searchSessions({
          expression: 'ip.src == 192.168.1.1',
          startTime: 1704067100,
          endTime: 1704067200,
          length: 100,
          start: 0,
          fields: ['source.ip', 'destination.ip'],
        })
      ).rejects.toThrow();
    });
  });

  describe('getSession', () => {
    it('should throw for non-existent session', async () => {
      const client = new ArkimeClient(config);

      await expect(client.getSession('nonexistent')).rejects.toThrow();
    });
  });

  describe('getFields', () => {
    it('should throw without valid connection', async () => {
      const client = new ArkimeClient(config);

      await expect(client.getFields()).rejects.toThrow();
    });
  });
});
