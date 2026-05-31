import { describe, it, expect } from 'vitest';
import { resolve } from 'path';
import { existsSync, readFileSync } from 'fs';
import { ArkimeClient } from '../../src/services/arkime-client.js';
import { loadValidatedConfig } from '../../src/services/config.js';
import { analyzeTraffic, huntSuspicious } from '../../src/controllers/analysis.js';

const envPath = resolve(__dirname, '../../.env');
if (existsSync(envPath)) {
  readFileSync(envPath, 'utf-8').split('\n').forEach(line => {
    const trimmed = line.trim();
    if (trimmed && !trimmed.startsWith('#')) {
      const [key, ...valueParts] = trimmed.split('=');
      const value = valueParts.join('=').replace(/^['"]|['"]$/g, '');
      if (key && value && !process.env[key]) process.env[key] = value;
    }
  });
}

let client: ArkimeClient;
const startTime = new Date(Date.now() - 730 * 24 * 60 * 60 * 1000).toISOString();
const endTime = new Date().toISOString();

try {
  const config = loadValidatedConfig();
  client = new ArkimeClient(config);
} catch {
  // No valid config — tests will be skipped below.
}

const testDescribe = client ? describe : describe.skip;

testDescribe('Arkime API Integration Tests', () => {
  describe('getFields', () => {
    it('should fetch available fields from Arkime', async () => {
      const fields = await client.getFields();

      expect(Array.isArray(fields)).toBe(true);
      expect(fields.length).toBeGreaterThan(0);

      const firstField = fields[0];
      expect(firstField).toHaveProperty('dbName');
      expect(firstField).toHaveProperty('friendlyName');
      expect(firstField).toHaveProperty('type');
      expect(firstField).toHaveProperty('group');
    });
  });

  describe('searchSessions', () => {
    it('should search sessions without expression', async () => {
      const response = await client.searchSessions({
        length: 10,
      });

      expect(response).toHaveProperty('data');
      expect(response).toHaveProperty('recordsTotal');
      expect(response).toHaveProperty('recordsFiltered');
      expect(Array.isArray(response.data)).toBe(true);
    });

    it('should search sessions with limit', async () => {
      const response = await client.searchSessions({
        length: 5,
      });

      expect(response.data.length).toBeLessThanOrEqual(5);
    });

    it('should search sessions with specific fields', async () => {
      const response = await client.searchSessions({
        length: 5,
        fields: ['source.ip', 'destination.ip'],
      });

      expect(response.data.length).toBeLessThanOrEqual(5);
    });

    it('should search sessions with date expression', async () => {
      const response = await client.searchSessions({
        expression: 'ipProtocol == 6',
        length: 5,
      });

      expect(response).toHaveProperty('data');
      expect(response).toHaveProperty('recordsTotal');
    });
  });

  describe('getSession', () => {
    it('should throw not found for invalid session ID', async () => {
      await expect(client.getSession('invalid-session-id-12345'))
        .rejects
        .toThrow('Session not found');
    });
  });

  describe('analyzeTraffic', () => {
    it('should analyze top talkers', async () => {
      const result = await analyzeTraffic(client, {
        analysisType: 'top-talkers',
        limit: 10,
        startTime,
        endTime,
      });

      expect(result.isError).toBeUndefined();
      expect(result.content[0].type).toBe('text');
      expect(result.content[0].text).toContain('Top Talkers');
    });

    it('should analyze protocols', async () => {
      const result = await analyzeTraffic(client, {
        analysisType: 'protocols',
        limit: 10,
        startTime,
        endTime,
      });

      expect(result.content[0].text).toContain('Protocol');
    });

    it('should analyze ports', async () => {
      const result = await analyzeTraffic(client, {
        analysisType: 'ports',
        limit: 10,
        startTime,
        endTime,
      });

      expect(result.content[0].text).toContain('Port');
    });
  });

  describe('huntSuspicious', () => {
    it('should hunt for port scanners', async () => {
      const result = await huntSuspicious(client, {
        huntType: 'port-scanners',
        threshold: 50,
      });

      expect(result.isError).toBeUndefined();
      expect(result.content[0].type).toBe('text');
    });

    it('should hunt for data exfiltration', async () => {
      const result = await huntSuspicious(client, {
        huntType: 'data-exfil',
        threshold: 1000000,
      });

      expect(result.content[0].text).toBeTypeOf('string');
    });
  });
});
