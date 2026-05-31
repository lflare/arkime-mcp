import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { loadConfig, validateConfig, loadValidatedConfig, type ArkimeConfig } from '@/services/config';
import { ErrorCode, McpError } from '@/utils/errors';

describe('Config', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    process.env = { ...originalEnv };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  describe('loadConfig', () => {
    it('should load config from environment variables', () => {
      process.env.ARKIME_HOST = 'http://test.local:8005';
      process.env.ARKIME_USER = 'admin';
      process.env.ARKIME_PASSWORD = 'secret';
      process.env.ARKIME_TIMEOUT = '60000';

      const config = loadConfig();

      expect(config.host).toBe('http://test.local:8005');
      expect(config.user).toBe('admin');
      expect(config.password).toBe('secret');
      expect(config.timeout).toBe(60000);
    });

    it('should use default timeout when not specified', () => {
      process.env.ARKIME_HOST = 'http://test.local:8005';
      process.env.ARKIME_USER = 'admin';
      process.env.ARKIME_PASSWORD = 'secret';
      delete process.env.ARKIME_TIMEOUT;

      const config = loadConfig();

      expect(config.timeout).toBe(30000);
    });

    it('should handle missing optional env vars', () => {
      process.env.ARKIME_HOST = 'http://test.local:8005';
      process.env.ARKIME_USER = 'admin';
      process.env.ARKIME_PASSWORD = 'secret';

      const config = loadConfig();

      expect(config.host).toBe('http://test.local:8005');
      expect(config.user).toBe('admin');
      expect(config.password).toBe('secret');
    });
  });

  describe('validateConfig', () => {
    it('should return valid for complete config', () => {
      const config: ArkimeConfig = {
        host: 'http://localhost:8005',
        user: 'admin',
        password: 'secret',
        timeout: 30000,
      };

      const result = validateConfig(config);

      expect(result.valid).toBe(true);
      expect(result.errors).toEqual([]);
    });

    it('should detect missing host', () => {
      const config: ArkimeConfig = {
        host: '',
        user: 'admin',
        password: 'secret',
        timeout: 30000,
      };

      const result = validateConfig(config);

      expect(result.valid).toBe(false);
      expect(result.errors).toContain('ARKIME_HOST is required');
    });

    it('should detect missing user', () => {
      const config: ArkimeConfig = {
        host: 'http://test.local:8005',
        user: '',
        password: 'secret',
        timeout: 30000,
      };

      const result = validateConfig(config);

      expect(result.valid).toBe(false);
      expect(result.errors).toContain('ARKIME_USER is required');
    });

    it('should detect missing password', () => {
      const config: ArkimeConfig = {
        host: 'http://test.local:8005',
        user: 'admin',
        password: '',
        timeout: 30000,
      };

      const result = validateConfig(config);

      expect(result.valid).toBe(false);
      expect(result.errors).toContain('ARKIME_PASSWORD is required');
    });

    it('should detect multiple missing fields', () => {
      const config: ArkimeConfig = {
        host: '',
        user: '',
        password: '',
        timeout: 30000,
      };

      const result = validateConfig(config);

      expect(result.valid).toBe(false);
      expect(result.errors.length).toBe(3);
    });

    it('should reject invalid timeout', () => {
      const config: ArkimeConfig = {
        host: 'http://test.local:8005',
        user: 'admin',
        password: 'secret',
        timeout: -1,
      };

      const result = validateConfig(config);

      expect(result.valid).toBe(false);
      expect(result.errors).toContain('ARKIME_TIMEOUT must be positive');
    });

    it('should allow http://localhost as host', () => {
      const config: ArkimeConfig = {
        host: 'http://localhost:8005',
        user: 'admin',
        password: 'secret',
        timeout: 30000,
      };

      const result = validateConfig(config);

      expect(result.valid).toBe(true);
    });

    it('should allow http://127.0.0.1 as host', () => {
      const config: ArkimeConfig = {
        host: 'http://127.0.0.1:8005',
        user: 'admin',
        password: 'secret',
        timeout: 30000,
      };

      const result = validateConfig(config);

      expect(result.valid).toBe(true);
    });

    it('should reject http://localhost.evil.com as localhost', () => {
      const config: ArkimeConfig = {
        host: 'http://localhost.evil.com:8005',
        user: 'admin',
        password: 'secret',
        timeout: 30000,
      };

      const result = validateConfig(config);

      expect(result.valid).toBe(false);
      expect(result.errors).toContain('ARKIME_HOST must use HTTPS or be localhost/127.0.0.1');
    });

    it('should reject http://notlocalhost as localhost', () => {
      const config: ArkimeConfig = {
        host: 'http://notlocalhost:8005',
        user: 'admin',
        password: 'secret',
        timeout: 30000,
      };

      const result = validateConfig(config);

      expect(result.valid).toBe(false);
      expect(result.errors).toContain('ARKIME_HOST must use HTTPS or be localhost/127.0.0.1');
    });

    it('should reject localhost-like subdomains', () => {
      const config: ArkimeConfig = {
        host: 'http://localhost.localdomain:8005',
        user: 'admin',
        password: 'secret',
        timeout: 30000,
      };

      const result = validateConfig(config);

      expect(result.valid).toBe(false);
    });
  });

  describe('loadValidatedConfig', () => {
    it('should return config when validation passes', () => {
      process.env.ARKIME_HOST = 'http://localhost:8005';
      process.env.ARKIME_USER = 'admin';
      process.env.ARKIME_PASSWORD = 'secret';

      const config = loadValidatedConfig();

      expect(config.user).toBe('admin');
    });

    it('should throw AUTH_MISSING when credentials are missing', () => {
      process.env.ARKIME_HOST = 'http://localhost:8005';
      delete process.env.ARKIME_USER;
      delete process.env.ARKIME_PASSWORD;

      try {
        loadValidatedConfig();
        expect.unreachable('should have thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(McpError);
        expect((error as McpError).code).toBe(ErrorCode.AUTH_MISSING);
      }
    });

    it('should throw CONFIG_ERROR for negative timeout', () => {
      process.env.ARKIME_HOST = 'http://localhost:8005';
      process.env.ARKIME_USER = 'admin';
      process.env.ARKIME_PASSWORD = 'secret';
      process.env.ARKIME_TIMEOUT = '-1';

      try {
        loadValidatedConfig();
        expect.unreachable('should have thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(McpError);
        expect((error as McpError).code).toBe(ErrorCode.CONFIG_ERROR);
      }
    });

    it('should throw CONFIG_ERROR for non-HTTPS non-localhost host', () => {
      process.env.ARKIME_HOST = 'http://localhost.evil.com:8005';
      process.env.ARKIME_USER = 'admin';
      process.env.ARKIME_PASSWORD = 'secret';

      try {
        loadValidatedConfig();
        expect.unreachable('should have thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(McpError);
        expect((error as McpError).code).toBe(ErrorCode.CONFIG_ERROR);
      }
    });
  });
});
