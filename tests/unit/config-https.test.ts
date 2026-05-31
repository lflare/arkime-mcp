import { describe, it, expect } from 'vitest';
import { validateConfig } from '@/services/config';

describe('validateConfig HTTPS enforcement', () => {
  it('should flag HTTP host as insecure', () => {
    const result = validateConfig({
      host: 'http://arkime.example.com:8005',
      user: 'admin',
      password: 'secret',
      timeout: 30000,
    });
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('HTTPS'))).toBe(true);
  });

  it('should allow HTTPS hosts', () => {
    const result = validateConfig({
      host: 'https://arkime.example.com:8005',
      user: 'admin',
      password: 'secret',
      timeout: 30000,
    });
    expect(result.valid).toBe(true);
  });

  it('should allow localhost HTTP', () => {
    const result = validateConfig({
      host: 'http://localhost:8005',
      user: 'admin',
      password: 'secret',
      timeout: 30000,
    });
    expect(result.valid).toBe(true);
  });

  it('should allow 127.0.0.1 HTTP', () => {
    const result = validateConfig({
      host: 'http://127.0.0.1:8005',
      user: 'admin',
      password: 'secret',
      timeout: 30000,
    });
    expect(result.valid).toBe(true);
  });
});
