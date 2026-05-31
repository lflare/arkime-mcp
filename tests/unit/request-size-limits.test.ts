import { describe, it, expect } from 'vitest';
import { ArkimeClient } from '@/services/arkime-client';

describe('ArkimeClient request size limits', () => {
  const client = new ArkimeClient({
    host: 'https://arkime.example.com:8005',
    user: 'test',
    password: 'test',
    timeout: 30000,
  });

  const axios = (client as any).axios;

  it('should set maxContentLength to 50MB', () => {
    expect(axios.defaults.maxContentLength).toBe(50 * 1024 * 1024);
  });

  it('should set maxBodyLength to 50MB', () => {
    expect(axios.defaults.maxBodyLength).toBe(50 * 1024 * 1024);
  });
});
