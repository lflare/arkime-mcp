import { describe, it, expect } from 'vitest';
import { ArkimeClient } from '@/services/arkime-client';

describe('ArkimeClient recursion guard', () => {
  it('should have a MAX_AUTH_RETRIES constant', () => {
    expect((ArkimeClient as any).MAX_AUTH_RETRIES).toBeDefined();
    expect((ArkimeClient as any).MAX_AUTH_RETRIES).toBe(2);
  });

  it('should track auth retry count', () => {
    const client = new ArkimeClient({
      host: 'https://arkime.example.com:8005',
      user: 'test',
      password: 'test',
      timeout: 30000,
    });
    expect((client as any).authRetries).toBe(0);
  });
});
