import { describe, it, expect, vi } from 'vitest';
import { listFields } from '@/controllers/fields';
import { ArkimeClient } from '@/services/arkime-client';
import type { FieldDefinition } from '@/types/arkime';

vi.mock('@/services/arkime-client');

describe('listFields controller', () => {
  it('should return formatted field list', async () => {
    const mockFields: FieldDefinition[] = [
      { dbName: 'source.ip', friendlyName: 'Source IP', type: 'ip', group: 'general' },
      { dbName: 'destination.ip', friendlyName: 'Destination IP', type: 'ip', group: 'general' },
      { dbName: 'http.uri', friendlyName: 'HTTP URI', type: 'string', group: 'http' },
    ];

    vi.mocked(ArkimeClient).prototype.getFields = vi.fn().mockResolvedValue(mockFields);

    const client = new ArkimeClient({
      host: 'https://test.com',
      user: 'admin',
      password: 'secret',
      timeout: 30000,
    });

    const result = await listFields(client, {});

    expect(result.isError).toBeUndefined();
    expect(result.content[0].type).toBe('text');
    expect(result.content[0].text).toContain('source.ip');
    expect(result.content[0].text).toContain('http.uri');
  });

  it('should handle empty field list', async () => {
    vi.mocked(ArkimeClient).prototype.getFields = vi.fn().mockResolvedValue([]);

    const client = new ArkimeClient({
      host: 'https://test.com',
      user: 'admin',
      password: 'secret',
      timeout: 30000,
    });

    const result = await listFields(client, {});

    expect(result.content[0].text).toContain('No fields');
  });

  it('should propagate errors', async () => {
    vi.mocked(ArkimeClient).prototype.getFields = vi.fn().mockRejectedValue(
      new Error('API error')
    );

    const client = new ArkimeClient({
      host: 'https://test.com',
      user: 'admin',
      password: 'secret',
      timeout: 30000,
    });

    await expect(listFields(client, {})).rejects.toThrow('API error');
  });
});
