import { describe, it, expect, vi } from 'vitest';
import { getSession } from '@/controllers/sessions';
import { ArkimeClient } from '@/services/arkime-client';
import { McpError, ErrorCode } from '@/utils/errors';
import type { Session } from '@/types/arkime';

vi.mock('@/services/arkime-client');

describe('getSession controller', () => {
  it('should return formatted session details', async () => {
    const mockSession: Session = {
      id: 'session-123',
      lastPacket: 1704067200000,
      source: { ip: '192.168.1.100', port: 45678 },
      destination: { ip: '10.0.0.50', port: 443 },
      protocol: 6,
      'source.bytes': 1500,
      'destination.bytes': 5000,
    };

    vi.mocked(ArkimeClient).prototype.getSession = vi.fn().mockResolvedValue(mockSession);

    const client = new ArkimeClient({
      host: 'https://test.com',
      user: 'admin',
      password: 'secret',
      timeout: 30000,
    });

    const result = await getSession(client, { id: 'session-123' });

    expect(result.isError).toBeUndefined();
    expect(result.content[0].type).toBe('text');
    expect(result.content[0].text).toContain('session-123');
    expect(result.content[0].text).toContain('192.168.1.100');
    expect(result.content[0].text).toContain('10.0.0.50');
  });

  it('should propagate errors', async () => {
    vi.mocked(ArkimeClient).prototype.getSession = vi.fn().mockRejectedValue(
      new Error('Session not found')
    );

    const client = new ArkimeClient({
      host: 'https://test.com',
      user: 'admin',
      password: 'secret',
      timeout: 30000,
    });

    await expect(getSession(client, { id: 'nonexistent' })).rejects.toThrow('Session not found');
  });

  it('should strip node@ prefix from session ID', async () => {
    const mockSession: Session = {
      id: '260127-GwFt1w7eKJREbKdq8VYTsuEk',
      lastPacket: 1704067200000,
      source: { ip: '10.0.0.1', port: 12345 },
      destination: { ip: '10.0.0.2', port: 443 },
      ipProtocol: 6,
    };

    vi.mocked(ArkimeClient).prototype.getSession = vi.fn().mockResolvedValue(mockSession);

    const client = new ArkimeClient({
      host: 'https://test.com',
      user: 'admin',
      password: 'secret',
      timeout: 30000,
    });

    const result = await getSession(client, { id: '3@260127-GwFt1w7eKJREbKdq8VYTsuEk' });

    expect(result.content[0].text).toContain('260127-GwFt1w7eKJREbKdq8VYTsuEk');
    // Verify the client received the stripped ID (without node@ prefix)
    expect(vi.mocked(ArkimeClient).prototype.getSession).toHaveBeenCalledWith(
      '260127-GwFt1w7eKJREbKdq8VYTsuEk'
    );
  });

  it('should propagate McpError NOT_FOUND', async () => {
    vi.mocked(ArkimeClient).prototype.getSession = vi.fn().mockRejectedValue(
      new McpError(ErrorCode.NOT_FOUND, 'Session not found: nonexistent-id')
    );

    const client = new ArkimeClient({
      host: 'https://test.com',
      user: 'admin',
      password: 'secret',
      timeout: 30000,
    });

    await expect(getSession(client, { id: 'nonexistent-id' })).rejects.toThrow(McpError);

    try {
      await getSession(client, { id: 'nonexistent-id' });
    } catch (error) {
      expect(error).toBeInstanceOf(McpError);
      expect((error as McpError).code).toBe(ErrorCode.NOT_FOUND);
      expect((error as McpError).message).toContain('Session not found');
    }
  });

  it('should propagate McpError API_ERROR', async () => {
    vi.mocked(ArkimeClient).prototype.getSession = vi.fn().mockRejectedValue(
      new McpError(ErrorCode.API_ERROR, 'Internal Server Error')
    );

    const client = new ArkimeClient({
      host: 'https://test.com',
      user: 'admin',
      password: 'secret',
      timeout: 30000,
    });

    try {
      await getSession(client, { id: 'some-id' });
    } catch (error) {
      expect(error).toBeInstanceOf(McpError);
      expect((error as McpError).code).toBe(ErrorCode.API_ERROR);
    }
  });

  it('should propagate McpError NETWORK_ERROR', async () => {
    vi.mocked(ArkimeClient).prototype.getSession = vi.fn().mockRejectedValue(
      new McpError(ErrorCode.NETWORK_ERROR, 'Connection refused')
    );

    const client = new ArkimeClient({
      host: 'https://test.com',
      user: 'admin',
      password: 'secret',
      timeout: 30000,
    });

    try {
      await getSession(client, { id: 'some-id' });
    } catch (error) {
      expect(error).toBeInstanceOf(McpError);
      expect((error as McpError).code).toBe(ErrorCode.NETWORK_ERROR);
    }
  });
});
