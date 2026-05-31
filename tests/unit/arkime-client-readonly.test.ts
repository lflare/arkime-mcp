import { describe, it, expect } from 'vitest';
import { ArkimeClient } from '@/services/arkime-client';
import type { ArkimeConfig } from '@/services/config';

describe('ArkimeClient read-only endpoint methods', () => {
  // Non-routable localhost port so connection refuses immediately.
  const config: ArkimeConfig = {
    host: 'http://127.0.0.1:1',
    user: 'admin',
    password: 'secret',
    timeout: 2000,
  };

  const client = () => new ArkimeClient(config);

  // --- analytics ---
  it('getSpiGraph throws when server unavailable', async () => {
    await expect(client().getSpiGraph('destination.ip', { expression: 'tcp', size: 10 })).rejects.toThrow();
  });

  it('getSpiGraphHierarchy throws when server unavailable', async () => {
    await expect(client().getSpiGraphHierarchy('source.ip,destination.ip', { expression: 'tcp' })).rejects.toThrow();
  });

  it('getBuildQuery throws when server unavailable', async () => {
    await expect(client().getBuildQuery({ expression: 'ip.src == 1.2.3.4' })).rejects.toThrow();
  });

  it('getDecodings throws when server unavailable', async () => {
    await expect(client().getDecodings()).rejects.toThrow();
  });

  // --- metadata ---
  it('getCrons throws when server unavailable', async () => {
    await expect(client().getCrons()).rejects.toThrow();
  });

  it('getNotifiers throws when server unavailable', async () => {
    await expect(client().getNotifiers()).rejects.toThrow();
  });

  it('getShareables throws when server unavailable', async () => {
    await expect(client().getShareables()).rejects.toThrow();
  });

  it('getHistories throws when server unavailable', async () => {
    await expect(client().getHistories({ length: 50 })).rejects.toThrow();
  });

  it('getRemoteClusters throws when server unavailable', async () => {
    await expect(client().getRemoteClusters()).rejects.toThrow();
  });

  it('getCurrentUser throws when server unavailable', async () => {
    await expect(client().getCurrentUser()).rejects.toThrow();
  });

  it('getUserRoles throws when server unavailable', async () => {
    await expect(client().getUserRoles()).rejects.toThrow();
  });

  it('getValueActions throws when server unavailable', async () => {
    await expect(client().getValueActions()).rejects.toThrow();
  });

  it('getFieldActions throws when server unavailable', async () => {
    await expect(client().getFieldActions()).rejects.toThrow();
  });

  // --- ES / cluster health ---
  it('getEsHealth throws when server unavailable', async () => {
    await expect(client().getEsHealth()).rejects.toThrow();
  });

  it('getEsStats throws when server unavailable', async () => {
    await expect(client().getEsStats()).rejects.toThrow();
  });

  it('getEsIndices throws when server unavailable', async () => {
    await expect(client().getEsIndices()).rejects.toThrow();
  });

  it('getEsShards throws when server unavailable', async () => {
    await expect(client().getEsShards()).rejects.toThrow();
  });

  it('getEsTasks throws when server unavailable', async () => {
    await expect(client().getEsTasks()).rejects.toThrow();
  });

  it('getEsRecovery throws when server unavailable', async () => {
    await expect(client().getEsRecovery()).rejects.toThrow();
  });

  it('getDstats throws when server unavailable', async () => {
    await expect(client().getDstats({ nodeName: 'ALL', name: 'deltaPackets' })).rejects.toThrow();
  });

  it('getAppVersion throws when server unavailable', async () => {
    await expect(client().getAppVersion()).rejects.toThrow();
  });

  // --- session binary data ---
  it('getSessionPackets throws when server unavailable', async () => {
    await expect(client().getSessionPackets('node1', '250101-abc')).rejects.toThrow();
  });
});
