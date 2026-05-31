import { describe, it, expect } from 'vitest';
import {
  cronList,
  notifierList,
  shareableList,
  historyList,
  remoteClusters,
  currentUser,
  userRoles,
  valueActions,
  fieldActions,
} from '@/controllers/metadata.js';
import { ArkimeClient } from '@/services/arkime-client.js';

describe('cronList', () => {
  it('should return periodic queries', async () => {
    const client = {
      getCrons: async () => ({ success: true, data: [{ name: 'daily' }] }),
    } as unknown as ArkimeClient;

    const result = await cronList(client, {});

    expect(result.content[0].type).toBe('text');
    expect(result.content[0].text).toContain('Periodic');
    expect(result.content[0].text).toContain('daily');
    expect(result.content[0].text).toContain('Total: 1');
  });

  it('should handle empty results', async () => {
    const client = {
      getCrons: async () => ({ success: true, data: [] }),
    } as unknown as ArkimeClient;

    const result = await cronList(client, {});

    expect(result.content[0].text).toContain('No periodic queries found.');
  });
});

describe('notifierList', () => {
  it('should return notifiers', async () => {
    const client = {
      getNotifiers: async () => ({ success: true, data: [{ name: 'slack-alerts' }] }),
    } as unknown as ArkimeClient;

    const result = await notifierList(client, {});

    expect(result.content[0].text).toContain('Notifiers');
    expect(result.content[0].text).toContain('slack-alerts');
    expect(result.content[0].text).toContain('Total: 1');
  });

  it('should handle empty results', async () => {
    const client = {
      getNotifiers: async () => ({ success: true, data: [] }),
    } as unknown as ArkimeClient;

    const result = await notifierList(client, {});

    expect(result.content[0].text).toContain('No notifiers configured.');
  });
});

describe('shareableList', () => {
  it('should return shareables', async () => {
    const client = {
      getShareables: async () => ({ success: true, data: [{ name: 'team-view' }] }),
    } as unknown as ArkimeClient;

    const result = await shareableList(client, {});

    expect(result.content[0].text).toContain('Shareables');
    expect(result.content[0].text).toContain('team-view');
    expect(result.content[0].text).toContain('Total: 1');
  });

  it('should handle empty results', async () => {
    const client = {
      getShareables: async () => ({ success: true, data: [] }),
    } as unknown as ArkimeClient;

    const result = await shareableList(client, {});

    expect(result.content[0].text).toContain('No shareables found.');
  });
});

describe('historyList', () => {
  it('should return request history', async () => {
    const client = {
      getHistories: async () => ({ success: true, data: [{ uiPage: 'sessions', api: '/api/sessions' }] }),
    } as unknown as ArkimeClient;

    const result = await historyList(client, { limit: 10 });

    expect(result.content[0].text).toContain('Request History');
    expect(result.content[0].text).toContain('/api/sessions');
    expect(result.content[0].text).toContain('Total: 1');
  });

  it('should handle empty results', async () => {
    const client = {
      getHistories: async () => ({ success: true, data: [] }),
    } as unknown as ArkimeClient;

    const result = await historyList(client, { limit: 10 });

    expect(result.content[0].text).toContain('No history entries found.');
  });
});

describe('remoteClusters', () => {
  it('should return remote clusters', async () => {
    const client = {
      getRemoteClusters: async () => ({
        cluster1: { url: 'https://remote1.example.com' },
        cluster2: { url: 'https://remote2.example.com' },
      }),
    } as unknown as ArkimeClient;

    const result = await remoteClusters(client, {});

    expect(result.content[0].text).toContain('Remote Clusters');
    expect(result.content[0].text).toContain('cluster1');
    expect(result.content[0].text).toContain('cluster2');
  });

  it('should handle no remote clusters', async () => {
    const client = {
      getRemoteClusters: async () => ({}),
    } as unknown as ArkimeClient;

    const result = await remoteClusters(client, {});

    expect(result.content[0].text).toContain('No remote clusters configured.');
  });
});

describe('currentUser', () => {
  it('should return current user details', async () => {
    const client = {
      getCurrentUser: async () => ({
        userId: 'admin',
        userName: 'Administrator',
        roles: ['arkimeAdmin', 'arkimeUser'],
      }),
    } as unknown as ArkimeClient;

    const result = await currentUser(client, {});

    expect(result.content[0].text).toContain('Current User');
    expect(result.content[0].text).toContain('User ID: admin');
    expect(result.content[0].text).toContain('User Name: Administrator');
    expect(result.content[0].text).toContain('Roles: arkimeAdmin, arkimeUser');
  });

  it('should handle empty user response', async () => {
    const client = {
      getCurrentUser: async () => ({}),
    } as unknown as ArkimeClient;

    const result = await currentUser(client, {});

    expect(result.content[0].text).toContain('Current User');
  });
});

describe('userRoles', () => {
  it('should return assignable roles', async () => {
    const client = {
      getUserRoles: async () => ({ roles: ['arkimeAdmin', 'arkimeUser', 'cont3xtUser'] }),
    } as unknown as ArkimeClient;

    const result = await userRoles(client, {});

    expect(result.content[0].text).toContain('Assignable Roles');
    expect(result.content[0].text).toContain('arkimeAdmin');
    expect(result.content[0].text).toContain('cont3xtUser');
  });

  it('should handle no roles', async () => {
    const client = {
      getUserRoles: async () => ({ roles: [] }),
    } as unknown as ArkimeClient;

    const result = await userRoles(client, {});

    expect(result.content[0].text).toContain('No roles available.');
  });
});

describe('valueActions', () => {
  it('should return value actions', async () => {
    const client = {
      getValueActions: async () => ({
        VirusTotal: { name: 'VirusTotal', url: 'https://virustotal.com/%TEXT%' },
      }),
    } as unknown as ArkimeClient;

    const result = await valueActions(client, {});

    expect(result.content[0].text).toContain('Value Actions');
    expect(result.content[0].text).toContain('VirusTotal');
  });

  it('should handle no value actions', async () => {
    const client = {
      getValueActions: async () => ({}),
    } as unknown as ArkimeClient;

    const result = await valueActions(client, {});

    expect(result.content[0].text).toContain('No value actions configured.');
  });
});

describe('fieldActions', () => {
  it('should return field actions', async () => {
    const client = {
      getFieldActions: async () => ({
        OpenSearch: { name: 'OpenSearch', url: 'https://search.example.com/%FIELD%' },
      }),
    } as unknown as ArkimeClient;

    const result = await fieldActions(client, {});

    expect(result.content[0].text).toContain('Field Actions');
    expect(result.content[0].text).toContain('OpenSearch');
  });

  it('should handle no field actions', async () => {
    const client = {
      getFieldActions: async () => ({}),
    } as unknown as ArkimeClient;

    const result = await fieldActions(client, {});

    expect(result.content[0].text).toContain('No field actions configured.');
  });
});
