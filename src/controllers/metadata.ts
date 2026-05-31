import type { ArkimeClient } from '@/services/arkime-client.js';
import { formatJson } from '@/utils/formatters.js';
import type {
  CronListParams,
  NotifierListParams,
  ShareableListParams,
  HistoryListParams,
  RemoteClustersParams,
  CurrentUserParams,
  UserRolesParams,
  ValueActionsParams,
  FieldActionsParams,
} from '@/tools/schemas.js';
import type {
  ArkimeListResponse,
  RemoteClustersResponse,
  UserResponse,
  UserRolesResponse,
} from '@/types/arkime.js';

function renderList(title: string, response: ArkimeListResponse, emptyMsg: string): string {
  const items = Array.isArray(response.data) ? response.data : [];
  if (items.length === 0) return `${title}\n${'='.repeat(60)}\n\n${emptyMsg}`;
  return `${title}\n${'='.repeat(60)}\n\nTotal: ${items.length}\n\n${formatJson(items)}`;
}

// --- cron-list ---

export async function cronList(
  client: ArkimeClient,
  _params: CronListParams
): Promise<{ content: Array<{ type: 'text'; text: string }> }> {
  const response = await client.getCrons();
  const text = renderList('Periodic (Cron) Queries', response, 'No periodic queries found.');
  return { content: [{ type: 'text', text }] };
}

// --- notifier-list ---

export async function notifierList(
  client: ArkimeClient,
  _params: NotifierListParams
): Promise<{ content: Array<{ type: 'text'; text: string }> }> {
  const response = await client.getNotifiers();
  const text = renderList('Notifiers', response, 'No notifiers configured.');
  return { content: [{ type: 'text', text }] };
}

// --- shareable-list ---

export async function shareableList(
  client: ArkimeClient,
  _params: ShareableListParams
): Promise<{ content: Array<{ type: 'text'; text: string }> }> {
  const response = await client.getShareables();
  const text = renderList('Shareables', response, 'No shareables found.');
  return { content: [{ type: 'text', text }] };
}

// --- history-list ---

export async function historyList(
  client: ArkimeClient,
  params: HistoryListParams
): Promise<{ content: Array<{ type: 'text'; text: string }> }> {
  const response = await client.getHistories({ length: params.limit });
  const text = renderList('Request History', response, 'No history entries found.');
  return { content: [{ type: 'text', text }] };
}

// --- remote-clusters ---

export async function remoteClusters(
  client: ArkimeClient,
  _params: RemoteClustersParams
): Promise<{ content: Array<{ type: 'text'; text: string }> }> {
  const response: RemoteClustersResponse = await client.getRemoteClusters();

  const lines = ['Remote Clusters', '='.repeat(60), ''];

  const keys = Object.keys(response ?? {});
  if (keys.length === 0) {
    lines.push('No remote clusters configured.');
  } else {
    for (const key of keys) {
      lines.push(`- ${key}`);
    }
    lines.push('');
    lines.push(formatJson(response));
  }

  return { content: [{ type: 'text', text: lines.join('\n') }] };
}

// --- current-user ---

export async function currentUser(
  client: ArkimeClient,
  _params: CurrentUserParams
): Promise<{ content: Array<{ type: 'text'; text: string }> }> {
  const response: UserResponse = await client.getCurrentUser();

  const lines = ['Current User', '='.repeat(60), ''];

  if (response.userId) lines.push(`User ID: ${response.userId}`);
  if (response.userName) lines.push(`User Name: ${response.userName}`);
  if (response.roles && response.roles.length > 0) {
    lines.push(`Roles: ${response.roles.join(', ')}`);
  }
  lines.push('');
  lines.push(formatJson(response));

  return { content: [{ type: 'text', text: lines.join('\n') }] };
}

// --- user-roles ---

export async function userRoles(
  client: ArkimeClient,
  _params: UserRolesParams
): Promise<{ content: Array<{ type: 'text'; text: string }> }> {
  const response: UserRolesResponse = await client.getUserRoles();

  const lines = ['Assignable Roles', '='.repeat(60), ''];

  const roles = Array.isArray(response.roles) ? response.roles : [];
  if (roles.length === 0) {
    lines.push('No roles available.');
  } else {
    for (const role of roles) {
      lines.push(role);
    }
  }

  return { content: [{ type: 'text', text: lines.join('\n') }] };
}

// --- value-actions ---

export async function valueActions(
  client: ArkimeClient,
  _params: ValueActionsParams
): Promise<{ content: Array<{ type: 'text'; text: string }> }> {
  const response: Record<string, unknown> = await client.getValueActions();

  const lines = ['Value Actions', '='.repeat(60), ''];

  if (Object.keys(response ?? {}).length === 0) {
    lines.push('No value actions configured.');
  } else {
    lines.push(formatJson(response));
  }

  return { content: [{ type: 'text', text: lines.join('\n') }] };
}

// --- field-actions ---

export async function fieldActions(
  client: ArkimeClient,
  _params: FieldActionsParams
): Promise<{ content: Array<{ type: 'text'; text: string }> }> {
  const response: Record<string, unknown> = await client.getFieldActions();

  const lines = ['Field Actions', '='.repeat(60), ''];

  if (Object.keys(response ?? {}).length === 0) {
    lines.push('No field actions configured.');
  } else {
    lines.push(formatJson(response));
  }

  return { content: [{ type: 'text', text: lines.join('\n') }] };
}
