#!/usr/bin/env node
// Smoke-test MCP tool handlers against the real Arkime server.
import { readFileSync, existsSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const envPath = resolve(__dirname, '../.env');
if (existsSync(envPath)) {
  for (const line of readFileSync(envPath, 'utf-8').split('\n')) {
    const t = line.trim();
    if (!t || t.startsWith('#')) continue;
    const [k, ...v] = t.split('=');
    if (k && !process.env[k]) process.env[k] = v.join('=').replace(/^['"]|['"]$/g, '');
  }
}

const { ArkimeClient } = await import('../dist/services/arkime-client.js');
const { loadValidatedConfig } = await import('../dist/services/config.js');
const { searchSessions, getSession, getSessionSpi } = await import('../dist/controllers/sessions.js');
const { listFields } = await import('../dist/controllers/fields.js');
const { analyzeTraffic, huntSuspicious } = await import('../dist/controllers/analysis.js');
const { buildAttackTimeline, extractIocs } = await import('../dist/controllers/forensics.js');

const client = new ArkimeClient(loadValidatedConfig());

// Probe server for a recent timestamp of available data.
// Walk back up to ~2 years to find data.
const now = Math.floor(Date.now() / 1000);
let probe;
let center = null;
for (const daysBack of [1, 7, 30, 90, 180, 365, 730]) {
  probe = await client.searchSessions({ length: 1, startTime: now - daysBack * 86400, endTime: now });
  if (probe.data.length) {
    center = Math.floor(probe.data[0].firstPacket / 1000);
    break;
  }
}
if (!center) {
  console.error('Server has no data within the past 2 years');
  process.exit(1);
}
const startTime = new Date((center - 3600) * 1000).toISOString();
const endTime = new Date((center + 3600) * 1000).toISOString();
console.log(`Using time window around real data: ${startTime} -> ${endTime}`);

const results = [];
async function run(name, fn) {
  try {
    const r = await fn();
    const snippet = (r?.content?.[0]?.text || '').slice(0, 120).replace(/\n/g, ' ');
    results.push({ name, ok: !r?.isError, snippet });
    console.log(`  ${r?.isError ? 'FAIL' : 'OK  '} ${name}: ${snippet}`);
  } catch (e) {
    results.push({ name, ok: false, snippet: e.message });
    console.log(`  FAIL ${name}: ${e.message}`);
  }
}

console.log('\n=== MCP Tool Smoke Tests ===');

await run('list-fields', () => listFields(client, { group: 'general' }));
await run('search-sessions', () => searchSessions(client, { limit: 5, startTime, endTime }));
await run('get-session-spi', () => getSessionSpi(client, { expression: 'ipProtocol == 6', categories: ['all'], limit: 3 }));
await run('analyze-traffic:top-talkers', () => analyzeTraffic(client, { analysisType: 'top-talkers', limit: 5, startTime, endTime }));
await run('analyze-traffic:protocols', () => analyzeTraffic(client, { analysisType: 'protocols', limit: 5, startTime, endTime }));
await run('analyze-traffic:ports', () => analyzeTraffic(client, { analysisType: 'ports', limit: 5, startTime, endTime }));
await run('analyze-traffic:connections', () => analyzeTraffic(client, { analysisType: 'connections', limit: 5, startTime, endTime }));
await run('hunt-suspicious:port-scanners', () => huntSuspicious(client, { huntType: 'port-scanners', threshold: 10 }));
await run('hunt-suspicious:beaconing', () => huntSuspicious(client, { huntType: 'beaconing', threshold: 5 }));
await run('hunt-suspicious:data-exfil', () => huntSuspicious(client, { huntType: 'data-exfil', threshold: 1 }));
await run('hunt-suspicious:lateral-movement', () => huntSuspicious(client, { huntType: 'lateral-movement', threshold: 20 }));
await run('build-attack-timeline', () => buildAttackTimeline(client, { startTime, endTime }));
await run('extract-iocs', () => extractIocs(client, { expression: 'ipProtocol == 6', iocTypes: ['ip', 'domain'] }));

// get-session using an ID discovered via search
const searchRes = await client.searchSessions({ length: 1, startTime: center - 3600, endTime: center + 3600 });
if (searchRes.data[0]?.id) {
  await run('get-session', () => getSession(client, { id: searchRes.data[0].id }));
}

const fails = results.filter(r => !r.ok);
console.log(`\n${results.length - fails.length}/${results.length} tools OK`);
if (fails.length) {
  console.log('Failures:', fails.map(f => f.name).join(', '));
  process.exit(1);
}
