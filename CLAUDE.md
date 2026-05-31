# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Purpose**: MCP (Model Context Protocol) server for Arkime, enabling LLM-assisted network traffic investigations.

**Tech Stack**: TypeScript, Node.js (ES2022), @modelcontextprotocol/sdk, axios, Zod

**Arkime API**: https://arkime.com/apiv3 — HTTP Digest authentication required for all endpoints.

## Build/Lint/Test Commands

```bash
# Install dependencies
npm install

# Development mode (watch)
npm run dev

# Build production (tsc + tsc-alias for path alias resolution)
npm run build

# Run all tests
npm test

# Run single test file
npm test -- tests/unit/flow.test.ts

# Run tests with coverage
npm run test:coverage

# Lint check / auto-fix
npm run lint
npm run lint:fix

# Type check
npm run typecheck

# Start built server
npm start
```

## Architecture

Request flow for a single tool call:

```
MCP Client (LLM)
  |
  v
index.ts -> createServer() -> StdioServerTransport
  |
  v
tools/index.ts -> server.tool('name', desc, schema.shape, wrapHandler(handler))
  |
  v
tools/schemas.ts -> Zod schema validates input, infers typed params
  |
  v
controllers/*.ts -> business logic, calls ArkimeClient methods, formats responses
  |
  v
services/arkime-client.ts -> HTTP client with digest auth, builds URLs/params
  |
  v
Arkime API -> JSON response or Buffer (PCAP data)
```

Key design decisions:

- **Controllers receive `ArkimeClient` as a parameter** — this enables dependency injection for testing. Never instantiate `ArkimeClient` in a controller; always accept it as an argument.
- **`tools/index.ts` uses a lazy `getClient()` singleton** — the client is created on first tool call, not at module load. Config errors surface when the tool is actually invoked.
- **`wrapHandler()` is a type passthrough** — it preserves Zod-inferred types through the MCP SDK's `(params: unknown) => Promise<unknown>` signature. It does not handle errors.
- **Controllers throw `McpError`** — errors propagate through `wrapHandler` to the MCP SDK, which converts them to MCP error responses.

### Digest Auth Flow

`ArkimeClient.request()` implements digest auth in two phases:

1. **First call (no nonce)**: Sends unauthenticated request. On 401, parses `WWW-Authenticate` header for `realm`, `nonce`, `qop`. Then builds and sends the digest auth header.
2. **Subsequent calls**: Uses cached nonce to build `Authorization` header directly. On 401, increments `authRetries` and retries up to `MAX_AUTH_RETRIES` (2) before throwing `AUTH_INVALID`.

Some methods (`getPcap`, `getSessionBody`, etc.) return `Buffer` via `responseType: 'arraybuffer'`. The `request()` method handles this by wrapping `Buffer.from(response.data)` before return.

### Error Classification

`McpError` uses `ErrorCode` to classify failures:

- `AUTH_MISSING` / `AUTH_INVALID` — missing env vars or digest auth failure
- `API_ERROR` — Arkime API errors (5xx, generic `Error`, string errors)
- `NETWORK_ERROR` — no response (connection refused, timeout)
- `INVALID_INPUT` — bad parameters (Zod handles most validation)
- `NOT_FOUND` — 404 responses or session not found
- `CONFIG_ERROR` — invalid config values (e.g., negative timeout)

`ArkimeClient.handleError()` is the single error classification point:
- No response → `NETWORK_ERROR`
- 401 → `AUTH_INVALID` (after retry exhaustion in `request()`)
- 404 → `NOT_FOUND`
- 5xx → `API_ERROR`
- `Error` instance → `API_ERROR` with message
- String/other → `API_ERROR` with "Unknown error occurred"

## Project Structure

```
src/
├── index.ts              # Entry: createServer() -> connect(StdioServerTransport)
├── server.ts             # createServer() — creates McpServer, calls registerTools()
├── controllers/          # Request handlers (10 files, 30 tools total)
│   ├── sessions.ts       # searchSessions, getSession, getSessionSpi
│   ├── fields.ts         # listFields
│   ├── pcap.ts           # getPcap (bulk PCAP extraction)
│   ├── packet.ts         # getPacket (single session PCAP)
│   ├── flow.ts           # getFlow (TCP/UDP flow between endpoints)
│   ├── analysis.ts       # analyzeTraffic, huntSuspicious
│   ├── forensics.ts      # buildAttackTimeline, trackLateralMovement, extractIocs
│   ├── investigation.ts  # investigateNtlm
│   ├── explorer.ts       # topTalkers, reverseDns, dnsLookups, geoSummary, captureStatus, pcapFiles
│   └── gap-fill.ts       # sessionsSummary, multiUnique, connections, spiSessions,
│                          # sessionDetail, huntList, viewList, shortcutList,
│                          # appInfo, nodeStats, sessionFile
├── tools/
│   ├── schemas.ts        # 32 Zod schemas with type exports
│   └── index.ts          # registerTools() — 30 server.tool() calls
├── services/
│   ├── arkime-client.ts  # ArkimeClient class — digest auth, ~20 API methods
│   └── config.ts         # loadConfig(), validateConfig(), loadValidatedConfig()
├── utils/
│   ├── errors.ts         # McpError class, ErrorCode enum
│   └── formatters.ts     # formatTable, formatSession, formatBytes, isPrivateIp, etc.
└── types/
    ├── arkime.ts         # Arkime API types + type guards (isSession, isFieldDefinition)
    └── mcp-sdk.d.ts      # MCP SDK type augmentations
```

## Code Style Guidelines

### Imports

```typescript
// 1. Node.js built-ins
import { readFileSync } from 'fs';

// 2. External packages (alphabetical)
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import axios from 'axios';

// 3. Internal modules (alphabetical, use @/ path aliases)
import { searchSessions } from '@/controllers/sessions.js';
import { ArkimeClient } from '@/services/arkime-client.js';
import { McpError } from '@/utils/errors.js';

// Blank line between each group. Always include .js extension in imports.
```

### TypeScript Configuration

- **Strict mode**: Enabled
- **Target**: ES2022
- **Module**: NodeNext with ESM
- **Path aliases**: `@/*` maps to `src/*` (resolved by `tsc-alias` at build time)
- **No `any`**: Use `unknown` with type guards

### Naming Conventions

| Type | Convention | Example |
|------|------------|---------|
| Files | kebab-case | `search-sessions.ts` |
| Classes | PascalCase | `ArkimeClient` |
| Interfaces | PascalCase (no `I` prefix) | `SessionQuery` |
| Functions | camelCase | `buildSearchQuery()` |
| Constants | SCREAMING_SNAKE | `MAX_RESULT_LENGTH` |
| Zod schemas | camelCase + `Schema` | `searchSessionsSchema` |
| Types | PascalCase | `SearchSessionsParams` |

## Environment Variables

```bash
ARKIME_HOST      # Required: Arkime server URL (e.g., https://arkime.example.com:8005)
ARKIME_USER      # Required: API username
ARKIME_PASSWORD  # Required: API password
ARKIME_TIMEOUT   # Optional: Request timeout in ms (default: 30000)
```

Config is validated at `loadValidatedConfig()` time: requires host/user/password, enforces HTTPS for non-localhost hosts, and rejects negative/zero timeout. HTTP is allowed for `localhost` and `127.0.0.1`.

## Testing Guidelines

### Test Structure

- Unit tests: `tests/unit/*.test.ts` (32 files, ~561 tests)
- Integration tests: `tests/integration/*.test.ts` (auto-skip when no API credentials)

### Mocking Pattern

Controllers accept `ArkimeClient` as a parameter. Tests create inline mock clients:

```typescript
const client = {
  searchSessions: async () => ({ data: [...], recordsTotal: 1, recordsFiltered: 1 }),
} as unknown as ArkimeClient;

const result = await searchSessions(client, { expression: 'ip.src == 1.2.3.4' });
```

For connection-refusal tests, create a real `ArkimeClient` with an unreachable host:

```typescript
const client = new ArkimeClient({
  host: 'http://127.0.0.1:1',  // connection refused
  user: 'admin',
  password: 'secret',
  timeout: 2000,
});
// Any API call will throw McpError(ErrorCode.NETWORK_ERROR)
```

For API error propagation tests, throw typed `McpError` from the mock:

```typescript
const client = {
  searchSessions: async () => {
    throw new McpError(ErrorCode.API_ERROR, 'Internal Server Error');
  },
} as unknown as ArkimeClient;
```

### Running Tests

```bash
npm test                          # all tests
npm test -- tests/unit/flow.test.ts  # single file
npm test -- --watch               # watch mode
npm run test:coverage             # coverage report
```

## Arkime API Notes

- **Field names**: Database fields (`source.ip`) differ from expression fields (`ip.src`)
- **Date handling**: `searchSessions` uses `date` param (hours) by default; `startTime`/`endTime` override it. Arkime expects `stopTime`, not `endTime`.
- **Pagination**: Use `start` and `length` params. Arkime caps at 2,000,000 sessions.
- **Session ID format**: `YYYYMMDD-shortId` (e.g., `260127-GwFt1w7eKJREbKdq8VYTsuEk`). Node-prefixed IDs use `node@id` format.

### PCAP Extraction

Three tools extract raw packet data:

- **get-pcap**: Bulk extraction. Expression uses `&&`/`||` (not `AND`/`OR`). Uses `ip.src`/`ip.dst`, not `source.ip`.
- **get-packet**: Single session by ID. Handles `node@id` format. Builds `id=="${shortId}"` expression.
- **get-flow**: Flow between two endpoints. Builds flow expression with protocol/port filters. TCP → `ip.protocol == 6`, UDP → `ip.protocol == 17`.

All three return base64-encoded PCAP as MCP resource content, with MD5 hash in the text response.

### Key Endpoints (All Exposed via MCP Tools)

| Endpoint | MCP Tool |
|----------|----------|
| `GET /api/sessions` | `search-sessions` |
| `GET /api/session/:id` | `get-session` |
| `GET /api/session/:node/:id/detail` | `session-detail` |
| `GET /api/session/:node/:id/packets` | `get-packet` |
| `GET /api/fields` | `list-fields` |
| `GET /api/unique/:field` | `unique-values` |
| `GET /api/multiunique` | `multi-unique` |
| `GET /api/sessions/summary` | `sessions-summary` |
| `GET /api/connections` | `connections` |
| `GET /api/spiview` | `spi-sessions` |
| `GET /api/clusters` | `capture-status` |
| `GET /api/files` | `pcap-files` |
| `GET /api/hunts` | `hunt-list` |
| `GET /api/views` | `view-list` |
| `GET /api/shortcuts` | `shortcut-list` |
| `GET /api/appinfo` | `app-info` |
| `GET /api/stats` | `node-stats` |
| `GET /api/reversedns` | `reverse-dns` |
| `POST /api/sessions/pcap` | `get-pcap` |
| Session body/hash/flow | `session-file`, `get-flow`, `get-packet` |

## Git Commit Guidelines

**Make a conventional git commit after every logical change.**  Do not batch multiple unrelated changes into a single commit.

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>
```

**Types**: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

## MCP Tool Design Principles

1. **Clear descriptions**: Each tool needs a detailed description for LLM understanding
2. **Schema validation**: All inputs validated via Zod (32 schemas)
3. **Token-efficient responses**: Use tables, summaries, not verbose JSON
4. **Error context**: Include actionable error messages
5. **Pagination**: Support limit/offset for large result sets
