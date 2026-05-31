# Arkime MCP Server

[Model Context Protocol](https://modelcontextprotocol.io/) server that connects your AI assistant to an [Arkime](https://arkime.com/) network traffic analysis deployment. Exposes **55 read-only tools** for searching sessions, extracting PCAP data, hunting threats, building attack timelines, inspecting cluster/Elasticsearch health, and performing network forensics -- all through natural language.

## What This Does

Point an AI assistant (Claude Code, Cursor, Zed, etc.) at your Arkime server and ask questions in plain English:

- *"Show me all SMB traffic from 192.168.1.100 in the last hour"*
- *"Extract the PCAP for session 250101-AbCdEf12"*
- *"Are any hosts scanning ports on the internal network?"*
- *"Build a timeline of activity from this suspect IP"*
- *"What IOCs can you extract from this traffic?"*

The MCP server translates these requests into Arkime API calls, validates inputs, handles authentication, and returns structured results the AI can reason about.

## Prerequisites

- **Node.js 20+** (ES2022 required)
- **npm** (or any Node package manager)
- **Arkime server** with a working API (v3+)
- **API credentials** -- a user account with permission to query sessions

## Configuration

This server connects to **your** Arkime deployment. Configuration is entirely through environment variables -- no hard-coded endpoints.

### Environment Variables

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `ARKIME_HOST` | Yes | Arkime server URL | `https://arkime.your-domain.com:8005` |
| `ARKIME_USER` | Yes | API username | `api-user` |
| `ARKIME_PASSWORD` | Yes | API password | `your-secure-password` |
| `ARKIME_TIMEOUT` | No | Request timeout in milliseconds (default: `30000`) | `60000` |

### Security Notes

- **HTTPS is required** for non-localhost hosts. The server will refuse to connect over HTTP to a remote address.
- **HTTP is allowed** for `localhost` and `127.0.0.1` (useful for local development).
- Authentication uses **HTTP Digest auth** -- credentials are never sent in plain text.
- Environment variables are validated at startup. Invalid configuration produces a clear error message.

### Setting Environment Variables

Create a `.env` file in the project root:

```env
ARKIME_HOST=https://your-arkime-server.example.com:8005
ARKIME_USER=your-api-username
ARKIME_PASSWORD=your-api-password
# Optional: increase timeout for large queries (default: 30000)
# ARKIME_TIMEOUT=60000
```

The `.env` file is git-ignored. Never commit credentials.

For production deployments, set these variables in your deployment environment (systemd service file, docker-compose, CI/CD pipeline, etc.).

## Installation

```bash
# Clone the repository
git clone https://github.com/lflare/arkime-mcp.git
cd arkime-mcp

# Install dependencies
npm install

# Build for production
npm run build
```

## Usage

This server communicates over **stdio** (standard input/output), the standard transport for MCP servers. You configure your AI client to launch the server process and communicate with it through stdin/stdout.

### Claude Code

Add to your Claude Code configuration (`~/.claude/settings.json` or project-level `.claude/settings.json`):

```json
{
  "mcpServers": {
    "arkime": {
      "command": "node",
      "args": ["<path-to-arkime-mcp>/dist/index.js"],
      "env": {
        "ARKIME_HOST": "https://your-arkime-server.example.com:8005",
        "ARKIME_USER": "your-api-username",
        "ARKIME_PASSWORD": "your-api-password"
      }
    }
  }
}
```

Alternatively, if you've set the environment variables in your shell:

```json
{
  "mcpServers": {
    "arkime": {
      "command": "node",
      "args": ["<path-to-arkime-mcp>/dist/index.js"]
    }
  }
}
```

### Cursor

Add to your Cursor settings (`Cursor > Settings > MCP` or `.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "arkime": {
      "command": "node",
      "args": ["<path-to-arkime-mcp>/dist/index.js"],
      "env": {
        "ARKIME_HOST": "https://your-arkime-server.example.com:8005",
        "ARKIME_USER": "your-api-username",
        "ARKIME_PASSWORD": "your-api-password"
      }
    }
  }
}
```

### Zed

Add to your Zed settings (`~/.config/zed/settings.json`):

```json
{
  "mcp_servers": {
    "arkime": {
      "command": "node",
      "args": ["<path-to-arkime-mcp>/dist/index.js"],
      "env": {
        "ARKIME_HOST": "https://your-arkime-server.example.com:8005",
        "ARKIME_USER": "your-api-username",
        "ARKIME_PASSWORD": "your-api-password"
      }
    }
  }
}
```

### VS Code (with MCP extension)

Install an MCP client extension, then configure in your workspace or user settings:

```json
{
  "mcp.servers": {
    "arkime": {
      "command": "node",
      "args": ["<path-to-arkime-mcp>/dist/index.js"],
      "env": {
        "ARKIME_HOST": "https://your-arkime-server.example.com:8005",
        "ARKIME_USER": "your-api-username",
        "ARKIME_PASSWORD": "your-api-password"
      }
    }
  }
}
```

### Running Standalone

For testing or debugging, you can run the server directly:

```bash
export ARKIME_HOST=https://your-arkime-server.example.com:8005
export ARKIME_USER=your-api-username
export ARKIME_PASSWORD=your-api-password
node dist/index.js
```

The server will output `Arkime MCP Server running on stdio` to stderr and wait for requests on stdin/stdout.

## Available Tools

### Session Querying

| Tool | Description |
|------|-------------|
| `search-sessions` | Search network sessions using Arkime expressions. Filter by IP, port, protocol, time range, and any database field. Returns results in a tabular format. |
| `get-session` | Retrieve detailed information for a specific session by ID. Shows source/destination IPs, ports, protocol, bytes transferred, and all parsed metadata. |
| `list-fields` | Discover available database fields. Returns fields grouped by category (general, http, dns, smb, ldap, etc.) so you know what you can query. |

### PCAP & Packet Extraction

| Tool | Description |
|------|-------------|
| `get-pcap` | Extract raw PCAP data for sessions matching an expression. Returns base64-encoded PCAP (up to 10MB) suitable for opening in Wireshark. |
| `get-packet` | Extract PCAP for a single session by its session ID. Useful for deep packet inspection of a specific flow. |
| `get-flow` | Extract all packets for a TCP/UDP flow between two endpoints. Returns the complete stream for analysis (e.g., full SMB negotiation, HTTP transaction). |

### Traffic Analysis

| Tool | Description |
|------|-------------|
| `analyze-traffic` | Analyze traffic patterns: top talkers (most active IPs), protocol distribution, destination port usage, or source-destination connection pairs. |
| `hunt-suspicious` | Hunt for suspicious activity: port scanners, beaconing (C2-like periodic connections), data exfiltration (large outbound transfers), and lateral movement patterns. |

### Session Protocol Information (SPI)

| Tool | Description |
|------|-------------|
| `get-session-spi` | Extract parsed application-layer data from sessions: DNS queries, HTTP URIs and headers, TLS SNI, email headers, file transfer details, SOCKS, and SSH metadata. |
| `spi-sessions` | Get SPI data grouped by field for sessions matching an expression. Useful for bulk extraction of domains queried, URLs accessed, or certificates observed. |

### Network Forensics

| Tool | Description |
|------|-------------|
| `investigate-ntlm` | Investigate NTLM authentication and lateral movement. Searches SMB, LDAP, and Kerberos traffic for suspicious auth patterns, user enumeration, and domain reconnaissance. |
| `build-attack-timeline` | Build a chronological timeline of network events for a suspect IP or user. Correlates SMB auth, LDAP queries, Kerberos tickets, HTTP requests, and DNS queries. |
| `track-lateral-movement` | Analyze lateral movement across hosts. Builds a relationship graph (GraphViz output) showing which hosts connected to which, via what protocols, using what accounts. |
| `extract-iocs` | Extract Indicators of Compromise from traffic: external IPs, domains, URLs, file hashes, and email addresses. Automatically filters private/internal IPs. |

### Network Explorer

| Tool | Description |
|------|-------------|
| `top-talkers` | Get the top N values for any database field by session count. Works with any field (sourceIP, domain, tlsSNI, httpHost, protocol, etc.). |
| `reverse-dns` | Look up reverse DNS (PTR) records for an IP from captured traffic. |
| `dns-lookups` | Search DNS queries captured in traffic. Filter by domain pattern or source IP. |
| `geo-summary` | Break down destination traffic by country using GeoIP data. Shows session counts and percentages per country. |
| `capture-status` | Check Arkime cluster health: viewer and capture nodes, versions, roles, and uptime. |
| `pcap-files` | List PCAP capture files with sizes, session counts, and time ranges. Useful for understanding capture coverage. |

### Aggregate Data

| Tool | Description |
|------|-------------|
| `sessions-summary` | Get aggregate statistics for matching sessions: histograms, connection counts, total bytes, and packet counts. |
| `multi-unique` | Get unique values for multiple database fields in a single API call. More efficient than calling `top-talkers` repeatedly. |
| `connections` | Get a network connection graph showing nodes (IPs) and links (connections between them) with session counts, packets, and bytes. |

### Session Detail & Files

| Tool | Description |
|------|-------------|
| `session-detail` | Get every parsed field for a specific session. Returns the complete session object including all SPI data extracted by Arkime. |
| `session-file` | Download a file that was transferred within a session, identified by its hash. Useful for retrieving malware samples or documents captured in traffic. |

### System Information

| Tool | Description |
|------|-------------|
| `hunt-list` | List all active packet hunts configured in Arkime. Hunts monitor live traffic for matching expressions. |
| `view-list` | List saved views (saved searches) in Arkime. |
| `shortcut-list` | List saved query shortcuts in Arkime. |
| `app-info` | Get comprehensive application information: current user, Elasticsearch health, cluster status, and view counts. |
| `node-stats` | Get per-node statistics: packets processed, bytes captured, sessions created, and node roles. |

### Field Aggregation & Query Building

| Tool | Description |
|------|-------------|
| `spi-graph` | Aggregate a single field across matching sessions and return value counts (a spigraph). Great for "top values" of any field over a time range. |
| `spi-graph-hierarchy` | Aggregate an ordered list of fields as a nested hierarchy (treemap/pie data) for drill-down analysis. |
| `build-query` | Compile an Arkime search expression into the underlying OpenSearch/Elasticsearch query *without running it*. Validates syntax and catches mistakes like `AND` vs `&&` or `source.ip` vs `ip.src`. |
| `list-decodings` | List the packet decodings (gzip, base64, etc.) Arkime can apply when extracting session data. |

### Configuration & Metadata Listings

| Tool | Description |
|------|-------------|
| `cron-list` | List periodic (cron) queries -- saved expressions that run on a schedule to tag matching sessions. |
| `notifier-list` | List configured notifiers (Slack, email, webhook, etc.) used for alerts. |
| `shareable-list` | List shareable links/items configured in Arkime. |
| `history-list` | List recent API request history (audit log) for the current user. |
| `remote-clusters` | List remote Arkime clusters known to this viewer (cross-cluster search and forwarding). |
| `current-user` | Get the current authenticated user, including ID, name, and assigned roles/permissions. |
| `user-roles` | List the roles the current user is allowed to see or assign. |
| `value-actions` | List configured right-click value actions (custom menu actions on field values). |
| `field-actions` | List configured field actions (custom menu actions on fields). |

### Elasticsearch & Cluster Health

| Tool | Description |
|------|-------------|
| `es-health` | Get Elasticsearch/OpenSearch cluster health: status (green/yellow/red), node counts, and shard counts. |
| `es-stats` | Get per-node Elasticsearch/OpenSearch statistics (heap, disk, document counts, load). |
| `es-indices` | List the Elasticsearch/OpenSearch indices backing Arkime, with sizes and document counts. |
| `es-shards` | Show shard allocation across nodes, including any allocation excludes. |
| `es-tasks` | List currently running Elasticsearch/OpenSearch tasks. Useful for spotting stuck operations. |
| `es-recovery` | Show shard recovery status (shards relocating or initializing). |
| `node-dstats` | Get time-series stats for a capture node (or ALL nodes), e.g. deltaPackets/deltaBytes over a window. Useful for spotting capture gaps. |
| `app-version` | Get the Arkime viewer version and backend Elasticsearch/OpenSearch version. |

### Session Binary Data

| Tool | Description |
|------|-------------|
| `get-session-packets` | Get the decoded per-packet breakdown Arkime parsed for a session (structured JSON). Requires `nodeId` and `sessionId`. |
| `get-session-pcap` | Extract the entire PCAP for a single session as a base64 resource for Wireshark. Requires `nodeId` and `sessionId`. |
| `get-session-raw` | Extract the raw packet payload bytes for a single session as a base64 resource. Requires `nodeId` and `sessionId`. |
| `get-session-body` | Extract a specific transferred body/file from a session by body type and index, as a base64 resource. |

## Example Workflows

### Investigate a Suspect Host

```
1. search-sessions    → expression: "ip.src == 192.168.1.100"
2. get-session        → id: "250101-AbCdEf12" (from search results)
3. get-packet         → sessionId: "250101-AbCdEf12" (PCAP for Wireshark)
4. extract-iocs       → expression: "ip.src == 192.168.1.100"
5. build-attack-timeline → suspectIp: "192.168.1.100"
```

### Hunt for Threats

```
1. hunt-suspicious    → huntType: "port-scanners"
2. investigate-ntlm   → suspectIp: (from hunt results)
3. track-lateral-movement → sourceIp: (from investigation)
4. extract-iocs       → expression: (from movement tracking)
```

### Understand the Network

```
1. capture-status     → verify Arkime is healthy
2. list-fields        → discover available fields
3. analyze-traffic    → analysisType: "top-talkers"
4. geo-summary        → see traffic by country
5. sessions-summary   → get aggregate statistics
```

## Search Expressions

Arkime uses its own expression language. Common patterns:

| Goal | Expression |
|------|-----------|
| Filter by source IP | `ip.src == 192.168.1.1` |
| Filter by destination port | `port.dst == 443` |
| Filter by protocol | `ipProtocol == 6` (TCP) or `ipProtocol == 17` (UDP) |
| Filter by domain | `domain == example.com` |
| Filter by HTTP host | `http.host contains api` |
| Filter by SMB user | `smb.user == admin` |
| Time range | Use `startTime`/`endTime` parameters (ISO 8601) |
| Combine conditions | Use `AND`, `OR`, `&&`, `||` |

Note: Expression syntax differs from database field names. Use `ip.src` in expressions, but `source.ip` when requesting fields.

## Development

```bash
# Install dependencies
npm install

# Development mode (watch for changes)
npm run dev

# Build for production
npm run build

# Run tests
npm test

# Run a single test file
npm test -- tests/unit/flow.test.ts

# Run tests with coverage
npm run test:coverage

# Lint
npm run lint          # check
npm run lint:fix      # auto-fix

# Type check
npm run typecheck
```

### Project Structure

```
src/
├── index.ts                 # Entry point (stdio transport)
├── server.ts                # MCP server creation
├── controllers/             # Request handlers (55 tools)
│   ├── sessions.ts          # search-sessions, get-session, get-session-spi
│   ├── pcap.ts              # get-pcap (bulk PCAP extraction)
│   ├── packet.ts            # get-packet (single session PCAP)
│   ├── flow.ts              # get-flow (TCP/UDP flow extraction)
│   ├── analysis.ts          # analyze-traffic, hunt-suspicious
│   ├── forensics.ts         # build-attack-timeline, track-lateral-movement, extract-iocs
│   ├── investigation.ts     # investigate-ntlm
│   ├── explorer.ts          # top-talkers, reverse-dns, dns-lookups, geo-summary, capture-status, pcap-files
│   ├── gap-fill.ts          # sessions-summary, multi-unique, connections, spi-sessions,
│   │                         # session-detail, hunt-list, view-list, shortcut-list,
│   │                         # app-info, node-stats, session-file
│   ├── analytics.ts         # spi-graph, spi-graph-hierarchy, build-query, list-decodings
│   ├── metadata.ts          # cron-list, notifier-list, shareable-list, history-list, remote-clusters,
│   │                         # current-user, user-roles, value-actions, field-actions
│   ├── es-health.ts         # es-health, es-stats, es-indices, es-shards, es-tasks, es-recovery,
│   │                         # node-dstats, app-version
│   ├── session-data.ts      # get-session-packets, get-session-pcap, get-session-raw, get-session-body
│   └── fields.ts            # list-fields
├── tools/
│   ├── schemas.ts           # Zod validation schemas (one per tool)
│   └── index.ts             # Tool registration
├── services/
│   ├── arkime-client.ts     # Arkime API client (digest auth)
│   └── config.ts            # Environment configuration
├── utils/
│   ├── errors.ts            # McpError class and ErrorCode enum
│   └── formatters.ts        # Response formatting utilities
└── types/
    ├── arkime.ts            # Arkime API type definitions
    └── mcp-sdk.d.ts         # MCP SDK type augmentations
```

## Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| `AUTH_MISSING` | Missing `ARKIME_HOST`, `ARKIME_USER`, or `ARKIME_PASSWORD` | Set all required environment variables |
| `AUTH_INVALID` | Digest auth failed after retries | Verify credentials are correct and the user has API access |
| `CONFIG_ERROR` | Invalid configuration (e.g., HTTP to non-localhost host, negative timeout) | Use HTTPS for remote hosts; ensure timeout is positive |
| `NETWORK_ERROR` | Cannot reach Arkime server | Check `ARKIME_HOST` URL, network connectivity, and firewall rules |
| `NOT_FOUND` | Session or resource doesn't exist | Verify the session ID from `search-sessions` results |
| `API_ERROR` | Arkime API returned 5xx | Check Arkime server logs; the service may be under load |

### Debug Output

The server prints status messages to stderr:

```
Arkime MCP Server running on stdio
```

If you see this message, the server started successfully. Any configuration or connection errors are also printed to stderr.

### Arkime API Version

This server uses the Arkime v3 API. Check your Arkime version with the `app-info` tool after connecting.

## License

[GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0-or-later). See the [`LICENSE`](LICENSE) file for the full text.
