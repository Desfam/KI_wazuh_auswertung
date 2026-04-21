# Wazuh Data Reference — KI Wazuh Auswertung

> Comprehensive reference for all Wazuh data sources, APIs, index patterns, and field schemas.  
> Based on Wazuh v4.14.x source code and official documentation.  
> Use this file as the authoritative guide when building or extending backend services.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Data Source: Wazuh Indexer REST API](#2-data-source-wazuh-indexer-rest-api)
3. [All Index Patterns](#3-all-index-patterns)
4. [Index Field Schemas](#4-index-field-schemas)
5. [Data Source: Wazuh Manager API](#5-data-source-wazuh-manager-api)
6. [Syscollector Endpoints (per-agent)](#6-syscollector-endpoints-per-agent)
7. [Data Source: alerts.json / archives.json](#7-data-source-alertsjson--archivesjson)
8. [Agent Field Mapping (version quirks)](#8-agent-field-mapping-version-quirks)
9. [How Our App Currently Uses Each Source](#9-how-our-app-currently-uses-each-source)
10. [Query Patterns & Examples](#10-query-patterns--examples)
11. [Authentication Methods](#11-authentication-methods)
12. [Known Gaps & Opportunities](#12-known-gaps--opportunities)

---

## 1. Architecture Overview

```
[Wazuh Agents] ──OSSEC/TCP──► [Wazuh Manager]
                                    │
                          analyses events
                          writes alerts.json
                          writes archives.json (if enabled)
                                    │
                              [Filebeat]
                                    │ HTTP POST /_bulk
                                    ▼
                          [Wazuh Indexer]  ← OpenSearch-compatible
                          (port 9200, HTTPS)
                                    │
                          stores in daily indices
                          wazuh-alerts-4.x-YYYY.MM.DD
                                    │
                              [Our Backend]
                              queries via _search
```

**Three independent data paths:**

| Path | What it contains | How we access it |
|------|-----------------|-----------------|
| Wazuh Indexer API | Indexed alerts, vuln states, inventory states | REST API `POST /index/_search` |
| Wazuh Manager API | Agent metadata, live Syscollector data, SCA, FIM database | REST API `GET /agents`, `/syscollector`, etc. |
| Local log files | Raw JSON events, all data before indexing | Read `/var/ossec/logs/alerts/alerts.json` directly on manager |

---

## 2. Data Source: Wazuh Indexer REST API

### Connection

```python
BASE_URL = "https://<indexer_host>:9200"
AUTH = ("admin", "<password>")   # Basic auth
VERIFY_SSL = False               # or path to CA cert
```

### Standard search request

```http
POST /{index_pattern}/_search
Content-Type: application/json
Authorization: Basic <base64>
```

```json
{
  "size": 500,
  "sort": [{"timestamp": {"order": "desc", "unmapped_type": "boolean"}}],
  "stored_fields": ["*"],
  "docvalue_fields": [{"field": "timestamp", "format": "date_time"}],
  "_source": {"excludes": ["@timestamp"]},
  "query": {
    "bool": {
      "must": [],
      "filter": [
        {"range": {"timestamp": {"gte": "2024-01-01T00:00:00Z", "lte": "now"}}}
      ],
      "should": [],
      "must_not": []
    }
  }
}
```

### Response structure

```json
{
  "hits": {
    "total": {"value": 1234, "relation": "eq"},
    "hits": [
      {
        "_index": "wazuh-alerts-4.x-2024.01.15",
        "_id": "abc123",
        "_source": { /* the actual document */ }
      }
    ]
  },
  "aggregations": { /* if requested */ }
}
```

### Useful API endpoints (Indexer)

```http
GET /_cat/indices/wazuh-*?v                 # list all wazuh indices
GET /_cat/indices/wazuh-alerts-*?v          # list alert indices only
GET /{index}/_mapping                        # get field mapping for an index
GET /{index}/_count                          # count documents
POST /{index}/_search                        # search with body
GET /_cluster/health                         # cluster status
```

---

## 3. All Index Patterns

### Primary data indices

| Index Pattern | Purpose | Created by | Frequency |
|--------------|---------|------------|-----------|
| `wazuh-alerts-4.x-*` | Security alerts (rule-triggered events) | Filebeat from alerts.json | Daily → `YYYY.MM.DD` |
| `wazuh-archives-4.x-*` | ALL events, including non-alerts (requires `logall_json=yes`) | Filebeat from archives.json | Daily → `YYYY.MM.DD` |
| `wazuh-monitoring-*` | Agent connection status history | Wazuh Dashboard | Weekly |
| `wazuh-statistics-*` | Manager performance metrics (events decoded, bytes received) | Wazuh Dashboard | Weekly |

### Vulnerability / state indices

| Index Pattern | Purpose | Content |
|--------------|---------|---------|
| `wazuh-states-vulnerabilities-*` | CVE detections on endpoints | CVE ID, severity, score, affected package, agent |

### Inventory state indices (Syscollector data, pushed to indexer)

| Index Pattern | Purpose | Key fields |
|--------------|---------|------------|
| `wazuh-states-inventory-system-*` | OS info, hostname, architecture | `os.name`, `os.version`, `host.hostname`, `host.architecture` |
| `wazuh-states-inventory-hardware-*` | CPU, RAM, board serial | `hardware.cpu.name`, `hardware.ram.total`, `hardware.ram.free` |
| `wazuh-states-inventory-packages-*` | Installed software packages | `package.name`, `package.version`, `package.vendor`, `package.architecture`, `package.format` |
| `wazuh-states-inventory-processes-*` | Running processes | `process.name`, `process.pid`, `process.state`, `process.euser`, `process.ppid` |
| `wazuh-states-inventory-ports-*` | Open network ports | `network.local.ip`, `network.local.port`, `network.protocol`, `network.state`, `network.process` |
| `wazuh-states-inventory-interfaces-*` | Network interfaces (status, MAC, packet stats) | `interface.name`, `interface.state`, `interface.mac`, `interface.mtu` |
| `wazuh-states-inventory-networks-*` | IP address assignments per interface | `network.address`, `network.netmask`, `network.broadcast`, `iface` |
| `wazuh-states-inventory-protocols-*` | Routing configuration per interface | `network.gateway`, `network.type`, `network.dhcp`, `iface` |
| `wazuh-states-inventory-hotfixes-*` | Windows KB updates (hotfixes) | `package.hotfix.name` (KB number) |
| `wazuh-states-inventory-browser-extensions-*` | Browser extensions | `package.name`, `package.version`, `browser` |
| `wazuh-states-inventory-services-*` | System services (Windows/Linux) | `service.name`, `service.state`, `service.startup_type` |
| `wazuh-states-inventory-groups-*` | User groups on endpoint | `group.name`, `group.id` |
| `wazuh-states-inventory-users-*` | User accounts on endpoint | `user.name`, `user.id`, `user.groups` |

> **Note:** All inventory state indices are prefixed with the agent ID and refreshed on Syscollector scan cycles.

---

## 4. Index Field Schemas

### 4.1 `wazuh-alerts-4.x-*` — Alert fields

These are the fields generated when any detection rule fires.

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `timestamp` | date | Event timestamp (ISO 8601) | `2024-01-15T10:23:44.000+0000` |
| `@timestamp` | date | Same as timestamp (Filebeat-added) | |
| `agent.id` | keyword | 3-digit agent ID | `"001"` |
| `agent.name` | keyword | Agent hostname as registered | `"win-server-01"` |
| `agent.ip` | ip | Agent IP address | `"192.168.1.50"` |
| `agent.version` | keyword | Wazuh agent version | `"Wazuh v4.8.0"` |
| `agent.labels` | object | Custom labels | |
| `manager.name` | keyword | Name of manager that processed event | `"wazuh-manager"` |
| `rule.id` | keyword | Rule ID that fired | `"5710"` |
| `rule.level` | integer | Rule severity level (0-15) | `7` |
| `rule.description` | keyword | Human-readable rule description | `"sshd: authentication failed"` |
| `rule.groups` | keyword[] | Rule group tags | `["authentication_failed","sshd"]` |
| `rule.firedtimes` | integer | How many times this rule fired | `3` |
| `rule.pci_dss` | keyword[] | PCI DSS requirement IDs | `["10.2.4","10.2.5"]` |
| `rule.hipaa` | keyword[] | HIPAA requirement IDs | |
| `rule.nist_800_53` | keyword[] | NIST 800-53 requirement IDs | |
| `rule.gdpr` | keyword[] | GDPR requirement IDs | |
| `rule.tsc` | keyword[] | TSC requirement IDs | |
| `rule.mitre.id` | keyword[] | MITRE ATT&CK technique IDs | `["T1110"]` |
| `rule.mitre.tactic` | keyword[] | MITRE tactic names | `["Credential Access"]` |
| `rule.mitre.technique` | keyword[] | MITRE technique names | `["Brute Force"]` |
| `decoder.name` | keyword | Decoder that parsed the log | `"sshd"` |
| `decoder.parent` | keyword | Parent decoder | |
| `location` | keyword | Log source location | `"/var/log/auth.log"` |
| `full_log` | text | Raw log line | |
| `data.*` | object | Decoded data fields (varies by module) | |
| `data.srcip` | ip | Source IP (if applicable) | `"10.0.0.1"` |
| `data.srcuser` | keyword | Source username | `"root"` |
| `data.dstuser` | keyword | Destination user | |
| `GeoLocation.country_name` | keyword | GeoIP country | `"Germany"` |
| `GeoLocation.city_name` | keyword | GeoIP city | |
| `GeoLocation.location` | geo_point | Lat/lon | |
| `syscheck.*` | object | FIM event data (see below) | |

#### Windows-specific fields (EventLog events)

| Field | Description |
|-------|-------------|
| `data.win.system.eventID` | Windows Event ID |
| `data.win.system.channel` | Event channel (Security, System, etc.) |
| `data.win.system.computer` | Computer name |
| `data.win.system.providerName` | Event provider |
| `data.win.system.level` | Event level |
| `data.win.eventdata.targetUserName` | Target username |
| `data.win.eventdata.subjectUserName` | Subject username |
| `data.win.eventdata.logonType` | Logon type (2=Interactive, 3=Network, 10=RemoteInteractive) |
| `data.win.eventdata.ipAddress` | Source IP for logon events |
| `data.win.eventdata.processName` | Process path |
| `data.win.eventdata.workstationName` | Workstation name |

#### FIM (Syscheck) event fields

| Field | Description |
|-------|-------------|
| `syscheck.path` | Full path of changed file |
| `syscheck.event` | Change type: `added`, `modified`, `deleted` |
| `syscheck.size_after` / `syscheck.size_before` | File size |
| `syscheck.md5_after` / `syscheck.md5_before` | MD5 hash |
| `syscheck.sha1_after` / `syscheck.sha1_before` | SHA1 hash |
| `syscheck.sha256_after` / `syscheck.sha256_before` | SHA256 hash |
| `syscheck.mtime_after` / `syscheck.mtime_before` | Modification time |
| `syscheck.perm_after` / `syscheck.perm_before` | File permissions |
| `syscheck.uname_after` | Owner username after |
| `syscheck.gname_after` | Owner group name after |
| `syscheck.arch` | `[x32]` or `[x64]` (Windows registry) |
| `syscheck.value_name` | Registry value name (Windows) |

---

### 4.2 `wazuh-states-vulnerabilities-*` — Vulnerability fields

| Field | Type | Description |
|-------|------|-------------|
| `agent.id` | keyword | Agent ID |
| `agent.name` | keyword | Agent hostname |
| `agent.ip` | ip | Agent IP |
| `vulnerability.id` | keyword | CVE identifier (e.g. `CVE-2023-1234`) |
| `vulnerability.severity` | keyword | `Low`, `Medium`, `High`, `Critical` |
| `vulnerability.score.base` | float | CVSS base score (0-10) |
| `vulnerability.score.version` | keyword | CVSS version (`2.0`, `3.0`, `3.1`) |
| `vulnerability.description` | text | CVE description |
| `vulnerability.detected_at` | date | When Wazuh first detected it |
| `vulnerability.published_at` | date | When CVE was published |
| `vulnerability.status` | keyword | `VALID`, `OBSOLETE`, etc. |
| `vulnerability.reference` | keyword | CVE reference URL |
| `vulnerability.type` | keyword | `OS` or `PACKAGE` |
| `package.name` | keyword | Affected package name |
| `package.version` | keyword | Installed version |
| `package.architecture` | keyword | `x86_64`, `amd64`, etc. |
| `package.format` | keyword | `deb`, `rpm`, `msi`, etc. |
| `package.installed` | date | Package installation date |

---

### 4.3 `wazuh-monitoring-*` — Agent monitoring fields

| Field | Description |
|-------|-------------|
| `agent.id` | Agent ID |
| `agent.name` | Agent name |
| `agent.ip` | Agent IP |
| `agent.status` | `Active`, `Disconnected`, `Pending`, `Never connected` |
| `agent.version` | Agent version |
| `agent.dateAdd` | Registration date |
| `agent.lastKeepAlive` | Last heartbeat timestamp |
| `agent.os.platform` | `windows`, `linux`, `darwin` |
| `agent.os.name` | Full OS name |
| `agent.os.version` | OS version |
| `agent.os.arch` | Architecture |
| `agent.group` | Agent group assignment |
| `agent.node_name` | Manager node name |
| `timestamp` | When status was recorded |

---

## 5. Data Source: Wazuh Manager API

### Authentication

```http
POST https://<manager_host>:55000/security/user/authenticate
Authorization: Basic <base64(user:pass)>

# Returns JWT token valid for 900 seconds (configurable)
# Use in subsequent requests:
Authorization: Bearer <jwt_token>
```

### Base URL

```
https://<manager_host>:55000
```

### Response envelope

All API responses follow this structure:

```json
{
  "data": {
    "affected_items": [...],
    "total_affected_items": 123,
    "total_failed_items": 0,
    "failed_items": []
  },
  "message": "All selected agents information was returned",
  "error": 0
}
```

### Common query parameters

| Parameter | Description |
|-----------|-------------|
| `pretty` | `true` = human-readable JSON |
| `wait_for_complete` | Disable timeout (for slow queries) |
| `offset` | Pagination start (default: 0) |
| `limit` | Max results (default: 500, max: 100000) |
| `sort` | `+field` or `-field` |
| `search` | Full-text search |
| `select` | Comma-separated field list to return |
| `q` | Query filter: `q="status=active"` |

---

## 6. Syscollector Endpoints (per-agent)

All per-agent endpoints include information for a specific agent identified by `{agent_id}` (3-digit string).

### 6.1 Hardware

```http
GET /syscollector/{agent_id}/hardware
```

Returns: CPU name, cores, MHz, RAM total/free, board serial.

```json
{
  "cpu": {"name": "Intel Core i7", "cores": 8, "mhz": 2400.0},
  "ram": {"total": 16384, "free": 8192, "usage": 50},
  "board_serial": "XYZ123"
}
```

### 6.2 OS Info

```http
GET /syscollector/{agent_id}/os
```

Returns: OS name, version, architecture, kernel, hostname.

```json
{
  "os": {"name": "Windows 10 Pro", "platform": "windows", "version": "10.0.19045"},
  "hostname": "WIN-MACHINE",
  "architecture": "x86_64",
  "release": "10"
}
```

### 6.3 Packages

```http
GET /syscollector/{agent_id}/packages
# Filters: vendor, name, architecture, format, version, q, offset, limit
```

Returns: `name`, `version`, `vendor`, `architecture`, `format` (deb/rpm/msi), `description`, `install_time`.

### 6.4 Processes

```http
GET /syscollector/{agent_id}/processes
# Filters: pid, state, ppid, name, euser, egroup, fgroup, priority, q
```

Returns: `pid`, `ppid`, `name`, `state`, `euser`, `egroup`, `fgroup`, `cmd`, `priority`, `nlwp`.

### 6.5 Ports

```http
GET /syscollector/{agent_id}/ports
# Filters: pid, protocol, local.ip, local.port, remote.ip, state, process
```

Returns: `protocol`, `local.ip`, `local.port`, `remote.ip`, `tx_queue`, `rx_queue`, `state`, `pid`, `process`.

### 6.6 Network Interfaces

```http
GET /syscollector/{agent_id}/netiface
# Filters: name, adapter, type, state, mtu, tx.*, rx.*
```

Returns: `name`, `type`, `state`, `mtu`, `mac`, `tx.bytes`, `rx.bytes`, `tx.packets`, `rx.packets`, `tx.errors`, `rx.errors`.

### 6.7 Network Addresses

```http
GET /syscollector/{agent_id}/netaddr
# Filters: iface, proto, address, broadcast, netmask
```

Returns: `iface`, `proto` (ipv4/ipv6), `address`, `broadcast`, `netmask`.

### 6.8 Network Protocols / Routing

```http
GET /syscollector/{agent_id}/netproto
# Filters: iface, type, gateway, dhcp
```

Returns: `iface`, `type`, `gateway`, `dhcp` (enabled/disabled/unknown).

### 6.9 Hotfixes (Windows)

```http
GET /syscollector/{agent_id}/hotfixes
# Filters: hotfix (KB number)
```

Returns: `hotfix` (KB number string).

### 6.10 Users

```http
GET /syscollector/{agent_id}/users
```

Returns local user accounts on the endpoint.

### 6.11 Groups

```http
GET /syscollector/{agent_id}/groups
```

Returns local user groups on the endpoint.

### 6.12 Services

```http
GET /syscollector/{agent_id}/services
```

Returns Windows/Linux services: `name`, `state`, `startup_type`, `executable`.

### 6.13 Browser Extensions

```http
GET /syscollector/{agent_id}/browser_extensions
```

Returns browser extension inventory per agent.

---

## 7. Agents API

### List all agents

```http
GET /agents
# Filters: status, name, ip, version, group, node_name, os.platform, os.version
```

Response per agent includes:

```json
{
  "id": "001",
  "name": "hostname",
  "ip": "192.168.1.50",
  "status": "active",      // "active" | "pending" | "never_connected" | "disconnected"
  "version": "Wazuh v4.8.0",
  "dateAdd": "2024-01-01T10:00:00Z",
  "lastKeepAlive": "2024-01-15T12:30:00Z",
  "os": {
    "platform": "windows",
    "name": "Windows Server 2022",
    "version": "10.0.20348",
    "arch": "x86_64"
  },
  "group": ["default", "web-servers"],
  "node_name": "node01",
  "configSum": "abc123",
  "mergedSum": "def456"
}
```

### Agent status values

| Status | Meaning |
|--------|---------|
| `active` | Connected and sending heartbeats |
| `pending` | Waiting for manager acknowledgment |
| `never_connected` | Registered but never checked in |
| `disconnected` | Was active, now silent |

### Get agent summary

```http
GET /agents/summary/status       # count by status
GET /agents/summary/os           # count by OS platform
GET /overview/agents             # combined overview
```

---

## 8. SCA (Security Configuration Assessment)

```http
GET /sca/{agent_id}              # list policies for agent
GET /sca/{agent_id}/checks/{policy_id}  # individual check results
```

### SCA check fields

| Field | Description |
|-------|-------------|
| `policy` | Policy name |
| `policy_id` | Policy identifier |
| `score` | Compliance percentage |
| `passed` | Number of passed checks |
| `failed` | Number of failed checks |
| `invalid` | Checks that could not run |
| `check.id` | Individual check ID |
| `check.title` | Check description |
| `check.result` | `passed`, `failed`, `not applicable` |
| `check.remediation` | How to fix the finding |

---

## 9. FIM (File Integrity Monitoring) via Manager API

```http
GET /syscheck/{agent_id}         # get FIM database results
# Filters: file, type, arch, md5, sha1, sha256, hash, summary
```

### FIM result fields

| Field | Description |
|-------|-------------|
| `file` | Full path of monitored file |
| `type` | `file`, `registry_key`, `registry_value` |
| `date` | Last modification date |
| `changes` | Number of times file changed |
| `size` | File size in bytes |
| `perm` | POSIX permissions or Windows ACL |
| `md5` | MD5 hash |
| `sha1` | SHA1 hash |
| `sha256` | SHA256 hash |
| `uname` | Owner username |
| `gname` | Owner group |
| `arch` | `[x32]` or `[x64]` (registry entries) |
| `value_name` | Registry value name |
| `value_type` | Registry value type |

---

## 10. Data Source: alerts.json / archives.json

### alerts.json

- **Location:** `/var/ossec/logs/alerts/alerts.json` on the Wazuh manager
- **Content:** All events that triggered a detection rule
- **Format:** Newline-deliminated JSON (one document per line)
- **Rotation:** Daily, kept for `N` days (configurable in ossec.conf)
- **Used by:** Filebeat → Wazuh Indexer (`wazuh-alerts-*` indices)

### archives.json

- **Location:** `/var/ossec/logs/archives/archives.json` on manager
- **Content:** ALL events received, regardless of whether a rule fired
- **Requires:** `<logall_json>yes</logall_json>` in `/var/ossec/etc/ossec.conf`
- **Used by:** Filebeat → Wazuh Indexer (`wazuh-archives-*` indices)
- **Warning:** Can produce very high data volume — every raw log line is stored

### Sample alert document (alerts.json)

```json
{
  "timestamp": "2024-01-15T10:23:44.000+0000",
  "rule": {
    "level": 7,
    "description": "sshd: Attempt to login using a denied user",
    "id": "5710",
    "firedtimes": 1,
    "mail": false,
    "groups": ["sshd", "authentication_failed"],
    "mitre": {
      "id": ["T1110"],
      "tactic": ["Credential Access"],
      "technique": ["Brute Force"]
    }
  },
  "agent": {
    "id": "001",
    "name": "linux-server-01",
    "ip": "10.0.0.5"
  },
  "manager": {
    "name": "wazuh-manager"
  },
  "id": "1705312824.123",
  "full_log": "Jan 15 10:23:44 linux-server-01 sshd[12345]: Invalid user hacker from 45.33.32.156",
  "decoder": {
    "name": "sshd"
  },
  "data": {
    "srcip": "45.33.32.156",
    "srcport": "54321",
    "srcuser": "hacker"
  },
  "location": "/var/log/auth.log"
}
```

---

## 11. Agent Field Mapping (version quirks)

**Problem:** Wazuh stores the agent/host name in different fields depending on the event source, module, and Wazuh version. This causes host matching to be unreliable if you only check one field.

### Host identification field priority (check in this order)

```python
HOSTNAME_PATHS = [
    "agent.name",          # Most reliable — agent name as registered with manager
    "agent.hostname",      # Older Wazuh versions used this
    "host.name",           # ECS-style (some modules)
    "manager.name",        # Events from the manager itself (agent 000)
    "hostname",            # Flat field (some decoders)
]
```

### Our `_pick()` implementation pattern

```python
def _pick(source: dict, *paths: str) -> Any:
    """Try multiple dot-notation paths until one returns a non-empty value."""
    for path in paths:
        current = source
        for part in path.split("."):
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                current = None
                break
        if current not in (None, ""):
            return current
    return None

host = _pick(raw, "agent.name", "agent.hostname", "host.name", "manager.name") or "unknown"
```

### Agent ID vs. agent name

- `agent.id` = 3-digit zero-padded string (`"001"`, `"042"`)
- `agent.id = "000"` = the Wazuh manager itself
- Use `agent.name` for matching; use `agent.id` for joining with Manager API

### Common multi-field search in OpenSearch

```json
{
  "query": {
    "bool": {
      "should": [
        {"term": {"agent.name": "hostname"}},
        {"wildcard": {"agent.name": "*hostname*"}},
        {"term": {"host.name": "hostname"}},
        {"term": {"agent.hostname": "hostname"}}
      ],
      "minimum_should_match": 1
    }
  }
}
```

---

## 12. Authentication Methods

### Wazuh Indexer (OpenSearch)

```python
import httpx
auth = ("admin", "password")
verify = False  # or True with CA cert

with httpx.Client(auth=auth, verify=verify) as client:
    r = client.post(
        "https://indexer:9200/wazuh-alerts-*/_search",
        json=payload
    )
```

### Wazuh Manager API (JWT)

```python
import httpx

# Step 1: Get JWT token
def get_manager_token(host: str, user: str, pw: str) -> str:
    r = httpx.post(
        f"https://{host}:55000/security/user/authenticate",
        auth=(user, pw),
        verify=False
    )
    return r.json()["data"]["token"]

# Step 2: Use token
token = get_manager_token("manager", "wazuh", "pass")
headers = {"Authorization": f"Bearer {token}"}
r = httpx.get("https://manager:55000/agents", headers=headers, verify=False)
```

**JWT token lifetime:** 900 seconds (15 minutes) by default. Implement token refresh.

---

## 13. How Our App Currently Uses Each Source

### wazuh_indexer.py — current usage

| Function | Index | Purpose |
|----------|-------|---------|
| `fetch_alerts()` | `wazuh-alerts-*` | Pull recent alerts per host |
| `fetch_vulnerabilities()` | `wazuh-states-vulnerabilities-*` | CVE data per host |
| `normalize_alert()` | n/a | Field normalization with `_pick()` |
| `detect_platform()` | n/a | Infer Windows/Linux from rule groups, decoder, event_id |

### fullscan_service.py — assumed coverage

| Module | Data source | Index queried |
|--------|------------|---------------|
| Events | Indexer | `wazuh-alerts-*` |
| Vulnerabilities | Indexer | `wazuh-states-vulnerabilities-*` |
| FIM | Indexer | `wazuh-alerts-*` (using syscheck rule groups filter) |
| Config/SCA | Manager API | `/sca/{agent_id}` |
| Threat Intel | Indexer | `wazuh-alerts-*` (MITRE fields) |

---

## 14. Query Patterns & Examples

### Alert query for specific host (time-bounded)

```json
{
  "size": 200,
  "sort": [{"timestamp": {"order": "desc"}}],
  "query": {
    "bool": {
      "filter": [
        {"range": {"timestamp": {"gte": "now-24h", "lte": "now"}}},
        {"bool": {
          "should": [
            {"term": {"agent.name": "TARGET_HOST"}},
            {"term": {"host.name": "TARGET_HOST"}}
          ],
          "minimum_should_match": 1
        }}
      ]
    }
  }
}
```

### Aggregation: top rule IDs

```json
{
  "size": 0,
  "query": {"match_all": {}},
  "aggs": {
    "top_rules": {
      "terms": {"field": "rule.id", "size": 10}
    }
  }
}
```

### Aggregation: alerts per host

```json
{
  "size": 0,
  "query": {
    "bool": {
      "filter": [{"range": {"timestamp": {"gte": "now-7d"}}}]
    }
  },
  "aggs": {
    "per_host": {
      "terms": {"field": "agent.name", "size": 50}
    }
  }
}
```

### Filter: only high-severity alerts (level >= 10)

```json
{
  "query": {
    "bool": {
      "filter": [
        {"range": {"rule.level": {"gte": 10}}},
        {"range": {"timestamp": {"gte": "now-24h"}}}
      ]
    }
  }
}
```

### Filter: MITRE technique filter

```json
{
  "query": {
    "bool": {
      "filter": [
        {"terms": {"rule.mitre.id": ["T1110", "T1078", "T1021"]}}
      ]
    }
  }
}
```

### FIM alerts only (via rule groups)

```json
{
  "query": {
    "bool": {
      "filter": [
        {"term": {"rule.groups": "syscheck"}}
      ]
    }
  }
}
```

### Vulnerability query with CVSS score filter

```json
{
  "query": {
    "bool": {
      "filter": [
        {"range": {"vulnerability.score.base": {"gte": 7.0}}},
        {"term": {"agent.name": "TARGET_HOST"}}
      ]
    }
  },
  "sort": [{"vulnerability.score.base": {"order": "desc"}}]
}
```

### Query inventory packages for host

```json
// POST /wazuh-states-inventory-packages-*/_search
{
  "size": 500,
  "query": {
    "bool": {
      "filter": [
        {"term": {"agent.name": "TARGET_HOST"}}
      ]
    }
  },
  "_source": ["package.name", "package.version", "package.vendor", "package.architecture"]
}
```

---

## 15. Known Gaps & Opportunities

### Data sources NOT yet used in our app

| Source | Index / Endpoint | What it provides | Priority |
|--------|-----------------|-----------------|----------|
| Agent list | Manager API `/agents` | Real-time status, last keepalive, OS data | **HIGH** |
| Packages | `wazuh-states-inventory-packages-*` | Installed software inventory per host | HIGH |
| Processes | `wazuh-states-inventory-processes-*` | Running processes snapshot | HIGH |
| Open ports | `wazuh-states-inventory-ports-*` | Exposed network ports | HIGH |
| System info | `wazuh-states-inventory-system-*` | OS version, hostname, architecture | HIGH |
| Hardware | `wazuh-states-inventory-hardware-*` | CPU, RAM per host | MEDIUM |
| Services | `wazuh-states-inventory-services-*` | Windows/Linux service status | MEDIUM |
| SCA checks | Manager API `/sca/{agent_id}/checks/{policy}` | Config compliance per check | MEDIUM |
| FIM database | Manager API `/syscheck/{agent_id}` | Full FIM state (not just alerts) | MEDIUM |
| Users/Groups | `wazuh-states-inventory-users-*` / `groups-*` | Local account inventory | LOW |
| Browser extensions | `wazuh-states-inventory-browser-extensions-*` | Extension risk surface | LOW |
| Archives | `wazuh-archives-*` | Raw non-alert events (requires enabling) | LOW |

### Recommended improvements

1. **Replace mock `connection_status`** → Query `wazuh-monitoring-*` or Manager API `/agents?select=status,lastKeepAlive` for real agent status
2. **OS detection from data** → Query `wazuh-states-inventory-system-*` instead of guessing from alert rule groups
3. **Software inventory** → Query `wazuh-states-inventory-packages-*` for installed packages (useful for vuln context)
4. **Port inventory** → Query `wazuh-states-inventory-ports-*` to show exposed services
5. **Process anomalies** → Query `wazuh-states-inventory-processes-*` for suspicious process detection
6. **Real agent health** → Use Manager API GET `/agents/{agent_id}` for `lastKeepAlive`, `version`, `group`, connection status

---

## 16. MITRE ATT&CK Fields Reference

Fields in `wazuh-alerts-*` under `rule.mitre.*`:

| Field | Content | Example |
|-------|---------|---------|
| `rule.mitre.id` | Technique IDs | `["T1110", "T1078"]` |
| `rule.mitre.tactic` | Tactic phase names | `["Credential Access", "Initial Access"]` |
| `rule.mitre.technique` | Technique names | `["Brute Force", "Valid Accounts"]` |

**Manager API MITRE endpoints:**

```http
GET /mitre/tactics               # list all 14 MITRE tactics
GET /mitre/techniques            # list all techniques
GET /mitre/groups                # threat actor groups
GET /mitre/mitigations           # defensive mitigations
GET /mitre/software              # malware/tools used
```

---

## 17. Important Operational Notes

### Index naming pattern

```
wazuh-alerts-4.x-YYYY.MM.DD    ← daily, per calendar day UTC
wazuh-monitoring-YYYY.WWw      ← weekly (W = week number)
wazuh-statistics-YYYY.WWw      ← weekly
```

Always use wildcard patterns (`wazuh-alerts-*`) when querying across multiple days.

### SSL verification

Wazuh Indexer uses a self-signed certificate by default:
- In dev: `verify=False`
- In prod: supply the CA cert path: `verify="/etc/wazuh-indexer/certs/root-ca.pem"`

### Pagination (Indexer)

```json
// For >10k results, use search_after:
{
  "size": 1000,
  "search_after": ["<last_sort_value>"],
  "sort": [{"timestamp": "desc"}, {"_id": "desc"}]
}
```

### Pagination (Manager API)

```http
GET /agents?offset=0&limit=500     # page 1
GET /agents?offset=500&limit=500   # page 2
```

### Rate limiting (Manager API)

Default: **30 requests per minute** per endpoint for write operations. Read endpoints have higher limits. The API returns `429` when exceeded.

---

## 18. Quick Reference: Which API for What

| I want to know... | Use this |
|-------------------|---------|
| Recent security alerts for a host | Indexer: `wazuh-alerts-*` |
| CVEs / vulnerabilities for a host | Indexer: `wazuh-states-vulnerabilities-*` |
| Is agent X currently connected? | Manager API: `GET /agents/{agent_id}` → `.status` |
| OS version/platform of host X | Indexer: `wazuh-states-inventory-system-*` or Manager API: `GET /syscollector/{id}/os` |
| Installed packages on host X | Indexer: `wazuh-states-inventory-packages-*` or Manager API: `GET /syscollector/{id}/packages` |
| Open ports on host X | Indexer: `wazuh-states-inventory-ports-*` or Manager API: `GET /syscollector/{id}/ports` |
| Running processes on host X | Indexer: `wazuh-states-inventory-processes-*` or Manager API: `GET /syscollector/{id}/processes` |
| FIM changes for host X | Indexer: `wazuh-alerts-*` (filter `rule.groups=syscheck`) or Manager API: `GET /syscheck/{id}` |
| SCA compliance score | Manager API: `GET /sca/{agent_id}` |
| Windows hotfixes installed | Indexer: `wazuh-states-inventory-hotfixes-*` or Manager API: `GET /syscollector/{id}/hotfixes` |
| All agents with their status | Manager API: `GET /agents?select=id,name,ip,status,lastKeepAlive,os` |
| MITRE technique details | Manager API: `GET /mitre/techniques` |
| Alert counts over time | Indexer: `wazuh-alerts-*` with `date_histogram` aggregation |
| Raw events that never fired rules | Indexer: `wazuh-archives-*` (requires enabling) |
