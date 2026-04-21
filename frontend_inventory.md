# Frontend Functional Inventory

> **Purpose:** Complete reference of every view, component, action, data field, filter, and navigation path in the frontend UI. Created for redesign preparation — nothing should be lost.
>
> **Tech stack:** React · TypeScript · Vite · Tailwind CSS · anime.js · ReactMarkdown · lucide-react · Custom inline SVG charts
>
> **Last analysed:** all `frontend/src/pages/` + `frontend/src/components/` source files

---

## Table of Contents

1. [App Shell & Navigation](#1-app-shell--navigation)
2. [AppStart Overlay (Boot Screen)](#2-appstart-overlay-boot-screen)
3. [Dashboard](#3-dashboard)
4. [Chat](#4-chat)
5. [Tasks](#5-tasks)
6. [Hosts](#6-hosts)
7. [Snipen](#7-snipen)
8. [Full Scan](#8-full-scan)
9. [Baseline](#9-baseline)
10. [Settings Modal](#10-settings-modal)
11. [Shared Components](#11-shared-components)
12. [Cross-Tab Navigation Map](#12-cross-tab-navigation-map)
13. [API Actions Summary](#13-api-actions-summary)

---

## 1. App Shell & Navigation

### Purpose
Single-page application shell with persistent left sidebar, theme toggle, AI status indicator, and a boot-gate overlay. Manages all top-level state and passes props down.

### Sidebar Navigation Items

| Tab ID | Label | Icon | Badge |
|--------|-------|------|-------|
| `dashboard` | Dashboard | LayoutDashboard | `●` dot when `lastReportJson` exists |
| `chat` | Chat | MessageSquare | none |
| `tasks` | Tasks | CheckSquare | count of `generatedTasks` |
| `hosts` | Hosts | Server | none |
| `snipen` | Snipen | Crosshair | none |
| `fullscan` | Full Scan | Cpu | none |
| `baseline` | Baseline | Database | none |

### Bottom Sidebar Elements

| Element | Description |
|---------|-------------|
| AI status dot | Green / yellow / red circle indicating AI backend health (`aiStatus`) |
| Theme toggle | "Dark Mode" / "Light Mode" text + icon — toggles `theme` state |
| Einstellungen button | Opens `SettingsModal` overlay |

### Global State (App.tsx)

| State | Type | Description |
|-------|------|-------------|
| `theme` | `'dark' \| 'light'` | UI theme |
| `activeTab` | string | Currently visible page |
| `aiStatus` | `'ok' \| 'warning' \| 'error'` | AI health from preflight |
| `chatMessages` | array | Full chat history |
| `generatedTasks` | array | Tasks created by AI |
| `snipenPrefillHost` | string | Host to auto-select when opening Snipen |
| `analysisProfile` | object | Settings saved from SettingsModal |
| `profiles` | array | Host profile definitions |
| `profileAssignments` | map | `hostname → profile assignment` |
| `lastReportJson` | object | Most recent scan report (triggers Dashboard badge) |

---

## 2. AppStart Overlay (Boot Screen)

### Purpose
Full-screen blocking overlay shown during application startup. Runs 7 sequential preflight checks before allowing entry. Uses dark blue monospace terminal aesthetic.

### Visual Elements

| Element | Description |
|---------|-------------|
| Dot grid background | Faint blue grid lines, full screen |
| Ambient glows | Radial gradient blobs (left-top blue, right-bottom purple, center pulsing) |
| Horizontal scan line | Animated blue scan line sweeping top-to-bottom in a loop |
| Drifting particles | 6 small dots drifting on CSS keyframe paths |
| Left panel "event stream" | List of preflight check results in terminal log style |
| Right panel (UI mock) | Decorative metric rows + shimmer bars + status dots |
| Center card | Main status card with logo, progress bar, shimmer, status text |
| Check log items | One row per check: `[OK]`/`[WRN]`/`[ERR]`/`[RUN]`/`[---]` tag + label + detail |

### Preflight Checks (7, in order)

| Key | Label | Required (blocking)? |
|-----|-------|---------------------|
| `backend` | Backend-Verbindung | Yes |
| `connection` | Netzwerk-Verbindung | Yes |
| `indexer` | Indexer-Status | Yes |
| `hosts` | Host-Daten laden | No |
| `profile` | Profile laden | No |
| `ollama` | Ollama / KI-Modell | No |
| `ai` | KI-Backend | No |

### Check States

- `pending` — not yet started (gray `[---]`)
- `running` — currently checking (blue `[RUN]`, animated pulse)
- `success` — passed (blue `[OK ]`)
- `warning` — non-fatal issue (purple `[WRN]`)
- `error` — failed (red `[ERR]`)

### Progress Bar
`settledCount / totalCount × 100%` — shown as shimmer bar on center card.

### Actions

| Button | Condition | Action |
|--------|-----------|--------|
| **Retry** button | `hasBlockingFailure` is true | `onRetry()` — re-runs preflight |
| **Weiter** / Enter button | `canEnter` is true | `onContinue()` — dismisses overlay with fade-out animation |

### Lifecycle
- Overlay fades out (anime.js, 500 ms, `inOutQuad`) when `visible` changes to `false`
- `onExited()` callback fires after fade completes → unmounts overlay

---

## 3. Dashboard

### Purpose
Live aggregated security overview — top 10 most-active hosts over the last 24 hours. Refreshes every 90 seconds.

### Data Fetched
- `getSnipenHosts(24)` — host list
- `getSnipenHostEvents(host, { hours: 24, limit: 300 })` — events for top 10 hosts by alert count

### UI Elements

#### Lagebild Banner
Full-width status banner at the top.

| Field | Values |
|-------|--------|
| Status label | KRITISCH / ERHÖHT / NORMAL |
| Border / background | red / amber / green |
| Status text | Human-readable reason derived from host data |
| Last-checked timestamp | Auto-refresh timestamp |

#### 4 Metric Cards (MetricCard component)

| Card | Icon | Accent | Data |
|------|------|--------|------|
| Gesamte Alerts | 📈 | purple | Sum of all alert counts across hosts |
| Kritische Findings | 🛡️ | red | Count of critical-severity events |
| Aktive Hosts | 🖥️ | green | Hosts with recent activity |
| Avg. Response | ⏱️ | yellow | Simulated average response time |

Each MetricCard shows: value, hint text, trend badge (↑ red / ↓ green / → neutral).

#### Alert-Verlauf Chart (SVG, 2/3 width)
- 8 time buckets over 24 hours
- Solid teal line = today
- Dashed gray line = "Vortag" (simulated at ~74% scale)
- Area gradient fill under today's line
- Dot markers at non-zero data points
- X-axis time labels
- Legend: "Heute" + "Vortag"
- **"Snipen →" button** in chart header → navigates to Snipen tab

#### Severity Donut Chart (SVG, 1/3 width)
- Four segments: Low `#0acf97`, Medium `#727cf5`, High `#ffbc00`, Critical `#fa5c7c`
- Center: total event count
- Legend: each severity with count + percentage

#### Top 5 Hosts Panel
- Numbered rows 01–05
- Columns: rank, hostname, `ProfileBadge`, alert count, risk badge (Crit/High/Med/Low), horizontal bar chart colored by risk, top rule description
- **Each row is clickable** → navigates to Snipen tab with that host

#### Regel-Kategorien Panel
5 categories with horizontal bar and count:
- Sysmon
- Authentication
- FIM
- Vuln. Detection
- MITRE ATT&CK

#### Letzte Aktivitäten Feed
- 8 most recent events, ordered by recency
- Row: severity dot, hostname, `ProfileBadge`, event_family badge, relative timestamp, rule description
- "Live" indicator (green pulse dot + "Live" label)
- **Each item is clickable** → navigates to Snipen tab

### Filters / Search
None — data is computed from top 10 hosts automatically.

### Navigation Actions
| Trigger | Destination |
|---------|-------------|
| "Snipen →" button in chart | `snipen` tab |
| Top Host row click | `snipen` tab |
| Letzte Aktivitäten item click | `snipen` tab |

---

## 4. Chat

### Purpose
AI conversational interface for SOC queries. Supports report-context-aware analysis, script-triggered data collection, and task generation.

### UI Elements

#### Message History (scrollable)
- User messages: right-aligned bubbles with amber tint
- AI messages: left-aligned bubbles with surface color, rendered as **Markdown** (ReactMarkdown + remark-gfm)
- Empty state: robot emoji + "KI Chat bereit" or "Report-Kontext geladen" text

#### Generated Tasks Card
Shown when `generatedTasks.length > 0` (inside the AI message bubble):
- Up to 10 task entries shown
- Each: severity color badge + task title
- **"→ Alle Tasks anzeigen (N gesamt)"** button → navigates to Tasks tab

#### Typing Indicator
- Shows while AI is responding
- "KI analysiert…" text + animated dot pulse

#### Context Indicator (right-aligned, muted)
- "✓ Kontext" — report context is loaded
- "○ Kein Kontext" — no report loaded

#### Report Drawer Button ("Report ↗")
- Only shown when `hasReportFiles` is true
- Opens slide-in drawer with two tabs:
  - **TXT tab** — pre-formatted text report content
  - **JSON tab** — formatted JSON report content

#### Input Area
| Element | Description |
|---------|-------------|
| Textarea | 3 rows, `Enter` = send message, `Shift+Enter` = new line |
| Lookback presets | `24h` / `7d` / `30d` pills — highlighted when selected |
| **"▶ Skript starten (Xh)"** button | Triggers script run with selected lookback: sends `{ run_script: true, lookback: X }` |
| **"Senden ↑"** button | Sends current textarea content as a chat message |

### Data Shown
- Chat messages (`role: user | assistant`, `content`)
- AI-generated tasks (`severity`, `host`, `title`, `description`)
- Report context status
- Script run summary returned by AI

### Navigation Actions
| Trigger | Destination |
|---------|-------------|
| "→ Alle Tasks anzeigen" button | `tasks` tab |

---

## 5. Tasks

### Purpose
Triage workflow for AI-generated security investigation tasks. 4-state lifecycle: Neu → Investigation → Resolved / False Positive.

### Stats Bar (4 cards)

| Card | Color | Count |
|------|-------|-------|
| Gesamt | neutral | All tasks |
| Investigation | blue | Tasks with status `investigating` |
| Resolved | green | Tasks with status `resolved` |
| Offen | amber | Tasks with status `new` |

### Filters

| Filter | Type | Options |
|--------|------|---------|
| Severity | Pills | Alle, Critical, High, Medium, Low |
| Status | Pills | Alle Status, Neu, Investigation, False Pos., Resolved |

### Task Cards (animated staggered entry, 80 ms delay per card)

#### Compact Header (always visible, click to expand/collapse)
| Element | Description |
|---------|-------------|
| Left border | Color by severity: red (critical), orange (high), amber (medium), emerald (low) |
| Severity badge | Text label + color |
| Hostname | Host that triggered the finding |
| `ProfileBadge` | Profile assignment for the host |
| EID badge | Monospace, format `EID XXXX` |
| Count badge | `3×` format, shown when `count > 1` |
| Rule description | Truncated title text |
| Status badge | 🟡 Neu / 🔵 Investigation / 🟢 Resolved / ⚪ False Positive |
| ▲ / ▼ indicator | Expand/collapse arrow |

#### Expanded Detail (collapsible)
**Event Context panel:**
| Field | Description |
|-------|-------------|
| EID badge | Event ID (monospace) |
| Platform badge | Windows / Linux |
| Count badge | Event count |
| Risk score badge | Number, color: red ≥8, amber ≥5, green otherwise |
| MITRE ID badges | Violet monospace tags (e.g. `T1059.001`) |
| rule_description | Full rule text |
| reason | Analyst reason text |

**Empfohlene Checks panel:**
- Bullet list of recommended investigation steps

#### Status Workflow Buttons (context-sensitive)

| Current Status | Available Buttons |
|---------------|-------------------|
| Neu | "🔵 Investigation starten" |
| Investigating | "🟢 Resolve" + "⚪ False Positive" |
| Resolved / False Positive | "↩ Zurücksetzen" |
| Always present | **"🔍 In Snipen untersuchen"** |

- **"🔍 In Snipen untersuchen"** → navigates to `snipen` tab with `{ host }` context (prefills host search)
- Resolved / FP cards dimmed to 50% opacity

### Empty States
- "Keine Tasks vorhanden. Starte das Skript im Chat-Tab" — when no tasks exist at all
- "Keine Tasks für diesen Filter." — when filters produce empty result

### Navigation Actions
| Trigger | Destination |
|---------|-------------|
| "🔍 In Snipen untersuchen" | `snipen` tab + host prefill |

---

## 6. Hosts

### Purpose
Full host inventory with detailed per-host deep-dive. Two modes: overview list and single-host detail view with 11 sub-tabs.

---

### 6A. Overview Mode

#### Header
- "Hosts" title + total host count
- **Host search input** — filters by hostname and platform

#### Profile Filter Bar
Shown when profiles exist:
- "Alle Profile" pill
- One pill per profile name
- "Ohne Profil" pill
- Active pill is highlighted

#### Critical Hosts Cards (top 3, `risk_score ≥ 7`)
- Hostname, platform, last_activity (relative), online/offline status badge
- Large red risk score number
- Alert count (amber), Findings count
- **Clickable** → opens detail view for that host

#### Stats Row (4 cards)

| Card | Color | Metric |
|------|-------|--------|
| Online | green | Hosts with online status |
| Offline | gray | Hosts with offline status |
| Kritisch | red | Hosts with risk_score ≥ 7 |
| Alerts 24h | amber | Total alerts in last 24h |

#### Hosts Table

| Column | Content |
|--------|---------|
| Host | Hostname + IP address |
| Profil | `ProfileBadge` |
| Status | Colored dot + "Online" / "Offline" label |
| Access | SSH badge (green if `ssh_enabled`, gray otherwise) + RDP badge (blue if `rdp_enabled`, gray otherwise) |
| Plattform | OS name |
| Alerts 24h | Count |
| Findings | Count |
| Risk Score | Colored circle (red ≥9, orange ≥7, yellow ≥4, green otherwise) |
| Scan | Status badge: "Abgeschlossen" (green), "Fehlgeschlagen" (red), other (gray) |
| Letzte Aktivität | Relative timestamp |
| Aktion | **"Öffnen" button** → opens detail view |

**Skeleton loading:** 8 skeleton rows shown while data loads.

---

### 6B. Detail Mode

#### Header
- **Back button** (←) → returns to overview
- Host name as heading
- **Quick Scan button** → calls `triggerQuickScan(host)` API + navigates to `fullscan` tab
- **Profile assignment dropdown** — select or clear a profile for the host

#### 11 Detail Tabs

| Tab | Count Badge Color Rule | Data Shown |
|-----|----------------------|------------|
| Events | rose/amber by severity | Security events for host |
| Processes | amber/emerald | Process activity |
| Authentication | rose if high counts | Auth events (login/logout/fail) |
| Persistence | rose if non-zero | Persistence mechanisms |
| Vulnerabilities | rose/amber by severity | CVEs and vulnerability findings |
| FIM | amber | File Integrity Monitoring changes |
| Configuration | sky | Configuration audit findings |
| Threat Intel | rose | Threat intelligence matches |
| MITRE | amber/rose | MITRE ATT&CK technique cards |
| Raw Data | slate | Raw JSON events |
| Reports | slate | Past scan reports |

Each tab shows a count badge. Badge color is coded by severity/count thresholds.

#### MITRE Tab — Card Layout
Each MITRE card:
- Tactic badge (e.g. `Defense Evasion`)
- Technique ID + name
- Description / details

#### Live Activity Sidebar
- Up to 6 items derived from events/scan/TI data
- Each: activity type, description, timestamp

#### Profile Assignment
- Dropdown per host showing all available profiles + "Kein Profil"
- Selects → `setHostProfileAssignment(hostname, profileId)`
- Clears → `removeHostProfileAssignment(hostname)`

### Filters
| Filter | Scope |
|--------|-------|
| `query` text search | Hostname + platform filter in overview |
| `profileFilter` dropdown | Profile filter in overview |

### Navigation Actions
| Trigger | Destination |
|---------|-------------|
| "Öffnen" button / Critical Host card click | Host detail view |
| Back (←) button | Overview mode |
| Quick Scan button | `fullscan` tab |

---

## 7. Snipen

### Purpose
Host-centric threat hunting interface. 3-column layout: host list → event timeline → event/host detail panel.

---

### Column 1 — Host List

| Element | Description |
|---------|-------------|
| Title "🎯 Snipen" | Section heading |
| **↻ Refresh button** | Reloads host list from API |
| Time range pills | `1h / 6h / 24h / 3d / 7d` — changes lookback for host list |
| Host search input | Filters host cards by hostname |
| Platform filter pills | Alle / 🪟 Win / 🐧 Lin |
| Host cards | Animated list (scrollable) |

#### Host Card Content
| Field | Description |
|-------|-------------|
| Left border color | Top severity color for that host |
| Hostname | Bold text |
| `SeverityPill` | Top severity level badge |
| `ProfileBadge` | Profile assignment |
| Alert count | Number of alerts |
| Platform icons | OS emoji(s) |
| Last seen | Relative timestamp |

**Host card is clickable** → selects host, loads event timeline (Column 2).

---

### Column 2 — Event Timeline

#### Controls
| Element | Description |
|---------|-------------|
| Host name header | Selected host displayed as heading |
| Time presets | `1h / 6h / 24h / 3d / 7d` pills |
| Limit dropdown | `50 / 100 / 200 / 500 Events` |
| Platform filter | Alle Plattformen / Windows / Linux |
| Category filter | Alle / auth / process / service / registry / powershell / network |
| Severity filter | Alle / Critical / High / Medium / Low / Info |
| **"🧠 Analysiere diesen Host vollständig"** button | Calls `analyzeSnipenHost()` API — full AI host analysis |
| **"↻ Laden"** button | Reloads events with current filter settings |

#### Search Bar
| Mode | Icon | Behavior |
|------|------|----------|
| Keyword | 🔍 | Client-side text filter on rule description + fields |
| EID | EID | Filter by Event ID (exact match) |
| User | 👤 | Filter by username field |
| IP | 🌐 | Filter by IP address field |
| Process | ⚙️ | Filter by process name field |
| AI | 🤖 | Sends query to AI, returns answer + highlights matching events |

- Text modes: shows **✕ clear button** when query is active
- AI mode: shows **→ submit button**, Enter key also submits
- AI search result: shows answer banner with query text, AI response, matched events count

#### Analyst Workspace Panel ("hunt@snipen")
Terminal-styled suggestion panel with 3 preset hunt queries:
1. "zeige mir alle ungewöhnlichen Prozesse"
2. "zeige mir mögliche lateral movement"
3. "zeige mir suspicious logins"

Clicking a preset fills the AI search bar and submits.

#### AI Query Answer Banner
Shown after an AI search returns:
- Query text
- AI answer text
- "N matched events" count

#### Event List (scrollable, animated)
Each event row:
| Field | Description |
|-------|-------------|
| Left border | Color by severity |
| Rule description | Primary text |
| Event tag badge | `AUTH` / `PROC` / `REG` / `NET` / `ALERT` / `INFO` with emoji + color |
| `SeverityPill` | Severity level |
| Timestamp | Formatted datetime |
| EID | Event ID (monospace) |
| User badge | Username (if present) |
| IP badge | IP address (if present) |

**Event row is clickable** → selects event, loads detail (Column 3).

#### Summary Bar
"N Events (von X) · hostname" — shown below event list.

---

### Column 3 — Detail Panel

#### State: No host selected
Empty / placeholder state.

#### State: Host selected, no event selected, no scan

**Host Overview panel** (`📊 Host Overview`):
| Element | Description |
|---------|-------------|
| Host name | Label in header |
| Profile context block | ProfileBadge + label if profile assigned |
| 3 KPI cards | Gesamt Events (purple), High Alerts (amber), Critical (red) — animated counter |
| Letzte Aktivität | Last activity timestamp |
| Top Event IDs | Clickable chip tags — clicking sets EID search filter |
| Top Prozesse | List with ⚙️ icons — clicking sets Process search filter |
| Top User | Clickable chip tags — clicking sets User search filter |

#### State: Host selected, no event selected, scan running

AI scan loading animation.

#### State: Scan completed (no event selected)

**Scan Result panel**:
| Element | Description |
|---------|-------------|
| Host name + `RiskBadge` | Header row |
| Event count, hours, "Full Investigation" | Scan metadata |
| Amber info box | Context note |
| AI summary text | Free-text narrative |
| Suspicious patterns list (⚠️, red) | List of suspicious findings |
| "✅ Wahrscheinlich harmlos" section | Benign explanations |
| "🔍 Empfohlene Checks" section | Recommended next steps (blue →) |

#### State: No event selected, timeline data available

**Timeline Mode panel** (`📈 Timeline Mode`):
| Element | Description |
|---------|-------------|
| Subtitle | "Verlauf, Peaks und Anomalien für {host}" |
| Peak count badge | Count of peak buckets |
| Anomalien badge | Count of anomaly buckets (red if non-zero) |
| SVG chart | Area fill + gradient stroke line, dot markers: red (peak), amber (anomaly), cyan (normal) |
| Hover interaction | Shows tooltip with bucket time window + count + Peak/Anomalie label |
| X-axis labels | First / middle / last bucket timestamps |
| Active Zeitfenster list | Bucket rows with start-end time + count badge (red=peak, amber=anomaly, purple=normal) |
| Anomaly chips | Up to 5 anomalous buckets shown as chips |

#### State: Event selected

**Detail mode tabs (top of panel):**
- `📋 Smart` — parsed smart fields
- `{} Raw` — raw JSON
- `🤖 AI` — AI analysis result

**Action buttons (always shown when event is selected):**
| Button | API Call | Description |
|--------|----------|-------------|
| **"🤖 Erklären"** | `explainSnipenEvent()` | AI explanation of event, switches to AI tab |
| **"🛡️ Remediation"** | `remediateSnipenEvent()` | AI remediation steps, switches to AI tab |
| **"🔗 Related"** | `getRelatedSnipenEvents()` | Loads related events panel |
| **"📋 Copy"** | Clipboard | Copies Markdown-formatted event to clipboard |

---

#### 📋 Smart Tab

Named fields with optional red highlight when flagged by AI:

| Field | Source |
|-------|--------|
| Timestamp | `smart.timestamp` |
| Host | `smart.host` |
| Platform | `smart.platform` |
| Event ID | `smart.event_id` |
| Event Meaning | `smart.system_message \| smart.event_explanation` |
| System Message | `smart.system_message` |
| Rule ID | `smart.rule_id` |
| Rule Level | `smart.rule_level` |
| User | `smart.user` |
| Logon Type | `smart.logon_type` |
| IP Address | `smart.ip_address` |
| Process | `smart.process` |
| CommandLine | `smart.command_line` |
| ServiceName | `smart.service_name` |
| RegistryKey | `smart.registry_key` |
| Status | `smart.status` |
| MITRE ID | `smart.mitre_id` |
| MITRE Tactic | `smart.mitre_tactic` |
| Decoder | `smart.decoder` |
| Location | `smart.location` |
| Groups | `smart.groups[]` joined |
| **CLSID lookup** | Auto-extracted GUIDs resolved from `/clsid.json` — shows name badge if found, "Unknown CLSID" if not |

Fields flagged by AI `suspicious_fields` are highlighted with red background.

---

#### `{}` Raw Tab

Raw JSON dump of `selectedEvent.raw` in `<pre>` block, pretty-printed with 2-space indent.

---

#### 🤖 AI Tab

Shown after "Erklären" or "Remediation":
| Element | Description |
|---------|-------------|
| Header | "🛡️ Remediation" or "🤖 KI-Erklärung" title |
| `SeverityPill` | AI-assessed severity |
| Confidence badge | `very_high` (green) / `high` (green) / `medium` (amber) / low (gray) |
| Risk Score bar | 0–10 scale, color: red ≥8, orange ≥6, amber ≥4, green otherwise |
| MITRE ATT&CK tags | Purple monospace technique tags (e.g. `T1059.001`) |
| Summary text | Free-text AI narrative in a rounded card |
| Suspicious Fields | Red chips from `aiResult.suspicious_fields` |
| Unusual Behavior | Orange bullet list from `aiResult.unusual_behavior` |
| Deviations | Amber bullet list from `aiResult.deviations` |

(Full AI result panel also surfaced in the scan result card above the event list when "Analysiere diesen Host vollständig" is triggered.)

---

### Data Shown (Snipen)
- Host severity, alert counts, profile, platform, last seen
- Events: rule description, event_id, severity, timestamp, user, IP, category/tag
- Host overview KPIs: total events, high alerts, critical count, last activity
- Host top EIDs, top processes, top users
- Timeline buckets: time, count, peak/anomaly flags
- AI explanation / remediation fields (see AI tab above)
- CLSID name lookup from local JSON

---

## 8. Full Scan

### Purpose
AI-powered full host investigation with configurable scope, modules, and scan depth. Produces structured Markdown reports.

---

### Left Sidebar — Configuration

| Element | Description |
|---------|-------------|
| **Host dropdown** | Populated from `getSnipenHosts(168)`. Fallback to hardcoded list. |
| Platform display | Read-only label derived from selected host |
| `ProfileBadge` | Profile of selected host |
| **Time window buttons** | `1h / 6h / 24h / 3d / 7d / Custom` |
| **Event scope dropdown** | Top 100 Events / Top 250 Events / Top 500 Events / Alle relevanten Events / Raw Full |
| **Scan mode buttons (2×2 grid)** | Quick / Standard / Deep / Raw Deep |
| **Module checkboxes (11)** | Custom amber-styled checkboxes |

#### Module Checkboxes

| Module | Default |
|--------|---------|
| Events | ✓ |
| Raw Event JSON | — |
| Vulnerabilities | ✓ |
| FIM | — |
| Configuration | — |
| MITRE / Rules | — |
| Threat Intel | ✓ |
| Host Context / Inventory | — |
| Include Noise | — |
| Nur relevante Events | — |
| Nur High/Medium | — |

---

### Top Action Bar

| Element | Description |
|---------|-------------|
| Status pill | Bereit (gray) / Läuft (amber, pulsing ring) / Fertig (green) / Fehler (red) |
| Active module name | Shows current module during scan |
| Quick Scan All progress | "Host X/N" counter during bulk scan |
| **"⚡ Quick Scan (All)"** button | Scans all hosts sequentially with preset: 1h, Top 100, Events + Vulnerabilities + Threat Intel |
| **"🚀 Full Scan starten"** button | Starts scan with current config via `startFullScan()` API |

---

### Progress Bar

- 0–100%
- Color: amber (running), cyan (finished), red (error)
- Glow effect while scan is running

---

### Scan Log Panel
- Monospaced font
- Color-coded lines:
  - `❌` → red
  - `✅` → cyan
  - `🚀` / `📊` → blue

---

### Running Animation
- Concentric circle spinner
- 4-step progress indicator:
  1. Host-Daten laden
  2. Events analysieren
  3. KI-Bewertung
  4. Report generieren

---

### Result Display States

| State | Display |
|-------|---------|
| Idle | "Bereit für Full Scan" placeholder |
| Running | Concentric spinner + step progress |
| Finished (with markdown) | `<pre>`-formatted Markdown report |
| Finished (without markdown) | Raw JSON dump |
| Failed | "⚠️ Scan fehlgeschlagen" error state |

---

### Right Sidebar — Result Tabs

| Tab | Content |
|-----|---------|
| Summary | Pre-formatted text summary |
| Findings | Pre-formatted findings list |
| Events | Pre-formatted events section |
| Vulnerabilities | Pre-formatted vulnerability data |
| FIM | Pre-formatted FIM changes |
| Configuration | Pre-formatted config findings |
| Threat Intel | Pre-formatted TI matches |
| Raw JSON | JSON dump of full scan result |
| Markdown Report | Full Markdown report text |

Empty state: "Ergebnisse erscheinen nach dem Scan"

---

## 9. Baseline

### Purpose
Host behavioral baseline — learns normal patterns, detects deviations, tracks history of anomaly detection over time.

### Header
- "Host Baseline" title + subtitle
- **Host selector dropdown** — populated from `getHostsCentral(168)`

---

### Status Card (shown when baseline exists)

| Element | Description |
|---------|-------------|
| Status badge | Stable (green) / Slight Deviation (amber) / Strong Anomaly (red) |
| Reason bullets | Computed explanation text |
| **"↺ Recompute" button** | Calls `computeBaseline(host, 168)` |
| Last computed timestamp | Human-readable date/time |

---

### 4 Sub-Tabs

#### Summary Tab

**6 Stat Cards:**
| Card | Color when non-zero |
|------|---------------------|
| Total Events | purple |
| Daily Avg | blue |
| High Alerts | amber |
| Critical | red |
| Open Deviations | amber |
| Window (h) | slate |

**"What changed vs. baseline" panel:**
- Volume Spike (ratio value)
- New Services (chip tags)
- New Users (chip tags)
- New Processes (chip tags)
- New IPs (chip tags)
- New Event IDs (chip tags)

**Top Risk Deviations list:**
| Field | Description |
|-------|-------------|
| `RiskCircle` | Score + color (0–10) |
| key | Feature key name |
| `RiskBadge` | Risk level label |
| feature type | Badge for type |
| reason | Explanation text |

**Recommendations panel:**
- Up to 4 items, prefixed with `→`

**Empty state:** "Compute Baseline" button → calls `computeBaseline()`

---

#### Patterns Tab

Chip clouds grouped by feature type:
- Processes
- Users
- Services
- IPs
- Event IDs
- Event Families

Each chip: `feature_key (count_seen)`
Per group: **"↓ Show N more"** / **"↑ Show less"** expand/collapse button.

---

#### Deviations Tab

**Summary chips per deviation type:**
- `new_service` → red chip
- others → amber chip

**Grouped deviation cards:**
| Field | Description |
|-------|-------------|
| `RiskCircle` | Score + color |
| feature_key | Name of deviating feature |
| `RiskBadge` | Risk level |
| feature_type badge | Category label |
| reason | Text explanation |
| timestamp | When detected |
| confidence | Confidence value |
| **"Resolve" button** | Calls `resolveDeviation(id)` API |

---

#### History Tab

Chronological list of baseline snapshots:
| Field | Description |
|-------|-------------|
| computed_at | Timestamp (amber) |
| event count | Total events in that snapshot |
| window hours | Time window |
| high alerts count | |
| critical alerts count | |
| deviation count | |
| status badge | Stable / Slight Deviation / Strong Anomaly |

---

### API Actions (Baseline)

| Action | API Call |
|--------|----------|
| Load baseline | `getBaseline(host)` |
| Recompute | `computeBaseline(host, 168)` |
| Resolve deviation | `resolveDeviation(id)` |

---

## 10. Settings Modal

### Purpose
Configuration overlay for video background and AI analysis profile parameters.

### Trigger
"Einstellungen" button in bottom sidebar → opens modal.

### Modal Layout
- Full-screen scrim (clickable to close)
- Centered card, max 500px wide, scrollable content
- **✕ close button** in header

---

### Section: Video-Hintergrund

| Element | Description |
|---------|-------------|
| Description text | Explains MP4 loop background for dark mode |
| Video preview | Live preview (if video is set): `<video autoPlay loop muted>` |
| **"📁 Video auswählen"** button | Opens hidden `<input type="file" accept="video/mp4,video/webm,video/mpeg">` |
| **"🗑️ Löschen"** button | Only shown when video is set; clears video source + resets file input |

Note text: Video is not persisted across sessions (Tauri compatibility).

---

### Section: Analyse-Profil (Phase 1)

| Field | Type | Range / Notes |
|-------|------|---------------|
| Min Rule Level | Number input | 0–20 |
| Max Findings | Number input | 10–1000 |
| Max Events pro Host | Number input | 0–20000 (0 = unlimited) |
| Windows Event IDs | Text input | CSV, e.g. `4625,4688,7045` (empty = script default) |
| Include agent info | Checkbox | |
| Include commandLine | Checkbox | |
| Include full_log | Checkbox | |
| Include MITRE mapping | Checkbox | |

All changes saved immediately via `onSaveAnalysisProfile()` on each input change.

### Footer
- Empty footer row (no buttons — all changes are auto-saved)

---

## 11. Shared Components

### ProfileBadge
- Shows profile assignment for a host
- Props: `assignment`, `size` (`sm`/`md`), `showLabel` flag
- Displays: profile name, optional label text
- Used in: DashboardPage, TasksPage, HostsPage, SnipenPage, FullScanTab, BaselinePage

### SeverityPill
- Colored pill badge showing severity level
- Values: Critical (red), High (orange), Medium (amber), Low (emerald), Info (slate)

### RiskCircle
- Circular score indicator
- Color: red ≥9, orange ≥7, amber ≥4, green otherwise

### RiskBadge
- Text badge with same color logic as RiskCircle

### SmartFieldRow (Snipen)
- One labeled row in Smart event view
- Props: `label`, `value`, `highlight` (red tint if flagged), `dark`
- Shows nothing if `value` is null/empty

### AppStartOverlay
- Full boot screen — see [Section 2](#2-appstart-overlay-boot-screen)

### SettingsModal
- Settings overlay — see [Section 10](#10-settings-modal)

---

## 12. Cross-Tab Navigation Map

| Source | Trigger | Target Tab | Extra Context |
|--------|---------|------------|---------------|
| Dashboard — "Snipen →" chart button | Click | `snipen` | — |
| Dashboard — Top Host row | Click | `snipen` | — |
| Dashboard — Letzte Aktivitäten item | Click | `snipen` | — |
| Chat — "→ Alle Tasks anzeigen" | Click | `tasks` | — |
| Tasks — "🔍 In Snipen untersuchen" | Click | `snipen` | `snipenPrefillHost = task.host` |
| Hosts — Quick Scan button | Click | `fullscan` | selected host prefilled |
| FullScan — (no outbound navigation) | — | — | — |
| Snipen — (no outbound navigation) | — | — | — |
| Baseline — (no outbound navigation) | — | — | — |
| AppStart Overlay — "Weiter" button | Click | (first tab / `dashboard`) | overlay dismissed |

---

## 13. API Actions Summary

| Page | Action | API Function | Method |
|------|--------|--------------|--------|
| Dashboard | Load hosts | `getSnipenHosts(24)` | GET |
| Dashboard | Load host events | `getSnipenHostEvents(host, params)` | GET |
| Chat | Send message | internal state + backend | POST |
| Chat | Run script | `run_script: true` message | POST |
| Tasks | (no direct API — tasks from AI) | — | — |
| Hosts | Load hosts | `getHostsCentral(168)` or similar | GET |
| Hosts | Set profile | `setHostProfileAssignment(host, profileId)` | POST/PUT |
| Hosts | Remove profile | `removeHostProfileAssignment(host)` | DELETE |
| Hosts | Quick scan | `triggerQuickScan(host)` | POST |
| Snipen | Load host list | `getSnipenHosts(hours)` | GET |
| Snipen | Load events | `getSnipenHostEvents(host, params)` | GET |
| Snipen | Host full analysis | `analyzeSnipenHost(host, params)` | POST |
| Snipen | Explain event | `explainSnipenEvent(event)` | POST |
| Snipen | Remediation | `remediateSnipenEvent(event)` | POST |
| Snipen | Related events | `getRelatedSnipenEvents(event)` | POST |
| Snipen | AI search query | AI mode search | POST |
| FullScan | Load host list | `getSnipenHosts(168)` | GET |
| FullScan | Start scan | `startFullScan(host, params)` | POST |
| FullScan | Quick Scan All | `startFullScan()` × N hosts | POST (sequential) |
| Baseline | Load hosts | `getHostsCentral(168)` | GET |
| Baseline | Load baseline | `getBaseline(host)` | GET |
| Baseline | Recompute | `computeBaseline(host, 168)` | POST |
| Baseline | Resolve deviation | `resolveDeviation(id)` | POST/PATCH |

---

*End of frontend inventory.*
