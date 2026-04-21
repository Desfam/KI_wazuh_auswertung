# Redesign Integration Checklist

Integration of the `__REDESIGN__` SOC UI into the existing frontend.
All mock data has been replaced with real API data. All existing functionality preserved.

---

## ✅ Completed

### 1. SOC Design System Foundation
**Files:** `frontend/src/index.css`, `frontend/tailwind.config.js`

- Added JetBrains Mono Google Font import
- Added SOC CSS custom properties to `:root`:
  - Severity: `--soc-critical` (#d43f3f), `--soc-high` (#d47a2a), `--soc-warning` (#c9b820), `--soc-success` (#3ab87a), `--soc-info` (#3a8fc9)
  - Surfaces: `--soc-background`, `--soc-foreground`, `--soc-panel`, `--soc-border`, `--soc-row-hover`
  - Sidebar: `--soc-sidebar`, `--soc-sidebar-fg`, `--soc-sidebar-accent`
  - Inputs: `--soc-muted`, `--soc-muted-fg`, `--soc-accent`, `--soc-input`, `--soc-primary`
- Added Tailwind color tokens referencing CSS vars (18 tokens: `soc-critical`, `soc-high`, etc.)
- Added Tailwind `mono` font family (JetBrains Mono)
- Added SOC utility CSS classes:
  - `.soc-badge` — base badge pill
  - `.soc-row` + hover — dense list row
  - `.soc-border-l-critical/high/warning/info/success/muted` — severity left borders
  - `.soc-kpi-strip` + `.soc-kpi-cell` — metrics strip
  - `.soc-section-header` — section title bar
  - `.soc-sidebar` + `.soc-sidebar-item` (+ `.active`) — sidebar nav
  - `.soc-topbar` — topbar strip
  - `.soc-scroll` — slim scrollbars for dense UI

---

### 2. SOC Components

#### `frontend/src/components/soc/Badges.tsx` ✅
- **`SeverityBadge`** — maps severity string → color-coded badge pill
  - CRITICAL → red, HIGH → orange, MEDIUM → yellow, LOW → blue, INFO → muted
- **`StatusBadge`** — maps task status → OPEN/INVESTIGATING/CONTAINED/CLOSED label
- **`SocTag`** — muted pill for MITRE IDs, groups, etc.
- **`normaliseSeverity()`** — normalises any severity string to `SocSeverity` type
- **`incidentBorderClass()`** — returns CSS border-l class for incident card severity indicator

#### `frontend/src/components/soc/IncidentCard.tsx` ✅
A dense SOC-style incident row card for task/incident queues.
- Props: `{ task: GeneratedTask, selected, onSelect, onInvestigate, onStatusChange, timeAgo? }`
- **Real data:** Uses `GeneratedTask` type mirroring actual API task shape (task_id, host, severity, title, details, recommended_checks, event_id, rule_id, platform, local_score, mitre_ids, status)
- **Real actions:**
  - "Investigate" → calls `onInvestigate(host)` → navigates to Snipen with host prefill
  - "Start Investigation" / "Resolve" / "False Positive" / "↩ Reset" → calls `onStatusChange(taskId, status)`
- Layout: SeverityBadge + StatusBadge + metadata row + title + MITRE tags + action buttons

#### `frontend/src/components/soc/ContextPanel.tsx` ✅
Right-side detail panel for selected incidents/events. Supports three variants:
- **`kind='empty'`** — shows "select an incident →" placeholder
- **`kind='task'`** — shows full `GeneratedTask` details with workflow actions
  - Props: `{ task: GeneratedTask, onInvestigate, onStatusChange }`
  - Sections: header (badges + title + KV grid), Description, Recommended Checks, Quick Pivots
  - Actions: Investigate, Start Investigation / Resolve / False Positive / Reset
- **`kind='event'`** — shows `SocEvent` (live dashboard event) details
  - Props: `{ event: SocEvent, onInvestigate }`
  - Sections: header (badge + title + KV grid), Event Tags, MITRE ATT&CK, Command Line, Quick Pivots
  - Action: "Investigate in Snipen" → `onInvestigate(host)` → Snipen with host prefill

---

### 3. App Shell — Sidebar + Topbar
**File:** `frontend/src/App.tsx`

#### Sidebar (replaced visual style, all logic kept)
- Now uses `.soc-sidebar` + `.soc-sidebar-item` CSS classes
- SOC dark style: `var(--soc-sidebar)` background, `var(--soc-sidebar-fg)` text
- Active item: `border-left-color: var(--soc-primary)` + accent background
- Nav items unchanged: Dashboard, Chat, Incidents (was: Tasks), Hosts, Investigation (was: Snipen), Full Scan, Baseline
- Badges: alert count on Incidents tab, `●` dot on Dashboard when report is available
- AI status dot: green (online), yellow (running), red (offline)
- Theme toggle and Settings button kept
- Live clock state (`clockStr`) ticks every second

#### Topbar (NEW)
A `.soc-topbar` strip at the top of the content area showing:
- Current tab title (left)
- Alert count badge → clickable, switches to Incidents tab (red, only when `generatedTasks.length > 0`)
- AI status indicator (green/yellow/red dot + text)
- Live clock (`HH:MM:SS`)

---

### 4. DashboardPage — SOC Layout
**File:** `frontend/src/pages/DashboardPage.tsx`

Replaced old card-grid layout with SOC 2-column layout. All API calls preserved.

#### Data (unchanged)
- `getSnipenHosts(24)` → `hosts[]`
- `getSnipenHostEvents(host, { hours: 24, limit: 300 })` per top-10 hosts → `eventsByHost`
- 90-second auto-refresh loop
- Computed: `allEvents`, `metrics`, `topHosts`, `lageBild`, `recentActivities`
- `profileAssignments` used in Top Hosts panel (ProfileBadge shown)

#### Layout (new)
```
┌─────────────────────────────────────────┬──────────────────┐
│ KPI STRIP: Threat Level · Active Alerts · Critical · Active Hosts · Total Agents │
├─────────────────────────────────────────┼──────────────────┤
│ INCIDENT QUEUE                          │                  │
│ [All Open] [Crit+High]                  │  CONTEXT PANEL   │
│                                         │  (selected event │
│ ← SocEvent rows from allEvents          │   details)       │
│   sorted by severity + timestamp        │                  │
│                                         │                  │
├───────────────────┬─────────────────────┤                  │
│ TOP HOSTS         │ RECENT ACTIVITY     │                  │
│ (real host data)  │ (real event feed)   │                  │
└───────────────────┴─────────────────────┴──────────────────┘
```

#### Real data mapping
| SOC UI element | Real data source |
|---------------|------------------|
| KPI "Threat Level" | `lageBild.status` (critical/warning/normal) |
| KPI "Active Alerts" | `metrics.totalAlerts` (sum of `host.alert_count`) |
| KPI "Critical" | `metrics.criticalFindings` (events with rule_level ≥ 14) |
| KPI "Active Hosts" | `metrics.activeHosts` (hosts seen in last 6h) |
| KPI "Total Agents" | `hosts.length` |
| Incident queue rows | `allEvents` sorted by severity + timestamp |
| Event row severity | `severityFromLevel(ev.smart.rule_level)` |
| Context panel | `ContextPanel kind="event"` with full `SocEvent` fields |
| "Investigate" button | `onSwitchTab('snipen', { host })` → Snipen prefill |
| Top Hosts | `topHosts` (top 5 by alert_count, with ProfileBadge) |
| Recent Activity | `recentActivities` (8 most recent events) |

#### Props (unchanged + extended)
```typescript
interface Props {
  active: boolean;
  theme: 'light' | 'dark';
  onSwitchTab: (tab, context?: { host?: string }) => void;  // extended with context
  profileAssignments: Record<string, HostProfileAssignment>;
}
```

---

### 5. TasksPage — SOC Incident Layout
**File:** `frontend/src/pages/TasksPage.tsx`

Replaced custom accordion cards with `IncidentCard` + `ContextPanel`. All state and filter logic preserved.

#### Layout (new)
```
┌─────────────────────────────────────────┬──────────────────┐
│ KPI STRIP: Total · Open · Investigating · Resolved          │
├─────────────────────────────────────────┼──────────────────┤
│ INCIDENTS [n]                           │                  │
│ [All][Critical][High][Med][Low] | [All Status][Open][Active][Resolved] │
│                                         │  CONTEXT PANEL   │
│ ← IncidentCard rows (generatedTasks)    │  (selected task  │
│   fade-in animation preserved           │   details +      │
│   severity + status filter active       │   workflow btns) │
└─────────────────────────────────────────┴──────────────────┘
```

#### Real data & functionality preserved
- All `generatedTasks` from App state shown as `IncidentCard` components
- `taskStatuses` state preserved (internal `'neu'` mapped to `'new'` for IncidentCard)
- Severity filter: All / Critical / High / Medium / Low
- Status filter: All Status / Open / Active / Resolved
- Animated entry (fade-in stagger, 50ms delay per card)
- "Investigate" → `onSwitchTab('snipen', { host })` → Snipen with host prefill
- Workflow buttons (Start Investigation, Resolve, False Positive, Reset) → update `taskStatuses`
- Selected task → shown in right ContextPanel with same workflow buttons

---

## Pages Not Modified (benefit from new CSS vars)

| Page | Status | Notes |
|------|--------|-------|
| ChatPage | No change | Existing UI intact |
| HostsPage | No change | Existing UI intact |
| SnipenPage | No change | Existing UI intact |
| FullScanTab | No change | Existing UI intact |
| BaselinePage | No change | Existing UI intact |
| SettingsModal | No change | Existing UI intact |

---

## Data Mapping Reference

| Redesign mock type | Real app equivalent |
|-------------------|---------------------|
| `incidents[]` (mock data) | `generatedTasks[]` from App state (TasksPage) |
| Dashboard event queue | `allEvents` from `getSnipenHostEvents()` (DashboardPage) |
| `h.risk` (0-100 mock) | `host.alert_count` + `hostRiskLabel(host.top_rule_level)` |
| `incident.severity` | `severityFromLevel(ev.smart.rule_level)` → SocSeverity |
| `incident.status` | `taskStatuses[taskId]` mapped to OPEN/INVESTIGATING/CONTAINED/CLOSED |
| `incident.mitre` | `task.mitre_ids[]` |
| `incident.eventId` | `task.event_id` |

---

## Architecture Notes

- **NOT a TanStack Router migration** — tab-based SPA architecture preserved
- **Theme toggle kept** — SOC CSS vars are always active in `:root`, dark mode class still applied for other components (ChatPage, HostsPage, etc.)
- **Font change** — root `font-mono` on App.tsx; individual pages unaffected unless they opt-in via class
- **Backwards compatible** — all existing component APIs (ChatPage, HostsPage, SnipenPage, FullScanTab, BaselinePage) are unchanged
- **No new API endpoints** — all backend calls use existing `services/api.ts` functions
