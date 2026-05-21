import { useMemo, useState, type CSSProperties } from 'react';
import type { ConstellationEventRaw } from '../../services/api';

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
type GroupBy = 'flat' | 'host' | 'event' | 'tactic';

const COLORS: Record<Severity, string> = {
  critical: '#ff2f55',
  high: '#ff7a18',
  medium: '#ffd21f',
  low: '#23d36b',
  info: '#00d9ff',
};

const RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

type TimelineEntry = {
  id: string;
  timestamp: string;
  hostname: string;
  ip: string | null;
  eventType: string;
  ruleId: string;
  ruleLevel: number;
  severity: Severity;
  count: number;
  user: string | null;
  process: string | null;
  mitreTactic: string | null;
  mitreId: string | null;
  explanation: string;
};

type TimelineGroup = {
  key: string;
  label: string;
  entries: TimelineEntry[];
  maxSeverity: Severity;
  totalCount: number;
};

export type EventTimelineMapProps = {
  events: ConstellationEventRaw[];
  onSelectEvent?: (event: ConstellationEventRaw) => void;
};

// ── Helpers ───────────────────────────────────────────────────────────────────

function normSev(v: unknown): Severity {
  const s = String(v ?? '').toLowerCase().trim();
  if (s === 'critical') return 'critical';
  if (s === 'high') return 'high';
  if (s === 'medium') return 'medium';
  if (s === 'low') return 'low';
  return 'info';
}

function getEventLabel(e: ConstellationEventRaw): string {
  const eid = String(e.eventId ?? '').trim();
  if (eid === '4625') return '4625 Login Failure';
  if (eid === '4624') return '4624 Successful Logon';
  if (eid === '4672') return '4672 Special Privileges';
  if (eid === '4688') return '4688 Process Created';
  if (eid === '7045') return '7045 New Service';
  const desc = String(e.ruleDescription ?? '').toLowerCase();
  if (desc.includes('powershell')) return 'PowerShell Execution';
  if (desc.includes('service')) return 'Service Activity';
  if (desc.includes('auth') || desc.includes('logon') || desc.includes('login')) return 'Auth Event';
  if (desc.includes('process')) return 'Process Activity';
  if (eid) return `Event ${eid}`;
  if (e.ruleId) return `Rule ${e.ruleId}`;
  return 'Wazuh Alert';
}

function fmtDateTime(v?: string): string {
  if (!v) return '—';
  const d = new Date(v);
  if (isNaN(d.getTime())) return v.slice(0, 19).replace('T', ' ');
  return `${d.toLocaleDateString('de-DE', { day: '2-digit', month: '2-digit' })} ${d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}`;
}

function cut(v: string, max = 28): string {
  return v.length > max ? `${v.slice(0, max - 1)}\u2026` : v;
}

// ── Data processing ───────────────────────────────────────────────────────────

function buildEntries(events: ConstellationEventRaw[]): TimelineEntry[] {
  return events
    .filter((e) => String(e.agentName ?? '').trim())
    .map((e) => ({
      id: String(e.id ?? Math.random()),
      timestamp: String(e.timestamp ?? ''),
      hostname: String(e.agentName ?? '').trim(),
      ip: e.agentIp ?? null,
      eventType: getEventLabel(e),
      ruleId: String(e.ruleId ?? ''),
      ruleLevel: Number(e.ruleLevel ?? 0),
      severity: normSev(e.severity),
      count: Math.max(1, Number(e.count ?? 1)),
      user: String(e.user ?? '').trim() || null,
      process: String(e.process ?? '').trim() || null,
      mitreTactic: String(e.mitreTactic ?? '').trim() || null,
      mitreId: String(e.mitreId ?? '').trim() || null,
      explanation: String(e.ruleDescription ?? e.explanation ?? ''),
    }))
    .sort((a, b) => b.timestamp.localeCompare(a.timestamp));
}

function groupEntries(entries: TimelineEntry[], groupBy: GroupBy): TimelineGroup[] {
  if (groupBy === 'flat') {
    return [
      {
        key: 'all',
        label: 'All Events',
        entries,
        maxSeverity: entries.reduce<Severity>(
          (max, e) => (RANK[e.severity] > RANK[max] ? e.severity : max),
          'info',
        ),
        totalCount: entries.reduce((s, e) => s + e.count, 0),
      },
    ];
  }

  const map = new Map<string, TimelineEntry[]>();
  for (const entry of entries) {
    let key = '';
    if (groupBy === 'host') key = entry.hostname;
    else if (groupBy === 'event') key = entry.eventType;
    else if (groupBy === 'tactic') key = entry.mitreTactic ?? 'No Tactic';

    const list = map.get(key) ?? [];
    list.push(entry);
    map.set(key, list);
  }

  return Array.from(map.entries())
    .map(([key, es]) => ({
      key,
      label: key,
      entries: es,
      maxSeverity: es.reduce<Severity>(
        (max, e) => (RANK[e.severity] > RANK[max] ? e.severity : max),
        'info',
      ),
      totalCount: es.reduce((s, e) => s + e.count, 0),
    }))
    .sort((a, b) => RANK[b.maxSeverity] - RANK[a.maxSeverity] || b.totalCount - a.totalCount);
}

// ── Subcomponents ─────────────────────────────────────────────────────────────

function SevBadge({ severity }: { severity: Severity }) {
  const color = COLORS[severity];
  return (
    <span
      style={{
        display: 'inline-block',
        padding: '1px 7px',
        borderRadius: 999,
        border: `1px solid ${color}`,
        background: `${color}18`,
        color,
        fontSize: 9,
        fontWeight: 900,
        textTransform: 'uppercase',
        letterSpacing: '0.07em',
        whiteSpace: 'nowrap',
      }}
    >
      {severity}
    </span>
  );
}

function EntryRow({
  entry,
  isSelected,
  onClick,
}: {
  entry: TimelineEntry;
  isSelected: boolean;
  onClick: () => void;
}) {
  const color = COLORS[entry.severity];
  return (
    <button
      type="button"
      onClick={onClick}
      style={{
        display: 'grid',
        gridTemplateColumns: '3px 90px 1fr auto',
        gap: 0,
        width: '100%',
        background: isSelected ? `${color}12` : 'transparent',
        border: 'none',
        borderBottom: '1px solid rgba(0,217,255,0.07)',
        borderLeft: isSelected ? `2px solid ${color}` : '2px solid transparent',
        padding: '7px 12px 7px 10px',
        cursor: 'pointer',
        textAlign: 'left',
        fontFamily: 'ui-monospace, monospace',
        color: '#dff8ff',
        alignItems: 'start',
        transition: 'background 0.12s',
      } as CSSProperties}
    >
      {/* Severity color bar */}
      <div
        style={{
          width: 3,
          height: '100%',
          background: color,
          borderRadius: 2,
          marginRight: 10,
          alignSelf: 'stretch',
          minHeight: 28,
        }}
      />

      {/* Timestamp */}
      <div style={{ paddingRight: 10 }}>
        <div style={{ fontSize: 10, color: '#6a8fa4', whiteSpace: 'nowrap' }}>
          {fmtDateTime(entry.timestamp)}
        </div>
        <div style={{ fontSize: 10, color: '#4a6a7c', marginTop: 2 }}>
          {entry.count > 1 ? `×${entry.count}` : '\u00a0'}
        </div>
      </div>

      {/* Main content */}
      <div>
        <div style={{ fontSize: 12, fontWeight: 700, color: isSelected ? '#fff' : '#dff8ff', marginBottom: 3 }}>
          {cut(entry.eventType, 36)}
        </div>
        <div
          style={{
            display: 'flex',
            gap: 8,
            flexWrap: 'wrap',
            fontSize: 10,
            color: '#7fa4b8',
          }}
        >
          <span>⬡ {cut(entry.hostname, 20)}</span>
          {entry.user && <span>👤 {cut(entry.user, 14)}</span>}
          {entry.process && <span>⚙ {cut(entry.process, 14)}</span>}
          {entry.mitreTactic && (
            <span style={{ color: '#8b5cf6' }}>▲ {entry.mitreTactic}</span>
          )}
        </div>
        {isSelected && entry.explanation && (
          <div
            style={{
              marginTop: 6,
              fontSize: 10,
              color: '#9fc8dc',
              lineHeight: 1.5,
              maxWidth: 420,
            }}
          >
            {entry.explanation}
          </div>
        )}
      </div>

      {/* Severity badge */}
      <div style={{ paddingLeft: 10 }}>
        <SevBadge severity={entry.severity} />
        {entry.ruleLevel > 0 && (
          <div style={{ fontSize: 9, color: '#4a6a7c', textAlign: 'right', marginTop: 4 }}>
            lvl {entry.ruleLevel}
          </div>
        )}
      </div>
    </button>
  );
}

function GroupHeader({ group, expanded, onToggle }: {
  group: TimelineGroup;
  expanded: boolean;
  onToggle: () => void;
}) {
  const color = COLORS[group.maxSeverity];
  return (
    <button
      type="button"
      onClick={onToggle}
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 10,
        width: '100%',
        padding: '8px 12px',
        background: `${color}0c`,
        border: 'none',
        borderBottom: `1px solid ${color}30`,
        borderLeft: `3px solid ${color}`,
        cursor: 'pointer',
        fontFamily: 'ui-monospace, monospace',
        color: '#dff8ff',
        textAlign: 'left',
      }}
    >
      <span style={{ fontSize: 11, color: '#5a7a8c', marginRight: 2 }}>{expanded ? '▼' : '▶'}</span>
      <span style={{ fontSize: 12, fontWeight: 900, color: '#e8f4fa', flex: 1 }}>{group.label}</span>
      <SevBadge severity={group.maxSeverity} />
      <span style={{ fontSize: 11, color: '#9fc8dc', minWidth: 60, textAlign: 'right' }}>
        {group.totalCount.toLocaleString()} alerts
      </span>
      <span style={{ fontSize: 10, color: '#5a7a8c' }}>{group.entries.length} entries</span>
    </button>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export default function EventTimelineMap({ events }: EventTimelineMapProps) {
  const [groupBy, setGroupBy] = useState<GroupBy>('flat');
  const [filterSev, setFilterSev] = useState<Set<Severity>>(
    new Set(['critical', 'high', 'medium', 'low', 'info']),
  );
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(new Set());
  const [filterText, setFilterText] = useState('');
  const [limit, setLimit] = useState(150);

  const entries = useMemo(() => buildEntries(events), [events]);

  const filtered = useMemo(() => {
    const txt = filterText.toLowerCase().trim();
    return entries
      .filter((e) => filterSev.has(e.severity))
      .filter(
        (e) =>
          !txt ||
          e.hostname.toLowerCase().includes(txt) ||
          e.eventType.toLowerCase().includes(txt) ||
          (e.user ?? '').toLowerCase().includes(txt) ||
          (e.mitreTactic ?? '').toLowerCase().includes(txt),
      )
      .slice(0, limit);
  }, [entries, filterSev, filterText, limit]);

  const groups = useMemo(() => groupEntries(filtered, groupBy), [filtered, groupBy]);

  const totalAlerts = filtered.reduce((s, e) => s + e.count, 0);
  const critCount = filtered.filter((e) => e.severity === 'critical').length;
  const highCount = filtered.filter((e) => e.severity === 'high').length;

  const toggleSev = (sev: Severity) => {
    setFilterSev((prev) => {
      const next = new Set(prev);
      if (next.has(sev)) {
        if (next.size > 1) next.delete(sev);
      } else {
        next.add(sev);
      }
      return next;
    });
  };

  const toggleGroup = (key: string) => {
    setExpandedGroups((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  const baseStyle: CSSProperties = {
    width: '100%',
    height: '100%',
    display: 'flex',
    flexDirection: 'column',
    background: '#02070d',
    fontFamily: 'ui-monospace, SFMono-Regular, monospace',
    color: '#dff8ff',
    overflow: 'hidden',
  };

  const toolbarStyle: CSSProperties = {
    display: 'flex',
    gap: 8,
    alignItems: 'center',
    padding: '8px 12px',
    borderBottom: '1px solid rgba(0,217,255,0.13)',
    flexShrink: 0,
    flexWrap: 'wrap',
  };

  const pillBase: CSSProperties = {
    padding: '3px 10px',
    borderRadius: 999,
    border: '1px solid rgba(0,217,255,0.22)',
    background: 'rgba(0,217,255,0.06)',
    color: '#7fa4b8',
    fontSize: 10,
    fontWeight: 700,
    cursor: 'pointer',
    fontFamily: 'inherit',
    textTransform: 'uppercase' as const,
    letterSpacing: '0.06em',
  };

  const pillActive: CSSProperties = {
    ...pillBase,
    background: 'rgba(0,217,255,0.16)',
    borderColor: '#00d9ff',
    color: '#dff8ff',
  };

  return (
    <div style={baseStyle}>
      {/* Toolbar */}
      <div style={toolbarStyle}>
        {/* Stats */}
        <span style={{ fontSize: 11, color: '#00d9ff', fontWeight: 900, marginRight: 4 }}>
          ◆ TIMELINE
        </span>
        <span style={{ fontSize: 10, color: '#9fc8dc' }}>{filtered.length} entries</span>
        <span style={{ fontSize: 10, color: '#9fc8dc' }}>
          {totalAlerts.toLocaleString()} alerts
        </span>
        {critCount > 0 && (
          <span style={{ fontSize: 10, color: COLORS.critical }}>● {critCount} critical</span>
        )}
        {highCount > 0 && (
          <span style={{ fontSize: 10, color: COLORS.high }}>● {highCount} high</span>
        )}

        <span style={{ flex: 1 }} />

        {/* Filter input */}
        <input
          value={filterText}
          onChange={(e) => setFilterText(e.target.value)}
          placeholder="filter host / event / tactic..."
          style={{
            height: 26,
            padding: '0 10px',
            background: 'rgba(0,0,0,0.3)',
            border: '1px solid rgba(0,217,255,0.22)',
            borderRadius: 6,
            color: '#dff8ff',
            fontSize: 11,
            fontFamily: 'inherit',
            width: 200,
            outline: 'none',
          }}
        />

        {/* Group by */}
        <span style={{ fontSize: 9, color: '#5a7a8c', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
          Group:
        </span>
        {(['flat', 'host', 'event', 'tactic'] as GroupBy[]).map((g) => (
          <button
            key={g}
            type="button"
            onClick={() => {
              setGroupBy(g);
              setExpandedGroups(new Set());
            }}
            style={groupBy === g ? pillActive : pillBase}
          >
            {g === 'flat' ? 'All' : g}
          </button>
        ))}
      </div>

      {/* Severity filter row */}
      <div
        style={{
          display: 'flex',
          gap: 6,
          padding: '5px 12px',
          borderBottom: '1px solid rgba(0,217,255,0.08)',
          flexShrink: 0,
          flexWrap: 'wrap',
          alignItems: 'center',
        }}
      >
        <span style={{ fontSize: 9, color: '#5a7a8c', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
          Severity:
        </span>
        {(['critical', 'high', 'medium', 'low', 'info'] as Severity[]).map((sev) => {
          const active = filterSev.has(sev);
          const color = COLORS[sev];
          return (
            <button
              key={sev}
              type="button"
              onClick={() => toggleSev(sev)}
              style={{
                padding: '2px 9px',
                borderRadius: 999,
                border: `1px solid ${active ? color : 'rgba(255,255,255,0.12)'}`,
                background: active ? `${color}18` : 'transparent',
                color: active ? color : '#4a6a7c',
                fontSize: 9,
                fontWeight: 700,
                cursor: 'pointer',
                fontFamily: 'inherit',
                textTransform: 'uppercase',
                letterSpacing: '0.06em',
              }}
            >
              ● {sev}
            </button>
          );
        })}
      </div>

      {/* Timeline list */}
      <div style={{ flex: 1, overflowY: 'auto', scrollbarWidth: 'thin' }}>
        {filtered.length === 0 ? (
          <div
            style={{
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              height: '60%',
              gap: 12,
              color: '#3a6a88',
              fontFamily: 'inherit',
            }}
          >
            <span style={{ fontSize: 28 }}>◌</span>
            <span style={{ fontSize: 13 }}>No events match current filter</span>
          </div>
        ) : groupBy === 'flat' ? (
          <>
            {filtered.map((entry) => (
              <EntryRow
                key={entry.id}
                entry={entry}
                isSelected={selectedId === entry.id}
                onClick={() =>
                  setSelectedId((prev) => (prev === entry.id ? null : entry.id))
                }
              />
            ))}
            {entries.length > limit && (
              <div
                style={{
                  padding: '12px 16px',
                  borderTop: '1px solid rgba(0,217,255,0.12)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 12,
                }}
              >
                <span style={{ fontSize: 11, color: '#5a7a8c' }}>
                  Showing {limit} of {entries.length} entries
                </span>
                <button
                  type="button"
                  onClick={() => setLimit((l) => l + 150)}
                  style={{
                    padding: '3px 12px',
                    borderRadius: 6,
                    border: '1px solid rgba(0,217,255,0.22)',
                    background: 'rgba(0,217,255,0.06)',
                    color: '#00d9ff',
                    fontSize: 10,
                    cursor: 'pointer',
                    fontFamily: 'inherit',
                  }}
                >
                  Load more
                </button>
              </div>
            )}
          </>
        ) : (
          groups.map((group) => {
            const expanded = expandedGroups.has(group.key);
            return (
              <div key={group.key}>
                <GroupHeader
                  group={group}
                  expanded={expanded}
                  onToggle={() => toggleGroup(group.key)}
                />
                {expanded &&
                  group.entries.map((entry) => (
                    <EntryRow
                      key={entry.id}
                      entry={entry}
                      isSelected={selectedId === entry.id}
                      onClick={() =>
                        setSelectedId((prev) => (prev === entry.id ? null : entry.id))
                      }
                    />
                  ))}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
