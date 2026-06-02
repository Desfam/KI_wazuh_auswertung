/**
 * SnipenPage – Host-centric Threat Hunting & Event Investigation
 * Layout: type-filter sidebar | event timeline | detail panel
 */
import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Search,
  Cpu,
  Network,
  KeyRound,
  Wrench,
  FileText,
  Database,
  Plus,
  Download,
  GitBranch,
  RefreshCw,
  Sparkles,
  PanelLeftClose,
  PanelLeftOpen,
  PanelRightClose,
  PanelRightOpen,
} from 'lucide-react';
import {
  getSnipenHostEvents,
  getSnipenHosts,
  getSnipenAllEvents,
  explainSnipenEvent,
  explainSnipenEventWithContext,
} from '../services/api';
import type {
  HostProfileAssignment,
  SnipenEvent,
  SnipenHostInfo,
  SnipenExplainResult,
} from '../types';

// ── Types & constants ─────────────────────────────────────────────────────────

interface SnipenPageProps {
  active: boolean;
  theme: 'light' | 'dark';
  profileAssignments: Record<string, HostProfileAssignment>;
  prefillHost?: string | null;
  prefillEventTs?: string | null;
  onPrefillConsumed?: () => void;
}

type CategoryFilter = 'all' | 'process' | 'network' | 'auth' | 'service' | 'file' | 'registry';
type TimePreset = 1 | 6 | 24 | 72 | 168;

const TYPES: { id: CategoryFilter; label: string; icon: React.ComponentType<{ className?: string }> }[] = [
  { id: 'all', label: 'all', icon: FileText },
  { id: 'process', label: 'process', icon: Cpu },
  { id: 'network', label: 'network', icon: Network },
  { id: 'auth', label: 'auth', icon: KeyRound },
  { id: 'service', label: 'service', icon: Wrench },
  { id: 'file', label: 'file', icon: FileText },
  { id: 'registry', label: 'registry', icon: Database },
];

const TIME_PRESETS: TimePreset[] = [1, 6, 24, 72, 168];

// ── Severity helpers ──────────────────────────────────────────────────────────

function ruleLevelToSeverity(level: number | null | undefined): string {
  if (!level) return 'info';
  if (level >= 14) return 'critical';
  if (level >= 10) return 'high';
  if (level >= 7) return 'medium';
  if (level >= 4) return 'low';
  return 'info';
}

function sevBadgeClass(sev: string) {
  if (sev === 'critical') return 'bg-critical/15 text-critical border-critical/40';
  if (sev === 'high') return 'bg-warning/15 text-warning border-warning/40';
  if (sev === 'medium') return 'bg-warning/10 text-warning border-warning/40';
  if (sev === 'low') return 'bg-success/15 text-success border-success/40';
  return 'bg-muted text-muted-foreground border-border';
}

function sevTextClass(sev: string) {
  if (sev === 'critical') return 'text-critical';
  if (sev === 'high') return 'text-high';
  if (sev === 'medium') return 'text-warning';
  if (sev === 'low') return 'text-success';
  return 'text-info';
}

// ── Event helpers ─────────────────────────────────────────────────────────────

function deriveCategory(event: SnipenEvent): CategoryFilter {
  const s = event.smart;
  const groups = (s.groups ?? []).map((g) => g.toLowerCase()).join(' ');
  const family = (s.event_family ?? '').toLowerCase();
  const eid = s.event_id ?? '';
  if (['4624', '4625', '4768', '4769', '4771', '4776'].includes(eid) || family.includes('auth') || groups.includes('auth')) return 'auth';
  if (s.process || s.command_line || family.includes('process') || groups.includes('process')) return 'process';
  if (s.registry_key || family.includes('registry') || groups.includes('registry')) return 'registry';
  if (s.ip_address || family.includes('network') || groups.includes('network')) return 'network';
  if (['7045', '4697'].includes(eid) || family.includes('service') || groups.includes('service')) return 'service';
  if (family.includes('file') || groups.includes('file')) return 'file';
  return 'all';
}

function categoryIcon(cat: CategoryFilter): React.ComponentType<{ className?: string }> {
  const found = TYPES.find((t) => t.id === cat);
  return found?.icon ?? FileText;
}

/** Format a UTC ISO timestamp as "dd.MM  HH:MM:SS" in the browser's local timezone. */
function fmtTime(ts: string | null | undefined): string {
  if (!ts) return '—';
  const d = new Date(ts);
  const day   = String(d.getDate()).padStart(2, '0');
  const month = String(d.getMonth() + 1).padStart(2, '0');
  const time  = d.toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  return `${day}.${month}  ${time}`;
}

// ── Main component ────────────────────────────────────────────────────────────

export function SnipenPage({
  active,
  prefillHost,
  prefillEventTs,
  onPrefillConsumed,
}: SnipenPageProps) {
  // Host list state
  const [hosts, setHosts] = useState<SnipenHostInfo[]>([]);
  const [hostsLoading, setHostsLoading] = useState(false);
  const [hostsError, setHostsError] = useState<string | null>(null);
  const [selectedHost, setSelectedHost] = useState<string | null>(null);
  const [hours, setHours] = useState<TimePreset>(24);
  const [eventLimit, setEventLimit] = useState<number>(500);

  // Event state
  const [events, setEvents] = useState<SnipenEvent[]>([]);
  const [eventsLoading, setEventsLoading] = useState(false);
  const [selectedEventTs, setSelectedEventTs] = useState<string | null>(null);
  const [typeFilter, setTypeFilter] = useState<CategoryFilter>('all');
  const [query, setQuery] = useState('');

  // AI explain state
  const [explainResult, setExplainResult] = useState<SnipenExplainResult | null>(null);
  const [explainLoading, setExplainLoading] = useState(false);
  const [explainContextLoading, setExplainContextLoading] = useState(false);
  const [explainError, setExplainError] = useState<string | null>(null);
  const [rawExpanded, setRawExpanded] = useState(false);
  const [detailMode, setDetailMode] = useState<'smart' | 'raw' | 'ai'>('smart');

  const loadHosts = useCallback(() => {
    setHostsLoading(true);
    setHostsError(null);
    getSnipenHosts(hours)
      .then((data) => {
        setHosts(data);
        if (data.length > 0 && !selectedHost) {
          setSelectedHost(data[0].host);
        }
      })
      .catch((e: unknown) => setHostsError(e instanceof Error ? e.message : 'Failed to load hosts'))
      .finally(() => setHostsLoading(false));
  }, [hours, selectedHost]);

  // Load hosts on mount / when active
  useEffect(() => {
    if (!active) return;
    loadHosts();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active, hours]);

  // Handle prefill from Tasks tab
  useEffect(() => {
    if (prefillHost && active) {
      setSelectedHost(prefillHost);
      setQuery(`host:${prefillHost}`);
      onPrefillConsumed?.();
    }
  }, [prefillHost, active, onPrefillConsumed]);

  // Auto-select a specific event after events are loaded
  useEffect(() => {
    if (prefillEventTs && events.length > 0) {
      setSelectedEventTs(prefillEventTs);
    }
  }, [prefillEventTs, events]);

  // Load events when host changes
  useEffect(() => {
    if (!selectedHost) return;
    setEventsLoading(true);
    setEvents([]);
    setSelectedEventTs(null);
    setExplainResult(null);
    setExplainError(null);
    const loadPromise = selectedHost === '__all__'
      ? getSnipenAllEvents({ hours, limit: eventLimit })
      : getSnipenHostEvents(selectedHost, { hours, limit: eventLimit });
    loadPromise
      .then((data) => {
        setEvents(data);
        if (data.length > 0) setSelectedEventTs(data[0].smart.timestamp ?? null);
      })
      .catch(() => setEvents([]))
      .finally(() => setEventsLoading(false));
  }, [selectedHost, hours, eventLimit]);

  // Filtered events
  const filtered = useMemo(() => {
    return events.filter((e) => {
      const s = e.smart;
      if (typeFilter !== 'all' && deriveCategory(e) !== typeFilter) return false;
      if (!query) return true;
      const q = query.toLowerCase();
      // pivot syntax: host:X user:X eid:X process:X
      const pairs = q.split(/\s+/).filter((x) => x.includes(':'));
      if (pairs.length === 0) {
        const text = [s.rule_description, s.event_id, s.host, s.user, s.process, s.summary]
          .filter(Boolean)
          .join(' ')
          .toLowerCase();
        return text.includes(q);
      }
      return pairs.every((p) => {
        const [k, v] = p.split(':');
        if (!v) return true;
        switch (k) {
          case 'host': return (s.host ?? '').toLowerCase().includes(v);
          case 'user': return (s.user ?? '').toLowerCase().includes(v);
          case 'eid': return s.event_id === v;
          case 'process': return (s.process ?? '').toLowerCase().includes(v);
          default: return true;
        }
      });
    });
  }, [events, typeFilter, query]);

  const selectedEvent = events.find((e) => e.smart.timestamp === selectedEventTs) ?? filtered[0] ?? null;

  // Clear explain when event changes
  useEffect(() => {
    setExplainResult(null);
    setExplainError(null);
    setExplainContextLoading(false);
    setRawExpanded(false);
    setDetailMode('smart');
  }, [selectedEventTs]);

  function handleExplain() {
    if (!selectedEvent || explainLoading) return;
    setDetailMode('ai');
    setExplainLoading(true);
    setExplainError(null);
    explainSnipenEvent((selectedEvent.raw ?? selectedEvent.smart) as unknown as Record<string, unknown>)
      .then((res) => setExplainResult(res))
      .catch((e: unknown) => setExplainError(e instanceof Error ? e.message : 'Explain failed'))
      .finally(() => setExplainLoading(false));
  }

  function handleExplainWithContext() {
    if (!selectedEvent || explainContextLoading) return;
    setDetailMode('ai');
    setExplainContextLoading(true);
    setExplainError(null);
    explainSnipenEventWithContext((selectedEvent.raw ?? selectedEvent.smart) as unknown as Record<string, unknown>)
      .then((res) => setExplainResult(res))
      .catch((e: unknown) => setExplainError(e instanceof Error ? e.message : 'Context explain failed'))
      .finally(() => setExplainContextLoading(false));
  }

  // Top host stats
  const topHosts = useMemo(() => {
    const counts: Record<string, number> = {};
    events.forEach((e) => { const h = e.smart.host ?? ''; if (h) counts[h] = (counts[h] ?? 0) + 1; });
    return Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 5);
  }, [events]);

  const topUsers = useMemo(() => {
    const counts: Record<string, number> = {};
    events.forEach((e) => { const u = e.smart.user ?? ''; if (u && u !== 'SYSTEM') counts[u] = (counts[u] ?? 0) + 1; });
    return Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 4).map(([u]) => u);
  }, [events]);

  const [leftCollapsed, setLeftCollapsed] = useState(false);
  const [rightCollapsed, setRightCollapsed] = useState(false);

  return (
    <div
      className="h-full grid min-h-0"
      style={{ gridTemplateColumns: `${leftCollapsed ? '28px' : '180px'} 1fr ${rightCollapsed ? '28px' : '460px'}` }}
    >
      {/* Left: type filter + context */}
      <aside className="border-r border-border bg-[var(--panel)] flex flex-col min-h-0 overflow-hidden">
        {leftCollapsed ? (
          /* collapsed: just the expand button */
          <div className="flex-1 flex flex-col items-center justify-end pb-2 pt-1">
            <button
              onClick={() => setLeftCollapsed(false)}
              title="Sidebar aufklappen"
              className="h-6 w-6 rounded-sm border border-border hover:bg-accent inline-flex items-center justify-center text-muted-foreground"
            >
              <PanelLeftOpen className="h-3.5 w-3.5" />
            </button>
          </div>
        ) : (
          <>
        <FSec title="Type">
          {TYPES.map((t) => {
            const active2 = typeFilter === t.id;
            const Icon = t.icon;
            return (
              <button
                key={t.id}
                onClick={() => setTypeFilter(t.id)}
                className={
                  'w-full flex items-center gap-2 h-6 px-2 rounded-sm text-[11.5px] font-mono ' +
                  (active2
                    ? 'bg-accent text-foreground'
                    : 'text-muted-foreground hover:bg-accent hover:text-foreground')
                }
              >
                <Icon className="h-3 w-3" />
                {t.label}
              </button>
            );
          })}
        </FSec>

        <FSec title="Time Range">
          {TIME_PRESETS.map((h) => (
            <button
              key={h}
              onClick={() => setHours(h)}
              className={
                'w-full text-left h-6 px-2 rounded-sm text-[11.5px] font-mono ' +
                (hours === h
                  ? 'bg-accent text-foreground'
                  : 'text-muted-foreground hover:bg-accent hover:text-foreground')
              }
            >
              {h === 1 ? 'last 1h' : h === 6 ? 'last 6h' : h === 24 ? 'last 24h' : h === 72 ? 'last 3d' : 'last 7d'}
            </button>
          ))}
        </FSec>

        <FSec title="Hosts" scrollable>
          {/* All-hosts shortcut */}
          <button
            onClick={() => { setSelectedHost('__all__'); setQuery(''); }}
            className={
              'w-full text-left h-6 px-2 rounded-sm text-[11.5px] font-mono truncate ' +
              (selectedHost === '__all__'
                ? 'bg-accent text-foreground'
                : 'text-muted-foreground hover:bg-accent hover:text-foreground')
            }
          >
            ★ All Hosts
          </button>
          {hostsLoading && (
            <div className="px-2 text-[11px] font-mono text-muted-foreground">loading…</div>
          )}
          {hostsError && (
            <div className="px-2 text-[11px] font-mono text-critical truncate">{hostsError}</div>
          )}
          {hosts.map((h) => (
            <button
              key={h.host}
              onClick={() => { setSelectedHost(h.host); setQuery(`host:${h.host}`); }}
              className={
                'w-full text-left h-6 px-2 rounded-sm text-[11.5px] font-mono truncate ' +
                (selectedHost === h.host
                  ? 'bg-accent text-foreground'
                  : 'text-muted-foreground hover:bg-accent hover:text-foreground')
              }
            >
              → {h.host}
            </button>
          ))}
        </FSec>

        {topUsers.length > 0 && (
          <FSec title="Top Users">
            {topUsers.map((u) => (
              <button
                key={u}
                onClick={() => setQuery(`user:${u}`)}
                className="w-full text-left h-6 px-2 rounded-sm text-[11.5px] font-mono text-muted-foreground hover:bg-accent hover:text-foreground truncate"
              >
                → {u}
              </button>
            ))}
          </FSec>
        )}

        {topHosts.length > 1 && (
          <FSec title="Top Hosts">
            {topHosts.map(([h, n]) => (
              <button
                key={h}
                onClick={() => setQuery(`host:${h}`)}
                className="w-full text-left h-6 px-2 rounded-sm text-[11.5px] font-mono text-muted-foreground hover:bg-accent hover:text-foreground flex items-center gap-1"
              >
                <span className="truncate flex-1">→ {h}</span>
                <span className="text-[10.5px] shrink-0">{n}</span>
              </button>
            ))}
          </FSec>
        )}

        <div className="mt-auto p-2 border-t border-border flex flex-col gap-1">
          {!leftCollapsed && (
            <button
              onClick={loadHosts}
              className="w-full h-6 rounded-sm border border-border hover:bg-accent text-[11px] font-mono inline-flex items-center justify-center gap-1 text-muted-foreground"
            >
              <RefreshCw className="h-3 w-3" /> Refresh
            </button>
          )}
          <button
            onClick={() => setLeftCollapsed((v) => !v)}
            title={leftCollapsed ? 'Sidebar aufklappen' : 'Sidebar einklappen'}
            className="w-full h-6 rounded-sm border border-border hover:bg-accent text-[11px] font-mono inline-flex items-center justify-center gap-1 text-muted-foreground"
          >
            {leftCollapsed ? <PanelLeftOpen className="h-3.5 w-3.5" /> : <PanelLeftClose className="h-3.5 w-3.5" />}
            {!leftCollapsed && <span>Einklappen</span>}
          </button>
        </div>
          </> 
        )}
      </aside>

      {/* Center: event timeline */}
      <div className="flex flex-col min-h-0 border-r border-border">
        {/* Search toolbar */}
        <div className="border-b border-border bg-[var(--panel)] px-3 py-2 flex items-center gap-2">
          <div className="flex items-center gap-2 h-7 flex-1 px-2 rounded-sm bg-input border border-border">
            <Search className="h-3.5 w-3.5 text-muted-foreground" />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="host: user: eid: process: keyword"
              className="bg-transparent flex-1 outline-none text-[12px] font-mono placeholder:text-muted-foreground"
            />
            <span className="text-[10px] font-mono text-muted-foreground shrink-0">{filtered.length} hits</span>
          </div>
          <select
            value={eventLimit}
            onChange={(e) => setEventLimit(Number(e.target.value))}
            className="h-7 px-2 rounded-sm border border-border bg-[var(--panel)] text-[11px] font-mono text-muted-foreground cursor-pointer hover:bg-accent"
          >
            {[500, 1000, 2000, 5000, 10000, 50000, 100000].map((l) => (
              <option key={l} value={l}>{l >= 100000 ? 'All' : l >= 50000 ? '50 k' : l >= 10000 ? '10 k' : l >= 5000 ? '5 k' : l}</option>
            ))}
          </select>
          <button
            onClick={loadHosts}
            className="h-7 px-2 rounded-sm border border-border hover:bg-accent text-[11px] font-mono inline-flex items-center gap-1"
          >
            <RefreshCw className="h-3 w-3" />
          </button>
          <button className="h-7 px-2 rounded-sm border border-border hover:bg-accent text-[11px] font-mono inline-flex items-center gap-1">
            <Plus className="h-3 w-3" /> Add to Incident
          </button>
          <button className="h-7 px-2 rounded-sm border border-border hover:bg-accent text-[11px] font-mono inline-flex items-center gap-1">
            <Download className="h-3 w-3" /> Export
          </button>
        </div>

        {/* Histogram strip */}
        <div
          className="px-3 py-2 border-b border-border bg-[var(--panel)] grid gap-[2px] h-12"
          style={{ gridTemplateColumns: 'repeat(30, minmax(0, 1fr))' }}
        >
          {Array.from({ length: 30 }).map((_, i) => {
            const v = (Math.sin(i * 0.7) + 1) * 0.5 * 100;
            const sev =
              filtered.some((e) => {
                const sev2 = ruleLevelToSeverity(e.smart.rule_level);
                return sev2 === 'critical';
              }) && i === 22
                ? 'bg-critical'
                : v > 70
                  ? 'bg-warning/60'
                  : 'bg-info/40';
            return (
              <div key={i} className="flex items-end">
                <div className={'w-full rounded-sm ' + sev} style={{ height: `${Math.max(10, v)}%` }} />
              </div>
            );
          })}
        </div>

        {/* Event list */}
        <div className="flex-1 overflow-y-auto">
          {eventsLoading && (
            <div className="flex items-center justify-center h-20 text-[12px] font-mono text-muted-foreground">
              loading events…
            </div>
          )}
          {!eventsLoading && filtered.length === 0 && (
            <div className="flex items-center justify-center h-20 text-[12px] font-mono text-muted-foreground">
              {selectedHost ? 'no events match filter' : 'select a host or All Hosts →'}
            </div>
          )}
          {filtered.map((e) => {
            const s = e.smart;
            const sev = ruleLevelToSeverity(s.rule_level);
            const sel = s.timestamp === selectedEventTs;
            const Icon = categoryIcon(deriveCategory(e));
            return (
              <button
                key={(s.timestamp ?? '') + (s.event_id ?? '') + (e.doc_id ?? '')}
                onClick={() => setSelectedEventTs(s.timestamp ?? null)}
                className={
                  'w-full text-left grid grid-cols-[110px_22px_60px_70px_1fr_120px] gap-2 px-3 py-1.5 border-b border-border/60 hover:bg-[var(--row-hover)] ' +
                  (sel ? 'bg-[var(--row-hover)] border-l-2 border-l-primary -ml-px pl-[11px]' : '')
                }
              >
                <span className="text-[11px] font-mono text-muted-foreground truncate">
                  {fmtTime(s.timestamp)}
                </span>
                <Icon className="h-3.5 w-3.5 text-muted-foreground" />
                <span
                  className={
                    'inline-flex items-center h-[18px] px-1.5 rounded-sm text-[10px] font-mono uppercase tracking-wider border self-center ' +
                    sevBadgeClass(sev)
                  }
                >
                  {sev}
                </span>
                <span className={'text-[11px] font-mono ' + sevTextClass(sev)}>
                  [{s.event_id ?? '—'}]
                </span>
                <span className="text-[12px] truncate">
                  {s.summary ?? s.rule_description ?? '—'}
                </span>
                <span className="text-[11px] font-mono text-muted-foreground truncate text-right">
                  {s.host ?? selectedHost ?? '—'}
                </span>
              </button>
            );
          })}
        </div>

        {/* Footer: event count */}
        {!eventsLoading && events.length > 0 && (
          <div className="border-t border-border bg-[var(--panel)] px-3 h-6 flex items-center justify-between flex-shrink-0">
            <span className="text-[10.5px] font-mono text-muted-foreground">{filtered.length} Events</span>
            <span className="text-[10.5px] font-mono text-muted-foreground">{selectedHost === '__all__' ? 'All Hosts' : (selectedHost ?? '')}</span>
          </div>
        )}

        {/* Process tree mini */}
        <div className="border-t border-border bg-[var(--panel)] px-3 py-2">
          <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground mb-1.5 flex items-center gap-1">
            <GitBranch className="h-3 w-3" /> Process Tree
          </div>
          <pre className="text-[11px] font-mono leading-snug text-muted-foreground">
            {selectedEvent?.smart.process
              ? `${selectedEvent.smart.process}\n  ↳ pid ${selectedEvent.smart.process_id ?? '?'}`
              : 'no process context'}
          </pre>
        </div>
      </div>

      {/* Right: event detail */}
      <aside className="bg-[var(--panel)] flex flex-col min-h-0 overflow-hidden">
        {/* Header: mode tabs + actions */}
        <div className="h-9 px-2 flex items-center gap-2 border-b border-border shrink-0">
          {/* Right-panel collapse toggle — always visible */}
          <button
            onClick={() => setRightCollapsed((v) => !v)}
            title={rightCollapsed ? 'Detail aufklappen' : 'Detail einklappen'}
            className="h-6 w-6 rounded-sm border border-border hover:bg-accent inline-flex items-center justify-center text-muted-foreground shrink-0"
          >
            {rightCollapsed ? <PanelRightOpen className="h-3.5 w-3.5" /> : <PanelRightClose className="h-3.5 w-3.5" />}
          </button>
          {!rightCollapsed && selectedEvent ? (
            <>
              {/* Mode toggle */}
              <div className="flex rounded-sm overflow-hidden border border-border text-[11px] font-mono shrink-0">
                {(['smart', 'raw', 'ai'] as const).map((m) => (
                  <button
                    key={m}
                    type="button"
                    onClick={() => setDetailMode(m)}
                    className={
                      'px-2.5 py-0.5 transition ' +
                      (detailMode === m
                        ? 'bg-accent text-foreground'
                        : 'text-muted-foreground hover:text-foreground')
                    }
                  >
                    {m === 'smart' ? '{ } Smart' : m === 'raw' ? 'Raw' : '✦ AI'}
                  </button>
                ))}
              </div>
              {/* Severity */}
              <span
                className={
                  'inline-flex items-center h-[18px] px-1.5 rounded-sm text-[10px] font-mono uppercase tracking-wider border shrink-0 ' +
                  sevBadgeClass(ruleLevelToSeverity(selectedEvent.smart.rule_level))
                }
              >
                {ruleLevelToSeverity(selectedEvent.smart.rule_level)}
              </span>
              {/* Explain button */}
              <button
                type="button"
                onClick={handleExplain}
                disabled={explainLoading || explainContextLoading}
                className="ml-auto h-6 px-2 rounded-sm border border-border hover:bg-accent text-[11px] font-mono inline-flex items-center gap-1 disabled:opacity-50 shrink-0"
              >
                <Sparkles className="h-3 w-3" />
                {explainLoading ? 'AI…' : 'Erklären'}
              </button>
              {/* Context-aware explain button */}
              <button
                type="button"
                onClick={handleExplainWithContext}
                disabled={explainLoading || explainContextLoading}
                title="Erklärt das Event im Kontext der ±15-Minuten-Ereignisse auf demselben Host"
                className="h-6 px-2 rounded-sm border border-border hover:bg-accent text-[11px] font-mono inline-flex items-center gap-1 disabled:opacity-50 shrink-0"
              >
                <GitBranch className="h-3 w-3" />
                {explainContextLoading ? 'Kontext…' : '+Kontext'}
              </button>
            </>
          ) : (
            !rightCollapsed && <span className="text-[12px] font-semibold tracking-wide px-1">EVENT</span>
          )}
        </div>

        {!rightCollapsed && selectedEvent ? (
          <div className="flex-1 overflow-y-auto">
            {/* Event title + meta (always visible) */}
            <div className="px-3 py-2 border-b border-border">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-[12px] font-semibold leading-tight">
                  {selectedEvent.smart.rule_description ?? `Rule ${selectedEvent.smart.rule_id ?? '?'}`}
                </span>
              </div>
              <div className="mt-0.5 flex flex-wrap gap-x-2 text-[10.5px] font-mono text-muted-foreground">
                <span>{selectedEvent.smart.host ?? selectedHost ?? '—'}</span>
                <span>•</span>
                <span>{fmtTime(selectedEvent.smart.timestamp)}</span>
                {selectedEvent.smart.event_id && <><span>•</span><span>[{selectedEvent.smart.event_id}]</span></>}
              </div>
            </div>

            {/* ── SMART view: flat field rows ── */}
            {detailMode === 'smart' && (
              <div className="border-b border-border">
                {([
                  ['FIM Path',       selectedEvent.smart.fim_path],
                  ['FIM Mode',       selectedEvent.smart.fim_mode],
                  ['FIM Owner',      selectedEvent.smart.fim_owner],
                  ['FIM Group',      selectedEvent.smart.fim_group],
                  ['Event Meaning',  selectedEvent.smart.event_explanation],
                  ['System Message', selectedEvent.smart.system_message],
                  ['Rule ID',        selectedEvent.smart.rule_id],
                  ['Rule Level',     selectedEvent.smart.rule_level != null ? String(selectedEvent.smart.rule_level) : null],
                  ['MITRE ID',       selectedEvent.smart.mitre_id],
                  ['MITRE Tactic',   selectedEvent.smart.mitre_tactic],
                  ['User',           selectedEvent.smart.user],
                  ['IP Address',     selectedEvent.smart.ip_address],
                  ['Process',        selectedEvent.smart.process],
                  ['Command Line',   selectedEvent.smart.command_line],
                  ['Logon Type',     selectedEvent.smart.logon_type],
                  ['Service',        selectedEvent.smart.service_name],
                  ['Registry Key',   selectedEvent.smart.registry_key],
                  ['Decoder',        selectedEvent.smart.decoder],
                  ['Location',       selectedEvent.smart.location],
                ] as [string, string | null | undefined][])
                  .filter(([, v]) => v != null && v !== '')
                  .map(([label, value]) => (
                    <div
                      key={label}
                      className="flex gap-3 px-3 py-1 text-[11px] border-b border-border/40 last:border-0"
                    >
                      <span className="w-28 shrink-0 text-muted-foreground font-mono">{label}</span>
                      <span className="font-mono break-all text-foreground text-[10.5px]">{value}</span>
                    </div>
                  ))}
                {(selectedEvent.smart.groups?.length ?? 0) > 0 && (
                  <div className="flex flex-wrap gap-1 px-3 py-1.5 border-b border-border/40">
                    {selectedEvent.smart.groups.map((g) => (
                      <span key={g} className="font-mono text-[10px] px-1.5 py-0.5 rounded-sm border border-border bg-muted/40 text-muted-foreground">
                        #{g}
                      </span>
                    ))}
                  </div>
                )}
                {/* Quick Pivots */}
                <div className="px-3 py-1.5">
                  <div className="text-[9.5px] font-mono uppercase tracking-wider text-muted-foreground mb-1">Quick Pivots</div>
                  <div className="flex flex-wrap gap-1">
                    {[
                      selectedEvent.smart.host        ? `host:${selectedEvent.smart.host}` : null,
                      selectedEvent.smart.event_id    ? `eid:${selectedEvent.smart.event_id}` : null,
                      selectedEvent.smart.user        ? `user:${selectedEvent.smart.user}` : null,
                      selectedEvent.smart.process     ? `process:${selectedEvent.smart.process}` : null,
                      selectedEvent.smart.ip_address  ? `ip:${selectedEvent.smart.ip_address}` : null,
                      selectedEvent.smart.rule_id     ? `rule:${selectedEvent.smart.rule_id}` : null,
                    ]
                      .filter(Boolean)
                      .map((p) => (
                        <button
                          key={p as string}
                          onClick={() => setQuery(p as string)}
                          className="h-5 px-2 rounded-sm border border-border hover:bg-accent text-[10px] font-mono truncate"
                        >
                          → {p}
                        </button>
                      ))}
                  </div>
                </div>
              </div>
            )}

            {/* ── RAW view ── */}
            {detailMode === 'raw' && (
              <pre className="px-3 py-2 text-[11px] font-mono whitespace-pre-wrap leading-snug text-muted-foreground overflow-y-auto">
                {JSON.stringify(selectedEvent.raw ?? selectedEvent.smart, null, 2)}
              </pre>
            )}

            {/* ── AI view ── */}
            {detailMode === 'ai' && (
              <div className="px-3 py-2">
                {(explainLoading || explainContextLoading) && (
                  <div className="flex items-center gap-2 py-4 text-[11px] font-mono text-muted-foreground">
                    <Sparkles className="h-3.5 w-3.5 animate-pulse" />
                    {explainContextLoading ? 'Kontextfenster wird geladen…' : 'Analysing…'}
                  </div>
                )}
                {explainError && (
                  <div className="text-[11px] font-mono text-critical py-2">{explainError}</div>
                )}
                {!explainLoading && !explainContextLoading && !explainResult && !explainError && (
                  <div className="flex flex-col items-center gap-3 py-8 text-[11px] font-mono text-muted-foreground">
                    <Sparkles className="h-5 w-5" />
                    <p>Click <strong className="text-foreground">Erklären</strong> or <strong className="text-foreground">+Kontext</strong> to analyse this event</p>
                  </div>
                )}
                {explainResult && (
                  <div className="space-y-3">
                    {/* Header: severity + risk score + confidence */}
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className={
                        'inline-flex items-center h-[18px] px-1.5 rounded-sm text-[10px] font-mono uppercase tracking-wider border ' +
                        sevBadgeClass(explainResult.severity)
                      }>
                        {explainResult.severity}
                      </span>
                      {explainResult.confidence && (
                        <span className="font-mono text-[10px] px-1.5 py-0.5 rounded-sm border border-border bg-muted text-muted-foreground">
                          ±{explainResult.confidence}
                        </span>
                      )}
                      {explainResult.risk_score != null && (
                        <span className="ml-auto text-[13px] font-bold tabular-nums"
                          style={{
                            color: explainResult.risk_score >= 8 ? 'var(--color-critical)' :
                                   explainResult.risk_score >= 6 ? '#ff8c00' :
                                   explainResult.risk_score >= 4 ? 'var(--color-warning)' : 'var(--color-success)'
                          }}>
                          {explainResult.risk_score.toFixed(1)} / 10
                        </span>
                      )}
                    </div>
                    {/* Risk bar */}
                    {explainResult.risk_score != null && (
                      <div className="h-1.5 w-full rounded-full overflow-hidden bg-muted">
                        <div className="h-full rounded-full transition-all duration-700"
                          style={{
                            width: `${Math.min(100, (explainResult.risk_score / 10) * 100)}%`,
                            background: explainResult.risk_score >= 8 ? 'var(--color-critical)' :
                                        explainResult.risk_score >= 6 ? '#ff8c00' :
                                        explainResult.risk_score >= 4 ? 'var(--color-warning)' : 'var(--color-success)',
                          }} />
                      </div>
                    )}
                    {/* MITRE */}
                    {explainResult.mitre_techniques.length > 0 && (
                      <div>
                        <div className="text-[9.5px] font-mono uppercase tracking-wider text-muted-foreground mb-1">⚔ MITRE ATT&amp;CK</div>
                        <div className="flex flex-wrap gap-1">
                          {explainResult.mitre_techniques.map((m) => (
                            <span key={m} className="font-mono text-[10px] px-1.5 py-0.5 rounded-sm border border-border bg-muted text-muted-foreground">
                              {m}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                    {/* Summary */}
                    <div className="text-[12px] leading-snug">{explainResult.summary}</div>
                    {/* Why suspicious */}
                    {explainResult.why_suspicious && (
                      <div>
                        <div className="text-[9.5px] font-mono uppercase tracking-wider text-warning mb-0.5">⚠ Warum verdächtig</div>
                        <div className="text-[11px] font-mono text-foreground leading-snug">{explainResult.why_suspicious}</div>
                      </div>
                    )}
                    {/* Against it */}
                    {explainResult.against_it && (
                      <div>
                        <div className="text-[9.5px] font-mono uppercase tracking-wider text-success mb-0.5">✓ Spricht dagegen</div>
                        <div className="text-[11px] font-mono text-foreground leading-snug">{explainResult.against_it}</div>
                      </div>
                    )}
                    {/* Suspicious fields */}
                    {explainResult.suspicious_fields.length > 0 && (
                      <div>
                        <div className="text-[9.5px] font-mono uppercase tracking-wider text-critical mb-1">⬥ Auffällige Felder</div>
                        <div className="flex flex-wrap gap-1">
                          {explainResult.suspicious_fields.map((f, i) => (
                            <span key={`${f}-${i}`} className="font-mono text-[10px] px-1.5 py-0.5 rounded-sm border border-critical/30 bg-critical/10 text-critical">
                              {f}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                    {/* Unusual behavior */}
                    {explainResult.unusual_behavior.length > 0 && (
                      <div>
                        <div className="text-[9.5px] font-mono uppercase tracking-wider text-warning mb-1">◈ Unusual Behavior</div>
                        <ul className="space-y-0.5">
                          {explainResult.unusual_behavior.map((item, i) => (
                            <li key={i} className="text-[11px] font-mono flex gap-1.5">
                              <span className="text-warning shrink-0">•</span>{item}
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                    {/* Deviations */}
                    {explainResult.deviations.length > 0 && (
                      <div>
                        <div className="text-[9.5px] font-mono uppercase tracking-wider text-muted-foreground mb-1">↗ Abweichungen</div>
                        <ul className="space-y-0.5">
                          {explainResult.deviations.map((item, i) => (
                            <li key={i} className="text-[11px] font-mono flex gap-1.5 text-muted-foreground">
                              <span className="shrink-0">↗</span>{item}
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                    {/* Remediation */}
                    {explainResult.remediation.length > 0 && (
                      <div>
                        <div className="text-[9.5px] font-mono uppercase tracking-wider text-muted-foreground mb-1">🛡 Maßnahmen</div>
                        <ol className="space-y-0.5 list-none">
                          {explainResult.remediation.map((r, i) => (
                            <li key={i} className="text-[11px] font-mono flex gap-1.5">
                              <span className="text-muted-foreground shrink-0 tabular-nums w-4">{i + 1}</span>{r}
                            </li>
                          ))}
                        </ol>
                      </div>
                    )}
                    {/* Next checks */}
                    {explainResult.next_checks.length > 0 && (
                      <div>
                        <div className="text-[9.5px] font-mono uppercase tracking-wider text-muted-foreground mb-1">🔍 Nächste Checks</div>
                        <ul className="space-y-0.5">
                          {explainResult.next_checks.map((r, i) => (
                            <li key={i} className="text-[11px] font-mono text-muted-foreground flex gap-1.5">
                              <span className="shrink-0">→</span>{r}
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}

            {/* ── Event Trail (always visible) ── */}
            {(() => {
              const sorted = [...events]
                .filter((e) => Boolean(e.smart.timestamp))
                .sort((a, b) => new Date(a.smart.timestamp!).getTime() - new Date(b.smart.timestamp!).getTime());
              const idx = sorted.findIndex((e) => e.smart.timestamp === selectedEvent.smart.timestamp);
              if (idx < 0) return null;
              const prev = sorted.slice(Math.max(0, idx - 4), idx).reverse();
              const next = sorted.slice(idx + 1, idx + 5);
              return (
                <div className="px-3 py-1.5 border-t border-border">
                  <div className="text-[9.5px] font-mono uppercase tracking-wider text-muted-foreground mb-1">Event Trail</div>
                  <div className="grid grid-cols-2 gap-3 text-[11px] font-mono">
                    <div>
                      <div className="text-[9px] uppercase tracking-wider text-muted-foreground/70 mb-0.5">Previous</div>
                      {prev.length === 0 ? <span className="text-muted-foreground text-[10px]">—</span> : prev.map((e) => (
                        <div
                          key={(e.smart.timestamp ?? '') + (e.smart.event_id ?? '')}
                          onClick={() => setSelectedEventTs(e.smart.timestamp ?? null)}
                          className="py-px cursor-pointer hover:text-foreground text-muted-foreground"
                        >
                          <span className="tabular-nums text-[10px]">{fmtTime(e.smart.timestamp)}</span>
                          <span className="ml-1 text-[10px] block truncate">{e.smart.summary ?? e.smart.rule_description ?? '—'}</span>
                        </div>
                      ))}
                    </div>
                    <div>
                      <div className="text-[9px] uppercase tracking-wider text-muted-foreground/70 mb-0.5">Next</div>
                      {next.length === 0 ? <span className="text-muted-foreground text-[10px]">—</span> : next.map((e) => (
                        <div
                          key={(e.smart.timestamp ?? '') + (e.smart.event_id ?? '')}
                          onClick={() => setSelectedEventTs(e.smart.timestamp ?? null)}
                          className="py-px cursor-pointer hover:text-foreground text-muted-foreground"
                        >
                          <span className="tabular-nums text-[10px]">{fmtTime(e.smart.timestamp)}</span>
                          <span className="ml-1 text-[10px] block truncate">{e.smart.summary ?? e.smart.rule_description ?? '—'}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              );
            })()}
          </div>
        ) : (
          <div className="flex-1 grid place-items-center text-[12px] font-mono text-muted-foreground">
            select event →
          </div>
        )}
      </aside>
    </div>
  );
}

// ── Sub-components ────────────────────────────────────────────────────────────

function FSec({ title, children, scrollable }: { title: string; children: React.ReactNode; scrollable?: boolean }) {
  return (
    <div className={`border-b border-border p-2 ${scrollable ? 'flex flex-col min-h-0 flex-1 overflow-hidden' : ''}`}>
      <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground mb-1 px-1 flex-shrink-0">
        {title}
      </div>
      <div className={`space-y-[1px] ${scrollable ? 'overflow-y-auto' : ''}`}>{children}</div>
    </div>
  );
}

