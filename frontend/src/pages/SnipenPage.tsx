/**
 * Snipen – Host-centric Threat Hunting & Event Investigation
 * 3-column layout: Host list | Event timeline | Detail panel
 */
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type {
  SnipenAIQueryResult,
  SnipenAnalysisResult,
  SnipenEvent,
  SnipenExplainResult,
  SnipenHostInfo,
} from '../types';
import {
  aiQuerySnipen,
  analyzeSnipenHost,
  explainSnipenEvent,
  getRelatedSnipenEvents,
  getSnipenHostEvents,
  getSnipenHosts,
  remediateSnipenEvent,
} from '../services/api';

// ── Types ─────────────────────────────────────────────────────────────────────

type DetailMode = 'smart' | 'raw' | 'ai';
type TimePreset = 1 | 6 | 24 | 72 | 168;
type CategoryFilter = 'all' | 'auth' | 'process' | 'service' | 'registry' | 'powershell' | 'network';
type PlatformFilter = 'all' | 'windows' | 'linux';
type SearchMode = 'keyword' | 'eventid' | 'user' | 'ip' | 'process' | 'ai';

interface SnipenPageProps {
  active: boolean;
  theme: 'light' | 'dark';
}

// ── Severity helpers ──────────────────────────────────────────────────────────

function ruleLevelToSeverity(level: number | null | undefined): string {
  if (!level) return 'info';
  if (level >= 14) return 'critical';
  if (level >= 10) return 'high';
  if (level >= 7) return 'medium';
  if (level >= 4) return 'low';
  return 'info';
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'bg-red-600 text-white',
  high: 'bg-orange-500 text-white',
  medium: 'bg-amber-500 text-black',
  low: 'bg-blue-500 text-white',
  info: 'bg-slate-400 text-white',
  unknown: 'bg-slate-300 text-slate-800',
};

function SeverityPill({ sev }: { sev: string }) {
  const cls = SEVERITY_COLORS[sev] ?? SEVERITY_COLORS.unknown;
  return (
    <span className={`rounded px-2 py-0.5 text-[0.68rem] font-bold uppercase tracking-wide ${cls}`}>
      {sev}
    </span>
  );
}

// ── Formatters ────────────────────────────────────────────────────────────────

function fmtTs(ts: string | null | undefined): string {
  if (!ts) return '—';
  try {
    return new Date(ts).toLocaleString('de-DE', {
      day: '2-digit',
      month: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });
  } catch {
    return ts;
  }
}

function normalizeProcessName(value: string | null | undefined): string {
  if (!value) return '';
  const parts = value.split(/[/\\]/).filter(Boolean);
  return (parts[parts.length - 1] ?? value).toLowerCase();
}

function normalizeFieldKey(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]/g, '');
}

function fieldIsFlagged(fields: string[], ...aliases: string[]): boolean {
  if (!fields.length) return false;
  const normalized = new Set(fields.map(normalizeFieldKey));
  return aliases.some((alias) => normalized.has(normalizeFieldKey(alias)));
}

function buildTimelineBuckets(events: SnipenEvent[], hours: number) {
  if (!events.length) return [] as Array<{ key: string; label: string; count: number; peak: boolean; anomaly: boolean }>;

  const bucketMinutes = hours <= 6 ? 15 : hours <= 24 ? 60 : hours <= 72 ? 180 : 360;
  const counts = new Map<string, number>();

  for (const event of events) {
    if (!event.smart.timestamp) continue;
    const date = new Date(event.smart.timestamp);
    if (Number.isNaN(date.getTime())) continue;
    date.setSeconds(0, 0);
    date.setMinutes(Math.floor(date.getMinutes() / bucketMinutes) * bucketMinutes);
    const key = date.toISOString();
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }

  const entries = [...counts.entries()]
    .sort((a, b) => new Date(a[0]).getTime() - new Date(b[0]).getTime())
    .map(([key, count]) => ({
      key,
      label: new Date(key).toLocaleString('de-DE', {
        day: hours > 24 ? '2-digit' : undefined,
        month: hours > 24 ? '2-digit' : undefined,
        hour: '2-digit',
        minute: '2-digit',
      }),
      count,
    }));

  if (!entries.length) return [];

  const avg = entries.reduce((sum, item) => sum + item.count, 0) / entries.length;
  const max = Math.max(...entries.map((item) => item.count));

  return entries.map((item) => ({
    ...item,
    peak: item.count === max && max > 1,
    anomaly: item.count >= Math.max(3, Math.ceil(avg * 1.8)),
  }));
}

// ── Sub-components ────────────────────────────────────────────────────────────

function SmartFieldRow({
  label,
  value,
  highlight = false,
  dark = false,
}: {
  label: string;
  value: string | null | undefined;
  highlight?: boolean;
  dark?: boolean;
}) {
  if (!value) return null;
  return (
    <div className={`flex gap-2 rounded-md px-2 py-1 text-xs ${highlight ? dark ? 'bg-red-950/30 ring-1 ring-red-500/30' : 'bg-red-50 ring-1 ring-red-200' : ''}`}>
      <span className={`w-32 flex-shrink-0 font-medium ${highlight ? dark ? 'text-red-300' : 'text-red-700' : 'text-slate-500'}`}>{label}</span>
      <span className="break-all font-mono">{value}</span>
    </div>
  );
}

function RiskBadge({ risk }: { risk: string }) {
  const map: Record<string, string> = {
    critical: 'bg-red-600 text-white',
    high: 'bg-orange-500 text-white',
    medium: 'bg-amber-400 text-black',
    low: 'bg-emerald-600 text-white',
    unknown: 'bg-slate-400 text-white',
  };
  return (
    <span className={`rounded-full px-3 py-1 text-xs font-bold uppercase ${map[risk] ?? map.unknown}`}>
      {risk}
    </span>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export function SnipenPage({ active, theme }: SnipenPageProps) {
  const dark = theme === 'dark';

  // — Host list state —
  const [hosts, setHosts] = useState<SnipenHostInfo[]>([]);
  const [hostsLoading, setHostsLoading] = useState(false);
  const [hostSearch, setHostSearch] = useState('');
  const [platformFilter, setPlatformFilter] = useState<PlatformFilter>('all');
  const [hostHoursFilter, setHostHoursFilter] = useState<TimePreset>(24);
  const [selectedHost, setSelectedHost] = useState<string | null>(null);
  const [hostsError, setHostsError] = useState<string | null>(null);

  // — Event list state —
  const [events, setEvents] = useState<SnipenEvent[]>([]);
  const [eventsLoading, setEventsLoading] = useState(false);
  const [eventsError, setEventsError] = useState<string | null>(null);
  const [timePreset, setTimePreset] = useState<TimePreset>(24);
  const [eventLimit, setEventLimit] = useState<number>(100);
  const [categoryFilter, setCategoryFilter] = useState<CategoryFilter>('all');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [eventPlatformFilter, setEventPlatformFilter] = useState<PlatformFilter>('all');
  const [selectedEvent, setSelectedEvent] = useState<SnipenEvent | null>(null);

  // — Detail panel state —
  const [detailMode, setDetailMode] = useState<DetailMode>('smart');
  const [aiResult, setAiResult] = useState<SnipenExplainResult | null>(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiAction, setAiAction] = useState<'explain' | 'remediate' | null>(null);
  const [aiError, setAiError] = useState<string | null>(null);
  const [scanResult, setScanResult] = useState<SnipenAnalysisResult | null>(null);
  const [scanLoading, setScanLoading] = useState(false);
  const [relatedEvents, setRelatedEvents] = useState<SnipenEvent[]>([]);
  const [relatedLoading, setRelatedLoading] = useState(false);
  const [showRelated, setShowRelated] = useState(false);

  // — Search bar state —
  const [searchMode, setSearchMode] = useState<SearchMode>('keyword');
  const [searchQuery, setSearchQuery] = useState('');
  const [aiQueryResult, setAiQueryResult] = useState<SnipenAIQueryResult | null>(null);
  const [aiQueryLoading, setAiQueryLoading] = useState(false);

  // — Load hosts once tab becomes active —
  const hasLoaded = useRef(false);
  const loadHosts = useCallback(async (hours: TimePreset) => {
    setHostsLoading(true);
      setHostsError(null);
    try {
      const data = await getSnipenHosts(hours);
      setHosts(data);
    } catch (e) {
      setHostsError(e instanceof Error ? e.message : 'Indexer nicht erreichbar');
    } finally {
      setHostsLoading(false);
    }
  }, []);

  useEffect(() => {
    if (active && !hasLoaded.current) {
      hasLoaded.current = true;
      void loadHosts(hostHoursFilter);
    }
  }, [active, hostHoursFilter, loadHosts]);

  // — Load events when host or filters change —
  const loadEvents = useCallback(async () => {
    if (!selectedHost) return;
    setSearchQuery('');
    setAiQueryResult(null);
    setEventsLoading(true);
    setEventsError(null);
    setSelectedEvent(null);
    setAiResult(null);
    setScanResult(null);
    setShowRelated(false);
    try {
      const data = await getSnipenHostEvents(selectedHost, {
        hours: timePreset,
        limit: eventLimit,
        platform: eventPlatformFilter === 'all' ? null : eventPlatformFilter,
        category: categoryFilter === 'all' ? null : categoryFilter,
      });
      setEvents(data);
    } catch (e) {
      setEventsError(e instanceof Error ? e.message : 'Fetch failed');
    } finally {
      setEventsLoading(false);
    }
  }, [selectedHost, timePreset, eventLimit, categoryFilter, eventPlatformFilter]);

  useEffect(() => {
    if (selectedHost) void loadEvents();
  }, [selectedHost, loadEvents]);

  // — Computed: filtered events (severity + text search + AI query results) —
  const filteredEvents = useMemo(() => {
    // If AI query returned results, show those (bypass normal filter)
    if (searchMode === 'ai' && aiQueryResult) {
      return aiQueryResult.matched_events;
    }
    let base = severityFilter === 'all'
      ? events
      : events.filter((ev) => ruleLevelToSeverity(ev.smart.rule_level) === severityFilter);
    if (searchQuery.trim() && searchMode !== 'ai') {
      const q = searchQuery.trim().toLowerCase();
      base = base.filter((ev) => {
        const s = ev.smart;
        switch (searchMode) {
          case 'eventid':  return s.event_id?.toLowerCase().includes(q) ?? false;
          case 'user':     return s.user?.toLowerCase().includes(q) ?? false;
          case 'ip':       return s.ip_address?.toLowerCase().includes(q) ?? false;
          case 'process':  return (s.process?.toLowerCase().includes(q) ?? false) || (s.command_line?.toLowerCase().includes(q) ?? false);
          default:         return (
            (s.rule_description?.toLowerCase().includes(q) ?? false) ||
            (s.user?.toLowerCase().includes(q) ?? false) ||
            (s.ip_address?.toLowerCase().includes(q) ?? false) ||
            (s.process?.toLowerCase().includes(q) ?? false) ||
            (s.event_id?.toLowerCase().includes(q) ?? false) ||
            (s.command_line?.toLowerCase().includes(q) ?? false)
          );
        }
      });
    }
    return base;
  }, [events, severityFilter, searchQuery, searchMode, aiQueryResult]);

  // — Computed: host overview stats from loaded events —
  const hostOverview = useMemo(() => {
    if (!events.length) return null;
    const highAlerts = events.filter((ev) => (ev.smart.rule_level ?? 0) >= 10).length;
    const criticalAlerts = events.filter((ev) => (ev.smart.rule_level ?? 0) >= 14).length;
    const lastActivity = events[0]?.smart.timestamp ?? null;
    const eidCount: Record<string, number> = {};
    const procCount: Record<string, number> = {};
    const userCount: Record<string, number> = {};
    for (const ev of events) {
      if (ev.smart.event_id) eidCount[ev.smart.event_id] = (eidCount[ev.smart.event_id] ?? 0) + 1;
      if (ev.smart.process) {
          const _parts = ev.smart.process.split('\\');
          const proc = _parts[_parts.length - 1] ?? ev.smart.process;
        procCount[proc] = (procCount[proc] ?? 0) + 1;
      }
      if (ev.smart.user) userCount[ev.smart.user] = (userCount[ev.smart.user] ?? 0) + 1;
    }
    const topEids = Object.entries(eidCount).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([id, cnt]) => `${id} (${cnt}×)`);
    const topProcs = Object.entries(procCount).sort((a, b) => b[1] - a[1]).slice(0, 6).map(([p, cnt]) => `${p} (${cnt}×)`);
    const topUsers = Object.entries(userCount).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([u, cnt]) => `${u} (${cnt}×)`);
    return { highAlerts, criticalAlerts, lastActivity, topEids, topProcs, topUsers };
  }, [events]);

  const timelineBuckets = useMemo(() => buildTimelineBuckets(events, timePreset), [events, timePreset]);

  const timelineSummary = useMemo(() => {
    if (!timelineBuckets.length) return { peakCount: 0, anomalyCount: 0, maxCount: 0 };
    return {
      peakCount: timelineBuckets.filter((bucket) => bucket.peak).length,
      anomalyCount: timelineBuckets.filter((bucket) => bucket.anomaly).length,
      maxCount: Math.max(...timelineBuckets.map((bucket) => bucket.count)),
    };
  }, [timelineBuckets]);

  const selectedEventTrail = useMemo(() => {
    if (!selectedEvent) {
      return {
        previous: [] as SnipenEvent[],
        next: [] as SnipenEvent[],
        processChain: [] as SnipenEvent[],
      };
    }

    const selectedKey = selectedEvent.doc_id
      ? `doc:${selectedEvent.doc_id}`
      : `ts:${selectedEvent.smart.timestamp ?? ''}|rule:${selectedEvent.smart.rule_id ?? ''}|eid:${selectedEvent.smart.event_id ?? ''}`;

    const selectedIndex = events.findIndex((event) => {
      const eventKey = event.doc_id
        ? `doc:${event.doc_id}`
        : `ts:${event.smart.timestamp ?? ''}|rule:${event.smart.rule_id ?? ''}|eid:${event.smart.event_id ?? ''}`;
      return eventKey === selectedKey;
    });

    if (selectedIndex === -1) {
      return {
        previous: [] as SnipenEvent[],
        next: [] as SnipenEvent[],
        processChain: [] as SnipenEvent[],
      };
    }

    const previous = events.slice(selectedIndex + 1, selectedIndex + 5);
    const next = events.slice(Math.max(0, selectedIndex - 4), selectedIndex).reverse();

    const processKey = normalizeProcessName(selectedEvent.smart.process || selectedEvent.smart.command_line || null);
    const selectedTs = selectedEvent.smart.timestamp ? new Date(selectedEvent.smart.timestamp).getTime() : null;
    const processChain = processKey
      ? events.filter((event) => {
          if (event === selectedEvent) return true;
          const eventProcess = normalizeProcessName(event.smart.process || event.smart.command_line || null);
          if (eventProcess !== processKey) return false;
          if (selectedTs == null || !event.smart.timestamp) return true;
          const eventTs = new Date(event.smart.timestamp).getTime();
          return Math.abs(eventTs - selectedTs) <= 1000 * 60 * 60 * 12;
        }).slice(0, 8)
      : [];

    return { previous, next, processChain };
  }, [events, selectedEvent]);

  const huntSuggestions = useMemo(
    () => [
      'zeige mir alle ungewöhnlichen Prozesse',
      'zeige mir mögliche lateral movement',
      'zeige mir suspicious logins',
    ],
    []
  );

  // — Filtered hosts by search + platform —
  const filteredHosts = hosts.filter((h) => {
    if (hostSearch && !h.host.toLowerCase().includes(hostSearch.toLowerCase())) return false;
    if (platformFilter !== 'all' && !h.platforms.includes(platformFilter)) return false;
    return true;
  });

  // — Actions —
  async function handleSelectEvent(ev: SnipenEvent) {
    setSelectedEvent(ev);
    setAiResult(null);
    setAiError(null);
    setAiAction(null);
    setShowRelated(false);
    setRelatedEvents([]);
    setDetailMode('smart');
  }

  async function handleExplain() {
    if (!selectedEvent) return;
    setAiLoading(true);
    setAiAction('explain');
    setAiError(null);
    setAiResult(null);
    setDetailMode('ai');
    try {
      const result = await explainSnipenEvent(selectedEvent.raw);
      setAiResult(result);
    } catch (e) {
      setAiError(e instanceof Error ? e.message : 'AI explain failed');
    } finally {
      setAiLoading(false);
    }
  }

  async function handleRemediate() {
    if (!selectedEvent) return;
    setAiLoading(true);
    setAiAction('remediate');
    setAiError(null);
    setAiResult(null);
    setDetailMode('ai');
    try {
      const result = await remediateSnipenEvent(selectedEvent.raw);
      setAiResult(result);
    } catch (e) {
      setAiError(e instanceof Error ? e.message : 'AI remediate failed');
    } finally {
      setAiLoading(false);
    }
  }

  async function handleAIQuery() {
    if (!selectedHost || !searchQuery.trim()) return;
    setAiQueryLoading(true);
    setAiQueryResult(null);
    try {
      const result = await aiQuerySnipen(selectedHost, searchQuery.trim(), timePreset, eventLimit);
      setAiQueryResult(result);
    } catch (e) {
      setAiQueryResult({
        query: searchQuery,
        answer: e instanceof Error ? e.message : 'AI Query fehlgeschlagen',
        matched_events: [],
        ran_ai: false,
      });
    } finally {
      setAiQueryLoading(false);
    }
  }

  async function handleRelated() {
    if (!selectedEvent) return;
    setRelatedLoading(true);
    setShowRelated(true);
    try {
      const data = await getRelatedSnipenEvents(selectedEvent.raw, 20, timePreset);
      setRelatedEvents(data);
    } catch {
      setRelatedEvents([]);
    } finally {
      setRelatedLoading(false);
    }
  }

  async function handleScanHost() {
    if (!selectedHost) return;
    setScanLoading(true);
    setScanResult(null);
    setSelectedEvent(null);
    setAiResult(null);
    setShowRelated(false);
    setDetailMode('ai');
    try {
      const result = await analyzeSnipenHost(selectedHost, {
        hours: timePreset,
        limit: 100,
        windows_only: eventPlatformFilter === 'windows',
        linux_only: eventPlatformFilter === 'linux',
        include_noise: false,
        run_ai: true,
      });
      setScanResult(result);
    } catch (e) {
      setAiError(e instanceof Error ? e.message : 'Host scan failed');
    } finally {
      setScanLoading(false);
    }
  }

  function handleHuntSuggestion(query: string) {
    setSearchMode('ai');
    setSearchQuery(query);
    setAiQueryResult(null);
    if (selectedHost) {
      void (async () => {
        setAiQueryLoading(true);
        try {
          const result = await aiQuerySnipen(selectedHost, query, timePreset, eventLimit);
          setAiQueryResult(result);
        } catch (e) {
          setAiQueryResult({
            query,
            answer: e instanceof Error ? e.message : 'AI Query fehlgeschlagen',
            matched_events: [],
            ran_ai: false,
          });
        } finally {
          setAiQueryLoading(false);
        }
      })();
    }
  }

  function handleCopyMarkdown() {
    if (!selectedEvent) return;
    const s = selectedEvent.smart;
    const md = [
      `## Event: ${s.rule_description ?? s.rule_id ?? 'Unknown'}`,
      `- **Host**: ${s.host ?? '—'}`,
      `- **Timestamp**: ${fmtTs(s.timestamp)}`,
      `- **Event ID**: ${s.event_id ?? '—'}`,
      `- **Rule ID**: ${s.rule_id ?? '—'} (Level ${s.rule_level ?? '—'})`,
      `- **User**: ${s.user ?? '—'}`,
      `- **IP**: ${s.ip_address ?? '—'}`,
      `- **Process**: ${s.process ?? '—'}`,
      s.command_line ? `- **CommandLine**: \`${s.command_line}\`` : '',
      s.mitre_id ? `- **MITRE**: ${s.mitre_id} – ${s.mitre_tactic ?? ''}` : '',
    ]
      .filter(Boolean)
      .join('\n');
    void navigator.clipboard.writeText(md);
  }

  // ── Styling helpers ─────────────────────────────────────────────────────────

  const panelCls = dark
    ? 'bg-slate-700 border-slate-600 text-white'
    : 'bg-white border-slate-200 text-slate-800';
  const inputCls = dark
    ? 'bg-slate-700 border-slate-500 text-white placeholder-slate-300'
    : 'bg-white border-slate-300 text-slate-800 placeholder-slate-400';
  const btnBase =
    'rounded-lg px-3 py-1.5 text-xs font-medium transition hover:-translate-y-0.5 disabled:opacity-50';
  const btnPrimary = `${btnBase} ${dark ? 'bg-amber-600/40 text-amber-200 hover:bg-amber-600/60' : 'bg-ember/90 text-white hover:bg-ember'}`;
  const btnSecondary = `${btnBase} ${dark ? 'bg-slate-700 text-slate-100 hover:bg-slate-600' : 'bg-slate-100 text-slate-700 hover:bg-slate-200'}`;

  if (!active) return null;

  return (
    <div className={`flex h-full overflow-hidden ${dark ? 'bg-slate-800 text-white' : 'bg-slate-50 text-slate-900'}`}>
      {/* ── Column 1: Host list ─────────────────────────────────────────────── */}
      <aside className={`flex w-60 flex-shrink-0 flex-col border-r ${dark ? 'border-slate-600 bg-slate-800' : 'border-slate-200 bg-white'}`}>
        <div className={`border-b px-3 py-3 ${dark ? 'border-slate-700' : 'border-slate-200'}`}>
          <div className="mb-2 flex items-center justify-between">
            <h2 className="text-sm font-bold">🎯 Snipen</h2>
            <button
              type="button"
              className={btnSecondary}
              onClick={() => void loadHosts(hostHoursFilter)}
              disabled={hostsLoading}
            >
              {hostsLoading ? '…' : '↻'}
            </button>
          </div>

          {/* Time range for host list */}
          <div className="mb-2 flex flex-wrap gap-1">
            {([1, 6, 24, 72, 168] as TimePreset[]).map((h) => (
              <button
                key={h}
                type="button"
                onClick={() => {
                  setHostHoursFilter(h);
                  void loadHosts(h);
                }}
                className={`rounded px-1.5 py-0.5 text-[0.6rem] font-semibold transition ${
                  hostHoursFilter === h
                    ? dark ? 'bg-amber-500 text-black' : 'bg-ember text-white'
                    : dark ? 'bg-slate-700 text-slate-100 hover:bg-slate-600' : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                }`}
              >
                {h < 24 ? `${h}h` : h === 24 ? '24h' : h === 72 ? '3d' : '7d'}
              </button>
            ))}
          </div>

          {/* Search */}
          <input
            type="text"
            value={hostSearch}
            onChange={(e) => setHostSearch(e.target.value)}
            placeholder="Host suchen…"
            className={`mb-2 w-full rounded-lg border px-2 py-1.5 text-xs outline-none focus:ring-1 focus:ring-amber-500 ${inputCls}`}
          />

          {/* Platform filter */}
          <div className="flex gap-1">
            {(['all', 'windows', 'linux'] as PlatformFilter[]).map((p) => (
              <button
                key={p}
                type="button"
                onClick={() => setPlatformFilter(p)}
                className={`flex-1 rounded px-1 py-1 text-[0.6rem] font-semibold transition ${
                  platformFilter === p
                    ? dark ? 'bg-amber-500 text-black' : 'bg-ember text-white'
                    : dark ? 'bg-slate-700 text-slate-100 hover:bg-slate-600' : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                }`}
              >
                {p === 'all' ? 'Alle' : p === 'windows' ? '🪟 Win' : '🐧 Lin'}
              </button>
            ))}
          </div>
        </div>

        {/* Host list */}
        <ul className="flex-1 overflow-y-auto">
          {hostsLoading && (
            <li className="px-3 py-4 text-center text-xs text-slate-400">Lade Hosts…</li>
          )}
          {hostsError && (
            <li className="px-3 py-3 text-xs text-red-400 break-all">{hostsError}</li>
          )}
          {!hostsLoading && !hostsError && filteredHosts.length === 0 && (
            <li className="px-3 py-4 text-center text-xs text-slate-400">
              {hosts.length === 0 ? 'Keine Hosts gefunden' : 'Kein Ergebnis'}
            </li>
          )}
          {filteredHosts.map((h) => {
            const sev = ruleLevelToSeverity(h.top_rule_level);
            const isSelected = selectedHost === h.host;
            return (
              <li key={h.host}>
                <button
                  type="button"
                  onClick={() => setSelectedHost(h.host)}
                  className={`w-full border-b px-3 py-2.5 text-left transition ${
                    isSelected
                      ? dark ? 'bg-amber-600/25 border-amber-600/30' : 'bg-ember/10 border-ember/20'
                      : dark ? 'border-slate-700 hover:bg-slate-700/70' : 'border-slate-100 hover:bg-slate-50'
                  }`}
                >
                  <div className="flex items-center justify-between gap-1">
                    <span className="truncate text-sm font-semibold">{h.host}</span>
                    <SeverityPill sev={sev} />
                  </div>
                  <div className={`mt-1 flex items-center gap-2 text-xs ${dark ? 'text-slate-300' : 'text-slate-600'}`}>
                    <span>{h.alert_count} Events</span>
                    {h.platforms.map((p) => (
                      <span key={p}>{p === 'windows' ? '🪟' : '🐧'}</span>
                    ))}
                  </div>
                  {h.last_seen && (
                    <div className={`mt-0.5 text-[0.72rem] ${dark ? 'text-slate-200' : 'text-slate-500'}`}>
                      {fmtTs(h.last_seen)}
                    </div>
                  )}
                </button>
              </li>
            );
          })}
        </ul>
      </aside>

      {/* ── Column 2: Event timeline ────────────────────────────────────────── */}
      <div className={`flex w-[26rem] flex-shrink-0 flex-col border-r ${dark ? 'border-slate-700' : 'border-slate-200'}`}>
        {!selectedHost ? (
          <div className="flex flex-1 items-center justify-center">
            <p className={`text-sm ${dark ? 'text-slate-300' : 'text-slate-400'}`}>
              ← Host auswählen
            </p>
          </div>
        ) : (
          <>
            {/* Event toolbar */}
            <div className={`flex flex-wrap items-center gap-2 border-b px-3 py-2 ${dark ? 'border-slate-600 bg-slate-800' : 'border-slate-200 bg-slate-50'}`}>
              <span className="truncate text-sm font-bold">{selectedHost}</span>

              {/* Time presets */}
              <div className="flex gap-1">
                {([1, 6, 24, 72, 168] as TimePreset[]).map((h) => (
                  <button
                    key={h}
                    type="button"
                    onClick={() => setTimePreset(h)}
                    className={`rounded px-2 py-1 text-xs font-semibold transition ${
                      timePreset === h
                        ? dark ? 'bg-amber-500 text-black' : 'bg-ember text-white'
                        : dark ? 'bg-slate-700 text-slate-100 hover:bg-slate-600' : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                    }`}
                  >
                    {h < 24 ? `${h}h` : h === 24 ? '24h' : h === 72 ? '3d' : '7d'}
                  </button>
                ))}
              </div>

              {/* Limit */}
              <select
                value={eventLimit}
                onChange={(e) => setEventLimit(Number(e.target.value))}
                className={`rounded border px-2 py-1 text-xs outline-none ${inputCls}`}
              >
                {[50, 100, 200, 500].map((n) => (
                  <option key={n} value={n}>{n} Events</option>
                ))}
              </select>

              {/* Platform filter */}
              <select
                value={eventPlatformFilter}
                onChange={(e) => setEventPlatformFilter(e.target.value as PlatformFilter)}
                className={`rounded border px-2 py-1 text-xs outline-none ${inputCls}`}
              >
                <option value="all">Alle Plattformen</option>
                <option value="windows">Windows</option>
                <option value="linux">Linux</option>
              </select>
            </div>

            {/* Second toolbar row: category + severity */}
            <div className={`flex flex-wrap items-center gap-1.5 border-b px-3 py-1.5 ${dark ? 'border-slate-700' : 'border-slate-200'}`}>
              <div className="flex flex-wrap gap-1">
                {(['all', 'auth', 'process', 'service', 'registry', 'powershell', 'network'] as CategoryFilter[]).map((c) => (
                  <button
                    key={c}
                    type="button"
                    onClick={() => setCategoryFilter(c)}
                    className={`rounded px-2 py-1 text-xs font-medium transition ${
                      categoryFilter === c
                        ? dark ? 'bg-amber-500/80 text-black' : 'bg-amber-500 text-white'
                        : dark ? 'bg-slate-700 text-slate-100 hover:bg-slate-600' : 'bg-slate-100 text-slate-500 hover:bg-slate-200'
                    }`}
                  >
                    {c === 'all' ? 'Alle' : c}
                  </button>
                ))}
              </div>

              {/* Severity filter */}
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className={`ml-auto rounded border px-2 py-1 text-xs outline-none ${inputCls}`}
              >
                <option value="all">Alle Severity</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="info">Info</option>
              </select>
            </div>

            {/* Host scan buttons */}
            <div className={`flex gap-2 border-b px-3 py-2 ${dark ? 'border-slate-700' : 'border-slate-200'}`}>
              <button
                type="button"
                className={btnPrimary}
                onClick={() => void handleScanHost()}
                disabled={scanLoading}
              >
                {scanLoading ? '⏳ Vollanalyse läuft…' : '🧠 Analysiere diesen Host vollständig'}
              </button>
              <button
                type="button"
                className={btnSecondary}
                onClick={() => void loadEvents()}
                disabled={eventsLoading}
              >
                {eventsLoading ? '…' : '↻ Laden'}
              </button>
            </div>

            {/* Search bar */}
            <div className={`flex items-center gap-1.5 border-b px-3 py-2 ${dark ? 'border-slate-700' : 'border-slate-200'}`}>
              <select
                value={searchMode}
                onChange={(e) => {
                  setSearchMode(e.target.value as SearchMode);
                  setSearchQuery('');
                  setAiQueryResult(null);
                }}
                className={`rounded border px-1.5 py-1 text-xs outline-none ${inputCls}`}
              >
                <option value="keyword">🔍 Keyword</option>
                <option value="eventid">EID</option>
                <option value="user">👤 User</option>
                <option value="ip">🌐 IP</option>
                <option value="process">⚙️ Process</option>
                <option value="ai">🤖 AI</option>
              </select>
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => {
                  setSearchQuery(e.target.value);
                  if (searchMode !== 'ai') setAiQueryResult(null);
                }}
                onKeyDown={(e) => { if (e.key === 'Enter' && searchMode === 'ai') void handleAIQuery(); }}
                placeholder={
                  searchMode === 'ai' ? '"Verdächtige Prozesse"…' :
                  searchMode === 'eventid' ? 'Event ID…' :
                  searchMode === 'user' ? 'Username…' :
                  searchMode === 'ip' ? 'IP-Adresse…' :
                  searchMode === 'process' ? 'Prozessname…' : 'Suche…'
                }
                className={`flex-1 min-w-0 rounded border px-2 py-1 text-xs outline-none focus:ring-1 focus:ring-amber-500 ${inputCls}`}
              />
              {searchMode === 'ai' ? (
                <button
                  type="button"
                  onClick={() => void handleAIQuery()}
                  disabled={!searchQuery.trim() || aiQueryLoading}
                  className={btnPrimary}
                >
                  {aiQueryLoading ? '⏳' : '→'}
                </button>
              ) : searchQuery ? (
                <button
                  type="button"
                  onClick={() => { setSearchQuery(''); setAiQueryResult(null); }}
                  className={`text-xs px-1 ${dark ? 'text-slate-200 hover:text-white' : 'text-slate-400 hover:text-slate-700'}`}
                >
                  ✕
                </button>
              ) : null}
            </div>

            {selectedHost && (
              <div className={`border-b px-3 py-2 ${dark ? 'border-slate-700 bg-slate-900' : 'border-slate-200 bg-white'}`}>
                <div className="mb-1.5 flex items-center justify-between">
                  <span className={`text-[0.68rem] font-bold uppercase tracking-[0.18em] ${dark ? 'text-amber-300' : 'text-amber-700'}`}>
                    Hunting Mode
                  </span>
                  <span className={`text-[0.68rem] ${dark ? 'text-slate-300' : 'text-slate-400'}`}>
                    Natural Language Hunts
                  </span>
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {huntSuggestions.map((query) => (
                    <button
                      key={query}
                      type="button"
                      onClick={() => handleHuntSuggestion(query)}
                      className={`rounded-full px-2.5 py-1 text-[0.68rem] transition ${dark ? 'bg-slate-700 text-slate-100 hover:bg-amber-600/25 hover:text-amber-200' : 'bg-amber-50 text-amber-700 hover:bg-amber-100'}`}
                    >
                      {query}
                    </button>
                  ))}
                </div>
              </div>
            )}

            {/* AI query answer banner */}
            {aiQueryResult && (
              <div className={`border-b px-3 py-2 ${dark ? 'border-slate-700 bg-amber-950/20' : 'border-amber-200 bg-amber-50'}`}>
                <p className={`text-xs font-semibold mb-1 ${dark ? 'text-amber-300' : 'text-amber-700'}`}>
                  🤖 AI: „{aiQueryResult.query}"
                </p>
                <p className={`text-xs leading-relaxed ${dark ? 'text-slate-300' : 'text-slate-700'}`}>{aiQueryResult.answer}</p>
                {aiQueryResult.matched_events.length > 0 && (
                  <p className={`mt-1 text-[0.7rem] ${dark ? 'text-slate-300' : 'text-slate-400'}`}>
                    {aiQueryResult.matched_events.length} relevante Events ↓
                  </p>
                )}
              </div>
            )}

            {/* Event list */}
            <ul className="flex-1 overflow-y-auto">
              {eventsLoading && (
                <li className="px-3 py-4 text-center text-xs text-slate-400">Lade Events…</li>
              )}
              {eventsError && (
                <li className="px-3 py-3 text-xs text-red-400">{eventsError}</li>
              )}
              {!eventsLoading && filteredEvents.length === 0 && !eventsError && (
                <li className="px-3 py-4 text-center text-xs text-slate-400">Keine Events gefunden</li>
              )}
              {filteredEvents.map((ev, idx) => {
                const s = ev.smart;
                const sev = ruleLevelToSeverity(s.rule_level);
                const isSelected = selectedEvent === ev;
                return (
                  <li key={`${idx}-${s.timestamp ?? ''}`}>
                    <button
                      type="button"
                      onClick={() => void handleSelectEvent(ev)}
                      className={`w-full border-b border-l-[3px] px-3 py-2.5 text-left transition ${
                        isSelected
                          ? dark ? 'bg-amber-600/20 border-b-amber-600/30 border-l-amber-400' : 'bg-ember/10 border-b-ember/20 border-l-ember'
                          : sev === 'critical'
                            ? dark ? 'border-b-slate-700 border-l-red-500 hover:bg-red-950/20' : 'border-b-slate-100 border-l-red-500 hover:bg-red-50'
                          : sev === 'high'
                            ? dark ? 'border-b-slate-700 border-l-orange-400 hover:bg-orange-950/20' : 'border-b-slate-100 border-l-orange-400 hover:bg-orange-50'
                            : dark ? 'border-b-slate-700 border-l-transparent hover:bg-slate-700/70' : 'border-b-slate-100 border-l-transparent hover:bg-slate-50'
                      }`}
                    >
                      <div className="flex items-center justify-between gap-1">
                        <span className={`truncate text-sm font-semibold ${dark ? 'text-slate-100' : 'text-slate-900'}`}>
                          {s.rule_description ?? `Rule ${s.rule_id ?? '?'}`}
                        </span>
                        <SeverityPill sev={sev} />
                      </div>
                      <div className={`mt-1 flex flex-wrap gap-x-2 text-xs ${dark ? 'text-slate-300' : 'text-slate-600'}`}>
                        <span>{fmtTs(s.timestamp)}</span>
                        {s.event_id && <span>EID {s.event_id}</span>}
                        {s.user && <span>👤 {s.user}</span>}
                        {s.ip_address && s.ip_address !== '-' && <span>🌐 {s.ip_address}</span>}
                      </div>
                    </button>
                  </li>
                );
              })}
            </ul>

            {/* Summary bar */}
            <div className={`border-t px-3 py-2 text-xs ${dark ? 'border-slate-700 text-slate-400' : 'border-slate-200 text-slate-600'}`}>
              {filteredEvents.length} Events
              {filteredEvents.length !== events.length && ` (von ${events.length})`}
              {selectedHost && ` · ${selectedHost}`}
            </div>
          </>
        )}
      </div>

      {/* ── Column 3: Detail panel ──────────────────────────────────────────── */}
      <div className="flex flex-1 flex-col overflow-hidden">
        {!selectedHost ? (
          <div className="flex flex-1 items-center justify-center">
            <div className="text-center">
              <div className="mb-4 text-5xl">🎯</div>
              <h3 className={`text-lg font-bold ${dark ? 'text-slate-300' : 'text-slate-600'}`}>Snipen</h3>
              <p className={`mt-2 text-sm ${dark ? 'text-slate-300' : 'text-slate-400'}`}>
                Host-centric Threat Hunting & Event Investigation.<br />
                Wähle links einen Host aus, um zu starten.
              </p>
            </div>
          </div>
        ) : (
          <>
            {/* Detail toolbar */}
            <div className={`flex items-center gap-2 border-b px-4 py-2 ${dark ? 'border-slate-700 bg-slate-850' : 'border-slate-200 bg-slate-50'}`}>
              {selectedEvent && (
                <div className="flex rounded-lg border overflow-hidden text-xs">
                  {(['smart', 'raw', 'ai'] as DetailMode[]).map((m) => (
                    <button
                      key={m}
                      type="button"
                      onClick={() => setDetailMode(m)}
                      className={`px-3 py-1 font-medium transition ${
                        detailMode === m
                          ? dark ? 'bg-amber-600/50 text-amber-100' : 'bg-ember text-white'
                          : dark ? 'bg-slate-800 text-slate-400 hover:bg-slate-700' : 'bg-white text-slate-600 hover:bg-slate-100'
                      }`}
                    >
                      {m === 'smart' ? '📋 Smart' : m === 'raw' ? '{}  Raw' : '🤖 AI'}
                    </button>
                  ))}
                </div>
              )}

              <div className="ml-auto flex gap-2">
                {selectedEvent && (
                  <>
                    <button type="button" className={btnPrimary} onClick={() => void handleExplain()} disabled={aiLoading}>
                      {aiLoading && aiAction === 'explain' ? '⏳ Erklären…' : '🤖 Erklären'}
                    </button>
                    <button type="button" className={btnSecondary} onClick={() => void handleRemediate()} disabled={aiLoading}>
                      {aiLoading && aiAction === 'remediate' ? '⏳ Remediation…' : '🛡️ Remediation'}
                    </button>
                    <button type="button" className={btnSecondary} onClick={() => void handleRelated()}>
                      🔗 Related
                    </button>
                    <button type="button" className={btnSecondary} onClick={handleCopyMarkdown}>
                      📋 Copy
                    </button>
                  </>
                )}
              </div>
            </div>

            <div className="flex-1 overflow-y-auto p-4 space-y-4">
              {/* ── Scan loading ── */}
              {scanLoading && (
                <div className={`rounded-xl border p-4 ${panelCls}`}>
                  <p className="text-sm text-slate-400">⏳ KI-Scan läuft… bitte warten.</p>
                </div>
              )}

              {/* ── Scan result ── */}
              {scanResult && !selectedEvent && (
                <div className={`rounded-xl border p-4 space-y-3 ${panelCls}`}>
                  <div className="flex items-center gap-3">
                    <h3 className="text-sm font-bold">Host Scan: {scanResult.host}</h3>
                    <RiskBadge risk={scanResult.host_risk} />
                    <span className={`ml-auto text-xs ${dark ? 'text-slate-200' : 'text-slate-500'}`}>
                      {scanResult.total_events} Events · {scanResult.hours}h · Full Investigation
                    </span>
                  </div>

                  <div className={`rounded-lg px-3 py-2 text-xs ${dark ? 'bg-amber-950/20 text-amber-200' : 'bg-amber-50 text-amber-800'}`}>
                    Analysiert wurden die letzten <strong>100 Events</strong> des Hosts, inklusive Muster, Risiko und Empfehlungen.
                  </div>

                  {scanResult.ai_summary && (
                    <div className={`rounded-lg p-3 text-sm leading-relaxed ${dark ? 'bg-slate-800/60' : 'bg-slate-50'}`}>
                      {scanResult.ai_summary}
                    </div>
                  )}

                  {scanResult.suspicious_patterns.length > 0 && (
                    <div>
                      <h4 className="mb-1 text-xs font-bold text-red-400">⚠️ Verdächtige Muster</h4>
                      <ul className="space-y-1">
                        {scanResult.suspicious_patterns.map((p, i) => (
                          <li key={i} className="text-xs flex gap-2">
                            <span className="text-red-400 flex-shrink-0">•</span>
                            <span>{p}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {scanResult.likely_benign.length > 0 && (
                    <div>
                      <h4 className="mb-1 text-xs font-bold text-emerald-400">✅ Wahrscheinlich harmlos</h4>
                      <ul className="space-y-1">
                        {scanResult.likely_benign.map((p, i) => (
                          <li key={i} className="text-xs flex gap-2">
                            <span className="text-emerald-400 flex-shrink-0">•</span>
                            <span>{p}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {scanResult.recommended_checks.length > 0 && (
                    <div>
                      <h4 className="mb-1 text-xs font-bold text-blue-400">🔍 Empfohlene Checks</h4>
                      <ul className="space-y-1">
                        {scanResult.recommended_checks.map((c, i) => (
                          <li key={i} className="text-xs flex gap-2">
                            <span className="text-blue-400 flex-shrink-0">→</span>
                            <span>{c}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              )}

              {/* ── Host Overview ── */}
              {!selectedEvent && !scanResult && !scanLoading && selectedHost && (
                <div className={`rounded-xl border p-4 space-y-4 ${panelCls}`}>
                  <div className="flex items-center justify-between">
                    <h3 className="text-sm font-bold">📊 Host Overview</h3>
                    <span className={`text-xs ${dark ? 'text-slate-200' : 'text-slate-500'}`}>{selectedHost}</span>
                  </div>

                  {/* Stat cards */}
                  <div className="grid grid-cols-3 gap-3">
                    <div className={`rounded-lg p-3 text-center ${dark ? 'bg-slate-800' : 'bg-slate-50 border border-slate-200'}`}>
                      <div className={`text-2xl font-bold ${dark ? 'text-amber-300' : 'text-amber-600'}`}>{events.length}</div>
                      <div className={`mt-0.5 text-[0.65rem] ${dark ? 'text-slate-200' : 'text-slate-500'}`}>Gesamt Events</div>
                    </div>
                    <div className={`rounded-lg p-3 text-center ${dark ? 'bg-slate-800' : 'bg-slate-50 border border-slate-200'}`}>
                      <div className={`text-2xl font-bold ${hostOverview?.highAlerts ? 'text-orange-400' : dark ? 'text-slate-300' : 'text-slate-400'}`}>
                        {hostOverview?.highAlerts ?? 0}
                      </div>
                      <div className={`mt-0.5 text-[0.65rem] ${dark ? 'text-slate-200' : 'text-slate-500'}`}>High Alerts</div>
                    </div>
                    <div className={`rounded-lg p-3 text-center ${dark ? 'bg-slate-800' : 'bg-slate-50 border border-slate-200'}`}>
                      <div className={`text-2xl font-bold ${hostOverview?.criticalAlerts ? 'text-red-400' : dark ? 'text-slate-300' : 'text-slate-400'}`}>
                        {hostOverview?.criticalAlerts ?? 0}
                      </div>
                      <div className={`mt-0.5 text-[0.65rem] ${dark ? 'text-slate-200' : 'text-slate-500'}`}>Critical</div>
                    </div>
                  </div>

                  {hostOverview?.lastActivity && (
                    <div className="flex items-center gap-2">
                      <span className={`text-xs ${dark ? 'text-slate-200' : 'text-slate-500'}`}>🕐 Letzte Aktivität:</span>
                      <span className="text-xs font-medium">{fmtTs(hostOverview.lastActivity)}</span>
                    </div>
                  )}

                  {hostOverview?.topEids && hostOverview.topEids.length > 0 && (
                    <div>
                      <h4 className={`mb-2 text-xs font-bold ${dark ? 'text-slate-200' : 'text-slate-500'}`}>Top Event IDs</h4>
                      <div className="flex flex-wrap gap-1.5">
                        {hostOverview.topEids.map((e, i) => (
                          <span
                            key={i}
                            className={`rounded px-2 py-0.5 text-xs font-mono cursor-pointer hover:opacity-80 ${dark ? 'bg-slate-800 text-amber-300 border border-slate-700' : 'bg-amber-50 text-amber-700 border border-amber-200'}`}
                            onClick={() => { setSearchMode('eventid'); setSearchQuery(e.split(' ')[0]); setAiQueryResult(null); }}
                          >
                            {e}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {hostOverview?.topProcs && hostOverview.topProcs.length > 0 && (
                    <div>
                      <h4 className={`mb-2 text-xs font-bold ${dark ? 'text-slate-200' : 'text-slate-500'}`}>Top Prozesse</h4>
                      <ul className="space-y-1">
                        {hostOverview.topProcs.map((p, i) => (
                          <li key={i} className="flex items-center gap-2">
                            <span className="text-slate-400">⚙️</span>
                            <span
                              className={`text-xs font-mono cursor-pointer hover:underline ${dark ? 'text-slate-300' : 'text-slate-700'}`}
                              onClick={() => { setSearchMode('process'); setSearchQuery(p.split(' ')[0]); setAiQueryResult(null); }}
                            >
                              {p}
                            </span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {hostOverview?.topUsers && hostOverview.topUsers.length > 0 && (
                    <div>
                      <h4 className={`mb-2 text-xs font-bold ${dark ? 'text-slate-200' : 'text-slate-500'}`}>Top User</h4>
                      <div className="flex flex-wrap gap-1.5">
                        {hostOverview.topUsers.map((u, i) => (
                          <span
                            key={i}
                            className={`rounded px-2 py-0.5 text-xs cursor-pointer hover:opacity-80 ${dark ? 'bg-slate-800 text-blue-300 border border-slate-700' : 'bg-blue-50 text-blue-700 border border-blue-200'}`}
                            onClick={() => { setSearchMode('user'); setSearchQuery(u.split(' ')[0]); setAiQueryResult(null); }}
                          >
                            👤 {u}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  <p className={`text-xs ${dark ? 'text-slate-300' : 'text-slate-400'}`}>
                    ← Event auswählen oder <strong>Scan</strong> ausführen
                  </p>
                </div>
              )}

              {!selectedEvent && selectedHost && timelineBuckets.length > 0 && (
                <div className={`rounded-xl border p-4 space-y-3 ${panelCls}`}>
                  <div className="flex items-center justify-between">
                    <div>
                      <h3 className="text-sm font-bold">📈 Timeline Mode</h3>
                      <p className={`mt-0.5 text-xs ${dark ? 'text-slate-200' : 'text-slate-500'}`}>
                        Verlauf, Peaks und Anomalien für {selectedHost}
                      </p>
                    </div>
                    <div className="flex gap-2 text-[0.68rem]">
                      <span className={`rounded-full px-2 py-0.5 ${dark ? 'bg-slate-800 text-slate-300' : 'bg-slate-100 text-slate-700'}`}>
                        Peak {timelineSummary.peakCount}
                      </span>
                      <span className={`rounded-full px-2 py-0.5 ${timelineSummary.anomalyCount ? dark ? 'bg-red-950/30 text-red-300' : 'bg-red-50 text-red-700' : dark ? 'bg-slate-800 text-slate-500' : 'bg-slate-100 text-slate-500'}`}>
                        Anomalien {timelineSummary.anomalyCount}
                      </span>
                    </div>
                  </div>

                  <div className="flex h-36 items-end gap-1 overflow-hidden rounded-lg border px-2 py-3">
                    {timelineBuckets.map((bucket) => {
                      const height = timelineSummary.maxCount > 0 ? Math.max(8, (bucket.count / timelineSummary.maxCount) * 100) : 8;
                      return (
                        <div key={bucket.key} className="flex min-w-0 flex-1 flex-col items-center justify-end gap-1">
                          <div className={`text-[0.62rem] ${bucket.anomaly ? 'font-bold text-red-400' : dark ? 'text-slate-300' : 'text-slate-400'}`}>
                            {bucket.count}
                          </div>
                          <div
                            className={`w-full rounded-t-sm transition-all ${bucket.peak ? 'bg-red-500' : bucket.anomaly ? 'bg-orange-400' : dark ? 'bg-amber-500/70' : 'bg-amber-400'}`}
                            style={{ height: `${height}%` }}
                            title={`${bucket.label}: ${bucket.count} Events`}
                          />
                          <div className={`w-full truncate text-center text-[0.55rem] ${dark ? 'text-slate-300' : 'text-slate-400'}`}>
                            {bucket.label}
                          </div>
                        </div>
                      );
                    })}
                  </div>

                  <div className="flex flex-wrap gap-1.5">
                    {timelineBuckets.filter((bucket) => bucket.anomaly).slice(0, 5).map((bucket) => (
                      <span key={bucket.key} className={`rounded-full px-2 py-0.5 text-[0.68rem] ${dark ? 'bg-red-950/30 text-red-300' : 'bg-red-50 text-red-700'}`}>
                        {bucket.label} · {bucket.count} Events
                      </span>
                    ))}
                    {!timelineBuckets.some((bucket) => bucket.anomaly) && (
                      <span className={`text-xs ${dark ? 'text-slate-300' : 'text-slate-400'}`}>
                        Keine auffälligen Peaks im aktuellen Fenster erkannt.
                      </span>
                    )}
                  </div>
                </div>
              )}

              {/* ── Event detail ── */}
              {selectedEvent && (
                <>
                  {aiResult && (
                    <div className={`rounded-xl border p-4 space-y-3 ${panelCls}`}>
                      <div className="flex items-center justify-between gap-3">
                        <div>
                          <h3 className="text-sm font-bold">🎯 Warum genau dieser Event wichtig ist</h3>
                          <p className={`mt-0.5 text-xs ${dark ? 'text-slate-200' : 'text-slate-500'}`}>
                            KI markiert relevante Felder, Auffälligkeiten und Abweichungen.
                          </p>
                        </div>
                        <SeverityPill sev={aiResult.severity} />
                      </div>

                      {aiResult.suspicious_fields.length > 0 && (
                        <div>
                          <h4 className="mb-1 text-xs font-bold text-red-400">Marked Suspicious Fields</h4>
                          <div className="flex flex-wrap gap-1.5">
                            {aiResult.suspicious_fields.map((field, index) => (
                              <span key={`${field}-${index}`} className={`rounded-full px-2 py-0.5 text-[0.68rem] ${dark ? 'bg-red-950/30 text-red-300 border border-red-500/20' : 'bg-red-50 text-red-700 border border-red-200'}`}>
                                {field}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}

                      {aiResult.unusual_behavior.length > 0 && (
                        <div>
                          <h4 className="mb-1 text-xs font-bold text-orange-400">Unusual Behavior</h4>
                          <ul className="space-y-1">
                            {aiResult.unusual_behavior.map((item, index) => (
                              <li key={`${item}-${index}`} className="flex gap-2 text-xs">
                                <span className="text-orange-400">•</span>
                                <span>{item}</span>
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}

                      {aiResult.deviations.length > 0 && (
                        <div>
                          <h4 className="mb-1 text-xs font-bold text-amber-400">Deviations</h4>
                          <ul className="space-y-1">
                            {aiResult.deviations.map((item, index) => (
                              <li key={`${item}-${index}`} className="flex gap-2 text-xs">
                                <span className="text-amber-400">↗</span>
                                <span>{item}</span>
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </div>
                  )}

                  {/* Smart view */}
                  {detailMode === 'smart' && (
                    <div className={`rounded-xl border p-4 ${panelCls}`}>
                      <div className="mb-3 flex items-center gap-2">
                        <h3 className="text-sm font-bold">
                          {selectedEvent.smart.rule_description ?? `Rule ${selectedEvent.smart.rule_id ?? '?'}`}
                        </h3>
                        <SeverityPill sev={ruleLevelToSeverity(selectedEvent.smart.rule_level)} />
                      </div>
                      <div className="divide-y divide-dashed divide-slate-200/20 space-y-0.5">
                        <SmartFieldRow label="Timestamp" value={fmtTs(selectedEvent.smart.timestamp)} highlight={fieldIsFlagged(aiResult?.suspicious_fields ?? [], 'timestamp', '@timestamp', 'time')} dark={dark} />
                        <SmartFieldRow label="Host" value={selectedEvent.smart.host} highlight={fieldIsFlagged(aiResult?.suspicious_fields ?? [], 'host', 'agent.name')} dark={dark} />
                        <SmartFieldRow label="Platform" value={selectedEvent.smart.platform} highlight={fieldIsFlagged(aiResult?.suspicious_fields ?? [], 'platform')} dark={dark} />
                        <SmartFieldRow label="Event ID" value={selectedEvent.smart.event_id} highlight={fieldIsFlagged(aiResult?.suspicious_fields ?? [], 'event id', 'event_id', 'eventid')} dark={dark} />
                        <SmartFieldRow label="Event Meaning" value={selectedEvent.smart.event_explanation} highlight={fieldIsFlagged(aiResult?.suspicious_fields ?? [], 'event meaning', 'event explanation', 'event_explanation')} dark={dark} />
                        <SmartFieldRow label="Rule ID" value={selectedEvent.smart.rule_id} highlight={fieldIsFlagged(aiResult?.suspicious_fields ?? [], 'rule id', 'rule_id')} dark={dark} />
                        <SmartFieldRow label="Rule Level" value={selectedEvent.smart.rule_level?.toString()} highlight={fieldIsFlagged(aiResult?.suspicious_fields ?? [], 'rule level', 'rule_level', 'severity')} dark={dark} />
                        <SmartFieldRow label="User" value={selectedEvent.smart.user} highlight={fieldIsFlagged(aiResult?.suspicious_fields ?? [], 'user', 'username', 'subjectuser', 'targetuser')} dark={dark} />
                        <SmartFieldRow label="Logon Type" value={selectedEvent.smart.logon_type} highlight={fieldIsFlagged(aiResult?.suspicious_fields ?? [], 'logon type', 'logon_type')} dark={dark} />
                        <SmartFieldRow label="IP Address" value={selectedEvent.smart.ip_address} highlight={fieldIsFlagged(aiResult?.suspicious_fields ?? [], 'ip', 'ip address', 'ip_address', 'source ip')} dark={dark} />
                        <SmartFieldRow label="Process" value={selectedEvent.smart.process} highlight={fieldIsFlagged(aiResult?.suspicious_fields ?? [], 'process', 'process name', 'image')} dark={dark} />
                        <SmartFieldRow label="CommandLine" value={selectedEvent.smart.command_line} highlight={fieldIsFlagged(aiResult?.suspicious_fields ?? [], 'commandline', 'command line', 'cmdline')} dark={dark} />
                        <SmartFieldRow label="ServiceName" value={selectedEvent.smart.service_name} highlight={fieldIsFlagged(aiResult?.suspicious_fields ?? [], 'service', 'servicename', 'service_name')} dark={dark} />
                        <SmartFieldRow label="RegistryKey" value={selectedEvent.smart.registry_key} highlight={fieldIsFlagged(aiResult?.suspicious_fields ?? [], 'registry', 'registrykey', 'registry_key')} dark={dark} />
                        <SmartFieldRow label="Status" value={selectedEvent.smart.status} highlight={fieldIsFlagged(aiResult?.suspicious_fields ?? [], 'status', 'result')} dark={dark} />
                        <SmartFieldRow label="MITRE ID" value={selectedEvent.smart.mitre_id} highlight={fieldIsFlagged(aiResult?.suspicious_fields ?? [], 'mitre', 'mitre id', 'mitre_id')} dark={dark} />
                        <SmartFieldRow label="MITRE Tactic" value={selectedEvent.smart.mitre_tactic} highlight={fieldIsFlagged(aiResult?.suspicious_fields ?? [], 'mitre tactic', 'mitre_tactic')} dark={dark} />
                        <SmartFieldRow label="Decoder" value={selectedEvent.smart.decoder} highlight={fieldIsFlagged(aiResult?.suspicious_fields ?? [], 'decoder')} dark={dark} />
                        <SmartFieldRow label="Location" value={selectedEvent.smart.location} highlight={fieldIsFlagged(aiResult?.suspicious_fields ?? [], 'location', 'log source')} dark={dark} />
                        {selectedEvent.smart.groups.length > 0 && (
                          <SmartFieldRow label="Groups" value={selectedEvent.smart.groups.join(', ')} highlight={fieldIsFlagged(aiResult?.suspicious_fields ?? [], 'groups', 'rule groups')} dark={dark} />
                        )}
                      </div>
                    </div>
                  )}

                  {/* Raw view */}
                  {detailMode === 'raw' && (
                    <div className={`rounded-xl border ${panelCls}`}>
                      <div className="border-b px-4 py-2 text-xs font-bold text-slate-400">
                        Raw JSON
                      </div>
                      <pre className={`overflow-auto p-4 text-[0.65rem] leading-relaxed ${dark ? 'text-slate-300' : 'text-slate-700'}`}>
                        {JSON.stringify(selectedEvent.raw, null, 2)}
                      </pre>
                    </div>
                  )}

                  {/* AI view */}
                  {detailMode === 'ai' && (
                    <div className={`rounded-xl border p-4 space-y-3 ${panelCls}`}>
                      {aiLoading && (
                        <p className="text-sm text-slate-400">⏳ KI analysiert…</p>
                      )}
                      {aiError && (
                        <p className="text-sm text-red-400">{aiError}</p>
                      )}
                      {!aiLoading && !aiResult && !aiError && (
                        <p className={`text-sm ${dark ? 'text-slate-200' : 'text-slate-500'}`}>
                          Klicke <strong>Erklären</strong> oder <strong>Remediation</strong> um die KI zu befragen.
                        </p>
                      )}
                      {aiResult && (
                        <>
                          {/* Header row */}
                          <div className="flex flex-wrap items-center gap-2">
                            <h3 className="text-sm font-bold">
                              {aiAction === 'remediate' ? '🛡️ Remediation' : '🤖 KI-Erklärung'}
                            </h3>
                            <SeverityPill sev={aiResult.severity} />
                            {aiResult.confidence && (
                              <span className={`rounded px-2 py-0.5 text-xs font-semibold ${
                                aiResult.confidence === 'very_high' ? 'bg-emerald-600/30 text-emerald-300' :
                                aiResult.confidence === 'high' ? 'bg-green-600/30 text-green-300' :
                                aiResult.confidence === 'medium' ? 'bg-amber-600/30 text-amber-300' :
                                dark ? 'bg-slate-700 text-slate-400' : 'bg-slate-100 text-slate-500'
                              }`}>
                                ±{aiResult.confidence.replace('_', ' ')}
                              </span>
                            )}
                          </div>

                          {/* Risk Score bar */}
                          {aiResult.risk_score != null && (
                            <div>
                              <div className="mb-1.5 flex items-center justify-between">
                                <span className={`text-xs font-bold ${dark ? 'text-slate-200' : 'text-slate-500'}`}>🎯 Risk Score</span>
                                <span className={`text-sm font-bold tabular-nums ${
                                  aiResult.risk_score >= 8 ? 'text-red-400' :
                                  aiResult.risk_score >= 6 ? 'text-orange-400' :
                                  aiResult.risk_score >= 4 ? 'text-amber-400' : 'text-emerald-400'
                                }`}>{aiResult.risk_score.toFixed(1)} / 10</span>
                              </div>
                              <div className={`h-2 rounded-full overflow-hidden ${dark ? 'bg-slate-700' : 'bg-slate-200'}`}>
                                <div
                                  className={`h-full rounded-full transition-all duration-700 ${
                                    aiResult.risk_score >= 8 ? 'bg-red-500' :
                                    aiResult.risk_score >= 6 ? 'bg-orange-500' :
                                    aiResult.risk_score >= 4 ? 'bg-amber-400' : 'bg-emerald-500'
                                  }`}
                                  style={{ width: `${Math.min(100, (aiResult.risk_score / 10) * 100)}%` }}
                                />
                              </div>
                            </div>
                          )}

                          {/* MITRE techniques */}
                          {aiResult.mitre_techniques.length > 0 && (
                            <div>
                              <h4 className="mb-1.5 text-xs font-bold text-purple-400">🗡️ MITRE ATT&CK</h4>
                              <div className="flex flex-wrap gap-1.5">
                                {aiResult.mitre_techniques.map((t, i) => (
                                  <span key={i} className={`rounded px-2 py-0.5 text-xs font-mono ${
                                    dark ? 'bg-purple-900/40 text-purple-300 border border-purple-700/50' : 'bg-purple-50 text-purple-700 border border-purple-200'
                                  }`}>{t}</span>
                                ))}
                              </div>
                            </div>
                          )}

                          {/* Summary */}
                          <div className={`rounded-lg p-3 text-sm leading-relaxed ${dark ? 'bg-slate-800/60' : 'bg-slate-50'}`}>
                            {aiResult.summary}
                          </div>

                          {aiResult.why_suspicious && (
                            <div>
                              <h4 className="mb-1 text-xs font-bold text-orange-400">⚠️ Warum verdächtig</h4>
                              <p className="text-xs leading-relaxed">{aiResult.why_suspicious}</p>
                            </div>
                          )}
                          {aiResult.against_it && (
                            <div>
                              <h4 className="mb-1 text-xs font-bold text-emerald-400">✅ Spricht dagegen</h4>
                              <p className="text-xs leading-relaxed">{aiResult.against_it}</p>
                            </div>
                          )}
                          {aiResult.remediation.length > 0 && (
                            <div>
                              <h4 className="mb-1 text-xs font-bold text-amber-400">🛡️ Maßnahmen</h4>
                              <ol className="space-y-1.5">
                                {aiResult.remediation.map((r, i) => (
                                  <li key={i} className="text-xs flex gap-2">
                                    <span className={`flex-shrink-0 rounded-full w-4 h-4 flex items-center justify-center text-[0.6rem] font-bold ${dark ? 'bg-amber-600/40 text-amber-200' : 'bg-amber-100 text-amber-700'}`}>{i + 1}</span>
                                    <span className="leading-relaxed">{r}</span>
                                  </li>
                                ))}
                              </ol>
                            </div>
                          )}
                          {aiResult.next_checks.length > 0 && (
                            <div>
                              <h4 className="mb-1 text-xs font-bold text-blue-400">🔍 Nächste Checks</h4>
                              <ul className="space-y-1">
                                {aiResult.next_checks.map((c, i) => (
                                  <li key={i} className="text-xs flex gap-2">
                                    <span className="text-blue-400 flex-shrink-0">→</span>
                                    <span className="leading-relaxed">{c}</span>
                                  </li>
                                ))}
                              </ul>
                            </div>
                          )}
                        </>
                      )}
                    </div>
                  )}

                  {/* Related events panel */}
                  {showRelated && (
                    <div className={`rounded-xl border ${panelCls}`}>
                      <div className="border-b px-4 py-2 flex items-center justify-between">
                        <span className="text-xs font-bold">🔗 Related Events</span>
                        <button
                          type="button"
                          className={`text-xs ${dark ? 'text-slate-400 hover:text-slate-200' : 'text-slate-400 hover:text-slate-700'}`}
                          onClick={() => setShowRelated(false)}
                        >
                          ✕
                        </button>
                      </div>
                      {relatedLoading && (
                        <p className="px-4 py-3 text-xs text-slate-400">Lade related events…</p>
                      )}
                      {!relatedLoading && relatedEvents.length === 0 && (
                        <p className="px-4 py-3 text-xs text-slate-400">Keine ähnlichen Events gefunden.</p>
                      )}
                      {!relatedLoading && relatedEvents.map((ev, i) => {
                        const sev = ruleLevelToSeverity(ev.smart.rule_level);
                        return (
                          <button
                            key={i}
                            type="button"
                            onClick={() => void handleSelectEvent(ev)}
                            className={`w-full border-b px-4 py-2 text-left transition ${dark ? 'border-white/5 hover:bg-white/5' : 'border-slate-100 hover:bg-slate-50'}`}
                          >
                            <div className="flex items-center justify-between">
                              <span className="text-xs font-medium truncate">
                                {ev.smart.rule_description ?? `Rule ${ev.smart.rule_id}`}
                              </span>
                              <SeverityPill sev={sev} />
                            </div>
                            <div className={`text-[0.7rem] mt-0.5 ${dark ? 'text-slate-200' : 'text-slate-500'}`}>
                              {fmtTs(ev.smart.timestamp)}
                              {ev.smart.user && ` · 👤 ${ev.smart.user}`}
                            </div>
                          </button>
                        );
                      })}
                    </div>
                  )}

                  <div className={`rounded-xl border p-4 space-y-3 ${panelCls}`}>
                    <div className="flex items-center justify-between">
                      <div>
                        <h3 className="text-sm font-bold">🧭 Follow the Trail</h3>
                        <p className={`mt-0.5 text-xs ${dark ? 'text-slate-200' : 'text-slate-500'}`}>
                          Vorherige, nachfolgende und zusammenhängende Prozess-Events.
                        </p>
                      </div>
                    </div>

                    <div className="grid gap-3 md:grid-cols-3">
                      <div>
                        <h4 className="mb-2 text-xs font-bold text-slate-400">Vorherige Events</h4>
                        <div className="space-y-1.5">
                          {selectedEventTrail.previous.length ? selectedEventTrail.previous.map((event, index) => (
                            <button
                              key={`prev-${event.doc_id ?? index}`}
                              type="button"
                              onClick={() => void handleSelectEvent(event)}
                              className={`w-full rounded-lg border px-2 py-1.5 text-left text-xs transition ${dark ? 'border-slate-700 hover:bg-white/5' : 'border-slate-200 hover:bg-slate-50'}`}
                            >
                              <div className="truncate font-medium">{event.smart.rule_description ?? `Rule ${event.smart.rule_id ?? '?'}`}</div>
                              <div className={`mt-0.5 ${dark ? 'text-slate-200' : 'text-slate-500'}`}>{fmtTs(event.smart.timestamp)}</div>
                            </button>
                          )) : <p className={`text-xs ${dark ? 'text-slate-300' : 'text-slate-400'}`}>Keine älteren Treffer.</p>}
                        </div>
                      </div>

                      <div>
                        <h4 className="mb-2 text-xs font-bold text-slate-400">Nachfolgende Events</h4>
                        <div className="space-y-1.5">
                          {selectedEventTrail.next.length ? selectedEventTrail.next.map((event, index) => (
                            <button
                              key={`next-${event.doc_id ?? index}`}
                              type="button"
                              onClick={() => void handleSelectEvent(event)}
                              className={`w-full rounded-lg border px-2 py-1.5 text-left text-xs transition ${dark ? 'border-slate-700 hover:bg-white/5' : 'border-slate-200 hover:bg-slate-50'}`}
                            >
                              <div className="truncate font-medium">{event.smart.rule_description ?? `Rule ${event.smart.rule_id ?? '?'}`}</div>
                              <div className={`mt-0.5 ${dark ? 'text-slate-200' : 'text-slate-500'}`}>{fmtTs(event.smart.timestamp)}</div>
                            </button>
                          )) : <p className={`text-xs ${dark ? 'text-slate-300' : 'text-slate-400'}`}>Keine neueren Treffer.</p>}
                        </div>
                      </div>

                      <div>
                        <h4 className="mb-2 text-xs font-bold text-slate-400">Gleiche Process Chain</h4>
                        <div className="space-y-1.5">
                          {selectedEventTrail.processChain.length ? selectedEventTrail.processChain.map((event, index) => (
                            <button
                              key={`chain-${event.doc_id ?? index}`}
                              type="button"
                              onClick={() => void handleSelectEvent(event)}
                              className={`w-full rounded-lg border px-2 py-1.5 text-left text-xs transition ${event === selectedEvent ? dark ? 'border-amber-500/40 bg-amber-600/10' : 'border-amber-300 bg-amber-50' : dark ? 'border-slate-700 hover:bg-white/5' : 'border-slate-200 hover:bg-slate-50'}`}
                            >
                              <div className="truncate font-medium">{event.smart.process ?? event.smart.command_line ?? event.smart.rule_description ?? `Rule ${event.smart.rule_id ?? '?'}`}</div>
                              <div className={`mt-0.5 ${dark ? 'text-slate-200' : 'text-slate-500'}`}>{fmtTs(event.smart.timestamp)}</div>
                            </button>
                          )) : <p className={`text-xs ${dark ? 'text-slate-300' : 'text-slate-400'}`}>Keine Process Chain erkannt.</p>}
                        </div>
                      </div>
                    </div>
                  </div>
                </>
              )}
            </div>
          </>
        )}
      </div>
    </div>
  );
}
