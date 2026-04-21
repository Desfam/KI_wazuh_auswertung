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
  Play,
  Download,
  GitBranch,
  RefreshCw,
} from 'lucide-react';
import {
  getSnipenHostEvents,
  getSnipenHosts,
} from '../services/api';
import type {
  HostProfileAssignment,
  SnipenEvent,
  SnipenHostInfo,
} from '../types';

// ── Types & constants ─────────────────────────────────────────────────────────

interface SnipenPageProps {
  active: boolean;
  theme: 'light' | 'dark';
  profileAssignments: Record<string, HostProfileAssignment>;
  prefillHost?: string | null;
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

// ── Main component ────────────────────────────────────────────────────────────

export function SnipenPage({
  active,
  prefillHost,
  onPrefillConsumed,
}: SnipenPageProps) {
  // Host list state
  const [hosts, setHosts] = useState<SnipenHostInfo[]>([]);
  const [hostsLoading, setHostsLoading] = useState(false);
  const [hostsError, setHostsError] = useState<string | null>(null);
  const [selectedHost, setSelectedHost] = useState<string | null>(null);
  const [hours, setHours] = useState<TimePreset>(24);

  // Event state
  const [events, setEvents] = useState<SnipenEvent[]>([]);
  const [eventsLoading, setEventsLoading] = useState(false);
  const [selectedEventTs, setSelectedEventTs] = useState<string | null>(null);
  const [typeFilter, setTypeFilter] = useState<CategoryFilter>('all');
  const [query, setQuery] = useState('');

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

  // Load events when host changes
  useEffect(() => {
    if (!selectedHost) return;
    setEventsLoading(true);
    setEvents([]);
    setSelectedEventTs(null);
    getSnipenHostEvents(selectedHost, { hours, limit: 200 })
      .then((data) => {
        setEvents(data);
        if (data.length > 0) setSelectedEventTs(data[0].smart.timestamp ?? null);
      })
      .catch(() => setEvents([]))
      .finally(() => setEventsLoading(false));
  }, [selectedHost, hours]);

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

  return (
    <div className="h-full grid grid-cols-[180px_1fr_360px] min-h-0">
      {/* Left: type filter + context */}
      <aside className="border-r border-border bg-[var(--panel)] flex flex-col min-h-0">
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

        <FSec title="Hosts">
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
              className="w-full text-left h-6 px-2 rounded-sm text-[11.5px] font-mono text-muted-foreground hover:bg-accent hover:text-foreground truncate"
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

        <div className="mt-auto p-2 border-t border-border">
          <button
            onClick={loadHosts}
            className="w-full h-6 rounded-sm border border-border hover:bg-accent text-[11px] font-mono inline-flex items-center justify-center gap-1 text-muted-foreground"
          >
            <RefreshCw className="h-3 w-3" /> Refresh
          </button>
        </div>
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
          <button className="h-7 px-2 rounded-sm border border-border hover:bg-accent text-[11px] font-mono inline-flex items-center gap-1">
            <Play className="h-3 w-3" /> Run
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
              {selectedHost ? 'no events match filter' : 'select a host →'}
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
                  'w-full text-left grid grid-cols-[60px_22px_60px_70px_1fr_120px] gap-2 px-3 py-1.5 border-b border-border/60 hover:bg-[var(--row-hover)] ' +
                  (sel ? 'bg-[var(--row-hover)] border-l-2 border-l-primary -ml-px pl-[11px]' : '')
                }
              >
                <span className="text-[11px] font-mono text-muted-foreground truncate">
                  {s.timestamp ? s.timestamp.slice(11, 19) : '—'}
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
      <aside className="bg-[var(--panel)] flex flex-col min-h-0">
        <div className="h-9 px-3 flex items-center border-b border-border">
          <span className="text-[12px] font-semibold tracking-wide">EVENT</span>
          {selectedEvent && (
            <span className="ml-2 text-[10.5px] font-mono text-muted-foreground">
              [{selectedEvent.smart.event_id}] · {selectedEvent.smart.timestamp?.slice(11, 19) ?? '—'}
            </span>
          )}
          {selectedEvent && (
            <span className="ml-auto">
              <span
                className={
                  'inline-flex items-center h-[18px] px-1.5 rounded-sm text-[10px] font-mono uppercase tracking-wider border ' +
                  sevBadgeClass(ruleLevelToSeverity(selectedEvent.smart.rule_level))
                }
              >
                {ruleLevelToSeverity(selectedEvent.smart.rule_level)}
              </span>
            </span>
          )}
        </div>

        {selectedEvent ? (
          <div className="flex-1 overflow-y-auto">
            <Sec title="Summary">
              <div className="text-[12px] leading-snug">
                {selectedEvent.smart.summary ?? selectedEvent.smart.rule_description ?? '—'}
              </div>
              <div className="mt-1.5 grid grid-cols-2 gap-x-3 gap-y-1 text-[11px] font-mono">
                <KV k="host" v={selectedEvent.smart.host ?? selectedHost ?? '—'} />
                <KV k="type" v={deriveCategory(selectedEvent)} />
                {selectedEvent.smart.user && <KV k="user" v={selectedEvent.smart.user} />}
                {selectedEvent.smart.process && <KV k="proc" v={selectedEvent.smart.process} />}
                {selectedEvent.smart.mitre_id && <KV k="MITRE" v={selectedEvent.smart.mitre_id} />}
                {selectedEvent.smart.mitre_tactic && <KV k="tactic" v={selectedEvent.smart.mitre_tactic} />}
              </div>
            </Sec>

            {selectedEvent.smart.command_line && (
              <Sec title="Command Line">
                <pre className="text-[11px] font-mono whitespace-pre-wrap leading-snug break-all">
                  {selectedEvent.smart.command_line}
                </pre>
              </Sec>
            )}

            {selectedEvent.smart.ip_address && (
              <Sec title="Network">
                <KV k="IP" v={selectedEvent.smart.ip_address} />
                {selectedEvent.smart.logon_type && <KV k="logon" v={selectedEvent.smart.logon_type} />}
              </Sec>
            )}

            <Sec title="Raw Data">
              <pre className="text-[11px] font-mono whitespace-pre-wrap leading-snug text-muted-foreground max-h-[200px] overflow-y-auto">
                {Object.entries(selectedEvent.smart)
                  .filter(([, v]) => v != null && v !== '' && (Array.isArray(v) ? v.length > 0 : true))
                  .map(([k, v]) => `${k.padEnd(18)} ${Array.isArray(v) ? v.join(', ') : v}`)
                  .join('\n')}
              </pre>
            </Sec>

            <Sec title="Quick Pivots">
              <div className="grid grid-cols-2 gap-1">
                {[
                  selectedEvent.smart.host ? `host:${selectedEvent.smart.host}` : null,
                  selectedEvent.smart.event_id ? `eid:${selectedEvent.smart.event_id}` : null,
                  selectedEvent.smart.user ? `user:${selectedEvent.smart.user}` : null,
                  selectedEvent.smart.process ? `process:${selectedEvent.smart.process}` : null,
                ]
                  .filter(Boolean)
                  .map((p) => (
                    <button
                      key={p as string}
                      onClick={() => setQuery(p as string)}
                      className="text-left h-6 px-2 rounded-sm border border-border hover:bg-accent text-[11px] font-mono truncate"
                    >
                      → {p}
                    </button>
                  ))}
              </div>
            </Sec>

            <Sec title="Related Events">
              {events
                .filter((e) => e.smart.host === selectedEvent.smart.host && e.smart.timestamp !== selectedEvent.smart.timestamp)
                .slice(0, 4)
                .map((e) => (
                  <div
                    key={(e.smart.timestamp ?? '') + (e.smart.event_id ?? '')}
                    className="grid grid-cols-[60px_44px_1fr] gap-2 text-[11px] font-mono py-1 border-b border-border/60 last:border-0 cursor-pointer hover:bg-[var(--row-hover)]"
                    onClick={() => setSelectedEventTs(e.smart.timestamp ?? null)}
                  >
                    <span className="text-muted-foreground">{e.smart.timestamp?.slice(11, 19) ?? '—'}</span>
                    <span className="text-info">[{e.smart.event_id ?? '—'}]</span>
                    <span className="truncate">{e.smart.summary ?? e.smart.rule_description ?? '—'}</span>
                  </div>
                ))}
            </Sec>
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

function FSec({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="border-b border-border p-2">
      <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground mb-1 px-1">
        {title}
      </div>
      <div className="space-y-[1px]">{children}</div>
    </div>
  );
}

function Sec({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="px-3 py-2 border-b border-border">
      <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground mb-1.5">
        {title}
      </div>
      {children}
    </div>
  );
}

function KV({ k, v }: { k: string; v: string }) {
  return (
    <div className="flex gap-2 min-w-0">
      <span className="text-muted-foreground w-12 shrink-0">{k}</span>
      <span className="truncate">{v}</span>
    </div>
  );
}
