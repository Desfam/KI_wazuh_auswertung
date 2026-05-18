/**
 * FleetScanHUD – Live Fleet-Scan Dashboard (center panel)
 * Matches the screenshot layout:
 *   TOP   → status banner + stats row + filter tabs
 *   MID   → per-host progress table
 *   BOT   → log stream  |  top findings
 */
import React, { useMemo, useState } from 'react';
import { AlertTriangle, CheckCircle2, Clock, Loader2, ShieldAlert, ShieldCheck, Zap } from 'lucide-react';

// ─── types ──────────────────────────────────────────────────────
export interface HostStatus {
  status: 'queued' | 'scanning' | 'done' | 'failed';
  progress: number;
  findings: number;
  high_findings: number;
  risk_score: number | null;
  active_module: string | null;
  ti_matches: number;
  total_events: number;
}

export interface TopFinding {
  title?: string;
  description?: string;
  severity?: string;
  category?: string;
  hosts?: string[];
  seen_on?: number;
  id?: string | number;
}

export interface LiveStats {
  total_findings: number;
  high_findings: number;
  critical_hosts: number;
  fleet_risk_score: number;
}

export interface FleetStatusPayload {
  status: string;
  progress: number;
  total_hosts: number;
  finished_hosts: number;
  failed_hosts: number;
  current_phase: string;
  active_hosts: string[];
  log: string[];
  host_statuses: Record<string, HostStatus>;
  top_findings: TopFinding[];
  started_at?: string;
  params?: Record<string, unknown>;
  live_stats?: LiveStats;
}

interface Props {
  status: FleetStatusPayload | null;
  hosts: string[];                   // full ordered list from sidebar
  onCancel?: () => void;
  onExportCsv?: () => void;
  onDrilldown?: (host: string) => void;
  fleetState: 'running' | 'finished' | 'failed' | 'idle';
}

// ─── helpers ────────────────────────────────────────────────────
type FilterTab = 'all' | 'scanning' | 'done' | 'queued' | 'failed';

const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function sevColor(sev: string) {
  switch (sev?.toLowerCase()) {
    case 'critical': return { badge: 'bg-critical text-white', text: 'text-critical' };
    case 'high':     return { badge: 'bg-[#f97316] text-white', text: 'text-[#f97316]' };
    case 'medium':   return { badge: 'bg-warning text-black', text: 'text-warning' };
    case 'low':      return { badge: 'bg-info text-black', text: 'text-[#22d3ee]' };
    default:         return { badge: 'bg-border text-muted-foreground', text: 'text-muted-foreground' };
  }
}

function riskColor(score: number | null) {
  if (score === null) return 'text-muted-foreground';
  if (score >= 80) return 'text-critical';
  if (score >= 60) return 'text-high';
  if (score >= 40) return 'text-warning';
  return 'text-success';
}

// ─── sub-components ──────────────────────────────────────────────
function StatTile({ label, value, tone }: { label: string; value: number | string; tone?: 'critical' | 'high' | 'warning' | 'success' }) {
  const col = tone === 'critical' ? 'text-critical' : tone === 'high' ? 'text-[#f97316]' : tone === 'warning' ? 'text-warning' : tone === 'success' ? 'text-success' : 'text-foreground';
  return (
    <div className="flex-1 border border-border bg-[var(--panel)] rounded-md px-4 py-2.5">
      <div className="text-[9px] font-mono uppercase tracking-widest text-muted-foreground">{label}</div>
      <div className={`text-[20px] font-mono font-bold tabular-nums mt-0.5 ${col}`}>{value}</div>
    </div>
  );
}

function ProgressBar({ value, status }: { value: number; status: HostStatus['status'] }) {
  const color =
    status === 'done'    ? 'bg-success' :
    status === 'failed'  ? 'bg-critical' :
    status === 'scanning'? 'bg-primary' :
                           'bg-border';
  return (
    <div className="relative h-1.5 w-full rounded-full bg-border/40 overflow-hidden">
      <div
        className={`absolute left-0 top-0 h-full rounded-full transition-all duration-500 ${color} ${status === 'scanning' ? 'opacity-80' : ''}`}
        style={{ width: `${value}%` }}
      />
      {status === 'scanning' && (
        <div
          className="absolute top-0 h-full w-8 rounded-full opacity-60"
          style={{
            background: 'linear-gradient(90deg, transparent, var(--primary), transparent)',
            animation: 'scanBeam 2s ease-in-out infinite',
            left: `${Math.max(0, value - 12)}%`,
          }}
        />
      )}
    </div>
  );
}

function StatusBadge({ status }: { status: HostStatus['status'] }) {
  switch (status) {
    case 'done':     return <span className="inline-flex items-center gap-1 h-5 px-2 rounded-sm bg-success/15 border border-success/30 text-success text-[9px] font-mono uppercase"><CheckCircle2 className="h-2.5 w-2.5" />done</span>;
    case 'scanning': return <span className="inline-flex items-center gap-1 h-5 px-2 rounded-sm bg-primary/15 border border-primary/40 text-primary text-[9px] font-mono uppercase"><Loader2 className="h-2.5 w-2.5 animate-spin" />scanning</span>;
    case 'failed':   return <span className="inline-flex items-center gap-1 h-5 px-2 rounded-sm bg-critical/10 border border-critical/30 text-critical text-[9px] font-mono uppercase"><AlertTriangle className="h-2.5 w-2.5" />failed</span>;
    default:         return <span className="inline-flex items-center gap-1 h-5 px-2 rounded-sm bg-border/40 border border-border text-muted-foreground text-[9px] font-mono uppercase"><Clock className="h-2.5 w-2.5" />queued</span>;
  }
}

// ─── main component ──────────────────────────────────────────────
export function FleetScanHUD({ status, hosts, onCancel, onExportCsv, onDrilldown, fleetState }: Props) {
  const [filter, setFilter] = useState<FilterTab>('all');
  const [logAutoScroll] = useState(true);
  const logRef = React.useRef<HTMLDivElement>(null);

  React.useEffect(() => {
    if (logAutoScroll && logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [status?.log, logAutoScroll]);

  const hostStatuses = status?.host_statuses ?? {};
  const allHostList = hosts.length > 0 ? hosts : Object.keys(hostStatuses);

  // counts per status
  const counts = useMemo(() => {
    const c = { scanning: 0, done: 0, queued: 0, failed: 0 };
    allHostList.forEach(h => {
      const s = (hostStatuses[h]?.status as FilterTab) ?? 'queued';
      if (s in c) c[s as keyof typeof c]++;
    });
    return c;
  }, [allHostList, hostStatuses]);

  const filteredHosts = useMemo(() =>
    filter === 'all' ? allHostList : allHostList.filter(h => (hostStatuses[h]?.status ?? 'queued') === filter),
    [allHostList, hostStatuses, filter]
  );

  const ls = status?.live_stats;
  const isRunning = fleetState === 'running';

  return (
    <div className="flex-1 flex flex-col min-h-0 overflow-hidden">

      {/* ── STATUS BANNER ────────────────────────────────── */}
      <div className="shrink-0 px-5 py-2.5 border-b border-border bg-[var(--panel)] flex items-center gap-4">
        <div className="flex items-center gap-2">
          {isRunning
            ? <span className="h-2 w-2 rounded-full bg-warning animate-pulse" />
            : fleetState === 'finished'
            ? <span className="h-2 w-2 rounded-full bg-success" />
            : <span className="h-2 w-2 rounded-full bg-critical" />}
          <span className="text-[13px] font-mono font-bold">
            {isRunning
              ? `running · ${status?.finished_hosts ?? 0}/${status?.total_hosts ?? 0} complete`
              : fleetState === 'finished'
              ? `finished · ${status?.finished_hosts ?? 0}/${status?.total_hosts ?? 0} hosts`
              : 'failed'}
          </span>
        </div>
        {status?.params && (
          <div className="text-[10px] font-mono text-muted-foreground">
            parallelism: 6 · mode: {String(status.params.mode ?? 'quick')} · started {status.started_at ?? '—'}
          </div>
        )}
        <div className="ml-auto flex items-center gap-1.5">
          {isRunning && onCancel && (
            <button
              onClick={onCancel}
              className="h-6 px-2.5 rounded-sm border border-warning/50 bg-warning/10 text-warning text-[10px] font-mono hover:bg-warning/20"
            >
              ⏸ Pause
            </button>
          )}
          {onExportCsv && (
            <button
              onClick={onExportCsv}
              className="h-6 px-2.5 rounded-sm border border-border text-[10px] font-mono hover:bg-accent"
            >
              Export CSV
            </button>
          )}
        </div>
      </div>

      {/* ── PROGRESS BAR ─────────────────────────────────── */}
      <div className="shrink-0">
        <div className="h-[3px] w-full bg-border/30">
          <div
            className="h-full bg-primary transition-all duration-500"
            style={{ width: `${status?.progress ?? 0}%` }}
          />
        </div>
      </div>

      {/* ── STATS ROW ────────────────────────────────────── */}
      <div className="shrink-0 flex gap-2 px-5 py-2.5 border-b border-border">
        <StatTile label="Hosts" value={status?.total_hosts ?? 0} />
        <StatTile label="Done" value={status?.finished_hosts ?? 0} tone="success" />
        <StatTile label="Findings" value={ls?.total_findings ?? 0} tone={(ls?.total_findings ?? 0) > 0 ? 'warning' : undefined} />
        <StatTile label="Critical" value={ls?.critical_hosts ?? 0} tone={(ls?.critical_hosts ?? 0) > 0 ? 'critical' : undefined} />
        <StatTile label="High" value={ls?.high_findings ?? 0} tone={(ls?.high_findings ?? 0) > 0 ? 'high' : undefined} />
      </div>

      {/* ── FILTER TABS ──────────────────────────────────── */}
      <div className="shrink-0 flex items-center gap-0 px-5 py-1.5 border-b border-border bg-[var(--panel)]">
        {(['all', 'scanning', 'done', 'queued', 'failed'] as FilterTab[]).map(tab => {
          const cnt = tab === 'all' ? allHostList.length : counts[tab as keyof typeof counts];
          return (
            <button
              key={tab}
              onClick={() => setFilter(tab)}
              className={`h-6 px-3 text-[10px] font-mono rounded-sm mr-1 transition-colors ${
                filter === tab
                  ? 'bg-primary/15 border border-primary/40 text-primary'
                  : 'text-muted-foreground hover:text-foreground hover:bg-accent border border-transparent'
              }`}
            >
              {tab} {cnt > 0 && <span className="opacity-60">({cnt})</span>}
            </button>
          );
        })}
      </div>

      {/* ── PER-HOST TABLE ───────────────────────────────── */}
      <div className="flex-1 flex flex-col min-h-0 overflow-hidden">
        {/* table header */}
        <div className="shrink-0 grid gap-2 px-5 py-1 border-b border-border bg-[var(--panel)]"
          style={{ gridTemplateColumns: '200px 90px 1fr 80px 48px 48px 48px' }}>
          {['HOST', 'STATUS', 'PROGRESS', 'MODULE', 'RISK', 'F', 'HIGH'].map(h => (
            <div key={h} className="text-[9px] font-mono uppercase tracking-widest text-muted-foreground">{h}</div>
          ))}
        </div>
        {/* table body */}
        <div className="flex-1 overflow-y-auto">
          <div className="text-[10px] font-mono text-muted-foreground px-5 pt-1.5 pb-0.5 uppercase tracking-widest">
            Fleet · Per-Host Progress · {filteredHosts.length}
          </div>
          {filteredHosts.map(host => {
            const hs = hostStatuses[host] ?? { status: 'queued', progress: 0, findings: 0, high_findings: 0, risk_score: null, active_module: null, ti_matches: 0, total_events: 0 };
            return (
              <div
                key={host}
                className="group px-5 py-1.5 hover:bg-[var(--row-hover)] cursor-pointer border-b border-border/40"
                onClick={() => hs.status === 'done' && onDrilldown?.(host)}
              >
                <div className="grid gap-2 items-center"
                  style={{ gridTemplateColumns: '200px 90px 1fr 80px 48px 48px 48px' }}>
                  {/* host */}
                  <div className="flex items-center gap-1.5 min-w-0">
                    {hs.risk_score !== null && hs.risk_score >= 60
                      ? <ShieldAlert className={`h-3 w-3 shrink-0 ${riskColor(hs.risk_score)}`} />
                      : hs.status === 'done'
                      ? <ShieldCheck className="h-3 w-3 shrink-0 text-success" />
                      : hs.status === 'scanning'
                      ? <Loader2 className="h-3 w-3 shrink-0 text-primary animate-spin" />
                      : <Clock className="h-3 w-3 shrink-0 text-muted-foreground" />}
                    <span className="font-mono text-[11px] truncate font-semibold">{host}</span>
                    {hs.ti_matches > 0 && (
                      <Zap className="h-2.5 w-2.5 shrink-0 text-critical" aria-label={`${hs.ti_matches} TI hits`} />
                    )}
                  </div>
                  {/* status badge */}
                  <div><StatusBadge status={hs.status} /></div>
                  {/* progress bar */}
                  <div className="py-1"><ProgressBar value={hs.progress} status={hs.status} /></div>
                  {/* active module */}
                  <div className="text-[9px] font-mono text-muted-foreground truncate">
                    {hs.active_module ? hs.active_module.split(' ')[0] : (hs.status === 'done' ? 'done' : hs.status === 'queued' ? '—' : '')}
                  </div>
                  {/* risk */}
                  <div className={`text-[11px] font-mono font-bold tabular-nums text-right ${riskColor(hs.risk_score)}`}>
                    {hs.risk_score !== null ? hs.risk_score : '—'}
                  </div>
                  {/* findings */}
                  <div className={`text-[11px] font-mono tabular-nums text-right ${hs.findings > 0 ? 'text-warning' : 'text-muted-foreground'}`}>
                    {hs.findings}
                  </div>
                  {/* high */}
                  <div className={`text-[11px] font-mono tabular-nums text-right ${hs.high_findings > 0 ? 'text-critical' : 'text-muted-foreground'}`}>
                    {hs.high_findings}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* ── BOTTOM: LOG + TOP FINDINGS ───────────────────── */}
      <div className="shrink-0 border-t border-border flex" style={{ height: 210 }}>

        {/* Log stream */}
        <div className="w-[42%] border-r border-border flex flex-col min-h-0">
          <div className="shrink-0 flex items-center justify-between px-4 py-1 border-b border-border">
            <span className="text-[9px] font-mono uppercase tracking-widest text-muted-foreground">Live Log Stream</span>
            <span className="text-[9px] font-mono text-muted-foreground">{status?.log?.length ?? 0} lines · auto-scroll</span>
          </div>
          <div ref={logRef} className="flex-1 overflow-y-auto px-4 py-1.5 space-y-0.5">
            {(status?.log ?? ['Warte auf Scan-Start…']).map((line, i) => {
              const isLatest = i === (status?.log?.length ?? 1) - 1;
              const isSuccess = line.includes('✓');
              const isError = line.includes('✗') || line.includes('Fehler');
              const isStart = line.includes('→');
              return (
                <div
                  key={i}
                  className={`text-[10px] font-mono leading-relaxed ${
                    isLatest ? 'text-foreground' :
                    isSuccess ? 'text-success/70' :
                    isError ? 'text-critical/70' :
                    isStart ? 'text-primary/60' :
                    'text-muted-foreground'
                  }`}
                >
                  {line}
                </div>
              );
            })}
          </div>
        </div>

        {/* Top Findings */}
        <div className="flex-1 flex flex-col min-h-0">
          <div className="shrink-0 px-4 py-1 border-b border-border">
            <span className="text-[9px] font-mono uppercase tracking-widest text-muted-foreground">
              Fleet · Top Findings · {status?.top_findings?.length ?? 0}
            </span>
          </div>
          <div className="flex-1 overflow-y-auto">
            {(status?.top_findings ?? []).length === 0 ? (
              <div className="flex items-center justify-center h-full text-[11px] font-mono text-muted-foreground">
                {isRunning ? 'warten auf erste Findings…' : 'keine Findings'}
              </div>
            ) : (
              (status?.top_findings ?? []).map((f, i) => {
                const sev = f.severity?.toLowerCase() ?? 'info';
                const { badge } = sevColor(sev);
                const title = f.title || f.description || 'Unbekanntes Finding';
                return (
                  <div key={i} className="flex items-start gap-2.5 px-4 py-2 border-b border-border/40 hover:bg-[var(--row-hover)]">
                    <span className="text-[9px] font-mono px-1.5 py-0.5 rounded shrink-0 mt-0.5 uppercase font-bold" style={{ background: sev === 'critical' ? 'var(--destructive)' : sev === 'high' ? '#f97316' : sev === 'medium' ? '#eab308' : '#22d3ee', color: sev === 'medium' ? '#000' : '#fff' }}>
                      {sev}
                    </span>
                    <div className="min-w-0 flex-1">
                      <div className="text-[11px] font-mono font-semibold truncate">{title}</div>
                      {f.category && (
                        <div className="text-[9.5px] font-mono text-muted-foreground truncate">{f.category}</div>
                      )}
                    </div>
                    <div className="shrink-0 text-[9.5px] font-mono text-muted-foreground whitespace-nowrap">
                      seen on {f.seen_on ?? 1} host{(f.seen_on ?? 1) > 1 ? 's' : ''}
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

      </div>
    </div>
  );
}
