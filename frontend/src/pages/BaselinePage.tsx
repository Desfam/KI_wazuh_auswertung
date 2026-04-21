import { useEffect, useMemo, useState } from 'react';
import { GitCompareArrows, Cpu, KeyRound, Wrench, Network, Check, Eye, RefreshCw, Database } from 'lucide-react';
import { computeBaseline, getBaselineDeviations, getBaselineSummary, getHostsCentral, resolveDeviation } from '../services/api';
import type { BaselineDeviation, BaselineSummary, HostCentralListItem } from '../types';

type BaselinePageProps = {
  active: boolean;
  theme: 'light' | 'dark';
  onSwitchTab: (tab: 'dashboard' | 'chat' | 'tasks' | 'snipen' | 'fullscan' | 'hosts' | 'baseline', context?: { host?: string }) => void;
};

type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';

function severityFromRisk(risk: number): SeverityLevel {
  if (risk >= 80) return 'critical';
  if (risk >= 60) return 'high';
  if (risk >= 40) return 'medium';
  if (risk >= 20) return 'low';
  return 'info';
}

function riskColor(level: string) {
  if (level === 'critical') return 'text-critical';
  if (level === 'high') return 'text-high';
  if (level === 'medium') return 'text-warning';
  return 'text-success';
}

function riskBg(level: string) {
  if (level === 'critical') return 'bg-critical';
  if (level === 'high') return 'bg-high';
  if (level === 'medium') return 'bg-warning';
  return 'bg-success';
}

function stateClass(d: BaselineDeviation) {
  const sev = severityFromRisk(d.risk_score);
  return {
    dot: sev === 'critical' ? 'bg-critical' : sev === 'high' ? 'bg-high' : sev === 'medium' ? 'bg-warning' : 'bg-success',
    score: riskColor(d.risk_level ?? sev),
    badge:
      sev === 'critical'
        ? 'bg-critical/15 text-critical border-critical/40'
        : sev === 'high'
          ? 'bg-warning/15 text-warning border-warning/40'
          : 'bg-success/15 text-success border-success/40',
    label: sev === 'critical' ? 'abnormal' : sev === 'high' ? 'unusual' : 'normal',
  };
}

function kindIcon(kind: string) {
  if (kind === 'process') return Cpu;
  if (kind === 'user') return KeyRound;
  if (kind === 'service') return Wrench;
  return Network;
}

export function BaselinePage({ active, onSwitchTab }: BaselinePageProps) {
  const [hosts, setHosts] = useState<HostCentralListItem[]>([]);
  const [selectedHost, setSelectedHost] = useState<string | null>(null);
  const [deviations, setDeviations] = useState<BaselineDeviation[]>([]);
  const [summary, setSummary] = useState<BaselineSummary | null>(null);
  const [selected, setSelected] = useState<BaselineDeviation | null>(null);
  const [loading, setLoading] = useState(false);
  const [loadingDev, setLoadingDev] = useState(false);
  const [search, setSearch] = useState('');
  const [computingBaseline, setComputingBaseline] = useState(false);
  const [acceptedIds, setAcceptedIds] = useState<Set<number>>(new Set());

  async function handleComputeBaseline() {
    if (!selectedHost) return;
    setComputingBaseline(true);
    try {
      await computeBaseline(selectedHost);
      // Refresh deviations
      setLoadingDev(true);
      const [devs, sum] = await Promise.all([
        getBaselineDeviations(selectedHost, true),
        getBaselineSummary(selectedHost).catch(() => null),
      ]);
      setDeviations(devs);
      setSummary(sum);
      setSelected(devs.length > 0 ? devs[0] : null);
    } catch (e) {
      console.error('Failed to compute baseline:', e);
    } finally {
      setComputingBaseline(false);
      setLoadingDev(false);
    }
  }

  async function handleAcceptAsBaseline() {
    if (!selected) return;
    try {
      await resolveDeviation(selected.id);
      setAcceptedIds((prev) => new Set([...prev, selected.id]));
      // Select next unaccepted deviation
      const remaining = deviations.filter((d) => d.id !== selected.id && !acceptedIds.has(d.id));
      setSelected(remaining.length > 0 ? remaining[0] : null);
    } catch (e) {
      console.error('Failed to resolve deviation:', e);
    }
  }

  function handleInvestigate() {
    if (!selected) return;
    onSwitchTab('snipen', { host: selected.host });
  }

  useEffect(() => {
    if (!active) return;
    setLoading(true);
    getHostsCentral()
      .then((data) => {
        setHosts(data);
        if (data.length > 0 && !selectedHost) {
          setSelectedHost(data[0].host);
        }
      })
      .finally(() => setLoading(false));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active]);

  useEffect(() => {
    if (!selectedHost) return;
    setLoadingDev(true);
    setDeviations([]);
    setSummary(null);
    setSelected(null);
    Promise.all([
      getBaselineDeviations(selectedHost, true),
      getBaselineSummary(selectedHost).catch(() => null),
    ])
      .then(([devs, sum]) => {
        setDeviations(devs);
        setSummary(sum);
        if (devs.length > 0) setSelected(devs[0]);
      })
      .finally(() => setLoadingDev(false));
  }, [selectedHost]);

  const filtered = useMemo(
    () =>
      deviations.filter(
        (d) =>
          !acceptedIds.has(d.id) &&
          (!search ||
          d.feature_key.toLowerCase().includes(search.toLowerCase()) ||
          d.feature_type.toLowerCase().includes(search.toLowerCase()) ||
          d.reason.toLowerCase().includes(search.toLowerCase())),
      ),
    [deviations, search, acceptedIds],
  );

  const abnormal = filtered.filter((d) => d.risk_score >= 80);
  const unusual = filtered.filter((d) => d.risk_score >= 40 && d.risk_score < 80);

  if (!active) return null;

  return (
    <div className="h-full grid grid-cols-[200px_1fr_360px] min-h-0">
      {/* Left: host list */}
      <aside className="border-r border-border bg-[var(--panel)] flex flex-col min-h-0">
        <div className="px-3 py-2 border-b border-border flex items-center gap-2">
          <span className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground flex-1">Hosts</span>
          <button
            onClick={() => active && setSelectedHost(selectedHost)}
            className="h-5 w-5 rounded-sm hover:bg-accent inline-flex items-center justify-center"
            title="Refresh"
          >
            <RefreshCw className="h-3 w-3 text-muted-foreground" />
          </button>
        </div>
        <div className="flex-1 overflow-y-auto">
          {loading && (
            <div className="px-3 py-2 text-[11px] font-mono text-muted-foreground">loading…</div>
          )}
          {hosts.map((h) => {
            const sel = h.host === selectedHost;
            const risk = h.risk_score ?? 0;
            return (
              <button
                key={h.host}
                onClick={() => setSelectedHost(h.host)}
                className={
                  'w-full text-left px-3 py-2 border-b border-border/60 hover:bg-[var(--row-hover)] ' +
                  (sel ? 'bg-[var(--row-hover)] border-l-2 border-l-primary -ml-px pl-[11px]' : '')
                }
              >
                <div className="text-[12px] font-mono truncate">{h.host}</div>
                <div className="mt-0.5 text-[10.5px] font-mono text-muted-foreground">
                  risk{' '}
                  <span className={risk >= 80 ? 'text-critical' : risk >= 60 ? 'text-high' : risk >= 40 ? 'text-warning' : 'text-success'}>
                    {risk}
                  </span>
                </div>
              </button>
            );
          })}
        </div>
        {summary && (
          <div className="px-3 py-2 border-t border-border text-[10.5px] font-mono text-muted-foreground space-y-0.5">
            <div className="flex justify-between">
              <span>deviations</span>
              <span className="text-critical">{summary.open_deviations}</span>
            </div>
            <div className="flex justify-between">
              <span>events (24h)</span>
              <span>{summary.total_events}</span>
            </div>
          </div>
        )}
        {selectedHost && (
          <div className="px-3 py-2 border-t border-border">
            <button
              onClick={() => void handleComputeBaseline()}
              disabled={computingBaseline}
              className="w-full h-7 rounded-sm border border-border hover:bg-accent text-[11.5px] font-mono inline-flex items-center justify-center gap-1 disabled:opacity-50"
              title="Compute a new baseline snapshot for this host"
            >
              <Database className={`h-3 w-3 ${computingBaseline ? 'animate-pulse text-primary' : ''}`} />
              {computingBaseline ? 'Computing…' : 'Compute Baseline'}
            </button>
          </div>
        )}
      </aside>

      {/* Center: deviations tables */}
      <div className="flex flex-col min-h-0 border-r border-border overflow-y-auto">
        <div className="px-3 py-2 border-b border-border bg-[var(--panel)] flex items-center gap-2 sticky top-0 z-10">
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="filter deviations…"
            className="bg-transparent flex-1 outline-none text-[11.5px] font-mono placeholder:text-muted-foreground"
          />
          {loadingDev && <span className="text-[10.5px] font-mono text-muted-foreground">loading…</span>}
        </div>

        {/* Abnormal section */}
        <Header title="ABNORMAL" sub={`${abnormal.length} flagged`} tone="critical" icon={GitCompareArrows} />
        <ItemTable items={abnormal} onSelect={setSelected} selected={selected} />

        {/* Unusual section */}
        <Header title="UNUSUAL" sub={`${unusual.length} flagged`} tone="warning" icon={GitCompareArrows} />
        <ItemTable items={unusual} onSelect={setSelected} selected={selected} />

        {filtered.length === 0 && !loadingDev && (
          <div className="px-3 py-6 text-center text-[11.5px] font-mono text-muted-foreground">
            {selectedHost ? 'no deviations found' : 'select a host →'}
          </div>
        )}
      </div>

      {/* Right: detail */}
      <aside className="bg-[var(--panel)] flex flex-col min-h-0">
        <div className="h-9 px-3 flex items-center border-b border-border">
          <span className="text-[12px] font-semibold tracking-wide">DETAIL</span>
          {selected && (
            <span className="ml-2 text-[10.5px] font-mono text-muted-foreground truncate">
              {selected.feature_key}
            </span>
          )}
          {selected && (
            <span className="ml-auto">
              <StateBadge deviation={selected} />
            </span>
          )}
        </div>

        {selected ? (
          <div className="flex-1 overflow-y-auto">
            <Sec title="Identity">
              <KV k="host" v={selected.host} />
              <KV k="kind" v={selected.feature_type} />
              <KV k="name" v={selected.feature_key} />
              <KV k="type" v={selected.deviation_type} />
              <KV k="detected" v={selected.detected_at} />
            </Sec>

            <Sec title="Deviation Score">
              <div className="flex items-baseline gap-2">
                <span className={'text-[28px] font-mono font-semibold ' + riskColor(selected.risk_level ?? 'info')}>
                  {selected.risk_score}
                </span>
                <span className="text-[11px] font-mono text-muted-foreground">/ 100</span>
              </div>
              <div className="mt-1 h-1 w-full bg-muted rounded-sm overflow-hidden">
                <div
                  className={'h-full ' + riskBg(selected.risk_level ?? 'info')}
                  style={{ width: `${selected.risk_score}%` }}
                />
              </div>
            </Sec>

            <Sec title="Reason">
              <div className="text-[11.5px] font-mono leading-snug">{selected.reason}</div>
              <div className="mt-1.5 text-[10.5px] font-mono text-muted-foreground">
                confidence {Math.round(selected.confidence * 100)}%
              </div>
            </Sec>

            {Object.keys(selected.details ?? {}).length > 0 && (
              <Sec title="Details">
                <pre className="text-[11px] font-mono whitespace-pre-wrap leading-snug text-muted-foreground">
                  {JSON.stringify(selected.details, null, 2)}
                </pre>
              </Sec>
            )}

            <Sec title="Actions">
              <div className="flex flex-wrap gap-1.5">
                <ActBtn icon={Check} label="Accept as baseline" tone="success" onClick={() => void handleAcceptAsBaseline()} />
                <ActBtn icon={Eye} label="Investigate" onClick={handleInvestigate} />
              </div>
            </Sec>
          </div>
        ) : (
          <div className="flex-1 grid place-items-center text-[12px] font-mono text-muted-foreground">
            select deviation →
          </div>
        )}
      </aside>
    </div>
  );
}

// ── Sub-components ────────────────────────────────────────────────────────────

function Header({
  title,
  sub,
  tone,
  icon: Icon,
}: {
  title: string;
  sub: string;
  tone: 'success' | 'critical' | 'warning';
  icon: React.ComponentType<{ className?: string }>;
}) {
  const c = tone === 'critical' ? 'text-critical' : tone === 'warning' ? 'text-warning' : 'text-success';
  return (
    <div className="px-3 py-2 border-b border-border bg-[var(--panel)] flex items-center gap-2 sticky top-0 z-10">
      <Icon className={'h-3.5 w-3.5 ' + c} />
      <span className="text-[12px] font-semibold tracking-wide">{title}</span>
      <span className="text-[10.5px] font-mono text-muted-foreground">{sub}</span>
    </div>
  );
}

function ItemTable({
  items,
  onSelect,
  selected,
}: {
  items: BaselineDeviation[];
  onSelect: (d: BaselineDeviation) => void;
  selected: BaselineDeviation | null;
}) {
  if (items.length === 0) return null;
  return (
    <table className="w-full text-[11.5px] font-mono">
      <thead className="border-b border-border text-[10px] uppercase tracking-wider text-muted-foreground">
        <tr>
          <th className="px-3 py-1.5 text-left font-medium w-[20px]" />
          <th className="px-3 py-1.5 text-left font-medium">Name</th>
          <th className="px-3 py-1.5 text-left font-medium w-[90px]">Kind</th>
          <th className="px-3 py-1.5 text-right font-medium w-[60px]">Score</th>
          <th className="px-3 py-1.5 text-left font-medium w-[90px]">State</th>
        </tr>
      </thead>
      <tbody>
        {items.map((d) => {
          const sel = selected?.id === d.id;
          const sc = stateClass(d);
          const Icon = kindIcon(d.feature_type);
          return (
            <tr
              key={d.id}
              onClick={() => onSelect(d)}
              className={
                'border-b border-border/60 cursor-pointer hover:bg-[var(--row-hover)] ' +
                (sel ? 'bg-[var(--row-hover)]' : '')
              }
            >
              <td className="px-3 py-1.5">
                <span className={'inline-block h-1.5 w-1.5 rounded-full ' + sc.dot} />
              </td>
              <td className="px-3 py-1.5 truncate max-w-[180px]">
                <span className="inline-flex items-center gap-2">
                  <Icon className="h-3 w-3 text-muted-foreground shrink-0" />
                  <span className="truncate">{d.feature_key}</span>
                </span>
              </td>
              <td className="px-3 py-1.5 text-muted-foreground">{d.feature_type}</td>
              <td className={'px-3 py-1.5 text-right font-semibold ' + sc.score}>{d.risk_score}</td>
              <td className="px-3 py-1.5">
                <StateBadge deviation={d} />
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

function StateBadge({ deviation: d }: { deviation: BaselineDeviation }) {
  const sc = stateClass(d);
  return (
    <span
      className={
        'inline-flex items-center h-[18px] px-1.5 rounded-sm text-[10px] font-mono uppercase tracking-wider border ' +
        sc.badge
      }
    >
      {sc.label}
    </span>
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
    <div className="flex gap-2 text-[11.5px] font-mono py-0.5">
      <span className="text-muted-foreground w-16 shrink-0">{k}</span>
      <span className="truncate">{v}</span>
    </div>
  );
}

function ActBtn({
  icon: Icon,
  label,
  tone = 'default',
  onClick,
}: {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  tone?: 'default' | 'success';
  onClick?: () => void;
}) {
  const t =
    tone === 'success'
      ? 'border-success/40 hover:bg-success/10 text-success'
      : 'border-border hover:bg-accent text-foreground';
  return (
    <button onClick={onClick} className={'h-6 px-2 rounded-sm border text-[11px] font-mono inline-flex items-center gap-1 ' + t}>
      <Icon className="h-3 w-3" />
      {label}
    </button>
  );
}
