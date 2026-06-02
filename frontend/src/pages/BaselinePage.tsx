import { useEffect, useMemo, useState } from 'react';
import {
  Check,
  Clock,
  Cpu,
  Database,
  Eye,
  GitCompareArrows,
  Globe,
  Hash,
  Layers,
  RefreshCw,
  Shield,
  Users,
  Wrench,
} from 'lucide-react';
import {
  computeBaseline,
  getBaselineDeviations,
  getBaselineFeatures,
  getBaselineHistory,
  getBaselineSummary,
  getHostsCentral,
  resolveDeviation,
} from '../services/api';
import { ClassificationBadge } from '../components/ClassificationBadge';
import type {
  BaselineDeviation,
  BaselineFeature,
  BaselineSnapshot,
  BaselineSummary,
  HostCentralListItem,
} from '../types';

type Tab = 'summary' | 'known' | 'deviations' | 'patterns' | 'history';

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
  if (level === 'high')     return 'text-high';
  if (level === 'medium')   return 'text-warning';
  if (level === 'low')      return 'text-blue-400';
  return 'text-muted-foreground';
}

function riskBg(level: string) {
  if (level === 'critical') return 'bg-critical';
  if (level === 'high')     return 'bg-high';
  if (level === 'medium')   return 'bg-warning';
  if (level === 'low')      return 'bg-blue-500';
  return 'bg-muted-foreground/60';
}

function stateClass(d: BaselineDeviation) {
  const sev = severityFromRisk(d.risk_score);
  const map: Record<SeverityLevel, { dot: string; score: string; badge: string; label: string; circle: string }> = {
    critical: {
      dot:    'bg-critical',
      score:  'text-critical',
      badge:  'bg-critical/15 text-critical border-critical/50',
      label:  'CRITICAL',
      circle: 'bg-critical/20 text-critical border-critical/60',
    },
    high: {
      dot:    'bg-high',
      score:  'text-high',
      badge:  'bg-high/15 text-high border-high/50',
      label:  'HIGH',
      circle: 'bg-high/20 text-high border-high/60',
    },
    medium: {
      dot:    'bg-warning',
      score:  'text-warning',
      badge:  'bg-warning/15 text-warning border-warning/50',
      label:  'MEDIUM',
      circle: 'bg-warning/20 text-warning border-warning/60',
    },
    low: {
      dot:    'bg-blue-500',
      score:  'text-blue-400',
      badge:  'bg-blue-500/15 text-blue-400 border-blue-500/50',
      label:  'LOW',
      circle: 'bg-blue-500/20 text-blue-400 border-blue-500/60',
    },
    info: {
      dot:    'bg-muted-foreground/50',
      score:  'text-muted-foreground',
      badge:  'bg-muted/60 text-muted-foreground border-muted-foreground/25',
      label:  'INFO',
      circle: 'bg-muted/50 text-muted-foreground border-muted-foreground/40',
    },
  };
  return map[sev];
}

function typeChipClass(type: string): string {
  if (type === 'service_name' || type === 'service')
    return 'bg-orange-500/15 text-orange-400 border-orange-500/40';
  if (type === 'process')
    return 'bg-blue-500/15 text-blue-400 border-blue-500/40';
  if (type === 'user')
    return 'bg-purple-500/15 text-purple-400 border-purple-500/40';
  if (type === 'ip')
    return 'bg-cyan-500/15 text-cyan-400 border-cyan-500/40';
  if (type === 'event_id')
    return 'bg-yellow-500/15 text-yellow-500 border-yellow-500/40';
  if (type === 'event_family')
    return 'bg-emerald-500/15 text-emerald-400 border-emerald-500/40';
  return 'bg-muted/50 text-muted-foreground border-border/40';
}

function kindIcon(kind: string) {
  if (kind === 'process') return Cpu;
  if (kind === 'user') return Users;
  if (kind === 'service' || kind === 'service_name') return Wrench;
  if (kind === 'ip') return Globe;
  if (kind === 'event_id') return Hash;
  if (kind === 'event_family') return Layers;
  return GitCompareArrows;
}

function formatDate(s: string | null | undefined): string {
  if (!s) return '—';
  try {
    return new Date(s).toLocaleString('de-DE', { dateStyle: 'short', timeStyle: 'short' });
  } catch {
    return s;
  }
}

const TYPE_GROUPS = [
  { key: 'new_service',         label: 'New Services',          chip: 'bg-orange-500/20 text-orange-400 border-orange-500/50' },
  { key: 'new_process',         label: 'New Processes',         chip: 'bg-blue-500/20 text-blue-400 border-blue-500/50' },
  { key: 'new_user',            label: 'New Users',             chip: 'bg-purple-500/20 text-purple-400 border-purple-500/50' },
  { key: 'new_ip',              label: 'New IPs',               chip: 'bg-cyan-500/20 text-cyan-400 border-cyan-500/50' },
  { key: 'new_event_id',        label: 'Event ID Anomalies',    chip: 'bg-yellow-500/20 text-yellow-500 border-yellow-500/50' },
  { key: 'new_event_family',    label: 'New Event Families',    chip: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/50' },
  { key: 'volume_spike',        label: 'Volume Spikes',         chip: 'bg-red-500/20 text-red-400 border-red-500/50' },
  { key: 'suspicious_behavior', label: 'Suspicious Behavior',   chip: 'bg-critical/20 text-critical border-critical/50' },
];

function overallBadgeCls(level: SeverityLevel): string {
  if (level === 'critical') return 'bg-red-500/20 text-red-400 border-red-500/50';
  if (level === 'high')     return 'bg-orange-500/20 text-orange-400 border-orange-500/50';
  if (level === 'medium')   return 'bg-yellow-500/20 text-yellow-500 border-yellow-500/50';
  if (level === 'low')      return 'bg-blue-500/20 text-blue-400 border-blue-500/50';
  return 'bg-muted/40 text-muted-foreground border-muted-foreground/30';
}

function overallLabel(level: SeverityLevel): string {
  if (level === 'critical') return 'CRITICAL DEVIATION';
  if (level === 'high')     return 'HIGH DEVIATION';
  if (level === 'medium')   return 'MODERATE DEVIATION';
  if (level === 'low')      return 'SLIGHT DEVIATION';
  return 'INFORMATIONAL';
}

// ── Component ─────────────────────────────────────────────────────────────────

export function BaselinePage({ active, onSwitchTab }: BaselinePageProps) {
  const [hosts, setHosts] = useState<HostCentralListItem[]>([]);
  const [selectedHost, setSelectedHost] = useState<string | null>(null);
  const [deviations, setDeviations] = useState<BaselineDeviation[]>([]);
  const [summary, setSummary] = useState<BaselineSummary | null>(null);
  const [features, setFeatures] = useState<BaselineFeature[]>([]);
  const [historySnaps, setHistorySnaps] = useState<BaselineSnapshot[]>([]);
  const [selected, setSelected] = useState<BaselineDeviation | null>(null);
  const [loading, setLoading] = useState(false);
  const [loadingDev, setLoadingDev] = useState(false);
  const [search, setSearch] = useState('');
  const [computingBaseline, setComputingBaseline] = useState(false);
  const [acceptedIds, setAcceptedIds] = useState<Set<number>>(new Set());
  const [activeTab, setActiveTab] = useState<Tab>('deviations');
  const [hostSearch, setHostSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState<string | null>(null);
  const [knownSearch, setKnownSearch] = useState('');
  // Baseline candidate modal
  const [showBaselineModal, setShowBaselineModal] = useState(false);
  const [baselineReason, setBaselineReason] = useState('');
  const [baselineSubmitting, setBaselineSubmitting] = useState(false);
  const [baselineError, setBaselineError] = useState<string | null>(null);

  async function loadHostData(host: string) {
    setLoadingDev(true);
    setDeviations([]);
    setSummary(null);
    setFeatures([]);
    setHistorySnaps([]);
    setSelected(null);
    try {
      const [devs, sum, feats, hist] = await Promise.all([
        getBaselineDeviations(host, true),
        getBaselineSummary(host).catch(() => null),
        getBaselineFeatures(host).catch(() => [] as BaselineFeature[]),
        getBaselineHistory(host, 10).catch(() => [] as BaselineSnapshot[]),
      ]);
      setDeviations(devs);
      setSummary(sum);
      setFeatures(feats);
      setHistorySnaps(hist);
      if (devs.length > 0) setSelected(devs[0]);
    } finally {
      setLoadingDev(false);
    }
  }

  async function handleComputeBaseline() {
    if (!selectedHost) return;
    setComputingBaseline(true);
    try {
      await computeBaseline(selectedHost);
      await loadHostData(selectedHost);
    } catch (e) {
      console.error('Failed to compute baseline:', e);
    } finally {
      setComputingBaseline(false);
    }
  }

  async function handleAcceptAsBaseline() {
    if (!selected) return;
    // Open confirmation modal instead of acting immediately
    setBaselineReason('');
    setBaselineError(null);
    setShowBaselineModal(true);
  }

  async function handleConfirmBaselineCandidate() {
    if (!selected || !baselineReason.trim()) {
      setBaselineError('Please provide a reason for accepting this deviation as baseline.');
      return;
    }
    setBaselineSubmitting(true);
    setBaselineError(null);
    try {
      await resolveDeviation(selected.id);
      setAcceptedIds((prev) => new Set([...prev, selected.id]));
      const remaining = deviations.filter((d) => d.id !== selected.id && !acceptedIds.has(d.id));
      setSelected(remaining.length > 0 ? remaining[0] : null);
      setShowBaselineModal(false);
    } catch (e) {
      setBaselineError('Failed to create baseline candidate. Please try again.');
      console.error('Failed to resolve deviation:', e);
    } finally {
      setBaselineSubmitting(false);
    }
  }

  function handleInvestigate() {
    if (!selected) return;
    onSwitchTab('snipen', { host: selected.host });
  }

  async function handleResolve(d: BaselineDeviation) {
    try {
      await resolveDeviation(d.id);
      setAcceptedIds((prev) => new Set([...prev, d.id]));
      if (selected?.id === d.id) setSelected(null);
    } catch (e) {
      console.error('Failed to resolve deviation:', e);
    }
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
    void loadHostData(selectedHost);
    // eslint-disable-next-line react-hooks/exhaustive-deps
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

  const abnormal     = filtered.filter((d) => d.risk_score >= 80);
  const unusual      = filtered.filter((d) => d.risk_score >= 40 && d.risk_score < 80);
  const informational = filtered.filter((d) => d.risk_score < 40);
  void abnormal; void unusual; void informational; // kept for summary tab counts if needed

  const maxRisk   = useMemo(() => deviations.reduce((m, d) => Math.max(m, d.risk_score), 0), [deviations]);
  const overallSev = severityFromRisk(maxRisk);

  const activeGroups = useMemo(
    () => TYPE_GROUPS
      .map((g) => ({ ...g, items: filtered.filter((d) => d.deviation_type === g.key) }))
      .filter((g) => g.items.length > 0),
    [filtered],
  );

  const displayedGroups = typeFilter
    ? activeGroups.filter((g) => g.key === typeFilter)
    : activeGroups;

  const changeSummary = useMemo(
    () => ({
      services:  deviations.filter((d) => d.deviation_type === 'new_service').length,
      processes: deviations.filter((d) => d.deviation_type === 'new_process').length,
      users:     deviations.filter((d) => d.deviation_type === 'new_user').length,
      ips:       deviations.filter((d) => d.deviation_type === 'new_ip').length,
      event_ids: deviations.filter((d) => d.deviation_type === 'new_event_id').length,
      families:  deviations.filter((d) => d.deviation_type === 'new_event_family').length,
      spikes:    deviations.filter((d) => d.deviation_type === 'volume_spike').length,
      behaviors: deviations.filter((d) => d.deviation_type === 'suspicious_behavior').length,
      // Classification counts
      escalated:   deviations.filter((d) => d.final_classification === 'escalated').length,
      suspicious:  deviations.filter((d) => d.final_classification === 'known_but_suspicious').length,
      investigate: deviations.filter((d) => d.final_classification === 'needs_investigation').length,
      expected:    deviations.filter((d) => d.final_classification === 'expected_for_profile').length,
      flagged:   deviations.filter((d) => d.risk_score >= 40).length,
      total:     deviations.length,
    }),
    [deviations],
  );

  const featuresByType = useMemo(() => {
    const result: Record<string, BaselineFeature[]> = {};
    for (const f of features) {
      if (!result[f.feature_type]) result[f.feature_type] = [];
      result[f.feature_type].push(f);
    }
    return result;
  }, [features]);

  const knownCounts = useMemo(
    () => ({
      processes: featuresByType['process']?.length ?? 0,
      users:     featuresByType['user']?.length ?? 0,
      services:  featuresByType['service_name']?.length ?? 0,
      ips:       featuresByType['ip']?.length ?? 0,
      event_ids: featuresByType['event_id']?.length ?? 0,
      families:  featuresByType['event_family']?.length ?? 0,
    }),
    [featuresByType],
  );

  const hasSummary = summary !== null;
  const hasFeatures = features.length > 0;
  void hasFeatures;

  // Deviation keys for Known tab cross-reference
  const deviatingKeys = useMemo(
    () => new Set(deviations.filter((d) => !acceptedIds.has(d.id)).map((d) => d.feature_key)),
    [deviations, acceptedIds],
  );

  const KNOWN_GROUPS = [
    { type: 'process',      label: 'Processes',      chip: 'bg-blue-500/20 text-blue-400 border-blue-500/50' },
    { type: 'user',         label: 'Users',          chip: 'bg-purple-500/20 text-purple-400 border-purple-500/50' },
    { type: 'service_name', label: 'Services',       chip: 'bg-orange-500/20 text-orange-400 border-orange-500/50' },
    { type: 'ip',           label: 'IPs',            chip: 'bg-cyan-500/20 text-cyan-400 border-cyan-500/50' },
    { type: 'event_id',     label: 'Event IDs',      chip: 'bg-yellow-500/20 text-yellow-500 border-yellow-500/50' },
    { type: 'event_family', label: 'Event Families', chip: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/50' },
  ];

  const knownGroups = useMemo(() => {
    const q = knownSearch.toLowerCase();
    return KNOWN_GROUPS
      .map((g) => ({
        ...g,
        items: (featuresByType[g.type] ?? [])
          .filter((f) => !q || f.feature_key.toLowerCase().includes(q))
          .slice()
          .sort((a, b) => b.count_seen - a.count_seen),
      }))
      .filter((g) => g.items.length > 0);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [featuresByType, knownSearch]);

  const TAB_LABELS: Record<Tab, string> = {
    summary:    'Summary',
    known:      'Known',
    deviations: 'Deviations',
    patterns:   'Patterns',
    history:    'History',
  };
  const TAB_COUNTS: Partial<Record<Tab, number>> = {
    known:      features.length,
    deviations: deviations.length,
    patterns:   features.length,
    history:    historySnaps.length,
  };

  if (!active) return null;

  return (
    <div className="h-full grid grid-cols-[200px_1fr_360px] min-h-0">

      {/* ── Left: host list ─────────────────────────────────────────────── */}
      <aside className="border-r border-border bg-[var(--panel)] flex flex-col min-h-0">
        <div className="px-2 py-1.5 border-b border-border flex items-center gap-1">
          <input
            value={hostSearch}
            onChange={(e) => setHostSearch(e.target.value)}
            placeholder="hosts…"
            className="bg-transparent flex-1 outline-none text-[11px] font-mono placeholder:text-muted-foreground min-w-0"
          />
          <button
            onClick={() => selectedHost && void loadHostData(selectedHost)}
            className="h-5 w-5 rounded-sm hover:bg-accent inline-flex items-center justify-center shrink-0"
            title="Refresh"
          >
            <RefreshCw className="h-3 w-3 text-muted-foreground" />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto">
          {loading && (
            <div className="px-3 py-1 text-[11px] font-mono text-muted-foreground">loading…</div>
          )}
          {hosts.filter((h) => !hostSearch || h.host.toLowerCase().includes(hostSearch.toLowerCase())).map((h) => {
            const isSel = h.host === selectedHost;
            const risk = h.risk_score ?? 0;
            return (
              <button
                key={h.host}
                onClick={() => setSelectedHost(h.host)}
                className={
                  'w-full text-left px-2.5 py-1.5 border-b border-border/60 hover:bg-[var(--row-hover)] ' +
                  (isSel
                    ? 'bg-[var(--row-hover)] border-l-2 border-l-primary -ml-px pl-[9px]'
                    : '')
                }
              >
                <div className="text-[11.5px] font-mono truncate">{h.host}</div>
                <div className="text-[10px] font-mono text-muted-foreground">
                  risk{' '}
                  <span className={risk >= 80 ? 'text-critical' : risk >= 60 ? 'text-high' : risk >= 40 ? 'text-warning' : 'text-success'}>
                    {risk}
                  </span>
                </div>
              </button>
            );
          })}
        </div>

        {hasSummary && (
          <div className="px-2.5 py-1.5 border-t border-border text-[10px] font-mono text-muted-foreground">
            <div className="flex justify-between">{deviations.length} dev · <span className="text-critical">{changeSummary.flagged} flagged</span></div>
            <div className="text-muted-foreground/60">{summary!.total_events.toLocaleString()} events</div>
          </div>
        )}

        {selectedHost && (
          <div className="px-3 py-2 border-t border-border">
            <button
              onClick={() => void handleComputeBaseline()}
              disabled={computingBaseline}
              className="w-full h-7 rounded-sm border border-border hover:bg-accent text-[11.5px] font-mono inline-flex items-center justify-center gap-1 disabled:opacity-50"
            >
              <Database className={`h-3 w-3 ${computingBaseline ? 'animate-pulse text-primary' : ''}`} />
              {computingBaseline ? 'Computing…' : 'Compute Baseline'}
            </button>
          </div>
        )}
      </aside>

      {/* ── Center: Known State + tabs ──────────────────────────────────── */}
      <div className="flex flex-col min-h-0 border-r border-border">

        {/* Deviation summary banner */}
        {selectedHost && (
          <div className="shrink-0 px-3 py-2 border-b border-border bg-[var(--panel)] flex items-start gap-3">
            {deviations.length > 0 ? (
              <>
                <span className={`shrink-0 mt-0.5 inline-flex items-center h-[22px] px-2 rounded text-[10.5px] font-bold uppercase tracking-wider border ${overallBadgeCls(overallSev)}`}>
                  {overallLabel(overallSev)}
                </span>
                <div className="flex-1 text-[11px] font-mono text-muted-foreground min-w-0 space-y-0.5">
                  {changeSummary.services  > 0 && <div>▸ {changeSummary.services} new service{changeSummary.services  > 1 ? 's' : ''} not in baseline</div>}
                  {changeSummary.processes > 0 && <div>▸ {changeSummary.processes} new process{changeSummary.processes > 1 ? 'es' : ''} not in baseline</div>}
                  {changeSummary.users     > 0 && <div>▸ {changeSummary.users} new user{changeSummary.users     > 1 ? 's' : ''} detected</div>}
                  {changeSummary.ips       > 0 && <div>▸ {changeSummary.ips} new IP{changeSummary.ips       > 1 ? 's' : ''} seen</div>}
                  {changeSummary.event_ids > 0 && <div>▸ {changeSummary.event_ids} new event ID{changeSummary.event_ids > 1 ? 's' : ''} detected</div>}
                  {changeSummary.families  > 0 && <div>▸ {changeSummary.families} new event {changeSummary.families > 1 ? 'families' : 'family'} detected</div>}
                  {changeSummary.spikes    > 0 && <div>▸ {changeSummary.spikes} volume spike{changeSummary.spikes > 1 ? 's' : ''} detected</div>}
                </div>
              </>
            ) : (
              <span className="flex-1 text-[11px] font-mono text-success">✓ No deviations — system matches known baseline state</span>
            )}
            <div className="shrink-0 flex flex-col items-end gap-1 ml-auto">
              <button
                onClick={() => void handleComputeBaseline()}
                disabled={computingBaseline}
                className="h-6 px-2 rounded-sm border border-border hover:bg-accent text-[11px] font-mono inline-flex items-center gap-1 disabled:opacity-50"
              >
                <RefreshCw className={`h-3 w-3 ${computingBaseline ? 'animate-spin text-primary' : ''}`} />
                Recompute
              </button>
              {summary?.computed_at && (
                <span className="text-[9.5px] font-mono text-muted-foreground/50">{formatDate(summary.computed_at)}</span>
              )}
            </div>
          </div>
        )}

        {/* Tab bar */}
        <div className="shrink-0 border-b border-border bg-[var(--panel)] flex items-center px-3 h-8">
          {(['summary', 'known', 'deviations', 'patterns', 'history'] as Tab[]).map((t) => {
            const isActive = activeTab === t;
            const cnt = TAB_COUNTS[t];
            return (
              <button
                key={t}
                onClick={() => setActiveTab(t)}
                className={
                  'h-full px-3 text-[11.5px] font-mono border-b-2 transition-colors inline-flex items-center gap-1.5 ' +
                  (isActive
                    ? 'border-primary text-foreground'
                    : 'border-transparent text-muted-foreground hover:text-foreground')
                }
              >
                {TAB_LABELS[t]}
                {cnt != null && cnt > 0 && (
                  <span
                    className={
                      'text-[10px] px-1 rounded-sm ' +
                      (isActive ? 'bg-primary/20 text-primary' : 'bg-muted/60 text-muted-foreground')
                    }
                  >
                    {cnt}
                  </span>
                )}
              </button>
            );
          })}
          {loadingDev && (
            <span className="ml-auto text-[10.5px] font-mono text-muted-foreground animate-pulse">
              loading…
            </span>
          )}
        </div>

        {/* Tab content */}
        <div className="flex-1 min-h-0 overflow-y-auto">

          {/* ── SUMMARY TAB ── */}
          {activeTab === 'summary' && (
            <div>
              {/* Stats row */}
              {hasSummary && (
                <div className="px-3 py-1.5 border-b border-border flex items-center gap-4 text-[11px] font-mono">
                  <span className="text-muted-foreground">events <span className="text-foreground font-semibold">{summary!.total_events.toLocaleString()}</span></span>
                  <span className="text-muted-foreground">avg/day <span className="text-foreground font-semibold">{summary!.daily_avg_events.toFixed(0)}</span></span>
                  <span className="text-muted-foreground">high <span className={summary!.high_alerts > 0 ? 'text-warning font-semibold' : 'text-foreground font-semibold'}>{summary!.high_alerts}</span></span>
                  <span className="text-muted-foreground">window <span className="text-foreground font-semibold">{summary!.window_hours}h</span></span>
                </div>
              )}
              {/* Changes row */}
              {changeSummary.total > 0 && (
                <div className="px-3 py-1.5 border-b border-border flex items-center gap-3 flex-wrap text-[11px] font-mono">
                  <span className="text-muted-foreground shrink-0">new</span>
                  {changeSummary.services  > 0 && <ChipStat label="svc"     value={changeSummary.services}  tone="critical" />}
                  {changeSummary.processes > 0 && <ChipStat label="proc"    value={changeSummary.processes} tone="warning" />}
                  {changeSummary.users     > 0 && <ChipStat label="user"    value={changeSummary.users}     tone="warning" />}
                  {changeSummary.ips       > 0 && <ChipStat label="ip"      value={changeSummary.ips}       tone="info" />}
                  {changeSummary.event_ids > 0 && <ChipStat label="evid"    value={changeSummary.event_ids} tone="info" />}
                  {changeSummary.families  > 0 && <ChipStat label="fam"     value={changeSummary.families}  tone="info" />}
                  {changeSummary.spikes    > 0 && <ChipStat label="spike"   value={changeSummary.spikes}    tone="critical" />}
                  <span className="ml-auto text-muted-foreground">{changeSummary.flagged} flagged</span>
                </div>
              )}
              {/* Classification summary — answers: what needs action? */}
              {changeSummary.total > 0 && (changeSummary.escalated > 0 || changeSummary.suspicious > 0 || changeSummary.investigate > 0) && (
                <div className="px-3 py-1.5 border-b border-border flex items-center gap-2 flex-wrap bg-[var(--panel)]/50">
                  {changeSummary.escalated > 0 && (
                    <span className="inline-flex items-center gap-1 text-[10px] font-mono font-bold text-critical">
                      <span className="h-1.5 w-1.5 rounded-full bg-critical animate-pulse" />
                      {changeSummary.escalated} escalated
                    </span>
                  )}
                  {changeSummary.suspicious > 0 && (
                    <span className="inline-flex items-center gap-1 text-[10px] font-mono font-semibold text-warning">
                      <span className="h-1.5 w-1.5 rounded-full bg-warning" />
                      {changeSummary.suspicious} known·suspicious
                    </span>
                  )}
                  {changeSummary.investigate > 0 && (
                    <span className="inline-flex items-center gap-1 text-[10px] font-mono text-amber-400">
                      <span className="h-1.5 w-1.5 rounded-full bg-amber-500" />
                      {changeSummary.investigate} investigate
                    </span>
                  )}
                  {changeSummary.expected > 0 && (
                    <span className="inline-flex items-center gap-1 text-[10px] font-mono text-blue-400">
                      {changeSummary.expected} profile-expected
                    </span>
                  )}
                </div>
              )}
              {/* Top risk deviations */}
              {summary?.top_deviations && summary.top_deviations.length > 0 && (
                <table className="w-full text-[11.5px] font-mono">
                  <thead className="border-b border-border text-[10px] uppercase tracking-wider text-muted-foreground">
                    <tr>
                      <th className="px-3 py-1 text-right font-medium w-[50px]">score</th>
                      <th className="px-3 py-1 text-left font-medium">name</th>
                      <th className="px-3 py-1 text-left font-medium w-[100px]">type</th>
                    </tr>
                  </thead>
                  <tbody>
                    {summary.top_deviations.map((d, i) => {
                      const score = d.risk_score as number;
                      const sc = score >= 75 ? 'text-critical' : score >= 50 ? 'text-warning' : 'text-muted-foreground';
                      return (
                        <tr key={i} className="border-b border-border/60">
                          <td className={`px-3 py-1 text-right font-semibold ${sc}`}>{score}</td>
                          <td className="px-3 py-1 truncate max-w-0">{d.key as string}</td>
                          <td className="px-3 py-1 text-muted-foreground">{d.type as string}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              )}
              {changeSummary.total === 0 && hasSummary && !loadingDev && (
                <div className="px-3 py-4 text-[11px] font-mono text-muted-foreground">
                  no deviations — system matches known state
                </div>
              )}
              {!hasSummary && !loadingDev && (
                <div className="px-3 py-4 text-[11px] font-mono text-muted-foreground">
                  {selectedHost ? 'no baseline — run Compute Baseline' : 'select a host →'}
                </div>
              )}
            </div>
          )}

          {/* ── KNOWN TAB ── */}
          {activeTab === 'known' && (
            <div>
              {/* Sticky search */}
              <div className="sticky top-0 z-10 bg-[var(--panel)] border-b border-border px-3 py-1.5 flex items-center gap-2">
                <Shield className="h-3 w-3 text-primary/60 shrink-0" />
                <input
                  value={knownSearch}
                  onChange={(e) => setKnownSearch(e.target.value)}
                  placeholder="search known baseline…"
                  className="bg-transparent flex-1 outline-none text-[11.5px] font-mono placeholder:text-muted-foreground"
                />
                {features.length > 0 && (
                  <span className="text-[10.5px] font-mono text-muted-foreground shrink-0">{features.length} known</span>
                )}
              </div>

              {knownGroups.length === 0 && !loadingDev && (
                <div className="px-3 py-4 text-[11px] font-mono text-muted-foreground">
                  {selectedHost ? 'no baseline data — run Compute Baseline' : 'select a host →'}
                </div>
              )}

              {knownGroups.map((g) => (
                <div key={g.type}>
                  {/* Group header */}
                  <div className="px-3 py-1 border-b border-border flex items-center gap-2 bg-[var(--panel)]/60 sticky top-[34px] z-[9]">
                    <span className={`inline-flex items-center h-[18px] px-1.5 rounded-sm text-[9.5px] font-mono font-semibold border ${g.chip}`}>
                      {g.label}
                    </span>
                    <span className="text-[10px] font-mono text-muted-foreground">{g.items.length} known</span>
                  </div>
                  {/* Table */}
                  <table className="w-full text-[11.5px] font-mono">
                    <thead className="border-b border-border/60 text-[10px] uppercase tracking-wider text-muted-foreground">
                      <tr>
                        <th className="px-3 py-1 text-left font-medium">name</th>
                        <th className="px-3 py-1 text-left font-medium w-[90px]">type</th>
                        <th className="px-3 py-1 text-right font-medium w-[60px]">seen</th>
                        <th className="px-3 py-1 text-right font-medium w-[70px]">stable</th>
                        <th className="px-3 py-1 text-right font-medium w-[110px]">last seen</th>
                      </tr>
                    </thead>
                    <tbody>
                      {g.items.map((f) => {
                        const isDeviating = deviatingKeys.has(f.feature_key);
                        const stab = Math.round(f.stability_score * 100);
                        const stabCls = stab >= 90 ? 'text-success' : stab >= 70 ? 'text-warning' : 'text-muted-foreground';
                        return (
                          <tr
                            key={f.id}
                            className={`border-b border-border/60 hover:bg-[var(--row-hover)] ${
                              isDeviating ? 'bg-warning/[0.05]' : ''
                            }`}
                          >
                            <td className="px-3 py-1 min-w-0">
                              <span className="flex items-center gap-1.5">
                                <span className="truncate">{f.feature_key}</span>
                                {isDeviating && (
                                  <span className="shrink-0 inline-flex items-center h-[14px] px-1 rounded-sm text-[9px] font-mono font-semibold border bg-warning/20 text-warning border-warning/50">
                                    ⚠ deviating
                                  </span>
                                )}
                              </span>
                            </td>
                            <td className="px-3 py-1">
                              <span className={`inline-flex items-center h-[16px] px-1.5 rounded-sm text-[9.5px] font-mono border ${typeChipClass(f.feature_type)}`}>
                                {f.feature_type}
                              </span>
                            </td>
                            <td className="px-3 py-1 text-right text-muted-foreground">{f.count_seen}x</td>
                            <td className={`px-3 py-1 text-right font-semibold ${stabCls}`}>{stab}%</td>
                            <td className="px-3 py-1 text-right text-muted-foreground/70">{formatDate(f.last_seen)}</td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              ))}
            </div>
          )}
          {activeTab === 'deviations' && (
            <div>
              {/* Sticky header: search + filter chips */}
              <div className="sticky top-0 z-10 bg-[var(--panel)] border-b border-border">
                <div className="px-3 py-1.5 flex items-center gap-2 border-b border-border/60">
                  <input
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                    placeholder="filter deviations…"
                    className="bg-transparent flex-1 outline-none text-[11.5px] font-mono placeholder:text-muted-foreground"
                  />
                  {!loadingDev && deviations.length > 0 && (
                    <span className="text-[10.5px] font-mono text-muted-foreground shrink-0">
                      {filtered.length} of {deviations.length}
                    </span>
                  )}
                </div>
                {activeGroups.length > 0 && (
                  <div className="px-3 py-1.5 flex flex-wrap gap-1.5">
                    {activeGroups.map((g) => (
                      <button
                        key={g.key}
                        onClick={() => setTypeFilter(typeFilter === g.key ? null : g.key)}
                        className={`inline-flex items-center h-[22px] px-2 rounded-sm text-[10.5px] font-mono border transition-colors ${g.chip} ${typeFilter && typeFilter !== g.key ? 'opacity-40' : ''}`}
                      >
                        {g.items.length} {g.label}
                      </button>
                    ))}
                  </div>
                )}
              </div>

              {/* Grouped card rows */}
              {displayedGroups.map((g) => (
                <div key={g.key}>
                  {/* Group header pill */}
                  <div className="px-3 py-1 border-b border-border flex items-center gap-2 bg-[var(--panel)]/60">
                    <span className={`inline-flex items-center h-[18px] px-1.5 rounded-sm text-[9.5px] font-mono font-semibold border ${g.chip}`}>
                      {g.label}
                    </span>
                    <span className="text-[10px] font-mono text-muted-foreground">{g.items.length}</span>
                  </div>
                  {/* Rows */}
                  {g.items.map((d) => {
                    const isSel = selected?.id === d.id;
                    const sc    = stateClass(d);
                    return (
                      <div
                        key={d.id}
                        onClick={() => setSelected(d)}
                        className={`px-3 py-2 border-b border-border/60 cursor-pointer hover:bg-[var(--row-hover)] flex items-start gap-3 ${
                          isSel ? 'bg-[var(--row-hover)] border-l-2 border-l-primary' : ''
                        }`}
                      >
                        {/* Score circle */}
                        <span className={`shrink-0 mt-0.5 inline-flex h-[30px] w-[30px] rounded-full items-center justify-center text-[10.5px] font-bold border ${sc.circle}`}>
                          {d.risk_score}
                        </span>
                        {/* Info */}
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-1.5 flex-wrap min-w-0">
                            <span className="text-[12px] font-semibold font-mono truncate">{d.feature_key}</span>
                            <span className={`shrink-0 inline-flex items-center h-[15px] px-1 rounded-sm text-[9px] font-mono font-semibold uppercase tracking-wider border ${sc.badge}`}>
                              {sc.label}
                            </span>
                            <span className={`shrink-0 inline-flex items-center h-[15px] px-1 rounded-sm text-[9px] font-mono border ${typeChipClass(d.feature_type)}`}>
                              {d.feature_type}
                            </span>
                            <ClassificationBadge value={d.final_classification ?? 'unknown'} />
                            {d.details?.is_known === true && (
                              <span className="shrink-0 inline-flex items-center h-[15px] px-1 rounded-sm text-[9px] font-mono border bg-success/10 text-success border-success/30">
                                KNOWN
                              </span>
                            )}
                          </div>
                          <div className="text-[11px] font-mono text-muted-foreground mt-0.5 truncate">{d.reason}</div>
                          {Array.isArray(d.details?.behavior_flags) && (d.details.behavior_flags as string[]).length > 0 && (
                            <div className="flex flex-wrap gap-1 mt-1">
                              {(d.details.behavior_flags as string[]).map((flag) => (
                                <span key={flag} className="inline-flex items-center h-[15px] px-1.5 rounded-sm text-[9px] font-mono font-bold tracking-wide bg-critical/15 text-critical border border-critical/30">
                                  ⚠ {flag}
                                </span>
                              ))}
                            </div>
                          )}
                          <div className="text-[10px] font-mono text-muted-foreground/60">
                            {formatDate(d.detected_at)} · confidence {Math.round(d.confidence * 100)}%
                          </div>
                        </div>
                        {/* Resolve button */}
                        <button
                          onClick={(e) => { e.stopPropagation(); void handleResolve(d); }}
                          className="shrink-0 self-center h-6 px-2 rounded-sm border border-border hover:bg-success/10 hover:border-success/40 hover:text-success text-[10.5px] font-mono transition-colors"
                        >
                          Resolve
                        </button>
                      </div>
                    );
                  })}
                </div>
              ))}
              {filtered.length === 0 && !loadingDev && (
                <div className="px-3 py-6 text-[11.5px] font-mono text-muted-foreground">
                  {selectedHost ? 'no deviations found' : 'select a host →'}
                </div>
              )}
            </div>
          )}

          {/* ── PATTERNS TAB ── */}
          {activeTab === 'patterns' && (
            <div>
              {features.length === 0 && !loadingDev && (
                <div className="px-3 py-6 text-center text-[11.5px] font-mono text-muted-foreground">
                  {selectedHost ? 'no pattern data — compute a baseline first' : 'select a host →'}
                </div>
              )}
              {(
                [
                  ['process',      'Processes', Cpu],
                  ['user',         'Users',     Users],
                  ['service_name', 'Services',  Wrench],
                  ['ip',           'IPs',       Globe],
                  ['event_id',     'Event IDs', Hash],
                  ['event_family', 'Families',  Layers],
                ] as [string, string, React.ComponentType<{ className?: string }>][]
              ).map(([type, label, Icon]) => {
                const items = featuresByType[type] ?? [];
                if (items.length === 0) return null;
                return (
                  <div key={type}>
                    <div className="px-3 py-2 border-b border-border bg-[var(--panel)] flex items-center gap-2 sticky top-0 z-10">
                      <Icon className="h-3.5 w-3.5 text-muted-foreground" />
                      <span className="text-[12px] font-semibold tracking-wide">{label.toUpperCase()}</span>
                      <span className="text-[10.5px] font-mono text-muted-foreground">{items.length} known</span>
                    </div>
                    <div className="px-3 py-2 flex flex-wrap gap-1.5 border-b border-border/60">
                      {items.slice(0, 50).map((f) => (
                        <span
                          key={f.id}
                          className="inline-flex items-center h-[18px] px-1.5 rounded-sm text-[10px] font-mono bg-muted/60 text-muted-foreground border border-border/40"
                          title={`Seen ${f.count_seen}× · stability ${Math.round(f.stability_score * 100)}%`}
                        >
                          {f.feature_key}
                        </span>
                      ))}
                      {items.length > 50 && (
                        <span className="text-[10px] font-mono text-muted-foreground self-center">
                          +{items.length - 50} more
                        </span>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {/* ── HISTORY TAB ── */}
          {activeTab === 'history' && (
            <div>
              {historySnaps.length === 0 && !loadingDev && (
                <div className="px-3 py-6 text-center text-[11.5px] font-mono text-muted-foreground">
                  {selectedHost ? 'no history available' : 'select a host →'}
                </div>
              )}
              {historySnaps.map((snap) => (
                <div
                  key={snap.id}
                  className="px-3 py-2.5 border-b border-border/60 hover:bg-[var(--row-hover)] text-[11.5px] font-mono"
                >
                  <div className="flex items-center gap-3">
                    <Clock className="h-3 w-3 text-muted-foreground shrink-0" />
                    <span className="flex-1 text-foreground">{formatDate(snap.computed_at)}</span>
                    <span className="text-muted-foreground">{snap.total_events.toLocaleString()} events</span>
                    {snap.deviation_count > 0 && (
                      <span className="text-warning">{snap.deviation_count} dev.</span>
                    )}
                  </div>
                  <div className="mt-0.5 text-[10.5px] text-muted-foreground pl-5">
                    window {snap.window_hours}h · {snap.high_alerts} high alerts
                    {snap.top_processes.length > 0 && <> · {snap.top_processes.length} top processes</>}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* ── Right: detail panel ─────────────────────────────────────────── */}
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
              <KV k="host"     v={selected.host} />
              <KV k="kind"     v={selected.feature_type} />
              <KV k="name"     v={selected.feature_key} />
              <KV k="type"     v={selected.deviation_type} />
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
                {/* Behavior flags — shown prominently when present */}
                {Array.isArray(selected.details?.behavior_flags) && (selected.details.behavior_flags as string[]).length > 0 && (
                  <div className="mb-2">
                    <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground mb-1">Behavior Flags</div>
                    <div className="flex flex-wrap gap-1">
                      {(selected.details.behavior_flags as string[]).map((flag) => (
                        <span key={flag} className="inline-flex items-center h-[17px] px-1.5 rounded-sm text-[9.5px] font-mono font-bold bg-critical/15 text-critical border border-critical/30">
                          ⚠ {flag}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
                {/* is_known indicator */}
                {'is_known' in (selected.details ?? {}) && (
                  <div className="mb-2 text-[11px] font-mono">
                    Entity status:{' '}
                    {selected.details.is_known === true ? (
                      <span className="text-success font-semibold">KNOWN (in baseline)</span>
                    ) : (
                      <span className="text-warning font-semibold">NEW (not in baseline)</span>
                    )}
                  </div>
                )}
                {/* Other raw details (excluding known display fields) */}
                {(() => {
                  const rest = Object.fromEntries(
                    Object.entries(selected.details ?? {}).filter(([k]) => k !== 'behavior_flags' && k !== 'is_known' && k !== 'behavior_score_delta')
                  );
                  return Object.keys(rest).length > 0 ? (
                    <pre className="text-[11px] font-mono whitespace-pre-wrap leading-snug text-muted-foreground">
                      {JSON.stringify(rest, null, 2)}
                    </pre>
                  ) : null;
                })()}
              </Sec>
            )}

            <Sec title="Actions">
              <div className="flex flex-wrap gap-1.5">
                <ActBtn icon={Check} label="Create Baseline Candidate" tone="success" onClick={() => void handleAcceptAsBaseline()} />
                <ActBtn icon={Eye} label="Investigate" onClick={handleInvestigate} />
              </div>
            </Sec>
          </div>
        ) : (
          <div className="flex-1 grid place-items-center text-[11.5px] font-mono text-muted-foreground">
            select deviation →
          </div>
        )}
      </aside>

      {/* ── Baseline Candidate Confirmation Modal ─────────────────────────── */}
      {showBaselineModal && selected && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
          <div className="w-[440px] rounded-lg border border-border bg-[var(--panel)] shadow-2xl">
            <div className="flex items-center gap-2 border-b border-border px-4 py-3">
              <Shield className="h-4 w-4 text-warning" />
              <p className="text-[13px] font-semibold text-foreground">Create Baseline Candidate</p>
            </div>
            <div className="px-4 py-3 space-y-3">
              <div className="rounded p-2 text-[11.5px] border border-warning/30 bg-warning/8 text-warning/90">
                <span className="font-semibold">Warning:</span> Accepting a deviation as baseline marks it as
                expected behaviour for this host. This action is audited and requires a justification.
              </div>
              <div>
                <p className="text-[11px] text-muted-foreground mb-1">Deviation</p>
                <p className="text-[12px] font-mono text-foreground truncate">{selected.feature_key}</p>
                <p className="text-[11px] text-muted-foreground mt-0.5">{selected.reason}</p>
              </div>
              <div>
                <label className="text-[11px] text-muted-foreground block mb-1">
                  Reason / Justification <span className="text-critical">*</span>
                </label>
                <textarea
                  value={baselineReason}
                  onChange={(e) => { setBaselineReason(e.target.value); setBaselineError(null); }}
                  placeholder="e.g. Approved change after CAB review #2024-001, confirmed legitimate service"
                  rows={3}
                  className="w-full rounded-sm border border-border bg-[var(--bg)] text-[11.5px] font-mono px-2 py-1 outline-none focus:border-primary resize-none placeholder:text-muted-foreground/50"
                />
              </div>
              {baselineError && (
                <p className="text-[11px] text-critical">{baselineError}</p>
              )}
            </div>
            <div className="flex justify-end gap-2 border-t border-border px-4 py-2.5">
              <button
                onClick={() => setShowBaselineModal(false)}
                disabled={baselineSubmitting}
                className="h-7 px-3 rounded-sm border border-border text-[11.5px] font-mono hover:bg-accent disabled:opacity-50"
              >
                Cancel
              </button>
              <button
                onClick={() => void handleConfirmBaselineCandidate()}
                disabled={baselineSubmitting || !baselineReason.trim()}
                className="h-7 px-3 rounded-sm border border-success/50 bg-success/10 text-success text-[11.5px] font-mono hover:bg-success/20 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {baselineSubmitting ? 'Submitting…' : 'Confirm Baseline Candidate'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Sub-components ────────────────────────────────────────────────────────────

function KnownPill({ label, value }: { label: string; value: number }) {
  return (
    <span className="text-muted-foreground">
      {label} <span className={value > 0 ? 'text-foreground font-semibold' : 'text-muted-foreground/40'}>{value}</span>
    </span>
  );
}

function Header({
  title: _t,
  sub: _s,
  tone: _tone,
  icon: _icon,
}: {
  title: string;
  sub: string;
  tone: 'success' | 'critical' | 'warning';
  icon: React.ComponentType<{ className?: string }>;
}) {
  // retained for potential future use
  void _t; void _s; void _tone; void _icon;
  return null;
}

function ItemTable({
  items: _items,
  onSelect: _onSelect,
  selected: _selected,
}: {
  items: BaselineDeviation[];
  onSelect: (d: BaselineDeviation) => void;
  selected: BaselineDeviation | null;
}) {
  // retained for potential future use
  void _items; void _onSelect; void _selected;
  return null;
}

function StateBadge({ deviation: d }: { deviation: BaselineDeviation }) {
  const sc = stateClass(d);
  return (
    <span className={'inline-flex items-center h-[18px] px-1.5 rounded-sm text-[10px] font-mono uppercase tracking-wider border ' + sc.badge}>
      {sc.label}
    </span>
  );
}

function Sec({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="px-3 py-2 border-b border-border">
      <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground mb-1.5">{title}</div>
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
  const t = tone === 'success' ? 'border-success/40 hover:bg-success/10 text-success' : 'border-border hover:bg-accent text-foreground';
  return (
    <button onClick={onClick} className={`h-6 px-2 rounded-sm border text-[11px] font-mono inline-flex items-center gap-1 ${t}`}>
      <Icon className="h-3 w-3" />
      {label}
    </button>
  );
}

function ChipStat({ label, value, tone }: { label: string; value: number; tone: 'critical' | 'warning' | 'info' }) {
  const c =
    tone === 'critical' ? 'text-critical' :
    tone === 'warning'  ? 'text-warning'  : 'text-[var(--soc-primary,theme(colors.blue.400))]';
  return (
    <span className="text-[10.5px] font-mono text-muted-foreground">
      {label} <span className={`font-semibold ${c}`}>{value}</span>
    </span>
  );
}
