import { useEffect, useMemo, useRef, useState } from 'react';
import {
  AlertTriangle,
  ArrowLeft,
  BarChart2,
  CheckCircle,
  ChevronRight,
  Crosshair,
  Database,
  RefreshCw,
  Shield,
  UserCog,
  Wifi,
  WifiOff,
  X,
} from 'lucide-react';
import {
  computeBaseline,
  getBaselineDeviations,
  getBaselineFeatures,
  getBaselineSummary,
  getHostProfileAssignment,
  getProfiles,
  removeHostProfileAssignment,
  setHostProfileAssignment,
} from '../services/api';
import { ClassificationBadge } from '../components/ClassificationBadge';
import type {
  BaselineDeviation,
  BaselineFeature,
  BaselineSummary,
  HostCentralListItem,
  HostProfile,
  HostProfileAssignment,
} from '../types';

type HostOverviewPageProps = {
  host: string;
  hostData?: HostCentralListItem | null;
  onBack: () => void;
  onGoBaseline: (host: string) => void;
  onGoSnipen: (host: string) => void;
  onGoFullScan: () => void;
};

// ── helpers ────────────────────────────────────────────────────────────────────

function riskColor(r: number) {
  if (r >= 80) return 'text-critical';
  if (r >= 60) return 'text-high';
  if (r >= 40) return 'text-warning';
  if (r >= 20) return 'text-blue-400';
  return 'text-success';
}
function riskBadgeCls(r: number) {
  if (r >= 80) return 'bg-critical/20 text-critical border-critical/50';
  if (r >= 60) return 'bg-high/20 text-high border-high/50';
  if (r >= 40) return 'bg-warning/20 text-warning border-warning/50';
  if (r >= 20) return 'bg-blue-500/20 text-blue-400 border-blue-500/40';
  return 'bg-success/20 text-success border-success/40';
}
function riskLabel(r: number) {
  if (r >= 80) return 'CRITICAL';
  if (r >= 60) return 'HIGH';
  if (r >= 40) return 'MODERATE';
  if (r >= 20) return 'LOW';
  return 'NORMAL';
}

function devTypeLabel(dt: string): string {
  switch (dt) {
    case 'new_service':      return 'New Service';
    case 'new_process':      return 'New Process';
    case 'new_user':         return 'New User';
    case 'new_ip':           return 'New IP';
    case 'new_event_id':     return 'New Event';
    case 'new_event_family': return 'New Event Family';
    case 'volume_spike':     return 'Volume Spike';
    default: return dt.replace(/_/g, ' ');
  }
}

function devTypeChipCls(dt: string): string {
  switch (dt) {
    case 'new_service':      return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
    case 'new_process':      return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
    case 'new_user':         return 'bg-purple-500/20 text-purple-400 border-purple-500/30';
    case 'new_ip':           return 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30';
    case 'new_event_id':     return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
    case 'new_event_family': return 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30';
    case 'volume_spike':     return 'bg-critical/20 text-critical border-critical/30';
    default:                 return 'bg-muted/40 text-muted-foreground border-border';
  }
}

function devLeftBar(r: number): string {
  if (r >= 80) return 'bg-critical';
  if (r >= 60) return 'bg-high';
  if (r >= 40) return 'bg-warning';
  return 'bg-blue-500';
}

function fmtShort(s: string | null | undefined): string {
  if (!s) return '—';
  try { return new Date(s).toLocaleString('de-DE', { dateStyle: 'short', timeStyle: 'short' }); }
  catch { return s; }
}

function fmtTimeOnly(s: string | null | undefined): string {
  if (!s) return '';
  try {
    const d = new Date(s);
    const today = new Date();
    if (d.toDateString() === today.toDateString()) {
      return d.toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' });
    }
    return d.toLocaleDateString('de-DE', { day: '2-digit', month: '2-digit' }) + ' ' +
           d.toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' });
  } catch { return ''; }
}

// human-readable activity line for a deviation
function activityLabel(d: BaselineDeviation): string {
  switch (d.deviation_type) {
    case 'new_event_id':
      return `Event ${d.feature_key}${d.details?.event_family ? ' (' + String(d.details.event_family) + ')' : ''}`;
    case 'new_event_family':
      return `Event family: ${d.feature_key}`;
    case 'new_process':
      return `Process: ${d.feature_key}`;
    case 'new_service':
      return `Service: ${d.feature_key}`;
    case 'new_user':
      return `User: ${d.feature_key}`;
    case 'new_ip':
      return `IP: ${d.feature_key}`;
    case 'volume_spike':
      return `Volume spike${d.details?.ratio ? ' ×' + Number(d.details.ratio).toFixed(1) : ''}`;
    default:
      return d.feature_key;
  }
}

// ── sub-components ─────────────────────────────────────────────────────────────

function ActionBtn({
  icon: Icon,
  label,
  sub,
  badge,
  primary,
  onClick,
}: {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  sub: string;
  badge?: number | null;
  primary?: boolean;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className={`flex-1 min-w-0 rounded-sm border px-3 py-2.5 flex items-center gap-2.5 transition-colors text-left group ${
        primary
          ? 'border-primary/60 bg-primary/5 hover:bg-primary/12'
          : 'border-border hover:bg-accent'
      }`}
    >
      <Icon className={`h-4 w-4 shrink-0 ${primary ? 'text-primary' : 'text-muted-foreground'}`} />
      <div className="flex-1 min-w-0">
        <div className={`text-[12px] font-semibold font-mono ${primary ? 'text-primary' : 'text-foreground'}`}>{label}</div>
        <div className="text-[9.5px] font-mono text-muted-foreground truncate">{sub}</div>
      </div>
      {badge != null && badge > 0 && (
        <span className="shrink-0 h-[18px] min-w-[20px] px-1 rounded-sm bg-critical/20 text-critical text-[10px] font-mono font-bold inline-flex items-center justify-center">
          {badge}
        </span>
      )}
      <ChevronRight className="h-3 w-3 shrink-0 text-muted-foreground/30 group-hover:text-muted-foreground/60" />
    </button>
  );
}

// ── main component ─────────────────────────────────────────────────────────────

export function HostOverviewPage({
  host,
  hostData,
  onBack,
  onGoBaseline,
  onGoSnipen,
  onGoFullScan,
}: HostOverviewPageProps) {
  const [summary, setSummary]         = useState<BaselineSummary | null>(null);
  const [deviations, setDeviations]   = useState<BaselineDeviation[]>([]);
  const [features, setFeatures]       = useState<BaselineFeature[]>([]);
  const [loading, setLoading]         = useState(true);
  const [recomputing, setRecomputing] = useState(false);

  // ── Profile picker state ──────────────────────────────────────────────────
  const [assignment, setAssignment]       = useState<HostProfileAssignment | null>(null);
  const [profiles, setProfiles]           = useState<HostProfile[]>([]);
  const [pickerOpen, setPickerOpen]       = useState(false);
  const [savingProfile, setSavingProfile] = useState(false);
  const pickerRef                         = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!pickerOpen) return;
    function onOutside(e: MouseEvent) {
      if (pickerRef.current && !pickerRef.current.contains(e.target as Node)) {
        setPickerOpen(false);
      }
    }
    document.addEventListener('mousedown', onOutside);
    return () => document.removeEventListener('mousedown', onOutside);
  }, [pickerOpen]);

  async function load() {
    setLoading(true);
    try {
      const [sum, devs, feats, asgn, profs] = await Promise.all([
        getBaselineSummary(host).catch(() => null),
        getBaselineDeviations(host, true).catch(() => [] as BaselineDeviation[]),
        getBaselineFeatures(host).catch(() => [] as BaselineFeature[]),
        getHostProfileAssignment(host).catch(() => null),
        getProfiles().catch(() => [] as HostProfile[]),
      ]);
      setSummary(sum);
      setDeviations(devs);
      setFeatures(feats);
      setAssignment(asgn);
      setProfiles(profs);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { void load(); }, [host]); // eslint-disable-line react-hooks/exhaustive-deps

  async function handleRecompute() {
    setRecomputing(true);
    try { await computeBaseline(host); await load(); }
    catch (e) { console.error('recompute failed:', e); }
    finally { setRecomputing(false); }
  }

  async function handleAssignProfile(profileId: number | null) {
    setSavingProfile(true);
    setPickerOpen(false);
    try {
      if (profileId === null) {
        await removeHostProfileAssignment(host);
        setAssignment(null);
      } else {
        const result = await setHostProfileAssignment(host, profileId);
        setAssignment(result);
      }
    } catch (e) {
      console.error('profile assign failed:', e);
    } finally {
      setSavingProfile(false);
    }
  }

  // ── derived ──────────────────────────────────────────────────────────────────

  // Top deviation = highest risk score
  const topDev = useMemo(
    () => deviations.length > 0
      ? [...deviations].sort((a, b) => b.risk_score - a.risk_score)[0]
      : null,
    [deviations],
  );

  const counts = useMemo(() => ({
    services:  deviations.filter((d) => d.deviation_type === 'new_service').length,
    processes: deviations.filter((d) => d.deviation_type === 'new_process').length,
    users:     deviations.filter((d) => d.deviation_type === 'new_user').length,
    ips:       deviations.filter((d) => d.deviation_type === 'new_ip').length,
    event_ids: deviations.filter((d) => d.deviation_type === 'new_event_id').length,
    families:  deviations.filter((d) => d.deviation_type === 'new_event_family').length,
    spikes:    deviations.filter((d) => d.deviation_type === 'volume_spike').length,
  }), [deviations]);

  const knownCounts = useMemo(() => ({
    processes: features.filter((f) => f.feature_type === 'process').length,
    users:     features.filter((f) => f.feature_type === 'user').length,
    services:  features.filter((f) => f.feature_type === 'service_name').length,
    ips:       features.filter((f) => f.feature_type === 'ip').length,
  }), [features]);

  const newEntityCount = counts.services + counts.processes + counts.users +
                         counts.ips + counts.event_ids + counts.families;

  const derivedRisk = useMemo(() => {
    if (hostData?.risk_score != null && hostData.risk_score > 0) return hostData.risk_score;
    if (deviations.length === 0) return 0;
    return Math.max(...deviations.map((d) => d.risk_score));
  }, [hostData, deviations]);

  // Secondary list — top 8 after topDev
  const secondaryDevs = useMemo(() => {
    if (!topDev) return deviations.slice(0, 8);
    return deviations
      .filter((d) => d.id !== topDev.id)
      .sort((a, b) => b.risk_score - a.risk_score)
      .slice(0, 8);
  }, [deviations, topDev]);

  const platform = (hostData?.platforms ?? [])[0] ?? null;
  const isOnline = hostData?.status === 'online';
  const hasData  = !loading;

  return (
    <div className="h-full flex flex-col min-h-0 overflow-hidden bg-[var(--background)]">

      {/* ━━━ 1. HEADER ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */}
      <div className="shrink-0 border-b border-border bg-[var(--panel)] px-4 py-2 flex items-center gap-3">
        <button onClick={onBack} className="h-6 w-6 rounded-sm hover:bg-accent inline-flex items-center justify-center shrink-0">
          <ArrowLeft className="h-3.5 w-3.5 text-muted-foreground" />
        </button>
        <span className="text-[15px] font-bold font-mono">{host}</span>
        {platform && (
          <span className="h-[17px] px-1.5 rounded-sm bg-muted/60 text-[9px] font-mono text-muted-foreground uppercase tracking-wider inline-flex items-center shrink-0">
            {platform}
          </span>
        )}
        {hostData?.ip && (
          <span className="text-[11px] font-mono text-muted-foreground/60 shrink-0">{hostData.ip}</span>
        )}
        {hostData && (
          <span className="inline-flex items-center gap-1 text-[10.5px] font-mono shrink-0">
            {isOnline ? <Wifi className="h-3 w-3 text-success" /> : <WifiOff className="h-3 w-3 text-muted-foreground/40" />}
            <span className={isOnline ? 'text-success' : 'text-muted-foreground/40'}>{isOnline ? 'online' : 'offline'}</span>
          </span>
        )}
        <div className="flex items-center gap-1.5">
          <span className={`text-[17px] font-bold font-mono tabular-nums leading-none ${riskColor(derivedRisk)}`}>{derivedRisk}</span>
          <span className={`inline-flex items-center h-[17px] px-1.5 rounded-sm border text-[9px] font-mono font-bold uppercase tracking-wider ${riskBadgeCls(derivedRisk)}`}>
            {riskLabel(derivedRisk)}
          </span>
        </div>
        <div className="flex-1" />
        {hostData?.last_activity && (
          <span className="text-[10px] font-mono text-muted-foreground/50">last seen {fmtShort(hostData.last_activity)}</span>
        )}
        {/* Profile badge + picker trigger */}
        <div className="relative" ref={pickerRef}>
          <button
            onClick={() => setPickerOpen((o) => !o)}
            disabled={savingProfile}
            title="Change host profile"
            className={`h-6 px-2 rounded-sm border text-[10.5px] font-mono inline-flex items-center gap-1.5 transition-colors disabled:opacity-40 ${
              assignment
                ? 'border-primary/40 bg-primary/10 text-primary hover:bg-primary/20'
                : 'border-border hover:bg-accent text-muted-foreground'
            }`}
          >
            <UserCog className="h-3 w-3 shrink-0" />
            <span className="max-w-[100px] truncate">
              {savingProfile ? 'saving…' : (assignment?.profile_display_name ?? assignment?.profile_name ?? 'No Profile')}
            </span>
          </button>

          {/* Dropdown picker */}
          {pickerOpen && (
            <div className="absolute right-0 top-full mt-1 z-50 min-w-[220px] border border-border rounded-sm bg-[var(--panel)] shadow-lg overflow-hidden">
              <div className="px-3 py-1.5 border-b border-border flex items-center justify-between">
                <span className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Assign Profile</span>
                <button onClick={() => setPickerOpen(false)} className="hover:text-foreground text-muted-foreground/50">
                  <X className="h-3 w-3" />
                </button>
              </div>
              {/* None option */}
              <button
                onClick={() => void handleAssignProfile(null)}
                className={`w-full flex items-center gap-2 px-3 py-2 text-[11px] font-mono hover:bg-accent border-b border-border/40 ${
                  !assignment ? 'text-primary font-semibold' : 'text-muted-foreground'
                }`}
              >
                <Shield className="h-3 w-3 shrink-0" />
                <span>No Profile</span>
                {!assignment && <span className="ml-auto text-[9px]">✓</span>}
              </button>
              {/* Profile options */}
              {profiles.map((p) => {
                const isActive = assignment?.profile_id === p.id;
                const tolColor =
                  p.risk_tolerance === 'low' ? 'text-critical' :
                  p.risk_tolerance === 'high' ? 'text-success' : 'text-warning';
                return (
                  <button
                    key={p.id}
                    onClick={() => void handleAssignProfile(p.id!)}
                    className={`w-full flex items-start gap-2 px-3 py-2 text-left hover:bg-accent border-b border-border/40 last:border-b-0 ${
                      isActive ? 'bg-primary/10' : ''
                    }`}
                  >
                    <div className="flex-1 min-w-0">
                      <div className={`text-[11px] font-mono font-semibold ${isActive ? 'text-primary' : 'text-foreground'}`}>
                        {p.display_name}
                        {p.is_builtin && (
                          <span className="ml-1.5 text-[8px] border border-border/60 rounded-sm px-1 font-normal text-muted-foreground">builtin</span>
                        )}
                      </div>
                      <div className="text-[9.5px] font-mono text-muted-foreground/70 truncate mt-0.5">{p.description}</div>
                      <span className={`text-[9px] font-mono ${tolColor}`}>{p.risk_tolerance} tolerance</span>
                    </div>
                    {isActive && <span className="text-primary text-[9px] mt-0.5 shrink-0">✓</span>}
                  </button>
                );
              })}
            </div>
          )}
        </div>
        <button
          onClick={() => void handleRecompute()}
          disabled={recomputing || loading}
          className="h-6 px-2 rounded-sm border border-border hover:bg-accent text-[11px] font-mono inline-flex items-center gap-1 disabled:opacity-40"
        >
          <RefreshCw className={`h-3 w-3 ${recomputing ? 'animate-spin text-primary' : 'text-muted-foreground'}`} />
          Recompute
        </button>
      </div>

      {/* ━━━ SCROLLABLE BODY ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */}
      <div className="flex-1 min-h-0 overflow-y-auto">
        <div className="max-w-[960px] mx-auto px-4 py-3 flex flex-col gap-3">

          {/* ━━━ 2. PRIMARY KEY FINDING ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */}
          {loading && (
            <div className="border border-border rounded-sm bg-[var(--panel)] px-4 py-4 text-[11px] font-mono text-muted-foreground animate-pulse">
              Analysing host…
            </div>
          )}

          {hasData && deviations.length === 0 && (
            <div className="border border-success/30 rounded-sm bg-success/5 px-4 py-4 flex items-center gap-3">
              <CheckCircle className="h-5 w-5 text-success shrink-0" />
              <div>
                <div className="text-[13px] font-semibold font-mono text-success">Within baseline</div>
                <div className="text-[10.5px] font-mono text-muted-foreground mt-0.5">
                  {features.length > 0
                    ? `${features.length} known entities — no active deviations`
                    : 'No baseline yet — run Recompute to establish one'}
                </div>
              </div>
            </div>
          )}

          {hasData && topDev && (
            <div className={`rounded-sm border-l-4 border border-border bg-[var(--panel)] overflow-hidden ${
              topDev.risk_score >= 80 ? 'border-l-critical' :
              topDev.risk_score >= 60 ? 'border-l-high' :
              topDev.risk_score >= 40 ? 'border-l-warning' : 'border-l-blue-500'
            }`}>
              <div className="px-4 py-3">
                <div className="flex items-start gap-3">
                  <AlertTriangle className={`h-4 w-4 mt-0.5 shrink-0 ${riskColor(topDev.risk_score)}`} />
                  <div className="flex-1 min-w-0">
                    {/* headline */}
                    <div className="flex items-baseline gap-2 flex-wrap">
                      <span className={`text-[14px] font-bold font-mono ${riskColor(topDev.risk_score)}`}>
                        {devTypeLabel(topDev.deviation_type)}
                      </span>
                      <span className="text-[13px] font-mono font-semibold text-foreground truncate">
                        {topDev.feature_key}
                      </span>
                      {deviations.length > 1 && (
                        <span className="text-[10.5px] font-mono text-muted-foreground/60 shrink-0">
                          +{deviations.length - 1} more
                        </span>
                      )}
                    </div>
                    {/* meta row */}
                    <div className="flex items-center gap-3 mt-1 flex-wrap">
                      <span className={`inline-flex items-center h-[16px] px-1.5 rounded-sm border text-[9px] font-mono font-bold tracking-wide ${devTypeChipCls(topDev.deviation_type)}`}>
                        {devTypeLabel(topDev.deviation_type).toUpperCase()}
                      </span>
                      <ClassificationBadge value={topDev.final_classification ?? 'unknown'} />
                      <span className="text-[10.5px] font-mono text-muted-foreground">
                        score <span className={`font-bold ${riskColor(topDev.risk_score)}`}>{topDev.risk_score}</span>
                      </span>
                      <span className="text-[10.5px] font-mono text-muted-foreground">
                        conf <span className="text-foreground/70">{(topDev.confidence * 100).toFixed(0)}%</span>
                      </span>
                      <span className="text-[10.5px] font-mono text-muted-foreground">
                        first seen <span className="text-foreground/70">{fmtTimeOnly(topDev.detected_at)}</span>
                      </span>
                    </div>
                    {/* reason */}
                    <div className="mt-1.5 text-[11px] font-mono text-muted-foreground/80 leading-snug">
                      {topDev.reason}
                    </div>
                  </div>
                  <span className={`shrink-0 text-[22px] font-bold font-mono tabular-nums ${riskColor(topDev.risk_score)}`}>
                    {topDev.risk_score}
                  </span>
                </div>
              </div>
            </div>
          )}

          {/* ━━━ 3. ACTIONS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */}
          <div className="flex gap-2">
            <ActionBtn
              icon={Database}
              label="Open Baseline"
              sub="deviations · known state · history"
              badge={deviations.length}
              primary
              onClick={() => onGoBaseline(host)}
            />
            <ActionBtn
              icon={Crosshair}
              label="Investigate"
              sub="events · threat hunting · timeline"
              onClick={() => onGoSnipen(host)}
            />
            <ActionBtn
              icon={BarChart2}
              label="Full Scan"
              sub="deep analysis · compliance"
              onClick={onGoFullScan}
            />
          </div>

          {/* ━━━ 4. CONTEXT ROW ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */}
          <div className="grid grid-cols-3 gap-2">

            {/* Known vs New */}
            <div className="border border-border rounded-sm bg-[var(--panel)] overflow-hidden">
              <div className="px-3 py-1.5 border-b border-border/60 text-[9.5px] font-mono uppercase tracking-widest text-muted-foreground">
                Known vs New
              </div>
              {loading && <div className="px-3 py-2 text-[10.5px] font-mono text-muted-foreground/40 animate-pulse">loading…</div>}
              {!loading && (
                <div className="px-3 py-2 space-y-1.5">
                  {/* inline comparison rows */}
                  {([
                    { label: 'Processes', known: knownCounts.processes, newN: counts.processes, color: 'text-blue-400' },
                    { label: 'Services',  known: knownCounts.services,  newN: counts.services,  color: 'text-orange-400' },
                    { label: 'Users',     known: knownCounts.users,     newN: counts.users,     color: 'text-purple-400' },
                    { label: 'IPs',       known: knownCounts.ips,       newN: counts.ips,       color: 'text-cyan-400' },
                  ] as const).filter((r) => r.known > 0 || r.newN > 0).map((row) => (
                    <div key={row.label} className="flex items-center gap-1 text-[10.5px] font-mono">
                      <span className={`w-[60px] font-medium ${row.color}`}>{row.label}</span>
                      <span className="text-muted-foreground">{row.known}</span>
                      {row.newN > 0 && (
                        <span className="text-warning font-bold ml-1">+{row.newN}</span>
                      )}
                    </div>
                  ))}
                  {(counts.event_ids > 0 || counts.families > 0) && (
                    <div className="pt-1 border-t border-border/40 text-[10px] font-mono text-muted-foreground/60">
                      {counts.event_ids > 0 && <span>+{counts.event_ids} event IDs  </span>}
                      {counts.families  > 0 && <span>+{counts.families} families</span>}
                    </div>
                  )}
                  {counts.spikes > 0 && (
                    <div className="text-[10px] font-mono text-critical">+{counts.spikes} volume spike{counts.spikes > 1 ? 's' : ''}</div>
                  )}
                  {features.length === 0 && !loading && (
                    <div className="text-[10px] font-mono text-muted-foreground/40">no baseline yet</div>
                  )}
                </div>
              )}
            </div>

            {/* Summary stats */}
            <div className="border border-border rounded-sm bg-[var(--panel)] overflow-hidden">
              <div className="px-3 py-1.5 border-b border-border/60 text-[9.5px] font-mono uppercase tracking-widest text-muted-foreground">
                Activity Window
              </div>
              <div className="px-3 py-2 space-y-1">
                {summary ? (
                  <>
                    <div className="flex justify-between text-[10.5px] font-mono">
                      <span className="text-muted-foreground">Events</span>
                      <span className="font-semibold">{summary.total_events.toLocaleString('de-DE')}</span>
                    </div>
                    <div className="flex justify-between text-[10.5px] font-mono">
                      <span className="text-muted-foreground">Window</span>
                      <span>{summary.window_hours}h</span>
                    </div>
                    <div className="flex justify-between text-[10.5px] font-mono">
                      <span className="text-muted-foreground">Avg / day</span>
                      <span>{summary.daily_avg_events.toFixed(0)}</span>
                    </div>
                    <div className="flex justify-between text-[10.5px] font-mono">
                      <span className="text-muted-foreground">High alerts</span>
                      <span className={(summary.high_alerts > 0) ? 'text-warning font-semibold' : ''}>{summary.high_alerts}</span>
                    </div>
                    <div className="flex justify-between text-[10.5px] font-mono">
                      <span className="text-muted-foreground">Critical</span>
                      <span className={(summary.critical_alerts > 0) ? 'text-critical font-semibold' : ''}>{summary.critical_alerts}</span>
                    </div>
                    {summary.top_event_families.length > 0 && (
                      <div className="pt-1 border-t border-border/40 flex flex-wrap gap-1">
                        {summary.top_event_families.slice(0, 4).map((f) => (
                          <span key={f} className="h-[15px] px-1 rounded-sm bg-emerald-500/10 text-emerald-400 text-[9px] font-mono inline-flex items-center border border-emerald-500/20">
                            {f}
                          </span>
                        ))}
                      </div>
                    )}
                  </>
                ) : loading ? (
                  <div className="text-[10.5px] font-mono text-muted-foreground/40 animate-pulse">loading…</div>
                ) : (
                  <div className="text-[10.5px] font-mono text-muted-foreground/40">no baseline yet</div>
                )}
              </div>
            </div>

            {/* Host meta */}
            <div className="border border-border rounded-sm bg-[var(--panel)] overflow-hidden">
              <div className="px-3 py-1.5 border-b border-border/60 text-[9.5px] font-mono uppercase tracking-widest text-muted-foreground">
                Host Info
              </div>
              <div className="px-3 py-2 space-y-1">
                {hostData ? (
                  <>
                    <div className="flex justify-between text-[10.5px] font-mono">
                      <span className="text-muted-foreground">Status</span>
                      <span className={isOnline ? 'text-success' : 'text-muted-foreground/50'}>{hostData.status}</span>
                    </div>
                    {hostData.ip && (
                      <div className="flex justify-between text-[10.5px] font-mono">
                        <span className="text-muted-foreground">IP</span>
                        <span>{hostData.ip}</span>
                      </div>
                    )}
                    {platform && (
                      <div className="flex justify-between text-[10.5px] font-mono">
                        <span className="text-muted-foreground">Platform</span>
                        <span>{platform}</span>
                      </div>
                    )}
                    <div className="flex justify-between text-[10.5px] font-mono">
                      <span className="text-muted-foreground">Alerts 24h</span>
                      <span className={hostData.alerts_24h > 0 ? 'text-warning font-semibold' : ''}>{hostData.alerts_24h}</span>
                    </div>
                    <div className="flex justify-between text-[10.5px] font-mono">
                      <span className="text-muted-foreground">Findings</span>
                      <span>{hostData.findings_count}</span>
                    </div>
                    {hostData.last_scan_at && (
                      <div className="flex justify-between text-[10.5px] font-mono">
                        <span className="text-muted-foreground">Last scan</span>
                        <span className="text-muted-foreground/60 text-right max-w-[100px] truncate">{fmtShort(hostData.last_scan_at)}</span>
                      </div>
                    )}
                  </>
                ) : (
                  <div className="text-[10.5px] font-mono text-muted-foreground/40">—</div>
                )}
                {summary?.computed_at && (
                  <div className="pt-1 border-t border-border/40 text-[9.5px] font-mono text-muted-foreground/50">
                    baseline {fmtShort(summary.computed_at)}
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* ━━━ 5. SECONDARY DEVIATIONS LIST ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */}
          {secondaryDevs.length > 0 && (
            <div className="border border-border rounded-sm bg-[var(--panel)] overflow-hidden">
              <div className="px-3 py-1.5 border-b border-border/60 text-[9.5px] font-mono uppercase tracking-widest text-muted-foreground">
                Other Deviations ({deviations.length - 1})
              </div>
              <div className="divide-y divide-border/40">
                {secondaryDevs.map((d) => (
                  <div key={d.id} className="flex items-center hover:bg-[var(--row-hover)]">
                    <div className={`w-0.5 self-stretch shrink-0 ${devLeftBar(d.risk_score)}`} />
                    <span className={`px-2.5 py-1.5 text-[12px] font-bold font-mono tabular-nums w-[36px] text-right shrink-0 ${riskColor(d.risk_score)}`}>
                      {d.risk_score}
                    </span>
                    <span className={`shrink-0 mx-1.5 inline-flex items-center h-[15px] px-1 rounded-sm border text-[8.5px] font-mono font-bold tracking-wide ${devTypeChipCls(d.deviation_type)}`}>
                      {devTypeLabel(d.deviation_type).toUpperCase().slice(0, 7)}
                    </span>
                    <ClassificationBadge value={d.final_classification ?? 'unknown'} className="mx-1" />
                    <span className="flex-1 min-w-0 py-1.5 text-[11px] font-mono text-foreground/80 truncate">{activityLabel(d)}</span>
                    <span className="shrink-0 px-3 text-[9.5px] font-mono text-muted-foreground/40">{fmtTimeOnly(d.detected_at)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* baseline meta footer when no deviations */}
          {hasData && deviations.length === 0 && summary?.computed_at && (
            <div className="text-[10px] font-mono text-muted-foreground/40 text-center py-1">
              Baseline computed {fmtShort(summary.computed_at)} · {summary.window_hours}h window · {summary.total_events.toLocaleString('de-DE')} events
            </div>
          )}

        </div>
      </div>
    </div>
  );
}
