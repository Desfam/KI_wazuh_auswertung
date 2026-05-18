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
import HostCommandCenterView from '../components/hosts/HostCommandCenterView';
import type { HostOverviewData } from '../components/hosts/HostCommandCenterView';
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
  void hasData; // used in legacy JSX below — kept for future restoration

  // ── Build HostOverviewData from available state ───────────────────────────
  const commandCenterData = useMemo((): HostOverviewData => {
    const score10 = derivedRisk > 10
      ? Math.round((derivedRisk / 10) * 10) / 10
      : Math.round(derivedRisk * 10) / 10;

    return {
      host,
      platform: platform ?? undefined,
      domain: undefined,
      ip: hostData?.ip ?? undefined,
      lastSeen: hostData?.last_activity ? fmtShort(hostData.last_activity) : undefined,
      uptime: undefined,
      agentHealth: isOnline ? 'connected' : 'offline',
      riskScore: score10,

      security: {
        activeFindings: hostData?.findings_count ?? 0,
        critical: 0,
        high: hostData?.alerts_24h ?? 0,
        medium: 0,
        baselineDeviations: deviations.length,
        threatIntelMatches: 0,
        decisionSummary: topDev
          ? [
              `Höchste Abweichung: ${topDev.feature_key} (Score ${topDev.risk_score})`,
              topDev.reason ?? '',
              `${deviations.length} aktive Baseline-Abweichungen erkannt.`,
              `${features.length} bekannte Entitäten in der Baseline.`,
            ].filter(Boolean)
          : ['Keine aktiven Abweichungen erkannt. Host ist innerhalb der Baseline.'],
        topFindings: deviations
          .sort((a, b) => b.risk_score - a.risk_score)
          .slice(0, 5)
          .map((d) => ({
            title: `${devTypeLabel(d.deviation_type)}: ${d.feature_key}`,
            severity:
              d.risk_score >= 80 ? ('critical' as const)
              : d.risk_score >= 60 ? ('high' as const)
              : d.risk_score >= 40 ? ('medium' as const)
              : ('low' as const),
            time: d.detected_at ? fmtTimeOnly(d.detected_at) : undefined,
          })),
        timeline: [],
      },

      remoteAccess: undefined,
      tacticalRmm: undefined,

      inventory: {
        os: platform ?? undefined,
        primaryIp: hostData?.ip ?? undefined,
        secondaryIps: [],
        topProcesses: [],
        topUsers: [],
        topEventIds: [],
      },

      baseline: {
        newUsers: counts.users,
        newIps: counts.ips,
        newProcesses: counts.processes,
        newServices: counts.services,
        changedRegistryKeys: 0,
        removedFiles: 0,
      },

      incidents: [],

      network: {
        openPorts: [],
        outboundConnections24h: undefined,
      },
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [host, derivedRisk, platform, hostData, deviations, features, topDev, counts, isOnline]);

  return (
    <div className="h-full flex flex-col min-h-0 overflow-hidden bg-[var(--background)]">
      {/* Back header */}
      <div className="shrink-0 border-b border-border bg-[var(--panel)] px-4 py-2 flex items-center gap-2">
        <button
          onClick={onBack}
          className="h-6 w-6 rounded-sm hover:bg-accent inline-flex items-center justify-center shrink-0"
        >
          <ArrowLeft className="h-3.5 w-3.5 text-muted-foreground" />
        </button>
        <span className="text-[13px] font-mono text-muted-foreground">Host Overview</span>
      </div>

      {/* Command Center */}
      <div className="flex-1 min-h-0">
        <HostCommandCenterView
          data={commandCenterData}
          onRecompute={() => { void handleRecompute(); }}
          onFullScan={onGoFullScan}
          onInvestigate={() => onGoSnipen(host)}
          onIsolate={() => console.log('[placeholder] isolate', host)}
          onOpenRdp={() => console.log('[placeholder] rdp', host)}
          onOpenSsh={() => console.log('[placeholder] ssh', host)}
          onOpenFileTransfer={() => console.log('[placeholder] file-transfer', host)}
          onRunScript={() => console.log('[placeholder] run-script', host)}
          onOpenTactical={() => console.log('[placeholder] tactical-rmm', host)}
          onRemoteShell={() => console.log('[placeholder] remote-shell', host)}
          onOpenProcesses={() => console.log('[placeholder] processes', host)}
          onOpenServices={() => console.log('[placeholder] services', host)}
          onOpenEventViewer={() => console.log('[placeholder] event-viewer', host)}
          onManagePatches={() => console.log('[placeholder] patches', host)}
          onRebootHost={() => console.log('[placeholder] reboot', host)}
        />
      </div>
    </div>
  );
}
