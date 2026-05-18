import { useEffect, useRef, useState } from 'react';
import { Brain, Cpu, Database, Download, FileJson, FileSearch, FolderSearch, GitMerge, Globe2, Layers, Network, RefreshCw, ScanLine, Search, Server, Settings2, ShieldAlert, ShieldOff } from 'lucide-react';
import { getSnipenHosts } from '../services/api';
import { getFullScanResult, getFullScanStatus, startFullScan, startFleetScan, getFleetScanStatus, getFleetScanResult, cancelFleetScan } from '../services/fullscan';
import { HostScanDecisionDashboard, FleetScanDecisionDashboard } from '../components/fullscan/ScanDecisionDashboards';
import type { FleetHostRow, FleetScanDashboardData, HostScanDashboardData, TrueFinding, ModuleResult, DecisionStatus } from '../components/fullscan/ScanDecisionDashboards';
import { FleetScanHUD } from '../components/fullscan/FleetScanHUD';
import { FleetMetaPanel } from '../components/fullscan/FleetMetaPanel';
import type { HostProfileAssignment, SnipenHostInfo } from '../types';

/* ─── sessionStorage keys ──────────────────────────────────────────────────── */
const SS_RESULT       = 'sentinelops.fullscan.lastResult';
const SS_HOST         = 'sentinelops.fullscan.selectedHost';
const SS_SCAN_TIME    = 'sentinelops.fullscan.scanTime';
const SS_FLEET_RESULT = 'sentinelops.fullscan.fleetResult';
const SS_FLEET_STATUS = 'sentinelops.fullscan.fleetStatus';

function ssSave(key: string, value: unknown) {
  try { sessionStorage.setItem(key, JSON.stringify(value)); } catch { /* ignore */ }
}
function ssLoad<T>(key: string): T | null {
  try { const v = sessionStorage.getItem(key); return v ? (JSON.parse(v) as T) : null; } catch { return null; }
}

/* ─── Download helper ───────────────────────────────────────────────────────── */
function downloadFile(name: string, content: string, mime = 'text/plain') {
  const blob = new Blob([content], { type: mime });
  const url  = URL.createObjectURL(blob);
  const a    = Object.assign(document.createElement('a'), { href: url, download: name });
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

/* ─── Robust value extractors ───────────────────────────────────────────────── */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function getNumber(...values: any[]): number | undefined {
  for (const v of values) {
    if (typeof v === 'number' && !Number.isNaN(v)) return v;
    if (typeof v === 'string' && v.trim() !== '' && !Number.isNaN(Number(v))) return Number(v);
  }
  return undefined;
}

function normalise10(raw: number): number {
  return raw > 10 ? Math.round((raw / 10) * 10) / 10 : Math.round(raw * 10) / 10;
}

function calculateFleetRisk(hosts: Array<{ riskScore: number }>): number {
  if (!hosts.length) return 0;
  const sorted   = [...hosts].sort((a, b) => b.riskScore - a.riskScore);
  const topFive  = sorted.slice(0, 5);
  const avgTop   = topFive.reduce((s, h) => s + h.riskScore, 0) / topFive.length;
  const critBoost = hosts.filter((h) => h.riskScore >= 8).length * 0.4;
  const highBoost = hosts.filter((h) => h.riskScore >= 6 && h.riskScore < 8).length * 0.15;
  return Math.min(10, Math.round((avgTop + critBoost + highBoost) * 10) / 10);
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function extractBaselineDiff(result: any) {
  const summary   = result?.summary ?? {};
  const raw       = result?.raw_json ?? {};
  const baseline  = result?.baseline ?? raw?.baseline ?? raw?.baseline_diff ?? {};
  const devs      = result?.deviations ?? raw?.deviations ?? {};
  return {
    newEventIds:    getNumber(summary.new_event_ids,  summary.newEventIds,  baseline.new_event_ids,  baseline.newEventIds,  devs.new_event_ids,  devs.newEventIds)  ?? 0,
    newUsers:       getNumber(summary.new_users,      summary.newUsers,     baseline.new_users,      baseline.newUsers,     devs.new_users,      devs.newUsers)     ?? 0,
    newIps:         getNumber(summary.new_ips,        summary.newIps,       baseline.new_ips,        baseline.newIps,       devs.new_ips,        devs.newIps)       ?? 0,
    newProcesses:   getNumber(summary.new_processes,  summary.newProcesses, baseline.new_processes,  baseline.newProcesses, devs.new_processes,  devs.newProcesses) ?? 0,
    newServices:    getNumber(summary.new_services,   summary.newServices,  baseline.new_services,   baseline.newServices,  devs.new_services,   devs.newServices)  ?? 0,
    openDeviations: getNumber(summary.open_deviations,summary.openDeviations,baseline.open_deviations,baseline.openDeviations,devs.open_deviations,devs.openDeviations) ?? 0,
  };
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function sumFleetBaseline(hostResults: any[]) {
  return hostResults.reduce(
    (acc, r) => {
      const b = extractBaselineDiff(r);
      acc.newEventIds    += b.newEventIds;
      acc.newUsers       += b.newUsers;
      acc.newIps         += b.newIps;
      acc.newProcesses   += b.newProcesses;
      acc.newServices    += b.newServices;
      acc.openDeviations += b.openDeviations;
      return acc;
    },
    { newEventIds: 0, newUsers: 0, newIps: 0, newProcesses: 0, newServices: 0, openDeviations: 0 },
  );
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function derivePrimaryReason(hostResult: any): string {
  const findings = hostResult?.findings ?? hostResult?.scan_findings ?? [];
  const summary  = hostResult?.summary  ?? {};
  const baseline = hostResult?.baseline ?? hostResult?.raw_json?.baseline ?? {};
  const metrics  = hostResult?.raw_json?.metrics ?? {};
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const topFinding = findings.find((f: any) =>
    ['critical', 'high', 'medium'].includes(String(f.severity ?? '').toLowerCase())
  );
  if (topFinding?.title && topFinding?.reason) return `${topFinding.title as string}: ${topFinding.reason as string}`;
  if (topFinding?.title) return topFinding.title as string;
  const ti         = getNumber(metrics.ti_matches, summary.ti_matches) ?? 0;
  const newUsers   = getNumber(baseline.new_users,  summary.new_users)   ?? 0;
  const newEventIds= getNumber(baseline.new_event_ids, summary.new_event_ids) ?? 0;
  const newProcs   = getNumber(baseline.new_processes, summary.new_processes) ?? 0;
  const reasons: string[] = [];
  if (ti > 0)         reasons.push(`${ti} TI-Hinweis(e)`);
  if (newUsers > 0)   reasons.push(`${newUsers} neue Nutzer`);
  if (newEventIds > 0)reasons.push(`${newEventIds} neue Event-IDs`);
  if (newProcs > 0)   reasons.push(`${newProcs} neue Prozesse`);
  return reasons.length > 0 ? reasons.join(' · ') : (hostResult?.top_finding ?? hostResult?.summary_text ?? 'Keine relevante Abweichung erkannt');
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function findHostResult(result: any, host: string): any {
  const candidates =
    result?.host_results ??
    result?.results ??
    result?.hosts ??
    result?.fleet_results ?? [];
  if (Array.isArray(candidates)) {
    return (candidates as any[]).find((r) =>
      r?.host === host || r?.agent?.name === host || r?.summary?.host === host || r?.target === host
    ) ?? null;
  }
  if (candidates && typeof candidates === 'object') return (candidates as Record<string, unknown>)[host] ?? null;
  return null;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function buildHostScanData(
  result: any,
  selectedHost: string,
  host: SnipenHostInfo | undefined,
  scanTime: string,
  findings: Array<Record<string, any>>,
  suggestions: Array<{ check?: string; why?: string; tool?: string }>,
): HostScanDashboardData {
  const rawScore = getNumber(
    result?.risk_score, result?.summary?.risk_score, result?.raw_json?.summary?.risk_score,
    result?.raw_json?.risk_score,
  ) ?? 0;
  const score10 = normalise10(rawScore);
  const status: DecisionStatus =
    score10 >= 8 ? 'action_required' : score10 >= 6 ? 'review' : score10 >= 4 ? 'watch' : 'stable';

  const mappedFindings: TrueFinding[] = findings.map((f, i) => ({
    id: f.id ?? `F-${String(i + 1).padStart(2, '0')}`,
    severity: f.severity ?? 'medium',
    category: f.category ?? f.type ?? '—',
    title: f.title ?? f.rule ?? '—',
    summary: f.reason ?? f.summary ?? f.description ?? '',
    eventCount: f.event_count ?? f.count ?? undefined,
    mitre: f.mitre ?? undefined,
  }));

  const moduleResults: ModuleResult[] = Object.entries(
    result?.module_results ?? result?.modules ?? {}
  ).map(([module, st]: [string, any]) => ({
    module,
    status: st === 'done' || st === 'completed' ? 'completed' : st === 'failed' ? 'failed' : 'skipped',
    checked: undefined,
  }));

  return {
    host: selectedHost,
    platform: (host?.platforms ?? [])[0],
    scanTime,
    scanMode: 'Full Scan',
    riskScore: score10,
    status,
    totalEvents: result?.total_events ?? result?.event_count ?? 0,
    findings: mappedFindings,
    moduleResults,
    baseline: {
      ...extractBaselineDiff(result),
      newHashes:  getNumber(result?.baseline?.new_hashes,  result?.raw_json?.baseline?.new_hashes)  ?? 0,
      newDomains: getNumber(result?.baseline?.new_domains, result?.raw_json?.baseline?.new_domains) ?? 0,
    },
    threatIntel: {
      confirmed: result?.ti_matches ?? result?.threat_intel_matches ?? 0,
      unvalidated: result?.threat_intel_unvalidated ?? 0,
    },
    topEventIds: result?.top_event_ids ?? [],
    topRules: result?.top_rules ?? [],
    topProcesses: result?.top_processes ?? [],
    topUsers: result?.top_users ?? [],
    whyRiskRaised: result?.why_risk_raised ?? [],
    whyNotWorse: result?.why_not_worse ?? [],
    recommendedActions: suggestions.map(s => s.check ?? '').filter(Boolean),
    timeline: (result?.timeline ?? []).map((t: any) => ({
      time: t.time ?? '',
      title: t.title ?? '',
      subtitle: t.subtitle ?? t.description ?? '',
      severity: t.severity ?? undefined,
    })),
  };
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function buildFleetScanData(
  fleetResult: any,
  fleetStatus: any,
  fleetScanStartMs: number | null,
  hostsTotal: number,
  hostsCompleted: number,
): FleetScanDashboardData {
  const hostRows: FleetHostRow[] = [];

  // Collect all individual host results for fallback aggregation
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const allHostResults: any[] = [];

  if (fleetResult?.host_results) {
    const entries = typeof fleetResult.host_results === 'object' && !Array.isArray(fleetResult.host_results)
      ? Object.entries(fleetResult.host_results as Record<string, unknown>)
      : (fleetResult.host_results as unknown[]).map((r, i) => [(r as any)?.host ?? String(i), r]);

    for (const [host, r] of entries as [string, any][]) {
      allHostResults.push(r);
      const rawScore = getNumber(r?.risk_score, r?.summary?.risk_score, r?.raw_json?.summary?.risk_score) ?? 0;
      const score10 = normalise10(rawScore);
      const status: DecisionStatus =
        score10 >= 8 ? 'action_required' : score10 >= 6 ? 'review' : score10 >= 4 ? 'watch' : 'stable';
      hostRows.push({
        host,
        platform: r?.platform ?? r?.os_platform ?? r?.summary?.platform ?? undefined,
        riskScore: score10,
        findings: getNumber(r?.findings_count, r?.summary?.findings_count, (r?.findings ?? []).length) ?? 0,
        critical: getNumber(r?.critical_count, r?.summary?.critical_count) ?? 0,
        status,
        primaryReason: derivePrimaryReason(r),
        lastSeen: r?.last_seen ?? r?.summary?.last_seen ?? undefined,
      });
    }
    hostRows.sort((a, b) => b.riskScore - a.riskScore);
  }

  const stats = fleetResult?.fleet_stats ?? fleetResult?.summary ?? {};

  // Fleet risk: try explicit field first, then calculate from host rows
  const explicitRisk = getNumber(
    stats.fleet_risk_score, stats.risk_score,
    fleetResult?.fleet_risk_score, fleetResult?.risk_score,
    fleetResult?.raw_json?.summary?.risk_score,
  );
  const fleetRisk10 = explicitRisk != null && explicitRisk > 0
    ? normalise10(explicitRisk)
    : calculateFleetRisk(hostRows);

  const criticalHosts = hostRows.filter((h) => h.riskScore >= 8).length;
  const totalFindings = getNumber(stats.total_findings, fleetResult?.total_findings)
    ?? hostRows.reduce((s, h) => s + h.findings, 0);
  const tiMatches = getNumber(stats.total_ti_matches, stats.ti_matches, fleetResult?.ti_matches) ?? 0;

  const topFindingsRaw = [
    ...(fleetResult?.top_findings ?? []),
    ...(fleetStatus?.top_findings ?? []),
  ].filter(Boolean);
  const seen = new Set<string>();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const topFindings: TrueFinding[] = topFindingsRaw.filter((f: any) => {
    const k = f.title ?? f.rule ?? '';
    if (seen.has(k)) return false; seen.add(k); return true;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  }).map((f: any, i: number) => ({
    id: `TF-${i + 1}`,
    severity: f.severity ?? 'medium',
    category: f.category ?? '—',
    title: f.title ?? f.rule ?? '—',
    summary: f.description ?? f.reason ?? f.summary ?? '',
    affectedHosts: getNumber(f.hosts?.length, f.seen_on, f.affected_hosts) ?? 1,
  }));

  const activity = (fleetStatus?.log ?? []).slice(-5).reverse()
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    .map((line: any) => ({
      time: String(line).match(/\d{2}:\d{2}:\d{2}/)?.[0] ?? '',
      title: String(line).replace(/^\[\d{2}:\d{2}:\d{2}\] /, ''),
      subtitle: '',
    }));

  // Baseline: try stats first, then sum over host results
  const statsBaseline = {
    newEventIds:    getNumber(stats.new_event_ids,    stats.newEventIds)    ?? -1,
    newUsers:       getNumber(stats.new_users,        stats.newUsers)       ?? -1,
    newIps:         getNumber(stats.new_ips,          stats.newIps)         ?? -1,
    newProcesses:   getNumber(stats.new_processes,    stats.newProcesses)   ?? -1,
    openDeviations: getNumber(stats.open_deviations,  stats.openDeviations) ?? -1,
  };
  const aggregatedBaseline = sumFleetBaseline(allHostResults);
  const baseline = {
    newEventIds:    statsBaseline.newEventIds    >= 0 ? statsBaseline.newEventIds    : aggregatedBaseline.newEventIds,
    newUsers:       statsBaseline.newUsers       >= 0 ? statsBaseline.newUsers       : aggregatedBaseline.newUsers,
    newIps:         statsBaseline.newIps         >= 0 ? statsBaseline.newIps         : aggregatedBaseline.newIps,
    newProcesses:   statsBaseline.newProcesses   >= 0 ? statsBaseline.newProcesses   : aggregatedBaseline.newProcesses,
    openDeviations: statsBaseline.openDeviations >= 0 ? statsBaseline.openDeviations : aggregatedBaseline.openDeviations,
  };

  const statusOverall: DecisionStatus = criticalHosts > 0 ? 'action_required' : totalFindings > 50 ? 'review' : 'watch';

  const markdownReport: string =
    fleetResult?.markdown_report ?? fleetResult?.report ?? fleetResult?.full_report ?? '';

  return {
    scanTime: fleetStatus?.started_at ?? fleetResult?.started_at ?? '—',
    duration: fleetScanStartMs ? fmtDuration(fleetScanStartMs) : (fleetResult?.duration ?? '—'),
    scanMode: fleetStatus?.params?.mode === 'deep' ? 'Deep Scan (All)' : 'Full Scan (All)',
    hostsTotal,
    hostsCompleted,
    fleetRiskScore: fleetRisk10,
    status: statusOverall,
    totalFindings,
    criticalHosts,
    threatIntel: { confirmed: tiMatches, unvalidated: 0 },
    hosts: hostRows,
    topFindings,
    baseline,
    whyFocusNeeded: criticalHosts > 0
      ? [`${criticalHosts} Host${criticalHosts > 1 ? 's' : ''} mit kritischem Risiko erfordern sofortige Maßnahmen.`]
      : [],
    recommendedActions: fleetResult?.recommendations ?? fleetResult?.suggested_actions ?? [],
    activity,
    markdownReport,
    rawResult: fleetResult,
  };
}

function fmtDuration(startMs: number): string {
  const secs = Math.round((Date.now() - startMs) / 1000);
  const m = Math.floor(secs / 60);
  const s = secs % 60;
  return m > 0 ? `${m}m ${s}s` : `${s}s`;
}

type FullScanTabProps = {
  theme: 'light' | 'dark';
  profileAssignments: Record<string, HostProfileAssignment>;
};

type ScanState = 'idle' | 'running' | 'finished' | 'failed';

export default function FullScanTab(_props: FullScanTabProps) {
  const [hosts, setHosts] = useState<SnipenHostInfo[]>([]);
  const [hostsLoading, setHostsLoading] = useState(false);
  const [hostsError, setHostsError] = useState<string | null>(null);
  const [selectedHost, setSelectedHost] = useState<string>('');

  const [scanState, setScanState] = useState<ScanState>('idle');
  const [progress, setProgress] = useState(0);
  const [scanLog, setScanLog] = useState<string[]>([]);
  const [jobId, setJobId] = useState<string | null>(null);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const [result, setResult] = useState<any>(null);
  const [resultLoading, setResultLoading] = useState(false);
  const [resultError, setResultError] = useState<string | null>(null);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const [selectedFinding, setSelectedFinding] = useState<any>(null);
  const [scanTime, setScanTime] = useState('');
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const currentJobIdRef = useRef<string | null>(null);
  const [activeModule, setActiveModule] = useState<string | null>(null);
  const [moduleStatus, setModuleStatus] = useState<Record<string, string>>({});
  const [scanMetrics, setScanMetrics] = useState<{
    total_modules: number; completed_modules: number;
    total_events: number; relevant_events: number; processed_events: number;
    findings: number; high_findings: number; ti_matches: number;
    risk_score: number; ai_enabled: boolean;
    ai_iterations_target: number; ai_iterations_completed: number;
  } | null>(null);

  // Fleet Scan ("All" button)
  type FleetState = 'idle' | 'running' | 'finished' | 'failed';
  const [fleetState, setFleetState] = useState<FleetState>('idle');
  const [fleetJobId, setFleetJobId] = useState<string | null>(null);
  const [fleetProgress, setFleetProgress] = useState(0);
  const [fleetFinished, setFleetFinished] = useState(0);
  const [fleetTotal, setFleetTotal] = useState(0);
  const [fleetActiveHosts, setFleetActiveHosts] = useState<string[]>([]);
  const [fleetLog, setFleetLog] = useState<string[]>([]);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const [fleetResult, setFleetResult] = useState<any>(null);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const [fleetStatus, setFleetStatus] = useState<any>(null);
  const [fleetScanStartMs, setFleetScanStartMs] = useState<number | null>(null);
  const fleetPollingRef = useRef<ReturnType<typeof setInterval> | null>(null);
  // legacy bulk state kept only to satisfy disabled checks
  const bulkRunning = fleetState === 'running';

  // ── Restore from sessionStorage on mount ───────────────────────────────────
  useEffect(() => {
    const cachedResult = ssLoad<unknown>(SS_RESULT);
    const cachedHost   = ssLoad<string>(SS_HOST);
    const cachedTime   = ssLoad<string>(SS_SCAN_TIME);
    if (cachedResult && cachedHost) {
      setResult(cachedResult);
      setScanState('finished');
      if (cachedHost) setSelectedHost(cachedHost);
      if (cachedTime) setScanTime(cachedTime);
      const findings = (cachedResult as any)?.findings ?? (cachedResult as any)?.scan_findings ?? [];
      if (findings.length > 0) setSelectedFinding(findings[0]);
    }
    const cachedFleetResult = ssLoad<unknown>(SS_FLEET_RESULT);
    const cachedFleetStatus = ssLoad<unknown>(SS_FLEET_STATUS);
    if (cachedFleetResult) {
      setFleetResult(cachedFleetResult);
      setFleetStatus(cachedFleetStatus);
      setFleetState('finished');
      setFleetTotal((cachedFleetResult as any)?.total_hosts ?? 0);
      setFleetFinished((cachedFleetResult as any)?.finished_hosts ?? (cachedFleetResult as any)?.total_hosts ?? 0);
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Fleet scan polling effect
  useEffect(() => {
    if (!fleetJobId || fleetState !== 'running') return;
    const poll = async () => {
      try {
        const st = await getFleetScanStatus(fleetJobId);
        setFleetStatus(st);
        setFleetProgress(st.progress ?? 0);
        setFleetFinished(st.finished_hosts ?? 0);
        setFleetTotal(st.total_hosts ?? 0);
        setFleetActiveHosts(st.active_hosts ?? []);
        if (st.log) setFleetLog(Array.isArray(st.log) ? st.log : [String(st.log)]);
        if (st.status === 'finished') {
          clearInterval(fleetPollingRef.current!);
          setFleetState('finished');
          try {
            const r = await getFleetScanResult(fleetJobId);
            setFleetResult(r);
            // keep last status for the result view
            setFleetStatus((prev: any) => ({ ...prev, ...st }));
            ssSave(SS_FLEET_RESULT, r);
            ssSave(SS_FLEET_STATUS, { ...st });
          } catch (e: unknown) {
            setFleetState('failed');
          }
        } else if (st.status === 'failed') {
          clearInterval(fleetPollingRef.current!);
          setFleetState('failed');
        }
      } catch { /* ignore transient network errors */ }
    };
    fleetPollingRef.current = setInterval(poll, 2000);
    return () => { if (fleetPollingRef.current) clearInterval(fleetPollingRef.current); };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [fleetJobId, fleetState]);

  // Polls a job and keeps all HUD states in sync (used by bulk scan to show live animation per host)
  async function pollUntilDoneWithHUD(jid: string, hostName: string): Promise<void> {
    // Switch HUD to this host
    setSelectedHost(hostName);
    setScanState('running');
    setScanLog([]);
    setResult(null);
    setResultLoading(false);
    setResultError(null);
    setSelectedFinding(null);
    setProgress(0);
    setActiveModule(null);
    setModuleStatus({});
    setScanMetrics(null);
    // NOTE: jobId is intentionally NOT set here — the useEffect poller
    // only fires when jobId changes. We drive the state updates ourselves.
    return new Promise((resolve) => {
      const iv = setInterval(async () => {
        try {
          const st = await getFullScanStatus(jid) as Record<string, unknown>;
          const prog = typeof st.progress === 'number' ? st.progress : 0;
          setProgress(prog);
          if (st.log) setScanLog(Array.isArray(st.log) ? st.log as string[] : [String(st.log)]);
          if (st.active_module != null) setActiveModule(st.active_module as string | null);
          if (st.module_status && typeof st.module_status === 'object')
            setModuleStatus(st.module_status as Record<string, string>);
          if (st.metrics && typeof st.metrics === 'object')
            setScanMetrics(st.metrics as typeof scanMetrics);
          if (st.status === 'finished' || st.status === 'done') {
            clearInterval(iv);
            setScanState('finished');
            setScanTime(new Date().toLocaleString('de-DE'));
            resolve();
          } else if (st.status === 'failed' || st.status === 'error') {
            clearInterval(iv);
            setScanState('failed');
            resolve();
          }
        } catch {
          clearInterval(iv);
          resolve();
        }
      }, 2000);
    });
  }

  const handleQuickScanAll = async () => {
    if (fleetState === 'running' || hosts.length === 0) return;
    setFleetState('running');
    setFleetResult(null);
    setFleetStatus(null);
    setFleetScanStartMs(Date.now());
    setFleetProgress(0);
    setFleetFinished(0);
    setFleetTotal(hosts.length);
    setFleetActiveHosts([]);
    setFleetLog([]);
    try {
      const { job_id } = await startFleetScan(
        hosts.map(h => h.host),
        { mode: 'quick', scope: 'full', time_range_hours: 24 }
      );
      setFleetJobId(job_id);
    } catch (e: unknown) {
      setFleetState('failed');
      setFleetLog([`Fehler beim Starten: ${e instanceof Error ? e.message : String(e)}`]);
    }
  };

  const handleCancelFleet = () => {
    if (fleetJobId) cancelFleetScan(fleetJobId);
    if (fleetPollingRef.current) clearInterval(fleetPollingRef.current);
    setFleetState('idle');
  };

  // Scan configuration
  const [timeRange, setTimeRange] = useState<24 | 168 | 720>(168);
  const [scanMode, setScanMode] = useState<'quick' | 'standard' | 'deep'>('standard');
  const [scanScope, setScanScope] = useState({
    processes: true,
    files: true,
    services: true,
    registry: true,
  });

  useEffect(() => {
    setHostsLoading(true);
    setHostsError(null);
    getSnipenHosts(168)
      .then((data) => {
        setHosts(data);
        if (data.length > 0) setSelectedHost(data[0].host);
      })
      .catch((e: unknown) => setHostsError(e instanceof Error ? e.message : 'Failed to load hosts'))
      .finally(() => setHostsLoading(false));
  }, []);

  async function fetchAndSetResult(jid: string) {
    setResultLoading(true);
    setResultError(null);
    try {
      const r = await getFullScanResult(jid);
      setResult(r);
      const findings = r?.findings ?? r?.scan_findings ?? [];
      if (findings.length > 0) setSelectedFinding(findings[0]);
      ssSave(SS_RESULT, r);
      ssSave(SS_HOST, selectedHost);
      ssSave(SS_SCAN_TIME, new Date().toLocaleString('de-DE'));
    } catch (e: unknown) {
      setResultError(e instanceof Error ? e.message : 'Ergebnis konnte nicht geladen werden');
    } finally {
      setResultLoading(false);
    }
  }

  // Polling for scan status
  useEffect(() => {
    if (!jobId || scanState !== 'running') return;
    const poll = async () => {
      let statusData: Record<string, unknown>;
      try {
        statusData = await getFullScanStatus(jobId);
      } catch {
        // ignore transient network errors during polling
        return;
      }
      const prog = typeof statusData.progress === 'number' ? statusData.progress : 0;
      setProgress(prog);
      if (statusData.log) setScanLog(Array.isArray(statusData.log) ? statusData.log : [String(statusData.log)]);
      if (statusData.active_module != null) setActiveModule(statusData.active_module as string | null);
      if (statusData.module_status && typeof statusData.module_status === 'object')
        setModuleStatus(statusData.module_status as Record<string, string>);
      if (statusData.metrics && typeof statusData.metrics === 'object')
        setScanMetrics(statusData.metrics as typeof scanMetrics);
      if (statusData.status === 'finished' || statusData.status === 'done') {
        setScanState('finished');
        setScanTime(new Date().toLocaleString('de-DE'));
        clearInterval(pollingRef.current!);
        fetchAndSetResult(jobId);
      } else if (statusData.status === 'failed' || statusData.status === 'error') {
        setScanState('failed');
        clearInterval(pollingRef.current!);
      }
    };
    pollingRef.current = setInterval(poll, 2000);
    return () => {
      if (pollingRef.current) clearInterval(pollingRef.current);
    };
  // fetchAndSetResult is stable (defined above with no deps captured via closure)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [jobId, scanState]);

  const handleStartScan = async () => {
    if (!selectedHost) return;
    setScanState('running');
    setScanLog([]);
    setResult(null);
    setResultLoading(false);
    setResultError(null);
    setSelectedFinding(null);
    setProgress(0);
    setJobId(null);
    currentJobIdRef.current = null;
    setActiveModule(null);
    setModuleStatus({});
    setScanMetrics(null);
    const activeScope = Object.entries(scanScope)
      .filter(([, enabled]) => enabled)
      .map(([key]) => key)
      .join(',') || 'full';
    try {
      const { job_id } = await startFullScan(selectedHost, {
        mode: scanMode,
        scope: activeScope,
        time_range_hours: timeRange,
      });
      setJobId(job_id);
    } catch (e: unknown) {
      setScanState('failed');
      setScanLog([`Error: ${e instanceof Error ? e.message : String(e)}`]);
    }
  };

  const host = hosts.find((h) => h.host === selectedHost);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const findings: Array<Record<string, any>> = result?.findings ?? result?.scan_findings ?? [];
  const suggestions: Array<{ check?: string; why?: string; tool?: string }> =
    result?.suggestions ?? result?.scan_suggestions ?? [];

  const showDashboard = scanState === 'finished' && !resultLoading && result != null;
  const showFleetResult = fleetState === 'finished';
  const showFleetHUD = fleetState === 'running' || fleetState === 'failed';
  const showFleet = fleetState !== 'idle';

  return (
    <div className={`h-full min-h-0 grid ${showDashboard || showFleetResult ? 'grid-cols-[200px_1fr]' : showFleetHUD ? 'grid-cols-[200px_1fr_280px]' : 'grid-cols-[200px_1fr_360px]'}`}>
      {/* Left: host picker */}
      <aside className="border-r border-border bg-[var(--panel)] flex flex-col min-h-0">
        <div className="px-3 py-2 border-b border-border">
          <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground mb-1.5">
            Scan Targets
          </div>
          <div className="flex gap-1">
            <button
              onClick={handleStartScan}
              disabled={!selectedHost || scanState === 'running' || bulkRunning}
              className="flex-1 h-7 rounded-sm border border-border hover:bg-accent text-[11.5px] font-mono inline-flex items-center justify-center gap-1 disabled:opacity-50"
            >
              <ScanLine className="h-3 w-3" />
              {scanState === 'running' ? 'Scanning…' : 'New Scan'}
            </button>
            <button
              onClick={bulkRunning ? handleCancelFleet : handleQuickScanAll}
              disabled={hosts.length === 0 || scanState === 'running'}
              title={bulkRunning ? 'Abbrechen' : `Fleet-Scan alle ${hosts.length} Hosts (parallel, quick)`}
              className={`h-7 px-2 rounded-sm border text-[11.5px] font-mono inline-flex items-center gap-1 disabled:opacity-50 transition-colors ${
                bulkRunning
                  ? 'border-warning/60 bg-warning/10 text-warning hover:bg-warning/20'
                  : 'border-border hover:bg-accent'
              }`}
            >
              <Layers className="h-3 w-3" />
              {bulkRunning ? `${fleetFinished}/${fleetTotal}` : 'All'}
            </button>
          </div>
          {/* Fleet progress bar */}
          {bulkRunning && (
            <div className="mt-1.5 space-y-0.5">
              <div className="h-1 w-full rounded-full bg-border overflow-hidden">
                <div
                  className="h-full bg-warning transition-all duration-300 rounded-full"
                  style={{ width: `${fleetProgress}%` }}
                />
              </div>
              {fleetActiveHosts.length > 0 && (
                <div className="text-[9.5px] font-mono text-muted-foreground truncate">
                  ⚡ {fleetActiveHosts.slice(0, 3).join(', ')}{fleetActiveHosts.length > 3 ? ` +${fleetActiveHosts.length - 3}` : ''}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Scan configuration */}
        <div className="px-3 py-2 border-b border-border space-y-2">
          <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">Config</div>

          {/* Time range */}
          <div>
            <div className="text-[10px] font-mono text-muted-foreground mb-1">Time Range</div>
            <div className="flex gap-1">
              {([24, 168, 720] as const).map((h) => (
                <button
                  key={h}
                  onClick={() => setTimeRange(h)}
                  disabled={scanState === 'running'}
                  className={
                    'flex-1 h-5 rounded-sm border text-[10px] font-mono disabled:opacity-50 ' +
                    (timeRange === h
                      ? 'bg-accent border-primary text-foreground'
                      : 'border-border text-muted-foreground hover:bg-accent')
                  }
                >
                  {h === 24 ? '24h' : h === 168 ? '7d' : '30d'}
                </button>
              ))}
            </div>
          </div>

          {/* Scan mode */}
          <div>
            <div className="text-[10px] font-mono text-muted-foreground mb-1">Mode</div>
            <div className="flex gap-1">
              {(['quick', 'standard', 'deep'] as const).map((m) => (
                <button
                  key={m}
                  onClick={() => setScanMode(m)}
                  disabled={scanState === 'running'}
                  className={
                    'flex-1 h-5 rounded-sm border text-[10px] font-mono disabled:opacity-50 ' +
                    (scanMode === m
                      ? 'bg-accent border-primary text-foreground'
                      : 'border-border text-muted-foreground hover:bg-accent')
                  }
                >
                  {m}
                </button>
              ))}
            </div>
          </div>

          {/* Scope checkboxes */}
          <div>
            <div className="text-[10px] font-mono text-muted-foreground mb-1">Scope</div>
            <div className="space-y-0.5">
              {(Object.keys(scanScope) as Array<keyof typeof scanScope>).map((key) => (
                <label key={key} className="flex items-center gap-1.5 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={scanScope[key]}
                    disabled={scanState === 'running'}
                    onChange={(e) =>
                      setScanScope((prev) => ({ ...prev, [key]: e.target.checked }))
                    }
                    className="h-3 w-3 accent-primary"
                  />
                  <span className="text-[10.5px] font-mono">{key}</span>
                </label>
              ))}
            </div>
          </div>
        </div>
        <div className="flex-1 overflow-y-auto">
          {hostsLoading && (
            <div className="px-3 py-2 text-[11px] font-mono text-muted-foreground">loading…</div>
          )}
          {hostsError && (
            <div className="px-3 py-2 text-[11px] font-mono text-critical">{hostsError}</div>
          )}
          {hosts.map((h) => {
            const sel = h.host === selectedHost;
            const r = h.top_rule_level != null ? Math.min(100, Math.round(h.top_rule_level * 6.25)) : 0;
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
                <div className="mt-0.5 flex items-center gap-2 text-[10.5px] font-mono">
                  <span className={r >= 80 ? 'text-critical' : r >= 60 ? 'text-high' : r >= 40 ? 'text-warning' : 'text-success'}>
                    risk {r}
                  </span>
                  <span className="text-muted-foreground">· {h.alert_count} alr</span>
                </div>
              </button>
            );
          })}
        </div>
      </aside>

      {/* Center: scan report */}
      <div className="flex flex-col min-h-0 border-r border-border overflow-y-auto">
        {/* Pre-dashboard header (idle / running / failed) */}
        {!showDashboard && (
          <div className="px-3 py-3 border-b border-border bg-[var(--panel)] flex items-start gap-4">
            <div className="flex-1">
              <div className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">target</div>
              <div className="text-[16px] font-mono font-semibold">{selectedHost || '—'}</div>
              <div className="text-[11px] font-mono text-muted-foreground">
                {(host?.platforms ?? [])[0] ?? '—'} · {host?.last_seen ?? '—'}
              </div>
              <div className="mt-1">
                {scanState === 'idle' && (
                  <span className="text-[11px] font-mono text-muted-foreground">ready to scan</span>
                )}
                {scanState === 'running' && (
                  <span className="inline-flex items-center gap-1.5 text-[11px] font-mono">
                    <span className="h-1.5 w-1.5 rounded-full bg-warning animate-pulse" />
                    scanning… {progress > 0 ? `${progress}%` : ''}
                  </span>
                )}
                {scanState === 'failed' && (
                  <span className="inline-flex items-center gap-1.5 text-[11px] font-mono text-critical">scan failed</span>
                )}
              </div>
            </div>
            <div className="flex flex-col gap-1.5">
              <BarBtn icon={RefreshCw} label="Re-scan" onClick={handleStartScan} />
              <BarBtn icon={Download} label="Export" onClick={() => result && downloadFile(`scan-${selectedHost}-${new Date().toISOString().slice(0, 10)}.json`, JSON.stringify(result, null, 2), 'application/json')} />
              <BarBtn icon={ShieldOff} label="Isolate" tone="critical" />
            </div>
          </div>
        )}

        {/* Progress bar */}
        {scanState === 'running' && (
          <div className="px-3 py-2 border-b border-border bg-[var(--panel)]">
            <div className="h-1 w-full bg-muted rounded-sm overflow-hidden">
              <div
                className="h-full bg-primary transition-all"
                style={{ width: `${progress}%` }}
              />
            </div>
            {scanLog.length > 0 && (
              <div className="mt-1.5 text-[10.5px] font-mono text-muted-foreground truncate">
                {scanLog[scanLog.length - 1]}
              </div>
            )}
          </div>
        )}

        {/* Scan log (idle/failed) */}
        {(scanState === 'idle' || scanState === 'failed') && scanLog.length > 0 && (
          <Section title="Log">
            <div className="space-y-0.5">
              {scanLog.map((line, i) => (
                <div key={i} className="text-[11px] font-mono text-muted-foreground">
                  {line}
                </div>
              ))}
            </div>
          </Section>
        )}

        {/* Loading state while result is being fetched */}
        {scanState === 'finished' && resultLoading && (
          <div className="flex-1 flex flex-col items-center justify-center gap-5 select-none">
            <div className="relative h-16 w-16">
              <div className="absolute inset-0 rounded-full border-2 border-primary/20" />
              <div className="absolute inset-0 rounded-full border-2 border-transparent border-t-primary animate-spin" />
              <div className="absolute inset-3 rounded-full border border-primary/30 animate-spin"
                style={{ animationDirection: 'reverse', animationDuration: '1.5s' }} />
            </div>
            <div className="text-center space-y-1">
              <div className="text-[13px] font-mono font-semibold">Lade Scan-Ergebnis…</div>
              <div className="text-[11px] font-mono text-muted-foreground">KI-Analyse wird abgerufen</div>
            </div>
          </div>
        )}

        {/* Error state if result fetch failed */}
        {scanState === 'finished' && resultError && !resultLoading && (
          <div className="flex-1 flex flex-col items-center justify-center gap-4 px-8 select-none">
            <div className="h-10 w-10 rounded-full border border-critical/50 bg-critical/10 grid place-items-center">
              <span className="text-critical font-mono font-bold text-lg">!</span>
            </div>
            <div className="text-center space-y-1">
              <div className="text-[13px] font-mono font-semibold text-critical">Ergebnis konnte nicht geladen werden</div>
              <div className="text-[11px] font-mono text-muted-foreground max-w-xs break-all">{resultError}</div>
            </div>
            <button
              onClick={() => jobId && fetchAndSetResult(jobId)}
              className="h-8 px-4 rounded-md border border-border text-[12px] font-mono hover:bg-accent"
            >
              Erneut versuchen
            </button>
          </div>
        )}

        {/* SOC dashboard (finished state) */}
        {showDashboard && (
          <HostScanDecisionDashboard
            data={buildHostScanData(result, selectedHost, host, scanTime, findings, suggestions)}
            onRescan={handleStartScan}
            onExport={() => result && downloadFile(`scan-${selectedHost}-${new Date().toISOString().slice(0, 10)}.json`, JSON.stringify(result, null, 2), 'application/json')}
            onIsolate={() => undefined}
            onInvestigateFinding={(f) => setSelectedFinding(f)}
          />
        )}

        {/* Scan-in-progress HUD */}
        {scanState === 'running' && (
          <div className="flex-1 flex flex-col min-h-0 overflow-hidden select-none relative">

            {/* Background dot-grid */}
            <div className="absolute inset-0 pointer-events-none" style={{ backgroundImage: `radial-gradient(circle, color-mix(in oklab, var(--primary) 18%, transparent) 1px, transparent 1px)`, backgroundSize: '28px 28px', opacity: 0.28 }} />
            <div className="absolute inset-0 pointer-events-none" style={{ background: 'radial-gradient(ellipse 80% 80% at 50% 50%, transparent 30%, var(--background) 100%)' }} />

            {/* TOP HUD BAR */}
            <div className="relative z-10 shrink-0 px-5 py-2.5 flex items-center gap-4" style={{ borderBottom: '1px solid color-mix(in oklab, var(--primary) 18%, transparent)' }}>
              <div className="flex items-center gap-2">
                <span className="h-1.5 w-1.5 rounded-full bg-primary animate-pulse" />
                <span className="text-[12px] font-mono font-bold tracking-wider" style={{ color: 'var(--primary)' }}>{selectedHost}</span>
              </div>
              <div className="flex-1 flex items-center gap-2.5">
                <div className="flex gap-[2px]">
                  {Array.from({ length: 28 }).map((_, i) => {
                    const filled = progress > 0 ? i < Math.round((progress / 100) * 28) : false;
                    const isFront = progress > 0 && i === Math.round((progress / 100) * 28) - 1;
                    return <div key={i} style={{ width: 7, height: 4, borderRadius: 1, background: filled ? 'var(--primary)' : 'color-mix(in oklab, var(--primary) 12%, transparent)', boxShadow: isFront ? '0 0 8px 2px color-mix(in oklab, var(--primary) 80%, transparent)' : 'none', transition: 'box-shadow 0.2s' }} />;
                  })}
                </div>
                <span className="text-[11px] font-mono tabular-nums" style={{ color: 'color-mix(in oklab, var(--primary) 65%, transparent)' }}>
                  {progress > 0 ? `${Math.round(progress)}%` : '…'}
                </span>
              </div>
              {scanMetrics && (
                <span className="text-[11px] font-mono" style={{ color: 'color-mix(in oklab, var(--primary) 45%, transparent)' }}>
                  Modul {scanMetrics.completed_modules}/{scanMetrics.total_modules}
                </span>
              )}
            </div>

            {/* MAIN AREA */}
            <div className="flex-1 flex min-h-0 relative z-10">

              {/* LEFT: radar */}
              <div className="w-[250px] shrink-0 flex items-center justify-center" style={{ borderRight: '1px solid color-mix(in oklab, var(--primary) 12%, transparent)' }}>
                <div className="relative" style={{ width: 210, height: 210 }}>
                  {/* Corner brackets */}
                  {([{ s: { top: 0, left: 0 }, p: 'M2 24 L2 2 L24 2' }, { s: { top: 0, right: 0 }, p: 'M2 2 L24 2 L24 24' }, { s: { bottom: 0, right: 0 }, p: 'M24 2 L24 24 L2 24' }, { s: { bottom: 0, left: 0 }, p: 'M24 24 L2 24 L2 2' }] as const).map(({ s, p }, i) => (
                    <svg key={i} className="absolute" width="26" height="26" viewBox="0 0 26 26" fill="none"
                      style={{ ...s, animation: 'scanCornerPulse 2s ease-in-out infinite', animationDelay: `${i * 0.18}s` }}>
                      <path d={p} stroke="var(--primary)" strokeWidth="1.5" strokeLinecap="square" />
                    </svg>
                  ))}
                  {/* Outer dashed ring */}
                  <div className="absolute inset-0 rounded-full" style={{ border: '1px dashed color-mix(in oklab, var(--primary) 22%, transparent)', animation: 'spin 22s linear infinite reverse' }} />
                  {/* Fast sweep ring */}
                  <div className="absolute rounded-full" style={{ inset: 14, border: '1px solid transparent', borderTopColor: 'color-mix(in oklab, var(--primary) 80%, transparent)', borderRightColor: 'color-mix(in oklab, var(--primary) 30%, transparent)', borderBottomColor: 'color-mix(in oklab, var(--primary) 6%, transparent)', borderLeftColor: 'color-mix(in oklab, var(--primary) 45%, transparent)', borderRadius: '50%', animation: 'spin 4.5s linear infinite', boxShadow: '0 0 6px 1px color-mix(in oklab, var(--primary) 25%, transparent)' }} />
                  {/* Inner counter ring */}
                  <div className="absolute rounded-full" style={{ inset: 40, border: '1px solid transparent', borderRightColor: 'color-mix(in oklab, var(--primary) 60%, transparent)', borderBottomColor: 'color-mix(in oklab, var(--primary) 20%, transparent)', borderRadius: '50%', animation: 'spin 3s linear infinite reverse' }} />
                  {/* Static rings */}
                  {[170, 120, 78].map((d, i) => (
                    <div key={i} className="absolute rounded-full" style={{ width: d, height: d, top: '50%', left: '50%', transform: 'translate(-50%, -50%)', border: `1px solid color-mix(in oklab, var(--primary) ${10 + i * 4}%, transparent)` }} />
                  ))}
                  {/* Sweep cone */}
                  <div className="absolute rounded-full overflow-hidden" style={{ inset: 14 }}>
                    <div className="absolute inset-0 origin-center" style={{ animation: 'spin 2s linear infinite', background: `conic-gradient(from 0deg, transparent 0%, transparent 42%, color-mix(in oklab, var(--primary) 4%, transparent) 58%, color-mix(in oklab, var(--primary) 18%, transparent) 75%, color-mix(in oklab, var(--primary) 50%, transparent) 90%, color-mix(in oklab, var(--primary) 75%, transparent) 100%)` }} />
                  </div>
                  {/* Scan beam */}
                  <div className="absolute overflow-hidden" style={{ inset: 14, borderRadius: '50%' }}>
                    <div className="absolute left-0 right-0" style={{ height: 1, background: `linear-gradient(90deg, transparent 0%, color-mix(in oklab, var(--primary) 85%, transparent) 35%, color-mix(in oklab, var(--primary) 85%, transparent) 65%, transparent 100%)`, boxShadow: `0 0 10px 2px color-mix(in oklab, var(--primary) 55%, transparent)`, animation: 'scanBeam 2.4s ease-in-out infinite' }} />
                  </div>
                  {/* Center reticle */}
                  <div className="absolute inset-0 flex items-center justify-center">
                    <div className="relative flex items-center justify-center">
                      <div className="h-2.5 w-2.5 rounded-full" style={{ background: 'var(--primary)', boxShadow: '0 0 14px 4px color-mix(in oklab, var(--primary) 65%, transparent)', animation: 'scanCornerPulse 1.4s ease-in-out infinite' }} />
                      <div className="absolute rounded-full border border-primary/50 animate-ping" style={{ width: 20, height: 20, animationDuration: '1.6s' }} />
                      <div className="absolute rounded-full border border-primary/20 animate-ping" style={{ width: 36, height: 36, animationDuration: '2.2s', animationDelay: '0.4s' }} />
                    </div>
                  </div>
                </div>
              </div>

              {/* RIGHT: live data */}
              <div className="flex-1 flex flex-col min-h-0 px-5 py-4 gap-4 overflow-y-auto">

                {/* Active module */}
                <div>
                  <div className="text-[9px] font-mono uppercase tracking-widest mb-2" style={{ color: 'color-mix(in oklab, var(--primary) 35%, transparent)' }}>Aktives Modul</div>
                  <div className="flex items-center gap-3 px-3 py-2.5 rounded-lg" style={{ border: '1px solid color-mix(in oklab, var(--primary) 22%, transparent)', background: 'color-mix(in oklab, var(--primary) 5%, transparent)' }}>
                    <ModuleIcon name={activeModule} />
                    <div className="min-w-0">
                      <div className="text-[13px] font-mono font-semibold truncate" style={{ color: 'var(--primary)' }}>
                        {activeModule ?? 'Initialisierung…'}
                      </div>
                      <div className="text-[10.5px] font-mono text-muted-foreground truncate">
                        {MODULE_DESC[activeModule ?? ''] ?? 'Scan wird vorbereitet…'}
                      </div>
                    </div>
                    <span className="ml-auto h-2 w-2 shrink-0 rounded-full bg-primary animate-pulse" />
                  </div>
                </div>

                {/* Module pipeline */}
                {Object.keys(moduleStatus).length > 0 && (
                  <div>
                    <div className="text-[9px] font-mono uppercase tracking-widest mb-2" style={{ color: 'color-mix(in oklab, var(--primary) 35%, transparent)' }}>Module Pipeline</div>
                    <div className="flex flex-wrap gap-1.5">
                      {Object.entries(moduleStatus).map(([mod, st]) => {
                        const isActive = mod === activeModule;
                        const isDone = st === 'done';
                        const isFailed = st === 'failed' || st === 'canceled';
                        return (
                          <div key={mod} className="inline-flex items-center gap-1.5 h-6 px-2.5 rounded-full text-[10px] font-mono" style={{
                            border: `1px solid ${isActive ? 'color-mix(in oklab, var(--primary) 60%, transparent)' : isDone ? 'color-mix(in oklab, var(--success) 40%, transparent)' : isFailed ? 'color-mix(in oklab, var(--destructive) 40%, transparent)' : 'color-mix(in oklab, var(--primary) 15%, transparent)'}`,
                            background: isActive ? 'color-mix(in oklab, var(--primary) 12%, transparent)' : isDone ? 'color-mix(in oklab, var(--success) 8%, transparent)' : 'transparent',
                            color: isActive ? 'var(--primary)' : isDone ? 'var(--success)' : isFailed ? 'var(--destructive)' : 'var(--muted-foreground)',
                          }}>
                            <span>{isDone ? '✓' : isFailed ? '✗' : isActive ? '▶' : '○'}</span>
                            <span>{mod}</span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}

                {/* Live counters */}
                <div>
                  <div className="text-[9px] font-mono uppercase tracking-widest mb-2" style={{ color: 'color-mix(in oklab, var(--primary) 35%, transparent)' }}>Live Daten</div>
                  <div className="grid grid-cols-3 gap-2">
                    {([
                      { label: 'Events geladen', value: scanMetrics?.total_events ?? 0, tone: 'default' as const },
                      { label: 'Relevant', value: scanMetrics?.relevant_events ?? 0, tone: 'default' as const },
                      { label: 'Verarbeitet', value: scanMetrics?.processed_events ?? 0, tone: 'default' as const },
                      { label: 'Findings', value: scanMetrics?.findings ?? 0, tone: ((scanMetrics?.findings ?? 0) > 0 ? 'warning' : 'default') as 'warning' | 'default' },
                      { label: 'High Findings', value: scanMetrics?.high_findings ?? 0, tone: ((scanMetrics?.high_findings ?? 0) > 0 ? 'critical' : 'default') as 'critical' | 'default' },
                      { label: 'TI Treffer', value: scanMetrics?.ti_matches ?? 0, tone: ((scanMetrics?.ti_matches ?? 0) > 0 ? 'critical' : 'default') as 'critical' | 'default' },
                    ]).map(({ label, value, tone }) => {
                      const col = tone === 'critical' ? 'var(--destructive)' : tone === 'warning' ? '#eab308' : 'color-mix(in oklab, var(--primary) 70%, transparent)';
                      return (
                        <div key={label} className="rounded-md px-3 py-2" style={{ border: '1px solid color-mix(in oklab, var(--primary) 10%, transparent)', background: 'color-mix(in oklab, var(--primary) 3%, transparent)' }}>
                          <div className="text-[9px] font-mono text-muted-foreground uppercase tracking-wide mb-1">{label}</div>
                          <div className="text-[18px] font-mono font-bold tabular-nums" style={{ color: col }}>{value.toLocaleString()}</div>
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* AI status */}
                {scanMetrics?.ai_enabled && (
                  <div className="flex items-center gap-3 px-3 py-2 rounded-md" style={{ border: '1px solid color-mix(in oklab, var(--primary) 15%, transparent)' }}>
                    <Brain className="h-4 w-4 shrink-0" style={{ color: 'var(--primary)' }} />
                    <div className="text-[11px] font-mono text-muted-foreground">
                      KI-Analyse aktiv · Iteration {scanMetrics.ai_iterations_completed}/{scanMetrics.ai_iterations_target}
                    </div>
                    <div className="ml-auto flex gap-[3px]">
                      {Array.from({ length: Math.max(1, scanMetrics.ai_iterations_target) }).map((_, i) => (
                        <div key={i} style={{ width: 10, height: 4, borderRadius: 1, background: i < scanMetrics!.ai_iterations_completed ? 'var(--primary)' : 'color-mix(in oklab, var(--primary) 15%, transparent)' }} />
                      ))}
                    </div>
                  </div>
                )}

              </div>
            </div>

            {/* BOTTOM LOG STREAM */}
            <div className="relative z-10 shrink-0 px-4 py-2 overflow-hidden" style={{ borderTop: '1px solid color-mix(in oklab, var(--primary) 12%, transparent)', maxHeight: 130 }}>
              <div className="text-[9px] font-mono uppercase tracking-widest mb-1.5" style={{ color: 'color-mix(in oklab, var(--primary) 25%, transparent)' }}>Log Stream</div>
              <div className="space-y-0.5">
                {(scanLog.length > 0 ? scanLog.slice(-7) : ['Initialisierung…']).map((line, i, arr) => (
                  <div key={i} className="text-[10.5px] font-mono truncate" style={{ color: i === arr.length - 1 ? 'color-mix(in oklab, var(--primary) 75%, transparent)' : 'color-mix(in oklab, var(--primary) 28%, transparent)' }}>
                    <span style={{ color: 'color-mix(in oklab, var(--primary) 22%, transparent)', marginRight: 6 }}>▸</span>{line}
                  </div>
                ))}
              </div>
            </div>

          </div>
        )}

        {scanState === 'idle' && findings.length === 0 && fleetState === 'idle' && (
          <div className="flex-1 grid place-items-center text-[12px] font-mono text-muted-foreground">
            select a host and start a scan →
          </div>
        )}

        {/* Fleet scan HUD — running / failed */}
        {showFleetHUD && (
          <FleetScanHUD
            status={fleetStatus}
            hosts={hosts.map(h => h.host)}
            fleetState={fleetState as 'running' | 'finished' | 'failed' | 'idle'}
            onCancel={handleCancelFleet}
            onDrilldown={(host) => {
              setSelectedHost(host);
              setFleetState('idle');
              setFleetResult(null);
              setFleetStatus(null);
            }}
          />
        )}

        {/* Fleet scan results dashboard — finished */}
        {showFleetResult && (
          <FleetScanDecisionDashboard
            data={buildFleetScanData(fleetResult, fleetStatus, fleetScanStartMs, fleetTotal, fleetFinished)}
            onRescan={handleQuickScanAll}
            onExport={() => {
              const d = buildFleetScanData(fleetResult, fleetStatus, fleetScanStartMs, fleetTotal, fleetFinished);
              downloadFile(
                `fleet-scan-${new Date().toISOString().slice(0, 10)}.json`,
                JSON.stringify(d.rawResult ?? fleetResult, null, 2),
                'application/json',
              );
            }}
            onDownloadReport={() => {
              const d = buildFleetScanData(fleetResult, fleetStatus, fleetScanStartMs, fleetTotal, fleetFinished);
              if (d.markdownReport) {
                downloadFile(`fleet-report-${new Date().toISOString().slice(0, 10)}.md`, d.markdownReport, 'text/markdown');
              } else {
                downloadFile(
                  `fleet-report-${new Date().toISOString().slice(0, 10)}.txt`,
                  `Fleet Scan Report\n=================\nScan-Zeit: ${d.scanTime}\nRisk: ${d.fleetRiskScore}/10\nHosts: ${d.hostsCompleted}/${d.hostsTotal}\nFindings: ${d.totalFindings}\n`,
                );
              }
            }}
            onOpenHost={(h) => {
              const hostRes = findHostResult(fleetResult, h);
              if (hostRes) {
                // Load the individual host result and switch to single-host view
                setResult(hostRes);
                setSelectedHost(h);
                const t = new Date().toLocaleString('de-DE');
                setScanTime(t);
                setScanState('finished');
                ssSave(SS_RESULT, hostRes);
                ssSave(SS_HOST, h);
                ssSave(SS_SCAN_TIME, t);
              } else {
                setSelectedHost(h);
              }
              setFleetState('idle');
              setFleetResult(null);
              setFleetStatus(null);
              sessionStorage.removeItem(SS_FLEET_RESULT);
              sessionStorage.removeItem(SS_FLEET_STATUS);
            }}
          />
        )}
      </div>

      {/* Right: single-scan meta OR fleet meta panel */}
      {showFleetHUD ? (
        <FleetMetaPanel
          status={fleetStatus}
          onDrilldown={(host) => {
            setSelectedHost(host);
            setFleetState('idle');
            setFleetResult(null);
            setFleetStatus(null);
          }}
        />
      ) : !showDashboard && !showFleetResult && (
        <aside className="bg-[var(--panel)] flex flex-col min-h-0">
          <div className="h-9 px-3 flex items-center border-b border-border">
            <span className="text-[12px] font-semibold tracking-wide">
              {selectedFinding ? 'FINDING' : 'SCAN META'}
            </span>
          </div>
          <div className="flex-1 overflow-y-auto">
            {selectedFinding ? (
              <>
                <Sec title="Finding">
                  <KV k="id" v={selectedFinding.id ?? '—'} />
                  <KV k="severity" v={selectedFinding.severity ?? '—'} />
                  <KV k="category" v={selectedFinding.category ?? '—'} />
                </Sec>
                <Sec title="Title">
                  <div className="text-[12px] leading-snug">{selectedFinding.title}</div>
                </Sec>
                {selectedFinding.reason && (
                  <Sec title="Reason">
                    <div className="text-[11.5px] font-mono leading-snug">{selectedFinding.reason}</div>
                  </Sec>
                )}
              </>
            ) : (
              <>
                <Sec title="Host">
                  <KV k="name" v={selectedHost || '—'} />
                  <KV k="platform" v={(host?.platforms ?? [])[0] ?? '—'} />
                  <KV k="alerts" v={String(host?.alert_count ?? 0)} />
                  <KV k="last seen" v={host?.last_seen ?? '—'} />
                </Sec>
                <Sec title="Scan State">
                  <KV k="status" v={scanState} />
                  <KV k="job id" v={jobId ?? '—'} />
                  <KV k="progress" v={progress > 0 ? `${progress}%` : '—'} />
                  <KV k="findings" v={String(findings.length)} />
                </Sec>
              </>
            )}
          </div>
        </aside>
      )}
    </div>
  );
}

// ── Sub-components ────────────────────────────────────────────────────────────

const MODULE_DESC: Record<string, string> = {
  'Events': 'Lade und filtere Event-Daten aus dem Wazuh Indexer',
  'Raw Event JSON': 'Analysiere rohe Event-Strukturen und Felder',
  'Vulnerabilities': 'Prüfe bekannte CVEs und Schwachstellen',
  'FIM': 'File Integrity Monitoring – Dateisystemänderungen',
  'Configuration': 'Analysiere Systemkonfiguration und Inventar',
  'MITRE / Rules': 'Mappe Events auf MITRE ATT&CK Taktiken',
  'Threat Intel': 'Gleiche IPs, Hashes, Domains gegen IOC-Listen ab',
  'Host Context / Inventory': 'Sammle Host-Metadaten und Systeminventar',
  'Final Correlation': 'Korreliere alle Modul-Ergebnisse zu Gesamtbefund',
  'AI Summary': 'KI erstellt strukturierten Analysebericht',
};

function ModuleIcon({ name }: { name: string | null }) {
  const cls = 'h-5 w-5 shrink-0';
  const col = { color: 'var(--primary)' };
  if (!name) return <ScanLine className={cls} style={col} />;
  if (name === 'Events') return <Search className={cls} style={col} />;
  if (name === 'Raw Event JSON') return <FileJson className={cls} style={col} />;
  if (name === 'Vulnerabilities') return <ShieldAlert className={cls} style={col} />;
  if (name === 'FIM') return <FolderSearch className={cls} style={col} />;
  if (name === 'Configuration') return <Settings2 className={cls} style={col} />;
  if (name === 'MITRE / Rules') return <Network className={cls} style={col} />;
  if (name === 'Threat Intel') return <Globe2 className={cls} style={col} />;
  if (name.includes('Inventory') || name.includes('Context')) return <Server className={cls} style={col} />;
  if (name === 'Final Correlation') return <GitMerge className={cls} style={col} />;
  if (name === 'AI Summary') return <Brain className={cls} style={col} />;
  return <Database className={cls} style={col} />;
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="px-3 py-2.5 border-b border-border">
      <div className="text-[11px] font-mono uppercase tracking-wider text-muted-foreground mb-2">
        {title}
      </div>
      {children}
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
    <div className="flex gap-2 text-[11.5px] font-mono py-0.5">
      <span className="text-muted-foreground w-16">{k}</span>
      <span>{v}</span>
    </div>
  );
}

function BarBtn({
  icon: Icon,
  label,
  tone = 'default',
  onClick,
}: {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  tone?: 'default' | 'critical';
  onClick?: () => void;
}) {
  const t =
    tone === 'critical'
      ? 'border-critical/50 hover:bg-critical/15 text-critical'
      : 'border-border hover:bg-accent text-foreground';
  return (
    <button onClick={onClick} className={'h-6 px-2 rounded-sm border text-[11px] font-mono inline-flex items-center gap-1 ' + t}>
      <Icon className="h-3 w-3" />
      {label}
    </button>
  );
}
