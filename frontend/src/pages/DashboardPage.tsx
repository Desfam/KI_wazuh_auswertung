import { useEffect, useMemo, useState } from 'react';
import { getHostOverview, getHostTrend } from '../services/api';
import type { HostOverview, HostTrendPoint } from '../types';

interface Finding {
  host: string;
  platform: string;
  event_id: string | number;
  rule_description: string;
  count: number;
  local_severity: string;
  ai_severity: string;
  suspicious: boolean;
  reason: string;
  first_seen: string;
  last_seen: string;
  local_score: number;
  confidence: string;
  recommended_checks: string[];
}

interface ReportData {
  total_alerts: number;
  relevant_alerts: number;
  top_hosts: Record<string, number>;
  findings: Finding[];
}

interface Props {
  active: boolean;
  theme: 'light' | 'dark';
  reportJson: string | null;
  scriptSummary: { lookback_hours: number; total_alerts: number; relevant_alerts: number } | null;
}

type SortKey = 'count' | 'local_score' | 'local_severity' | 'host';
type SortDir = 'asc' | 'desc';

const SEVERITY_ORDER: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

const SEVERITY_STYLES: Record<string, { bar: string; text: string; pill: string }> = {
  critical: { bar: 'bg-rose-500',    text: 'text-rose-600',    pill: 'bg-rose-100 text-rose-700' },
  high:     { bar: 'bg-orange-500',  text: 'text-orange-600',  pill: 'bg-orange-100 text-orange-700' },
  medium:   { bar: 'bg-yellow-400',  text: 'text-yellow-600',  pill: 'bg-yellow-100 text-yellow-700' },
  low:      { bar: 'bg-emerald-500', text: 'text-emerald-600', pill: 'bg-emerald-100 text-emerald-700' },
  info:     { bar: 'bg-sky-400',     text: 'text-sky-600',     pill: 'bg-sky-100 text-sky-700' },
};

const SEVERITY_STYLES_DARK: Record<string, { bar: string; text: string; pill: string }> = {
  critical: { bar: 'bg-rose-500',    text: 'text-rose-400',    pill: 'bg-rose-900/40 text-rose-300' },
  high:     { bar: 'bg-orange-500',  text: 'text-orange-400',  pill: 'bg-orange-900/40 text-orange-300' },
  medium:   { bar: 'bg-yellow-400',  text: 'text-yellow-400',  pill: 'bg-yellow-900/40 text-yellow-300' },
  low:      { bar: 'bg-emerald-500', text: 'text-emerald-400', pill: 'bg-emerald-900/40 text-emerald-300' },
  info:     { bar: 'bg-sky-400',     text: 'text-sky-400',     pill: 'bg-sky-900/40 text-sky-300' },
};

function sevStyle(sev: string, dark: boolean) {
  const map = dark ? SEVERITY_STYLES_DARK : SEVERITY_STYLES;
  return map[(sev ?? 'info').toLowerCase()] ?? map.info;
}

function KpiCard({
  label, value, sub, accentClass, theme,
}: {
  label: string; value: string | number; sub?: string; accentClass: string; theme: 'light' | 'dark';
}) {
  const dk = theme === 'dark';
  return (
    <div className={`flex flex-col gap-1 rounded-2xl p-5 shadow-sm ring-1 ${dk ? 'bg-white/5 ring-white/10' : 'bg-white ring-black/5'}`}>
      <span className={`text-3xl font-bold tabular-nums ${accentClass}`}>{value}</span>
      <span className={`text-xs font-semibold uppercase tracking-widest ${dk ? 'text-slate-400' : 'text-slate-500'}`}>{label}</span>
      {sub && <span className={`text-xs ${dk ? 'text-slate-500' : 'text-slate-400'}`}>{sub}</span>}
    </div>
  );
}

export function DashboardPage({ active, theme, reportJson, scriptSummary }: Props) {
  const [sortKey, setSortKey] = useState<SortKey>('count');
  const [sortDir, setSortDir] = useState<SortDir>('desc');
  const [expandedRow, setExpandedRow] = useState<number | null>(null);
  const [selectedHost, setSelectedHost] = useState<string>('all');
  const [hostOverview, setHostOverview] = useState<HostOverview | null>(null);
  const [hostTrend, setHostTrend] = useState<HostTrendPoint[]>([]);
  const dk = theme === 'dark';

  const data = useMemo<ReportData | null>(() => {
    if (!reportJson) return null;
    try { return JSON.parse(reportJson) as ReportData; }
    catch { return null; }
  }, [reportJson]);

  const stats = useMemo(() => {
    if (!data) return null;
    const findings = data.findings ?? [];
    const severityCounts: Record<string, number> = {};
    const platformCounts: Record<string, number> = {};
    let suspiciousCount = 0;

    for (const f of findings) {
      const sev = (f.local_severity ?? 'info').toLowerCase();
      severityCounts[sev] = (severityCounts[sev] ?? 0) + 1;
      const plat = (f.platform ?? '').toLowerCase().includes('win') ? 'Windows' : 'Linux/Other';
      platformCounts[plat] = (platformCounts[plat] ?? 0) + 1;
      if (f.suspicious) suspiciousCount++;
    }

    const hostEntries = Object.entries(data.top_hosts ?? {}).sort((a, b) => b[1] - a[1]).slice(0, 10);
    const maxHostCount = hostEntries[0]?.[1] ?? 1;
    return { severityCounts, platformCounts, suspiciousCount, hostEntries, maxHostCount, findings };
  }, [data]);

  const sortedFindings = useMemo(() => {
    if (!stats) return [];
    return [...stats.findings].sort((a, b) => {
      let cmp = 0;
      if (sortKey === 'count') cmp = a.count - b.count;
      else if (sortKey === 'local_score') cmp = (a.local_score ?? 0) - (b.local_score ?? 0);
      else if (sortKey === 'local_severity') {
        cmp = (SEVERITY_ORDER[(a.local_severity ?? '').toLowerCase()] ?? 0)
            - (SEVERITY_ORDER[(b.local_severity ?? '').toLowerCase()] ?? 0);
      } else if (sortKey === 'host') cmp = a.host.localeCompare(b.host);
      return sortDir === 'desc' ? -cmp : cmp;
    });
  }, [stats, sortKey, sortDir]);

  const hostOptions = useMemo(() => {
    if (!stats) return [] as string[];
    const fromTopHosts = stats.hostEntries.map(([host]) => host);
    const fromFindings = [...new Set(stats.findings.map((item) => item.host).filter(Boolean))];
    const merged = [...fromTopHosts, ...fromFindings.filter((host) => !fromTopHosts.includes(host))];
    return merged;
  }, [stats]);

  useEffect(() => {
    if (selectedHost !== 'all' && !hostOptions.includes(selectedHost)) {
      setSelectedHost('all');
    }
  }, [hostOptions, selectedHost]);

  useEffect(() => {
    setExpandedRow(null);
  }, [selectedHost]);

  useEffect(() => {
    let activeRequest = true;
    async function loadHostDrilldown() {
      if (selectedHost === 'all') {
        setHostOverview(null);
        setHostTrend([]);
        return;
      }
      try {
        const [overview, trend] = await Promise.all([
          getHostOverview(selectedHost),
          getHostTrend(selectedHost, 14),
        ]);
        if (!activeRequest) return;
        setHostOverview(overview);
        setHostTrend(trend);
      } catch {
        if (!activeRequest) return;
        setHostOverview(null);
        setHostTrend([]);
      }
    }
    void loadHostDrilldown();
    return () => {
      activeRequest = false;
    };
  }, [selectedHost]);

  const filteredFindings = useMemo(() => {
    if (selectedHost === 'all') return sortedFindings;
    return sortedFindings.filter((item) => item.host === selectedHost);
  }, [sortedFindings, selectedHost]);

  const perHostCritical = useMemo(() => {
    if (!stats) return [] as Array<{ host: string; total: number; top: Finding | null }>;
    const grouped = new Map<string, Finding[]>();
    for (const finding of stats.findings) {
      const host = finding.host || 'unknown-host';
      const list = grouped.get(host) ?? [];
      list.push(finding);
      grouped.set(host, list);
    }

    const list = Array.from(grouped.entries()).map(([host, findings]) => {
      const sorted = [...findings].sort((a, b) => {
        const sevA = SEVERITY_ORDER[(a.ai_severity || a.local_severity || '').toLowerCase()] ?? 0;
        const sevB = SEVERITY_ORDER[(b.ai_severity || b.local_severity || '').toLowerCase()] ?? 0;
        if (sevB !== sevA) return sevB - sevA;
        if ((b.local_score ?? 0) !== (a.local_score ?? 0)) return (b.local_score ?? 0) - (a.local_score ?? 0);
        return (b.count ?? 0) - (a.count ?? 0);
      });
      const total = findings.reduce((sum, item) => sum + (item.count ?? 0), 0);
      return { host, total, top: sorted[0] ?? null };
    });

    return list.sort((a, b) => {
      const aSev = SEVERITY_ORDER[(a.top?.ai_severity || a.top?.local_severity || '').toLowerCase()] ?? 0;
      const bSev = SEVERITY_ORDER[(b.top?.ai_severity || b.top?.local_severity || '').toLowerCase()] ?? 0;
      if (bSev !== aSev) return bSev - aSev;
      return b.total - a.total;
    });
  }, [stats]);

  function toggleSort(key: SortKey) {
    if (sortKey === key) setSortDir(d => d === 'desc' ? 'asc' : 'desc');
    else { setSortKey(key); setSortDir('desc'); }
  }

  function SortIcon({ k }: { k: SortKey }) {
    if (sortKey !== k) return <span className="ml-1 opacity-30">↕</span>;
    return <span className="ml-1 opacity-80">{sortDir === 'desc' ? '↓' : '↑'}</span>;
  }

  if (!active) return null;

  return (
    <div className={`h-full overflow-y-auto p-5 ${dk ? 'text-slate-200' : 'text-slate-800'}`}>

      {/* ── Empty state ── */}
      {!data && (
        <div className="flex h-full flex-col items-center justify-center gap-4">
          <span className="text-6xl">📊</span>
          <p className={`text-lg font-semibold ${dk ? 'text-slate-300' : 'text-slate-600'}`}>Noch keine Daten vorhanden</p>
          <p className={`text-sm ${dk ? 'text-slate-500' : 'text-slate-400'}`}>
            Starte einen Wazuh-Scan im Chat, um das Dashboard zu befüllen.
          </p>
        </div>
      )}

      {data && stats && (
        <div className="space-y-6">

          {/* ── Header ── */}
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <h1 className="text-2xl font-bold">Wazuh Dashboard</h1>
              {scriptSummary && (
                <p className={`text-xs ${dk ? 'text-slate-500' : 'text-slate-400'}`}>
                  Zeitraum: letzte {scriptSummary.lookback_hours}h &nbsp;·&nbsp; {new Date().toLocaleString('de-DE')}
                </p>
              )}
            </div>
            <span className={`rounded-full px-3 py-1 text-xs font-medium ${dk ? 'bg-emerald-900/30 text-emerald-300' : 'bg-emerald-50 text-emerald-700'}`}>
              ● Aktuell
            </span>
          </div>

          {/* ── KPI cards ── */}
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            <KpiCard label="Gesamt Alerts"    value={data.total_alerts.toLocaleString('de-DE')} accentClass={dk ? 'text-sky-300' : 'text-sky-600'} theme={theme} />
            <KpiCard label="Relevante Alerts" value={data.relevant_alerts.toLocaleString('de-DE')}
              sub={`${Math.round((data.relevant_alerts / Math.max(data.total_alerts, 1)) * 100)}% aller Alerts`}
              accentClass={dk ? 'text-amber-300' : 'text-amber-600'} theme={theme} />
            <KpiCard label="Verdächtig"       value={stats.suspiciousCount} sub="als suspicious markiert"
              accentClass={dk ? 'text-rose-300' : 'text-rose-600'} theme={theme} />
            <KpiCard label="Aktive Hosts"     value={stats.hostEntries.length}
              sub={`${stats.findings.length} Findings gesamt`}
              accentClass={dk ? 'text-emerald-300' : 'text-emerald-600'} theme={theme} />
          </div>

          {/* ── Host ranking + Severity + Platform ── */}
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">

            {/* Host ranking bars */}
            <div className={`col-span-1 rounded-2xl p-5 shadow-sm ring-1 lg:col-span-2 ${dk ? 'bg-white/5 ring-white/10' : 'bg-white ring-black/5'}`}>
              <h2 className={`mb-4 text-sm font-semibold uppercase tracking-wide ${dk ? 'text-slate-400' : 'text-slate-500'}`}>
                Top Hosts nach Alert-Anzahl
              </h2>
              <div className="space-y-2.5">
                {stats.hostEntries.map(([host, count]) => {
                  const pct = Math.round((count / stats.maxHostCount) * 100);
                  return (
                    <div key={host} className="flex items-center gap-3">
                      <span className={`w-36 truncate text-right text-xs font-mono ${dk ? 'text-slate-300' : 'text-slate-600'}`} title={host}>{host}</span>
                      <div className={`flex-1 overflow-hidden rounded-full ${dk ? 'bg-white/10' : 'bg-slate-100'}`} style={{ height: 12 }}>
                        <div className="h-full rounded-full bg-sky-500 transition-all duration-500" style={{ width: `${pct}%` }} />
                      </div>
                      <span className={`w-10 text-right text-xs tabular-nums font-semibold ${dk ? 'text-sky-300' : 'text-sky-600'}`}>{count}</span>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Severity + Platform stacked */}
            <div className="flex flex-col gap-4">

              {/* Severity breakdown */}
              <div className={`rounded-2xl p-5 shadow-sm ring-1 ${dk ? 'bg-white/5 ring-white/10' : 'bg-white ring-black/5'}`}>
                <h2 className={`mb-4 text-sm font-semibold uppercase tracking-wide ${dk ? 'text-slate-400' : 'text-slate-500'}`}>Schweregrad</h2>
                <div className="space-y-2">
                  {(['critical', 'high', 'medium', 'low', 'info'] as const).map((sev) => {
                    const cnt = stats.severityCounts[sev] ?? 0;
                    if (!cnt) return null;
                    const col = sevStyle(sev, dk);
                    const maxSev = Math.max(...Object.values(stats.severityCounts));
                    const pct = Math.round((cnt / maxSev) * 100);
                    return (
                      <div key={sev} className="flex items-center gap-2">
                        <span className={`w-16 text-right text-[0.7rem] font-semibold uppercase ${col.text}`}>{sev}</span>
                        <div className={`flex-1 overflow-hidden rounded-full ${dk ? 'bg-white/10' : 'bg-slate-100'}`} style={{ height: 8 }}>
                          <div className={`h-full rounded-full ${col.bar} transition-all duration-500`} style={{ width: `${pct}%` }} />
                        </div>
                        <span className={`w-6 text-right text-xs tabular-nums font-bold ${col.text}`}>{cnt}</span>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Platform split */}
              <div className={`rounded-2xl p-5 shadow-sm ring-1 ${dk ? 'bg-white/5 ring-white/10' : 'bg-white ring-black/5'}`}>
                <h2 className={`mb-4 text-sm font-semibold uppercase tracking-wide ${dk ? 'text-slate-400' : 'text-slate-500'}`}>Plattform</h2>
                <div className="space-y-2">
                  {Object.entries(stats.platformCounts).sort((a, b) => b[1] - a[1]).map(([plat, cnt]) => {
                    const total = Object.values(stats.platformCounts).reduce((s, n) => s + n, 0);
                    const pct = Math.round((cnt / total) * 100);
                    const isWin = plat.toLowerCase().includes('win');
                    return (
                      <div key={plat} className="flex items-center gap-2">
                        <span className="text-base">{isWin ? '🪟' : '🐧'}</span>
                        <div className={`flex-1 overflow-hidden rounded-full ${dk ? 'bg-white/10' : 'bg-slate-100'}`} style={{ height: 8 }}>
                          <div className={`h-full rounded-full transition-all duration-500 ${isWin ? 'bg-cyan-500' : 'bg-violet-500'}`} style={{ width: `${pct}%` }} />
                        </div>
                        <span className={`w-8 text-right text-xs tabular-nums font-semibold ${dk ? 'text-slate-300' : 'text-slate-600'}`}>{cnt}</span>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          </div>

          {/* ── Findings table ── */}
          <div className={`rounded-2xl shadow-sm ring-1 ${dk ? 'bg-white/5 ring-white/10' : 'bg-white ring-black/5'}`}>
            <div className={`flex items-center justify-between px-5 py-4 ${dk ? 'border-b border-white/10' : 'border-b border-slate-100'}`}>
              <h2 className={`text-sm font-semibold uppercase tracking-wide ${dk ? 'text-slate-400' : 'text-slate-500'}`}>
                Findings
                <span className={`ml-2 rounded-full px-2 py-0.5 text-[0.65rem] font-bold ${dk ? 'bg-white/10 text-slate-300' : 'bg-slate-100 text-slate-600'}`}>
                  {filteredFindings.length}
                </span>
              </h2>
              <span className={`text-xs ${dk ? 'text-slate-500' : 'text-slate-400'}`}>Klick auf Zeile für Details</span>
            </div>

            <div className={`border-b px-5 py-3 ${dk ? 'border-white/10' : 'border-slate-100'}`}>
              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  onClick={() => setSelectedHost('all')}
                  className={`rounded-xl px-3 py-1.5 text-xs font-semibold transition ${selectedHost === 'all' ? (dk ? 'bg-amber-700/40 text-amber-200' : 'bg-amber-100 text-amber-700') : (dk ? 'bg-white/5 text-slate-300 hover:bg-white/10' : 'bg-slate-100 text-slate-600 hover:bg-slate-200')}`}
                >
                  Alle PCs
                </button>
                {hostOptions.map((host) => (
                  <button
                    key={host}
                    type="button"
                    onClick={() => setSelectedHost(host)}
                    className={`rounded-xl px-3 py-1.5 text-xs font-semibold transition ${selectedHost === host ? (dk ? 'bg-sky-700/40 text-sky-200' : 'bg-sky-100 text-sky-700') : (dk ? 'bg-white/5 text-slate-300 hover:bg-white/10' : 'bg-slate-100 text-slate-600 hover:bg-slate-200')}`}
                  >
                    {host}
                  </button>
                ))}
              </div>
            </div>

            <div className={`border-b px-5 py-4 ${dk ? 'border-white/10' : 'border-slate-100'}`}>
              <h3 className={`mb-3 text-xs font-semibold uppercase tracking-widest ${dk ? 'text-slate-400' : 'text-slate-500'}`}>
                Kritischste Findings pro PC
              </h3>
              <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
                {perHostCritical.slice(0, 9).map((entry) => {
                  const topFinding = entry.top;
                  const sev = topFinding?.ai_severity || topFinding?.local_severity || 'info';
                  const col = sevStyle(sev, dk);
                  return (
                    <button
                      key={entry.host}
                      type="button"
                      onClick={() => setSelectedHost(entry.host)}
                      className={`rounded-xl border p-3 text-left transition hover:-translate-y-0.5 ${selectedHost === entry.host ? (dk ? 'border-sky-500/50 bg-sky-500/10' : 'border-sky-200 bg-sky-50') : (dk ? 'border-white/10 bg-white/5 hover:bg-white/10' : 'border-slate-100 bg-slate-50 hover:bg-slate-100')}`}
                    >
                      <p className={`truncate text-xs font-bold ${dk ? 'text-slate-100' : 'text-slate-800'}`}>{entry.host}</p>
                      <p className={`mt-2 inline-block rounded-full px-2 py-0.5 text-[0.65rem] font-bold uppercase ${col.pill}`}>
                        {sev}
                      </p>
                      <p className={`mt-2 line-clamp-2 text-[0.72rem] ${dk ? 'text-slate-300' : 'text-slate-600'}`}>
                        {topFinding?.rule_description || '(keine Regelbeschreibung)'}
                      </p>
                      <p className={`mt-1 text-[0.68rem] ${dk ? 'text-slate-400' : 'text-slate-500'}`}>
                        Top Count: {topFinding?.count ?? 0} · Gesamt auf PC: {entry.total}
                      </p>
                    </button>
                  );
                })}
              </div>
            </div>

            {selectedHost !== 'all' && (
              <div className={`border-b px-5 py-4 ${dk ? 'border-white/10' : 'border-slate-100'}`}>
                <h3 className={`mb-3 text-xs font-semibold uppercase tracking-widest ${dk ? 'text-slate-400' : 'text-slate-500'}`}>
                  Host Full Scan: {selectedHost}
                </h3>
                {!hostOverview ? (
                  <p className={`text-xs ${dk ? 'text-slate-500' : 'text-slate-400'}`}>Keine Host-Detaildaten verfügbar.</p>
                ) : (
                  <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4">
                    <div className={`rounded-xl p-3 ${dk ? 'bg-white/5' : 'bg-slate-50'}`}>
                      <p className={`text-[0.65rem] uppercase ${dk ? 'text-slate-500' : 'text-slate-400'}`}>Gruppierte Events</p>
                      <p className="mt-1 text-lg font-bold">{hostOverview.total_grouped_events}</p>
                    </div>
                    <div className={`rounded-xl p-3 ${dk ? 'bg-white/5' : 'bg-slate-50'}`}>
                      <p className={`text-[0.65rem] uppercase ${dk ? 'text-slate-500' : 'text-slate-400'}`}>Finding-Gruppen</p>
                      <p className="mt-1 text-lg font-bold">{hostOverview.finding_groups}</p>
                    </div>
                    <div className={`rounded-xl p-3 ${dk ? 'bg-white/5' : 'bg-slate-50'}`}>
                      <p className={`text-[0.65rem] uppercase ${dk ? 'text-slate-500' : 'text-slate-400'}`}>Top Score</p>
                      <p className="mt-1 text-lg font-bold">{hostOverview.top_local_score}</p>
                    </div>
                    <div className={`rounded-xl p-3 ${dk ? 'bg-white/5' : 'bg-slate-50'}`}>
                      <p className={`text-[0.65rem] uppercase ${dk ? 'text-slate-500' : 'text-slate-400'}`}>Suspicious Gruppen</p>
                      <p className="mt-1 text-lg font-bold">{hostOverview.suspicious_groups}</p>
                    </div>
                  </div>
                )}
                {hostTrend.length > 0 && (
                  <div className="mt-4">
                    <p className={`mb-2 text-[0.65rem] uppercase tracking-widest ${dk ? 'text-slate-500' : 'text-slate-400'}`}>
                      Historischer Verlauf (letzte {hostTrend.length} Runs)
                    </p>
                    <div className="space-y-2">
                      {hostTrend.map((point) => {
                        const maxTotal = Math.max(...hostTrend.map((x) => x.total_grouped_events), 1);
                        const pct = Math.round((point.total_grouped_events / maxTotal) * 100);
                        return (
                          <div key={point.job_id} className="flex items-center gap-2">
                            <span className={`w-24 text-[0.68rem] ${dk ? 'text-slate-400' : 'text-slate-500'}`}>Job #{point.job_id}</span>
                            <div className={`h-2 flex-1 overflow-hidden rounded-full ${dk ? 'bg-white/10' : 'bg-slate-100'}`}>
                              <div className="h-full rounded-full bg-indigo-500" style={{ width: `${pct}%` }} />
                            </div>
                            <span className={`w-20 text-right text-[0.68rem] ${dk ? 'text-slate-300' : 'text-slate-600'}`}>{point.total_grouped_events}</span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}
              </div>
            )}

            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className={dk ? 'bg-white/5 text-slate-400' : 'bg-slate-50 text-slate-500'}>
                    {([
                      { key: 'host' as SortKey, label: 'Host' },
                      { key: null,               label: 'Plattform' },
                      { key: null,               label: 'Event-ID' },
                      { key: null,               label: 'Regel' },
                      { key: 'count' as SortKey, label: 'Anz.' },
                      { key: 'local_severity' as SortKey, label: 'Schwere' },
                      { key: 'local_score' as SortKey,    label: 'Score' },
                      { key: null,               label: 'Verd.' },
                    ] as const).map(({ key, label }) => (
                      <th
                        key={label}
                        className={`px-4 py-2.5 text-left font-semibold uppercase tracking-wide ${key ? 'cursor-pointer select-none hover:opacity-70' : ''}`}
                        onClick={key ? () => toggleSort(key) : undefined}
                      >
                        {label}{key && <SortIcon k={key} />}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {filteredFindings.map((f, i) => {
                    const col = sevStyle(f.local_severity, dk);
                    const isExpanded = expandedRow === i;
                    return (
                      <>
                        <tr
                          key={`r${i}`}
                          onClick={() => setExpandedRow(isExpanded ? null : i)}
                          className={`cursor-pointer border-t transition-colors ${dk ? 'border-white/5 hover:bg-white/5' : 'border-slate-50 hover:bg-slate-50'} ${isExpanded ? (dk ? 'bg-white/5' : 'bg-slate-50') : ''}`}
                        >
                          <td className={`px-4 py-2 font-mono ${dk ? 'text-sky-300' : 'text-sky-700'}`}>{f.host}</td>
                          <td className="px-4 py-2">{(f.platform ?? '').toLowerCase().includes('win') ? '🪟 Win' : '🐧 Linux'}</td>
                          <td className={`px-4 py-2 font-mono ${dk ? 'text-slate-400' : 'text-slate-500'}`}>{f.event_id}</td>
                          <td className={`max-w-[220px] truncate px-4 py-2 ${dk ? 'text-slate-200' : 'text-slate-700'}`} title={f.rule_description}>{f.rule_description}</td>
                          <td className={`px-4 py-2 font-bold tabular-nums ${dk ? 'text-amber-300' : 'text-amber-600'}`}>{f.count}</td>
                          <td className="px-4 py-2">
                            <span className={`inline-block rounded-full px-2 py-0.5 text-[0.65rem] font-bold uppercase ${col.pill}`}>
                              {f.local_severity}
                            </span>
                          </td>
                          <td className={`px-4 py-2 tabular-nums ${dk ? 'text-slate-300' : 'text-slate-600'}`}>{f.local_score?.toFixed(1) ?? '—'}</td>
                          <td className="px-4 py-2 text-center">
                            {f.suspicious ? <span title="Suspicious">⚠️</span> : <span className={dk ? 'text-slate-600' : 'text-slate-300'}>–</span>}
                          </td>
                        </tr>

                        {isExpanded && (
                          <tr key={`d${i}`} className={dk ? 'bg-white/5' : 'bg-slate-50'}>
                            <td colSpan={8} className="px-6 pb-4 pt-2">
                              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
                                <div>
                                  <p className={`mb-1 text-[0.6rem] font-semibold uppercase tracking-widest ${dk ? 'text-slate-500' : 'text-slate-400'}`}>KI-Schwere</p>
                                  <span className={`inline-block rounded-full px-2 py-0.5 text-[0.65rem] font-bold uppercase ${sevStyle(f.ai_severity, dk).pill}`}>{f.ai_severity ?? '—'}</span>
                                </div>
                                <div>
                                  <p className={`mb-1 text-[0.6rem] font-semibold uppercase tracking-widest ${dk ? 'text-slate-500' : 'text-slate-400'}`}>Konfidenz</p>
                                  <span className={dk ? 'text-slate-300' : 'text-slate-700'}>{f.confidence ?? '—'}</span>
                                </div>
                                <div>
                                  <p className={`mb-1 text-[0.6rem] font-semibold uppercase tracking-widest ${dk ? 'text-slate-500' : 'text-slate-400'}`}>Zeitraum</p>
                                  <span className={`font-mono text-[0.7rem] ${dk ? 'text-slate-400' : 'text-slate-500'}`}>
                                    {f.first_seen ? new Date(f.first_seen).toLocaleString('de-DE') : '—'}
                                    {' → '}
                                    {f.last_seen ? new Date(f.last_seen).toLocaleString('de-DE') : '—'}
                                  </span>
                                </div>
                                <div className="sm:col-span-2 lg:col-span-3">
                                  <p className={`mb-1 text-[0.6rem] font-semibold uppercase tracking-widest ${dk ? 'text-slate-500' : 'text-slate-400'}`}>Grund</p>
                                  <p className={dk ? 'text-slate-300' : 'text-slate-700'}>{f.reason ?? '—'}</p>
                                </div>
                                {f.recommended_checks?.length > 0 && (
                                  <div className="sm:col-span-2 lg:col-span-3">
                                    <p className={`mb-1 text-[0.6rem] font-semibold uppercase tracking-widest ${dk ? 'text-slate-500' : 'text-slate-400'}`}>Empfohlene Prüfungen</p>
                                    <ul className={`list-disc space-y-0.5 pl-4 ${dk ? 'text-slate-400' : 'text-slate-600'}`}>
                                      {f.recommended_checks.map((c, ci) => <li key={ci}>{c}</li>)}
                                    </ul>
                                  </div>
                                )}
                              </div>
                            </td>
                          </tr>
                        )}
                      </>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
