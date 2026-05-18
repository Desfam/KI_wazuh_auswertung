import type { ComponentType } from 'react';
import {
  AlertTriangle,
  BarChart3,
  CalendarClock,
  CheckCircle2,
  ChevronRight,
  CircleDot,
  ClipboardList,
  Database,
  Download,
  FileText,
  Globe2,
  Info,
  Monitor,
  RefreshCw,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Upload,
} from 'lucide-react';

// CalendarClock / Server / ClipboardList used below
void CalendarClock; void Server; void ClipboardList;

export type FleetScanHostRow = {
  host: string;
  platform?: string;
  riskScore: number; // 0-10
  findings: number;
  critical: number;
  status: 'critical' | 'high' | 'medium' | 'low' | 'watch';
  lastSeen?: string;
  trend?: number[];
};

export type FleetScanFinding = {
  title: string;
  affectedHosts: number;
  trend: number;
  severity?: 'critical' | 'high' | 'medium' | 'low';
};

export type FleetScanBaselineItem = {
  label: string;
  value: number;
  delta?: number;
};

export type FleetScanActivity = {
  time: string;
  text: string;
  level?: 'info' | 'warning' | 'critical' | 'success';
};

export type FleetScanResultsDashboardProps = {
  hosts: FleetScanHostRow[];
  startedAt?: string;
  duration?: string;
  scanMode?: string;
  totalEvents?: number;
  analyzedLogs?: number;
  checkedFiles?: number;
  checkedConfigs?: number;
  checkedVulnerabilities?: number;
  tiTotal?: number;
  tiConfirmed?: number;
  tiMaliciousIps?: number;
  tiMalwareHashes?: number;
  tiDomains?: number;
  tiGeoRisk?: number;
  baselineItems?: FleetScanBaselineItem[];
  topFindings?: FleetScanFinding[];
  recentActivity?: FleetScanActivity[];
  onRescan?: () => void;
  onExport?: () => void;
  onDownloadReport?: () => void;
  onOpenHost?: (host: string) => void;
  onShowAllHosts?: () => void;
  onShowFindings?: () => void;
};

function riskLevel(score: number) {
  if (score >= 7) return 'critical';
  if (score >= 5) return 'high';
  if (score >= 3) return 'medium';
  return 'low';
}

function riskLabel(score: number) {
  if (score >= 7) return 'HOCH';
  if (score >= 5) return 'MITTEL';
  if (score >= 3) return 'NIEDRIG';
  return 'SEHR NIEDRIG';
}

function scoreColor(score: number) {
  if (score >= 7) return 'text-critical';
  if (score >= 5) return 'text-warning';
  return 'text-success';
}

function statusClass(status: FleetScanHostRow['status']) {
  if (status === 'critical') return 'border-critical/50 bg-critical/10 text-critical';
  if (status === 'high') return 'border-high/50 bg-high/10 text-high';
  if (status === 'medium') return 'border-warning/50 bg-warning/10 text-warning';
  if (status === 'watch') return 'border-primary/50 bg-primary/10 text-primary';
  return 'border-success/50 bg-success/10 text-success';
}

function statusText(status: FleetScanHostRow['status']) {
  if (status === 'critical') return 'Kritisch';
  if (status === 'high') return 'Hoch';
  if (status === 'medium') return 'Warnung';
  if (status === 'watch') return 'Beobachten';
  return 'Niedrig';
}

function platformIcon(platform?: string) {
  const p = (platform ?? '').toLowerCase();
  if (p.includes('linux') || p.includes('ubuntu') || p.includes('debian')) return '🐧';
  if (p.includes('windows')) return '🪟';
  return '🖥️';
}

function miniTrendColor(score: number) {
  if (score >= 7) return '#ef4444';
  if (score >= 5) return '#f59e0b';
  return '#22c55e';
}

function formatNumber(n?: number) {
  if (n == null) return '—';
  return n.toLocaleString('de-DE');
}

function defaultTrend(score: number) {
  const base = Math.max(0.5, score - 1.8);
  return [base, base + 0.3, base + 0.1, base + 0.5, score - 0.3, score - 0.1, score];
}

function Sparkline({ values, color }: { values: number[]; color: string }) {
  const max = Math.max(...values, 1);
  const min = Math.min(...values, 0);
  const points = values
    .map((v, i) => {
      const x = (i / Math.max(values.length - 1, 1)) * 90;
      const y = 28 - ((v - min) / Math.max(max - min, 0.1)) * 24;
      return `${x},${y}`;
    })
    .join(' ');
  return (
    <svg viewBox="0 0 90 30" className="h-7 w-24">
      <polyline points={points} fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function TopButton({ icon: Icon, label, onClick }: { icon: ComponentType<{ className?: string }>; label: string; onClick?: () => void }) {
  return (
    <button onClick={onClick} className="h-9 px-3 rounded-md border border-border hover:bg-accent text-[12px] font-mono inline-flex items-center gap-2">
      <Icon className="h-4 w-4" />
      {label}
    </button>
  );
}

function Card({ children, className = '' }: { children: React.ReactNode; className?: string }) {
  return (
    <div className={'rounded-lg border border-border bg-[var(--panel)]/80 shadow-[0_0_35px_rgba(0,140,255,0.05)] ' + className}>
      {children}
    </div>
  );
}

function CardHeader({ title, right }: { title: string; right?: React.ReactNode }) {
  return (
    <div className="h-10 px-4 border-b border-border flex items-center justify-between">
      <div className="text-[11px] font-mono uppercase tracking-widest text-muted-foreground">{title}</div>
      {right && <div className="text-[11px] font-mono text-muted-foreground">{right}</div>}
    </div>
  );
}

function StatCard({
  label, value, sub, icon: Icon, tone = 'default',
}: {
  label: string;
  value: React.ReactNode;
  sub?: React.ReactNode;
  icon: ComponentType<{ className?: string }>;
  tone?: 'default' | 'success' | 'warning' | 'critical' | 'primary';
}) {
  const iconClass =
    tone === 'critical' ? 'text-critical' :
    tone === 'warning' ? 'text-warning' :
    tone === 'success' ? 'text-success' : 'text-primary';

  return (
    <Card className="px-4 py-3 min-h-[118px]">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">{label}</div>
          <div className="mt-2 text-[30px] font-mono font-bold leading-none">{value}</div>
          {sub && <div className="mt-2 text-[11px] font-mono text-muted-foreground">{sub}</div>}
        </div>
        <Icon className={`h-9 w-9 opacity-80 ${iconClass}`} />
      </div>
    </Card>
  );
}

function RiskDonut({ critical, high, medium, low }: { critical: number; high: number; medium: number; low: number }) {
  const total = Math.max(critical + high + medium + low, 1);
  const c = (critical / total) * 100;
  const h = (high / total) * 100;
  const m = (medium / total) * 100;
  return (
    <div
      className="h-32 w-32 rounded-full grid place-items-center"
      style={{ background: `conic-gradient(#ef4444 0 ${c}%, #f97316 ${c}% ${c + h}%, #eab308 ${c + h}% ${c + h + m}%, #22c55e ${c + h + m}% 100%)` }}
    >
      <div className="h-20 w-20 rounded-full bg-[var(--panel)] grid place-items-center border border-border">
        <div className="text-center">
          <div className="text-[22px] font-mono font-bold">{total}</div>
          <div className="text-[10px] font-mono text-muted-foreground">Hosts</div>
        </div>
      </div>
    </div>
  );
}

function RiskDistribution({ critical, high, medium, low, total }: { critical: number; high: number; medium: number; low: number; total: number }) {
  const rows = [
    ['Kritisch', critical, 'bg-critical', 'text-critical'],
    ['Hoch', high, 'bg-high', 'text-high'],
    ['Mittel', medium, 'bg-warning', 'text-warning'],
    ['Niedrig', low, 'bg-success', 'text-success'],
  ] as const;

  return (
    <div className="grid grid-cols-[140px_1fr] gap-4 items-center p-4">
      <RiskDonut critical={critical} high={high} medium={medium} low={low} />
      <div className="space-y-2">
        {rows.map(([label, value, bg, text]) => {
          const pct = total > 0 ? Math.round((value / total) * 100) : 0;
          return (
            <div key={label} className="grid grid-cols-[70px_1fr_70px] gap-2 items-center">
              <div className="text-[11px] font-mono text-muted-foreground">{label}</div>
              <div className="h-2 rounded-full bg-muted overflow-hidden">
                <div className={`h-full ${bg}`} style={{ width: `${pct}%` }} />
              </div>
              <div className={`text-[11px] font-mono text-right ${text}`}>{value} ({pct}%)</div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

export default function FleetScanResultsDashboard({
  hosts,
  startedAt = '—',
  duration = '—',
  scanMode = 'Full Scan (All)',
  totalEvents,
  analyzedLogs,
  checkedFiles,
  checkedConfigs,
  checkedVulnerabilities,
  tiTotal = 0,
  tiConfirmed = 0,
  tiMaliciousIps = 0,
  tiMalwareHashes = 0,
  tiDomains = 0,
  tiGeoRisk = 0,
  baselineItems,
  topFindings,
  recentActivity,
  onRescan,
  onExport,
  onDownloadReport,
  onOpenHost,
  onShowAllHosts,
  onShowFindings,
}: FleetScanResultsDashboardProps) {
  const totalHosts = hosts.length;
  const completedHosts = totalHosts;

  const criticalHosts = hosts.filter(h => h.riskScore >= 7).length;
  const highHosts = hosts.filter(h => h.riskScore >= 5 && h.riskScore < 7).length;
  const mediumHosts = hosts.filter(h => h.riskScore >= 3 && h.riskScore < 5).length;
  const lowHosts = hosts.filter(h => h.riskScore < 3).length;

  const totalFindings = hosts.reduce((sum, h) => sum + h.findings, 0);
  const fleetRisk = totalHosts > 0 ? hosts.reduce((sum, h) => sum + h.riskScore, 0) / totalHosts : 0;

  const sortedHosts = [...hosts].sort((a, b) => b.riskScore - a.riskScore);

  const baseline = baselineItems ?? [
    { label: 'Konfiguration', value: 31, delta: 9 },
    { label: 'Sicherheits-Updates', value: 22, delta: -5 },
    { label: 'Benutzer & Berechtigungen', value: 16, delta: 4 },
    { label: 'Services & Prozesse', value: 12, delta: 0 },
  ];

  const findings = topFindings ?? [
    { title: 'Veraltete Sicherheitsupdates', affectedHosts: 26, trend: 6, severity: 'medium' as const },
    { title: 'Schwache Passwortrichtlinien', affectedHosts: 18, trend: 3, severity: 'high' as const },
    { title: 'Offene, nicht benötigte Ports', affectedHosts: 15, trend: 2, severity: 'medium' as const },
    { title: 'Unsichere Service-Konfigurationen', affectedHosts: 13, trend: 4, severity: 'medium' as const },
    { title: 'Verdächtige Anmeldeaktivitäten', affectedHosts: 11, trend: 1, severity: 'high' as const },
  ];

  const activity = recentActivity ?? [
    { time: '—', text: 'Fleet Scan abgeschlossen', level: 'success' as const },
    { time: '—', text: 'Bericht generiert', level: 'info' as const },
    { time: '—', text: 'Alle Hosts analysiert', level: 'info' as const },
    { time: '—', text: 'Ergebnisse aggregiert', level: 'info' as const },
  ];

  return (
    <div className="h-full min-h-0 overflow-y-auto bg-background px-4 py-4">
      {/* Header */}
      <div className="mb-4 flex items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <div className="h-10 w-10 rounded-lg border border-primary/40 bg-primary/10 flex items-center justify-center">
              <Shield className="h-6 w-6 text-primary" />
            </div>
            <div>
              <div className="flex items-center gap-3">
                <h1 className="text-[25px] font-semibold tracking-tight">Fleet Scan Results</h1>
                <span className="h-7 px-3 rounded-md border border-success/40 bg-success/10 text-success text-[11px] font-mono uppercase tracking-wider inline-flex items-center gap-1.5">
                  <CheckCircle2 className="h-3 w-3" />
                  Fleet Scan abgeschlossen
                </span>
                <span className="text-[16px] font-mono font-bold">
                  {completedHosts} / {totalHosts} hosts complete
                </span>
              </div>
              <div className="mt-1.5 flex items-center gap-2">
                <span className="h-5 px-2 rounded-sm border border-primary/30 bg-primary/10 text-primary text-[10px] font-mono uppercase tracking-widest inline-flex items-center">
                  Audit Snapshot
                </span>
                <span className="text-[12px] font-mono text-muted-foreground">
                  {scanMode} · {startedAt} · Dauer: {duration}
                </span>
              </div>
            </div>
          </div>
        </div>
        <div className="flex gap-2 shrink-0">
          <TopButton icon={Upload} label="Export" onClick={onExport} />
          <TopButton icon={Download} label="Bericht herunterladen" onClick={onDownloadReport} />
          <TopButton icon={RefreshCw} label="Re-scan" onClick={onRescan} />
        </div>
      </div>

      {/* Top Stats */}
      <div className="grid grid-cols-6 gap-3">
        <StatCard
          label="Fleet Risk Score"
          value={
            <span className={scoreColor(fleetRisk)}>
              {fleetRisk.toFixed(1)}
              <span className="text-[16px] text-muted-foreground"> /10</span>
            </span>
          }
          sub={
            <span className={`px-1.5 py-px rounded-sm border text-[11px] ${statusClass(riskLevel(fleetRisk) as FleetScanHostRow['status'])}`}>
              {riskLabel(fleetRisk)}
            </span>
          }
          icon={Shield}
          tone="primary"
        />
        <StatCard
          label="Hosts gescannt"
          value={<span>{completedHosts}<span className="text-[16px] text-muted-foreground"> / {totalHosts}</span></span>}
          sub={<span className="text-success">100% abgeschlossen</span>}
          icon={Monitor}
          tone="primary"
        />
        <StatCard
          label="Findings gesamt"
          value={<span className="text-warning">{totalFindings}</span>}
          sub="Alle Hosts zusammen"
          icon={FileText}
          tone="warning"
        />
        <StatCard
          label="Kritische Hosts"
          value={<span className="text-critical">{criticalHosts}</span>}
          sub="Hosts mit kritischem Risiko"
          icon={AlertTriangle}
          tone="critical"
        />
        <StatCard
          label="Threat Intel Treffer"
          value={<span>{tiConfirmed}<span className="text-[16px] text-muted-foreground"> /{tiTotal || tiConfirmed}</span></span>}
          sub="Bestätigte IOC-Matches"
          icon={Globe2}
          tone="primary"
        />
        <StatCard
          label="Gesamtstatus"
          value={
            <span className={`text-[22px] ${criticalHosts > 0 ? 'text-warning' : 'text-success'}`}>
              {criticalHosts > 0 ? 'SICHERHEIT ERFORDERT' : 'OK'}
            </span>
          }
          sub={criticalHosts > 0 ? 'Taktische Maßnahmen empfohlen' : 'Keine kritischen Befunde'}
          icon={ShieldCheck}
          tone={criticalHosts > 0 ? 'warning' : 'success'}
        />
      </div>

      <div className="mt-3 grid grid-cols-[2.25fr_0.85fr] gap-3">
        {/* Left main area */}
        <div className="space-y-3">
          {/* Hosts table */}
          <Card>
            <CardHeader title={`Hosts (${totalHosts})`} right={`1–${Math.min(15, totalHosts)} von ${totalHosts} Hosts`} />
            <div className="overflow-x-auto">
              <table className="w-full text-[12px] font-mono">
                <thead className="border-b border-border text-[10px] uppercase tracking-wider text-muted-foreground">
                  <tr>
                    <th className="px-3 py-2 text-left w-[34px]" />
                    <th className="px-3 py-2 text-left">Host</th>
                    <th className="px-3 py-2 text-left">Platform</th>
                    <th className="px-3 py-2 text-left">Risk Score</th>
                    <th className="px-3 py-2 text-left">Findings</th>
                    <th className="px-3 py-2 text-left">Kritisch</th>
                    <th className="px-3 py-2 text-left">Status</th>
                    <th className="px-3 py-2 text-left">Trend (7d)</th>
                    <th className="px-3 py-2 text-left">Last Seen</th>
                  </tr>
                </thead>
                <tbody>
                  {sortedHosts.slice(0, 15).map(h => {
                    const trend = h.trend?.length ? h.trend : defaultTrend(h.riskScore);
                    return (
                      <tr
                        key={h.host}
                        onClick={() => onOpenHost?.(h.host)}
                        className="border-b border-border/60 hover:bg-[var(--row-hover)] cursor-pointer"
                      >
                        <td className="px-3 py-2 text-muted-foreground"><CircleDot className="h-3.5 w-3.5" /></td>
                        <td className="px-3 py-2 font-semibold">
                          <span className="mr-2">{platformIcon(h.platform)}</span>{h.host}
                        </td>
                        <td className="px-3 py-2 text-muted-foreground">{h.platform ?? '—'}</td>
                        <td className={`px-3 py-2 font-bold ${scoreColor(h.riskScore)}`}>
                          {h.riskScore.toFixed(1)}<span className="text-muted-foreground font-normal"> /10</span>
                        </td>
                        <td className="px-3 py-2">{h.findings}</td>
                        <td className={`px-3 py-2 font-bold ${h.critical > 0 ? 'text-critical' : 'text-success'}`}>{h.critical}</td>
                        <td className="px-3 py-2">
                          <span className={`h-6 px-2 rounded-sm border text-[10px] uppercase font-bold inline-flex items-center ${statusClass(h.status)}`}>
                            {statusText(h.status)}
                          </span>
                        </td>
                        <td className="px-3 py-2"><Sparkline values={trend} color={miniTrendColor(h.riskScore)} /></td>
                        <td className="px-3 py-2 text-muted-foreground">{h.lastSeen ?? '—'}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            <div className="h-11 px-4 flex items-center justify-between">
              <div className="text-[11px] font-mono text-muted-foreground">1–{Math.min(15, totalHosts)} von {totalHosts} Hosts</div>
              <button
                onClick={onShowAllHosts}
                className="h-7 px-3 rounded-sm border border-border hover:bg-accent text-[12px] font-mono inline-flex items-center gap-1"
              >
                Alle Hosts anzeigen<ChevronRight className="h-3 w-3" />
              </button>
            </div>
          </Card>

          {/* Bottom grid */}
          <div className="grid grid-cols-[0.95fr_0.95fr_0.8fr] gap-3">
            {/* Baseline */}
            <Card>
              <CardHeader title="Baseline Vergleich (Fleet)" />
              <div className="grid grid-cols-4 divide-x divide-border">
                {baseline.map(item => (
                  <div key={item.label} className="p-4 min-h-[150px]">
                    <div className="text-[11px] font-mono text-muted-foreground leading-snug">{item.label}</div>
                    <div className="mt-5 text-[32px] font-mono font-bold">{item.value}</div>
                    <div className={`mt-2 text-[11px] font-mono ${(item.delta ?? 0) > 0 ? 'text-critical' : (item.delta ?? 0) < 0 ? 'text-success' : 'text-muted-foreground'}`}>
                      {item.delta == null ? '—' : item.delta > 0 ? `↑ +${item.delta}` : item.delta < 0 ? `↓ ${item.delta}` : '± 0'}
                    </div>
                  </div>
                ))}
              </div>
              <div className="h-10 px-4 border-t border-border flex items-center">
                <button className="text-[12px] font-mono text-primary hover:underline">Detaillierten Vergleich anzeigen</button>
              </div>
            </Card>

            {/* Top Findings */}
            <Card>
              <CardHeader title="Top Findings (Fleet)" right={findings.length} />
              <div className="divide-y divide-border/60">
                {findings.map(f => (
                  <div key={f.title} className="px-4 py-2.5 grid grid-cols-[1fr_90px_60px] gap-3">
                    <div className="flex items-center gap-2 min-w-0">
                      <Info className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                      <span className="truncate text-[12px] font-mono">{f.title}</span>
                    </div>
                    <div className="text-[12px] font-mono text-muted-foreground">{f.affectedHosts} Hosts</div>
                    <div className={`text-[12px] font-mono text-right ${f.trend > 0 ? 'text-critical' : 'text-success'}`}>
                      {f.trend > 0 ? `↑ +${f.trend}` : `↓ ${f.trend}`}
                    </div>
                  </div>
                ))}
              </div>
              <div className="h-10 px-4 border-t border-border flex items-center">
                <button onClick={onShowFindings} className="text-[12px] font-mono text-primary hover:underline">Alle Findings anzeigen</button>
              </div>
            </Card>

            {/* Recent Activity */}
            <Card>
              <CardHeader title="Kürzliche Aktivität (Fleet)" />
              <div className="divide-y divide-border/60">
                {activity.map((a, i) => (
                  <div key={`${a.time}-${i}`} className="px-4 py-2.5 flex items-center gap-3">
                    <div className="w-16 text-[11px] font-mono text-muted-foreground">{a.time}</div>
                    <div className="flex-1 text-[12px] font-mono truncate">{a.text}</div>
                    <span className={`h-5 px-2 rounded-sm border text-[10px] font-mono ${
                      a.level === 'critical' ? 'border-critical/40 bg-critical/10 text-critical' :
                      a.level === 'warning' ? 'border-warning/40 bg-warning/10 text-warning' :
                      a.level === 'success' ? 'border-success/40 bg-success/10 text-success' :
                      'border-primary/40 bg-primary/10 text-primary'
                    }`}>{a.level ?? 'info'}</span>
                  </div>
                ))}
              </div>
              <div className="h-10 px-4 border-t border-border flex items-center">
                <button className="text-[12px] font-mono text-primary hover:underline">Vollständiger Aktivitätsverlauf</button>
              </div>
            </Card>
          </div>
        </div>

        {/* Right side panel */}
        <div className="space-y-3">
          {/* Scan Summary — prominenter Report-Block */}
          <Card>
            <div className="h-10 px-4 border-b border-border flex items-center gap-2">
              <ClipboardList className="h-4 w-4 text-primary" />
              <span className="text-[11px] font-mono uppercase tracking-widest text-muted-foreground">Scan Summary</span>
            </div>
            <div className="p-4 space-y-2 text-[12px] font-mono">
              <MetaRow k="Scan Typ" v={scanMode} />
              <MetaRow k="Scan Start" v={startedAt} />
              <MetaRow k="Dauer" v={duration} />
              <MetaRow k="Hosts" v={`${completedHosts} / ${totalHosts} (100%)`} />
              <MetaRow k="Module" v="Events · Rules · Users · Procs · Files · TI" />
              <div className="pt-1 border-t border-border">
                <div className={`text-[12px] font-mono font-bold ${
                  criticalHosts > 0 ? 'text-warning' : 'text-success'
                }`}>
                  Ergebnis: {criticalHosts > 0 ? 'Security Action Required' : 'No Critical Findings'}
                </div>
              </div>
            </div>
          </Card>

          {/* Immediate Actions — Prioritätenliste */}
          {(criticalHosts > 0 || tiTotal > 0 || totalFindings > 0) && (
            <Card>
              <div className="h-10 px-4 border-b border-border flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 text-critical" />
                <span className="text-[11px] font-mono uppercase tracking-widest text-muted-foreground">Immediate Actions</span>
              </div>
              <div className="p-3 space-y-1">
                {sortedHosts.slice(0, 3).map((h, i) => (
                  <button
                    key={h.host}
                    onClick={() => onOpenHost?.(h.host)}
                    className="w-full flex items-center gap-2 h-9 px-2 rounded-sm hover:bg-accent text-left"
                  >
                    <span className={`h-5 w-5 rounded-full text-[10px] font-mono font-bold flex items-center justify-center shrink-0 ${
                      i === 0 ? 'bg-critical/20 text-critical' : i === 1 ? 'bg-high/20 text-high' : 'bg-warning/20 text-warning'
                    }`}>{i + 1}</span>
                    <span className="flex-1 text-[11.5px] font-mono truncate">{h.host} prüfen</span>
                    <span className={`text-[11px] font-mono font-bold shrink-0 ${
                      h.riskScore >= 7 ? 'text-critical' : h.riskScore >= 5 ? 'text-warning' : 'text-success'
                    }`}>Risk {h.riskScore.toFixed(1)}</span>
                  </button>
                ))}
                {tiTotal > 0 && (
                  <div className="flex items-center gap-2 h-9 px-2 rounded-sm text-[11.5px] font-mono">
                    <span className="h-5 w-5 rounded-full bg-primary/20 text-primary text-[10px] font-mono font-bold flex items-center justify-center shrink-0">4</span>
                    <span className="flex-1 truncate text-muted-foreground">{tiTotal} TI-Treffer validieren</span>
                    <Globe2 className="h-3.5 w-3.5 text-primary shrink-0" />
                  </div>
                )}
                {totalFindings > 0 && (
                  <div className="flex items-center gap-2 h-9 px-2 rounded-sm text-[11.5px] font-mono">
                    <span className="h-5 w-5 rounded-full bg-muted text-muted-foreground text-[10px] font-mono font-bold flex items-center justify-center shrink-0">{Math.min(5, criticalHosts + 2)}</span>
                    <span className="flex-1 truncate text-muted-foreground">{totalFindings} Findings deduplizieren</span>
                    <FileText className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                  </div>
                )}
              </div>
            </Card>
          )}

          <Card>
            <CardHeader title="Key Data (Fleet)" />
            <div className="p-4 space-y-3">
              <MetaRow k="Events verarbeitet" v={formatNumber(totalEvents)} />
              <MetaRow k="Logs analysiert" v={formatNumber(analyzedLogs)} />
              <MetaRow k="Dateien überprüft" v={formatNumber(checkedFiles)} />
              <MetaRow k="Konfigurationen geprüft" v={formatNumber(checkedConfigs)} />
              <MetaRow k="Schwachstellen geprüft" v={formatNumber(checkedVulnerabilities)} />
            </div>
          </Card>

          <Card>
            <CardHeader title="Threat Intel (Fleet)" />
            <div className="p-4 space-y-3">
              <MetaRow k="Gesamt Treffer" v={String(tiTotal)} valueClass={tiTotal > 0 ? 'text-warning' : ''} />
              <MetaRow k="Malicious IPs" v={String(tiMaliciousIps)} valueClass={tiMaliciousIps > 0 ? 'text-warning' : ''} />
              <MetaRow k="Malware Hashes" v={String(tiMalwareHashes)} valueClass={tiMalwareHashes > 0 ? 'text-warning' : ''} />
              <MetaRow k="Domains" v={String(tiDomains)} valueClass={tiDomains > 0 ? 'text-warning' : ''} />
              <MetaRow k="Geolocations (hoch riskant)" v={String(tiGeoRisk)} valueClass={tiGeoRisk > 0 ? 'text-warning' : ''} />
            </div>
          </Card>

          <Card>
            <CardHeader title="Risk Distribution" />
            <RiskDistribution critical={criticalHosts} high={highHosts} medium={mediumHosts} low={lowHosts} total={totalHosts} />
          </Card>

          <Card>
            <CardHeader title="Warum Fokus nötig ist" />
            <div className="p-4 space-y-2 text-[12px] font-mono text-muted-foreground">
              {criticalHosts > 0 && <Bullet>{criticalHosts} Hosts mit kritischem Risiko erfordern sofortige Maßnahmen</Bullet>}
              {tiTotal > 0 && <Bullet>{tiTotal} Threat Intel Treffer deuten auf erhöhte externe Risiken hin</Bullet>}
              {totalFindings > 0 && <Bullet>{totalFindings} Findings über alle Hosts gefunden</Bullet>}
              {criticalHosts === 0 && tiTotal === 0 && <Bullet>Keine kritischen Auffälligkeiten gefunden</Bullet>}
            </div>
          </Card>

          <Card>
            <CardHeader title="Empfohlene Maßnahmen" />
            <div className="p-3 space-y-2">
              {criticalHosts > 0 && <ActionLine icon={ShieldAlert} label="Kritische Hosts priorisiert behandeln" badge={criticalHosts} tone="critical" />}
              <ActionLine icon={Download} label="Sicherheitsupdates auf allen Hosts prüfen" />
              {tiTotal > 0 && <ActionLine icon={Globe2} label="Threat Intel Treffer validieren und blockieren" badge={tiTotal} />}
              <ActionLine icon={BarChart3} label="Konfigurations-Härtung umsetzen" />
              <ActionLine icon={Database} label="Baseline Abweichungen beheben" />
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}

function MetaRow({ k, v, valueClass = '' }: { k: string; v: string; valueClass?: string }) {
  return (
    <div className="grid grid-cols-[150px_1fr] gap-2 text-[12px] font-mono">
      <div className="text-muted-foreground">{k}</div>
      <div className={`text-right truncate ${valueClass}`}>{v}</div>
    </div>
  );
}

function Bullet({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex items-start gap-2">
      <CheckCircle2 className="h-4 w-4 text-success mt-0.5 shrink-0" />
      <span>{children}</span>
    </div>
  );
}

function ActionLine({ icon: Icon, label, badge, tone = 'default' }: {
  icon: ComponentType<{ className?: string }>;
  label: string;
  badge?: number;
  tone?: 'default' | 'critical';
}) {
  return (
    <button className="w-full h-9 rounded-md border border-border hover:bg-accent px-3 flex items-center gap-2 text-left">
      <Icon className={`h-4 w-4 shrink-0 ${tone === 'critical' ? 'text-critical' : 'text-warning'}`} />
      <span className="flex-1 text-[12px] font-mono">{label}</span>
      {badge != null && (
        <span className={`h-5 min-w-5 px-1.5 rounded-full border text-[10px] font-mono inline-flex items-center justify-center ${
          tone === 'critical' ? 'border-critical/40 bg-critical/10 text-critical' : 'border-warning/40 bg-warning/10 text-warning'
        }`}>{badge}</span>
      )}
    </button>
  );
}
